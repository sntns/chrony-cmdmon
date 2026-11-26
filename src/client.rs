//! The client: requests to chronyd over its Unix socket, where it accepts
//! every command, privileged ones included (`burst`, `makestep`, ...).
//!
//! chronyd answers a datagram to the address it came from: the client binds
//! a socket of its own, next to chronyd's, in a private directory chronyd
//! (which drops root for its own user) can still reach - as chronyc does.

use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::UnixDatagram;
use tokio::sync::Mutex;

use crate::protocol::*;
use crate::Error;

/// chronyd's command socket, as distributions build it.
pub const DEFAULT_SOCKET: &str = "/run/chrony/chronyd.sock";

/// How long chronyd has to answer an attempt, and how many attempts.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
const DEFAULT_ATTEMPTS: u16 = 3;

/// chronyd's answer to a request, undecoded ([`Client::request_raw`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawReply {
    /// The request's sequence number, which the answer echoes.
    pub sequence: u32,
    /// The reply packet as received, header included.
    pub packet: Vec<u8>,
}

/// A client of chronyd. Requests are sent one at a time (the client may be
/// shared: `&self`).
pub struct Client {
    socket: Mutex<UnixDatagram>,
    sequence: std::sync::atomic::AtomicU32,
    timeout: Duration,
    attempts: u16,
    /// The commands this chronyd only knows in their older form.
    legacy: std::sync::Mutex<std::collections::HashSet<u16>>,
    _dir: SocketDir,
}

impl Client {
    /// A client of the chronyd listening on `server` (see
    /// [`DEFAULT_SOCKET`]). Fails when the socket can't be reached, or the
    /// client's own can't be made next to it (chronyd's directory is
    /// usually root's and chrony's only).
    pub async fn connect(server: impl AsRef<Path>) -> Result<Client, Error> {
        let server = server.as_ref();
        let parent = server.parent().unwrap_or(Path::new("/"));
        let dir = SocketDir::new(parent)?;
        let socket = UnixDatagram::bind(&dir.socket)?;
        std::fs::set_permissions(&dir.socket, std::fs::Permissions::from_mode(0o666))?;
        socket.connect(server)?;
        Ok(Client {
            socket: Mutex::new(socket),
            sequence: std::sync::atomic::AtomicU32::new(random_u32()),
            legacy: std::sync::Mutex::new(std::collections::HashSet::new()),
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            _dir: dir,
        })
    }

    /// How long chronyd has to answer each attempt (1 s by default).
    pub fn with_timeout(mut self, timeout: Duration) -> Client {
        self.timeout = timeout;
        self
    }

    /// How many times a request is sent before giving up (3 by default).
    pub fn with_attempts(mut self, attempts: u16) -> Client {
        self.attempts = attempts.max(1);
        self
    }

    /// Sends `request`, again after each timeout, and decodes the answer.
    ///
    /// A request with an older form ([`Request::legacy_code`]) that chronyd
    /// refuses as invalid (a version before the current form) is sent again
    /// in that form, and from then on in that form only.
    pub async fn request(&self, request: &Request) -> Result<Reply, Error> {
        let legacy = self.uses_legacy(request);
        let raw = self.exchange(request, legacy).await?;
        match Reply::decode(request, raw.sequence, &raw.packet) {
            Err(Error::Status(Status::Invalid)) if !legacy && request.legacy_code().is_some() => {
                let raw = self.exchange(request, true).await?;
                let reply = Reply::decode(request, raw.sequence, &raw.packet);
                if reply.is_ok() {
                    self.legacy
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(request.code());
                }
                reply
            }
            reply => reply,
        }
    }

    /// Sends `request`, again after each timeout, and returns chronyd's
    /// answer undecoded: the packet whose sequence is the request's (to
    /// record, or to decode otherwise). In its older form if chronyd was
    /// found to need it.
    pub async fn request_raw(&self, request: &Request) -> Result<RawReply, Error> {
        self.exchange(request, self.uses_legacy(request)).await
    }

    fn uses_legacy(&self, request: &Request) -> bool {
        request.legacy_code().is_some()
            && self
                .legacy
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&request.code())
    }

    async fn exchange(&self, request: &Request, legacy: bool) -> Result<RawReply, Error> {
        let socket = self.socket.lock().await;
        let sequence = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut buffer = [0u8; 2048];
        for attempt in 0..self.attempts {
            let packet = match legacy {
                true => request
                    .encode_legacy(sequence, attempt)
                    .unwrap_or_else(|| request.encode(sequence, attempt))?,
                false => request.encode(sequence, attempt)?,
            };
            socket.send(&packet).await?;
            let deadline = tokio::time::Instant::now() + self.timeout;
            loop {
                let received = tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await;
                let Ok(received) = received else {
                    break;
                };
                let packet = &buffer[..received?];
                // A late answer to an earlier request: not this one's.
                if ReplyHeader::parse(packet).map(|h| h.sequence).ok() == Some(sequence) {
                    return Ok(RawReply {
                        sequence,
                        packet: packet.to_vec(),
                    });
                }
            }
        }
        Err(Error::Timeout)
    }

    async fn null(&self, request: Request) -> Result<(), Error> {
        self.request(&request).await.map(|_| ())
    }

    /// `chronyc tracking`.
    pub async fn tracking(&self) -> Result<Tracking, Error> {
        match self.request(&Request::Tracking).await? {
            Reply::Tracking(tracking) => Ok(tracking),
            _ => Err(unexpected()),
        }
    }

    /// How many sources chronyd has (`sources` lists them).
    pub async fn n_sources(&self) -> Result<u32, Error> {
        match self.request(&Request::NSources).await? {
            Reply::NSources(n) => Ok(n),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc sources`: every source, in chronyd's order.
    pub async fn sources(&self) -> Result<Vec<SourceData>, Error> {
        self.each_source(
            |index| Request::SourceData { index },
            |reply| match reply {
                Reply::SourceData(source) => Some(source),
                _ => None,
            },
        )
        .await
    }

    /// `chronyc sourcestats`: every source's statistics, in chronyd's order.
    pub async fn sourcestats(&self) -> Result<Vec<Sourcestats>, Error> {
        self.each_source(
            |index| Request::Sourcestats { index },
            |reply| match reply {
                Reply::Sourcestats(stats) => Some(stats),
                _ => None,
            },
        )
        .await
    }

    /// `chronyc selectdata`: what the source selection made of every
    /// source.
    pub async fn select_data(&self) -> Result<Vec<SelectData>, Error> {
        self.each_source(
            |index| Request::SelectData { index },
            |reply| match reply {
                Reply::SelectData(data) => Some(data),
                _ => None,
            },
        )
        .await
    }

    /// One request per source index; a source removed meanwhile (reload
    /// sources, a pool's server replaced) ends the list.
    async fn each_source<T>(
        &self,
        request: impl Fn(u32) -> Request,
        extract: impl Fn(Reply) -> Option<T>,
    ) -> Result<Vec<T>, Error> {
        let n = self.n_sources().await?;
        let mut items = Vec::with_capacity(n as usize);
        for index in 0..n {
            match self.request(&request(index)).await {
                Ok(reply) => items.push(extract(reply).ok_or_else(unexpected)?),
                Err(Error::Status(Status::NoSuchSource)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(items)
    }

    /// `chronyc ntpdata`, for the source at `address`.
    pub async fn ntp_data(&self, address: impl Into<Address>) -> Result<NtpData, Error> {
        match self.request(&Request::NtpData(address.into())).await? {
            Reply::NtpData(data) => Ok(data),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc sourcename`: the name the source at `address` was
    /// configured with.
    pub async fn source_name(&self, address: impl Into<Address>) -> Result<String, Error> {
        match self
            .request(&Request::NtpSourceName(address.into()))
            .await?
        {
            Reply::NtpSourceName(name) => Ok(name),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc authdata`, for the source at `address`.
    pub async fn auth_data(&self, address: impl Into<Address>) -> Result<AuthData, Error> {
        match self.request(&Request::AuthData(address.into())).await? {
            Reply::AuthData(data) => Ok(data),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc activity`.
    pub async fn activity(&self) -> Result<Activity, Error> {
        match self.request(&Request::Activity).await? {
            Reply::Activity(activity) => Ok(activity),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc smoothing`.
    pub async fn smoothing(&self) -> Result<Smoothing, Error> {
        match self.request(&Request::Smoothing).await? {
            Reply::Smoothing(smoothing) => Ok(smoothing),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc rtcdata`.
    pub async fn rtc_data(&self) -> Result<Rtc, Error> {
        match self.request(&Request::RtcReport).await? {
            Reply::Rtc(rtc) => Ok(rtc),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc serverstats`.
    pub async fn server_stats(&self) -> Result<ServerStats, Error> {
        match self.request(&Request::ServerStats).await? {
            Reply::ServerStats(stats) => Ok(stats),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc manual list`.
    pub async fn manual_list(&self) -> Result<Vec<ManualSample>, Error> {
        match self.request(&Request::ManualList).await? {
            Reply::ManualList(samples) => Ok(samples),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc clients`: every client chronyd remembers with at least
    /// `min_hits` hits, `reset` clearing their counters as they are read.
    pub async fn clients(&self, min_hits: u32, reset: bool) -> Result<Vec<ClientAccess>, Error> {
        let mut clients = Vec::new();
        let mut first_index = 0;
        loop {
            let batch = match self
                .request(&Request::ClientAccesses {
                    first_index,
                    n_clients: CLIENT_ACCESSES as u32,
                    min_hits,
                    reset,
                })
                .await?
            {
                Reply::ClientAccesses(batch) => batch,
                _ => return Err(unexpected()),
            };
            clients.extend(batch.clients);
            // Done, or chronyd made no progress (its table shrank).
            if batch.next_index >= batch.n_indices || batch.next_index <= first_index {
                return Ok(clients);
            }
            first_index = batch.next_index;
        }
    }

    /// `chronyc settime`: a manual sample of the time (manual mode must be
    /// on).
    pub async fn settime(&self, time: std::time::SystemTime) -> Result<ManualTimestamp, Error> {
        match self.request(&Request::Settime(time)).await? {
            Reply::ManualTimestamp(timestamp) => Ok(timestamp),
            _ => Err(unexpected()),
        }
    }

    /// `chronyc burst n_good/n_total`, for every source.
    pub async fn burst(&self, n_good: u32, n_total: u32) -> Result<(), Error> {
        self.null(Request::Burst {
            selection: SourceSelection::All,
            n_good,
            n_total,
        })
        .await
    }

    /// `chronyc online` (`true`) or `chronyc offline` (`false`), for every
    /// source.
    pub async fn set_online(&self, online: bool) -> Result<(), Error> {
        let selection = SourceSelection::All;
        self.null(if online {
            Request::Online(selection)
        } else {
            Request::Offline(selection)
        })
        .await
    }

    /// `chronyc onoffline`: each source online or offline, as its route.
    pub async fn onoffline(&self) -> Result<(), Error> {
        self.null(Request::OnOffline).await
    }

    /// `chronyc add server|peer|pool`.
    pub async fn add_source(&self, source: NtpSource) -> Result<(), Error> {
        self.null(Request::AddSource(Box::new(source))).await
    }

    /// `chronyc delete`.
    pub async fn delete_source(&self, address: impl Into<Address>) -> Result<(), Error> {
        self.null(Request::DelSource(address.into())).await
    }

    /// `chronyc makestep`.
    pub async fn make_step(&self) -> Result<(), Error> {
        self.null(Request::MakeStep).await
    }

    /// `chronyc reload sources`.
    pub async fn reload_sources(&self) -> Result<(), Error> {
        self.null(Request::ReloadSources).await
    }

    /// `chronyc reset sources`.
    pub async fn reset_sources(&self) -> Result<(), Error> {
        self.null(Request::ResetSources).await
    }

    /// `chronyc refresh`.
    pub async fn refresh(&self) -> Result<(), Error> {
        self.null(Request::Refresh).await
    }

    /// `chronyc reselect`.
    pub async fn reselect(&self) -> Result<(), Error> {
        self.null(Request::Reselect).await
    }

    /// `chronyc dump`.
    pub async fn dump(&self) -> Result<(), Error> {
        self.null(Request::Dump).await
    }

    /// `chronyc cyclelogs`.
    pub async fn cycle_logs(&self) -> Result<(), Error> {
        self.null(Request::CycleLogs).await
    }

    /// `chronyc rekey`.
    pub async fn rekey(&self) -> Result<(), Error> {
        self.null(Request::Rekey).await
    }

    /// `chronyc writertc`.
    pub async fn write_rtc(&self) -> Result<(), Error> {
        self.null(Request::WriteRtc).await
    }

    /// `chronyc trimrtc`.
    pub async fn trim_rtc(&self) -> Result<(), Error> {
        self.null(Request::TrimRtc).await
    }

    /// `chronyc shutdown`.
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.null(Request::Shutdown).await
    }

    /// `chronyc accheck`: whether NTP clients at `ip` are allowed.
    pub async fn ntp_access(&self, ip: std::net::IpAddr) -> Result<bool, Error> {
        access(self.request(&Request::AcCheck(ip)).await)
    }

    /// `chronyc cmdaccheck`: whether command clients at `ip` are allowed.
    pub async fn command_access(&self, ip: std::net::IpAddr) -> Result<bool, Error> {
        access(self.request(&Request::CmdAcCheck(ip)).await)
    }
}

/// A reply of another type than the request's: `decode` rules it out.
fn unexpected() -> Error {
    Error::Malformed("unexpected reply type")
}

/// chronyd answers an access check with a status.
fn access(result: Result<Reply, Error>) -> Result<bool, Error> {
    match result {
        Err(Error::Status(Status::AccessAllowed)) => Ok(true),
        Err(Error::Status(Status::AccessDenied)) => Ok(false),
        Ok(_) => Err(unexpected()),
        Err(e) => Err(e),
    }
}

/// The client's socket and the directories holding it, removed when the
/// client is dropped: `<dir>/chrony-cmdmon.<pid>/<random>/sock`, the
/// directories 0711 and the socket 0666 so that chronyd (its own user)
/// reaches it while other users can't find it.
struct SocketDir {
    process: PathBuf,
    hidden: PathBuf,
    socket: PathBuf,
}

impl SocketDir {
    fn new(parent: &Path) -> std::io::Result<SocketDir> {
        let process = parent.join(format!("chrony-cmdmon.{}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o711).create(&process) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        // Ours, a directory, not a link someone planted.
        let metadata = std::fs::symlink_metadata(&process)?;
        if !metadata.is_dir() || metadata.uid() != effective_uid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("unexpected owner or type of {}", process.display()),
            ));
        }
        std::fs::set_permissions(&process, std::fs::Permissions::from_mode(0o711))?;
        let hidden = process.join(format!("{:016x}", random_u64()));
        std::fs::DirBuilder::new().mode(0o711).create(&hidden)?;
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o711))?;
        let socket = hidden.join("sock");
        Ok(SocketDir {
            process,
            hidden,
            socket,
        })
    }
}

impl Drop for SocketDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.hidden);
        // Another client of this process may still use it.
        let _ = std::fs::remove_dir(&self.process);
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn random_u64() -> u64 {
    use std::io::Read;
    let mut bytes = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_err()
    {
        // Unpredictable enough to avoid collisions, not secret.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        return now.as_nanos() as u64 ^ (u64::from(std::process::id()) << 32);
    }
    u64::from_ne_bytes(bytes)
}

fn random_u32() -> u32 {
    random_u64() as u32
}
