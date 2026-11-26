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

use crate::protocol::reply_sequence;
use crate::protocol::Reply;
use crate::protocol::Request;
use crate::protocol::SourceData;
use crate::protocol::Sources;
use crate::protocol::Tracking;
use crate::Error;

/// chronyd's command socket, as distributions build it.
pub const DEFAULT_SOCKET: &str = "/run/chrony/chronyd.sock";

/// How long chronyd has to answer an attempt, and how many attempts.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
const DEFAULT_ATTEMPTS: u16 = 3;

/// A client of chronyd. Requests are sent one at a time (the client may be
/// shared: `&self`).
pub struct Client {
    socket: Mutex<UnixDatagram>,
    sequence: std::sync::atomic::AtomicU32,
    timeout: Duration,
    attempts: u16,
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
    pub async fn request(&self, request: &Request) -> Result<Reply, Error> {
        let socket = self.socket.lock().await;
        let sequence = self
            .sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut buffer = [0u8; 1024];
        for attempt in 0..self.attempts {
            socket.send(&request.encode(sequence, attempt)).await?;
            let deadline = tokio::time::Instant::now() + self.timeout;
            loop {
                let received = tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await;
                let Ok(received) = received else {
                    break;
                };
                let packet = &buffer[..received?];
                // A late answer to an earlier request: not this one's.
                if reply_sequence(packet) != Some(sequence) {
                    continue;
                }
                return Reply::decode(request, sequence, packet);
            }
        }
        Err(Error::Timeout)
    }

    /// `chronyc tracking`.
    pub async fn tracking(&self) -> Result<Tracking, Error> {
        match self.request(&Request::Tracking).await? {
            Reply::Tracking(tracking) => Ok(tracking),
            _ => Err(Error::Malformed("unexpected reply type")),
        }
    }

    /// `chronyc sources`: every source, in chronyd's order.
    pub async fn sources(&self) -> Result<Vec<SourceData>, Error> {
        let n = match self.request(&Request::NSources).await? {
            Reply::NSources(n) => n,
            _ => return Err(Error::Malformed("unexpected reply type")),
        };
        let mut sources = Vec::with_capacity(n as usize);
        for index in 0..n {
            match self.request(&Request::SourceData { index }).await {
                Ok(Reply::SourceData(source)) => sources.push(source),
                // Removed meanwhile (reload sources, a pool's server).
                Err(Error::Status(crate::Status::NoSuchSource)) => break,
                Ok(_) => return Err(Error::Malformed("unexpected reply type")),
                Err(e) => return Err(e),
            }
        }
        Ok(sources)
    }

    /// `chronyc burst n_good/n_total`, for every source.
    pub async fn burst(&self, n_good: u32, n_total: u32) -> Result<(), Error> {
        self.null(&Request::Burst {
            sources: Sources::All,
            n_good,
            n_total,
        })
        .await
    }

    /// `chronyc online` (`true`) or `chronyc offline` (`false`), for every
    /// source.
    pub async fn set_online(&self, online: bool) -> Result<(), Error> {
        let sources = Sources::All;
        self.null(&if online {
            Request::Online { sources }
        } else {
            Request::Offline { sources }
        })
        .await
    }

    /// `chronyc makestep`.
    pub async fn make_step(&self) -> Result<(), Error> {
        self.null(&Request::MakeStep).await
    }

    /// `chronyc reload sources`.
    pub async fn reload_sources(&self) -> Result<(), Error> {
        self.null(&Request::ReloadSources).await
    }

    async fn null(&self, request: &Request) -> Result<(), Error> {
        self.request(request).await.map(|_| ())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A chronyd answering `NSources` (3) and refusing the rest; the first
    /// request is dropped, to make the client try again.
    async fn fake_chronyd(dir: &Path) -> PathBuf {
        let path = dir.join("chronyd.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let mut first = true;
            loop {
                let Ok((n, from)) = server.recv_from(&mut buffer).await else {
                    return;
                };
                if first {
                    first = false;
                    continue;
                }
                let request = &buffer[..n];
                let command = u16::from_be_bytes([request[4], request[5]]);
                let (reply, status, data): (u16, u16, Vec<u8>) = if command == 14 {
                    (2, 0, 3u32.to_be_bytes().to_vec())
                } else {
                    (1, 2, Vec::new())
                };
                let mut packet = vec![6, 2, 0, 0];
                packet.extend_from_slice(&command.to_be_bytes());
                packet.extend_from_slice(&reply.to_be_bytes());
                packet.extend_from_slice(&status.to_be_bytes());
                packet.extend_from_slice(&[0; 6]);
                packet.extend_from_slice(&request[8..12]);
                packet.extend_from_slice(&[0; 8]);
                packet.extend_from_slice(&data);
                let to = from.as_pathname().unwrap().to_path_buf();
                let _ = server.send_to(&packet, to).await;
            }
        });
        path
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("chrony-cmdmon-test-{:x}", random_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_request_is_sent_again_until_answered() {
        let dir = temp_dir();
        let server = fake_chronyd(&dir).await;
        let client = Client::connect(&server)
            .await
            .unwrap()
            .with_timeout(Duration::from_millis(100));
        assert_eq!(
            client.request(&Request::NSources).await.unwrap(),
            Reply::NSources(3)
        );
        assert!(matches!(
            client.reload_sources().await,
            Err(Error::Status(crate::Status::Unauthorised))
        ));
        drop(client);
        // Its own socket and directories are gone.
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(left.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn no_chronyd() {
        let dir = temp_dir();
        assert!(Client::connect(dir.join("chronyd.sock")).await.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
