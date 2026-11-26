//! The client against a scripted chronyd on a Unix socket of its own.

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chrony_cmdmon::*;
use tokio::net::UnixDatagram;

/// What the scripted chronyd answers to a request packet: any number of
/// datagrams (none: the request is lost).
type Script = dyn Fn(&[u8], usize) -> Vec<Vec<u8>> + Send + Sync;

struct FakeChronyd {
    dir: PathBuf,
    socket: PathBuf,
    received: Arc<AtomicUsize>,
}

impl FakeChronyd {
    fn start(script: impl Fn(&[u8], usize) -> Vec<Vec<u8>> + Send + Sync + 'static) -> FakeChronyd {
        let dir = std::env::temp_dir().join(format!(
            "chrony-cmdmon-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("chronyd.sock");
        let server = UnixDatagram::bind(&socket).unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let script: Arc<Script> = Arc::new(script);
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((n, from)) = server.recv_from(&mut buffer).await {
                let nth = count.fetch_add(1, Ordering::SeqCst);
                let to = from.as_pathname().unwrap().to_path_buf();
                for reply in script(&buffer[..n], nth) {
                    let _ = server.send_to(&reply, &to).await;
                }
            }
        });
        FakeChronyd {
            dir,
            socket,
            received,
        }
    }

    async fn client(&self) -> Client {
        Client::connect(&self.socket)
            .await
            .unwrap()
            .with_timeout(Duration::from_millis(100))
    }

    fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

impl Drop for FakeChronyd {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn command(request: &[u8]) -> u16 {
    u16::from_be_bytes([request[4], request[5]])
}

fn data_u32(request: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(request[20 + at..24 + at].try_into().unwrap())
}

/// chronyd's answer to `request`: of `kind`, with `status` and `data`.
fn reply(request: &[u8], kind: ReplyKind, status: Status, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![6, 2, 0, 0];
    packet.extend_from_slice(&request[4..6]);
    packet.extend_from_slice(&kind.code().to_be_bytes());
    packet.extend_from_slice(&status.code().to_be_bytes());
    packet.extend_from_slice(&[0; 6]);
    packet.extend_from_slice(&request[8..12]);
    packet.extend_from_slice(&[0; 8]);
    packet.extend_from_slice(data);
    packet.resize(packet.len().max(kind.length()), 0);
    packet
}

fn null(request: &[u8]) -> Vec<u8> {
    reply(request, ReplyKind::Null, Status::Success, &[])
}

fn n_sources(request: &[u8], n: u32) -> Vec<u8> {
    reply(
        request,
        ReplyKind::NSources,
        Status::Success,
        &n.to_be_bytes(),
    )
}

/// A source at 192.0.2.`index`.
fn source(request: &[u8], index: u32) -> Vec<u8> {
    let mut data = vec![192, 0, 2, index as u8];
    data.extend_from_slice(&[0; 12]);
    data.extend_from_slice(&[0, 1, 0, 0]);
    reply(request, ReplyKind::SourceData, Status::Success, &data)
}

#[tokio::test]
async fn a_lost_request_is_sent_again() {
    let chronyd = FakeChronyd::start(|request, nth| {
        if nth == 0 {
            vec![]
        } else {
            vec![n_sources(request, 3)]
        }
    });
    let client = chronyd.client().await;
    assert_eq!(client.n_sources().await.unwrap(), 3);
    assert_eq!(chronyd.received(), 2);
}

#[tokio::test]
async fn a_chronyd_that_never_answers_times_out() {
    let chronyd = FakeChronyd::start(|_, _| vec![]);
    let client = chronyd.client().await.with_attempts(4);
    assert!(matches!(client.tracking().await, Err(Error::Timeout)));
    assert_eq!(chronyd.received(), 4);
}

#[tokio::test]
async fn a_late_answer_to_an_earlier_request_is_ignored() {
    let chronyd = FakeChronyd::start(|request, _| {
        let mut stale = n_sources(request, 99);
        // The sequence of the request before.
        let sequence = u32::from_be_bytes(request[8..12].try_into().unwrap()).wrapping_sub(1);
        stale[16..20].copy_from_slice(&sequence.to_be_bytes());
        vec![b"garbage".to_vec(), stale, n_sources(request, 3)]
    });
    let client = chronyd.client().await;
    assert_eq!(client.n_sources().await.unwrap(), 3);
}

#[tokio::test]
async fn a_source_removed_meanwhile_ends_the_list() {
    let chronyd = FakeChronyd::start(|request, _| {
        vec![match command(request) {
            14 => n_sources(request, 3),
            15 if data_u32(request, 0) < 2 => source(request, data_u32(request, 0)),
            _ => reply(request, ReplyKind::Null, Status::NoSuchSource, &[]),
        }]
    });
    let client = chronyd.client().await;
    let sources = client.sources().await.unwrap();
    let addresses: Vec<String> = sources.iter().map(|s| s.address.to_string()).collect();
    assert_eq!(addresses, ["192.0.2.0", "192.0.2.1"]);
}

#[tokio::test]
async fn clients_are_read_in_batches() {
    // 10 clients: a batch of 8, then 2.
    let chronyd = FakeChronyd::start(|request, _| {
        let first = data_u32(request, 0);
        let n = (10 - first).min(8);
        let mut data = Vec::new();
        for value in [10, first + n, n] {
            data.extend_from_slice(&u32::to_be_bytes(value));
        }
        for i in 0..n {
            let mut client = vec![10, 0, 0, (first + i) as u8];
            client.extend_from_slice(&[0; 12]);
            client.extend_from_slice(&[0, 1, 0, 0]);
            client.extend_from_slice(&(first + i).to_be_bytes());
            client.resize(60, 0);
            data.extend_from_slice(&client);
        }
        vec![reply(
            request,
            ReplyKind::ClientAccesses,
            Status::Success,
            &data,
        )]
    });
    let client = chronyd.client().await;
    let clients = client.clients(0, false).await.unwrap();
    assert_eq!(clients.len(), 10);
    assert_eq!(clients[9].address.to_string(), "10.0.0.9");
    assert_eq!(clients[9].ntp_hits, 9);
    assert_eq!(chronyd.received(), 2);
}

#[tokio::test]
async fn access_checks_answer_with_a_status() {
    let chronyd = FakeChronyd::start(|request, _| {
        let allowed = request[20] == 10;
        let status = if allowed {
            Status::AccessAllowed
        } else {
            Status::AccessDenied
        };
        vec![reply(request, ReplyKind::Null, status, &[])]
    });
    let client = chronyd.client().await;
    assert!(client
        .ntp_access("10.0.0.1".parse().unwrap())
        .await
        .unwrap());
    assert!(!client
        .command_access("192.0.2.1".parse().unwrap())
        .await
        .unwrap());
}

#[tokio::test]
async fn a_refusal_is_its_status() {
    let chronyd = FakeChronyd::start(|request, _| {
        vec![reply(request, ReplyKind::Null, Status::Unauthorised, &[])]
    });
    let client = chronyd.client().await;
    assert!(matches!(
        client.reload_sources().await,
        Err(Error::Status(Status::Unauthorised))
    ));
}

#[tokio::test]
async fn an_invalid_request_is_not_sent() {
    let chronyd = FakeChronyd::start(|request, _| vec![null(request)]);
    let client = chronyd.client().await;
    assert!(matches!(
        client.add_source(NtpSource::server("")).await,
        Err(Error::InvalidRequest(_))
    ));
    assert_eq!(chronyd.received(), 0);
    client
        .add_source(NtpSource::server("ntp.example.org"))
        .await
        .unwrap();
    assert_eq!(chronyd.received(), 1);
}

#[tokio::test]
async fn requests_from_tasks_sharing_a_client_get_their_own_answers() {
    let chronyd = FakeChronyd::start(|request, _| {
        vec![match command(request) {
            14 => n_sources(request, 5),
            _ => source(request, data_u32(request, 0)),
        }]
    });
    let client = Arc::new(chronyd.client().await);
    let tasks: Vec<_> = (0..8)
        .map(|index| {
            let client = client.clone();
            tokio::spawn(async move {
                match client
                    .request(&Request::SourceData { index })
                    .await
                    .unwrap()
                {
                    Reply::SourceData(s) => s.address.to_string(),
                    other => panic!("{other:?}"),
                }
            })
        })
        .collect();
    for (index, task) in tasks.into_iter().enumerate() {
        assert_eq!(task.await.unwrap(), format!("192.0.2.{index}"));
    }
}

#[tokio::test]
async fn a_raw_reply_is_the_packet_received() {
    let chronyd = FakeChronyd::start(|request, _| vec![n_sources(request, 7)]);
    let client = chronyd.client().await;
    let raw = client.request_raw(&Request::NSources).await.unwrap();
    assert_eq!(raw.packet.len(), 32);
    assert_eq!(
        Reply::decode(&Request::NSources, raw.sequence, &raw.packet).unwrap(),
        Reply::NSources(7)
    );
}

#[tokio::test]
async fn the_clients_sockets_are_removed_when_dropped() {
    let chronyd = FakeChronyd::start(|request, _| vec![null(request)]);
    let first = chronyd.client().await;
    let second = chronyd.client().await;
    first.make_step().await.unwrap();
    second.make_step().await.unwrap();
    let process_dir = chronyd
        .dir
        .join(format!("chrony-cmdmon.{}", std::process::id()));
    assert_eq!(std::fs::read_dir(&process_dir).unwrap().count(), 2);
    drop(first);
    assert_eq!(std::fs::read_dir(&process_dir).unwrap().count(), 1);
    drop(second);
    assert!(!process_dir.exists());
}

#[tokio::test]
async fn no_chronyd() {
    let dir = std::env::temp_dir().join(format!("chrony-cmdmon-none-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    assert!(matches!(
        Client::connect(dir.join("chronyd.sock")).await,
        Err(Error::Io(_))
    ));
    // Nothing left behind.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir(&dir).unwrap();
}

/// The kind of reply chronyd answers a command code with.
fn kind_of(code: u16) -> ReplyKind {
    match code {
        11 => ReplyKind::ManualTimestamp,
        14 => ReplyKind::NSources,
        15 => ReplyKind::SourceData,
        33 => ReplyKind::Tracking,
        34 => ReplyKind::Sourcestats,
        35 => ReplyKind::Rtc,
        41 => ReplyKind::ManualList,
        44 => ReplyKind::Activity,
        51 => ReplyKind::Smoothing,
        54 => ReplyKind::ServerStats,
        57 => ReplyKind::NtpData,
        65 => ReplyKind::NtpSourceName,
        67 => ReplyKind::AuthData,
        68 => ReplyKind::ClientAccesses,
        69 => ReplyKind::SelectData,
        _ => ReplyKind::Null,
    }
}

#[tokio::test]
async fn every_method_sends_its_command() {
    let codes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = codes.clone();
    let chronyd = FakeChronyd::start(move |request, _| {
        let code = command(request);
        seen.lock().unwrap().push(code);
        let data: Vec<u8> = match code {
            // One source, and an empty table of clients.
            14 => 1u32.to_be_bytes().to_vec(),
            _ => Vec::new(),
        };
        vec![reply(request, kind_of(code), Status::Success, &data)]
    });
    let c = chronyd.client().await;
    let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    c.tracking().await.unwrap();
    assert_eq!(c.sources().await.unwrap().len(), 1);
    assert_eq!(c.sourcestats().await.unwrap().len(), 1);
    assert_eq!(c.select_data().await.unwrap().len(), 1);
    c.ntp_data(ip).await.unwrap();
    c.source_name(ip).await.unwrap();
    c.auth_data(ip).await.unwrap();
    c.activity().await.unwrap();
    c.smoothing().await.unwrap();
    c.rtc_data().await.unwrap();
    c.server_stats().await.unwrap();
    c.manual_list().await.unwrap();
    c.clients(0, true).await.unwrap();
    c.settime(std::time::SystemTime::now()).await.unwrap();
    c.burst(4, 4).await.unwrap();
    c.set_online(true).await.unwrap();
    c.set_online(false).await.unwrap();
    c.onoffline().await.unwrap();
    c.add_source(NtpSource::pool("pool.ntp.org")).await.unwrap();
    c.delete_source(ip).await.unwrap();
    c.make_step().await.unwrap();
    c.reload_sources().await.unwrap();
    c.reset_sources().await.unwrap();
    c.refresh().await.unwrap();
    c.reselect().await.unwrap();
    c.dump().await.unwrap();
    c.cycle_logs().await.unwrap();
    c.rekey().await.unwrap();
    c.write_rtc().await.unwrap();
    c.trim_rtc().await.unwrap();
    c.shutdown().await.unwrap();
    assert_eq!(
        *codes.lock().unwrap(),
        [
            33, 14, 15, 14, 34, 14, 69, 57, 65, 67, 44, 51, 35, 54, 41, 68, 11, 3, 1, 2, 63, 64,
            29, 43, 70, 66, 53, 48, 6, 37, 16, 30, 36, 62
        ]
    );
}

#[tokio::test]
async fn a_reply_of_another_kind_is_malformed() {
    // chronyd answering a tracking request with a source count.
    let chronyd = FakeChronyd::start(|request, _| {
        vec![reply(request, ReplyKind::NSources, Status::Success, &[])]
    });
    let client = chronyd.client().await;
    assert!(matches!(client.tracking().await, Err(Error::Malformed(_))));
}
