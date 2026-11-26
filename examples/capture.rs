//! Records chronyd's answers to every request that changes nothing: one
//! line per request, `name<TAB>sequence<TAB>packet in hex` (the fixtures of
//! the golden tests). `capture [socket]`.

use chrony_cmdmon::*;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let chronyd = Client::connect(socket).await?;
    let n = chronyd.n_sources().await?;
    let mut requests: Vec<(String, Request)> = vec![
        ("tracking".into(), Request::Tracking),
        ("n_sources".into(), Request::NSources),
        ("activity".into(), Request::Activity),
        ("smoothing".into(), Request::Smoothing),
        ("rtcdata".into(), Request::RtcReport),
        ("serverstats".into(), Request::ServerStats),
        ("manual_list".into(), Request::ManualList),
        (
            "clients".into(),
            Request::ClientAccesses {
                first_index: 0,
                n_clients: 8,
                min_hits: 0,
                reset: false,
            },
        ),
        ("accheck".into(), Request::AcCheck("192.0.2.1".parse()?)),
        (
            "cmdaccheck".into(),
            Request::CmdAcCheck("127.0.0.1".parse()?),
        ),
        (
            "source_data_out_of_range".into(),
            Request::SourceData { index: 999 },
        ),
    ];
    for index in 0..n {
        requests.push((
            format!("source_data {index}"),
            Request::SourceData { index },
        ));
        requests.push((
            format!("sourcestats {index}"),
            Request::Sourcestats { index },
        ));
        requests.push((
            format!("select_data {index}"),
            Request::SelectData { index },
        ));
        if let Reply::SourceData(source) = chronyd.request(&Request::SourceData { index }).await? {
            let address = source.address;
            requests.push((format!("ntp_data {address}"), Request::NtpData(address)));
            requests.push((
                format!("source_name {address}"),
                Request::NtpSourceName(address),
            ));
            requests.push((format!("auth_data {address}"), Request::AuthData(address)));
        }
    }
    for (name, request) in requests {
        let raw = chronyd.request_raw(&request).await?;
        let hex: String = raw.packet.iter().map(|b| format!("{b:02x}")).collect();
        println!("{name}\t{}\t{hex}", raw.sequence);
    }
    Ok(())
}
