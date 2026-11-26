//! Against a running chronyd: `CHRONY_CMDMON_SOCKET=/run/chrony/chronyd.sock
//! cargo test --test live` (as root, or chronyd's user). Skipped without the
//! variable. With `CHRONY_CMDMON_PRIVILEGED=1` it also sends commands that
//! change nothing lasting (`burst`, `reload sources`).

use chrony_cmdmon::*;

async fn chronyd() -> Option<Client> {
    let socket = std::env::var("CHRONY_CMDMON_SOCKET").ok()?;
    Some(Client::connect(socket).await.expect("connect to chronyd"))
}

#[tokio::test]
async fn every_report() {
    let Some(chronyd) = chronyd().await else {
        eprintln!("CHRONY_CMDMON_SOCKET not set: skipped");
        return;
    };
    let tracking = chronyd.tracking().await.unwrap();
    eprintln!("tracking: {tracking:?}");

    let n = chronyd.n_sources().await.unwrap();
    let sources = chronyd.sources().await.unwrap();
    assert_eq!(sources.len(), n as usize);
    assert_eq!(chronyd.sourcestats().await.unwrap().len(), sources.len());
    assert_eq!(chronyd.select_data().await.unwrap().len(), sources.len());

    let activity = chronyd.activity().await.unwrap();
    let counted = activity.online
        + activity.offline
        + activity.burst_online
        + activity.burst_offline
        + activity.unresolved;
    assert!(counted >= n as i32, "{activity:?} against {n} sources");

    for source in &sources {
        if source.mode == SourceMode::ReferenceClock {
            continue;
        }
        let data = chronyd.ntp_data(source.address).await.unwrap();
        assert_eq!(data.remote_address, source.address);
        assert!(!chronyd
            .source_name(source.address)
            .await
            .unwrap()
            .is_empty());
        chronyd.auth_data(source.address).await.unwrap();
    }

    chronyd.server_stats().await.unwrap();
    chronyd.manual_list().await.unwrap();
    chronyd.clients(0, false).await.unwrap();
    // Not configured everywhere: a refusal is an answer too.
    for result in [
        chronyd.smoothing().await.map(|_| ()),
        chronyd.rtc_data().await.map(|_| ()),
    ] {
        assert!(
            matches!(result, Ok(()) | Err(Error::Status(_))),
            "{result:?}"
        );
    }
    assert!(matches!(
        chronyd
            .request(&Request::SourceData { index: n + 1000 })
            .await,
        Err(Error::Status(Status::NoSuchSource))
    ));
}

#[tokio::test]
async fn harmless_privileged_commands() {
    if std::env::var("CHRONY_CMDMON_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("CHRONY_CMDMON_PRIVILEGED not set: skipped");
        return;
    }
    let Some(chronyd) = chronyd().await else {
        return;
    };
    chronyd.burst(1, 2).await.unwrap();
    chronyd.reload_sources().await.unwrap();
}
