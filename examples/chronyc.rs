//! A tiny chronyc: `chronyc [socket] [tracking|sources|burst|makestep|reload]`.

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let socket = if args.first().is_some_and(|a| a.starts_with('/')) {
        args.remove(0)
    } else {
        chrony_cmdmon::DEFAULT_SOCKET.to_string()
    };
    let chronyd = chrony_cmdmon::Client::connect(socket).await?;
    match args.first().map(String::as_str).unwrap_or("tracking") {
        "tracking" => println!("{:#?}", chronyd.tracking().await?),
        "sources" => {
            for s in chronyd.sources().await? {
                println!(
                    "{}{} {:<40} {:>2} {:>3} {:>3o} {:>5} {:+.9} [{:+.9}] +/- {:.9}",
                    s.mode.symbol(),
                    s.state.symbol(),
                    s.address.to_string(),
                    s.stratum,
                    s.poll,
                    s.reachability,
                    s.since_sample,
                    s.latest_meas,
                    s.orig_latest_meas,
                    s.latest_meas_err
                );
            }
        }
        "burst" => chronyd.burst(4, 4).await?,
        "makestep" => chronyd.make_step().await?,
        "reload" => chronyd.reload_sources().await?,
        other => return Err(format!("unknown command {other}").into()),
    }
    Ok(())
}
