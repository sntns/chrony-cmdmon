//! Real replies decoded as chronyc decodes them.
//!
//! `fixtures/chronyd-replies.tsv` holds chronyd 4.8's answers to every
//! request that changes nothing, recorded with `examples/capture.rs`;
//! `fixtures/chronyc-outputs.txt` what `chronyc -c` printed just before and
//! just after. The decoded values must be chronyc's, to its printed
//! precision. A few drift with time between the two (the age of a sample,
//! a dispersion growing, an offset extrapolated to now): those get a
//! tolerance.

use std::collections::HashMap;
use std::time::SystemTime;

use chrony_cmdmon::*;

struct Fixtures {
    replies: HashMap<String, (u32, Vec<u8>)>,
    /// `chronyc -c` lines by command, from the snapshot taken after.
    chronyc: HashMap<String, Vec<Vec<String>>>,
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn fixtures() -> Fixtures {
    let replies = include_str!("fixtures/chronyd-replies.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next().unwrap().to_string();
            let sequence = fields.next().unwrap().parse().unwrap();
            (name, (sequence, unhex(fields.next().unwrap())))
        })
        .collect();
    let outputs = include_str!("fixtures/chronyc-outputs.txt");
    let after = &outputs[outputs.find("=====AFTER").unwrap()..];
    let mut chronyc: HashMap<String, Vec<Vec<String>>> = HashMap::new();
    let mut section = String::new();
    for line in after.lines().skip(1) {
        if let Some(command) = line.strip_prefix("### chronyc -c ") {
            section = command.trim_start_matches("-n ").to_string();
            chronyc.entry(section.clone()).or_default();
        } else if !line.is_empty() {
            chronyc
                .entry(section.clone())
                .or_default()
                .push(line.split(',').map(str::to_string).collect());
        }
    }
    Fixtures { replies, chronyc }
}

impl Fixtures {
    fn decode(&self, name: &str, request: Request) -> Result<Reply, Error> {
        let (sequence, packet) = &self.replies[name];
        Reply::decode(&request, *sequence, packet)
    }

    fn lines(&self, command: &str) -> &[Vec<String>] {
        &self.chronyc[command]
    }

    /// The chronyc line about `address`, in a per-source listing.
    fn line_of(&self, command: &str, column: usize, address: &Address) -> &[String] {
        self.lines(command)
            .iter()
            .find(|line| line[column] == address.to_string())
            .unwrap_or_else(|| panic!("no `{command}` line for {address}"))
    }
}

/// `value` as chronyc printed it, to within `tolerance`.
fn close(field: &str, value: f64, printed: &str, tolerance: f64) {
    let printed: f64 = printed.parse().unwrap();
    assert!(
        (value - printed).abs() <= tolerance,
        "{field}: decoded {value}, chronyc printed {printed}"
    );
}

/// chronyc's `%.9f` and friends: exact to the printed digits.
fn same(field: &str, value: f64, printed: &str) {
    let decimals = printed.split('.').nth(1).map_or(0, str::len);
    close(
        field,
        value,
        printed,
        0.5 * 10f64.powi(-(decimals as i32)) + 1e-12,
    );
}

fn epoch_seconds(time: SystemTime) -> f64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[test]
fn tracking() {
    let f = fixtures();
    let Reply::Tracking(t) = f.decode("tracking", Request::Tracking).unwrap() else {
        panic!("tracking");
    };
    let c = &f.lines("tracking")[0];
    assert_eq!(format!("{:08X}", t.ref_id), c[0]);
    assert_eq!(t.address.to_string(), c[1]);
    assert_eq!(t.stratum.to_string(), c[2]);
    same("ref_time", epoch_seconds(t.ref_time), &c[3]);
    same("current_correction", t.current_correction, &c[4]);
    same("last_offset", t.last_offset, &c[5]);
    same("rms_offset", t.rms_offset, &c[6]);
    same("freq_ppm", t.freq_ppm, &c[7]);
    same("resid_freq_ppm", t.resid_freq_ppm, &c[8]);
    same("skew_ppm", t.skew_ppm, &c[9]);
    same("root_delay", t.root_delay, &c[10]);
    // Grows with the time since the last update.
    close("root_dispersion", t.root_dispersion, &c[11], 1e-6);
    same("last_update_interval", t.last_update_interval, &c[12]);
    assert_eq!(t.leap_status.to_string(), c[13]);
    assert!(t.synchronized());
}

#[test]
fn sources() {
    let f = fixtures();
    let Reply::NSources(n) = f.decode("n_sources", Request::NSources).unwrap() else {
        panic!("n_sources");
    };
    assert_eq!(n as usize, f.lines("sources").len());
    for index in 0..n {
        let name = format!("source_data {index}");
        let Reply::SourceData(s) = f.decode(&name, Request::SourceData { index }).unwrap() else {
            panic!("{name}");
        };
        let c = f.line_of("sources", 2, &s.address);
        assert_eq!(s.mode.symbol().to_string(), c[0]);
        assert_eq!(s.state.symbol().to_string(), c[1]);
        assert_eq!(s.stratum.to_string(), c[3]);
        assert_eq!(s.poll.to_string(), c[4]);
        assert_eq!(format!("{:o}", s.reachability), c[5]);
        // A second or two passed.
        close("since_sample", s.since_sample.into(), &c[6], 2.0);
        same("latest_meas", s.latest_meas, &c[7]);
        same("orig_latest_meas", s.orig_latest_meas, &c[8]);
        same("latest_meas_err", s.latest_meas_err, &c[9]);
        assert_eq!(s.flags, 0);
    }
}

#[test]
fn sourcestats() {
    let f = fixtures();
    for index in 0..5 {
        let name = format!("sourcestats {index}");
        let Reply::Sourcestats(s) = f.decode(&name, Request::Sourcestats { index }).unwrap() else {
            panic!("{name}");
        };
        let c = f.line_of("sourcestats", 0, &s.address);
        assert_eq!(s.n_samples.to_string(), c[1]);
        assert_eq!(s.n_runs.to_string(), c[2]);
        assert_eq!(s.span_seconds.to_string(), c[3]);
        same("resid_freq_ppm", s.resid_freq_ppm, &c[4]);
        same("skew_ppm", s.skew_ppm, &c[5]);
        // Extrapolated to the time of the request.
        close("est_offset", s.est_offset, &c[6], 1e-7);
        same("sd", s.sd, &c[7]);
        assert!(s.est_offset_err > 0.0);
    }
}

#[test]
fn select_data() {
    let f = fixtures();
    for index in 0..5 {
        let name = format!("select_data {index}");
        let Reply::SelectData(s) = f.decode(&name, Request::SelectData { index }).unwrap() else {
            panic!("{name}");
        };
        let c = f.line_of("selectdata", 1, &s.address);
        assert_eq!(s.state.to_string(), c[0]);
        assert_eq!(if s.authentication { "Y" } else { "N" }, c[2]);
        assert!(c[3..13].iter().all(|option| option == "-"));
        assert_eq!(s.conf_options, SelectOptions::default());
        assert_eq!(s.eff_options, SelectOptions::default());
        assert_eq!(s.last_sample_ago.to_string(), c[13]);
        same("score", s.score, &c[14]);
        same("lo_limit", s.lo_limit, &c[15]);
        same("hi_limit", s.hi_limit, &c[16]);
        assert_eq!(LeapStatus::from(u16::from(s.leap)).to_string(), c[17]);
    }
}

#[test]
fn activity_and_server_stats() {
    let f = fixtures();
    let Reply::Activity(a) = f.decode("activity", Request::Activity).unwrap() else {
        panic!("activity");
    };
    let c = &f.lines("activity")[0];
    assert_eq!(
        [
            a.online,
            a.offline,
            a.burst_online,
            a.burst_offline,
            a.unresolved
        ]
        .map(|v| v.to_string()),
        [&c[0], &c[1], &c[2], &c[3], &c[4]].map(String::clone)
    );
    let Reply::ServerStats(s) = f.decode("serverstats", Request::ServerStats).unwrap() else {
        panic!("serverstats");
    };
    let c = &f.lines("serverstats")[0];
    // chronyc prints them in this order.
    assert_eq!(s.ntp_hits.to_string(), c[0]);
    assert_eq!(s.ntp_drops.to_string(), c[1]);
    // chronyc's own commands since count too.
    let cmd_hits: u64 = c[2].parse().unwrap();
    assert!(s.cmd_hits <= cmd_hits && s.cmd_hits + 100 > cmd_hits);
    assert_eq!(s.cmd_drops.to_string(), c[3]);
    assert_eq!(s.log_drops.to_string(), c[4]);
    assert_eq!(s.nke_hits.to_string(), c[5]);
    assert_eq!(s.nke_drops.to_string(), c[6]);
    assert_eq!(s.ntp_auth_hits.to_string(), c[7]);
}

#[test]
fn ntp_data() {
    let f = fixtures();
    for line in f.lines("ntpdata 162.159.200.1").iter().chain(
        [
            "ntpdata 164.132.166.29",
            "ntpdata 172.232.44.156",
            "ntpdata 23.161.104.133",
            "ntpdata 109.190.177.205",
        ]
        .iter()
        .flat_map(|command| f.lines(command)),
    ) {
        let address = Address::Ip(line[0].parse().unwrap());
        let name = format!("ntp_data {address}");
        let Reply::NtpData(d) = f.decode(&name, Request::NtpData(address)).unwrap() else {
            panic!("{name}");
        };
        assert_eq!(d.remote_address, address);
        assert_eq!(d.remote_port.to_string(), line[2]);
        assert_eq!(d.local_address.to_string(), line[3]);
        assert_eq!(LeapStatus::from(u16::from(d.leap)).to_string(), line[5]);
        assert_eq!(d.version.to_string(), line[6]);
        assert_eq!((d.mode, line[7].as_str()), (4, "Server"));
        assert_eq!(d.stratum.to_string(), line[8]);
        assert_eq!(d.poll.to_string(), line[9]);
        assert_eq!(d.precision.to_string(), line[11]);
        same("precision", 2f64.powi(d.precision.into()), &line[12]);
        same("root_delay", d.root_delay, &line[13]);
        same("root_dispersion", d.root_dispersion, &line[14]);
        assert_eq!(format!("{:08X}", d.ref_id), line[15]);
        assert_eq!(ref_id_name_if_refclock(d.ref_id, d.stratum), line[16]);
        same("ref_time", epoch_seconds(d.ref_time), &line[17]);
        same("offset", d.offset, &line[18]);
        same("peer_delay", d.peer_delay, &line[19]);
        same("peer_dispersion", d.peer_dispersion, &line[20]);
        same("response_time", d.response_time, &line[21]);
        same("jitter_asymmetry", d.jitter_asymmetry, &line[22]);
        assert_eq!(format!("{:03b}", d.tests() >> 7), line[23]);
        assert_eq!(format!("{:03b}", (d.tests() >> 4) & 0x7), line[24]);
        assert_eq!(format!("{:04b}", d.tests() & 0xf), line[25]);
        assert_eq!(if d.interleaved() { "Yes" } else { "No" }, line[26]);
        assert_eq!(if d.authenticated() { "Yes" } else { "No" }, line[27]);
        assert_eq!(timestamping(d.tx_timestamping), line[28]);
        assert_eq!(timestamping(d.rx_timestamping), line[29]);
        let totals = [
            d.total_tx_count,
            d.total_rx_count,
            d.total_valid_count,
            d.total_good_count,
            d.total_kernel_tx_ts,
            d.total_kernel_rx_ts,
            d.total_hw_tx_ts,
            d.total_hw_rx_ts,
        ];
        assert_eq!(
            totals.map(|t| t.to_string()).to_vec(),
            line[30..38].to_vec()
        );
    }
}

/// chronyc names the reference of a stratum-1 server (`PPS`, `GPS`).
fn ref_id_name_if_refclock(ref_id: u32, stratum: u8) -> String {
    if stratum <= 1 {
        ref_id_name(ref_id)
    } else {
        String::new()
    }
}

fn timestamping(source: char) -> &'static str {
    match source {
        'D' => "Daemon",
        'K' => "Kernel",
        'H' => "Hardware",
        _ => "?",
    }
}

#[test]
fn auth_data_and_source_names() {
    let f = fixtures();
    for line in f.lines("authdata") {
        let address = Address::Ip(line[0].parse().unwrap());
        let name = format!("auth_data {address}");
        let Reply::AuthData(a) = f.decode(&name, Request::AuthData(address)).unwrap() else {
            panic!("{name}");
        };
        assert_eq!((a.mode, line[1].as_str()), (AuthMode::None, "-"));
        assert_eq!(a.key_id.to_string(), line[2]);
        assert_eq!(a.key_type.to_string(), line[3]);
        assert_eq!(a.key_length.to_string(), line[4]);
        assert_eq!(a.last_ke_ago.to_string(), line[5]);
        assert_eq!(a.ke_attempts.to_string(), line[6]);
        assert_eq!(u16::from(a.nak).to_string(), line[7]);
        assert_eq!(a.cookies.to_string(), line[8]);
        assert_eq!(a.cookie_length.to_string(), line[9]);

        let name = format!("source_name {address}");
        let Reply::NtpSourceName(source) =
            f.decode(&name, Request::NtpSourceName(address)).unwrap()
        else {
            panic!("{name}");
        };
        // Four sources came from chrony.conf's pool (named after it), one
        // was configured by its address.
        let expected = if address.to_string() == "109.190.177.205" {
            address.to_string()
        } else {
            "0.openembedded.pool.ntp.org".to_string()
        };
        assert_eq!(source, expected);
    }
}

#[test]
fn empty_lists() {
    let f = fixtures();
    assert_eq!(
        f.decode("manual_list", Request::ManualList).unwrap(),
        Reply::ManualList(Vec::new())
    );
    let clients = Request::ClientAccesses {
        first_index: 0,
        n_clients: 8,
        min_hits: 0,
        reset: false,
    };
    let Reply::ClientAccesses(c) = f.decode("clients", clients).unwrap() else {
        panic!("clients");
    };
    assert!(c.clients.is_empty());
    assert_eq!(c.next_index, c.n_indices);
}

#[test]
fn refusals() {
    let f = fixtures();
    let status = |name: &str, request: Request| match f.decode(name, request) {
        Err(Error::Status(status)) => status,
        other => panic!("{name}: {other:?}"),
    };
    assert_eq!(status("smoothing", Request::Smoothing), Status::NotEnabled);
    assert_eq!(status("rtcdata", Request::RtcReport), Status::NoRtc);
    assert_eq!(
        status("accheck", Request::AcCheck("192.0.2.1".parse().unwrap())),
        Status::AccessDenied
    );
    assert_eq!(
        status(
            "cmdaccheck",
            Request::CmdAcCheck("127.0.0.1".parse().unwrap())
        ),
        Status::AccessDenied
    );
    assert_eq!(
        status(
            "source_data_out_of_range",
            Request::SourceData { index: 999 }
        ),
        Status::NoSuchSource
    );
}
