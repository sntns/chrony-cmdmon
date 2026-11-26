//! `cmdmon`: chronyc's commands over chronyd's Unix socket, with this crate.
//!
//! ```text
//! cmdmon [-c] [-h SOCKET] COMMAND [ARGS...]
//! ```
//!
//! The commands and their arguments are chronyc's (`tracking`, `sources`,
//! `burst 4/4`, `add server ntp.example.org iburst`, ...); `-c` prints the
//! reports as chronyc's `-c` does (comma-separated values). `cmdmon help`
//! lists them.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use chrony_cmdmon::*;

const USAGE: &str = "\
Usage: cmdmon [-c] [-h SOCKET] COMMAND [ARGS...]

  -c         print the reports as comma-separated values
  -h SOCKET  chronyd's command socket (default /run/chrony/chronyd.sock)

Reports:
  tracking | sources | sourcestats | selectdata | activity | serverstats
  ntpdata [ADDRESS] | sourcename ADDRESS | authdata | smoothing | rtcdata
  clients [MIN_HITS] [reset] | manual list | accheck ADDRESS | cmdaccheck ADDRESS
Sources:
  add server|pool|peer NAME [iburst] [burst] [prefer] [noselect] [trust]
      [require] [offline] [nts] [port N] [minpoll N] [maxpoll N] [key N]
      [maxsources N] [maxdelay S] [offset S] [certset N] [ntsport N]
  delete ADDRESS | burst GOOD/TOTAL [SUBNET] | online [SUBNET] | offline [SUBNET]
  onoffline | reload sources | reset sources | refresh | reselect
  minpoll|maxpoll|minstratum|polltarget ADDRESS N
  maxdelay|maxdelayratio|maxdelaydevratio ADDRESS VALUE
  selectopts ADDRESS [+|-]noselect|prefer|trust|require...
  offset ADDRESS SECONDS | reselectdist SECONDS
Clock:
  makestep [THRESHOLD LIMIT] | maxupdateskew PPM | dfreq PPM | doffset SECONDS
  local [stratum N] [distance S] [orphan] [activate S] [waitsynced S]
      [waitunsynced S] | local off
  manual on|off|reset|list|delete INDEX | settime UNIX_SECONDS|RFC3339
  smoothtime reset|activate
Access:
  allow|deny|cmdallow|cmddeny [all] [SUBNET]
Daemon:
  dump | cyclelogs | rekey | writertc | trimrtc | shutdown
";

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1).peekable();
    let mut csv = false;
    let mut socket = DEFAULT_SOCKET.to_string();
    while let Some(arg) = args.peek() {
        match arg.as_str() {
            "-c" => csv = true,
            // chronyc's resolving switches: names are never resolved here.
            "-n" | "-4" | "-6" => {}
            "-h" => {
                args.next();
                match args.peek() {
                    Some(path) => socket = path.clone(),
                    None => return fail("-h needs a socket"),
                }
            }
            "--help" | "help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" | "-v" => {
                println!("cmdmon (chrony-cmdmon) {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => break,
        }
        args.next();
    }
    let words: Vec<String> = args.collect();
    if words.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    let chronyd = match Client::connect(&socket).await {
        Ok(client) => client,
        Err(e) => return fail(&format!("Could not open connection to daemon: {e}")),
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match run(&chronyd, csv, &words).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::FAILURE
}

type Result<T> = std::result::Result<T, String>;

fn chronyd_error(e: Error) -> String {
    match e {
        // chronyc's wording, e.g. "506 Cannot talk to daemon"
        Error::Status(status) => format!("{} {status}", 500 + status.code()),
        Error::Timeout => "506 Cannot talk to daemon".to_string(),
        other => other.to_string(),
    }
}

fn number<T: std::str::FromStr>(word: Option<&&str>, what: &str) -> Result<T> {
    word.and_then(|w| w.parse().ok())
        .ok_or_else(|| format!("Invalid syntax: {what} expected"))
}

fn address(word: Option<&&str>) -> Result<Address> {
    word.and_then(|w| w.parse::<IpAddr>().ok())
        .map(Address::Ip)
        .ok_or_else(|| "Invalid host/IP address".to_string())
}

/// `ADDRESS[/BITS]`, or nothing: every address.
fn subnet(word: Option<&&str>) -> Result<Subnet> {
    let Some(word) = word else {
        return Ok(Subnet::ANY);
    };
    let (ip, bits) = match word.split_once('/') {
        Some((ip, bits)) => (ip, Some(bits)),
        None => (*word, None),
    };
    let ip: IpAddr = ip.parse().map_err(|_| format!("Bad subnet {word}"))?;
    let bits = match bits {
        Some(bits) => bits.parse().map_err(|_| format!("Bad subnet {word}"))?,
        None => Subnet::host(ip).bits,
    };
    Ok(Subnet { ip: Some(ip), bits })
}

/// `ADDRESS/BITS` as an address and a mask, or nothing: every source.
fn selection(word: Option<&&str>) -> Result<SourceSelection> {
    let subnet = subnet(word)?;
    let Some(ip) = subnet.ip else {
        return Ok(SourceSelection::All);
    };
    let mask = match ip {
        IpAddr::V4(_) => {
            let bits = u32::from(subnet.bits.min(32));
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            IpAddr::V4(mask.into())
        }
        IpAddr::V6(_) => {
            let bits = u32::from(subnet.bits.min(128));
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6(mask.into())
        }
    };
    Ok(SourceSelection::Matching { address: ip, mask })
}

async fn null(chronyd: &Client, request: Request) -> Result<()> {
    chronyd.request(&request).await.map_err(chronyd_error)?;
    println!("200 OK");
    Ok(())
}

async fn run(chronyd: &Client, csv: bool, words: &[&str]) -> Result<()> {
    let out = Output { csv };
    let arg = |i: usize| words.get(i);
    match words {
        ["tracking"] => out.tracking(&chronyd.tracking().await.map_err(chronyd_error)?),
        ["sources", ..] => out.sources(&chronyd.sources().await.map_err(chronyd_error)?),
        ["sourcestats", ..] => {
            out.sourcestats(&chronyd.sourcestats().await.map_err(chronyd_error)?)
        }
        ["selectdata", ..] => out.select_data(&chronyd.select_data().await.map_err(chronyd_error)?),
        ["activity"] => out.activity(&chronyd.activity().await.map_err(chronyd_error)?),
        ["serverstats"] => out.server_stats(&chronyd.server_stats().await.map_err(chronyd_error)?),
        ["smoothing"] => out.smoothing(&chronyd.smoothing().await.map_err(chronyd_error)?),
        ["rtcdata"] => out.rtc(&chronyd.rtc_data().await.map_err(chronyd_error)?),
        ["manual", "list"] => out.manual_list(&chronyd.manual_list().await.map_err(chronyd_error)?),
        ["clients", ..] => {
            let min_hits = words.get(1).and_then(|w| w.parse().ok()).unwrap_or(0);
            let reset = words.contains(&"reset");
            out.clients(
                &chronyd
                    .clients(min_hits, reset)
                    .await
                    .map_err(chronyd_error)?,
            )
        }
        ["ntpdata"] => {
            for source in chronyd.sources().await.map_err(chronyd_error)? {
                if source.mode != SourceMode::ReferenceClock {
                    out.ntp_data(
                        &chronyd
                            .ntp_data(source.address)
                            .await
                            .map_err(chronyd_error)?,
                    );
                }
            }
        }
        ["ntpdata", _] => out.ntp_data(
            &chronyd
                .ntp_data(address(arg(1))?)
                .await
                .map_err(chronyd_error)?,
        ),
        ["sourcename", _] => {
            println!(
                "{}",
                chronyd
                    .source_name(address(arg(1))?)
                    .await
                    .map_err(chronyd_error)?
            )
        }
        ["authdata", ..] => {
            let mut rows = Vec::new();
            for source in chronyd.sources().await.map_err(chronyd_error)? {
                if source.mode != SourceMode::ReferenceClock {
                    let auth = chronyd
                        .auth_data(source.address)
                        .await
                        .map_err(chronyd_error)?;
                    rows.push((source.address, auth));
                }
            }
            out.auth_data(&rows);
        }
        ["accheck", ip] | ["cmdaccheck", ip] => {
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| "Invalid host/IP address".to_string())?;
            let allowed = if words[0] == "accheck" {
                chronyd.ntp_access(ip).await
            } else {
                chronyd.command_access(ip).await
            };
            println!(
                "{}",
                match allowed.map_err(chronyd_error)? {
                    true => "208 Access allowed",
                    false => "209 Access denied",
                }
            );
        }
        ["add", kind, name, options @ ..] => {
            let source = ntp_source(kind, name, options)?;
            null(chronyd, Request::AddSource(Box::new(source))).await?
        }
        ["delete", _] => null(chronyd, Request::DelSource(address(arg(1))?)).await?,
        ["burst", counts, ..] => {
            let (good, total) = counts
                .split_once('/')
                .and_then(|(g, t)| Some((g.parse().ok()?, t.parse().ok()?)))
                .ok_or("Invalid syntax for burst command")?;
            let request = Request::Burst {
                selection: selection(arg(2))?,
                n_good: good,
                n_total: total,
            };
            null(chronyd, request).await?
        }
        ["online", ..] => null(chronyd, Request::Online(selection(arg(1))?)).await?,
        ["offline", ..] => null(chronyd, Request::Offline(selection(arg(1))?)).await?,
        ["onoffline"] => null(chronyd, Request::OnOffline).await?,
        ["reload", "sources"] => null(chronyd, Request::ReloadSources).await?,
        ["reset", "sources"] => null(chronyd, Request::ResetSources).await?,
        ["refresh"] => null(chronyd, Request::Refresh).await?,
        ["reselect"] => null(chronyd, Request::Reselect).await?,
        ["reselectdist", _] => {
            null(
                chronyd,
                Request::ReselectDistance(number(arg(1), "distance")?),
            )
            .await?
        }
        ["minpoll", _, _] => {
            let request = Request::ModifyMinpoll {
                address: address(arg(1))?,
                minpoll: number(arg(2), "minpoll")?,
            };
            null(chronyd, request).await?
        }
        ["maxpoll", _, _] => {
            let request = Request::ModifyMaxpoll {
                address: address(arg(1))?,
                maxpoll: number(arg(2), "maxpoll")?,
            };
            null(chronyd, request).await?
        }
        ["minstratum", _, _] => {
            let request = Request::ModifyMinstratum {
                address: address(arg(1))?,
                min_stratum: number(arg(2), "stratum")?,
            };
            null(chronyd, request).await?
        }
        ["polltarget", _, _] => {
            let request = Request::ModifyPolltarget {
                address: address(arg(1))?,
                poll_target: number(arg(2), "poll target")?,
            };
            null(chronyd, request).await?
        }
        ["maxdelay", _, _] => {
            let request = Request::ModifyMaxdelay {
                address: address(arg(1))?,
                max_delay: number(arg(2), "delay")?,
            };
            null(chronyd, request).await?
        }
        ["maxdelayratio", _, _] => {
            let request = Request::ModifyMaxdelayratio {
                address: address(arg(1))?,
                ratio: number(arg(2), "ratio")?,
            };
            null(chronyd, request).await?
        }
        ["maxdelaydevratio", _, _] => {
            let request = Request::ModifyMaxdelaydevratio {
                address: address(arg(1))?,
                ratio: number(arg(2), "ratio")?,
            };
            null(chronyd, request).await?
        }
        ["selectopts", _, options @ ..] => {
            let (mut mask, mut set) = (SelectOptions::default(), SelectOptions::default());
            for option in options {
                let (enable, name) = match option.split_at(1) {
                    ("+", name) => (true, name),
                    ("-", name) => (false, name),
                    _ => return Err(format!("Invalid option {option}")),
                };
                let flag = match name {
                    "noselect" => SelectOptions::NOSELECT,
                    "prefer" => SelectOptions::PREFER,
                    "trust" => SelectOptions::TRUST,
                    "require" => SelectOptions::REQUIRE,
                    _ => return Err(format!("Invalid option {option}")),
                };
                mask = mask | flag;
                if enable {
                    set = set | flag;
                }
            }
            let request = Request::ModifySelectOpts {
                address: address(arg(1))?,
                ref_id: 0,
                mask,
                options: set,
            };
            null(chronyd, request).await?
        }
        ["offset", _, _] => {
            let request = Request::ModifyOffset {
                address: address(arg(1))?,
                ref_id: 0,
                offset: number(arg(2), "offset")?,
            };
            null(chronyd, request).await?
        }
        ["makestep"] => null(chronyd, Request::MakeStep).await?,
        ["makestep", _, _] => {
            let request = Request::ModifyMakestep {
                threshold: number(arg(1), "threshold")?,
                limit: number(arg(2), "limit")?,
            };
            null(chronyd, request).await?
        }
        ["maxupdateskew", _] => {
            let request = Request::ModifyMaxupdateskew {
                skew_ppm: number(arg(1), "skew")?,
            };
            null(chronyd, request).await?
        }
        ["dfreq", _] => null(chronyd, Request::Dfreq(number(arg(1), "frequency")?)).await?,
        ["doffset", _] => null(chronyd, Request::Doffset(number(arg(1), "offset")?)).await?,
        ["local", "off"] => null(chronyd, Request::Local(LocalOptions::off())).await?,
        ["local", options @ ..] => null(chronyd, Request::Local(local(options)?)).await?,
        ["manual", "on"] => null(chronyd, Request::Manual(ManualOption::On)).await?,
        ["manual", "off"] => null(chronyd, Request::Manual(ManualOption::Off)).await?,
        ["manual", "reset"] => null(chronyd, Request::Manual(ManualOption::Reset)).await?,
        ["manual", "delete", _] => {
            let request = Request::ManualDelete {
                index: number(arg(2), "index")?,
            };
            null(chronyd, request).await?
        }
        ["settime", time] => {
            let time = parse_time(time)?;
            let done = chronyd.settime(time).await.map_err(chronyd_error)?;
            println!(
                "Clock was {:.2} seconds fast.  Frequency change = {:.2}ppm, new frequency = {:.2}ppm",
                -done.offset, done.dfreq_ppm, done.new_afreq_ppm
            );
        }
        ["smoothtime", "reset"] => {
            null(chronyd, Request::SmoothTime(SmoothTimeOption::Reset)).await?
        }
        ["smoothtime", "activate"] => {
            null(chronyd, Request::SmoothTime(SmoothTimeOption::Activate)).await?
        }
        [access @ ("allow" | "deny" | "cmdallow" | "cmddeny"), rest @ ..] => {
            let (all, rest) = match rest {
                ["all", rest @ ..] => (true, rest),
                rest => (false, rest),
            };
            let subnet = subnet(rest.first())?;
            let request = match (*access, all) {
                ("allow", false) => Request::Allow(subnet),
                ("allow", true) => Request::AllowAll(subnet),
                ("deny", false) => Request::Deny(subnet),
                ("deny", true) => Request::DenyAll(subnet),
                ("cmdallow", false) => Request::CmdAllow(subnet),
                ("cmdallow", true) => Request::CmdAllowAll(subnet),
                ("cmddeny", false) => Request::CmdDeny(subnet),
                _ => Request::CmdDenyAll(subnet),
            };
            null(chronyd, request).await?
        }
        ["dump"] => null(chronyd, Request::Dump).await?,
        ["cyclelogs"] => null(chronyd, Request::CycleLogs).await?,
        ["rekey"] => null(chronyd, Request::Rekey).await?,
        ["writertc"] => null(chronyd, Request::WriteRtc).await?,
        ["trimrtc"] => null(chronyd, Request::TrimRtc).await?,
        ["shutdown"] => null(chronyd, Request::Shutdown).await?,
        _ => return Err(format!("Unrecognized command: {}", words.join(" "))),
    }
    Ok(())
}

fn ntp_source(kind: &str, name: &str, options: &[&str]) -> Result<NtpSource> {
    let mut source = match kind {
        "server" => NtpSource::server(name),
        "pool" => NtpSource::pool(name),
        "peer" => NtpSource::peer(name),
        _ => return Err(format!("Invalid syntax for add command: {kind}")),
    };
    let mut words = options.iter();
    while let Some(word) = words.next() {
        let mut value = |what: &str| words.next().copied().ok_or(format!("{what} expected"));
        match *word {
            "iburst" => source.flags |= SourceFlags::IBURST,
            "burst" => source.flags |= SourceFlags::BURST,
            "prefer" => source.flags |= SourceFlags::PREFER,
            "noselect" => source.flags |= SourceFlags::NOSELECT,
            "trust" => source.flags |= SourceFlags::TRUST,
            "require" => source.flags |= SourceFlags::REQUIRE,
            "xleave" => source.flags |= SourceFlags::INTERLEAVED,
            "nts" => source.flags |= SourceFlags::NTS,
            "copy" => source.flags |= SourceFlags::COPY,
            "auto_offline" => source.flags |= SourceFlags::AUTO_OFFLINE,
            "offline" => source.flags = SourceFlags(source.flags.0 & !SourceFlags::ONLINE.0),
            "port" => source.port = parse(value("port")?)?,
            "minpoll" => source.minpoll = parse(value("minpoll")?)?,
            "maxpoll" => source.maxpoll = parse(value("maxpoll")?)?,
            "key" => source.authkey = parse(value("key")?)?,
            "maxsources" => source.max_sources = parse(value("maxsources")?)?,
            "minstratum" => source.min_stratum = parse(value("minstratum")?)?,
            "polltarget" => source.poll_target = parse(value("polltarget")?)?,
            "version" => source.version = parse(value("version")?)?,
            "minsamples" => source.min_samples = parse(value("minsamples")?)?,
            "maxsamples" => source.max_samples = parse(value("maxsamples")?)?,
            "maxdelay" => source.max_delay = parse(value("maxdelay")?)?,
            "maxdelayratio" => source.max_delay_ratio = parse(value("maxdelayratio")?)?,
            "maxdelaydevratio" => source.max_delay_dev_ratio = parse(value("maxdelaydevratio")?)?,
            "mindelay" => source.min_delay = parse(value("mindelay")?)?,
            "asymmetry" => source.asymmetry = parse(value("asymmetry")?)?,
            "offset" => source.offset = parse(value("offset")?)?,
            "filter" => source.filter_length = parse(value("filter")?)?,
            "certset" => source.cert_set = parse(value("certset")?)?,
            "ntsport" => source.nts_port = parse(value("ntsport")?)?,
            "maxunreach" => source.max_unreach = parse(value("maxunreach")?)?,
            "presend" => source.presend_minpoll = parse(value("presend")?)?,
            other => return Err(format!("Invalid option {other}")),
        }
    }
    Ok(source)
}

fn parse<T: std::str::FromStr>(word: &str) -> Result<T> {
    word.parse().map_err(|_| format!("Invalid value {word}"))
}

fn local(options: &[&str]) -> Result<LocalOptions> {
    let mut local = LocalOptions::default();
    let mut words = options.iter();
    while let Some(word) = words.next() {
        let mut value = |what: &str| words.next().copied().ok_or(format!("{what} expected"));
        match *word {
            "stratum" => local.stratum = parse(value("stratum")?)?,
            "distance" => local.distance = parse(value("distance")?)?,
            "orphan" => local.orphan = true,
            "activate" => local.activate = parse(value("activate")?)?,
            "waitsynced" => local.wait_synced = parse(value("waitsynced")?)?,
            "waitunsynced" => local.wait_unsynced = parse(value("waitunsynced")?)?,
            other => return Err(format!("Invalid option {other}")),
        }
    }
    Ok(local)
}

/// Seconds since the epoch, or RFC 3339 in UTC (`2026-01-02T03:04:05Z`).
fn parse_time(text: &str) -> Result<SystemTime> {
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(UNIX_EPOCH + Duration::from_secs(seconds));
    }
    let invalid =
        || format!("Invalid time {text} (seconds since the epoch, or YYYY-MM-DDTHH:MM:SSZ)");
    let text = text.strip_suffix('Z').ok_or_else(invalid)?;
    let (date, time) = text.split_once('T').ok_or_else(invalid)?;
    let d: Vec<i64> = date
        .split('-')
        .map(|n| n.parse().map_err(|_| invalid()))
        .collect::<Result<_>>()?;
    let t: Vec<i64> = time
        .split(':')
        .map(|n| n.parse().map_err(|_| invalid()))
        .collect::<Result<_>>()?;
    let (&[year, month, day], &[hour, minute, second]) = (&d[..], &t[..]) else {
        return Err(invalid());
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(seconds)
        .map(|s| UNIX_EPOCH + Duration::from_secs(s))
        .map_err(|_| invalid())
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Seconds since the epoch, with the fraction.
fn epoch(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// chronyc's dates: `Thu Nov 26 06:55:30 2026` (UTC).
fn date(time: SystemTime) -> String {
    let seconds = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {year}",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(month - 1) as usize],
        day,
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// An offset with the unit that keeps it at 4 digits or fewer, as chronyc's
/// source reports print it (`+1039ns`, `-25ms`).
fn scaled(seconds: f64, signed: bool) -> String {
    let (value, unit) = match seconds.abs() {
        x if x < 9999.5e-9 => (seconds * 1e9, "ns"),
        x if x < 9999.5e-6 => (seconds * 1e6, "us"),
        x if x < 9999.5e-3 => (seconds * 1e3, "ms"),
        _ => (seconds, "s"),
    };
    if signed {
        format!("{value:+.0}{unit}")
    } else {
        format!("{value:.0}{unit}")
    }
}

/// An interval in whole seconds with a unit (`64`, `17m`, `3h`, `2d`).
fn interval(seconds: u32) -> String {
    match seconds {
        u32::MAX => "-".to_string(),
        s if s < 1200 => format!("{s}"),
        s if s < 72_000 => format!("{}m", s / 60),
        s if s < 1_728_000 => format!("{}h", s / 3600),
        s if s < 31_536_000 => format!("{}d", s / 86_400),
        s => format!("{}y", s / 31_536_000),
    }
}

fn name(address: &Address, ref_id: u32) -> String {
    match address {
        Address::Unspecified | Address::Id(_) => ref_id_name(ref_id),
        address => address.to_string(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

struct Output {
    csv: bool,
}

impl Output {
    fn tracking(&self, t: &Tracking) {
        let reference = name(&t.address, t.ref_id);
        if self.csv {
            println!(
                "{:08X},{reference},{},{:.9},{:.9},{:.9},{:.9},{:.3},{:.3},{:.3},{:.9},{:.9},{:.1},{}",
                t.ref_id,
                t.stratum,
                epoch(t.ref_time),
                t.current_correction,
                t.last_offset,
                t.rms_offset,
                t.freq_ppm,
                t.resid_freq_ppm,
                t.skew_ppm,
                t.root_delay,
                t.root_dispersion,
                t.last_update_interval,
                t.leap_status
            );
            return;
        }
        let slow_fast = |slow: bool| if slow { "slow" } else { "fast" };
        println!("Reference ID    : {:08X} ({reference})", t.ref_id);
        println!("Stratum         : {}", t.stratum);
        println!("Ref time (UTC)  : {}", date(t.ref_time));
        println!(
            "System time     : {:.9} seconds {} of NTP time",
            t.current_correction.abs(),
            slow_fast(t.current_correction > 0.0)
        );
        println!("Last offset     : {:+.9} seconds", t.last_offset);
        println!("RMS offset      : {:.9} seconds", t.rms_offset);
        println!(
            "Frequency       : {:.3} ppm {}",
            t.freq_ppm.abs(),
            slow_fast(t.freq_ppm > 0.0)
        );
        println!("Residual freq   : {:+.3} ppm", t.resid_freq_ppm);
        println!("Skew            : {:.3} ppm", t.skew_ppm);
        println!("Root delay      : {:.9} seconds", t.root_delay);
        println!("Root dispersion : {:.9} seconds", t.root_dispersion);
        println!("Update interval : {:.1} seconds", t.last_update_interval);
        println!("Leap status     : {}", t.leap_status);
    }

    fn sources(&self, sources: &[SourceData]) {
        if !self.csv {
            println!("MS Name/IP address         Stratum Poll Reach LastRx Last sample");
            println!(
                "==============================================================================="
            );
        }
        for s in sources {
            let name = s.address.to_string();
            if self.csv {
                println!(
                    "{},{},{name},{},{},{:o},{},{:.9},{:.9},{:.9}",
                    s.mode.symbol(),
                    s.state.symbol(),
                    s.stratum,
                    s.poll,
                    s.reachability,
                    s.since_sample,
                    s.latest_meas,
                    s.orig_latest_meas,
                    s.latest_meas_err
                );
            } else {
                println!(
                    "{}{} {name:<27} {:>2}  {:>2}   {:>3o}  {:>4}  {:>7}[{:>7}] +/- {:>6}",
                    s.mode.symbol(),
                    s.state.symbol(),
                    s.stratum,
                    s.poll,
                    s.reachability,
                    interval(s.since_sample),
                    scaled(s.latest_meas, true),
                    scaled(s.orig_latest_meas, true),
                    scaled(s.latest_meas_err, false)
                );
            }
        }
    }

    fn sourcestats(&self, stats: &[Sourcestats]) {
        if !self.csv {
            println!(
                "Name/IP Address            NP  NR  Span  Frequency  Freq Skew  Offset  Std Dev"
            );
            println!(
                "=============================================================================="
            );
        }
        for s in stats {
            let name = name(&s.address, s.ref_id);
            if self.csv {
                println!(
                    "{name},{},{},{},{:.3},{:.3},{:.9},{:.9}",
                    s.n_samples,
                    s.n_runs,
                    s.span_seconds,
                    s.resid_freq_ppm,
                    s.skew_ppm,
                    s.est_offset,
                    s.sd
                );
            } else {
                println!(
                    "{name:<25} {:>3} {:>3} {:>5} {:>+10.3} {:>10.3} {:>7} {:>8}",
                    s.n_samples,
                    s.n_runs,
                    interval(s.span_seconds),
                    s.resid_freq_ppm,
                    s.skew_ppm,
                    scaled(s.est_offset, true),
                    scaled(s.sd, false)
                );
            }
        }
    }

    fn select_data(&self, data: &[SelectData]) {
        let options = |o: SelectOptions| {
            [
                (SelectOptions::NOSELECT, 'N'),
                (SelectOptions::PREFER, 'P'),
                (SelectOptions::TRUST, 'T'),
                (SelectOptions::REQUIRE, 'R'),
            ]
            .map(|(flag, letter)| if o.contains(flag) { letter } else { '-' })
        };
        if !self.csv {
            println!("S Name/IP Address        Auth COpts EOpts Last Score     Interval  Leap");
            println!("=======================================================================");
        }
        for s in data {
            let name = name(&s.address, s.ref_id);
            let leap = LeapStatus::from(u16::from(s.leap));
            let (conf, eff) = (options(s.conf_options), options(s.eff_options));
            if self.csv {
                let options: Vec<String> = conf
                    .iter()
                    .chain(['-'].iter())
                    .chain(eff.iter())
                    .chain(['-'].iter())
                    .map(char::to_string)
                    .collect();
                println!(
                    "{},{name},{},{},{},{:.1},{:.9},{:.9},{leap}",
                    s.state,
                    if s.authentication { "Y" } else { "N" },
                    options.join(","),
                    s.last_sample_ago,
                    s.score,
                    s.lo_limit,
                    s.hi_limit
                );
            } else {
                println!(
                    "{} {name:<25} {} {}- {}- {:>4} {:>5.1} {:>7} {:>7}  {}",
                    s.state,
                    if s.authentication { 'Y' } else { 'N' },
                    conf.iter().collect::<String>(),
                    eff.iter().collect::<String>(),
                    interval(s.last_sample_ago),
                    s.score,
                    scaled(s.lo_limit, true),
                    scaled(s.hi_limit, true),
                    match leap {
                        LeapStatus::Normal => "N",
                        LeapStatus::InsertSecond => "+",
                        LeapStatus::DeleteSecond => "-",
                        _ => "?",
                    }
                );
            }
        }
    }

    fn activity(&self, a: &Activity) {
        if self.csv {
            println!(
                "{},{},{},{},{}",
                a.online, a.offline, a.burst_online, a.burst_offline, a.unresolved
            );
            return;
        }
        println!("200 OK");
        println!("{} sources online", a.online);
        println!("{} sources offline", a.offline);
        println!("{} sources doing burst (return to online)", a.burst_online);
        println!(
            "{} sources doing burst (return to offline)",
            a.burst_offline
        );
        println!("{} sources with unknown address", a.unresolved);
    }

    fn server_stats(&self, s: &ServerStats) {
        let rows = [
            ("NTP packets received", s.ntp_hits),
            ("NTP packets dropped", s.ntp_drops),
            ("Command packets received", s.cmd_hits),
            ("Command packets dropped", s.cmd_drops),
            ("Client log records dropped", s.log_drops),
            ("NTS-KE connections accepted", s.nke_hits),
            ("NTS-KE connections dropped", s.nke_drops),
            ("Authenticated NTP packets", s.ntp_auth_hits),
            ("Interleaved NTP packets", s.ntp_interleaved_hits),
            ("NTP timestamps held", s.ntp_timestamps),
            ("NTP timestamp span", s.ntp_span_seconds),
            ("NTP daemon RX timestamps", s.ntp_daemon_rx_timestamps),
            ("NTP daemon TX timestamps", s.ntp_daemon_tx_timestamps),
            ("NTP kernel RX timestamps", s.ntp_kernel_rx_timestamps),
            ("NTP kernel TX timestamps", s.ntp_kernel_tx_timestamps),
            ("NTP hardware RX timestamps", s.ntp_hw_rx_timestamps),
            ("NTP hardware TX timestamps", s.ntp_hw_tx_timestamps),
        ];
        if self.csv {
            let csv: Vec<String> = rows.iter().map(|(_, value)| value.to_string()).collect();
            println!("{}", csv.join(","));
            return;
        }
        for (label, value) in rows {
            println!("{label:<27}: {value}");
        }
    }

    fn smoothing(&self, s: &Smoothing) {
        if self.csv {
            println!(
                "{},{},{:.9},{:.6},{:.6},{:.1},{:.1}",
                yes_no(s.active),
                yes_no(s.leap_only),
                s.offset,
                s.freq_ppm,
                s.wander_ppm,
                s.last_update_ago,
                s.remaining_time
            );
            return;
        }
        println!(
            "Active         : {}{}",
            yes_no(s.active),
            if s.leap_only {
                " (leap second only)"
            } else {
                ""
            }
        );
        println!("Offset         : {:+.9} seconds", s.offset);
        println!("Frequency      : {:+.6} ppm", s.freq_ppm);
        println!("Wander         : {:+.6} ppm per second", s.wander_ppm);
        println!("Last update    : {:.1} seconds ago", s.last_update_ago);
        println!("Remaining time : {:.1} seconds", s.remaining_time);
    }

    fn rtc(&self, r: &Rtc) {
        if self.csv {
            println!(
                "{:.9},{},{},{},{:.9},{:.6}",
                epoch(r.ref_time),
                r.n_samples,
                r.n_runs,
                r.span_seconds,
                r.rtc_seconds_fast,
                r.rtc_gain_rate_ppm
            );
            return;
        }
        println!("RTC ref time (UTC) : {}", date(r.ref_time));
        println!("Number of samples  : {}", r.n_samples);
        println!("Number of runs     : {}", r.n_runs);
        println!("Sample span period : {}", interval(r.span_seconds));
        println!("RTC is fast by     : {:12.6} seconds", r.rtc_seconds_fast);
        println!("RTC gains time at  : {:9.3} ppm", r.rtc_gain_rate_ppm);
    }

    fn manual_list(&self, samples: &[ManualSample]) {
        if !self.csv {
            println!("210 n_samples = {}", samples.len());
            println!("#    Date     Time(UTC)    Slewed   Original   Residual");
            println!("=======================================================");
        }
        for (i, s) in samples.iter().enumerate() {
            if self.csv {
                println!(
                    "{i},{:.9},{:.2},{:.2},{:.2}",
                    epoch(s.when),
                    s.slewed_offset,
                    s.orig_offset,
                    s.residual
                );
            } else {
                println!(
                    "{i:2} {} {:10.2} {:10.2} {:10.2}",
                    date(s.when),
                    s.slewed_offset,
                    s.orig_offset,
                    s.residual
                );
            }
        }
    }

    fn clients(&self, clients: &[ClientAccess]) {
        if !self.csv {
            println!(
                "Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last"
            );
            println!(
                "==============================================================================="
            );
        }
        for c in clients {
            if self.csv {
                println!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    c.address,
                    c.ntp_hits,
                    c.ntp_drops,
                    c.ntp_interval,
                    c.ntp_timeout_interval,
                    c.last_ntp_hit_ago,
                    c.cmd_hits,
                    c.cmd_drops,
                    c.cmd_interval,
                    c.last_cmd_hit_ago,
                    c.nke_hits,
                    c.nke_drops,
                    c.nke_interval,
                    c.last_nke_hit_ago
                );
            } else {
                println!(
                    "{:<25} {:>7} {:>6} {:>3} {:>4} {:>4} {:>7} {:>6} {:>3} {:>5}",
                    c.address.to_string(),
                    c.ntp_hits,
                    c.ntp_drops,
                    c.ntp_interval,
                    c.ntp_timeout_interval,
                    interval(c.last_ntp_hit_ago),
                    c.cmd_hits,
                    c.cmd_drops,
                    c.cmd_interval,
                    interval(c.last_cmd_hit_ago)
                );
            }
        }
    }

    fn ntp_data(&self, d: &NtpData) {
        let mode = match d.mode {
            1 => "Symmetric active",
            2 => "Symmetric passive",
            3 => "Client",
            4 => "Server",
            5 => "Broadcast",
            _ => "Invalid",
        };
        let leap = LeapStatus::from(u16::from(d.leap));
        let timestamping = |c: char| match c {
            'D' => "Daemon",
            'K' => "Kernel",
            'H' => "Hardware",
            _ => "Invalid",
        };
        let ip_ref_id = |a: &Address| match a {
            Address::Ip(IpAddr::V4(v4)) => format!("{:08X}", u32::from(*v4)),
            _ => "00000000".to_string(),
        };
        let reference = if d.stratum <= 1 {
            ref_id_name(d.ref_id)
        } else {
            String::new()
        };
        let tests = d.tests();
        let (a, b, c) = (tests >> 7, (tests >> 4) & 0x7, tests & 0xf);
        if self.csv {
            println!(
                "{},{},{},{},{},{leap},{},{mode},{},{},{:.0},{},{:.9},{:.6},{:.6},{:08X},{reference},{:.9},{:.9},{:.9},{:.9},{:.9},{:.2},{a:03b},{b:03b},{c:04b},{},{},{},{},{},{},{},{},{},{},{},{}",
                d.remote_address,
                ip_ref_id(&d.remote_address),
                d.remote_port,
                d.local_address,
                ip_ref_id(&d.local_address),
                d.version,
                d.stratum,
                d.poll,
                2f64.powi(d.poll.into()),
                d.precision,
                2f64.powi(d.precision.into()),
                d.root_delay,
                d.root_dispersion,
                d.ref_id,
                epoch(d.ref_time),
                d.offset,
                d.peer_delay,
                d.peer_dispersion,
                d.response_time,
                d.jitter_asymmetry,
                yes_no(d.interleaved()),
                yes_no(d.authenticated()),
                timestamping(d.tx_timestamping),
                timestamping(d.rx_timestamping),
                d.total_tx_count,
                d.total_rx_count,
                d.total_valid_count,
                d.total_good_count,
                d.total_kernel_tx_ts,
                d.total_kernel_rx_ts,
                d.total_hw_tx_ts,
                d.total_hw_rx_ts
            );
            return;
        }
        println!();
        println!(
            "Remote address  : {} ({})",
            d.remote_address,
            ip_ref_id(&d.remote_address)
        );
        println!("Remote port     : {}", d.remote_port);
        println!(
            "Local address   : {} ({})",
            d.local_address,
            ip_ref_id(&d.local_address)
        );
        println!("Leap status     : {leap}");
        println!("Version         : {}", d.version);
        println!("Mode            : {mode}");
        println!("Stratum         : {}", d.stratum);
        println!(
            "Poll interval   : {} ({:.0} seconds)",
            d.poll,
            2f64.powi(d.poll.into())
        );
        println!(
            "Precision       : {} ({:.9} seconds)",
            d.precision,
            2f64.powi(d.precision.into())
        );
        println!("Root delay      : {:.6} seconds", d.root_delay);
        println!("Root dispersion : {:.6} seconds", d.root_dispersion);
        println!("Reference ID    : {:08X} ({reference})", d.ref_id);
        println!("Reference time  : {}", date(d.ref_time));
        println!("Offset          : {:+.9} seconds", d.offset);
        println!("Peer delay      : {:.9} seconds", d.peer_delay);
        println!("Peer dispersion : {:.9} seconds", d.peer_dispersion);
        println!("Response time   : {:.9} seconds", d.response_time);
        println!("Jitter asymmetry: {:+.2}", d.jitter_asymmetry);
        println!("NTP tests       : {a:03b} {b:03b} {c:04b}");
        println!("Interleaved     : {}", yes_no(d.interleaved()));
        println!("Authenticated   : {}", yes_no(d.authenticated()));
        println!("TX timestamping : {}", timestamping(d.tx_timestamping));
        println!("RX timestamping : {}", timestamping(d.rx_timestamping));
        println!("Total TX        : {}", d.total_tx_count);
        println!("Total RX        : {}", d.total_rx_count);
        println!("Total valid RX  : {}", d.total_valid_count);
        println!("Total good RX   : {}", d.total_good_count);
        println!("Total kernel TX : {}", d.total_kernel_tx_ts);
        println!("Total kernel RX : {}", d.total_kernel_rx_ts);
        println!("Total HW TX     : {}", d.total_hw_tx_ts);
        println!("Total HW RX     : {}", d.total_hw_rx_ts);
    }

    fn auth_data(&self, rows: &[(Address, AuthData)]) {
        let mode = |m: AuthMode| match m {
            AuthMode::None => "-",
            AuthMode::Symmetric => "SK",
            AuthMode::Nts => "NTS",
            AuthMode::Other(_) => "?",
        };
        if !self.csv {
            println!("Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen");
            println!("=========================================================================");
        }
        for (address, a) in rows {
            if self.csv {
                println!(
                    "{address},{},{},{},{},{},{},{},{},{}",
                    mode(a.mode),
                    a.key_id,
                    a.key_type,
                    a.key_length,
                    a.last_ke_ago,
                    a.ke_attempts,
                    u8::from(a.nak),
                    a.cookies,
                    a.cookie_length
                );
            } else {
                println!(
                    "{:<27} {:>4} {:>5} {:>4} {:>4} {:>4} {:>4} {:>4} {:>4} {:>4}",
                    address.to_string(),
                    mode(a.mode),
                    a.key_id,
                    a.key_type,
                    a.key_length,
                    interval(a.last_ke_ago),
                    a.ke_attempts,
                    u8::from(a.nak),
                    a.cookies,
                    a.cookie_length
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(UNIX_EPOCH), "Thu Jan  1 00:00:00 1970");
        let t = UNIX_EPOCH + Duration::from_secs(1_795_673_700);
        assert_eq!(date(t), "Thu Nov 26 06:15:00 2026");
        assert_eq!(parse_time("2026-11-26T06:15:00Z").unwrap(), t);
        assert_eq!(parse_time("1795673700").unwrap(), t);
        assert!(parse_time("yesterday").is_err());
    }

    #[test]
    fn scaled_offsets_and_intervals() {
        assert_eq!(scaled(1.039e-6, true), "+1039ns");
        assert_eq!(scaled(-0.025, true), "-25ms");
        assert_eq!(scaled(0.0123, false), "12ms");
        assert_eq!(interval(64), "64");
        assert_eq!(interval(3600), "60m");
        assert_eq!(interval(u32::MAX), "-");
    }

    #[test]
    fn subnets_and_selections() {
        assert_eq!(subnet(None).unwrap(), Subnet::ANY);
        let s = subnet(Some(&"10.0.0.0/8")).unwrap();
        assert_eq!((s.ip.unwrap().to_string(), s.bits), ("10.0.0.0".into(), 8));
        let SourceSelection::Matching { mask, .. } = selection(Some(&"192.168.1.0/24")).unwrap()
        else {
            panic!("a selection");
        };
        assert_eq!(mask.to_string(), "255.255.255.0");
        assert!(subnet(Some(&"nonsense")).is_err());
    }

    #[test]
    fn add_options() {
        let source = ntp_source(
            "pool",
            "pool.ntp.org",
            &["iburst", "maxsources", "3", "offline"],
        )
        .unwrap();
        assert_eq!(source.kind, SourceKind::Pool);
        assert_eq!(source.max_sources, 3);
        assert!(source.flags.contains(SourceFlags::IBURST));
        assert!(!source.flags.contains(SourceFlags::ONLINE));
        assert!(ntp_source("server", "x", &["bogus"]).is_err());
        assert!(ntp_source("server", "x", &["port"]).is_err());
    }
}
