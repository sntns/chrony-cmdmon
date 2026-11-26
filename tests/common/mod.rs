//! What the tests share: the request this crate sends for each chronyc
//! command line, and hex helpers.
#![allow(dead_code)]

use std::net::IpAddr;
use std::time::Duration;
use std::time::SystemTime;

use chrony_cmdmon::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn address(s: &str) -> Address {
    Address::Ip(ip(s))
}

fn subnet(s: &str, bits: u8) -> Subnet {
    Subnet {
        ip: Some(ip(s)),
        bits,
    }
}

/// The request this crate sends for a chronyc command line.
pub fn request(command: &str) -> Request {
    let host = address("192.0.2.1");
    let lan = SourceSelection::Matching {
        address: ip("192.168.1.0"),
        mask: ip("255.255.255.0"),
    };
    match command {
        "tracking" => Request::Tracking,
        // chronyc counts the sources first.
        "sources" | "sourcestats" | "selectdata" | "authdata" => Request::NSources,
        "activity" => Request::Activity,
        "smoothing" => Request::Smoothing,
        "rtcdata" => Request::RtcReport,
        "serverstats" => Request::ServerStats,
        "manual list" => Request::ManualList,
        "clients" => Request::ClientAccesses {
            first_index: 0,
            n_clients: 8,
            min_hits: 0,
            reset: false,
        },
        "ntpdata 192.0.2.1" => Request::NtpData(host),
        "sourcename 192.0.2.1" => Request::NtpSourceName(host),
        "online" => Request::Online(SourceSelection::All),
        "offline" => Request::Offline(SourceSelection::All),
        "online 192.168.1.0/24" => Request::Online(lan),
        "burst 4/4" => Request::Burst {
            selection: SourceSelection::All,
            n_good: 4,
            n_total: 4,
        },
        "burst 2/10 192.168.1.0/24" => Request::Burst {
            selection: lan,
            n_good: 2,
            n_total: 10,
        },
        "minpoll 192.0.2.1 5" => Request::ModifyMinpoll {
            address: host,
            minpoll: 5,
        },
        "maxpoll 192.0.2.1 9" => Request::ModifyMaxpoll {
            address: host,
            maxpoll: 9,
        },
        "dump" => Request::Dump,
        "maxdelay 192.0.2.1 0.5" => Request::ModifyMaxdelay {
            address: host,
            max_delay: 0.5,
        },
        "maxdelayratio 192.0.2.1 2.5" => Request::ModifyMaxdelayratio {
            address: host,
            ratio: 2.5,
        },
        "maxdelaydevratio 192.0.2.1 3" => Request::ModifyMaxdelaydevratio {
            address: host,
            ratio: 3.0,
        },
        "minstratum 192.0.2.1 2" => Request::ModifyMinstratum {
            address: host,
            min_stratum: 2,
        },
        "polltarget 192.0.2.1 6" => Request::ModifyPolltarget {
            address: host,
            poll_target: 6,
        },
        "maxupdateskew 100" => Request::ModifyMaxupdateskew { skew_ppm: 100.0 },
        "makestep 0.1 3" => Request::ModifyMakestep {
            limit: 3,
            threshold: 0.1,
        },
        "makestep" => Request::MakeStep,
        "local stratum 8 orphan distance 0.5 activate 0.1 waitsynced 30 waitunsynced 60" => {
            Request::Local(LocalOptions {
                enabled: true,
                stratum: 8,
                distance: 0.5,
                orphan: true,
                activate: 0.1,
                wait_synced: 30.0,
                wait_unsynced: 60.0,
            })
        }
        "local off" => Request::Local(LocalOptions::off()),
        "manual on" => Request::Manual(ManualOption::On),
        "manual off" => Request::Manual(ManualOption::Off),
        "manual reset" => Request::Manual(ManualOption::Reset),
        "manual delete 2" => Request::ManualDelete { index: 2 },
        // 2030-01-02 03:04:05 in the capturing player's zone (CET).
        "settime 2030-01-02 03:04:05" => {
            Request::Settime(SystemTime::UNIX_EPOCH + Duration::from_secs(0x70dd_4715))
        }
        "rekey" => Request::Rekey,
        "allow 10.0.0.0/8" => Request::Allow(subnet("10.0.0.0", 8)),
        "allow all 10.0.0.0/8" => Request::AllowAll(subnet("10.0.0.0", 8)),
        "allow" => Request::Allow(Subnet::ANY),
        "deny 192.168.0.1" => Request::Deny(subnet("192.168.0.1", 32)),
        "deny all 2001:db8::/32" => Request::DenyAll(subnet("2001:db8::", 32)),
        "cmdallow 10.1.0.0/16" => Request::CmdAllow(subnet("10.1.0.0", 16)),
        "cmdallow all" => Request::CmdAllowAll(Subnet::ANY),
        "cmddeny 10.2.0.0/16" => Request::CmdDeny(subnet("10.2.0.0", 16)),
        "cmddeny all 10.3.0.0/16" => Request::CmdDenyAll(subnet("10.3.0.0", 16)),
        "accheck 192.0.2.1" => Request::AcCheck(ip("192.0.2.1")),
        "cmdaccheck 2001:db8::1" => Request::CmdAcCheck(ip("2001:db8::1")),
        "add server 192.0.2.1 iburst prefer minpoll 4 maxpoll 8" => {
            Request::AddSource(Box::new(NtpSource {
                minpoll: 4,
                maxpoll: 8,
                flags: SourceFlags::ONLINE | SourceFlags::IBURST | SourceFlags::PREFER,
                ..NtpSource::server("192.0.2.1")
            }))
        }
        "add peer 192.0.2.2 key 7 offset 0.25 maxdelay 0.1" => {
            Request::AddSource(Box::new(NtpSource {
                authkey: 7,
                offset: 0.25,
                max_delay: 0.1,
                ..NtpSource::peer("192.0.2.2")
            }))
        }
        "add pool 192.0.2.11 maxsources 3 nts" => Request::AddSource(Box::new(NtpSource {
            max_sources: 3,
            flags: SourceFlags::ONLINE | SourceFlags::NTS,
            ..NtpSource::pool("192.0.2.11")
        })),
        "add server 192.0.2.10 nts certset 1 port 1123 ntsport 4461" => {
            Request::AddSource(Box::new(NtpSource {
                port: 1123,
                nts_port: 4461,
                cert_set: 1,
                flags: SourceFlags::ONLINE | SourceFlags::NTS,
                ..NtpSource::server("192.0.2.10")
            }))
        }
        "delete 192.0.2.1" => Request::DelSource(host),
        "writertc" => Request::WriteRtc,
        "dfreq 1.5" => Request::Dfreq(1.5),
        "doffset -0.25" => Request::Doffset(-0.25),
        "trimrtc" => Request::TrimRtc,
        "cyclelogs" => Request::CycleLogs,
        "reselect" => Request::Reselect,
        "reselectdist 0.002" => Request::ReselectDistance(0.002),
        "smoothtime reset" => Request::SmoothTime(SmoothTimeOption::Reset),
        "smoothtime activate" => Request::SmoothTime(SmoothTimeOption::Activate),
        "refresh" => Request::Refresh,
        "shutdown" => Request::Shutdown,
        "onoffline" => Request::OnOffline,
        "reset sources" => Request::ResetSources,
        "reload sources" => Request::ReloadSources,
        "selectopts 192.0.2.1 +prefer -noselect +trust" => Request::ModifySelectOpts {
            address: host,
            ref_id: 0,
            mask: SelectOptions::PREFER | SelectOptions::NOSELECT | SelectOptions::TRUST,
            options: SelectOptions::PREFER | SelectOptions::TRUST,
        },
        "offset 192.0.2.1 0.01" => Request::ModifyOffset {
            address: host,
            ref_id: 0,
            offset: 0.01,
        },
        other => panic!("no request for the chronyc command `{other}`"),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// Where the packets of two encoders first differ, for a failure message.
/// Ours may be longer by zeros: padding to the reply of a newer chronyd,
/// which an older one accepts.
pub fn difference(ours: &[u8], theirs: &[u8]) -> Option<String> {
    if ours.len() >= theirs.len()
        && ours[..theirs.len()] == *theirs
        && ours[theirs.len()..].iter().all(|b| *b == 0)
    {
        return None;
    }
    let first = ours
        .iter()
        .zip(theirs)
        .position(|(a, b)| a != b)
        .unwrap_or(ours.len().min(theirs.len()));
    let window = |p: &[u8]| hex(&p[first.saturating_sub(4)..(first + 24).min(p.len())]);
    Some(format!(
        "{} bytes against {}, first difference at {first}\n  ours    {}\n  theirs  {}",
        ours.len(),
        theirs.len(),
        window(ours),
        window(theirs)
    ))
}

/// The chronyc command lines the interoperability tests cover.
pub fn commands() -> Vec<&'static str> {
    include_str!("../fixtures/chronyc-requests.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split_once('\t').unwrap().0)
        .collect()
}

/// A chronyc version, e.g. `(4, 8)` (a micro release counts as its minor).
pub type Version = (u32, u32);

/// The version of `chronyc --version`'s output.
pub fn parse_version(output: &str) -> Version {
    let version = output
        .split_whitespace()
        .skip_while(|word| *word != "version")
        .nth(1)
        .expect("a chronyc version");
    let mut numbers = version.split('.').map(|n| n.parse().unwrap());
    (numbers.next().unwrap(), numbers.next().unwrap())
}

/// `request` encoded in the form chronyc used for `theirs` (the current one
/// or the older), as chronyc `version` fills it: the fields that version
/// does not know yet are sent as zeros. `None` if chronyc used another
/// command.
pub fn encode_like(
    request: &chrony_cmdmon::Request,
    theirs: &[u8],
    version: Version,
) -> Option<Vec<u8>> {
    use chrony_cmdmon::*;
    let code = u16::from_be_bytes([theirs[4], theirs[5]]);
    let sequence = u32::from_be_bytes(theirs[8..12].try_into().unwrap());
    let attempt = u16::from_be_bytes(theirs[6..8].try_into().unwrap());
    let mut request = request.clone();
    match &mut request {
        Request::AddSource(source) => {
            if version < (4, 1) {
                source.cert_set = 0;
            }
            if version < (4, 3) {
                source.max_delay_quant = 0.0;
            }
            if version < (4, 8) {
                source.max_unreach = 0;
            }
        }
        // 4.6 reserved the room of the waits 4.7 added.
        Request::Local(local) if version < (4, 7) => {
            local.wait_synced = 0.0;
            local.wait_unsynced = 0.0;
        }
        _ => {}
    }
    if code == request.code() {
        Some(request.encode(sequence, attempt).unwrap())
    } else if Some(code) == request.legacy_code() {
        Some(request.encode_legacy(sequence, attempt).unwrap().unwrap())
    } else {
        None
    }
}
