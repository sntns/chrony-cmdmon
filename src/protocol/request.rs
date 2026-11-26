//! Requests: every command chronyd 4.x accepts.
//!
//! Commands of earlier protocol versions that chronyd now refuses (`LOGON`,
//! `LOCAL` and `LOCAL2`, `ADD_SERVER*` and `ADD_PEER*`, `DOFFSET`,
//! `SUBNETS_ACCESSED`, `CLIENT_ACCESSES` and `CLIENT_ACCESSES_BY_INDEX*`
//! before the third) are left out: their successors are here.

use std::net::IpAddr;
use std::time::SystemTime;

use super::wire::Writer;
use super::wire::IP_ADDR_LEN;
use super::Address;
use super::ReplyKind;
use super::SelectOptions;
use crate::Error;

/// Which sources a command applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSelection {
    /// Every source.
    All,
    /// The sources whose address matches `address` under `mask`
    /// (`chronyc burst 4/4 192.168.1.0/24`).
    Matching {
        /// The address to match.
        address: IpAddr,
        /// The mask applied to both addresses.
        mask: IpAddr,
    },
}

/// A subnet for the access commands (`allow`, `deny`, ...): `ip` `None`
/// with 0 bits is every address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    /// The network address; `None` for any family.
    pub ip: Option<IpAddr>,
    /// The prefix length.
    pub bits: u8,
}

impl Subnet {
    /// Every address.
    pub const ANY: Subnet = Subnet { ip: None, bits: 0 };

    /// `ip` alone (/32 or /128).
    pub fn host(ip: IpAddr) -> Subnet {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        Subnet { ip: Some(ip), bits }
    }
}

/// Source selection options, and the flags of a source added
/// ([`NtpSource::flags`]): a bit set. The values are those of `ADD_SOURCE`
/// (chronyd 4.0 to 4.8), translated for `ADD_SOURCE2` (4.9 and later),
/// which renumbered some.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SourceFlags(pub u32);

impl SourceFlags {
    /// Online (not `offline`).
    pub const ONLINE: SourceFlags = SourceFlags(0x1);
    /// `auto_offline`.
    pub const AUTO_OFFLINE: SourceFlags = SourceFlags(0x2);
    /// `iburst`.
    pub const IBURST: SourceFlags = SourceFlags(0x4);
    /// `prefer`.
    pub const PREFER: SourceFlags = SourceFlags(0x8);
    /// `noselect`.
    pub const NOSELECT: SourceFlags = SourceFlags(0x10);
    /// `trust`.
    pub const TRUST: SourceFlags = SourceFlags(0x20);
    /// `require`.
    pub const REQUIRE: SourceFlags = SourceFlags(0x40);
    /// `xleave`.
    pub const INTERLEAVED: SourceFlags = SourceFlags(0x80);
    /// `burst`.
    pub const BURST: SourceFlags = SourceFlags(0x100);
    /// `nts`.
    pub const NTS: SourceFlags = SourceFlags(0x200);
    /// `copy`.
    pub const COPY: SourceFlags = SourceFlags(0x400);
    /// The experimental monotonic root extension field.
    pub const EF_EXP_MONO_ROOT: SourceFlags = SourceFlags(0x800);
    /// The network correction extension field (experimental before chronyd
    /// 4.9).
    pub const EF_NET_CORRECTION: SourceFlags = SourceFlags(0x1000);
    /// IPv4 addresses only (a name resolving to both).
    pub const IPV4: SourceFlags = SourceFlags(0x2000);
    /// IPv6 addresses only.
    pub const IPV6: SourceFlags = SourceFlags(0x4000);

    /// Whether every flag of `other` is set.
    pub fn contains(self, other: SourceFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// As `ADD_SOURCE2` numbers them: IPv4 and IPv6 moved down, the
    /// extension fields up.
    fn for_add_source2(self) -> u32 {
        let moved = [
            (SourceFlags::IPV4, 0x800),
            (SourceFlags::IPV6, 0x1000),
            (SourceFlags::EF_NET_CORRECTION, 0x1_0000),
            (SourceFlags::EF_EXP_MONO_ROOT, 0x8000_0000),
        ];
        let mut flags = self.0 & 0x7ff;
        for (flag, value) in moved {
            if self.contains(flag) {
                flags |= value;
            }
        }
        flags
    }
}

impl std::ops::BitOr for SourceFlags {
    type Output = SourceFlags;
    fn bitor(self, other: SourceFlags) -> SourceFlags {
        SourceFlags(self.0 | other.0)
    }
}

impl std::ops::BitOrAssign for SourceFlags {
    fn bitor_assign(&mut self, other: SourceFlags) {
        self.0 |= other.0;
    }
}

/// What a source added is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// `server`.
    Server,
    /// `peer`.
    Peer,
    /// `pool`.
    Pool,
}

/// A source to add (`chronyc add server|peer|pool`); its [`Default`] is
/// chronyd's defaults, online, with no name.
#[derive(Debug, Clone, PartialEq)]
pub struct NtpSource {
    /// Server, peer or pool.
    pub kind: SourceKind,
    /// A host name or an address: at most 255 bytes, no NUL.
    pub name: String,
    /// NTP port.
    pub port: u32,
    /// `minpoll` (power of 2 seconds).
    pub minpoll: i32,
    /// `maxpoll` (power of 2 seconds).
    pub maxpoll: i32,
    /// `presend` (power of 2 seconds).
    pub presend_minpoll: i32,
    /// `minstratum`.
    pub min_stratum: u32,
    /// `polltarget`.
    pub poll_target: u32,
    /// NTP version, 0 for chronyd's choice.
    pub version: u32,
    /// For a pool.
    pub max_sources: u32,
    /// -1 for chronyd's default.
    pub min_samples: i32,
    /// -1 for chronyd's default.
    pub max_samples: i32,
    /// 0 for none.
    pub authkey: u32,
    /// `ntsport`.
    pub nts_port: u32,
    /// `maxdelay` (seconds).
    pub max_delay: f64,
    /// `maxdelayratio`.
    pub max_delay_ratio: f64,
    /// `maxdelaydevratio`.
    pub max_delay_dev_ratio: f64,
    /// `mindelay` (seconds).
    pub min_delay: f64,
    /// `asymmetry`.
    pub asymmetry: f64,
    /// `offset` (seconds).
    pub offset: f64,
    /// The boolean options.
    pub flags: SourceFlags,
    /// 0 for no filter.
    pub filter_length: i32,
    /// `certset`.
    pub cert_set: u32,
    /// `maxdelayquant`.
    pub max_delay_quant: f64,
    /// `maxunreach` (chronyd 4.8 and later).
    pub max_unreach: i32,
    /// How many NTS-KE attempts before the source is replaced (chronyd 4.9
    /// and later; ignored by earlier ones).
    pub max_nts_retry: i32,
}

impl Default for NtpSource {
    fn default() -> Self {
        NtpSource {
            kind: SourceKind::Server,
            name: String::new(),
            port: 123,
            minpoll: 6,
            maxpoll: 10,
            presend_minpoll: 100,
            min_stratum: 0,
            poll_target: 8,
            version: 0,
            max_sources: 4,
            min_samples: -1,
            max_samples: -1,
            authkey: 0,
            nts_port: 4460,
            max_delay: 3.0,
            max_delay_ratio: 0.0,
            max_delay_dev_ratio: 10.0,
            min_delay: 0.0,
            asymmetry: 1.0,
            offset: 0.0,
            flags: SourceFlags::ONLINE,
            filter_length: 0,
            cert_set: 0,
            max_delay_quant: 0.0,
            max_unreach: 100_000,
            max_nts_retry: 19,
        }
    }
}

impl NtpSource {
    /// A server, with chronyd's defaults.
    pub fn server(name: impl Into<String>) -> NtpSource {
        NtpSource {
            name: name.into(),
            ..NtpSource::default()
        }
    }

    /// A pool, with chronyd's defaults.
    pub fn pool(name: impl Into<String>) -> NtpSource {
        NtpSource {
            kind: SourceKind::Pool,
            name: name.into(),
            ..NtpSource::default()
        }
    }

    /// A peer, with chronyd's defaults.
    pub fn peer(name: impl Into<String>) -> NtpSource {
        NtpSource {
            kind: SourceKind::Peer,
            name: name.into(),
            ..NtpSource::default()
        }
    }
}

/// The local reference (`chronyc local`); its [`Default`] is chronyc's:
/// enabled, stratum 10, distance 1 s, no orphan mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LocalOptions {
    /// Whether the local reference is enabled.
    pub enabled: bool,
    /// `stratum`.
    pub stratum: i32,
    /// `distance` (seconds).
    pub distance: f64,
    /// `orphan`.
    pub orphan: bool,
    /// `activate` (seconds).
    pub activate: f64,
    /// `waitsynced` (seconds; chronyd 4.7 and later).
    pub wait_synced: f64,
    /// `waitunsynced` (seconds; chronyd 4.7 and later).
    pub wait_unsynced: f64,
}

impl Default for LocalOptions {
    fn default() -> Self {
        LocalOptions {
            enabled: true,
            stratum: 10,
            distance: 1.0,
            orphan: false,
            activate: 0.0,
            wait_synced: 0.0,
            wait_unsynced: -1.0,
        }
    }
}

impl LocalOptions {
    /// `chronyc local off`: the local reference disabled.
    pub fn off() -> LocalOptions {
        LocalOptions {
            enabled: false,
            stratum: 0,
            distance: 0.0,
            orphan: false,
            activate: 0.0,
            wait_synced: 0.0,
            wait_unsynced: 0.0,
        }
    }
}

/// `chronyc manual on|off|reset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualOption {
    /// `manual off`.
    Off = 0,
    /// `manual on`.
    On = 1,
    /// `manual reset`.
    Reset = 2,
}

/// `chronyc smoothtime reset|activate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmoothTimeOption {
    /// `smoothtime reset`.
    Reset = 0,
    /// `smoothtime activate`.
    Activate = 1,
}

/// A request to chronyd. The `chronyc` command each one is noted; the
/// privileged ones (everything that changes something) are only accepted
/// over the Unix socket.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// `online`
    Online(SourceSelection),
    /// `offline`
    Offline(SourceSelection),
    /// `burst n_good/n_total`
    Burst {
        /// The sources.
        selection: SourceSelection,
        /// Good samples to collect.
        n_good: u32,
        /// At most this many samples.
        n_total: u32,
    },
    /// `minpoll`
    ModifyMinpoll {
        /// The source's address.
        address: Address,
        /// Power of 2 seconds.
        minpoll: i32,
    },
    /// `maxpoll`
    ModifyMaxpoll {
        /// The source's address.
        address: Address,
        /// Power of 2 seconds.
        maxpoll: i32,
    },
    /// `dump`
    Dump,
    /// `maxdelay`
    ModifyMaxdelay {
        /// The source's address.
        address: Address,
        /// Seconds.
        max_delay: f64,
    },
    /// `maxdelayratio`
    ModifyMaxdelayratio {
        /// The source's address.
        address: Address,
        /// The new ratio.
        ratio: f64,
    },
    /// `maxdelaydevratio`
    ModifyMaxdelaydevratio {
        /// The source's address.
        address: Address,
        /// The new ratio.
        ratio: f64,
    },
    /// `minstratum`
    ModifyMinstratum {
        /// The source's address.
        address: Address,
        /// The new minimum stratum.
        min_stratum: i32,
    },
    /// `polltarget`
    ModifyPolltarget {
        /// The source's address.
        address: Address,
        /// The new target.
        poll_target: i32,
    },
    /// `maxupdateskew`
    ModifyMaxupdateskew {
        /// ppm.
        skew_ppm: f64,
    },
    /// `makestep limit threshold`
    ModifyMakestep {
        /// Clock updates it applies to (-1: any).
        limit: i32,
        /// Seconds.
        threshold: f64,
    },
    /// `settime`: a manual time sample.
    Settime(SystemTime),
    /// `local`, `local off`
    Local(LocalOptions),
    /// `manual on|off|reset`
    Manual(ManualOption),
    /// `sources` (how many)
    NSources,
    /// `sources` (one)
    SourceData {
        /// 0 to [`Reply::NSources`](crate::Reply::NSources) - 1.
        index: u32,
    },
    /// `rekey`
    Rekey,
    /// `allow`
    Allow(Subnet),
    /// `allow all`
    AllowAll(Subnet),
    /// `deny`
    Deny(Subnet),
    /// `deny all`
    DenyAll(Subnet),
    /// `cmdallow`
    CmdAllow(Subnet),
    /// `cmdallow all`
    CmdAllowAll(Subnet),
    /// `cmddeny`
    CmdDeny(Subnet),
    /// `cmddeny all`
    CmdDenyAll(Subnet),
    /// `accheck`
    AcCheck(IpAddr),
    /// `cmdaccheck`
    CmdAcCheck(IpAddr),
    /// `add server|peer|pool`
    AddSource(Box<NtpSource>),
    /// `delete`
    DelSource(Address),
    /// `writertc`
    WriteRtc,
    /// `dfreq` (ppm)
    Dfreq(f64),
    /// `doffset` (seconds)
    Doffset(f64),
    /// `tracking`
    Tracking,
    /// `sourcestats` (one)
    Sourcestats {
        /// 0 to [`Reply::NSources`](crate::Reply::NSources) - 1.
        index: u32,
    },
    /// `rtcdata`
    RtcReport,
    /// `trimrtc`
    TrimRtc,
    /// `cyclelogs`
    CycleLogs,
    /// `manual list`
    ManualList,
    /// `manual delete`
    ManualDelete {
        /// The sample's index in `manual list`.
        index: i32,
    },
    /// `makestep`
    MakeStep,
    /// `activity`
    Activity,
    /// `reselect`
    Reselect,
    /// `reselectdist`
    ReselectDistance(f64),
    /// `smoothing`
    Smoothing,
    /// `smoothtime`
    SmoothTime(SmoothTimeOption),
    /// `refresh`
    Refresh,
    /// `serverstats`
    ServerStats,
    /// `ntpdata`
    NtpData(Address),
    /// `shutdown`
    Shutdown,
    /// `onoffline`
    OnOffline,
    /// `sourcename`
    NtpSourceName(Address),
    /// `reset sources`
    ResetSources,
    /// `authdata`
    AuthData(Address),
    /// `clients` (one batch: at most 8 from `first_index`)
    ClientAccesses {
        /// The index of the first client.
        first_index: u32,
        /// How many clients (at most 8).
        n_clients: u32,
        /// Only clients with at least this many hits.
        min_hits: u32,
        /// Reset the counters after reading them.
        reset: bool,
    },
    /// `selectdata` (one)
    SelectData {
        /// 0 to [`Reply::NSources`](crate::Reply::NSources) - 1.
        index: u32,
    },
    /// `reload sources`
    ReloadSources,
    /// `selectopts`: set the options in `mask` to their value in `options`.
    ModifySelectOpts {
        /// The source's address.
        address: Address,
        /// Or its reference ID (reference clocks).
        ref_id: u32,
        /// The options to change.
        mask: SelectOptions,
        /// Their new values.
        options: SelectOptions,
    },
    /// `offset`
    ModifyOffset {
        /// The source's address.
        address: Address,
        /// Or its reference ID (reference clocks).
        ref_id: u32,
        /// The new offset (seconds).
        offset: f64,
    },
}

/// Request codes (`REQ_*`).
pub(crate) mod code {
    pub const ONLINE: u16 = 1;
    pub const OFFLINE: u16 = 2;
    pub const BURST: u16 = 3;
    pub const MODIFY_MINPOLL: u16 = 4;
    pub const MODIFY_MAXPOLL: u16 = 5;
    pub const DUMP: u16 = 6;
    pub const MODIFY_MAXDELAY: u16 = 7;
    pub const MODIFY_MAXDELAYRATIO: u16 = 8;
    pub const MODIFY_MAXUPDATESKEW: u16 = 9;
    pub const SETTIME: u16 = 11;
    pub const MANUAL: u16 = 13;
    pub const N_SOURCES: u16 = 14;
    pub const SOURCE_DATA: u16 = 15;
    pub const REKEY: u16 = 16;
    pub const ALLOW: u16 = 17;
    pub const ALLOWALL: u16 = 18;
    pub const DENY: u16 = 19;
    pub const DENYALL: u16 = 20;
    pub const CMDALLOW: u16 = 21;
    pub const CMDALLOWALL: u16 = 22;
    pub const CMDDENY: u16 = 23;
    pub const CMDDENYALL: u16 = 24;
    pub const ACCHECK: u16 = 25;
    pub const CMDACCHECK: u16 = 26;
    pub const DEL_SOURCE: u16 = 29;
    pub const WRITERTC: u16 = 30;
    pub const DFREQ: u16 = 31;
    pub const TRACKING: u16 = 33;
    pub const SOURCESTATS: u16 = 34;
    pub const RTCREPORT: u16 = 35;
    pub const TRIMRTC: u16 = 36;
    pub const CYCLELOGS: u16 = 37;
    pub const MANUAL_LIST: u16 = 41;
    pub const MANUAL_DELETE: u16 = 42;
    pub const MAKESTEP: u16 = 43;
    pub const ACTIVITY: u16 = 44;
    pub const MODIFY_MINSTRATUM: u16 = 45;
    pub const MODIFY_POLLTARGET: u16 = 46;
    pub const MODIFY_MAXDELAYDEVRATIO: u16 = 47;
    pub const RESELECT: u16 = 48;
    pub const RESELECTDISTANCE: u16 = 49;
    pub const MODIFY_MAKESTEP: u16 = 50;
    pub const SMOOTHING: u16 = 51;
    pub const SMOOTHTIME: u16 = 52;
    pub const REFRESH: u16 = 53;
    pub const SERVER_STATS: u16 = 54;
    pub const NTP_DATA: u16 = 57;
    pub const SHUTDOWN: u16 = 62;
    pub const ONOFFLINE: u16 = 63;
    pub const ADD_SOURCE: u16 = 64;
    pub const ADD_SOURCE2: u16 = 75;
    /// Older forms: `DOFFSET` before 4.1, `LOCAL2` before 4.6.
    pub const DOFFSET: u16 = 32;
    pub const LOCAL2: u16 = 56;
    pub const NTP_SOURCE_NAME: u16 = 65;
    pub const RESET_SOURCES: u16 = 66;
    pub const AUTH_DATA: u16 = 67;
    pub const CLIENT_ACCESSES_BY_INDEX3: u16 = 68;
    pub const SELECT_DATA: u16 = 69;
    pub const RELOAD_SOURCES: u16 = 70;
    pub const DOFFSET2: u16 = 71;
    pub const MODIFY_SELECTOPTS: u16 = 72;
    pub const MODIFY_OFFSET: u16 = 73;
    pub const LOCAL3: u16 = 74;
}

const PKT_TYPE_REQUEST: u8 = 1;
/// The request header: version, type, two reserved bytes, command,
/// attempt, sequence and two padding words.
pub(crate) const HEADER_LEN: usize = 20;
/// The longest a source name may be, its NUL included.
const NAME_LEN: usize = 256;

impl Request {
    /// The request code (`REQ_*`).
    pub fn code(&self) -> u16 {
        use Request::*;
        match self {
            Online(_) => code::ONLINE,
            Offline(_) => code::OFFLINE,
            Burst { .. } => code::BURST,
            ModifyMinpoll { .. } => code::MODIFY_MINPOLL,
            ModifyMaxpoll { .. } => code::MODIFY_MAXPOLL,
            Dump => code::DUMP,
            ModifyMaxdelay { .. } => code::MODIFY_MAXDELAY,
            ModifyMaxdelayratio { .. } => code::MODIFY_MAXDELAYRATIO,
            ModifyMaxdelaydevratio { .. } => code::MODIFY_MAXDELAYDEVRATIO,
            ModifyMinstratum { .. } => code::MODIFY_MINSTRATUM,
            ModifyPolltarget { .. } => code::MODIFY_POLLTARGET,
            ModifyMaxupdateskew { .. } => code::MODIFY_MAXUPDATESKEW,
            ModifyMakestep { .. } => code::MODIFY_MAKESTEP,
            Settime(_) => code::SETTIME,
            Local(_) => code::LOCAL3,
            Manual(_) => code::MANUAL,
            NSources => code::N_SOURCES,
            SourceData { .. } => code::SOURCE_DATA,
            Rekey => code::REKEY,
            Allow(_) => code::ALLOW,
            AllowAll(_) => code::ALLOWALL,
            Deny(_) => code::DENY,
            DenyAll(_) => code::DENYALL,
            CmdAllow(_) => code::CMDALLOW,
            CmdAllowAll(_) => code::CMDALLOWALL,
            CmdDeny(_) => code::CMDDENY,
            CmdDenyAll(_) => code::CMDDENYALL,
            AcCheck(_) => code::ACCHECK,
            CmdAcCheck(_) => code::CMDACCHECK,
            AddSource(_) => code::ADD_SOURCE2,
            DelSource(_) => code::DEL_SOURCE,
            WriteRtc => code::WRITERTC,
            Dfreq(_) => code::DFREQ,
            Doffset(_) => code::DOFFSET2,
            Tracking => code::TRACKING,
            Sourcestats { .. } => code::SOURCESTATS,
            RtcReport => code::RTCREPORT,
            TrimRtc => code::TRIMRTC,
            CycleLogs => code::CYCLELOGS,
            ManualList => code::MANUAL_LIST,
            ManualDelete { .. } => code::MANUAL_DELETE,
            MakeStep => code::MAKESTEP,
            Activity => code::ACTIVITY,
            Reselect => code::RESELECT,
            ReselectDistance(_) => code::RESELECTDISTANCE,
            Smoothing => code::SMOOTHING,
            SmoothTime(_) => code::SMOOTHTIME,
            Refresh => code::REFRESH,
            ServerStats => code::SERVER_STATS,
            NtpData(_) => code::NTP_DATA,
            Shutdown => code::SHUTDOWN,
            OnOffline => code::ONOFFLINE,
            NtpSourceName(_) => code::NTP_SOURCE_NAME,
            ResetSources => code::RESET_SOURCES,
            AuthData(_) => code::AUTH_DATA,
            ClientAccesses { .. } => code::CLIENT_ACCESSES_BY_INDEX3,
            SelectData { .. } => code::SELECT_DATA,
            ReloadSources => code::RELOAD_SOURCES,
            ModifySelectOpts { .. } => code::MODIFY_SELECTOPTS,
            ModifyOffset { .. } => code::MODIFY_OFFSET,
        }
    }

    /// The kinds of reply chronyd answers it with: the current one first,
    /// then those of older chronyd versions still decoded.
    pub fn reply_kinds(&self) -> &'static [ReplyKind] {
        match self {
            Request::ServerStats => &[
                ReplyKind::ServerStats,
                ReplyKind::ServerStats3,
                ReplyKind::ServerStats2,
            ],
            Request::NtpData(_) => &[ReplyKind::NtpData, ReplyKind::NtpDataV1],
            _ => {
                let kind = self.reply_kind();
                let at = ReplyKind::ALL.iter().position(|k| *k == kind).unwrap_or(0);
                std::slice::from_ref(&ReplyKind::ALL[at])
            }
        }
    }

    /// The (current) reply chronyd answers it with.
    pub fn reply_kind(&self) -> ReplyKind {
        use Request::*;
        match self {
            Settime(_) => ReplyKind::ManualTimestamp,
            NSources => ReplyKind::NSources,
            SourceData { .. } => ReplyKind::SourceData,
            Tracking => ReplyKind::Tracking,
            Sourcestats { .. } => ReplyKind::Sourcestats,
            RtcReport => ReplyKind::Rtc,
            ManualList => ReplyKind::ManualList,
            Activity => ReplyKind::Activity,
            Smoothing => ReplyKind::Smoothing,
            ServerStats => ReplyKind::ServerStats,
            NtpData(_) => ReplyKind::NtpData,
            NtpSourceName(_) => ReplyKind::NtpSourceName,
            AuthData(_) => ReplyKind::AuthData,
            ClientAccesses { .. } => ReplyKind::ClientAccesses,
            SelectData { .. } => ReplyKind::SelectData,
            _ => ReplyKind::Null,
        }
    }

    fn data(&self) -> Result<Vec<u8>, Error> {
        use Request::*;
        let mut w = Writer::default();
        match self {
            Online(selection) | Offline(selection) => {
                selection_record(&mut w, selection);
            }
            Burst {
                selection,
                n_good,
                n_total,
            } => {
                selection_record(&mut w, selection);
                w.u32(*n_good).u32(*n_total);
            }
            ModifyMinpoll {
                address,
                minpoll: value,
            }
            | ModifyMaxpoll {
                address,
                maxpoll: value,
            }
            | ModifyMinstratum {
                address,
                min_stratum: value,
            }
            | ModifyPolltarget {
                address,
                poll_target: value,
            } => {
                w.address(address).i32(*value);
            }
            Dump => {
                w.i32(0);
            }
            ModifyMaxdelay {
                address,
                max_delay: value,
            }
            | ModifyMaxdelayratio {
                address,
                ratio: value,
            }
            | ModifyMaxdelaydevratio {
                address,
                ratio: value,
            } => {
                w.address(address).float(*value);
            }
            ModifyMaxupdateskew { skew_ppm: value }
            | Dfreq(value)
            | Doffset(value)
            | ReselectDistance(value) => {
                w.float(*value);
            }
            ModifyMakestep { limit, threshold } => {
                w.i32(*limit).float(*threshold);
            }
            Settime(time) => {
                w.timespec(*time);
            }
            Local(local) => {
                w.i32(local.enabled.into())
                    .i32(local.stratum)
                    .float(local.distance)
                    .i32(local.orphan.into())
                    .float(local.activate)
                    .float(local.wait_synced)
                    .float(local.wait_unsynced);
            }
            Manual(option) => {
                w.i32(*option as i32);
            }
            SourceData { index } | Sourcestats { index } | SelectData { index } => {
                w.u32(*index);
            }
            Allow(subnet) | AllowAll(subnet) | Deny(subnet) | DenyAll(subnet)
            | CmdAllow(subnet) | CmdAllowAll(subnet) | CmdDeny(subnet) | CmdDenyAll(subnet) => {
                w.ip(subnet.ip).i32(subnet.bits.into());
            }
            AcCheck(ip) | CmdAcCheck(ip) => {
                w.ip(Some(*ip));
            }
            AddSource(source) => ntp_source2(&mut w, source)?,
            DelSource(address) | NtpData(address) | NtpSourceName(address) | AuthData(address) => {
                w.address(address);
            }
            ManualDelete { index } => {
                w.i32(*index);
            }
            SmoothTime(option) => {
                w.i32(*option as i32);
            }
            ClientAccesses {
                first_index,
                n_clients,
                min_hits,
                reset,
            } => {
                w.u32(*first_index)
                    .u32(*n_clients)
                    .u32(*min_hits)
                    .u32((*reset).into());
            }
            ModifySelectOpts {
                address,
                ref_id,
                mask,
                options,
            } => {
                // The mask is sent as selection options, the options as the
                // flags of a source added (chronyd's convention).
                w.address(address)
                    .u32(*ref_id)
                    .u32(mask.0.into())
                    .u32(options.as_source_flags().0);
            }
            ModifyOffset {
                address,
                ref_id,
                offset,
            } => {
                w.address(address).u32(*ref_id).float(*offset);
            }
            NSources | Rekey | WriteRtc | Tracking | RtcReport | TrimRtc | CycleLogs
            | ManualList | MakeStep | Activity | Reselect | Smoothing | Refresh | ServerStats
            | Shutdown | OnOffline | ResetSources | ReloadSources => {}
        }
        Ok(w.0)
    }

    /// The request's packet in its current form, `attempt` counting the
    /// resends of the same `sequence`: padded to at least the length of its
    /// reply, so that chronyd never answers with more than it received.
    pub fn encode(&self, sequence: u32, attempt: u16) -> Result<Vec<u8>, Error> {
        self.packet(self.code(), &self.data()?, sequence, attempt)
    }

    /// The code of the older form of this request, for the chronyd versions
    /// that do not know the current one: `ADD_SOURCE` (4.0 to 4.8) for
    /// `AddSource`, `LOCAL2` (4.0 to 4.5) for `Local`, `DOFFSET` (4.0) for
    /// `Doffset`. `None` for the others.
    pub fn legacy_code(&self) -> Option<u16> {
        match self {
            Request::AddSource(_) => Some(code::ADD_SOURCE),
            Request::Local(_) => Some(code::LOCAL2),
            Request::Doffset(_) => Some(code::DOFFSET),
            _ => None,
        }
    }

    /// The request's packet in its older form ([`legacy_code`](Self::legacy_code)),
    /// if it has one. What the older form has no room for is left out (the
    /// local reference's activation and waits, a source's NTS-KE retries).
    pub fn encode_legacy(&self, sequence: u32, attempt: u16) -> Option<Result<Vec<u8>, Error>> {
        let code = self.legacy_code()?;
        let mut w = Writer::default();
        match self {
            Request::AddSource(source) => {
                if let Err(e) = ntp_source(&mut w, source) {
                    return Some(Err(e));
                }
            }
            Request::Local(local) => {
                w.i32(local.enabled.into())
                    .i32(local.stratum)
                    .float(local.distance)
                    .i32(local.orphan.into());
            }
            Request::Doffset(offset) => {
                // Whole seconds rounded down, and microseconds.
                let seconds = offset.floor();
                let micros = ((offset - seconds) * 1e6).round();
                w.i32(seconds as i32).i32(micros as i32);
            }
            _ => return None,
        }
        Some(self.packet(code, &w.0, sequence, attempt))
    }

    fn packet(
        &self,
        code: u16,
        data: &[u8],
        sequence: u32,
        attempt: u16,
    ) -> Result<Vec<u8>, Error> {
        let length = (HEADER_LEN + data.len()).max(self.reply_kind().length());
        let mut w = Writer(Vec::with_capacity(length));
        w.u8(super::PROTOCOL_VERSION)
            .u8(PKT_TYPE_REQUEST)
            .u16(0)
            .u16(code)
            .u16(attempt)
            .u32(sequence)
            .zeros(8)
            .bytes(data);
        w.0.resize(length, 0);
        Ok(w.0)
    }
}

fn selection_record(w: &mut Writer, selection: &SourceSelection) {
    match selection {
        SourceSelection::All => {
            w.zeros(2 * IP_ADDR_LEN);
        }
        SourceSelection::Matching { address, mask } => {
            w.ip(Some(*mask)).ip(Some(*address));
        }
    }
}

/// A source's kind and name, as both forms start.
fn source_name(w: &mut Writer, source: &NtpSource) -> Result<(), Error> {
    let name = source.name.as_bytes();
    if name.is_empty() || name.len() >= NAME_LEN || name.contains(&0) {
        return Err(Error::InvalidRequest(
            "a source name is 1 to 255 bytes, without NUL",
        ));
    }
    let kind = match source.kind {
        SourceKind::Server => 1,
        SourceKind::Peer => 2,
        SourceKind::Pool => 3,
    };
    w.u32(kind).bytes(name).zeros(NAME_LEN - name.len());
    Ok(())
}

/// `ADD_SOURCE2` (chronyd 4.9 and later): the fields reordered, eight
/// reserved words at the end.
fn ntp_source2(w: &mut Writer, source: &NtpSource) -> Result<(), Error> {
    source_name(w, source)?;
    w.u32(source.port)
        .i32(source.minpoll)
        .i32(source.maxpoll)
        .i32(source.presend_minpoll)
        .u32(source.min_stratum)
        .u32(source.poll_target)
        .u32(source.version)
        .u32(source.max_sources)
        .i32(source.min_samples)
        .i32(source.max_samples)
        .i32(source.max_unreach)
        .i32(source.filter_length)
        .u32(source.authkey)
        .u32(source.nts_port)
        .u32(source.cert_set)
        .i32(source.max_nts_retry)
        .float(source.max_delay)
        .float(source.max_delay_ratio)
        .float(source.max_delay_dev_ratio)
        .float(source.max_delay_quant)
        .float(source.min_delay)
        .float(source.asymmetry)
        .float(source.offset)
        .u32(source.flags.for_add_source2())
        .zeros(32);
    Ok(())
}

/// `ADD_SOURCE` (chronyd 4.0 to 4.8), as 4.8 lays it out: the fields an
/// earlier version does not know fall in its reserved words.
fn ntp_source(w: &mut Writer, source: &NtpSource) -> Result<(), Error> {
    source_name(w, source)?;
    w.u32(source.port)
        .i32(source.minpoll)
        .i32(source.maxpoll)
        .i32(source.presend_minpoll)
        .u32(source.min_stratum)
        .u32(source.poll_target)
        .u32(source.version)
        .u32(source.max_sources)
        .i32(source.min_samples)
        .i32(source.max_samples)
        .u32(source.authkey)
        .u32(source.nts_port)
        .float(source.max_delay)
        .float(source.max_delay_ratio)
        .float(source.max_delay_dev_ratio)
        .float(source.min_delay)
        .float(source.asymmetry)
        .float(source.offset)
        .u32(source.flags.0)
        .i32(source.filter_length)
        .u32(source.cert_set)
        .float(source.max_delay_quant)
        .i32(source.max_unreach);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a() -> Address {
        Address::Ip("192.0.2.1".parse().unwrap())
    }

    /// Every request, with the length chronyd expects of it: its data or
    /// its reply's, whichever is longer (chronyd's `pktlength.c`).
    fn every_request() -> Vec<(Request, usize)> {
        let s = Subnet::ANY;
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        vec![
            (Request::Online(SourceSelection::All), 60),
            (Request::Offline(SourceSelection::All), 60),
            (
                Request::Burst {
                    selection: SourceSelection::All,
                    n_good: 4,
                    n_total: 4,
                },
                68,
            ),
            (
                Request::ModifyMinpoll {
                    address: a(),
                    minpoll: 4,
                },
                44,
            ),
            (
                Request::ModifyMaxpoll {
                    address: a(),
                    maxpoll: 8,
                },
                44,
            ),
            (Request::Dump, 28),
            (
                Request::ModifyMaxdelay {
                    address: a(),
                    max_delay: 1.0,
                },
                44,
            ),
            (
                Request::ModifyMaxdelayratio {
                    address: a(),
                    ratio: 1.0,
                },
                44,
            ),
            (
                Request::ModifyMaxdelaydevratio {
                    address: a(),
                    ratio: 1.0,
                },
                44,
            ),
            (
                Request::ModifyMinstratum {
                    address: a(),
                    min_stratum: 1,
                },
                44,
            ),
            (
                Request::ModifyPolltarget {
                    address: a(),
                    poll_target: 6,
                },
                44,
            ),
            (Request::ModifyMaxupdateskew { skew_ppm: 100.0 }, 28),
            (
                Request::ModifyMakestep {
                    limit: 3,
                    threshold: 1.0,
                },
                28,
            ),
            (Request::Settime(SystemTime::UNIX_EPOCH), 40),
            (Request::Local(LocalOptions::default()), 48),
            (Request::Manual(ManualOption::On), 28),
            (Request::NSources, 32),
            (Request::SourceData { index: 0 }, 76),
            (Request::Rekey, 28),
            (Request::Allow(s), 44),
            (Request::AllowAll(s), 44),
            (Request::Deny(s), 44),
            (Request::DenyAll(s), 44),
            (Request::CmdAllow(s), 44),
            (Request::CmdAllowAll(s), 44),
            (Request::CmdDeny(s), 44),
            (Request::CmdDenyAll(s), 44),
            (Request::AcCheck(ip), 40),
            (Request::CmdAcCheck(ip), 40),
            (Request::AddSource(Box::new(NtpSource::server("ntp"))), 408),
            (Request::DelSource(a()), 40),
            (Request::WriteRtc, 28),
            (Request::Dfreq(1.0), 28),
            (Request::Doffset(1.0), 28),
            (Request::Tracking, 104),
            (Request::Sourcestats { index: 0 }, 84),
            (Request::RtcReport, 56),
            (Request::TrimRtc, 28),
            (Request::CycleLogs, 28),
            (Request::ManualList, 416),
            (Request::ManualDelete { index: 0 }, 28),
            (Request::MakeStep, 28),
            (Request::Activity, 48),
            (Request::Reselect, 28),
            (Request::ReselectDistance(0.001), 28),
            (Request::Smoothing, 52),
            (Request::SmoothTime(SmoothTimeOption::Reset), 28),
            (Request::Refresh, 28),
            (Request::ServerStats, 196),
            (Request::NtpData(a()), 172),
            (Request::Shutdown, 28),
            (Request::OnOffline, 28),
            (Request::NtpSourceName(a()), 284),
            (Request::ResetSources, 28),
            (Request::AuthData(a()), 52),
            (
                Request::ClientAccesses {
                    first_index: 0,
                    n_clients: 8,
                    min_hits: 0,
                    reset: false,
                },
                // The longest: 484 bytes of padding, chronyd's maximum.
                520,
            ),
            (Request::SelectData { index: 0 }, 76),
            (Request::ReloadSources, 28),
            (
                Request::ModifySelectOpts {
                    address: a(),
                    ref_id: 0,
                    mask: SelectOptions::PREFER,
                    options: SelectOptions::PREFER,
                },
                52,
            ),
            (
                Request::ModifyOffset {
                    address: a(),
                    ref_id: 0,
                    offset: 0.1,
                },
                48,
            ),
        ]
    }

    #[test]
    fn every_request_has_chronyds_length() {
        let requests = every_request();
        // chronyd 4.8 knows 75 request codes; it refuses the 15 left out.
        assert_eq!(requests.len(), 60);
        for (request, length) in requests {
            let packet = request.encode(1, 0).unwrap();
            assert_eq!(packet.len(), length, "{request:?}");
        }
    }

    #[test]
    fn every_request_has_its_own_code() {
        let mut codes: Vec<u16> = every_request().iter().map(|(r, _)| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 60);
        // The commands chronyd no longer accepts are not among them.
        for retired in [10, 12, 27, 28, 32, 38, 39, 40, 55, 56, 58, 59, 60, 61] {
            assert!(!codes.contains(&retired), "{retired}");
        }
    }

    #[test]
    fn the_header() {
        let packet = Request::SourceData { index: 2 }
            .encode(0x0102_0304, 3)
            .unwrap();
        assert_eq!(
            &packet[..HEADER_LEN],
            &[6, 1, 0, 0, 0, 15, 0, 3, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&packet[20..24], &[0, 0, 0, 2]);
        // The padding is zeros.
        assert!(packet[24..].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_source_name_must_fit() {
        let long = "a".repeat(255);
        let ok = Request::AddSource(Box::new(NtpSource::pool(long.clone())));
        let packet = ok.encode(1, 0).unwrap();
        assert_eq!(&packet[24..24 + 255], long.as_bytes());
        assert_eq!(packet[24 + 255], 0);
        for name in ["", "with\0nul", &"a".repeat(256)] {
            let request = Request::AddSource(Box::new(NtpSource::server(name)));
            assert!(
                matches!(request.encode(1, 0), Err(Error::InvalidRequest(_))),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_source_known_by_its_reference_id() {
        let packet = Request::DelSource(Address::Id(0x5050_5300))
            .encode(1, 0)
            .unwrap();
        assert_eq!(&packet[20..24], &[0x50, 0x50, 0x53, 0]);
        assert_eq!(&packet[36..38], &[0, 3]);
    }

    #[test]
    fn select_options_are_sent_as_source_flags() {
        let options = SelectOptions::NOSELECT | SelectOptions::REQUIRE;
        assert_eq!(
            options.as_source_flags(),
            SourceFlags::NOSELECT | SourceFlags::REQUIRE
        );
    }

    #[test]
    fn subnets() {
        let host = Subnet::host("192.0.2.1".parse().unwrap());
        assert_eq!(host.bits, 32);
        assert_eq!(Subnet::host("2001:db8::1".parse().unwrap()).bits, 128);
        let packet = Request::Allow(host).encode(1, 0).unwrap();
        assert_eq!(&packet[40..44], &[0, 0, 0, 32]);
    }

    #[test]
    fn older_forms() {
        let add = Request::AddSource(Box::new(NtpSource::server("ntp")));
        let local = Request::Local(LocalOptions::default());
        let doffset = Request::Doffset(-0.25);
        assert_eq!(add.legacy_code(), Some(64));
        assert_eq!(local.legacy_code(), Some(56));
        assert_eq!(doffset.legacy_code(), Some(32));
        assert_eq!(Request::Tracking.legacy_code(), None);
        assert!(Request::Tracking.encode_legacy(1, 0).is_none());
        let length = |r: &Request| r.encode_legacy(1, 0).unwrap().unwrap().len();
        assert_eq!(length(&add), 372);
        assert_eq!(length(&local), 36);
        assert_eq!(length(&doffset), 28);
        let packet = doffset.encode_legacy(1, 0).unwrap().unwrap();
        assert_eq!(&packet[4..6], &[0, 32]);
        // -0.25 s: -1 s and 750000 us.
        assert_eq!(
            &packet[20..28],
            &[0xff, 0xff, 0xff, 0xff, 0, 0x0b, 0x71, 0xb0]
        );
    }

    #[test]
    fn add_source2_renumbers_flags_and_moves_fields() {
        let source = NtpSource {
            flags: SourceFlags::ONLINE
                | SourceFlags::IPV6
                | SourceFlags::EF_NET_CORRECTION
                | SourceFlags::EF_EXP_MONO_ROOT,
            max_nts_retry: 7,
            max_unreach: 9,
            ..NtpSource::server("ntp")
        };
        let packet = Request::AddSource(Box::new(source)).encode(1, 0).unwrap();
        assert_eq!(&packet[4..6], &[0, 75]);
        let word = |at: usize| u32::from_be_bytes(packet[at..at + 4].try_into().unwrap());
        // After the type and the name: 10 words, then max_unreach.
        assert_eq!(word(20 + 4 + 256 + 40), 9);
        assert_eq!(word(20 + 4 + 256 + 60), 7);
        assert_eq!(
            word(20 + 4 + 256 + 92),
            0x1 | 0x1000 | 0x1_0000 | 0x8000_0000
        );
        // Eight reserved words at the end.
        assert!(packet[packet.len() - 32..].iter().all(|b| *b == 0));
    }
}
