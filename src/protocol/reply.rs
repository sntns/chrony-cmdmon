//! Replies: every report chronyd 4.x sends.

use std::time::SystemTime;

use super::wire::Reader;
use super::Address;
use super::Request;
use super::Status;
use super::PROTOCOL_VERSION;
use crate::Error;

const PKT_TYPE_REPLY: u8 = 2;
/// The reply header: version, type, two reserved bytes, command, reply,
/// status, three padding halves, sequence and two padding words.
pub(crate) const HEADER_LEN: usize = 28;

/// The kinds of reply, by code (`RPY_*`). Those chronyd 4.0 and later no
/// longer send are left out; the older forms of a reply some of them still
/// send are kept (`ServerStats2`, `ServerStats3`, `NtpDataV1`), decoded as
/// the current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplyKind {
    /// No data: a plain status (`RPY_NULL`).
    Null,
    /// [`Reply::NSources`] (`RPY_N_SOURCES`).
    NSources,
    /// [`Reply::SourceData`] (`RPY_SOURCE_DATA`).
    SourceData,
    /// [`Reply::Tracking`] (`RPY_TRACKING`).
    Tracking,
    /// [`Reply::Sourcestats`] (`RPY_SOURCESTATS`).
    Sourcestats,
    /// [`Reply::Rtc`] (`RPY_RTC`).
    Rtc,
    /// [`Reply::Activity`] (`RPY_ACTIVITY`).
    Activity,
    /// [`Reply::Smoothing`] (`RPY_SMOOTHING`).
    Smoothing,
    /// [`Reply::ManualTimestamp`] (`RPY_MANUAL_TIMESTAMP2`).
    ManualTimestamp,
    /// [`Reply::ManualList`] (`RPY_MANUAL_LIST2`).
    ManualList,
    /// [`Reply::NtpSourceName`] (`RPY_NTP_SOURCE_NAME`).
    NtpSourceName,
    /// [`Reply::AuthData`] (`RPY_AUTH_DATA`).
    AuthData,
    /// [`Reply::ClientAccesses`] (`RPY_CLIENT_ACCESSES_BY_INDEX3`).
    ClientAccesses,
    /// [`Reply::SelectData`] (`RPY_SELECT_DATA`).
    SelectData,
    /// [`Reply::ServerStats`] (`RPY_SERVER_STATS4`).
    ServerStats,
    /// [`Reply::NtpData`] (`RPY_NTP_DATA2`).
    NtpData,
    /// `serverstats` from chronyd 4.0 and 4.1: 32-bit counters, fewer.
    ServerStats2,
    /// `serverstats` from chronyd 4.2 and 4.3: 32-bit counters.
    ServerStats3,
    /// `ntpdata` from chronyd 4.0 to 4.5: no timestamping counts.
    NtpDataV1,
}

impl ReplyKind {
    pub(crate) const ALL: &'static [ReplyKind; 19] = &[
        ReplyKind::Null,
        ReplyKind::NSources,
        ReplyKind::SourceData,
        ReplyKind::Tracking,
        ReplyKind::Sourcestats,
        ReplyKind::Rtc,
        ReplyKind::Activity,
        ReplyKind::Smoothing,
        ReplyKind::ManualTimestamp,
        ReplyKind::ManualList,
        ReplyKind::NtpSourceName,
        ReplyKind::AuthData,
        ReplyKind::ClientAccesses,
        ReplyKind::SelectData,
        ReplyKind::ServerStats,
        ReplyKind::NtpData,
        ReplyKind::ServerStats2,
        ReplyKind::ServerStats3,
        ReplyKind::NtpDataV1,
    ];

    /// The reply code (`RPY_*`).
    pub fn code(self) -> u16 {
        match self {
            ReplyKind::Null => 1,
            ReplyKind::NSources => 2,
            ReplyKind::SourceData => 3,
            ReplyKind::Tracking => 5,
            ReplyKind::Sourcestats => 6,
            ReplyKind::Rtc => 7,
            ReplyKind::Activity => 12,
            ReplyKind::Smoothing => 13,
            ReplyKind::ManualTimestamp => 17,
            ReplyKind::ManualList => 18,
            ReplyKind::NtpSourceName => 19,
            ReplyKind::AuthData => 20,
            ReplyKind::ClientAccesses => 21,
            ReplyKind::SelectData => 23,
            ReplyKind::ServerStats => 25,
            ReplyKind::NtpData => 26,
            ReplyKind::ServerStats2 => 22,
            ReplyKind::ServerStats3 => 24,
            ReplyKind::NtpDataV1 => 16,
        }
    }

    /// The kind of reply `code`, if this protocol version has it.
    pub fn from_code(code: u16) -> Option<ReplyKind> {
        ReplyKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.code() == code)
    }

    /// The length of the whole packet.
    pub fn length(self) -> usize {
        HEADER_LEN
            + match self {
                ReplyKind::Null => 0,
                ReplyKind::NSources => 4,
                ReplyKind::SourceData => 48,
                ReplyKind::Tracking => 76,
                ReplyKind::Sourcestats => 56,
                ReplyKind::Rtc => 28,
                ReplyKind::Activity => 20,
                ReplyKind::Smoothing => 24,
                ReplyKind::ManualTimestamp => 12,
                ReplyKind::ManualList => 4 + MANUAL_LIST_SAMPLES * 24,
                ReplyKind::NtpSourceName => 256,
                ReplyKind::AuthData => 24,
                ReplyKind::ClientAccesses => 12 + CLIENT_ACCESSES * 60,
                ReplyKind::SelectData => 48,
                ReplyKind::ServerStats => 21 * 8,
                ReplyKind::NtpData => 144,
                ReplyKind::ServerStats2 => 8 * 4,
                ReplyKind::ServerStats3 => 11 * 4,
                ReplyKind::NtpDataV1 => 124,
            }
    }
}

/// The most samples a manual list has room for.
const MANUAL_LIST_SAMPLES: usize = 16;
/// The most clients one `ClientAccesses` reply has room for.
pub const CLIENT_ACCESSES: usize = 8;

/// The leap second status (`tracking`, `ntpdata`, `selectdata`);
/// `Unsynchronised` while nothing vouches for the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeapStatus {
    /// No leap second pending.
    Normal,
    /// A leap second will be inserted at the end of the day.
    InsertSecond,
    /// A leap second will be deleted at the end of the day.
    DeleteSecond,
    /// The clock is not synchronized.
    Unsynchronised,
    /// A value this crate does not know.
    Other(u16),
}

impl From<u16> for LeapStatus {
    fn from(code: u16) -> Self {
        match code {
            0 => LeapStatus::Normal,
            1 => LeapStatus::InsertSecond,
            2 => LeapStatus::DeleteSecond,
            3 => LeapStatus::Unsynchronised,
            other => LeapStatus::Other(other),
        }
    }
}

impl std::fmt::Display for LeapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // chronyc's wording
        match self {
            LeapStatus::Normal => f.write_str("Normal"),
            LeapStatus::InsertSecond => f.write_str("Insert second"),
            LeapStatus::DeleteSecond => f.write_str("Delete second"),
            LeapStatus::Unsynchronised => f.write_str("Not synchronised"),
            LeapStatus::Other(code) => write!(f, "Unknown ({code})"),
        }
    }
}

/// `chronyc tracking`.
#[derive(Debug, Clone, PartialEq)]
pub struct Tracking {
    /// The reference ID of the source synchronized to (0 when none).
    pub ref_id: u32,
    /// The address of the source synchronized to.
    pub address: Address,
    /// The stratum of the local clock (0: unsynchronized).
    pub stratum: u16,
    /// The leap second status.
    pub leap_status: LeapStatus,
    /// When the last measurement from the reference was processed.
    pub ref_time: SystemTime,
    /// How far the system clock is from NTP time, being corrected (seconds;
    /// positive: the clock is slow).
    pub current_correction: f64,
    /// The offset at the last clock update (seconds).
    pub last_offset: f64,
    /// The long-term average of the offset (seconds).
    pub rms_offset: f64,
    /// The rate the clock would be wrong at, uncorrected (ppm; positive:
    /// fast).
    pub freq_ppm: f64,
    /// The residual frequency of the reference (ppm).
    pub resid_freq_ppm: f64,
    /// The estimated error bound of the frequency (ppm).
    pub skew_ppm: f64,
    /// Round-trip delay to the stratum-1 source (seconds).
    pub root_delay: f64,
    /// Total dispersion accumulated to the stratum-1 source (seconds).
    pub root_dispersion: f64,
    /// Between the last two clock updates (seconds).
    pub last_update_interval: f64,
}

impl Tracking {
    /// Whether a source vouches for the system clock.
    pub fn synchronized(&self) -> bool {
        self.leap_status != LeapStatus::Unsynchronised
    }
}

/// What a source is (`chronyc sources`' first column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceMode {
    /// A server (`^`).
    Client,
    /// A peer (`=`).
    Peer,
    /// A reference clock (`#`).
    ReferenceClock,
    /// A value this crate does not know.
    Other(u16),
}

impl From<u16> for SourceMode {
    fn from(code: u16) -> Self {
        match code {
            0 => SourceMode::Client,
            1 => SourceMode::Peer,
            2 => SourceMode::ReferenceClock,
            other => SourceMode::Other(other),
        }
    }
}

impl SourceMode {
    /// `chronyc sources`' symbol.
    pub fn symbol(self) -> char {
        match self {
            SourceMode::Client => '^',
            SourceMode::Peer => '=',
            SourceMode::ReferenceClock => '#',
            SourceMode::Other(_) => ' ',
        }
    }
}

/// What the source selection made of a source (`chronyc sources`' second
/// column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceState {
    /// Synchronized to (`*`).
    Selected,
    /// Not selectable: unreachable, too few samples, ... (`?`).
    NonSelectable,
    /// Disagrees with the majority (`x`).
    Falseticker,
    /// Too much jitter (`~`).
    Jittery,
    /// Combined with the selected source (`+`).
    Unselected,
    /// Selectable, not combined (`-`).
    Selectable,
    /// A value this crate does not know.
    Other(u16),
}

impl From<u16> for SourceState {
    fn from(code: u16) -> Self {
        match code {
            0 => SourceState::Selected,
            1 => SourceState::NonSelectable,
            2 => SourceState::Falseticker,
            3 => SourceState::Jittery,
            4 => SourceState::Unselected,
            5 => SourceState::Selectable,
            other => SourceState::Other(other),
        }
    }
}

impl SourceState {
    /// `chronyc sources`' symbol.
    pub fn symbol(self) -> char {
        match self {
            SourceState::Selected => '*',
            SourceState::NonSelectable => '?',
            SourceState::Falseticker => 'x',
            SourceState::Jittery => '~',
            SourceState::Unselected => '+',
            SourceState::Selectable => '-',
            SourceState::Other(_) => ' ',
        }
    }
}

/// One line of `chronyc sources`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceData {
    /// The source's address (or reference ID for a reference clock).
    pub address: Address,
    /// The polling interval, as a power of 2 seconds.
    pub poll: i16,
    /// The source's stratum.
    pub stratum: u16,
    /// The source's selection state.
    pub state: SourceState,
    /// Server, peer or reference clock.
    pub mode: SourceMode,
    /// Unused by chronyd 4.x (always 0).
    pub flags: u16,
    /// The last 8 polls, the latest in the lowest bit: answered or not.
    pub reachability: u8,
    /// Since the last sample (seconds).
    pub since_sample: u32,
    /// The last sample's offset as measured (seconds; positive: the local
    /// clock is fast) - chronyc's value in brackets.
    pub orig_latest_meas: f64,
    /// The same, adjusted for the clock's corrections since - chronyc's
    /// first value.
    pub latest_meas: f64,
    /// Its error margin (seconds).
    pub latest_meas_err: f64,
}

/// One line of `chronyc sourcestats`.
#[derive(Debug, Clone, PartialEq)]
pub struct Sourcestats {
    /// The source's reference ID.
    pub ref_id: u32,
    /// The source's address.
    pub address: Address,
    /// Sample points retained.
    pub n_samples: u32,
    /// Runs of residuals with the same sign after the last regression.
    pub n_runs: u32,
    /// The interval spanned by the samples (seconds).
    pub span_seconds: u32,
    /// Standard deviation of the samples (seconds).
    pub sd: f64,
    /// The estimated residual frequency (ppm).
    pub resid_freq_ppm: f64,
    /// The estimated error bound of the frequency (ppm).
    pub skew_ppm: f64,
    /// The estimated offset of the source (seconds).
    pub est_offset: f64,
    /// The estimated error of the offset (seconds).
    pub est_offset_err: f64,
}

/// `chronyc rtcdata`.
#[derive(Debug, Clone, PartialEq)]
pub struct Rtc {
    /// When the last measurement was made.
    pub ref_time: SystemTime,
    /// Measurements retained.
    pub n_samples: u16,
    /// Runs of residuals with the same sign after the last regression.
    pub n_runs: u16,
    /// The interval spanned by the measurements (seconds).
    pub span_seconds: u32,
    /// How far the RTC is ahead of the system clock (seconds).
    pub rtc_seconds_fast: f64,
    /// How fast the RTC gains (ppm; negative: loses).
    pub rtc_gain_rate_ppm: f64,
}

/// `chronyc settime`: what the manual sample did.
#[derive(Debug, Clone, PartialEq)]
pub struct ManualTimestamp {
    /// The offset applied (seconds).
    pub offset: f64,
    /// The frequency change applied (ppm).
    pub dfreq_ppm: f64,
    /// The new absolute frequency (ppm).
    pub new_afreq_ppm: f64,
}

/// One sample of `chronyc manual list`.
#[derive(Debug, Clone, PartialEq)]
pub struct ManualSample {
    /// When the sample was entered.
    pub when: SystemTime,
    /// Its offset, corrected for the slewing since (seconds).
    pub slewed_offset: f64,
    /// Its offset as entered (seconds).
    pub orig_offset: f64,
    /// Its residual after the regression (seconds).
    pub residual: f64,
}

/// `chronyc activity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activity {
    /// Sources online.
    pub online: i32,
    /// Sources offline.
    pub offline: i32,
    /// Sources in a burst, going online after it.
    pub burst_online: i32,
    /// Sources in a burst, going offline after it.
    pub burst_offline: i32,
    /// Sources whose address is not resolved yet.
    pub unresolved: i32,
}

/// `chronyc smoothing`.
#[derive(Debug, Clone, PartialEq)]
pub struct Smoothing {
    /// Whether time smoothing is enabled.
    pub active: bool,
    /// Only leap seconds are smoothed.
    pub leap_only: bool,
    /// The offset being smoothed out (seconds).
    pub offset: f64,
    /// The frequency offset of the smoothing (ppm).
    pub freq_ppm: f64,
    /// The wander of the smoothing (ppm per second).
    pub wander_ppm: f64,
    /// Seconds since the last update.
    pub last_update_ago: f64,
    /// Seconds until the smoothing ends.
    pub remaining_time: f64,
}

/// One client of `chronyc clients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAccess {
    /// The client's address.
    pub address: Address,
    /// NTP requests received.
    pub ntp_hits: u32,
    /// NTS-KE connections accepted.
    pub nke_hits: u32,
    /// Command requests received.
    pub cmd_hits: u32,
    /// NTP requests dropped (rate limiting).
    pub ntp_drops: u32,
    /// NTS-KE connections dropped.
    pub nke_drops: u32,
    /// Command requests dropped.
    pub cmd_drops: u32,
    /// Average intervals, as powers of 2 seconds.
    pub ntp_interval: i8,
    /// NTS-KE average interval.
    pub nke_interval: i8,
    /// Command average interval.
    pub cmd_interval: i8,
    /// Average interval of the NTP timeouts.
    pub ntp_timeout_interval: i8,
    /// Seconds since the last hit (`u32::MAX`: never).
    pub last_ntp_hit_ago: u32,
    /// Seconds since the last NTS-KE connection.
    pub last_nke_hit_ago: u32,
    /// Seconds since the last command.
    pub last_cmd_hit_ago: u32,
}

/// A batch of `chronyc clients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAccesses {
    /// How many entries chronyd's table has.
    pub n_indices: u32,
    /// The index after those this batch covered: the next request's first.
    pub next_index: u32,
    /// The clients of this batch.
    pub clients: Vec<ClientAccess>,
}

/// `chronyc serverstats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerStats {
    /// NTP requests received.
    pub ntp_hits: u64,
    /// NTS-KE connections accepted.
    pub nke_hits: u64,
    /// Command requests received.
    pub cmd_hits: u64,
    /// NTP requests dropped.
    pub ntp_drops: u64,
    /// NTS-KE connections dropped.
    pub nke_drops: u64,
    /// Command requests dropped.
    pub cmd_drops: u64,
    /// Client log records dropped.
    pub log_drops: u64,
    /// Authenticated NTP requests.
    pub ntp_auth_hits: u64,
    /// Interleaved NTP requests.
    pub ntp_interleaved_hits: u64,
    /// NTP timestamps held for interleaved mode.
    pub ntp_timestamps: u64,
    /// The interval the held timestamps span (seconds).
    pub ntp_span_seconds: u64,
    /// NTP requests received with a daemon timestamp.
    pub ntp_daemon_rx_timestamps: u64,
    /// NTP responses sent with a daemon timestamp.
    pub ntp_daemon_tx_timestamps: u64,
    /// NTP requests received with a kernel timestamp.
    pub ntp_kernel_rx_timestamps: u64,
    /// NTP responses sent with a kernel timestamp.
    pub ntp_kernel_tx_timestamps: u64,
    /// NTP requests received with a hardware timestamp.
    pub ntp_hw_rx_timestamps: u64,
    /// NTP responses sent with a hardware timestamp.
    pub ntp_hw_tx_timestamps: u64,
}

/// `chronyc ntpdata`: the last NTP exchange with a source.
#[derive(Debug, Clone, PartialEq)]
pub struct NtpData {
    /// The source's address.
    pub remote_address: Address,
    /// The local address the source is reached from.
    pub local_address: Address,
    /// The source's port.
    pub remote_port: u16,
    /// Leap indicator of the last packet.
    pub leap: u8,
    /// NTP version of the last packet.
    pub version: u8,
    /// NTP mode of the last packet.
    pub mode: u8,
    /// Stratum of the last packet.
    pub stratum: u8,
    /// Poll interval (power of 2 seconds).
    pub poll: i8,
    /// The source's precision (power of 2 seconds).
    pub precision: i8,
    /// Root delay (seconds).
    pub root_delay: f64,
    /// Root dispersion (seconds).
    pub root_dispersion: f64,
    /// Reference ID of the last packet.
    pub ref_id: u32,
    /// Reference timestamp of the last packet.
    pub ref_time: SystemTime,
    /// The measured offset (seconds).
    pub offset: f64,
    /// The measured delay (seconds).
    pub peer_delay: f64,
    /// The measured dispersion (seconds).
    pub peer_dispersion: f64,
    /// How long the source took to respond (seconds).
    pub response_time: f64,
    /// The jitter asymmetry estimated (-0.5 to 0.5).
    pub jitter_asymmetry: f64,
    /// The packet tests passed (the low 10 bits), interleaved mode
    /// (0x4000) and authentication (0x8000).
    pub flags: u16,
    /// Where the transmit and receive timestamps came from: `D`aemon,
    /// `K`ernel or `H`ardware.
    pub tx_timestamping: char,
    /// See `tx_timestamping`.
    pub rx_timestamping: char,
    /// Packets sent.
    pub total_tx_count: u32,
    /// Packets received.
    pub total_rx_count: u32,
    /// Valid packets received.
    pub total_valid_count: u32,
    /// Packets accepted as samples (0 before chrony 4.3).
    pub total_good_count: u32,
    /// Packets sent with a kernel timestamp.
    pub total_kernel_tx_ts: u32,
    /// Packets received with a kernel timestamp.
    pub total_kernel_rx_ts: u32,
    /// Packets sent with a hardware timestamp.
    pub total_hw_tx_ts: u32,
    /// Packets received with a hardware timestamp.
    pub total_hw_rx_ts: u32,
}

impl NtpData {
    /// The packet tests passed (`chronyc ntpdata`'s `Test result`).
    pub fn tests(&self) -> u16 {
        self.flags & 0x3ff
    }

    /// Whether the last exchange was in interleaved mode.
    pub fn interleaved(&self) -> bool {
        self.flags & 0x4000 != 0
    }

    /// Whether the last packet was authenticated.
    pub fn authenticated(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// How a source authenticates (`chronyc authdata`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMode {
    /// No authentication.
    None,
    /// A symmetric key (`key`).
    Symmetric,
    /// Network Time Security (`nts`).
    Nts,
    /// A mode this crate does not know.
    Other(u16),
}

impl From<u16> for AuthMode {
    fn from(code: u16) -> Self {
        match code {
            0 => AuthMode::None,
            1 => AuthMode::Symmetric,
            2 => AuthMode::Nts,
            other => AuthMode::Other(other),
        }
    }
}

/// `chronyc authdata`, for one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthData {
    /// How the source authenticates.
    pub mode: AuthMode,
    /// The key's type (cipher or hash).
    pub key_type: u16,
    /// The key's ID (symmetric key).
    pub key_id: u32,
    /// The key's length (bits).
    pub key_length: u16,
    /// NTS-KE attempts since the last success.
    pub ke_attempts: u16,
    /// Seconds since the last NTS-KE.
    pub last_ke_ago: u32,
    /// NTS cookies held.
    pub cookies: u16,
    /// The length of the cookies (bytes).
    pub cookie_length: u16,
    /// Whether an NTS NAK was received.
    pub nak: bool,
}

/// A source's selection options (`noselect`, `prefer`, `trust`,
/// `require`): as `chronyc selectdata` reports them and `selectopts` sets
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SelectOptions(pub u16);

impl SelectOptions {
    /// Never selected.
    pub const NOSELECT: SelectOptions = SelectOptions(0x1);
    /// Preferred.
    pub const PREFER: SelectOptions = SelectOptions(0x2);
    /// Trusted.
    pub const TRUST: SelectOptions = SelectOptions(0x4);
    /// Required.
    pub const REQUIRE: SelectOptions = SelectOptions(0x8);

    /// Whether every option of `other` is set.
    pub fn contains(self, other: SelectOptions) -> bool {
        self.0 & other.0 == other.0
    }

    /// The same options as the flags of a source added.
    pub fn as_source_flags(self) -> super::SourceFlags {
        use super::SourceFlags as F;
        let mut flags = F::default();
        for (option, flag) in [
            (SelectOptions::NOSELECT, F::NOSELECT),
            (SelectOptions::PREFER, F::PREFER),
            (SelectOptions::TRUST, F::TRUST),
            (SelectOptions::REQUIRE, F::REQUIRE),
        ] {
            if self.contains(option) {
                flags |= flag;
            }
        }
        flags
    }
}

impl std::ops::BitOr for SelectOptions {
    type Output = SelectOptions;
    fn bitor(self, other: SelectOptions) -> SelectOptions {
        SelectOptions(self.0 | other.0)
    }
}

/// One line of `chronyc selectdata`.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectData {
    /// The source's reference ID.
    pub ref_id: u32,
    /// The source's address.
    pub address: Address,
    /// chronyc's state column (`*`, `+`, `N`, `s`, ...).
    pub state: char,
    /// Whether the source is authenticated.
    pub authentication: bool,
    /// Its leap indicator.
    pub leap: u8,
    /// The options configured.
    pub conf_options: SelectOptions,
    /// The options in effect.
    pub eff_options: SelectOptions,
    /// Seconds since the last sample.
    pub last_sample_ago: u32,
    /// Its selection score.
    pub score: f64,
    /// Low end of its offset interval (seconds).
    pub lo_limit: f64,
    /// High end of its offset interval (seconds).
    pub hi_limit: f64,
}

/// A reply from chronyd, decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Done; nothing to report.
    Null,
    /// `sources`: how many there are.
    NSources(u32),
    /// `sources`: one.
    SourceData(SourceData),
    /// `tracking`.
    Tracking(Tracking),
    /// `sourcestats`: one.
    Sourcestats(Sourcestats),
    /// `rtcdata`.
    Rtc(Rtc),
    /// `activity`.
    Activity(Activity),
    /// `smoothing`.
    Smoothing(Smoothing),
    /// `settime`.
    ManualTimestamp(ManualTimestamp),
    /// `manual list`.
    ManualList(Vec<ManualSample>),
    /// `sourcename`.
    NtpSourceName(String),
    /// `authdata`.
    AuthData(AuthData),
    /// `clients`: one batch.
    ClientAccesses(ClientAccesses),
    /// `selectdata`: one.
    SelectData(SelectData),
    /// `serverstats`.
    ServerStats(ServerStats),
    /// `ntpdata`.
    NtpData(NtpData),
}

impl Reply {
    /// The kind of reply.
    pub fn kind(&self) -> ReplyKind {
        match self {
            Reply::Null => ReplyKind::Null,
            Reply::NSources(_) => ReplyKind::NSources,
            Reply::SourceData(_) => ReplyKind::SourceData,
            Reply::Tracking(_) => ReplyKind::Tracking,
            Reply::Sourcestats(_) => ReplyKind::Sourcestats,
            Reply::Rtc(_) => ReplyKind::Rtc,
            Reply::Activity(_) => ReplyKind::Activity,
            Reply::Smoothing(_) => ReplyKind::Smoothing,
            Reply::ManualTimestamp(_) => ReplyKind::ManualTimestamp,
            Reply::ManualList(_) => ReplyKind::ManualList,
            Reply::NtpSourceName(_) => ReplyKind::NtpSourceName,
            Reply::AuthData(_) => ReplyKind::AuthData,
            Reply::ClientAccesses(_) => ReplyKind::ClientAccesses,
            Reply::SelectData(_) => ReplyKind::SelectData,
            Reply::ServerStats(_) => ReplyKind::ServerStats,
            Reply::NtpData(_) => ReplyKind::NtpData,
        }
    }

    /// Decodes `packet` as chronyd's answer to `request` sent as
    /// `sequence`: checked to be that answer, carried out, of the expected
    /// kind and long enough. Never panics, whatever the bytes.
    pub fn decode(request: &Request, sequence: u32, packet: &[u8]) -> Result<Reply, Error> {
        let header = ReplyHeader::parse(packet)?;
        if header.sequence != sequence {
            return Err(Error::Malformed("reply to another request (sequence)"));
        }
        if header.command != request.code() && Some(header.command) != request.legacy_code() {
            return Err(Error::Malformed("reply to another command"));
        }
        if header.status != Status::Success {
            return Err(Error::Status(header.status));
        }
        let kind = request
            .reply_kinds()
            .iter()
            .copied()
            .find(|kind| kind.code() == header.reply)
            .ok_or(Error::Malformed("unexpected reply type"))?;
        if packet.len() < kind.length() {
            return Err(Error::Malformed("reply shorter than its data"));
        }
        Ok(Reply::decode_data(kind, &packet[HEADER_LEN..]))
    }

    /// Decodes the data of a reply of `kind`, at least as long as it.
    fn decode_data(kind: ReplyKind, data: &[u8]) -> Reply {
        let mut r = Reader::new(data);
        match kind {
            ReplyKind::Null => Reply::Null,
            ReplyKind::NSources => Reply::NSources(r.u32()),
            ReplyKind::SourceData => Reply::SourceData(SourceData {
                address: r.address(),
                poll: r.i16(),
                stratum: r.u16(),
                state: SourceState::from(r.u16()),
                mode: SourceMode::from(r.u16()),
                flags: r.u16(),
                reachability: r.u16() as u8,
                since_sample: r.u32(),
                orig_latest_meas: r.float(),
                latest_meas: r.float(),
                latest_meas_err: r.float(),
            }),
            ReplyKind::Tracking => Reply::Tracking(Tracking {
                ref_id: r.u32(),
                address: r.address(),
                stratum: r.u16(),
                leap_status: LeapStatus::from(r.u16()),
                ref_time: r.timespec(),
                current_correction: r.float(),
                last_offset: r.float(),
                rms_offset: r.float(),
                freq_ppm: r.float(),
                resid_freq_ppm: r.float(),
                skew_ppm: r.float(),
                root_delay: r.float(),
                root_dispersion: r.float(),
                last_update_interval: r.float(),
            }),
            ReplyKind::Sourcestats => Reply::Sourcestats(Sourcestats {
                ref_id: r.u32(),
                address: r.address(),
                n_samples: r.u32(),
                n_runs: r.u32(),
                span_seconds: r.u32(),
                sd: r.float(),
                resid_freq_ppm: r.float(),
                skew_ppm: r.float(),
                est_offset: r.float(),
                est_offset_err: r.float(),
            }),
            ReplyKind::Rtc => Reply::Rtc(Rtc {
                ref_time: r.timespec(),
                n_samples: r.u16(),
                n_runs: r.u16(),
                span_seconds: r.u32(),
                rtc_seconds_fast: r.float(),
                rtc_gain_rate_ppm: r.float(),
            }),
            ReplyKind::Activity => Reply::Activity(Activity {
                online: r.i32(),
                offline: r.i32(),
                burst_online: r.i32(),
                burst_offline: r.i32(),
                unresolved: r.i32(),
            }),
            ReplyKind::Smoothing => {
                let flags = r.u32();
                Reply::Smoothing(Smoothing {
                    active: flags & 0x1 != 0,
                    leap_only: flags & 0x2 != 0,
                    offset: r.float(),
                    freq_ppm: r.float(),
                    wander_ppm: r.float(),
                    last_update_ago: r.float(),
                    remaining_time: r.float(),
                })
            }
            ReplyKind::ManualTimestamp => Reply::ManualTimestamp(ManualTimestamp {
                offset: r.float(),
                dfreq_ppm: r.float(),
                new_afreq_ppm: r.float(),
            }),
            ReplyKind::ManualList => {
                let n = (r.u32() as usize).min(MANUAL_LIST_SAMPLES);
                Reply::ManualList(
                    (0..n)
                        .map(|_| ManualSample {
                            when: r.timespec(),
                            slewed_offset: r.float(),
                            orig_offset: r.float(),
                            residual: r.float(),
                        })
                        .collect(),
                )
            }
            ReplyKind::NtpSourceName => {
                let name: [u8; 256] = r.bytes();
                let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
                Reply::NtpSourceName(String::from_utf8_lossy(&name[..end]).into_owned())
            }
            ReplyKind::AuthData => Reply::AuthData(AuthData {
                mode: AuthMode::from(r.u16()),
                key_type: r.u16(),
                key_id: r.u32(),
                key_length: r.u16(),
                ke_attempts: r.u16(),
                last_ke_ago: r.u32(),
                cookies: r.u16(),
                cookie_length: r.u16(),
                nak: r.u16() != 0,
            }),
            ReplyKind::ClientAccesses => {
                let n_indices = r.u32();
                let next_index = r.u32();
                let n = (r.u32() as usize).min(CLIENT_ACCESSES);
                let clients = (0..n)
                    .map(|_| ClientAccess {
                        address: r.address(),
                        ntp_hits: r.u32(),
                        nke_hits: r.u32(),
                        cmd_hits: r.u32(),
                        ntp_drops: r.u32(),
                        nke_drops: r.u32(),
                        cmd_drops: r.u32(),
                        ntp_interval: r.i8(),
                        nke_interval: r.i8(),
                        cmd_interval: r.i8(),
                        ntp_timeout_interval: r.i8(),
                        last_ntp_hit_ago: r.u32(),
                        last_nke_hit_ago: r.u32(),
                        last_cmd_hit_ago: r.u32(),
                    })
                    .collect();
                Reply::ClientAccesses(ClientAccesses {
                    n_indices,
                    next_index,
                    clients,
                })
            }
            ReplyKind::SelectData => Reply::SelectData(SelectData {
                ref_id: r.u32(),
                address: r.address(),
                state: r.u8() as char,
                authentication: r.u8() != 0,
                leap: r.u8(),
                conf_options: SelectOptions(r.skip(1).u16()),
                eff_options: SelectOptions(r.u16()),
                last_sample_ago: r.u32(),
                score: r.float(),
                lo_limit: r.float(),
                hi_limit: r.float(),
            }),
            ReplyKind::ServerStats2 | ReplyKind::ServerStats3 => {
                let mut stats = ServerStats {
                    ntp_hits: r.u32().into(),
                    nke_hits: r.u32().into(),
                    cmd_hits: r.u32().into(),
                    ntp_drops: r.u32().into(),
                    nke_drops: r.u32().into(),
                    cmd_drops: r.u32().into(),
                    log_drops: r.u32().into(),
                    ntp_auth_hits: r.u32().into(),
                    ..ServerStats::default()
                };
                if kind == ReplyKind::ServerStats3 {
                    stats.ntp_interleaved_hits = r.u32().into();
                    stats.ntp_timestamps = r.u32().into();
                    stats.ntp_span_seconds = r.u32().into();
                }
                Reply::ServerStats(stats)
            }
            ReplyKind::ServerStats => Reply::ServerStats(ServerStats {
                ntp_hits: r.u64(),
                nke_hits: r.u64(),
                cmd_hits: r.u64(),
                ntp_drops: r.u64(),
                nke_drops: r.u64(),
                cmd_drops: r.u64(),
                log_drops: r.u64(),
                ntp_auth_hits: r.u64(),
                ntp_interleaved_hits: r.u64(),
                ntp_timestamps: r.u64(),
                ntp_span_seconds: r.u64(),
                ntp_daemon_rx_timestamps: r.u64(),
                ntp_daemon_tx_timestamps: r.u64(),
                ntp_kernel_rx_timestamps: r.u64(),
                ntp_kernel_tx_timestamps: r.u64(),
                ntp_hw_rx_timestamps: r.u64(),
                ntp_hw_tx_timestamps: r.u64(),
            }),
            ReplyKind::NtpData | ReplyKind::NtpDataV1 => Reply::NtpData(NtpData {
                remote_address: r.address(),
                local_address: r.address(),
                remote_port: r.u16(),
                leap: r.u8(),
                version: r.u8(),
                mode: r.u8(),
                stratum: r.u8(),
                poll: r.i8(),
                precision: r.i8(),
                root_delay: r.float(),
                root_dispersion: r.float(),
                ref_id: r.u32(),
                ref_time: r.timespec(),
                offset: r.float(),
                peer_delay: r.float(),
                peer_dispersion: r.float(),
                response_time: r.float(),
                jitter_asymmetry: r.float(),
                flags: r.u16(),
                tx_timestamping: r.u8() as char,
                rx_timestamping: r.u8() as char,
                total_tx_count: r.u32(),
                total_rx_count: r.u32(),
                total_valid_count: r.u32(),
                // Reserved (0) before chronyd 4.3.
                total_good_count: r.u32(),
                // Not in the older form: 0.
                total_kernel_tx_ts: current(kind, &mut r),
                total_kernel_rx_ts: current(kind, &mut r),
                total_hw_tx_ts: current(kind, &mut r),
                total_hw_rx_ts: current(kind, &mut r),
            }),
        }
    }
}

/// A field of the current `ntpdata`, 0 in its older form.
fn current(kind: ReplyKind, r: &mut Reader) -> u32 {
    if kind == ReplyKind::NtpData {
        r.u32()
    } else {
        0
    }
}

/// A reply's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyHeader {
    /// The command answered.
    pub command: u16,
    /// The reply type.
    pub reply: u16,
    /// Whether the command was carried out.
    pub status: Status,
    /// The sequence number of the request.
    pub sequence: u32,
}

impl ReplyHeader {
    /// The header of `packet`, if it is a reply of this protocol version.
    pub fn parse(packet: &[u8]) -> Result<ReplyHeader, Error> {
        if packet.len() < HEADER_LEN {
            return Err(Error::Malformed("reply shorter than its header"));
        }
        if packet[1] != PKT_TYPE_REPLY {
            return Err(Error::Malformed("not a reply"));
        }
        if packet[0] != PROTOCOL_VERSION {
            return Err(Error::Version(packet[0]));
        }
        let mut r = Reader::new(&packet[4..HEADER_LEN]);
        let command = r.u16();
        let reply = r.u16();
        let status = Status::from(r.u16());
        let sequence = r.skip(6).u32();
        Ok(ReplyHeader {
            command,
            reply,
            status,
            sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply packet of `kind` to `request`, its data `data` padded with
    /// zeros to the kind's length.
    fn packet(
        request: &Request,
        kind: ReplyKind,
        status: u16,
        sequence: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![PROTOCOL_VERSION, PKT_TYPE_REPLY, 0, 0];
        packet.extend_from_slice(&request.code().to_be_bytes());
        packet.extend_from_slice(&kind.code().to_be_bytes());
        packet.extend_from_slice(&status.to_be_bytes());
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(data);
        packet.resize(packet.len().max(kind.length()), 0);
        packet
    }

    #[test]
    fn every_kind_has_chronyds_length_and_code() {
        // chronyd's pktlength.c, header included.
        let lengths = [
            (ReplyKind::Null, 1, 28),
            (ReplyKind::NSources, 2, 32),
            (ReplyKind::SourceData, 3, 76),
            (ReplyKind::Tracking, 5, 104),
            (ReplyKind::Sourcestats, 6, 84),
            (ReplyKind::Rtc, 7, 56),
            (ReplyKind::Activity, 12, 48),
            (ReplyKind::Smoothing, 13, 52),
            (ReplyKind::ManualTimestamp, 17, 40),
            (ReplyKind::ManualList, 18, 416),
            (ReplyKind::NtpSourceName, 19, 284),
            (ReplyKind::AuthData, 20, 52),
            (ReplyKind::ClientAccesses, 21, 520),
            (ReplyKind::SelectData, 23, 76),
            (ReplyKind::ServerStats, 25, 196),
            (ReplyKind::NtpData, 26, 172),
            // Older forms, from chronyd 4.0 to 4.5.
            (ReplyKind::NtpDataV1, 16, 152),
            (ReplyKind::ServerStats2, 22, 60),
            (ReplyKind::ServerStats3, 24, 72),
        ];
        assert_eq!(lengths.len(), ReplyKind::ALL.len());
        for (kind, code, length) in lengths {
            assert_eq!(kind.code(), code, "{kind:?}");
            assert_eq!(kind.length(), length, "{kind:?}");
            assert_eq!(ReplyKind::from_code(code), Some(kind));
        }
        // Replies of earlier protocol versions.
        for retired in [4, 8, 9, 10, 11, 14, 15, 27] {
            assert_eq!(ReplyKind::from_code(retired), None);
        }
    }

    #[test]
    fn a_reply_is_checked_against_its_request() {
        let request = Request::NSources;
        let ok = packet(&request, ReplyKind::NSources, 0, 7, &3u32.to_be_bytes());
        assert_eq!(Reply::decode(&request, 7, &ok).unwrap(), Reply::NSources(3));
        // Another request's answer.
        assert!(matches!(
            Reply::decode(&request, 8, &ok),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            Reply::decode(&Request::Tracking, 7, &ok),
            Err(Error::Malformed(_))
        ));
        // The right command, the wrong kind of reply.
        let wrong = packet(&request, ReplyKind::Tracking, 0, 7, &[]);
        assert!(matches!(
            Reply::decode(&request, 7, &wrong),
            Err(Error::Malformed(_))
        ));
        // Refused.
        let refused = packet(&request, ReplyKind::Null, 2, 7, &[]);
        assert!(matches!(
            Reply::decode(&request, 7, &refused),
            Err(Error::Status(Status::Unauthorised))
        ));
        // Another protocol version, or not a reply.
        let mut old = ok.clone();
        old[0] = 5;
        assert!(matches!(
            Reply::decode(&request, 7, &old),
            Err(Error::Version(5))
        ));
        let mut not_reply = ok.clone();
        not_reply[1] = 1;
        assert!(matches!(
            Reply::decode(&request, 7, &not_reply),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn a_reply_shorter_than_its_kind_is_refused() {
        let request = Request::Tracking;
        let full = packet(&request, ReplyKind::Tracking, 0, 1, &[]);
        for length in [0, 10, HEADER_LEN, full.len() - 1] {
            assert!(
                matches!(
                    Reply::decode(&request, 1, &full[..length]),
                    Err(Error::Malformed(_))
                ),
                "{length}"
            );
        }
        assert!(Reply::decode(&request, 1, &full).is_ok());
    }

    #[test]
    fn counts_beyond_the_room_are_capped() {
        let mut data = 100u32.to_be_bytes().to_vec();
        data.resize(4 + MANUAL_LIST_SAMPLES * 24, 0);
        let list = packet(&Request::ManualList, ReplyKind::ManualList, 0, 1, &data);
        let Reply::ManualList(samples) = Reply::decode(&Request::ManualList, 1, &list).unwrap()
        else {
            panic!("manual list");
        };
        assert_eq!(samples.len(), MANUAL_LIST_SAMPLES);

        let request = Request::ClientAccesses {
            first_index: 0,
            n_clients: 8,
            min_hits: 0,
            reset: false,
        };
        let mut data = Vec::new();
        for value in [20u32, 8, 50] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        let clients = packet(&request, ReplyKind::ClientAccesses, 0, 1, &data);
        let Reply::ClientAccesses(batch) = Reply::decode(&request, 1, &clients).unwrap() else {
            panic!("clients");
        };
        assert_eq!(batch.clients.len(), CLIENT_ACCESSES);
        assert_eq!((batch.n_indices, batch.next_index), (20, 8));
    }

    #[test]
    fn a_source_name_ends_at_its_nul_or_its_room() {
        let request = Request::NtpSourceName(Address::Unspecified);
        let named = packet(
            &request,
            ReplyKind::NtpSourceName,
            0,
            1,
            b"pool.ntp.org\0junk",
        );
        assert_eq!(
            Reply::decode(&request, 1, &named).unwrap(),
            Reply::NtpSourceName("pool.ntp.org".into())
        );
        let full = packet(&request, ReplyKind::NtpSourceName, 0, 1, &[b'a'; 256]);
        let Reply::NtpSourceName(name) = Reply::decode(&request, 1, &full).unwrap() else {
            panic!("name");
        };
        assert_eq!(name.len(), 256);
    }

    #[test]
    fn smoothing_flags_and_select_options() {
        let mut data = 3u32.to_be_bytes().to_vec();
        data.extend_from_slice(&0x0480_0000u32.to_be_bytes());
        let smoothing = packet(&Request::Smoothing, ReplyKind::Smoothing, 0, 1, &data);
        let Reply::Smoothing(s) = Reply::decode(&Request::Smoothing, 1, &smoothing).unwrap() else {
            panic!("smoothing");
        };
        assert!(s.active && s.leap_only);
        assert_eq!(s.offset, 1.0);

        let mut data = vec![0; 24];
        data.extend_from_slice(&[b'*', 1, 0, 0, 0, 0x6, 0, 0x2]);
        let request = Request::SelectData { index: 0 };
        let select = packet(&request, ReplyKind::SelectData, 0, 1, &data);
        let Reply::SelectData(s) = Reply::decode(&request, 1, &select).unwrap() else {
            panic!("select data");
        };
        assert_eq!(s.state, '*');
        assert!(s.authentication);
        assert!(s
            .conf_options
            .contains(SelectOptions::PREFER | SelectOptions::TRUST));
        assert_eq!(s.eff_options, SelectOptions::PREFER);
    }

    #[test]
    fn statuses_round_trip() {
        for code in 0..32 {
            let status = Status::from(code);
            assert_eq!(status.code(), code);
            assert!(!status.to_string().is_empty());
        }
    }

    #[test]
    fn older_forms_decode_as_the_current_one() {
        let request = Request::ServerStats;
        let counters: Vec<u8> = (1..=11u32).flat_map(u32::to_be_bytes).collect();
        let v2 = packet(&request, ReplyKind::ServerStats2, 0, 1, &counters[..32]);
        let Reply::ServerStats(s) = Reply::decode(&request, 1, &v2).unwrap() else {
            panic!("server stats 2");
        };
        assert_eq!((s.ntp_hits, s.ntp_auth_hits, s.ntp_timestamps), (1, 8, 0));
        let v3 = packet(&request, ReplyKind::ServerStats3, 0, 1, &counters);
        let Reply::ServerStats(s) = Reply::decode(&request, 1, &v3).unwrap() else {
            panic!("server stats 3");
        };
        assert_eq!((s.ntp_interleaved_hits, s.ntp_span_seconds), (9, 11));

        let request = Request::NtpData(Address::Unspecified);
        let mut data = vec![0u8; 124];
        data[104..108].copy_from_slice(&7u32.to_be_bytes());
        data[108..112].copy_from_slice(&9u32.to_be_bytes());
        let v1 = packet(&request, ReplyKind::NtpDataV1, 0, 1, &data);
        let Reply::NtpData(d) = Reply::decode(&request, 1, &v1).unwrap() else {
            panic!("ntp data 1");
        };
        assert_eq!((d.total_valid_count, d.total_good_count), (7, 9));
        assert_eq!(d.total_hw_rx_ts, 0);
        // But only for the request whose reply it is.
        assert!(Reply::decode(&Request::Tracking, 1, &v1).is_err());
    }
}
