//! chronyd's command and monitoring protocol, version 6: requests encoded and
//! replies decoded, without I/O.
//!
//! Every packet is a fixed-size binary record in network byte order. A
//! request is padded to at least the length of its reply, so that chronyd
//! never answers with more bytes than it received.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::SystemTime;

use crate::Error;

/// The protocol version this crate speaks (chrony 4.x).
pub const PROTOCOL_VERSION: u8 = 6;

const PKT_TYPE_REQUEST: u8 = 1;
const PKT_TYPE_REPLY: u8 = 2;

const REQUEST_HEADER: usize = 20;
const REPLY_HEADER: usize = 28;

/// Request codes.
mod command {
    pub const ONLINE: u16 = 1;
    pub const OFFLINE: u16 = 2;
    pub const BURST: u16 = 3;
    pub const N_SOURCES: u16 = 14;
    pub const SOURCE_DATA: u16 = 15;
    pub const TRACKING: u16 = 33;
    pub const MAKESTEP: u16 = 43;
    pub const RELOAD_SOURCES: u16 = 70;
}

/// Reply codes, and the length of their data after the reply header.
mod reply {
    pub const NULL: (u16, usize) = (1, 0);
    pub const N_SOURCES: (u16, usize) = (2, 4);
    pub const SOURCE_DATA: (u16, usize) = (3, 48);
    pub const TRACKING: (u16, usize) = (5, 76);
}

/// Address families of the protocol's IP address record.
mod family {
    // 0: unspecified (`Sources::All`, an unknown address)
    pub const INET4: u16 = 1;
    pub const INET6: u16 = 2;
    pub const ID: u16 = 3;
}

const IP_ADDR_LEN: usize = 20;

/// Which sources a command applies to: an address and a mask, as chronyc's
/// `burst 4/4 192.168.1.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sources {
    /// Every source.
    All,
    /// The sources whose address matches `address` under `mask`.
    Matching { address: IpAddr, mask: IpAddr },
}

/// A request to chronyd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// The system clock's synchronization (`chronyc tracking`).
    Tracking,
    /// How many sources there are.
    NSources,
    /// The source at `index` (0 to `NSources` - 1), as `chronyc sources`.
    SourceData { index: u32 },
    /// Have sources take `n_good` good samples out of at most `n_total`
    /// quickly (`chronyc burst`).
    Burst {
        sources: Sources,
        n_good: u32,
        n_total: u32,
    },
    /// Sources reachable again (`chronyc online`).
    Online { sources: Sources },
    /// Sources unreachable (`chronyc offline`).
    Offline { sources: Sources },
    /// Step the system clock now, whatever the offset (`chronyc makestep`).
    MakeStep,
    /// Read the `sourcedir` directories again (`chronyc reload sources`).
    ReloadSources,
}

impl Request {
    fn command(&self) -> u16 {
        match self {
            Request::Tracking => command::TRACKING,
            Request::NSources => command::N_SOURCES,
            Request::SourceData { .. } => command::SOURCE_DATA,
            Request::Burst { .. } => command::BURST,
            Request::Online { .. } => command::ONLINE,
            Request::Offline { .. } => command::OFFLINE,
            Request::MakeStep => command::MAKESTEP,
            Request::ReloadSources => command::RELOAD_SOURCES,
        }
    }

    /// The reply code expected, and the length of its data.
    fn reply(&self) -> (u16, usize) {
        match self {
            Request::Tracking => reply::TRACKING,
            Request::NSources => reply::N_SOURCES,
            Request::SourceData { .. } => reply::SOURCE_DATA,
            Request::Burst { .. }
            | Request::Online { .. }
            | Request::Offline { .. }
            | Request::MakeStep
            | Request::ReloadSources => reply::NULL,
        }
    }

    fn data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match *self {
            Request::SourceData { index } => data.extend_from_slice(&index.to_be_bytes()),
            Request::Burst {
                sources,
                n_good,
                n_total,
            } => {
                put_sources(&mut data, sources);
                data.extend_from_slice(&n_good.to_be_bytes());
                data.extend_from_slice(&n_total.to_be_bytes());
            }
            Request::Online { sources } | Request::Offline { sources } => {
                put_sources(&mut data, sources)
            }
            Request::Tracking | Request::NSources | Request::MakeStep | Request::ReloadSources => {}
        }
        data
    }

    /// The request's packet: `attempt` counts the resends of the same
    /// `sequence`.
    pub fn encode(&self, sequence: u32, attempt: u16) -> Vec<u8> {
        let data = self.data();
        let (_, reply_data) = self.reply();
        let length = (REQUEST_HEADER + data.len()).max(REPLY_HEADER + reply_data);
        let mut packet = Vec::with_capacity(length);
        packet.extend_from_slice(&[PROTOCOL_VERSION, PKT_TYPE_REQUEST, 0, 0]);
        packet.extend_from_slice(&self.command().to_be_bytes());
        packet.extend_from_slice(&attempt.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&data);
        packet.resize(length, 0);
        packet
    }
}

fn put_sources(data: &mut Vec<u8>, sources: Sources) {
    match sources {
        Sources::All => data.extend_from_slice(&[0; 2 * IP_ADDR_LEN]),
        Sources::Matching { address, mask } => {
            put_ip(data, mask);
            put_ip(data, address);
        }
    }
}

fn put_ip(data: &mut Vec<u8>, ip: IpAddr) {
    let mut addr = [0u8; 16];
    let family = match ip {
        IpAddr::V4(v4) => {
            addr[..4].copy_from_slice(&v4.octets());
            family::INET4
        }
        IpAddr::V6(v6) => {
            addr.copy_from_slice(&v6.octets());
            family::INET6
        }
    };
    data.extend_from_slice(&addr);
    data.extend_from_slice(&family.to_be_bytes());
    data.extend_from_slice(&[0; 2]);
}

/// Whether chronyd carried out a command (the reply's status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    Failed,
    /// A privileged command over UDP, or without the right key.
    Unauthorised,
    Invalid,
    NoSuchSource,
    NotEnabled,
    Inactive,
    BadPacketVersion,
    BadPacketLength,
    Other(u16),
}

impl From<u16> for Status {
    fn from(code: u16) -> Self {
        match code {
            0 => Status::Success,
            1 => Status::Failed,
            2 => Status::Unauthorised,
            3 => Status::Invalid,
            4 => Status::NoSuchSource,
            6 => Status::NotEnabled,
            15 => Status::Inactive,
            18 => Status::BadPacketVersion,
            19 => Status::BadPacketLength,
            other => Status::Other(other),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Success => f.write_str("success"),
            Status::Failed => f.write_str("failed"),
            Status::Unauthorised => f.write_str("not authorised"),
            Status::Invalid => f.write_str("invalid command"),
            Status::NoSuchSource => f.write_str("no such source"),
            Status::NotEnabled => f.write_str("not enabled"),
            Status::Inactive => f.write_str("inactive"),
            Status::BadPacketVersion => f.write_str("protocol version mismatch"),
            Status::BadPacketLength => f.write_str("bad packet length"),
            Status::Other(code) => write!(f, "status {code}"),
        }
    }
}

/// An address as chronyd reports it: an IP address, or the reference ID of
/// a source without one (a reference clock, a source not resolved yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    Unspecified,
    Ip(IpAddr),
    Id(u32),
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Unspecified => f.write_str("[UNSPEC]"),
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Id(id) => write!(f, "ID#{id:010}"),
        }
    }
}

/// The leap second status of the system clock; `Unsynchronised` while no
/// source vouches for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapStatus {
    Normal,
    InsertSecond,
    DeleteSecond,
    Unsynchronised,
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

/// `chronyc tracking`.
#[derive(Debug, Clone, PartialEq)]
pub struct Tracking {
    /// The reference ID of the source synchronized to (0 when none).
    pub ref_id: u32,
    /// Its address.
    pub address: Address,
    pub stratum: u16,
    pub leap_status: LeapStatus,
    /// When the last measurement from the reference was processed.
    pub ref_time: SystemTime,
    /// How far the system clock is from NTP time (seconds; positive: the
    /// clock is slow), being corrected.
    pub current_correction: f64,
    /// The offset at the last clock update (seconds).
    pub last_offset: f64,
    /// The long-term average of the offset (seconds).
    pub rms_offset: f64,
    /// The rate the clock would be wrong at, uncorrected (ppm; positive:
    /// fast).
    pub freq_ppm: f64,
    pub resid_freq_ppm: f64,
    pub skew_ppm: f64,
    /// Round-trip delay to the stratum-1 source (seconds).
    pub root_delay: f64,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    /// A server (`^`).
    Client,
    /// A peer (`=`).
    Peer,
    /// A reference clock (`#`).
    ReferenceClock,
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

/// What the source selection made of a source (`chronyc sources`' second
/// column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn symbol(&self) -> char {
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
    pub address: Address,
    /// The polling interval, as a power of 2 seconds.
    pub poll: i16,
    pub stratum: u16,
    pub state: SourceState,
    pub mode: SourceMode,
    pub flags: u16,
    /// The last 8 polls, the latest in the lowest bit: answered or not.
    pub reachability: u8,
    /// Since the last sample (seconds).
    pub since_sample: u32,
    /// The last sample's offset as measured (seconds; positive: the local
    /// clock is fast).
    pub orig_latest_meas: f64,
    /// The same, adjusted for the clock's corrections since.
    pub latest_meas: f64,
    /// Its error margin (seconds).
    pub latest_meas_err: f64,
}

/// A reply from chronyd, decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// Done; nothing to report.
    Null,
    NSources(u32),
    SourceData(SourceData),
    Tracking(Tracking),
}

/// The reply header's sequence, if `packet` is long enough to have one: to
/// tell an answer to an earlier attempt from the one awaited.
pub fn reply_sequence(packet: &[u8]) -> Option<u32> {
    packet.get(16..20).map(|b| be_u32(b, 0))
}

impl Reply {
    /// Decodes `packet` as chronyd's answer to `request` sent as `sequence`.
    pub fn decode(request: &Request, sequence: u32, packet: &[u8]) -> Result<Reply, Error> {
        if packet.len() < REPLY_HEADER {
            return Err(Error::Malformed("reply shorter than its header"));
        }
        if packet[1] != PKT_TYPE_REPLY {
            return Err(Error::Malformed("not a reply"));
        }
        if packet[0] != PROTOCOL_VERSION {
            return Err(Error::Version(packet[0]));
        }
        if be_u32(packet, 16) != sequence {
            return Err(Error::Malformed("reply to another request (sequence)"));
        }
        if be_u16(packet, 4) != request.command() {
            return Err(Error::Malformed("reply to another command"));
        }
        let status = Status::from(be_u16(packet, 8));
        if status != Status::Success {
            return Err(Error::Status(status));
        }
        let (code, length) = request.reply();
        if be_u16(packet, 6) != code {
            return Err(Error::Malformed("unexpected reply type"));
        }
        if packet.len() < REPLY_HEADER + length {
            return Err(Error::Malformed("reply shorter than its data"));
        }
        let data = &packet[REPLY_HEADER..];
        Ok(match request {
            Request::NSources => Reply::NSources(be_u32(data, 0)),
            Request::SourceData { .. } => Reply::SourceData(SourceData {
                address: address(&data[0..IP_ADDR_LEN]),
                poll: be_u16(data, 20) as i16,
                stratum: be_u16(data, 22),
                state: SourceState::from(be_u16(data, 24)),
                mode: SourceMode::from(be_u16(data, 26)),
                flags: be_u16(data, 28),
                reachability: be_u16(data, 30) as u8,
                since_sample: be_u32(data, 32),
                orig_latest_meas: float(data, 36),
                latest_meas: float(data, 40),
                latest_meas_err: float(data, 44),
            }),
            Request::Tracking => Reply::Tracking(Tracking {
                ref_id: be_u32(data, 0),
                address: address(&data[4..4 + IP_ADDR_LEN]),
                stratum: be_u16(data, 24),
                leap_status: LeapStatus::from(be_u16(data, 26)),
                ref_time: timespec(data, 28),
                current_correction: float(data, 40),
                last_offset: float(data, 44),
                rms_offset: float(data, 48),
                freq_ppm: float(data, 52),
                resid_freq_ppm: float(data, 56),
                skew_ppm: float(data, 60),
                root_delay: float(data, 64),
                root_dispersion: float(data, 68),
                last_update_interval: float(data, 72),
            }),
            _ => Reply::Null,
        })
    }
}

fn be_u16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The protocol's IP address record: 16 bytes of address, its family.
fn address(record: &[u8]) -> Address {
    match be_u16(record, 16) {
        family::INET4 => Address::Ip(IpAddr::V4(Ipv4Addr::from(be_u32(record, 0)))),
        family::INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&record[..16]);
            Address::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        family::ID => Address::Id(be_u32(record, 0)),
        // family::UNSPEC, or one this crate does not know
        _ => Address::Unspecified,
    }
}

/// Seconds (high and low 32 bits) and nanoseconds since the epoch; a high
/// half of 0x7fffffff means none (32-bit seconds).
fn timespec(data: &[u8], at: usize) -> SystemTime {
    let high = be_u32(data, at);
    let low = be_u32(data, at + 4);
    let nanos = be_u32(data, at + 8).min(999_999_999);
    let secs = if high == 0x7fff_ffff {
        u64::from(low)
    } else {
        (u64::from(high) << 32) | u64::from(low)
    };
    SystemTime::UNIX_EPOCH + Duration::new(secs, nanos)
}

/// The protocol's 32-bit float: a 7-bit signed exponent and a 25-bit signed
/// coefficient, `coefficient * 2^(exponent - 25)`.
fn float(data: &[u8], at: usize) -> f64 {
    decode_float(be_u32(data, at))
}

const COEF_BITS: u32 = 25;
const EXP_BITS: u32 = 7;

pub(crate) fn decode_float(word: u32) -> f64 {
    let mut exponent = (word >> COEF_BITS) as i32;
    if exponent >= 1 << (EXP_BITS - 1) {
        exponent -= 1 << EXP_BITS;
    }
    let mut coefficient = (word & ((1 << COEF_BITS) - 1)) as i32;
    if coefficient >= 1 << (COEF_BITS - 1) {
        coefficient -= 1 << COEF_BITS;
    }
    f64::from(coefficient) * 2f64.powi(exponent - COEF_BITS as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats() {
        assert_eq!(decode_float(0), 0.0);
        // 2^23 * 2^(2 - 25)
        assert_eq!(decode_float(0x0480_0000), 1.0);
        assert_eq!(decode_float(0x0580_0000), -1.0);
        // 2^23 * 2^(-8 - 25) = 2^-10
        assert_eq!(decode_float(0xf080_0000), 1.0 / 1024.0);
    }

    #[test]
    fn requests_are_padded_to_their_reply() {
        let length = |r: Request| r.encode(1, 0).len();
        assert_eq!(length(Request::Tracking), 104);
        assert_eq!(length(Request::NSources), 32);
        assert_eq!(length(Request::SourceData { index: 0 }), 76);
        assert_eq!(length(Request::MakeStep), 28);
        assert_eq!(length(Request::ReloadSources), 28);
        assert_eq!(
            length(Request::Online {
                sources: Sources::All
            }),
            60
        );
        assert_eq!(
            length(Request::Burst {
                sources: Sources::All,
                n_good: 4,
                n_total: 4
            }),
            68
        );
    }

    #[test]
    fn a_request_header() {
        let packet = Request::SourceData { index: 2 }.encode(0x0102_0304, 1);
        assert_eq!(&packet[..12], &[6, 1, 0, 0, 0, 15, 0, 1, 1, 2, 3, 4]);
        assert_eq!(&packet[20..24], &[0, 0, 0, 2]);
        let burst = Request::Burst {
            sources: Sources::All,
            n_good: 4,
            n_total: 8,
        }
        .encode(1, 0);
        assert_eq!(&burst[60..68], &[0, 0, 0, 4, 0, 0, 0, 8]);
    }

    fn reply_packet(command: u16, reply: u16, status: u16, sequence: u32, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![6, 2, 0, 0];
        packet.extend_from_slice(&command.to_be_bytes());
        packet.extend_from_slice(&reply.to_be_bytes());
        packet.extend_from_slice(&status.to_be_bytes());
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(data);
        packet
    }

    #[test]
    fn a_reply_is_checked_against_its_request() {
        let ok = reply_packet(14, 2, 0, 7, &3u32.to_be_bytes());
        assert_eq!(
            Reply::decode(&Request::NSources, 7, &ok).unwrap(),
            Reply::NSources(3)
        );
        assert!(Reply::decode(&Request::NSources, 8, &ok).is_err());
        assert!(Reply::decode(&Request::Tracking, 7, &ok).is_err());
        let refused = reply_packet(70, 1, 2, 7, &[]);
        assert!(matches!(
            Reply::decode(&Request::ReloadSources, 7, &refused),
            Err(Error::Status(Status::Unauthorised))
        ));
        let mut old = ok.clone();
        old[0] = 5;
        assert!(matches!(
            Reply::decode(&Request::NSources, 7, &old),
            Err(Error::Version(5))
        ));
    }

    #[test]
    fn a_source() {
        let mut data = Vec::new();
        put_ip(&mut data, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        for value in [6u16, 2, 0, 0, 0, 0o377] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        data.extend_from_slice(&64u32.to_be_bytes());
        for word in [0x0480_0000u32, 0x0580_0000, 0xf080_0000] {
            data.extend_from_slice(&word.to_be_bytes());
        }
        let packet = reply_packet(15, 3, 0, 9, &data);
        let Reply::SourceData(source) =
            Reply::decode(&Request::SourceData { index: 0 }, 9, &packet).unwrap()
        else {
            panic!("a source");
        };
        assert_eq!(source.address.to_string(), "192.0.2.1");
        assert_eq!(source.poll, 6);
        assert_eq!(source.stratum, 2);
        assert_eq!(source.state.symbol(), '*');
        assert_eq!(source.mode, SourceMode::Client);
        assert_eq!(source.reachability, 0o377);
        assert_eq!(source.since_sample, 64);
        assert_eq!(source.orig_latest_meas, 1.0);
        assert_eq!(source.latest_meas, -1.0);
        assert_eq!(source.latest_meas_err, 1.0 / 1024.0);
    }
}
