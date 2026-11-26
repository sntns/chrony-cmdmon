//! chronyd's command and monitoring protocol, version 6 (chrony 4.x):
//! requests encoded and replies decoded, without I/O.
//!
//! Every packet is a fixed-size binary record in network byte order. A
//! request is padded to at least the length of its reply, so that chronyd
//! never answers with more bytes than it received.

mod reply;
mod request;
pub mod wire;

pub use reply::*;
pub use request::*;

use std::net::IpAddr;

/// The protocol version this crate speaks (chrony 4.x).
pub const PROTOCOL_VERSION: u8 = 6;

/// Whether chronyd carried out a command (`STT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// The command was carried out (`STT_SUCCESS`).
    Success,
    /// The command failed (`STT_FAILED`).
    Failed,
    /// A privileged command over UDP.
    Unauthorised,
    /// Unknown command, or not supported by this chronyd (`STT_INVALID`).
    Invalid,
    /// No source with that address (`STT_NOSUCHSOURCE`).
    NoSuchSource,
    /// Stale or duplicate timestamp (`STT_INVALIDTS`).
    InvalidTimestamp,
    /// The facility is not enabled in chronyd (`STT_NOTENABLED`).
    NotEnabled,
    /// Invalid subnet (`STT_BADSUBNET`).
    BadSubnet,
    /// `accheck`/`cmdaccheck`: access allowed (`STT_ACCESSALLOWED`).
    AccessAllowed,
    /// `accheck`/`cmdaccheck`: access denied (`STT_ACCESSDENIED`).
    AccessDenied,
    /// The source is already known (`STT_SOURCEALREADYKNOWN`).
    SourceAlreadyKnown,
    /// No room for another source (`STT_TOOMANYSOURCES`).
    TooManySources,
    /// The RTC driver is not running (`STT_NORTC`).
    NoRtc,
    /// The RTC parameters could not be written (`STT_BADRTCFILE`).
    BadRtcFile,
    /// The facility is not active (`STT_INACTIVE`).
    Inactive,
    /// Manual sample index out of range (`STT_BADSAMPLE`).
    BadSample,
    /// Address family not supported (`STT_INVALIDAF`).
    InvalidAddressFamily,
    /// Protocol version mismatch (`STT_BADPKTVERSION`).
    BadPacketVersion,
    /// Bad packet length (`STT_BADPKTLENGTH`).
    BadPacketLength,
    /// Invalid source name (`STT_INVALIDNAME`).
    InvalidName,
    /// A status this crate does not know.
    Other(u16),
}

impl Status {
    /// The status code.
    pub fn code(self) -> u16 {
        match self {
            Status::Success => 0,
            Status::Failed => 1,
            Status::Unauthorised => 2,
            Status::Invalid => 3,
            Status::NoSuchSource => 4,
            Status::InvalidTimestamp => 5,
            Status::NotEnabled => 6,
            Status::BadSubnet => 7,
            Status::AccessAllowed => 8,
            Status::AccessDenied => 9,
            Status::SourceAlreadyKnown => 11,
            Status::TooManySources => 12,
            Status::NoRtc => 13,
            Status::BadRtcFile => 14,
            Status::Inactive => 15,
            Status::BadSample => 16,
            Status::InvalidAddressFamily => 17,
            Status::BadPacketVersion => 18,
            Status::BadPacketLength => 19,
            Status::InvalidName => 21,
            Status::Other(code) => code,
        }
    }
}

impl From<u16> for Status {
    fn from(code: u16) -> Self {
        match code {
            0 => Status::Success,
            1 => Status::Failed,
            2 => Status::Unauthorised,
            3 => Status::Invalid,
            4 => Status::NoSuchSource,
            5 => Status::InvalidTimestamp,
            6 => Status::NotEnabled,
            7 => Status::BadSubnet,
            8 => Status::AccessAllowed,
            9 => Status::AccessDenied,
            11 => Status::SourceAlreadyKnown,
            12 => Status::TooManySources,
            13 => Status::NoRtc,
            14 => Status::BadRtcFile,
            15 => Status::Inactive,
            16 => Status::BadSample,
            17 => Status::InvalidAddressFamily,
            18 => Status::BadPacketVersion,
            19 => Status::BadPacketLength,
            21 => Status::InvalidName,
            other => Status::Other(other),
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // chronyc's wording
        let text = match self {
            Status::Success => "Success",
            Status::Failed => "Failed",
            Status::Unauthorised => "Not authorised",
            Status::Invalid => "Invalid command",
            Status::NoSuchSource => "No such source",
            Status::InvalidTimestamp => "Duplicate or stale logon detected",
            Status::NotEnabled => "Facility not enabled in daemon",
            Status::BadSubnet => "Bad subnet",
            Status::AccessAllowed => "Access allowed",
            Status::AccessDenied => "Access denied",
            Status::SourceAlreadyKnown => "Source already present",
            Status::TooManySources => "Too many sources present",
            Status::NoRtc => "RTC driver not running",
            Status::BadRtcFile => "Can't write RTC parameters",
            Status::Inactive => "Facility not active",
            Status::BadSample => "Sample index out of range",
            Status::InvalidAddressFamily => "Invalid address family",
            Status::BadPacketVersion => "Protocol version mismatch",
            Status::BadPacketLength => "Bad packet length",
            Status::InvalidName => "Invalid name",
            Status::Other(code) => return write!(f, "Unknown status {code}"),
        };
        f.write_str(text)
    }
}

/// An address as chronyd reports it: an IP address, or the reference ID of
/// a source without one (a reference clock, a source not resolved yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// No address.
    Unspecified,
    /// An IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A reference ID (a source without an address).
    Id(u32),
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        Address::Ip(ip)
    }
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

/// A reference ID as chronyc shows it for reference clocks: up to 4 ASCII
/// characters (`GPS`, `PPS`).
pub fn ref_id_name(ref_id: u32) -> String {
    ref_id
        .to_be_bytes()
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| {
            if b.is_ascii_graphic() {
                *b as char
            } else {
                '?'
            }
        })
        .collect()
}
