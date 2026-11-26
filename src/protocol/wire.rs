//! The protocol's field encodings: integers in network byte order, its own
//! 32-bit float, timespecs, IP addresses and 64-bit integers split in two.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::SystemTime;

use super::Address;

/// The length of the protocol's IP address record: 16 bytes of address, a
/// 16-bit family and 16 bits of padding.
pub(crate) const IP_ADDR_LEN: usize = 20;

/// Address families of the IP address record.
pub(crate) mod family {
    pub const UNSPEC: u16 = 0;
    pub const INET4: u16 = 1;
    pub const INET6: u16 = 2;
    pub const ID: u16 = 3;
}

/// A timespec's high half of seconds meaning "none" (32-bit seconds).
const TV_NOHIGHSEC: u32 = 0x7fff_ffff;

const COEF_BITS: i32 = 25;
const EXP_BITS: i32 = 7;
const EXP_MIN: i32 = -(1 << (EXP_BITS - 1));
const EXP_MAX: i32 = (1 << (EXP_BITS - 1)) - 1;
const COEF_MAX: i64 = (1 << (COEF_BITS - 1)) - 1;

/// Decodes the protocol's 32-bit float: a 7-bit signed exponent and a 25-bit
/// signed coefficient, worth `coefficient * 2^(exponent - 25)`.
pub fn decode_float(word: u32) -> f64 {
    let mut exponent = (word >> COEF_BITS) as i32;
    if exponent > EXP_MAX {
        exponent -= 1 << EXP_BITS;
    }
    let mut coefficient = (word & ((1 << COEF_BITS) - 1)) as i32;
    if coefficient > COEF_MAX as i32 {
        coefficient -= 1 << COEF_BITS;
    }
    f64::from(coefficient) * 2f64.powi(exponent - COEF_BITS)
}

/// Encodes `x` as the protocol's 32-bit float, as chronyd and chronyc do (to
/// the bit): rounded to 25 bits then truncated to 24 when the magnitude is
/// at least 1; magnitudes beyond about 2^62 saturate, below about 2^-88
/// become zero, as do NaNs.
pub fn encode_float(x: f64) -> u32 {
    let negative = x < 0.0;
    let magnitude = x.abs();
    let neg = i64::from(negative);
    let (exponent, coefficient) = if magnitude.is_nan() || magnitude < 1e-100 {
        (0, 0)
    } else if magnitude > 1e100 {
        (EXP_MAX, COEF_MAX + neg)
    } else {
        // log2 rounded toward zero, plus one; the coefficient rounded, then
        // halved (truncating) while too large.
        let mut exponent = (magnitude.ln() / 2f64.ln() + 1.0) as i32;
        let mut coefficient = (magnitude * 2f64.powi(COEF_BITS - exponent) + 0.5) as i64;
        while coefficient > COEF_MAX + neg {
            coefficient >>= 1;
            exponent += 1;
        }
        if exponent > EXP_MAX {
            (EXP_MAX, COEF_MAX + neg)
        } else if exponent < EXP_MIN {
            if exponent + COEF_BITS >= EXP_MIN {
                (EXP_MIN, coefficient >> (EXP_MIN - exponent))
            } else {
                (0, 0)
            }
        } else {
            (exponent, coefficient)
        }
    };
    let coefficient = if negative { -coefficient } else { coefficient };
    ((exponent as u32 & ((1 << EXP_BITS) - 1)) << COEF_BITS)
        | (coefficient as u32 & ((1 << COEF_BITS) - 1))
}

/// Appends fields to a request.
#[derive(Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }

    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn i32(&mut self, value: i32) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub(crate) fn float(&mut self, value: f64) -> &mut Self {
        self.u32(encode_float(value))
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.0.extend_from_slice(value);
        self
    }

    pub(crate) fn zeros(&mut self, n: usize) -> &mut Self {
        self.0.resize(self.0.len() + n, 0);
        self
    }

    /// An IP address record; `None` is the unspecified family (all
    /// addresses, or none, depending on the command).
    pub(crate) fn ip(&mut self, ip: Option<IpAddr>) -> &mut Self {
        let mut addr = [0u8; 16];
        let family = match ip {
            None => family::UNSPEC,
            Some(IpAddr::V4(v4)) => {
                addr[..4].copy_from_slice(&v4.octets());
                family::INET4
            }
            Some(IpAddr::V6(v6)) => {
                addr.copy_from_slice(&v6.octets());
                family::INET6
            }
        };
        self.bytes(&addr).u16(family).u16(0)
    }

    /// An address record for a source known by its reference ID only.
    pub(crate) fn address(&mut self, address: &Address) -> &mut Self {
        match *address {
            Address::Unspecified => self.ip(None),
            Address::Ip(ip) => self.ip(Some(ip)),
            Address::Id(id) => self.u32(id).zeros(12).u16(family::ID).u16(0),
        }
    }

    /// A timespec; times before the epoch are sent as the epoch.
    pub(crate) fn timespec(&mut self, time: SystemTime) -> &mut Self {
        let since = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = since.as_secs();
        self.u32((secs >> 32) as u32)
            .u32(secs as u32)
            .u32(since.subsec_nanos())
    }
}

/// Reads the fields of a reply's data, whose length was checked against
/// its type first: reads never go past the end.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        if let Some(slice) = self.data.get(self.at..self.at + N) {
            bytes.copy_from_slice(slice);
        }
        self.at += N;
        bytes
    }

    pub(crate) fn skip(&mut self, n: usize) -> &mut Self {
        self.at += n;
        self
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    pub(crate) fn i8(&mut self) -> i8 {
        self.u8() as i8
    }

    pub(crate) fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take())
    }

    pub(crate) fn i16(&mut self) -> i16 {
        self.u16() as i16
    }

    pub(crate) fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    pub(crate) fn i32(&mut self) -> i32 {
        self.u32() as i32
    }

    /// A 64-bit integer, high half first.
    pub(crate) fn u64(&mut self) -> u64 {
        (u64::from(self.u32()) << 32) | u64::from(self.u32())
    }

    pub(crate) fn float(&mut self) -> f64 {
        decode_float(self.u32())
    }

    pub(crate) fn bytes<const N: usize>(&mut self) -> [u8; N] {
        self.take()
    }

    pub(crate) fn address(&mut self) -> Address {
        let addr: [u8; 16] = self.take();
        let family = self.u16();
        self.skip(2);
        match family {
            family::INET4 => Address::Ip(IpAddr::V4(Ipv4Addr::new(
                addr[0], addr[1], addr[2], addr[3],
            ))),
            family::INET6 => Address::Ip(IpAddr::V6(Ipv6Addr::from(addr))),
            family::ID => Address::Id(u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]])),
            _ => Address::Unspecified,
        }
    }

    /// A timespec: seconds (high half first) and nanoseconds since the
    /// epoch.
    pub(crate) fn timespec(&mut self) -> SystemTime {
        let high = self.u32();
        let low = self.u32();
        let nanos = self.u32().min(999_999_999);
        let secs = if high == TV_NOHIGHSEC {
            u64::from(low)
        } else {
            (u64::from(high) << 32) | u64::from(low)
        };
        // Out of the platform's range (malformed): the epoch, chronyd's
        // "never".
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(secs, nanos))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_floats() {
        assert_eq!(decode_float(0), 0.0);
        // 2^23 * 2^(2 - 25)
        assert_eq!(decode_float(0x0480_0000), 1.0);
        assert_eq!(decode_float(0x0580_0000), -1.0);
        // 2^23 * 2^(-8 - 25)
        assert_eq!(decode_float(0xf080_0000), 1.0 / 1024.0);
        assert_eq!(encode_float(1.0), 0x0480_0000);
        // A negative coefficient goes one lower than a positive one: chronyd
        // encodes -1 as -2^24 * 2^(1 - 25).
        assert_eq!(encode_float(-1.0), 0x0300_0000);
        assert_eq!(decode_float(0x0300_0000), -1.0);
        assert_eq!(encode_float(1.0 / 1024.0), 0xf080_0000);
    }

    #[test]
    fn float_edges() {
        assert_eq!(encode_float(0.0), 0);
        assert_eq!(encode_float(-0.0), 0);
        assert_eq!(encode_float(f64::NAN), 0);
        assert_eq!(encode_float(1e-120), 0);
        // Saturates at the largest exponent and coefficient.
        assert_eq!(
            decode_float(encode_float(f64::INFINITY)),
            16_777_215.0 * 2f64.powi(38)
        );
        assert_eq!(
            decode_float(encode_float(f64::NEG_INFINITY)),
            -16_777_216.0 * 2f64.powi(38)
        );
        // The smallest exponent keeps fewer significant bits, then none.
        let tiny = 2f64.powi(-80);
        assert_eq!(decode_float(encode_float(tiny)), tiny);
        assert_eq!(encode_float(2f64.powi(-95)), 0);
    }

    #[test]
    fn floats_round_to_nearest() {
        for x in [0.1, -0.1, 3.0e-9, 1234.5678, -7.25e5, 0.000_292_523, 1030.1] {
            let back = decode_float(encode_float(x));
            assert!(
                ((back - x) / x).abs() <= 2f64.powi(-24),
                "{x} came back as {back}"
            );
        }
    }

    #[test]
    fn addresses() {
        let mut w = Writer::default();
        w.ip(Some("192.0.2.1".parse().unwrap()))
            .ip(Some("2001:db8::1".parse().unwrap()))
            .ip(None)
            .address(&Address::Id(0x4750_5300));
        assert_eq!(w.0.len(), 4 * IP_ADDR_LEN);
        assert_eq!(&w.0[..4], &[192, 0, 2, 1]);
        assert_eq!(&w.0[16..18], &[0, 1]);
        assert_eq!(&w.0[36..38], &[0, 2]);
        let mut r = Reader::new(&w.0);
        assert_eq!(r.address().to_string(), "192.0.2.1");
        assert_eq!(r.address().to_string(), "2001:db8::1");
        assert_eq!(r.address(), Address::Unspecified);
        assert_eq!(r.address(), Address::Id(0x4750_5300));
    }

    #[test]
    fn timespecs() {
        let time = SystemTime::UNIX_EPOCH + Duration::new(0x1_2345_6789, 42);
        let mut w = Writer::default();
        w.timespec(time);
        assert_eq!(w.0, [0, 0, 0, 1, 0x23, 0x45, 0x67, 0x89, 0, 0, 0, 42]);
        assert_eq!(Reader::new(&w.0).timespec(), time);
        // 32-bit seconds only.
        let old = [0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 10, 0, 0, 0, 0];
        assert_eq!(
            Reader::new(&old).timespec(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(10)
        );
    }

    #[test]
    fn a_timespec_out_of_range_is_the_epoch() {
        let huge = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
        assert_eq!(Reader::new(&huge).timespec(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn a_short_reader_reads_zeros() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u32(), 0);
        assert_eq!(r.u64(), 0);
    }

    #[test]
    fn integers() {
        let mut w = Writer::default();
        w.u8(0xfe).u16(0xbeef).i32(-2).u32(7);
        let mut r = Reader::new(&w.0);
        assert_eq!(r.i8(), -2);
        assert_eq!(r.i16(), 0xbeef_u16 as i16);
        assert_eq!(r.i32(), -2);
        assert_eq!(r.u32(), 7);
        let int64 = [0, 0, 0, 1, 0, 0, 0, 2];
        assert_eq!(Reader::new(&int64).u64(), (1 << 32) | 2);
    }
}
