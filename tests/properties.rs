//! Properties over arbitrary values: floats survive the protocol's
//! encoding to its precision, encoding never fails on a valid request, and
//! decoding never panics, whatever the bytes.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::time::Duration;
use std::time::SystemTime;

use chrony_cmdmon::protocol::wire::decode_float;
use chrony_cmdmon::protocol::wire::encode_float;
use chrony_cmdmon::*;
use proptest::prelude::*;

/// The magnitudes the protocol's float holds without saturating or
/// losing bits to the smallest exponent.
fn normal_float() -> impl Strategy<Value = f64> {
    (-60i32..60, 1.0f64..2.0, any::<bool>())
        .prop_map(|(exp, mantissa, neg)| if neg { -1.0 } else { 1.0 } * mantissa * 2f64.powi(exp))
}

fn ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|o| IpAddr::V4(Ipv4Addr::from(o))),
        any::<[u8; 16]>().prop_map(|o| IpAddr::V6(Ipv6Addr::from(o))),
    ]
}

fn address() -> impl Strategy<Value = Address> {
    prop_oneof![
        Just(Address::Unspecified),
        ip().prop_map(Address::Ip),
        any::<u32>().prop_map(Address::Id),
    ]
}

fn selection() -> impl Strategy<Value = SourceSelection> {
    prop_oneof![
        Just(SourceSelection::All),
        (ip(), ip()).prop_map(|(address, mask)| SourceSelection::Matching { address, mask }),
    ]
}

fn subnet() -> impl Strategy<Value = Subnet> {
    (proptest::option::of(ip()), any::<u8>()).prop_map(|(ip, bits)| Subnet { ip, bits })
}

fn source() -> impl Strategy<Value = NtpSource> {
    (
        "[a-z0-9.-]{1,255}",
        any::<(u32, i32, i32, u32, u32)>(),
        any::<(f64, f64, f64, u32)>(),
    )
        .prop_map(
            |(name, (port, minpoll, maxpoll, authkey, flags), (delay, ratio, offset, cert))| {
                NtpSource {
                    name,
                    port,
                    minpoll,
                    maxpoll,
                    authkey,
                    flags: SourceFlags(flags),
                    max_delay: delay,
                    max_delay_ratio: ratio,
                    offset,
                    cert_set: cert,
                    ..NtpSource::default()
                }
            },
        )
}

/// Every kind of request, with arbitrary values.
fn request() -> impl Strategy<Value = Request> {
    let f = any::<f64>;
    prop_oneof![
        selection().prop_map(Request::Online),
        selection().prop_map(Request::Offline),
        (selection(), any::<u32>(), any::<u32>()).prop_map(|(selection, n_good, n_total)| {
            Request::Burst {
                selection,
                n_good,
                n_total,
            }
        }),
        (address(), any::<i32>())
            .prop_map(|(address, minpoll)| Request::ModifyMinpoll { address, minpoll }),
        (address(), f())
            .prop_map(|(address, max_delay)| Request::ModifyMaxdelay { address, max_delay }),
        (any::<i32>(), f())
            .prop_map(|(limit, threshold)| Request::ModifyMakestep { limit, threshold }),
        any::<u64>()
            .prop_map(|s| Request::Settime(SystemTime::UNIX_EPOCH + Duration::from_secs(s >> 2))),
        (any::<bool>(), any::<i32>(), f(), any::<bool>()).prop_map(
            |(enabled, stratum, distance, orphan)| {
                Request::Local(LocalOptions {
                    enabled,
                    stratum,
                    distance,
                    orphan,
                    ..LocalOptions::default()
                })
            }
        ),
        any::<u32>().prop_map(|index| Request::SourceData { index }),
        subnet().prop_map(Request::Allow),
        subnet().prop_map(Request::CmdDenyAll),
        ip().prop_map(Request::AcCheck),
        source().prop_map(|s| Request::AddSource(Box::new(s))),
        address().prop_map(Request::DelSource),
        f().prop_map(Request::Doffset),
        address().prop_map(Request::NtpData),
        (any::<u32>(), any::<u32>(), any::<u32>(), any::<bool>()).prop_map(
            |(first_index, n_clients, min_hits, reset)| Request::ClientAccesses {
                first_index,
                n_clients,
                min_hits,
                reset
            }
        ),
        (address(), any::<u32>(), any::<u16>(), any::<u16>()).prop_map(
            |(address, ref_id, mask, options)| {
                Request::ModifySelectOpts {
                    address,
                    ref_id,
                    mask: SelectOptions(mask),
                    options: SelectOptions(options),
                }
            }
        ),
        (address(), any::<u32>(), f()).prop_map(|(address, ref_id, offset)| {
            Request::ModifyOffset {
                address,
                ref_id,
                offset,
            }
        }),
        Just(Request::Tracking),
        Just(Request::ManualList),
        Just(Request::ServerStats),
    ]
}

proptest! {
    #[test]
    fn floats_keep_24_significant_bits(x in normal_float()) {
        let back = decode_float(encode_float(x));
        prop_assert!(((back - x) / x).abs() <= 2f64.powi(-23), "{} came back as {}", x, back);
        prop_assert_eq!(back.signum(), x.signum());
    }

    #[test]
    fn any_float_encodes(x in any::<f64>()) {
        let back = decode_float(encode_float(x));
        prop_assert!(back.is_finite());
        if x.is_nan() {
            prop_assert_eq!(back, 0.0);
        }
    }

    #[test]
    fn any_word_decodes_to_a_finite_float(word in any::<u32>()) {
        prop_assert!(decode_float(word).is_finite());
    }

    #[test]
    fn a_request_is_its_header_and_its_padded_data(
        request in request(),
        sequence in any::<u32>(),
        attempt in any::<u16>(),
    ) {
        let packet = request.encode(sequence, attempt).unwrap();
        prop_assert!(packet.len() >= request.reply_kind().length());
        prop_assert!(packet.len() <= 520);
        prop_assert_eq!(&packet[..2], &[6, 1]);
        prop_assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), request.code());
        prop_assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), attempt);
        prop_assert_eq!(u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]), sequence);
    }

    #[test]
    fn arbitrary_bytes_never_panic(request in request(), sequence in any::<u32>(), bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = Reply::decode(&request, sequence, &bytes);
    }

    #[test]
    fn a_valid_header_with_arbitrary_data_decodes(
        request in request(),
        sequence in any::<u32>(),
        data in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let kind = request.reply_kind();
        let mut packet = vec![6, 2, 0, 0];
        packet.extend_from_slice(&request.code().to_be_bytes());
        packet.extend_from_slice(&kind.code().to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&[0; 8]);
        packet.extend_from_slice(&data);
        match Reply::decode(&request, sequence, &packet) {
            Ok(reply) => {
                prop_assert!(packet.len() >= kind.length());
                prop_assert_eq!(reply.kind(), kind);
            }
            Err(Error::Malformed(_)) => prop_assert!(packet.len() < kind.length()),
            Err(e) => prop_assert!(false, "{}", e),
        }
    }
}
