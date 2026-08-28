//! The bridge encoding, round-tripped and attacked.
//!
//! Every bound in the module table is exercised here, on this host. That is the
//! point of putting the encoding on this side of the JNI boundary: a payload
//! validator that only runs on a device is a validator nobody has run.

use super::*;
use twinvpn_types::V6Addr;

fn v6(low: u16) -> V6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1] = 0x7c;
    octets[14] = (low >> 8) as u8;
    octets[15] = (low & 0xff) as u8;
    V6Addr::new(octets, None).expect("global v6 needs no zone")
}

fn network() -> AndroidNetwork {
    AndroidNetwork {
        handle: 0x0001_0000_0000_002a,
        name: InterfaceName::new("wlan0").expect("name"),
        transports: TransportSet::from_bits(TransportSet::WIFI),
        addresses: vec![
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([192, 168, 1, 0])), 24).expect("v4"),
            IpPrefix::new(IpAddr::V6(v6(0)), 64).expect("v6"),
        ],
        default_routes: PerFamily::new(true, true),
        resolvers: vec![
            IpAddr::V4(V4Addr::from_octets([192, 168, 1, 1])),
            IpAddr::V6(v6(0x53)),
        ],
        mtu: 1500,
        metered: false,
        nat64: None,
        private_dns_active: true,
        is_up: true,
    }
}

#[test]
fn a_network_round_trips_through_the_wire() {
    let original = network();
    let bytes = encode_network(&original);
    let decoded = decode_network(&bytes).expect("decodes");
    assert_eq!(decoded, original);
}

#[test]
fn an_ipv6_only_network_carries_its_nat64_prefix() {
    let mut original = network();
    original.nat64 = Some(Nat64Prefix::well_known());
    original.default_routes = PerFamily::new(false, true);
    let decoded = decode_network(&encode_network(&original)).expect("decodes");
    assert_eq!(decoded.nat64, Some(Nat64Prefix::well_known()));
    assert_eq!(decoded, original);
}

#[test]
fn every_flag_survives_independently() {
    type Set = fn(&mut AndroidNetwork);
    type Read = fn(&AndroidNetwork) -> bool;
    let cases: [(Set, Read); 5] = [
        (|n| n.is_up = false, |n| !n.is_up),
        (|n| n.metered = true, |n| n.metered),
        (|n| n.private_dns_active = false, |n| !n.private_dns_active),
        (
            |n| n.default_routes = PerFamily::new(false, true),
            |n| !n.default_routes.v4 && n.default_routes.v6,
        ),
        (
            |n| n.default_routes = PerFamily::new(true, false),
            |n| n.default_routes.v4 && !n.default_routes.v6,
        ),
    ];
    for (set, read) in cases {
        let mut original = network();
        set(&mut original);
        let decoded = decode_network(&encode_network(&original)).expect("decodes");
        assert!(read(&decoded), "a flag did not survive the round trip");
    }
}

// ---------------------------------------------------------------------------
// Every bound, refused rather than truncated
// ---------------------------------------------------------------------------

#[test]
fn an_empty_or_oversized_payload_is_refused_before_anything_is_read() {
    assert!(decode_network(&[]).is_err());
    let huge = vec![WIRE_VERSION; MAX_PAYLOAD_BYTES + 1];
    let err = decode_network(&huge).expect_err("over the payload cap");
    assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    assert_eq!(err.os_detail().map(|d| d.call), Some("bridge.version"));
}

#[test]
fn an_unknown_version_is_refused_rather_than_guessed() {
    let mut bytes = encode_network(&network());
    bytes[0] = WIRE_VERSION + 1;
    let err = decode_network(&bytes).expect_err("unknown version");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::EPROTO))
    );
}

#[test]
fn a_truncated_payload_is_refused_at_every_length() {
    let full = encode_network(&network());
    for cut in 1..full.len() {
        assert!(
            decode_network(&full[..cut]).is_err(),
            "a payload truncated at {cut} decoded, which means a bound is missing"
        );
    }
    assert!(decode_network(&full).is_ok());
}

#[test]
fn trailing_bytes_are_a_reject_rather_than_a_shrug() {
    let mut bytes = encode_network(&network());
    bytes.push(0);
    assert!(decode_network(&bytes).is_err());
}

#[test]
fn an_over_long_interface_name_is_refused_and_never_truncated() {
    let mut original = network();
    // `InterfaceName::new` caps at 255, so the cap is exercised through the
    // declared length rather than through a constructible name.
    original.name = InterfaceName::new(&"a".repeat(InterfaceName::MAX_BYTES)).expect("at the cap");
    assert!(decode_network(&encode_network(&original)).is_ok());

    let mut bytes = encode_network(&original);
    // Claim a longer name than the payload holds.
    bytes[9..11].copy_from_slice(&(u16::MAX).to_be_bytes());
    let err = decode_network(&bytes).expect_err("over the name cap");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::ENAMETOOLONG))
    );
}

#[test]
fn a_zero_length_interface_name_is_refused() {
    let mut bytes = encode_network(&network());
    bytes[9..11].copy_from_slice(&0u16.to_be_bytes());
    assert!(decode_network(&bytes).is_err());
}

#[test]
fn a_declared_address_count_over_the_bound_allocates_nothing() {
    let mut original = network();
    original.addresses.clear();
    let mut bytes = encode_network(&original);
    // The address count sits immediately after the 4-byte MTU. Find it by
    // rebuilding the prefix rather than by a magic offset.
    let prefix_len = 1 + 8 + 2 + original.name.as_str().len() + 4 + 1 + 4;
    assert_eq!(bytes[prefix_len], 0, "the fixture has no addresses");
    bytes[prefix_len] = u8::try_from(MAX_ADDRESSES).expect("small") + 1;
    let err = decode_network(&bytes).expect_err("over the address bound");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::E2BIG))
    );
    assert_eq!(err.os_detail().map(|d| d.call), Some("bridge.addresses"));
}

#[test]
fn a_declared_resolver_count_over_the_bound_allocates_nothing() {
    let mut original = network();
    original.addresses.clear();
    original.resolvers.clear();
    let mut bytes = encode_network(&original);
    let at = 1 + 8 + 2 + original.name.as_str().len() + 4 + 1 + 4 + 1;
    assert_eq!(bytes[at], 0, "the fixture has no resolvers");
    bytes[at] = u8::try_from(MAX_RESOLVERS).expect("small") + 1;
    let err = decode_network(&bytes).expect_err("over the resolver bound");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::E2BIG))
    );
}

#[test]
fn an_unknown_address_family_is_refused_rather_than_read_as_something_else() {
    let mut original = network();
    original.addresses =
        vec![IpPrefix::new(IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0])), 8).expect("v4")];
    original.resolvers.clear();
    let mut bytes = encode_network(&original);
    let family_at = 1 + 8 + 2 + original.name.as_str().len() + 4 + 1 + 4 + 1;
    assert_eq!(bytes[family_at], 4);
    bytes[family_at] = 9;
    let err = decode_network(&bytes).expect_err("family 9");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::EAFNOSUPPORT))
    );
}

/// A non-canonical prefix is refused rather than masked. Masking loses the host
/// address the core actually needs, and inventing one is worse than dropping.
#[test]
fn a_non_canonical_prefix_is_refused_rather_than_masked() {
    let mut original = network();
    original.addresses =
        vec![IpPrefix::new(IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0])), 8).expect("v4")];
    original.resolvers.clear();
    let mut bytes = encode_network(&original);
    let prefix_len_at = 1 + 8 + 2 + original.name.as_str().len() + 4 + 1 + 4 + 1 + 1;
    assert_eq!(bytes[prefix_len_at], 8);
    // 10.0.0.0/4 has a set host bit and is not canonical.
    bytes[prefix_len_at] = 4;
    let err = decode_network(&bytes).expect_err("not canonical");
    assert_eq!(
        err.os_detail().map(|d| d.code),
        Some(i64::from(libc::EINVAL))
    );
}

/// The same rule the socket layer applies: a link-local address with no
/// interface index is unusable on a multi-homed host and is refused.
#[test]
fn a_link_local_address_with_no_zone_is_refused() {
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    let zoned = V6Addr::new(octets, twinvpn_types::ZoneIndex::new(3)).expect("zoned");
    let mut original = network();
    original.addresses.clear();
    original.resolvers = vec![IpAddr::V6(zoned)];
    let bytes = encode_network(&original);
    assert!(decode_network(&bytes).is_ok(), "a zoned link-local decodes");

    // Strip the zone: the last four bytes of the resolver are its zone index,
    // and the NAT64-absent octet follows.
    let mut stripped = bytes.clone();
    let len = stripped.len();
    stripped[len - 5..len - 1].copy_from_slice(&0u32.to_be_bytes());
    assert!(
        decode_network(&stripped).is_err(),
        "a link-local address with no interface index is unusable"
    );
}

/// **The §10.4 prohibition, asserted structurally.** The bridge's vocabulary is
/// Android's; a TwinVPN domain fact must not be sayable on it.
#[test]
fn the_bridge_encoding_carries_no_twinvpn_domain_fact() {
    let source = include_str!("../wire.rs");
    // Comment lines are stripped: the module documentation quotes the rule, and
    // a scan that could not tell a rule from a violation would forbid stating it.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    for forbidden in [
        "ConnectionState",
        "ReasonCode",
        "ErrorClass",
        "Diagnostic",
        "PathClass",
        "TrafficDisposition",
        "HealthState",
    ] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` appears in the bridge encoding: §10.4 forbids a \
             TwinVPN domain fact on this surface"
        );
    }
    // `PlatformError` IS permitted and IS present: it is how a reject is typed,
    // and it never crosses to Kotlin -- the JNI layer turns it into a throw.
    assert!(code.contains("PlatformError"));
}
