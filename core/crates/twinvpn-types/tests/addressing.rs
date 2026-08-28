//! Address-type tests: the canonical forms, the zone-index rule, NAT64, and the
//! co-equality of the two families.

use proptest::prelude::*;
use twinvpn_types::{
    AddressFamily, Endpoint, InterfaceAddress, IpAddr, IpPrefix, Nat64Prefix, PerFamily, Port,
    TypeError, UnderlayFamilies, V4Addr, V6Addr, ZoneIndex,
};

fn v6(octets: [u8; 16]) -> V6Addr {
    V6Addr::new(octets, None).expect("global v6")
}

// ---------------------------------------------------------------------------
// RFC 4007 zone index — docs/protocol.md §10.4
// ---------------------------------------------------------------------------

#[test]
fn link_local_v6_requires_a_non_zero_zone() {
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;

    // Without a zone it is unusable on a multi-interface host, so it is refused.
    assert_eq!(V6Addr::new(ll, None).unwrap_err(), TypeError::Ipv6ZoneIndex);
    // Zero is not a zone; it is the absence of one.
    assert_eq!(
        V6Addr::from_slice(&ll, 0).unwrap_err(),
        TypeError::Ipv6ZoneIndex
    );

    let with_zone = V6Addr::from_slice(&ll, 7).expect("link-local with zone");
    assert!(with_zone.is_link_local());
    assert_eq!(with_zone.zone().map(ZoneIndex::get), Some(7));
    assert_eq!(with_zone.zone_index_wire(), 7);
}

#[test]
fn the_whole_of_fe80_slash_10_counts_as_link_local() {
    // fe80::/10 spans fe80:: .. febf:ffff:..., so the second octet's top two
    // bits are what decide. An implementation that tested `== 0x80` would let
    // fe9x:: through without a zone.
    for second in [0x80u8, 0x9f, 0xbf] {
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = second;
        assert!(V6Addr::new(ll, None).is_err(), "fe{second:02x} accepted");
        assert!(V6Addr::from_slice(&ll, 1).is_ok());
    }
    // fec0::/10 is site-local, not link-local, and must NOT demand a zone.
    let mut site = [0u8; 16];
    site[0] = 0xfe;
    site[1] = 0xc0;
    assert!(V6Addr::new(site, None).is_ok());
}

#[test]
fn a_non_link_local_address_must_not_carry_a_zone() {
    let mut global = [0u8; 16];
    global[0] = 0x20;
    global[1] = 0x01;
    assert_eq!(
        V6Addr::from_slice(&global, 3).unwrap_err(),
        TypeError::Ipv6ZoneIndex
    );
}

// ---------------------------------------------------------------------------
// Canonical forms — common.proto §4
// ---------------------------------------------------------------------------

#[test]
fn v4_mapped_v6_is_rejected_not_unmapped() {
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 10;
    assert_eq!(
        V6Addr::new(mapped, None).unwrap_err(),
        TypeError::Ipv4MappedIpv6
    );
}

#[test]
fn wrong_width_addresses_are_rejected_never_padded_or_truncated() {
    assert!(V4Addr::from_slice(&[10, 0, 0]).is_err());
    assert!(V4Addr::from_slice(&[10, 0, 0, 1, 1]).is_err());
    assert!(V6Addr::from_slice(&[0u8; 15], 0).is_err());
    assert!(V6Addr::from_slice(&[0u8; 17], 0).is_err());
}

#[test]
fn a_non_canonical_prefix_is_rejected_never_normalized() {
    // 10.0.0.1/24 — the exact example common.proto gives.
    let addr = IpAddr::V4(V4Addr::from_octets([10, 0, 0, 1]));
    assert_eq!(
        IpPrefix::new(addr, 24).unwrap_err(),
        TypeError::PrefixNotCanonical
    );
    // 10.0.0.0/24 is canonical.
    let net = IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0]));
    assert!(IpPrefix::new(net, 24).is_ok());
    // A set bit inside a partial octet is equally non-canonical.
    let partial = IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0b0001_0000]));
    assert!(IpPrefix::new(partial, 25).is_err());
}

#[test]
fn prefix_length_is_validated_against_the_family() {
    let v4 = IpAddr::V4(V4Addr::UNSPECIFIED);
    let v6a = IpAddr::V6(V6Addr::UNSPECIFIED);
    assert!(IpPrefix::new(v4, 32).is_ok());
    assert!(matches!(
        IpPrefix::new(v4, 33),
        Err(TypeError::PrefixLength {
            limit: 32,
            observed: 33
        })
    ));
    assert!(IpPrefix::new(v6a, 128).is_ok());
    assert!(IpPrefix::new(v6a, 129).is_err());
}

#[test]
fn a_prefix_must_not_carry_a_scope_zone() {
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    let scoped = IpAddr::V6(V6Addr::from_slice(&ll, 2).unwrap());
    assert_eq!(
        IpPrefix::new(scoped, 10).unwrap_err(),
        TypeError::PrefixHasZone
    );
}

#[test]
fn prefix_containment_never_crosses_families() {
    let v4_default = IpPrefix::new(IpAddr::V4(V4Addr::UNSPECIFIED), 0).unwrap();
    let v6_addr = IpAddr::V6(v6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    // A v4 default route does not contain a v6 address. Answering anything but
    // `false` would need a mapping this crate refuses to perform.
    assert!(!v4_default.contains(v6_addr));
    assert!(v4_default.contains(IpAddr::V4(V4Addr::from_octets([8, 8, 8, 8]))));
}

#[test]
fn prefix_containment_is_exact_at_a_partial_octet_boundary() {
    let net = IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 0])), 10).unwrap();
    assert!(net.contains(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 1]))));
    assert!(net.contains(IpAddr::V4(V4Addr::from_octets([100, 127, 255, 255]))));
    assert!(!net.contains(IpAddr::V4(V4Addr::from_octets([100, 128, 0, 0]))));
    assert!(!net.contains(IpAddr::V4(V4Addr::from_octets([100, 63, 255, 255]))));
}

#[test]
fn port_zero_is_malformed_and_a_wide_wire_value_cannot_alias_to_it() {
    assert_eq!(Port::new(0).unwrap_err(), TypeError::PortZero);
    assert_eq!(Port::from_wire(0).unwrap_err(), TypeError::PortZero);
    // 65536 truncated to u16 is 0. Rejecting before the narrowing is the point.
    assert_eq!(Port::from_wire(65_536).unwrap_err(), TypeError::PortZero);
    assert_eq!(Port::from_wire(65_535).unwrap().get(), 65_535);
}

// ---------------------------------------------------------------------------
// ADR-0010 R1 and §11.7
// ---------------------------------------------------------------------------

#[test]
fn underlay_shape_is_its_own_fact_not_derived_from_which_addresses_exist() {
    assert!(UnderlayFamilies::V4Only.carries(AddressFamily::V4));
    assert!(!UnderlayFamilies::V4Only.carries(AddressFamily::V6));
    assert!(UnderlayFamilies::V6Only { nat64: None }.carries(AddressFamily::V6));
    assert!(!UnderlayFamilies::V6Only { nat64: None }.carries(AddressFamily::V4));
    assert!(UnderlayFamilies::DualStack.carries(AddressFamily::V4));
    assert!(UnderlayFamilies::DualStack.carries(AddressFamily::V6));
    // 464XLAT is v4-shaped but is NOT the same value as V4Only: ADR-0010 §11.7
    // attaches a reduced MTU and a CGNAT-equivalent NAT class to it.
    assert!(UnderlayFamilies::Xlat464.carries(AddressFamily::V4));
    assert_ne!(UnderlayFamilies::Xlat464, UnderlayFamilies::V4Only);
}

#[test]
fn nat64_synthesis_round_trips_at_every_rfc_6052_prefix_length() {
    let v4 = V4Addr::from_octets([192, 0, 2, 33]);
    for len in [32u32, 40, 48, 56, 64, 96] {
        let mut octets = [0u8; 16];
        // A distinct prefix per length, canonical and with a zero u-octet.
        let full = (len / 8) as usize;
        for (i, slot) in octets.iter_mut().enumerate().take(full) {
            *slot = if i == 8 {
                0
            } else {
                0x20 + u8::try_from(i).unwrap()
            };
        }
        let prefix = Nat64Prefix::new(octets, len).expect("canonical NAT64 prefix");
        let synth = prefix.synthesize(v4);
        assert_eq!(synth.octets()[8], 0, "u-octet must stay zero at /{len}");
        assert_eq!(synth.zone(), None);
        assert_eq!(prefix.extract(synth), Some(v4), "/{len} round trip");
    }
}

#[test]
fn nat64_well_known_prefix_is_the_rfc_6052_one() {
    let wk = Nat64Prefix::well_known();
    assert_eq!(wk.prefix_len(), 96);
    let synth = wk.synthesize(V4Addr::from_octets([198, 51, 100, 7]));
    let o = synth.octets();
    assert_eq!(&o[..4], &[0x00, 0x64, 0xff, 0x9b]);
    assert_eq!(&o[12..], &[198, 51, 100, 7]);
}

#[test]
fn nat64_rejects_lengths_outside_rfc_6052_and_a_non_zero_u_octet() {
    assert!(matches!(
        Nat64Prefix::new([0u8; 16], 80),
        Err(TypeError::Nat64PrefixLength { observed: 80 })
    ));
    let mut bad_u = [0u8; 16];
    bad_u[8] = 1;
    assert_eq!(
        Nat64Prefix::new(bad_u, 96).unwrap_err(),
        TypeError::Nat64PrefixNotCanonical
    );
}

#[test]
fn nat64_extract_refuses_an_address_outside_the_prefix() {
    let wk = Nat64Prefix::well_known();
    let elsewhere = v6([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(wk.extract(elsewhere), None);
}

#[test]
fn per_family_holds_both_halves_and_indexes_by_family() {
    let mut counts = PerFamily::new(0u32, 0u32);
    *counts.get_mut(AddressFamily::V6) += 1;
    assert_eq!(*counts.get(AddressFamily::V4), 0);
    assert_eq!(*counts.get(AddressFamily::V6), 1);
    let doubled = counts.map(|_, v| v * 2);
    assert_eq!(doubled.v6, 2);
}

#[test]
fn address_family_helpers_are_symmetric() {
    assert_eq!(AddressFamily::V4.other(), AddressFamily::V6);
    assert_eq!(AddressFamily::V6.other(), AddressFamily::V4);
    assert_eq!(AddressFamily::V4.address_bytes(), 4);
    assert_eq!(AddressFamily::V6.address_bytes(), 16);
}

#[test]
fn debug_redacts_addresses_so_a_derived_debug_cannot_leak_one() {
    let a = V4Addr::from_octets([203, 0, 113, 9]);
    let rendered = format!("{a:?}");
    assert!(
        !rendered.contains("203"),
        "address leaked in Debug: {rendered}"
    );
    let g = v6([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff]);
    let rendered = format!("{g:?}");
    assert!(
        !rendered.contains("255") && !rendered.contains("ff"),
        "{rendered}"
    );
}

// ---------------------------------------------------------------------------
// Property tests over the adversarial input space
// ---------------------------------------------------------------------------

proptest! {
    /// No octet/length pair may panic, and any accepted prefix is canonical:
    /// re-deriving the network address from the accepted value must be a no-op.
    #[test]
    fn prefix_construction_never_panics_and_accepts_only_canonical_values(
        octets in proptest::array::uniform16(any::<u8>()),
        len in 0u32..=128,
        v6_family in any::<bool>(),
    ) {
        let addr = if v6_family {
            match V6Addr::new(octets, None) {
                Ok(a) => IpAddr::V6(a),
                Err(_) => return Ok(()),
            }
        } else {
            IpAddr::V4(V4Addr::from_octets([octets[0], octets[1], octets[2], octets[3]]))
        };
        if let Ok(p) = IpPrefix::new(addr, len) {
            prop_assert!(len <= p.family().max_prefix_len());
            prop_assert!(p.contains(addr));
        }
    }

    /// Every 16-byte value either constructs or is rejected — never a panic —
    /// and the zone rule holds in both directions for every one of them.
    #[test]
    fn v6_construction_upholds_the_zone_rule_for_every_input(
        octets in proptest::array::uniform16(any::<u8>()),
        zone in 0u32..8,
    ) {
        let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
        let mapped = octets[..10].iter().all(|b| *b == 0)
            && octets[10] == 0xff
            && octets[11] == 0xff;
        match V6Addr::from_slice(&octets, zone) {
            Ok(a) => {
                prop_assert!(!mapped);
                prop_assert_eq!(a.is_link_local(), zone != 0);
                prop_assert_eq!(a.zone_index_wire(), zone);
            }
            Err(_) => prop_assert!(mapped || link_local != (zone != 0)),
        }
    }

    /// NAT64 synthesis and extraction are inverse for every v4 literal.
    #[test]
    fn nat64_round_trip_is_total_over_v4(octets in proptest::array::uniform4(any::<u8>())) {
        let v4 = V4Addr::from_octets(octets);
        let wk = Nat64Prefix::well_known();
        prop_assert_eq!(wk.extract(wk.synthesize(v4)), Some(v4));
    }

    /// Endpoints round-trip their family, and no port value panics.
    #[test]
    fn endpoint_family_matches_its_address(port in any::<u16>()) {
        let Ok(p) = Port::new(port) else { return Ok(()); };
        let e4 = Endpoint::new(IpAddr::V4(V4Addr::UNSPECIFIED), p);
        let e6 = Endpoint::new(IpAddr::V6(V6Addr::UNSPECIFIED), p);
        prop_assert_eq!(e4.family(), AddressFamily::V4);
        prop_assert_eq!(e6.family(), AddressFamily::V6);
    }
}

// ---------------------------------------------------------------------------
// InterfaceAddress — an interface's OWN address (the IpPrefix conjunction)
// ---------------------------------------------------------------------------

#[test]
fn an_interface_address_keeps_its_host_bits() {
    // 192.0.2.10/24. `IpPrefix` rejects this and must: it names a range.
    let addr = IpAddr::V4(V4Addr::from_octets([192, 0, 2, 10]));
    assert!(IpPrefix::new(addr, 24).is_err());

    // `InterfaceAddress` keeps it, which is the whole point: the address to bind
    // and to offer as a host candidate is 192.0.2.10, not 192.0.2.0.
    let iface = InterfaceAddress::new(addr, 24).expect("an interface address");
    assert_eq!(iface.address(), addr);
    assert_eq!(iface.prefix_len(), 24);
    assert!(!iface.is_host_route());
}

#[test]
fn an_interface_address_derives_its_on_link_network() {
    let iface =
        InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([192, 0, 2, 10])), 24).unwrap();
    let net = iface.network();
    assert_eq!(net.prefix_len(), 24);
    assert_eq!(
        net.address(),
        IpAddr::V4(V4Addr::from_octets([192, 0, 2, 0]))
    );
    assert!(net.contains(iface.address()));
}

#[test]
fn masking_is_exact_at_a_partial_octet_boundary() {
    let iface =
        InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([100, 100, 5, 7])), 10).unwrap();
    assert_eq!(
        iface.network().address(),
        IpAddr::V4(V4Addr::from_octets([100, 64, 0, 0]))
    );
}

#[test]
fn a_link_local_interface_address_keeps_its_zone_and_still_yields_a_prefix() {
    // W-39's conjunction: V6Addr::new demands a zone on link-local and
    // IpPrefix::new rejects any zone, so link-local prefixes were unrepresentable.
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    let scoped = V6Addr::from_slice(&ll, 3).expect("link-local with a zone");
    let iface = InterfaceAddress::new(IpAddr::V6(scoped), 64).expect("interface address");

    // The address keeps its zone — it is usable as an endpoint on this interface.
    match iface.address() {
        IpAddr::V6(a) => assert_eq!(a.zone_index_wire(), 3),
        IpAddr::V4(_) => panic!("family flipped"),
    }

    // And the network derives, zoneless, which it could not before.
    let net = iface.network();
    assert_eq!(net.prefix_len(), 64);
    match net.address() {
        IpAddr::V6(a) => {
            assert_eq!(a.zone(), None, "a prefix has no interface to be scoped to");
            assert_eq!(a.octets()[..2], [0xfe, 0x80]);
        }
        IpAddr::V4(_) => panic!("family flipped"),
    }
}

#[test]
fn v6_prefix_base_accepts_a_zoneless_link_local_and_still_rejects_v4_mapped() {
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    // `new` refuses it — correct for an endpoint.
    assert!(V6Addr::new(ll, None).is_err());
    // `prefix_base` accepts it — correct for a range.
    let base = V6Addr::prefix_base(ll).expect("fe80:: is a legal prefix base");
    assert_eq!(base.zone(), None);
    assert!(IpPrefix::new(IpAddr::V6(base), 10).is_ok());

    // The v4-mapped rejection is unchanged: that rule is about canonical form,
    // not about scope.
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    assert_eq!(
        V6Addr::prefix_base(mapped).unwrap_err(),
        TypeError::Ipv4MappedIpv6
    );
}

#[test]
fn the_overlays_own_addresses_are_host_routes() {
    // ADR-0010 §11.1 allocates a /32 and a /128 per Device.
    let v4 = InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([100, 64, 0, 7])), 32).unwrap();
    let v6a = InterfaceAddress::new(
        IpAddr::V6(v6([
            0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])),
        128,
    )
    .unwrap();
    assert!(v4.is_host_route());
    assert!(v6a.is_host_route());
    assert_eq!(v4.network().address(), v4.address());
}

#[test]
fn an_interface_address_still_validates_its_prefix_length() {
    assert!(InterfaceAddress::new(IpAddr::V4(V4Addr::UNSPECIFIED), 33).is_err());
    assert!(InterfaceAddress::new(IpAddr::V6(V6Addr::UNSPECIFIED), 129).is_err());
    assert!(InterfaceAddress::new(IpAddr::V4(V4Addr::UNSPECIFIED), 32).is_ok());
}

proptest! {
    /// Every accepted interface address derives a canonical network that
    /// contains it, for every octet pattern and every prefix length.
    #[test]
    fn an_interface_address_always_lies_inside_its_own_network(
        octets in proptest::array::uniform4(any::<u8>()),
        len in 0u32..=32,
    ) {
        let addr = IpAddr::V4(V4Addr::from_octets(octets));
        let iface = InterfaceAddress::new(addr, len).expect("v4 length is in range");
        let net = iface.network();
        prop_assert!(net.contains(addr));
        prop_assert_eq!(net.prefix_len(), len);
    }
}
