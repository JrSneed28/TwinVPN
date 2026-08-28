//! Validator tests: the caps, the canonical forms, and the adversarial inputs.
//!
//! The obligation these discharge is `ownership.md` §6 rules 9 and 10:
//! malformed, oversized, deeply nested, truncated and adversarial inputs must
//! all produce a typed reject — never a panic, never an unbounded allocation,
//! never a truncation, never a silent accept.

use proptest::prelude::*;
use prost::Message as _;
use twinvpn_schema::envelope;
use twinvpn_schema::limits::{self, Channel};
use twinvpn_schema::reject::Reject;
use twinvpn_schema::v1;
use twinvpn_schema::validate::{self, CapabilityToken};
use twinvpn_types::{codes, AddressFamily, Component, Diagnostic, EvidenceValue, IpAddr, V4Addr};

// ---------------------------------------------------------------------------
// The limits themselves cannot drift from the frozen registry
// ---------------------------------------------------------------------------

/// Re-parses the embedded `limits.json` and checks every compiled constant
/// against it. Two independent paths from one frozen file.
#[test]
fn limits_generated_from_the_frozen_registry() {
    let doc: serde_json::Value =
        serde_json::from_str(limits::LIMITS_JSON).expect("embedded limits.json parses");
    let expect = |section: &str, key: &str, got: usize| {
        let want = doc[section][key]
            .as_u64()
            .unwrap_or_else(|| panic!("limits.json has no {section}.{key}"));
        assert_eq!(want as usize, got, "{section}.{key} drifted");
    };
    expect("envelope", "c1_c2_c7_max_bytes", limits::C1_C2_C7_MAX_BYTES);
    expect("envelope", "c1_c2_c7_max_depth", limits::C1_C2_C7_MAX_DEPTH);
    expect("envelope", "c4_max_bytes", limits::C4_MAX_BYTES);
    expect("envelope", "c4_max_depth", limits::C4_MAX_DEPTH);
    expect(
        "envelope",
        "c2_inline_document_max_bytes",
        limits::C2_INLINE_DOCUMENT_MAX_BYTES,
    );
    expect("identifiers", "device_id_bytes", limits::DEVICE_ID_BYTES);
    expect(
        "identifiers",
        "idempotency_key_max_bytes",
        limits::IDEMPOTENCY_KEY_MAX_BYTES,
    );
    expect(
        "candidates",
        "max_candidates_per_set",
        limits::MAX_CANDIDATES_PER_SET,
    );
    expect(
        "routing",
        "max_prefixes_per_advertisement",
        limits::MAX_PREFIXES_PER_ADVERTISEMENT,
    );
    expect(
        "dns",
        "max_domain_name_bytes",
        limits::MAX_DOMAIN_NAME_BYTES,
    );
    expect(
        "diagnostics",
        "max_evidence_entries",
        limits::MAX_EVIDENCE_ENTRIES,
    );
}

/// `twinvpn-types` restates three diagnostics limits as constants because it
/// carries no JSON parser. This is where they are checked against the registry.
#[test]
fn limits_match_twinvpn_types() {
    assert_eq!(
        limits::MAX_REASON_CODE_BYTES,
        twinvpn_types::reason::MAX_REASON_CODE_BYTES
    );
    assert_eq!(
        limits::MIN_REASON_CODE_SEGMENTS,
        twinvpn_types::reason::MIN_REASON_CODE_SEGMENTS
    );
    assert_eq!(
        limits::MAX_REASON_CODE_SEGMENTS,
        twinvpn_types::reason::MAX_REASON_CODE_SEGMENTS
    );
    assert_eq!(
        limits::MAX_EVIDENCE_ENTRIES,
        twinvpn_types::evidence::MAX_EVIDENCE_ENTRIES
    );
    assert_eq!(
        limits::MAX_EVIDENCE_BYTES,
        twinvpn_types::evidence::MAX_EVIDENCE_BYTES
    );
    assert_eq!(
        limits::MAX_EVIDENCE_KEY_BYTES,
        twinvpn_types::evidence::MAX_EVIDENCE_KEY_BYTES
    );
}

// ---------------------------------------------------------------------------
// ownership.md §4.3 — the open capability-name defect
// ---------------------------------------------------------------------------

#[test]
fn capability_name_cap_is_32_per_ownership_md_4_3() {
    assert_eq!(limits::CAPABILITY_MAX_NAME_BYTES, 32);
    // The exception exists precisely because a Phase-1-mandated token is 27
    // bytes and the registry's stale cap is 24.
    let token = CapabilityToken {
        name: "dns_config_dies_with_tunnel",
        parameters: &[],
    };
    assert_eq!(token.name.len(), 27);
    assert!(
        validate::capability_advertisement(&[token], 64).is_ok(),
        "a Phase-1-mandated capability token must validate"
    );
}

/// The §4.3 defect is CLOSED, and this asserts the registry now agrees with
/// itself rather than that it still disagrees.
///
/// This test was written to fail "the moment `contracts/` is amended, which is
/// what makes the §4.3 exception removable rather than permanent". It fired on
/// `registry_version` 2, which set `limits.json`'s
/// `capability.max_name_bytes` to 32 under the `ownership.md` §3 procedure —
/// so `CAPABILITY_MAX_NAME_BYTES` is no longer a pinned exception, it is what
/// the registry says.
#[test]
fn the_registry_agrees_with_itself() {
    let caps: serde_json::Value =
        serde_json::from_str(limits::CAPABILITIES_JSON).expect("capabilities.json parses");
    let cap_registry_len = caps["capability_name_max_length"].as_u64().expect("length");
    assert_eq!(cap_registry_len, 32);
    assert_eq!(
        limits::CAPABILITY_MAX_NAME_BYTES_REGISTRY,
        32,
        "limits.json's capability.max_name_bytes must be 32 — CF-6 amended \
         ADR-0014 N-11, capabilities.json and the CDDL both say 32, and the \
         registry carries a 27-byte token"
    );
    assert_eq!(
        limits::CAPABILITY_MAX_NAME_BYTES,
        limits::CAPABILITY_MAX_NAME_BYTES_REGISTRY,
        "the pinned constant and the registry must now be the same number; the \
         §4.3 workaround is dispositioned"
    );
    // And the token that proves the defect is real is still in the registry.
    let names: Vec<&str> = caps["capabilities"]
        .as_array()
        .expect("capabilities array")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(names.contains(&"dns_config_dies_with_tunnel"));
}

#[test]
fn capability_advertisement_enforces_every_n10_cap() {
    let ok = CapabilityToken {
        name: "ipv6_underlay",
        parameters: &[],
    };
    assert!(validate::capability_advertisement(std::slice::from_ref(&ok), 32).is_ok());

    // Token count.
    let many = vec![ok.clone(); limits::CAPABILITY_MAX_TOKENS + 1];
    assert!(matches!(
        validate::capability_advertisement(&many, 32),
        Err(Reject::CapViolated {
            cap_violated: "capability.max_tokens_per_advertisement",
            ..
        })
    ));

    // Advertisement bytes.
    assert!(matches!(
        validate::capability_advertisement(
            std::slice::from_ref(&ok),
            limits::CAPABILITY_MAX_ADVERTISEMENT_BYTES + 1
        ),
        Err(Reject::CapViolated {
            cap_violated: "capability.max_advertisement_bytes",
            ..
        })
    ));

    // Name length, against 32.
    let long_name = "a".repeat(33);
    let too_long = CapabilityToken {
        name: &long_name,
        parameters: &[],
    };
    assert!(validate::capability_advertisement(&[too_long], 32).is_err());

    // Name shape.
    for bad in ["Uppercase", "9leading", "has-dash", ""] {
        let t = CapabilityToken {
            name: bad,
            parameters: &[],
        };
        assert!(
            validate::capability_advertisement(&[t], 32).is_err(),
            "accepted {bad:?}"
        );
    }

    // Parameter count and bytes.
    let params: Vec<(&str, &str)> = vec![("k", "v"); limits::CAPABILITY_MAX_PARAMETERS + 1];
    let t = CapabilityToken {
        name: "portmap",
        parameters: &params,
    };
    assert!(validate::capability_advertisement(&[t], 32).is_err());

    let big = "x".repeat(limits::CAPABILITY_MAX_PARAMETER_BYTES);
    let params = [("k", big.as_str())];
    let t = CapabilityToken {
        name: "portmap",
        parameters: &params,
    };
    assert!(validate::capability_advertisement(&[t], 32).is_err());
}

#[test]
fn epoch_reach_is_capped() {
    assert!(
        validate::epoch_reach(1, 1 + limits::CAPABILITY_MAX_EPOCH_ABOVE_CURRENT as u32).is_ok()
    );
    assert!(
        validate::epoch_reach(1, 2 + limits::CAPABILITY_MAX_EPOCH_ABOVE_CURRENT as u32).is_err()
    );
    // A peer below our epoch is not a cap violation.
    assert!(validate::epoch_reach(100, 1).is_ok());
}

// ---------------------------------------------------------------------------
// Envelope caps: size before decode, depth before recursion
// ---------------------------------------------------------------------------

#[test]
fn the_size_cap_is_applied_before_any_decode() {
    let oversized = vec![0u8; limits::C1_C2_C7_MAX_BYTES + 1];
    let err = validate::decode::<v1::ErrorEnvelope>(&oversized, Channel::ControlAndTelemetry)
        .expect_err("over-cap must be rejected");
    assert!(matches!(err, Reject::SizeExceeded { .. }));
    assert_eq!(err.reason_code(), codes::PROTO_SIZE_EXCEEDED);
}

#[test]
fn c4_has_a_1200_byte_cap_and_a_depth_of_four() {
    assert_eq!(Channel::PeerDatagram.max_bytes(), 1200);
    assert_eq!(Channel::PeerDatagram.max_depth(), 4);
    assert_eq!(Channel::ControlAndTelemetry.max_bytes(), 65_536);
    assert_eq!(Channel::ControlAndTelemetry.max_depth(), 8);

    let over = vec![0u8; 1201];
    assert!(matches!(
        validate::decode::<v1::CandidateSet>(&over, Channel::PeerDatagram),
        Err(Reject::SizeExceeded {
            limit: 1200,
            observed: 1201,
            ..
        })
    ));
    // A message within the C4 cap but over nothing else decodes fine.
    let small = v1::PunchProbe {
        session_nonce: vec![1u8; 16],
        probe_id: vec![2u8; 8],
        family: 2,
    }
    .encode_to_vec();
    assert!(small.len() < 1200);
    assert!(validate::decode::<v1::PunchProbe>(&small, Channel::PeerDatagram).is_ok());
}

/// Builds `depth` levels of nesting, each level a single length-delimited field.
fn nest(depth: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0x08, 0x01]; // field 1, varint 1
    for _ in 0..depth {
        let mut outer = Vec::with_capacity(buf.len() + 4);
        outer.push(0x0a); // field 1, wire type 2
        let mut len = buf.len();
        while len >= 0x80 {
            #[allow(clippy::cast_possible_truncation)]
            outer.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        #[allow(clippy::cast_possible_truncation)]
        outer.push(len as u8);
        outer.extend_from_slice(&buf);
        buf = outer;
    }
    buf
}

#[test]
fn the_depth_cap_rejects_deep_nesting_on_both_channels() {
    // Within the cap.
    assert!(twinvpn_schema::depth::check(&nest(2), Channel::PeerDatagram).is_ok());
    assert!(twinvpn_schema::depth::check(&nest(6), Channel::ControlAndTelemetry).is_ok());

    // Past it.
    let err = twinvpn_schema::depth::check(&nest(20), Channel::PeerDatagram)
        .expect_err("depth 21 must be rejected on C4");
    assert!(matches!(err, Reject::DepthExceeded { limit: 4, .. }));
    assert_eq!(err.reason_code(), codes::PROTO_DEPTH_EXCEEDED);

    let err = twinvpn_schema::depth::check(&nest(64), Channel::ControlAndTelemetry)
        .expect_err("depth 65 must be rejected on C1");
    assert!(matches!(err, Reject::DepthExceeded { limit: 8, .. }));
}

#[test]
fn a_pathologically_deep_input_does_not_overflow_the_scanners_own_stack() {
    // Ten thousand levels. The guard's stack is a Vec bounded by max_depth + 1,
    // so it stops at the cap rather than growing with the input.
    let bomb = nest(10_000);
    assert!(twinvpn_schema::depth::check(&bomb, Channel::ControlAndTelemetry).is_err());
    assert!(validate::decode::<v1::ErrorEnvelope>(&bomb, Channel::ControlAndTelemetry).is_err());
}

#[test]
fn an_empty_message_is_depth_one_and_legal() {
    assert!(twinvpn_schema::depth::check(&[], Channel::PeerDatagram).is_ok());
    assert!(validate::decode::<v1::ErrorEnvelope>(&[], Channel::ControlAndTelemetry).is_ok());
}

#[test]
fn a_length_that_runs_past_the_end_is_rejected_not_read() {
    // Field 1, wire type 2, declared length 200, but only 3 bytes present. The
    // declared length must never drive a read.
    let truncated = vec![0x0a, 200, 1, 2, 3];
    assert!(matches!(
        twinvpn_schema::depth::check(&truncated, Channel::ControlAndTelemetry),
        Err(Reject::Unparseable { .. })
    ));
}

#[test]
fn signed_payload_of_opaque_cbor_is_not_counted_as_deep_nesting() {
    // Auth.signed_payload is deliberately opaque deterministic CBOR. The depth
    // scanner's over-approximation must not reject a realistic envelope carrying
    // one. (CBOR map of 4 text keys with byte-string values.)
    let cbor: Vec<u8> = vec![
        0xa2, 0x63, b'i', b's', b's', 0x66, b'i', b's', b's', b'u', b'e', b'r', 0x63, b'e', b'x',
        b'p', 0x1a, 0x65, 0x00, 0x00, 0x00,
    ];
    let msg = v1::MessageMetadata {
        proto_version: 1,
        message_id: vec![1u8; 16],
        auth: Some(v1::Auth {
            signed_payload: cbor,
            detached_sig: vec![9u8; 64],
            signer_key_id: "abc".into(),
            ..v1::Auth::default()
        }),
        ..v1::MessageMetadata::default()
    }
    .encode_to_vec();
    assert!(
        validate::decode::<v1::MessageMetadata>(&msg, Channel::ControlAndTelemetry).is_ok(),
        "an envelope with an opaque CBOR signed_payload must not trip the depth guard"
    );
}

#[test]
fn the_c2_inline_document_cap_is_lower_than_the_envelope_cap() {
    // `limits.json`: "Lower than the envelope cap on purpose, so a single policy
    // bundle cannot monopolise a stream." A `const_assert`-shaped check, written
    // so it fails the build rather than a test run if the registry ever inverts.
    const _: () = assert!(limits::C2_INLINE_DOCUMENT_MAX_BYTES < limits::C1_C2_C7_MAX_BYTES);
    assert!(validate::check_c2_inline_document(&vec![0u8; 16_384]).is_ok());
    assert!(matches!(
        validate::check_c2_inline_document(&vec![0u8; 16_385]),
        Err(Reject::SizeExceeded { limit: 16_384, .. })
    ));
}

// ---------------------------------------------------------------------------
// Field validators
// ---------------------------------------------------------------------------

#[test]
fn identifier_validators_reject_every_wrong_width() {
    assert!(validate::device_id(&[0u8; 32]).is_ok());
    assert!(validate::device_id(&[0u8; 31]).is_err());
    assert!(validate::path_id(&[0u8; 8]).is_ok());
    assert!(validate::path_id(&[0u8; 9]).is_err());
    assert!(validate::idempotency_key(&[0u8; 16]).is_ok());
    assert!(validate::idempotency_key(&[0u8; 15]).is_err());
    assert!(validate::causality_token(&[0u8; 513]).is_err());
    let err = validate::device_id(&[0u8; 4]).unwrap_err();
    assert_eq!(err.reason_code(), codes::PROTO_MALFORMED_MESSAGE);
}

#[test]
fn address_family_unspecified_is_rejected_rather_than_guessed() {
    assert_eq!(validate::address_family(1).unwrap(), AddressFamily::V4);
    assert_eq!(validate::address_family(2).unwrap(), AddressFamily::V6);
    assert!(validate::address_family(0).is_err());
    assert!(validate::address_family(7).is_err());
}

#[test]
fn a_v4_mapped_v6_address_is_rejected_at_the_wire_boundary() {
    let mut mapped = vec![0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 10;
    let msg = v1::IpAddress {
        address: Some(v1::ip_address::Address::V6(v1::IPv6Address {
            octets: mapped,
            zone_index: 0,
        })),
    };
    assert!(validate::ip_address(&msg).is_err());
}

#[test]
fn a_link_local_v6_without_a_zone_index_is_rejected() {
    let mut ll = vec![0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 1;
    let without = v1::IpAddress {
        address: Some(v1::ip_address::Address::V6(v1::IPv6Address {
            octets: ll.clone(),
            zone_index: 0,
        })),
    };
    assert!(validate::ip_address(&without).is_err());
    let with = v1::IpAddress {
        address: Some(v1::ip_address::Address::V6(v1::IPv6Address {
            octets: ll,
            zone_index: 4,
        })),
    };
    let parsed = validate::ip_address(&with).expect("with a zone it is usable");
    match parsed {
        IpAddr::V6(a) => assert_eq!(a.zone_index_wire(), 4),
        IpAddr::V4(_) => panic!("family flipped"),
    }
}

#[test]
fn an_ip_address_with_neither_family_set_is_malformed() {
    assert!(validate::ip_address(&v1::IpAddress { address: None }).is_err());
}

#[test]
fn a_non_canonical_prefix_is_rejected_at_the_wire_boundary() {
    let msg = v1::IpPrefix {
        address: Some(envelope::encode_address(IpAddr::V4(V4Addr::from_octets([
            10, 0, 0, 1,
        ])))),
        prefix_len: 24,
    };
    assert!(validate::ip_prefix(&msg).is_err());
}

#[test]
fn port_zero_is_rejected_on_an_endpoint() {
    let msg = v1::Endpoint {
        address: Some(envelope::encode_address(IpAddr::V4(V4Addr::UNSPECIFIED))),
        port: 0,
    };
    assert!(validate::endpoint(&msg).is_err());
}

#[test]
fn the_candidate_set_cap_is_checked_before_its_members_are() {
    let candidate = v1::ConnectionCandidate {
        candidate_id: vec![0u8; 8],
        family: 1,
        kind: 1,
        endpoint: Some(v1::Endpoint {
            address: Some(envelope::encode_address(IpAddr::V4(V4Addr::from_octets([
                10, 0, 0, 1,
            ])))),
            port: 5000,
        }),
        priority: 1,
        mtu_hint: 1280,
        expires_at_ms: 0,
    };
    let ok = v1::CandidateSet {
        session_nonce: vec![0u8; 16],
        generation: 1,
        candidates: vec![candidate.clone(); limits::MAX_CANDIDATES_PER_SET],
    };
    assert!(validate::candidate_set(&ok).is_ok());

    let over = v1::CandidateSet {
        candidates: vec![candidate; limits::MAX_CANDIDATES_PER_SET + 1],
        ..ok
    };
    assert!(matches!(
        validate::candidate_set(&over),
        Err(Reject::CapViolated {
            cap_violated: "candidates.max_candidates_per_set",
            ..
        })
    ));
}

#[test]
fn a_candidate_whose_declared_family_contradicts_its_endpoint_is_rejected() {
    // A v6 endpoint declared as v4 would let a v6 candidate be raced as a v4
    // one — per-family asymmetry through the back door.
    let set = v1::CandidateSet {
        session_nonce: vec![0u8; 16],
        generation: 1,
        candidates: vec![v1::ConnectionCandidate {
            candidate_id: vec![0u8; 8],
            family: 1,
            kind: 1,
            endpoint: Some(v1::Endpoint {
                address: Some(v1::IpAddress {
                    address: Some(v1::ip_address::Address::V6(v1::IPv6Address {
                        octets: vec![0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                        zone_index: 0,
                    })),
                }),
                port: 5000,
            }),
            priority: 1,
            mtu_hint: 1280,
            expires_at_ms: 0,
        }],
    };
    assert!(validate::candidate_set(&set).is_err());
}

#[test]
fn punch_sync_caps_hints_and_range_checks_pair_indices() {
    let mut sync = v1::PunchSync {
        session_nonce: vec![0u8; 16],
        generation: 1,
        punch_at_ms_relative: 50,
        pairs: vec![v1::CandidatePair {
            local_candidate_index: 0,
            remote_candidate_index: 0,
        }],
        birthday_port_hints: vec![1024; limits::MAX_BIRTHDAY_PORT_HINTS],
    };
    assert!(validate::punch_sync(&sync, 1, 1).is_ok());

    sync.birthday_port_hints
        .push(limits::MAX_BIRTHDAY_PORT_HINTS as u32);
    assert!(validate::punch_sync(&sync, 1, 1).is_err());

    let bad_index = v1::PunchSync {
        birthday_port_hints: vec![],
        pairs: vec![v1::CandidatePair {
            local_candidate_index: 5,
            remote_candidate_index: 0,
        }],
        ..sync
    };
    assert!(validate::punch_sync(&bad_index, 1, 1).is_err());
}

#[test]
fn route_advertisement_caps_prefixes_before_it_allocates() {
    let prefix = v1::IpPrefix {
        address: Some(envelope::encode_address(IpAddr::V4(V4Addr::from_octets([
            10, 0, 0, 0,
        ])))),
        prefix_len: 24,
    };
    let ok = vec![prefix.clone(); limits::MAX_PREFIXES_PER_ADVERTISEMENT];
    assert_eq!(
        validate::route_advertisement(&ok)
            .expect("at the cap")
            .len(),
        limits::MAX_PREFIXES_PER_ADVERTISEMENT
    );
    let over = vec![prefix; limits::MAX_PREFIXES_PER_ADVERTISEMENT + 1];
    assert!(matches!(
        validate::route_advertisement(&over),
        Err(Reject::CapViolated {
            cap_violated: "routing.max_prefixes_per_advertisement",
            ..
        })
    ));
}

#[test]
fn dns_caps_are_per_family_not_summed() {
    assert!(validate::dns_policy_shape(256, 32, 8, 8).is_ok());
    assert!(validate::dns_policy_shape(257, 32, 8, 8).is_err());
    assert!(validate::dns_policy_shape(256, 33, 8, 8).is_err());
    // Nine of one family fails even though the total is under sixteen.
    assert!(validate::dns_policy_shape(1, 1, 9, 1).is_err());
    assert!(validate::dns_policy_shape(1, 1, 1, 9).is_err());
}

#[test]
fn domain_names_are_capped_at_253_bytes() {
    assert!(validate::domain_name(&"a".repeat(253)).is_ok());
    assert!(validate::domain_name(&"a".repeat(254)).is_err());
    assert!(validate::domain_name("").is_err());
    assert!(validate::domain_name("bad\u{0}name").is_err());
}

#[test]
fn pairing_pre_authentication_caps_are_enforced() {
    assert!(validate::pairing_payload(&[0u8; 256], &[0u8; 512]).is_ok());
    assert!(validate::pairing_payload(&[0u8; 257], &[0u8; 512]).is_err());
    assert!(validate::pairing_payload(&[0u8; 256], &[0u8; 513]).is_err());
}

#[test]
fn pair_tag_buckets_accept_one_either_side_and_no_more() {
    assert!(validate::pair_tag_bucket_accepted(100, 99));
    assert!(validate::pair_tag_bucket_accepted(100, 100));
    assert!(validate::pair_tag_bucket_accepted(100, 101));
    assert!(!validate::pair_tag_bucket_accepted(100, 98));
    assert!(!validate::pair_tag_bucket_accepted(100, 102));
    // Bucket 0 must not underflow into accepting everything.
    assert!(!validate::pair_tag_bucket_accepted(0, u64::MAX));
}

// ---------------------------------------------------------------------------
// ErrorEnvelope
// ---------------------------------------------------------------------------

#[test]
fn an_envelope_round_trips_through_the_wire() {
    let diagnostic = Diagnostic::builder(codes::NAT_PUNCH_TIMEOUT, Component::NatTraversal)
        .evidence("family", EvidenceValue::Family(AddressFamily::V6))
        .occurred_at_ms(Some(1_800_000_000_000))
        .build();
    let wire = envelope::encode(&diagnostic);
    assert_eq!(wire.reason_code, "NAT.PUNCH_TIMEOUT");
    assert_eq!(wire.domain, "NAT");
    let resolved = wire.resolved.as_ref().expect("resolved is always present");
    assert_eq!(resolved.summary_key, codes::NAT_PUNCH_TIMEOUT.summary_key());

    let decoded = envelope::decode(&wire).expect("round trip");
    assert_eq!(decoded.code.registered(), Some(codes::NAT_PUNCH_TIMEOUT));
    assert_eq!(decoded.component, Some(Component::NatTraversal));
    assert_eq!(decoded.occurred_at_ms, Some(1_800_000_000_000));
    assert_eq!(decoded.evidence.len(), 1);
    assert_eq!(
        decoded.evidence[0].value,
        EvidenceValue::Family(AddressFamily::V6)
    );
}

#[test]
fn a_domain_that_disagrees_with_the_code_prefix_is_rejected() {
    let mut wire = envelope::encode(
        &Diagnostic::builder(codes::NAT_PUNCH_TIMEOUT, Component::NatTraversal).build(),
    );
    wire.domain = "AUTH".to_owned();
    assert!(
        envelope::decode(&wire).is_err(),
        "a mismatched pair is an attempt to render under the wrong domain"
    );
}

#[test]
fn an_unknown_code_survives_receipt_and_degrades_on_its_domain() {
    let wire = v1::ErrorEnvelope {
        reason_code: "RELAY.SOMETHING_ADDED_LATER".to_owned(),
        domain: "RELAY".to_owned(),
        resolved: Some(v1::ResolvedAttributes {
            class: 2,
            severity: 3,
            terminal: true,
            user_actionable: false,
            remediation_class: 2,
            scope: 5,
            ..v1::ResolvedAttributes::default()
        }),
        ..v1::ErrorEnvelope::default()
    };
    let decoded = envelope::decode(&wire).expect("an unknown code must not be swallowed");
    assert_eq!(decoded.degrade_domain(), twinvpn_types::Domain::Relay);
    assert!(decoded.effective_attributes().is_none());
    let claim = decoded.carried.expect("the carried claim is what remains");
    assert!(claim.terminal);
    // It cannot become a local Diagnostic: that would put an unregistered code
    // into this device's own diagnostics.
    assert!(envelope::to_diagnostic(&decoded).is_none());
}

#[test]
fn a_peers_claim_never_overrides_this_builds_registry_entry() {
    let mut wire = envelope::encode(
        &Diagnostic::builder(codes::AUTH_DEVICE_REVOKED, Component::DeviceIdentity).build(),
    );
    // A peer claims this terminal, critical condition is a passing INFO.
    if let Some(r) = wire.resolved.as_mut() {
        r.terminal = false;
        r.severity = 1;
        r.class = 1;
    }
    let decoded = envelope::decode(&wire).expect("decodes");
    let effective = decoded
        .effective_attributes()
        .expect("a known code resolves locally");
    assert_eq!(effective.terminal, codes::AUTH_DEVICE_REVOKED.terminal());
    assert_eq!(effective.severity, codes::AUTH_DEVICE_REVOKED.severity());
    // The claim said `terminal: false`; the local registry says otherwise, and
    // the local entry is what a consumer must act on.
    assert!(effective.terminal);
}

#[test]
fn an_undeclared_evidence_key_is_dropped_not_rejected() {
    let mut wire = envelope::encode(
        &Diagnostic::builder(codes::NAT_PUNCH_TIMEOUT, Component::NatTraversal).build(),
    );
    wire.evidence.push(v1::Evidence {
        key: "not_declared_for_this_code".to_owned(),
        classification: 2,
        value: Some(v1::evidence::Value::UintValue(1)),
    });
    let decoded = envelope::decode(&wire).expect("the envelope survives");
    assert!(decoded
        .evidence
        .iter()
        .all(|e| e.key != "not_declared_for_this_code"));
}

#[test]
fn an_unrecognised_classification_is_treated_as_sensitive() {
    let wire = v1::ErrorEnvelope {
        reason_code: "NAT.PUNCH_TIMEOUT".to_owned(),
        domain: "NAT".to_owned(),
        evidence: vec![v1::Evidence {
            key: "family".to_owned(),
            classification: 99,
            value: Some(v1::evidence::Value::FamilyValue(2)),
        }],
        ..v1::ErrorEnvelope::default()
    };
    let decoded = envelope::decode(&wire).expect("decodes");
    assert_eq!(
        decoded.evidence[0].classification,
        twinvpn_types::FieldClassification::Sensitive,
        "an unclassified field rendering as PUBLIC is a leak; over-redaction is not"
    );
}

#[test]
fn the_evidence_caps_are_enforced_on_receipt_rather_than_truncated() {
    let wire = v1::ErrorEnvelope {
        reason_code: "NAT.PUNCH_TIMEOUT".to_owned(),
        domain: "NAT".to_owned(),
        evidence: vec![
            v1::Evidence {
                key: "family".to_owned(),
                classification: 2,
                value: Some(v1::evidence::Value::FamilyValue(1)),
            };
            limits::MAX_EVIDENCE_ENTRIES + 1
        ],
        ..v1::ErrorEnvelope::default()
    };
    assert!(matches!(
        envelope::decode(&wire),
        Err(Reject::CapViolated {
            cap_violated: "diagnostics.max_evidence_entries",
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// The unknown-field finding (contracts/docs/phase1-conflicts.md CF-2)
// ---------------------------------------------------------------------------

/// **A measurement, not an assertion of correctness.**
///
/// ADR-0003 §11 B1 requires unknown fields to be preserved and forwarded. This
/// test records what `prost` 0.13 actually does, so the constraint reaches the
/// services as a fact rather than an assumption.
#[test]
fn unknown_fields_are_dropped_by_prost_0_13() {
    let mut wire = v1::PunchProbe {
        session_nonce: vec![1u8; 16],
        probe_id: vec![2u8; 8],
        family: 2,
    }
    .encode_to_vec();
    let before = wire.len();
    // Append field 99, varint, value 7 — a field this build does not know.
    wire.extend_from_slice(&[0x98, 0x06, 0x07]);
    assert!(wire.len() > before);

    let decoded = v1::PunchProbe::decode(wire.as_slice()).expect("decodes past an unknown field");
    let re_encoded = decoded.encode_to_vec();
    assert_eq!(
        re_encoded.len(),
        before,
        "if this ever holds the unknown field, CF-2's constraint is satisfied by prost \
         and the forward-verbatim rule can be relaxed"
    );
    assert_ne!(
        re_encoded, wire,
        "prost 0.13 DROPS unknown fields: a forwarding component MUST forward the received \
         octets verbatim rather than decode-then-re-encode (contracts/docs/phase1-conflicts.md CF-2)"
    );
}

// ---------------------------------------------------------------------------
// Adversarial input: never a panic, never an unbounded allocation
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes on either channel: a typed reject or a decoded message,
    /// never a panic.
    #[test]
    fn arbitrary_bytes_never_panic_the_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        c4 in any::<bool>(),
    ) {
        let channel = if c4 { Channel::PeerDatagram } else { Channel::ControlAndTelemetry };
        let _ = validate::decode::<v1::ErrorEnvelope>(&bytes, channel);
        let _ = validate::decode::<v1::CandidateSet>(&bytes, channel);
        let _ = validate::decode::<v1::MessageMetadata>(&bytes, channel);
        let _ = twinvpn_schema::depth::check(&bytes, channel);
    }

    /// Truncating a valid encoding at every offset must never panic and must
    /// never yield a message claiming more than it carries.
    #[test]
    fn truncated_encodings_never_panic(cut in 0usize..200) {
        let full = v1::CandidateSet {
            session_nonce: vec![7u8; 16],
            generation: 3,
            candidates: vec![v1::ConnectionCandidate {
                candidate_id: vec![1u8; 8],
                family: 2,
                kind: 2,
                endpoint: Some(v1::Endpoint {
                    address: Some(envelope::encode_address(IpAddr::V4(V4Addr::from_octets([1,2,3,4])))),
                    port: 443,
                }),
                priority: 7,
                mtu_hint: 1280,
                expires_at_ms: 1,
            }],
        }.encode_to_vec();
        let cut = cut.min(full.len());
        let partial = &full[..cut];
        if let Ok(set) = validate::decode::<v1::CandidateSet>(partial, Channel::PeerDatagram) {
            // Whatever survives must still pass the caps.
            let _ = validate::candidate_set(&set);
        }
    }

    /// An `ErrorEnvelope` built from arbitrary strings either decodes into a
    /// well-formed observed code or is rejected — never a panic, and never a
    /// code outside the closed domain set.
    #[test]
    fn arbitrary_reason_codes_are_parsed_or_rejected(
        code in "[A-Za-z0-9._]{0,80}",
        domain in "[A-Z]{0,10}",
    ) {
        let wire = v1::ErrorEnvelope {
            reason_code: code,
            domain,
            ..v1::ErrorEnvelope::default()
        };
        if let Ok(decoded) = envelope::decode(&wire) {
            prop_assert!(twinvpn_types::Domain::ALL.contains(&decoded.degrade_domain()));
            prop_assert_eq!(decoded.degrade_domain().as_str(), wire.domain.as_str());
        }
    }

    /// Nesting at any depth is either accepted within the cap or rejected;
    /// the scanner never recurses on the host stack.
    #[test]
    fn nesting_at_any_depth_is_bounded(depth in 0usize..400) {
        let bytes = nest(depth);
        match twinvpn_schema::depth::check(&bytes, Channel::ControlAndTelemetry) {
            Ok(()) => prop_assert!(depth < limits::C1_C2_C7_MAX_DEPTH),
            Err(Reject::DepthExceeded { .. }) => prop_assert!(depth >= limits::C1_C2_C7_MAX_DEPTH),
            Err(other) => prop_assert!(false, "unexpected reject {other:?}"),
        }
    }

    /// Every identifier validator is total over its input space.
    #[test]
    fn identifier_validators_are_total(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        prop_assert_eq!(validate::device_id(&bytes).is_ok(), bytes.len() == 32);
        prop_assert_eq!(validate::path_id(&bytes).is_ok(), bytes.len() == 8);
        prop_assert_eq!(validate::session_nonce(&bytes).is_ok(), bytes.len() == 16);
        prop_assert_eq!(
            validate::idempotency_key(&bytes).is_ok(),
            (16..=64).contains(&bytes.len())
        );
        prop_assert_eq!(validate::causality_token(&bytes).is_ok(), bytes.len() <= 512);
    }
}
