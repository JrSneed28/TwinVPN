//! Identifier, evidence and diagnostic tests.

use proptest::prelude::*;
use twinvpn_types::evidence::{EVIDENCE_TRUNCATED_KEY, MAX_EVIDENCE_ENTRIES};
use twinvpn_types::{
    codes, AddressFamily, CandidateId, CausalityToken, ChannelBinding, Component, ConnectionState,
    CorrelationId, DeviceId, Diagnostic, Evidence, EvidenceSet, EvidenceValue, FieldClassification,
    IdScope, IdempotencyKey, Identifier, IdentityId, MessageId, Opacity, PathClass, PathId,
    RegionId, Reuse, TrafficDisposition, TunnelId, TwinnetId, TypeError,
};

// ---------------------------------------------------------------------------
// Widths, ranges, and the "never truncate, never pad" rule
// ---------------------------------------------------------------------------

#[test]
fn fixed_width_identifiers_reject_every_wrong_length() {
    assert!(DeviceId::from_slice(&[0u8; 32]).is_ok());
    for len in [0usize, 1, 31, 33, 64] {
        assert!(
            DeviceId::from_slice(&vec![0u8; len]).is_err(),
            "DeviceId accepted {len} bytes"
        );
    }
    assert!(PathId::from_slice(&[0u8; 8]).is_ok());
    assert!(PathId::from_slice(&[0u8; 16]).is_err());
    assert!(CandidateId::from_slice(&[0u8; 8]).is_ok());
}

#[test]
fn identifier_length_rejection_names_the_registry_key_and_both_numbers() {
    let err = DeviceId::from_slice(&[0u8; 31]).unwrap_err();
    assert_eq!(
        err,
        TypeError::IdentifierLength {
            kind: "device_id_bytes",
            expected: 32,
            observed: 31
        }
    );
    assert_eq!(err.reason_code(), codes::PROTO_MALFORMED_MESSAGE);
    assert_eq!(err.cap_violated(), Some("device_id_bytes"));
}

#[test]
fn idempotency_key_enforces_the_128_bit_floor_and_the_64_byte_ceiling() {
    assert!(IdempotencyKey::from_slice(&[0u8; 15]).is_err());
    assert!(IdempotencyKey::from_slice(&[0u8; 16]).is_ok());
    assert!(IdempotencyKey::from_slice(&[0u8; 64]).is_ok());
    assert!(IdempotencyKey::from_slice(&[0u8; 65]).is_err());
    let k = IdempotencyKey::from_slice(&[7u8; 20]).unwrap();
    assert_eq!(k.as_bytes().len(), 20);
}

#[test]
fn bounded_text_identifiers_reject_over_cap_empty_and_control_characters() {
    assert!(TwinnetId::new(&"a".repeat(64)).is_ok());
    assert!(TwinnetId::new(&"a".repeat(65)).is_err());
    assert!(TwinnetId::new("").is_err());
    assert!(TwinnetId::new("net\nname").is_err());
    assert!(RegionId::new("eu-west-1").is_ok());
}

#[test]
fn causality_token_is_capped_before_it_allocates_and_is_echo_only() {
    assert!(CausalityToken::from_slice(&[0u8; 512]).is_ok());
    assert!(CausalityToken::from_slice(&[0u8; 513]).is_err());
    let t = CausalityToken::from_slice(b"opaque").unwrap();
    assert_eq!(t.octets_to_echo(), b"opaque");
}

// ---------------------------------------------------------------------------
// The registry facts the types carry
// ---------------------------------------------------------------------------

#[test]
fn scope_distinguishes_a_process_scoped_id_from_a_global_one() {
    // identifiers.md §1: a TunnelId is unique in ONE PROCESS; a SessionId is
    // globally unique. Two 16-byte bags of bits that mean entirely different
    // things, and the type system is what keeps them apart.
    assert_eq!(TunnelId::SCOPE, IdScope::Process);
    assert_eq!(twinvpn_types::SessionId::SCOPE, IdScope::Global);
    assert_eq!(PathId::SCOPE, IdScope::Tunnel);
    assert_eq!(twinvpn_types::PairTag::SCOPE, IdScope::RelayBucket);
    assert_eq!(twinvpn_types::PairTag::REUSE, Reuse::Rotates);
}

#[test]
fn only_the_three_meaningful_identifiers_are_self_certifying() {
    assert_eq!(DeviceId::OPACITY, Opacity::SelfCertifying);
    assert_eq!(IdentityId::OPACITY, Opacity::SelfCertifying);
    assert_eq!(twinvpn_types::PairingId::OPACITY, Opacity::SelfCertifying);
    // Everything else is a bag of bits whose only property is equality.
    assert_eq!(twinvpn_types::SessionId::OPACITY, Opacity::Opaque);
    assert_eq!(TunnelId::OPACITY, Opacity::Opaque);
    assert_eq!(twinvpn_types::RelayId::OPACITY, Opacity::Opaque);
}

#[test]
fn generation_zero_identity_id_is_the_device_id() {
    let bytes = [9u8; 32];
    let identity = IdentityId::from_array(bytes);
    assert_eq!(
        identity.as_generation_zero_device_id(),
        DeviceId::from_array(bytes)
    );
}

// ---------------------------------------------------------------------------
// Redaction: an identifier must not reach a log through a derived Debug
// ---------------------------------------------------------------------------

#[test]
fn sensitive_identifiers_are_redacted_in_debug() {
    let d = DeviceId::from_array([0xab; 32]);
    let rendered = format!("{d:?}");
    assert_eq!(rendered, "DeviceId(<32 B redacted>)");
    assert!(!rendered.contains("abab"));
    // Even nested inside another structure, which is the real failure mode.
    let wrapper = (d, "context");
    assert!(!format!("{wrapper:?}").contains("abab"));
}

#[test]
fn correlation_identifiers_are_visible_because_a_trace_needs_them() {
    // ownership.md §6 rule 6 requires correlation_id and causation_id to be
    // preserved across every component boundary. A redacted Debug on those
    // would make a distributed trace unreadable, and they are OPERATIONAL, not
    // SENSITIVE.
    assert_eq!(MessageId::CLASSIFICATION, FieldClassification::Operational);
    let m = MessageId::from_array([0x01; 16]);
    assert!(format!("{m:?}").contains("0101"));
}

#[test]
fn channel_binding_is_redacted_and_compares_without_an_early_exit() {
    let a = ChannelBinding::from_array([1u8; 32]);
    let b = ChannelBinding::from_array([1u8; 32]);
    let c = ChannelBinding::from_array([2u8; 32]);
    assert!(a.verify_against(&b));
    assert!(!a.verify_against(&c));
    assert_eq!(format!("{a:?}"), "ChannelBinding(<32 B redacted>)");
    assert!(ChannelBinding::from_slice(&[0u8; 31]).is_err());
}

#[test]
fn device_text_form_and_fingerprint_are_explicit_never_display() {
    let d = DeviceId::from_array([0u8; 32]);
    assert!(d.text_form().starts_with("twd1"));
    let fp = d.fingerprint();
    // Twenty characters in five groups of four: 20 chars + 4 separators.
    assert_eq!(fp.len(), 24);
    assert_eq!(fp.matches('-').count(), 4);
    assert_eq!(fp.chars().filter(|c| *c != '-').count(), 20);
}

#[test]
fn fingerprints_of_different_devices_differ() {
    let a = DeviceId::from_array([0u8; 32]).fingerprint();
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = 0xff;
    let b = DeviceId::from_array(b_bytes).fingerprint();
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

#[test]
fn evidence_accepts_only_keys_the_registry_declares_for_the_code() {
    // PROTO.DEPTH_EXCEEDED declares {parser_id, observed, limit}.
    assert!(Evidence::new(
        codes::PROTO_DEPTH_EXCEEDED,
        "observed",
        EvidenceValue::Uint(9)
    )
    .is_ok());
    // `capability` is declared for a different code, so it is refused here.
    let err = Evidence::new(
        codes::PROTO_DEPTH_EXCEEDED,
        "capability",
        EvidenceValue::Uint(1),
    )
    .unwrap_err();
    assert!(matches!(err, TypeError::EvidenceKeyUndeclared { .. }));
}

#[test]
fn evidence_rejects_a_malformed_key_shape() {
    for bad in ["Observed", "9lives", "has-dash", ""] {
        assert!(twinvpn_types::evidence::validate_key(bad).is_err(), "{bad}");
    }
    assert!(twinvpn_types::evidence::validate_key(&"a".repeat(49)).is_err());
    assert!(twinvpn_types::evidence::validate_key(&"a".repeat(48)).is_ok());
}

#[test]
fn address_family_is_carried_as_evidence_not_as_a_namespace() {
    // ownership.md §4.2 and ADR-0015 §11.2: a v4 failure and a v6 failure are
    // the SAME code with different `family_value` evidence. There is no
    // per-family code, and this is the mechanism that keeps it that way.
    for code in [
        codes::NAT_PUNCH_TIMEOUT,
        codes::NAT_SYMMETRIC_BOTH_ENDS,
        codes::POLICY_LEAK_DETECTED,
        codes::ROUTE_DEFAULT_SINGLE_FAMILY,
    ] {
        let v4 = Evidence::new(code, "family", EvidenceValue::Family(AddressFamily::V4));
        let v6 = Evidence::new(code, "family", EvidenceValue::Family(AddressFamily::V6));
        assert!(v4.is_ok() && v6.is_ok(), "{code} must accept both families");
    }
    // And there is no per-family CODE anywhere in the registry to accept
    // instead: no domain is a family, and no code names one.
    for code in twinvpn_types::ReasonCode::all() {
        let name = code.as_str();
        assert!(
            !name.starts_with("IPV4.") && !name.starts_with("IPV6."),
            "{name} is a per-family namespace, which ADR-0015 §11.2 refuses"
        );
    }
}

#[test]
fn an_address_value_is_sensitive_whatever_a_peer_claims() {
    let e = Evidence::new(
        codes::NAT_PUNCH_TIMEOUT,
        "family",
        EvidenceValue::Family(AddressFamily::V6),
    )
    .unwrap();
    assert_eq!(e.classification(), FieldClassification::Operational);
    // Classification only ever moves in the strict direction.
    let raised = e.with_classification_floor(FieldClassification::Sensitive);
    assert_eq!(raised.classification(), FieldClassification::Sensitive);
    let not_lowered = raised.with_classification_floor(FieldClassification::Public);
    assert_eq!(not_lowered.classification(), FieldClassification::Sensitive);
}

#[test]
fn evidence_set_truncates_at_the_entry_cap_and_records_the_marker() {
    let mut set = EvidenceSet::new();
    for _ in 0..MAX_EVIDENCE_ENTRIES {
        let e = Evidence::new(
            codes::PROTO_DEPTH_EXCEEDED,
            "observed",
            EvidenceValue::Uint(1),
        )
        .unwrap();
        assert!(set.push(e));
    }
    let overflow = Evidence::new(
        codes::PROTO_DEPTH_EXCEEDED,
        "observed",
        EvidenceValue::Uint(2),
    )
    .unwrap();
    assert!(!set.push(overflow));
    assert!(set.is_truncated());
    assert_eq!(set.len(), MAX_EVIDENCE_ENTRIES);
    assert_eq!(
        set.truncation_marker().map(|(k, _)| k),
        Some(EVIDENCE_TRUNCATED_KEY)
    );
}

#[test]
fn evidence_set_truncates_at_the_byte_cap_too() {
    let mut set = EvidenceSet::new();
    let big = "x".repeat(2000);
    for _ in 0..4 {
        let e = Evidence::new(
            codes::INTERNAL_INVARIANT_VIOLATED,
            "invariant",
            EvidenceValue::Text(big.clone()),
        )
        .unwrap();
        set.push(e);
    }
    assert!(set.is_truncated());
    assert!(set.budget_used() <= twinvpn_types::evidence::MAX_EVIDENCE_BYTES);
}

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_resolves_its_attributes_from_the_registry_not_from_a_field() {
    let d = Diagnostic::builder(codes::AUTH_DEVICE_REVOKED, Component::DeviceIdentity).build();
    let r = d.resolved();
    assert_eq!(r.class, codes::AUTH_DEVICE_REVOKED.class());
    assert_eq!(r.severity, codes::AUTH_DEVICE_REVOKED.severity());
    assert_eq!(r.terminal, codes::AUTH_DEVICE_REVOKED.terminal());
    if r.user_actionable {
        assert!(r.next_action_key.is_some());
    }
}

#[test]
fn invariant_violated_carries_its_declared_evidence() {
    let d = Diagnostic::invariant_violated(Component::TunnelEngine, "two mutating attaches");
    assert_eq!(d.code(), codes::INTERNAL_INVARIANT_VIOLATED);
    let e = d.evidence().get("invariant").expect("invariant evidence");
    assert_eq!(
        e.value(),
        &EvidenceValue::Text("two mutating attaches".to_owned())
    );
    assert!(d.code().terminal());
}

#[test]
fn a_type_error_becomes_a_registered_diagnostic_never_a_raw_error() {
    let err = DeviceId::from_slice(&[0u8; 3]).unwrap_err();
    let d: Diagnostic = err.into();
    assert_eq!(d.code(), codes::PROTO_MALFORMED_MESSAGE);
    assert!(d.evidence().get("cap_violated").is_some());
    assert!(d.evidence().get("observed").is_some());
    assert!(d.evidence().get("limit").is_some());
}

#[test]
fn diagnostic_records_a_transition_and_a_correlation() {
    let d = Diagnostic::builder(codes::NET_NO_ROUTE, Component::RoutingEngine)
        .transition(ConnectionState::Connecting, ConnectionState::Failed)
        .correlated_to(MessageId::from_array([3u8; 16]))
        .contributing(codes::NET_IFACE_DOWN)
        .occurred_at_ms(None)
        .build();
    let t = d.transition().expect("transition");
    assert_eq!(t.from, ConnectionState::Connecting);
    assert_eq!(t.to, ConnectionState::Failed);
    assert_eq!(
        d.correlation_id(),
        Some(CorrelationId::from_array([3u8; 16]))
    );
    assert_eq!(d.contributing(), &[codes::NET_IFACE_DOWN]);
    // CD-1a: a device with an Unset wall clock has no timestamp to give, and
    // writing a zero would render as 1970.
    assert_eq!(d.occurred_at_ms(), None);
}

// ---------------------------------------------------------------------------
// ConnectionState
// ---------------------------------------------------------------------------

#[test]
fn connection_state_carries_exactly_the_frozen_twelve_plus_unspecified() {
    assert_eq!(ConnectionState::ALL.len(), 12);
    for (i, s) in ConnectionState::ALL.iter().enumerate() {
        assert_eq!(s.to_wire(), i32::try_from(i).unwrap() + 1);
        assert_eq!(ConnectionState::from_wire(s.to_wire()).unwrap(), *s);
        assert!(s.specified().is_ok());
    }
    assert_eq!(
        ConnectionState::from_wire(0).unwrap(),
        ConnectionState::Unspecified
    );
    assert!(ConnectionState::Unspecified.specified().is_err());
    assert!(ConnectionState::from_wire(13).is_err());
    assert!(ConnectionState::from_wire(-1).is_err());
}

#[test]
fn degraded_carries_traffic_and_blocked_does_not() {
    // reliability.md R6: DEGRADED is a QUALITY violation and traffic continues;
    // a policy violation must not let traffic continue, so it is BLOCKED.
    assert!(ConnectionState::Degraded.carries_traffic());
    assert!(ConnectionState::Migrating.carries_traffic());
    assert!(!ConnectionState::Blocked.carries_traffic());
    assert!(!ConnectionState::Reconnecting.carries_traffic());
    assert!(!ConnectionState::Disconnected.carries_traffic());
    assert!(ConnectionState::Failed.is_terminal_for_attempt());
}

#[test]
fn steady_carrier_is_none_where_there_is_no_single_answer() {
    assert_eq!(
        ConnectionState::Relayed.steady_carrier(),
        Some(PathClass::Relayed)
    );
    // DEGRADED is parameterised by its carrier; MIGRATING has two endpoints.
    assert_eq!(ConnectionState::Degraded.steady_carrier(), None);
    assert_eq!(ConnectionState::Migrating.steady_carrier(), None);
}

#[test]
fn only_one_traffic_disposition_is_unprotected_and_it_needs_an_opt_out() {
    let unprotected: Vec<_> = [
        TrafficDisposition::TunneledLocalDirect,
        TrafficDisposition::TunneledWanDirect,
        TrafficDisposition::TunneledRelay,
        TrafficDisposition::TunneledDual,
        TrafficDisposition::QueuedBounded,
        TrafficDisposition::DroppedFailClosed,
        TrafficDisposition::DroppedNoRoute,
        TrafficDisposition::UnprotectedAnnounced,
    ]
    .into_iter()
    .filter(|d| d.is_unprotected())
    .collect();
    assert_eq!(unprotected, vec![TrafficDisposition::UnprotectedAnnounced]);
    assert!(!TrafficDisposition::DroppedFailClosed.packets_flow());
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// No byte string of any length panics a fixed-width constructor, and the
    /// accept set is exactly the declared width.
    #[test]
    fn fixed_width_construction_is_total(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
        prop_assert_eq!(DeviceId::from_slice(&bytes).is_ok(), bytes.len() == 32);
        prop_assert_eq!(PathId::from_slice(&bytes).is_ok(), bytes.len() == 8);
        prop_assert_eq!(
            IdempotencyKey::from_slice(&bytes).is_ok(),
            (16..=64).contains(&bytes.len())
        );
    }

    /// Text identifiers accept exactly the strings within the cap that carry no
    /// control character, and never panic.
    #[test]
    fn text_identifier_construction_is_total(s in ".{0,200}") {
        let expected = !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control);
        prop_assert_eq!(TwinnetId::new(&s).is_ok(), expected);
    }

    /// Any i32 either decodes to a frozen state or is rejected — never a panic
    /// and never a silently invented state.
    #[test]
    fn connection_state_decoding_is_total(v in any::<i32>()) {
        match ConnectionState::from_wire(v) {
            Ok(s) => prop_assert_eq!(s.to_wire(), v),
            Err(_) => prop_assert!(!(0..=12).contains(&v)),
        }
    }
}
