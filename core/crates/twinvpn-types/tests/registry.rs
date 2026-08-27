//! Tests over the embedded reason-code registry and the taxonomy rules.
//!
//! These assert ADR-0015 §11.2's rules against the *compiled* table, so a
//! registry that drifts out of the taxonomy fails `cargo test` rather than a
//! wire exchange.

use twinvpn_types::reason::validate_syntax;
use twinvpn_types::{codes, CodeStatus, Domain, ObservedReasonCode, ReasonCode};

#[test]
fn registry_has_the_201_frozen_codes() {
    assert_eq!(ReasonCode::all().count(), 201);
}

#[test]
fn registry_domain_set_is_closed_at_sixteen() {
    assert_eq!(Domain::ALL.len(), 16);
    for code in ReasonCode::all() {
        assert!(
            Domain::ALL.contains(&code.domain()),
            "{code} is outside the closed set"
        );
    }
}

/// ADR-0015 §11.2: "a `user_actionable` code without a `next_action_key` fails
/// the registry's CI check". `ownership.md` names this as a defect to assert.
#[test]
fn registry_user_actionable_codes_declare_a_next_action() {
    for code in ReasonCode::all() {
        if code.user_actionable() {
            assert!(
                code.next_action_key().is_some(),
                "{code} is user_actionable with no next_action_key"
            );
        }
    }
}

/// Rule 7: two or three segments, uppercase ASCII, at most 64 bytes.
#[test]
fn registry_codes_all_satisfy_the_format_rules() {
    for code in ReasonCode::all() {
        validate_syntax(code.as_str()).unwrap_or_else(|e| panic!("{code}: {e}"));
        assert!(
            code.as_str().starts_with(code.domain().as_str()),
            "{code} does not begin with its domain"
        );
    }
}

#[test]
fn registry_evidence_keys_are_lower_snake_case_within_48_bytes() {
    for code in ReasonCode::all() {
        for key in code.evidence_fields() {
            twinvpn_types::evidence::validate_key(key)
                .unwrap_or_else(|e| panic!("{code} declares {key}: {e}"));
        }
    }
}

#[test]
fn registry_codes_are_all_active_in_this_frozen_set() {
    for code in ReasonCode::all() {
        assert_eq!(code.status(), CodeStatus::Active, "{code}");
    }
}

#[test]
fn lookup_finds_a_registered_code_and_refuses_an_unregistered_one() {
    assert_eq!(
        ReasonCode::lookup("PROTO.MALFORMED_MESSAGE"),
        Some(codes::PROTO_MALFORMED_MESSAGE)
    );
    assert_eq!(ReasonCode::lookup("PROTO.NOT_A_REAL_CODE"), None);
    // Case matters: the taxonomy is uppercase ASCII, and a case-insensitive
    // match would let one code arrive under two spellings.
    assert_eq!(ReasonCode::lookup("proto.malformed_message"), None);
}

#[test]
fn observed_code_degrades_an_unregistered_code_on_its_domain() {
    // A code shipped after this build: unknown, but in the closed domain set.
    let observed = ObservedReasonCode::parse("NAT.SOMETHING_NEW_IN_2027").unwrap();
    assert_eq!(observed.domain(), Domain::Nat);
    assert_eq!(observed.registered(), None);
    assert_eq!(observed.as_str(), "NAT.SOMETHING_NEW_IN_2027");
}

#[test]
fn observed_code_prefers_the_local_registry_entry_when_it_knows_the_code() {
    let observed = ObservedReasonCode::parse("AUTH.DEVICE_REVOKED").unwrap();
    let registered = observed.registered().expect("registered");
    assert_eq!(registered.domain(), Domain::Auth);
    assert!(registered.terminal());
}

#[test]
fn observed_code_rejects_a_domain_outside_the_closed_set() {
    // `TVPN-*` is the rejected scheme of ownership.md §4.2 / CF-3. Even spelled
    // as a dotted code, `TVPN` is not an admitted domain and cannot be degraded
    // on, so it is refused rather than guessed at.
    assert!(ObservedReasonCode::parse("TVPN.AUTH_FAILED").is_err());
    assert!(ObservedReasonCode::parse("MADEUP.THING").is_err());
}

#[test]
fn observed_code_rejects_malformed_shapes() {
    for bad in [
        "",
        "SINGLE",
        "NET.A.B.C",
        "net.no_route",
        "NET..EMPTY",
        "NET.trailing_lower",
    ] {
        assert!(
            ObservedReasonCode::parse(bad).is_err(),
            "accepted malformed code {bad:?}"
        );
    }
    // 64 bytes is the cap; 65 is not.
    let long = format!("NET.{}", "A".repeat(61));
    assert_eq!(long.len(), 65);
    assert!(ObservedReasonCode::parse(&long).is_err());
}

#[test]
fn observed_code_accepts_a_code_at_exactly_the_64_byte_cap() {
    let at_cap = format!("NET.{}", "A".repeat(60));
    assert_eq!(at_cap.len(), 64);
    assert!(ObservedReasonCode::parse(&at_cap).is_ok());
}

/// The registry version is what `SchemaDescriptor.reason_registry_version`
/// carries; a build that embeds one registry and reports another is a support
/// case nobody can answer.
#[test]
fn registry_version_is_embedded() {
    assert_eq!(twinvpn_types::REASON_REGISTRY_VERSION, 1);
}
