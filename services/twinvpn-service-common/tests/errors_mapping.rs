//! Component tests for `twinvpn_service_common::errors`.
//!
//! Kept out of `src/errors.rs` so that file stays under the 500-line limit in
//! `CLAUDE.md`, and because every property asserted here is a property of the
//! **public** surface the four service domains consume.

use prost::Message as _;
use twinvpn_schema::{v1, Channel, Reject};
use twinvpn_service_common::errors::*;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, Component};

#[test]
fn a_reject_becomes_a_registered_code_with_its_declared_evidence() {
    let r = Reject::SizeExceeded {
        parser_id: Channel::PeerDatagram.parser_id(),
        observed: 5000,
        limit: 1200,
    };
    let e = ServiceError::from_reject(&r, Component::RendezvousClient);
    assert_eq!(e.code(), codes::PROTO_SIZE_EXCEEDED);
    let env = e.envelope();
    assert_eq!(env.reason_code, "PROTO.SIZE_EXCEEDED");
    assert_eq!(env.domain, "PROTO");
    let keys: Vec<_> = env.evidence.iter().map(|x| x.key.clone()).collect();
    assert!(keys.contains(&"parser_id".to_owned()));
    assert!(keys.contains(&"observed".to_owned()));
    assert!(keys.contains(&"limit".to_owned()));
}

#[test]
fn every_envelope_carries_the_registry_attributes_even_for_a_terminal_code() {
    let e = ServiceError::new(
        codes::INTERNAL_INVARIANT_VIOLATED,
        Component::CoordinationService,
    )
    .evidence(
        "invariant",
        EvidenceValue::Text("write_lease.single_writer".to_owned()),
    )
    .build();
    let env = e.envelope();
    let resolved = env.resolved.expect("resolved is present for every code");
    assert!(resolved.terminal);
    assert_eq!(resolved.severity, v1::ErrorSeverity::Critical as i32);
    assert_eq!(resolved.class, v1::ErrorClass::Fatal as i32);
    assert!(!resolved.doc_anchor.is_empty());
    assert!(!resolved.summary_key.is_empty());
}

#[test]
fn no_text_beyond_the_registry() {
    // The one property CF-4 exists to guarantee: an internal message string
    // cannot reach the wire.
    const CANARY: &str = "connect to 203.0.113.7:5432 refused for user twinvpn";
    let e = ServiceError::from_os_error(
        codes::CONTROL_UNREACHABLE,
        Component::CoordinationService,
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, CANARY),
    );
    let bytes = e.envelope().encode_to_vec();
    let rendered = String::from_utf8_lossy(&bytes);
    assert!(!rendered.contains("203.0.113.7"), "{rendered}");
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("refused for user"));
    // ...while the detail is still available in-process for a log line.
    assert!(e.source_detail().is_some());
    assert!(format!("{:?}", e.source_detail().unwrap()).contains("203.0.113.7"));
}

#[test]
fn display_is_the_code_and_nothing_else() {
    let e = ServiceError::new(codes::CONTROL_UNREACHABLE, Component::CoordinationService)
        .source(std::io::Error::other("a very descriptive sentence"))
        .build();
    assert_eq!(e.to_string(), "CONTROL.UNREACHABLE");
}

#[test]
fn an_os_error_is_never_the_whole_story() {
    let e = ServiceError::from_os_error(
        codes::CONTROL_UNREACHABLE,
        Component::CoordinationService,
        std::io::Error::from_raw_os_error(111),
    );
    let env = e.envelope();
    assert_eq!(env.reason_code, "CONTROL.UNREACHABLE");
    assert!(
        env.resolved.is_some(),
        "the registry attributes accompany the code, always"
    );
}

#[test]
fn http_status_is_a_pure_function_of_the_code() {
    let deferred = ServiceError::new(
        codes::CONTROL_ADMISSION_DEFERRED,
        Component::CoordinationService,
    )
    .build();
    assert_eq!(
        deferred.http_status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );

    let malformed = ServiceError::new(
        codes::PROTO_MALFORMED_MESSAGE,
        Component::CoordinationService,
    )
    .build();
    assert_eq!(malformed.http_status(), axum::http::StatusCode::BAD_REQUEST);

    let invariant = ServiceError::new(
        codes::INTERNAL_INVARIANT_VIOLATED,
        Component::CoordinationService,
    )
    .build();
    assert_eq!(
        invariant.http_status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );

    // Same code, twice, from two constructions: the same status.
    let a = ServiceError::new(codes::POLICY_EXIT_NOT_PERMITTED, Component::PolicyEngine).build();
    let b = ServiceError::new(codes::POLICY_EXIT_NOT_PERMITTED, Component::Dns).build();
    assert_eq!(a.http_status(), b.http_status());
    assert_eq!(a.http_status(), axum::http::StatusCode::FORBIDDEN);
}

#[test]
fn the_envelope_domain_matches_the_code_prefix() {
    for code in [
        codes::PROTO_SIZE_EXCEEDED,
        codes::CONTROL_ADMISSION_DEFERRED,
        codes::INTERNAL_INVARIANT_VIOLATED,
    ] {
        let env = ServiceError::new(code, Component::CoordinationService)
            .build()
            .envelope();
        assert!(
            env.reason_code.starts_with(&env.domain),
            "{} vs {}",
            env.reason_code,
            env.domain
        );
    }
}

#[test]
fn contributing_codes_keep_the_specific_one_primary() {
    let e = ServiceError::new(codes::RELAY_NONE_REACHABLE, Component::RelayClient)
        .contributing(codes::NAT_UDP_BLOCKED)
        .build();
    let env = e.envelope();
    assert_eq!(env.reason_code, "RELAY.NONE_REACHABLE");
    assert_eq!(env.contributing_reason_codes, vec!["NAT.UDP_BLOCKED"]);
}
