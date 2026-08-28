//! Two properties that must hold about *absence*, so they are checked in the
//! source rather than in behaviour.
//!
//! 1. **S-29 is not persistable.** `architecture.md` §5 row S-29: replicas
//!    "None — MUST NOT be persisted or replicated", durability "Non-durable by
//!    requirement". Loss is the design: it produces flow death, which produces
//!    `MIGRATING`. A behavioural test can show the table is empty after a
//!    restart; only a source assertion can show there is no way to write it out.
//!
//! 2. **The relay cannot reconstruct the pairing.**
//!    `contracts/proto/twinvpn/v1/relay.proto`: `peer_key_id` "is WITHDRAWN
//!    precisely because that field would have told the relay which two devices
//!    are talking, defeating A11". Honouring that intent means the word must not
//!    reappear in a log line, a metric label, a data structure or an operator
//!    interface — which is again a claim about absence.

use std::path::{Path, PathBuf};

fn read(name: &str) -> String {
    let p: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn all_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("src/ readable") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            out.push((name, std::fs::read_to_string(&path).expect("read")));
        }
    }
    out
}

/// The production code only: comment lines blanked, and everything from
/// `#[cfg(test)]` onward dropped.
///
/// Both exclusions matter. A *description* of a forbidden thing — "this must
/// never carry a `pair_tag`" — is not the thing, and neither is a test that
/// asserts its absence. Scanning them would make every one of these checks
/// self-defeating: writing the assertion would break it.
fn code_only(source: &str) -> String {
    let end = source.find("#[cfg(test)]").unwrap_or(source.len());
    source[..end]
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ===========================================================================
// 1. S-29 — in memory, LOCAL, never persisted or replicated.
// ===========================================================================

#[test]
fn nothing_in_the_flow_table_can_be_serialised() {
    let flow = code_only(&read("flow.rs"));
    for forbidden in [
        "Serialize",
        "Deserialize",
        "serde",
        "to_writer",
        "write_all",
        "File::create",
        "OpenOptions",
    ] {
        assert!(
            !flow.contains(forbidden),
            "flow.rs mentions `{forbidden}`. S-29's replica column is \"None — MUST \
             NOT be persisted or replicated\" and its durability is \"Non-durable \
             by requirement\". A serialiser on this type is the first step to a \
             file, a row, or a replica."
        );
    }
}

#[test]
fn the_relay_writes_no_flow_peer_pair_or_token_record_anywhere() {
    // ADR-0005 RQ10 and §10: "A relay persists nothing durable about flows,
    // peers, or pairs" — only its static Noise key, its TLS material, the issuer
    // key set and the epoch floor, all of which are READ, never written.
    for (name, source) in all_sources() {
        let code = code_only(&source);
        for forbidden in [
            "std::fs::write",
            "fs::write(",
            "File::create",
            "OpenOptions",
            "create_dir",
            "sqlx",
            "postgres",
            "redis",
        ] {
            assert!(
                !code.contains(forbidden),
                "{name} contains `{forbidden}`: a relay persists nothing (RQ10), \
                 and there is no datastore anywhere in this service"
            );
        }
    }
    // The one filesystem verb that IS permitted, and only for reading config.
    let issuer = code_only(&read("issuer.rs"));
    assert!(issuer.contains("std::fs::read_to_string"));
}

// ===========================================================================
// 2. The pairing is not reconstructable.
// ===========================================================================

#[test]
fn the_withdrawn_peer_key_id_field_never_reappears() {
    for (name, source) in all_sources() {
        let code = code_only(&source);
        for forbidden in [
            "peer_key_id",
            "peer_public_key",
            "device_id",
            "DeviceId",
            "identity_key",
        ] {
            assert!(
                !code.contains(forbidden),
                "{name} names `{forbidden}`. relay.proto withdrew `peer_key_id` \
                 because it \"would have told the relay which two devices are \
                 talking, defeating A11\"; reintroducing an equivalent under \
                 another name defeats it identically."
            );
        }
    }
}

#[test]
fn no_log_line_or_metric_label_can_carry_a_join_key_or_a_flow_pair() {
    let observe = code_only(&read("observe.rs"));
    // The emitted vocabulary is closed. These are the dimensions that would
    // reconstruct a pairing, and none of them is emittable.
    for forbidden in [
        "pair_tag",
        "flow_id",
        "peer_addr",
        "session_id",
        "correlation_id",
        "causation_id",
        "message_id",
    ] {
        assert!(
            !observe.contains(forbidden),
            "observe.rs can emit `{forbidden}`. ADR-0015 O-13: a relay that logs \
             both ends holds the peer graph, defeating I1 in metadata."
        );
    }
    // And the emit side never imports the correlation machinery at all, so the
    // collector's `transform/relay-severs-context` has nothing to sever.
    assert!(!observe.contains("Correlation"));
    assert!(!observe.contains("use twinvpn_service_common::correlation"));
}

#[test]
fn the_pair_tag_and_the_subject_have_no_rendering_path() {
    // The types are redacted rather than merely unlogged, so an enclosing
    // `#[derive(Debug)]` six months from now is still safe.
    let tag = twinvpn_relay::PairTag::from_wire(&[0xAB; 16]).expect("16 bytes");
    assert_eq!(format!("{tag:?}"), "PairTag(<redacted>)");

    let sub = twinvpn_relay::RelaySub::from_verified_claim([0xCD; 16]);
    assert_eq!(format!("{sub:?}"), "RelaySub(<redacted>)");

    // And an enclosing type inherits that, which is the property that matters.
    #[derive(Debug)]
    #[allow(dead_code, reason = "the fields exist only to be rendered by Debug")]
    struct Enclosing {
        tag: twinvpn_relay::PairTag,
        sub: twinvpn_relay::RelaySub,
    }
    let rendered = format!("{:?}", Enclosing { tag, sub });
    assert!(!rendered.contains("ab") && !rendered.contains("cd"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn the_operator_interface_exposes_no_per_flow_dimension() {
    // The whole operator surface is the admin listener from service-common
    // (/healthz, /readyz, /metrics) plus the metrics this crate registers. There
    // is no relay-specific HTTP route, no debug endpoint, and no flow dump.
    for (name, source) in all_sources() {
        let code = code_only(&source);
        for forbidden in [
            "axum::Router",
            "Router::new",
            ".route(",
            "axum::routing",
            "TcpListener::bind",
        ] {
            assert!(
                !code.contains(forbidden),
                "{name} defines an HTTP route. The relay's only operator surface \
                 is service-common's admin listener; a per-flow debug endpoint is \
                 exactly the per-session relay debugging ADR-0015 §13 records as \
                 DELIBERATELY IMPOSSIBLE."
            );
        }
    }
}

// ===========================================================================
// The behavioural half: loss really is the design.
// ===========================================================================

#[test]
fn a_restart_kills_every_flow_and_that_is_the_designed_outcome() {
    use twinvpn_relay::flow::{BindOutcome, PairTable, PairTag};
    use twinvpn_relay::RelaySub;

    let mut t = PairTable::new(30_000, 900_000, 1_000);
    for n in 0..10_u8 {
        let tag = PairTag::from_wire(&[n; 16]).expect("16");
        assert!(matches!(
            t.bind(
                tag,
                format!("[::1]:{}", u16::from(n) + 1).parse().expect("addr"),
                RelaySub::from_verified_claim([n; 16]),
                0
            ),
            BindOutcome::Pending { .. }
        ));
    }
    assert_eq!(t.half_flow_count(), 10);
    assert_eq!(t.drop_everything(), 10);
    assert_eq!(t.half_flow_count(), 0);
    // S-29: "loss ⇒ flow death ⇒ MIGRATING". The client migrates; the relay
    // neither replays nor recovers, because there is nothing to recover from.
}
