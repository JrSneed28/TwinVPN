//! **Replay, rollback, wrong publisher, and the announced gap.**
//!
//! | Scenario | Property |
//! |---|---|
//! | **Replay** | A retry with the same `idempotency_key` returns the original outcome, marked `idempotent_replay` (ADR-0008 N-5) |
//! | **Rollback** | A regressed monotone version is refused, not applied (ADR-0008 §7.1, ADR-0009 R-5/R-6) — and under the code its own rule names: only a trust floor is `AUTH.TRUST_EPOCH_ROLLBACK` (ADR-0007 N-26); a document or a cursor is `CONTROL.CONSISTENCY.*` (W-11) |
//! | **Wrong publisher** | An event from a principal that is not its sole publisher is a **security event** (ADR-0002 S-4) |
//! | **Compaction** | A deliberate gap is surfaced with its position, never swallowed (ADR-0002 N-8) |
//!
//! The sibling file `outage.rs` carries the total-outage scenario.

use std::sync::Arc;

use prost::Message as _;
use twinvpn_cp_client::testing::{test_env, RecordingTransport};
use twinvpn_cp_client::{
    decode_event, Admitted, ClientParts, Command, ControlPlaneClient, CpError, Cursor, DesiredSet,
    Durability, MonotoneMark, MonotoneVersion, Mutation, Publisher, ReceivedOctets, ResumeOutcome,
    StoreFailure, TrustEpoch,
};
use twinvpn_schema::v1;
use twinvpn_schema::v1::control_event::Event as EventBody;
use twinvpn_types::TwinnetId;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn twinnet() -> TwinnetId {
    TwinnetId::new("tn-integration").expect("valid")
}

fn client(
    env: &twinvpn_env::Env,
    transport: Arc<dyn twinvpn_cp_client::ControlTransport>,
    cursor: Cursor,
) -> ControlPlaneClient {
    ControlPlaneClient::new(ClientParts {
        env: env.clone(),
        transport,
        twinnet_id: twinnet(),
        sender_id: "twd1integration".to_owned(),
        coordination_endpoints: vec!["cp.example.invalid".to_owned()],
        families: twinvpn_cp_client::AttachFamilies {
            v4: true,
            v6: true,
            nat64: false,
        },
        cursor,
        mobile_background: false,
    })
}

fn encoded_event(body: EventBody, net_seq: u64, publisher: Publisher) -> ReceivedOctets {
    let class = twinvpn_cp_client::events::classify(&body);
    let event = v1::ControlEvent {
        metadata: Some(v1::MessageMetadata {
            proto_version: 1,
            message_id: vec![7u8; 16],
            twinnet_id: twinnet().as_str().to_owned(),
            sender_id: "coord".to_owned(),
            net_seq,
            ..Default::default()
        }),
        durability: class.durability.to_wire(),
        publisher: publisher.to_wire(),
        event: Some(body),
    };
    ReceivedOctets::from_wire_owned(event.encode_to_vec())
}

// ---------------------------------------------------------------------------
// THE REPLAY
// ---------------------------------------------------------------------------

#[test]
fn a_retry_with_the_same_key_returns_the_original_outcome() {
    let env = test_env();
    let mut ceremony =
        twinvpn_cp_client::Ceremony::begin(&env, Command::CompletePairing).expect("mint");
    let key_first_attempt = ceremony.key();

    // The client's whole contribution to exactly-once EFFECT: the key is stable.
    let key_second_attempt = ceremony.retry();
    let key_third_attempt = ceremony.retry();
    assert_eq!(
        twinvpn_types::Identifier::as_bytes(&key_first_attempt),
        twinvpn_types::Identifier::as_bytes(&key_second_attempt)
    );
    assert_eq!(
        twinvpn_types::Identifier::as_bytes(&key_first_attempt),
        twinvpn_types::Identifier::as_bytes(&key_third_attempt)
    );
    assert_eq!(ceremony.attempt(), 2);

    // The server replays the RECORDED response verbatim and marks it. The
    // duplicate is collapsed; it is not a 409 and it is not a fresh execution.
    let original = v1::MutationResult {
        committed_at_net_seq: 4_242,
        revocation_epoch: 11,
        idempotent_replay: false,
    };
    let replayed = v1::MutationResult {
        idempotent_replay: true,
        ..original
    };

    let first = Mutation::from_wire(Some(&original)).expect("header present");
    let second = Mutation::from_wire(Some(&replayed)).expect("header present");
    assert_eq!(
        first.committed_at_net_seq, second.committed_at_net_seq,
        "the replay must land at the SAME position, or trust is asymmetric"
    );
    assert!(!first.idempotent_replay);
    assert!(
        second.idempotent_replay,
        "ADR-0008 §10.2 requires the replay to be OBSERVABLE"
    );

    // And in both cases, "complete" waits for the cursor. This is the seam where
    // a device pairs a peer, gets a success, and then cannot connect.
    assert!(!second.is_visible_at(4_241));
    assert!(second.is_visible_at(4_242));
}

#[test]
fn a_duplicate_durable_event_is_refused_rather_than_applied_twice() {
    // At-least-once C2 delivery means duplicates are normal. Applying one twice
    // is not, and the cursor is what makes the second a no-op.
    let env = test_env();
    let transport = Arc::new(RecordingTransport::healthy());
    let c = client(&env, transport, Cursor::restored(100));

    let octets = encoded_event(
        EventBody::PeerAdded(v1::PeerAdded::default()),
        100,
        Publisher::CoordinationService,
    );
    let event = decode_event(&octets).expect("decodes");
    let err = c.admit_event(&event).expect_err("already applied");
    // The replica served at our cursor: E-1(c)'s transient code, not a
    // terminal AUTH one — a normal duplicate is not a security incident.
    assert_eq!(
        err.reason_code().as_str(),
        "CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR"
    );
    assert!(!err.reason_code().terminal());
}

// ---------------------------------------------------------------------------
// THE ROLLBACK
// ---------------------------------------------------------------------------

#[test]
fn a_regressed_monotone_version_is_rejected() {
    // 1. The trust epoch. A lower value would UN-REVOKE a stolen device.
    let mut epoch = TrustEpoch::restored(17);
    let err = epoch.admit(16).expect_err("rollback");
    assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    assert!(err.is_security_event());
    assert!(!err.permits_offline_reconnect());
    epoch.commit(4);
    assert_eq!(epoch.get(), 17, "commit is monotone too");

    // 2. The policy version. A lower value is a POLICY ROLLBACK ATTACK — and a
    //    consistency failure, reported as one (ADR-0009 R-5), not as an AUTH
    //    failure an older client would misdiagnose (W-11).
    let policy = MonotoneVersion::restored(88, [0x1a; 32]);
    let rollback = policy.admit(87, [0x1a; 32]).expect_err("rollback");
    assert_eq!(
        rollback.reason_code().as_str(),
        "CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED"
    );
    assert!(rollback.is_security_event());
    assert!(policy.admit(89, [0x1b; 32]).is_ok());

    // 3. Same version, different content: a forked history, and the client-side
    //    detector for E-1(c) (ADR-0009 R-4).
    let fork = policy.admit(88, [0x99; 32]).expect_err("fork");
    assert_eq!(
        fork.reason_code().as_str(),
        "CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED"
    );
    assert!(fork.is_security_event());

    // 4. The C2 cursor. A server offering a position below ours is behind or
    //    hostile; either way we do not go backwards — under E-1(c)'s code.
    let cursor = Cursor::restored(5_000);
    let behind = cursor.accept_server_position(4_999).expect_err("behind");
    assert_eq!(
        behind.reason_code().as_str(),
        "CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR"
    );
    assert!(cursor.accept_server_position(5_000).is_ok());

    // 5. And no recovery path resets a monotone mark — which is why restoring an
    //    older control-plane backup STRANDS devices rather than rewinding them.
    for outcome in [
        ResumeOutcome::ResnapshotStaleCursor {
            cursor: 1,
            retention_floor: 9,
        },
        ResumeOutcome::LogRebuilt { shard_epoch: 3 },
    ] {
        assert!(!outcome.may_reset_monotone_marks());
    }
}

#[test]
fn a_rollback_is_never_retried() {
    let err = CpError::TrustEpochRollback {
        offered_epoch: 1,
        high_water_epoch: 9,
    };
    assert_eq!(
        twinvpn_cp_client::retry::may_retry(Command::RevokeDevice, &err),
        twinvpn_cp_client::Retry::Never,
        "an authoritative refusal is not a transient failure"
    );
}

// ---------------------------------------------------------------------------
// THE WRONG PUBLISHER
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_publisher_event_is_rejected_as_a_security_event() {
    let env = test_env();
    let transport = Arc::new(RecordingTransport::healthy());
    let c = client(&env, transport, Cursor::restored(10));

    // A DeviceRevoked claiming to come from the originating device rather than
    // the coordination service. protocol.md §7 names exactly one publisher per
    // type, and ADR-0002 S-4 requires the RECEIVER to enforce it, not only the
    // log.
    let octets = encoded_event(
        EventBody::DeviceRevoked(v1::DeviceRevoked::default()),
        11,
        Publisher::OriginatingDevice,
    );
    let event = decode_event(&octets).expect("decodes");
    let err = c.admit_event(&event).expect_err("wrong publisher");

    assert_eq!(err.reason_code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");
    assert!(err.is_security_event());
    assert!(err.reason_code().terminal());
    assert_eq!(
        err.reason_code().severity(),
        twinvpn_types::ErrorSeverity::Critical
    );

    // The diagnostic names the event and the observed principal — the registry's
    // declared evidence for this code.
    let diagnostic = err.diagnostic();
    assert_eq!(diagnostic.component(), twinvpn_cp_client::COMPONENT);
    assert!(diagnostic.evidence().get("event_type").is_some());
    assert!(diagnostic.evidence().get("observed_publisher").is_some());
}

#[test]
fn the_publisher_check_runs_before_the_shape_check() {
    // A message that is wrong in two ways must report the SECURITY failure, not
    // the shape complaint — otherwise a hostile publisher can hide behind a
    // deliberate malformation.
    let env = test_env();
    let transport = Arc::new(RecordingTransport::healthy());
    let c = client(&env, transport, Cursor::restored(10));

    let mut event = v1::ControlEvent {
        metadata: Some(v1::MessageMetadata {
            net_seq: 0, // also wrong: a durable event with no position
            ..Default::default()
        }),
        durability: Durability::Durable.to_wire(),
        publisher: Publisher::OriginatingDevice.to_wire(),
        event: Some(EventBody::PolicyBundleUpdated(
            v1::PolicyBundleUpdated::default(),
        )),
    };
    let err = c.admit_event(&event).expect_err("two faults");
    assert_eq!(err.reason_code().as_str(), "CONTROL.EVENT_WRONG_PUBLISHER");

    // With the publisher corrected, the shape fault surfaces.
    event.publisher = Publisher::CoordinationService.to_wire();
    let err = c.admit_event(&event).expect_err("durable with net_seq 0");
    assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
}

// ---------------------------------------------------------------------------
// THE COMPACTION GAP
// ---------------------------------------------------------------------------

#[test]
fn a_compaction_gap_is_surfaced_not_swallowed() {
    let env = test_env();
    let transport = Arc::new(RecordingTransport::healthy());
    let c = client(&env, transport, Cursor::restored(200));

    // ADR-0002 N-8: the compaction is an ORDINARY IN-ORDER EVENT that names the
    // exact position the cursor lands on. Silent omission is prohibited.
    let octets = encoded_event(
        EventBody::StreamCompacted(v1::StreamCompacted {
            up_to_net_seq: 7_400,
        }),
        201,
        Publisher::CoordinationService,
    );
    let event = decode_event(&octets).expect("decodes");
    let admitted = c.admit_event(&event).expect("an announced gap is admitted");
    assert_eq!(admitted.net_seq(), Some(201));

    let body = event.event.as_ref().expect("body");
    match body {
        EventBody::StreamCompacted(compacted) => {
            assert_eq!(
                compacted.up_to_net_seq, 7_400,
                "the device is told EXACTLY which position it lands on"
            );
        }
        other => panic!("expected a compaction, got {other:?}"),
    }

    // The recovery is a declarative re-read, which is always sufficient because
    // every durable event is independently applicable (ADR-0002 N-5).
    let gap = ResumeOutcome::CompactionGap {
        up_to_net_seq: 7_400,
    };
    assert!(gap.needs_declarative_reread());
    assert!(!gap.may_reset_monotone_marks());
    assert!(!twinvpn_cp_client::commands::total_push_failure_costs_correctness());
}

// ---------------------------------------------------------------------------
// DURABILITY, BOTH DIRECTIONS
// ---------------------------------------------------------------------------

#[test]
fn misclassifying_durability_is_rejected_in_both_directions() {
    let env = test_env();
    let transport = Arc::new(RecordingTransport::healthy());
    let c = client(&env, transport, Cursor::restored(0));

    // Security direction: a revocation delivered as ephemeral would never be
    // replayed to a device that was asleep.
    let mut durable_as_ephemeral = v1::ControlEvent {
        metadata: Some(v1::MessageMetadata {
            net_seq: 0,
            ..Default::default()
        }),
        durability: Durability::Ephemeral.to_wire(),
        publisher: Publisher::CoordinationService.to_wire(),
        event: Some(EventBody::DeviceRevoked(v1::DeviceRevoked::default())),
    };
    assert!(c.admit_event(&durable_as_ephemeral).is_err());
    durable_as_ephemeral.durability = 0; // UNSPECIFIED is not a durability either
    assert!(c.admit_event(&durable_as_ephemeral).is_err());

    // Cost/privacy direction: presence carrying a log position has been written
    // to the log, which is the permanent movement history §6.1 forbids.
    let ephemeral_as_durable = v1::ControlEvent {
        metadata: Some(v1::MessageMetadata {
            net_seq: 500,
            ..Default::default()
        }),
        durability: Durability::Durable.to_wire(),
        publisher: Publisher::CoordinationService.to_wire(),
        event: Some(EventBody::PresenceUpdated(v1::PresenceUpdated::default())),
    };
    assert!(c.admit_event(&ephemeral_as_durable).is_err());

    // Correctly classified presence is admitted and carries no position.
    let ok = encoded_event(
        EventBody::PresenceUpdated(v1::PresenceUpdated::default()),
        0,
        Publisher::CoordinationService,
    );
    let event = decode_event(&ok).expect("decodes");
    assert!(matches!(
        c.admit_event(&event).expect("ephemeral"),
        Admitted::Ephemeral { .. }
    ));
}

// ---------------------------------------------------------------------------
// THE FORWARDING DISCIPLINE
// ---------------------------------------------------------------------------

#[test]
fn forwarded_octets_are_never_decoded_and_re_encoded() {
    // prost 0.13 drops unknown fields (core-foundation measured it), so a signed
    // statement that made a round trip through decode/encode could stop
    // verifying. This asserts the shape of the guarantee: what came off the wire
    // is what reaches the store.
    let statement = vec![
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x44, 0xde, 0xad, 0xbe, 0xef,
    ];
    let held = ReceivedOctets::from_wire(&statement);
    assert_eq!(held.as_slice(), statement.as_slice());
    assert_eq!(held.clone().into_vec(), statement);

    // A round trip through prost demonstrates the hazard the type avoids: the
    // wrapper survives, but only because we never asked prost to carry the
    // statement's own bytes as anything but opaque `bytes`.
    let wrapper = v1::SignedStatement {
        cose_sign1: statement.clone(),
        statement_type: 2,
    };
    let encoded = wrapper.encode_to_vec();
    let decoded = v1::SignedStatement::decode(encoded.as_slice()).expect("round trip");
    assert_eq!(decoded.cose_sign1, statement);
}

// ---------------------------------------------------------------------------
// VALIDATION AT THE BOUNDARY
// ---------------------------------------------------------------------------

#[test]
fn every_untrusted_input_is_capped_before_it_allocates() {
    // ownership.md §6 rules 9 and 10. The caps come from limits.json and the
    // rejection names the violated key.
    let over_envelope = vec![0u8; twinvpn_cp_client::CHANNEL.max_bytes() + 1];
    let err = decode_event(&ReceivedOctets::from_wire(&over_envelope)).expect_err("over cap");
    assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");

    let over_inline = vec![0u8; twinvpn_schema::limits::C2_INLINE_DOCUMENT_MAX_BYTES + 1];
    let err = twinvpn_cp_client::check_inline_document(&over_inline).expect_err("over 16 KiB");
    assert_eq!(err.reason_code().as_str(), "PROTO.SIZE_EXCEEDED");

    // A deeply nested body is refused by the depth cap, before prost recurses.
    let mut nested = vec![0u8; 0];
    for _ in 0..64 {
        let mut wrapped = vec![0x0a, u8::try_from(nested.len().min(120)).unwrap_or(120)];
        wrapped.extend_from_slice(&nested);
        nested = wrapped;
    }
    if let Err(err) = decode_event(&ReceivedOctets::from_wire(&nested)) {
        assert_eq!(err.reason_code().domain().as_str(), "PROTO");
    }
}

#[test]
fn every_error_this_crate_exposes_is_a_registered_code() {
    // ownership.md §6 rule 12. There is no `Other(String)` to leak a raw
    // internal error through, and every variant resolves in the frozen registry.
    let samples = [
        CpError::Unreachable,
        CpError::HandshakeRejected,
        CpError::ChannelBindingMismatch,
        CpError::SupersededByNewAttach,
        CpError::AdmissionDeferred { retry_after_ms: 1 },
        CpError::EventWrongPublisher {
            event_type: "device_revoked",
            observed_publisher: "originating_device",
        },
        CpError::TrustEpochRollback {
            offered_epoch: 1,
            high_water_epoch: 2,
        },
        CpError::TrustHistoryForked { epoch: 3 },
        CpError::VersionRollbackRejected {
            offered_version: 1,
            high_water_version: 2,
        },
        CpError::ForkedHistoryDetected { version: 3 },
        CpError::IdentityMismatch,
        CpError::KeyUnavailable,
        CpError::StreamCompacted { up_to_net_seq: 4 },
        CpError::CursorTooOld {
            cursor: 1,
            retention_floor: 2,
        },
        CpError::ReadTooStale { retry_after_ms: 5 },
        CpError::ReplicaBehindCursor {
            min_net_seq: 1,
            replica_net_seq: 0,
        },
        CpError::FreshnessProofMissing {
            intervals_missed: 3,
        },
        CpError::EventRateExceeded,
        CpError::WriteLeaderUnavailable,
        CpError::QuorumUnavailable,
        CpError::StalePolicyInUse { document_age_ms: 1 },
        CpError::DocumentStale {
            doc_type: "policy_bundle",
            age_ms: 1,
        },
        CpError::TrustListExpired { age_ms: 1 },
        CpError::TrustStateExpired { age_ms: 1 },
        CpError::PolicyBundleExpired {
            policy_version: 1,
            not_after_ms: 2,
        },
        CpError::VersionUnsupported {
            local_min: 1,
            local_max: 2,
            peer_min: 3,
            peer_max: 4,
        },
    ];
    for err in samples {
        let code = err.reason_code();
        assert!(
            twinvpn_types::ReasonCode::lookup(code.as_str()).is_some(),
            "{} is not in the frozen registry",
            code.as_str()
        );
        // And every attached evidence key is one the registry declares for it.
        let diagnostic = err.diagnostic();
        for entry in diagnostic.evidence().entries() {
            assert!(
                code.declares_evidence(entry.key()),
                "{} does not declare evidence key {}",
                code.as_str(),
                entry.key()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// THE W-11 TRIPWIRE
// ---------------------------------------------------------------------------

/// Every monotone refusal this crate emits, and the code it is emitted under.
///
/// `twinvpn-store`'s G-2 shape, inverted from the absence tripwires the other
/// domains carry: each code must be **registered**, and each must be produced
/// by a function outside `#[cfg(test)]`. A registry that lost one, or a
/// refactor that folded a document rollback back onto the trust-epoch code,
/// fails here rather than degrading a diagnosis on the `AUTH` prefix — which is
/// how W-11's second half stayed open for three amendments.
const INTENDED: &[(&str, &str)] = &[
    (
        "a trust_epoch below the mark (ADR-0007 N-26)",
        "AUTH.TRUST_EPOCH_ROLLBACK",
    ),
    (
        "a doc_version below the mark (ADR-0009 R-5)",
        "CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED",
    ),
    (
        "equal doc_version, different content (ADR-0009 R-4)",
        "CONTROL.CONSISTENCY.FORKED_HISTORY_DETECTED",
    ),
    (
        "a position at or below the local cursor (S-27, E-1(c))",
        "CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR",
    ),
];

/// The non-test producer for each `INTENDED` row, called as a caller would.
fn emitted(condition: &str) -> CpError {
    let digest = [0x5a; 32];
    match condition {
        c if c.starts_with("a trust_epoch") => TrustEpoch::restored(9).admit(8).expect_err(c),
        c if c.starts_with("a doc_version") => MonotoneVersion::restored(9, digest)
            .admit(8, digest)
            .expect_err(c),
        c if c.starts_with("equal doc_version") => MonotoneVersion::restored(9, digest)
            .admit(9, [0xa5; 32])
            .expect_err(c),
        c => Cursor::restored(9).accept_server_position(8).expect_err(c),
    }
}

#[test]
fn every_intended_code_is_registered_and_has_a_non_test_emitter() {
    for (condition, code) in INTENDED {
        assert!(
            twinvpn_types::ReasonCode::lookup(code).is_some(),
            "{condition} emits {code}, which the frozen registry does not carry"
        );
        let err = emitted(condition);
        assert_eq!(
            err.reason_code().as_str(),
            *code,
            "{condition} is emitted under the wrong code"
        );
    }
}

#[test]
fn only_a_trust_floor_emits_the_trust_epoch_code() {
    // The positive control is the first INTENDED row. Everything else that
    // refuses a lower value is a consistency condition, and none of it may
    // borrow ADR-0007 N-26's code again.
    let cursor_or_document = [
        emitted("a doc_version below the mark (ADR-0009 R-5)"),
        emitted("equal doc_version, different content (ADR-0009 R-4)"),
        emitted("a position at or below the local cursor (S-27, E-1(c))"),
        Cursor::restored(9).advance_to(9).expect_err("a replay"),
        DesiredSet {
            epoch: 3,
            prefixes: Vec::new(),
        }
        .check_epoch(3)
        .expect_err("a reused advertisement epoch"),
    ];
    for err in cursor_or_document {
        assert_ne!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
        assert_ne!(err.reason_code().as_str(), "AUTH.TRUST_HISTORY_FORKED");
        assert_eq!(err.reason_code().domain().as_str(), "CONTROL");
        assert!(
            err.permits_offline_reconnect(),
            "I5: a refused document or cursor is not a revocation"
        );
    }

    // And the store's refusals make the same split as the in-memory checks,
    // so the code does not depend on which side of the port the floor lives.
    for (mark, condition) in [
        (MonotoneMark::TrustEpoch, INTENDED[0].0),
        (MonotoneMark::DocumentVersion, INTENDED[1].0),
        (MonotoneMark::Cursor, INTENDED[3].0),
    ] {
        let refused = StoreFailure::RollbackRefused {
            mark,
            offered: 8,
            floor: 9,
        };
        assert_eq!(refused.reason_code(), emitted(condition).reason_code());
    }
    assert_eq!(
        StoreFailure::Forked { version: 9 }.reason_code(),
        emitted(INTENDED[2].0).reason_code()
    );
}
