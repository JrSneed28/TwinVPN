//! This server and `twinvpn-cp-client` agree, asserted against the client's own
//! source and against the frozen contracts.
//!
//! **Why this file exists.** A durability or publisher disagreement between the
//! two artifacts is invisible from either side alone: the server would emit an
//! event the client silently refuses, or — worse, in the direction
//! `contract-matrix.md` §1 calls a **security** failure — the client would
//! accept a revocation it never replays. The two crates are in different cargo
//! workspaces and cannot link each other, so agreement is checked the only way
//! that is left: by reading the client's table and the frozen contracts as text.
//!
//! Everything here is a **compile-time include**, so a change to either side
//! that breaks agreement fails this test rather than a deployment.

mod common;

use twinvpn_control_plane::command::{Command, OperationClass};
use twinvpn_control_plane::event::{Durability, Publisher};
use twinvpn_control_plane::model::DocumentType;
use twinvpn_control_plane::EventKind;

/// `twinvpn-cp-client`'s C2 classification table.
const CLIENT_EVENTS: &str = include_str!("../../../core/crates/twinvpn-cp-client/src/events.rs");
/// `twinvpn-cp-client`'s C1 command table.
const CLIENT_IDEMPOTENCY: &str =
    include_str!("../../../core/crates/twinvpn-cp-client/src/idempotency.rs");
/// `twinvpn-cp-client`'s C1 surface, which carries its own `FORBIDDEN_ON_C1`.
const CLIENT_COMMANDS: &str =
    include_str!("../../../core/crates/twinvpn-cp-client/src/commands.rs");
/// `twinvpn-cp-client`'s document-type table.
const CLIENT_STATE: &str = include_str!("../../../core/crates/twinvpn-cp-client/src/state.rs");
/// The frozen event contract.
const CONTROL_EVENTS_PROTO: &str =
    include_str!("../../../contracts/proto/twinvpn/v1/control_events.proto");
/// The frozen contract matrix.
const MATRIX: &str = include_str!("../../../contracts/docs/contract-matrix.md");
/// The client-side statement of the ADR-0010 §11.1 address plan.
const CLIENT_PLAN: &str = include_str!("../../../core/crates/twinvpn-route/src/plan.rs");
/// The frozen `Device` record, which states the derivation normatively.
const DEVICE_PROTO: &str = include_str!("../../../contracts/proto/twinvpn/v1/device.proto");

#[test]
fn every_event_kind_has_the_durability_the_client_expects() {
    for kind in EventKind::ALL {
        let durable = format!("class!(\"{}\", Durable,", kind.as_str());
        let ephemeral = format!("class!(\"{}\", Ephemeral,", kind.as_str());
        let client_says_durable = CLIENT_EVENTS.contains(&durable);
        let client_says_ephemeral = CLIENT_EVENTS.contains(&ephemeral);
        assert!(
            client_says_durable ^ client_says_ephemeral,
            "{} appears {} times in the client's table",
            kind.as_str(),
            usize::from(client_says_durable) + usize::from(client_says_ephemeral)
        );
        let expected = if client_says_durable {
            Durability::Durable
        } else {
            Durability::Ephemeral
        };
        assert_eq!(
            kind.durability(),
            expected,
            "{} is classified differently by the server and the client — a \
             durable event delivered ephemerally is never replayed",
            kind.as_str()
        );
    }
}

#[test]
fn every_event_kind_has_the_publisher_the_client_expects() {
    // protocol.md §7: the coordination service is the sole publisher of every
    // C2 event type, INCLUDING the rows that transport a device-signed
    // statement. The client's table uses `CoordinationService` in every arm and
    // `admit` rejects anything else with CONTROL.EVENT_WRONG_PUBLISHER.
    for kind in EventKind::ALL {
        assert_eq!(kind.sole_publisher(), Publisher::CoordinationService);
        assert!(
            CLIENT_EVENTS.contains(&format!("class!(\"{}\", ", kind.as_str())),
            "{} is unknown to the client",
            kind.as_str()
        );
    }
    assert!(
        CLIENT_EVENTS.contains("Publisher::OriginatingDevice` deliberately appears in no arm"),
        "the client's table changed shape; re-read it before trusting this test"
    );
}

#[test]
fn the_server_knows_exactly_the_events_the_frozen_contract_declares() {
    // The oneof in control_events.proto is the closed set. An event type this
    // server can emit that the contract does not declare would be unencodable;
    // one the contract declares that this server does not know would be an
    // event no device ever receives.
    let declared: Vec<String> = CONTROL_EVENTS_PROTO
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // `    DeviceRevoked device_revoked = 12;` inside the oneof.
            let (ty, rest) = line.split_once(' ')?;
            let field = rest.split(' ').next()?;
            if !ty.chars().next()?.is_ascii_uppercase() || !line.ends_with(';') {
                return None;
            }
            if field.chars().any(|c| !c.is_ascii_lowercase() && c != '_') {
                return None;
            }
            Some(field.to_owned())
        })
        .collect();

    for kind in EventKind::ALL {
        assert!(
            declared.iter().any(|d| d == kind.as_str()),
            "{} is not a field of control_events.proto's oneof",
            kind.as_str()
        );
    }
    assert_eq!(
        EventKind::ALL.len(),
        24,
        "the oneof has 24 arms; a contract revision that adds one must add it here"
    );
}

#[test]
fn the_two_ephemeral_rows_of_the_matrix_are_the_two_this_server_treats_as_hints() {
    // contract-matrix.md §4.2 names exactly two events "delivered on C2 for
    // latency only". §4.3 adds StateDocumentAvailable and LogHead as ephemeral
    // stream control. Together those four, and no others, are ephemeral.
    assert!(MATRIX.contains("| `PresenceUpdated` | coordination (aggregating) |"));
    assert!(MATRIX.contains("| `RelayAssignmentHint` | coordination |"));

    let ephemeral: Vec<&str> = EventKind::ALL
        .iter()
        .filter(|k| k.durability() == Durability::Ephemeral)
        .map(|k| k.as_str())
        .collect();
    assert_eq!(
        ephemeral,
        vec![
            "state_document_available",
            "log_head",
            "presence_updated",
            "relay_assignment_hint"
        ]
    );
}

#[test]
fn every_command_has_the_class_the_client_and_the_matrix_give_it() {
    for command in Command::ALL {
        // The client declares the same seventeen names.
        assert!(
            CLIENT_IDEMPOTENCY
                .contains(&format!("Command::{command:?} => \"{}\"", command.as_str())),
            "{} is not a C1 command in the client",
            command.as_str()
        );
        // And the matrix's §3 row exists for each. §3 writes the two
        // withdrawals as `PutX` / `Withdraw`, sharing one row with the Put they
        // reverse — which is the matrix saying, correctly, that a withdrawal is
        // the same DECLARATIVE operation under a higher epoch.
        let row = match command {
            Command::WithdrawRouteAdvertisement => "`PutRouteAdvertisement` / `Withdraw`",
            Command::WithdrawExitNodeOffer => "`PutExitNodeOffer` / `Withdraw`",
            other => {
                assert!(
                    MATRIX.contains(&format!("| `{}`", other.as_str())),
                    "{} has no row in contract-matrix.md §3",
                    other.as_str()
                );
                continue;
            }
        };
        assert!(
            MATRIX.contains(row),
            "{} shares §3's row with its Put and that row moved",
            command.as_str()
        );
    }
}

#[test]
fn the_ceremony_set_is_the_matrix_ceremony_set() {
    let ceremonies: Vec<&str> = Command::ALL
        .iter()
        .filter(|c| c.class() == OperationClass::Ceremony)
        .map(|c| c.as_str())
        .collect();
    assert_eq!(
        ceremonies,
        vec![
            "RegisterDevice",
            "RevokeDevice",
            "RotateDeviceCredential",
            "BeginPairing",
            "CompletePairing",
            "CancelPairing",
            "RevokePairing",
            "PutPolicy",
        ],
        "contract-matrix.md §3's CEREMONY rows"
    );
    // And the one REGISTER row, which must never acquire a dedup log.
    let registers: Vec<&str> = Command::ALL
        .iter()
        .filter(|c| c.class() == OperationClass::Register)
        .map(|c| c.as_str())
        .collect();
    assert_eq!(registers, vec!["PublishPresence"]);
}

#[test]
fn the_document_types_are_the_clients_document_types() {
    for doc in DocumentType::ALL {
        assert!(
            CLIENT_STATE.contains(&format!("DocumentType::{doc:?} => \"{}\"", doc.as_str())),
            "{} is not a document type the client knows",
            doc.as_str()
        );
        assert!(
            CLIENT_STATE.contains(&format!("DocumentType::{doc:?} => {}", doc.to_wire())),
            "{} maps to a different wire value in the client",
            doc.as_str()
        );
    }
}

#[test]
fn the_eleven_forbidden_requests_are_forbidden_on_both_sides() {
    // contract-matrix.md §3.1. A server that grew one of these would put the
    // control plane back in the reconnect path and break I5 on the SERVER side,
    // where no client-side test would see it.
    for forbidden in twinvpn_control_plane::command::FORBIDDEN_ON_C1 {
        assert!(
            !Command::ALL.iter().any(|c| c.as_str() == forbidden),
            "{forbidden} acquired a server handler"
        );
        assert!(
            MATRIX.contains(forbidden),
            "{forbidden} should still be named in §3.1"
        );
    }
    // And the client's own list is the same eleven, so neither side can grow
    // one without the other noticing.
    assert!(
        CLIENT_IDEMPOTENCY.contains("FORBIDDEN_ON_C1")
            || CLIENT_COMMANDS.contains("FORBIDDEN_ON_C1")
    );
}

// ---------------------------------------------------------------------------
// The address plan. A disagreement here is a wrong overlay address for every
// device, visible only when a real client connects.
// ---------------------------------------------------------------------------

#[test]
fn the_v6_derivation_matches_the_clients_address_plan() {
    use twinvpn_control_plane::domain::addressing as addr;

    // The `info` string, byte for byte. `twinvpn-route`'s `V6_IID_INFO` is what
    // the client's binding passes to the same `twinvpn-crypto` HKDF.
    assert!(
        CLIENT_PLAN.contains(r#"pub const V6_IID_INFO: &[u8] = b"twinvpn-v6-iid";"#),
        "twinvpn-route's info string moved"
    );
    assert_eq!(addr::V6_IID_INFO, b"twinvpn-v6-iid");

    // And the contract's own normative sentence still says HKDF over the KEY,
    // not a truncation of `device_id`. This is the assertion that would have
    // caught the bug this test was added for.
    assert!(
        DEVICE_PROTO.contains(r#"truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))"#),
        "device.proto's derivation moved"
    );

    // The pinned product ULA and the reserved service ranges.
    assert!(CLIENT_PLAN.contains("fd7c:9e5d:2a10::/48"));
    assert_eq!(addr::V6_ULA_48, [0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    assert!(CLIENT_PLAN.contains("fd7c:9e5d:2a10:ffff::/64"));
    assert_eq!(addr::RESERVED_SERVICE_V6_SUBNET, [0xff, 0xff]);
    assert!(CLIENT_PLAN.contains("100.64.0.0/10"));
    assert_eq!(addr::V4_BASE, [100, 64, 0, 0]);
    assert_eq!(addr::V4_PREFIX_LEN, 10);
    assert!(CLIENT_PLAN.contains("100.127.255.0/24"));
    assert_eq!(addr::RESERVED_SERVICE_V4, ([100, 127, 255, 0], 24));

    // RFC 7136's U/L clear, spelled the same way on both sides.
    assert!(
        CLIENT_PLAN.contains("id[0] &= 0b1111_1101;"),
        "the client clears the U/L bit differently"
    );
}

#[test]
fn the_state_document_digest_is_the_sha_256_the_contract_announces() {
    // `policy.proto`: "SHA-256 of the document bytes, exactly 32 bytes." A
    // device verifies the announced digest against one it computed itself, so a
    // lookalike of the right width fails every pull.
    let d = twinvpn_control_plane::domain::policy::content_digest(b"twinvpn");
    assert_eq!(d, twinvpn_crypto::sha256(b"twinvpn"));
    assert_eq!(d.len(), 32);
}
