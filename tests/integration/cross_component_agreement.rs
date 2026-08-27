//! **Integration.** Pairs of artifacts that must agree, and cannot link each
//! other to find out.
//!
//! **Authority:** `docs/testing-strategy.md` §2.4; the pattern is
//! `services/control-plane/tests/client_agreement.rs`, which reads the client's
//! table, the frozen `.proto` and `contract-matrix.md` as text and asserts all
//! three agree.
//!
//! # Why text, and why here
//!
//! `core/`, `services/` and `lab/` are separate cargo workspaces (ownership.md
//! §1), so a client crate and its server cannot link each other. Agreement is
//! therefore checked the only way left: **compile-time `include_str!`**, so a
//! change on either side breaks this test rather than a deployment.
//!
//! `client_agreement.rs` does this for the control plane and its client. Four
//! other pairs had nobody doing it, and each is a place where one side could
//! change without the other noticing:
//!
//! | Pair | Why it matters |
//! |---|---|
//! | `twinvpn-relay-client` ↔ `relay.proto` ↔ `relay-directory` | three independent spellings of `Carriage`, `AdminState` and `HealthState` |
//! | `services/rendezvous`'s framing ↔ its README §5 ↔ `limits.json` | finding **RZ-1**: no frozen message describes this framing at all |
//! | every core crate's `UNREGISTERED` table ↔ `reason_codes.json` | finding **W-18**: each domain tripwires only its own slice |
//! | `services/relay`'s `Verbatim` claim ↔ what it actually forwards | finding **W-4**, and a stale claim in `lib.rs` |

use twinvpn_types::ReasonCode;

// ---------------------------------------------------------------------------
// The artifacts, read as text at compile time.
// ---------------------------------------------------------------------------

const RELAY_PROTO: &str = include_str!("../../contracts/proto/twinvpn/v1/relay.proto");
const CONNECTION_PROTO: &str = include_str!("../../contracts/proto/twinvpn/v1/connection.proto");
const LIMITS_JSON: &str = include_str!("../../contracts/registry/limits.json");
const REASON_CODES_JSON: &str = include_str!("../../contracts/registry/reason_codes.json");

const RELAY_CLIENT_MAP: &str = include_str!("../../core/crates/twinvpn-relay-client/src/map.rs");
const RELAY_CLIENT_BIND: &str = include_str!("../../core/crates/twinvpn-relay-client/src/bind.rs");
const RELAY_DIRECTORY_FLEET: &str = include_str!("../../services/relay-directory/src/fleet.rs");
const RELAY_SERVICE_FRAME: &str = include_str!("../../services/relay/src/frame.rs");
const RELAY_SERVICE_LIB: &str = include_str!("../../services/relay/src/lib.rs");
const RELAY_SERVICE_FORWARD: &str = include_str!("../../services/relay/src/forward.rs");

const RENDEZVOUS_FRAME: &str = include_str!("../../services/rendezvous/src/frame.rs");
const RENDEZVOUS_README: &str = include_str!("../../services/rendezvous/README.md");

// ---------------------------------------------------------------------------
// 1. Relay: three spellings of the same three enums.
// ---------------------------------------------------------------------------

#[test]
fn the_relay_carriage_vocabulary_is_the_same_on_all_three_sides() {
    // `RelayCarriage` in the frozen contract, `Carriage` in the device client,
    // and whatever the directory service ranks. A carriage the client cannot
    // name is a relay it silently never selects.
    for (proto, rust) in [
        ("RELAY_CARRIAGE_UDP", "Udp"),
        ("RELAY_CARRIAGE_QUIC", "Quic"),
        ("RELAY_CARRIAGE_TLS", "Tls"),
    ] {
        assert!(
            RELAY_PROTO.contains(proto),
            "the frozen contract no longer declares {proto}"
        );
        assert!(
            RELAY_CLIENT_MAP.contains(rust),
            "twinvpn-relay-client does not name the carriage {proto} declares"
        );
    }
    // The negative half: the client must not have invented a fourth carriage the
    // contract cannot express.
    assert!(
        !RELAY_CLIENT_MAP.contains("pub enum Carriage {\n    Udp,\n    Quic,\n    Tls,\n    "),
        "twinvpn-relay-client's Carriage has a variant relay.proto does not declare"
    );
}

#[test]
fn the_admin_state_vocabulary_is_the_same_on_all_three_sides() {
    for (proto, rust) in [
        ("RELAY_ADMIN_STATE_ACTIVE", "Active"),
        ("RELAY_ADMIN_STATE_DRAINING", "Draining"),
        ("RELAY_ADMIN_STATE_RETIRED", "Retired"),
    ] {
        assert!(RELAY_PROTO.contains(proto), "contract lost {proto}");
        assert!(
            RELAY_CLIENT_MAP.contains(rust),
            "the device client cannot name {proto}"
        );
        assert!(
            RELAY_DIRECTORY_FLEET.contains(rust),
            "relay-directory cannot name {proto}; a state the directory publishes \
             and the client cannot read is a relay that is never excluded"
        );
    }
}

#[test]
fn the_health_state_vocabulary_agrees_with_the_frozen_enum() {
    // W-20: `HealthState` is exported from `connection.proto` and was modelled
    // twice. The registry of truth is the proto; this asserts the client's five
    // variants are exactly its five.
    for (proto, rust) in [
        ("HEALTH_STATE_HEALTHY", "Healthy"),
        ("HEALTH_STATE_DEGRADED", "Degraded"),
        ("HEALTH_STATE_UNHEALTHY", "Unhealthy"),
        ("HEALTH_STATE_UNKNOWN", "Unknown"),
    ] {
        assert!(CONNECTION_PROTO.contains(proto), "contract lost {proto}");
        assert!(
            RELAY_CLIENT_MAP.contains(rust),
            "twinvpn-relay-client cannot name {proto}"
        );
    }
}

#[test]
fn the_pair_tag_bucket_the_client_uses_is_the_one_limits_json_fixes() {
    // A device that bucketed on a different period would present a `pair_tag`
    // the relay computes differently, and the two peers would never match. The
    // failure is silent: the relay simply never pairs them.
    let limits: serde_json::Value = serde_json::from_str(LIMITS_JSON).expect("limits.json");
    let bucket = limits["relay"]["pair_tag_bucket_seconds"]
        .as_u64()
        .expect("relay.pair_tag_bucket_seconds");
    let skew = limits["relay"]["accepted_bucket_skew"]
        .as_u64()
        .expect("relay.accepted_bucket_skew");

    assert_eq!(
        twinvpn_relay_client::bind::BUCKET_SECONDS,
        bucket,
        "twinvpn-relay-client's BUCKET_SECONDS disagrees with limits.json"
    );
    assert_eq!(
        twinvpn_relay_client::bind::ACCEPTED_BUCKET_SKEW,
        skew,
        "twinvpn-relay-client's ACCEPTED_BUCKET_SKEW disagrees with limits.json"
    );
    assert!(
        RELAY_CLIENT_BIND.contains("BUCKET_SECONDS: u64 = 600"),
        "the constant moved; re-read it before trusting this test"
    );
}

#[test]
fn a_bind_request_still_carries_no_peer_identifier() {
    // I1's client half, asserted against the frozen contract's `RelayBinding`:
    // the relay identifies a pair only by `pair_tag`, and the request the client
    // sends must not smuggle anything else in.
    assert!(
        RELAY_PROTO.contains("pair_tag"),
        "relay.proto no longer carries pair_tag"
    );
    for forbidden in ["device_id", "peer_id", "identity_id"] {
        assert!(
            !RELAY_CLIENT_BIND.contains(&format!("pub {forbidden}:")),
            "BindRequest gained a `{forbidden}` field; the relay must never learn \
             a peer identity (I1)"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. The relay data frame: a specification with one implementation and no
//    counterpart. This is a FINDING, asserted as a tripwire.
// ---------------------------------------------------------------------------

const RELAY_CLIENT_SOURCES: [&str; 2] = [RELAY_CLIENT_MAP, RELAY_CLIENT_BIND];

#[test]
fn the_relay_data_frame_still_has_no_device_side_implementation() {
    // FINDING. `services/relay/src/frame.rs` implements ADR-0005 §9.1's 16-byte
    // header — `HEADER_LEN`, `FrameType`, the counter and the auth tag. Nothing
    // in `core/crates/twinvpn-relay-client` does. The device can therefore
    // *select* a relay, *bind* to one, and *fail over* between them, but cannot
    // put a byte on the wire to one.
    //
    // This is a tripwire, not an approval: it passes today because the gap is
    // real, and it fails the moment someone implements the device side — which
    // is exactly when the agreement test between the two framings must be
    // written. Delete this test and write that one.
    assert!(
        RELAY_SERVICE_FRAME.contains("HEADER_LEN"),
        "the service side of the relay frame moved; re-read it"
    );
    for src in RELAY_CLIENT_SOURCES {
        assert!(
            !src.contains("HEADER_LEN"),
            "twinvpn-relay-client now implements the relay frame header. The \
             device and service framings must now be checked against each other; \
             delete this tripwire and write that agreement test."
        );
    }
}

#[test]
fn the_relay_services_own_documentation_agrees_with_what_it_forwards() {
    // FINDING. `services/relay/src/lib.rs` states that the forwarding path's
    // payload type is `twinvpn_service_common::Verbatim`; `src/forward.rs` uses
    // `crate::frame::Opaque`, because `Verbatim::from_received` runs a protobuf
    // depth scan that an L-DATA payload cannot pass (the relay's own W-4
    // finding). One of the two statements is stale.
    let lib_claims_verbatim = RELAY_SERVICE_LIB.contains("Verbatim");
    let forward_uses_opaque = RELAY_SERVICE_FORWARD.contains("Opaque");
    assert!(
        forward_uses_opaque,
        "the forwarding path no longer uses Opaque; re-read both files"
    );
    assert!(
        lib_claims_verbatim,
        "services/relay/src/lib.rs no longer claims Verbatim — if the claim was \
         corrected, delete this tripwire"
    );
    // Recorded as a divergence between a crate's prose and its code. Not
    // repaired here: `services/` belongs to `relay-plane`.
}

// ---------------------------------------------------------------------------
// 3. Rendezvous: a framing with no contract at all (finding RZ-1).
// ---------------------------------------------------------------------------

#[test]
fn the_rendezvous_framing_matches_the_specification_its_readme_carries() {
    // RZ-1: `contracts/` declares no message for this envelope, so the README's
    // §5 table is the specification of record and `src/frame.rs` is its only
    // implementation. Nothing checked the two against each other.
    for (name, code, variant) in [
        ("ATTACH", "0x01", "Attach"),
        ("CALL", "0x02", "Call"),
        ("ACK", "0x81", "Ack"),
        ("DELIVER", "0x82", "Deliver"),
        ("REFLEXIVE", "0x83", "Reflexive"),
    ] {
        assert!(
            RENDEZVOUS_README.contains(&format!("`{code} {name}`")),
            "the README's §5 table no longer declares {code} {name}"
        );
        assert!(
            RENDEZVOUS_FRAME.contains(&format!("{variant} = {code},")),
            "src/frame.rs does not bind the opcode {name} to {code} the README \
             specifies"
        );
    }
    assert!(
        RENDEZVOUS_FRAME.contains("TVR1"),
        "the magic changed; the README says 0x54 0x56 0x52 0x31"
    );
    assert!(
        RENDEZVOUS_README.contains("0x54 0x56 0x52 0x31"),
        "the README's magic changed"
    );
}

#[test]
fn the_rendezvous_body_bounds_come_from_limits_json_and_not_from_a_constant() {
    // The bound on an untrusted body must be the frozen one (ownership.md §6
    // rule 9). A service that hard-coded 1200 would keep working while the
    // registry moved, and would then reject or accept the wrong sizes.
    let limits: serde_json::Value = serde_json::from_str(LIMITS_JSON).expect("limits.json");
    let c4 = limits["envelope"]["c4_max_bytes"].as_u64().expect("c4");
    let device_id = limits["identifiers"]["device_id_bytes"]
        .as_u64()
        .expect("device_id_bytes");

    assert!(
        RENDEZVOUS_FRAME.contains("limits::C4_MAX_BYTES"),
        "src/frame.rs no longer derives its body cap from limits.json"
    );
    assert!(
        RENDEZVOUS_FRAME.contains("limits::DEVICE_ID_BYTES"),
        "src/frame.rs no longer derives DEVICE_ID_LEN from limits.json"
    );
    assert_eq!(
        u64::try_from(twinvpn_schema::limits::C4_MAX_BYTES).expect("fits"),
        c4,
        "the compiled-in C4 cap disagrees with the mounted registry"
    );
    assert_eq!(
        u64::try_from(twinvpn_schema::limits::DEVICE_ID_BYTES).expect("fits"),
        device_id
    );
    // The README's own numbers, so the specification and the registry agree too.
    assert!(
        RENDEZVOUS_README.contains("(exactly 32 bytes)"),
        "the README's ATTACH body size no longer says 32"
    );
    assert!(
        RENDEZVOUS_README.contains("1‥1200"),
        "the README's C4 range changed"
    );
}

// ---------------------------------------------------------------------------
// 4. W-18, across every domain at once.
// ---------------------------------------------------------------------------

/// Every `UNREGISTERED` substitution table in `core/`, in one place.
///
/// Each domain tripwires **its own** slice, which is right; nobody was checking
/// them together, and the combined count is the number that says how large W-18
/// actually is on the client side.
fn all_unregistered_spellings() -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for s in twinvpn_path::codes::UNREGISTERED {
        out.push(("twinvpn-path", s.specified));
    }
    for s in twinvpn_relay_client::codes::UNREGISTERED {
        out.push(("twinvpn-relay-client", s.specified));
    }
    for s in twinvpn_enforce::codes::UNREGISTERED {
        out.push(("twinvpn-enforce", s.specified));
    }
    for (spelling, _) in twinvpn_route::error::UNREGISTERED_SPELLINGS {
        out.push(("twinvpn-route", spelling));
    }
    out
}

#[test]
fn every_unregistered_spelling_in_the_core_is_still_absent_from_the_frozen_registry() {
    // W-18's standard tripwire, applied across four crates at once. When the
    // registry gains one of these codes this test names the crate whose
    // substitution must be deleted — which a per-crate tripwire cannot do,
    // because it only sees its own.
    let mut still_absent = 0;
    for (crate_name, spelling) in all_unregistered_spellings() {
        assert!(
            ReasonCode::lookup(spelling).is_none(),
            "`{spelling}` is now registered. Delete {crate_name}'s substitution \
             for it and emit the real code."
        );
        assert!(
            !REASON_CODES_JSON.contains(&format!("\"{spelling}\"")),
            "`{spelling}` appears in reason_codes.json but ReasonCode::lookup \
             does not find it — the compiled-in registry and the mounted one \
             have diverged"
        );
        still_absent += 1;
    }
    assert!(
        still_absent >= 24,
        "the combined substitution set shrank to {still_absent}; if codes were \
         registered this test should have named them"
    );
}

#[test]
fn every_substituted_code_is_itself_registered() {
    // The half a tripwire usually forgets: substituting an *unregistered* code
    // for an unregistered one would leave the emitter no better off, and the
    // per-crate tests assert only that the specified spelling is absent.
    for s in twinvpn_path::codes::UNREGISTERED {
        assert!(
            ReasonCode::lookup(s.emitted.as_str()).is_some(),
            "twinvpn-path substitutes `{}` for `{}`, and the substitute is not \
             registered either",
            s.emitted.as_str(),
            s.specified
        );
    }
    for s in twinvpn_relay_client::codes::UNREGISTERED {
        assert!(
            ReasonCode::lookup(s.emitted.as_str()).is_some(),
            "twinvpn-relay-client's substitute `{}` is unregistered",
            s.emitted.as_str()
        );
    }
    for s in twinvpn_enforce::codes::UNREGISTERED {
        assert!(
            ReasonCode::lookup(s.emitted.as_str()).is_some(),
            "twinvpn-enforce's substitute `{}` is unregistered",
            s.emitted.as_str()
        );
    }
}

#[test]
fn no_substitution_crosses_a_reason_code_domain_without_saying_so() {
    // ADR-0015 §11.2's forward-compatibility story is **prefix degradation**: an
    // older client meeting `AUTH.*` where a `RELAY.*` condition occurred
    // degrades to the wrong diagnosis. A substitution that stays inside its
    // domain preserves that; one that leaves it silently breaks it.
    //
    // Reported, not enforced: three of them do cross, and each is a deliberate
    // interim mapping the wave accepted (W-18). This test pins the set so a
    // fourth cannot appear unnoticed.
    let mut crossings: Vec<String> = Vec::new();
    let domain = |code: &str| code.split('.').next().unwrap_or_default().to_owned();
    for s in twinvpn_path::codes::UNREGISTERED {
        if domain(s.specified) != domain(s.emitted.as_str()) {
            crossings.push(format!(
                "twinvpn-path {} -> {}",
                s.specified,
                s.emitted.as_str()
            ));
        }
    }
    for s in twinvpn_relay_client::codes::UNREGISTERED {
        if domain(s.specified) != domain(s.emitted.as_str()) {
            crossings.push(format!(
                "twinvpn-relay-client {} -> {}",
                s.specified,
                s.emitted.as_str()
            ));
        }
    }
    for s in twinvpn_enforce::codes::UNREGISTERED {
        if domain(s.specified) != domain(s.emitted.as_str()) {
            crossings.push(format!(
                "twinvpn-enforce {} -> {}",
                s.specified,
                s.emitted.as_str()
            ));
        }
    }
    crossings.sort();
    // The set as it stands. A new crossing changes this list and fails here,
    // which is the point: a domain crossing is a decision, never an accident.
    assert_eq!(
        crossings,
        [
            "twinvpn-enforce POLICY.COEXIST.FILTER_CONFLICT -> PLATFORM.THIRD_PARTY_FILTER_SUSPECTED",
            "twinvpn-enforce POLICY.COEXIST.SECOND_VPN_DEFAULT_ROUTE -> ROUTE.IFACE_CONFLICT",
            "twinvpn-enforce POLICY.EXEMPT.PLATFORM_MANDATED -> PLATFORM.THIRD_PARTY_FILTER_SUSPECTED",
            "twinvpn-enforce POLICY.KILLSWITCH.ASSERTION_MISMATCH -> ROUTE.DRIFT_DETECTED",
            "twinvpn-enforce POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE -> PLATFORM.ADAPTER_UNAVAILABLE",
            "twinvpn-enforce POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE -> MGMT.DISARM_REQUIRES_LOCAL_AUTH",
            "twinvpn-enforce POLICY.KILLSWITCH.TRAFFIC_RESTORED -> NET.SESSION.RECOVERED",
            "twinvpn-enforce POLICY.LEAK.DNS_UNPROTECTED -> DNS.RESOLUTION.BLOCKED_FAIL_CLOSED",
            "twinvpn-enforce POLICY.PORTAL.EXEMPTION_ACTIVE -> NET.CAPTIVE_PORTAL",
            "twinvpn-enforce POLICY.PORTAL.EXEMPTION_EXPIRED -> NET.CAPTIVE_PORTAL",
            "twinvpn-path NET.EGRESS_RESTRICTED -> NAT.UDP_BLOCKED",
            "twinvpn-path NET.HAIRPIN_UNSUPPORTED -> NAT.PUNCH_TIMEOUT",
            "twinvpn-path NET.PROXY_REQUIRED -> NAT.UDP_BLOCKED",
            "twinvpn-relay-client RELAY.UPGRADE.FLAPPING_SUPPRESSED -> NAT.DIRECT_UPGRADED",
        ],
        "the set of substitutions that cross a reason-code domain changed"
    );
}

// ---------------------------------------------------------------------------
// 5. The compiled-in registry versus the mounted one.
// ---------------------------------------------------------------------------

#[test]
fn the_compiled_in_reason_registry_agrees_with_the_frozen_file() {
    // W-17 endorsed `service-common`'s stronger check for `limits.json`, but
    // `reason_codes.json` is only *version*-compared there. This is the content
    // half, from the client side: every registered code the file declares must
    // resolve in the compiled-in registry and vice versa for a sample.
    let registry: serde_json::Value =
        serde_json::from_str(REASON_CODES_JSON).expect("reason_codes.json");
    let codes = registry["reason_codes"]
        .as_array()
        .expect("the registry's `reason_codes` array");
    assert!(!codes.is_empty());
    let mut checked = 0;
    for entry in codes {
        let code = entry["reason_code"]
            .as_str()
            .expect("every registry entry declares a `reason_code`");
        assert!(
            ReasonCode::lookup(code).is_some(),
            "`{code}` is in the frozen registry file but the compiled-in registry \
             does not know it"
        );
        checked += 1;
    }
    assert_eq!(
        checked, 201,
        "contracts/FROZEN records 201 reason codes; the file now has {checked}"
    );
}
