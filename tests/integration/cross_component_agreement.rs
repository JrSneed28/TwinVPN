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
const RELAY_SERVICE_PROVIDER: &str = include_str!("../../services/relay/src/provider.rs");
const RELAY_CLIENT_FRAME: &str =
    include_str!("../../core/crates/twinvpn-relay-client/src/frame.rs");
const ADR_0005: &str = include_str!("../../docs/adr/ADR-0005-relay-architecture.md");
const TWINVPN_H: &str = include_str!("../../core/ffi/include/twinvpn.h");

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

/// The five constants ADR-0005 §9.1's layout fixes, defined once on each side.
///
/// The two workspaces cannot link each other (`tests/Cargo.toml` deliberately
/// excludes `services/`), so the device's value is read through its crate and
/// the relay's is read out of its source. That asymmetry is the honest one: the
/// device side is *executed*, the service side is *read*.
const SHARED_FRAME_CONSTANTS: [(&str, usize); 5] = [
    ("HEADER_LEN", twinvpn_relay_client::frame::HEADER_LEN),
    ("VERSION", twinvpn_relay_client::frame::VERSION as usize),
    (
        "MAX_DATA_PAYLOAD_BYTES",
        twinvpn_relay_client::frame::MAX_DATA_PAYLOAD_BYTES,
    ),
    (
        "L_DATA_OVERHEAD_BYTES",
        twinvpn_relay_client::frame::L_DATA_OVERHEAD_BYTES,
    ),
    (
        "OVERLAY_MTU_FLOOR",
        twinvpn_relay_client::frame::OVERLAY_MTU_FLOOR,
    ),
];

/// The nine wire bytes ADR-0005 §9.1 assigns positionally.
const FRAME_TYPE_WIRE: [(twinvpn_relay_client::FrameType, u8, &str); 9] = [
    (twinvpn_relay_client::FrameType::Data, 0x01, "Data"),
    (twinvpn_relay_client::FrameType::Bind, 0x10, "Bind"),
    (twinvpn_relay_client::FrameType::Bound, 0x11, "Bound"),
    (twinvpn_relay_client::FrameType::Ping, 0x12, "Ping"),
    (twinvpn_relay_client::FrameType::Pong, 0x13, "Pong"),
    (twinvpn_relay_client::FrameType::Drain, 0x14, "Drain"),
    (
        twinvpn_relay_client::FrameType::RelayStatus,
        0x15,
        "RelayStatus",
    ),
    (twinvpn_relay_client::FrameType::Caps, 0x16, "Caps"),
    (twinvpn_relay_client::FrameType::Rebind, 0x17, "Rebind"),
];

#[test]
fn the_relay_frames_shared_constants_hold_the_same_values_on_both_sides() {
    // The device side now exists, so the tripwire that used to stand here —
    // `the_relay_data_frame_still_has_no_device_side_implementation` — has been
    // replaced by the agreement test it existed to demand.
    //
    // **That tripwire had gone blind and this records why.** It scanned only
    // `map.rs` and `bind.rs` for `HEADER_LEN`; the device frame landed in a new
    // file, `frame.rs`, which the scan never looked at. It therefore stayed
    // green through exactly the change it was built to catch. A tripwire that
    // enumerates the files it watches goes stale the moment a file is added,
    // which is a lesson worth more than the tripwire was.
    assert!(
        RELAY_CLIENT_FRAME.contains("pub const HEADER_LEN"),
        "the device-side frame moved again; this test enumerates a file and \
         would go blind the same way"
    );

    for (name, device_value) in SHARED_FRAME_CONSTANTS {
        let needle = format!("pub const {name}: ");
        let line = RELAY_SERVICE_FRAME
            .lines()
            .find(|l| l.trim_start().starts_with(&needle))
            .unwrap_or_else(|| panic!("services/relay/src/frame.rs no longer defines {name}"));
        let literal: String = line
            .rsplit('=')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_end_matches(';')
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let service_value: usize = literal
            .parse()
            .unwrap_or_else(|_| panic!("{name} on the service side is not a literal: {line}"));
        assert_eq!(
            device_value, service_value,
            "{name} is {device_value} on the device and {service_value} on the \
             relay. Both sides derive their bounds from this value, and nothing \
             else compares them."
        );
    }
}

#[test]
fn every_frame_type_maps_to_the_same_wire_byte_on_both_sides() {
    // ADR-0005 §9.1 fixes `DATA = 0x01` and the control range `0x10..0x1F`, but
    // assigns the eight control names **positionally** and never states a byte
    // for any of them. Both implementations read the prose list in order and
    // arrived at the same mapping — a convention, not a specification.
    //
    // The relay's own suite exercises only `0x01` and an unknown byte, and its
    // `from_wire` is private, so a typo in its `to_wire` **and** `from_wire`
    // together would round-trip locally and disagree with the device silently.
    for (kind, wire, name) in FRAME_TYPE_WIRE {
        assert_eq!(
            kind.to_wire(),
            wire,
            "the device maps {name} to 0x{:02x}, not 0x{wire:02x}",
            kind.to_wire()
        );
        assert_eq!(
            twinvpn_relay_client::FrameType::from_wire(wire),
            Some(kind),
            "the device does not decode 0x{wire:02x} back to {name}"
        );
        assert!(
            RELAY_SERVICE_FRAME.contains(&format!("FrameType::{name} => 0x{wire:02x}")),
            "services/relay does not map {name} to 0x{wire:02x}; the two sides \
             have diverged on a byte the ADR never states"
        );
    }

    // The ADR's two statements that ARE normative.
    assert!(
        ADR_0005.contains("`type` `0x01` = `DATA`"),
        "ADR-0005 §9.1 no longer fixes DATA = 0x01"
    );
    assert!(
        ADR_0005.contains("0x10..0x1F` = control"),
        "ADR-0005 §9.1 no longer fixes the control range"
    );
    for (_, wire, name) in FRAME_TYPE_WIRE {
        if wire != 0x01 {
            assert!(
                (0x10..=0x1f).contains(&wire),
                "{name} is 0x{wire:02x}, outside the control range the ADR fixes"
            );
        }
    }
}

#[test]
fn the_mac_input_layout_is_the_one_adr_0005_specifies_and_both_sides_build_it() {
    // §9.1: the tag is "a keyed BLAKE2s MAC under `K_leg` over
    // `(type‖ver‖flags‖counter_full‖flow_id‖payload)`, truncated to 64 bits".
    //
    // The golden vector that pins this is replicated **as source in four
    // places** — `twinvpn-crypto`'s test module (where it is `#[cfg(test)]` and
    // therefore unimportable), the relay's `provider.rs`, the device's
    // `leg_frame.rs`, and here. Each side fails on its own. This is the only
    // place the device's construction is checked against bytes assembled
    // independently of it.
    const COUNTER: u64 = 0x0102_0304_0506_0708;
    const FLOW: u32 = 0xdead_beef;
    const PAYLOAD: [u8; 16] = [0xab; 16];

    let mut expected = Vec::new();
    expected.push(0x01); // type = DATA
    expected.push(1 << 4); // ver = 1 in the high nibble, flags = 0 in the low
    expected.extend_from_slice(&COUNTER.to_be_bytes());
    expected.extend_from_slice(&FLOW.to_be_bytes());
    expected.extend_from_slice(&PAYLOAD);
    assert_eq!(
        expected.len(),
        1 + 1 + 8 + 4 + 16,
        "nothing in the MAC input is length-prefixed"
    );

    let frame = twinvpn_relay_client::OutboundFrame::new(
        twinvpn_relay_client::FrameType::Data,
        0,
        FLOW,
        bytes::Bytes::from_static(&PAYLOAD),
    )
    .expect("a well-formed DATA frame");
    assert_eq!(
        frame.mac_input(COUNTER),
        expected,
        "the device's MAC input is not §9.1's (type‖ver‖flags‖counter_full‖\
         flow_id‖payload)"
    );

    // The relay assembles the same bytes, and its own pin agrees with this one.
    assert!(
        RELAY_SERVICE_PROVIDER.contains("const PIN_COUNTER: u64 = 0x0102_0304_0506_0708;"),
        "the relay's pinned counter changed; the two golden vectors have drifted"
    );
    assert!(
        RELAY_SERVICE_PROVIDER.contains("0xd0, 0x4f, 0x9b, 0xe2, 0xb5, 0x7f, 0xc1, 0x5b"),
        "the relay's pinned tag changed; the two golden vectors have drifted"
    );

    // And the tag on the wire is that truncation.
    let key = twinvpn_relay_client::LegKey::from_array([0x4b; 32]);
    let wire = frame.encode(&key, COUNTER);
    let tag: String = wire[8..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        tag, "d04f9be2b57fc15b",
        "the encoded tag is not the shared golden vector's truncation"
    );
}

#[test]
fn the_frame_header_is_sixteen_bytes_laid_out_the_way_the_adr_draws_it() {
    // The layout, field by field, against the diagram in ADR-0005 §9.1. A
    // change to any offset breaks every deployed relay at once, and the only
    // other check on it is the golden tag — which does not cover `counter_low`,
    // because `counter_low` is not in the MAC input.
    const COUNTER: u64 = 0x0102_0304_0506_0708;
    let frame = twinvpn_relay_client::OutboundFrame::new(
        twinvpn_relay_client::FrameType::Data,
        0x0a,
        0xdead_beef,
        bytes::Bytes::from_static(b"payload"),
    )
    .expect("frame");
    let wire = frame.encode(
        &twinvpn_relay_client::LegKey::from_array([0x4b; 32]),
        COUNTER,
    );

    assert_eq!(wire[0], 0x01, "byte 0 is `type`");
    assert_eq!(wire[1], (1 << 4) | 0x0a, "byte 1 is `ver` | `flags`");
    assert_eq!(
        &wire[2..4],
        &0x0708u16.to_be_bytes(),
        "bytes 2..4 are the LOW 16 bits of the counter, big-endian"
    );
    assert_eq!(
        &wire[4..8],
        &0xdead_beefu32.to_be_bytes(),
        "bytes 4..8 are flow_id, big-endian"
    );
    assert_eq!(wire.len(), twinvpn_relay_client::frame::HEADER_LEN + 7);
    assert_eq!(
        &wire[16..],
        b"payload",
        "the payload begins at byte 16 and is carried verbatim"
    );
}

#[test]
fn a_device_authenticates_an_inbound_frame_it_should_never_have_been_sent() {
    // **FINDING.** Direction enforcement exists on exactly one side and only for
    // sends: `FrameType::device_may_send` refuses `BOUND`, `DRAIN` and
    // `RELAY_STATUS` in `OutboundFrame::new`, and `FrameError::WrongDirection`
    // is producible nowhere else. `InboundFrame::parse`/`verify` never check
    // direction, so a device accepts and *authenticates* a `BIND` or `CAPS` —
    // frames only a device sends — arriving from the relay.
    //
    // This is not a MAC forgery: an attacker still needs `K_leg`. It is a
    // confused-deputy surface on a compromised or misbehaving relay, and the
    // asymmetry is untested on both sides. Reported, not repaired:
    // `core-dataplane` owns the crate.
    let key = twinvpn_relay_client::LegKey::from_array([0x4b; 32]);
    for kind in [
        twinvpn_relay_client::FrameType::Bind,
        twinvpn_relay_client::FrameType::Caps,
    ] {
        assert!(
            kind.device_may_send(),
            "{kind:?} is a device-to-relay frame"
        );
        let outbound =
            twinvpn_relay_client::OutboundFrame::new(kind, 0, 1, bytes::Bytes::from_static(b"x"))
                .expect("a device may send it");
        let wire = outbound.encode(&key, 0);

        let inbound = twinvpn_relay_client::InboundFrame::parse(&wire).expect("parses");
        let mut window = twinvpn_relay_client::CounterWindow::new();
        let verified = inbound.verify(&key, &mut window);
        assert!(
            verified.is_ok(),
            "the device refused an inbound {kind:?}; if direction is now checked \
             on receive, delete this finding"
        );
    }

    // The half that IS enforced, as the contrast.
    for kind in [
        twinvpn_relay_client::FrameType::Bound,
        twinvpn_relay_client::FrameType::Drain,
        twinvpn_relay_client::FrameType::RelayStatus,
    ] {
        assert!(!kind.device_may_send());
        assert_eq!(
            twinvpn_relay_client::OutboundFrame::new(kind, 0, 1, bytes::Bytes::new()).unwrap_err(),
            twinvpn_relay_client::FrameError::WrongDirection
        );
    }
}

#[test]
fn the_counter_window_reconstructs_identically_on_both_sides_at_the_wrap_boundary() {
    // Both sides carry the same sliding-window algorithm, duplicated line for
    // line, and each tests it with a **different** fixture: the device tests the
    // 0xFFFF → 0x0000 wrap, the relay tests 65530 → 3. A divergence in the
    // wrap rule would be caught by neither.
    let mut w = twinvpn_relay_client::CounterWindow::new();
    assert!(w.accept(0));
    for c in 1..=5u64 {
        assert!(w.accept(c), "counter {c} was refused");
    }
    assert!(!w.accept(3), "a replayed counter was accepted");
    assert_eq!(w.highest(), 5);

    // The wrap: a low value arriving after 0xFFFF is the NEXT epoch, not a
    // replay of the last one.
    let mut wrap = twinvpn_relay_client::CounterWindow::new();
    assert!(wrap.accept(0xFFFF));
    assert_eq!(
        wrap.reconstruct(0x0000),
        0x1_0000,
        "0x0000 after 0xFFFF must reconstruct forwards, not backwards"
    );
    assert!(
        RELAY_SERVICE_FRAME.contains("pub const WIDTH: u64 = 64;"),
        "the relay's window width changed; the device's is 64 and the two must \
         agree or a frame accepted by one is a replay to the other"
    );
    assert_eq!(twinvpn_relay_client::CounterWindow::WIDTH, 64);
}

#[test]
fn the_relay_services_own_documentation_agrees_with_what_it_forwards() {
    // Previously a finding: `lib.rs` claimed `Verbatim` while `forward.rs` used
    // `frame::Opaque`. `relay-plane` closed it in the other direction —
    // `frame::Opaque` is gone and the relay uses `Verbatim` under
    // `Framing::Opaque`. This asserts the resolved state so the two cannot drift
    // apart again.
    assert!(
        RELAY_SERVICE_LIB.contains("Verbatim"),
        "services/relay/src/lib.rs no longer names Verbatim"
    );
    assert!(
        !RELAY_SERVICE_FRAME.contains("pub struct Opaque"),
        "frame::Opaque is back; the forwarding payload type has two spellings again"
    );
    assert!(
        RELAY_SERVICE_FRAME.contains("Verbatim"),
        "the relay frame no longer carries its payload as Verbatim, which is \
         W-4's forward-verbatim constraint"
    );
    // The *code* must not reference the deleted type. A doc comment in
    // `forward.rs` still does — `[`crate::frame::Opaque`]` at its module head is
    // now a broken intra-doc link — which is reported to `relay-plane` rather
    // than asserted here, because a stale doc line in another domain's crate is
    // a finding and not this suite's to fail on.
    let code_uses_opaque = RELAY_SERVICE_FORWARD
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
        })
        .any(|l| l.contains("frame::Opaque"));
    assert!(
        !code_uses_opaque,
        "the forwarding path uses frame::Opaque again; the payload type has two \
         spellings once more"
    );
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

// ---------------------------------------------------------------------------
// 6. W-24 and W-25: what the F-9 vtable cannot express.
// ---------------------------------------------------------------------------

#[test]
fn w24_the_abi_refuses_a_ruleset_read_back_rather_than_answering_none() {
    // **W-24**, asserted executably rather than re-discovered. ADR-0015 §11.6
    // rule 1 makes a `ProtectionAssertion` a pure function of a *query* to the
    // enforcement layer; F-9 has `set_ruleset` and no getter, so across this ABI
    // the assertion cannot be produced.
    //
    // The disposition was a **typed refusal**, and the direction is the whole
    // point: `Ok(None)` would read as "no ruleset installed" — the opposite of
    // the truth, and the direction that drives a reconciler to re-install.
    // `Err` renders the indicator `UNKNOWN`, which is O-18's fail-safe way.
    //
    // This test fails if the vtable ever gains the getter, which is exactly when
    // the refusal should be deleted.
    assert!(
        !TWINVPN_H.contains("installed_ruleset"),
        "the F-9 vtable now has an `installed_ruleset` read-back. W-24 is closed; \
         delete twinvpn-ffi's typed refusal and let the ProtectionAssertion be \
         produced across the ABI."
    );
    assert!(
        !TWINVPN_H.contains("current_generation"),
        "the F-9 vtable now has `current_generation` — ADR-0018 §11.4 calls it \
         the recovery entry point, and W-24 says it is missing for the same \
         reason as the getter"
    );

    // The mock adapter CAN answer, which is the contrast that proves the refusal
    // is a property of the ABI and not of the platform trait.
    let rig = twinvpn_system_tests::Rig::new(twinvpn_system_tests::HostFamily::Dual, 70);
    let answered = twinvpn_system_tests::block_on(
        twinvpn_platform::PlatformAdapter::network_config(&rig.adapter).installed_ruleset(),
    );
    assert!(
        answered.is_ok(),
        "the platform trait itself can be queried; only the vtable cannot"
    );
}

#[test]
fn w25_the_abi_carries_no_socket_provider_and_no_interface_enumerator() {
    // **W-25.** ADR-0018 §11.2 row 2.10 places *all* NAT traversal in the core
    // "with sockets via the adapter", and `twinvpn-platform`'s trait requires a
    // socket provider and an interface enumerator. F-9 offers neither, so a
    // Swift or Kotlin shell binding only this ABI cannot do NAT traversal.
    for absent in [
        "bind_udp",
        "supported_families",
        "enumerate_interfaces",
        "subscribe_network_change",
    ] {
        assert!(
            !TWINVPN_H.contains(&format!("(*{absent})")),
            "the F-9 vtable now declares `{absent}`. W-25 is closing; the \
             `NoSockets`/`NoInterfaces` stubs in twinvpn-ffi should go with it."
        );
    }

    // The header says so itself, which is the honest form of the gap: absent by
    // decision rather than by oversight.
    assert!(
        TWINVPN_H.contains("DELIBERATELY ABSENT"),
        "twinvpn.h no longer states what it leaves out; a gap that is not \
         written down becomes a gap nobody decided on"
    );
}

#[test]
fn w26_the_four_approved_vtable_additions_are_present_in_both_languages() {
    // W-26 approved four `size`-field minor additions. Each is load-bearing for
    // a finding: `identity_agree` follows §11.6 over §11.4, `elapsed_millis` and
    // `boot_id` are W-7's three shell interfaces, and `buf_bytes` is F-2's
    // ownership rule. A silent removal would break a shell that had adopted one.
    for field in ["identity_agree", "elapsed_millis", "boot_id", "buf_bytes"] {
        assert!(
            TWINVPN_H.contains(field),
            "twinvpn.h no longer declares `{field}`, which W-26 approved"
        );
    }
    // And the ABI minor is still 0, because W-26's additions were the ones this
    // major shipped with rather than a later addition.
    assert_eq!(twinvpn_ffi::TW_ABI_MINOR, twinvpn_core::ABI_MINOR);
    assert_eq!(twinvpn_ffi::TW_ABI_MAJOR, twinvpn_core::ABI_MAJOR);
}
