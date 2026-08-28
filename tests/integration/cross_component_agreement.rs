//! **Integration.** Pairs of artifacts that must agree, and cannot link each
//! other to find out.
//!
//! **Authority:** `docs/testing-strategy.md` §2.4; the pattern is
//! `services/control-plane/tests/client_agreement.rs`, which reads the client's
//! table, the frozen `.proto` and `contract-matrix.md` and asserts all three
//! agree.
//!
//! # Enumerate the property, not the files or the literals
//!
//! This file was written as compile-time `include_str!` of the other side's
//! source, because `core/`, `services/`, `lab/` and `tests/` are separate cargo
//! workspaces and a client crate cannot link its server. That reasoning is still
//! true. The conclusion drawn from it was wrong, and it broke four times in one
//! wave — twice in this domain's own tests:
//!
//! - a `HEADER_LEN` tripwire scanned `map.rs` and `bind.rs`; the device frame
//!   landed in a new `frame.rs` and it stayed green through exactly the change
//!   it was built to catch;
//! - a MAC-vector check scraped `services/relay/src/provider.rs` for four
//!   literal declarations, and failed with "the two golden vectors have
//!   drifted" on the day `relay-plane` **deleted** those literals in favour of
//!   one shared artifact. The opposite of drift, reported as drift.
//!
//! A check that enumerates its subject's source form fails loudest exactly when
//! the subject improves. So the rule this file now follows:
//!
//! | Read | Do not read |
//! |---|---|
//! | a **frozen contract** — `relay.proto`, `limits.json`, `reason_codes.json`, the generated bindings | another crate's **source** |
//! | a **specification** — an ADR's normative sentence, the ABI header | another crate's **literals** |
//! | a **shared artifact** by value — `twinvpn_crypto::blake2s::vectors` | a file list, or a variant list, spelled out here |
//!
//! Where the two sides can be made to share one artifact, agreement becomes a
//! value comparison and this file stops being the place it is checked. Where
//! they cannot, an **exhaustive match** against the generated bindings moves the
//! check to the compiler, which is stronger than any string search: a variant
//! added on either side fails to build.
//!
//! # The one residual, named
//!
//! `services/rendezvous`'s framing is finding **RZ-1**: `contracts/` declares no
//! message for it, so its README §5 table is the specification of record and
//! `src/frame.rs` is the only implementation. There is nothing to compare by
//! value and nothing frozen to compare against, so the opcode check below is
//! still a source read. It is the residual of a missing contract rather than a
//! choice, and it goes away the day RZ-1 does.

use twinvpn_crypto::blake2s::vectors;
use twinvpn_schema::v1;
use twinvpn_types::ReasonCode;

// ---------------------------------------------------------------------------
// The artifacts, read as text at compile time.
// ---------------------------------------------------------------------------

const RELAY_PROTO: &str = include_str!("../../contracts/proto/twinvpn/v1/relay.proto");
const LIMITS_JSON: &str = include_str!("../../contracts/registry/limits.json");
const REASON_CODES_JSON: &str = include_str!("../../contracts/registry/reason_codes.json");

const ADR_0005: &str = include_str!("../../docs/adr/ADR-0005-relay-architecture.md");
const TWINVPN_H: &str = include_str!("../../core/ffi/include/twinvpn.h");

const RENDEZVOUS_FRAME: &str = include_str!("../../services/rendezvous/src/frame.rs");
const RENDEZVOUS_README: &str = include_str!("../../services/rendezvous/README.md");

// ---------------------------------------------------------------------------
// 1. Relay: three spellings of the same three enums.
// ---------------------------------------------------------------------------
//
// These used to compare the device's enum against `contracts/`'s `.proto` text
// and `services/relay-directory/src/fleet.rs`'s source. The proto half was
// legitimate — a frozen contract is a specification — but the source half was
// the pattern that broke elsewhere in this file, and the proto half only ever
// proved that a *name* appeared somewhere in a file.
//
// What replaces both: an **exhaustive match in each direction** against the
// generated bindings. A variant added to either side fails to compile here,
// which is a stronger guarantee than any string search, and it is checked by
// the compiler rather than by a test that has to be run and read.

fn carriage_to_wire(c: twinvpn_relay_client::map::Carriage) -> v1::RelayCarriage {
    match c {
        twinvpn_relay_client::map::Carriage::Udp => v1::RelayCarriage::Udp,
        twinvpn_relay_client::map::Carriage::Quic => v1::RelayCarriage::Quic,
        twinvpn_relay_client::map::Carriage::Tls => v1::RelayCarriage::Tls,
    }
}

fn carriage_from_wire(w: v1::RelayCarriage) -> Option<twinvpn_relay_client::map::Carriage> {
    match w {
        v1::RelayCarriage::Unspecified => None,
        v1::RelayCarriage::Udp => Some(twinvpn_relay_client::map::Carriage::Udp),
        v1::RelayCarriage::Quic => Some(twinvpn_relay_client::map::Carriage::Quic),
        v1::RelayCarriage::Tls => Some(twinvpn_relay_client::map::Carriage::Tls),
    }
}

fn admin_to_wire(a: twinvpn_relay_client::map::AdminState) -> v1::RelayAdminState {
    match a {
        twinvpn_relay_client::map::AdminState::Active => v1::RelayAdminState::Active,
        twinvpn_relay_client::map::AdminState::Draining => v1::RelayAdminState::Draining,
        twinvpn_relay_client::map::AdminState::Retired => v1::RelayAdminState::Retired,
    }
}

fn admin_from_wire(w: v1::RelayAdminState) -> Option<twinvpn_relay_client::map::AdminState> {
    match w {
        v1::RelayAdminState::Unspecified => None,
        v1::RelayAdminState::Active => Some(twinvpn_relay_client::map::AdminState::Active),
        v1::RelayAdminState::Draining => Some(twinvpn_relay_client::map::AdminState::Draining),
        v1::RelayAdminState::Retired => Some(twinvpn_relay_client::map::AdminState::Retired),
    }
}

fn health_to_wire(h: twinvpn_relay_client::map::HealthState) -> v1::HealthState {
    match h {
        twinvpn_relay_client::map::HealthState::Healthy => v1::HealthState::Healthy,
        twinvpn_relay_client::map::HealthState::Degraded => v1::HealthState::Degraded,
        twinvpn_relay_client::map::HealthState::Unhealthy => v1::HealthState::Unhealthy,
        twinvpn_relay_client::map::HealthState::Unknown => v1::HealthState::Unknown,
    }
}

fn health_from_wire(w: v1::HealthState) -> Option<twinvpn_relay_client::map::HealthState> {
    match w {
        v1::HealthState::Unspecified => None,
        v1::HealthState::Healthy => Some(twinvpn_relay_client::map::HealthState::Healthy),
        v1::HealthState::Degraded => Some(twinvpn_relay_client::map::HealthState::Degraded),
        v1::HealthState::Unhealthy => Some(twinvpn_relay_client::map::HealthState::Unhealthy),
        v1::HealthState::Unknown => Some(twinvpn_relay_client::map::HealthState::Unknown),
    }
}

#[test]
fn the_relay_carriage_vocabulary_is_the_frozen_one_exactly() {
    // A carriage the device cannot name is a relay it silently never selects.
    // The two matches above make that a compile error; this asserts the round
    // trip and that `UNSPECIFIED` — proto3's zero value — maps to nothing,
    // because a relay published with no carriage must not read as UDP.
    for c in [
        twinvpn_relay_client::map::Carriage::Udp,
        twinvpn_relay_client::map::Carriage::Quic,
        twinvpn_relay_client::map::Carriage::Tls,
    ] {
        assert_eq!(carriage_from_wire(carriage_to_wire(c)), Some(c));
    }
    assert_eq!(carriage_from_wire(v1::RelayCarriage::Unspecified), None);

    // The wire numbers are the contract's, so a renumbering is caught too.
    assert_eq!(
        carriage_to_wire(twinvpn_relay_client::map::Carriage::Udp) as i32,
        1
    );
    assert_eq!(
        carriage_to_wire(twinvpn_relay_client::map::Carriage::Quic) as i32,
        2
    );
    assert_eq!(
        carriage_to_wire(twinvpn_relay_client::map::Carriage::Tls) as i32,
        3
    );
}

#[test]
fn the_admin_state_vocabulary_is_the_frozen_one_exactly() {
    // A state the directory publishes and the client cannot read is a relay
    // that is never excluded — `RETIRED` being unreadable is the dangerous
    // direction, because the device would keep binding to a relay that no
    // longer exists as a signed entity.
    for a in [
        twinvpn_relay_client::map::AdminState::Active,
        twinvpn_relay_client::map::AdminState::Draining,
        twinvpn_relay_client::map::AdminState::Retired,
    ] {
        assert_eq!(admin_from_wire(admin_to_wire(a)), Some(a));
    }
    assert_eq!(admin_from_wire(v1::RelayAdminState::Unspecified), None);
    assert_eq!(
        admin_to_wire(twinvpn_relay_client::map::AdminState::Retired) as i32,
        3
    );
}

#[test]
fn the_health_state_vocabulary_is_the_frozen_one_exactly() {
    // W-20: `HealthState` is exported from `connection.proto` and was once
    // modelled twice. The exhaustive matches make a third model impossible to
    // introduce silently.
    for h in [
        twinvpn_relay_client::map::HealthState::Healthy,
        twinvpn_relay_client::map::HealthState::Degraded,
        twinvpn_relay_client::map::HealthState::Unhealthy,
        twinvpn_relay_client::map::HealthState::Unknown,
    ] {
        assert_eq!(health_from_wire(health_to_wire(h)), Some(h));
    }
    assert_eq!(health_from_wire(v1::HealthState::Unspecified), None);

    // The contract's own comment — "NEVER RENDERED AS HEALTHY" — is a property
    // of `UNKNOWN`, and the device's default must honour it.
    assert_eq!(
        twinvpn_relay_client::map::HealthState::default(),
        twinvpn_relay_client::map::HealthState::Unknown,
        "the device's default health must be UNKNOWN, never HEALTHY"
    );
}

#[test]
fn the_pair_tag_bucket_the_client_uses_is_the_one_limits_json_fixes() {
    // A device bucketing on a different period presents a `pair_tag` the relay
    // computes differently, and the two peers never match. The failure is
    // silent: the relay simply never pairs them.
    let limits: serde_json::Value = serde_json::from_str(LIMITS_JSON).expect("limits.json");
    assert_eq!(
        twinvpn_relay_client::bind::BUCKET_SECONDS,
        limits["relay"]["pair_tag_bucket_seconds"]
            .as_u64()
            .expect("relay.pair_tag_bucket_seconds"),
        "twinvpn-relay-client's BUCKET_SECONDS disagrees with limits.json"
    );
    assert_eq!(
        twinvpn_relay_client::bind::ACCEPTED_BUCKET_SKEW,
        limits["relay"]["accepted_bucket_skew"]
            .as_u64()
            .expect("relay.accepted_bucket_skew"),
        "twinvpn-relay-client's ACCEPTED_BUCKET_SKEW disagrees with limits.json"
    );
}

#[test]
fn a_bind_request_carries_nothing_but_the_pair_tag_and_its_leg_shape() {
    // I1's client half. This used to grep the source for forbidden field names,
    // which catches only the names it thought to list. Exhaustive destructuring
    // catches **any** added field, at compile time: adding `device_id` to
    // `BindRequest` breaks this line, and the reviewer has to say why.
    let request = twinvpn_relay_client::bind::BindRequest {
        pair_tag: twinvpn_types::PairTag::from_array([0x33; 16]),
        bucket: 1,
        carriage: twinvpn_relay_client::map::Carriage::Udp,
        family: twinvpn_types::AddressFamily::V4,
    };
    let twinvpn_relay_client::bind::BindRequest {
        pair_tag,
        bucket,
        carriage,
        family,
    } = request;

    // And each surviving field is one the relay may see: a blinded tag, the
    // bucket it was derived for, and the leg's own shape. None of them names a
    // peer, and the relay must never learn one (I1).
    assert_eq!(twinvpn_types::Identifier::as_bytes(&pair_tag).len(), 16);
    assert_eq!(bucket, 1);
    assert_eq!(carriage, twinvpn_relay_client::map::Carriage::Udp);
    assert_eq!(family, twinvpn_types::AddressFamily::V4);

    // The contract agrees that the tag is what identifies the pair.
    assert!(
        RELAY_PROTO.contains("pair_tag"),
        "relay.proto no longer carries pair_tag"
    );
}

/// The nine frame types, with the wire byte each occupies.
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

/// A conforming relay must carry the overlay floor plus L-DATA's overhead.
///
/// Every term is a `const`, so this is a **build** failure rather than a test
/// failure — which is the stronger place for it. A relay leg whose maximum
/// payload fell below `OVERLAY_MTU_FLOOR + L_DATA_OVERHEAD_BYTES` would
/// black-hole every full-size packet on every carriage, and no test run would be
/// needed to know that.
const _: () = assert!(
    twinvpn_relay_client::frame::MAX_DATA_PAYLOAD_BYTES
        >= twinvpn_relay_client::frame::OVERLAY_MTU_FLOOR
            + twinvpn_relay_client::frame::L_DATA_OVERHEAD_BYTES,
    "the relay leg cannot carry the overlay floor plus L-DATA overhead"
);

#[test]
fn the_frame_constants_are_derived_from_the_specification_not_from_each_other() {
    use twinvpn_relay_client::frame as f;

    // `VERSION` and the `DATA` byte now live in one artifact all three sides
    // import, so agreement is a value comparison against it.
    assert_eq!(
        f::VERSION,
        vectors::FRAME_VERSION,
        "the device's frame VERSION disagrees with the shared vector's"
    );
    assert_eq!(
        twinvpn_relay_client::FrameType::Data.to_wire(),
        vectors::FRAME_TYPE_DATA
    );
    assert_eq!(
        f::VERSION << 4,
        vectors::FRAME_VER_FLAGS,
        "byte 1 is `ver` in the high nibble and `flags` in the low"
    );

    // `HEADER_LEN` is the sum of §9.1's field widths, not a number to remember:
    // type(1) + ver|flags(1) + counter_low(2) + flow_id(4) + tag(8).
    assert_eq!(
        f::HEADER_LEN,
        1 + 1 + 2 + 4 + f::TAG_LEN,
        "HEADER_LEN is no longer the sum of the fields the ADR draws"
    );

    // The overlay floor is one value shared with the route planner. Nothing
    // compared them before, and a relay carrying less than the planner installs
    // would black-hole every full-size packet.
    assert_eq!(
        f::OVERLAY_MTU_FLOOR,
        twinvpn_route::plan::MTU_FLOOR as usize,
        "the relay leg's overlay floor and the route planner's MTU floor differ"
    );

    // `MAX_DATA_PAYLOAD_BYTES` is derived from §9.2's overhead table at the row
    // with the least framing beneath `RelayFrame` — R-UDP over IPv4 — so it is
    // asserted as that arithmetic rather than as the literal it evaluates to.
    assert_eq!(
        f::MAX_DATA_PAYLOAD_BYTES,
        1500 - 20 - 8 - f::HEADER_LEN,
        "the DATA payload bound is no longer 1500 minus IPv4, UDP and RelayFrame"
    );
    // The conformance relation between the three is asserted at COMPILE time,
    // just below — every term is a `const`, so a runtime `assert!` would be
    // folded to `true` and could never fail. Clippy catches that, and it is
    // right to: an assertion that cannot fail is not a test.

    // And it is NOT C4's cap. Borrowing the rendezvous bound here would make the
    // 1280 overlay floor unachievable on every carriage — the mistake the
    // constant's own documentation exists to prevent.
    assert_ne!(
        f::MAX_DATA_PAYLOAD_BYTES,
        twinvpn_schema::limits::C4_MAX_BYTES,
        "the DATA bound has been set to C4's pre-authentication cap"
    );
}

#[test]
fn every_frame_type_round_trips_and_sits_where_the_adr_puts_it() {
    // ADR-0005 §9.1 fixes `DATA = 0x01` and the control range `0x10..0x1F`, and
    // assigns the eight control names **positionally** without stating a byte
    // for any of them. Both implementations read that list in order; the mapping
    // is a convention. So what is asserted here is the device's round trip, the
    // two bytes the ADR does fix, and that every control type lands inside the
    // range it fixes — none of which needs anyone's source.
    let mut seen: Vec<u8> = Vec::new();
    for (kind, wire, name) in FRAME_TYPE_WIRE {
        assert_eq!(
            kind.to_wire(),
            wire,
            "{name} maps to 0x{:02x}, not 0x{wire:02x}",
            kind.to_wire()
        );
        assert_eq!(
            twinvpn_relay_client::FrameType::from_wire(wire),
            Some(kind),
            "0x{wire:02x} does not decode back to {name}"
        );
        assert!(
            !seen.contains(&wire),
            "0x{wire:02x} is assigned twice; {name} collides with an earlier type"
        );
        seen.push(wire);
        if wire != vectors::FRAME_TYPE_DATA {
            assert!(
                (0x10..=0x1f).contains(&wire),
                "{name} is 0x{wire:02x}, outside the control range the ADR fixes"
            );
        }
    }

    // The ADR's two normative statements, read from the specification rather
    // than from anyone's implementation.
    assert!(
        ADR_0005.contains("`type` `0x01` = `DATA`"),
        "ADR-0005 §9.1 no longer fixes DATA = 0x01"
    );
    assert!(
        ADR_0005.contains("0x10..0x1F` = control"),
        "ADR-0005 §9.1 no longer fixes the control range"
    );

    // An unassigned byte is refused rather than guessed at.
    for unassigned in [0x00u8, 0x02, 0x18, 0x1f, 0xff] {
        assert_eq!(
            twinvpn_relay_client::FrameType::from_wire(unassigned),
            None,
            "0x{unassigned:02x} is unassigned and was decoded anyway"
        );
    }
}

#[test]
fn the_mac_input_is_the_shared_vector_built_through_the_devices_own_assembler() {
    // §9.1: the tag is "a keyed BLAKE2s MAC under `K_leg` over
    // `(type‖ver‖flags‖counter_full‖flow_id‖payload)`, truncated to 64 bits".
    //
    // This test used to compare the device's construction against literals
    // scraped out of `services/relay/src/provider.rs`. `relay-plane` then
    // imported the shared vectors and deleted its copies — and the scrape
    // failed, reporting "the two golden vectors have drifted" when the opposite
    // had happened. A check that enumerates its subject's source form fails
    // loudest exactly when the subject improves.
    //
    // What replaces it: the frame is built from the **field** constants through
    // the device's own assembler and compared against the assembled constant.
    // Importing `FRAME_MAC_INPUT` and handing it straight to the MAC would only
    // prove that a crate can copy an array.
    let frame = twinvpn_relay_client::OutboundFrame::new(
        twinvpn_relay_client::FrameType::Data,
        vectors::FRAME_FLAGS,
        vectors::FRAME_FLOW_ID,
        bytes::Bytes::from_static(&vectors::FRAME_PAYLOAD),
    )
    .expect("a well-formed DATA frame");

    assert_eq!(
        frame.mac_input(vectors::FRAME_COUNTER_FULL),
        vectors::FRAME_MAC_INPUT,
        "the device's MAC input is not §9.1's \
         (type‖ver‖flags‖counter_full‖flow_id‖payload)"
    );

    // The tag on the wire is that input's truncated MAC.
    let key = twinvpn_relay_client::LegKey::from_array(vectors::FRAME_MAC_KEY);
    let wire = frame.encode(&key, vectors::FRAME_COUNTER_FULL);
    assert_eq!(
        &wire[8..16],
        &vectors::FRAME_MAC_TAG,
        "the encoded tag is not the shared vector's"
    );

    // The truncation discrimination stays pinned: a reading that asks BLAKE2s
    // for an 8-byte output instead of truncating a 32-byte one is a *different*
    // value, and the device must not produce it.
    assert_ne!(
        vectors::FRAME_MAC_TAG,
        vectors::FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED,
        "the accepted and rejected readings are equal, so the pin is vacuous"
    );
    assert_ne!(
        wire[8..16],
        vectors::FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED,
        "the device produced the short-output reading ADR-0005 rejects"
    );
}

#[test]
fn the_shared_vectors_agree_with_the_implementation_that_produced_them() {
    // One shared artifact removes four copies and introduces exactly one new
    // failure mode: the artifact drifting from `frame_mac`. `self_consistency`
    // is published so every consumer can close that hole rather than assume it,
    // and both relay crates already call it. This suite is a third caller — and
    // the only one that is neither the artifact's own crate nor a producer.
    vectors::self_consistency();

    // The HRW half, so the relay-directory's ranking input is covered here too
    // rather than only in its own suite.
    assert_eq!(
        twinvpn_crypto::blake2s::hrw_weight_digest(&vectors::HRW_RELAY_ID, &vectors::HRW_PAIR_ID),
        vectors::HRW_DIGEST
    );
}

#[test]
fn the_frame_header_is_sixteen_bytes_laid_out_the_way_the_adr_draws_it() {
    // The layout, field by field, against the diagram in ADR-0005 §9.1. A change
    // to any offset breaks every deployed relay at once, and the only other
    // check on it is the golden tag — which does not cover `counter_low`,
    // because `counter_low` is not in the MAC input.
    const FLAGS: u8 = 0x0a;
    let frame = twinvpn_relay_client::OutboundFrame::new(
        twinvpn_relay_client::FrameType::Data,
        FLAGS,
        vectors::FRAME_FLOW_ID,
        bytes::Bytes::from_static(b"payload"),
    )
    .expect("frame");
    let wire = frame.encode(
        &twinvpn_relay_client::LegKey::from_array(vectors::FRAME_MAC_KEY),
        vectors::FRAME_COUNTER_FULL,
    );

    assert_eq!(wire[0], vectors::FRAME_TYPE_DATA, "byte 0 is `type`");
    assert_eq!(
        wire[1],
        (twinvpn_relay_client::frame::VERSION << 4) | FLAGS,
        "byte 1 is `ver` | `flags`"
    );
    assert_eq!(
        &wire[2..4],
        &vectors::FRAME_COUNTER_LOW.to_be_bytes(),
        "bytes 2..4 are the LOW 16 bits of the counter, big-endian"
    );
    assert_eq!(
        &wire[4..8],
        &vectors::FRAME_FLOW_ID.to_be_bytes(),
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
fn the_counter_window_reconstructs_forwards_at_the_wrap_boundary() {
    // Both sides carry the same sliding-window algorithm, and each tests it with
    // a different fixture: the device tests the 0xFFFF → 0x0000 wrap, the relay
    // tests 65530 → 3. Neither covers the other's. The window width has no
    // shared artifact to compare against, so what is asserted here is the
    // device's behaviour at the boundary — the relay pins its own.
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

    // And the width is real rather than declared: a counter exactly `WIDTH`
    // behind the highest is too old to distinguish from a replay.
    let mut edge = twinvpn_relay_client::CounterWindow::new();
    let width = twinvpn_relay_client::CounterWindow::WIDTH;
    assert!(edge.accept(width));
    assert!(
        edge.accept(1),
        "a counter inside the window must be judgeable"
    );
    assert!(
        !edge.accept(0),
        "a counter {width} behind the highest must be refused as too old"
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
