//! **Integration.** The sender and the receiver, checked against each other.
//!
//! **Authority:** ADR-0001 §7.1 (the replay window), ADR-0006 §11.2 (the relay
//! score); `docs/implementation/ownership.md` §8 findings **W-31** and **D-2**.
//!
//! # Where this file came from
//!
//! It is what survives `tests/defects/tripwires.rs`, which is now deleted. That
//! file recorded five defects as executable evidence; `core-dataplane` fixed all
//! five, so the tripwires were removed with them.
//!
//! What must **not** be removed is the shape that found the worst of them. W-31
//! — the first data packet of every tunnel rejected as a replay — was invisible
//! to both owning crates' suites because **every existing test started at
//! counter 1**. The replay window was thoroughly tested for the attack it
//! defends against and untested at its own origin, and only a test that ran a
//! sender against a receiver could see it.
//!
//! So the tripwires are gone and the *regressions* stay, in their positive form:
//! these assert the fixed behaviour, and they are permanent.
//!
//! # The receiver was fixed, not the sender, and that reasoning is preserved here
//!
//! `core-dataplane` moved `ReplayWindow`'s origin rather than `SendCounter`'s. A
//! conforming peer sends counter 0 first, so a receiver refusing it is broken
//! against every correct implementation regardless of its own sender; starting
//! `SendCounter` at 1 would have made two TwinVPN devices agree with each other
//! and left them both wrong against WireGuard. `interoperability_is_what_fixing_the
//! _receiver_bought` states that as an assertion rather than as a memory.

use twinvpn_env::MonotonicInstant;
use twinvpn_relay_client::map::{AdminState, Carriage, HealthState, Relay};
use twinvpn_relay_client::select::{score, Observations, BASE, MAX_MEASUREMENT_PENALTY};
use twinvpn_tunnel::crypto::{CryptoUnavailable, TransportKeys};
use twinvpn_tunnel::replay::{ReplayWindow, SendCounter, WINDOW_BITS};
use twinvpn_tunnel::{Tunnel, TunnelError};
use twinvpn_types::{
    Endpoint, IpAddr, PerFamily, Port, RegionId, RelayId, SessionId, TunnelId, V4Addr,
};

const ADR_0001: &str =
    include_str!("../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md");

// ---------------------------------------------------------------------------
// A sender and a receiver, which is the composition neither crate tests.
// ---------------------------------------------------------------------------

/// A deterministic, reversible stand-in for the record AEAD.
///
/// **Not cryptography, and it does not claim to be.** It exists so the replay
/// window and the send counter can be exercised through `Tunnel`'s real
/// seal/open path without key material. It is reversible and counter-dependent,
/// so a counter mismatch is still detectable — which is the only property these
/// tests need from it.
struct ReversibleKeys;

impl TransportKeys for ReversibleKeys {
    fn seal(
        &self,
        counter: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        out.clear();
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(plaintext);
        Ok(())
    }

    fn open(
        &self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoUnavailable> {
        if ciphertext.len() < 8 || ciphertext[..8] != counter.to_le_bytes() {
            return Err(CryptoUnavailable);
        }
        out.clear();
        out.extend_from_slice(&ciphertext[8..]);
        Ok(())
    }

    fn zeroize(&mut self) {}
}

fn established_tunnel(seed: u8) -> Tunnel {
    let mut t = Tunnel::absent(
        TunnelId::from_array([seed; 16]),
        SessionId::from_array([seed; 16]),
        MonotonicInstant::ORIGIN,
    );
    t.handshake_completed(
        Box::new(ReversibleKeys),
        Endpoint::new(
            IpAddr::V4(V4Addr::from_octets([198, 51, 100, 1])),
            Port::new(51820).expect("port"),
        ),
        1,
        MonotonicInstant::ORIGIN,
    );
    let transcript = [seed; 32];
    t.confirm_negotiation(&transcript, &transcript)
        .expect("matching transcripts");
    t
}

#[test]
fn w31_the_first_data_packet_a_tunnel_sends_is_accepted_by_its_peer() {
    // The permanent regression for the wave's P1. If this ever fails again, no
    // tunnel can carry its first packet — and no unit test in either owning
    // crate would notice, because this is the only place a sender meets a
    // receiver.
    let mut sender = established_tunnel(1);
    let mut receiver = established_tunnel(1);

    let mut wire = Vec::new();
    let counter = sender.seal(b"the first packet", &mut wire).expect("seal");
    assert_eq!(counter, 0, "a conforming peer sends counter 0 first");

    let mut plain = Vec::new();
    receiver
        .open(counter, &wire, &mut plain)
        .expect("W-31 HAS REGRESSED: the first record of every tunnel is rejected");
    assert_eq!(plain, b"the first packet");
}

#[test]
fn a_whole_run_of_records_survives_the_seam_in_order() {
    // The generalisation: not just the first, but a run long enough to cross the
    // first window word. A window that treated its own origin specially would
    // have failed at 0; one that shifts wrongly fails somewhere in here.
    let mut sender = established_tunnel(2);
    let mut receiver = established_tunnel(2);
    for i in 0..200u64 {
        let mut wire = Vec::new();
        let counter = sender
            .seal(format!("record {i}").as_bytes(), &mut wire)
            .expect("seal");
        assert_eq!(counter, i, "the send counter skipped a value");
        let mut plain = Vec::new();
        receiver
            .open(counter, &wire, &mut plain)
            .unwrap_or_else(|e| panic!("record {i} was refused: {e:?}"));
        assert_eq!(plain, format!("record {i}").into_bytes());
    }
}

#[test]
fn a_replayed_record_is_still_refused_and_the_refusal_is_fatal() {
    // The property the origin fix must not have weakened. A window that accepted
    // counter 0 by accepting *everything* would pass the two tests above and
    // defend against nothing.
    let mut sender = established_tunnel(3);
    let mut receiver = established_tunnel(3);
    let mut wire = Vec::new();
    let counter = sender.seal(b"once", &mut wire).expect("seal");

    let mut plain = Vec::new();
    receiver
        .open(counter, &wire, &mut plain)
        .expect("first delivery");
    assert_eq!(
        receiver.open(counter, &wire, &mut plain),
        Err(TunnelError::Replay),
        "the same record was accepted twice"
    );
}

#[test]
fn interoperability_is_what_fixing_the_receiver_bought() {
    // The two halves must agree about what counter 0 means, and the agreement
    // must be the *wire's*, not ours: a conforming peer's first record is 0.
    //
    // This is why the fix went into the receiver. A `SendCounter` starting at 1
    // would satisfy "our sender and our receiver agree" — the two tests above
    // would pass — while leaving both ends wrong against every other correct
    // implementation. Asserted separately so that a future change that "fixes"
    // it the other way fails here rather than in the field.
    let mut counter = SendCounter::new();
    assert_eq!(
        counter.take_next(),
        Some(0),
        "the sender's first counter must be 0, which is what a conforming peer \
         emits; moving it to 1 makes two TwinVPN devices agree with each other \
         and both wrong against WireGuard"
    );
    assert!(
        ReplayWindow::new().would_accept(0),
        "a fresh replay window must accept counter 0"
    );
    assert!(
        !ReplayWindow::new().would_accept(u64::MAX),
        "the control: the window is not simply accept-everything"
    );
}

#[test]
fn the_replay_window_is_the_width_adr_0001_specifies() {
    // The second defect found while fixing W-31: the window was 2048 counters
    // where ADR-0001 §7.1 specifies 8192. Nobody had flagged it, because the
    // width appears in the ADR as prose and in the code as a constant, and
    // nothing compared them.
    assert_eq!(
        WINDOW_BITS, 8192,
        "the replay window is {WINDOW_BITS} counters; ADR-0001 §7.1 specifies 8192"
    );
    assert!(
        ADR_0001.contains("8192"),
        "ADR-0001 no longer states the window width; the constant is now \
         unanchored and the next change to it will be invisible"
    );

    // And the width is real, not just declared: a counter one short of the
    // window is still judgeable, and one past it is refused as too old.
    let mut w = ReplayWindow::new();
    assert!(w.accept(WINDOW_BITS));
    assert!(
        w.would_accept(1),
        "a counter {} behind the highest must still be within the window",
        WINDOW_BITS - 1
    );
    assert!(
        !w.would_accept(0),
        "a counter {WINDOW_BITS} behind the highest is too old to distinguish \
         from a replay and must be refused"
    );
}

// ---------------------------------------------------------------------------
// D-2's fix: the measurement contribution is bounded again.
// ---------------------------------------------------------------------------

fn relay(id: u8) -> Relay {
    Relay {
        id: RelayId::from_array([id; 8]),
        operator_group_id: "twinvpn".to_owned(),
        region: RegionId::new("eu-west").expect("region"),
        endpoints: PerFamily::new(
            vec![Endpoint::new(
                IpAddr::V4(V4Addr::from_octets([198, 51, 100, id])),
                Port::new(443).expect("port"),
            )],
            Vec::new(),
        ),
        carriages: vec![Carriage::Udp],
        failure_domain: format!("d{id}"),
        server_rank: 0,
        load_class: 0,
        capacity_weight: 100,
        admin_state: AdminState::Active,
        self_hosted: false,
        supports_drain: false,
        supports_caps: false,
    }
}

#[test]
fn d2_no_measurement_can_drive_the_score_past_the_declared_floor() {
    // The defect was **unboundedness**: `-x.max(-250)` parses as `-(x.max(-250))`
    // and the floor never fired, so a single 5 s RTT sample cost −5000 against a
    // declared maximum of −410. ADR-0006's ranking model rests on the
    // measurement contribution being bounded, so that one bad observation cannot
    // outweigh capacity, health and operator preference combined.
    //
    // Asserted over an extreme sweep rather than one value, because the defect
    // was invisible at ordinary magnitudes — every existing test used realistic
    // numbers, where an inert floor and a working one agree.
    let r = relay(1);
    let clean = score(&r, Observations::default());
    for (name, obs) in [
        (
            "rtt",
            Observations {
                ewma_rtt_ms: 60_000,
                ..Observations::default()
            },
        ),
        (
            "loss",
            Observations {
                loss_pct: 100,
                ..Observations::default()
            },
        ),
        (
            "jitter",
            Observations {
                ewma_jitter_ms: 60_000,
                ..Observations::default()
            },
        ),
    ] {
        let penalty = score(&r, obs) - clean;
        assert!(
            penalty >= MAX_MEASUREMENT_PENALTY,
            "a single extreme {name} observation cost {penalty}, past the \
             declared floor of {MAX_MEASUREMENT_PENALTY}"
        );
    }

    // All three at once must still respect the combined floor, which is what
    // MAX_MEASUREMENT_PENALTY actually declares.
    let everything = score(
        &r,
        Observations {
            ewma_rtt_ms: 60_000,
            loss_pct: 100,
            ewma_jitter_ms: 60_000,
            ..Observations::default()
        },
    ) - clean;
    assert!(
        everything >= MAX_MEASUREMENT_PENALTY,
        "every measurement at its worst cost {everything}, past the declared \
         combined floor of {MAX_MEASUREMENT_PENALTY}"
    );
    assert!(
        clean + everything > 0,
        "a relay with the worst possible measurements scored {} against a BASE \
         of {BASE}; the model is meant to rank it last, not to make it \
         unreachable",
        clean + everything
    );
}

#[test]
fn d2_the_measurement_floor_still_discriminates_below_the_bound() {
    // The negative control for the test above: a floor that clamped everything
    // to the same value would satisfy it and destroy the ranking. Below the
    // bound the score must still order relays by how good they actually are.
    let r = relay(2);
    let fast = score(
        &r,
        Observations {
            ewma_rtt_ms: 10,
            ..Observations::default()
        },
    );
    let medium = score(
        &r,
        Observations {
            ewma_rtt_ms: 100,
            ..Observations::default()
        },
    );
    let slow = score(
        &r,
        Observations {
            ewma_rtt_ms: 240,
            ..Observations::default()
        },
    );
    assert!(
        fast > medium && medium > slow,
        "the floor flattened the ranking: {fast} / {medium} / {slow}"
    );
}

#[test]
fn d2_an_unhealthy_relay_and_a_slow_one_are_ordered_by_the_adrs_own_weighting() {
    // The tripwire that used to stand here asserted a crossover the ADR itself
    // sets: §11.2 floors RTT at −250 and gives UNHEALTHY −150, so a relay slower
    // than 150 ms *should* rank below one reported unhealthy. That was the
    // correction to this domain's original filing, and it is worth keeping as a
    // pin so a re-weighting has to be a decision rather than a side effect.
    let r = relay(3);
    let unhealthy = score(
        &r,
        Observations {
            health: HealthState::Unhealthy,
            ..Observations::default()
        },
    );
    let slower_than_the_crossover = score(
        &r,
        Observations {
            ewma_rtt_ms: 200,
            health: HealthState::Healthy,
            ..Observations::default()
        },
    );
    let faster_than_the_crossover = score(
        &r,
        Observations {
            ewma_rtt_ms: 100,
            health: HealthState::Healthy,
            ..Observations::default()
        },
    );
    assert!(
        slower_than_the_crossover < unhealthy,
        "a 200 ms relay ({slower_than_the_crossover}) should rank below an \
         UNHEALTHY one ({unhealthy}); §11.2's floors put the crossover at 150 ms"
    );
    assert!(
        faster_than_the_crossover > unhealthy,
        "a 100 ms relay ({faster_than_the_crossover}) should rank above an \
         UNHEALTHY one ({unhealthy})"
    );
}
