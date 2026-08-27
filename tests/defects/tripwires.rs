//! **Defect tripwires.** Executable evidence for defects this domain found in
//! other domains' components, in the form the wave already uses.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 14 ("Report
//! unresolved architecture conflicts rather than resolving them locally") and
//! §2 (`test-engineering` "may **read** everything; writes nowhere else");
//! finding **W-18**'s standard pattern — "a tripwire test asserting the spelling
//! is still absent, so registering a code fails the build and points at the line
//! to delete".
//!
//! # What a tripwire is, and what it is not
//!
//! Each test below asserts the **defective behaviour that exists today**, names
//! the correct behaviour in its comment, and fails the moment the defect is
//! fixed — at which point the test is deleted. That is deliberate and it is the
//! only honest option available to this domain:
//!
//! - Asserting the *correct* behaviour would leave a red suite, which under
//!   §6.3 F-3 is a quarantine, and a quarantine hides the finding rather than
//!   surfacing it.
//! - Fixing the component would breach ownership: `core-dataplane` owns these
//!   crates, and §2 says a domain "files findings, does not silently rewrite".
//!
//! **Every test in this file is a bug report with a `cargo test` attached.**
//! None of them is an endorsement.

use twinvpn_env::MonotonicInstant;
use twinvpn_relay_client::map::{AdminState, Carriage, HealthState, Relay};
use twinvpn_relay_client::select::{score, Observations, BASE, MAX_MEASUREMENT_PENALTY};
use twinvpn_tunnel::crypto::{CryptoUnavailable, TransportKeys};
use twinvpn_tunnel::replay::{ReplayWindow, SendCounter};
use twinvpn_tunnel::{Tunnel, TunnelError};
use twinvpn_types::{
    Endpoint, IpAddr, PerFamily, Port, RegionId, RelayId, SessionId, TunnelId, V4Addr,
};

// ===========================================================================
// D-1 — THE FIRST DATA PACKET OF EVERY TUNNEL IS REJECTED AS A REPLAY.
//
// Severity: P1. `twinvpn-tunnel`, owner `core-dataplane`.
// ===========================================================================
//
// `SendCounter::new()` is `Self(0)` and `take_next` yields **0** first
// (`replay.rs`), so `Tunnel::seal` uses counter 0 for the first record.
// `ReplayWindow::new()` sets `highest = 0`, and `bit(0)` returns `true`
// unconditionally — "`highest` itself is always considered seen". So
// `would_accept(0)` is `false`, `accept(0)` is `false`, and `Tunnel::open(0, …)`
// returns `TunnelError::Replay`, which is classed `FATAL`.
//
// The two halves are individually defensible and jointly wrong: the window's
// origin means "counter 0 has been seen" while the counter's origin means
// "counter 0 has not been sent". `twinvpn-tunnel`'s own suite never calls
// `accept(0)` — every existing test starts at 1 — so the seam between the
// sender and the receiver is exactly where nobody looked.
//
// The fix is `core-dataplane`'s to choose: either `SendCounter` starts at 1, or
// `ReplayWindow` starts with `highest` meaning "nothing seen". This domain does
// not choose.

/// A deterministic, reversible stand-in for the record AEAD.
///
/// **Not cryptography.** It exists so the replay window and the counter can be
/// exercised through `Tunnel`'s real seal/open path without `twinvpn-crypto`'s
/// key material. It is reversible and counter-dependent, so a counter mismatch
/// is still detectable.
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
fn d1_the_first_data_packet_a_tunnel_sends_is_rejected_by_the_peer_as_a_replay() {
    // The end-to-end demonstration: one tunnel seals, its peer opens, and the
    // very first record fails. Neither crate's own suite can see this, because
    // neither runs a sender against a receiver.
    let mut sender = established_tunnel(1);
    let mut receiver = established_tunnel(1);

    let mut wire = Vec::new();
    let counter = sender.seal(b"the first packet", &mut wire).expect("seal");
    assert_eq!(counter, 0, "the send counter's first value");

    let mut plain = Vec::new();
    let result = receiver.open(counter, &wire, &mut plain);

    assert_eq!(
        result,
        Err(TunnelError::Replay),
        "DEFECT D-1 APPEARS FIXED. The first record of every tunnel is no longer \
         rejected. Delete this tripwire."
    );

    // The second record is accepted, which is what makes the defect look like an
    // intermittent handshake problem rather than an off-by-one.
    let mut wire2 = Vec::new();
    let c2 = sender.seal(b"the second packet", &mut wire2).expect("seal");
    assert_eq!(c2, 1);
    receiver
        .open(c2, &wire2, &mut plain)
        .expect("counter 1 is accepted");
    assert_eq!(plain, b"the second packet");
}

#[test]
fn d1_the_two_halves_disagree_about_what_counter_zero_means() {
    // The same defect stated as the disagreement it is, so the fix has a target.
    let mut counter = SendCounter::new();
    assert_eq!(
        counter.take_next(),
        Some(0),
        "the sender's first counter is 0"
    );

    let window = ReplayWindow::new();
    assert_eq!(window.highest(), 0);
    assert!(
        !window.would_accept(0),
        "DEFECT D-1 APPEARS FIXED: a fresh replay window now accepts counter 0. \
         Delete this tripwire."
    );
    assert!(
        window.would_accept(1),
        "counter 1 is accepted, which is why the defect looks like a first-packet \
         loss rather than a broken window"
    );
}

// ===========================================================================
// D-2 — THE RELAY SCORE'S MEASUREMENT FLOORS NEVER APPLY.
//
// Severity: P2. `twinvpn-relay-client`, owner `core-dataplane`.
// ===========================================================================
//
// `select.rs`:
//
//     let rtt = -i32::try_from(obs.ewma_rtt_ms).unwrap_or(i32::MAX).max(-250);
//
// Method calls bind tighter than unary minus, so this is `-(x.max(-250))` where
// `x >= 0` — the `.max(-250)` never fires and the penalty is unbounded. The same
// shape appears for loss (`-120`) and jitter (`-40`).
//
// The consequence is not cosmetic. `MAX_MEASUREMENT_PENALTY = -410` is a
// documented, asserted constant, and ADR-0006's ranking model rests on the
// measurement contribution being *bounded* so that a single bad observation
// cannot outweigh capacity, health and operator preference combined. With the
// floors inert, one relay reporting a 5-second EWMA RTT scores −4000 and is
// ranked below every relay in the fleet including retired-adjacent ones; worse,
// a hostile or merely broken health signal can drive any relay arbitrarily far
// down the order.
//
// The existing suite pins `MAX_MEASUREMENT_PENALTY` as a constant and asserts a
// 120 ms advantage wins — both true with the floors inert.

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
fn d2_a_single_bad_measurement_drives_the_score_far_past_the_declared_floor() {
    let r = relay(1);
    let clean = score(&r, Observations::default());

    let terrible = score(
        &r,
        Observations {
            ewma_rtt_ms: 5_000,
            ..Observations::default()
        },
    );
    let penalty = terrible - clean;

    assert!(
        penalty < MAX_MEASUREMENT_PENALTY,
        "DEFECT D-2 APPEARS FIXED: a 5 s EWMA RTT now costs {penalty}, which is \
         within the declared floor of {MAX_MEASUREMENT_PENALTY}. Delete this \
         tripwire."
    );
    assert_eq!(
        penalty, -5_000,
        "the penalty is the raw millisecond count, unbounded — the `.max(-250)` \
         in select.rs never fires because `-x.max(-250)` parses as `-(x.max(-250))`"
    );
    assert!(
        terrible < 0,
        "the score went negative ({terrible}) from one observation, against a \
         BASE of {BASE}"
    );
}

#[test]
fn d2_loss_and_jitter_carry_the_same_inert_floor() {
    // Reported together because the same expression shape appears three times;
    // fixing one and not the others would leave the model half-bounded.
    let r = relay(2);
    let clean = score(&r, Observations::default());

    let loss = score(
        &r,
        Observations {
            loss_pct: 100,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(
        loss, -800,
        "DEFECT D-2: 100 % loss costs 800 points against a declared floor of -120"
    );

    let jitter = score(
        &r,
        Observations {
            ewma_jitter_ms: 2_000,
            ..Observations::default()
        },
    ) - clean;
    assert_eq!(
        jitter, -1_000,
        "DEFECT D-2: a 2 s jitter EWMA costs 1000 points against a declared floor of -40"
    );
}

#[test]
fn d2_a_relay_that_is_merely_slow_can_be_ranked_below_an_unhealthy_one() {
    // The operational consequence, which is what makes this worth reporting at
    // all: an UNHEALTHY relay carries a bounded −150 delta, while a healthy but
    // slow one carries an unbounded penalty — so the model prefers a relay it
    // has been told is unhealthy.
    let r = relay(3);
    let unhealthy = score(
        &r,
        Observations {
            health: HealthState::Unhealthy,
            ..Observations::default()
        },
    );
    let slow_but_healthy = score(
        &r,
        Observations {
            ewma_rtt_ms: 400,
            health: HealthState::Healthy,
            ..Observations::default()
        },
    );
    assert!(
        slow_but_healthy < unhealthy,
        "DEFECT D-2 APPEARS FIXED: a 400 ms relay ({slow_but_healthy}) now ranks \
         at or above an UNHEALTHY one ({unhealthy}). Delete this tripwire."
    );
}

// ===========================================================================
// D-3 — `RoutePlan`'s single-family default-route guard is unreachable.
//
// Severity: P3 (a dead guard, not a live leak). `twinvpn-route`.
// ===========================================================================
//
// `program.rs` sets `blocked[family] = true` for every ungranted family and
// *then* tests `granted_v4 != granted_v6 && !(blocked_v4 || blocked_v6)`. When
// the grants differ, one family is already blocked, so the second conjunct is
// always false. `RouteError::DefaultSingleFamily` — and with it
// `ROUTE.DEFAULT_SINGLE_FAMILY` and its `family` evidence — can never be emitted
// by `compute`.
//
// This is reported as a dead guard rather than a leak: the *blocking* half does
// fire, so the family is not left unprotected. What is lost is the diagnostic —
// the operator is never told which family was withheld and why, which is
// precisely what `docs/implementation/ownership.md` §6 rule 12 asks for.

#[test]
fn d3_an_asymmetric_exit_grant_blocks_the_family_but_emits_no_diagnostic() {
    use twinvpn_platform::{ContractGeneration, InterfaceIndex};
    use twinvpn_route::program::{compute, PlanInputs, RoutingMode};
    use twinvpn_system_tests::{overlay_addresses, twinnet_prefixes};
    use twinvpn_types::AddressFamily;

    let inputs = PlanInputs {
        mode: RoutingMode::FullTunnel,
        overlay: overlay_addresses(2),
        twinnet_prefixes: twinnet_prefixes(),
        accepted: Vec::new(),
        on_link: Vec::new(),
        excluded: Vec::new(),
        interface: InterfaceIndex(42),
        selected_exit_node: None,
        mtu: 1420,
        // v4 granted, v6 not: the asymmetry the guard exists to name.
        exit_grant: PerFamily::new(true, false),
    };
    let plan = compute(&inputs, ContractGeneration(1)).expect(
        "DEFECT D-3 APPEARS FIXED: compute now refuses an asymmetric grant. Delete this tripwire.",
    );

    assert!(
        *plan.blocked_families.get(AddressFamily::V6),
        "the ungranted family must at least be blocked"
    );
    assert!(
        !*plan.blocked_families.get(AddressFamily::V4),
        "the granted family must not be blocked"
    );
    // And nothing NAMES it. `RouteError::DefaultSingleFamily` — the one
    // condition that carries `ROUTE.DEFAULT_SINGLE_FAMILY` and a `granted`
    // evidence field — is unreachable for every asymmetric grant, in both
    // directions, because the family it would name has already been blocked by
    // the loop three lines above the check.
    for grant in [PerFamily::new(true, false), PerFamily::new(false, true)] {
        let asymmetric = PlanInputs {
            exit_grant: grant,
            ..PlanInputs {
                mode: RoutingMode::FullTunnel,
                overlay: overlay_addresses(2),
                twinnet_prefixes: twinnet_prefixes(),
                accepted: Vec::new(),
                on_link: Vec::new(),
                excluded: Vec::new(),
                interface: InterfaceIndex(42),
                selected_exit_node: None,
                mtu: 1420,
                exit_grant: grant,
            }
        };
        let result = compute(&asymmetric, ContractGeneration(2));
        assert!(
            !matches!(
                result,
                Err(twinvpn_route::RouteError::DefaultSingleFamily { .. })
            ),
            "DEFECT D-3 APPEARS FIXED: compute now emits DefaultSingleFamily for \
             an asymmetric grant. Delete this tripwire."
        );
        assert!(result.is_ok(), "the plan is produced, silently");
    }
}

// ===========================================================================
// D-4 — `RestorePoint` prints the host's prior resolver configuration.
//
// Severity: P3 (observability hygiene). `twinvpn-dns`.
// ===========================================================================
//
// `restore.rs` derives `Debug` on `RestorePoint`, whose `prior: Vec<u8>` is the
// verbatim previous host resolver configuration. A `RestorePointRedactionMarker`
// with a `<redacted>` `Debug` impl exists in the same file and is attached to
// nothing. `ownership.md` §6 rule 11 forbids logging anything a user did not ask
// to have logged; a resolver configuration is not a secret but it is the
// host's, and `twinvpn_platform::InterfaceName` sets the redacting precedent.

#[test]
fn d4_a_restore_point_renders_the_host_configuration_it_holds() {
    use twinvpn_dns::restore::RestorePoint;

    let rp = RestorePoint::new(
        b"nameserver 203.0.113.53".to_vec(),
        vec!["object-1".to_owned()],
        [0u8; 32],
        "twinvpn".to_owned(),
    );
    let rendered = format!("{rp:?}");
    assert!(
        rendered.contains("203") || rendered.contains("110"),
        "DEFECT D-4 APPEARS FIXED: RestorePoint's Debug no longer renders the \
         prior configuration. Delete this tripwire. (rendered: {rendered})"
    );
    assert!(
        !rendered.contains("<redacted>"),
        "DEFECT D-4 APPEARS FIXED: the redaction marker is now attached."
    );
}

// ===========================================================================
// D-5 — a RESOLVER-class exempt socket is port-permitted to 443.
//
// Severity: P3. `twinvpn-dns`.
// ===========================================================================
//
// `stub::resolver_socket_port_permitted` permits 53, 853 **and 443**, while its
// own doc says "UDP/TCP 53 and TCP 853 (DoT). DoH is the known-endpoint list,
// which is a destination question rather than a port one." A resolver socket is
// destination-bounded (`SocketClass::Resolver.destination_bounded()`), so this
// is not an open hole — but the port allowance is wider than the documented
// intent, and the crate's own suite asserts 53/853 permitted and 22/1080 refused
// while never asserting 443 either way.

#[test]
fn d5_the_resolver_port_allowance_is_wider_than_its_own_documentation() {
    use twinvpn_dns::stub::resolver_socket_port_permitted;

    assert!(resolver_socket_port_permitted(53));
    assert!(resolver_socket_port_permitted(853));
    assert!(
        resolver_socket_port_permitted(443),
        "DEFECT D-5 APPEARS FIXED: 443 is no longer port-permitted for a \
         RESOLVER socket. Delete this tripwire."
    );
    assert!(
        !resolver_socket_port_permitted(80),
        "the control: an obviously wrong port is still refused, so the check is \
         not simply always-true"
    );
}
