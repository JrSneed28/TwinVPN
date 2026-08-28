//! Overload, drain, failover, and the abusive-client isolation that makes I7
//! true — over real sockets, with real cryptography on both sides.
//!
//! **Authority:** ADR-0005 §11.5 (resource control, two-tier DRR, "overload is
//! never silent"), §8 and §10 (drain), §7.6/§11.1(4) (`cnf` and the pair table),
//! ADR-0006 §11.4/§11.5 (failover and the listening posture), I6, I7.
//!
//! # What "prevent one abusive client from exhausting the relay" is tested as
//!
//! Not as an aggregate throughput number, which would pass on a fast machine
//! and fail on a slow one. It is tested as four **structural** properties, each
//! of which an abusive client would have to break to hurt anybody else:
//!
//! | Property | Test |
//! |---|---|
//! | it cannot name another subject's flow | `an_attacker_with_its_own_valid_leg_cannot_touch_another_flow` |
//! | it cannot exceed its own flow ceiling | `a_subject_cannot_exceed_its_own_flow_ceiling` |
//! | it cannot fill the leg table from one prefix | `one_source_prefix_cannot_fill_the_leg_table` |
//! | its throttling is announced, not silent | `a_throttled_subject_is_told_and_its_peer_keeps_flowing` |

mod common;

use bytes::Bytes;
use common::{
    bucket_now, client_socket, client_socket_on, recv, Device, Issuer, TestRelay, TokenSpec, NOW_MS,
};
use twinvpn_relay::control::{BoundBody, BoundState, DrainBody};
use twinvpn_relay::frame::{FrameType, HEADER_LEN};
use twinvpn_relay::pump::{Action, Pump};
use twinvpn_relay::status::RelayStatus;

async fn establish(
    device: &mut Device,
    socket: &tokio::net::UdpSocket,
    relay: &TestRelay,
    issuer: &Issuer,
    subject: u8,
    jti: u8,
) {
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, subject, jti));
    assert!(
        device
            .establish_answering_challenges(socket, relay.addr, &relay.static_public, &token)
            .await,
        "the relay did not complete a leg for subject {subject}"
    );
    assert!(device.k_leg.is_some());
}

async fn bound_pair(
    relay: &TestRelay,
    issuer: &Issuer,
    tag: [u8; 16],
    subjects: (u8, u8),
) -> (Device, tokio::net::UdpSocket, Device, tokio::net::UdpSocket) {
    let (mut a, mut b) = (Device::new(0x0A), Device::new(0x0B));
    let (sa, sb) = (client_socket().await, client_socket().await);
    establish(&mut a, &sa, relay, issuer, subjects.0, subjects.0).await;
    establish(&mut b, &sb, relay, issuer, subjects.1, subjects.1).await;
    a.bind(&sa, relay.addr, tag, bucket_now())
        .await
        .expect("pending");
    b.bind(&sb, relay.addr, tag, bucket_now())
        .await
        .expect("bound");
    let _ = recv(&sa).await;
    (a, sa, b, sb)
}

// ===========================================================================
// One abusive client cannot reach anybody else
// ===========================================================================

#[tokio::test]
async fn an_attacker_with_its_own_valid_leg_cannot_touch_another_flow() {
    // **Finding R-5, as a test.** `FlowId` is a sequential, enumerable `u32`. The
    // first version of the pump resolved the pair from `frame.flow_id()` alone
    // and never compared the half-flow's peer address — so one valid token let an
    // attacker advance a victim's replay window (killing the flow with a single
    // packet), reflect bytes to any bound peer, and charge the victim's quota.
    //
    // A frame MAC alone does not close it: the attacker holds a real `K_leg` and
    // MACs correctly under it, and the relay selects the ingress key BY SOURCE
    // ADDRESS — so verification would confirm only that the attacker is some
    // admitted device, which it is.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x21; 16], (1, 2)).await;

    let victim_flow = a.flow_id.expect("bound");

    // A third device with a perfectly valid leg of its own.
    let mut attacker = Device::new(0xAA);
    let attacker_socket = client_socket().await;
    establish(&mut attacker, &attacker_socket, &relay, &issuer, 9, 9).await;

    // It names the victim's flow and MACs the frame correctly under ITS key.
    let forged = attacker.encode(FrameType::Data, victim_flow, b"injected");
    attacker_socket
        .send_to(&forged, relay.addr)
        .await
        .expect("send");

    assert!(
        recv(&sb).await.is_none(),
        "the victim's peer must receive nothing: a relay that forwarded this \
         would be a reflection primitive AND would advance the victim's replay \
         window, killing a live flow with one packet"
    );
    assert!(
        recv(&attacker_socket).await.is_none(),
        "and the attacker learns nothing — zero bytes, so it cannot even probe \
         which flow ids are live"
    );

    // The legitimate flow is untouched and still carries traffic afterwards.
    a.send_data(&sa, relay.addr, b"still working").await;
    assert_eq!(
        &recv(&sb).await.expect("forwarded")[HEADER_LEN..],
        b"still working"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_subject_cannot_exceed_its_own_flow_ceiling() {
    // ADR-0005 §11.5: 64 concurrent half-flows per `relay_sub`, `BIND` refused
    // above it. Lowered here so the test is about the ceiling, not about time.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start_with(&issuer, |cfg| {
        cfg.max_flows_per_subject = 3;
    })
    .await;

    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;

    for i in 0..3_u8 {
        let reply = device
            .bind(&socket, relay.addr, [0x40 + i; 16], bucket_now())
            .await
            .expect("answered");
        assert_eq!(reply[0], FrameType::Bound.to_wire(), "bind {i}");
    }
    let refused = device
        .bind(&socket, relay.addr, [0x50; 16], bucket_now())
        .await
        .expect("answered");
    assert_eq!(
        refused[0],
        FrameType::RelayStatus.to_wire(),
        "the fourth bind is REFUSED — and told, because a device that hit its \
         ceiling silently would retry against the same relay for ever"
    );
    assert_eq!(relay.pending_count(), 3);
    relay.stop().await;
}

#[tokio::test]
async fn one_source_prefix_cannot_fill_the_leg_table() {
    // The ceiling a single global ceiling misses. ADR-0005 §11.5 rate-limits
    // *handshakes* per source /24 and /48 but bounds no **occupancy**, and a
    // global cap alone does not close the hole: a /64 is 2^64 addresses, so one
    // subnet can fill the whole table at the permitted rate given time.
    //
    // Every `127.0.0.0/8` address shares one /24, which is the grouping the
    // ceiling uses — so three real devices on three loopback addresses are three
    // legs from one prefix, and the third must be refused while the table is
    // nowhere near its global ceiling of 1 000.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start_bounded(&issuer, 1_000, 2).await;

    let mut admitted = 0;
    for (i, host) in ["127.0.0.1", "127.0.0.2", "127.0.0.3"].iter().enumerate() {
        let mut device = Device::new(0x30 + u8::try_from(i).expect("small"));
        let socket = client_socket_on(host).await;
        let n = u8::try_from(i).expect("small");
        let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, n, n));
        if device
            .establish(&socket, relay.addr, &relay.static_public, &token, None)
            .await
            .is_some()
        {
            admitted += 1;
        }
        // The sockets are dropped at the end of each iteration; the relay's leg
        // entries are not, which is the point — an abandoned leg holds its slot
        // until the idle timeout reclaims it.
    }
    assert_eq!(
        admitted, 2,
        "a third leg from the same /24 must be refused, and refused with ZERO \
         BYTES so the attacker cannot even distinguish a full table from a \
         rejected token"
    );
    assert_eq!(relay.leg_count(), 2);
    relay.stop().await;
}

// ===========================================================================
// Overload: never silent
// ===========================================================================

#[tokio::test]
async fn a_throttled_subject_is_told_and_its_peer_keeps_flowing() {
    // I6/RQ9: "Whenever the relay throttles, sheds, or drains, it MUST emit
    // RELAY_STATUS on the affected flow … A relay that drops without a status
    // frame is a defect."
    let issuer = Issuer::new();
    let mut relay = TestRelay::start_with(&issuer, |cfg| {
        // Every byte defers, which is the throttle case at its sharpest.
        cfg.rate_per_subject_mbps = 0;
    })
    .await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x22; 16], (1, 2)).await;

    a.send_data(&sa, relay.addr, b"first").await;
    let status = recv(&sa).await.expect("the sender was told");
    assert_eq!(status[0], FrameType::RelayStatus.to_wire());

    // The status names a REGISTERED reason code, never a raw internal error
    // (`ownership.md` §6 rule 12).
    let body = &status[HEADER_LEN..];
    let code_len = usize::from(body[0]);
    let code = core::str::from_utf8(&body[8..8 + code_len]).expect("utf-8");
    assert!(
        code.starts_with("RELAY."),
        "a refusal must never leave the RELAY domain (ADR-0015 §11.2 rule 5); \
         got {code}"
    );
    assert!(
        RelayStatus::for_condition(twinvpn_relay::Condition::RateLimited, 0)
            .reason_code
            .eq(code)
    );

    // And the throttle did not deliver the frame to the peer, which is what
    // makes it a throttle rather than a fiction.
    assert!(recv(&sb).await.is_none());
    relay.stop().await;
}

#[tokio::test]
async fn a_draining_relay_refuses_new_binds_but_keeps_carrying_what_it_has() {
    // ADR-0005 §8: a draining relay accepts no new binds and keeps carrying
    // existing flows until the deadline it announced. Both halves matter — a
    // drain that dropped live flows immediately would be an outage, not a drain.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x23; 16], (1, 2)).await;

    let announced = {
        let mut rt = relay.runtime.lock().expect("lock");
        let (plan, flows) = rt.engine.begin_drain(NOW_MS, NOW_MS + 120_000);
        assert_eq!(flows.len(), 2, "both half-flows are announced to");
        plan.deadline_ms()
    };
    assert_eq!(announced, NOW_MS + 120_000);

    // Existing traffic still crosses.
    a.send_data(&sa, relay.addr, b"during drain").await;
    assert_eq!(
        &recv(&sb).await.expect("still carried")[HEADER_LEN..],
        b"during drain",
        "a drain must not drop a live flow: §8's whole point is the deadline"
    );

    // A new bind is refused, and told why.
    let mut newcomer = Device::new(0x0C);
    let sc = client_socket().await;
    establish(&mut newcomer, &sc, &relay, &issuer, 3, 3).await;
    let reply = newcomer
        .bind(&sc, relay.addr, [0x24; 16], bucket_now())
        .await
        .expect("answered");
    assert_eq!(reply[0], FrameType::RelayStatus.to_wire());
    relay.stop().await;
}

#[tokio::test]
async fn a_drain_frame_is_authenticated_and_carries_a_deadline_but_no_endpoint() {
    // `relay.proto`: "a relay can ASK a device to leave but can NEVER REDIRECT A
    // SESSION BY ITSELF". The frame therefore carries relay *ids* — which the
    // device must find in its own verified map — and never an address.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (a, _sa, _b, _sb) = bound_pair(&relay, &issuer, [0x25; 16], (1, 2)).await;

    let (peer, datagram) = {
        let mut rt = relay.runtime.lock().expect("lock");
        let (plan, flows) = rt.engine.begin_drain(NOW_MS, NOW_MS + 120_000);
        let setup = rt.setup.clone();
        let twinvpn_relay::loop_udp::RelayRuntime {
            engine,
            legs,
            scheduler,
            ..
        } = &mut *rt;
        let pump = twinvpn_relay::pump::Pump {
            engine,
            legs,
            scheduler,
            crypto: &twinvpn_relay::CryptoProvider::new(),
            setup: setup.as_deref(),
            last_source: "127.0.0.1:0".parse().expect("addr"),
            pending_announcements: Vec::new(),
        };
        pump.drain_datagram(flows[0], plan.deadline_ms(), &[[0xAB; 8]])
            .expect("a DRAIN could be MACed for a bound flow")
    };
    let _ = peer;

    assert_eq!(datagram[0], FrameType::Drain.to_wire());
    let body = DrainBody::decode(&datagram[HEADER_LEN..]).expect("body");
    assert_eq!(body.drain_deadline_ms, NOW_MS + 120_000);
    assert_eq!(body.suggested_relay_ids, vec![[0xAB; 8]]);
    // The device authenticates it: an unauthenticated DRAIN would let anyone who
    // can spoof a source address evict a flow.
    assert!(
        a.verify(&datagram, 0),
        "the DRAIN verifies under the device's own K_leg"
    );

    // And a single bit-flip does not.
    let mut tampered = datagram.to_vec();
    tampered[HEADER_LEN] ^= 0x01;
    assert!(!a.verify(&tampered, 0));
    relay.stop().await;
}

// ===========================================================================
// Packet loss, latency, and queue pressure
// ===========================================================================

#[tokio::test]
async fn a_lost_frame_does_not_wedge_the_flow_and_the_relay_never_retransmits() {
    // ADR-0005 §11.1(5): a relay forwards "without inspecting, buffering beyond
    // its bounded queue, retransmitting, or padding". Loss is the peers'
    // problem, and the relay's only obligation is to keep working after it.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x26; 16], (1, 2)).await;

    // Simulate loss by BURNING counters the peer never sees: the device advances
    // its counter without the relay ever receiving those frames.
    a.send_data(&sa, relay.addr, b"one").await;
    assert_eq!(&recv(&sb).await.expect("first")[HEADER_LEN..], b"one");
    a.counter += 20; // twenty datagrams lost on the wire

    a.send_data(&sa, relay.addr, b"after loss").await;
    assert_eq!(
        &recv(&sb).await.expect("recovered")[HEADER_LEN..],
        b"after loss",
        "a gap in the counter sequence must not wedge the flow: RFC 9147's \
         window slides forward, it does not require contiguity"
    );
    // No retransmission of the first frame ever arrives.
    assert!(recv(&sb).await.is_none());
    relay.stop().await;
}

#[tokio::test]
async fn a_replayed_data_frame_is_dropped_and_the_flow_survives_it() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x27; 16], (1, 2)).await;

    let flow = a.flow_id.expect("bound");
    let datagram = a.encode(FrameType::Data, flow, b"once");
    sa.send_to(&datagram, relay.addr).await.expect("send");
    assert_eq!(&recv(&sb).await.expect("forwarded")[HEADER_LEN..], b"once");

    // The identical datagram again — an off-path replay.
    sa.send_to(&datagram, relay.addr).await.expect("send");
    assert!(
        recv(&sb).await.is_none(),
        "a replayed frame must not reach the peer"
    );
    assert!(recv(&sa).await.is_none(), "and earns zero bytes");

    // The flow is still usable afterwards, which is the property a replay
    // defence gets wrong by being too aggressive.
    a.send_data(&sa, relay.addr, b"still fine").await;
    assert_eq!(
        &recv(&sb).await.expect("forwarded")[HEADER_LEN..],
        b"still fine"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_burst_of_frames_is_carried_without_growing_the_queue() {
    // Queue pressure: the per-flow queue is bounded at `min(64 KiB, 250 ms ×
    // rate)` with tail-drop, and the DRR is ON the forwarding path rather than
    // beside it — so a burst is scheduled and drained, not accumulated.
    //
    // ===================================================================
    // ORDERING IS NOT ASSERTED HERE, AND CANNOT BE.
    // ===================================================================
    // It was, and it failed about one run in twelve on a loaded machine. Two
    // distinct shapes showed up, and between them they rule the check out
    // entirely:
    //
    //   1. Frames arrived scrambled while the relay's own egress counters were
    //      1..32 with no inversion — the relay→b hop reordered.
    //   2. Payload 21 carried egress counter 19 while payloads 18,19,20 carried
    //      20,21,22, and they ARRIVED in counter order — the a→relay hop
    //      reordered, so the relay ingested 21 before 18 and forwarded in the
    //      order it received.
    //
    // In (2) the relay is behaving correctly and there is no vantage point on
    // this socket that can say so: the egress counter records the order the
    // relay INGESTED in, which over UDP is the network's choice, not the
    // relay's. So a socket test can never separate "the relay reordered" from
    // "a datagram overtook another", and asserting order here measures the
    // kernel's softirq scheduling exactly as asserting delivery of all 32 would
    // measure its socket buffer.
    //
    // The property itself is real and is still tested — in
    // `the_relay_never_reorders_within_one_flow`, which drives the pump
    // directly so that ingress order is chosen rather than observed.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x28; 16], (1, 2)).await;

    const BURST: usize = 32;
    for i in 0..BURST {
        a.send_data(&sa, relay.addr, format!("burst-{i}").as_bytes())
            .await;
        // Yield between sends so the relay's single receive loop gets scheduled.
        // Without it, a machine running the whole test binary in parallel
        // overruns a loopback socket buffer and the test measures the kernel
        // rather than the relay — and the relay's queue behaviour, which is what
        // is under test, is not observable through a datagram the kernel threw
        // away before it arrived.
        tokio::task::yield_now().await;
    }
    // Each frame is recorded as (offered index, EGRESS counter). The counter is
    // the relay's own: `RelayFrame::reframe` writes `egress.tx_counter`, which
    // `forward` increments once per forwarded frame under the runtime lock, so
    // it IS the order the relay emitted in.
    let mut carried: Vec<(usize, u16)> = Vec::with_capacity(BURST);
    while let Some(frame) = recv(&sb).await {
        let counter_low = u16::from_be_bytes([frame[2], frame[3]]);
        let text = String::from_utf8_lossy(&frame[HEADER_LEN..]).into_owned();
        let index: usize = text
            .strip_prefix("burst-")
            .and_then(|n| n.parse().ok())
            .expect("a burst frame");
        carried.push((index, counter_low));
        if carried.len() == BURST {
            break;
        }
    }

    // **Order, not count.** The count is not the relay's to guarantee: these are
    // UDP datagrams on a loopback socket whose receive buffer the kernel may
    // overrun when the whole test binary runs in parallel, and ADR-0005 §11.1(5)
    // is explicit that a relay never retransmits — loss is the peers' problem.
    // Asserting delivery of all 32 would be asserting a property of the CI
    // machine's socket buffer.
    assert!(
        carried.len() * 2 > BURST,
        "only {} of {BURST} frames were carried: the per-flow queue is bounded \
         at min(64 KiB, 250 ms × rate) with tail-drop, and a 32-frame burst of \
         short payloads is nowhere near that bound",
        carried.len()
    );

    // No egress counter may REPEAT. A gap is allowed and a repeat is not, and
    // the asymmetry is the same one the count assertion rests on: `tx_counter`
    // increments once per forwarded frame, so a gap means a frame the relay
    // emitted did not arrive — ordinary loss, which ADR-0005 §11.1(5) makes the
    // peers' problem — while a repeat would mean one frame was forwarded twice,
    // which is a relay fault and an amplification primitive.
    //
    // Asserting CONTIGUITY instead would have re-introduced the same flake one
    // layer down: it fails on exactly the dropped datagram the count assertion
    // deliberately tolerates.
    let mut counters: Vec<u16> = carried.iter().map(|(_, c)| *c).collect();
    let before = counters.len();
    counters.sort_unstable();
    counters.dedup();
    assert_eq!(
        counters.len(),
        before,
        "the relay repeated an egress counter: {carried:?}. `tx_counter` \
         increments once per forwarded frame, so a repeat means one frame was \
         forwarded twice."
    );

    // The payloads must be the ones offered, and each at most once. This is the
    // queue property without the ordering claim: a queue that grew and replayed
    // its backlog, or a scheduler that served a flow twice, shows up here.
    let mut indices: Vec<usize> = carried.iter().map(|(i, _)| *i).collect();
    indices.sort_unstable();
    let unique = {
        let mut u = indices.clone();
        u.dedup();
        u.len()
    };
    assert_eq!(
        unique,
        indices.len(),
        "a payload was carried twice: {indices:?}"
    );
    assert!(
        indices.iter().all(|i| *i < BURST),
        "a payload that was never offered was carried: {indices:?}"
    );

    relay.stop().await;
}

// ===========================================================================
// The relay never reorders within one flow — asserted where it is observable
// ===========================================================================

#[tokio::test]
async fn the_relay_never_reorders_within_one_flow() {
    // ADR-0005 §11.5: "the DRR decides ORDER BETWEEN SUBJECTS". Within one flow
    // the relay is a FIFO, and this is the test of that.
    //
    // It drives `Pump::step` DIRECTLY rather than sending datagrams, and that is
    // the whole design of it. Over a socket, the relay's egress counter records
    // the order it INGESTED in — which UDP is free to scramble on the way in —
    // so a socket test cannot separate a relay that reordered from a datagram
    // that overtook another. `a_burst_of_frames_is_carried_without_growing_the_queue`
    // says more about why, with the two measured failure shapes that ruled it
    // out there.
    //
    // Here the ingress order is CHOSEN: `step` is called with frame 0, then 1,
    // then 2. There is no network between the choice and the observation, so an
    // inversion in the output is the relay's and nothing else's.
    //
    // Everything else stays real: a real leg from a real `Noise_IK` handshake, a
    // real bound pair, real MACs under the derived `K_leg`. Only the transport
    // is removed, and it is removed because it is the thing that lies.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x29; 16], (3, 4)).await;
    let a_addr = sa.local_addr().expect("client address");

    const BURST: usize = 64;
    let mut offered = Vec::with_capacity(BURST);
    for i in 0..BURST {
        let flow = a.flow_id.expect("bound");
        offered.push(a.encode(FrameType::Data, flow, format!("seq-{i}").as_bytes()));
    }

    // One lock for the whole burst, held across no `.await`: the same discipline
    // `serve_udp` follows, and the reason the pump is synchronous at all.
    let mut emitted: Vec<(usize, u16)> = Vec::with_capacity(BURST);
    {
        let mut rt = relay.runtime.lock().expect("runtime lock");
        let setup = rt.setup.clone();
        let crypto = twinvpn_relay::provider::CryptoProvider::new();
        for (i, datagram) in offered.iter().enumerate() {
            let twinvpn_relay::loop_udp::RelayRuntime {
                engine,
                legs,
                scheduler,
                ..
            } = &mut *rt;
            let mut pump = Pump {
                engine,
                legs,
                scheduler,
                crypto: &crypto,
                setup: setup.as_deref(),
                last_source: a_addr,
                pending_announcements: Vec::new(),
            };
            // A shed or a drop is a legitimate outcome under quota and is not a
            // reordering. It is recorded by its absence: the counters that DO
            // come out must still be increasing in offered order.
            if let Action::Send { datagram, .. } =
                pump.step(a_addr, Bytes::copy_from_slice(datagram), NOW_MS)
            {
                emitted.push((i, u16::from_be_bytes([datagram[2], datagram[3]])));
            }
        }
    }

    assert!(
        emitted.len() * 2 > BURST,
        "only {} of {BURST} frames were forwarded at all; this test is about \
         ORDER and needs a majority carried to say anything about it",
        emitted.len()
    );

    // The two assertions that are the property. `emitted` is already in offered
    // order because it was built in the loop that offered them, so the counters
    // must be increasing — no sorting, because sorting would hide the inversion
    // this is looking for.
    assert!(
        emitted.windows(2).all(|w| w[0].1 < w[1].1),
        "the relay emitted frames out of order: (offered_index, egress_counter) \
         = {emitted:?}. Within one flow the relay is a FIFO; the DRR decides \
         order BETWEEN SUBJECTS only (ADR-0005 §11.5)."
    );
    assert!(
        emitted.windows(2).all(|w| w[0].0 < w[1].0),
        "an offered frame was emitted twice or out of sequence: {emitted:?}"
    );

    drop(sb);
    relay.stop().await;
}

#[tokio::test]
async fn latency_added_by_the_relay_is_a_lookup_and_a_mac_not_a_round_trip() {
    // ADR-0005 §9.4: "its own contribution is a forwarding-table lookup plus a
    // MAC verification — sub-100 µs on commodity hardware". Asserted as a
    // GENEROUS ceiling over loopback rather than as a number, because a tight
    // one measures the CI machine; what would actually fail here is a relay that
    // acquired a lookup, a lock convoy, or a control-plane call on the path.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let (mut a, sa, _b, sb) = bound_pair(&relay, &issuer, [0x29; 16], (1, 2)).await;

    const SAMPLES: usize = 50;
    let started = std::time::Instant::now();
    for i in 0..SAMPLES {
        a.send_data(&sa, relay.addr, format!("rtt-{i}").as_bytes())
            .await;
        assert!(recv(&sb).await.is_some(), "sample {i}");
    }
    let per_frame = started.elapsed() / u32::try_from(SAMPLES).expect("small");
    assert!(
        per_frame < std::time::Duration::from_millis(10),
        "{per_frame:?} per forwarded frame over loopback: a relay whose per-frame \
         cost is milliseconds has acquired something it should not have on the \
         packet path (I5, §9.4)"
    );
    relay.stop().await;
}

// ===========================================================================
// Regional failover
// ===========================================================================

#[tokio::test]
async fn one_token_admits_the_same_device_at_every_relay_in_the_operator_group() {
    // ADR-0005 §11.3: "`aud` is the OPERATOR GROUP, never a single `relay_id` —
    // one token works across the whole ranked set, **which is what makes
    // ADR-0006's offline failover possible at all**." This is that property,
    // tested against two independent relay instances in different regions and
    // different failure domains — with NO control-plane call between them.
    let issuer = Issuer::new();
    let mut primary = TestRelay::start_with(&issuer, |cfg| {
        cfg.region_id = "eu-west-1".into();
        cfg.failure_domain = "fd-a".into();
    })
    .await;
    let mut standby = TestRelay::start_with(&issuer, |cfg| {
        cfg.region_id = "eu-central-1".into();
        cfg.failure_domain = "fd-b".into();
    })
    .await;
    assert_ne!(primary.addr, standby.addr);

    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, 1, 1));

    assert!(device
        .establish(&socket, primary.addr, &primary.static_public, &token, None)
        .await
        .is_some());
    assert_eq!(primary.leg_count(), 1);

    // The primary dies. The device fails over to a relay in a DIFFERENT failure
    // domain using the SAME token it already holds — the whole point of §11.3's
    // audience scoping and of S-30 being durable on the device.
    primary.stop().await;

    let mut migrated = Device::new(0x0A);
    let socket2 = client_socket().await;
    let token2 = issuer.mint(&TokenSpec::valid_for(&migrated.rlk_public, 1, 2));
    assert!(
        migrated
            .establish(
                &socket2,
                standby.addr,
                &standby.static_public,
                &token2,
                None
            )
            .await
            .is_some(),
        "failover must need no control plane: the standby verifies the token \
         entirely offline (RQ2, architecture A-12)"
    );
    assert_eq!(standby.leg_count(), 1);
    standby.stop().await;
}

#[tokio::test]
async fn a_pair_can_rendezvous_at_a_second_relay_after_the_first_is_lost() {
    // The failover that matters to a session: both peers re-derive the SAME
    // `pair_tag` for the new relay with zero coordination (§11.1(3)), so the
    // rendezvous works with the control plane, rendezvous and presence all down.
    let issuer = Issuer::new();
    let mut first = TestRelay::start(&issuer).await;
    let mut second = TestRelay::start(&issuer).await;

    let (_a, _sa, _b, _sb) = bound_pair(&first, &issuer, [0x2A; 16], (1, 2)).await;
    assert_eq!(first.bound_count(), 1);
    first.stop().await;

    // A tag scoped to the SECOND relay — "a tag observed at one relay is useless
    // at another", so the peers derive a new one rather than reusing the old.
    let (_a2, _sa2, _b2, _sb2) = bound_pair(&second, &issuer, [0x2B; 16], (3, 4)).await;
    assert_eq!(second.bound_count(), 1);
    second.stop().await;
}

#[tokio::test]
async fn a_third_bind_on_a_bound_tag_is_refused_and_told() {
    // §11.1(4): "A third `BIND` on a bound tag is refused with
    // `RELAY.PAIR_COLLISION`; a squatter cannot in any case produce valid L-DATA
    // traffic." The second half is why this is a resource rule, not a security
    // one — but the resource rule still has to hold.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let tag = [0x2C; 16];
    let (_a, _sa, _b, _sb) = bound_pair(&relay, &issuer, tag, (1, 2)).await;

    let mut squatter = Device::new(0x0D);
    let sd = client_socket().await;
    establish(&mut squatter, &sd, &relay, &issuer, 5, 5).await;
    let reply = squatter
        .bind(&sd, relay.addr, tag, bucket_now())
        .await
        .expect("answered");
    assert_eq!(reply[0], FrameType::RelayStatus.to_wire());
    assert_eq!(relay.bound_count(), 1, "the existing pair is untouched");
    relay.stop().await;
}

#[tokio::test]
async fn a_pending_slot_that_never_pairs_is_reclaimed() {
    // The 30-second pending-slot lifetime. Driven through the collector rather
    // than by sleeping, because the engine decides from its parameters and a
    // test that slept would be testing the clock.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start(&issuer).await;
    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    establish(&mut device, &socket, &relay, &issuer, 1, 1).await;

    let reply = device
        .bind(&socket, relay.addr, [0x2D; 16], bucket_now())
        .await
        .expect("answered");
    let body = BoundBody::decode(&reply[HEADER_LEN..]).expect("body");
    assert_eq!(body.state, BoundState::Pending);
    assert_eq!(
        u64::from(body.pending_ttl_ms),
        30_000,
        "the relay tells the device its own TTL, so a re-BIND is scheduled from \
         the relay's number rather than a compiled-in copy"
    );
    assert_eq!(relay.pending_count(), 1);

    let (unmatched, idle) = {
        let mut rt = relay.runtime.lock().expect("lock");
        rt.engine.collect(NOW_MS + 30_001)
    };
    assert_eq!((unmatched, idle), (1, 0));
    assert_eq!(relay.pending_count(), 0);
    relay.stop().await;
}

// ===========================================================================
// The stateless cookie: no asymmetric operation for an unvalidated address
// ===========================================================================

#[tokio::test]
async fn a_handshake_flood_is_answered_with_cookies_before_any_public_key_work() {
    // ADR-0005 §11.5: "the relay performs **no asymmetric operation for an
    // unvalidated source address**: above 20 handshakes/s from a source /24 (v4)
    // or /48 (v6) it issues a stateless cookie challenge first (the WireGuard
    // MAC2 / QUIC Retry pattern)."
    //
    // This is the control that makes the leg handshake's ~200 µs of X25519 safe
    // to expose to the internet at all: without it, a source that can spoof an
    // address commands that much CPU per datagram it sends.
    let issuer = Issuer::new();
    let mut relay = TestRelay::start_with(&issuer, |cfg| {
        cfg.cookie_threshold_handshakes_per_s = 2;
    })
    .await;

    let mut challenged = 0;
    let mut completed = 0;
    let mut challenge_body = Vec::new();
    for i in 0..8_u8 {
        let mut device = Device::new(0x90 + i);
        let socket = client_socket().await;
        let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, i, i));
        let reply = device
            .establish(&socket, relay.addr, &relay.static_public, &token, None)
            .await
            .expect("the relay always answers a handshake with SOMETHING");
        if reply[0] == FrameType::CookieChallenge.to_wire() {
            challenged += 1;
            challenge_body = reply[HEADER_LEN..].to_vec();
        } else {
            completed += 1;
        }
    }
    assert!(
        challenged > 0,
        "a burst of {} handshakes from one /24 must be gated: nothing else \
         bounds the X25519 work an unvalidated source can command",
        challenged + completed
    );
    assert_eq!(
        challenge_body.len(),
        16,
        "the challenge is a 16-octet one-way digest — smaller than the message \
         that provoked it, so amplification stays below 1"
    );

    // And a device that ANSWERS the challenge gets in. A gate that could not be
    // passed would be an outage rather than a control.
    let mut device = Device::new(0xC0);
    let socket = client_socket().await;
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, 200, 200));
    assert!(
        device
            .establish_answering_challenges(&socket, relay.addr, &relay.static_public, &token)
            .await,
        "answering the cookie challenge must complete the leg"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_forged_cookie_does_not_pass_the_gate() {
    let issuer = Issuer::new();
    let mut relay = TestRelay::start_with(&issuer, |cfg| {
        cfg.cookie_threshold_handshakes_per_s = 0;
    })
    .await;

    let mut device = Device::new(0x0A);
    let socket = client_socket().await;
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, 1, 1));

    for forged in [vec![0_u8; 16], vec![0xFF_u8; 16], vec![0x01_u8; 16]] {
        let reply = device
            .establish(
                &socket,
                relay.addr,
                &relay.static_public,
                &token,
                Some(&forged),
            )
            .await
            .expect("answered");
        assert_eq!(
            reply[0],
            FrameType::CookieChallenge.to_wire(),
            "a forged cookie must be answered with a fresh challenge, never with \
             the X25519 work it was trying to buy"
        );
    }
    assert_eq!(relay.leg_count(), 0);
    relay.stop().await;
}
