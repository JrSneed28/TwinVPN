//! **The product carries traffic.** Two pumps facing each other over the mock
//! seam, and an attacker on the same fabric.
//!
//! # The claim nothing in this repository asserted before
//!
//! Every platform adapter declares `Datapath::Userspace`, which by ADR-0018
//! §11.2 row 2.3 makes the core the datapath, and all five implement
//! `read_packet` and `write_packet`. Nothing called either one, so no test
//! anywhere said *a plaintext IP packet written into one TUN comes out of the
//! peer's TUN, byte-identical, having been sealed and opened*.
//! [`a_packet_crosses_from_one_tun_to_the_peers_tun_byte_identical`] is that
//! test.
//!
//! # And the claim that matters just as much
//!
//! An attacker who can put **one** datagram on the wire must not be able to
//! tear a tunnel down. Three tests inject one — a replay, a forgery, and
//! something far too large — and each asserts two things: the datagram was
//! refused with the registered code it deserves, **and** the tunnel is still
//! carrying traffic afterwards. That second assertion is the point; a test that
//! only checked the reject would pass over a pump that killed the session.
//!
#![cfg(feature = "full")]

#[path = "datapath/support.rs"]
mod support;

use support::{
    bind, capture, fabric, inject, packet, paired, parked, poll_parked, ready, tunnel, LEFT_INDEX,
    MTU, RIGHT_INDEX,
};

use core::task::Poll;
use std::sync::Arc;

use twinvpn_core::datapath::{
    Budget, Cancel, DataHeader, Pump, PumpParts, Refused, Reject, Step, Stop, HEADER_BYTES,
    OVERLAY_MTU_FLOOR, TAG_BYTES,
};
use twinvpn_core::testing;
use twinvpn_platform::config::{Datapath, TunnelHandle};
use twinvpn_platform::error::PlatformError;
use twinvpn_platform::mock::{MockAdapter, MockNetwork, MockOptions};
use twinvpn_platform::PlatformAdapter;
use twinvpn_types::codes;

// ---------------------------------------------------------------------------
// The headline
// ---------------------------------------------------------------------------

#[test]
fn a_packet_crosses_from_one_tun_to_the_peers_tun_byte_identical() {
    // THE test. Before this module existed nothing in the repository asserted
    // that the product moves a packet at all.
    let fabric = fabric();
    let plaintext = packet(1200);

    fabric
        .left
        .adapter
        .tunnel_mock()
        .push_inbound(plaintext.clone());

    let mut out = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_outbound(&mut out)),
        Step::Moved(plaintext.len()),
        "the left pump reads the TUN, seals, and sends"
    );
    // Nothing plaintext reached the peer's interface yet, and nothing was
    // written back onto the sender's own.
    assert!(fabric.left.written().is_empty());

    let mut inbound = fabric.right.pump.buffers();
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut inbound)),
        Step::Moved(plaintext.len()),
        "the right pump receives, opens, and writes the TUN"
    );

    assert_eq!(
        fabric.right.written(),
        vec![plaintext.clone()],
        "byte-identical, having been sealed and opened"
    );
}

#[test]
fn the_packet_crosses_in_both_directions_over_one_tunnel() {
    // The reverse leg is not symmetric by construction: each direction has its
    // own counter, its own receiver index and its own key.
    let fabric = fabric();
    let outbound = packet(64);
    let inbound = packet(900);

    fabric
        .left
        .adapter
        .tunnel_mock()
        .push_inbound(outbound.clone());
    let mut buffers = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_outbound(&mut buffers)),
        Step::Moved(outbound.len())
    );
    let mut buffers = fabric.right.pump.buffers();
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Moved(outbound.len())
    );

    fabric
        .right
        .adapter
        .tunnel_mock()
        .push_inbound(inbound.clone());
    let mut buffers = fabric.right.pump.buffers();
    assert_eq!(
        ready(fabric.right.pump.step_outbound(&mut buffers)),
        Step::Moved(inbound.len())
    );
    let mut buffers = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_inbound(&mut buffers)),
        Step::Moved(inbound.len())
    );

    assert_eq!(fabric.right.written(), vec![outbound]);
    assert_eq!(fabric.left.written(), vec![inbound]);
}

// ---------------------------------------------------------------------------
// One injected datagram is never a teardown
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_datagram_is_refused_and_the_tunnel_is_not_torn_down() {
    let fabric = fabric();
    let plaintext = packet(300);
    let datagram = capture(&fabric, &plaintext);

    let mut buffers = fabric.right.pump.buffers();

    inject(&fabric, &datagram, fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Moved(plaintext.len()),
        "the genuine datagram crosses"
    );

    inject(&fabric, &datagram, fabric.right.endpoint);
    let replayed = ready(fabric.right.pump.step_inbound(&mut buffers));
    assert_eq!(replayed, Step::Rejected(Reject::Replay));
    assert_eq!(
        Reject::Replay.reason_code(),
        Some(codes::CRYPTO_REPLAY_DETECTED)
    );

    // The property this test exists for. A replay is `FATAL`/`CRITICAL` and the
    // registry marks it `terminal = false`; anyone who can observe one genuine
    // datagram can send it again, so treating it as terminal would be a
    // one-packet remote teardown.
    assert!(!Reject::Replay.tears_down());
    assert!(
        fabric.right.carries_traffic(),
        "the tunnel survives an injected replay"
    );
    assert_eq!(
        fabric.right.written(),
        vec![plaintext.clone()],
        "the replay was not delivered a second time"
    );

    // And it still carries traffic afterwards, which is the only proof that
    // "not torn down" means anything.
    let next = packet(120);
    fabric.left.adapter.tunnel_mock().push_inbound(next.clone());
    let mut outbound = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_outbound(&mut outbound)),
        Step::Moved(next.len())
    );
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Moved(next.len())
    );
    assert_eq!(fabric.right.written(), vec![plaintext, next]);
}

#[test]
fn a_tampered_datagram_is_dropped_and_the_pump_keeps_running() {
    let fabric = fabric();
    let plaintext = packet(300);
    let mut datagram = capture(&fabric, &plaintext);

    // Flip one bit inside the sealed record. The header, and therefore the
    // counter, is untouched: this is a forgery, not a replay, and the two must
    // not collapse into one disposition.
    let victim = HEADER_BYTES + 4;
    datagram[victim] ^= 0x01;

    let mut buffers = fabric.right.pump.buffers();
    inject(&fabric, &datagram, fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Rejected(Reject::Unauthenticated)
    );
    // ADR-0001 §7.2: no response to unauthenticated packets. A per-datagram
    // reason code would be an oracle and a log-amplification lever, so the
    // observable is the counter, not a diagnostic.
    assert_eq!(Reject::Unauthenticated.reason_code(), None);
    assert!(!Reject::Unauthenticated.tears_down());
    assert!(fabric.right.written().is_empty(), "nothing was delivered");
    assert!(fabric.right.carries_traffic());

    // The window was not advanced by the forgery: the genuine datagram at the
    // same counter still opens.
    inject(
        &fabric,
        &capture(&fabric, &plaintext),
        fabric.right.endpoint,
    );
    let step = ready(fabric.right.pump.step_inbound(&mut buffers));
    assert!(
        matches!(step, Step::Moved(_)),
        "the pump kept running: {step:?}"
    );
}

#[test]
fn a_datagram_for_another_receiver_index_is_dropped_before_the_aead() {
    let fabric = fabric();
    let plaintext = packet(200);
    let mut datagram = capture(&fabric, &plaintext);

    // Re-address it to a tunnel that is not this one. WireGuard's demux
    // position, and a cheap shed that keeps an unrelated flow's frames out of
    // the authentication-failure counter.
    datagram[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());

    let mut buffers = fabric.right.pump.buffers();
    inject(&fabric, &datagram, fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Rejected(Reject::ForeignReceiver)
    );
    assert!(fabric.right.written().is_empty());
    assert!(fabric.right.carries_traffic());
}

#[test]
fn a_datagram_that_is_not_a_transport_frame_is_dropped() {
    // ADR-0001 §7.2 permits a disco message type on the same socket, so this is
    // an ordinary event on a shared socket rather than an attack.
    let fabric = fabric();
    let mut buffers = fabric.right.pump.buffers();
    let mut disco = vec![0u8; HEADER_BYTES + TAG_BYTES];
    disco[0] = 1;

    inject(&fabric, &disco, fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Rejected(Reject::Malformed)
    );

    // And something too short to be a frame at all does not panic or underflow.
    inject(&fabric, &[4u8, 0, 0, 0], fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Rejected(Reject::Malformed)
    );
    assert!(fabric.right.carries_traffic());
}

#[test]
fn an_oversized_datagram_is_rejected_without_allocating_to_its_declared_size() {
    let fabric = fabric();
    let mut buffers = fabric.right.pump.buffers();
    let capacity_before = buffers.wire_capacity();
    assert_eq!(
        capacity_before,
        fabric.right.pump.budget().datagram_capacity()
    );

    // Sixteen times the whole budget, with a well-formed header so that nothing
    // but the length can be what refuses it.
    let mut monster = Vec::with_capacity(capacity_before * 16);
    DataHeader {
        receiver: RIGHT_INDEX,
        counter: 0,
    }
    .write(&mut monster);
    monster.resize(capacity_before * 16, 0xff);

    inject(&fabric, &monster, fabric.right.endpoint);
    assert_eq!(
        ready(fabric.right.pump.step_inbound(&mut buffers)),
        Step::Rejected(Reject::Truncated),
        "a typed reject, never a truncation and never a pad (ownership.md §6 rule 9)"
    );
    assert_eq!(
        Reject::Truncated.reason_code(),
        Some(codes::PROTO_SIZE_EXCEEDED)
    );
    assert_eq!(
        buffers.wire_capacity(),
        capacity_before,
        "the peer's declared length never drove an allocation"
    );
    assert!(fabric.right.carries_traffic());
}

// ---------------------------------------------------------------------------
// The datapath the core must not touch
// ---------------------------------------------------------------------------

#[test]
fn a_kernel_offload_adapter_makes_the_pump_refuse_rather_than_read_a_packet() {
    let (env, _time) = testing::env();
    let net = MockNetwork::new();
    let adapter = Arc::new(MockAdapter::on_network(
        &net,
        &MockOptions {
            datapath: Datapath::KernelOffload,
            ..MockOptions::default()
        },
    ));
    let (socket, endpoint) = bind(&adapter);
    let handle = TunnelHandle(1);
    let (keys, _peer_keys) = paired();
    let tunnel = tunnel(0x33, keys, endpoint, &env);

    let refused = Pump::new(PumpParts {
        env,
        adapter: Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        handle,
        socket,
        tunnel,
        local_receiver: LEFT_INDEX,
        peer_receiver: RIGHT_INDEX,
        overlay_mtu: MTU,
        cancel: Cancel::new(),
    })
    .err()
    .expect("a kernel-offload adapter must not get a pump");
    assert_eq!(refused, Refused::KernelOffload);
    assert_eq!(refused.reason_code(), codes::PLATFORM_OS_UNSUPPORTED);

    // There is no `Pump` to call `step_outbound` on, which is the structural
    // half of the guarantee. The other half: had one existed, this is what the
    // adapter would have answered — the pump's refusal and the adapter's carry
    // the same registered code, so refusing early tells the same story sooner.
    let mut scratch = [0u8; 64];
    let error = ready(adapter.tunnel().read_packet(handle, &mut scratch))
        .expect_err("read_packet is unsupported here");
    assert!(matches!(error, PlatformError::OsUnsupported(_)));
    assert_eq!(error.reason_code(), refused.reason_code());
    assert!(adapter.tunnel_mock().written().is_empty());
}

#[test]
fn an_mtu_outside_its_bounds_is_a_refusal_and_never_a_clamp() {
    // A silently clamped MTU means the interface and the pump disagree about
    // how large a packet may be, and every packet in between is lost with no
    // explanation.
    assert_eq!(
        Budget::new(OVERLAY_MTU_FLOOR - 1),
        Err(Refused::MtuBelowFloor {
            mtu: OVERLAY_MTU_FLOOR - 1
        })
    );
    assert_eq!(
        Budget::new(u32::MAX),
        Err(Refused::MtuAboveCeiling { mtu: u32::MAX })
    );
    let budget = Budget::new(1420).expect("the networking.md §6.1 IPv6 row");
    assert_eq!(budget.plaintext_capacity(), 1420);
    assert_eq!(budget.datagram_capacity(), 1420 + 32);
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

#[test]
fn cancellation_stops_a_blocked_pump_promptly_and_leaves_nothing_half_written() {
    let fabric = fabric();
    let mut buffers = fabric.right.pump.buffers();

    // Nothing is queued, so the step is parked inside `recv_from` — the state a
    // pump on a quiet tunnel spends nearly all its time in.
    let mut step = parked(fabric.right.pump.step_inbound(&mut buffers));
    assert_eq!(
        poll_parked(&mut step),
        Poll::Pending,
        "blocked on the receive"
    );

    fabric.right.cancel.cancel();

    // Promptly: the very next poll, with no datagram and no timer.
    assert_eq!(
        poll_parked(&mut step),
        Poll::Ready(Step::Stopped(Stop::Cancelled))
    );
    drop(step);

    // Cleanly: the interface saw nothing.
    assert!(fabric.right.written().is_empty());
    assert!(
        fabric.right.carries_traffic(),
        "a shutdown request is not a teardown"
    );
}

#[test]
fn a_cancelled_pump_stops_without_touching_the_interface() {
    let fabric = fabric();
    // A packet is waiting, and the pump must still not take it: cancellation is
    // checked before the read, so a stopped pump cannot consume a packet it
    // will never deliver.
    fabric.left.adapter.tunnel_mock().push_inbound(packet(100));
    fabric.left.cancel.cancel();

    let report = ready(fabric.left.pump.run_outbound());
    assert_eq!(report.stop, Stop::Cancelled);
    assert!(report.stop.is_graceful());
    assert_eq!(report.counters.packets, 0);
    assert_eq!(report.counters.rejected_total(), 0);

    // One token, both directions of the same end: a shutdown request does not
    // have to be delivered twice, and cannot half-arrive.
    let mut buffers = fabric.left.pump.buffers();
    assert_eq!(
        ready(fabric.left.pump.step_inbound(&mut buffers)),
        Step::Stopped(Stop::Cancelled)
    );
    assert!(fabric.left.written().is_empty());
    // The peer's token is its own and is untouched, which is what keeps one
    // session's shutdown from being another's.
    assert!(!fabric.right.cancel.is_cancelled());
}

#[test]
fn a_run_loop_reports_what_it_carried() {
    let fabric = fabric();
    let first = packet(128);
    let second = packet(256);
    // The mock returns the most recently pushed packet first, so the run loop
    // sees them in reverse; only the totals are asserted.
    fabric
        .left
        .adapter
        .tunnel_mock()
        .push_inbound(first.clone());
    fabric
        .left
        .adapter
        .tunnel_mock()
        .push_inbound(second.clone());

    // The loop drains the interface, finds it empty, and waits — at which point
    // the pre-tripped-on-idle token ends it. Tripping it up front instead would
    // stop the loop before it moved anything.
    let cancel = fabric.left.pump.cancel_handle();
    let mut run = parked(fabric.left.pump.run_outbound());
    assert_eq!(poll_parked(&mut run), Poll::Pending, "waiting out an idle");
    cancel.cancel();
    let Poll::Ready(report) = poll_parked(&mut run) else {
        panic!("the idle wait must give up on cancellation");
    };

    assert_eq!(report.stop, Stop::Cancelled);
    assert_eq!(report.counters.packets, 2);
    assert_eq!(
        report.counters.bytes,
        (first.len() + second.len()) as u64,
        "lengths, never payloads"
    );
    assert!(report.counters.idle_waits >= 1);
    assert_eq!(report.counters.rejected_total(), 0);

    // Both packets are on the wire and both open on the far side.
    let mut buffers = fabric.right.pump.buffers();
    let mut delivered = Vec::new();
    for _ in 0..2 {
        match ready(fabric.right.pump.step_inbound(&mut buffers)) {
            Step::Moved(len) => delivered.push(len),
            other => panic!("expected a delivery, got {other:?}"),
        }
    }
    delivered.sort_unstable();
    assert_eq!(delivered, vec![first.len(), second.len()]);
}
