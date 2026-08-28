//! The connectivity behaviours Phase 1 names, exercised over real sockets:
//! duplicate signaling, stale candidates, peers that disappear and reconnect,
//! simultaneous attempts, restart, a saturated buffer, a relay-directory or
//! control-plane outage, and sustained abuse.
//!
//! Every one of these is a *behaviour under adversity*, and adversity is the
//! case this service exists for: the whole reason `docs/protocol.md` §10.1 keeps
//! the control plane out of the `CALL` path (**I5**) is that the interesting
//! moments are the ones where something else is already broken.
//!
//! Two rules shape what is asserted, and they are the same two rules the service
//! is built on:
//!
//! - **Nothing here is ever a gate.** A stale candidate, a missing peer, a full
//!   buffer and a dependency outage all produce an *informational* answer that
//!   the initiator must not block on (ADR-0002 §11.5). A test that accepted a
//!   refusal where an informational answer belongs would be asserting the
//!   opposite of the requirement.
//! - **Ephemeral means ephemeral.** ADR-0002 N-9: a `CALL` must not survive its
//!   TTL, must not be replayed, and must not survive a restart. Three of the
//!   tests below exist to prove the absence of durability rather than the
//!   presence of a feature, which is the harder thing to keep true.

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use twinvpn_rendezvous as rz;
use twinvpn_rendezvous::testkit;
use twinvpn_service_common::binding::Binding as _;

const LOCAL6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// A payload carrying a field number this build has no name for, so a decode →
/// re-encode round trip would visibly destroy it (finding W-4).
fn opaque(tag: u8) -> Vec<u8> {
    vec![0xf8, 0x01, tag, 0xf2, 0x01, 0x03, 0x01, 0x02, 0x03]
}

/// Attaches `key` as `target` and returns the connection, ack consumed.
async fn attach(h: &common::Harness, key: &common::TestKey, target: [u8; 32]) -> common::Client {
    let mut c = h.client_as(key).await;
    c.write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    let ack = common::within(c.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("attach answered");
    assert!(
        ack.is_empty(),
        "attach refused: {:?}",
        common::reason_code(&ack)
    );
    c
}

// ---------------------------------------------------------------------------
// Duplicate signaling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_duplicated_call_is_delivered_twice_and_never_silently_coalesced() {
    // Retransmission is the initiator's business, not the courier's. ADR-0002
    // §11.5 makes C4 at-most-once and unordered, which means a client that does
    // not hear back retransmits — and a courier that "helpfully" de-duplicated
    // would have to remember what it had already carried, which is precisely the
    // durable state N-9 forbids it to hold. Two identical frames are two
    // deliveries; the peer, which can verify the Rule-B signature, decides.
    let h = common::start(LOCAL6).await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let mut responder = attach(&h, &device, target).await;

    let payload = opaque(0x2a);
    let mut initiator = h.client().await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;

    for nth in 0..2 {
        let got = common::within(responder.read_until(rz::frame::Opcode::Deliver))
            .await
            .unwrap_or_else(|| panic!("delivery {nth} never arrived"));
        assert_eq!(got, payload, "delivery {nth} was not verbatim");
    }
    h.stop().await;
}

#[tokio::test]
async fn a_repeated_attach_on_one_connection_refreshes_and_does_not_pin_the_table() {
    // The holder count `claim` increments is decremented exactly once, at
    // teardown — and a *held* entry is neither swept at its TTL nor evictable
    // for capacity. So an `ATTACH` that took a fresh hold every time would let
    // one authenticated peer, sending no flood and tripping no rate limit, fill
    // the binding table with entries nothing can ever reclaim and shut every
    // other device out of the service for the life of the process.
    //
    // The observable is the table AFTER the connection closes: it must be
    // reclaimable, which it only is when the holds balance.
    let h = common::start_with(LOCAL6, |mut c| {
        c.binding.ttl = Duration::from_millis(50);
        c
    })
    .await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);

    let mut c = h.client_as(&device).await;
    for _ in 0..16 {
        c.write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
            .await;
        common::within(c.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("every repeat is answered");
    }
    assert_eq!(h.shared.bindings.lock().await.len(), 1, "one subject, once");

    drop(c);
    // The connection is gone and the TTL has lapsed, so the sweep must reclaim.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let mut bindings = h.shared.bindings.lock().await;
    bindings.sweep(Instant::now());
    assert_eq!(
        bindings.len(),
        0,
        "a repeated ATTACH left an unreclaimable hold — one peer can wedge the table"
    );
    drop(bindings);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Stale candidates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_candidate_past_its_ttl_is_dropped_and_never_delivered_late() {
    // `docs/protocol.md` §6.1 on why late delivery is worse than no delivery:
    // a stale candidate set probes "NAT mappings that expired and IP addresses
    // now belonging to someone else", so reliable delivery of stale data
    // "makes this worse, because the stale data is guaranteed to arrive."
    let h = common::start_with(LOCAL6, |mut c| {
        c.mailbox.ttl = Duration::from_millis(120);
        c
    })
    .await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);

    let mut initiator = h.client().await;
    initiator
        .write(&testkit::call_frame(target, &opaque(0x01)))
        .await;
    let ack = common::within(initiator.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&ack).as_deref(),
        Some("CONTROL.PEER_NOT_ATTACHED"),
        "informational, never a gate"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut responder = attach(&h, &device, target).await;
    let late = tokio::time::timeout(
        Duration::from_millis(250),
        responder.read_until(rz::frame::Opcode::Deliver),
    )
    .await;
    assert!(
        late.is_err(),
        "a candidate older than the TTL was delivered anyway"
    );
    h.stop().await;
}

#[tokio::test]
async fn the_sweep_reclaims_stale_bytes_without_waiting_for_anyone_to_attach() {
    // The TTL must be enforced on a timer, not only as a side effect of the next
    // touch of that target. A target nobody ever attaches as is the case that
    // matters: those bytes have no other event coming.
    let h = common::start_with(LOCAL6, |mut c| {
        c.mailbox.ttl = Duration::from_millis(80);
        c
    })
    .await;

    let mut initiator = h.client().await;
    for n in 0..4u8 {
        initiator
            .write(&testkit::call_frame([n; 32], &opaque(n)))
            .await;
        common::within(initiator.read_until(rz::frame::Opcode::Ack)).await;
    }
    assert!(
        h.shared.router.lock().await.mailboxes.total_bytes() > 0,
        "the buffer holds what was just queued"
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    h.shared.router.lock().await.sweep(Instant::now());
    assert_eq!(
        h.shared.router.lock().await.mailboxes.total_bytes(),
        0,
        "ADR-0002 N-9: nothing survives its TTL"
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Peers that disappear, and peers that come back
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_peer_that_disappears_stops_being_a_delivery_path() {
    // Not "the write fails and we shrug": the attachment must be gone, so the
    // CALL takes the mailbox rung and the initiator is told which rung it got.
    let h = common::start(LOCAL6).await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);

    let responder = attach(&h, &device, target).await;
    assert_eq!(h.shared.router.lock().await.attachments.len(), 1);
    drop(responder);

    // The accept loop notices the close and detaches.
    for _ in 0..50 {
        if h.shared.router.lock().await.attachments.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        h.shared.router.lock().await.attachments.len(),
        0,
        "a closed connection is not a delivery path"
    );

    let mut initiator = h.client().await;
    initiator
        .write(&testkit::call_frame(target, &opaque(0x03)))
        .await;
    let ack = common::within(initiator.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_eq!(
        common::reason_code(&ack).as_deref(),
        Some("CONTROL.PEER_NOT_ATTACHED")
    );
    h.stop().await;
}

#[tokio::test]
async fn a_reconnecting_peer_resumes_delivery_and_collects_what_arrived_meanwhile() {
    // The reconnect path is the one I5 exists to protect: it must work with no
    // control-plane involvement whatsoever, and it must work for the peer's OWN
    // identity — the same key, so the binding recognises it rather than
    // refusing it.
    let h = common::start(LOCAL6).await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);

    let first = attach(&h, &device, target).await;
    drop(first);
    for _ in 0..50 {
        if h.shared.router.lock().await.attachments.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A CALL lands while the peer is away.
    let payload = opaque(0x04);
    let mut initiator = h.client().await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    common::within(initiator.read_until(rz::frame::Opcode::Ack)).await;

    let mut second = h.client_as(&device).await;
    second
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    let delivered = common::within(second.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the reconnecting peer collects the buffered CALL");
    assert_eq!(delivered, payload);

    // And it is a live path again, not just a drain.
    let payload2 = opaque(0x05);
    initiator
        .write(&testkit::call_frame(target, &payload2))
        .await;
    let live = common::within(second.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("delivery resumed on the new connection");
    assert_eq!(live, payload2);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Simultaneous attempts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_peers_calling_each_other_at_once_both_get_through() {
    // Glare. Both sides decide to connect at the same instant, so each is
    // simultaneously an initiator and a responder. `docs/protocol.md` §10.1's
    // whole design — no ordering, no session, no lock — means neither side has
    // to win: there is nothing to arbitrate, and this test is what says so.
    let h = common::start(LOCAL6).await;
    let key_a = common::TestKey::generate();
    let key_b = common::TestKey::generate();
    let a = common::proven_device_id(&key_a);
    let b = common::proven_device_id(&key_b);

    let mut ca = attach(&h, &key_a, a).await;
    let mut cb = attach(&h, &key_b, b).await;

    let offer_a = opaque(0x0a);
    let offer_b = opaque(0x0b);
    // Written back to back with no read in between: neither side waits.
    ca.write(&testkit::call_frame(b, &offer_a)).await;
    cb.write(&testkit::call_frame(a, &offer_b)).await;

    let got_b = common::within(cb.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("B received A's offer");
    let got_a = common::within(ca.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("A received B's offer");
    assert_eq!(got_b, offer_a);
    assert_eq!(got_a, offer_b);
    h.stop().await;
}

#[tokio::test]
async fn two_initiators_calling_one_target_at_once_both_land() {
    let h = common::start(LOCAL6).await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let mut responder = attach(&h, &device, target).await;

    let first = opaque(0x0c);
    let second = opaque(0x0d);
    let mut ia = h.client().await;
    let mut ib = h.client().await;
    ia.write(&testkit::call_frame(target, &first)).await;
    ib.write(&testkit::call_frame(target, &second)).await;

    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(
            common::within(responder.read_until(rz::frame::Opcode::Deliver))
                .await
                .expect("both CALLs reach the one attached peer"),
        );
    }
    assert!(seen.contains(&first) && seen.contains(&second), "{seen:?}");
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_restart_loses_every_buffered_candidate_and_serves_at_once() {
    // Two assertions, and the first is the unusual one: the test wants the data
    // GONE. ADR-0002 N-9 forbids a `CALL` surviving, and `docs/protocol.md` §6.1
    // explains that surviving is the harm, not the loss. The second assertion is
    // that losing it costs nothing but latency — a fresh process serves a live
    // exchange immediately, with no warm-up and no state to recover.
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let payload = opaque(0x0e);

    let first = common::start(LOCAL6).await;
    let mut initiator = first.client().await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    common::within(initiator.read_until(rz::frame::Opcode::Ack)).await;
    assert!(first.shared.router.lock().await.mailboxes.total_bytes() > 0);
    first.stop().await;

    // A new process. Nothing is carried across; there is no store to carry it in.
    let second = common::start(LOCAL6).await;
    assert_eq!(
        second.shared.router.lock().await.mailboxes.total_bytes(),
        0,
        "a restart must not resurrect a buffered CALL"
    );

    let mut responder = attach(&second, &device, target).await;
    let replayed = tokio::time::timeout(
        Duration::from_millis(200),
        responder.read_until(rz::frame::Opcode::Deliver),
    )
    .await;
    assert!(replayed.is_err(), "nothing survived the restart");

    // ...and the new process is immediately useful.
    let fresh = opaque(0x0f);
    let mut initiator2 = second.client().await;
    initiator2.write(&testkit::call_frame(target, &fresh)).await;
    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("the restarted service serves without warm-up");
    assert_eq!(delivered, fresh);
    second.stop().await;
}

// ---------------------------------------------------------------------------
// The buffer as the thing that is "out" — this service's cache-outage case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_saturated_buffer_degrades_the_detached_rung_and_leaves_delivery_untouched() {
    // This service has no database and no cache to lose (`README.md` §2), so the
    // equivalent failure is its one bounded table being unusable. The ceiling is
    // set below a single payload here, which is the only way `push` can refuse
    // outright — the distinct-target and per-target ceilings both *evict* rather
    // than refuse, deliberately, so that a target flooded by an attacker cannot
    // deny service to a target that is not.
    //
    // The requirement is that saturation costs the *buffering* rung and nothing
    // else: an attached peer still receives, because rung [1] never touches the
    // buffer at all.
    let h = common::start_with(LOCAL6, |mut c| {
        c.mailbox.max_total_bytes = 4;
        c
    })
    .await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let mut responder = attach(&h, &device, target).await;

    let mut initiator = h.client().await;
    let mut codes = Vec::new();
    for n in 0..4u8 {
        initiator
            .write(&testkit::call_frame([0xd0 | n; 32], &opaque(n)))
            .await;
        let ack = common::within(initiator.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("every CALL is answered");
        codes.push(common::reason_code(&ack));
    }
    assert!(
        codes
            .iter()
            .all(|c| c.as_deref() == Some("CONTROL.CALL_UNDELIVERABLE")),
        "an unusable buffer must be reported, not silently absorbed: {codes:?}"
    );
    assert!(
        codes.iter().all(Option::is_some),
        "every answer is informational — none is a refusal: {codes:?}"
    );

    // The live rung is unaffected by the unusable one.
    let payload = opaque(0x11);
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("a full buffer must not stop delivery to an attached peer");
    assert_eq!(delivered, payload);
    h.stop().await;
}

#[tokio::test]
async fn a_target_flooded_past_its_depth_keeps_the_newest_candidates() {
    // ADR-0002 §11.5 fixes drop-oldest, and the direction matters: candidates
    // decay, so the newest set is the one with any chance of working. Dropping
    // the newest to preserve arrival order would preserve exactly the entries
    // `docs/protocol.md` §6.1 says are harmful to deliver.
    //
    // Note what the initiator is NOT told. Overflow is an operator signal —
    // `CONTROL.MAILBOX_OVERFLOW`, on the metric and in the log — and the answer
    // on the wire stays `CONTROL.PEER_NOT_ATTACHED`. Telling an arbitrary caller
    // that a target's buffer overflowed would tell it how much traffic that
    // target is receiving from everyone else, which is a fact about the target
    // that the caller has no business learning from a courier.
    let h = common::start_with(LOCAL6, |mut c| {
        c.mailbox.capacity_per_target = 2;
        c
    })
    .await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);

    let mut initiator = h.client().await;
    for n in 0..5u8 {
        initiator
            .write(&testkit::call_frame(target, &opaque(0x20 | n)))
            .await;
        let ack = common::within(initiator.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("answered");
        assert_eq!(
            common::reason_code(&ack).as_deref(),
            Some("CONTROL.PEER_NOT_ATTACHED"),
            "overflow must not be disclosed to the caller"
        );
    }
    assert!(
        h.shared
            .metrics
            .render()
            .contains("CONTROL.MAILBOX_OVERFLOW"),
        "drop-oldest fired and must be visible to an operator"
    );

    // The drain is written BEFORE the attach ack, so the survivors are collected
    // by reading until the ack rather than by reading past it.
    let mut responder = h.client_as(&device).await;
    responder
        .write(&rz::frame::encode(rz::frame::Opcode::Attach, &target))
        .await;
    let kept = common::within(async {
        let mut kept = Vec::new();
        loop {
            let (op, body) = responder.read_frame().await?;
            if op == rz::frame::Opcode::Deliver.as_wire() {
                kept.push(body);
            } else if op == rz::frame::Opcode::Ack.as_wire() {
                return Some(kept);
            }
        }
    })
    .await
    .expect("the attach is answered");
    assert_eq!(kept.len(), 2, "only the depth-limited survivors are held");
    assert!(
        kept.contains(&opaque(0x24)) && kept.contains(&opaque(0x23)),
        "the two NEWEST must survive, not the two oldest: {kept:?}"
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Dependency outages: relay directory, control plane
// ---------------------------------------------------------------------------

#[test]
fn the_call_path_names_no_dependency_that_could_have_an_outage() {
    // A structural assertion, because a behavioural one can only show that
    // *today's* code path does not call out. `architecture.md` §2.9 gives this
    // service a control-plane dependency for AUTHORIZING A CALLER; ADR-0006
    // gives the relay directory to the relay plane. Neither may be on the `CALL`
    // path (I5), and the way to keep that true is for the crate to be unable to
    // reach them at all.
    // Comments are stripped first: the manifest deliberately *names* the crates
    // that are absent and says why, so a raw substring search would find the
    // explanation and call it a dependency.
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("this crate's manifest")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "relay-directory",
        "twinvpn-relay",
        "reqwest",
        "sqlx",
        "redis",
        "tonic",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "`{forbidden}` on the CALL path would make someone else's outage this service's: I5"
        );
    }
}

#[tokio::test]
async fn a_full_exchange_completes_with_every_other_service_unreachable() {
    // The behavioural half. `TWINVPN_RZ_CONTROL_PLANE_URL` points at a port with
    // nothing behind it and no relay directory exists in this process at all —
    // which is the steady state of this test binary. A complete
    // attach → call → deliver still runs, because none of it consults anyone.
    let h = common::start_with(LOCAL6, |mut c| {
        // A reserved-documentation address (RFC 5737) that cannot answer.
        c.control_plane_url = "https://192.0.2.1:8443".to_string();
        c
    })
    .await;
    let device = common::TestKey::generate();
    let target = common::proven_device_id(&device);
    let mut responder = attach(&h, &device, target).await;

    let payload = opaque(0x30);
    let mut initiator = h.client().await;
    initiator
        .write(&testkit::call_frame(target, &payload))
        .await;
    let delivered = common::within(responder.read_until(rz::frame::Opcode::Deliver))
        .await
        .expect("I5: a control-plane outage must not prevent re-establishing a session");
    assert_eq!(delivered, payload);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Abuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_sustained_flood_from_one_source_does_not_starve_a_different_source() {
    // S-6's requirement is that shedding is *per source*, and the test needs two
    // genuinely different source addresses to say anything: `127.0.0.0/8` is
    // entirely local on Linux, so `127.0.0.2` is a real second host as far as the
    // limiter's keying is concerned.
    let h = common::start_with(IpAddr::V4(Ipv4Addr::LOCALHOST), |mut c| {
        c.admission.sustained_per_sec = 1.0;
        c.admission.burst = 2;
        c
    })
    .await;

    let attacker_key = common::TestKey::generate();
    let mut attacker = h
        .client_from(IpAddr::V4(Ipv4Addr::LOCALHOST), &attacker_key)
        .await;
    let frame = testkit::call_frame([0x55u8; 32], &testkit::payload(16));
    for _ in 0..12 {
        attacker.write(&frame).await;
    }
    let mut deferred = false;
    for _ in 0..12 {
        let body = common::within(attacker.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("every CALL is answered, never reset");
        deferred |= common::reason_code(&body).as_deref() == Some("CONTROL.ADMISSION_DEFERRED");
    }
    assert!(deferred, "the flood must be shed");

    // A different source, arriving mid-flood, is unaffected.
    let victim_key = common::TestKey::generate();
    let mut victim = h
        .client_from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), &victim_key)
        .await;
    victim
        .write(&testkit::call_frame([0x56u8; 32], &testkit::payload(16)))
        .await;
    let body = common::within(victim.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("answered");
    assert_ne!(
        common::reason_code(&body).as_deref(),
        Some("CONTROL.ADMISSION_DEFERRED"),
        "one host's flood must not shed another host's traffic"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_shed_caller_is_answered_and_left_connected_never_reset() {
    // ADR-0002 §11.7 rule 3 states the reason: "a reset is indistinguishable
    // from network failure and drives clients into the aggressive interactive
    // backoff regime, amplifying the very flood it was meant to shed." So the
    // socket must still be usable after the deferral — which is the part a test
    // that only checks the reason code would miss.
    let h = common::start_with(LOCAL6, |mut c| {
        c.admission.sustained_per_sec = 1.0;
        c.admission.burst = 1;
        c
    })
    .await;

    let mut c = h.client().await;
    let frame = testkit::call_frame([0x57u8; 32], &testkit::payload(16));
    for _ in 0..5 {
        c.write(&frame).await;
    }
    for _ in 0..5 {
        common::within(c.read_until(rz::frame::Opcode::Ack))
            .await
            .expect("answered, not reset");
    }

    // The bucket refills; the same connection is still good.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    c.write(&frame).await;
    let body = common::within(c.read_until(rz::frame::Opcode::Ack))
        .await
        .expect("the connection survived the deferral");
    assert_ne!(
        common::reason_code(&body).as_deref(),
        Some("CONTROL.ADMISSION_DEFERRED"),
        "the bucket must refill rather than latch"
    );
    h.stop().await;
}
