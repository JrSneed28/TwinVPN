//! Presence under the conditions that actually happen: peers that vanish, peers
//! that come back, a restart, a table at its ceiling, an outage somewhere else,
//! duplicate and reordered heartbeats, and a client that abuses the channel.
//!
//! Every assertion below descends from one sentence in `architecture.md` §2.13 —
//! presence **"MUST NOT gate connection attempts"**, and its unavailability
//! *"degrades reconnect latency, not reconnect capability"*. So the question a
//! failure test asks here is never "does it still answer" but **"is the wrong
//! answer still harmless"**: an expired record must read as *unknown* and not as
//! *offline*, a full table must lose hints and not refuse binds, and a restart
//! must lose everything and cost nothing but one heartbeat interval.
//!
//! `never_a_gate.rs` proves the structural half — the connection path does not
//! link this crate at all. This file proves the behavioural half.

mod common;

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use twinvpn_presence as pr;
use twinvpn_presence::testkit;
use twinvpn_schema::v1;
use twinvpn_service_common::binding::Binding as _;

const LOCAL6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

fn now_ms() -> u64 {
    pr::server::now_ms()
}

/// Publishes one heartbeat on an already-bound connection and returns the
/// decoded response.
async fn publish(
    c: &mut common::Client,
    device: [u8; 32],
    state: v1::PresenceState,
    expires_at_ms: u64,
) -> v1::PublishPresenceResponse {
    c.write(&testkit::publish_frame(&testkit::heartbeat(
        device,
        state,
        expires_at_ms,
    )))
    .await;
    let ack = common::within(c.read_until(pr::frame::Opcode::Ack))
        .await
        .expect("every publish is answered");
    common::response(&ack)
}

// ---------------------------------------------------------------------------
// Duplicate and repeated signaling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_duplicated_heartbeat_is_idempotent_and_still_fans_out() {
    // A device that does not hear an ack retransmits — ADR-0008 N-9 makes a
    // heartbeat "PERMITTED TO BE LOST", which is precisely why it is repeated.
    // The table must settle on one record, and a subscriber must not have to
    // reason about how many copies it saw: `PresenceUpdated` carries the whole
    // state, so a duplicate is a no-op for the reader.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let mut subscriber = h.client().await;
    subscriber
        .write(&pr::frame::encode(pr::frame::Opcode::Subscribe, &[]))
        .await;
    common::within(subscriber.read_until(pr::frame::Opcode::Ack)).await;

    let mut publisher = h.client_as(&key).await;
    publisher.bind(device).await;
    let expiry = now_ms() + 60_000;
    for _ in 0..3 {
        let resp = publish(&mut publisher, device, v1::PresenceState::Online, expiry).await;
        assert!(resp.error.is_none(), "{:?}", resp.error);
    }

    assert_eq!(
        h.shared.store.lock().await.len(),
        1,
        "three copies of one assertion are one record"
    );
    for _ in 0..3 {
        common::within(subscriber.read_until(pr::frame::Opcode::Event))
            .await
            .expect("each is fanned out; the reader coalesces, not the service");
    }
    h.stop().await;
}

#[tokio::test]
async fn a_repeated_bind_on_one_connection_does_not_pin_the_table() {
    // `claim` increments a holder count that teardown decrements exactly once,
    // and a held entry is neither swept at its TTL nor evictable for capacity.
    // Without a matching release, one authenticated client repeating `BIND(D)`
    // fills the binding table with entries nothing can reclaim — after which
    // every other device's first `BIND` is refused for capacity, and under S-11
    // a device that cannot bind cannot speak for itself at all.
    let h = common::start_with(LOCAL6, |mut c| {
        c.binding.ttl = Duration::from_millis(50);
        c
    })
    .await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let mut c = h.client_as(&key).await;
    for _ in 0..16 {
        c.bind(device).await;
    }
    assert_eq!(h.shared.bindings.lock().await.len(), 1);

    drop(c);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let mut bindings = h.shared.bindings.lock().await;
    bindings.sweep(Instant::now());
    assert_eq!(
        bindings.len(),
        0,
        "a repeated BIND left an unreclaimable hold — one peer can wedge the table"
    );
    drop(bindings);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Stale records: unknown, never "offline"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_expired_record_reads_as_unknown_and_not_as_offline() {
    // The distinction is the whole safety property. "Offline" is an answer a
    // caller might act on; "unknown" is not. `architecture.md` §2.13 forbids
    // presence from suppressing an attempt, and a stale record that decayed into
    // a confident "offline" would do exactly that.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let mut publisher = h.client_as(&key).await;
    publisher.bind(device).await;
    let resp = publish(
        &mut publisher,
        device,
        v1::PresenceState::Online,
        now_ms() + 40,
    )
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);

    tokio::time::sleep(Duration::from_millis(120)).await;
    let mut store = h.shared.store.lock().await;
    assert!(
        store.get(device, Instant::now()).is_none(),
        "an expired record must vanish, not decay into a confident OFFLINE"
    );
    drop(store);
    h.stop().await;
}

#[tokio::test]
async fn the_sweep_reclaims_expired_records_with_nobody_asking() {
    // A device that stops heartbeating is the common case and generates no
    // further event. Its record must go on a timer, or the "permanent movement
    // history" `docs/protocol.md` §6.1 forbids accumulates by inaction.
    let h = common::start(LOCAL6).await;
    for n in 0..3u8 {
        let key = common::TestKey::generate();
        let device = common::proven_device_id(&key);
        let mut c = h.client_as(&key).await;
        c.bind(device).await;
        let resp = publish(
            &mut c,
            device,
            v1::PresenceState::Online,
            now_ms() + 40 + u64::from(n),
        )
        .await;
        assert!(resp.error.is_none(), "{:?}", resp.error);
    }
    assert_eq!(h.shared.store.lock().await.len(), 3);

    tokio::time::sleep(Duration::from_millis(150)).await;
    h.shared.store.lock().await.sweep(Instant::now());
    assert_eq!(
        h.shared.store.lock().await.len(),
        0,
        "nothing outlives its own declared expiry"
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Peers that disappear and reconnect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_disappearing_publisher_leaves_its_last_assertion_standing_until_it_expires() {
    // Deliberately NOT "a dropped connection means offline". The device is
    // authoritative for its own presence (S-11); a TCP close is this service's
    // observation, not the device's assertion, and inventing an OFFLINE from it
    // would be exactly the override S-11 forbids. The assertion decays on the
    // expiry the device itself chose.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let mut publisher = h.client_as(&key).await;
    publisher.bind(device).await;
    publish(
        &mut publisher,
        device,
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )
    .await;
    drop(publisher);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut store = h.shared.store.lock().await;
    let record = store
        .get(device, Instant::now())
        .expect("the assertion outlives the connection that made it");
    assert_eq!(record.state, v1::PresenceState::Online as i32);
    drop(store);
    h.stop().await;
}

#[tokio::test]
async fn a_reconnecting_device_rebinds_on_its_own_key_and_supersedes_its_own_record() {
    // The reconnect path: a device comes back on a NEW connection with the SAME
    // key, and must be able to correct its own record. If the binding could not
    // recognise it, S-11 would have locked the device out of its own name.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let mut first = h.client_as(&key).await;
    first.bind(device).await;
    publish(
        &mut first,
        device,
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )
    .await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut second = h.client_as(&key).await;
    second.bind(device).await;
    let resp = publish(
        &mut second,
        device,
        v1::PresenceState::Idle,
        now_ms() + 90_000,
    )
    .await;
    assert!(
        resp.error.is_none(),
        "a device must be able to correct its own record: {:?}",
        resp.error
    );

    let mut store = h.shared.store.lock().await;
    let record = store.get(device, Instant::now()).expect("still known");
    assert_eq!(
        record.state,
        v1::PresenceState::Idle as i32,
        "the later assertion wins"
    );
    drop(store);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_restart_empties_the_table_and_costs_only_one_heartbeat() {
    // `README.md` §10.4: no persistence, deliberately. The test asserts the loss
    // AND that the loss is cheap — a device re-asserts on its next heartbeat and
    // the new process is immediately correct. That is the designed recovery, and
    // it is why presence is classified ephemeral rather than a durability gap.
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);

    let first = common::start(LOCAL6).await;
    let mut c = first.client_as(&key).await;
    c.bind(device).await;
    publish(&mut c, device, v1::PresenceState::Online, now_ms() + 60_000).await;
    assert_eq!(first.shared.store.lock().await.len(), 1);
    first.stop().await;

    let second = common::start(LOCAL6).await;
    assert_eq!(
        second.shared.store.lock().await.len(),
        0,
        "a durable presence log is the privacy defect protocol.md §6.1 names"
    );

    let mut c2 = second.client_as(&key).await;
    c2.bind(device).await;
    let resp = publish(
        &mut c2,
        device,
        v1::PresenceState::Online,
        now_ms() + 60_000,
    )
    .await;
    assert!(resp.error.is_none(), "{:?}", resp.error);
    assert_eq!(
        second.shared.store.lock().await.len(),
        1,
        "one heartbeat restores the hint"
    );
    second.stop().await;
}

// ---------------------------------------------------------------------------
// The table at its ceiling — this service's cache-outage case
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_table_at_its_ceiling_loses_hints_and_refuses_nothing() {
    // This service holds no database (`README.md` §9, PR-1), so its equivalent
    // failure is the one bounded table being full. Losing a hint is acceptable;
    // refusing a device is not, because a device that cannot publish cannot be
    // seen at all and the caller has no way to tell "full" from "offline".
    let h = common::start_with(LOCAL6, |mut c| {
        c.store.max_devices = 2;
        c
    })
    .await;

    let mut keys = Vec::new();
    for _ in 0..5 {
        let key = common::TestKey::generate();
        let device = common::proven_device_id(&key);
        let mut c = h.client_as(&key).await;
        c.bind(device).await;
        let resp = publish(&mut c, device, v1::PresenceState::Online, now_ms() + 60_000).await;
        assert!(
            resp.error.is_none(),
            "a full table must never refuse a device: {:?}",
            resp.error
        );
        keys.push((key, device, c));
    }
    assert!(
        h.shared.store.lock().await.len() <= 2,
        "the ceiling holds; the excess is dropped rather than refused"
    );

    // The most recent assertion is the one kept — the freshest hint is the
    // useful one, and the stale entries are the ones §6.1 wants gone anyway.
    let (_, newest, _) = keys.last().expect("five were published");
    let mut store = h.shared.store.lock().await;
    assert!(
        store.get(*newest, Instant::now()).is_some(),
        "eviction must be oldest-first"
    );
    drop(store);
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Somebody else's outage
// ---------------------------------------------------------------------------

/// This crate's manifest with comment lines removed.
///
/// The comments deliberately *name* the crates that are absent and say why
/// (`Cargo.toml`'s own header on `sqlx` is the clearest example), so a raw
/// substring search over the file finds the explanation and calls it a
/// dependency. Stripping comments is what makes the assertion about the
/// dependency list rather than about the prose beside it.
fn manifest_without_comments() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("this crate's manifest")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_dependency_of_this_service_can_have_an_outage() {
    // PR-1's finding made structural. `docker-compose.yml` asks this service for
    // a database URL and `infra/README.md` §5 gives it "Postgres reachable"
    // readiness — but a durable presence record is the privacy defect
    // `docs/protocol.md` §6.1 names, so there is no client to have an outage,
    // and no control-plane call to make on the reconnect path (I5).
    let manifest = manifest_without_comments();
    for forbidden in ["sqlx", "redis", "reqwest", "tonic", "relay-directory"] {
        assert!(
            !manifest.contains(forbidden),
            "`{forbidden}` would give this hint service a dependency that can be down"
        );
    }
}

#[tokio::test]
async fn presence_serves_with_every_other_service_unreachable() {
    // The behavioural half of PR-1 and PR-5: `TWINVPN_PRESENCE_DATABASE_URL` is
    // loaded and validated (so an unedited `CHANGE-ME` still fails at startup)
    // and then dropped, and the control-plane URL is not consulted on this path
    // at all (I5). Pointing the control plane at an address that cannot answer
    // must therefore change nothing.
    let h = common::start_with(LOCAL6, |mut c| {
        // RFC 5737 documentation space: nothing can be listening there.
        c.control_plane_url = "https://192.0.2.1:8443".to_string();
        c
    })
    .await;
    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);
    let mut c = h.client_as(&key).await;
    c.bind(device).await;
    let resp = publish(&mut c, device, v1::PresenceState::Online, now_ms() + 60_000).await;
    assert!(
        resp.error.is_none(),
        "an unreachable database must be irrelevant: {:?}",
        resp.error
    );
    h.stop().await;
}

// ---------------------------------------------------------------------------
// Abuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_subscriber_that_never_reads_loses_updates_and_never_blocks_a_publisher() {
    // The back-pressure question, and the answer has to be "the reader loses":
    // presence is at-most-once and ADR-0008 N-9 permits a heartbeat to be lost,
    // so blocking a publisher to keep a slow reader current would turn a lossy
    // hint channel into a back-pressure source on every device's heartbeat —
    // and on battery, on the wake it was coalesced into.
    let h = common::start(LOCAL6).await;

    // Subscribes and then never reads a single event.
    let mut idle = h.client().await;
    idle.write(&pr::frame::encode(pr::frame::Opcode::Subscribe, &[]))
        .await;
    common::within(idle.read_until(pr::frame::Opcode::Ack)).await;

    let key = common::TestKey::generate();
    let device = common::proven_device_id(&key);
    let mut publisher = h.client_as(&key).await;
    publisher.bind(device).await;
    for n in 0..600u64 {
        let resp = publish(
            &mut publisher,
            device,
            v1::PresenceState::Online,
            now_ms() + 60_000 + n,
        )
        .await;
        assert!(
            resp.error.is_none(),
            "publish {n} was refused by a slow reader's back-pressure: {:?}",
            resp.error
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn a_device_cannot_speak_for_another_however_many_times_it_asks() {
    // S-11 is not rate-limited, softened, or eventually granted. Repeating the
    // violation must produce the same security event every time and must not
    // leave a partial record behind on any attempt.
    let h = common::start(LOCAL6).await;
    let key = common::TestKey::generate();
    let mine = common::proven_device_id(&key);
    let theirs = [0x99u8; 32];

    let mut c = h.client_as(&key).await;
    c.bind(mine).await;
    for _ in 0..5 {
        let resp = publish(&mut c, theirs, v1::PresenceState::Online, now_ms() + 60_000).await;
        let err = resp.error.expect("S-11: rejected, every time");
        assert_eq!(err.reason_code, "CONTROL.EVENT_WRONG_PUBLISHER");
    }
    let mut store = h.shared.store.lock().await;
    assert!(
        store.get(theirs, Instant::now()).is_none(),
        "a refused assertion must leave nothing behind"
    );
    drop(store);
    h.stop().await;
}
