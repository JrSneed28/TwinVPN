//! Presence is never a gate — asserted structurally, not by inspection.
//!
//! `docs/architecture.md` §2.13, S-11, and ADR-0002 §11.5 all say the same
//! thing in different words: *"presence says offline" MUST NOT prevent an
//! attempt*, a missing attachment "MUST NOT suppress a `CALL` attempt or a
//! connection attempt", and this service's unavailability "degrades reconnect
//! **latency**, not reconnect **capability**".
//!
//! A test that starts a connection and observes that it succeeded would only
//! show that presence did not gate it *this time*. What follows shows that it
//! **cannot**: the connection path does not link this crate, so there is no code
//! path along which a presence answer could be consulted at all.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use twinvpn_presence as pr;

mod common;

/// The rendezvous — the service actually on the connection path — must not
/// depend on presence, in either direction.
#[test]
fn the_connection_path_does_not_link_this_crate() {
    let rendezvous = std::fs::read_to_string("../rendezvous/Cargo.toml")
        .expect("the rendezvous manifest is a sibling in this workspace");
    let deps = rendezvous
        .split("[dependencies]")
        .nth(1)
        .expect("a dependencies section");
    assert!(
        !deps.contains("twinvpn-presence"),
        "the rendezvous names presence as a dependency; presence could then gate a CALL"
    );

    // And the reverse, so this service cannot reach back onto the connection
    // path either. Comment lines are stripped first: this manifest *explains*
    // the absent dependency in prose, and a test that matched the explanation
    // would fail on the very comment that documents it.
    let mine: String = std::fs::read_to_string("Cargo.toml")
        .expect("own manifest")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!mine.contains("twinvpn-rendezvous"));

    // No database client, so no durable presence record can exist.
    // `docs/protocol.md` §6.1 — a durable presence log is "a permanent movement
    // and IP-address history of the Owner".
    assert!(
        !mine.contains("sqlx"),
        "presence must have no durable store; see Cargo.toml's own comment"
    );
}

/// A device this service has never heard of is *unknown*, and unknown is not a
/// state anything may act on.
#[tokio::test]
async fn an_unknown_device_reads_as_unknown_and_not_as_offline() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let mut store = h.shared.store.lock().await;
    assert!(
        store.get([0xeeu8; 32], Instant::now()).is_none(),
        "absence must be absence"
    );
    drop(store);
    h.stop().await;
}

/// With the whole service stopped, nothing in this crate produces a refusal —
/// there is no value to read and no error to propagate.
#[tokio::test]
async fn with_presence_entirely_down_there_is_no_answer_to_gate_on() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let addr = h.addr;
    h.stop().await;

    // The service is gone. A client's attempt to reach it fails at the
    // transport, which is a *latency* cost: it learns nothing about a peer and
    // therefore has nothing that could stop it attempting a connection.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        tokio::net::TcpStream::connect(addr),
    )
    .await;
    let unreachable = match outcome {
        Err(_) => true,
        Ok(Err(_)) => true,
        Ok(Ok(mut s)) => {
            use tokio::io::AsyncReadExt as _;
            let mut b = [0u8; 1];
            matches!(
                tokio::time::timeout(std::time::Duration::from_millis(300), s.read(&mut b)).await,
                Ok(Ok(0)) | Err(_)
            )
        }
    };
    assert!(unreachable, "the aggregator stopped");
}

/// The record this service keeps carries no endpoint, so even a fully
/// compromised presence aggregator cannot hand out a device's address.
#[tokio::test]
async fn a_presence_record_carries_no_address() {
    let h = common::start(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    let device = [0x88u8; 32];
    let mut c = common::Client::connect(h.addr).await;
    c.bind(device).await;
    c.write(&pr::testkit::publish_frame(&pr::testkit::heartbeat(
        device,
        twinvpn_schema::v1::PresenceState::Online,
        pr::server::now_ms() + 60_000,
    )))
    .await;
    common::within(c.read_until(pr::frame::Opcode::Ack)).await;

    let mut store = h.shared.store.lock().await;
    let record = store.get(device, Instant::now()).expect("stored").clone();
    drop(store);

    // `Reachability` says what families work, not where the device is
    // (presence.proto). Rendering the whole record must contain no address.
    let rendered = format!("{record:?}").to_lowercase();
    for needle in ["addr", "endpoint", "octets", "ip"] {
        assert!(
            !rendered.contains(needle),
            "a presence record rendered {needle}: {rendered}"
        );
    }
    h.stop().await;
}
