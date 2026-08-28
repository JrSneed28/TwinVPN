//! Performance benchmarks for the relay data plane.
//!
//! **Authority:** ADR-0005 §9.4 ("its own contribution is a forwarding-table
//! lookup plus a MAC verification — sub-100 µs on commodity hardware"), §11.5
//! (the per-packet path must stay bounded), §10 ("a relay's binding constraint
//! is bandwidth and packet rate, not memory or CPU").
//!
//! # Why these are `#[test]`s and not a `criterion` suite
//!
//! `criterion` is not in `services/Cargo.toml`'s `[workspace.dependencies]`, and
//! that manifest is the integration lead's. Rather than take a dependency this
//! domain does not own, the benchmarks are written as ordinary tests that
//! measure, **print a table** (`cargo test -- --nocapture`), and assert only
//! generous ceilings.
//!
//! That split is deliberate and is the honest one:
//!
//! - **The numbers are the output.** They are for a human comparing a change
//!   against the same machine, which is what `ownership.md` step 8 means by "a
//!   source-bound candidate against a source-bound baseline".
//! - **The assertions are not the numbers.** A tight ceiling here would measure
//!   the CI machine and fail on a loaded one. Each ceiling below is set two to
//!   three orders of magnitude above the observed cost, so what it actually
//!   catches is a *structural* regression: a lock convoy, an allocation per
//!   frame, a lookup, or — the one that matters — a control-plane call
//!   appearing on the packet path, which I5 forbids and which would show up here
//!   as milliseconds rather than microseconds.
//!
//! Run them with:
//!
//! ```bash
//! cd services && cargo test -p twinvpn-relay --release --test benchmarks -- --nocapture
//! ```
//!
//! `--release` matters: the debug numbers are roughly an order of magnitude
//! worse and are not a useful baseline for anything.

mod common;

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{
    bucket_now, client_socket, recv, Device, Issuer, TestRelay, TokenSpec, RELAY_STATIC_PRIVATE,
};
use twinvpn_crypto::relay_leg::{LegInitiator, LegResponder};
use twinvpn_relay::frame::{FrameType, RelayFrame, HEADER_LEN, MAX_DATA_PAYLOAD_BYTES};

/// Prints one measured row.
fn report(what: &str, iterations: u32, elapsed: Duration) -> Duration {
    let each = elapsed / iterations;
    let per_second = if each.as_nanos() == 0 {
        f64::INFINITY
    } else {
        1e9 / each.as_nanos() as f64
    };
    println!("  {what:<52} {each:>12?}  {per_second:>12.0}/s");
    each
}

fn header(title: &str) {
    println!("\n{title}");
    println!("  {:<52} {:>12}  {:>12}", "operation", "per op", "rate");
    println!("  {}", "-".repeat(80));
}

// ===========================================================================
// The per-packet path
// ===========================================================================

#[test]
fn bench_frame_parse_and_mac() {
    header("Per-packet primitives (ADR-0005 §9.1)");
    let payload = vec![0xC3_u8; MAX_DATA_PAYLOAD_BYTES];
    let key = [0x11_u8; 32];

    let mut datagram = vec![FrameType::Data.to_wire(), 0x10, 0, 1, 0, 0, 0, 7];
    datagram.extend_from_slice(&[0; 8]);
    datagram.extend_from_slice(&payload);
    let bytes = Bytes::from(datagram);

    const N: u32 = 20_000;

    let started = Instant::now();
    for _ in 0..N {
        let frame = RelayFrame::parse(bytes.clone()).expect("parses");
        std::hint::black_box(frame.flow_id());
    }
    let parse = report("parse a 1456-byte DATA frame", N, started.elapsed());

    let frame = RelayFrame::parse(bytes.clone()).expect("parses");
    let mac_input = frame.mac_input(1);
    let tag = twinvpn_crypto::frame_mac(&key, &mac_input);

    let started = Instant::now();
    for _ in 0..N {
        std::hint::black_box(frame.mac_input(1));
    }
    let assemble = report("assemble the §9.1 MAC input", N, started.elapsed());

    let started = Instant::now();
    for _ in 0..N {
        assert!(twinvpn_crypto::verify_frame_mac(&key, &mac_input, &tag));
    }
    let verify = report(
        "verify the truncated BLAKE2s frame MAC",
        N,
        started.elapsed(),
    );

    // The whole per-packet cryptographic cost is one MAC verify and one MAC
    // compute. §9.4 budgets "sub-100 µs" for a lookup plus a MAC verification;
    // the ceiling here is 100× that, so it fails on a structural regression and
    // not on a busy machine.
    let total = parse + assemble + verify;
    assert!(
        total < Duration::from_millis(10),
        "{total:?} for parse + MAC on one frame. §9.4 budgets sub-100 µs for the \
         relay's whole per-frame contribution; milliseconds means something was \
         added to the packet path"
    );
}

#[test]
fn bench_forwarding_through_the_pump() {
    // The measurement that matters: one complete `Pump::step` over a bound flow,
    // including the source-address check, the replay window, the quota charge,
    // the DRR enqueue/dequeue and both MACs. No sockets — this isolates the
    // relay's own cost from the kernel's.
    header("The forwarding path, end to end in process");

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let issuer = Issuer::new();
        let mut relay = TestRelay::start(&issuer).await;

        let (mut a, sa) = (Device::new(0x0A), client_socket().await);
        let (mut b, sb) = (Device::new(0x0B), client_socket().await);
        for (device, socket, n) in [(&mut a, &sa, 1_u8), (&mut b, &sb, 2)] {
            let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, n, n));
            device
                .establish(socket, relay.addr, &relay.static_public, &token, None)
                .await
                .expect("handshake");
        }
        a.bind(&sa, relay.addr, [0x77; 16], bucket_now())
            .await
            .expect("pending");
        b.bind(&sb, relay.addr, [0x77; 16], bucket_now())
            .await
            .expect("bound");
        let _ = recv(&sa).await;

        // Pre-build the datagrams, so the measured loop is the relay's work and
        // not the harness's frame assembly.
        const N: u32 = 5_000;
        let payload = vec![0x5A_u8; 1_200];
        let mut datagrams = Vec::with_capacity(N as usize);
        for _ in 0..N {
            datagrams.push(Bytes::from(a.encode(
                FrameType::Data,
                a.flow_id.expect("bound"),
                &payload,
            )));
        }
        let from = sa.local_addr().expect("addr");

        let started = Instant::now();
        {
            let mut guard = relay.runtime.lock().expect("lock");
            let setup = guard.setup.clone();
            let twinvpn_relay::loop_udp::RelayRuntime {
                engine,
                legs,
                scheduler,
                ..
            } = &mut *guard;
            let crypto = twinvpn_relay::CryptoProvider::new();
            let mut pump = twinvpn_relay::pump::Pump {
                engine,
                legs,
                scheduler,
                crypto: &crypto,
                setup: setup.as_deref(),
                last_source: from,
                pending_announcements: Vec::new(),
            };
            for datagram in datagrams {
                let action = pump.step(from, datagram, common::NOW_MS);
                assert!(action.emits_bytes(), "every frame forwards");
            }
        }
        let each = report(
            "Pump::step over a bound flow (1200 B)",
            N,
            started.elapsed(),
        );
        println!(
            "  {:<52} {:>12.1} Mbit/s",
            "implied single-core forwarding rate",
            (1_200.0 * 8.0) / each.as_nanos() as f64 * 1e9 / 1e6
        );

        assert!(
            each < Duration::from_millis(1),
            "{each:?} per forwarded frame. ADR-0005 §9.4 says the relay's own \
             contribution is a lookup plus a MAC verification; a millisecond \
             means a lock, an allocation storm, or a call that does not belong \
             on this path (I5)"
        );
        relay.stop().await;
    });
}

// ===========================================================================
// The per-leg path
// ===========================================================================

#[test]
fn bench_leg_handshake() {
    // Once per (device, relay), not per packet — which is exactly why ADR-0005
    // §11.5 puts a cookie gate in front of it. The number here is what an
    // unvalidated source would cost the relay if that gate were removed.
    header("Leg establishment (ADR-0005 §11.1(2))");

    let entropy: std::sync::Arc<dyn twinvpn_crypto::relay_leg::Entropy> =
        std::sync::Arc::new(twinvpn_relay::entropy::SystemEntropy::open().expect("/dev/urandom"));
    let relay_public =
        twinvpn_crypto::relay_leg::static_public_key(&RELAY_STATIC_PRIVATE).expect("public");
    let device_private = [0x0A_u8; 32];

    const N: u32 = 500;
    let started = Instant::now();
    for _ in 0..N {
        let mut initiator =
            LegInitiator::new(&entropy, &device_private, &relay_public).expect("initiator");
        let msg1 = initiator.initiate(b"token").expect("msg1");
        std::hint::black_box(msg1);
    }
    report("Noise_IK message 1 (device side)", N, started.elapsed());

    let mut initiator =
        LegInitiator::new(&entropy, &device_private, &relay_public).expect("initiator");
    let msg1 = initiator.initiate(b"token").expect("msg1");

    let started = Instant::now();
    for _ in 0..N {
        let responder = LegResponder::new(&entropy, &RELAY_STATIC_PRIVATE).expect("responder");
        let (_, leg) = responder.respond(&msg1, b"caps").expect("respond");
        std::hint::black_box(leg.k_leg());
    }
    let each = report(
        "Noise_IK message 2 + K_leg (relay side)",
        N,
        started.elapsed(),
    );

    println!(
        "  {:<52} {:>12.0}/s",
        "handshakes the cookie gate admits per source", 20.0
    );
    println!(
        "  {:<52} {:>12}",
        "…so one unvalidated /24 costs at most",
        format!("{:?} of CPU per second", each * 20)
    );

    assert!(
        each < Duration::from_millis(50),
        "{each:?} per responder handshake: an X25519 handshake that costs tens of \
         milliseconds would make the 20/s cookie threshold (§11.5) a denial of \
         service in itself"
    );
}

#[test]
fn bench_token_verification() {
    // The other asymmetric operation, and the one an attacker reaches only AFTER
    // completing a handshake — ADR-0005 §11.3's ordering is what makes that true.
    header("Offline admission (ADR-0005 §11.3)");

    let issuer = Issuer::new();
    let device = Device::new(0x0A);
    let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, 1, 1));
    let issuers = twinvpn_relay::issuer::IssuerKeySet::parse(
        &issuer.key_set_json(),
        common::OPERATOR_GROUP,
        "bench",
    )
    .expect("key set");
    let key = issuers.find(common::ISSUER_KEY_ID).expect("held");
    let crypto = twinvpn_relay::CryptoProvider::new();

    const N: u32 = 500;
    let started = Instant::now();
    for _ in 0..N {
        let verified = twinvpn_relay::RelayCrypto::verify_statement(
            &crypto,
            key,
            twinvpn_relay::Statement::RelayCapabilityToken,
            &token,
        );
        assert!(verified.is_some(), "the fixture token verifies");
    }
    let each = report(
        "COSE_Sign1 / Ed25519 token verification",
        N,
        started.elapsed(),
    );

    assert!(
        each < Duration::from_millis(20),
        "{each:?} per token verification. It is once per leg, not per bind — \
         `crate::admit` holds the VerifiedToken on the leg precisely so a \
         listening device's 30 binds/min do not each cost this"
    );
}

// ===========================================================================
// Over a real socket
// ===========================================================================

#[test]
fn bench_end_to_end_over_loopback() {
    // The number an operator would recognise: a device sends, the peer receives.
    // It includes two kernel traversals the relay has no control over, so it is
    // reported and not asserted tightly — the in-process number above is the one
    // that isolates the relay's own cost.
    header("Device to peer, over real UDP sockets");

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let issuer = Issuer::new();
        let mut relay = TestRelay::start(&issuer).await;
        let (mut a, sa) = (Device::new(0x0A), client_socket().await);
        let (mut b, sb) = (Device::new(0x0B), client_socket().await);
        for (device, socket, n) in [(&mut a, &sa, 1_u8), (&mut b, &sb, 2)] {
            let token = issuer.mint(&TokenSpec::valid_for(&device.rlk_public, n, n));
            device
                .establish(socket, relay.addr, &relay.static_public, &token, None)
                .await
                .expect("handshake");
        }
        a.bind(&sa, relay.addr, [0x78; 16], bucket_now())
            .await
            .expect("pending");
        b.bind(&sb, relay.addr, [0x78; 16], bucket_now())
            .await
            .expect("bound");
        let _ = recv(&sa).await;

        const N: u32 = 200;
        let payload = vec![0x5A_u8; 1_200];
        let started = Instant::now();
        let mut delivered = 0_u32;
        for _ in 0..N {
            a.send_data(&sa, relay.addr, &payload).await;
            if recv(&sb).await.is_some() {
                delivered += 1;
            }
        }
        let elapsed = started.elapsed();
        report("send → relay → peer, 1200 B (round trip)", N, elapsed);
        println!(
            "  {:<52} {:>12}",
            "delivered",
            format!("{delivered}/{N} (UDP; loss is not the relay's to fix)")
        );

        assert!(
            delivered > N / 2,
            "only {delivered} of {N} datagrams arrived: loopback loss on this \
             scale is not UDP being UDP"
        );
        assert!(
            elapsed / N < Duration::from_millis(50),
            "{:?} per forwarded datagram over loopback",
            elapsed / N
        );
        relay.stop().await;
    });
}

#[test]
fn bench_concurrent_sessions() {
    // Scaling in the dimension ADR-0005 §10 says a relay is actually bounded by:
    // "per-flow memory is a fixed control block … a few hundred bytes", and the
    // binding constraint is packet rate, not the number of flows.
    header("Many concurrent sessions");

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let issuer = Issuer::new();
        let mut relay = TestRelay::start(&issuer).await;

        const PAIRS: u32 = 25;
        let started = Instant::now();
        let mut kept = Vec::new();
        for i in 0..PAIRS {
            let n = u8::try_from(i).expect("small");
            let (mut a, sa) = (Device::new(0x80 + n), client_socket().await);
            let (mut b, sb) = (Device::new(0xB0 + n), client_socket().await);
            for (device, socket, subject) in [(&mut a, &sa, n * 2), (&mut b, &sb, n * 2 + 1)] {
                let token =
                    issuer.mint(&TokenSpec::valid_for(&device.rlk_public, subject, subject));
                // Answering the cookie challenge is PART of the measurement here:
                // fifty handshakes from one loopback /24 in a burst is exactly
                // the case ADR-0005 §11.5's gate exists for, so a benchmark that
                // sidestepped it would be measuring a relay with the control off.
                assert!(
                    device
                        .establish_answering_challenges(
                            socket,
                            relay.addr,
                            &relay.static_public,
                            &token
                        )
                        .await,
                    "leg for subject {subject}"
                );
            }
            a.bind(&sa, relay.addr, [n + 1; 16], bucket_now())
                .await
                .expect("pending");
            b.bind(&sb, relay.addr, [n + 1; 16], bucket_now())
                .await
                .expect("bound");
            let _ = recv(&sa).await;
            kept.push((a, sa, b, sb));
        }
        report(
            "establish + bind one pair (2 legs, 2 binds)",
            PAIRS,
            started.elapsed(),
        );
        println!(
            "  {:<52} {:>12}",
            "legs / bound flows held",
            format!("{} / {}", relay.leg_count(), relay.bound_count())
        );

        assert_eq!(relay.leg_count(), PAIRS as usize * 2);
        assert_eq!(relay.bound_count(), PAIRS as usize);

        // Every pair still carries its own bytes with the table full.
        let started = Instant::now();
        let mut carried = 0_u32;
        for (a, sa, _b, sb) in &mut kept {
            a.send_data(sa, relay.addr, b"still mine").await;
            if let Some(frame) = recv(sb).await {
                assert_eq!(&frame[HEADER_LEN..], b"still mine");
                carried += 1;
            }
        }
        report(
            "forward one frame with 25 pairs bound",
            PAIRS,
            started.elapsed(),
        );
        assert!(
            carried > PAIRS / 2,
            "only {carried} of {PAIRS} pairs carried traffic with the table full"
        );
        relay.stop().await;
    });
}
