//! W-43: a production `Env` must be able to register a real I/O resource.
//!
//! # The gap this closes
//!
//! Every other test in this workspace binds `MockAdapter` (which needs no
//! driver) or `VirtualTime` (which needs no I/O), so the entire tree passed
//! while the production runtime had no I/O driver at all. That is the shape the
//! integration lead names alongside W-31 and R-1: **a property every local test
//! assumes and none verifies.**
//!
//! So this file deliberately does the one thing the rest of the suite does not —
//! it builds the *production* bindings and puts a real kernel socket on them. It
//! is not a determinism test and it must not become one.

#![cfg(feature = "runtime-tokio")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use twinvpn_env::binding::system::{
    ElapsedClockFn, SystemMonotonicClock, SystemWallClock, WallClockTrust,
};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{
    ElapsedInstant, Entropy, Env, EnvError, EnvParts, OffsetSource, Runtime, RuntimeKind,
    SystemRngSource,
};

/// A stand-in for the platform CSPRNG, which this crate deliberately does not
/// ship (CD-3 bans `getrandom`; the shell supplies it).
struct StubEntropy;

impl Entropy for StubEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        dst.fill(0x5a);
        Ok(())
    }
}

/// Builds an `Env` from the **production** bindings.
///
/// Two capabilities are stubs, and both are stubs because this crate ships no
/// production implementation of them by design, not because the test is cutting
/// a corner: `ElapsedClock` has no portable `std` source, and `Entropy` is the
/// platform CSPRNG. Everything under test here — the runtime and its drivers —
/// is the real thing.
fn production_env(runtime: Arc<TokioRuntime>) -> Env {
    let monotonic = Arc::new(SystemMonotonicClock::new());
    Env::new(EnvParts {
        monotonic: monotonic.clone(),
        elapsed: ElapsedClockFn::shared(|| ElapsedInstant::from_micros(0)),
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Unsynchronised(
            OffsetSource::PersistedLastKnown,
        ))),
        timer: runtime.timer(monotonic),
        runtime,
        entropy: Arc::new(StubEntropy),
        rng: Arc::new(SystemRngSource::new(Arc::new(StubEntropy))),
    })
}

/// What the async block hands back to the thread that called `block_on`.
type RoundTrip = Arc<Mutex<Option<Result<Vec<u8>, String>>>>;

/// Binds two real UDP sockets on a production `Env` and passes a datagram
/// between them.
///
/// Without the I/O driver, `UdpSocket::bind` panics with "there is no reactor
/// running". `send_to`/`recv_from` need it registered and readiness-polled, so
/// completing the round trip proves the driver is actually running rather than
/// merely compiled in.
fn round_trip_on(runtime: Arc<TokioRuntime>, expected_kind: RuntimeKind) {
    let env = production_env(Arc::clone(&runtime));
    assert_eq!(env.runtime().kind(), expected_kind);

    let outcome: RoundTrip = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&outcome);

    env.runtime().block_on(Box::pin(async move {
        let result = async {
            let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("bind listener: {e}"))?;
            let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("bind sender: {e}"))?;
            let to = listener.local_addr().map_err(|e| e.to_string())?;

            sender
                .send_to(b"disco", to)
                .await
                .map_err(|e| format!("send_to: {e}"))?;
            let mut buf = [0u8; 32];
            let (n, _from) = listener
                .recv_from(&mut buf)
                .await
                .map_err(|e| format!("recv_from: {e}"))?;
            Ok::<Vec<u8>, String>(buf[..n].to_vec())
        }
        .await;
        *sink.lock().expect("lock") = Some(result);
    }));

    let got = outcome.lock().expect("lock").take().expect("block_on ran");
    assert_eq!(
        got.as_deref(),
        Ok(b"disco".as_slice()),
        "a production Env could not complete a real UDP round trip"
    );
}

#[test]
fn the_work_stealing_runtime_can_register_a_real_socket() {
    let runtime = Arc::new(TokioRuntime::work_stealing().expect("work-stealing runtime"));
    round_trip_on(runtime, RuntimeKind::WorkStealing);
}

#[test]
fn the_single_threaded_runtime_can_register_a_real_socket() {
    // iOS and iPadOS take this binding, and the NetworkExtension provider needs
    // exactly the same I/O driver the desktop one does.
    let runtime = Arc::new(TokioRuntime::single_threaded().expect("single-threaded runtime"));
    round_trip_on(runtime, RuntimeKind::SingleThreaded);
}

#[test]
fn a_production_runtime_registers_ipv6_without_panicking() {
    // ADR-0010 R1: neither family is the special case. A host with no loopback
    // v6 address is a legitimate configuration, so a bind *failure* is reported
    // rather than asserted away — what must never happen is the panic from a
    // missing reactor, which is what this asserts by completing at all.
    let runtime = Arc::new(TokioRuntime::work_stealing().expect("runtime"));
    let bound = Arc::new(Mutex::new(false));
    let sink = Arc::clone(&bound);
    runtime.block_on(Box::pin(async move {
        if tokio::net::UdpSocket::bind("[::1]:0").await.is_ok() {
            *sink.lock().expect("lock") = true;
        }
    }));
    let reached_v6 = *bound.lock().expect("lock");
    if !reached_v6 {
        eprintln!("note: this host has no loopback IPv6 address; the reactor still ran");
    }
}

/// The timer still runs on the injected monotonic clock now that I/O is enabled:
/// adding a second driver must not have changed which clock a deadline uses.
#[test]
fn enabling_io_did_not_disturb_the_injected_timer() {
    let runtime = Arc::new(TokioRuntime::work_stealing().expect("runtime"));
    let env = production_env(Arc::clone(&runtime));
    let before = env.now_monotonic();
    let fired = Arc::new(Mutex::new(false));
    let sink = Arc::clone(&fired);
    let timer = Arc::clone(env.timer());
    env.runtime().block_on(Box::pin(async move {
        timer.sleep(Duration::from_millis(5)).await;
        *sink.lock().expect("lock") = true;
    }));
    assert!(*fired.lock().expect("lock"));
    assert!(env.now_monotonic() >= before);
}
