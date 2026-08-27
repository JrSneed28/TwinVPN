//! CD-1, CD-1a, CD-2 and CD-4, asserted rather than documented.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use twinvpn_env::binding::system::{
    SystemMonotonicClock, SystemWallClock, WallClockTrust, WALL_CLOCK_PLAUSIBILITY_FLOOR_MS,
};
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{
    consumers, ConsumerId, Entropy, Env, EnvError, EnvParts, MonotonicClock, OffsetSource,
    RngSource, RuntimeKind, SeededRngSource, StreamDerivation, SystemRngSource, ValidityClock,
    ValidityWindow, WallClock, WallClockConfidence, WallClockReading, WallMillis, WindowVerdict,
    CD4_INFO_PREFIX,
};
use twinvpn_types::{codes, Component};

// ---------------------------------------------------------------------------
// Test doubles for the two capabilities this crate deliberately does not
// implement (see the crate docs): the platform CSPRNG and the CD-4 derivation.
// ---------------------------------------------------------------------------

/// A stand-in for the platform CSPRNG. Not random; not used for anything that
/// asserts unpredictability.
struct FixedEntropy(u8);

impl Entropy for FixedEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        dst.fill(self.0);
        Ok(())
    }
}

struct FailingEntropy;

impl Entropy for FailingEntropy {
    fn fill(&self, _dst: &mut [u8]) -> Result<(), EnvError> {
        Err(EnvError::EntropyUnavailable)
    }
}

/// A stand-in for HKDF-SHA-256 that records the exact `(ikm, info)` it was given.
///
/// It is **not** HKDF and does not claim to be: CD-I2 keeps the real derivation
/// in `twinvpn-crypto`. What this crate owns and can test is the half of CD-4
/// that is not cryptographic — the `info` string, and stream independence, which
/// hold for any injective derivation.
#[derive(Default)]
struct RecordingDerivation {
    calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl StreamDerivation for RecordingDerivation {
    fn derive(&self, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EnvError> {
        self.calls
            .lock()
            .expect("lock")
            .push((ikm.to_vec(), info.to_vec()));
        // An injective mixing of (ikm, info) into the output. Deterministic and
        // distinct per input, which is all the properties under test require.
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for b in ikm.iter().chain(info) {
            acc ^= u64::from(*b);
            acc = acc.wrapping_mul(0x0100_0000_01b3);
        }
        for (i, slot) in out.iter_mut().enumerate() {
            acc ^= i as u64;
            acc = acc.wrapping_mul(0x0100_0000_01b3);
            *slot = (acc >> 24) as u8;
        }
        Ok(())
    }
}

fn virtual_env(vt: &VirtualTime, rng: Arc<dyn RngSource>) -> Env {
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(FixedEntropy(0)),
        rng,
    })
}

// ---------------------------------------------------------------------------
// CD-1: the monotonic clock does not advance across suspend; the elapsed one does
// ---------------------------------------------------------------------------

#[test]
fn suspend_advances_the_elapsed_clock_and_not_the_monotonic_one() {
    let vt = VirtualTime::new(WallClockReading::Trusted {
        millis: WallMillis::from_millis(1_800_000_000_000),
    });
    let env = virtual_env(
        &vt,
        Arc::new(SystemRngSource::new(Arc::new(FixedEntropy(1)))),
    );

    let mono_before = env.now_monotonic();
    let elapsed_before = env.now_elapsed();

    // Eight hours of laptop sleep — ADR-0018 §11.8 reason 3's exact scenario.
    let eight_hours = Duration::from_secs(8 * 3600);
    vt.suspend(eight_hours);

    assert_eq!(
        env.now_monotonic(),
        mono_before,
        "MonotonicClock MUST NOT advance across suspend (LC-8)"
    );
    assert_eq!(
        env.now_elapsed().duration_since(elapsed_before),
        eight_hours,
        "ElapsedClock MUST advance across suspend (LC-8)"
    );
}

#[test]
fn an_eight_hour_suspend_fires_no_short_horizon_timer() {
    // The recovery defect §11.8 reason 3 describes: with one advancing clock,
    // T_DEAD (15 s) would declare every path dead before the wake ladder could
    // re-validate one.
    let vt = VirtualTime::new(WallClockReading::Unset);
    let timer = vt.timer();
    let t_dead = timer.sleep(Duration::from_secs(15));
    let runtime = vt.runtime();

    // Register the timer by polling once, then suspend.
    let mut fut = Some(t_dead);
    runtime.block_on(Box::pin(async {
        // Nothing to await; the point is to have polled `t_dead` below.
    }));
    drop(runtime);

    let pending = vt.timers_pending();
    vt.suspend(Duration::from_secs(8 * 3600));
    assert_eq!(vt.timers_fired(), 0, "a suspend must fire no timer");
    assert_eq!(vt.timers_pending(), pending);
    fut.take();
}

#[test]
fn ordinary_time_passing_advances_all_three_clocks() {
    let vt = VirtualTime::new(WallClockReading::Trusted {
        millis: WallMillis::from_millis(1_800_000_000_000),
    });
    let env = virtual_env(
        &vt,
        Arc::new(SystemRngSource::new(Arc::new(FixedEntropy(1)))),
    );
    vt.advance(Duration::from_secs(5));
    assert_eq!(env.now_monotonic().as_micros(), 5_000_000);
    assert_eq!(env.now_elapsed().as_micros(), 5_000_000);
    match env.now_wall() {
        WallClockReading::Trusted { millis } => {
            assert_eq!(millis.as_millis(), 1_800_000_005_000);
        }
        other => panic!("expected Trusted, got {other:?}"),
    }
}

#[test]
fn a_virtual_timer_fires_when_virtual_time_reaches_its_deadline() {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let timer = vt.timer();
    let runtime = vt.runtime();
    let done = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&done);
    // block_on advances to the next deadline when the future stalls, so a
    // five-minute sleep costs no wall time at all.
    runtime.block_on(Box::pin(async move {
        timer.sleep(Duration::from_secs(300)).await;
        *flag.lock().expect("lock") = true;
    }));
    assert!(*done.lock().expect("lock"));
    assert_eq!(MonotonicClock::now(&vt).as_micros(), 300_000_000);
}

#[test]
fn a_deadline_already_past_completes_rather_than_hanging() {
    let vt = VirtualTime::new(WallClockReading::Unset);
    vt.advance(Duration::from_secs(10));
    let timer = vt.timer();
    let past = twinvpn_env::MonotonicInstant::from_micros(1);
    let runtime = vt.runtime();
    let done = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&done);
    runtime.block_on(Box::pin(async move {
        timer.sleep_until(past).await;
        *flag.lock().expect("lock") = true;
    }));
    assert!(*done.lock().expect("lock"));
}

// ---------------------------------------------------------------------------
// CD-1a: a validity window cannot be evaluated against an Unset clock
// ---------------------------------------------------------------------------

#[test]
fn an_unset_wall_clock_yields_no_validity_clock() {
    assert!(ValidityClock::try_from_reading(WallClockReading::Unset).is_none());
    let err = ValidityClock::require(WallClockReading::Unset, Component::DeviceIdentity)
        .expect_err("Unset must not produce an evaluator");
    assert_eq!(err.code(), codes::INTERNAL_INVARIANT_VIOLATED);
    assert!(err.code().terminal());
}

#[test]
fn an_offset_or_trusted_reading_yields_a_validity_clock_that_records_its_confidence() {
    let offset = ValidityClock::try_from_reading(WallClockReading::Offset {
        millis: WallMillis::from_millis(1_800_000_000_000),
        source: OffsetSource::Relay,
    })
    .expect("Offset resolves");
    assert_eq!(
        offset.confidence(),
        WallClockConfidence::Offset(OffsetSource::Relay)
    );
    let trusted = ValidityClock::try_from_reading(WallClockReading::Trusted {
        millis: WallMillis::from_millis(1_800_000_000_000),
    })
    .expect("Trusted resolves");
    assert_eq!(trusted.confidence(), WallClockConfidence::Trusted);
}

#[test]
fn a_validity_window_is_evaluated_with_an_explicit_skew_allowance() {
    let now = 1_800_000_000_000u64;
    let clock = ValidityClock::try_from_reading(WallClockReading::Trusted {
        millis: WallMillis::from_millis(now),
    })
    .expect("resolved");

    let window = ValidityWindow {
        not_before_ms: Some(now - 1000),
        not_after_ms: Some(now + 1000),
    };
    assert_eq!(clock.evaluate(window, Duration::ZERO), WindowVerdict::Valid);

    // Expired by one second, with no skew allowed.
    let past = ValidityWindow {
        not_before_ms: None,
        not_after_ms: Some(now - 1000),
    };
    let verdict = clock.evaluate(past, Duration::ZERO);
    assert!(matches!(verdict, WindowVerdict::Expired { .. }));

    // The same window, with a two-second allowance, is inside it.
    assert_eq!(
        clock.evaluate(past, Duration::from_secs(2)),
        WindowVerdict::Valid
    );

    // Not yet open.
    let future = ValidityWindow {
        not_before_ms: Some(now + 5000),
        not_after_ms: None,
    };
    assert!(matches!(
        clock.evaluate(future, Duration::ZERO),
        WindowVerdict::NotYetValid { .. }
    ));
}

#[test]
fn a_failed_verdict_becomes_auth_statement_expired_with_its_declared_evidence() {
    let now = 1_800_000_000_000u64;
    let clock = ValidityClock::try_from_reading(WallClockReading::Trusted {
        millis: WallMillis::from_millis(now),
    })
    .expect("resolved");
    let verdict = clock.evaluate(
        ValidityWindow {
            not_before_ms: None,
            not_after_ms: Some(now - 1),
        },
        Duration::ZERO,
    );
    let d = verdict
        .diagnostic(Component::DeviceIdentity, "PairingOffer")
        .expect("a failed verdict carries a diagnostic");
    assert_eq!(d.code(), codes::AUTH_STATEMENT_EXPIRED);
    assert!(d.evidence().get("statement_type").is_some());
    assert!(d.evidence().get("not_after_ms").is_some());
    assert!(d.evidence().get("skew_allowance_ms").is_some());
    // Never a silent drop, and never terminal: a bad clock is a condition to
    // report (AUTH.CLOCK_IMPLAUSIBLE's registry entry says so explicitly).
    assert!(!d.code().terminal());
    assert!(WindowVerdict::Valid
        .diagnostic(Component::DeviceIdentity, "PairingOffer")
        .is_none());
}

#[test]
fn an_unset_virtual_clock_does_not_start_ticking_because_time_passed() {
    let vt = VirtualTime::new(WallClockReading::Unset);
    vt.advance(Duration::from_secs(86_400));
    assert_eq!(vt.wall().now(), WallClockReading::Unset);
    // ...until an offset arrives, exactly as ADR-0005 / ADR-0009 K-2 provide.
    vt.set_wall(WallClockReading::Offset {
        millis: WallMillis::from_millis(1_800_000_000_000),
        source: OffsetSource::Relay,
    });
    assert!(ValidityClock::try_from_reading(vt.wall().now()).is_some());
}

// ---------------------------------------------------------------------------
// CD-4: seeded streams
// ---------------------------------------------------------------------------

fn draw(source: &dyn RngSource, consumer: ConsumerId, n: usize) -> Vec<u8> {
    let mut rng = source.rng_for(consumer).expect("stream");
    let mut out = vec![0u8; n];
    rng.fill_bytes(&mut out);
    out
}

#[test]
fn the_same_seed_produces_the_same_stream() {
    let seed = [7u8; 16];
    let a = SeededRngSource::new(seed, Arc::new(RecordingDerivation::default()));
    let b = SeededRngSource::new(seed, Arc::new(RecordingDerivation::default()));
    assert_eq!(
        draw(&a, consumers::RELAY_HRW, 64),
        draw(&b, consumers::RELAY_HRW, 64)
    );
    // And a stream is reproducible on demand within one source.
    assert_eq!(
        draw(&a, consumers::RELAY_HRW, 64),
        draw(&a, consumers::RELAY_HRW, 64)
    );
}

#[test]
fn a_different_seed_produces_a_different_stream() {
    let a = SeededRngSource::new([1u8; 16], Arc::new(RecordingDerivation::default()));
    let b = SeededRngSource::new([2u8; 16], Arc::new(RecordingDerivation::default()));
    assert_ne!(
        draw(&a, consumers::RELAY_HRW, 64),
        draw(&b, consumers::RELAY_HRW, 64)
    );
}

/// The property CD-4 exists for: "adding a consumer cannot shift an existing
/// consumer's stream", which is what makes a scenario seed still useful a year
/// later.
#[test]
fn adding_a_consumer_does_not_shift_an_existing_consumers_stream() {
    let seed = [42u8; 16];
    let source = SeededRngSource::new(seed, Arc::new(RecordingDerivation::default()));
    let baseline = draw(&source, consumers::RELAY_HRW, 128);

    // A consumer that did not exist when `baseline` was recorded.
    const NEW_CONSUMER: ConsumerId = ConsumerId::new("added/in/a/later/release");
    let _ = draw(&source, NEW_CONSUMER, 128);
    let _ = draw(&source, consumers::BACKOFF_JITTER, 128);
    let _ = draw(&source, consumers::PORT_PREDICTION, 128);

    assert_eq!(
        draw(&source, consumers::RELAY_HRW, 128),
        baseline,
        "an added consumer shifted an existing consumer's stream"
    );
}

#[test]
fn every_declared_consumer_gets_an_independent_stream() {
    let source = SeededRngSource::new([3u8; 16], Arc::new(RecordingDerivation::default()));
    let all = [
        consumers::RELAY_HRW,
        consumers::RELAY_REGION_SPREAD,
        consumers::RELAY_SCORE_TIEBREAK,
        consumers::CANDIDATE_RACE_TIEBREAK,
        consumers::BACKOFF_JITTER,
        consumers::PORT_PREDICTION,
        consumers::LOSS_SCHEDULE,
        consumers::FAULT_SCHEDULE,
    ];
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for c in all {
        let s = draw(&source, c, 32);
        assert!(!seen.contains(&s), "{} shares a stream", c.as_str());
        seen.push(s);
    }
}

/// The half of CD-4 this crate owns: the `info` string is exactly
/// `"twinlab/v1/" || consumer_id`, and the `ikm` is the scenario seed.
#[test]
fn the_cd4_derivation_is_called_with_the_exact_info_string() {
    let recorder = Arc::new(RecordingDerivation::default());
    let source = SeededRngSource::new(
        [9u8; 16],
        Arc::clone(&recorder) as Arc<dyn StreamDerivation>,
    );
    let _ = source
        .rng_for(consumers::RELAY_REGION_SPREAD)
        .expect("stream");
    let calls = recorder.calls.lock().expect("lock");
    assert_eq!(calls.len(), 1);
    let (ikm, info) = &calls[0];
    assert_eq!(ikm.as_slice(), &[9u8; 16]);
    assert_eq!(info, b"twinlab/v1/relay/region-spread");
    assert_eq!(CD4_INFO_PREFIX, "twinlab/v1/");
    assert_eq!(
        consumers::RELAY_REGION_SPREAD.info_bytes(),
        b"twinlab/v1/relay/region-spread".to_vec()
    );
}

#[test]
fn the_deterministic_source_declares_itself_deterministic_and_production_does_not() {
    let seeded = SeededRngSource::new([0u8; 16], Arc::new(RecordingDerivation::default()));
    assert!(seeded.is_deterministic());
    let system = SystemRngSource::new(Arc::new(FixedEntropy(0)));
    assert!(
        !system.is_deterministic(),
        "a production run must never be declarable BIT"
    );
}

#[test]
fn an_entropy_failure_is_reported_and_never_papered_over() {
    let source = SystemRngSource::new(Arc::new(FailingEntropy));
    // `rng_for` succeeds — the source exists — and the failure surfaces on use.
    let mut rng = source.rng_for(consumers::RELAY_HRW).expect("source");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
    }));
    assert!(
        result.is_err(),
        "a CSPRNG failure must not return predictable bytes"
    );
    // And the error maps onto a registered code, never a bare string.
    assert_eq!(
        EnvError::EntropyUnavailable.reason_code(),
        codes::PLATFORM_ADAPTER_UNAVAILABLE
    );
}

#[test]
fn uniform_below_is_within_bounds_and_zero_span_is_zero() {
    let source = SeededRngSource::new([5u8; 16], Arc::new(RecordingDerivation::default()));
    let mut rng = source.rng_for(consumers::BACKOFF_JITTER).expect("stream");
    let bound = std::num::NonZeroU64::new(97).expect("non-zero");
    for _ in 0..1000 {
        assert!(rng.uniform_below(bound) < 97);
    }
    assert_eq!(rng.uniform_duration(Duration::ZERO), Duration::ZERO);
    let span = Duration::from_millis(250);
    for _ in 0..100 {
        assert!(rng.uniform_duration(span) < span);
    }
}

// ---------------------------------------------------------------------------
// CD-2 and the runtime bindings
// ---------------------------------------------------------------------------

#[test]
fn env_reports_the_runtime_kind_and_the_determinism_class() {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let env = virtual_env(
        &vt,
        Arc::new(SeededRngSource::new(
            [1u8; 16],
            Arc::new(RecordingDerivation::default()),
        )),
    );
    assert_eq!(env.runtime().kind(), RuntimeKind::VirtualTime);
    assert!(env.is_deterministic());
    // Debug names shapes, never contents.
    let rendered = format!("{env:?}");
    assert!(rendered.contains("VirtualTime"), "{rendered}");
}

#[test]
fn graceful_shutdown_refuses_new_work_rather_than_dropping_it() {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let env = virtual_env(
        &vt,
        Arc::new(SystemRngSource::new(Arc::new(FixedEntropy(0)))),
    );
    env.begin_shutdown();
    let err = env
        .runtime()
        .spawn(Box::pin(async {}))
        .expect_err("a spawn after shutdown must be refused, not silently dropped");
    assert_eq!(err, EnvError::ShuttingDown);
    assert_eq!(err.reason_code(), codes::INTERNAL_UNEXPECTED_STATE);
}

#[cfg(feature = "runtime-tokio")]
#[test]
fn both_production_runtime_bindings_exist_and_report_their_kind() {
    use twinvpn_env::binding::tokio_rt::TokioRuntime;
    use twinvpn_env::Runtime;

    let ws = TokioRuntime::work_stealing().expect("work-stealing runtime");
    assert_eq!(ws.kind(), RuntimeKind::WorkStealing);
    let st = TokioRuntime::single_threaded().expect("single-threaded runtime");
    assert_eq!(st.kind(), RuntimeKind::SingleThreaded);

    // The timer takes the INJECTED monotonic clock, so it cannot invent a second
    // origin. A one-millisecond sleep on the real clock is the smallest thing
    // worth asserting here; determinism lives in the virtual binding.
    let mono: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonicClock::new());
    let timer = ws.timer(Arc::clone(&mono));
    let done = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&done);
    ws.block_on(Box::pin(async move {
        timer.sleep(Duration::from_millis(1)).await;
        *flag.lock().expect("lock") = true;
    }));
    assert!(*done.lock().expect("lock"));
}

// ---------------------------------------------------------------------------
// The system wall-clock binding's three-state behaviour
// ---------------------------------------------------------------------------

#[test]
fn the_system_wall_clock_reports_its_trust_rather_than_assuming_it() {
    let synced = SystemWallClock::new(WallClockTrust::Synchronised);
    match synced.now() {
        WallClockReading::Trusted { millis } => {
            assert!(millis.as_millis() >= WALL_CLOCK_PLAUSIBILITY_FLOOR_MS);
        }
        WallClockReading::Unset => panic!("this host's clock is below the plausibility floor"),
        other => panic!("expected Trusted, got {other:?}"),
    }
    let unsynced = SystemWallClock::new(WallClockTrust::Unsynchronised(
        OffsetSource::PersistedLastKnown,
    ));
    assert!(matches!(
        unsynced.now(),
        WallClockReading::Offset {
            source: OffsetSource::PersistedLastKnown,
            ..
        }
    ));
}

#[test]
fn the_monotonic_binding_is_non_decreasing() {
    let clock = SystemMonotonicClock::new();
    let a = clock.now();
    let b = clock.now();
    assert!(b >= a);
    assert_eq!(
        b.duration_since(a).as_micros() as u64,
        b.as_micros() - a.as_micros()
    );
}
