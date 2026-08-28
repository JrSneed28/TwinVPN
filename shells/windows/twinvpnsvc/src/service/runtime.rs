//! Building the `Env` and the core — and taking them down again.
//!
//! **Authority:** ADR-0018 CD-1 (the three clocks), CD-2 (every component takes
//! its `Env` at construction), CD-3, §11.3 (the two runtime bindings), §11.16
//! (a) (S-47: exactly one process holds a mutating core handle);
//! ADR-0022 LC-8; ADR-0016 §11.6; `ownership.md` §6 rule 7 and §8 **W-7**.
//!
//! # W-7: this is where the three clocks are bound, together
//!
//! `twinvpn-env` ships no production `ElapsedClock` and no production `Entropy`,
//! because reaching either needs `unsafe` or an OS branch. [`build_env`] is the
//! one place all three clocks are named at once, so a reviewer asking "does this
//! build have the suspend-inclusive clock" reads one function:
//!
//! | Capability | Binding | Windows primitive | Suspend |
//! |---|---|---|---|
//! | `MonotonicClock` | `WindowsMonotonicClock` | `QueryUnbiasedInterruptTimePrecise` | **excluded** |
//! | `ElapsedClock` | `WindowsElapsedClock` | `QueryInterruptTimePrecise` | **included** |
//! | `WallClock` | `WindowsWallClock` | `GetSystemTimeAsFileTime` | evidence only |
//!
//! **All three are the adapter's on this platform**, not just the elapsed one.
//! `twinvpn-env`'s `SystemMonotonicClock` is `std::time::Instant`, which on
//! Windows is `QueryPerformanceCounter` — and that does **not** exclude sleep.
//! LC-8's Windows row asks for the unbiased interrupt time, so binding
//! `SystemMonotonicClock` here would give this build a monotonic clock that
//! advanced across a suspend, which is the mirror image of the defect W-7 names
//! and equally invisible on a machine that never sleeps.
//!
//! # W-43 has landed, so this shell does not carry its refusal
//!
//! `shells/linux/twinvpnd` refuses to start when the injected runtime has no I/O
//! driver, because `twinvpn-env`'s `TokioRuntime` once built with
//! `.enable_time()` and not `.enable_io()`. `core/crates/twinvpn-env/src/binding/tokio_rt.rs`
//! now calls both, so the condition cannot arise and a probe here would assert a
//! fact about `twinvpn-env` that `twinvpn-env` already asserts about itself.
//! Recorded rather than silently omitted.
//!
//! # CD-2, and why the entropy source is a parameter
//!
//! [`build_env_with`] takes the CSPRNG rather than constructing one.
//! [`build_env`] is the production entry point and passes
//! [`WindowsEntropy`] — the platform CSPRNG, probed at startup and never
//! substituted. The injected form exists so a **test** on a host that is not
//! Windows can build an `Env` at all, and it says so at the call site; there is
//! no path by which the service binary passes anything else.

use std::sync::{Arc, Mutex};

use twinvpn_env::{
    ElapsedClock, Entropy, Env, EnvError, EnvParts, MonotonicClock, SystemRngSource,
};
use twinvpn_platform::PlatformAdapter;
use twinvpn_platform_windows::clock::{
    WallClockTrust, WindowsElapsedClock, WindowsEntropy, WindowsMonotonicClock, WindowsWallClock,
};

use super::start::StartupRefusal;

/// Binds all three clocks, the timer, the runtime and the two randomness
/// sources — with the platform CSPRNG.
///
/// # Errors
///
/// [`EnvError`] if the OS refuses the runtime's threads or the CSPRNG cannot be
/// read. **The entropy source is probed here**, not on first use: a CSPRNG that
/// fails mid-stream poisons the core, and finding out at startup is strictly
/// better than finding out during a handshake.
pub fn build_env() -> Result<(Env, Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>), EnvError> {
    let entropy = Arc::new(WindowsEntropy::new());
    entropy.probe()?;
    build_env_with(entropy)
}

/// The injected form.
///
/// # Errors
///
/// [`EnvError`] if the OS refuses the runtime's threads.
pub fn build_env_with(
    entropy: Arc<dyn Entropy>,
) -> Result<(Env, Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>), EnvError> {
    let monotonic: Arc<dyn MonotonicClock> = WindowsMonotonicClock::shared();
    // **W-7 and LC-8's Windows row.** `QueryInterruptTimePrecise`, which is
    // biased and therefore includes sleep — not the unbiased twin above it.
    let elapsed: Arc<dyn ElapsedClock> = WindowsElapsedClock::shared();

    // ADR-0018 §11.3: the **work-stealing** binding on a desktop host.
    let runtime = Arc::new(twinvpn_env::binding::tokio_rt::TokioRuntime::work_stealing()?);
    let timer = runtime.timer(Arc::clone(&monotonic));

    let env = Env::new(EnvParts {
        monotonic,
        elapsed,
        // CD-1a: the platform's synchronisation claim is a CONSTRUCTOR ARGUMENT,
        // never an assumption. This build does not query the Windows Time
        // service, so the honest answer is that it makes no claim — and a
        // Windows clock at boot *is* literally the persisted last-known time.
        wall: WindowsWallClock::shared(WallClockTrust::Unsynchronised),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn twinvpn_env::Runtime>,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    Ok((env, runtime))
}

/// Creates the core, with VR-4's ABI check first.
///
/// # Errors
///
/// [`StartupRefusal`] carrying `INTERNAL.ABI_VERSION_MISMATCH`. VR-4: an
/// `abi_major` mismatch "is a **packaging defect**, not an operating state — but
/// it is still checked, because the alternative is undefined behaviour".
pub fn build_core(
    env: &Env,
    adapter: Arc<dyn PlatformAdapter>,
    hardware_backed: bool,
    sek_custody: &str,
) -> Result<twinvpn_core::Core, StartupRefusal> {
    twinvpn_core::Core::create(twinvpn_core::CoreParts {
        env: env.clone(),
        adapter,
        // VR-4: `TW_ABI_MAJOR` as THIS shell compiled it.
        abi_major_expected: twinvpn_core::ABI_MAJOR,
        abi_major: twinvpn_core::ABI_MAJOR,
        abi_minor: twinvpn_core::ABI_MINOR,
        schema_digest: Vec::new(),
        crypto_provider: "twinvpn-crypto".to_owned(),
        // CB-6a's declared per-target fact, reported by the adapter and never
        // assumed: `PlatformPerformed` with a TPM, `CoreHeld` without.
        sek_custody: sek_custody.to_owned(),
        // §11.16 (l): reported by the adapter, truthfully. The core MUST NOT
        // assume it, and MUST NOT substitute a file-backed signer silently.
        hardware_backed,
        ledger_capacity: 1024,
        event_capacity: 256,
    })
    .map_err(|diagnostic| StartupRefusal {
        code: "INTERNAL.ABI_VERSION_MISMATCH",
        specified: "INTERNAL.ABI_VERSION_MISMATCH",
        detail: diagnostic.code().as_str().to_owned(),
        exit: 70,
    })
}

/// The running service: one `Env`, one adapter, one core.
///
/// **S-47**: "exactly **one process** [holds] a mutating core handle at a time",
/// and one adapter object, "because a core that assembled its platform from six
/// independently-supplied pieces could not state which adapter it was talking
/// to".
pub struct Service {
    /// The injected environment.
    pub env: Env,
    /// The platform seam.
    pub adapter: Arc<dyn PlatformAdapter>,
    /// The hosted core.
    pub core: Arc<twinvpn_core::Core>,
    /// **§11.10's event stream**, and the thread that feeds it.
    ///
    /// The shutdown comment below described a drain thread from the day it was
    /// written. There was none — `next_event` was called nowhere in this crate
    /// — which is `ownership.md` §10.8 **M-12** as it landed on this platform.
    pub fanout: Arc<super::events::Fanout>,
    drain: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Service {
    /// Assembles the service and **starts the drain**.
    ///
    /// The drain is a `std::thread` and not a runtime task: `Core::next_event`
    /// blocks on a condvar, and blocking a runtime worker on a condvar is how a
    /// runtime deadlocks. The core's own documentation says the same — *"called
    /// from the shell's drain thread, which is not inside the core's runtime"*.
    #[must_use]
    pub fn start(env: Env, adapter: Arc<dyn PlatformAdapter>, core: twinvpn_core::Core) -> Self {
        let core = Arc::new(core);
        let fanout = Arc::new(super::events::Fanout::new());
        let drain = std::thread::Builder::new()
            .name("twinvpn-mi-drain".to_owned())
            .spawn({
                let core = Arc::clone(&core);
                let fanout = Arc::clone(&fanout);
                move || super::events::drain(&core, &fanout, DRAIN_TIMEOUT)
            })
            .ok();
        if drain.is_none() {
            // A service that cannot spawn its drain would run with a bounded
            // ring nobody empties, dropping events oldest-first with nothing to
            // report the drop. Named rather than ignored; the service is still
            // useful for requests and says so.
            tracing::error!(
                target: "twinvpn.service",
                specified_code = "PLATFORM.SERVICE.DRAIN_UNAVAILABLE",
                "the event drain thread could not be spawned; no client will \
                 receive events and every command result will be empty"
            );
        }
        Self {
            env,
            adapter,
            core,
            fanout,
            drain: Mutex::new(drain),
        }
    }

    /// Begins graceful shutdown, in the order `ownership.md` §6 rule 7 fixes.
    ///
    /// > the runtime stops accepting work, the event stream closes so a drain
    /// > thread unblocks, and the adapter is told last — and telling the adapter
    /// > **does not** remove the installed ruleset, because CB-6 puts it in the
    /// > OS's custody so that the core going away cannot drop protection.
    ///
    /// ADR-0022 §11.4's Windows row says the same thing in the SCM's vocabulary:
    /// "Shutdown MUST NOT remove enforcement — persistent WFP filters stay."
    /// Nothing on this path calls `disarm`, and
    /// `shutdown_leaves_the_installed_filters_exactly_where_they_were` in the
    /// adapter's own `tests/enforcement.rs` asserts it against recorded engine
    /// state rather than against this comment.
    pub fn shutdown(&self) {
        tracing::info!(
            target: "twinvpn.service",
            "shutting down: draining the write-behind journal, then closing the event stream"
        );
        self.core.begin_shutdown();
        // §6 rule 7's middle step, which now exists: the event stream closes,
        // the drain unblocks, and every subscriber and every outstanding
        // completion is settled rather than left waiting on a body that will
        // never arrive.
        self.fanout.close();
        if let Some(handle) = self
            .drain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            // The thread is inside at most one `next_event` call, bounded by
            // `DRAIN_TIMEOUT`, so this join is bounded too.
            let _ = handle.join();
        }
        tracing::info!(
            target: "twinvpn.service",
            custody_survives_exit = twinvpn_platform::NetworkConfig::enforcement_custody(
                self.adapter.network_config()
            )
            .survives_core_exit(),
            "the installed enforcement ruleset is left in the OS's custody (CB-6)"
        );
    }
}

/// How long the drain thread sits in one `Core::next_event` call.
///
/// **Not a deadline for anything.** CD-3 makes timeouts the core's; this bounds
/// how long the thread is unresponsive to a shutdown that has already been
/// requested, which is a property of this thread and not of any protocol.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed source, for the one thing a host that is not Windows cannot do.
    ///
    /// **Never reachable from the service binary**: `build_env` passes
    /// [`WindowsEntropy`] and nothing else, and this type is `#[cfg(test)]`.
    /// It exists so the clocks, the runtime, the timer and the core can be
    /// exercised on the host this crate was written on.
    struct FixedEntropy;

    impl Entropy for FixedEntropy {
        fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = u8::try_from(i % 251).unwrap_or(0);
            }
            Ok(())
        }
    }

    fn env() -> Env {
        build_env_with(Arc::new(FixedEntropy))
            .expect("the runtime binds")
            .0
    }

    #[test]
    fn all_three_clocks_are_bound_and_the_elapsed_one_is_not_the_monotonic_one() {
        // W-7, and LC-8's invisible-on-CI failure. The monotonic clock zeroes at
        // construction; the elapsed clock is absolute since boot. A build that
        // substituted one for the other would read the same here.
        let env = env();
        let monotonic = env.now_monotonic().as_micros();
        let elapsed = env.now_elapsed().as_micros();
        assert!(
            monotonic < 1_000_000,
            "the monotonic clock zeroes at construction: {monotonic}"
        );
        assert!(
            elapsed > 1_000_000,
            "the elapsed clock is absolute since boot: {elapsed}"
        );
    }

    #[test]
    fn the_wall_clock_is_a_three_state_value_and_never_a_bare_timestamp() {
        // CD-1a. This build does not query the Windows Time service, so it
        // makes no synchronisation claim.
        assert!(!matches!(
            env().now_wall(),
            twinvpn_env::WallClockReading::Trusted { .. }
        ));
    }

    #[test]
    fn the_production_env_is_not_deterministic() {
        // TwinLab asserts `is_deterministic()` before declaring a BIT class, so
        // a production `Env` that claimed determinism would let a determinism
        // claim be made about a production run by mistake.
        assert!(!env().is_deterministic());
    }

    #[test]
    fn the_platform_csprng_is_probed_at_startup_and_this_host_has_none() {
        // `build_env` probes rather than deferring to the first nonce. On a
        // host that is not Windows the probe REFUSES rather than returning
        // synthetic bytes, which is the whole point: a fixed "random" value is
        // indistinguishable from working and produces predictable nonces.
        let outcome = build_env();
        if cfg!(windows) {
            assert!(outcome.is_ok(), "a Windows host has BCryptGenRandom");
        } else {
            let error = outcome.err().expect("no BCryptGenRandom on this host");
            assert!(matches!(error, EnvError::EntropyUnavailable));
        }
    }

    #[test]
    fn the_timer_runs_on_the_monotonic_clock_and_never_on_the_elapsed_one() {
        // CD-1: "every timer takes this". A timer on the suspend-inclusive
        // clock would fire everything at once on a wake, which is the mirror
        // image of a timer that never fires.
        let env = env();
        // The binding is asserted by construction — `runtime.timer(monotonic)`
        // above takes the monotonic clock and nothing else can be passed — so
        // what is checked here is that the two clocks really are different
        // objects with different readings.
        assert_ne!(
            env.now_monotonic().as_micros(),
            env.now_elapsed().as_micros()
        );
    }

    #[test]
    fn the_service_starts_a_drain_and_joins_it_on_shutdown() {
        // The wiring `ownership.md` §10.8 M-12 found missing: `shutdown`'s own
        // documentation described "the event stream closes so a drain thread
        // unblocks", and there was no drain thread. This asserts the thread
        // exists by observing what only a running drain can do — move an event
        // from the core's queue onto the fan-out — and that `shutdown` joins
        // it rather than leaking it.
        use twinvpn_platform::mock::{MockAdapter, MockOptions};

        let env = env();
        let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
        let core = build_core(
            &env,
            Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
            false,
            "core-held",
        )
        .expect("the ABI matches");

        let service = Service::start(env, adapter as Arc<dyn PlatformAdapter>, core);
        let id = service.fanout.subscribe(twinvpn_mgmt::SUBSCRIBER_WATERMARK);
        // `Default::default()` rather than a named `TransitionEvent`: this
        // shell has no `twinvpn-schema` dependency and must not acquire one —
        // CB-2's "translate, don't model" is why the core encodes and this
        // crate only forwards.
        #[allow(clippy::default_trait_access)]
        service
            .core
            .publish_transition(Default::default(), Some("dana".to_owned()));

        // The drain blocks in `next_event`, so the event arrives on another
        // thread's schedule. Bounded spin rather than a sleep: CD-3 keeps
        // `tokio::time` out of this crate, and a spin that gives up is a test
        // failure rather than a hang.
        let mut delivered = None;
        for _ in 0..2_000 {
            if let Some(frame) = service.fanout.next_for(id) {
                delivered = Some(frame);
                break;
            }
            std::thread::yield_now();
        }
        let Some(twinvpn_mgmt::Frame::Event { event, .. }) = delivered else {
            panic!("the drain never delivered the event; is the thread running?")
        };
        assert_eq!(event.topic, "transition");
        assert_eq!(event.actor_principal.as_deref(), Some("dana"));

        // And shutdown joins it. A leaked drain would hold an `Arc<Core>` for
        // the life of the process and keep publishing into a closed fan-out.
        service.shutdown();
        assert!(service.fanout.is_closed());
    }
}
