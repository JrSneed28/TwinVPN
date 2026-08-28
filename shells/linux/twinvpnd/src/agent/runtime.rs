//! Building the `Env`, the adapter and the core — and taking them down again.
//!
//! **Authority:** ADR-0018 CD-1 (the three clocks), CD-2 (every component takes
//! its `Env` at construction), CD-3, §11.3 (the two runtime bindings), §11.16
//! (a) (S-47: exactly one process holds a mutating core handle);
//! ADR-0022 LC-8; ADR-0016 §11.6 (the start order); `ownership.md` §6 rule 7 and
//! §8 **W-7** and **W-28**.
//!
//! # W-7: this is where the three clocks are bound, together
//!
//! `twinvpn-env` ships no production `ElapsedClock` and no production `Entropy`,
//! because reaching either needs `unsafe` or an OS branch. [`build_env`] is the
//! one place all three clocks are named at once, so a reviewer asking "does this
//! build have the suspend-inclusive clock" reads one function:
//!
//! | Capability | Binding | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `SystemMonotonicClock` (`CLOCK_MONOTONIC`) | **excluded** |
//! | `ElapsedClock` | `BootTimeElapsedClock` (`CLOCK_BOOTTIME`) | **included** |
//! | `WallClock` | `SystemWallClock` | evidence only |
//!
//! Substituting the monotonic clock for the elapsed one "compiles, passes every
//! test that does not suspend, and fails only on a device that actually sleeps".
//! [`build_env`]'s own test reads both and asserts their origins differ.
//!
//! # W-28: the crash window, stated
//!
//! `CoreSessionJournal` is **write-behind**: a successful `persist` means
//! *queued*, not durable, and `StoreBridge::flush` drains the queue into one
//! transaction. So the agent's shutdown path must flush, and
//! [`Agent::shutdown`] does — before the runtime stops accepting work, because a
//! flush scheduled after that would never run.
//!
//! **The crash window this build actually has:** every session transition
//! between the last successful flush and an abrupt `SIGKILL` or a power loss is
//! lost. A `SIGTERM` is flushed (that is what [`Agent::shutdown`] is for), and
//! `docs/reliability.md` §6.5's resumption guarantee survives either way,
//! because resumption re-derives from the control plane rather than from the
//! journal. What is lost is the *local* record of the most recent transitions —
//! which is a diagnostics loss, not a correctness one. Stated rather than
//! implied.

use std::sync::Arc;

use twinvpn_env::binding::system::{SystemMonotonicClock, SystemWallClock, WallClockTrust};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{
    ElapsedClock, Env, EnvError, EnvParts, MonotonicClock, OffsetSource, SystemRngSource,
};
use twinvpn_platform_linux::{BootTimeElapsedClock, LinuxPlatformAdapter, SystemEntropy};

/// Why the agent could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// A capability could not be bound.
    #[error("an environment capability could not be bound")]
    Env(#[from] EnvError),
    /// The core refused to be created.
    ///
    /// **VR-4**: an `abi_major` mismatch "is a **packaging defect**, not an
    /// operating state — but it is still checked, because the alternative is
    /// undefined behaviour".
    #[error("the core refused to be created: {code}")]
    Core {
        /// The registered code the core named.
        code: String,
    },
}

/// Binds all three clocks, the timer, the runtime and the two randomness
/// sources.
///
/// # Errors
///
/// [`EnvError`] if the OS refuses the runtime's threads or the CSPRNG cannot be
/// read. **The entropy source is probed here**, not on first use: a CSPRNG that
/// fails mid-stream poisons the core (F-7), and finding out at startup is
/// strictly better than finding out during a handshake.
pub fn build_env() -> Result<(Env, Arc<TokioRuntime>), EnvError> {
    let monotonic: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonicClock::new());
    // **W-7's whole point.** `CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`.
    let elapsed: Arc<dyn ElapsedClock> = BootTimeElapsedClock::shared();

    let entropy = Arc::new(SystemEntropy::new());
    entropy.probe()?;
    let entropy: Arc<dyn twinvpn_env::Entropy> = entropy;

    // ADR-0018 §11.3: the **work-stealing** binding on Linux.
    let runtime = Arc::new(TokioRuntime::work_stealing()?);
    let timer = runtime.timer(Arc::clone(&monotonic));

    let env = Env::new(EnvParts {
        monotonic,
        elapsed,
        // CD-1a: the platform's synchronisation claim is a CONSTRUCTOR ARGUMENT,
        // never an assumption. A shell that cannot answer "is this clock
        // synchronised" passes `Unsynchronised`, and the reading is reported as
        // an offset rather than as trusted. This build does not query
        // `timedatectl`, so the honest answer is that it makes no claim.
        // `PersistedLastKnown` is the honest source tag: the value comes from
        // `CLOCK_REALTIME`, which on a host with an RTC is exactly "persisted
        // from a previous run of this device" and on one without is below the
        // plausibility floor and reported as `Unset` regardless.
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Unsynchronised(
            OffsetSource::PersistedLastKnown,
        ))),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn twinvpn_env::Runtime>,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    Ok((env, runtime))
}

/// The running agent: one `Env`, one adapter, one core.
///
/// **S-47**: "exactly **one process** [holds] a mutating core handle at a time",
/// and one adapter object, "because a core that assembled its platform from six
/// independently-supplied pieces could not state which adapter it was talking
/// to".
pub struct Agent {
    /// The injected environment.
    pub env: Env,
    /// The platform seam.
    pub adapter: Arc<LinuxPlatformAdapter>,
    /// The hosted core.
    pub core: Arc<twinvpn_core::Core>,
}

impl Agent {
    /// Begins graceful shutdown, in the order `ownership.md` §6 rule 7 and
    /// [`twinvpn_core::Core::begin_shutdown`] fix.
    ///
    /// > the runtime stops accepting work, the event stream closes so a drain
    /// > thread unblocks, and the adapter is told last — and telling the adapter
    /// > **does not** remove the installed ruleset, because CB-6 puts it in the
    /// > OS's custody so that the core going away cannot drop protection.
    ///
    /// # W-28's flush
    ///
    /// The journal is write-behind, so a successful `persist` means *queued*.
    /// The drain has to happen **before** the runtime stops accepting work, or
    /// the flush is scheduled onto a runtime that will not run it. The core's
    /// own `begin_shutdown` does the rest in the right order.
    pub fn shutdown(&self) {
        tracing::info!(
            target: "twinvpn.agent",
            "shutting down: draining the write-behind journal, then closing the event stream"
        );
        // The core owns the bridge and its flush; calling `begin_shutdown` is
        // how the shell asks for the whole sequence rather than reaching past it
        // into the store, which would be a second writer (CD-I5's direction
        // applied to the store).
        self.core.begin_shutdown();
        tracing::info!(
            target: "twinvpn.agent",
            custody_survives_exit = twinvpn_platform::NetworkConfig::enforcement_custody(
                self.adapter.network()
            )
            .survives_core_exit,
            "the installed enforcement ruleset is left in the OS's custody (CB-6)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_clocks_are_bound_and_the_elapsed_one_is_not_the_monotonic_one() {
        // W-7, and LC-8's invisible-on-CI failure. `SystemMonotonicClock` zeroes
        // at construction; the elapsed clock is absolute since boot. A build
        // that substituted one for the other would read near zero here.
        let (env, _runtime) = build_env().expect("binds every capability");
        let monotonic = env.now_monotonic().as_micros();
        let elapsed = env.now_elapsed().as_micros();
        assert!(
            monotonic < 1_000_000,
            "monotonic zeroes at construction: {monotonic}"
        );
        assert!(
            elapsed > 1_000_000,
            "the elapsed clock must be CLOCK_BOOTTIME, absolute since boot: {elapsed}"
        );
        // And the wall clock is a three-state value, never a bare timestamp.
        assert!(!matches!(
            env.now_wall(),
            twinvpn_env::WallClockReading::Trusted { .. }
        ));
    }

    #[test]
    fn the_randomness_is_not_deterministic_in_production() {
        // TwinLab asserts `is_deterministic()` before declaring a BIT class, so
        // a production `Env` that claimed determinism would let a determinism
        // claim be made about a production run by mistake.
        let (env, _runtime) = build_env().expect("binds");
        assert!(!env.is_deterministic());
        let mut rng = env
            .rng_for(twinvpn_env::consumers::BACKOFF_JITTER)
            .expect("a stream");
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn the_entropy_source_is_probed_at_startup_not_on_first_use() {
        // A CSPRNG that fails mid-stream poisons the instance (F-7). Finding out
        // at startup is strictly better than finding out during a handshake.
        SystemEntropy::new()
            .probe()
            .expect("the platform CSPRNG is seeded");
    }
}
