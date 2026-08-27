//! CD-2: [`Env`], the bundle every component takes at construction.
//!
//! **Authority:** ADR-0018 §11.8 CD-2, `docs/architecture.md` §5.2 R-DET-1.
//!
//! > **CD-2.** Every component takes its `Env` at construction. No global, no
//! > `OnceCell` clock, no ambient default. A component that cannot be constructed
//! > without a clock cannot silently acquire one.
//!
//! Three things are deliberately absent, and each absence is the mechanism for
//! one clause of that rule:
//!
//! - **No `Default`.** R-DET-1 property 2: "'Injectable' is not 'bound at
//!   construction'. A settable global satisfies 'injectable'. A component that
//!   *can* be constructed without a clock will eventually acquire one." A
//!   `Default` impl would be exactly such a construction path.
//! - **No `static`, no `OnceCell`, no `set_global`.** There is no API in this
//!   crate that stores an `Env` anywhere; the only way to reach one is to have
//!   been handed one.
//! - **No partial construction.** [`Env::new`] takes [`EnvParts`], whose fields
//!   are all required. A missing capability is a compile error, not a runtime
//!   `unwrap`.
//!
//! `Env` is cheap to clone — it is an `Arc` around the capability set — so
//! passing it to every component costs a refcount, not a copy.

use std::sync::Arc;

use crate::clock::{ElapsedClock, MonotonicClock, WallClock, WallClockReading};
use crate::clock::{ElapsedInstant, MonotonicInstant};
use crate::error::EnvError;
use crate::rng::{ConsumerId, Entropy, Rng, RngSource};
use crate::task::{Runtime, Timer};

/// The capability set. Every field is required.
///
/// A struct rather than a builder for the reason CD-2 gives: a builder with
/// optional fields has a `build()` that can succeed without a clock, and that is
/// the construction path the rule exists to remove.
pub struct EnvParts {
    /// The suspend-**exclusive** clock. Every timer runs on it.
    pub monotonic: Arc<dyn MonotonicClock>,
    /// The suspend-**inclusive** clock. Suspend-gap measurement, rekey windows,
    /// NAT binding lifetime, and long-horizon policy deadlines (LC-8 F2).
    pub elapsed: Arc<dyn ElapsedClock>,
    /// The wall clock. **Evidence only, never a timer input**, and a three-state
    /// value (CD-1a).
    pub wall: Arc<dyn WallClock>,
    /// Scheduled waiting.
    pub timer: Arc<dyn Timer>,
    /// The async scheduler.
    pub runtime: Arc<dyn Runtime>,
    /// The OS CSPRNG, for anything that must be unpredictable.
    pub entropy: Arc<dyn Entropy>,
    /// The per-consumer stream source (CD-4).
    pub rng: Arc<dyn RngSource>,
}

struct Inner {
    monotonic: Arc<dyn MonotonicClock>,
    elapsed: Arc<dyn ElapsedClock>,
    wall: Arc<dyn WallClock>,
    timer: Arc<dyn Timer>,
    runtime: Arc<dyn Runtime>,
    entropy: Arc<dyn Entropy>,
    rng: Arc<dyn RngSource>,
}

/// The injected environment.
///
/// Deliberately has **no** `Default`, no global accessor, and no way to be
/// constructed with a capability missing. See the module documentation.
#[derive(Clone)]
pub struct Env {
    inner: Arc<Inner>,
}

impl Env {
    /// Binds a complete capability set.
    #[must_use]
    pub fn new(parts: EnvParts) -> Self {
        Self {
            inner: Arc::new(Inner {
                monotonic: parts.monotonic,
                elapsed: parts.elapsed,
                wall: parts.wall,
                timer: parts.timer,
                runtime: parts.runtime,
                entropy: parts.entropy,
                rng: parts.rng,
            }),
        }
    }

    /// The current **suspend-exclusive** monotonic reading.
    ///
    /// What every timer in `docs/reliability.md` §5 measures against.
    #[must_use]
    pub fn now_monotonic(&self) -> MonotonicInstant {
        self.inner.monotonic.now()
    }

    /// The current **suspend-inclusive** elapsed reading.
    ///
    /// For the suspend gap, rekey-window comparison, NAT binding lifetime, and
    /// the long-horizon policy deadlines of LC-8's finding F2. Never for a
    /// liveness or recovery timer — and the type system enforces that, because
    /// [`crate::Timer`] does not accept an [`ElapsedInstant`].
    #[must_use]
    pub fn now_elapsed(&self) -> ElapsedInstant {
        self.inner.elapsed.now()
    }

    /// The current wall-clock reading — a three-state value.
    ///
    /// Evidence only. To evaluate a validity window, pass this to
    /// [`crate::ValidityClock::try_from_reading`], which is the only way to get an
    /// evaluator and which cannot be built from `Unset`.
    #[must_use]
    pub fn now_wall(&self) -> WallClockReading {
        self.inner.wall.now()
    }

    /// The timer capability.
    #[must_use]
    pub fn timer(&self) -> &Arc<dyn Timer> {
        &self.inner.timer
    }

    /// The runtime capability.
    #[must_use]
    pub fn runtime(&self) -> &Arc<dyn Runtime> {
        &self.inner.runtime
    }

    /// The OS CSPRNG.
    #[must_use]
    pub fn entropy(&self) -> &Arc<dyn Entropy> {
        &self.inner.entropy
    }

    /// CD-4: an independent random stream for one `const`-declared consumer.
    ///
    /// Under the deterministic binding this is
    /// `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)`,
    /// with the derivation supplied by the binding; under the production binding
    /// every consumer draws from the platform CSPRNG. Either way, **adding a
    /// consumer does not shift an existing consumer's stream** — the property
    /// that makes a scenario seed still useful a year later.
    ///
    /// # Errors
    ///
    /// Propagates an entropy or derivation failure rather than substituting a
    /// weaker stream.
    pub fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        self.inner.rng.rng_for(consumer)
    }

    /// Whether this environment's randomness is reproducible from a seed.
    ///
    /// TwinLab asserts this before declaring a `BIT` determinism class, so a
    /// determinism claim cannot be made about a production run by mistake.
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.inner.rng.is_deterministic()
    }

    /// Begins graceful shutdown of the runtime.
    pub fn begin_shutdown(&self) {
        self.inner.runtime.begin_shutdown();
    }
}

impl core::fmt::Debug for Env {
    /// Names the capability *shapes*, never their contents.
    ///
    /// An `Env` reaches a `tracing` call whenever a component that holds one is
    /// formatted; the entropy source in particular must never render anything
    /// about its state.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Env")
            .field("runtime", &self.inner.runtime.kind())
            .field("deterministic", &self.is_deterministic())
            .finish_non_exhaustive()
    }
}
