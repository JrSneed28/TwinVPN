//! CD-4: randomness, entropy, and the per-consumer seeded streams.
//!
//! **Authority:** ADR-0018 §11.8 CD-3/CD-4, `docs/testing-strategy.md` §3.5,
//! `docs/architecture.md` §5.2 R-DET-1.
//!
//! # The CD-4 contract
//!
//! > `Env::rng_for(consumer_id)` derives
//! > `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)`.
//! > `consumer_id` is a `const` at each consumer, so adding a consumer cannot
//! > shift an existing consumer's stream.
//!
//! [`ConsumerId`] takes only a `&'static str`, which is what makes the `const`
//! half true at the type level.
//!
//! # An architectural conflict, resolved by the integration lead
//!
//! CD-I2 permits only `twinvpn-crypto` to declare a cryptographic dependency,
//! and §11.7's arrow already has `twinvpn-crypto` depending on `twinvpn-env` — so
//! an HKDF implementation *here* would be a dependency cycle as well as a CD-I2
//! violation. The integration lead's direction, which this module implements:
//!
//! - `twinvpn-env` declares `rng_for` as part of this trait surface and declares
//!   **no** cryptographic dependency;
//! - the **binding** supplies the derivation: the production binding takes
//!   platform entropy through [`Entropy`], and the deterministic binding — which
//!   only TwinLab needs — supplies HKDF-SHA-256 through [`StreamDerivation`].
//!
//! What this crate still owns, and tests, is the part of CD-4 that is not
//! cryptographic: that the `info` string is exactly `"twinlab/v1/" || consumer_id`
//! ([`CD4_INFO_PREFIX`]), and that stream independence holds — adding a consumer
//! does not shift an existing consumer's stream.
//!
//! This is reported as an architectural clarification requiring ADR-0018 §11.7
//! confirmation.

use alloc_free::SeededRng;
use core::num::NonZeroU64;
use std::sync::Arc;

use crate::error::EnvError;

/// The CD-4 `info` prefix. The derivation's `info` is this followed by the
/// consumer id, with no separator beyond the trailing slash already present here.
pub const CD4_INFO_PREFIX: &str = "twinlab/v1/";

/// A stable, `const`-declared name for one consumer of randomness.
///
/// Taking `&'static str` is the mechanism behind CD-4's "`consumer_id` is a
/// `const` at each consumer": a name assembled at runtime cannot be one, so a
/// consumer cannot accidentally take a different stream on different runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsumerId(&'static str);

impl ConsumerId {
    /// Declares a consumer.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// The consumer's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// The exact CD-4 `info` bytes for this consumer.
    #[must_use]
    pub fn info_bytes(self) -> Vec<u8> {
        let mut info = Vec::with_capacity(CD4_INFO_PREFIX.len() + self.0.len());
        info.extend_from_slice(CD4_INFO_PREFIX.as_bytes());
        info.extend_from_slice(self.0.as_bytes());
        info
    }
}

/// The consumers `docs/testing-strategy.md` §3.5 requires to be seeded.
///
/// Declared centrally so the set is auditable, and so that
/// `docs/testing-strategy.md`'s list and the code cannot silently diverge. A
/// consumer added here does **not** shift any existing consumer's stream, which
/// is the property CD-4's per-consumer derivation exists to provide.
pub mod consumers {
    use super::ConsumerId;

    /// ADR-0006 §11.7's HRW hash. Named in CD-4 itself.
    pub const RELAY_HRW: ConsumerId = ConsumerId::new("relay/hrw");
    /// ADR-0006's `uniform(0, T_REGION_SPREAD)` drain draw. Named in CD-4 itself.
    pub const RELAY_REGION_SPREAD: ConsumerId = ConsumerId::new("relay/region-spread");
    /// Relay-selection score tie-breaks.
    pub const RELAY_SCORE_TIEBREAK: ConsumerId = ConsumerId::new("relay/score-tiebreak");
    /// Candidate-racing tie-breaks.
    pub const CANDIDATE_RACE_TIEBREAK: ConsumerId = ConsumerId::new("path/candidate-tiebreak");
    /// Backoff jitter (`docs/reliability.md` §6.1).
    pub const BACKOFF_JITTER: ConsumerId = ConsumerId::new("reliability/backoff-jitter");
    /// Port-prediction socket selection (`docs/networking.md` §3.6).
    pub const PORT_PREDICTION: ConsumerId = ConsumerId::new("nat/port-prediction");
    /// The loss schedule, for a `BIT` scenario's precomputed drop bitmap.
    pub const LOSS_SCHEDULE: ConsumerId = ConsumerId::new("lab/loss-schedule");
    /// The fault-injection schedule.
    pub const FAULT_SCHEDULE: ConsumerId = ConsumerId::new("lab/fault-schedule");
}

/// The OS CSPRNG, supplied by the platform binding.
///
/// This crate declares no entropy dependency of its own: CD-3 bans `getrandom`
/// everywhere outside `twinvpn-env`'s implementations, and the *implementation*
/// that is permitted to call it is the shell's, reached through this trait. That
/// keeps `twinvpn-env` free of both a crypto dependency (CD-I2) and an OS branch
/// (CB-3).
pub trait Entropy: Send + Sync {
    /// Fills `dst` with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// [`EnvError::EntropyUnavailable`] if the platform CSPRNG cannot be read.
    /// **Never** falls back to a weaker source: a silent downgrade here is
    /// indistinguishable from working, and the value it produces is the one every
    /// nonce and key depends on.
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError>;
}

/// One consumer's random stream.
pub trait Rng: Send {
    /// Fills `dst` from the stream.
    fn fill_bytes(&mut self, dst: &mut [u8]);

    /// The next 64 bits.
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// A uniform value in `0..bound`, **without modulo bias**.
    ///
    /// Rejection-sampled rather than reduced: a plain `% bound` skews the low
    /// values, and a skewed jitter draw is exactly the kind of defect that shows
    /// up as a thundering herd under load and as nothing at all in a unit test.
    fn uniform_below(&mut self, bound: NonZeroU64) -> u64 {
        let bound = bound.get();
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % bound;
            }
        }
    }

    /// A duration uniformly distributed in `0..span`.
    ///
    /// The shape `docs/reliability.md` §6.1's backoff jitter and ADR-0006's
    /// `uniform(0, T_REGION_SPREAD)` both take.
    fn uniform_duration(&mut self, span: core::time::Duration) -> core::time::Duration {
        let micros = u64::try_from(span.as_micros()).unwrap_or(u64::MAX);
        match NonZeroU64::new(micros) {
            Some(b) => core::time::Duration::from_micros(self.uniform_below(b)),
            None => core::time::Duration::ZERO,
        }
    }
}

/// Derives a per-consumer stream seed.
///
/// # The contract this trait carries
///
/// An implementation **must** compute `HKDF-SHA-256(ikm, info)` exactly — that is
/// CD-4, and `docs/testing-strategy.md` §3.5 depends on it for a seed to still
/// reproduce a scenario a year later. It is a trait rather than a function
/// because CD-I2 forbids this crate the SHA-256 it would need; `twinvpn-crypto`
/// supplies the implementation and TwinLab injects it.
pub trait StreamDerivation: Send + Sync {
    /// Writes `out.len()` derived bytes for `(ikm, info)`.
    ///
    /// # Errors
    ///
    /// [`EnvError::StreamDerivationFailed`] if the derivation cannot produce the
    /// requested length.
    fn derive(&self, ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), EnvError>;
}

/// The source [`crate::Env::rng_for`] delegates to.
pub trait RngSource: Send + Sync {
    /// An independent stream for `consumer`.
    ///
    /// # Errors
    ///
    /// Propagates an entropy or derivation failure. Callers must **not** paper
    /// over one with a fallback stream.
    fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError>;

    /// Whether this source is reproducible from a seed.
    ///
    /// TwinLab asserts this is `true` before declaring a `BIT` scenario; the
    /// production binding answers `false`, so a determinism claim cannot be made
    /// about a production run by mistake.
    fn is_deterministic(&self) -> bool;
}

/// The production binding: every consumer draws directly from the OS CSPRNG.
///
/// `consumer` is accepted and **ignored**, deliberately. Production needs
/// unpredictability, not reproducibility, and deriving production streams from a
/// single seed would make every stream recoverable from that one value.
pub struct SystemRngSource {
    entropy: Arc<dyn Entropy>,
}

impl SystemRngSource {
    /// Binds to a platform entropy source.
    #[must_use]
    pub fn new(entropy: Arc<dyn Entropy>) -> Self {
        Self { entropy }
    }
}

impl RngSource for SystemRngSource {
    fn rng_for(&self, _consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        Ok(Box::new(EntropyRng {
            entropy: Arc::clone(&self.entropy),
        }))
    }

    fn is_deterministic(&self) -> bool {
        false
    }
}

struct EntropyRng {
    entropy: Arc<dyn Entropy>,
}

impl Rng for EntropyRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // `Rng::fill_bytes` has no error channel by design: a call site forced to
        // handle "no randomness today" on every draw grows a fallback, and a
        // fallback CSPRNG is indistinguishable from a working one right up until
        // it matters. A platform CSPRNG that fails mid-stream is unrecoverable,
        // so this panics rather than returning predictable bytes. ADR-0018 F-7
        // contains it at the ABI boundary: the instance is poisoned and reported
        // as INTERNAL.CORE_PANIC, which is the correct visible outcome.
        assert!(
            self.entropy.fill(dst).is_ok(),
            "platform entropy failed mid-stream; the core instance is poisoned (F-7)"
        );
    }
}

/// The deterministic binding TwinLab drives.
///
/// Holds one 128-bit `scenario_seed` and derives each consumer's stream through
/// the injected [`StreamDerivation`], per CD-4. The stream itself is a plain
/// deterministic PRNG — **not** a cryptographic one — because its job is
/// reproducibility, not secrecy, and putting a cipher here would be the CD-I2
/// violation this arrangement exists to avoid.
pub struct SeededRngSource {
    scenario_seed: [u8; 16],
    derivation: Arc<dyn StreamDerivation>,
}

impl SeededRngSource {
    /// Binds a scenario seed to a derivation.
    #[must_use]
    pub fn new(scenario_seed: [u8; 16], derivation: Arc<dyn StreamDerivation>) -> Self {
        Self {
            scenario_seed,
            derivation,
        }
    }

    /// The scenario seed, for a run manifest.
    #[must_use]
    pub const fn scenario_seed(&self) -> [u8; 16] {
        self.scenario_seed
    }
}

impl RngSource for SeededRngSource {
    fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        let info = consumer.info_bytes();
        let mut seed = [0u8; 32];
        self.derivation
            .derive(&self.scenario_seed, &info, &mut seed)?;
        Ok(Box::new(SeededRng::from_seed(seed)))
    }

    fn is_deterministic(&self) -> bool {
        true
    }
}

/// A deterministic, allocation-free PRNG. **Not cryptographic.**
mod alloc_free {
    use super::Rng;

    /// xoshiro256\*\* — a small, well-distributed, deterministic generator.
    ///
    /// # This is not a security primitive
    ///
    /// It is trivially predictable from a few outputs. It exists so that a
    /// TwinLab scenario at a given `scenario_seed` produces the same stream on
    /// every run and on every host. Anything needing unpredictability takes
    /// [`super::SystemRngSource`], which draws from the platform CSPRNG.
    pub struct SeededRng {
        s: [u64; 4],
    }

    impl SeededRng {
        /// Expands a 32-byte derived seed into the generator state.
        ///
        /// A zero state is a fixed point for this generator, so it is replaced
        /// with a fixed non-zero constant rather than silently producing an
        /// all-zero stream.
        pub fn from_seed(seed: [u8; 32]) -> Self {
            let mut s = [0u64; 4];
            for (i, slot) in s.iter_mut().enumerate() {
                let mut b = [0u8; 8];
                b.copy_from_slice(&seed[i * 8..i * 8 + 8]);
                *slot = u64::from_le_bytes(b);
            }
            if s == [0; 4] {
                s = [0x9e37_79b9_7f4a_7c15, 1, 2, 3];
            }
            Self { s }
        }

        fn next(&mut self) -> u64 {
            let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
            let t = self.s[1] << 17;
            self.s[2] ^= self.s[0];
            self.s[3] ^= self.s[1];
            self.s[1] ^= self.s[2];
            self.s[0] ^= self.s[3];
            self.s[2] ^= t;
            self.s[3] = self.s[3].rotate_left(45);
            result
        }
    }

    impl Rng for SeededRng {
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&v[..n]);
            }
        }

        fn next_u64(&mut self) -> u64 {
            self.next()
        }
    }
}
