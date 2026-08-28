//! §3.5's seeded streams — the binding that closes CD-4.
//!
//! **Authority:** ADR-0018 §11.8 **CD-4**, `docs/testing-strategy.md` §3.5,
//! wave-1 finding **W-1**.
//!
//! # The half of CD-4 that had no owner
//!
//! CD-4 specifies
//! `HKDF-SHA-256(ikm = scenario_seed, info = "twinlab/v1/" || consumer_id)`.
//! CD-I2 permits a cryptographic dependency only in `twinvpn-crypto`, and
//! §11.7's arrow already has crypto depending on env — so `twinvpn-env` declares
//! [`twinvpn_env::StreamDerivation`] and no crypto dependency, `twinvpn-crypto`
//! supplies [`twinvpn_crypto::HkdfSha256`], and **the binding is TwinLab's**.
//! That is finding W-1's "the *binding* supplies the derivation", and this module
//! is that binding.
//!
//! `twinvpn-env` tests the structural half (the `info` string, stream
//! independence). `twinvpn-crypto` tests the primitive against known vectors.
//! Neither can test that the two are actually wired together, because neither
//! constructs the pair. `tests/cd4_hkdf_end_to_end.rs` in this crate does, against
//! a vector computed **outside this workspace entirely**.

use std::sync::Arc;

use twinvpn_crypto::HkdfSha256;
use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{
    ConsumerId, Entropy, Env, EnvError, EnvParts, RngSource, SeededRngSource, StreamDerivation,
    WallClockReading,
};

use crate::error::LabError;

/// A scenario's 128-bit seed (§3.6: "128-bit hex; omitted = generated and
/// recorded").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioSeed([u8; 16]);

impl ScenarioSeed {
    /// A seed from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parses the 32-hex-character form a scenario document carries.
    ///
    /// # Errors
    ///
    /// [`LabError::Mechanism`] when the text is not exactly 32 hex characters.
    /// A seed is the whole reproducibility story, so a partly-parsed one is
    /// refused rather than padded.
    pub fn parse_hex(text: &str) -> Result<Self, LabError> {
        let t = text.trim();
        if t.len() != 32 {
            return Err(LabError::Mechanism {
                detail: format!("a scenario seed is 32 hex characters; got {}", t.len()),
            });
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot =
                u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).map_err(|_| LabError::Mechanism {
                    detail: "a scenario seed is hexadecimal".to_owned(),
                })?;
        }
        Ok(Self(out))
    }

    /// The hex form, for the run record.
    #[must_use]
    pub fn to_hex(self) -> String {
        use core::fmt::Write as _;
        self.0.iter().fold(String::with_capacity(32), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// The CD-4 derivation, bound.
///
/// A free function rather than a type, because there is exactly one correct
/// answer and a configurable one would be a way to get it wrong.
#[must_use]
pub fn cd4_derivation() -> Arc<dyn StreamDerivation> {
    Arc::new(HkdfSha256::new())
}

/// The seeded RNG source a `BIT` scenario runs on.
#[must_use]
pub fn seeded_rng_source(seed: ScenarioSeed) -> Arc<dyn RngSource> {
    Arc::new(SeededRngSource::new(seed.as_bytes(), cd4_derivation()))
}

/// Entropy that refuses to be used.
///
/// A deterministic scenario must never reach the platform CSPRNG: if it did, the
/// run would not be reproducible and nothing would say so. This binding makes
/// that a loud failure rather than a silent loss of determinism.
///
/// It is **not** a weak RNG standing in for a strong one — it produces nothing at
/// all. `twinvpn-env` propagates the error; §3.5's `BIT` claim survives.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefusingEntropy;

impl Entropy for RefusingEntropy {
    fn fill(&self, _dst: &mut [u8]) -> Result<(), EnvError> {
        Err(EnvError::EntropyUnavailable)
    }
}

/// A complete deterministic [`Env`]: virtual clocks plus CD-4 seeded streams.
///
/// This is the `Env` every TwinLab scenario and every system test constructs.
/// CD-2 requires each component to take its `Env` at construction, so there is
/// no global here and no `Default`.
#[derive(Clone)]
pub struct LabEnv {
    env: Env,
    time: Arc<VirtualTime>,
    seed: ScenarioSeed,
}

impl LabEnv {
    /// Builds a deterministic environment for `seed`.
    ///
    /// The wall clock starts [`WallClockReading::Unset`] on purpose: CD-1 makes
    /// wall time evidence only and three-state, and a scenario that needs a
    /// trusted wall clock must say so by calling
    /// [`twinvpn_env::virtual_time::VirtualTime::set_wall`].
    #[must_use]
    pub fn new(seed: ScenarioSeed) -> Self {
        Self::with_wall(seed, WallClockReading::Unset)
    }

    /// As [`LabEnv::new`], with an explicit initial wall reading.
    #[must_use]
    pub fn with_wall(seed: ScenarioSeed, wall: WallClockReading) -> Self {
        let time = Arc::new(VirtualTime::new(wall));
        let env = Env::new(EnvParts {
            monotonic: time.monotonic(),
            elapsed: time.elapsed(),
            wall: time.wall(),
            timer: time.timer(),
            runtime: time.runtime(),
            entropy: Arc::new(RefusingEntropy),
            rng: seeded_rng_source(seed),
        });
        Self { env, time, seed }
    }

    /// The environment to hand to a component at construction.
    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// A clone of the environment, for a component that takes it by value.
    #[must_use]
    pub fn env_owned(&self) -> Env {
        self.env.clone()
    }

    /// The virtual clock driver, for advancing time inside a scenario.
    #[must_use]
    pub fn time(&self) -> &VirtualTime {
        &self.time
    }

    /// The seed, for the run record.
    #[must_use]
    pub const fn seed(&self) -> ScenarioSeed {
        self.seed
    }

    /// A consumer's stream.
    ///
    /// # Errors
    ///
    /// Propagates a derivation failure — never substitutes a fallback stream,
    /// because a fallback would silently break the `BIT` claim.
    pub fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn twinvpn_env::Rng>, LabError> {
        Ok(self.env.rng_for(consumer)?)
    }

    /// Whether this environment can legitimately back a `BIT` scenario.
    ///
    /// §3.5: TwinLab asserts this before declaring `BIT`, so a determinism claim
    /// cannot be made about a production binding by mistake.
    #[must_use]
    pub fn is_deterministic(&self) -> bool {
        self.env.is_deterministic()
    }
}

impl core::fmt::Debug for LabEnv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The seed is not a secret — it is in the run record by design — but the
        // Env deliberately renders nothing, so this follows it.
        f.debug_struct("LabEnv")
            .field("seed", &self.seed.to_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_env::consumers;

    #[test]
    fn a_lab_env_is_deterministic_and_a_production_one_would_not_be() {
        let e = LabEnv::new(ScenarioSeed::from_bytes([7; 16]));
        assert!(e.is_deterministic());
    }

    #[test]
    fn the_same_seed_reproduces_the_same_stream() {
        let seed = ScenarioSeed::from_bytes([0x9f; 16]);
        let mut a = LabEnv::new(seed)
            .rng_for(consumers::BACKOFF_JITTER)
            .unwrap();
        let mut b = LabEnv::new(seed)
            .rng_for(consumers::BACKOFF_JITTER)
            .unwrap();
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn a_different_seed_produces_a_different_stream() {
        // The negative control for the test above: without this, a derivation
        // that ignored the seed entirely would look perfectly reproducible.
        let mut a = LabEnv::new(ScenarioSeed::from_bytes([1; 16]))
            .rng_for(consumers::BACKOFF_JITTER)
            .unwrap();
        let mut b = LabEnv::new(ScenarioSeed::from_bytes([2; 16]))
            .rng_for(consumers::BACKOFF_JITTER)
            .unwrap();
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn a_deterministic_scenario_never_reaches_the_platform_csprng() {
        let e = LabEnv::new(ScenarioSeed::from_bytes([3; 16]));
        let mut buf = [0u8; 4];
        assert!(
            e.env().entropy().fill(&mut buf).is_err(),
            "a BIT scenario that could draw from the OS CSPRNG would not be \
             reproducible, and nothing would say so"
        );
        assert_eq!(buf, [0u8; 4], "the refusing entropy wrote nothing");
    }

    #[test]
    fn a_seed_round_trips_through_its_hex_form() {
        let seed = ScenarioSeed::from_bytes([
            0x9f, 0x1c, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d,
        ]);
        assert_eq!(
            ScenarioSeed::parse_hex(&seed.to_hex()).expect("round trip"),
            seed
        );
    }

    #[test]
    fn a_short_or_non_hex_seed_is_refused_rather_than_padded() {
        assert!(ScenarioSeed::parse_hex("9f1c").is_err());
        assert!(ScenarioSeed::parse_hex(&"z".repeat(32)).is_err());
    }

    #[test]
    fn virtual_time_is_the_clock_and_it_does_not_run_on_its_own() {
        let e = LabEnv::new(ScenarioSeed::from_bytes([5; 16]));
        let t0 = e.env().now_monotonic();
        let t1 = e.env().now_monotonic();
        assert_eq!(t0, t1, "an injected clock must not advance by itself");
        e.time().advance(core::time::Duration::from_millis(250));
        assert_eq!(
            e.env().now_monotonic().duration_since(t0),
            core::time::Duration::from_millis(250)
        );
    }

    #[test]
    fn suspend_advances_the_elapsed_clock_and_not_the_monotonic_one() {
        // CD-1's whole point, and the mechanism behind T35's
        // `rekey_window_exceeded` guard.
        let e = LabEnv::new(ScenarioSeed::from_bytes([6; 16]));
        let m0 = e.env().now_monotonic();
        let el0 = e.env().now_elapsed();
        e.time().suspend(core::time::Duration::from_secs(3600));
        assert_eq!(e.env().now_monotonic(), m0, "monotonic must not move");
        assert_eq!(
            e.env().now_elapsed().duration_since(el0),
            core::time::Duration::from_secs(3600)
        );
    }
}
