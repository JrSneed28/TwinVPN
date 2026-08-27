//! Shared fixtures: a virtual-time `Env` and a `Guards` builder.
//!
//! CD-5's falsification test is what these exist for — every test in this crate
//! runs on a plain Linux CI runner with no VM, no device farm, and no network,
//! because the machine takes *declared facts* rather than asking the OS.

use std::sync::Arc;

use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{Env, EnvError, EnvParts, Entropy, Rng, RngSource, ConsumerId, WallClockReading};
use twinvpn_session::{EnforcementMode, Guards};
use twinvpn_types::SessionId;

/// A deterministic counter RNG. Not cryptographic and never used as one: it
/// feeds §6.1's jitter draw, which is the only randomness these tests need.
struct CounterRng(u64);

impl Rng for CounterRng {
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for b in dst.iter_mut() {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

struct TestRngSource;

impl RngSource for TestRngSource {
    fn rng_for(&self, consumer: ConsumerId) -> Result<Box<dyn Rng>, EnvError> {
        // Per-consumer, so adding a consumer does not shift an existing stream —
        // the CD-4 property, reproduced in miniature.
        let seed = consumer
            .as_str()
            .bytes()
            .fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x1000_0000_01b3)
            });
        Ok(Box::new(CounterRng(seed)))
    }

    fn is_deterministic(&self) -> bool {
        true
    }
}

struct TestEntropy;

impl Entropy for TestEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        dst.fill(0x5a);
        Ok(())
    }
}

/// A virtual-time `Env` and the driver that advances it.
#[must_use]
pub fn test_env() -> (Env, Arc<VirtualTime>) {
    let vt = Arc::new(VirtualTime::new(WallClockReading::Unset));
    let env = Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::new(TestEntropy),
        rng: Arc::new(TestRngSource),
    });
    (env, vt)
}

/// A fixed `SessionId`, so a failing assertion names the same session every run.
#[must_use]
pub fn session_id() -> SessionId {
    SessionId::from_array([7u8; 16])
}

/// Guards with everything a healthy establishment needs, and nothing more.
///
/// Deliberately *not* `Guards::default()`: default is the restrictive answer,
/// and a test that wants a successful path has to say so.
#[must_use]
pub fn healthy() -> Guards {
    Guards {
        credentials_valid: true,
        peer_authorized: true,
        usable_candidate: true,
        path_validated: true,
        no_l2_path_won: true,
        no_direct_path_won: true,
        new_path_committed: true,
        retry_budget_available: true,
        enforcement: Some(EnforcementMode::FailClosed),
        relay_set_nonempty: true,
        ..Guards::default()
    }
}
