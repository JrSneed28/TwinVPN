//! Test scaffolding: a deterministic `Env` and a blocking driver.
//!
//! Behind `test-support`, which is never enabled in a shipped build — the same
//! discipline `twinvpn-env`'s own `test-support` feature carries.
//!
//! The entropy source here is a counter, **not** the platform CSPRNG: ADR-0018
//! CD-3 bans reaching for one outside `twinvpn-env`'s binding, and a test that
//! did would be both a lint violation and a source of flakiness.

// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle.
#![allow(clippy::missing_panics_doc)]
// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle.
#![allow(clippy::missing_panics_doc)]
// Test scaffolding panics on a defect in its own fixtures rather than
// returning a `Result` nobody would handle.
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use twinvpn_crypto::aead::{StoreKey, STORE_ID_LEN};
use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};

/// A fixed `store_id` for tests that do not open a real store.
pub const STORE_ID: [u8; STORE_ID_LEN] = [0x1d; STORE_ID_LEN];

/// A deterministic, **non-cryptographic** entropy source.
pub struct CountingEntropy(std::sync::Mutex<u64>);

impl CountingEntropy {
    /// Seeds the counter.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(std::sync::Mutex::new(seed))
    }
}

impl Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut s = self.0.lock().expect("test mutex");
        for b in dst.iter_mut() {
            *s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = u8::try_from((*s >> 33) & 0xff).unwrap_or(0);
        }
        Ok(())
    }
}

/// An `Env` on the virtual clock with a counting entropy source.
#[must_use]
pub fn test_env() -> Env {
    test_env_seeded(11)
}

/// An `Env` with a chosen entropy seed.
#[must_use]
pub fn test_env_seeded(seed: u64) -> Env {
    let vt = twinvpn_env::virtual_time::VirtualTime::new(WallClockReading::Unset);
    let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy::new(seed));
    Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    })
}

/// A fixed `StoreKey` for record-level tests.
#[must_use]
pub fn store_key() -> StoreKey {
    let mut raw = [0x5eu8; 32];
    let sek = StoreKey::adopt_sek(&mut raw).expect("sek");
    sek.derive_namespace_key(&STORE_ID, "peer/")
        .expect("namespace key")
}

/// Drives a future to completion on the injected runtime and returns its value.
///
/// `Runtime::block_on` returns `()`, so the value is captured through a cell.
/// This is test scaffolding; the FFI boundary and the daemon's `main` are the
/// only production callers of `block_on` (ADR-0018 §11.8).
pub fn block_on<T: Send + 'static>(
    env: &Env,
    fut: impl core::future::Future<Output = T> + Send + 'static,
) -> T {
    let slot: Arc<std::sync::Mutex<Option<T>>> = Arc::new(std::sync::Mutex::new(None));
    let sink = Arc::clone(&slot);
    env.runtime().block_on(Box::pin(async move {
        let v = fut.await;
        *sink.lock().expect("test mutex") = Some(v);
    }));
    let mut g = slot.lock().expect("test mutex");
    g.take().expect("the future completed")
}
