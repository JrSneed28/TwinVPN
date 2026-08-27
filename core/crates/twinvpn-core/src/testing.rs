//! **CD-5.** Everything needed to exercise the composed core on a plain Linux CI
//! runner, with no VM, no device farm, and every shell deleted.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-2 (the falsification test) and §11.8 CD-5; `core/README.md` §5.
//!
//! > **CB-2.** The falsification test: with every shell deleted and a mock
//! > adapter bound, the core must still make every decision correctly. If it
//! > cannot, a decision leaked into a shell.
//!
//! This module is what makes that runnable. It is compiled only under
//! `test-support` (or `cfg(test)`) and is **never shipped** — the mock adapter
//! and the virtual clock are both behind features `core/README.md` §3 records as
//! never shipping.

use std::sync::Arc;

use twinvpn_env::virtual_time::VirtualTime;
use twinvpn_env::{Entropy, Env, EnvError, EnvParts, SystemRngSource, WallClockReading};
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_types::Diagnostic;

use crate::core::{Core, CoreParts};

/// The ABI major this test harness pretends the shell was compiled against.
pub const ABI_MAJOR: u32 = crate::ABI_MAJOR;

/// The ABI minor.
pub const ABI_MINOR: u32 = crate::ABI_MINOR;

/// A counting entropy source.
///
/// Deterministic and **obviously** so: a test that needs unpredictability must
/// say so rather than inherit it, and a source that looks random but is not is
/// worse than one that plainly counts.
#[derive(Debug, Default)]
pub struct CountingEntropy(std::sync::Mutex<u64>);

impl Entropy for CountingEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        let mut n = self.0.lock().map_err(|_| EnvError::EntropyUnavailable)?;
        for b in dst.iter_mut() {
            *n = n.wrapping_add(1);
            *b = u8::try_from(*n & 0xff).unwrap_or(0);
        }
        Ok(())
    }
}

/// An `Env` over virtual time, plus the driver that advances it.
///
/// `core/README.md` §5: *"`runtime.block_on(..)` advances virtual time to the
/// next deadline whenever the future stalls, so an eight-hour scenario costs no
/// wall time at all."*
#[must_use]
pub fn env() -> (Env, VirtualTime) {
    let vt = VirtualTime::new(WallClockReading::Unset);
    let entropy: Arc<dyn Entropy> = Arc::new(CountingEntropy::default());
    let env = Env::new(EnvParts {
        monotonic: vt.monotonic(),
        elapsed: vt.elapsed(),
        wall: vt.wall(),
        timer: vt.timer(),
        runtime: vt.runtime(),
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    (env, vt)
}

/// The parts for a mock-bound core.
#[must_use]
pub fn parts() -> (CoreParts, Arc<MockAdapter>, VirtualTime) {
    let (env, vt) = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let parts = CoreParts {
        env,
        adapter: Arc::clone(&adapter) as Arc<dyn twinvpn_platform::PlatformAdapter>,
        abi_major_expected: ABI_MAJOR,
        abi_major: ABI_MAJOR,
        abi_minor: ABI_MINOR,
        schema_digest: vec![0xcd; 32],
        crypto_provider: "twinvpn-crypto/test".to_owned(),
        sek_custody: "core-held:test".to_owned(),
        // The mock reports no secure element, and the core records that rather
        // than assuming otherwise (§11.16 (l)).
        hardware_backed: false,
        ledger_capacity: twinvpn_diag::ring::DEFAULT_CAPACITY,
        event_capacity: crate::events::DEFAULT_CAPACITY,
    };
    (parts, adapter, vt)
}

/// A mock-bound core.
///
/// # Errors
///
/// The [`Diagnostic`] `Core::create` returns.
pub fn core() -> Result<Core, Box<Diagnostic>> {
    Core::create(parts().0)
}

/// A mock-bound core plus the adapter, so a test can assert what the core did to
/// the platform — which is the only way to check that it did **nothing** in the
/// cases where doing nothing is the requirement (F-7, CB-6).
///
/// # Errors
///
/// The [`Diagnostic`] `Core::create` returns.
pub fn core_and_adapter() -> Result<(Core, Arc<MockAdapter>), Box<Diagnostic>> {
    let (parts, adapter, _vt) = parts();
    Ok((Core::create(parts)?, adapter))
}

/// A mock-bound core, with the parts adjusted first.
///
/// # Errors
///
/// The [`Diagnostic`] `Core::create` returns.
pub fn core_with(adjust: impl FnOnce(&mut CoreParts)) -> Result<Core, Box<Diagnostic>> {
    let (mut parts, _adapter, _vt) = parts();
    adjust(&mut parts);
    Core::create(parts)
}
