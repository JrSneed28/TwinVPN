//! The one-way shutdown latch.
//!
//! **Authority:** ADR-0018 CB-6; [`twinvpn_platform::PlatformAdapter::begin_shutdown`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use twinvpn_platform::PlatformError;

/// A one-way flag every capability in this crate consults before doing work.
///
/// # What it deliberately does not do
///
/// Setting it touches **nothing** — not the tunnel settings, not the on-demand
/// rules, not `includeAllNetworks`. CB-6 puts the installed enforcement in the
/// OS's custody "precisely so that the core going away does not drop
/// protection", and a shutdown that tore it down would defeat exactly that. On
/// iOS the point is sharper than elsewhere: ADR-0012's durability table already
/// gives this platform only `◐` across a provider kill, and a teardown on the
/// way out would turn that into `✘`.
#[derive(Debug, Clone, Default)]
pub struct ShutdownLatch {
    flag: Arc<AtomicBool>,
}

impl ShutdownLatch {
    /// A latch that has not been set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the latch. Idempotent, and callable from any thread.
    pub fn begin(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether shutdown has begun.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// `Err(ShuttingDown)` once the latch is set.
    ///
    /// Every fallible entry point in this crate starts with this, so a caller
    /// gets a named refusal rather than a hang or a silent success — which is
    /// the seam's stated contract for the post-shutdown window.
    pub fn guard(&self) -> Result<(), PlatformError> {
        if self.is_shutting_down() {
            return Err(PlatformError::ShuttingDown);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latch_is_one_way_and_idempotent() {
        let latch = ShutdownLatch::new();
        assert!(latch.guard().is_ok());
        latch.begin();
        latch.begin();
        assert!(latch.is_shutting_down());
        assert_eq!(latch.guard(), Err(PlatformError::ShuttingDown));
    }

    #[test]
    fn a_clone_shares_the_flag_so_every_capability_sees_one_shutdown() {
        let latch = ShutdownLatch::new();
        let clone = latch.clone();
        latch.begin();
        assert!(clone.is_shutting_down());
    }

    #[test]
    fn shutting_down_is_an_internal_state_and_not_a_platform_fault() {
        // The core asked for it; nothing about the platform went wrong.
        assert_eq!(
            PlatformError::ShuttingDown.reason_code().as_str(),
            "INTERNAL.UNEXPECTED_STATE"
        );
    }
}
