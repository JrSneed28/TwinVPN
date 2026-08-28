//! The adapter's shutdown latch.
//!
//! **Authority:** [`twinvpn_platform::PlatformAdapter::begin_shutdown`],
//! ADR-0018 CB-6, `docs/implementation/ownership.md` §6 rule 7.
//!
//! After [`ShutdownLatch::begin`], every adapter call returns
//! [`PlatformError::ShuttingDown`] "rather than hanging or silently succeeding"
//! — the two failure modes a shutdown flag exists to prevent, because a hang
//! looks like work in progress and a silent success looks like the work was
//! done.
//!
//! It does **not** tear down enforcement. On Android that has a sharper edge
//! than elsewhere: the route claim dies with the process anyway (see
//! [`crate::posture`]), so the *only* thing shutdown could usefully do to
//! enforcement is drop it early, and CB-6 is precisely the rule that says not to.
//! Nothing in this module touches the claim, the disposition, or the descriptor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use twinvpn_platform::PlatformError;

/// A one-way latch shared by every capability of one adapter.
#[derive(Debug, Clone, Default)]
pub struct ShutdownLatch {
    flag: Arc<AtomicBool>,
}

impl ShutdownLatch {
    /// A latch that is not yet set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Sets the latch. Idempotent, and callable from any thread.
    pub fn begin(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Whether shutdown has begun.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// The guard every fallible adapter call starts with.
    ///
    /// # Errors
    ///
    /// [`PlatformError::ShuttingDown`] once the latch is set.
    pub fn check(&self) -> Result<(), PlatformError> {
        if self.is_shutting_down() {
            Err(PlatformError::ShuttingDown)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latch_is_one_way_shared_and_idempotent() {
        let a = ShutdownLatch::new();
        let b = a.clone();
        assert!(a.check().is_ok());
        b.begin();
        b.begin();
        assert!(matches!(
            a.check().expect_err("set"),
            PlatformError::ShuttingDown
        ));
    }

    #[test]
    fn shutting_down_is_reported_as_a_state_the_core_asked_for_not_a_platform_fault() {
        let latch = ShutdownLatch::new();
        latch.begin();
        let err = latch.check().expect_err("set");
        assert_eq!(err.reason_code().as_str(), "INTERNAL.UNEXPECTED_STATE");
        assert_eq!(err.os_detail(), None, "there is no errno to carry");
    }
}
