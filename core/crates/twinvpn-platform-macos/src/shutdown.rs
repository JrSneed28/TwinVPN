//! The adapter's shutdown latch.
//!
//! **Authority:** [`twinvpn_platform::PlatformAdapter::begin_shutdown`],
//! ADR-0018 CB-6, `docs/implementation/ownership.md` §6 rule 7.
//!
//! After [`ShutdownLatch::begin`], every adapter call returns
//! [`PlatformError::ShuttingDown`] "rather than hanging or silently succeeding" —
//! the two failure modes a shutdown flag exists to prevent, because a hang looks
//! like work in progress and a silent success looks like the work was done.
//!
//! It does **not** tear down enforcement:
//!
//! > CB-6 puts the installed ruleset in the OS's custody precisely so that the
//! > core going away does not drop protection, and a shutdown that removed the
//! > rules would defeat that.
//!
//! Nothing in this module touches the `pf` anchor, the routes or the resolver,
//! and `lib.rs`'s `begin_shutdown_latches_and_leaves_the_anchor_alone` asserts it
//! against a recording enforcement engine rather than against this comment.

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
        // Nothing about the platform went wrong, so the registered code is
        // INTERNAL rather than PLATFORM, and there is no errno to carry.
        let latch = ShutdownLatch::new();
        latch.begin();
        let err = latch.check().expect_err("set");
        assert_eq!(err.reason_code().as_str(), "INTERNAL.UNEXPECTED_STATE");
        assert_eq!(err.os_detail(), None);
    }
}
