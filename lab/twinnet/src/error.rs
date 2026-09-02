//! One error type, and the distinction that matters most in a laboratory.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1.
//!
//! [`NetError::Unavailable`] exists so that "this host cannot produce the
//! condition" can never be spelled the same way as "the condition did not
//! hold". `twinlab::outcome::Verdict` has four values for the same reason, and
//! the mapping between the two is deliberately total: every `Unavailable` here
//! becomes a `Verdict::Unavailable` there, and nothing else does.

/// Why a fabric operation did not produce a usable result.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// This host cannot realize the facility at all.
    ///
    /// **Never a pass.** The caller must convert this into a non-passing
    /// verdict; there is no code path in this crate that turns it into one.
    #[error("this host cannot provide `{facility}`: {detail}")]
    Unavailable {
        /// The facility.
        facility: &'static str,
        /// What was actually observed when it was probed.
        detail: String,
    },

    /// A real mechanism ran and failed.
    #[error("`{program} {argv}` failed with status {status:?}: {stderr}")]
    Mechanism {
        /// The program.
        program: String,
        /// Its arguments, joined.
        argv: String,
        /// Its exit code, or `None` if it was signalled.
        status: Option<i32>,
        /// Its standard error, trimmed.
        stderr: String,
    },

    /// The topology or scenario was described incorrectly. A bug in the test,
    /// never a property of the system under test.
    #[error("malformed fabric: {0}")]
    Malformed(String),

    /// The sandbox agent could not be reached or spoke something unexpected.
    #[error("sandbox agent: {0}")]
    Agent(String),

    /// An operating-system call failed.
    #[error("{context}: {source}")]
    Os {
        /// What was being attempted.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

impl NetError {
    /// An OS error with context, so a bare `errno` never reaches a report.
    pub fn os(context: impl Into<String>, source: std::io::Error) -> Self {
        NetError::Os {
            context: context.into(),
            source,
        }
    }

    /// Whether this is the "cannot produce the condition" case.
    ///
    /// Callers use this to choose `Verdict::Unavailable`. It is a method rather
    /// than a `matches!` at each call site so that adding a second unavailable
    /// shape cannot silently be treated as a failure at eleven call sites.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, NetError::Unavailable { .. })
    }
}

/// The exit code a `twinnet` process uses for [`NetError::Unavailable`].
///
/// A named constant rather than a `3` in two files, because the two ends read
/// it in opposite directions: the binary's `main` writes it, and [`crate::Sandbox`]
/// reads it back off an agent that died before it could say anything. If those
/// two ever disagreed, "this host cannot" would arrive as "this rig is broken"
/// and panic a suite that should have skipped.
pub const UNAVAILABLE_EXIT_CODE: u8 = 3;

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, NetError>;
