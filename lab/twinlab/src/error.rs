//! The one error type TwinLab raises, and the distinction that matters most.
//!
//! [`LabError::FacilityUnavailable`] exists so that "this host cannot produce
//! that condition" can never be confused with "the condition did not hold".
//! `docs/testing-strategy.md` §3.1 is a claim about mechanism; a rig that cannot
//! run the mechanism has no claim to make.

/// Why TwinLab could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum LabError {
    /// The host does not provide a facility the requested realization needs.
    ///
    /// **This is not a test failure and it is not a test pass.** It is the
    /// absence of evidence, and [`crate::outcome::Verdict::Unavailable`] carries
    /// it forward so a caller cannot silently treat it as either.
    #[error("this host cannot provide {facility}: {detail}")]
    FacilityUnavailable {
        /// The facility class — `network namespaces`, `nftables`, …
        facility: &'static str,
        /// What specifically was missing.
        detail: String,
    },

    /// A real mechanism was available and refused.
    #[error("mechanism failed: {detail}")]
    Mechanism {
        /// What the mechanism said.
        detail: String,
    },

    /// The lab was asked for something the address plan forbids.
    #[error("address plan violation: {detail}")]
    Addressing {
        /// The rule that was broken.
        detail: String,
    },

    /// A scenario asserted something its determinism class does not permit
    /// (`docs/testing-strategy.md` §3.5 rule L-2).
    #[error("determinism class {class} does not permit assertion `{assertion}`")]
    DeterminismClass {
        /// The declared class.
        class: &'static str,
        /// The assertion that is invalid for it.
        assertion: String,
    },

    /// A derivation or seeding failure from `twinvpn-env`.
    #[error("environment: {0}")]
    Env(#[from] twinvpn_env::EnvError),
}
