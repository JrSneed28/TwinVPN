//! The `POLICY.*` codes this crate emits — and the seventeen ADR-0012 registers
//! that the frozen registry does not carry.
//!
//! **Authority:** ADR-0012 §11.9's code table, ADR-0015 §11.2,
//! `contracts/registry/reason_codes.json` (frozen), `ownership.md` §6 rule 12.
//!
//! # The finding
//!
//! ADR-0012 §11.9 contributes **twenty-one** `POLICY.*` codes. The frozen
//! registry carries **four** of them: `POLICY.KILLSWITCH.ENGAGED`,
//! `POLICY.KILLSWITCH.ARM_FAILED`, `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` and
//! `POLICY.LEAK.IPV6_UNPROTECTED`. The other seventeen are listed in
//! [`UNREGISTERED`], each with the registered code this build emits instead.
//!
//! Two of them are the ones that hurt: `POLICY.LEAK.EGRESS_OBSERVED` is the leak
//! canary's own verdict, and `POLICY.KILLSWITCH.TRAFFIC_RESTORED` is
//! `docs/reliability.md` T30's emit action. Neither can be spelled by a
//! `twinvpn_types::ReasonCode`, so both are substituted and both are reported.
//!
//! The registry also **classifies two of the four differently** from ADR-0012
//! §11.9: `POLICY.KILLSWITCH.ENGAGED` is `POLICY`/`WARN` in the registry and
//! `POLICY`/`ERROR` in the ADR; `POLICY.KILLSWITCH.ARM_FAILED` is
//! `FATAL`/`CRITICAL` in the registry and `PERSISTENT`/`CRITICAL` in the ADR.

use twinvpn_types::{codes as reg, Component, Diagnostic, EvidenceValue, ReasonCode};

/// One code ADR-0012 §11.9 registers that the frozen registry does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// The spelling ADR-0012 §11.9 uses.
    pub specified: &'static str,
    /// The registered code this build emits instead.
    pub emitted: ReasonCode,
}

/// The seventeen. A test asserts each `specified` spelling is genuinely absent,
/// so registering one fails the build and points at the line to delete.
pub const UNREGISTERED: &[Substitution] = &[];

// EMPTY as of `registry_version` 2. Every spelling ADR-0012 §11.9 uses is now
// carried by the frozen registry, so this build emits each code by its own name
// and no longer reports one condition under another's identifier. The table and
// its test are kept rather than deleted: the test asserts the table is empty,
// so a future ADR code that outruns the registry again lands here visibly
// instead of becoming a silent substitution.

/// `POLICY.KILLSWITCH.ENGAGED` — protected traffic is blocked because no
/// authorized secure path exists. Registered.
#[must_use]
pub const fn killswitch_engaged() -> ReasonCode {
    reg::POLICY_KILLSWITCH_ENGAGED
}

/// `POLICY.KILLSWITCH.ARM_FAILED` — the rule set could not be installed, and the
/// client refuses to enter a protected state. Registered.
#[must_use]
pub const fn ruleset_absent() -> ReasonCode {
    reg::POLICY_KILLSWITCH_ARM_FAILED
}

/// `POLICY.KILLSWITCH.ASSERTION_MISMATCH` — installed rules differ from intended
/// policy (O-17). Registered in `registry_version` 2.
#[must_use]
pub const fn assertion_mismatch() -> ReasonCode {
    reg::POLICY_KILLSWITCH_ASSERTION_MISMATCH
}

/// `POLICY.LEAK.EGRESS_OBSERVED` — the canary observed protected traffic on a
/// non-overlay interface. Registered in `registry_version` 2.
#[must_use]
pub const fn egress_observed() -> ReasonCode {
    reg::POLICY_LEAK_EGRESS_OBSERVED
}

/// `POLICY.LEAK.IPV6_UNPROTECTED` — the tunnel or exit grant is v4-only.
/// Registered.
#[must_use]
pub const fn ipv6_unprotected() -> ReasonCode {
    reg::POLICY_LEAK_IPV6_UNPROTECTED
}

/// `POLICY.KILLSWITCH.UNPROTECTED_FALLBACK` — enforcement is disabled and
/// traffic is flowing untunneled, persistently announced. Registered.
#[must_use]
pub const fn unprotected_fallback() -> ReasonCode {
    reg::POLICY_KILLSWITCH_UNPROTECTED_FALLBACK
}

/// `INTERNAL.INVARIANT_VIOLATED` — used where a canary probe is itself invalid.
#[must_use]
pub const fn invariant_violated() -> ReasonCode {
    reg::INTERNAL_INVARIANT_VIOLATED
}

/// A `KILL_SWITCH`-observed diagnostic, with the family named as evidence.
///
/// Address family is an **evidence field**, never a namespace
/// (`ownership.md` §4.2): "a per-family namespace makes 'we have a v4 story and
/// a v6 story' sayable — the exact asymmetry ADR-0010 R1 exists to forbid."
#[must_use]
pub fn diagnostic(code: ReasonCode, family: Option<twinvpn_types::AddressFamily>) -> Diagnostic {
    let mut b = Diagnostic::builder(code, Component::KillSwitch);
    if let Some(f) = family {
        b = b.evidence("family", EvidenceValue::Family(f));
    }
    b.build()
}
