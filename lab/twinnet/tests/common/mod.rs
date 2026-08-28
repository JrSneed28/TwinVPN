//! The test-side view of `twinnet::rigs`.
//!
//! The topologies themselves live in the library, so that
//! `twinlab-scenarios run` builds the same experiment a test does. What lives
//! here is the one thing a test needs and a CLI does not: the decision about
//! what to do when the host cannot provide a facility.
//!
//! **A test skips; it never passes.** `sandbox_or_skip` prints the evidence and
//! returns `None`, and every caller returns without asserting. That is the only
//! honest shape — a laboratory that cannot build a namespace must not report
//! that a NAT was traversed — and it is the reason the library exposes
//! `NetError::Unavailable` rather than a `bool`.

#![allow(dead_code)]

pub use twinnet::rigs::*;

use twinnet::sandbox::Sandbox;

/// Unwraps a rig, skipping only for a facility this host genuinely lacks.
///
/// **This exists because the obvious shape is a trap.** Every test in this
/// suite used to open with
///
/// ```ignore
/// let Ok(mut rig) = common::build_two_site("label") else { return };
/// ```
///
/// which returns silently for *any* error — including a rig that is broken. It
/// happened: a change made the two-site rig fail to install a route, and the
/// class-pair matrix went from asserting 24 cells to asserting none, in 5
/// seconds instead of 48, and reported `ok`. The suite had a hole in it and said
/// nothing.
///
/// So the two cases are separated here and only one of them is quiet:
///
/// | Error | What happens |
/// |---|---|
/// | [`NetError::Unavailable`] — the host cannot | the reason is printed and the test skips |
/// | anything else | **panic.** A rig that fails to build for a reason that is not host capability is a defect in the rig, and a defect that returns `None` is a suite that goes quiet |
pub fn or_skip(label: &str, built: Result<Rig, twinnet::NetError>) -> Option<Rig> {
    match built {
        Ok(rig) => Some(rig),
        Err(e) if e.is_unavailable() => {
            eprintln!("SKIP {label}: {e}");
            None
        }
        Err(e) => panic!(
            "the `{label}` rig failed to build, and not for a reason this host is \
             responsible for: {e}"
        ),
    }
}

/// Starts a sandbox, or prints why this host cannot and returns `None`.
pub fn sandbox_or_skip(what: &str) -> Option<Sandbox> {
    match twinnet::rigs::sandbox() {
        Ok(sb) => Some(sb),
        Err(e) if e.is_unavailable() => {
            eprintln!("SKIP {what}: {e}");
            None
        }
        Err(e) => panic!("the sandbox failed for a reason that is not host capability: {e}"),
    }
}

/// The single-site rig, named as the tests have always called it.
pub fn build(label: &str, second_client: bool) -> Result<Rig, twinnet::NetError> {
    twinnet::rigs::build_single_site(label, second_client)
}

/// The single-site middlebox configuration.
pub fn nat_config(rig: &Rig, p: &Personality) -> twinnet::nat::config::NatConfig {
    twinnet::rigs::single_site_nat(rig, p)
}
