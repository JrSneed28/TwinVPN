//! `twinvpnd` — the minimal privileged macOS `LaunchDaemon`, and the MI contract
//! both binaries share.
//!
//! **Authority:** `docs/application-architecture.md` §7's macOS row (HC-1, "NE
//! **system extension** + minimal `LaunchDaemon`", "pf anchor from
//! `/etc/pf.conf`, daemon-applied", "Unix socket / XPC"); ADR-0016 (the privilege
//! split, §11.6's start sequence, PS-1…PS-24); ADR-0017 (the local MI);
//! ADR-0018 §11.1 and §11.12 (CB-1, CB-2, the layout).
//!
//! # CB-2: this crate holds no decision
//!
//! A shell may translate, marshal, schedule and render. There is no branch in
//! this crate whose condition is a `ConnectionState`, a `reason_code` **class**,
//! a policy verdict, a candidate priority, a timer expiry or a version
//! comparison. Where something that *looks* like one was unavoidable — the MI
//! exit-code mapping, which switches on a diagnostic's **domain** — it is
//! rendering an answer the agent already computed, and it is called out where it
//! appears.
//!
//! # Why this is a library as well as a binary
//!
//! ADR-0017 MI-20 and ADR-0018 §11.16 (b): *"one contract, two carriages, **never
//! two contracts**"*. The MI envelope, its framing and its client are declared
//! once, in [`mi`], and `twinvpnctl` depends on this crate with
//! `default-features = false` — which excludes the whole `agent` feature, so the
//! unprivileged CLI links no pf, no route programme and no core-hosting code.
//!
//! # A statement about what has and has not been built
//!
//! **Nothing in this crate has ever been linked or run on macOS.**
//! `make cross-check` type-checks it for `aarch64-apple-darwin` with
//! `-D warnings`; `cargo test` on the Linux CI host runs the target-free half,
//! which is all of [`mi`] and the whole of [`agent::start`]'s sequence logic.
//! Everything that touches a live `pf`, a live `configd` or a live `launchd` is
//! written and unexercised, and `shells/macos/README.md` §7 lists it.

// **`deny`, not `forbid`, and the difference is one function.**
//
// `shells/linux` forbids `unsafe` outright and pays for it: `getgrouplist(3)`
// needs it, so that shell reads `/etc/group` instead and records as a gap that an
// LDAP or `nss-systemd` membership is invisible to it. That trade is available
// there because the group list is a REFINEMENT of the principal.
//
// It is not available here. ADR-0017 **MI-A1** requires the calling principal to
// be obtained from the kernel on the connected channel, and on Darwin the only
// source is `getsockopt(LOCAL_PEERCRED)`, for which neither `std` nor any
// dependency this shell has offers a safe wrapper. MI-A5 makes the alternative a
// closed connection, i.e. no MI at all.
//
// So `unsafe` is denied everywhere and allowed at exactly one call site, in
// `agent::peer::PeerCredentials::read`, with a `// SAFETY:` comment naming its
// invariant. `mi::tests::the_crate_has_exactly_one_unsafe_block` asserts the
// count, so a second one fails the build rather than a review.
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod mi;

#[cfg(feature = "agent")]
pub mod agent;

/// This build's own version string, for `HelloAck.agent_version`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The build profile. ADR-0017 §11.7: "**Build profile is not version.**"
///
/// A separate field because a debug build and a release build of the same version
/// behave differently under load and a support case needs to know which it has —
/// and because conflating the two is how "it works on my machine" becomes
/// unanswerable.
#[must_use]
pub const fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// The platform name MI-C3 carries.
///
/// A constant rather than a `cfg`, because this crate is only ever built for
/// macOS and a `cfg` here would be portability theatre.
pub const PLATFORM: &str = "macos";

#[cfg(test)]
mod tests {
    /// The `unsafe` budget, asserted rather than reviewed.
    ///
    /// `#![deny(unsafe_code)]` plus **exactly one** `#[allow]`, at
    /// `agent::peer::PeerCredentials::read`, because MI-A1 requires a
    /// kernel-sourced principal and `LOCAL_PEERCRED` is the only source on
    /// Darwin. A second one is a build failure here rather than a review finding.
    #[test]
    fn the_crate_allows_unsafe_in_exactly_one_place() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("mi/mod.rs"),
            include_str!("mi/wire.rs"),
            include_str!("mi/codec.rs"),
            include_str!("mi/scope.rs"),
            include_str!("mi/client.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/mod.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/start.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/peer.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/endpoint.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/logging.rs"),
            #[cfg(feature = "agent")]
            include_str!("agent/server.rs"),
        ];
        let allows: usize = sources
            .iter()
            .map(|source| {
                source
                    .lines()
                    .filter(|line| line.trim_start().starts_with("#[allow(unsafe_code)]"))
                    .count()
            })
            .sum();
        let expected = usize::from(cfg!(feature = "agent"));
        assert_eq!(
            allows, expected,
            "the unsafe budget is one allow with the agent feature on, and none \
             without it"
        );
    }
}
