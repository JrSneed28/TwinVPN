//! `twinvpnd` — the privileged Linux agent, and the management interface both
//! Linux binaries speak.
//!
//! **Authority:** [ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! (the privilege split, PS-1 … PS-24),
//! [ADR-0017](../../../docs/adr/ADR-0017-local-management-interface.md) (the MI),
//! [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-1, CB-2, §11.12; [ADR-0023](../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! (this host is ADR-0016 class **HC-3**, headless, per EM-1).
//!
//! **Owner:** `desktop-linux`.
//!
//! # Why this crate is a library as well as a binary
//!
//! ADR-0017 MI-20 and ADR-0018 §11.16 (b) require "one contract, two carriages,
//! **never two contracts**". [`mi`] is that one contract's carriage, declared
//! once and consumed by `twinvpnctl` with `default-features = false` — so the
//! unprivileged CLI links the envelope, the framing and the client, and **none**
//! of the tun, nftables, netlink or core-hosting code behind the `agent`
//! feature. A copy of the framing in each binary would be the second contract
//! those rules forbid.
//!
//! # CB-2: this crate holds no decision
//!
//! > A shell may translate, marshal, schedule and render. It must not contain a
//! > branch whose condition is a TwinVPN domain fact.
//!
//! There is no branch here on a `ConnectionState`, a `reason_code` class, a
//! policy verdict, a candidate priority, a timer expiry or a version comparison.
//! Three places came close, and each is resolved by asking the core rather than
//! answering locally — they are named in [`agent::server`]'s documentation so a
//! reviewer can check the resolution rather than take it on trust.
//!
//! The one authorization check the agent does make is **not** a domain decision:
//! ADR-0016 PS-12a assigns the daemon the job of resolving an OS principal to a
//! class, and *which* scope an operation needs comes from
//! [`twinvpn_mgmt::catalogue::entry`] — the core's own table. The shell compares
//! a core-supplied requirement against an OS-supplied fact. It invents neither.
//!
//! # Environment configuration, local startup and debugging
//!
//! `shells/linux/README.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod mi;

#[cfg(feature = "agent")]
pub mod agent;

/// This build's version, for `HelloAck.agent_version` and `version.get`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The build profile this binary was compiled as (ADR-0023 EM-1).
///
/// §11.7: "**Build profile is not version.**" A router agent built with a
/// reduced feature profile answers the same `mi_version` and offers a different
/// catalogue, so a client that branched on version alone would be wrong.
pub const BUILD_PROFILE: &str = "H-SRV";

#[cfg(test)]
mod tests {
    #[test]
    fn the_agent_version_is_the_packages_own() {
        // `HelloAck.agent_version` and `version.get` both carry it, and
        // ADR-0017 §11.7's "Reject{MGMT.VERSION_TOO_OLD} carrying
        // `agent_version`" needs it to be a real value.
        assert_eq!(super::AGENT_VERSION, env!("CARGO_PKG_VERSION"));
        assert!(super::AGENT_VERSION.contains('.'));
    }

    #[test]
    fn the_build_profile_is_one_of_adr_0023s_four() {
        assert!(matches!(
            super::BUILD_PROFILE,
            "H-SRV" | "H-EMB" | "H-CTR" | "H-CLI"
        ));
    }
}
