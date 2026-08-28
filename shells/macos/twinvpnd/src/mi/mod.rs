//! The local management interface: the envelope, the framing, and the client.
//!
//! **Authority:** ADR-0017 §10.1 (the endpoint's location), §11.2 (the
//! transport), §11.3 (the envelope), MI-20, MI-A1…MI-A5; ADR-0016 §11.14 (a).
//!
//! Compiled into **both** binaries, which is MI-20's "one contract, two
//! carriages" as a crate layout: `twinvpnd` serves it and `twinvpnctl` speaks it,
//! from one definition.
//!
//! # A reported duplication, not a second contract
//!
//! `shells/linux/twinvpnd/src/mi/` declares the same envelope, and it declares it
//! because ADR-0017 §11.3's message **appears nowhere in `contracts/`** —
//! `contracts/docs/phase1-conflicts.md` OQ-2 deliberately excluded an MI
//! transport schema from Phase 2 so the MI could not acquire an independent
//! vocabulary. The exclusion worked (the *vocabulary* here is the core's, from
//! `twinvpn_mgmt`), but it left the **carriage** unspecified, and the consequence
//! is that each shell now declares it.
//!
//! Two shells with two copies of one envelope is exactly the drift MI-20 exists
//! to prevent, one level up from where MI-20 is written. This module's field
//! names are ADR-0017 §11.3's, verbatim, so a later `mgmt.proto` — or a move of
//! this module into `twinvpn-mgmt`, which is where it belongs — is a re-encoding
//! rather than a redesign. **Reported to the integration lead as a request, not
//! resolved here:** `core/crates/twinvpn-mgmt` is `core-foundation`'s.

pub mod client;
pub mod codec;
pub mod scope;
pub mod wire;

pub use client::{Client, ClientError};
pub use scope::{Scopes, CLI_REQUESTED_SCOPES};
pub use wire::{
    Body, Compacted, Diagnostic, Event, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Request,
    Response, MAX_ENVELOPE_BYTES, MI_VERSION, MI_VERSION_MIN,
};

/// The endpoint. ADR-0017 §10.1, documented "because scripts and
/// configuration-management tooling will hard-code them".
///
/// > Relocation is an `mi_version` event, not a patch-level change.
///
/// `/var/run` and not Linux's `/run`: on macOS `/var/run` is the real directory
/// and `/run` does not exist.
pub const SOCKET_PATH: &str = "/var/run/twinvpn/mgmt.sock";

/// The directory the endpoint lives in.
///
/// **MI-A3**, and the one place macOS is weaker than Linux here. `systemd` has
/// `RuntimeDirectory=`, which recreates the directory with the right owner and
/// mode on **every** start; `launchd` has no equivalent. So the directory is the
/// **installer's**, created once, and `twinvpnd` **verifies and refuses** rather
/// than creating it — because an agent that created its own endpoint directory
/// could be raced by whatever created it first after a `/var/run` wipe.
///
/// That is a real weakening and it is stated in `shells/macos/README.md` §7
/// rather than hidden behind a `create_dir_all`.
pub const SOCKET_DIR: &str = "/var/run/twinvpn";

/// The endpoint's mode.
///
/// No world bit, in either direction. ADR-0016 PS-12a: the OBSERVE principal is a
/// dedicated group, "never a built-in everyone-group".
pub const SOCKET_MODE: u32 = 0o660;

/// The group that owns the endpoint.
pub const SOCKET_GROUP: &str = "twinvpn";

/// The XPC Mach service ADR-0017 §11.2 **prefers** on this platform.
///
/// Not served in this wave. Declared here so the name is fixed in one place, and
/// named as a gap in the README: a `MachServices` key in the `LaunchDaemon` plist
/// with no server behind it reproduces exactly the hang MI-A3 rejects socket
/// activation for, so the plist deliberately does not declare it either.
pub const XPC_SERVICE_NAME: &str = "com.twinvpn.agent.mgmt";

/// The environment variable that overrides [`SOCKET_PATH`].
///
/// Present for **local development and the component tests**, where a system-wide
/// `/var/run/twinvpn` is not available and running the agent as root to get one
/// would be a worse habit than a variable. ADR-0023 EM-19 makes changing the
/// management-socket path a restart-requiring setting, which is exactly what an
/// environment variable read once at start is.
///
/// It is **not** a security control and is not treated as one: the endpoint's
/// safety comes from the peer credential and the directory's ownership (MI-A3),
/// both of which are checked wherever the path points.
pub const SOCKET_PATH_ENV: &str = "TWINVPN_MGMT_SOCKET";

/// The endpoint this process should use.
///
/// Reads [`SOCKET_PATH_ENV`] once. Every variable has a default and the default
/// is the production value.
#[must_use]
pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os(SOCKET_PATH_ENV)
        .map_or_else(|| std::path::PathBuf::from(SOCKET_PATH), Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_a_filesystem_path_and_never_a_network_address() {
        // ADR-0017 §11.2 rejects loopback TCP ("no peer credentials … reachable
        // by every local user, by containers and WSL"). The rejection is
        // structural here: the constant is a path, and there is no port anywhere
        // in this module.
        assert!(SOCKET_PATH.starts_with('/'));
        assert!(!SOCKET_PATH.contains(':'));
        assert!(SOCKET_PATH.starts_with(SOCKET_DIR));
    }

    #[test]
    fn the_endpoint_has_no_world_bit_in_either_direction() {
        assert_eq!(SOCKET_MODE & 0o007, 0);
        assert_eq!(SOCKET_MODE, 0o660);
        assert_ne!(SOCKET_GROUP, "staff", "never a built-in everyone-group");
        assert_ne!(SOCKET_GROUP, "everyone");
    }

    #[test]
    fn the_socket_path_override_defaults_to_the_production_value() {
        if std::env::var_os(SOCKET_PATH_ENV).is_none() {
            assert_eq!(socket_path(), std::path::PathBuf::from(SOCKET_PATH));
        }
    }
}
