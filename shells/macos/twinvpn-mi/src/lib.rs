//! The local management interface: where it lives, how it is framed, what a
//! scope set is, and the client half.
//!
//! **Authority:** ADR-0017 §10.1 (the endpoint's location), §11.2 (the macOS
//! transport row — **both** channels), §11.3 (the envelope), MI-20,
//! MI-A1…MI-A5; ADR-0016 §11.14 (a), §11.2's macOS row and **PS-22**.
//!
//! **Owner:** `desktop-macos`.
//!
//! # Who serves this, after X-7
//!
//! The **NE system extension** does, in `twinvpn-bridge`. PS-22:
//!
//! > | the NE **system extension** | the core …, the management interface over
//! > XPC with `audit_token_t` (§11.14 (a)) |
//! > | `ksd`, the `LaunchDaemon` | the KS-19 boot anchor … **no core, no keys,
//! > no network sockets, no management interface** |
//!
//! So there is no `twinvpnd` any more, and this crate deliberately does not
//! name one. It carries the two things the authority and the CLI must agree on
//! and nothing else.
//!
//! # Two channels, one contract — and this is §11.2's own row
//!
//! ADR-0017 §11.2's macOS row gives this platform **two** channels for one
//! contract:
//!
//! > `NSXPCConnection` to Mach service `com.twinvpn.agent.mgmt`; `AF_UNIX` at
//! > `/var/run/twinvpn/mgmt.sock` **for non-XPC clients such as the CLI**
//!
//! with "XPC audit token → `SecCodeCheckValidity`" and "`LOCAL_PEERCRED` on the
//! socket" as their two peer attestations. Both are served **from the
//! extension**, which is what PS-22 moved. The envelope is byte-identical on
//! both — §11.2's own opening sentence, "a message that is valid on one channel
//! is byte-identical on another" — so this crate holds the framing once and
//! neither channel gets a dialect.
//!
//! [`XPC_SERVICE_NAME`] is the first; [`SOCKET_PATH`] is the second, and it is
//! what [`client::Client`] speaks.
//!
//! # A reported duplication that is now closed
//!
//! `shells/macos` §7 gap 15 asked for the envelope to move into
//! `core/crates/twinvpn-mgmt`, and X-4 moved it. [`wire`] re-exports it; there
//! is no second declaration here and no place for one to grow.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

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

/// This build's own version string, for `HelloAck.agent_version`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The platform name MI-C3 carries.
///
/// A constant rather than a `cfg`, because every crate in this shell is only
/// ever built for macOS and a `cfg` here would be portability theatre.
pub const PLATFORM: &str = "macos";

/// The build profile. ADR-0017 §11.7: "**Build profile is not version.**"
///
/// A separate field because a debug build and a release build of the same
/// version behave differently under load and a support case needs to know which
/// it has — and because conflating the two is how "it works on my machine"
/// becomes unanswerable.
#[must_use]
pub const fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// The socket endpoint. ADR-0017 §10.1, documented "because scripts and
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
/// mode on **every** start; neither `launchd` nor `systemextensionsd` has an
/// equivalent. So the directory is the **installer's**, created once, and the
/// authority **verifies and refuses** rather than creating it — because a
/// process that created its own endpoint directory could be raced by whatever
/// created it first after a `/var/run` wipe.
///
/// That is a real weakening and it is stated in `shells/macos/README.md` §7
/// rather than hidden behind a `create_dir_all`.
pub const SOCKET_DIR: &str = "/var/run/twinvpn";

/// The endpoint's mode.
///
/// No world bit, in either direction. ADR-0016 PS-12a: the OBSERVE principal is
/// a dedicated group, "never a built-in everyone-group".
pub const SOCKET_MODE: u32 = 0o660;

/// The group that owns the endpoint.
pub const SOCKET_GROUP: &str = "twinvpn";

/// The XPC Mach service ADR-0017 §11.2's macOS row names.
///
/// Served by the **system extension** (PS-22), declared to NE by
/// `NEMachServiceName` in the sysext `Info.plist`, and attested by
/// `audit_token_t` (§11.14 (a)). The name is fixed here, in one place, so the
/// plist and the code cannot disagree about it.
pub const XPC_SERVICE_NAME: &str = "com.twinvpn.agent.mgmt";

/// The environment variable that overrides [`SOCKET_PATH`].
///
/// Present for **local development and the component tests**, where a
/// system-wide `/var/run/twinvpn` is not available and running as root to get
/// one would be a worse habit than a variable. ADR-0023 EM-19 makes changing
/// the management-socket path a restart-requiring setting, which is exactly
/// what an environment variable read once at start is.
///
/// It is **not** a security control and is not treated as one: the endpoint's
/// safety comes from the peer credential and the directory's ownership
/// (MI-A3), both of which are checked wherever the path points.
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
    fn the_socket_endpoint_is_a_filesystem_path_and_never_a_network_address() {
        // ADR-0017 §11.2 rejects loopback TCP ("no peer credentials … reachable
        // by every local user, by containers and WSL"). The rejection is
        // structural here: the constant is a path, and there is no port anywhere
        // in this crate.
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

    #[test]
    fn the_xpc_service_name_is_a_mach_name_and_not_a_bundle_id_or_a_path() {
        // §11.2's macOS row names `com.twinvpn.agent.mgmt`. A Mach service name
        // is a reverse-DNS label, never a filesystem path — and it is
        // deliberately NOT the sysext's bundle identifier, because the bundle id
        // is `com.twinvpn.app.sysext` (PS-19) and a reader who conflated the two
        // would look for the MI on the wrong service.
        assert_eq!(XPC_SERVICE_NAME, "com.twinvpn.agent.mgmt");
        assert!(!XPC_SERVICE_NAME.starts_with('/'));
        assert!(!XPC_SERVICE_NAME.contains('/'));
        assert_ne!(XPC_SERVICE_NAME, "com.twinvpn.app.sysext");
    }

    #[test]
    fn this_crate_names_no_daemon_because_ps22_deleted_one() {
        // PS-22's table: `ksd` holds "no core, no keys, no network sockets, no
        // management interface". A constant here pointing at a daemon endpoint
        // would be exactly the forwarding hop PS-22 forbids, so its absence is
        // asserted rather than assumed.
        let source = include_str!("lib.rs");
        let code: String = source
            .lines()
            .take_while(|l| !l.trim_start().starts_with("mod tests"))
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!code.contains("twinvpnd"));
        assert!(!code.contains("com.twinvpn.ksd"));
    }
}
