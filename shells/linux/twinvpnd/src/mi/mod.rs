//! The local management interface: the envelope, the framing, and the client.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §10.1 (the endpoint's location), §11.2 (the Linux transport), MI-A3;
//! ADR-0016 §11.14 (a).
//!
//! Compiled into **both** binaries, which is MI-20's "one contract, two
//! carriages" as a crate layout: `twinvpnd` serves it and `twinvpnctl` speaks
//! it, from one definition.

pub mod client;
pub mod codec;
pub mod scope;
pub mod wire;

pub use client::{Client, ClientError};
pub use codec::TransportError;
pub use scope::{Scopes, CLI_REQUESTED_SCOPES};
pub use wire::{
    Body, Compacted, Diagnostic, Event, FrameError, Hello, HelloAck, MgmtEnvelope, PlatformCtx,
    Request, Response, MAX_ENVELOPE_BYTES, MI_VERSION, MI_VERSION_MIN,
};

/// The endpoint. ADR-0017 §10.1, documented "because scripts and
/// configuration-management tooling will hard-code them".
///
/// > Relocation is an `mi_version` event, not a patch-level change.
pub const SOCKET_PATH: &str = "/run/twinvpn/mgmt.sock";

/// The directory the init system creates (`RuntimeDirectory=twinvpn`).
///
/// **MI-A3**: created by the OS init system with a privileged owner and no
/// non-privileged write. "The agent MUST verify the directory's ownership and
/// mode before binding and MUST refuse to bind into a directory it does not
/// own."
pub const SOCKET_DIR: &str = "/run/twinvpn";

/// The endpoint's mode. §11.2's Linux row.
pub const SOCKET_MODE: u32 = 0o660;

/// The group that owns the endpoint. §11.2's Linux row.
pub const SOCKET_GROUP: &str = "twinvpn";

/// The environment variable that overrides [`SOCKET_PATH`].
///
/// Present for **local development and the component tests**, where a
/// system-wide `/run/twinvpn` is not available and running the agent as root to
/// get one would be a worse habit than a variable. ADR-0023 EM-19 makes changing
/// the management-socket path a restart-requiring setting, which is exactly what
/// an environment variable read once at start is.
///
/// It is **not** a security control and is not treated as one: the endpoint's
/// safety comes from `SO_PEERCRED` and the directory's ownership (MI-A3), both
/// of which are checked wherever the path points.
pub const SOCKET_PATH_ENV: &str = "TWINVPN_MGMT_SOCKET";

/// The endpoint this process should use.
///
/// Reads [`SOCKET_PATH_ENV`] once. `infra/README.md`'s convention: every
/// variable has a default and the default is the production value.
#[must_use]
pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os(SOCKET_PATH_ENV)
        .map_or_else(|| std::path::PathBuf::from(SOCKET_PATH), Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_where_adr_0017_10_1_says_it_is() {
        assert_eq!(SOCKET_PATH, "/run/twinvpn/mgmt.sock");
        assert_eq!(SOCKET_DIR, "/run/twinvpn");
        assert_eq!(SOCKET_MODE, 0o660);
        assert_eq!(SOCKET_GROUP, "twinvpn");
        // No world bit, in either direction: §11.2's mode is 0660 and the
        // OBSERVE principal is a dedicated group, "never a built-in
        // everyone-group" (ADR-0016 PS-12a).
        assert_eq!(SOCKET_MODE & 0o007, 0);
    }

    #[test]
    fn the_endpoint_is_a_filesystem_path_and_never_a_network_address() {
        // ADR-0017 §11.2 rejects loopback TCP ("no peer credentials … reachable
        // by every local user, by containers and WSL") and abstract sockets
        // ("visible across network namespaces"). Both rejections are structural
        // here: the constant is a path, and there is no port anywhere in this
        // module.
        assert!(SOCKET_PATH.starts_with('/'), "not abstract");
        assert!(!SOCKET_PATH.starts_with('@'), "not the abstract namespace");
        assert!(!SOCKET_PATH.contains(':'), "not a host:port");
    }

    #[test]
    fn the_socket_path_override_defaults_to_the_production_value() {
        // The variable is a development affordance, not a security control.
        if std::env::var_os(SOCKET_PATH_ENV).is_none() {
            assert_eq!(socket_path(), std::path::PathBuf::from(SOCKET_PATH));
        }
    }
}
