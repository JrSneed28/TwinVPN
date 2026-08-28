//! The local management interface: the endpoint, the envelope, the framing, the
//! DACL and the client.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §10.1 (the endpoint's location is documented and stable), §11.2 (the Windows
//! transport row), §11.4 MI-A1…MI-A5, §11.5 MI-S1/MI-S2, MI-20;
//! ADR-0016 §11.9 (the pipe DACL), PS-12a (the named principals).
//!
//! Compiled into **both** binaries, which is MI-20's "one contract, two
//! carriages" as a crate layout: `twinvpnsvc` serves it and `twinvpnctl` speaks
//! it, from one definition. `twinvpnctl` depends on this crate with
//! `default-features = false`, which excludes the whole `service` feature, so the
//! unprivileged CLI links no Wintun, no WFP, no IP Helper and no core-hosting
//! code.

pub mod client;
pub mod codec;
pub mod dacl;
pub mod scope;
pub mod wire;

pub use client::{Client, ClientError};
pub use codec::TransportError;
pub use dacl::{pipe_sddl, PrincipalSids};
pub use scope::{Scopes, CLI_REQUESTED_SCOPES, GRANTABLE};
pub use wire::{
    Body, Compacted, Diagnostic, Event, FrameError, Hello, HelloAck, MgmtEnvelope, PlatformCtx,
    Request, Response, MAX_ENVELOPE_BYTES, MI_VERSION, MI_VERSION_MIN,
};

/// The endpoint. ADR-0017 §11.2's Windows row and §10.1, documented "because
/// scripts and configuration-management tooling will hard-code them".
///
/// > Relocation is an `mi_version` event, not a patch-level change.
pub const PIPE_NAME: &str = r"\\.\pipe\TwinVPN\mgmt";

/// The environment variable that overrides [`PIPE_NAME`].
///
/// Present for **local development and the component tests**, where installing a
/// service to get a pipe is a worse habit than a variable. ADR-0023 EM-19 makes
/// changing the management endpoint a restart-requiring setting, which is
/// exactly what a variable read once at start is.
///
/// It is **not** a security control and is not treated as one: the endpoint's
/// safety comes from the DACL ([`dacl::pipe_sddl`]),
/// `PIPE_REJECT_REMOTE_CLIENTS` and the client-token check (MI-A1), all of which
/// apply wherever the name points.
pub const PIPE_NAME_ENV: &str = "TWINVPN_MGMT_PIPE";

/// The maximum number of concurrent pipe instances.
///
/// **A decision recorded as one.** No value is pinned in the corpus. ADR-0016
/// PS-13 requires concurrent clients to be *served* rather than serialised, and
/// ADR-0017's threat table accepts that "a local attacker can deny
/// **management**" — so the cap exists to bound the agent's own memory, not to
/// be a security control. Sixteen is well above the "a GUI, a CLI and a
/// monitoring agent" case §11.10 describes and far below anything that would
/// matter to a service holding a core.
pub const MAX_PIPE_INSTANCES: u32 = 16;

/// The endpoint this process should use.
///
/// Reads [`PIPE_NAME_ENV`] once. `infra/README.md`'s convention: every variable
/// has a default and the default is the production value.
#[must_use]
pub fn pipe_name() -> String {
    std::env::var(PIPE_NAME_ENV).unwrap_or_else(|_| PIPE_NAME.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_where_adr_0017_11_2_says_it_is() {
        assert_eq!(PIPE_NAME, r"\\.\pipe\TwinVPN\mgmt");
    }

    #[test]
    fn the_endpoint_is_a_pipe_name_and_never_a_network_address() {
        // ADR-0017 §11.2 rejects loopback TCP: "no peer credentials … reachable
        // by every local user, by containers and WSL". The rejection is
        // structural here — the constant is a pipe path, and there is no port
        // anywhere in this module.
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"), "a local pipe");
        assert!(!PIPE_NAME.contains(':'), "not a host:port");
        // And it is the LOCAL pipe namespace: `\\.\` and never `\\<host>\`,
        // which with `PIPE_REJECT_REMOTE_CLIENTS` is what keeps it off SMB.
        assert!(!PIPE_NAME.starts_with(r"\\\\"));
    }

    #[test]
    fn the_pipe_name_override_defaults_to_the_production_value() {
        // The variable is a development affordance, not a security control.
        if std::env::var(PIPE_NAME_ENV).is_err() {
            assert_eq!(pipe_name(), PIPE_NAME);
        }
    }
}
