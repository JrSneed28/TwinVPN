//! The management interface, served **from the authority**.
//!
//! **Authority:** ADR-0016 §11.2's macOS row and its amendment **PS-22**, §11.3
//! **PS-22** (the other one — see below), §11.14 (a), PS-1, PS-4, PS-12a;
//! ADR-0017 §11.2's macOS row, MI-A1…MI-A5, MI-20, A-12.
//!
//! # A corpus defect, reported here because this is where it bites
//!
//! **ADR-0016 uses the identifier `PS-22` twice.** §11.3 has *"Rule PS-22 — the
//! management server does not link the datapath"*, and §11.2's amendment (the
//! one `ownership.md` §9.6 X-7 records) is also called PS-22: *"how the core
//! gets into the system extension, and why the daemon is not the authority"*.
//! They are different rules about different things and both apply to this
//! module. ADR-0017 A-12 cites "§11.3 PS-22" and the X-7 disposition cites the
//! amendment, so both are live and neither is a typo for the other. Renumbering
//! is the integration lead's; this module cites them by section so a reader is
//! never left guessing which one is meant.
//!
//! # What lives here, and what deliberately does not
//!
//! | Module | Holds |
//! |---|---|
//! | [`server`] | the version window, the grant, the catalogue lookup, the authorization ladder, the reply — **for both carriages** |
//! | [`session`] | one XPC connection's state, over bytes Swift marshalled |
//! | [`peer`] | `getsockopt(LOCAL_PEERCRED)` — the socket carriage's principal |
//! | [`audit`] | `audit_token_t` — the XPC carriage's principal (§11.14 (a)) |
//! | [`endpoint`] | MI-A3's bind-then-rename for the socket carriage |
//!
//! Nothing here holds a packet, a route, a resolver entry or a `pf` rule, and
//! `server`'s own source test is what keeps that true now that the datapath is
//! in the same crate (ADR-0017 A-12: the check becomes a **module**-graph one).

pub mod audit;
pub mod endpoint;
pub mod peer;
pub mod server;
pub mod session;

pub use audit::AuditToken;
pub use endpoint::EndpointError;
pub use peer::{scopes_for, GroupPolicy, PeerCredentials};
pub use server::{serve, CommandSink, Ending, ServerContext};
pub use session::Session;

#[cfg(test)]
mod tests {
    /// A module's production half — everything before its first `#[cfg(test)]`.
    ///
    /// Both tests below name the things they forbid in their own assertions, so
    /// a scan that included the test modules would fire on itself. That is the
    /// same reason `server::executable_source` exists, applied across files.
    fn production_half(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    // `server_tests.rs` is deliberately absent from both lists below. It is
    // `server`'s test module, split into its own file only to keep `server.rs`
    // under the 500-line rule, and it names every forbidden string in its own
    // assertions — which is the same reason `production_half` exists. Scanning
    // it would be a check that can only fail.

    /// The `unsafe` budget of the management modules, asserted rather than
    /// reviewed.
    ///
    /// The crate as a whole is the FFI boundary and permits `unsafe` (DP-4), so
    /// a blanket count would say nothing. What matters is that the *management*
    /// side has exactly one: `getsockopt(LOCAL_PEERCRED)`, which MI-A1 makes the
    /// only kernel source of a principal on Darwin. A second one here is a build
    /// failure rather than a review finding.
    #[test]
    fn the_management_modules_use_unsafe_in_exactly_one_place() {
        let sources = [
            ("mod.rs", include_str!("mod.rs")),
            ("audit.rs", include_str!("audit.rs")),
            ("endpoint.rs", include_str!("endpoint.rs")),
            ("peer.rs", include_str!("peer.rs")),
            ("server.rs", include_str!("server.rs")),
            ("session.rs", include_str!("session.rs")),
        ];
        let mut blocks = Vec::new();
        for (name, source) in sources {
            for (n, line) in production_half(source).lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains("unsafe {") || code.contains("unsafe fn") {
                    blocks.push(format!("{name}:{}", n + 1));
                }
            }
        }
        assert_eq!(
            blocks.len(),
            1,
            "the management side's unsafe budget is one block, at \
             `peer::PeerCredentials::read`; found {blocks:?}"
        );
        assert!(blocks[0].starts_with("peer.rs"));
    }

    /// **PS-22 (§11.3) as a module-graph assertion over the whole subtree.**
    ///
    /// `server.rs` asserts it over its own source; this asserts it over every
    /// file here, so a helper added to `session.rs` or `endpoint.rs` cannot
    /// smuggle the edge in from beside the server.
    #[test]
    fn no_management_module_reaches_the_datapath() {
        let sources = [
            ("audit.rs", include_str!("audit.rs")),
            ("endpoint.rs", include_str!("endpoint.rs")),
            ("peer.rs", include_str!("peer.rs")),
            ("server.rs", include_str!("server.rs")),
            ("session.rs", include_str!("session.rs")),
        ];
        for (name, source) in sources {
            for (n, line) in production_half(source).lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                for forbidden in [
                    "twinvpn_platform_macos",
                    "twinvpn_core",
                    "crate::ext",
                    "crate::port",
                    "crate::host",
                ] {
                    assert!(
                        !code.contains(forbidden),
                        "{name}:{} reaches {forbidden}, which PS-22 (§11.3) forbids",
                        n + 1
                    );
                }
            }
        }
    }
}
