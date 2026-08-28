//! What the extension reads from its environment, read **once, at start**.
//!
//! **Authority:** ADR-0016 §11.2's macOS row and its **PS-22** amendment,
//! §11.9, PS-12a, KS-9(1); ADR-0018 CD-2 (every component takes its `Env` at
//! construction, nothing is discovered); ADR-0020 §11.3's macOS rows;
//! ADR-0023 EM-19 (a setting read at start is a restart-requiring setting).
//!
//! # The one change PS-22 makes that is an *improvement*, not a move
//!
//! ADR-0012 KS-9(1)'s macOS predicate is *"`pf` anchor keyed to the tunnel
//! provider's owning uid **plus the provider's socket set**"*. The
//! `LaunchDaemon` binding could satisfy only the first half — there is no NE
//! runtime to supply the second — so wave 2 declared
//! [`ExemptPredicate::UidOnly`] and the start sequence reported
//! `PLATFORM.PRIV.SANDBOX_DEGRADED` on every start.
//!
//! Inside the system extension **both halves hold**: the uid is matched in the
//! anchor and the socket-set half is supplied by the NE runtime, which excludes
//! the provider's own sockets from the tunnel it is serving. So this binding
//! declares [`ExemptPredicate::ProviderUidAndSocketSet`] and
//! `EnforcementConfig::ks9_complete()` is true. That is a real strengthening
//! that the wrong topology was costing, and it is worth saying plainly: moving
//! the authority did not only satisfy §11.2, it closed a KS-9 gap.
//!
//! It is still **declared, never assumed**: nothing here verifies that NE
//! actually excludes the provider's sockets, because nothing on this host can.
//! `shells/macos/README.md` §7 records it as a compile-and-review claim.

use std::path::PathBuf;
use std::sync::Arc;

use twinvpn_platform_macos::custody::{Accessibility, KeychainItemSpec};
use twinvpn_platform_macos::{EnforcementConfig, ExemptPredicate};

use crate::mgmt::GroupPolicy;

/// Everything the extension reads from its environment.
///
/// Every variable has a default and the default is the production value. None of
/// them is a security control: the endpoint's safety comes from the peer
/// credential and the directory's ownership, both checked wherever the path
/// points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionConfig {
    /// The MI socket endpoint (ADR-0017 §11.2's macOS row, second channel).
    pub socket_path: PathBuf,
    /// ADR-0020's vault directory.
    pub store_root: PathBuf,
    /// Where the package installed the pf anchor body (ADR-0016 §11.5).
    ///
    /// Read only to answer "is the KS-19 artifact installed" (PS-7). **The
    /// authority never writes it**: PS-7 makes it package-owned and says the
    /// authority "MUST NOT rewrite it as a runtime action".
    pub boot_anchor: PathBuf,
    /// The gids PS-12a's three classes come from.
    pub groups: GroupPolicy,
    /// The uid KS-9(1)'s anchor rule matches — this provider's own.
    pub exempt_uid: u32,
    /// The overlay interface name Tier 2 is scoped to.
    pub overlay_interface: String,
    /// Whether KS-4's `local_network_access` is `ALLOW`.
    pub local_network_access: bool,
}

impl ExtensionConfig {
    /// The production defaults.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            socket_path: PathBuf::from(twinvpn_mi::SOCKET_PATH),
            store_root: PathBuf::from(twinvpn_platform_macos::custody::DEFAULT_STORE_ROOT),
            boot_anchor: PathBuf::from(twinvpn_platform_macos::pf::ANCHOR_FILE),
            // **Placeholders that must be overridden, and are visible as such.**
            // PS-12a says the PACKAGE creates the principals and the authority
            // never does, so there is no sensible default gid — and a default of
            // 0 would silently make every class root-only, which fails closed
            // and is therefore the right shape for a value nobody set.
            groups: GroupPolicy {
                observe: 0,
                operate: 0,
                administer: 0,
            },
            // A system extension runs as root, so this is its uid. Overridable
            // for the same reason every other value here is: a test binding.
            exempt_uid: 0,
            overlay_interface: "utun7".to_owned(),
            local_network_access: true,
        }
    }

    /// The configuration this process should use.
    ///
    /// Reads the environment once. ADR-0023 EM-19 makes every one of these
    /// restart-requiring, which is exactly what a variable read at start is.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::defaults();
        config.socket_path = twinvpn_mi::socket_path();
        if let Some(root) = std::env::var_os("TWINVPN_STATE_DIRECTORY") {
            config.store_root = PathBuf::from(root);
        }
        if let Some(name) = std::env::var_os("TWINVPN_OVERLAY_INTERFACE") {
            config.overlay_interface = name.to_string_lossy().into_owned();
        }
        for (variable, slot) in [
            ("TWINVPN_GROUP_OBSERVE", &mut config.groups.observe),
            ("TWINVPN_GROUP_OPERATE", &mut config.groups.operate),
            ("TWINVPN_GROUP_ADMINISTER", &mut config.groups.administer),
            ("TWINVPN_EXEMPT_UID", &mut config.exempt_uid),
        ] {
            if let Some(value) = std::env::var(variable).ok().and_then(|v| v.parse().ok()) {
                *slot = value;
            }
        }
        config
    }

    /// The enforcement configuration this binding hands the adapter.
    ///
    /// **The system-extension binding: both halves of KS-9(1) hold.** See the
    /// module header for why that changed, and for what is still only declared.
    #[must_use]
    pub fn enforcement(&self) -> EnforcementConfig {
        EnforcementConfig {
            overlay_interface: self.overlay_interface.clone(),
            exempt: ExemptPredicate::ProviderUidAndSocketSet {
                uid: self.exempt_uid,
            },
            local_network_access: self.local_network_access,
            // Recomputed on every network-change event by the reconciler; empty
            // at start because nothing has been enumerated yet, and KS-4's
            // permitted set being empty fails CLOSED.
            on_link_prefixes: Vec::new(),
            // ADR-0011 §11.9's known-DoH list is an installation fact the seam
            // does not carry. Empty until the packaging supplies one, which the
            // README names as a gap.
            doh_endpoints: Vec::new(),
        }
    }

    /// The Keychain item shape.
    ///
    /// ADR-0020's **Developer ID** row: the System keychain, with the item ACL
    /// bound to the Team-signed binary. **Not** the shared
    /// `keychain-access-groups` entitlement — ADR-0016 §11.4's residual is that
    /// an access group "cannot be scoped below app identity", and §11.14 (g)
    /// requires the key handle to be *unopenable* by the unprivileged client.
    /// Only the System keychain is both openable with no user logged in and
    /// closed to the app, which is why `access_group` is `None` here and why
    /// the entitlements file says the shared group never holds the identity.
    ///
    /// The service name moved with the authority: it was `net.twinvpn.twinvpnd`
    /// while the daemon held the key, and a stale one would have the extension
    /// looking for an item under a component that no longer exists.
    #[must_use]
    pub fn keychain(&self) -> KeychainItemSpec {
        KeychainItemSpec {
            service: "net.twinvpn.sysext".to_owned(),
            access_group: None,
            accessibility: Accessibility::SystemKeychain,
        }
    }
}

/// Builds the adapter this binding uses.
///
/// **CD-2**: every part is injected, and nothing is discovered from the
/// environment inside the adapter.
#[must_use]
pub fn build_adapter(
    config: &ExtensionConfig,
    carriers: twinvpn_platform_macos::NetworkCarriers,
) -> Arc<twinvpn_platform_macos::MacosPlatformAdapter> {
    Arc::new(twinvpn_platform_macos::MacosPlatformAdapter::new(
        twinvpn_platform_macos::MacosAdapterParts {
            enforcement: config.enforcement(),
            carriers,
            // **The whole of X-7 in one field.** The OS hands this process a
            // flow; nothing here opens a `utun`. A capability, not an OS branch
            // — and the reason the daemon could never have been the authority,
            // since `NEPacketTunnelProvider.packetFlow` exists only here.
            tunnel_provenance: twinvpn_platform_macos::TunnelProvenance::OsProvidedFlow,
            store_root: config.store_root.clone(),
            // **§11.16 (l), truthfully.** No Secure Enclave signer is wired in
            // this wave, so the honest report is "absent" and the core records
            // it rather than a file-backed signer being substituted silently.
            identity_element: Arc::new(twinvpn_platform_macos::AbsentElement),
            keychain: config.keychain(),
        },
    ))
}

/// The carriers the **system-extension** binding uses.
///
/// # What changed from the daemon binding, and why it is fewer things
///
/// Under `NEPacketTunnelNetworkSettings` the **OS** installs the addresses, the
/// routes and the resolver: the settings document
/// [`twinvpn_platform_macos::nesettings`] renders is applied by NE, not by
/// `route(8)` and not by `SCDynamicStore`. So this binding carries
/// [`twinvpn_platform_macos::RouteCarrier::TunnelSettings`] and
/// [`twinvpn_platform_macos::resolver::ResolverCarrier::TunnelSettings`], and
/// the `route`/resolver engines are
/// present only to refuse by name if something asks them to act — which under
/// these carriers nothing does.
///
/// `pf` is on **both** bindings and always was: ADR-0012 §11.6 puts the kill
/// switch in `pf` whichever process is running, so there is no carrier under
/// which enforcement is absent.
#[must_use]
pub fn extension_carriers(
    resolver: Arc<dyn twinvpn_platform_macos::netcfg::ResolverEngine>,
    service_id: String,
) -> twinvpn_platform_macos::NetworkCarriers {
    twinvpn_platform_macos::NetworkCarriers {
        pf: Arc::new(twinvpn_platform_macos::netcfg::PfctlEngine),
        route: Arc::new(twinvpn_platform_macos::netcfg::RouteCommandEngine),
        resolver,
        route_carrier: twinvpn_platform_macos::RouteCarrier::TunnelSettings,
        resolver_carrier: twinvpn_platform_macos::resolver::ResolverCarrier::TunnelSettings,
        service_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::{scopes_for, PeerCredentials};

    #[test]
    fn the_extension_binding_satisfies_ks9_in_full() {
        // The improvement PS-22 bought. Wave 2's daemon binding declared
        // `UidOnly` and reported a degradation on every start; the provider
        // binding declares both halves.
        let config = ExtensionConfig::defaults();
        assert!(config.enforcement().ks9_complete());
        assert!(matches!(
            config.enforcement().exempt,
            ExemptPredicate::ProviderUidAndSocketSet { .. }
        ));
    }

    #[test]
    fn the_datapath_comes_from_the_os_and_is_never_opened_here() {
        // `NEPacketTunnelProvider.packetFlow` exists only in this process, which
        // is the physical argument PS-22 rests on. The adapter is told so as a
        // capability rather than inferring it from an OS check.
        let adapter = build_adapter(
            &ExtensionConfig::defaults(),
            extension_carriers(Arc::new(crate::host::NoResolver), String::new()),
        );
        assert!(adapter.posture().datapath_is_os_provided);
    }

    #[test]
    fn an_unset_group_policy_fails_closed_rather_than_open() {
        // PS-12a: the package creates the principals and the authority never
        // does. A gid nobody set must grant NOTHING to an ordinary account, and
        // 0 does exactly that — only root matches it, and root already holds
        // everything.
        let config = ExtensionConfig::defaults();
        let stranger = PeerCredentials {
            uid: 501,
            groups: vec![20, 12],
            groups_possibly_truncated: false,
        };
        assert!(scopes_for(&stranger, config.groups).names().is_empty());
    }

    #[test]
    fn the_keychain_row_is_adr_0020s_developer_id_row_and_never_the_shared_group() {
        // §11.14 (g): openable by the authority with no user logged in, and
        // UNOPENABLE by the unprivileged client. A shared access group cannot do
        // the second (ADR-0016 §11.4's residual), so `access_group` is None and
        // the identity never lives there.
        let spec = ExtensionConfig::defaults().keychain();
        assert_eq!(spec.accessibility, Accessibility::SystemKeychain);
        assert!(!spec.accessibility.uses_data_protection_keychain());
        assert!(spec.access_group.is_none(), "no app group on this row");
        assert!(!spec.synchronizable(), "Tier 1 never syncs");
        assert!(
            !spec.service.contains("twinvpnd"),
            "the daemon that held this item no longer exists"
        );
    }

    #[test]
    fn the_defaults_are_the_paths_the_adrs_name() {
        let config = ExtensionConfig::defaults();
        assert_eq!(
            config.store_root,
            PathBuf::from("/Library/Application Support/TwinVPN")
        );
        assert_eq!(config.boot_anchor, PathBuf::from("/etc/twinvpn/pf.anchor"));
        assert_eq!(
            config.socket_path,
            PathBuf::from("/var/run/twinvpn/mgmt.sock")
        );
    }

    #[test]
    fn the_os_carries_the_routes_and_the_resolver_on_this_binding() {
        // Not a decision: `setTunnelNetworkSettings` replaces the whole object,
        // so a second programme through `route(8)` would be two writers for one
        // fact. The carriers say which mechanism is in force and the transaction
        // above them does not ask which OS it is on.
        let carriers = extension_carriers(Arc::new(crate::host::NoResolver), String::new());
        assert_eq!(
            carriers.route_carrier,
            twinvpn_platform_macos::RouteCarrier::TunnelSettings
        );
        assert_eq!(
            carriers.resolver_carrier,
            twinvpn_platform_macos::resolver::ResolverCarrier::TunnelSettings
        );
    }
}
