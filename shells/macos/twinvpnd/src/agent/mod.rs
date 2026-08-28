//! The privileged half: configuration, the probes §11.6's sequence asks, and the
//! run loop.
//!
//! **Authority:** ADR-0016 §11.6, §11.5's macOS row, PS-1, PS-3, PS-11, PS-17,
//! PS-18; ADR-0018 CD-2 (every component takes its `Env` at construction);
//! ADR-0020 §11.3's macOS store row; ADR-0022 LC-8.

pub mod endpoint;
pub mod logging;
pub mod peer;
pub mod server;
pub mod start;

use std::path::PathBuf;
use std::sync::Arc;

use twinvpn_platform_macos::custody::{Accessibility, KeychainItemSpec};

/// Everything the agent reads from its environment, read **once, at start**.
///
/// Every variable has a default and the default is the production value. None of
/// them is a security control: the endpoint's safety comes from the peer
/// credential and the directory's ownership, both checked wherever the path
/// points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// The MI endpoint.
    pub socket_path: PathBuf,
    /// ADR-0020's vault directory.
    pub store_root: PathBuf,
    /// Where the package installed the pf anchor body (ADR-0016 §11.5).
    pub boot_anchor: PathBuf,
    /// The gids PS-12a's three classes come from.
    pub groups: peer::GroupPolicy,
    /// The uid the anchor's class-7 rule matches (KS-9(1)).
    pub exempt_uid: u32,
    /// The overlay interface name Tier 2 is scoped to.
    pub overlay_interface: String,
    /// Whether KS-4's `local_network_access` is `ALLOW`.
    pub local_network_access: bool,
}

impl AgentConfig {
    /// The production defaults.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            socket_path: PathBuf::from(crate::mi::SOCKET_PATH),
            store_root: PathBuf::from(twinvpn_platform_macos::custody::DEFAULT_STORE_ROOT),
            boot_anchor: PathBuf::from(twinvpn_platform_macos::pf::ANCHOR_FILE),
            // **Placeholders that must be overridden, and are visible as such.**
            // PS-12a says the PACKAGE creates the principals and the agent never
            // does, so there is no sensible default gid — and a default of 0 would
            // silently make every class root-only, which fails closed and is
            // therefore the right shape for a value nobody set.
            groups: peer::GroupPolicy {
                observe: 0,
                operate: 0,
                administer: 0,
            },
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
        config.socket_path = crate::mi::socket_path();
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

    /// The enforcement configuration this build hands the adapter.
    ///
    /// The `LaunchDaemon` binding: there is no NE runtime, so KS-9(1)'s
    /// socket-set half is not available and the predicate is the **weaker**
    /// uid-only one. Named here, reported by the start sequence, never upgraded.
    #[must_use]
    pub fn enforcement(&self) -> twinvpn_platform_macos::EnforcementConfig {
        twinvpn_platform_macos::EnforcementConfig {
            overlay_interface: self.overlay_interface.clone(),
            exempt: twinvpn_platform_macos::ExemptPredicate::UidOnly {
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

    /// The Keychain item shape. ADR-0020's **Developer ID `launchd` daemon** row:
    /// the System keychain, with the item ACL bound to the Team-signed binary.
    #[must_use]
    pub fn keychain(&self) -> KeychainItemSpec {
        KeychainItemSpec {
            service: "net.twinvpn.twinvpnd".to_owned(),
            // No app group on this row.
            access_group: None,
            accessibility: Accessibility::SystemKeychain,
        }
    }
}

/// The probes §11.6's sequence asks, answered against this host.
///
/// Every method is a **fact**. The sequence in [`start`] decides what each fact
/// means, and it is that decision — not these lookups — that the tests exercise.
// Five booleans, and each is a distinct fact §11.6 asks about on its own line:
// the clocks, the runtime's I/O driver, the enforcement read-back, the core and
// the endpoint are five different steps with five different refusals. Collapsing
// them into a bitflags type would make "which step refused" — the one thing a
// diagnostic bundle needs — invisible.
#[allow(clippy::struct_excessive_bools)]
pub struct DarwinProbes {
    config: AgentConfig,
    posture: Option<twinvpn_platform_macos::AdapterPosture>,
    read_back: bool,
    core_ready: bool,
    endpoint_ready: bool,
    clocks_bind: bool,
    runtime_has_io: bool,
}

impl DarwinProbes {
    /// Builds a probe set with nothing yet attempted.
    #[must_use]
    pub const fn new(config: AgentConfig) -> Self {
        Self {
            config,
            posture: None,
            read_back: false,
            core_ready: false,
            endpoint_ready: false,
            clocks_bind: false,
            runtime_has_io: false,
        }
    }

    /// Records the adapter's declared posture.
    pub fn with_posture(&mut self, posture: twinvpn_platform_macos::AdapterPosture) {
        self.posture = Some(posture);
    }

    /// Records the **read-back**, which is the only thing that may set this.
    ///
    /// Deliberately not `set_reclaimed(true)` at the point of a successful load:
    /// W-24's whole complaint is that a flag set after `Ok` is not an assertion.
    pub fn with_read_back(&mut self, assertion: &twinvpn_platform_macos::pfread::Assertion) {
        self.read_back = assertion.supports(twinvpn_platform::Ruleset::Blocked)
            || assertion.supports(twinvpn_platform::Ruleset::Protected);
    }

    /// Records that the clocks and the CSPRNG bound.
    pub fn with_clocks(&mut self, bound: bool) {
        self.clocks_bind = bound;
    }

    /// Records that the injected runtime has an I/O driver (W-43).
    pub fn with_runtime_io(&mut self, present: bool) {
        self.runtime_has_io = present;
    }

    /// Records that the core constructed.
    pub fn with_core(&mut self, ready: bool) {
        self.core_ready = ready;
    }

    /// Records that the endpoint bound.
    pub fn with_endpoint(&mut self, ready: bool) {
        self.endpoint_ready = ready;
    }
}

impl start::StartProbes for DarwinProbes {
    fn boot_artifact_installed(&self) -> bool {
        self.config.boot_anchor.exists()
    }

    fn is_root(&self) -> bool {
        effective_uid() == Some(0)
    }

    fn under_supervisor(&self) -> bool {
        logging::under_launchd()
    }

    fn clocks_bind(&self) -> bool {
        self.clocks_bind
    }

    fn runtime_has_io(&self) -> bool {
        self.runtime_has_io
    }

    fn enforcement_available(&self) -> bool {
        self.posture.is_some_and(|p| p.pfctl_present)
    }

    fn ks9_complete(&self) -> bool {
        self.posture.is_some_and(|p| p.ks9_complete)
    }

    fn enforcement_read_back(&self) -> bool {
        self.read_back
    }

    fn vault_ready(&self) -> bool {
        twinvpn_platform_macos::MacosSecureStore::root_is_owner_only(&self.config.store_root)
    }

    fn core_ready(&self) -> bool {
        self.core_ready
    }

    fn endpoint_ready(&self) -> bool {
        self.endpoint_ready
    }
}

/// This process's **effective** uid, without `unsafe`.
///
/// # Why not `libc::geteuid`
///
/// This crate carries `#![forbid(unsafe_code)]` and `std` has no `geteuid`, so
/// the choice was between relaxing the forbid for one line and asking the
/// question a different way. A file this process creates is owned by its
/// effective uid, so `create` + `metadata().uid()` is the same answer through a
/// safe API — and it has a property the syscall does not: it fails if the process
/// cannot write at all, which is a fact worth having.
///
/// Returns `None` when the probe file could not be created, which the caller
/// treats as "not root" — the closed direction.
#[must_use]
pub fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let path = std::env::temp_dir().join(format!("twinvpn-uid-probe-{}", std::process::id()));
    let uid = {
        let file = std::fs::File::create(&path).ok()?;
        file.metadata().ok()?.uid()
    };
    let _ = std::fs::remove_file(&path);
    Some(uid)
}

/// Builds the adapter this binding uses.
///
/// **CD-2**: every part is injected, and nothing is discovered from the
/// environment inside the adapter.
#[must_use]
pub fn build_adapter(
    config: &AgentConfig,
    carriers: twinvpn_platform_macos::NetworkCarriers,
) -> Arc<twinvpn_platform_macos::MacosPlatformAdapter> {
    Arc::new(twinvpn_platform_macos::MacosPlatformAdapter::new(
        twinvpn_platform_macos::MacosAdapterParts {
            enforcement: config.enforcement(),
            carriers,
            // The `LaunchDaemon` opens its own `utun`; the system extension is
            // handed a flow. A capability, not an OS branch.
            tunnel_provenance: twinvpn_platform_macos::TunnelProvenance::AdapterCreatedUtun,
            store_root: config.store_root.clone(),
            // **§11.16 (l), truthfully.** No Secure Enclave signer is wired in
            // this wave, so the honest report is "absent" and the core records it
            // rather than a file-backed signer being substituted silently.
            identity_element: Arc::new(twinvpn_platform_macos::AbsentElement),
            keychain: config.keychain(),
        },
    ))
}

/// The carriers the `LaunchDaemon` binding uses: `pfctl`, `route(8)` and
/// `SCDynamicStore`.
///
/// # `SCDynamicStore` is absent from this list, and that is the gap
///
/// `twinvpn_platform_macos::dynstore::DynamicStoreEngine` is
/// `#[cfg(target_os = "macos")]`, so it cannot be named in a function this crate
/// compiles on Linux — and wiring it behind a `cfg` here would put an OS branch
/// in the shell. Instead the resolver carrier is chosen by the caller, and
/// `main` passes the real engine on Darwin. Recorded as a gap because on this
/// host the branch is not exercised at all.
#[must_use]
pub fn daemon_carriers(
    resolver: Arc<dyn twinvpn_platform_macos::netcfg::ResolverEngine>,
    service_id: String,
) -> twinvpn_platform_macos::NetworkCarriers {
    twinvpn_platform_macos::NetworkCarriers {
        pf: Arc::new(twinvpn_platform_macos::netcfg::PfctlEngine),
        route: Arc::new(twinvpn_platform_macos::netcfg::RouteCommandEngine),
        resolver,
        route_carrier: twinvpn_platform_macos::RouteCarrier::Command,
        resolver_carrier: twinvpn_platform_macos::resolver::ResolverCarrier::DynamicStore,
        service_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_group_policy_fails_closed_rather_than_open() {
        // PS-12a: the package creates the principals and the agent never does. A
        // gid nobody set must grant NOTHING to an ordinary account, and 0 does
        // exactly that — only root matches it, and root already holds everything.
        let config = AgentConfig::defaults();
        let stranger = peer::PeerCredentials {
            uid: 501,
            groups: vec![20, 12],
            groups_possibly_truncated: false,
        };
        assert!(peer::scopes_for(&stranger, config.groups)
            .names()
            .is_empty());
    }

    #[test]
    fn the_daemon_binding_declares_the_weaker_ks9_predicate() {
        // There is no NE runtime here, so the socket-set half of KS-9(1) is not
        // available. Named, and reported by the start sequence as a degradation.
        let config = AgentConfig::defaults();
        assert!(!config.enforcement().ks9_complete());
        assert!(matches!(
            config.enforcement().exempt,
            twinvpn_platform_macos::ExemptPredicate::UidOnly { .. }
        ));
    }

    #[test]
    fn the_keychain_row_is_adr_0020s_developer_id_daemon_row() {
        let spec = AgentConfig::defaults().keychain();
        assert_eq!(spec.accessibility, Accessibility::SystemKeychain);
        assert!(!spec.accessibility.uses_data_protection_keychain());
        assert!(spec.access_group.is_none(), "no app group on this row");
        assert!(!spec.synchronizable(), "Tier 1 never syncs");
    }

    #[test]
    fn the_defaults_are_the_paths_the_adrs_name() {
        let config = AgentConfig::defaults();
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
    fn the_read_back_is_the_only_thing_that_can_set_the_reclaim_probe() {
        // W-24: a flag set after a load returned `Ok` is not an assertion. The
        // only mutator here takes an `Assertion`, and an assertion that supports
        // neither posture leaves the probe false.
        let mut probes = DarwinProbes::new(AgentConfig::defaults());
        assert!(!start::StartProbes::enforcement_read_back(&probes));
        probes.with_read_back(&twinvpn_platform_macos::pfread::Assertion {
            status: twinvpn_platform_macos::pfread::PfStatus::Disabled,
            installed: None,
        });
        assert!(
            !start::StartProbes::enforcement_read_back(&probes),
            "a disabled filter supports no assertion"
        );
    }
}
