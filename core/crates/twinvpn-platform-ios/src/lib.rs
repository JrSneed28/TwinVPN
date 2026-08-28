//! `twinvpn-platform-ios` — the iOS/iPadOS implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6, §11.2 row 2.5, §11.9 row 1, §11.12, §11.13,
//! CB-1…CB-7, DP-4; `docs/networking.md` §5.1, §5.2's iOS row, §5.4, §5.5;
//! ADR-0010, ADR-0011, ADR-0012, ADR-0016, ADR-0020, ADR-0022;
//! `docs/implementation/ownership.md` §10.
//!
//! **Owner:** `mobile-ios`.
//!
//! # Which surface a Swift shell binds, and why it is this crate
//!
//! `ownership.md` §8's **W-24** and **W-25** record that `twinvpn.h`'s F-9 vtable
//! has **no** `installed_ruleset` read-back, **no** `current_generation`, **no**
//! socket provider and **no** interface enumerator, so a shell bound only to that
//! ABI "cannot do NAT traversal and cannot produce a `ProtectionAssertion` at
//! all". `shells/linux` escapes by linking its adapter as a Rust crate; Swift
//! cannot link a Rust crate.
//!
//! §10.4's ruling for wave 3 is that the missing capabilities stay **in Rust,
//! in-process**, here, and Swift reaches them through [`bridge`] — internal
//! linkage, versionless, no compatibility obligation:
//!
//! | Capability | `twinvpn.h` F-9 | this crate |
//! |---|---|---|
//! | sockets (the NAT ladder) | **absent** (W-25) | [`sock`] |
//! | interface enumeration and events | **absent** (W-25) | [`iface`] |
//! | `installed_ruleset` read-back | **absent** (W-24) | [`netcfg::IosNetworkConfig::read_installed`] |
//! | `current_generation` | **absent** (W-24) | [`netcfg`] |
//! | `set_mtu`, `datapath`, `enforcement_custody`, `supported_families` | absent | present |
//! | `identity_agree` | absent from §11.4's struct (W-26) | [`custody`] |
//! | `ElapsedClock`, `Entropy`, `BootIdSource` | absent (W-7) | [`clock`] |
//!
//! # Where `unsafe` and `#[cfg]` live
//!
//! `ownership.md` §10.3: "`#[cfg]` is confined to the thinnest syscall shim, and
//! everything a reviewer would want to see exercised runs its tests on this Linux
//! host." That rule is why this crate has the shape it does.
//!
//! | Module | `#[cfg(target_os)]` | `unsafe` blocks | Tests run on the build host |
//! |---|---|---|---|
//! | [`oserr`], [`settings`], [`enforce`], [`pathmon`], [`keychain`], [`lifecycle`], [`cmsg`], [`sockplan`], [`shutdown`] | none | none | **yes** |
//! | [`netcfg`], [`tun`], [`custody`], [`iface`], [`host`] | none | none | **yes** |
//! | [`sock`] | one, on the option apply | 1 (`setsockopt`) | yes, for everything but the apply |
//! | [`bridge`] | none | 5 (pointer marshalling, each with a `// SAFETY:`) | yes |
//! | [`sys`] | **all of them** | 4 (`mach_continuous_time`, `mach_timebase_info`, `getentropy`, `sysctlbyname`) | absence is asserted |
//!
//! Every `unsafe` block carries a `// SAFETY:` comment naming its invariant.
//!
//! # What this crate is honest about
//!
//! - **Enforcement does not survive a core exit** ([`enforce::custody`]).
//!   ADR-0012 gives iOS `◐` and the seam's `bool` cannot say `◐`; O-18 fixes
//!   which way it rounds.
//! - **There is no boot-time enforcement** ([`enforce::EnforcementLimits`]), and
//!   the attach-to-arm window is **measured** ([`enforce::AttachToArm`]), never
//!   assumed to be zero.
//! - **The record AEAD is core-held** ([`custody::IosSecureStore`]), because the
//!   Secure Enclave has no arbitrary-length AEAD over caller data (CB-6a).
//! - **`identity_agree` refuses X25519** and substitutes nothing (ADR-0007 N-5).
//! - **`device_id` cannot be derived here** — see [`custody`]'s finding.
//! - **A route metric and a firewall mark are unrepresentable** and say so
//!   ([`settings::SettingsResidual`], [`sockplan::OptionResidual`]).

// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else
// outside the sibling adapter crates. Every `unsafe` block MUST carry a
// `// SAFETY:` comment stating the invariant it relies on.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::sync::Arc;

use twinvpn_platform::{
    IdentityCustody, InterfaceProvider, NetworkConfig, PlatformAdapter, PlatformError, SecureStore,
    SocketProvider, TunnelDevice,
};

pub mod bridge;
pub mod clock;
pub mod cmsg;
pub mod custody;
pub mod enforce;
pub mod host;
pub mod iface;
pub mod keychain;
pub mod lifecycle;
pub mod netcfg;
pub mod oserr;
pub mod pathmon;
pub mod settings;
pub mod shutdown;
pub mod sock;
pub mod sockplan;
pub mod sys;
pub mod tun;

pub use clock::{ClockPosture, ContinuousElapsedClock, KernBootTimeId, SystemEntropy};
pub use custody::{AbsentElement, EnclaveElement, IdentityRecord, SecureElement};
pub use enforce::{EnforcementLimits, EnforcementPosture};
pub use host::{DetachedHost, HostStatus, ProviderHost};
pub use keychain::KeychainConfig;
pub use netcfg::AppliedSettings;
pub use shutdown::ShutdownLatch;

/// The name prefix every TwinVPN overlay interface carries on this platform.
///
/// `is_overlay` is answered by this prefix and not by a link *kind*: on Darwin
/// every `NEPacketTunnelProvider` — including another vendor's — presents as a
/// `utun` interface of type `other`, so treating the kind as ours would make
/// ADR-0012's interface-scoped reasoning cover somebody else's tunnel.
pub const OVERLAY_PREFIX: &str = "utun";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "ios-networkextension";

/// Everything the adapter takes at construction.
///
/// **CD-2: no global, no `OnceCell`, no ambient default, and nothing discovered
/// from the environment.** In particular the Keychain access group and the App
/// Group container come from the signed App ID and are injected; an adapter that
/// read either from the environment would be reading a value an attacker on the
/// device can influence.
pub struct IosAdapterParts {
    /// The Swift provider, or [`DetachedHost`] before one registers.
    pub host: Arc<dyn ProviderHost>,
    /// Where Tier-1 items live (CB-7, ADR-0020 §11.3's iOS row).
    pub keychain: KeychainConfig,
    /// The enforcement posture the core computed (ADR-0012).
    pub enforcement: EnforcementPosture,
    /// The tunnel remote address the settings object is constructed with.
    pub tunnel_remote_address: String,
    /// The identity element. [`AbsentElement`] on a simulator, which reports
    /// `hardware_backed: false` truthfully and refuses rather than substituting a
    /// software signer (§11.16 (l)).
    pub identity_element: Arc<dyn SecureElement>,
}

impl IosAdapterParts {
    /// Parts bound to whatever Swift has registered, with the Secure Enclave as
    /// the element.
    ///
    /// Falls back to [`DetachedHost`] and [`AbsentElement`] when nothing is
    /// registered, so "no provider is running" is a state with a name rather than
    /// a null dereference.
    #[must_use]
    pub fn from_registered_bridge(
        keychain: KeychainConfig,
        enforcement: EnforcementPosture,
        tunnel_remote_address: impl Into<String>,
    ) -> Self {
        let host: Arc<dyn ProviderHost> = bridge::registered_host()
            .map_or_else(|| Arc::new(DetachedHost) as Arc<dyn ProviderHost>, |h| h);
        let identity_element: Arc<dyn SecureElement> = if host.enclave_hardware_backed() {
            Arc::new(EnclaveElement::new(host.clone(), keychain.clone()))
        } else {
            Arc::new(AbsentElement)
        };
        Self {
            host,
            keychain,
            enforcement,
            tunnel_remote_address: tunnel_remote_address.into(),
            identity_element,
        }
    }
}

/// The iOS/iPadOS platform adapter.
///
/// One object implementing all six capabilities, which is what lets the core
/// state *which* adapter it is talking to (S-47): "a core that assembled its
/// platform from six independently-supplied pieces could not state which adapter
/// it was talking to."
pub struct IosPlatformAdapter {
    shutdown: ShutdownLatch,
    sockets: sock::IosSocketProvider,
    tunnel: tun::IosTunnelDevice,
    network: netcfg::IosNetworkConfig,
    interfaces: iface::IosInterfaceProvider,
    identity: custody::IosIdentityCustody,
    store: custody::IosSecureStore,
}

impl IosPlatformAdapter {
    /// Builds the adapter.
    #[must_use]
    pub fn new(parts: IosAdapterParts) -> Self {
        let shutdown = ShutdownLatch::new();
        let applied_settings = AppliedSettings::default();
        let observed = pathmon::ObservedPath::default();
        Self {
            sockets: sock::IosSocketProvider::new(shutdown.clone()),
            tunnel: tun::IosTunnelDevice::new(
                parts.host.clone(),
                shutdown.clone(),
                applied_settings.clone(),
            ),
            network: netcfg::IosNetworkConfig::new(
                parts.host.clone(),
                shutdown.clone(),
                parts.enforcement,
                parts.tunnel_remote_address,
                applied_settings,
                observed.clone(),
            ),
            interfaces: iface::IosInterfaceProvider::new(
                parts.host.clone(),
                shutdown.clone(),
                observed,
            ),
            identity: custody::IosIdentityCustody::new(parts.identity_element, shutdown.clone()),
            store: custody::IosSecureStore::new(parts.host, parts.keychain, shutdown.clone()),
            shutdown,
        }
    }

    /// The concrete tunnel device, for the shell's own packet pump.
    ///
    /// The trait hides the batch shape, but PB-1's budget is *per batch*, and a
    /// pump driving [`tun::IosTunnelDevice::read_batch`] and
    /// [`tun::IosTunnelDevice::write_batch`] is what meets it.
    #[must_use]
    pub const fn tunnel_device(&self) -> &tun::IosTunnelDevice {
        &self.tunnel
    }

    /// The concrete network configuration, for the W-24 read-back.
    #[must_use]
    pub const fn network(&self) -> &netcfg::IosNetworkConfig {
        &self.network
    }

    /// The concrete interface provider, so the bridge can push path updates.
    #[must_use]
    pub const fn interface_provider(&self) -> &iface::IosInterfaceProvider {
        &self.interfaces
    }

    /// The concrete identity custody, so the composition root can supply the
    /// identifiers this crate may not derive (see [`custody`]).
    #[must_use]
    pub const fn identity_custody(&self) -> &custody::IosIdentityCustody {
        &self.identity
    }

    /// Whether the adapter has begun shutting down.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_shutting_down()
    }

    /// The health facts a shell reports at startup, so a degraded posture is
    /// **declared** rather than discovered by a user.
    ///
    /// ADR-0016 PS-17's principle: "Silently running wider than declared is the
    /// defect this rule retires." None of these is a decision this adapter makes.
    #[must_use]
    pub fn posture(&self) -> AdapterPosture {
        AdapterPosture {
            enforcement: EnforcementLimits::ios(),
            clocks: ClockPosture::probe(),
            sockets: self.sockets.posture(),
            hardware_backed_identity: self.identity.element_name() != "absent",
            provider_attached: !matches!(
                self.network.read_installed(),
                Err(PlatformError::AdapterUnavailable(_))
            ),
        }
    }
}

/// What the adapter can and cannot do on this build and this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPosture {
    /// What ADR-0012's iOS row structurally cannot enforce.
    pub enforcement: EnforcementLimits,
    /// Whether W-7's three capabilities are reachable.
    pub clocks: ClockPosture,
    /// Whether the NAT ladder's socket options were applied.
    pub sockets: sock::SocketPosture,
    /// Whether the identity element is genuinely hardware-backed (§11.16 (l)).
    ///
    /// Kept separate from every other field because "this device has a Secure
    /// Enclave and this build cannot use it" and "this is a simulator" have
    /// different remediations.
    pub hardware_backed_identity: bool,
    /// Whether a Swift provider has registered through [`bridge`].
    pub provider_attached: bool,
}

impl PlatformAdapter for IosPlatformAdapter {
    fn sockets(&self) -> &dyn SocketProvider {
        &self.sockets
    }

    fn tunnel(&self) -> &dyn TunnelDevice {
        &self.tunnel
    }

    fn network_config(&self) -> &dyn NetworkConfig {
        &self.network
    }

    fn interfaces(&self) -> &dyn InterfaceProvider {
        &self.interfaces
    }

    fn identity(&self) -> &dyn IdentityCustody {
        &self.identity
    }

    fn store(&self) -> &dyn SecureStore {
        &self.store
    }

    fn binding_name(&self) -> &'static str {
        BINDING_NAME
    }

    fn begin_shutdown(&self) {
        // Sets the latch and does **nothing else**. CB-6 puts the installed
        // ruleset in the OS's custody precisely so the core going away does not
        // drop protection, and on this platform the point is sharper than
        // elsewhere: ADR-0012's durability table already gives iOS only `◐`
        // across a provider kill, and a teardown on the way out would make it
        // `✘`. Nothing on this path touches the settings object, the on-demand
        // rules or `includeAllNetworks`.
        self.shutdown.begin();
    }
}

/// The error a shell reports when the adapter cannot be used at all.
///
/// Not a new type: the seam already has one, and adding a second failure
/// vocabulary at the shell boundary is how a `reason_code` gets lost.
pub type AdapterError = PlatformError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::RecordingHost;

    fn parts() -> IosAdapterParts {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios/AppGroup"));
        let keychain = KeychainConfig::new("ABCDE12345.group.com.twinvpn", "com.twinvpn.client")
            .expect("config");
        IosAdapterParts {
            identity_element: Arc::new(EnclaveElement::new(host.clone(), keychain.clone())),
            host,
            keychain,
            enforcement: EnforcementPosture::default(),
            tunnel_remote_address: "100.64.0.1".to_owned(),
        }
    }

    #[test]
    fn the_adapter_names_itself_so_s46_records_which_binding_was_loaded() {
        assert_eq!(
            IosPlatformAdapter::new(parts()).binding_name(),
            "ios-networkextension"
        );
    }

    #[test]
    fn one_object_carries_all_six_capabilities() {
        // S-47: "a core that assembled its platform from six
        // independently-supplied pieces could not state which adapter it was
        // talking to".
        let adapter = IosPlatformAdapter::new(parts());
        let _ = adapter.sockets();
        let _ = adapter.tunnel();
        let _ = adapter.network_config();
        let _ = adapter.interfaces();
        let _ = adapter.identity();
        let _ = adapter.store();
    }

    #[test]
    fn begin_shutdown_latches_and_touches_nothing_else() {
        let adapter = IosPlatformAdapter::new(parts());
        assert!(!adapter.is_shutting_down());
        adapter.begin_shutdown();
        assert!(adapter.is_shutting_down());
        // Idempotent, and callable from any thread.
        adapter.begin_shutdown();
        assert!(adapter.is_shutting_down());
        // The custody declaration is unchanged: the OS still holds the capture
        // half, and the swap is still atomic.
        assert!(
            adapter
                .network_config()
                .enforcement_custody()
                .swap_is_atomic
        );
    }

    #[test]
    fn the_posture_declares_every_platform_limit_rather_than_hiding_one() {
        let adapter = IosPlatformAdapter::new(parts());
        let posture = adapter.posture();
        // ADR-0012's iOS limitation row, as data.
        assert!(!posture.enforcement.boot_enforcement_available);
        assert!(!posture.enforcement.host_firewall_available);
        assert!(!posture.enforcement.per_app_tier_available);
        assert!(posture.enforcement.os_exempted_system_traffic);
        // W-7's three capabilities are absent on the build host, and the posture
        // says so rather than a caller discovering it from a zero reading.
        assert_eq!(
            posture.clocks.elapsed_clock_available,
            cfg!(target_os = "ios")
        );
        assert_eq!(
            posture.sockets.platform_options_applied,
            cfg!(target_os = "ios")
        );
        assert!(posture.hardware_backed_identity);
    }

    #[test]
    fn a_simulator_reports_no_hardware_backing_and_substitutes_nothing() {
        // §11.16 (l): "the core MUST NOT substitute a file-backed signer
        // silently."
        let mut parts = parts();
        parts.identity_element = Arc::new(AbsentElement);
        let adapter = IosPlatformAdapter::new(parts);
        assert!(!adapter.posture().hardware_backed_identity);
    }

    #[test]
    fn the_overlay_prefix_is_ours_and_is_not_a_link_kind() {
        // Every NEPacketTunnelProvider on Darwin presents as a `utun` of type
        // `other`, including another vendor's.
        assert_eq!(OVERLAY_PREFIX, "utun");
    }

    #[test]
    fn a_detached_bridge_yields_an_absent_element_and_a_named_state() {
        bridge::twinvpn_ios_bridge_unregister();
        let keychain = KeychainConfig::new("ABCDE12345.group.com.twinvpn", "com.twinvpn.client")
            .expect("config");
        let parts = IosAdapterParts::from_registered_bridge(
            keychain,
            EnforcementPosture::default(),
            "100.64.0.1",
        );
        let adapter = IosPlatformAdapter::new(parts);
        assert!(!adapter.posture().hardware_backed_identity);
        assert!(!adapter.posture().provider_attached);
    }
}
