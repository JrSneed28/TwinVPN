//! `twinvpn-platform-windows` — the Windows implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5,
//! CB-1, CB-2, CB-3, CB-5, CB-6, CB-6a, CB-7, CD-2, CD-3, DP-4;
//! `docs/application-architecture.md` §7's Windows row (HC-1, `TwinVPNService`
//! under LocalSystem with trimmed privileges, a WFP sublayer with persistent and
//! boot-time filters, a named pipe with an explicit DACL, MSI + Authenticode EV);
//! ADR-0010, ADR-0011, ADR-0012, ADR-0016, ADR-0020, ADR-0022 LC-8.
//!
//! **Owner:** `desktop-windows`.
//!
//! # The one thing to know before reading this crate
//!
//! **It was written on a Linux host and has never been linked or run.**
//! `make cross-check` type-checks it against the real `windows-sys` for
//! `x86_64-pc-windows-msvc` with `-D warnings`, which is a genuine compile proof
//! and is not a behaviour proof. The crate is therefore laid out so that the
//! largest possible share of its behaviour is **target-free and host-testable**,
//! and so that the part which genuinely cannot be is as small and as obvious as
//! possible.
//!
//! | Layer | Target-free | Where |
//! |---|---|---|
//! | what a Windows status *means* | yes | [`oserr`] |
//! | which filters a contract implies | yes | [`wfp::filters`] |
//! | what the engine's own answer says is installed | yes | [`wfp::readback`] |
//! | the leak canary's arithmetic | yes | [`wfp::canary`] |
//! | the KS-19 boot artifact, and its verification | yes | [`wfp::boot`] |
//! | which route rows a contract implies, and their rollback | yes | [`route`] |
//! | which NRPT rules and interface settings a `DnsConfig` implies | yes | [`dns`] |
//! | the DN-18 restore point, on disk and back | yes | [`restore`] |
//! | the transactional apply/rollback/reconcile state machine | yes | [`netcfg`] |
//! | socket options as a programme | yes | [`sock`] |
//! | interface-change decoding and `LinkClass` | yes | [`iface`] |
//! | custody classes and the store root's attributes | yes | [`custody`] |
//! | **the syscall shim** | **no** | [`sys`] |
//!
//! Every trait in [`sys`] has an in-memory implementation behind the
//! `test-support` feature, which is what lets the layers above it be exercised
//! end to end on this host. `WindowsPlatformAdapter::new` constructs the **real**
//! shim and there is no path by which a fake reaches a production build.
//!
//! # CB-3 and DP-4
//!
//! This crate is on the `unsafe` allowlist and is one of the few permitted
//! `#[cfg(target_os)]`. It uses both only inside `sys::win`, and every `unsafe`
//! block there carries a `// SAFETY:` comment naming its invariant. Everything
//! else in the crate is safe, portable Rust.
//!
//! # CD-3, and W-36
//!
//! [`clock`] names `QueryUnbiasedInterruptTimePrecise`,
//! `QueryInterruptTimePrecise` and `BCryptGenRandom`. The first two are on
//! `core/xtask/src/checks.rs`'s `CD3_PLATFORM_PRIMITIVES` list, which
//! `cd3_crate_may_read_platform_primitives` permits in a `twinvpn-platform-*`
//! crate — the exemption W-36 established for exactly this. What stays denied
//! even here is `Instant::now`, `SystemTime::now`, `tokio::time` and `chrono`,
//! and none of them appears in this crate.

// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else
// outside the two sibling adapter crates. Every `unsafe` block MUST carry a
// `// SAFETY:` comment stating the invariant it relies on.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod clock;
pub mod custody;
pub mod dns;
pub mod iface;
pub mod netcfg;
pub mod oserr;
pub mod power;
pub mod restore;
pub mod route;
pub mod shutdown;
pub mod sock;
pub mod sys;
pub mod wfp;
pub mod wintun;

pub use shutdown::ShutdownLatch;
pub use wfp::{EnforcementConfig, FilterSet, Ruleset};

/// The name prefix every TwinVPN overlay adapter carries.
///
/// `is_overlay` is answered by this prefix and not by the adapter's driver
/// identity: a Wintun adapter created by another product is a third party's, and
/// treating it as ours would make ADR-0012's Tier-2 interface-scoped permit
/// authorise somebody else's tunnel.
pub const OVERLAY_PREFIX: &str = "TwinVPN";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "windows-wfp";

use std::sync::Arc;

use twinvpn_platform::{
    IdentityCustody, InterfaceProvider, NetworkConfig, PlatformAdapter, PlatformError, SecureStore,
    SocketProvider, TunnelDevice,
};

/// Everything the adapter takes at construction. **CD-2: no global, no
/// `OnceCell`, no ambient default, and nothing discovered from the environment.**
pub struct WindowsAdapterParts {
    /// The enforcement facts the seam does not carry — see
    /// [`wfp::EnforcementConfig`], every field of which is a reported gap.
    pub enforcement: wfp::EnforcementConfig,
    /// The stub's four listening addresses (ADR-0011 §11.2's Windows row).
    pub stub: dns::StubAddresses,
    /// The vault directory, **injected, never discovered** (CB-7, CD-2).
    ///
    /// `%ProgramData%\TwinVPN\store\` in production, created by the MSI with
    /// ADR-0020 §11.9's ACL. A path the *service* discovered would be a path an
    /// attacker who could set an environment variable could move.
    pub store_root: std::path::PathBuf,
    /// Where the DN-18 resolver restore point is written.
    ///
    /// Readable by the package-owned restore service with the agent absent
    /// (ADR-0011 DN-20), which is why it is a path rather than an in-memory
    /// value.
    pub restore_point_path: std::path::PathBuf,
    /// The identity element. [`custody::AbsentElement`] on a host with none,
    /// which reports `hardware_backed: false` truthfully and refuses rather than
    /// substituting a file-backed signer (ADR-0018 §11.16 (l)).
    pub identity_element: Arc<dyn custody::SigningElement>,
    /// Which CNG backing a live probe found (ADR-0020 ST-9).
    pub tier1_backend: custody::Tier1Backend,
    /// The Wintun driver, loaded dynamically because ADR-0016 §10 puts the
    /// driver's lifecycle with the installer.
    pub tunnel_driver: Arc<dyn wintun::TunnelDriver>,
}

/// The Windows platform adapter.
///
/// One object implementing all six capabilities, which is what lets the core
/// state *which* adapter it is talking to (S-47): "a core that assembled its
/// platform from six independently-supplied pieces could not state which adapter
/// it was talking to".
pub struct WindowsPlatformAdapter {
    shutdown: ShutdownLatch,
    sockets: sock::WindowsSocketProvider,
    tunnel: wintun::WindowsTunnelDevice,
    network: netcfg::WindowsNetworkConfig,
    interfaces: iface::WindowsInterfaceProvider,
    identity: custody::WindowsIdentityCustody,
    store: custody::WindowsSecureStore,
    element_name: &'static str,
    tier1_backend: custody::Tier1Backend,
    store_root: std::path::PathBuf,
}

impl WindowsPlatformAdapter {
    /// Builds the adapter over the **real** Windows system.
    ///
    /// `#[cfg(windows)]`, and there is deliberately no host counterpart: a
    /// constructor that could bind an in-memory enforcement engine on a real
    /// host would be a way to install a ruleset that lives in a `HashMap`, which
    /// is exactly the belief ADR-0012 K12 forbids. The test double is reached
    /// through [`Self::with_system`], which is feature-gated.
    ///
    /// # Errors
    ///
    /// Whatever `FwpmEngineOpen0` refused with. **Fallible on purpose**:
    /// ADR-0016 PS-18 makes an absent capability a *startup* failure rather than
    /// a degradation, and ADR-0012 §8 says arming must never fail open. An
    /// infallible constructor would defer the refusal to the first call and let
    /// the service report itself running in a mode that cannot arm enforcement,
    /// which is the state PS-18 exists to forbid.
    #[cfg(windows)]
    pub fn new(parts: WindowsAdapterParts) -> Result<Self, PlatformError> {
        // The latch is built first so the system and every capability share
        // one: a shutdown that did not reach the interface provider would leave
        // an in-flight enumeration running past `begin_shutdown`.
        let shutdown = ShutdownLatch::new();
        let system: Arc<dyn sys::SystemOps> =
            Arc::new(sys::win::WindowsSystem::open(shutdown.clone())?);
        Ok(Self::assemble_with(parts, system, shutdown))
    }

    /// Builds the adapter over a supplied system.
    ///
    /// Behind `test-support`, which is what keeps it out of a production build.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_system(parts: WindowsAdapterParts, system: Arc<dyn sys::SystemOps>) -> Self {
        Self::assemble_with(parts, system, ShutdownLatch::new())
    }

    // Reachable from exactly two constructors: [`Self::new`] on Windows and
    // [`Self::with_system`] under `test-support`. On a host that is neither —
    // an ordinary `cargo build` of this crate on Linux — the adapter cannot be
    // assembled at all, which is the honest shape: there is no Windows system
    // here to bind, and a build that produced one would be producing a fiction.
    #[cfg(any(windows, test, feature = "test-support"))]
    fn assemble_with(
        parts: WindowsAdapterParts,
        system: Arc<dyn sys::SystemOps>,
        shutdown: ShutdownLatch,
    ) -> Self {
        let element_name = parts.identity_element.name();
        let tier1_backend = parts.tier1_backend;
        let store_root = parts.store_root.clone();
        // The network configuration owns the overlay LUID, and the tunnel device
        // is the only thing that learns it. Built in this order so there is ONE
        // cell: the device publishes what it created, and every filter, route and
        // NRPT rule keys on that instead of on the `0` a shell has to inject
        // before the adapter exists.
        let network = netcfg::WindowsNetworkConfig::new(netcfg::NetworkConfigParts {
            system,
            enforcement: parts.enforcement,
            stub: parts.stub,
            restore_point_path: parts.restore_point_path,
            shutdown: shutdown.clone(),
        });
        Self {
            sockets: sock::WindowsSocketProvider::new(shutdown.clone()),
            tunnel: wintun::WindowsTunnelDevice::new(
                parts.tunnel_driver,
                shutdown.clone(),
                network.overlay_luid(),
            ),
            network,
            interfaces: iface::WindowsInterfaceProvider::new(shutdown.clone()),
            identity: custody::WindowsIdentityCustody::new(
                parts.identity_element,
                shutdown.clone(),
            ),
            store: custody::WindowsSecureStore::new(
                parts.store_root,
                tier1_backend,
                shutdown.clone(),
            ),
            shutdown,
            element_name,
            tier1_backend,
            store_root,
        }
    }

    /// The concrete network configuration, for the shell's own start sequence.
    ///
    /// The trait deliberately hides the read-back, because `twinvpn.h`'s F-9
    /// vtable has no getter (W-24) — but the shell needs
    /// [`netcfg::WindowsNetworkConfig::reclaim`] and
    /// [`netcfg::WindowsNetworkConfig::assert_protection`] to discharge ADR-0016
    /// §11.6 step (2), and rediscovering them through the trait is not possible.
    /// This is why `shells/windows` links this crate directly rather than
    /// binding the C ABI.
    #[must_use]
    pub const fn network(&self) -> &netcfg::WindowsNetworkConfig {
        &self.network
    }

    /// The concrete tunnel device, for the same reason: the shell's bring-up
    /// needs the adapter's LUID to tell [`netcfg`] which link to program, and
    /// rediscovering it by name would turn a rename into a route on the wrong
    /// interface.
    #[must_use]
    pub const fn tunnel_device(&self) -> &wintun::WindowsTunnelDevice {
        &self.tunnel
    }

    /// The concrete secure store, so the shell can prepare the vault directory
    /// before the core asks for it.
    #[must_use]
    pub const fn secure_store(&self) -> &custody::WindowsSecureStore {
        &self.store
    }

    /// Whether the adapter has begun shutting down.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_shutting_down()
    }

    /// The health facts a shell reports at startup, so a degraded posture is
    /// **declared** rather than discovered by a user.
    ///
    /// Each is a fact the shell turns into a log line and a diagnostic-bundle
    /// field; none of them is a decision this adapter makes.
    #[must_use]
    pub fn posture(&self) -> AdapterPosture {
        AdapterPosture {
            custody_class: self.tier1_backend.custody_class(),
            hardware_backed_identity: matches!(
                self.tier1_backend,
                custody::Tier1Backend::PlatformCryptoProvider { .. }
            ),
            identity_element: self.element_name,
            record_aead_custody: self.store.record_aead_custody(),
            store_root_prepared: custody::store_root_prepared(&self.store_root),
        }
    }
}

/// What the adapter can and cannot do on this host.
///
/// Declared at startup, never inferred later. ADR-0016 PS-17: "If any directive
/// in this table fails to apply … the authority MUST emit
/// `PLATFORM.PRIV.SANDBOX_DEGRADED` … Silently running wider than declared is
/// the defect this rule retires." The same principle applied to the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPosture {
    /// The custody class a live probe justifies (ADR-0020 §11.4).
    pub custody_class: custody::CustodyClass,
    /// Whether the identity's private half is genuinely element-resident.
    ///
    /// Distinct from `custody_class` on purpose: "this host has a TPM and this
    /// build could not attest it" and "this host has no TPM" are different facts
    /// with different remediations, and a single class would collapse them.
    pub hardware_backed_identity: bool,
    /// Which element is bound — `"cng-pcp"`, `"cng-software"` or `"absent"`.
    pub identity_element: &'static str,
    /// Who performs the record AEAD (CB-6a).
    pub record_aead_custody: twinvpn_platform::RecordAeadCustody,
    /// Whether the vault directory exists with its attributes applied.
    pub store_root_prepared: bool,
}

impl PlatformAdapter for WindowsPlatformAdapter {
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
        // ruleset in the Base Filtering Engine's custody precisely so the core
        // going away does not drop protection, and ADR-0022 §11.4's Windows row
        // says it again: "shutdown MUST NOT remove enforcement — persistent WFP
        // filters stay". Nothing on this path touches the filters, the routes or
        // the NRPT rules.
        self.shutdown.begin();
    }
}

/// The error a shell reports when the adapter cannot be used at all.
///
/// Not a new type: the seam already has one, and adding a second failure
/// vocabulary at the shell boundary is how a `reason_code` gets lost.
pub type AdapterError = PlatformError;
