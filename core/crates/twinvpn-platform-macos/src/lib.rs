//! `twinvpn-platform-macos` — the macOS/Darwin implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5,
//! CB-1, CB-2, CB-3, CB-5, CB-6, CB-6a, CB-7, DP-4; `docs/networking.md` §5.1
//! (the adapter contract); `docs/application-architecture.md` §7 (the macOS row:
//! HC-1, "NE **system extension** + minimal `LaunchDaemon`", "pf anchor from
//! `/etc/pf.conf`, daemon-applied", "Unix socket / XPC", "Developer ID +
//! notarized, stapled"); ADR-0010, ADR-0011, ADR-0012, ADR-0016, ADR-0020,
//! ADR-0022 LC-8.
//!
//! **Owner:** `desktop-macos`.
//!
//! # The one thing to read first
//!
//! **This crate was written on a Linux host, and roughly half of it has never
//! run.** The split is deliberate and it is drawn here rather than left to a
//! reader to work out:
//!
//! | Layer | Modules | Compiled for Darwin | **Executed** |
//! |---|---|---|---|
//! | translation — pure data in, pure data out | [`pf`], [`pfread`], [`route`], [`nesettings`], [`resolver`], [`rtmsg`], [`power`], [`oserr`], [`addr`], [`clock`]'s timebase arithmetic | yes | **yes, on Linux, by `cargo test`** |
//! | transaction — apply / rollback / posture swap over injected carriers | [`netcfg`] | yes | **yes**, against recording carriers |
//! | framing — the `utun` 4-byte header, the socket option plan | [`utun`], [`sock`] | yes | partly |
//! | syscalls — `PF_SYSTEM`, `PF_ROUTE`, `SCDynamicStore`, Keychain, IOKit, mach | the `#[cfg(target_os = "macos")]` halves of [`utun`], [`iface`], [`custody`], [`clock`], [`sys`] | yes | **no** |
//!
//! Nothing links and nothing runs against a Darwin kernel here.
//! `make cross-check` is a **compile proof and never a behaviour proof**, and this
//! crate is arranged so that the compile-only fraction is as small as the
//! architecture permits.
//!
//! # CB-3, and the `cfg` budget
//!
//! `cargo run -p xtask -- lint` exempts `twinvpn-platform-*` from the
//! no-`target_os` rule, so this crate *may* branch on OS. It does so in as few
//! places as possible, and never above a syscall: every decision, every rendering
//! and every parse is target-free, and `#[cfg(target_os = "macos")]` appears only
//! where the alternative is a syscall the core cannot make.
//!
//! # CD-3, and the two mach clocks
//!
//! `CD3_PLATFORM_PRIMITIVES` permits `mach_absolute_time` and
//! `mach_continuous_time` **inside a `twinvpn-platform-*` crate and nowhere
//! else**, and still denies `Instant::now`, `SystemTime::now`,
//! `std::time::Instant`, `tokio::time` and `chrono` even here. ADR-0022 LC-8's
//! table is what makes the pair non-interchangeable:
//!
//! | Capability | Darwin primitive | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `mach_absolute_time` | **excluded** |
//! | `ElapsedClock` | `mach_continuous_time` | **included** |
//!
//! Getting them the wrong way round is the defect LC-8 says is invisible on Linux
//! CI. [`clock`] is where the pair is chosen once, with the reasoning beside it.
//!
//! # `unsafe`
//!
//! This crate is one of the three on the DP-4 allowlist. `unsafe` is permitted
//! here and appears only in the syscall shims; every block carries a `// SAFETY:`
//! comment naming the invariant it relies on, and
//! `#![deny(unsafe_op_in_unsafe_fn)]` is on.

// DP-4 unsafe allowlist member. Every `unsafe` block MUST carry a `// SAFETY:`
// comment stating the invariant it relies on.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod addr;
pub mod clock;
pub mod custody;
pub mod dynstore;
pub mod iface;
pub mod keychain;
pub mod nesettings;
pub mod netcfg;
pub mod oserr;
pub mod pf;
pub mod pfread;
pub mod power;
pub mod resolver;
pub mod route;
pub mod rtmsg;
pub mod shutdown;
pub mod sock;
pub mod sys;
pub mod utun;

#[doc(hidden)]
pub mod testkit;

use std::path::PathBuf;
use std::sync::Arc;

use twinvpn_platform::{
    IdentityCustody, InterfaceProvider, NetworkConfig, PlatformAdapter, PlatformError, SecureStore,
    SocketProvider, TunnelDevice,
};

pub use clock::{ContinuousElapsedClock, MachTimebase, SystemEntropy};
pub use custody::{
    AbsentElement, CustodyClass, KeychainItemSpec, MacosIdentityCustody, MacosSecureStore,
    SigningElement,
};
pub use netcfg::{MacosNetworkConfig, NetworkCarriers};
pub use pf::{EnforcementConfig, ExemptPredicate};
pub use route::RouteCarrier;
pub use shutdown::ShutdownLatch;
pub use utun::{TunnelProvenance, UTUN_CONTROL_NAME};

/// The name prefix every TwinVPN overlay interface carries on macOS.
///
/// `utun` and not `twin`: Darwin names the interfaces its `utun` control creates
/// and a caller does not get to pick the prefix. So `is_overlay` is answered by
/// **the handle this adapter created**, never by the name — a `utun` created by
/// another VPN is a third party's, and treating it as ours would make ADR-0012's
/// interface-scoped Tier-2 rule permit somebody else's tunnel. [`iface`] carries
/// the owned-index set that answers the question properly.
pub const OVERLAY_PREFIX: &str = "utun";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "macos-pf";

/// Everything the adapter takes at construction.
///
/// **CD-2: no global, no `OnceCell`, no ambient default, and nothing discovered
/// from the environment.**
pub struct MacosAdapterParts {
    /// The enforcement facts the seam does not carry — see
    /// [`pf::EnforcementConfig`], every field of which is a reported gap.
    pub enforcement: EnforcementConfig,
    /// Which carriers install routes, the resolver and the anchor on this
    /// binding. A **capability**, injected, never inferred from the OS.
    pub carriers: NetworkCarriers,
    /// Where the tunnel device comes from on this binding: the OS hands the
    /// provider a flow, or the daemon opens a `utun` itself.
    pub tunnel_provenance: TunnelProvenance,
    /// The vault directory, **injected, never discovered** (CB-7, CD-2).
    ///
    /// ADR-0020's macOS row: `/Library/Application Support/TwinVPN/`,
    /// `root:wheel`, `0700`, "the system extension / `launchd` daemon only".
    pub store_root: PathBuf,
    /// The identity element. [`AbsentElement`] on a host with none, which reports
    /// `hardware_backed: false` truthfully and refuses rather than substituting a
    /// file-backed signer (ADR-0018 §11.16 (l)).
    pub identity_element: Arc<dyn SigningElement>,
    /// The Keychain item shape Tier-1 items are written with (ADR-0020 §11.3).
    pub keychain: KeychainItemSpec,
}

/// The macOS platform adapter.
///
/// One object implementing all six capabilities, which is what lets the core
/// state *which* adapter it is talking to (S-47): "a core that assembled its
/// platform from six independently-supplied pieces could not state which adapter
/// it was talking to".
pub struct MacosPlatformAdapter {
    shutdown: ShutdownLatch,
    sockets: sock::MacosSocketProvider,
    tunnel: utun::MacosTunnelDevice,
    network: netcfg::MacosNetworkConfig,
    interfaces: iface::MacosInterfaceProvider,
    identity: custody::MacosIdentityCustody,
    store: custody::MacosSecureStore,
}

impl MacosPlatformAdapter {
    /// Builds the adapter.
    #[must_use]
    pub fn new(parts: MacosAdapterParts) -> Self {
        let shutdown = ShutdownLatch::new();
        Self {
            sockets: sock::MacosSocketProvider::new(shutdown.clone()),
            tunnel: utun::MacosTunnelDevice::new(shutdown.clone(), parts.tunnel_provenance),
            network: netcfg::MacosNetworkConfig::new(
                shutdown.clone(),
                parts.enforcement,
                parts.carriers,
            ),
            interfaces: iface::MacosInterfaceProvider::new(shutdown.clone()),
            identity: custody::MacosIdentityCustody::new(parts.identity_element, shutdown.clone()),
            store: custody::MacosSecureStore::new(
                parts.store_root,
                parts.keychain,
                shutdown.clone(),
            ),
            shutdown,
        }
    }

    /// The concrete tunnel device, for the shell's own bring-up sequence.
    ///
    /// The trait deliberately hides the OS handle, but the shell needs the
    /// interface's index to tell [`netcfg::MacosNetworkConfig`] which link to
    /// programme — and rediscovering it by name would turn a rename race into a
    /// route on the wrong link.
    #[must_use]
    pub const fn tunnel_device(&self) -> &utun::MacosTunnelDevice {
        &self.tunnel
    }

    /// The concrete network configuration, for the same reason.
    #[must_use]
    pub const fn network(&self) -> &netcfg::MacosNetworkConfig {
        &self.network
    }

    /// The concrete interface provider, so the shell can feed it the power events
    /// it receives from IOKit on its own run loop.
    #[must_use]
    pub const fn interface_provider(&self) -> &iface::MacosInterfaceProvider {
        &self.interfaces
    }

    /// The concrete secure store, so the shell can prepare the vault directory
    /// before the core asks for it.
    #[must_use]
    pub const fn secure_store(&self) -> &custody::MacosSecureStore {
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
    /// field; none of them is a decision this adapter makes. ADR-0016 PS-17: "if
    /// any directive in this table fails to apply … the authority MUST emit
    /// `PLATFORM.PRIV.SANDBOX_DEGRADED` … silently running wider than declared is
    /// the defect this rule retires."
    #[must_use]
    pub fn posture(&self) -> AdapterPosture {
        AdapterPosture {
            pfctl_present: netcfg::MacosNetworkConfig::pfctl_binary().is_ok(),
            route_binary_present: netcfg::MacosNetworkConfig::route_binary().is_ok(),
            ks9_complete: self.network.enforcement().ks9_complete(),
            custody_class: self.identity.custody_class(),
            datapath_is_os_provided: matches!(
                self.tunnel.provenance(),
                TunnelProvenance::OsProvidedFlow
            ),
        }
    }
}

/// What the adapter can and cannot do on this host.
///
/// Declared at startup, never inferred later.
// Four booleans and a class, and each is a distinct fact a shell reports on its
// own line. `pfctl_present` and `route_binary_present` in particular must stay
// separate: "this host cannot arm enforcement" and "this host cannot programme a
// route" have different remediations, and under the NE carrier the second is not
// needed at all. Collapsing them into a bitflags type would make exactly that
// distinction invisible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPosture {
    /// Whether `pfctl(8)` is present. Without it enforcement cannot be armed and
    /// the client MUST NOT enter a protected state (ADR-0012 §8).
    pub pfctl_present: bool,
    /// Whether `route(8)` is present. Only the `LaunchDaemon` carrier needs it;
    /// under `NEPacketTunnelNetworkSettings` the OS installs the routes.
    pub route_binary_present: bool,
    /// Whether KS-9(1)'s macOS predicate holds in **full** — the provider's uid
    /// *and* its socket set — or only in the weaker uid-alone form.
    pub ks9_complete: bool,
    /// The honest custody class of the identity key (ADR-0020's summary table).
    pub custody_class: CustodyClass,
    /// Whether the OS hands us the datapath (the NE provider) or we open a `utun`
    /// ourselves (the daemon). A **capability**, reported so the core need never
    /// ask which OS it is on.
    pub datapath_is_os_provided: bool,
}

impl PlatformAdapter for MacosPlatformAdapter {
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
        // drop protection, and a shutdown that removed the rules would defeat
        // that. Nothing on this path touches the pf anchor, the routes or the
        // resolver.
        self.shutdown.begin();
    }
}

/// The error a shell reports when the adapter cannot be used at all.
///
/// Not a new type: the seam already has one, and adding a second failure
/// vocabulary at the shell boundary is how a `reason_code` gets lost.
pub type AdapterError = PlatformError;
