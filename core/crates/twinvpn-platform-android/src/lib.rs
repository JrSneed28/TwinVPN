//! `twinvpn-platform-android` — the Android implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5,
//! §11.5's two Android rows, CB-1, CB-2, CB-3, CB-5, CB-6, CB-6a, CB-7, DP-4,
//! PB-1; `docs/networking.md` §5.1 (the adapter contract), §5.2's Android row,
//! §5.4, §5.5; ADR-0010, ADR-0011, ADR-0012, ADR-0019, ADR-0020, ADR-0022;
//! `docs/implementation/ownership.md` §10.
//!
//! **Owner:** `mobile-android`.
//!
//! # What this crate is for
//!
//! `docs/networking.md` §5.1: *"Every platform implements one interface.
//! Anything platform-specific lives behind it; nothing above it may branch on
//! OS."* This is the Android side of that line. It is one of the crates on the
//! DP-4 `unsafe` allowlist and one of the few permitted `#[cfg(target_os)]`
//! (CB-3), and it uses both privileges only where the alternative is a syscall
//! or a JNI call the core cannot make.
//!
//! # The design rule this crate is built to, and what it buys
//!
//! `ownership.md` §9.2, binding on wave 3 through §10.3: **every layer that can
//! be target-free is target-free.** The consequence is visible in the module
//! table below — the columns are what `make test` on a Linux host actually
//! exercises, and they are not a minority of the crate:
//!
//! | Module | What it holds | Runs on this host |
//! |---|---|---|
//! | [`builder`] | the `VpnService.Builder` **programme** rendered from a `NetworkContract` | **yes**, exhaustively |
//! | [`netchange`] | `ConnectivityManager.NetworkCallback` decoded and diffed into `NetworkChange` | **yes**, exhaustively |
//! | [`posture`] | the three-valued lockdown posture and the enforcement read-back | **yes**, exhaustively |
//! | [`power`] | Doze, thermal, standby, and the keepalive plan | **yes**, exhaustively |
//! | [`oserr`] | `errno` **and Java exception class** → `PlatformError` | **yes**, exhaustively |
//! | [`codes`] | the seventeen unregistered codes and their substitutions | **yes** |
//! | [`sock`] | UDP sockets, options, `recvmsg` + `cmsg`, the un-mapping | **yes**, over loopback |
//! | [`tun`] | the tun descriptor lifecycle and both packet directions | **yes**, over a `socketpair` |
//! | [`netcfg`] | `apply` / `rollback` / the KS-17 swap / link facts | **yes**, over a fake controller |
//! | [`custody`] | Keystore identity and Tier-1 storage | **yes**, over an in-memory element |
//! | [`clock`] | `CLOCK_BOOTTIME`, `/dev/urandom`, the boot identity | **yes** |
//! | [`iface`] | the change stream and its backpressure | **yes** |
//! | [`bridge::wire`] | the bridge's own encoding, and every bound on it | **yes**, exhaustively |
//! | [`bridge`] | the ingest entry points the JNI layer calls | **yes** |
//! | `bridge::jvm`, `bridge::entry` | the JNI symbols and the JVM-backed hostcalls | **no** — `cargo check` only |
//!
//! The two JVM submodules of [`bridge`] are the **only** thing behind
//! `#[cfg(target_os = "android")]`, and they contain no decision: they marshal
//! between the JVM and the two traits in [`hostcall`]. Everything the bridge
//! *decides* — how a payload is decoded, which bound refuses it, what it becomes
//! — is above that line and runs its tests here.
//!
//! # `ownership.md` §10.4, and what this crate exports beyond the trait
//!
//! W-24 and W-25 record that `twinvpn.h`'s F-9 vtable carries **no**
//! `installed_ruleset` read-back, **no** `current_generation`, **no** socket
//! provider and **no** interface enumerator, so a shell bound only to that
//! vtable cannot do NAT traversal and cannot produce a `ProtectionAssertion` at
//! all. §10.4 rules that on mobile those capabilities stay **in Rust,
//! in-process**, inside this crate:
//!
//! | Capability | `twinvpn.h` F-9 | this crate |
//! |---|---|---|
//! | sockets (the NAT ladder) | **absent** (W-25) | [`sock`] |
//! | interface enumeration and events | **absent** (W-25) | [`iface`] |
//! | `installed_ruleset` read-back | **absent** (W-24) | [`posture::EnforcementView`] |
//! | `current_generation` | **absent** (W-24) | [`netcfg`] |
//! | `set_mtu`, `datapath`, `enforcement_custody`, `supported_families` | absent | present |
//!
//! The Kotlin side reaches this crate through [`bridge`], which is **not** an
//! ABI of record, is **not** `twinvpn.h`, and carries **no TwinVPN domain
//! fact** — its vocabulary is Android's.
//!
//! # CB-3, honestly
//!
//! `#[cfg(target_os = "android")]` appears in exactly two places, both inside
//! [`bridge`]: the `jvm` and `entry` submodule declarations. Everything else
//! compiles for the host **and** for `aarch64-linux-android` from the same
//! source, which is what makes `make cross-check` a real gate on this crate
//! rather than a formality.

// DP-4 unsafe allowlist member. Every `unsafe` block MUST carry a `// SAFETY:`
// comment stating the invariant it relies on.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product nouns in prose, and a single uniform error type across the crate.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;
use std::sync::Arc;

use twinvpn_platform::{
    IdentityCustody, InterfaceProvider, NetworkConfig, PlatformAdapter, PlatformError, SecureStore,
    SocketProvider, TunnelDevice,
};

pub mod builder;
pub mod clock;
pub mod codes;
pub mod custody;
pub mod hostcall;
pub mod iface;
pub mod netcfg;
pub mod netchange;
pub mod oserr;
pub mod posture;
pub mod power;
pub mod shutdown;
pub mod sock;
pub mod tun;

pub mod bridge;

#[cfg(test)]
mod testkit;

pub use builder::{BuilderOp, Programme, VpnConfig};
pub use clock::{BootIdSourceKind, BootTimeElapsedClock, DerivedBootId, SystemEntropy};
pub use custody::{AbsentElement, AndroidIdentityCustody, AndroidSecureStore};
pub use hostcall::{KeystoreElement, RawFd, SecurityLevel, TunnelController};
pub use iface::AndroidInterfaceProvider;
pub use netcfg::AndroidNetworkConfig;
pub use netchange::{AndroidNetwork, Snapshot, TransportSet};
pub use posture::{EnforcementView, LockdownPosture};
pub use power::{KeepalivePlan, PowerSnapshot, StandbyBucket, ThermalStatus};
pub use shutdown::ShutdownLatch;
pub use sock::AndroidSocketProvider;
pub use tun::AndroidTunnelDevice;

/// The name prefix every TwinVPN overlay interface carries.
///
/// Android names the tun interface itself (`tun0`, `tun1`, …) and gives an app
/// no say in it, so this is the name the core *asks* for and not one the OS
/// honours. `is_overlay` is therefore answered from the recorded interface
/// index ([`AndroidInterfaceProvider::set_overlay`]) and **never** from a name
/// prefix: another product's `tun0` would otherwise be classified as ours.
pub const OVERLAY_PREFIX: &str = "twin";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "android-vpnservice";

/// Everything the adapter takes at construction.
///
/// **CD-2: no global, no `OnceCell`, no ambient default, and nothing discovered
/// from the environment.** Every field is something only the Android shell can
/// obtain, handed across once.
pub struct AndroidAdapterParts {
    /// The `VpnService`-side operations. [`bridge`] supplies the JNI-backed
    /// implementation; a test supplies its own.
    pub controller: Arc<dyn TunnelController>,
    /// The Keystore element. [`AbsentElement`] where it could not be opened,
    /// which reports `hardware_backed: false` truthfully and refuses rather than
    /// substituting a file-backed signer (§11.16 (l)).
    pub element: Arc<dyn KeystoreElement>,
    /// The vault directory, **injected, never discovered** (CB-7, CD-2).
    ///
    /// ADR-0020 §11's Android row: the default **credential-encrypted** context,
    /// created by the shell with `dataExtractionRules` already excluding it from
    /// both `<cloud-backup>` and `<device-transfer>`.
    pub store_root: PathBuf,
    /// Package names to exclude from the tunnel, resolved by the core from user
    /// configuration and handed here as data.
    pub vpn_config: VpnConfig,
}

/// The Android platform adapter.
///
/// One object implementing all six capabilities, which is what lets the core
/// state *which* adapter it is talking to (S-47): "a core that assembled its
/// platform from six independently-supplied pieces could not state which adapter
/// it was talking to".
#[derive(Debug, Clone)]
pub struct AndroidPlatformAdapter {
    shutdown: ShutdownLatch,
    sockets: AndroidSocketProvider,
    tunnel: AndroidTunnelDevice,
    network: AndroidNetworkConfig,
    interfaces: AndroidInterfaceProvider,
    identity: AndroidIdentityCustody,
    store: AndroidSecureStore,
}

impl AndroidPlatformAdapter {
    /// Builds the adapter.
    #[must_use]
    pub fn new(parts: AndroidAdapterParts) -> Self {
        let shutdown = ShutdownLatch::new();
        let tunnel = AndroidTunnelDevice::new(parts.controller.clone(), shutdown.clone());
        let interfaces = AndroidInterfaceProvider::new(shutdown.clone());
        let network = AndroidNetworkConfig::new(
            parts.controller.clone(),
            tunnel.clone(),
            interfaces.clone(),
            parts.vpn_config,
            shutdown.clone(),
        );
        Self {
            sockets: AndroidSocketProvider::new(parts.controller, shutdown.clone()),
            tunnel,
            network,
            interfaces,
            identity: AndroidIdentityCustody::new(parts.element.clone(), shutdown.clone()),
            store: AndroidSecureStore::new(parts.element, parts.store_root, shutdown.clone()),
            shutdown,
        }
    }

    /// The concrete tunnel device, for the shell's own bring-up sequence.
    ///
    /// The trait deliberately hides the OS handle, but on Android `apply` is
    /// what establishes the interface, so the shell has to hand the handle from
    /// `create_interface` to [`AndroidNetworkConfig::bind_handle`].
    #[must_use]
    pub const fn tunnel_device(&self) -> &AndroidTunnelDevice {
        &self.tunnel
    }

    /// The concrete network configuration, for the same reason — and because
    /// `installed_ruleset`'s read-back, the lockdown report and
    /// `setUnderlyingNetworks` are all reached through it.
    #[must_use]
    pub const fn network(&self) -> &AndroidNetworkConfig {
        &self.network
    }

    /// The concrete interface provider, so the JNI callbacks can feed it.
    #[must_use]
    pub const fn interface_provider(&self) -> &AndroidInterfaceProvider {
        &self.interfaces
    }

    /// The concrete identity custody, so a shell can report the security level.
    #[must_use]
    pub const fn identity_custody(&self) -> &AndroidIdentityCustody {
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
    /// Each is a fact the shell turns into a log line and a diagnostic-bundle
    /// field; none of them is a decision this adapter makes. ADR-0016 PS-17's
    /// principle — *"silently running wider than declared is the defect this
    /// rule retires"* — applied to the adapter.
    #[must_use]
    pub fn posture(&self) -> AdapterPosture {
        AdapterPosture {
            security_level: self.identity.security_level(),
            hardware_backed_identity: self.identity.security_level().hardware_backed(),
            lockdown: self.network.lockdown(),
            boot_id_source: DerivedBootId::read().ok().map(|id| id.kind()),
            entropy_available: SystemEntropy::new().probe().is_ok(),
        }
    }
}

/// What the adapter can and cannot do on this device.
///
/// Declared at startup, never inferred later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPosture {
    /// The Keystore level the identity key actually reached.
    pub security_level: SecurityLevel,
    /// Whether that level is hardware-backed. **Separate from
    /// `security_level`** on purpose: "this device has a TEE and no StrongBox"
    /// and "this device has a software keymaster" are different facts with
    /// different remediations, and ADR-0020's assurance ladder distinguishes
    /// them.
    pub hardware_backed_identity: bool,
    /// The three-valued always-on posture (LC-40). Defaults to
    /// [`LockdownPosture::Unverified`], which presents as unprotected.
    pub lockdown: LockdownPosture,
    /// Which source answered for the boot identity, or `None` if neither could.
    pub boot_id_source: Option<BootIdSourceKind>,
    /// Whether the platform CSPRNG could be drawn from at startup.
    pub entropy_available: bool,
}

impl PlatformAdapter for AndroidPlatformAdapter {
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
        // Sets the latch and does NOTHING else. CB-6 puts the installed ruleset
        // in the OS's custody precisely so the core going away does not drop
        // protection, and a shutdown that removed it would defeat that.
        //
        // On Android that has a sharper edge than elsewhere: the claim dies with
        // the process anyway (posture::EnforcementView::custody reports
        // `survives_core_exit: false` unless lockdown is CONFIRMED), so the only
        // thing this path could usefully do to enforcement is drop it EARLY.
        // Nothing here touches the descriptor, the claim, or the disposition.
        self.shutdown.begin();
    }
}

/// The error a shell reports when the adapter cannot be used at all.
///
/// Not a new type: the seam already has one, and adding a second failure
/// vocabulary at the shell boundary is how a `reason_code` gets lost.
pub type AdapterError = PlatformError;

#[cfg(test)]
mod tests;
