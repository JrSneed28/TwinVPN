//! `twinvpn-platform-linux` — the Linux/OpenWrt implementation of the
//! `twinvpn-platform` trait. **This crate is the seam** (ADR-0018 §11.6).
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5,
//! CB-1, CB-2, CB-3, CB-5, CB-6, CB-6a, CB-7, DP-4; `docs/networking.md` §5.1
//! (the adapter contract) and §5.2 (the Linux row); ADR-0010, ADR-0011, ADR-0012,
//! ADR-0016, ADR-0022 LC-8.
//!
//! **Owner:** `desktop-linux`.
//!
//! # What this crate is for
//!
//! `docs/networking.md` §5.1: "Every platform implements one interface. Anything
//! platform-specific lives behind it; nothing above it may branch on OS." This is
//! the Linux side of that line. It is one of the three crates on the DP-4
//! `unsafe` allowlist and one of the few permitted `#[cfg(target_os)]` (CB-3),
//! and it uses both privileges only where the alternative is a syscall the core
//! cannot make.
//!
//! # The twenty-seven `unsafe` blocks, and what each is for
//!
//! | Module | Blocks | What they are, and the invariant |
//! |---|---|---|
//! | [`sock`] | 14 | the single `setsockopt` call site; the zeroed `sockaddr_storage` and `msghdr` that `libc`'s private padding makes unconstructible in safe code; the `recvmsg`; the `cmsg` walk (`CMSG_FIRSTHDR`/`NXTHDR`/`DATA`/`LEN`, the two `copy_nonoverlapping`s, each guarded by a length check against `CMSG_LEN` **first**); and the two `sockaddr_in`/`in6` copies, each width-checked against the kernel-supplied `msg_namelen` |
//! | [`netlink`] | 6 | `socket`, `bind`, `send`, `recv`, and the zeroed `sockaddr_nl` — a fresh owned fd, and live buffers of their declared lengths |
//! | [`tun`] | 3 | `ioctl(TUNSETIFF)` on an open `/dev/net/tun` fd with a live 40-byte `ifreq`, and the `read`/`write` on an open tun fd with a live slice of its true length |
//! | [`nss`] | 1 | `getgrouplist(3)`'s two-call size protocol — a live C string and a buffer whose declared bound is its true bound. PS-12a's memberships from every NSS source, not just `/etc/group` |
//! | [`lock`] | 1 | `flock(LOCK_EX\|LOCK_NB)` on a live borrowed fd — two `c_int`s by value, dereferencing nothing. PS-1's crash-surviving exclusion |
//! | [`clock`] | 2 | `clock_gettime(CLOCK_BOOTTIME)` into a local `timespec`, and `getrandom(2)` into a slice this call holds exclusively — the two platform primitives CD-3's W-36 exemption places here (`cd3_crate_may_read_platform_primitives`) |
//!
//! **Every one carries a `// SAFETY:` comment naming its invariant** — 27 of 27,
//! and every hand-written C layout is asserted against `libc`'s own `size_of` in
//! the owning module's tests, so a drifting offset fails the build rather than
//! corrupting a route.
//!
//! # Which surface a shell should bind
//!
//! **The Rust crates, not the C ABI**, and the reason is `ownership.md` §8
//! **W-24** and **W-25** rather than convenience:
//!
//! | Capability | `twinvpn.h` F-9 | this crate |
//! |---|---|---|
//! | sockets (the NAT ladder) | **absent** (W-25) | [`sock`] |
//! | interface enumeration and events | **absent** (W-25) | [`iface`] |
//! | `installed_ruleset` read-back | **absent** (W-24) | [`nft::parse_installed`] |
//! | `current_generation` | **absent** (W-24) | [`netcfg`] |
//! | `set_mtu`, `datapath`, `enforcement_custody`, `supported_families` | absent | present |
//!
//! A shell bound only to the vtable cannot do NAT traversal and cannot produce a
//! `ProtectionAssertion` at all. `shells/linux` therefore links this crate
//! directly, and the ADR-0018 §11.4 amendment those two findings ask for is what
//! a Swift or Kotlin shell needs before it can do the same.
//!
//! # CB-3, honestly
//!
//! There is no `#[cfg(target_os = …)]` in this crate — not because the rule
//! forbids it here (it does not; `cb3_crate_is_exempt` names
//! `twinvpn-platform-*`) but because the crate is only ever compiled for Linux,
//! so a branch would be dead code pretending to be portability.

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

use std::path::PathBuf;
use std::sync::Arc;

use twinvpn_platform::{
    IdentityCustody, InterfaceProvider, NetworkConfig, PlatformAdapter, PlatformError, SecureStore,
    SocketProvider, TunnelDevice,
};

pub mod addr;
pub mod clock;
pub mod custody;
pub mod iface;
pub mod lock;
pub mod netcfg;
pub mod netlink;
pub mod nft;
pub mod nss;
pub mod oserr;
pub mod resolved;
pub mod resolver;
pub mod route;
pub mod shutdown;
pub mod sock;
pub mod tun;

pub use clock::{BootTimeElapsedClock, ProcBootId, SystemEntropy};
pub use custody::{AbsentElement, LinuxIdentityCustody, LinuxSecureStore, SigningElement};
pub use nft::{EnforcementConfig, DEFAULT_FWMARK};
pub use shutdown::ShutdownLatch;

/// The name prefix every TwinVPN overlay interface carries.
///
/// `is_overlay` is answered by this prefix and not by the netlink link *kind*:
/// a `wireguard` link created by `wg-quick` is a third party's, and treating it
/// as ours would make ADR-0012's Tier-2 interface-scoped deny permit somebody
/// else's tunnel.
pub const OVERLAY_PREFIX: &str = "twin";

/// The binding name recorded in `CoreBuildIdentity` (S-46).
///
/// Stable and non-localised, so a support case can answer "which adapter was
/// loaded" from the bundle rather than from an inference.
pub const BINDING_NAME: &str = "linux-nftables";

/// Everything the adapter takes at construction. **CD-2: no global, no
/// `OnceCell`, no ambient default, and nothing discovered from the environment.**
pub struct LinuxAdapterParts {
    /// The enforcement facts the seam does not carry — see
    /// [`nft::EnforcementConfig`], every field of which is a reported gap.
    pub enforcement: EnforcementConfig,
    /// The vault directory, **injected, never discovered** (CB-7, CD-2).
    pub store_root: PathBuf,
    /// Where the resolver restore point is written. Readable by
    /// `twinvpn-unblock` and the boot restore unit with the agent absent
    /// (ADR-0011 DN-20, ADR-0016 PS-6).
    pub resolver_restore_point: PathBuf,
    /// The identity element. [`AbsentElement`] on a host with none, which
    /// reports `hardware_backed: false` truthfully and refuses rather than
    /// substituting a file-backed signer (§11.16 (l)).
    pub identity_element: Arc<dyn SigningElement>,
}

/// The Linux platform adapter.
///
/// One object implementing all six capabilities, which is what lets the core
/// state *which* adapter it is talking to (S-47): "a core that assembled its
/// platform from six independently-supplied pieces could not state which adapter
/// it was talking to".
pub struct LinuxPlatformAdapter {
    shutdown: ShutdownLatch,
    sockets: sock::LinuxSocketProvider,
    tunnel: tun::LinuxTunnelDevice,
    network: netcfg::LinuxNetworkConfig,
    interfaces: iface::LinuxInterfaceProvider,
    identity: custody::LinuxIdentityCustody,
    store: custody::LinuxSecureStore,
}

impl LinuxPlatformAdapter {
    /// Builds the adapter.
    #[must_use]
    pub fn new(parts: LinuxAdapterParts) -> Self {
        let shutdown = ShutdownLatch::new();
        Self {
            sockets: sock::LinuxSocketProvider::new(shutdown.clone()),
            tunnel: tun::LinuxTunnelDevice::new(shutdown.clone()),
            network: netcfg::LinuxNetworkConfig::new(
                shutdown.clone(),
                parts.enforcement,
                parts.resolver_restore_point,
            ),
            interfaces: iface::LinuxInterfaceProvider::new(shutdown.clone()),
            identity: custody::LinuxIdentityCustody::new(parts.identity_element, shutdown.clone()),
            store: custody::LinuxSecureStore::new(parts.store_root, shutdown.clone()),
            shutdown,
        }
    }

    /// The concrete tunnel device, for the shell's own bring-up sequence.
    ///
    /// The trait deliberately hides the OS handle, but the shell needs the
    /// interface's index to tell [`netcfg::LinuxNetworkConfig`] which link to
    /// program — and rediscovering it by name would turn a rename race into a
    /// route on the wrong link.
    #[must_use]
    pub const fn tunnel_device(&self) -> &tun::LinuxTunnelDevice {
        &self.tunnel
    }

    /// The concrete network configuration, for the same reason.
    #[must_use]
    pub const fn network(&self) -> &netcfg::LinuxNetworkConfig {
        &self.network
    }

    /// The concrete secure store, so the shell can prepare the vault directory
    /// before the core asks for it.
    #[must_use]
    pub const fn secure_store(&self) -> &custody::LinuxSecureStore {
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
    /// Each is a `bool` the shell turns into a log line and a diagnostic-bundle
    /// field; none of them is a decision this adapter makes.
    #[must_use]
    pub fn posture(&self) -> AdapterPosture {
        AdapterPosture {
            nft_present: netcfg::LinuxNetworkConfig::nft_binary().is_ok(),
            tun_present: std::path::Path::new(tun::TUN_CLONE).exists(),
            tpm_present: custody::tpm_resource_manager_present(),
            hardware_backed_identity: self.identity.element_name() != "absent",
            resolved_in_force: !matches!(
                resolver::ResolverBackend::detect(),
                resolver::ResolverBackend::ResolvConf
            ),
            resolver_backend: resolver::ResolverBackend::detect(),
        }
    }
}

/// What the adapter can and cannot do on this host.
///
/// Declared at startup, never inferred later. ADR-0016 PS-17: "If any directive
/// in this table fails to apply … the authority MUST emit
/// `PLATFORM.PRIV.SANDBOX_DEGRADED` … Silently running wider than declared is
/// the defect this rule retires." The same principle applied to the adapter.
// Five booleans, and each is a distinct fact a shell reports on its own line:
// `tpm_present` and `hardware_backed_identity` in particular must stay separate,
// because "this host has a TPM and this build cannot use it" and "this host has
// no TPM" have different remediations. Collapsing them into a bitflags type
// would make exactly that distinction invisible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterPosture {
    /// Whether `nft(8)` is installed. Without it enforcement cannot be armed and
    /// the client MUST NOT enter a protected state (ADR-0012 §8).
    pub nft_present: bool,
    /// Whether `/dev/net/tun` exists.
    pub tun_present: bool,
    /// Whether a TPM resource manager exists. Distinct from
    /// `hardware_backed_identity`: "this host has a TPM and this build cannot
    /// use it" and "this host has no TPM" are different facts.
    pub tpm_present: bool,
    /// Whether the identity element is genuinely hardware-backed (§11.16 (l)).
    pub hardware_backed_identity: bool,
    /// Whether `systemd-resolved` is in force, i.e. whether DN-21's preferred
    /// mechanism is the one that applies on this host.
    ///
    /// **Not the same question as whether we can use it.** A host can have
    /// `resolved` in force and no `resolvectl` to reach it; that is
    /// [`AdapterPosture::resolver_backend`]'s
    /// [`resolver::ResolverBackend::ResolvedUnavailable`], and it is a packaging
    /// problem an operator can fix rather than a property of the host.
    pub resolved_in_force: bool,
    /// **Which of DN-21's two Linux forms this host will actually take**, and
    /// why, in one value.
    ///
    /// Reported rather than inferred from the boolean above, because
    /// `ResolverBackend::degradation` names the registered code the weaker path
    /// is taken under and a boolean cannot.
    pub resolver_backend: resolver::ResolverBackend,
}

impl PlatformAdapter for LinuxPlatformAdapter {
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
        // that. Nothing on this path touches nftables, the routes, or the
        // resolver.
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

    fn parts() -> LinuxAdapterParts {
        LinuxAdapterParts {
            enforcement: EnforcementConfig {
                overlay_interface: "twin0".to_owned(),
                firewall_mark: DEFAULT_FWMARK,
                cgroup_path: None,
                local_network_access: true,
                on_link_prefixes: Vec::new(),
            },
            store_root: std::env::temp_dir().join("twinvpn-adapter-test"),
            resolver_restore_point: std::env::temp_dir().join("twinvpn-adapter-test-restore"),
            identity_element: Arc::new(AbsentElement),
        }
    }

    #[test]
    fn the_adapter_names_itself_so_s46_records_which_binding_was_loaded() {
        let adapter = LinuxPlatformAdapter::new(parts());
        assert_eq!(adapter.binding_name(), "linux-nftables");
    }

    #[test]
    fn one_object_carries_all_six_capabilities() {
        // S-47: "a core that assembled its platform from six
        // independently-supplied pieces could not state which adapter it was
        // talking to".
        let adapter = LinuxPlatformAdapter::new(parts());
        let _ = adapter.sockets();
        let _ = adapter.tunnel();
        let _ = adapter.network_config();
        let _ = adapter.interfaces();
        let _ = adapter.identity();
        let _ = adapter.store();
    }

    #[test]
    fn begin_shutdown_latches_and_touches_nothing_else() {
        let adapter = LinuxPlatformAdapter::new(parts());
        assert!(!adapter.is_shutting_down());
        adapter.begin_shutdown();
        assert!(adapter.is_shutting_down());
        // Idempotent, and callable from any thread.
        adapter.begin_shutdown();
        assert!(adapter.is_shutting_down());
        // The custody declaration is unchanged: the OS still holds the rules.
        assert!(adapter
            .network_config()
            .enforcement_custody()
            .survives_core_exit());
    }

    #[test]
    fn the_posture_is_declared_rather_than_discovered_by_a_user() {
        let adapter = LinuxPlatformAdapter::new(parts());
        let posture = adapter.posture();
        // On this host `nft` is absent, which is itself the fact worth
        // declaring: the shell turns it into a startup refusal rather than
        // arming without a firewall.
        assert_eq!(
            posture.nft_present,
            netcfg::LinuxNetworkConfig::nft_binary().is_ok()
        );
        assert!(
            !posture.hardware_backed_identity,
            "AbsentElement reports false truthfully"
        );
        // `tpm_present` and `hardware_backed_identity` are SEPARATE facts.
        let _ = posture.tpm_present;
        let _ = posture.resolved_in_force;
        // DN-21's two forms are a three-state value, and the third state —
        // `resolved` in force with no client to reach it — is the one a boolean
        // could not carry.
        assert_eq!(
            posture.resolver_backend.is_scoped(),
            posture.resolver_backend == resolver::ResolverBackend::Resolved
        );
        let _ = posture.tun_present;
    }
}
