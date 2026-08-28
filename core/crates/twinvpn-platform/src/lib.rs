//! `twinvpn-platform` — the platform adapter **trait only**. This crate is the
//! seam.
//!
//! **Authority:** ADR-0018 §11.6 (the seam in both directions), §11.2 row 2.5
//! ("the **trait** | the **implementation** | *this is the seam*"), CB-1, CB-2,
//! CB-3, CB-5, CB-6, CB-6a, CB-7, CD-5, `docs/networking.md` §5.1.
//!
//! **Owner:** `core-foundation`. The *implementations* are shell-side:
//! `twinvpn-platform-linux` belongs to `desktop-linux` under CB-3.
//!
//! # Three rules this crate exists to hold
//!
//! **CB-1 — ambiguity resolves to the core.** Code belongs in a shell if and only
//! if it must call a platform API with no stable C-callable form, must run inside
//! an OS-started process, or is user-interface presentation. Everything else is
//! core. Every trait here is at that line: sockets, the tunnel device, route and
//! resolver programming, the firewall install, interface events, identity
//! operations, Tier-1 storage — and *nothing else*.
//!
//! **CB-2 — the shell holds no decision.** A shell may translate, marshal,
//! schedule and render. It must not contain a branch whose condition is a TwinVPN
//! domain fact. The falsification test is this crate's design target:
//!
//! > With every shell deleted and a mock adapter bound, the core must still make
//! > every decision correctly. If it cannot, a decision leaked into a shell.
//!
//! Which is why the `mock` feature exists, why CD-5 calls it "the payoff", and
//! why every method here reports a *fact* and takes an *instruction* rather than
//! answering a question.
//!
//! **CB-3 — no OS branch above the adapter.** There is no `#[cfg(target_os)]`
//! anywhere in this crate, and `cargo run -p xtask -- lint` fails the build if
//! one appears outside a `twinvpn-platform-*` crate. Where the core genuinely
//! needs to behave differently per target, it branches on a **declared
//! capability** — [`config::Datapath`], [`config::EnforcementCustody`] and its
//! [`config::BootEnforcement`], [`config::RouteCapabilities`],
//! [`custody::RecordAeadCustody`], [`socket::SupportedFamilies`],
//! [`socket::SocketCapabilities`], [`iface::LinkClass`] — never on which OS it
//! is.
//!
//! # The seam, both ways
//!
//! | Direction | Here |
//! |---|---|
//! | core → shell: create / apply / rollback / `set_link` / `set_ruleset` / `query_link_facts` / destroy | [`config::TunnelDevice`], [`config::NetworkConfig`] |
//! | core → shell: identity sign / agree / attest | [`custody::IdentityCustody`] (CB-5) |
//! | core → shell: store read / write | [`custody::SecureStore`] (CB-7) |
//! | shell → core: network change | [`iface::InterfaceProvider::subscribe`], a `Stream` |
//!
//! # Async, cancellation, timeouts, shutdown
//!
//! Every fallible call returns a `BoxFuture`. **Cancellation is dropping the
//! future**, and an adapter must release whatever the operation held.
//! **Timeouts are the core's**, composed from `twinvpn_env::Timer` on the
//! injected monotonic clock — an adapter that imposed its own would put a
//! deadline outside CD-1's reach. **Shutdown** is
//! [`PlatformAdapter::begin_shutdown`], after which calls return
//! [`PlatformError::ShuttingDown`] rather than hanging or silently succeeding.
//!
//! # Features
//!
//! | Feature | Default | Contents |
//! |---|---|---|
//! | `mock` | no | [`mock`] — an in-memory binding of every trait here, so CD-5's "100% of the decision logic on a Linux CI runner with no VM and no device farm" is affordable |

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod custody;
pub mod error;
pub mod iface;
pub mod socket;

// `doc` as well as the feature, so the intra-doc link to this module resolves
// when the docs are built without `mock`. See the same note in twinvpn-env.
#[cfg(any(feature = "mock", doc))]
pub mod mock;

pub use config::{
    ApplyBudget, BootEnforcement, ContractGeneration, Datapath, DnsConfig, EnforcementCustody,
    LinkFacts, LinkState, NetworkConfig, NetworkContract, RouteCapabilities, RouteEntry, Ruleset,
    TunnelDevice, TunnelHandle,
};
pub use custody::{
    IdentityAttestation, IdentityCustody, IdentityKeyRef, IdentityPublic, PeerPublicKey,
    RecordAeadCustody, SecureItem, SecureItemKey, SecureStore, SharedSecret, Signature, StoreRoot,
    StoreRootAttributes,
};
pub use error::{OsDetail, PlatformError};
pub use iface::{
    InterfaceFacts, InterfaceIndex, InterfaceName, InterfaceProvider, LinkClass, NetworkChange,
    ResumeFacts,
};
pub use socket::{
    AdapterResponseBudget, Datagram, FragmentPolicy, MulticastOptions, SocketCapabilities,
    SocketFamily, SocketOptions, SocketProvider, SupportedFamilies, UdpBindSpec, UdpSocket,
};

/// The whole adapter: every capability the core reaches the platform through.
///
/// One object rather than six injected separately, because ADR-0018 §11.16 (a)
/// requires **exactly one process** to hold a mutating core handle at a time
/// (S-47), and a core that assembled its platform from six independently-supplied
/// pieces could not state which adapter it was talking to.
///
/// Every accessor returns a borrow, so an adapter can implement all six on one
/// object where that is natural (it is, on most targets) without the core being
/// able to tell.
pub trait PlatformAdapter: Send + Sync {
    /// Sockets: v4, v6, dual-stack, IPv6-only, multicast, and the NAT ladder's
    /// per-socket options.
    fn sockets(&self) -> &dyn SocketProvider;

    /// The tunnel device.
    fn tunnel(&self) -> &dyn TunnelDevice;

    /// Transactional route, address, resolver and firewall programming.
    fn network_config(&self) -> &dyn NetworkConfig;

    /// Interface enumeration and change notification.
    fn interfaces(&self) -> &dyn InterfaceProvider;

    /// Identity operations performed inside the element (CB-5).
    fn identity(&self) -> &dyn IdentityCustody;

    /// Tier-1 secure items and the vended store root (CB-7).
    fn store(&self) -> &dyn SecureStore;

    /// A stable, non-localised name for this binding, e.g. `"linux-nftables"`.
    ///
    /// Recorded in `CoreBuildIdentity` (S-46) so a support case can answer "which
    /// adapter was loaded" from the bundle rather than from an inference.
    fn binding_name(&self) -> &'static str;

    /// Begins graceful shutdown.
    ///
    /// After this, calls return [`PlatformError::ShuttingDown`]. It does **not**
    /// tear down enforcement: CB-6 puts the installed ruleset in the OS's custody
    /// precisely so that the core going away does not drop protection, and a
    /// shutdown that removed the rules would defeat that.
    fn begin_shutdown(&self);
}
