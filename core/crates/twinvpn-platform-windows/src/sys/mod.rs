//! The syscall shim, and the seam that keeps it small.
//!
//! **Authority:** ADR-0018 CB-1 (code belongs in a shell "if and only if it must
//! call a platform API with no stable C-callable form"), CB-3, CD-2, DP-4;
//! `docs/implementation/ownership.md` §6.
//!
//! # Why there is a trait here at all
//!
//! **This host is Linux, and nothing in this crate can be linked or run on it.**
//! `make cross-check` type-checks the crate against the real `windows-sys` for
//! `x86_64-pc-windows-msvc` with `-D warnings` — a genuine compile proof, and
//! not a behaviour proof.
//!
//! So the crate is arranged around one rule: **everything that can be
//! target-free is target-free**, and the part that cannot is confined to the
//! four traits below. [`crate::wfp`], [`crate::route`], [`crate::dns`] and
//! [`crate::netcfg`] are written entirely against these traits, so the whole
//! transactional apply/rollback/reconcile machinery — the part where a mistake
//! is a leak rather than a compile error — runs its tests on this host against
//! [`fake`], and only the translation into `FwpmFilterAdd0` and
//! `CreateIpForwardEntry2` needs Windows.
//!
//! That is the same discipline `twinvpn-platform-linux` applies to `nft.rs`,
//! where the ruleset text and the `nft --json` parser are tested exhaustively on
//! a host with no `nft` installed.
//!
//! # The fake is not reachable from a production build
//!
//! [`fake`] is behind the `test-support` feature, and
//! [`crate::WindowsPlatformAdapter::new`] constructs [`win::WindowsSystem`]
//! unconditionally. There is no constructor a shell can call that would bind an
//! in-memory enforcement engine to a real host — an "installed" ruleset that
//! lives in a `HashMap` is exactly the belief ADR-0012 K12 forbids, and the way
//! to keep it out is to make it unreachable rather than to document that nobody
//! should use it.

#[cfg(any(test, feature = "test-support"))]
pub mod fake;

#[cfg(windows)]
pub mod win;

use std::pin::Pin;

use futures_core::Stream;
use twinvpn_platform::{InterfaceFacts, LinkFacts, NetworkChange, PlatformError};

use crate::dns::{DnsPlan, InterfaceDns, NrptRule};
use crate::route::{InstalledRoutes, InterfaceLuid, RoutePlan};
use crate::wfp::canary::NetEvent;
use crate::wfp::readback::EngineState;
use crate::wfp::FilterSet;

/// The Windows Filtering Platform, as this crate uses it.
///
/// Three operations, and the split between them is ADR-0012 K12's: what we
/// **ask for** ([`Self::commit`]) and what the engine **says it holds**
/// ([`Self::read`]) are separate calls returning separate values, so there is no
/// shape in which a successful commit could be mistaken for an installed
/// ruleset.
pub trait FilterEngine: Send + Sync {
    /// Installs a whole set in **one** transaction.
    ///
    /// `FwpmTransactionBegin0` … `FwpmTransactionCommit0`, so there is no
    /// instant at which the host holds no TwinVPN filters (KS-17). Every object
    /// not in `set` but carrying our provider key is deleted inside the same
    /// transaction, which is what makes a posture swap a swap rather than a
    /// remove-then-add (KS-23).
    fn commit(&self, set: &FilterSet) -> Result<(), PlatformError>;

    /// Enumerates what the engine holds.
    ///
    /// **The W-24 read-back.** Never cached, and a failure is an error rather
    /// than a remembered value.
    fn read(&self) -> Result<EngineState, PlatformError>;

    /// Drains the net-event window since the last call, and says whether the
    /// engine dropped any.
    ///
    /// The `bool` is the engine's own report and is not inferred from an empty
    /// slice: "we saw no events" and "we were not told about the events" are
    /// different facts, and [`crate::wfp::canary::canary_verdict`] refuses to
    /// conclude from the second.
    fn net_events(&self) -> Result<(Vec<NetEvent>, bool), PlatformError>;

    /// Removes every owner-tagged object.
    ///
    /// The `twinvpn-unblock` path of ADR-0012 KS-20a, and PS-21 step 5's
    /// "atomic-swap the enforcement rule set to *no TwinVPN rules*". Not part of
    /// ordinary shutdown: CB-6 puts the ruleset in the OS's custody precisely so
    /// the core going away does not drop protection.
    fn purge(&self) -> Result<(), PlatformError>;
}

/// IP Helper's route and address programming.
pub trait RouteTable: Send + Sync {
    /// Reads the rows and addresses the OS holds on one interface.
    ///
    /// The recovery entry point: R5's reversibility "including after an unclean
    /// process exit" works because rollback diffs from *this*, not from a
    /// remembered state.
    fn read(&self, overlay: InterfaceLuid) -> Result<InstalledRoutes, PlatformError>;

    /// Applies one plan.
    ///
    /// **All-or-nothing.** IP Helper has no transaction, so an implementation
    /// must undo what it managed before reporting the failure — see
    /// [`win::ip`]'s own note on what that costs and what it cannot guarantee.
    fn apply(&self, plan: &RoutePlan) -> Result<(), PlatformError>;

    /// The underlay's current facts.
    fn link_facts(&self, overlay: InterfaceLuid) -> Result<LinkFacts, PlatformError>;
}

/// NRPT and the interface resolver settings.
pub trait Resolver: Send + Sync {
    /// Reads the owner-tagged rules and the interface's current settings.
    ///
    /// Returns **every** rule, ours and not: DN-8's conflict diagnosis needs to
    /// know what else claimed a namespace.
    fn read(
        &self,
        overlay: InterfaceLuid,
    ) -> Result<(Vec<NrptRule>, InterfaceDns), PlatformError>;

    /// Applies one plan.
    fn apply(&self, plan: &DnsPlan) -> Result<(), PlatformError>;
}

/// Interface enumeration and change notification.
pub trait InterfaceTable: Send + Sync {
    /// Every interface the OS currently reports.
    fn enumerate(&self) -> Result<Vec<InterfaceFacts>, PlatformError>;

    /// The change stream.
    ///
    /// Event-driven, never polled: `NotifyIpInterfaceChange`,
    /// `NotifyRouteChange2` and `NotifyUnicastIpAddressChange`. A poll interval
    /// would be added directly to `T_FAILOVER_TARGET`.
    fn subscribe(&self)
        -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError>;
}

/// Everything the network-configuration layer needs, in one object.
///
/// One object rather than three injected separately, for the same reason
/// [`twinvpn_platform::PlatformAdapter`] is one object rather than six: a
/// component that assembled its system access from independently-supplied pieces
/// could not state which system it was talking to.
pub trait SystemOps: Send + Sync {
    /// The filtering engine.
    fn filters(&self) -> &dyn FilterEngine;
    /// The routing table.
    fn routes(&self) -> &dyn RouteTable;
    /// The resolver configuration.
    fn resolver(&self) -> &dyn Resolver;
    /// Interface enumeration and events.
    fn interfaces(&self) -> &dyn InterfaceTable;
}
