//! ADR-0011 §11.1's four resolution scopes, and DN-1's cache separation.
//!
//! **Authority:** ADR-0011 §11.1, DN-0, DN-1, DN-10, DN-22; ADR-0012 §11.5's
//! `RESOLVER` socket class and KS-16.
//!
//! # DN-1 is why `Scope` is a key, not a hint
//!
//! > The four scopes share no cache, no chain cache, and no negative cache. An
//! > answer learned in one scope MUST NOT be served in another.
//!
//! [`crate::cache::ScopedCaches`] holds four independent caches keyed by this
//! enum and offers no cross-scope lookup, so KS-16's "a portal-supplied answer
//! that persisted into protected resolution would convert a 300 s hole into a
//! durable redirection" is closed structurally.

use core::time::Duration;

/// The four scopes, exactly as `dns.proto`'s `ResolutionScope` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Answered from the cached signed contract, authoritatively, with **no
    /// network I/O**. Available with the control plane down and the tunnel down.
    Twinnet,
    /// Upstream resolvers named by policy, reached **only over the overlay**.
    /// Exists only while an authorized secure path exists.
    Protected,
    /// The attaching interface's DHCP/RA resolvers, over a live
    /// `PortalExemptionGrant` only.
    Portal,
    /// The narrowest scope: **agent-originated only**, a **closed name set** of
    /// the control-plane and rendezvous FQDNs, available **always including in
    /// `BLOCKED`**.
    Bootstrap,
}

impl Scope {
    /// All four, so a caller cannot iterate three by accident.
    pub const ALL: [Scope; 4] = [
        Scope::Twinnet,
        Scope::Protected,
        Scope::Portal,
        Scope::Bootstrap,
    ];

    /// The wire value of `twinvpn.v1.ResolutionScope`.
    #[must_use]
    pub const fn to_wire(self) -> i32 {
        match self {
            Scope::Twinnet => 1,
            Scope::Protected => 2,
            Scope::Portal => 3,
            Scope::Bootstrap => 4,
        }
    }

    /// Whether this scope may be served while no authorized secure path exists.
    ///
    /// `Twinnet` can: it is contract-only and needs no network at all (D3, I5).
    /// `Bootstrap` can, and must — DN-0: without it "a device in `BLOCKED` whose
    /// control plane is reached by GeoDNS could never re-establish".
    /// `Protected` cannot: "otherwise every query is a typed failure".
    /// `Portal` needs a live grant, which is a separate question.
    #[must_use]
    pub const fn servable_while_blocked(self) -> bool {
        matches!(self, Scope::Twinnet | Scope::Bootstrap)
    }

    /// Whether a **host process** may resolve in this scope.
    ///
    /// DN-0: `bootstrap` is "agent-originated only. No host process may resolve
    /// in this scope; the stub MUST refuse a `bootstrap`-scope query that did
    /// not originate from the agent itself."
    #[must_use]
    pub const fn open_to_host_processes(self) -> bool {
        !matches!(self, Scope::Bootstrap)
    }

    /// The TTL ceiling this scope's cache clamps to.
    ///
    /// `Bootstrap` is clamped to 300 s (§11.1). `Portal` is clamped to the
    /// remaining grant, which the caller supplies. `Twinnet` needs no cache —
    /// "the contract *is* the index".
    #[must_use]
    pub const fn ttl_ceiling(self) -> Option<Duration> {
        match self {
            Scope::Bootstrap => Some(Duration::from_secs(300)),
            Scope::Twinnet => Some(Duration::ZERO),
            Scope::Protected | Scope::Portal => None,
        }
    }
}

/// DN-10, clause 2: **scope never changes on failure**.
///
/// > A query classified for underlay forwarding in `SPLIT` mode MUST NOT be
/// > retried in-tunnel, and an in-tunnel query MUST NOT be retried on the
/// > underlay.
///
/// This function exists to be the *only* place a retry scope is chosen, and it
/// always answers "the same one". A caller that wants a different scope has to
/// re-classify the query from scratch, which is a different query.
#[must_use]
pub const fn retry_scope(original: Scope) -> Scope {
    original
}

/// DN-10, clause 1: whether this classification may **ever** reach a
/// pre-existing host or network resolver.
///
/// > A query classified `TWINNET` or `PROTECTED_UPSTREAM` MUST NOT, under
/// > **any** condition including stub error, upstream timeout, `SERVFAIL`,
/// > tunnel loss, or policy expiry, be sent to a pre-existing host or network
/// > resolver.
#[must_use]
pub const fn may_reach_preexisting_resolver(scope: Scope) -> bool {
    match scope {
        Scope::Twinnet | Scope::Protected => false,
        // §11.1: `bootstrap` reaches the host's configured upstream over a
        // RESOLVER-registered socket, and `portal` reaches the grant's resolvers.
        // Neither is *fallback*: both are the scope's own definition.
        Scope::Portal | Scope::Bootstrap => true,
    }
}
