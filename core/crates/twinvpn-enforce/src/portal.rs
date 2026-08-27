//! KS-14…KS-16: the captive-portal exemption, which is never automatic.
//!
//! **Authority:** ADR-0012 §11.7 (KS-14, KS-15, KS-16), §11.2 classes 11 and 13;
//! ADR-0011 §11.10 (DN-27, DN-28); `docs/architecture.md` S-35.
//!
//! # KS-14: there is deliberately no `ALWAYS`
//!
//! > `portal_policy` takes exactly two values, `PROMPT` (default) and `NEVER`.
//! > There is deliberately **no** `ALWAYS`. Detection of `NET.CAPTIVE_PORTAL`
//! > MUST NOT open any hole by itself; the network controls the detector's
//! > inputs, so an automatic exemption would be an attacker-triggerable egress
//! > permit.
//!
//! [`PortalPolicy`] has two variants, and [`PortalGrant::request`] takes a
//! `user_action: UserAction` that has no default constructor.

use core::time::Duration;

use twinvpn_env::ElapsedInstant;
use twinvpn_platform::InterfaceIndex;
use twinvpn_types::{Endpoint, IpAddr};

/// KS-14's two values. There is no third.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortalPolicy {
    /// The default. A grant requires a local user action, every time.
    Prompt,
    /// No grant is ever offered.
    Never,
}

/// Evidence that a human acted on this device.
///
/// Deliberately has no `Default` and no public field: a grant must not be
/// constructible from nothing, because "an automatic exemption would be an
/// attacker-triggerable egress permit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAction(());

impl UserAction {
    /// Records that a local interactive action occurred.
    ///
    /// Only the management/UI boundary calls this, and it is the single place a
    /// reviewer has to look to answer "can a grant happen without a human".
    #[must_use]
    pub const fn performed_locally() -> Self {
        Self(())
    }
}

/// KS-15's lifetime cap. Enforced **in the kernel**, "so agent death cannot
/// leave it open".
pub const MAX_LIFETIME: Duration = Duration::from_secs(300);

/// KS-15's reachable set, gathered by detection.
///
/// One value rather than four parameters, because the four are a single fact —
/// "the portal endpoints observed by detection, plus the DHCP/RA-supplied
/// resolver(s) of the attaching interface — nothing else" — and passing them
/// separately invites a caller to supply three of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachableSet {
    /// The portal endpoints detection observed.
    pub portal_endpoints: Vec<Endpoint>,
    /// The DHCP/RA-supplied resolvers of the attaching interface.
    pub resolvers: Vec<IpAddr>,
    /// The single attaching underlay interface. Never the overlay, never a
    /// second interface.
    pub interface: InterfaceIndex,
    /// The network this set belongs to.
    pub network_fingerprint: [u8; 16],
}

/// A live portal exemption (S-35).
///
/// **Non-durable by requirement**: "it does not survive process restart or
/// reboot", which is why it holds an [`ElapsedInstant`] rather than anything
/// persisted — §5.3.1 puts `PortalExemptionGrant` expiry on the elapsed clock so
/// a suspend cannot extend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalGrant {
    expires_at: ElapsedInstant,
    portal_endpoints: Vec<Endpoint>,
    resolvers: Vec<IpAddr>,
    interface: InterfaceIndex,
    network_fingerprint: [u8; 16],
}

impl PortalGrant {
    /// Requests a grant. Returns `None` under [`PortalPolicy::Never`].
    ///
    /// `_user_action` is unused by the body and required by the signature, which
    /// is the point: the type is the proof a human acted.
    #[must_use]
    pub fn request(
        policy: PortalPolicy,
        _user_action: UserAction,
        now: ElapsedInstant,
        lifetime: Duration,
        reachable: ReachableSet,
    ) -> Option<Self> {
        if policy == PortalPolicy::Never {
            return None;
        }
        Some(Self {
            expires_at: now.saturating_add(lifetime.min(MAX_LIFETIME)),
            portal_endpoints: reachable.portal_endpoints,
            resolvers: reachable.resolvers,
            interface: reachable.interface,
            network_fingerprint: reachable.network_fingerprint,
        })
    }

    /// Whether the grant is still live.
    #[must_use]
    pub fn is_live(&self, now: ElapsedInstant) -> bool {
        !now.reached(self.expires_at)
    }

    /// How long is left, for `POLICY.PORTAL.EXEMPTION_ACTIVE`'s evidence.
    #[must_use]
    pub fn remaining(&self, now: ElapsedInstant) -> Duration {
        self.expires_at.duration_since(now)
    }

    /// The network this grant belongs to. A second network needs a second grant.
    #[must_use]
    pub const fn network_fingerprint(&self) -> &[u8; 16] {
        &self.network_fingerprint
    }

    /// KS-15's destination and port rules, as one predicate.
    ///
    /// | Property | Value |
    /// |---|---|
    /// | Destination set | the portal endpoints observed by detection, plus the DHCP/RA-supplied resolvers — **nothing else** |
    /// | Ports | TCP 80/443 to the portal endpoints; UDP/TCP 53 and TCP 853 to the resolvers |
    /// | Interface | the single attaching underlay interface only; **never** the overlay, never a second interface |
    #[must_use]
    pub fn permits(
        &self,
        now: ElapsedInstant,
        egress: InterfaceIndex,
        destination: Endpoint,
    ) -> bool {
        if !self.is_live(now) || egress != self.interface {
            return false;
        }
        let port = destination.port.get();
        if self.portal_endpoints.contains(&destination) {
            return matches!(port, 80 | 443);
        }
        if self.resolvers.contains(&destination.address) {
            return matches!(port, 53 | 853);
        }
        false
    }

    /// KS-15's scope rule: "the protected scope of §11.1 **remains blocked
    /// throughout**. The exemption covers the portal conversation, never
    /// protected traffic."
    #[must_use]
    pub const fn protected_scope_stays_blocked() -> bool {
        true
    }
}

/// KS-16 / DN-1: answers obtained during a grant are `portal`-scope and MUST NOT
/// enter the protected resolution path or its cache.
///
/// > A portal-supplied answer that persisted into protected resolution would
/// > convert a 300 s hole into a durable redirection.
///
/// `twinvpn-dns`'s `ScopedCaches` has no cross-scope lookup, so this function
/// records the rule rather than implementing it — and a test asserts both ends.
#[must_use]
pub const fn portal_answers_may_enter_protected_cache() -> bool {
    false
}

/// One grant per network fingerprint per attachment; a second grant requires a
/// second user action.
#[derive(Debug, Default)]
pub struct GrantLedger {
    granted: Vec<[u8; 16]>,
}

impl GrantLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a grant may be issued for this network without a fresh user
    /// action.
    ///
    /// Always `false` once one has been issued: KS-15's renewal rule.
    #[must_use]
    pub fn may_auto_renew(&self, fingerprint: &[u8; 16]) -> bool {
        let _ = fingerprint;
        false
    }

    /// Records that a grant was issued.
    pub fn record(&mut self, fingerprint: [u8; 16]) {
        self.granted.push(fingerprint);
    }

    /// Whether this network has had a grant during this attachment.
    #[must_use]
    pub fn already_granted(&self, fingerprint: &[u8; 16]) -> bool {
        self.granted.contains(fingerprint)
    }

    /// Clears the ledger on a network detach, since the rule is "one grant per
    /// network fingerprint **per attachment**".
    pub fn on_detach(&mut self) {
        self.granted.clear();
    }
}
