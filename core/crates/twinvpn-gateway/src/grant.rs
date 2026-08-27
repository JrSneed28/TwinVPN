//! Grants: authored by the **gateway**, per client, never global.
//!
//! **Authority:** ADR-0013 §11.3 (MG-8, MG-9), S-36, `docs/protocol.md` A14,
//! §13.2 and §13.3; `contracts/proto/twinvpn/v1/gateway.proto` (frozen); CF-10.
//!
//! # S-36: the gateway is the enforcement authority
//!
//! `gateway.proto` on `LanAccessGrant`: "The **GATEWAY** is the enforcement
//! authority; the requesting client caches its own grant with the grant TTL, and
//! the **client's view of policy is ADVISORY**."
//!
//! So [`Grant`] is produced by [`decide`] on the gateway side, and there is no
//! constructor a client-side caller could use to mint one for itself.
//!
//! # An absent grant is a denial
//!
//! CF-10, and `gateway.proto` says it twice. On `ExitNode`: "an absent field is a
//! **DENIAL**, not a permission." On `ExitNodeGrant`: "An absent value is a
//! denial." [`Granted::from_optional`] is the only reader of those
//! explicit-presence bits and it maps `None` to `false`.

use twinvpn_types::{AddressFamily, DeviceId, IpPrefix, PerFamily};

/// A per-family grant decision read from an explicit-presence field.
///
/// The constructor is the whole point: proto3 cannot tell an absent `bool` from
/// `false`, so the schema carries `optional bool` and an absent value must read
/// as **denied**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Granted(bool);

impl Granted {
    /// Reads an explicit-presence field. `None` is a **denial**.
    #[must_use]
    pub const fn from_optional(v: Option<bool>) -> Self {
        match v {
            Some(true) => Self(true),
            _ => Self(false),
        }
    }

    /// Whether it is granted.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        self.0
    }
}

/// What a client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `LANAccessRequest`: reach a subnet behind this gateway.
    LanAccess {
        /// The prefix asked for.
        prefix: IpPrefix,
        /// Which family.
        family: AddressFamily,
    },
    /// `ExitNodeEngage`: egress through this gateway, requested **per family,
    /// independently**.
    ExitNode {
        /// Whether a v4 default route is requested.
        request_v4: bool,
        /// Whether a v6 default route is requested.
        request_v6: bool,
    },
}

/// The gateway's decision, per client.
///
/// "A grant issued to peer A creates **no reachability for peer B**."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// LAN access to one prefix.
    LanAccess {
        /// The peer it was issued to. A grant is never global.
        peer: DeviceId,
        /// The prefix.
        prefix: IpPrefix,
        /// Whether it was granted. Explicit-presence on the wire.
        granted: Granted,
        /// TTL in milliseconds.
        ttl_ms: u64,
        /// Why, when it was refused or partially granted.
        refusal: Option<Refusal>,
    },
    /// Exit-node egress, per family and independently.
    ExitNode {
        /// The peer.
        peer: DeviceId,
        /// Per family, independently, and an absent value is a denial.
        granted: PerFamily<Granted>,
        /// TTL in milliseconds.
        ttl_ms: u64,
        /// Why, when a family was withheld.
        refusal: Option<Refusal>,
    },
}

impl Grant {
    /// The peer this grant belongs to.
    #[must_use]
    pub const fn peer(&self) -> DeviceId {
        match self {
            Grant::LanAccess { peer, .. } | Grant::ExitNode { peer, .. } => *peer,
        }
    }

    /// Whether a family may egress under this grant.
    ///
    /// For a LAN grant the family is the prefix's; for an exit grant it is read
    /// per family, because `protocol.md` §13.3 is emphatic: "if a client requests
    /// full-tunnel egress and the exit node grants only one family, **the client
    /// MUST BLOCK the ungranted family** rather than letting it egress locally."
    #[must_use]
    pub fn permits(&self, family: AddressFamily) -> bool {
        match self {
            Grant::LanAccess {
                prefix, granted, ..
            } => granted.is_granted() && prefix.family() == family,
            Grant::ExitNode { granted, .. } => granted.get(family).is_granted(),
        }
    }

    /// Whether an exit grant is partial, which the client must be told so it can
    /// block the withheld family.
    ///
    /// "A partial grant is **NOT a silent success**."
    #[must_use]
    pub fn is_partial(&self) -> bool {
        match self {
            Grant::ExitNode { granted, .. } => {
                granted.get(AddressFamily::V4).is_granted()
                    != granted.get(AddressFamily::V6).is_granted()
            }
            Grant::LanAccess { .. } => false,
        }
    }
}

/// The precise refusals `protocol.md` §13.2 and §13.3 require to be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The gateway does not advertise that prefix.
    NotAdvertised,
    /// `AccessPolicy` refuses this requester.
    PolicyDenied,
    /// The client's **own** LAN uses the same RFC 1918 range. "An extremely
    /// common real-world failure that MUST carry the colliding prefix in the
    /// diagnostic."
    PrefixCollidesLocal,
    /// The gateway can forward only one family and **says so**, "rather than
    /// granting v4 and silently blackholing v6. Silent single-family grants are
    /// a leak/blackhole class defect."
    FamilyUnsupported,
    /// The gateway is at capacity.
    Capacity,
    /// The gateway has no live policy for this peer.
    Offline,
    /// No IPv6 egress is available at all.
    NoV6Egress,
    /// Exit-node use is not permitted for this peer.
    ExitNotPermitted,
}

/// What the gateway can actually do, and what policy permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayPolicy {
    /// The prefixes this gateway advertises, per family.
    pub advertised: PerFamily<Vec<IpPrefix>>,
    /// Which peers `AccessPolicy` permits, and to which prefixes.
    pub permitted: Vec<(DeviceId, IpPrefix)>,
    /// Which families this gateway can egress.
    pub egress_families: PerFamily<bool>,
    /// Whether exit-node use is permitted at all.
    pub exit_permitted: bool,
    /// The `policy_version` this was compiled from. Monotone (S-06).
    pub policy_version: u64,
    /// Whether a signed bundle has ever been received. MG-9: without one the
    /// peer is **refused**, because we never fail open.
    pub has_signed_bundle: bool,
    /// The default TTL a grant carries.
    pub ttl_ms: u64,
}

/// Evaluates one request. The **gateway** authors the answer (S-36).
///
/// `client_local_prefixes` is what the requester told us about its own LAN, so
/// `POLICY.PREFIX_COLLIDES_LOCAL` can name the colliding prefix rather than
/// describing it.
#[must_use]
pub fn decide(
    policy: &GatewayPolicy,
    peer: DeviceId,
    request: &Request,
    client_local_prefixes: &[IpPrefix],
) -> Grant {
    match request {
        Request::LanAccess { prefix, family } => {
            let refusal = lan_refusal(policy, peer, *prefix, *family, client_local_prefixes);
            Grant::LanAccess {
                peer,
                prefix: *prefix,
                granted: Granted(refusal.is_none()),
                ttl_ms: policy.ttl_ms,
                refusal,
            }
        }
        Request::ExitNode {
            request_v4,
            request_v6,
        } => {
            if !policy.has_signed_bundle {
                return Grant::ExitNode {
                    peer,
                    granted: PerFamily::new(Granted(false), Granted(false)),
                    ttl_ms: 0,
                    refusal: Some(Refusal::Offline),
                };
            }
            if !policy.exit_permitted {
                return Grant::ExitNode {
                    peer,
                    granted: PerFamily::new(Granted(false), Granted(false)),
                    ttl_ms: 0,
                    refusal: Some(Refusal::ExitNotPermitted),
                };
            }
            let v4 = *request_v4 && *policy.egress_families.get(AddressFamily::V4);
            let v6 = *request_v6 && *policy.egress_families.get(AddressFamily::V6);
            let refusal = if *request_v6 && !v6 {
                Some(Refusal::NoV6Egress)
            } else if *request_v4 && !v4 {
                Some(Refusal::FamilyUnsupported)
            } else {
                None
            };
            Grant::ExitNode {
                peer,
                granted: PerFamily::new(Granted(v4), Granted(v6)),
                ttl_ms: policy.ttl_ms,
                refusal,
            }
        }
    }
}

fn lan_refusal(
    policy: &GatewayPolicy,
    peer: DeviceId,
    prefix: IpPrefix,
    family: AddressFamily,
    client_local: &[IpPrefix],
) -> Option<Refusal> {
    if !policy.has_signed_bundle {
        // MG-9 and architecture §2.14: never fail open.
        return Some(Refusal::Offline);
    }
    if prefix.family() != family {
        return Some(Refusal::FamilyUnsupported);
    }
    if !policy
        .advertised
        .get(family)
        .iter()
        .any(|p| p.contains(prefix.address()))
    {
        return Some(Refusal::NotAdvertised);
    }
    if client_local.iter().any(|c| {
        c.family() == family && (c.contains(prefix.address()) || prefix.contains(c.address()))
    }) {
        return Some(Refusal::PrefixCollidesLocal);
    }
    if !policy
        .permitted
        .iter()
        .any(|(d, p)| *d == peer && p.contains(prefix.address()))
    {
        return Some(Refusal::PolicyDenied);
    }
    None
}

/// MG-8: a lower `policy_version` is refused (S-06 anti-rollback).
#[must_use]
pub const fn accepts_policy_version(current: u64, offered: u64) -> bool {
    offered > current
}

/// MG-8's recompile deadline: the gateway recompiles every peer's rule set
/// within this long of a `PolicyBundleUpdated`, and withdraws grants that no
/// longer pass.
pub const RECOMPILE_WITHIN: core::time::Duration = core::time::Duration::from_secs(1);

/// Recomputes which of a peer's live grants survive a new policy.
///
/// Returns the grants to withdraw, each of which emits
/// `POLICY.GRANT_REVOKED_BY_POLICY`.
#[must_use]
pub fn withdraw_after_policy_change(
    policy: &GatewayPolicy,
    live: &[Grant],
    client_local: &[IpPrefix],
) -> Vec<Grant> {
    live.iter()
        .filter(|g| match g {
            Grant::LanAccess { peer, prefix, .. } => {
                lan_refusal(policy, *peer, *prefix, prefix.family(), client_local).is_some()
            }
            Grant::ExitNode { granted, .. } => [AddressFamily::V4, AddressFamily::V6]
                .into_iter()
                .any(|f| granted.get(f).is_granted() && !*policy.egress_families.get(f)),
        })
        .cloned()
        .collect()
}
