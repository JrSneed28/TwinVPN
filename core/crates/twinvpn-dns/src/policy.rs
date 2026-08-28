//! `DNSPolicy` validation — and CF-10's explicit-presence fields, which are the
//! whole point of this module.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/dns.proto` (frozen),
//! `docs/protocol.md` §13.4, ADR-0011 §11.5, DN-8, DN-10; ADR-0008 N-3
//! (monotone version); `contracts/registry/limits.json` `dns.*`.
//!
//! # An absent `block_fallback` is not a permission
//!
//! `dns.proto`, verbatim:
//!
//! > `dns_policy` MUST specify servers for both families and MUST state
//! > `block_fallback` per family. A DNS policy that configures v4 resolvers and
//! > leaves v6 resolvers to the OS is a DNS LEAK; **the schema forbids
//! > expressing it** by requiring both lists to be present (EMPTY LIST = 'BLOCK
//! > THIS FAMILY', which is different from ABSENT).
//!
//! Proto3 cannot tell an empty repeated field from an absent one, so the schema
//! carries `servers_declared_v4` / `servers_declared_v6` as **explicit presence
//! bits**. [`validate()`] treats either bit unset as **malformed**, never as "v6
//! unconfigured" — §13.4 forbids expressing "v4 configured, v6 left to the OS",
//! and this is the enforcement of that.
//!
//! `block_fallback` is **deny-shaped**: `true` is honoured, `false` is a *grant*
//! that suspends on bundle expiry (ADR-0009 §11.4's grant/deny asymmetry). So an
//! absent `block_fallback` reads as `true` — the restrictive answer — and
//! [`Dnspolicy::block_fallback`] never returns "permitted" for a value nobody
//! supplied.

use twinvpn_schema::v1;
use twinvpn_schema::{validate, Reject};
use twinvpn_types::{AddressFamily, IpAddr, PerFamily, V4Addr, V6Addr};

/// `DNSPolicy.mode`, exactly ADR-0011 §11.5's three values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Default. TwinNet zones local; default-class queries to the host's
    /// pre-existing upstream over the underlay — **only** when the routing mode
    /// puts those destinations outside the protected scope.
    Split,
    /// TwinNet zones local; default-class queries to the policy's resolvers,
    /// **over the overlay only**.
    Full,
    /// Not served. Permitted **only** with TwinNet-only routing and an explicit
    /// setting; **never** with full routing or an engaged `ExitNode`.
    Off,
}

impl Mode {
    /// Decodes `twinvpn.v1.DnsMode`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Malformed`] for the unspecified zero value or an unknown
    /// one — never a silent default, which would pick a mode the author did not
    /// choose.
    pub fn from_wire(value: i32) -> Result<Self, PolicyError> {
        match value {
            1 => Ok(Mode::Split),
            2 => Ok(Mode::Full),
            3 => Ok(Mode::Off),
            _ => Err(PolicyError::Malformed("dns_policy.mode")),
        }
    }
}

/// What a split-domain rule does with a matching name (§11.4 class 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// Answer authoritatively from the TwinNet contract.
    Twinnet,
    /// Forward to the policy's protected upstream, over the overlay.
    ProtectedUpstream,
    /// `REFUSED` + EDE 18 Prohibited. **Never NXDOMAIN** (DN-11).
    Refuse,
}

impl Disposition {
    /// Decodes `twinvpn.v1.SplitDomainDisposition`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Malformed`] on the zero value or an unknown one.
    pub fn from_wire(value: i32) -> Result<Self, PolicyError> {
        match value {
            1 => Ok(Disposition::Twinnet),
            2 => Ok(Disposition::ProtectedUpstream),
            3 => Ok(Disposition::Refuse),
            _ => Err(PolicyError::Malformed("split_domain_rule.disposition")),
        }
    }
}

/// One validated steering rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRule {
    /// The suffix, lowercase, in wire-label form (DN-9).
    pub labels: Vec<Vec<u8>>,
    /// Whether this matches only the exact name, taking precedence over every
    /// suffix rule.
    pub exact: bool,
    /// What to do with a match.
    pub disposition: Disposition,
}

impl SplitRule {
    /// The rule's specificity: label count, with an exact match ranking above
    /// every suffix rule of any length.
    #[must_use]
    pub fn specificity(&self) -> (bool, usize) {
        (self.exact, self.labels.len())
    }
}

/// A validated `DNSPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnspolicy {
    /// The policy identifier.
    pub id: String,
    /// Monotone. ADR-0008 N-3: a device MUST reject a lower version.
    pub version: u64,
    /// The mode.
    pub mode: Mode,
    /// Protected-scope upstream resolvers, per family. **Both lists are
    /// structurally required**; an empty list means "block this family".
    pub servers: PerFamily<Vec<IpAddr>>,
    /// Steering rules, in policy order.
    pub split_rules: Vec<SplitRule>,
    /// Search domains pushed to the host.
    pub search_domains: Vec<String>,
    /// Per family. Deny-shaped: an absent value reads `true`.
    block_fallback: PerFamily<bool>,
    /// Whether the stub validates DNSSEC.
    pub dnssec_validate: bool,
    /// Whether upstream is reached over DoT.
    pub upstream_dot: bool,
    /// Bundle expiry, for ADR-0009 §11.4's grant suspension.
    pub not_after_ms: u64,
}

impl Dnspolicy {
    /// Whether fallback is blocked for `family`.
    ///
    /// Deny-shaped, so this is the **only** accessor and it never returns
    /// "permitted" for an absent value: [`validate()`] has already rejected a
    /// policy whose bits were not supplied.
    #[must_use]
    pub fn block_fallback(&self, family: AddressFamily) -> bool {
        *self.block_fallback.get(family)
    }

    /// ADR-0009 §11.4: on expiry, **grants suspend and denials persist**.
    ///
    /// A `block_fallback = false` is a grant, so an expired bundle turns it back
    /// into `true`. "An expired bundle can therefore only ever become **more**
    /// restrictive."
    pub fn suspend_grants_on_expiry(&mut self) {
        *self.block_fallback.get_mut(AddressFamily::V4) = true;
        *self.block_fallback.get_mut(AddressFamily::V6) = true;
    }
}

/// Validates a decoded `DnsPolicy` against the frozen schema's own rules.
///
/// The presence bits are checked **first**, because they are the check §13.4
/// exists for and because a policy that fails them must not be partially
/// interpreted.
///
/// # Errors
///
/// - [`PolicyError::ServersNotDeclared`] when `servers_declared_v4` or
///   `servers_declared_v6` is unset or `false`. **This is malformed, not "v6
///   unconfigured".**
/// - [`PolicyError::BlockFallbackNotDeclared`] when either `block_fallback_*` is
///   absent. An absent deny-shaped field is not a permission; refusing the
///   policy is the only reading that cannot leak.
/// - [`PolicyError::RuleConflict`] when two rules of equal specificity carry
///   different dispositions (DN-8) — rejected at bundle validation, with the
///   previous bundle left governing.
/// - [`PolicyError::Cap`] on any `limits.json` `dns.*` cap.
/// - [`PolicyError::Malformed`] on an enum zero value or a malformed name.
pub fn validate(msg: &v1::DnsPolicy) -> Result<Dnspolicy, PolicyError> {
    // CF-10 / §13.4, before anything else.
    if msg.servers_declared_v4 != Some(true) {
        return Err(PolicyError::ServersNotDeclared(AddressFamily::V4));
    }
    if msg.servers_declared_v6 != Some(true) {
        return Err(PolicyError::ServersNotDeclared(AddressFamily::V6));
    }
    let Some(block_v4) = msg.block_fallback_v4 else {
        return Err(PolicyError::BlockFallbackNotDeclared(AddressFamily::V4));
    };
    let Some(block_v6) = msg.block_fallback_v6 else {
        return Err(PolicyError::BlockFallbackNotDeclared(AddressFamily::V6));
    };

    // Caps before any allocation proportional to a declared length.
    validate::dns_policy_shape(
        msg.split_domains.len(),
        msg.search_domains.len(),
        msg.servers_v4.len(),
        msg.servers_v6.len(),
    )
    .map_err(PolicyError::Cap)?;

    let mode = Mode::from_wire(msg.mode)?;

    let mut servers = PerFamily::new(Vec::new(), Vec::new());
    for a in &msg.servers_v4 {
        let addr =
            V4Addr::from_slice(&a.octets).map_err(|_| PolicyError::Malformed("servers_v4"))?;
        servers.get_mut(AddressFamily::V4).push(IpAddr::V4(addr));
    }
    for a in &msg.servers_v6 {
        let addr = V6Addr::from_slice(&a.octets, a.zone_index)
            .map_err(|_| PolicyError::Malformed("servers_v6"))?;
        servers.get_mut(AddressFamily::V6).push(IpAddr::V6(addr));
    }

    let mut split_rules = Vec::with_capacity(msg.split_domains.len());
    for r in &msg.split_domains {
        validate::domain_name(&r.suffix).map_err(PolicyError::Cap)?;
        split_rules.push(SplitRule {
            labels: crate::classify::wire_labels(&r.suffix),
            exact: r.exact_match,
            disposition: Disposition::from_wire(r.disposition)?,
        });
    }

    // DN-8: ties are a policy defect, not a runtime coin-flip.
    for (i, a) in split_rules.iter().enumerate() {
        for b in &split_rules[i + 1..] {
            if a.labels == b.labels && a.exact == b.exact && a.disposition != b.disposition {
                return Err(PolicyError::RuleConflict);
            }
        }
    }

    for d in &msg.search_domains {
        validate::domain_name(d).map_err(PolicyError::Cap)?;
    }

    Ok(Dnspolicy {
        id: msg.dnspolicy_id.clone(),
        version: msg.version,
        mode,
        servers,
        split_rules,
        search_domains: msg.search_domains.clone(),
        block_fallback: PerFamily::new(block_v4, block_v6),
        dnssec_validate: msg.dnssec_validate,
        upstream_dot: msg.upstream_dot,
        not_after_ms: msg.not_after_ms,
    })
}

/// ADR-0008 N-3: a lower version is rejected and the rejection is a **security
/// event**, because "a stale `DNSPolicy` \[could\] reintroduce a leak that a newer
/// one closed".
#[must_use]
pub const fn accepts_version(current: u64, offered: u64) -> bool {
    offered > current
}

/// ADR-0011 §11.5: `OFF` is permitted **only** with TwinNet-only routing and an
/// explicit setting; **never** with full routing or an engaged `ExitNode`.
#[must_use]
pub const fn off_mode_permitted(full_tunnel: bool, exit_node_engaged: bool) -> bool {
    !full_tunnel && !exit_node_engaged
}

/// Why a policy was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// A `servers_declared_*` presence bit was unset. §13.4: malformed, **not**
    /// "that family is unconfigured".
    #[error("dns_policy did not declare servers for {0:?}")]
    ServersNotDeclared(AddressFamily),
    /// A `block_fallback_*` presence bit was absent. Deny-shaped fields have no
    /// permissive default.
    #[error("dns_policy did not state block_fallback for {0:?}")]
    BlockFallbackNotDeclared(AddressFamily),
    /// DN-8: two rules of equal specificity disagree.
    #[error("two split-domain rules of equal specificity disagree")]
    RuleConflict,
    /// A `limits.json` cap was violated.
    #[error("dns_policy violated a registry cap")]
    Cap(Reject),
    /// A field was malformed.
    #[error("dns_policy field {0} is malformed")]
    Malformed(&'static str),
}
