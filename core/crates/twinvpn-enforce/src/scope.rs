//! ADR-0012 §11.1's two tiers, and KS-3a's scope qualifier.
//!
//! **Authority:** ADR-0012 §11.1 (normative), KS-1, KS-2, KS-3, KS-3a, KS-4;
//! ADR-0010 §11.5.
//!
//! # Tier 2 references no prefix, ever
//!
//! §11.1: "Tier 2 is interface-scoped and default-deny, is expressed as one
//! object covering both families, and **MUST NOT** reference any destination
//! prefix."
//!
//! That is why [`Tier2`] carries an interface index and nothing else. A
//! prefix-shaped Tier 2 is the design ADR-0010 §11.5(2) rejects: "a newly
//! learned IPv6 prefix cannot escape by being unknown to an allow-list, because
//! there is no allow-list of prefixes."

use twinvpn_platform::InterfaceIndex;
use twinvpn_types::{AddressFamily, IpAddr, IpPrefix};

use twinvpn_route::RoutingMode;

/// KS-4's setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalNetworkAccess {
    /// On-link prefixes of non-overlay interfaces are permitted.
    ///
    /// The permitted set is "**on-link prefixes only**, recomputed on every
    /// network-change event, and never includes a destination reachable only via
    /// a router".
    Allow,
    /// The iOS/macOS `excludeLocalNetworks` inverse.
    Deny,
}

impl LocalNetworkAccess {
    /// KS-4's defaults: `ALLOW` in TwinNet-only and split-tunnel, and `ALLOW` in
    /// full tunnel with a one-toggle `DENY`.
    #[must_use]
    pub const fn default_for(_mode: RoutingMode) -> Self {
        LocalNetworkAccess::Allow
    }
}

/// Tier 1: **which packets are in the protected scope**.
///
/// Full tunnel is deliberately the **complement** form: §11.1 says it "MUST NOT
/// be expressed as an enumeration of protected prefixes", and the P07 mutant is
/// exactly "a build whose Tier 1 is prefix-enumerated rather than
/// complement-form in full-tunnel mode".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier1 {
    /// Destination ∈ the TwinNet prefixes.
    TwinnetOnly {
        /// The overlay prefixes, both families.
        overlay: Vec<IpPrefix>,
    },
    /// The above ∪ every **accepted** `Route` prefix, both families.
    SplitTunnel {
        /// The overlay prefixes.
        overlay: Vec<IpPrefix>,
        /// Accepted route prefixes.
        accepted: Vec<IpPrefix>,
    },
    /// **Every** packet except §11.2's exempt classes.
    FullTunnelComplement,
    /// The platform's app set.
    PerApp,
}

impl Tier1 {
    /// Builds the Tier-1 scope for a routing mode.
    #[must_use]
    pub fn for_mode(mode: RoutingMode, overlay: Vec<IpPrefix>, accepted: Vec<IpPrefix>) -> Self {
        match mode {
            RoutingMode::TwinnetOnly => Tier1::TwinnetOnly { overlay },
            RoutingMode::SplitTunnel => Tier1::SplitTunnel { overlay, accepted },
            RoutingMode::FullTunnel => Tier1::FullTunnelComplement,
            RoutingMode::PerApp => Tier1::PerApp,
        }
    }

    /// Whether a destination is inside the protected scope.
    ///
    /// KS-3a's qualifier is why this can answer `false`: the §11.2 table is
    /// "exhaustive **over the Tier-1 protected set**, which is mode-dependent;
    /// traffic outside that set is not governed by this table and is not dropped
    /// by it". Without that, a TwinNet-only device in `BLOCKED` would lose all
    /// name resolution and therefore all Internet.
    #[must_use]
    pub fn contains(&self, destination: IpAddr) -> bool {
        match self {
            Tier1::TwinnetOnly { overlay } => overlay.iter().any(|p| p.contains(destination)),
            Tier1::SplitTunnel { overlay, accepted } => overlay
                .iter()
                .chain(accepted.iter())
                .any(|p| p.contains(destination)),
            // The complement form: everything is in scope, and §11.2's exempt
            // classes are what carve pieces out. Per-app is the platform's app
            // set, which a destination check cannot narrow either — so both
            // answer "in scope" and let §11.2 do the carving.
            Tier1::FullTunnelComplement | Tier1::PerApp => true,
        }
    }

    /// Whether this scope is expressed as an enumeration of prefixes.
    ///
    /// Asserted by the P07 mutant test: full tunnel must answer `false`.
    #[must_use]
    pub const fn is_prefix_enumerated(&self) -> bool {
        matches!(self, Tier1::TwinnetOnly { .. } | Tier1::SplitTunnel { .. })
    }
}

/// Tier 2: **where a protected packet may egress**.
///
/// One value covering both families, because ADR-0010 §11.5(1) makes it one
/// object: "**There is no code path that installs IPv4 protection without IPv6
/// protection**, because there is no separate IPv6 object to forget. This is a
/// structural guarantee, not a discipline."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier2 {
    /// The **only** interface protected traffic may leave by.
    pub overlay_interface: InterfaceIndex,
}

impl Tier2 {
    /// Whether a protected packet on `egress` is permitted.
    ///
    /// Default deny, scoped by interface, with **no** destination in the
    /// question — which is what makes "IPv6 enabled after the tunnel is up"
    /// denied by the pre-existing rule with no rule update required for
    /// correctness.
    #[must_use]
    pub fn permits(self, egress: InterfaceIndex) -> bool {
        egress == self.overlay_interface
    }

    /// Both families are covered by construction; this exists so the property
    /// can be asserted rather than assumed (KS-5).
    #[must_use]
    pub const fn covers(self, _family: AddressFamily) -> bool {
        true
    }
}

/// KS-2: forwarded traffic is protected by the same Tier-2 rule and is **never**
/// eligible for any §11.2 exemption.
#[must_use]
pub const fn forwarded_traffic_is_exemptible() -> bool {
    false
}

/// KS-1: a Tier-1 scope change is applied **atomically with the contract
/// generation that caused it**.
///
/// > A scope may never be *narrowed* and a rule set *widened* in two steps; the
/// > transition is one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeTransaction {
    /// The generation this scope belongs to.
    pub generation: twinvpn_platform::ContractGeneration,
    /// The scope.
    pub tier1: Tier1,
    /// The egress rule.
    pub tier2: Tier2,
    /// KS-4's setting, and the on-link prefixes it permits.
    pub local_network_access: LocalNetworkAccess,
    /// The on-link prefixes of non-overlay interfaces, recomputed on every
    /// network-change event.
    pub on_link: Vec<IpPrefix>,
}

/// ADR-0012 §11.13's `ruleset_digest` width.
pub const RULESET_DIGEST_LEN: usize = 32;

/// The domain separator. A digest is only ever compared with another digest of
/// the same thing, and this makes "the same thing" explicit and versioned.
const RULESET_DIGEST_DOMAIN: &[u8] = b"twinvpn/enforce/ruleset-digest/v1";

impl ScopeTransaction {
    /// ADR-0012 §11.13's `ruleset_digest`: "hash of the installed rule set, for
    /// O-17 assertion".
    ///
    /// # What it covers, and why the generation is not in it
    ///
    /// The digest is over the **rule set**, which §11.1 defines as the Tier-1
    /// protected scope, the Tier-2 egress rule, and KS-4's local-network
    /// setting. [`ScopeTransaction::generation`] is deliberately **excluded**:
    /// it identifies the transaction, not the rules. Including it would make
    /// every re-application produce a new digest, and the clause this value
    /// exists to serve is a stability clause — `docs/testing-strategy.md` P07:
    /// "the `ruleset_digest` is **unchanged** across the trigger … A digest
    /// change here means the design's structural claim is false even if no
    /// packet leaked."
    ///
    /// `on_link` is folded in **only under [`LocalNetworkAccess::Allow`]**,
    /// because that is the only setting under which those prefixes are rules at
    /// all. Under `Deny` they permit nothing, so a new interface appearing must
    /// not move the digest — which is P07 variant (c) exactly. Under `Allow` a
    /// new on-link prefix genuinely does widen the installed rule set, and the
    /// digest says so rather than hiding it; that widening is what KS-4's `DENY`
    /// toggle exists to refuse.
    ///
    /// # Framing
    ///
    /// Length-prefixed, unlike this project's wire MACs. Those hash formats the
    /// ADRs specify as fixed-width-then-variable; this one concatenates several
    /// variable-length prefix lists, where an unprefixed encoding would let two
    /// different rule sets collide — the same call ADR-0020 §11.5 made for the
    /// record AAD. Prefixes are sorted and de-duplicated so that two equal rule
    /// sets discovered in different orders digest identically.
    #[must_use]
    pub fn ruleset_digest(&self) -> [u8; RULESET_DIGEST_LEN] {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(RULESET_DIGEST_DOMAIN);

        // Tier 1: the discriminant first, so a mode change alone moves the
        // digest even when the two modes carry the same prefix list.
        match &self.tier1 {
            Tier1::TwinnetOnly { overlay } => {
                buf.push(1);
                absorb_prefixes(&mut buf, overlay);
            }
            Tier1::SplitTunnel { overlay, accepted } => {
                buf.push(2);
                absorb_prefixes(&mut buf, overlay);
                absorb_prefixes(&mut buf, accepted);
            }
            // The complement form carries no prefix list, which is the whole
            // point of §11.1's "MUST NOT be expressed as an enumeration of
            // protected prefixes" — and is why a newly learned prefix cannot
            // move this digest in full-tunnel mode.
            Tier1::FullTunnelComplement => buf.push(3),
            Tier1::PerApp => buf.push(4),
        }

        // Tier 2: one interface, both families, no destination.
        buf.push(0x80);
        buf.extend_from_slice(&self.tier2.overlay_interface.0.to_be_bytes());

        // KS-4.
        buf.push(match self.local_network_access {
            LocalNetworkAccess::Allow => 1,
            LocalNetworkAccess::Deny => 2,
        });
        if self.local_network_access == LocalNetworkAccess::Allow {
            absorb_prefixes(&mut buf, &self.on_link);
        }

        twinvpn_crypto::sha256(&buf)
    }
}

/// Absorbs a prefix list: count, then each prefix as `family ‖ len ‖ octets`.
///
/// Sorted and de-duplicated first, so the digest is a function of the SET rather
/// than of the order the prefixes happened to be discovered in.
fn absorb_prefixes(buf: &mut Vec<u8>, prefixes: &[IpPrefix]) {
    let mut canonical: Vec<([u8; 16], usize, u32, u8)> = prefixes
        .iter()
        .map(|p| {
            let (octets, len) = p.address().octet_buffer();
            let family = match p.family() {
                AddressFamily::V4 => 4u8,
                AddressFamily::V6 => 6u8,
            };
            (octets, len, p.prefix_len(), family)
        })
        .collect();
    canonical.sort_unstable();
    canonical.dedup();

    buf.extend_from_slice(
        &u32::try_from(canonical.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (octets, len, prefix_len, family) in canonical {
        buf.push(family);
        buf.extend_from_slice(&prefix_len.to_be_bytes());
        buf.extend_from_slice(&octets[..len]);
    }
}
