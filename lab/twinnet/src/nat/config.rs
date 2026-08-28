//! What a middlebox is, expressed as data.
//!
//! **Authority:** `docs/testing-strategy.md` §3.3.
//!
//! §3.3's first sentence is the one that shapes this file:
//!
//! > Mapping and filtering are configured **independently**, because they are
//! > independent axes and conflating them is exactly the defect the legacy
//! > vocabulary causes.
//!
//! So there is no `Personality` enum here that a `match` could quietly collapse
//! into "cone or symmetric". A [`NatConfig`] carries a [`Mapping`] and a
//! [`Filtering`] that are set separately, plus the three orthogonal axes §3.3's
//! second table adds — mapping lifetime, hairpinning, and the port budget that
//! makes CGNAT exhaustion reachable. [`NatConfig::personality`] exists only to
//! *name* a combination for a run record; nothing in the forwarding path reads
//! it.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// RFC 4787 mapping behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mapping {
    /// No translation. `N-ROUTED`, and the IPv6 default.
    None,
    /// Endpoint-Independent Mapping: one external port per internal socket,
    /// whatever it is talking to.
    EndpointIndependent,
    /// Address-and-Port-Dependent Mapping with uniform allocation. §3.6's
    /// birthday-prediction target.
    AddressPortDependentRandom,
    /// Address-and-Port-Dependent Mapping with a monotone allocator. §3.6's
    /// delta-prediction target.
    AddressPortDependentSequential,
}

/// RFC 4787 filtering behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Filtering {
    /// No filtering — a router.
    None,
    /// Endpoint-Independent Filtering: any source may use an open mapping.
    EndpointIndependent,
    /// Address-Dependent Filtering: the source address must have been written
    /// to; the port need not match.
    AddressDependent,
    /// Address-and-Port-Dependent Filtering: both must match.
    AddressPortDependent,
}

/// What the middlebox does to traffic leaving the inside, before any
/// translation.
///
/// §3.4's "Blocked UDP" and "Egress restricted to 443" rows specify an `nft`
/// drop in the transit namespace. On a host with no `nftables` the same
/// observable condition is produced here, in the middlebox that is already in
/// the path. The system under test sees a network that drops its UDP; it cannot
/// see which subsystem dropped it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Egress {
    /// Everything passes.
    Allow,
    /// Every UDP datagram is dropped, both families.
    BlockUdp,
    /// UDP is dropped except to the listed destination ports.
    BlockUdpExcept {
        /// The destination ports that still pass.
        ports: Vec<u16>,
    },
    /// Only the listed destination ports pass, on any protocol. The
    /// "restricted to 443" row.
    AllowOnlyPorts {
        /// The destination ports that pass.
        ports: Vec<u16>,
    },
    /// Nothing passes in either direction. The blackhole a region outage, a
    /// control-plane outage and a network partition are all built from.
    Blackhole,
}

impl Egress {
    /// Whether a packet to `port` on `proto` may leave.
    #[must_use]
    pub fn permits(&self, proto: u8, port: u16) -> bool {
        const UDP: u8 = crate::ip::proto::UDP;
        match self {
            Egress::Allow => true,
            Egress::Blackhole => false,
            Egress::BlockUdp => proto != UDP,
            Egress::BlockUdpExcept { ports } => proto != UDP || ports.contains(&port),
            Egress::AllowOnlyPorts { ports } => ports.contains(&port),
        }
    }
}

/// A MAC address, as JSON carries it.
pub type Mac = [u8; 6];

/// A statically known next hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Neighbour {
    /// The address, in text form so a configuration file reads.
    pub addr: String,
    /// Its link-layer address.
    pub mac: Mac,
}

/// One middlebox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatConfig {
    /// §3.3's name for this combination, for the run record only. Nothing in
    /// the forwarding path reads it.
    pub personality: String,
    /// The mapping axis.
    pub mapping: Mapping,
    /// The filtering axis, set independently of the mapping.
    pub filtering: Filtering,

    /// The interface facing the subscriber.
    pub inside_if: String,
    /// The interface facing the transit network.
    pub outside_if: String,
    /// This middlebox's MAC on the inside.
    pub inside_mac: Mac,
    /// This middlebox's MAC on the outside.
    pub outside_mac: Mac,
    /// The next hop on the inside, used until a source MAC is learned for a
    /// given internal address.
    pub inside_peer_mac: Mac,
    /// The next hop on the outside, used for a destination no entry in
    /// [`NatConfig::outside_neighbours`] names and that has not been observed.
    pub outside_peer_mac: Mac,
    /// The prefixes that live behind this middlebox.
    ///
    /// Traffic from the inside to another inside address is **forwarded, not
    /// translated**. No NAT translates a packet that never leaves, and a
    /// middlebox that did would make two hosts on one LAN reach each other
    /// through a public address — which is the opposite of the local-direct
    /// path ADR-0004 prefers, and would have made a `LOCAL_DIRECT` scenario
    /// assert the wrong thing while looking green.
    #[serde(default)]
    pub inside_prefixes: Vec<String>,
    /// Static next hops on the outside segment.
    ///
    /// A middlebox with exactly one neighbour does not need this. One on a
    /// shared transit segment does, and the reason is the traversal matrix: the
    /// FIRST packet of a simultaneous open is aimed at a peer this middlebox has
    /// never heard from, so there is nothing to have learned yet. A middlebox
    /// that had to learn the next hop first would fail every direct-traversal
    /// scenario on its first packet and succeed on the retry, which is a
    /// laboratory artefact indistinguishable from a slow NAT.
    #[serde(default)]
    pub outside_neighbours: Vec<Neighbour>,

    /// The external IPv4 address, if this middlebox has one.
    pub public_v4: Option<Ipv4Addr>,
    /// The RFC 6052 translation prefix, when this middlebox is a NAT64.
    ///
    /// `None` is an ordinary middlebox. `Some` turns on §3.3's `N-NAT64` row:
    /// an IPv6 destination inside the prefix is **translated** into IPv4 rather
    /// than forwarded, and the reply is translated back. The two are mutually
    /// exclusive in practice — a v6-only access network has no v4 to route —
    /// and keeping it an `Option` rather than a personality variant is what lets
    /// the mapping and filtering axes stay independent here as everywhere else.
    #[serde(default)]
    pub pref64: Option<crate::nat::xlat::Pref64>,
    /// The external IPv6 address, if this middlebox translates v6 at all.
    /// `None` on every personality except a deliberately v6-NATting one, because
    /// §3.2's last row makes native v6 the case that must keep working.
    pub public_v6: Option<Ipv6Addr>,

    /// The low end of the external port budget, inclusive.
    ///
    /// A *budget*, not a range of convenience: §3.3 requires CGNAT port
    /// exhaustion to be reachable, and a middlebox with 60 000 ports is one
    /// whose exhaustion path is never taken.
    pub port_low: u16,
    /// The high end, inclusive.
    pub port_high: u16,

    /// How long an idle mapping survives. §3.3's three values are 30 s
    /// (mobile), 120 s and 300 s (home CPE).
    pub mapping_lifetime_ms: u64,
    /// RFC 4787 REQ-9. Off by default so a test must ask for the easy path.
    pub hairpin: bool,
    /// The seed the random allocator uses, so `-RAND` is reproducible.
    pub seed: u64,
    /// What leaves the inside at all.
    pub egress: Egress,
    /// The largest packet this middlebox will forward, if it constricts at all.
    ///
    /// A middlebox that forwards in userspace generates no ICMP of its own, so
    /// without this there is nothing for [`NatConfig::drop_pmtu_icmp`] to
    /// suppress and a "black hole" would be indistinguishable from a working
    /// path. With it, an oversize packet is dropped and the middlebox either
    /// **reports** it — an ordinary MTU mismatch, which PMTU discovery resolves
    /// — or does not, which is the black hole.
    #[serde(default)]
    pub egress_mtu: Option<u32>,
    /// Silently drop the ICMP messages Path MTU discovery depends on.
    ///
    /// §3.4's PMTU black hole row: "Reduced MTU **plus** `nft` drop of ICMPv4
    /// type 3 code 4 and ICMPv6 type 2 in the transit namespace". Those two
    /// messages are the *only* way a sender learns a path's MTU, so a middlebox
    /// that swallows them turns an MTU problem into a silent one — which is the
    /// condition, and is why it is a switch rather than a side effect of
    /// clamping the MTU.
    #[serde(default)]
    pub drop_pmtu_icmp: bool,
    /// Where to write the mapping-table snapshot when signalled, so a
    /// conformance run can read what the middlebox actually did.
    pub stats_path: Option<String>,
}

impl NatConfig {
    /// The number of external ports this middlebox may allocate.
    #[must_use]
    pub const fn budget(&self) -> u32 {
        (self.port_high as u32).saturating_sub(self.port_low as u32) + 1
    }

    /// Refuses a configuration that cannot mean what it says.
    ///
    /// # Errors
    ///
    /// A message naming the contradiction. Two are worth calling out because
    /// both produce a *green* run rather than a broken one:
    ///
    /// - a translating mapping with no public address translates to nothing and
    ///   silently drops every packet, which reads as "no traversal";
    /// - an inverted port budget allocates nothing, which reads the same way.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.pref64.is_some() && self.public_v4.is_none() {
            return Err(format!(
                "personality `{}` is a NAT64 and has no public IPv4 address to translate \
                 towards; every translated packet would be dropped, which reads as \
                 `the v4 Internet is unreachable`",
                self.personality
            ));
        }
        if self.pref64.is_some_and(|p| p.len != 96) {
            return Err(
                "only a /96 translation prefix is implemented; see `nat::xlat`'s module note"
                    .to_owned(),
            );
        }
        if self.mapping != Mapping::None && self.public_v4.is_none() && self.public_v6.is_none() {
            return Err(format!(
                "personality `{}` translates but has no public address to translate to",
                self.personality
            ));
        }
        if self.port_low > self.port_high {
            return Err(format!(
                "the port budget {}..={} is empty",
                self.port_low, self.port_high
            ));
        }
        if self.mapping_lifetime_ms == 0 {
            return Err(
                "a zero mapping lifetime expires every mapping before its reply".to_owned(),
            );
        }
        Ok(())
    }
}
