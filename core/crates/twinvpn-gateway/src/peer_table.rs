//! ADR-0013 §11.1's peer table, and §11.2's anti-spoofing.
//!
//! **Authority:** ADR-0013 §11.1 (MG-1 … MG-3), §11.2 (MG-4 … MG-7); ADR-0012
//! KS-2; ADR-0010 §11.1.
//!
//! # MG-4 is cryptokey routing's central security property
//!
//! > The binding of key to identity established by ADR-0001 and ADR-0007 is only
//! > worth something if the address in the inner header is checked against it.
//!
//! [`PeerTable::attribute_ingress`] performs that check "at the **decapsulation
//! stage** of the forwarding path, **before** route lookup, before conntrack,
//! before policy" — which is why it is the first method a packet meets and why
//! it returns a typed refusal rather than an `Option`.
//!
//! # Wildcards are not expressible
//!
//! MG-1: "Wildcards MUST NOT be expressible; `0.0.0.0/0` and `::/0` MUST NOT
//! appear in an `allowed_sources` set." [`AllowedSources::insert`] refuses a
//! zero-length prefix, so a wildcard cannot be built rather than being caught
//! later.

use twinvpn_types::{DeviceId, IpAddr, IpPrefix, PerFamily};

/// The set of addresses one peer may claim as a source.
///
/// "For an ordinary client peer this set is exactly two host addresses" — its
/// `/32` and its `/128`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSources {
    prefixes: PerFamily<Vec<IpPrefix>>,
}

impl Default for AllowedSources {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowedSources {
    /// An empty set. Default-deny: a peer with no entries may claim nothing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefixes: PerFamily::new(Vec::new(), Vec::new()),
        }
    }

    /// Adds a prefix, refusing a wildcard.
    ///
    /// Returns `false` for a zero-length prefix (MG-1). A wildcard in an
    /// `allowed_sources` set would make MG-4's check vacuous.
    pub fn insert(&mut self, prefix: IpPrefix) -> bool {
        if prefix.prefix_len() == 0 {
            return false;
        }
        self.prefixes.get_mut(prefix.family()).push(prefix);
        true
    }

    /// Whether `addr` is inside this set.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.prefixes
            .get(addr.family())
            .iter()
            .any(|p| p.contains(addr))
    }

    /// Whether both families are populated.
    ///
    /// MG-3: "A build that can populate the v4 half of a peer row **without the
    /// v6 half** is non-conforming, mirroring ADR-0012 KS-5."
    #[must_use]
    pub fn both_families_present(&self) -> bool {
        !self
            .prefixes
            .get(twinvpn_types::AddressFamily::V4)
            .is_empty()
            && !self
                .prefixes
                .get(twinvpn_types::AddressFamily::V6)
                .is_empty()
    }

    /// Whether this set overlaps another (MG-2).
    #[must_use]
    pub fn overlaps(&self, other: &AllowedSources) -> bool {
        for f in [
            twinvpn_types::AddressFamily::V4,
            twinvpn_types::AddressFamily::V6,
        ] {
            for a in self.prefixes.get(f) {
                for b in other.prefixes.get(f) {
                    if a.contains(b.address()) || b.contains(a.address()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Every prefix, per family.
    #[must_use]
    pub const fn prefixes(&self) -> &PerFamily<Vec<IpPrefix>> {
        &self.prefixes
    }
}

/// One row of the peer table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRow {
    /// Derived from the static key (ADR-0007).
    pub device_id: DeviceId,
    /// Ingress: what this peer may claim.
    pub allowed_sources: AllowedSources,
    /// The `policy_version` its compiled grants were stamped from. Monotone.
    pub policy_version: u64,
    /// Whether the peer is revoked at the current trust epoch (S-03, a cached
    /// bit — never a control-plane call on the forwarding path).
    pub revoked: bool,
}

/// Why a packet was refused, with the code §11.3's table names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// MG-4. `CRITICAL`, counted against the peer, and **never** forwarded,
    /// source-rewritten or silently discarded.
    #[error("the inner source address is not in the peer's allowed_sources")]
    SourceSpoofed,
    /// The peer is revoked at the current trust epoch.
    #[error("the peer is revoked")]
    PeerRevoked,
    /// MG-5. Transit is directional and is **not implied** by both devices being
    /// peers of the gateway.
    #[error("peer-to-peer transit through this gateway is not permitted")]
    PeerTransitDenied,
    /// The destination is not in the peer's granted prefix set.
    #[error("the destination prefix is not granted to this peer")]
    PrefixNotGranted,
    /// The port or protocol is outside the matched rule's scope.
    #[error("the port or protocol is outside the granted scope")]
    PortScopeDenied,
    /// No exit-node grant is engaged for this peer.
    #[error("no exit-node engagement exists for this peer")]
    ExitNotEngaged,
    /// The peer is unknown. A packet that authenticates under no key never
    /// reaches here, so this is a table-consistency defect.
    #[error("the peer is not admitted")]
    NotAdmitted,
}

/// The gateway's peer table.
#[derive(Debug, Default)]
pub struct PeerTable {
    rows: Vec<PeerRow>,
}

impl PeerTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many peers are admitted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Admits a peer, refusing an overlapping source set.
    ///
    /// MG-2: overlap is "a control-plane allocation bug … the check exists
    /// because a silent overlap would be a **cross-peer interception
    /// primitive**."
    ///
    /// # Errors
    ///
    /// [`AdmitError::SourceSetOverlap`] on an overlap with an admitted peer, and
    /// [`AdmitError::SingleFamilySourceSet`] when only one family is populated
    /// (MG-3).
    pub fn admit(&mut self, row: PeerRow) -> Result<(), AdmitError> {
        if !row.allowed_sources.both_families_present() {
            return Err(AdmitError::SingleFamilySourceSet);
        }
        if self
            .rows
            .iter()
            .any(|r| r.allowed_sources.overlaps(&row.allowed_sources))
        {
            return Err(AdmitError::SourceSetOverlap);
        }
        self.rows.push(row);
        Ok(())
    }

    /// Removes a peer.
    pub fn remove(&mut self, device: DeviceId) {
        self.rows.retain(|r| r.device_id != device);
    }

    /// The row for a peer.
    #[must_use]
    pub fn row(&self, device: DeviceId) -> Option<&PeerRow> {
        self.rows.iter().find(|r| r.device_id == device)
    }

    /// Ingress attribution, run **before** route lookup, conntrack and policy.
    ///
    /// The peer is identified by which key authenticated the frame — "the
    /// overlay source address is **never** used to identify the sender" — and
    /// then the inner source is checked against that peer's set.
    ///
    /// # Errors
    ///
    /// [`Refusal::NotAdmitted`], [`Refusal::SourceSpoofed`] (MG-4) or
    /// [`Refusal::PeerRevoked`].
    pub fn attribute_ingress(
        &self,
        authenticated_as: DeviceId,
        inner_source: IpAddr,
    ) -> Result<&PeerRow, Refusal> {
        let row = self.row(authenticated_as).ok_or(Refusal::NotAdmitted)?;
        if !row.allowed_sources.contains(inner_source) {
            return Err(Refusal::SourceSpoofed);
        }
        if row.revoked {
            return Err(Refusal::PeerRevoked);
        }
        Ok(row)
    }

    /// Egress: the unique peer a destination overlay address belongs to.
    ///
    /// "If no such K exists, the packet is **dropped, never flooded and never
    /// sent to a default peer**."
    #[must_use]
    pub fn egress_peer(&self, destination: IpAddr) -> Option<&PeerRow> {
        self.rows
            .iter()
            .find(|r| r.allowed_sources.contains(destination))
    }

    /// Whether `destination` belongs to a *different* admitted peer, which
    /// MG-5 makes transit rather than ordinary forwarding.
    #[must_use]
    pub fn is_peer_transit(&self, from: DeviceId, destination: IpAddr) -> bool {
        self.egress_peer(destination)
            .is_some_and(|r| r.device_id != from)
    }
}

/// Why admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdmitError {
    /// Two peers' `allowed_sources` overlap (MG-2).
    #[error("the peer's allowed_sources overlap an admitted peer's")]
    SourceSetOverlap,
    /// Only one family was populated (MG-3).
    #[error("a peer row must carry both families or neither")]
    SingleFamilySourceSet,
    /// Capacity could not be reserved (MG-12).
    #[error("capacity could not be reserved for this peer")]
    CapacityReservedUnavailable,
    /// The gateway is at its admitted-peer ceiling.
    #[error("the gateway is at its admitted-peer ceiling")]
    PeerLimitReached,
    /// MG-9: no signed bundle has ever been received for this peer.
    ///
    /// "Never fail open."
    #[error("no signed policy bundle exists for this peer")]
    NoSignedPolicy,
}

/// MG-6: loose reverse-path filtering is configured **because** strict RPF would
/// drop legitimate asymmetric overlay traffic — and it is **not** the
/// anti-spoofing control.
///
/// > MG-4 is the real anti-spoofing control, and MUST NOT be replaced by RPF
/// > configuration, which is a routing heuristic and not identity-bound.
#[must_use]
pub const fn rpf_is_the_antispoofing_control() -> bool {
    false
}

/// MG-7: conntrack entries are per-peer partitioned.
///
/// "NAT/conntrack entries created for peer A MUST be tagged with A's peer id and
/// MUST NOT be matched by a packet attributed to peer B. … the normative
/// requirement is the **property**, not the mechanism."
#[must_use]
pub fn conntrack_entry_matches(entry_owner: DeviceId, packet_peer: DeviceId) -> bool {
    entry_owner == packet_peer
}
