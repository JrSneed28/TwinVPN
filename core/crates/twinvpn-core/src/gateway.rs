//! The gateway role, reachable from the management interface.
//!
//! **Authority:** [ADR-0013](../../../../docs/adr/ADR-0013-multi-client-gateway-architecture.md)
//! G1, MG-14, MG-15, MG-21, MG-25, S-36 and §11.11's `gw_*` metrics;
//! [ADR-0023](../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! EM-35 (*"the catalogue nouns this profile requires to exist … `gateway` …"*);
//! [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-2, §11.7.
//!
//! # The finding this module exists to close
//!
//! `ownership.md` §9.6 X-3, reported by `desktop-linux` and verified by the
//! integration lead:
//!
//! > `twinvpn-gateway` has **no caller anywhere in the workspace**, and the MI
//! > catalogue has no `gateway` noun (ADR-0023 EM-35 requires one). ADR-0013's
//! > multi-client gateway is therefore not merely unimplemented but
//! > **unaddressable through the only interface a headless host has**.
//!
//! `twinvpn-gateway` was complete and well tested — `PeerTable`,
//! `AllowedSources`, `Grant`, `PeerQuota`, `Capacity`, the admission errors —
//! and `twinvpn-core` declared it optional under `full` and never `use`d it. So
//! the peer table, the grants, the quotas and MG-21's admission refusal were
//! unreachable from the MI, which is the only interface an `H-SRV` host has, and
//! ADR-0013's G1 (*"N ≥ 16 concurrent peers"*) was unaddressable rather than
//! merely unimplemented.
//!
//! This module is the caller. It is deliberately **thin**: the domain logic
//! stays in `twinvpn-gateway` and is not rewritten here, and every decision
//! stays in the core (CB-2) so the shells gain verbs rather than policy.
//!
//! # Why the state lives here and not in `twinvpn-gateway`
//!
//! ADR-0018 §11.7 puts `twinvpn-gateway` in the **data-plane** group, below the
//! composition root. A data-plane crate that owned a live, mutable table would
//! have to be reached by whoever mutates it, and the only thing entitled to do
//! that is the composition root. `twinvpn-gateway` therefore stays a set of
//! decision functions over values, and the values live here — the same shape
//! `session_table` already has for `twinvpn-session`.

use twinvpn_gateway::grant::Grant;
use twinvpn_gateway::peer_table::{PeerRow, PeerTable};
use twinvpn_gateway::quota::{self, Capacity, PeerQuota};
use twinvpn_types::{DeviceId, Identifier as _};

/// The gateway's live state: the peer table, the capacity reservation, and the
/// grants currently in force.
///
/// **S-36** is *"live per-client gateway grant set … non-durable;
/// reconstructible from S-06 + S-16 + the client's re-request"*, which is why
/// this is held in memory and not in the vault.
#[derive(Debug)]
pub struct GatewayState {
    peers: PeerTable,
    /// Admission order, so `gateway.peer.list` is deterministic.
    ///
    /// Held beside the table rather than read out of it because
    /// `twinvpn_gateway::peer_table::PeerTable` exposes `len`, `row(device)` and
    /// the forwarding-path predicates and **no iterator over its rows** — it was
    /// written for the forwarding path, which never enumerates. Reported to the
    /// integration lead: a `rows()` accessor there would let this field go away.
    admitted: Vec<DeviceId>,
    capacity: Capacity,
    /// The ceiling as **configured**, before `Capacity::new` clamps it.
    ///
    /// Held separately because `twinvpn_gateway::quota::Capacity::new` clamps
    /// `max_peers` **up** to MG-14's floor, which makes non-conformance
    /// unrepresentable in the clamped value: a host configured for 8 peers reads
    /// back as 16. The clamp is the safe direction — it raises a ceiling rather
    /// than lowering one, and MG-15's memory refusal is the backstop — but MG-14
    /// says "a build that cannot [support 16] is **non-conforming**", and a
    /// posture report that cannot say so is reporting the clamp rather than the
    /// host. Reported to the integration lead as a finding against
    /// `twinvpn-gateway`.
    requested_max_peers: usize,
    grants: Vec<Grant>,
    /// The uplink the floor share is computed against, as configured.
    ///
    /// Zero means "not configured", which is a **different fact** from "zero
    /// bandwidth": [`quota::floor_bits_per_sec`] is what turns it into a share,
    /// and a gateway with no configured uplink cannot state a floor.
    configured_uplink_bps: u64,
}

impl GatewayState {
    /// A gateway with no admitted peers, sized for `max_peers`.
    ///
    /// # MG-14 is checked here and not assumed
    ///
    /// *"A conforming gateway MUST support at least **16** concurrent admitted
    /// peers on any supported platform. A build that cannot is non-conforming."*
    /// [`GatewayState::conforms_to_mg14`] is the reading of that, reported
    /// through `gateway.get` rather than asserted in a comment.
    #[must_use]
    pub fn new(total_bytes: u64, max_peers: usize, configured_uplink_bps: u64) -> Self {
        Self {
            peers: PeerTable::new(),
            admitted: Vec::new(),
            capacity: Capacity::new(total_bytes, max_peers),
            requested_max_peers: max_peers,
            grants: Vec::new(),
            configured_uplink_bps,
        }
    }

    /// A gateway that is not configured on this host.
    ///
    /// **Not the same as a gateway with zero peers.** `max_peers = 0` fails
    /// MG-14, which is exactly what `gateway.get` should report on a host that
    /// has not been set up as one: the honest answer is "this is not a
    /// conforming gateway", not "this gateway is idle".
    #[must_use]
    pub fn unconfigured() -> Self {
        Self::new(0, 0, 0)
    }

    /// How many peers are admitted.
    #[must_use]
    pub fn admitted(&self) -> usize {
        self.peers.len()
    }

    /// The ceiling actually in force (MG-15), after MG-14's clamp.
    #[must_use]
    pub const fn max_admitted_peers(&self) -> usize {
        self.capacity.max_peers()
    }

    /// Whether this host was **configured** to satisfy ADR-0013 MG-14's
    /// sixteen-peer floor.
    ///
    /// Reads the requested ceiling, not the clamped one — see
    /// [`GatewayState::requested_max_peers`]'s note. A host set up for 8 peers
    /// runs with a ceiling of 16 and is reported as non-conforming, which is the
    /// honest pair of facts: the clamp protects the guarantee and the report
    /// says the operator asked for something the ADR does not allow.
    #[must_use]
    pub const fn conforms_to_mg14(&self) -> bool {
        self.requested_max_peers >= quota::MIN_ADMITTED_PEERS
    }

    /// Each admitted peer's guaranteed floor share, in bits per second.
    ///
    /// `0` when no uplink is configured — [`quota::floor_bits_per_sec`]'s own
    /// answer, not a substitute for it.
    #[must_use]
    pub fn floor_bits_per_sec(&self) -> u64 {
        quota::floor_bits_per_sec(self.configured_uplink_bps, self.capacity.max_peers())
    }

    /// The admitted peers, in admission order.
    #[must_use]
    pub fn peers(&self) -> &[DeviceId] {
        &self.admitted
    }

    /// One admitted peer's row, or `None`.
    #[must_use]
    pub fn row(&self, device: DeviceId) -> Option<&PeerRow> {
        self.peers.row(device)
    }

    /// The grants currently in force (S-36).
    #[must_use]
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Admits one peer, reserving its capacity first.
    ///
    /// **MG-12**: capacity is reserved *at admission*, so a peer that is
    /// admitted has its floor share and its fixed state already accounted.
    /// **MG-21**: at the ceiling a further peer is refused with
    /// `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` and **no admitted peer is
    /// displaced** — there is no LRU eviction, because "silently disconnecting
    /// someone to make room is the one-at-a-time defect in a larger costume".
    ///
    /// # Errors
    ///
    /// [`twinvpn_gateway::peer_table::AdmitError`], unchanged from the crate
    /// that decides it. This function makes no admission decision of its own.
    pub fn admit(
        &mut self,
        row: PeerRow,
        quota: PeerQuota,
    ) -> Result<(), twinvpn_gateway::peer_table::AdmitError> {
        self.capacity.reserve(quota)?;
        let device = row.device_id;
        // A peer already admitted is refused rather than duplicated: two rows
        // for one device would make `attribute_ingress` non-deterministic.
        if self.admitted.contains(&device) {
            self.capacity.release(quota);
            return Err(twinvpn_gateway::peer_table::AdmitError::SourceSetOverlap);
        }
        match self.peers.admit(row) {
            Ok(()) => {
                self.admitted.push(device);
                Ok(())
            }
            Err(e) => {
                // The reservation is released on a refusal, or a rejected peer
                // would consume capacity forever.
                self.capacity.release(quota);
                Err(e)
            }
        }
    }

    /// Removes a peer and releases its reservation.
    pub fn remove(&mut self, device: DeviceId, quota: PeerQuota) {
        self.peers.remove(device);
        self.admitted.retain(|d| *d != device);
        self.capacity.release(quota);
        self.grants.retain(|g| g.peer() != device);
    }

    /// Records a grant decision `twinvpn_gateway::grant::decide` produced.
    ///
    /// The decision is **not made here**: `decide` is the policy and this only
    /// remembers what it said, so `gateway.grant.list` can report it.
    pub fn record_grant(&mut self, grant: Grant) {
        let peer = grant.peer();
        self.grants.retain(|g| g.peer() != peer);
        self.grants.push(grant);
    }
}

/// The body `gateway.get` returns.
///
/// # There is no frozen `GatewayStatus` message, and none is invented
///
/// `contracts/docs/phase1-conflicts.md` OQ-2 excluded an MI response schema from
/// Phase 2 so the MI could not acquire a second vocabulary, and ADR-0017 §11.9's
/// table has **no `gateway.*` row at all** — the noun is required by ADR-0023
/// EM-35 and is not enumerated in ADR-0017. So this body follows the precedent
/// `lifecycle.get` already set (*"one selector byte; there is no frozen
/// `HostLifecycleState` message"*): a fixed-width, big-endian encoding, written
/// out here so a reader can see the whole of it.
///
/// | Offset | Width | Field |
/// |---|---|---|
/// | 0 | 8 | `admitted_peers` |
/// | 8 | 8 | `max_admitted_peers` |
/// | 16 | 8 | `floor_bits_per_sec` |
/// | 24 | 1 | `conforms_to_mg14` |
///
/// Reported to the integration lead: ADR-0017 §11.9 needs `gateway.*` rows, and
/// this encoding should be replaced by whatever they specify.
#[must_use]
pub fn encode_status(state: &GatewayState) -> Vec<u8> {
    let mut out = Vec::with_capacity(25);
    out.extend_from_slice(&(state.admitted() as u64).to_be_bytes());
    out.extend_from_slice(&(state.max_admitted_peers() as u64).to_be_bytes());
    out.extend_from_slice(&state.floor_bits_per_sec().to_be_bytes());
    out.push(u8::from(state.conforms_to_mg14()));
    out
}

/// The body `gateway.peer.list` returns: each admitted peer's `device_id`,
/// concatenated at the frozen 32-byte width.
///
/// A raw concatenation at a **fixed** width rather than a delimited list, for
/// the same reason `dispatch::peer_from_params` takes one: `limits.json`'s
/// `device_id_bytes` is the frozen width, so the reader needs no length prefix
/// and cannot desynchronise. Anything that is not a whole number of ids is a
/// defect in this function rather than something a client must tolerate.
#[must_use]
pub fn encode_peers(state: &GatewayState) -> Vec<u8> {
    let peers = state.peers();
    let mut out = Vec::with_capacity(peers.len() * 32);
    for device in peers {
        out.extend_from_slice(device.as_bytes());
    }
    out
}

/// The body `gateway.grant.list` returns: `device_id` followed by one byte per
/// family saying whether that family is permitted.
///
/// | Offset | Width | Field |
/// |---|---|---|
/// | 0 | 32 | `device_id` |
/// | 32 | 1 | v4 permitted |
/// | 33 | 1 | v6 permitted |
///
/// **Both families, always, and never a single flag** — ADR-0013 G9: *"Both
/// address families MUST be forwarded, policed, and accounted with equal rigor.
/// A v4-only gateway path is a leak, not a limitation."* A grant that permitted
/// one family and not the other is `Grant::is_partial`, and collapsing the two
/// bytes into one would make that unrepresentable on the wire.
#[must_use]
pub fn encode_grants(state: &GatewayState) -> Vec<u8> {
    use twinvpn_types::AddressFamily;
    let grants = state.grants();
    let mut out = Vec::with_capacity(grants.len() * 34);
    for grant in grants {
        out.extend_from_slice(grant.peer().as_bytes());
        out.push(u8::from(grant.permits(AddressFamily::V4)));
        out.push(u8::from(grant.permits(AddressFamily::V6)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_gateway::peer_table::AllowedSources;
    use twinvpn_types::{IpAddr, IpPrefix, V4Addr, V6Addr};

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_slice(&[tag; 32]).expect("32 bytes")
    }

    fn sources(third: u8) -> AllowedSources {
        let mut s = AllowedSources::new();
        s.insert(
            IpPrefix::new(IpAddr::V4(V4Addr::from_octets([100, 64, third, 0])), 24)
                .expect("canonical"),
        );
        let mut o = [0u8; 16];
        o[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
        o[6] = third;
        s.insert(
            IpPrefix::new(IpAddr::V6(V6Addr::prefix_base(o).expect("prefix base")), 64)
                .expect("canonical"),
        );
        s
    }

    fn row(tag: u8) -> PeerRow {
        PeerRow {
            device_id: device(tag),
            allowed_sources: sources(tag),
            policy_version: 1,
            revoked: false,
        }
    }

    fn gateway() -> GatewayState {
        // A G1 router-class gateway: 64 peers, ADR-0013 §11.5's default.
        GatewayState::new(64 * 1_024 * 1_024, 64, 100_000_000)
    }

    #[test]
    fn an_unconfigured_host_reports_that_it_is_not_a_conforming_gateway() {
        // "This is not a gateway" and "this gateway is idle" are different
        // answers, and MG-14's floor is what separates them.
        let idle = GatewayState::unconfigured();
        assert_eq!(idle.admitted(), 0);
        assert!(!idle.conforms_to_mg14());

        let real = gateway();
        assert_eq!(real.admitted(), 0);
        assert!(real.conforms_to_mg14());
    }

    #[test]
    fn mg14s_sixteen_peer_floor_is_read_from_the_gateway_crate_and_not_restated() {
        assert_eq!(quota::MIN_ADMITTED_PEERS, 16);
        assert!(!GatewayState::new(1 << 30, 15, 0).conforms_to_mg14());
        assert!(GatewayState::new(1 << 30, 16, 0).conforms_to_mg14());
    }

    #[test]
    fn admitting_a_peer_reserves_its_capacity_and_removing_it_gives_it_back() {
        let mut g = gateway();
        let q = PeerQuota::new(100_000_000, 64);
        g.admit(row(1), q).expect("admitted");
        assert_eq!(g.admitted(), 1);
        g.remove(device(1), q);
        assert_eq!(g.admitted(), 0);
    }

    /// **MG-21: a refusal must not displace an admitted peer, and must not leak
    /// the reservation either.**
    #[test]
    fn a_refused_admission_releases_the_capacity_it_reserved() {
        let mut g = GatewayState::new(64 * 1_024 * 1_024, 64, 100_000_000);
        let q = PeerQuota::new(100_000_000, 64);
        g.admit(row(1), q).expect("first");
        // The same peer again: it is refused, and the reservation it took must
        // come back or a retrying client exhausts the gateway.
        assert!(g.admit(row(1), q).is_err());
        assert_eq!(g.admitted(), 1, "the admitted peer was not displaced");
        // And a different peer still fits, which it would not if the refused
        // admission had kept its reservation.
        g.admit(row(2), q).expect("second");
        assert_eq!(g.admitted(), 2);
    }

    #[test]
    fn the_status_body_is_the_width_the_table_says() {
        let g = gateway();
        let body = encode_status(&g);
        assert_eq!(body.len(), 25);
        assert_eq!(u64::from_be_bytes(body[0..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_be_bytes(body[8..16].try_into().unwrap()), 64);
        assert_eq!(body[24], 1, "a 64-peer gateway conforms to MG-14");
    }

    #[test]
    fn the_peer_body_is_a_whole_number_of_device_ids() {
        let mut g = gateway();
        let q = PeerQuota::new(100_000_000, 64);
        g.admit(row(1), q).expect("one");
        g.admit(row(2), q).expect("two");
        let body = encode_peers(&g);
        assert_eq!(body.len(), 64, "two ids at the frozen 32-byte width");
        assert_eq!(&body[..32], device(1).as_bytes());
        assert_eq!(&body[32..], device(2).as_bytes());
    }

    /// **G9: a v4-only gateway path is a leak, not a limitation.**
    ///
    /// Two bytes per grant and never one, so a partial grant is representable on
    /// the wire rather than being rounded to "granted".
    #[test]
    fn a_grant_reports_both_families_separately() {
        use twinvpn_gateway::grant::{Grant, Granted};
        use twinvpn_types::PerFamily;

        let mut g = gateway();
        g.record_grant(Grant::ExitNode {
            peer: device(1),
            granted: PerFamily::new(
                Granted::from_optional(Some(true)),
                Granted::from_optional(None),
            ),
            ttl_ms: 60_000,
            refusal: None,
        });
        let body = encode_grants(&g);
        assert_eq!(body.len(), 34);
        assert_eq!(&body[..32], device(1).as_bytes());
        assert_eq!(body[32], 1, "v4 permitted");
        assert_eq!(body[33], 0, "v6 is NOT, and the wire can say so");
    }

    #[test]
    fn one_peer_holds_at_most_one_grant_record() {
        use twinvpn_gateway::grant::{Grant, Granted};
        use twinvpn_types::PerFamily;

        let mut g = gateway();
        let both = PerFamily::new(
            Granted::from_optional(Some(true)),
            Granted::from_optional(Some(true)),
        );
        for _ in 0..2 {
            g.record_grant(Grant::ExitNode {
                peer: device(1),
                granted: both,
                ttl_ms: 60_000,
                refusal: None,
            });
        }
        assert_eq!(g.grants().len(), 1, "a re-grant replaces, never duplicates");
    }
}
