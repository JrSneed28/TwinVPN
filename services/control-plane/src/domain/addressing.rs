//! S-08: `TwinNet` address allocation — single-writer, refused at allocation
//! time, immutable for the device's life.
//!
//! **Authority:** `device.proto`'s `twinnet_address_v4`/`v6` comment (the
//! normative text), `architecture.md` §5 row S-08, ADR-0010 R1, ADR-0008 §11.3
//! ("`TwinNet` address allocation … deterministic derivation from
//! `DeviceIdentity`, recorded once, immutable — **this is why no DHCP is needed
//! in the datapath**").
//!
//! # Both families, always
//!
//! > *A device MUST receive BOTH, even on a v4-only or v6-only network, because
//! > addressing inside the `TwinNet` is independent of underlay reachability. …
//! > A `Device` with one set and not the other is malformed — that asymmetry is
//! > exactly how a v6-aware design degrades into a v4-only one.*
//!
//! [`allocate`] returns a pair or an error. There is no way to obtain one half.
//!
//! # An open divergence, stated rather than hidden
//!
//! `device.proto` fixes the v6 derivation as
//! `prefix64 || truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))` with the U/L
//! bit cleared per RFC 7136. **HKDF-SHA-256 is a cryptographic implementation**,
//! CD-I2 places it in `twinvpn-crypto`, and this artifact does not link the core
//! (ADR-0018 §11.2 row 2.8). `services/Cargo.toml` — which this domain must not
//! edit — declares no HKDF, no SHA-2 and no cryptographic crate at all.
//!
//! So [`Ipv6Derivation`] is a port with two bindings:
//!
//! - [`Ipv6Derivation::Hkdf`] — the contract's derivation. **Unbindable in this
//!   build**; asking for it returns `AUTH.KEY_UNAVAILABLE` rather than
//!   pretending.
//! - [`Ipv6Derivation::DeviceIdTruncation`] — the shipped default. It truncates
//!   `device_id`, which `identity.proto` already defines as
//!   `SHA-256("TwinVPN/DeviceIdentity/v1" ‖ 0x00 ‖ dCBOR(COSE_Key(IK_pub)))`.
//!   It keeps every property S-08 depends on — deterministic from public
//!   material, collision-refused at allocation, immutable, no DHCP — and it is
//!   **not the derivation `device.proto` names**, so a client that computes its
//!   own v6 address per the contract will disagree.
//!
//! The integration lead's decision is needed. It is one of two one-line changes:
//! add `hkdf` + `sha2` to `services/Cargo.toml`'s `[workspace.dependencies]`, or
//! amend the derivation to `truncate64(device_id)`. Until then this build logs
//! the divergence at startup and `README.md` §8 records it.

use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::model::{DeviceKey, NetState};

/// The RFC 6598 shared address space `device.proto` allocates v4 from.
pub const V4_BASE: [u8; 4] = [100, 64, 0, 0];
/// `100.64.0.0/10` — 22 host bits.
pub const V4_PREFIX_LEN: u32 = 10;
/// The pinned product ULA `fd7c:9e5d:2a10::/48`.
pub const V6_PREFIX: [u8; 6] = [0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10];

/// The host-bit mask of `100.64.0.0/10` — 22 bits.
const V4_HOST_MASK: u32 = (1 << (32 - V4_PREFIX_LEN)) - 1;

/// The highest usable offset: every host bit set is the all-ones address, and
/// offset 0 is the network address, so neither is handed out.
const V4_MAX_OFFSET: u32 = V4_HOST_MASK - 1;

/// How the v6 interface identifier is derived. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Derivation {
    /// `truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))`, as `device.proto`
    /// specifies. **Not available in this build.**
    Hkdf,
    /// `truncate64(device_id)`. The shipped default; a documented divergence.
    DeviceIdTruncation,
}

impl Ipv6Derivation {
    /// A stable tag for the startup log line and the readiness body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Ipv6Derivation::Hkdf => "hkdf_device_key_pub",
            Ipv6Derivation::DeviceIdTruncation => "truncate64_device_id",
        }
    }

    /// Whether this build can actually perform the derivation.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Ipv6Derivation::DeviceIdTruncation)
    }
}

/// A device's pair of overlay addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    /// The `/32` from `100.64.0.0/10`.
    pub v4: [u8; 4],
    /// The `/128` inside `fd7c:9e5d:2a10::/48`.
    pub v6: [u8; 16],
    /// The offset consumed, so the caller can advance the counter in the same
    /// transaction.
    pub v4_offset: u32,
}

/// Allocates both addresses, or refuses.
///
/// # Errors
///
/// - `AUTH.KEY_UNAVAILABLE` when the configured derivation is not available in
///   this build.
/// - `RESOURCE.PEER_LIMIT_REACHED` when `100.64.0.0/10` is exhausted.
/// - `AUTH.IDENTITY_CONCURRENT_USE` on a v6 collision. S-08: "a collision is a
///   control-plane bug, **refused at allocation time**, never resolved at
///   runtime" — because resolving it at runtime is the silent blackhole R-03
///   exists to prevent.
pub fn allocate(
    state: &NetState,
    device_id: &DeviceKey,
    derivation: Ipv6Derivation,
) -> Result<Allocation, ServiceError> {
    if !derivation.is_available() {
        return Err(codes::bare(codes::NO_TRUST_ANCHOR));
    }

    let v6 = derive_v6(device_id);
    if state
        .devices
        .values()
        .any(|d| d.twinnet_addr_v6 == v6 && &d.device_id != device_id)
    {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_IDENTITY_CONCURRENT_USE,
        ));
    }

    let offset = state.next_v4_offset;
    if offset > V4_MAX_OFFSET {
        return Err(codes::bare(
            twinvpn_types::codes::RESOURCE_PEER_LIMIT_REACHED,
        ));
    }
    let v4 = v4_at(offset);
    if state
        .devices
        .values()
        .any(|d| d.twinnet_addr_v4 == v4 && &d.device_id != device_id)
    {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_IDENTITY_CONCURRENT_USE,
        ));
    }

    Ok(Allocation {
        v4,
        v6,
        v4_offset: offset,
    })
}

/// The `/32` at `offset` inside `100.64.0.0/10`.
#[must_use]
pub fn v4_at(offset: u32) -> [u8; 4] {
    let base = u32::from_be_bytes(V4_BASE);
    (base | (offset & V4_HOST_MASK)).to_be_bytes()
}

/// `prefix48 ‖ 0x0000 ‖ truncate64(device_id)`, U/L bit cleared per RFC 7136.
///
/// Clearing the U/L bit is not cosmetic: RFC 7136 reserves the bit's *meaning*,
/// and an IID that leaves it set claims a global uniqueness scope this address
/// does not have.
#[must_use]
pub fn derive_v6(device_id: &DeviceKey) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&V6_PREFIX);
    // bytes 6..8 are the subnet id inside the /48; one subnet in Phase 1.
    out[8..16].copy_from_slice(&device_id[..8]);
    out[8] &= 0b1111_1101; // clear the U/L bit (RFC 7136)
    out
}

#[cfg(test)]
mod tests {
    use super::{allocate, derive_v6, v4_at, Ipv6Derivation, V4_BASE, V6_PREFIX};
    use crate::model::{DeviceRecord, NetState};

    fn device(id: u8, v4: [u8; 4], v6: [u8; 16]) -> DeviceRecord {
        DeviceRecord {
            device_id: [id; 32],
            identity_id: [id; 32],
            identity_public_key: vec![id],
            generation: 0,
            tk_generation: 0,
            label: format!("d{id}"),
            version: 1,
            membership_epoch: 1,
            twinnet_addr_v4: v4,
            twinnet_addr_v6: v6,
            encoded: Vec::new(),
            revoked: false,
            net_seq: 1,
            created_at_ms: 0,
        }
    }

    #[test]
    fn both_families_are_allocated_or_neither_is() {
        // device.proto: "A Device with one set and not the other is malformed."
        // The API cannot express one half.
        let state = NetState::new("tn");
        let a = allocate(&state, &[1u8; 32], Ipv6Derivation::DeviceIdTruncation).expect("both");
        assert_eq!(a.v4[0], V4_BASE[0]);
        assert_eq!(&a.v6[..6], &V6_PREFIX);
    }

    #[test]
    fn the_contract_derivation_is_refused_rather_than_faked() {
        // The honest half of the divergence: asking for HKDF in a build that
        // cannot do HKDF returns a named refusal, not a lookalike address.
        let state = NetState::new("tn");
        let err =
            allocate(&state, &[1u8; 32], Ipv6Derivation::Hkdf).expect_err("not available here");
        assert_eq!(err.code().as_str(), "AUTH.KEY_UNAVAILABLE");
        assert!(!Ipv6Derivation::Hkdf.is_available());
        assert!(Ipv6Derivation::DeviceIdTruncation.is_available());
    }

    #[test]
    fn the_v6_iid_clears_the_ul_bit() {
        // RFC 7136: leaving it set claims a global uniqueness scope a ULA
        // address does not have.
        let mut id = [0u8; 32];
        id[0] = 0xff;
        let v6 = derive_v6(&id);
        assert_eq!(v6[8] & 0b0000_0010, 0);
    }

    #[test]
    fn the_derivation_is_deterministic_which_is_what_removes_dhcp() {
        assert_eq!(derive_v6(&[7u8; 32]), derive_v6(&[7u8; 32]));
        assert_ne!(derive_v6(&[7u8; 32]), derive_v6(&[8u8; 32]));
    }

    #[test]
    fn a_v6_collision_is_refused_at_allocation_never_resolved_at_runtime() {
        // S-08 / R-03: two devices at one address is a silent blackhole,
        // undiagnosable from either end. It must fail here or nowhere.
        let mut state = NetState::new("tn");
        let victim = derive_v6(&[5u8; 32]);
        state.devices.insert([9u8; 32], device(9, v4_at(1), victim));
        let err = allocate(&state, &[5u8; 32], Ipv6Derivation::DeviceIdTruncation)
            .expect_err("collision");
        assert_eq!(err.code().as_str(), "AUTH.IDENTITY_CONCURRENT_USE");
    }

    #[test]
    fn v4_allocation_stays_inside_the_shared_address_space() {
        for offset in [1u32, 2, 3, 1000, 4_194_301] {
            let a = v4_at(offset);
            assert_eq!(a[0], 100);
            assert!(
                (64..128).contains(&a[1]),
                "100.64.0.0/10 spans 100.64 through 100.127, got {a:?}"
            );
        }
    }

    #[test]
    fn consecutive_offsets_give_distinct_addresses() {
        // A mask that dropped a host bit would map offsets 2 and 3 to the same
        // /32 — two devices at one address, which is the silent blackhole S-08
        // and R-03 exist to prevent, arriving from an off-by-one.
        let mut seen = std::collections::BTreeSet::new();
        for offset in 1u32..=4096 {
            assert!(seen.insert(v4_at(offset)), "offset {offset} collided");
        }
    }

    #[test]
    fn the_pool_is_refused_when_exhausted_rather_than_wrapping() {
        // Wrapping would re-issue a live address, which is the collision the
        // previous test refuses — arriving through the back door.
        let mut state = NetState::new("tn");
        state.next_v4_offset = u32::MAX;
        let err = allocate(&state, &[1u8; 32], Ipv6Derivation::DeviceIdTruncation)
            .expect_err("exhausted");
        assert_eq!(err.code().as_str(), "RESOURCE.PEER_LIMIT_REACHED");
    }
}
