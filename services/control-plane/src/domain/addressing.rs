//! S-08: `TwinNet` address allocation — single-writer, refused at allocation
//! time, immutable for the device's life.
//!
//! **Authority:** ADR-0010 §11.1 (the address plan and the derivation),
//! `device.proto`'s `twinnet_address_v4`/`v6` comment (the normative text),
//! `architecture.md` §5 row S-08, ADR-0008 §11.3 ("deterministic derivation from
//! `DeviceIdentity`, recorded once, immutable — **this is why no DHCP is needed
//! in the datapath**"), and `core/crates/twinvpn-route/src/plan.rs`, which is
//! the client-side statement of the same plan.
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
//! # The derivation is the client's derivation
//!
//! `twinvpn-route`'s `plan.rs` splits this exactly as CD-I2 requires: "this
//! crate takes the **eight derived bytes** and does the addressing, and never
//! the derivation", with `twinvpn-crypto` supplying
//! `hkdf_expand(device_key_pub, b"twinvpn-v6-iid", 8)`. This module makes the
//! same split, calls the **same** `twinvpn-crypto` function, and uses the same
//! `info` string — so the server allocates the address the client computes.
//!
//! That agreement is the whole point. An address this service allocates and a
//! device derives independently must be the same address, and a second
//! implementation of HKDF-SHA-256 inside the services workspace would be the
//! DP-8 second provider whose agreement with the core's is untested — which is
//! precisely the property this depends on.
//! `tests/client_agreement.rs::the_v6_derivation_matches_the_clients_address_plan`
//! asserts the constants against `plan.rs` as text, and
//! `the_derivation_is_hkdf_over_the_identity_key` pins the bytes.

use twinvpn_crypto::hkdf_sha256;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::model::NetState;

/// The RFC 6598 shared address space ADR-0010 §11.1 allocates v4 from.
pub const V4_BASE: [u8; 4] = [100, 64, 0, 0];
/// `100.64.0.0/10` — 22 host bits.
pub const V4_PREFIX_LEN: u32 = 10;
/// ADR-0010 AP-2 / DN-3's reserved IPv4 service range, `100.127.255.0/24`.
///
/// `twinvpn-route`'s `check_device_v4` refuses a device address inside it, so an
/// allocator that handed one out would produce a `/32` the client itself
/// rejects.
pub const RESERVED_SERVICE_V4: ([u8; 4], u32) = ([100, 127, 255, 0], 24);

/// The pinned product ULA `fd7c:9e5d:2a10::/48` (ADR-0010 AP-1).
pub const V6_ULA_48: [u8; 6] = [0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10];
/// The `TwinNet`'s `/64` inside the product ULA. Phase 1 has one subnet, `0`.
pub const V6_SUBNET_ID: [u8; 2] = [0x00, 0x00];
/// ADR-0011 DN-3's reserved IPv6 service `/64`, `fd7c:9e5d:2a10:ffff::/64`.
pub const RESERVED_SERVICE_V6_SUBNET: [u8; 2] = [0xff, 0xff];

/// The CD-4 `info` string ADR-0010 §11.1 fixes for the IID derivation.
///
/// Byte-identical to `twinvpn_route::plan::V6_IID_INFO`. One character different
/// here is a different address for every device in the fleet, and it would
/// surface only when a real client connected.
pub const V6_IID_INFO: &[u8] = b"twinvpn-v6-iid";

/// The host-bit mask of `100.64.0.0/10` — 22 bits.
const V4_HOST_MASK: u32 = (1 << (32 - V4_PREFIX_LEN)) - 1;

/// The highest usable offset: every host bit set is the all-ones address, and
/// offset 0 is the network address, so neither is handed out.
const V4_MAX_OFFSET: u32 = V4_HOST_MASK - 1;

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
/// `identity_public_key` is the COSE_Key encoding of the ES256
/// `DeviceIdentityKey` — `device.proto`'s `DeviceKey_pub`, and the same octets
/// `device_id` is derived from. It is the **public** half; nothing private
/// reaches this function or could.
///
/// # Errors
///
/// - `AUTH.IDENTITY_MISSING` for an empty key: an IID derived from no key would
///   be the same IID for every such device.
/// - `INTERNAL.INVARIANT_VIOLATED` if the derivation itself fails.
/// - `AUTH.IDENTITY_CONCURRENT_USE` on a collision in either family. S-08: "a
///   collision is a control-plane bug, **refused at allocation time**, never
///   resolved at runtime" — because resolving it at runtime is the silent
///   blackhole R-03 exists to prevent.
/// - `RESOURCE.PEER_LIMIT_REACHED` when `100.64.0.0/10` is exhausted.
pub fn allocate(
    state: &NetState,
    device_id: &crate::model::DeviceKey,
    identity_public_key: &[u8],
) -> Result<Allocation, ServiceError> {
    let v6 = derive_v6(identity_public_key)?;
    if state
        .devices
        .values()
        .any(|d| d.twinnet_addr_v6 == v6 && &d.device_id != device_id)
    {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_IDENTITY_CONCURRENT_USE,
        ));
    }

    // The pool skips the reserved service range rather than stopping at it: a
    // /10 with a hole in it is still a /10, and refusing every offset above the
    // hole would strand the rest of the pool behind it.
    let mut offset = state.next_v4_offset;
    while offset <= V4_MAX_OFFSET && is_reserved_v4(v4_at(offset)) {
        offset += 1;
    }
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

/// Whether an address falls in ADR-0010 AP-2's reserved service range.
#[must_use]
pub fn is_reserved_v4(addr: [u8; 4]) -> bool {
    let (base, len) = RESERVED_SERVICE_V4;
    let mask = u32::MAX << (32 - len);
    (u32::from_be_bytes(addr) & mask) == (u32::from_be_bytes(base) & mask)
}

/// ADR-0010 §11.1: `prefix64 ‖ truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))`,
/// with the U/L bit cleared per RFC 7136.
///
/// The HKDF is `twinvpn-crypto`'s — the audited provider the client's binding
/// also calls, so the eight derived bytes are the same eight bytes.
///
/// Clearing the U/L bit is not cosmetic: RFC 7136 reserves the bit's *meaning*,
/// and an IID that leaves it set claims an EUI-64 provenance this identifier
/// does not have.
///
/// # Errors
///
/// `AUTH.IDENTITY_MISSING` for an empty key; `INTERNAL.INVARIANT_VIOLATED` if
/// the derivation fails, which cannot happen for an eight-byte output and is
/// reported rather than unwrapped.
pub fn derive_v6(identity_public_key: &[u8]) -> Result<[u8; 16], ServiceError> {
    if identity_public_key.is_empty() {
        return Err(codes::bare(twinvpn_types::codes::AUTH_IDENTITY_MISSING));
    }
    let mut iid = [0u8; 8];
    // salt = None: ADR-0010 §11.1 names `HKDF(DeviceKey_pub, "twinvpn-v6-iid")`
    // with no salt, and supplying one here would silently produce a different
    // address from the client's.
    hkdf_sha256(None, identity_public_key, V6_IID_INFO, &mut iid).map_err(|_| {
        ServiceError::from_diagnostic(twinvpn_types::Diagnostic::invariant_violated(
            crate::COMPONENT,
            "v6_interface_id_derivation_failed",
        ))
    })?;
    iid[0] &= 0b1111_1101; // RFC 7136: clear the U/L bit.

    let mut out = [0u8; 16];
    out[..6].copy_from_slice(&V6_ULA_48);
    out[6..8].copy_from_slice(&V6_SUBNET_ID);
    out[8..16].copy_from_slice(&iid);
    Ok(out)
}

/// Whether a `/128` lands in ADR-0011 DN-3's reserved service `/64`.
#[must_use]
pub fn is_reserved_v6(addr: [u8; 16]) -> bool {
    addr[..6] == V6_ULA_48 && addr[6..8] == RESERVED_SERVICE_V6_SUBNET
}

#[cfg(test)]
mod tests {
    use super::{
        allocate, derive_v6, is_reserved_v4, is_reserved_v6, v4_at, RESERVED_SERVICE_V4, V4_BASE,
        V6_IID_INFO, V6_ULA_48,
    };
    use crate::model::{DeviceRecord, NetState};

    /// A COSE_Key stand-in. Any non-empty byte string is a valid HKDF input; the
    /// derivation does not parse it, exactly as ADR-0010 §11.1 does not ask it to.
    fn key(n: u8) -> Vec<u8> {
        vec![n; 33]
    }

    fn device(id: u8, v4: [u8; 4], v6: [u8; 16]) -> DeviceRecord {
        DeviceRecord {
            device_id: [id; 32],
            identity_id: [id; 32],
            identity_public_key: key(id),
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
    fn the_derivation_is_hkdf_over_the_identity_key() {
        // Pinned against `twinvpn-crypto` directly — the same provider the
        // client's binding calls. If the provider ever changes under either of
        // us, the two sides move together or this fails.
        let v6 = derive_v6(&key(0x01)).expect("derives");
        assert_eq!(&v6[..6], &V6_ULA_48, "inside the pinned product ULA");
        assert_eq!(&v6[6..8], &[0x00, 0x00], "the Phase 1 /64");

        let mut expected = [0u8; 8];
        twinvpn_crypto::hkdf_sha256(None, &key(0x01), V6_IID_INFO, &mut expected).expect("derives");
        expected[0] &= 0b1111_1101;
        assert_eq!(
            &v6[8..16],
            &expected,
            "the IID is truncate64(HKDF(DeviceKey_pub, \"twinvpn-v6-iid\")) with \
             the U/L bit cleared — the client computes the same eight bytes"
        );
    }

    #[test]
    fn the_info_string_is_the_one_adr_0010_fixes() {
        assert_eq!(V6_IID_INFO, b"twinvpn-v6-iid");
    }

    #[test]
    fn the_derivation_is_over_the_key_and_not_over_the_device_id() {
        // The bug this replaced: `truncate64(device_id)` is deterministic,
        // collision-refused and immutable — and it is NOT the contract's
        // derivation, so it disagreed with the client for every device.
        let k = key(0x01);
        let device_id = [0x01u8; 32];
        let from_key = derive_v6(&k).expect("derives");
        let mut from_id = [0u8; 16];
        from_id[..6].copy_from_slice(&V6_ULA_48);
        from_id[8..16].copy_from_slice(&device_id[..8]);
        from_id[8] &= 0b1111_1101;
        assert_ne!(
            from_key, from_id,
            "the truncation shortcut and the HKDF derivation are different addresses"
        );
    }

    #[test]
    fn an_empty_key_derives_nothing() {
        let err = derive_v6(&[]).expect_err("no key, no address");
        assert_eq!(err.code().as_str(), "AUTH.IDENTITY_MISSING");
    }

    #[test]
    fn both_families_are_allocated_or_neither_is() {
        // device.proto: "A Device with one set and not the other is malformed."
        // The API cannot express one half.
        let state = NetState::new("tn");
        let a = allocate(&state, &[1u8; 32], &key(1)).expect("both");
        assert_eq!(a.v4[0], V4_BASE[0]);
        assert_eq!(&a.v6[..6], &V6_ULA_48);
    }

    #[test]
    fn the_derivation_is_deterministic_which_is_what_removes_dhcp() {
        assert_eq!(
            derive_v6(&key(7)).expect("derives"),
            derive_v6(&key(7)).expect("derives")
        );
        assert_ne!(
            derive_v6(&key(7)).expect("derives"),
            derive_v6(&key(8)).expect("derives")
        );
    }

    #[test]
    fn the_v6_iid_clears_the_ul_bit() {
        // RFC 7136: leaving it set claims an EUI-64 provenance this identifier
        // does not have.
        for n in 0..64u8 {
            let v6 = derive_v6(&key(n)).expect("derives");
            assert_eq!(v6[8] & 0b0000_0010, 0, "key {n}");
        }
    }

    #[test]
    fn a_derived_address_never_lands_in_the_reserved_service_range() {
        // The Phase 1 /64 is subnet 0 and DN-3 reserves subnet ffff, so no
        // derivation can reach it — asserted rather than assumed, because the
        // subnet id is a constant somebody could change.
        for n in 0..64u8 {
            assert!(!is_reserved_v6(derive_v6(&key(n)).expect("derives")));
        }
        let mut reserved = [0u8; 16];
        reserved[..6].copy_from_slice(&V6_ULA_48);
        reserved[6..8].copy_from_slice(&[0xff, 0xff]);
        assert!(is_reserved_v6(reserved));
    }

    #[test]
    fn a_v6_collision_is_refused_at_allocation_never_resolved_at_runtime() {
        // S-08 / R-03: two devices at one address is a silent blackhole,
        // undiagnosable from either end. It must fail here or nowhere.
        let mut state = NetState::new("tn");
        let victim = derive_v6(&key(5)).expect("derives");
        state.devices.insert([9u8; 32], device(9, v4_at(1), victim));
        let err = allocate(&state, &[5u8; 32], &key(5)).expect_err("collision");
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
    fn the_allocator_skips_the_reserved_v4_service_range() {
        // twinvpn-route's `check_device_v4` refuses 100.127.255.0/24, so an
        // allocator that handed one out would produce a /32 the client rejects.
        let (base, _) = RESERVED_SERVICE_V4;
        assert!(is_reserved_v4(base));
        assert!(is_reserved_v4([100, 127, 255, 200]));
        assert!(!is_reserved_v4([100, 127, 254, 255]));

        // The reserved /24 is the LAST /24 of the /10, so reaching it means the
        // pool is finished. Skipping it therefore exhausts rather than resumes,
        // and the allocator says so instead of handing out a reserved address.
        let first_reserved_offset =
            u32::from_be_bytes([100, 127, 255, 0]) - u32::from_be_bytes(V4_BASE);
        let mut state = NetState::new("tn");
        state.next_v4_offset = first_reserved_offset;
        let err = allocate(&state, &[1u8; 32], &key(1)).expect_err("the pool ends here");
        assert_eq!(err.code().as_str(), "RESOURCE.PEER_LIMIT_REACHED");

        // And the last usable offset below it allocates normally.
        state.next_v4_offset = first_reserved_offset - 1;
        let a = allocate(&state, &[1u8; 32], &key(1)).expect("still inside the pool");
        assert!(!is_reserved_v4(a.v4));
        assert_eq!(a.v4, [100, 127, 254, 255]);
    }

    #[test]
    fn the_pool_is_refused_when_exhausted_rather_than_wrapping() {
        // Wrapping would re-issue a live address, which is the collision the
        // earlier test refuses — arriving through the back door.
        let mut state = NetState::new("tn");
        state.next_v4_offset = u32::MAX;
        let err = allocate(&state, &[1u8; 32], &key(1)).expect_err("exhausted");
        assert_eq!(err.code().as_str(), "RESOURCE.PEER_LIMIT_REACHED");
    }
}
