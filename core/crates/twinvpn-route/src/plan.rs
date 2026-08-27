//! ADR-0010 §11.1's address plan, as constants and constructors.
//!
//! **Authority:** ADR-0010 §11.1 (normative), AP-1, AP-2, R1, R2, R3;
//! ADR-0011 DN-3 (the reserved service ranges); `docs/networking.md` §2.1.
//!
//! # AP-1: the product ULA is a pinned constant
//!
//! > The global ID is `7c:9e5d:2a10`, giving `fd7c:9e5d:2a10::/48`, generated
//! > once per RFC 4193 §3.2.2 and **fixed for the life of the product**. … It
//! > MUST be identical in every build, because two devices deriving different
//! > prefixes cannot reach each other and the failure looks like a routing bug
//! > rather than a version skew.
//!
//! So it is a `const` here, not a configuration value, and there is no API that
//! takes a different one.

use twinvpn_types::{IpPrefix, OverlayAddresses, TypeError, V4Addr, V6Addr};

/// The TwinNet IPv4 space: RFC 6598 shared address space.
///
/// Per-`TwinNet` one or more `/22`; per-`Device` one `/32`.
pub const TWINNET_V4_SPACE: ([u8; 4], u32) = ([100, 64, 0, 0], 10);

/// The product ULA `/48` (AP-1). `fd7c:9e5d:2a10::/48`.
pub const PRODUCT_ULA: ([u8; 16], u32) = (
    [
        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    48,
);

/// ADR-0011 DN-3's reserved IPv4 service range: `100.127.255.0/24`.
pub const RESERVED_SERVICE_V4: ([u8; 4], u32) = ([100, 127, 255, 0], 24);

/// ADR-0011 DN-3's reserved IPv6 service range: `fd7c:9e5d:2a10:ffff::/64`.
pub const RESERVED_SERVICE_V6: ([u8; 16], u32) = (
    [
        0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    64,
);

/// The IPv6 minimum link MTU, and TwinVPN's overlay floor (`networking.md` §6.2).
pub const MTU_FLOOR: u32 = 1280;

/// The TwinNet IPv4 space as a prefix.
///
/// # Errors
///
/// Never in practice: the constant is canonical. Returned as a `Result` because
/// `IpPrefix::new` rejects a non-canonical prefix and this crate does not
/// `unwrap` on a constructor.
pub fn twinnet_v4_space() -> Result<IpPrefix, TypeError> {
    IpPrefix::new(
        twinvpn_types::IpAddr::V4(V4Addr::from_octets(TWINNET_V4_SPACE.0)),
        TWINNET_V4_SPACE.1,
    )
}

/// The product ULA `/48` as a prefix.
///
/// # Errors
///
/// As [`twinnet_v4_space`].
pub fn product_ula() -> Result<IpPrefix, TypeError> {
    let addr = V6Addr::new(PRODUCT_ULA.0, None)?;
    IpPrefix::new(twinvpn_types::IpAddr::V6(addr), PRODUCT_ULA.1)
}

/// The reserved IPv4 service range.
///
/// # Errors
///
/// As [`twinnet_v4_space`].
pub fn reserved_service_v4() -> Result<IpPrefix, TypeError> {
    IpPrefix::new(
        twinvpn_types::IpAddr::V4(V4Addr::from_octets(RESERVED_SERVICE_V4.0)),
        RESERVED_SERVICE_V4.1,
    )
}

/// The reserved IPv6 service range.
///
/// # Errors
///
/// As [`twinnet_v4_space`].
pub fn reserved_service_v6() -> Result<IpPrefix, TypeError> {
    let addr = V6Addr::new(RESERVED_SERVICE_V6.0, None)?;
    IpPrefix::new(twinvpn_types::IpAddr::V6(addr), RESERVED_SERVICE_V6.1)
}

/// The source of a device's IPv6 interface identifier.
///
/// ADR-0010 §11.1 derives it as
/// `truncate64(HKDF(DeviceKey_pub, "twinvpn-v6-iid"))`, with the U/L bit cleared
/// per RFC 7136. HKDF is a cryptographic operation, and CD-I2 restricts those to
/// `twinvpn-crypto` — so this crate takes the **eight derived bytes** and does
/// the addressing, and never the derivation.
///
/// **Integration item:** `twinvpn-crypto` supplies
/// `hkdf_expand(device_key_pub, b"twinvpn-v6-iid", 8)`.
pub trait V6InterfaceIdSource {
    /// The eight derived bytes, before the U/L bit is cleared.
    fn interface_id(&self) -> [u8; 8];
}

/// The CD-4 `info` string ADR-0010 §11.1 fixes for the IID derivation.
pub const V6_IID_INFO: &[u8] = b"twinvpn-v6-iid";

/// Builds a device's overlay `/128` inside a `TwinNet`'s `/64`.
///
/// RFC 7136: the U/L bit (bit 6 of the first IID octet) is **cleared**, because
/// the identifier is not derived from an EUI-64 and claiming otherwise would be
/// a lie about its provenance.
///
/// # Errors
///
/// [`PlanError::PrefixNotSixtyFour`] if `twinnet_prefix64` is not a `/64`,
/// [`PlanError::NotInsideProductUla`] if it is outside `fd7c:9e5d:2a10::/48`,
/// and [`PlanError::ReservedServiceRange`] if the result lands in DN-3's
/// reserved `/64` (AP-2).
pub fn device_v6(
    twinnet_prefix64: IpPrefix,
    iid: &dyn V6InterfaceIdSource,
) -> Result<V6Addr, PlanError> {
    if twinnet_prefix64.prefix_len() != 64 {
        return Err(PlanError::PrefixNotSixtyFour);
    }
    let twinvpn_types::IpAddr::V6(base) = twinnet_prefix64.address() else {
        return Err(PlanError::PrefixNotSixtyFour);
    };
    let ula = product_ula().map_err(PlanError::Type)?;
    if !ula.contains(twinvpn_types::IpAddr::V6(base)) {
        return Err(PlanError::NotInsideProductUla);
    }
    let reserved = reserved_service_v6().map_err(PlanError::Type)?;
    if reserved.contains(twinvpn_types::IpAddr::V6(base)) {
        return Err(PlanError::ReservedServiceRange);
    }

    let mut octets = base.octets();
    let mut id = iid.interface_id();
    // RFC 7136: clear the U/L bit.
    id[0] &= 0b1111_1101;
    octets[8..16].copy_from_slice(&id);
    // Zone index is None: an overlay address is global-scope within the TwinNet
    // and a zone index on it would be meaningless.
    V6Addr::new(octets, None).map_err(PlanError::Type)
}

/// Checks a control-plane-allocated IPv4 `/32` against AP-2 and R4.
///
/// # Errors
///
/// [`PlanError::OutsideTwinnetSpace`] outside `100.64.0.0/10`, and
/// [`PlanError::ReservedServiceRange`] inside `100.127.255.0/24`.
pub fn check_device_v4(addr: V4Addr) -> Result<(), PlanError> {
    let space = twinnet_v4_space().map_err(PlanError::Type)?;
    if !space.contains(twinvpn_types::IpAddr::V4(addr)) {
        return Err(PlanError::OutsideTwinnetSpace);
    }
    let reserved = reserved_service_v4().map_err(PlanError::Type)?;
    if reserved.contains(twinvpn_types::IpAddr::V4(addr)) {
        return Err(PlanError::ReservedServiceRange);
    }
    Ok(())
}

/// Assembles the pair R1 requires.
///
/// > Every `Device` MUST have both an IPv4 and an IPv6 overlay address, always,
/// > regardless of underlay family.
///
/// `OverlayAddresses` has two non-optional fields, so there is no way to build
/// half of one — R1 expressed in the type system rather than in a check.
///
/// # Errors
///
/// Whatever [`check_device_v4`] and [`device_v6`] reject.
pub fn overlay_addresses(
    v4: V4Addr,
    twinnet_prefix64: IpPrefix,
    iid: &dyn V6InterfaceIdSource,
) -> Result<OverlayAddresses, PlanError> {
    check_device_v4(v4)?;
    let v6 = device_v6(twinnet_prefix64, iid)?;
    Ok(OverlayAddresses { v4, v6 })
}

/// Why an address plan was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// The TwinNet prefix is not a `/64`.
    #[error("the TwinNet IPv6 prefix must be a /64")]
    PrefixNotSixtyFour,
    /// The TwinNet prefix is outside the pinned product ULA (AP-1).
    #[error("the TwinNet IPv6 prefix is outside fd7c:9e5d:2a10::/48")]
    NotInsideProductUla,
    /// The address is outside `100.64.0.0/10`.
    #[error("the device IPv4 address is outside 100.64.0.0/10")]
    OutsideTwinnetSpace,
    /// The address falls inside ADR-0011 DN-3's reserved service range (AP-2).
    #[error("the address falls inside a reserved TwinVPN service range")]
    ReservedServiceRange,
    /// A `twinvpn-types` constructor rejected a value.
    #[error("address construction failed: {0}")]
    Type(TypeError),
}
