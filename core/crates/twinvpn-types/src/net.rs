//! Canonical network address types.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/common.proto` §4 (the canonical
//! forms), ADR-0010 R1 (IPv4 and IPv6 are co-equal), ADR-0010 §11.7 (IPv6-only,
//! NAT64, 464XLAT), `contracts/registry/limits.json` §`routing`.
//!
//! # ADR-0010 R1, expressed in types
//!
//! > "Every `Device` MUST have both an IPv4 and an IPv6 overlay address, always,
//! > regardless of underlay family."
//!
//! That is not a validation rule here, it is [`OverlayAddresses`]: a struct with
//! two non-optional fields. A device with only one family is not a value this
//! crate can build, so "v6 later" is not sayable. The same reasoning is why
//! there is no `Ip` type with optional halves and no `is_dual_stack()` derived
//! from "v4 is present": `common.proto` explicitly forbids a field
//! "interpretable as 'v4 present therefore dual-stack'", and [`UnderlayFamilies`]
//! states the underlay's shape as its own fact.
//!
//! # Canonical forms are enforced, never normalized
//!
//! Every constructor rejects. `common.proto` is explicit about why: "normalizing
//! attacker input before a policy check is how a rule intended to match one
//! network comes to match another", and accepting `::ffff:10.0.0.1` "would let
//! one logical address arrive under two encodings and defeat every
//! set-membership and prefix-match check that depends on a canonical form".

use core::fmt;
use core::num::NonZeroU16;

use crate::error::TypeError;

/// Address family. Mirrors `twinvpn.v1.AddressFamily` **without** its
/// `UNSPECIFIED` zero value: a family is either v4 or v6, and a third state
/// exists only as a proto3 encoding artifact that `twinvpn-schema` rejects at
/// the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressFamily {
    /// IPv4.
    V4 = 1,
    /// IPv6.
    V6 = 2,
}

impl AddressFamily {
    /// The maximum prefix length for this family (`limits.json` §`routing`).
    #[must_use]
    pub const fn max_prefix_len(self) -> u32 {
        match self {
            AddressFamily::V4 => 32,
            AddressFamily::V6 => 128,
        }
    }

    /// The address width in bytes (`limits.json` §`routing`).
    #[must_use]
    pub const fn address_bytes(self) -> usize {
        match self {
            AddressFamily::V4 => 4,
            AddressFamily::V6 => 16,
        }
    }

    /// The other family. Useful where a decision must be shown to consider both.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            AddressFamily::V4 => AddressFamily::V6,
            AddressFamily::V6 => AddressFamily::V4,
        }
    }
}

/// An IPv4 address: exactly four octets, network byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V4Addr([u8; 4]);

impl V4Addr {
    /// The unspecified address, `0.0.0.0`.
    pub const UNSPECIFIED: V4Addr = V4Addr([0; 4]);

    /// Builds from four octets.
    #[must_use]
    pub const fn from_octets(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    /// Builds from a wire slice, validating the width. Any other length is
    /// malformed — never truncated, never padded.
    pub fn from_slice(octets: &[u8]) -> Result<Self, TypeError> {
        if octets.len() != 4 {
            return Err(TypeError::IdentifierLength {
                kind: "ipv4_address_bytes",
                expected: 4,
                observed: octets.len(),
            });
        }
        let mut out = [0u8; 4];
        out.copy_from_slice(octets);
        Ok(Self(out))
    }

    /// The four octets.
    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }

    /// Whether this address is inside RFC 6598 shared address space,
    /// `100.64.0.0/10` — the overlay's own IPv4 range (ADR-0010 §11.1) and the
    /// range a CGNAT underlay also uses, which is the collision ADR-0010 §11.5
    /// and `docs/networking.md` §7.5 exist to handle.
    #[must_use]
    pub const fn is_shared_address_space(self) -> bool {
        self.0[0] == 100 && self.0[1] >= 64 && self.0[1] <= 127
    }
}

impl fmt::Debug for V4Addr {
    /// `SENSITIVE` under ADR-0015 §11.4: an address is a user-identifying fact.
    /// Redacted so a derived `Debug` up the struct tree cannot leak it into a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V4Addr(<redacted>)")
    }
}

/// An RFC 4007 scope zone index, always non-zero.
///
/// `docs/protocol.md` §10.4: "IPv6 link-local host candidates MUST carry
/// `zone_index` or they are unusable on multi-interface hosts." Zero is not a
/// zone; it is the absence of one, and it is represented by `Option<ZoneIndex>`
/// rather than by a sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneIndex(core::num::NonZeroU32);

impl ZoneIndex {
    /// Builds a zone index, rejecting zero.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match core::num::NonZeroU32::new(value) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// An IPv6 address: exactly sixteen octets, network byte order, plus the RFC
/// 4007 scope zone index when — and only when — the address is link-local.
///
/// Two rules are enforced at construction and neither is negotiable:
///
/// 1. An address in `fe80::/10` **must** carry a non-zero zone; any other
///    address **must not** carry one. A link-local address without its zone is
///    unusable on a multi-interface host, and a zone on a global address is a
///    second encoding of one value.
/// 2. An IPv4-mapped address (`::ffff:0:0/96`) is **rejected, not unmapped**.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V6Addr {
    octets: [u8; 16],
    zone: Option<ZoneIndex>,
}

impl V6Addr {
    /// The unspecified address, `::`.
    pub const UNSPECIFIED: V6Addr = V6Addr {
        octets: [0; 16],
        zone: None,
    };

    /// Builds from sixteen octets and an optional zone, enforcing both rules.
    pub fn new(octets: [u8; 16], zone: Option<ZoneIndex>) -> Result<Self, TypeError> {
        if is_v4_mapped(&octets) {
            return Err(TypeError::Ipv4MappedIpv6);
        }
        if is_link_local(&octets) != zone.is_some() {
            return Err(TypeError::Ipv6ZoneIndex);
        }
        Ok(Self { octets, zone })
    }

    /// Builds the **base of a prefix**, where the RFC 4007 zone rule does not
    /// apply.
    ///
    /// # W-39: the zone rule is about host candidates, not ranges
    ///
    /// `docs/protocol.md` §10.4 says "IPv6 link-local **host candidates** MUST
    /// carry `zone_index` or they are unusable on multi-interface hosts". A
    /// prefix names a *range*; it has no interface to be scoped to, and
    /// [`IpPrefix::new`] rejects a zone for exactly that reason. The two rules
    /// are each right and their conjunction made `fe80::/10` — and every
    /// link-local interface prefix — unrepresentable, so link-local prefixes
    /// were silently dropped.
    ///
    /// This constructor is the narrow relaxation: it accepts a zoneless
    /// link-local address, and nothing else changes. It still rejects an
    /// IPv4-mapped address.
    ///
    /// **Never use the result as an endpoint or a candidate.** A link-local
    /// address that reaches a socket without its zone is unusable on a
    /// multi-homed host, which is the defect §10.4 exists to prevent;
    /// [`V6Addr::new`] is the constructor for anything that will be connected to.
    pub fn prefix_base(octets: [u8; 16]) -> Result<Self, TypeError> {
        if is_v4_mapped(&octets) {
            return Err(TypeError::Ipv4MappedIpv6);
        }
        Ok(Self { octets, zone: None })
    }

    /// Builds from a wire slice and the proto's `uint32 zone_index`, where zero
    /// means "absent".
    pub fn from_slice(octets: &[u8], zone_index: u32) -> Result<Self, TypeError> {
        if octets.len() != 16 {
            return Err(TypeError::IdentifierLength {
                kind: "ipv6_address_bytes",
                expected: 16,
                observed: octets.len(),
            });
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(octets);
        Self::new(out, ZoneIndex::new(zone_index))
    }

    /// The sixteen octets.
    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        self.octets
    }

    /// The scope zone, present exactly when the address is link-local.
    #[must_use]
    pub const fn zone(self) -> Option<ZoneIndex> {
        self.zone
    }

    /// The proto's `zone_index` field value: the zone, or zero for "absent".
    #[must_use]
    pub const fn zone_index_wire(self) -> u32 {
        match self.zone {
            Some(z) => z.get(),
            None => 0,
        }
    }

    /// Whether this address is in `fe80::/10`.
    #[must_use]
    pub const fn is_link_local(self) -> bool {
        is_link_local(&self.octets)
    }

    /// Whether this address is inside the pinned product ULA
    /// `fd7c:9e5d:2a10::/48` (ADR-0010 AP-1).
    #[must_use]
    pub const fn is_product_ula(self) -> bool {
        self.octets[0] == 0xfd
            && self.octets[1] == 0x7c
            && self.octets[2] == 0x9e
            && self.octets[3] == 0x5d
            && self.octets[4] == 0x2a
            && self.octets[5] == 0x10
    }
}

impl fmt::Debug for V6Addr {
    /// Redacted for the same reason as [`V4Addr`]. The zone index is shown: it
    /// names a local interface ordinal, not the peer, and a link-local candidate
    /// failure is undiagnosable without it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.zone {
            Some(z) => write!(f, "V6Addr(<redacted>%{})", z.get()),
            None => f.write_str("V6Addr(<redacted>)"),
        }
    }
}

const fn is_link_local(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}

const fn is_v4_mapped(octets: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 10 {
        if octets[i] != 0 {
            return false;
        }
        i += 1;
    }
    octets[10] == 0xff && octets[11] == 0xff
}

/// An IP address of exactly one family.
///
/// `common.proto`: "Exactly one family is set. An `IPAddress` with neither set is
/// malformed; the oneof makes 'both' unrepresentable." A Rust enum makes both
/// halves of that true by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpAddr {
    /// An IPv4 address.
    V4(V4Addr),
    /// An IPv6 address.
    V6(V6Addr),
}

impl IpAddr {
    /// This address's family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        match self {
            IpAddr::V4(_) => AddressFamily::V4,
            IpAddr::V6(_) => AddressFamily::V6,
        }
    }

    /// The address octets — four or sixteen.
    #[must_use]
    pub fn octets(self) -> Vec<u8> {
        let (buf, len) = self.octet_buffer();
        buf[..len].to_vec()
    }

    /// The address octets in a fixed 16-byte buffer plus their true length.
    ///
    /// The allocation-free form, used by every prefix operation: prefix matching
    /// runs on the policy path and on every route decision, and an allocation per
    /// comparison there would be a per-packet-class cost for no benefit.
    #[must_use]
    pub const fn octet_buffer(self) -> ([u8; 16], usize) {
        match self {
            IpAddr::V4(a) => {
                let o = a.octets();
                (
                    [o[0], o[1], o[2], o[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    4,
                )
            }
            IpAddr::V6(a) => (a.octets(), 16),
        }
    }
}

/// A transport port. `common.proto`: "1..65535. Port 0 is malformed."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(NonZeroU16);

impl Port {
    /// Builds a port, rejecting zero.
    pub fn new(value: u16) -> Result<Self, TypeError> {
        NonZeroU16::new(value).map(Self).ok_or(TypeError::PortZero)
    }

    /// Builds from the proto's `uint32 port`, rejecting zero and anything above
    /// 65535 **before** it is narrowed — a cast would silently alias 65536 to 0.
    pub fn from_wire(value: u32) -> Result<Self, TypeError> {
        if value == 0 || value > u32::from(u16::MAX) {
            return Err(TypeError::PortZero);
        }
        #[allow(clippy::cast_possible_truncation)]
        Self::new(value as u16)
    }

    /// The port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// A transport endpoint — `docs/architecture.md` §3.3 `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// The address.
    pub address: IpAddr,
    /// The port.
    pub port: Port,
}

impl Endpoint {
    /// Builds an endpoint.
    #[must_use]
    pub const fn new(address: IpAddr, port: Port) -> Self {
        Self { address, port }
    }

    /// The endpoint's address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.address.family()
    }
}

/// A CIDR prefix in canonical form.
///
/// Canonical means every bit below `prefix_len` is zero. `10.0.0.1/24` is
/// **rejected**, never normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpPrefix {
    address: IpAddr,
    prefix_len: u32,
}

impl IpPrefix {
    /// Builds a prefix, validating the length against the family, rejecting a
    /// scope zone, and rejecting any set host bit.
    pub fn new(address: IpAddr, prefix_len: u32) -> Result<Self, TypeError> {
        let family = address.family();
        if prefix_len > family.max_prefix_len() {
            return Err(TypeError::PrefixLength {
                observed: prefix_len,
                limit: family.max_prefix_len(),
            });
        }
        if let IpAddr::V6(a) = address {
            if a.zone().is_some() {
                return Err(TypeError::PrefixHasZone);
            }
        }
        let (octets, len) = address.octet_buffer();
        if !host_bits_are_zero(&octets[..len], prefix_len) {
            return Err(TypeError::PrefixNotCanonical);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// The network address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix_len(self) -> u32 {
        self.prefix_len
    }

    /// The prefix's family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.address.family()
    }

    /// Whether `addr` falls inside this prefix.
    ///
    /// A cross-family test is always `false` — not an error and not a coercion.
    /// The families are separate address spaces, and answering "is this v4
    /// address in that v6 prefix" with anything but "no" would require a mapping
    /// this crate refuses to perform.
    #[must_use]
    pub fn contains(self, addr: IpAddr) -> bool {
        if addr.family() != self.family() {
            return false;
        }
        let (net, _) = self.address.octet_buffer();
        let (test, _) = addr.octet_buffer();
        let full = (self.prefix_len / 8) as usize;
        if net[..full] != test[..full] {
            return false;
        }
        let rem = self.prefix_len % 8;
        if rem == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        (net[full] & mask) == (test[full] & mask)
    }
}

/// An interface's **own address**, with the prefix length of the network it is
/// on.
///
/// # Why this is not an `IpPrefix`
///
/// The two look alike and are opposites. [`IpPrefix`] names a *range* and
/// requires every host bit to be zero, because it is matched against attacker
/// input in route and policy decisions and `common.proto` is explicit that
/// normalizing there "is how a rule intended to match one network comes to match
/// another". An interface address is the opposite kind of value: `192.0.2.10/24`
/// is a *host* address whose host bits are the whole point.
///
/// Conflating them was a real defect. `InterfaceFacts.addresses` was
/// `Vec<IpPrefix>`, so an adapter holding `192.0.2.10/24` had no representation
/// for it: `desktop-linux` masked to `192.0.2.0/24` and lost the address, and
/// `core-composition` could accept only `/32` and `/128`, reporting
/// `AddressNotReportable` for everything else — because a network address
/// offered as a candidate probes where nothing answers and reads as a NAT fault.
///
/// So this type keeps both facts: the address exactly as the OS reported it, and
/// the prefix length beside it. [`InterfaceAddress::network`] derives the
/// `IpPrefix` when a route is what is wanted — an explicit, named derivation of
/// our *own* data, which is a different act from normalizing a peer's.
///
/// A scope zone **is** permitted here, because a link-local interface address
/// genuinely has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterfaceAddress {
    address: IpAddr,
    prefix_len: u32,
}

impl InterfaceAddress {
    /// Builds an interface address.
    ///
    /// Validates the prefix length against the family and nothing else: host
    /// bits are expected, and a zone is expected on a link-local address.
    pub fn new(address: IpAddr, prefix_len: u32) -> Result<Self, TypeError> {
        let family = address.family();
        if prefix_len > family.max_prefix_len() {
            return Err(TypeError::PrefixLength {
                observed: prefix_len,
                limit: family.max_prefix_len(),
            });
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// The address itself — usable as an endpoint, zone and all.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// The prefix length of the network this address is on.
    #[must_use]
    pub const fn prefix_len(self) -> u32 {
        self.prefix_len
    }

    /// The address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.address.family()
    }

    /// Whether this is a host route — `/32` on v4, `/128` on v6.
    ///
    /// The overlay's own addresses are host routes (ADR-0010 §11.1 allocates a
    /// `/32` and a `/128` per `Device`); an underlay address usually is not.
    #[must_use]
    pub const fn is_host_route(self) -> bool {
        self.prefix_len == self.address.family().max_prefix_len()
    }

    /// The on-link network, as a canonical [`IpPrefix`].
    ///
    /// Masks the host bits and drops the scope zone, because a prefix has
    /// neither. This is a **derivation of our own OS-supplied data**, performed
    /// deliberately and named for what it does — not the normalization of
    /// untrusted input before a policy check that `common.proto` forbids.
    #[must_use]
    pub fn network(self) -> IpPrefix {
        let (mut octets, len) = self.address.octet_buffer();
        mask_host_bits(&mut octets[..len], self.prefix_len);
        let masked = match self.address.family() {
            AddressFamily::V4 => IpAddr::V4(V4Addr([octets[0], octets[1], octets[2], octets[3]])),
            // `prefix_base` rather than `new`: a masked link-local address is
            // `fe80::`, which has no interface to be scoped to. See W-39.
            AddressFamily::V6 => IpAddr::V6(V6Addr { octets, zone: None }),
        };
        IpPrefix {
            address: masked,
            prefix_len: self.prefix_len,
        }
    }
}

fn mask_host_bits(octets: &mut [u8], prefix_len: u32) {
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if full < octets.len() {
        if rem == 0 {
            octets[full..].fill(0);
        } else {
            octets[full] &= 0xffu8 << (8 - rem);
            octets[full + 1..].fill(0);
        }
    }
}

fn host_bits_are_zero(octets: &[u8], prefix_len: u32) -> bool {
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    if rem != 0 {
        let mask = 0xffu8 >> rem;
        if octets[full] & mask != 0 {
            return false;
        }
        if octets[full + 1..].iter().any(|b| *b != 0) {
            return false;
        }
    } else if octets[full..].iter().any(|b| *b != 0) {
        return false;
    }
    true
}

/// The overlay addresses of one `Device`.
///
/// **ADR-0010 R1 as a type.** Both fields are required, so a `Device` with one
/// family is not constructible. `docs/networking.md` §2.4 keeps this true even
/// when the *underlay* is single-stack: the overlay is dual-stack regardless,
/// which is why the underlay's shape is a separate value ([`UnderlayFamilies`])
/// and not an `Option` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OverlayAddresses {
    /// The `/32` from `100.64.0.0/10` (ADR-0010 §11.1).
    pub v4: V4Addr,
    /// The `/128` from the pinned product ULA `fd7c:9e5d:2a10::/48`.
    pub v6: V6Addr,
}

/// What the **underlay** offers, as its own fact.
///
/// Deliberately not derivable from "which overlay addresses exist": `common.proto`
/// forbids a field "interpretable as 'v4 present therefore dual-stack'", and
/// ADR-0010 §11.7 treats IPv6-only-with-NAT64, IPv6-only-without, and 464XLAT as
/// three distinct situations with three distinct behaviours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnderlayFamilies {
    /// IPv4 reachability only.
    V4Only,
    /// IPv6 reachability only. `nat64` carries ADR-0010 §11.7's PREF64 when the
    /// network has one; without it, an IPv4-literal peer or relay is reachable
    /// only via an IPv6-reachable relay.
    V6Only {
        /// The discovered NAT64 prefix, if any.
        nat64: Option<Nat64Prefix>,
    },
    /// Both families are reachable.
    DualStack,
    /// 464XLAT. ADR-0010 §11.7: "treated as IPv4 with `underlay=xlat`; effective
    /// MTU reduced; NAT class assumed CGNAT-equivalent." It is **not** the same
    /// value as [`UnderlayFamilies::V4Only`], because those two consequences do
    /// not follow from plain IPv4.
    Xlat464,
}

impl UnderlayFamilies {
    /// Whether a candidate of `family` can be gathered on this underlay.
    ///
    /// On `V6Only` with a NAT64 prefix an IPv4 *literal* is still reachable — by
    /// synthesis, not by native v4 — so this answers reachability of the family
    /// itself and callers use [`Nat64Prefix::synthesize`] for the literal case.
    #[must_use]
    pub const fn carries(self, family: AddressFamily) -> bool {
        matches!(
            (self, family),
            (
                UnderlayFamilies::V4Only | UnderlayFamilies::Xlat464,
                AddressFamily::V4
            ) | (UnderlayFamilies::V6Only { .. }, AddressFamily::V6)
                | (UnderlayFamilies::DualStack, _)
        )
    }

    /// The NAT64 prefix in force, if any.
    #[must_use]
    pub const fn nat64(self) -> Option<Nat64Prefix> {
        match self {
            UnderlayFamilies::V6Only { nat64 } => nat64,
            _ => None,
        }
    }
}

/// An RFC 6052 NAT64 prefix, used to synthesize an IPv6 address for an IPv4
/// literal on an IPv6-only underlay.
///
/// ADR-0010 §11.7: PREF64 is discovered via the RFC 8781 RA option (preferred)
/// or RFC 7050 `ipv4only.arpa` (fallback), and **"TwinVPN never depends on DNS64
/// to do this for it"** — our own resolver may be the one answering, which is a
/// circular dependency at bring-up. That is why synthesis is a pure function
/// here rather than a name lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nat64Prefix {
    octets: [u8; 16],
    prefix_len: u32,
}

impl Nat64Prefix {
    /// The RFC 6052 well-known prefix `64:ff9b::/96`.
    #[must_use]
    pub fn well_known() -> Self {
        let mut octets = [0u8; 16];
        octets[1] = 0x64;
        octets[2] = 0xff;
        octets[3] = 0x9b;
        Self {
            octets,
            prefix_len: 96,
        }
    }

    /// Builds a NAT64 prefix.
    ///
    /// Rejects any length outside RFC 6052's six, any set bit at or below the
    /// prefix length, and a non-zero u-octet (bits 64..71), which RFC 6052 §2.2
    /// requires to be zero.
    pub fn new(octets: [u8; 16], prefix_len: u32) -> Result<Self, TypeError> {
        if !matches!(prefix_len, 32 | 40 | 48 | 56 | 64 | 96) {
            return Err(TypeError::Nat64PrefixLength {
                observed: prefix_len,
            });
        }
        if !host_bits_are_zero(&octets, prefix_len) || octets[8] != 0 {
            return Err(TypeError::Nat64PrefixNotCanonical);
        }
        Ok(Self { octets, prefix_len })
    }

    /// The prefix length: one of 32, 40, 48, 56, 64, 96.
    #[must_use]
    pub const fn prefix_len(self) -> u32 {
        self.prefix_len
    }

    /// Synthesizes the IPv6 address for an IPv4 literal (RFC 6052 §2.2).
    ///
    /// The four IPv4 octets are written immediately after the prefix, skipping
    /// octet 8 — the u-octet, which stays zero — and every remaining suffix bit
    /// stays zero. The result is never link-local, so it carries no zone.
    #[must_use]
    pub fn synthesize(self, v4: V4Addr) -> V6Addr {
        let mut octets = self.octets;
        let v4 = v4.octets();
        let mut pos = (self.prefix_len / 8) as usize;
        for byte in v4 {
            if pos == 8 {
                pos = 9;
            }
            octets[pos] = byte;
            pos += 1;
        }
        V6Addr { octets, zone: None }
    }

    /// Extracts the embedded IPv4 literal, if `addr` is inside this prefix.
    ///
    /// Returns `None` for an address outside the prefix rather than producing a
    /// plausible-looking IPv4 address from unrelated bits.
    #[must_use]
    pub fn extract(self, addr: V6Addr) -> Option<V4Addr> {
        let a = addr.octets();
        let full = (self.prefix_len / 8) as usize;
        if a[..full] != self.octets[..full] {
            return None;
        }
        let mut out = [0u8; 4];
        let mut pos = full;
        for slot in &mut out {
            if pos == 8 {
                pos = 9;
            }
            *slot = a[pos];
            pos += 1;
        }
        Some(V4Addr(out))
    }
}

/// A value held once per address family, so a decision cannot be written for one
/// family and quietly omitted for the other.
///
/// ADR-0015 §11.2 refuses per-family reason-code *domains* for the same reason:
/// they make "we have a v4 story and a v6 story" sayable when the design is that
/// there is one story covering both. A `PerFamily<T>` makes the v6 half a
/// compile error to forget rather than a review comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PerFamily<T> {
    /// The IPv4 value.
    pub v4: T,
    /// The IPv6 value.
    pub v6: T,
}

impl<T> PerFamily<T> {
    /// Builds a per-family value.
    pub const fn new(v4: T, v6: T) -> Self {
        Self { v4, v6 }
    }

    /// Borrows the value for `family`.
    pub const fn get(&self, family: AddressFamily) -> &T {
        match family {
            AddressFamily::V4 => &self.v4,
            AddressFamily::V6 => &self.v6,
        }
    }

    /// Mutably borrows the value for `family`.
    pub const fn get_mut(&mut self, family: AddressFamily) -> &mut T {
        match family {
            AddressFamily::V4 => &mut self.v4,
            AddressFamily::V6 => &mut self.v6,
        }
    }

    /// Applies `f` to both halves.
    pub fn map<U>(self, mut f: impl FnMut(AddressFamily, T) -> U) -> PerFamily<U> {
        PerFamily {
            v4: f(AddressFamily::V4, self.v4),
            v6: f(AddressFamily::V6, self.v6),
        }
    }
}
