//! The bridge's own encoding — and every bound that makes an untrusted payload
//! safe to decode.
//!
//! **Authority:** `docs/implementation/ownership.md` §10.4 (the wave-3 bridge
//! ruling), §6 rules 9 and 10 ("validate every untrusted input … *before* any
//! allocation proportional to a declared length"; "bound every allocation an
//! untrusted input can drive"); ADR-0018 F-8's shape, borrowed rather than
//! inherited — see below.
//!
//! # Why this is not protobuf, and why that is not a contract violation
//!
//! ADR-0018 F-8 requires structured data crossing **`twinvpn.h`** to be "encoded
//! bytes generated from ADR-0003's contract artifacts". `ownership.md` §10.4 is
//! explicit that this bridge is **not** `twinvpn.h`: it is internal linkage
//! between two halves of one artifact compiled from one commit, it acquires no
//! compatibility obligation, and it is versionless "because there is nothing for
//! it to be compatible *with*".
//!
//! It also could not use a frozen message if it wanted to. The payload here is
//! an **Android `Network` as `ConnectivityManager` describes it** — a
//! `networkHandle`, a `NetworkCapabilities` transport bitset, `LinkProperties`.
//! `contracts/` defines no such message, and §3 forbids adding one. So the
//! encoding is defined here, in one file, with the whole of its validation
//! beside it.
//!
//! What it does inherit from F-8 is the *discipline*: only lengths, scalars and
//! octets cross; **no TwinVPN domain fact does**. There is no `ConnectionState`
//! here, no `reason_code`, no policy verdict, no candidate priority. A reviewer
//! checking §10.4's prohibition reads [`Field`] and is done.
//!
//! # Every bound, and where it comes from
//!
//! | Bound | Value | Source |
//! |---|---|---|
//! | payload | 4 KiB | this module — a `LinkProperties` is small, and the cap is what stops a malfunctioning shim driving an allocation |
//! | interface name | 255 B | [`twinvpn_platform::iface::InterfaceName::MAX_BYTES`] |
//! | addresses per network | 32 | this module; see [`MAX_ADDRESSES`] |
//! | resolvers per network | 8 per family × 2 | `limits.json` `dns.max_resolvers_per_family` |
//!
//! A violation is a **typed reject**, never a truncation, never a pad, never a
//! silent accept.

use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::PlatformError;
use twinvpn_types::{InterfaceAddress, IpAddr, Nat64Prefix, PerFamily, V4Addr};

use crate::netchange::{AndroidNetwork, TransportSet};
use crate::oserr;

/// The encoding version. Bumped only when both halves change together, which
/// under §10.4 is always — they ship as one artifact.
pub const WIRE_VERSION: u8 = 1;

/// The largest payload this decoder will look at.
///
/// A `LinkProperties` with the caps below encodes in well under 1 KiB; 4 KiB is
/// four times the worst case and is the point at which the sender is
/// malfunctioning rather than verbose.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

/// The most addresses one network may carry.
///
/// Not from `limits.json` — the registry has no bound for a platform interface's
/// own address set, because it is not a wire value. Stated here as a decision,
/// and chosen to match `candidates.max_candidates_per_set`, so the number in the
/// tree has one source rather than two.
pub const MAX_ADDRESSES: usize = 32;

/// The most resolvers one network may carry, across both families.
///
/// `limits.json` `dns.max_resolvers_per_family` is 8, and a network may report
/// both families.
pub const MAX_RESOLVERS: usize = 16;

/// A field tag. Present so a decode failure names *what* it was reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Version,
    Handle,
    Name,
    Transports,
    Flags,
    Mtu,
    Addresses,
    Resolvers,
    Nat64,
}

impl Field {
    /// A stable, non-localised tag for [`twinvpn_platform::OsDetail::call`].
    const fn tag(self) -> &'static str {
        match self {
            Field::Version => "bridge.version",
            Field::Handle => "bridge.handle",
            Field::Name => "bridge.name",
            Field::Transports => "bridge.transports",
            Field::Flags => "bridge.flags",
            Field::Mtu => "bridge.mtu",
            Field::Addresses => "bridge.addresses",
            Field::Resolvers => "bridge.resolvers",
            Field::Nat64 => "bridge.nat64",
        }
    }
}

/// A cursor that cannot read past its buffer.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize, field: Field) -> Result<&'a [u8], PlatformError> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| reject(field, libc::EOVERFLOW))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| reject(field, libc::EBADMSG))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, field: Field) -> Result<u8, PlatformError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: Field) -> Result<u16, PlatformError> {
        let b = self.take(2, field)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, field: Field) -> Result<u32, PlatformError> {
        let b = self.take(4, field)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, field: Field) -> Result<u64, PlatformError> {
        let b = self.take(8, field)?;
        let mut out = [0u8; 8];
        out.copy_from_slice(b);
        Ok(u64::from_be_bytes(out))
    }

    const fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
}

/// A typed reject. Never a truncation, never a pad, never a silent accept.
fn reject(field: Field, errno: i32) -> PlatformError {
    oserr::unavailable(field.tag(), errno)
}

/// Flag bits in the single flags octet.
const FLAG_UP: u8 = 1 << 0;
const FLAG_METERED: u8 = 1 << 1;
const FLAG_PRIVATE_DNS: u8 = 1 << 2;
const FLAG_DEFAULT_V4: u8 = 1 << 3;
const FLAG_DEFAULT_V6: u8 = 1 << 4;

/// Decodes one network the JNI layer observed.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on any bound violation, any truncation,
/// any unknown version, or any address that is not canonical in
/// `twinvpn-types`' sense. The caller has nothing to salvage: a half-decoded
/// `LinkProperties` describes a network that does not exist.
pub fn decode_network(bytes: &[u8]) -> Result<AndroidNetwork, PlatformError> {
    // Bounded BEFORE anything is read, let alone allocated.
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(reject(Field::Version, libc::EMSGSIZE));
    }
    let mut r = Reader::new(bytes);

    if r.u8(Field::Version)? != WIRE_VERSION {
        return Err(reject(Field::Version, libc::EPROTO));
    }
    let handle = r.u64(Field::Handle)?;

    let name_len = usize::from(r.u16(Field::Name)?);
    if name_len == 0 || name_len > InterfaceName::MAX_BYTES {
        return Err(reject(Field::Name, libc::ENAMETOOLONG));
    }
    let name_bytes = r.take(name_len, Field::Name)?;
    let name = core::str::from_utf8(name_bytes)
        .ok()
        .and_then(|s| InterfaceName::new(s).ok())
        .ok_or_else(|| reject(Field::Name, libc::EILSEQ))?;

    let transports = TransportSet::from_bits(r.u32(Field::Transports)?);
    let flags = r.u8(Field::Flags)?;
    let mtu = r.u32(Field::Mtu)?;

    let address_count = usize::from(r.u8(Field::Addresses)?);
    if address_count > MAX_ADDRESSES {
        return Err(reject(Field::Addresses, libc::E2BIG));
    }
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        let family = r.u8(Field::Addresses)?;
        let prefix_len = u32::from(r.u8(Field::Addresses)?);
        let address = read_address(&mut r, family, Field::Addresses)?;
        // **X-10.** This used to build an `IpPrefix`, which requires every host
        // bit to be zero — so `192.0.2.10/24`, the ordinary shape of what
        // `LinkProperties.getLinkAddresses()` reports, was REFUSED. Refusing
        // was the right call while the seam had nowhere to put it (masking
        // loses the address the core actually needs, and inventing one is
        // worse than dropping), and this crate said so here.
        //
        // `InterfaceAddress` is the seam now: it validates the prefix length
        // against the family and nothing else, because host bits are expected
        // and a zone is expected on a link-local address. A whole class of
        // Android interfaces stops being rejected at the bridge.
        let address = InterfaceAddress::new(address, prefix_len)
            .map_err(|_| reject(Field::Addresses, libc::EINVAL))?;
        addresses.push(address);
    }

    let resolver_count = usize::from(r.u8(Field::Resolvers)?);
    if resolver_count > MAX_RESOLVERS {
        return Err(reject(Field::Resolvers, libc::E2BIG));
    }
    let mut resolvers = Vec::with_capacity(resolver_count);
    for _ in 0..resolver_count {
        let family = r.u8(Field::Resolvers)?;
        resolvers.push(read_address(&mut r, family, Field::Resolvers)?);
    }

    let nat64 = if r.u8(Field::Nat64)? == 0 {
        None
    } else {
        let octets = r.take(16, Field::Nat64)?;
        let mut buf = [0u8; 16];
        buf.copy_from_slice(octets);
        let prefix_len = u32::from(r.u8(Field::Nat64)?);
        Some(Nat64Prefix::new(buf, prefix_len).map_err(|_| reject(Field::Nat64, libc::EINVAL))?)
    };

    // Trailing bytes are a reject, not a shrug: they mean the two halves
    // disagree about the encoding, and §10.4's "one commit, one artifact" is the
    // premise that makes disagreement impossible. If it happened, something is
    // wrong that silence would hide.
    if r.remaining() != 0 {
        return Err(reject(Field::Version, libc::EBADMSG));
    }

    Ok(AndroidNetwork {
        handle,
        name,
        transports,
        addresses,
        default_routes: PerFamily::new(flags & FLAG_DEFAULT_V4 != 0, flags & FLAG_DEFAULT_V6 != 0),
        resolvers,
        mtu,
        metered: flags & FLAG_METERED != 0,
        nat64,
        private_dns_active: flags & FLAG_PRIVATE_DNS != 0,
        is_up: flags & FLAG_UP != 0,
    })
}

/// Reads one address of the declared family.
fn read_address(r: &mut Reader<'_>, family: u8, field: Field) -> Result<IpAddr, PlatformError> {
    match family {
        4 => {
            let b = r.take(4, field)?;
            let mut octets = [0u8; 4];
            octets.copy_from_slice(b);
            Ok(IpAddr::V4(V4Addr::from_octets(octets)))
        }
        6 => {
            let b = r.take(16, field)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(b);
            let zone = r.u32(field)?;
            // The same rule the socket layer applies: the zone is part of the
            // address only for `fe80::/10`, and a link-local address with no
            // interface index is refused rather than made zoneless.
            crate::sock::addr::v6_from_kernel(octets, zone).map_err(|_| reject(field, libc::EINVAL))
        }
        // A family that is neither is a malfunctioning shim, not a v9 address.
        _ => Err(reject(field, libc::EAFNOSUPPORT)),
    }
}

/// Encodes one network. **Test and JNI-side reference only.**
///
/// Present so the decoder can be round-tripped rather than asserted against a
/// hand-written byte string that drifts. The Kotlin side writes the same layout,
/// and `a_network_round_trips_through_the_wire` is what keeps the two honest —
/// a layout change that broke the Kotlin writer breaks this test first.
#[must_use]
pub fn encode_network(network: &AndroidNetwork) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&network.handle.to_be_bytes());

    let name = network.name.as_str().as_bytes();
    out.extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(name);

    out.extend_from_slice(&network.transports.bits().to_be_bytes());

    let mut flags = 0u8;
    for (set, bit) in [
        (network.is_up, FLAG_UP),
        (network.metered, FLAG_METERED),
        (network.private_dns_active, FLAG_PRIVATE_DNS),
        (network.default_routes.v4, FLAG_DEFAULT_V4),
        (network.default_routes.v6, FLAG_DEFAULT_V6),
    ] {
        if set {
            flags |= bit;
        }
    }
    out.push(flags);
    out.extend_from_slice(&network.mtu.to_be_bytes());

    out.push(u8::try_from(network.addresses.len()).unwrap_or(u8::MAX));
    for address in &network.addresses {
        out.push(family_tag(address.address()));
        out.push(u8::try_from(address.prefix_len()).unwrap_or(u8::MAX));
        write_address(&mut out, address.address());
    }

    out.push(u8::try_from(network.resolvers.len()).unwrap_or(u8::MAX));
    for address in &network.resolvers {
        out.push(family_tag(*address));
        write_address(&mut out, *address);
    }

    match network.nat64 {
        None => out.push(0),
        Some(prefix) => {
            out.push(1);
            // `Nat64Prefix` exposes no octet accessor, so the octets are
            // recovered by synthesizing the unspecified IPv4 address: RFC 6052
            // embeds the v4 bits at a per-length offset and every other bit of
            // the result is the prefix, so synthesizing 0.0.0.0 yields exactly
            // the prefix. Round-tripped by
            // `an_ipv6_only_network_carries_its_nat64_prefix`.
            out.extend_from_slice(&prefix.synthesize(V4Addr::UNSPECIFIED).octets());
            out.push(u8::try_from(prefix.prefix_len()).unwrap_or(u8::MAX));
        }
    }
    out
}

/// The family tag the decoder reads.
const fn family_tag(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

/// Writes one address's octets, and a v6 address's scope zone.
fn write_address(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => {
            out.extend_from_slice(&v6.octets());
            out.extend_from_slice(&v6.zone_index_wire().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests;
