//! Address selection: Happy Eyeballs v2, and the NAT64 case ADR-0010 R1 makes
//! non-optional.
//!
//! **Authority:** ADR-0010 **R1** (IPv4 and IPv6 are equally required; there is
//! no "v6 later"), `docs/protocol.md` §4.1 (Happy Eyeballs v2 with a **250 ms**
//! IPv6 bias), RFC 8305 (Happy Eyeballs v2), RFC 6052 §2.2 (the IPv4-embedded
//! IPv6 address formats), RFC 8215 / RFC 6052 §2.1 (the well-known prefix),
//! RFC 7050 and RFC 8781 (how a host learns a prefix).
//!
//! # Why this is a module and not four `if` branches
//!
//! ADR-0010 R1 exists to forbid a design in which IPv4, IPv6, dual-stack and
//! IPv6-only are four code paths — and `ownership.md` §4.2 records the same
//! rule from the other side, refusing `TVPN-IPV4-*` as an error namespace
//! because a per-family namespace makes "we have a v4 story and a v6 story"
//! sayable.
//!
//! So family is **data** here. `plan` turns one endpoint plus the host's
//! [`AttachFamilies`] into two ordered lists, and the race in [`super`] is
//! written once over those lists. The IPv6-only host with NAT64 is not a
//! special case in the race; it is an endpoint whose v4 addresses were
//! rewritten before the race began.
//!
//! # Address resolution happens above this crate, and that is CB-1
//!
//! [`crate::transport::TransportConfig`] carries endpoint **names**, resolved
//! in the bootstrap DNS scope (ADR-0011 DN-0) so GeoDNS works. Resolving them
//! is a platform call — ADR-0018 CB-1 puts it at the platform seam, and a
//! blocking `getaddrinfo` inside an async attach would be the wrong shape even
//! if CB-1 permitted it. The composition root therefore supplies a resolved
//! [`ControlEndpoint`] per name, and this module chooses *among* addresses
//! rather than discovering them. A DNS64 resolver that already synthesised
//! AAAA records simply presents them as IPv6 addresses and
//! [`Nat64Prefix`] never runs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::CpError;
use crate::transport::AttachFamilies;

/// One coordination front-end: the name that goes in SNI, and its addresses.
///
/// The name is carried separately from the addresses because it is what the
/// TLS handshake presents and what
/// [`crate::transport::TransportConfig::coordination_endpoints`] names —
/// a literal in SNI would break GeoDNS front-ends that answer one name from
/// several regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEndpoint {
    server_name: String,
    addresses: Vec<SocketAddr>,
}

impl ControlEndpoint {
    /// Binds a resolved endpoint.
    ///
    /// # Errors
    ///
    /// [`CpError::Unreachable`] when the name is empty or resolved to nothing.
    /// An endpoint with no addresses cannot be attempted, and saying so at
    /// construction is better than a race that starts with an empty candidate
    /// list and reports a budget expiry.
    pub fn new(server_name: String, addresses: Vec<SocketAddr>) -> Result<Self, CpError> {
        if server_name.is_empty() || addresses.is_empty() {
            return Err(CpError::Unreachable);
        }
        Ok(Self {
            server_name,
            addresses,
        })
    }

    /// The name presented in SNI.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The resolved addresses, in the order the resolver returned them.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

/// An RFC 6052 `/96` NAT64 prefix.
///
/// Only `/96` is accepted. RFC 6052 §2.2 defines six lengths; `/96` is what
/// PREF64 (RFC 8781) advertises in practice and what the well-known prefix
/// uses, and it is the only one where the embedded IPv4 address is a
/// contiguous suffix. Supporting the other five would mean implementing the
/// bit-shuffling around the `u`-octet on a path that has never had a prefix to
/// test it with — a code path that cannot be exercised is not a capability.
/// A host given one of the other lengths reports it, and this is the finding to
/// raise rather than the constant to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nat64Prefix([u8; 12]);

impl Nat64Prefix {
    /// The RFC 6052 §2.1 well-known prefix, `64:ff9b::/96`.
    pub const WELL_KNOWN: Nat64Prefix =
        Nat64Prefix([0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Takes the first 96 bits of `prefix` as the NAT64 prefix.
    ///
    /// # Errors
    ///
    /// [`CpError::Unreachable`] when the low 32 bits are non-zero — that is not
    /// a `/96` prefix, and silently masking it off would attach to an address
    /// the operator did not configure.
    pub fn from_ipv6(prefix: Ipv6Addr) -> Result<Self, CpError> {
        let octets = prefix.octets();
        if octets[12..] != [0, 0, 0, 0] {
            return Err(CpError::Unreachable);
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&octets[..12]);
        Ok(Self(out))
    }

    /// Embeds `v4` in the prefix, per RFC 6052 §2.2's `/96` row.
    #[must_use]
    pub fn synthesize(self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[..12].copy_from_slice(&self.0);
        octets[12..].copy_from_slice(&v4.octets());
        Ipv6Addr::from(octets)
    }
}

/// The two ordered candidate lists a rung-1 attach races.
///
/// `primary` is tried immediately; `secondary` starts after
/// [`AttachFamilies::V6_BIAS`]. When `primary` is IPv6 that is exactly
/// `protocol.md` §4.1's bias. When the host has no IPv6 at all, `primary` is
/// the IPv4 list and `secondary` is empty — the same code, with the bias
/// applying to nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) primary: Vec<SocketAddr>,
    pub(super) secondary: Vec<SocketAddr>,
}

impl Plan {
    /// Whether there is anything at all to attempt.
    pub(super) fn is_empty(&self) -> bool {
        self.primary.is_empty() && self.secondary.is_empty()
    }
}

/// Turns one endpoint plus the host's families into the two racing lists.
///
/// The rules, in order:
///
/// 1. An address of a family the host does not have is dropped. Attempting it
///    would burn a slot in the race on a `EAFNOSUPPORT`.
/// 2. On a host with IPv6 but no IPv4, every dropped IPv4 address is
///    **synthesised** through `nat64` if a prefix is known, and appended
///    *after* the native IPv6 addresses. RFC 8305 §4 prefers a native address
///    to a synthesised one, and so does this: a NAT64 path traverses a
///    translator and a native path does not.
/// 3. IPv6 leads. `docs/protocol.md` §4.1 fixes the 250 ms bias, and the bias
///    is only meaningful if IPv6 is the one that starts first.
pub(super) fn plan(
    endpoint: &ControlEndpoint,
    families: AttachFamilies,
    nat64: Option<Nat64Prefix>,
) -> Plan {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    let mut synthesised = Vec::new();

    for addr in endpoint.addresses() {
        match addr.ip() {
            IpAddr::V6(_) if families.v6 => v6.push(*addr),
            IpAddr::V4(literal) => {
                if families.v4 {
                    v4.push(*addr);
                } else if families.v6 && families.nat64 {
                    if let Some(prefix) = nat64 {
                        synthesised.push(SocketAddr::new(
                            IpAddr::V6(prefix.synthesize(literal)),
                            addr.port(),
                        ));
                    }
                }
            }
            IpAddr::V6(_) => {}
        }
    }

    v6.extend(synthesised);
    if v6.is_empty() {
        // No IPv6 at all, so there is nothing for IPv4 to be biased *against*.
        // Putting the v4 list in `primary` means the 250 ms wait is skipped
        // rather than paid against an empty branch — RFC 8305's bias exists to
        // order two families, and a single-family host has no ordering problem.
        return Plan {
            primary: v4,
            secondary: Vec::new(),
        };
    }
    Plan {
        primary: v6,
        secondary: v4,
    }
}

#[cfg(test)]
mod tests {
    use super::{plan, ControlEndpoint, Nat64Prefix};
    use crate::transport::AttachFamilies;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn endpoint() -> ControlEndpoint {
        ControlEndpoint::new(
            "cp.example".to_owned(),
            vec![
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    443,
                ),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 443),
            ],
        )
        .expect("two addresses")
    }

    #[test]
    fn an_endpoint_with_no_name_or_no_address_is_refused() {
        assert!(ControlEndpoint::new(String::new(), vec![]).is_err());
        assert!(ControlEndpoint::new("cp.example".to_owned(), vec![]).is_err());
    }

    #[test]
    fn ipv6_leads_the_race_on_a_dual_stack_host() {
        let plan = plan(
            &endpoint(),
            AttachFamilies {
                v4: true,
                v6: true,
                nat64: false,
            },
            None,
        );
        assert_eq!(plan.primary.len(), 1);
        assert!(plan.primary[0].is_ipv6());
        assert_eq!(plan.secondary.len(), 1);
        assert!(plan.secondary[0].is_ipv4());
    }

    #[test]
    fn a_v4_only_host_races_v4_with_nothing_behind_it() {
        let plan = plan(
            &endpoint(),
            AttachFamilies {
                v4: true,
                v6: false,
                nat64: false,
            },
            None,
        );
        assert_eq!(plan.primary.len(), 1);
        assert!(plan.primary[0].is_ipv4());
        assert!(plan.secondary.is_empty());
    }

    #[test]
    fn a_v6_only_host_with_nat64_synthesises_the_v4_front_end() {
        // The transport-level half of `transport.rs`'s
        // `a_v6_only_host_with_nat64_can_still_attach`: that test asserts the
        // config admits the attempt, and this one asserts there is an address
        // to attempt. A v4-ONLY front-end is the case that matters — drop the
        // native v6 address and the synthesised one is all that is left.
        let v4_only_front_end = ControlEndpoint::new(
            "cp.example".to_owned(),
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                443,
            )],
        )
        .expect("one address");
        let families = AttachFamilies {
            v4: false,
            v6: true,
            nat64: true,
        };
        let synthesised = plan(&v4_only_front_end, families, Some(Nat64Prefix::WELL_KNOWN));
        assert_eq!(
            synthesised.primary.len(),
            1,
            "the NAT64 path is the only path"
        );
        assert_eq!(
            synthesised.primary[0].ip(),
            IpAddr::V6("64:ff9b::c633:6407".parse::<Ipv6Addr>().expect("literal"))
        );
        assert_eq!(synthesised.primary[0].port(), 443);

        // Without a prefix there is nothing to synthesise, and the plan says so
        // rather than presenting an address that cannot be reached.
        let no_prefix = plan(&v4_only_front_end, families, None);
        assert!(no_prefix.is_empty());
    }

    #[test]
    fn a_native_v6_address_is_raced_ahead_of_a_synthesised_one() {
        let plan = plan(
            &endpoint(),
            AttachFamilies {
                v4: false,
                v6: true,
                nat64: true,
            },
            Some(Nat64Prefix::WELL_KNOWN),
        );
        assert_eq!(plan.primary.len(), 2);
        assert_eq!(
            plan.primary[0].ip(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            "RFC 8305 §4 prefers native to translated"
        );
        assert!(plan.secondary.is_empty());
    }

    #[test]
    fn only_a_96_bit_prefix_is_accepted() {
        assert!(Nat64Prefix::from_ipv6("64:ff9b::".parse().expect("literal")).is_ok());
        let err = Nat64Prefix::from_ipv6("64:ff9b::1".parse().expect("literal"))
            .expect_err("the low 32 bits are not zero");
        assert_eq!(err.reason_code().as_str(), "CONTROL.UNREACHABLE");
    }

    #[test]
    fn the_well_known_prefix_is_rfc_6052_2_1() {
        assert_eq!(
            Nat64Prefix::WELL_KNOWN,
            Nat64Prefix::from_ipv6("64:ff9b::".parse().expect("literal")).expect("a /96")
        );
    }
}
