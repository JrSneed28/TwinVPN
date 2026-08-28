//! §3.2's address realism rule, and the contradiction inside it.
//!
//! **Authority:** `docs/testing-strategy.md` §3.2 ("Address realism
//! (normative)"), `docs/networking.md` §2.1, ADR-0010 §11.1, §7.5.
//!
//! # A finding, implemented rather than papered over
//!
//! §3.2 says, normatively, both of these:
//!
//! > The lab MUST use … RFC 6598 `100.64.0.0/10` for the carrier-NAT tier …
//!
//! > It MUST NOT reuse the `TwinNet` overlay prefixes … for underlay addressing
//! > — except in the one scenario family (`S-COLL-*`) …
//!
//! and `docs/networking.md` §2.1 makes the `TwinNet` **IPv4 overlay prefix**
//! `100.64.0.0/10`. The two sentences are therefore unsatisfiable together for
//! every CGNAT scenario, which is most of the interesting half of §3.3.
//!
//! The resolution implemented here — reported as a finding, not decided
//! unilaterally — reads the rule as its *purpose* rather than its letter. The
//! purpose is that an underlay address must never be confusable with an address
//! the overlay has allocated, and §2.1 allocates the overlay in control-plane
//! `/22` blocks, not the whole `/10`. So the lab carves two disjoint halves:
//!
//! | Use | Prefix | Why |
//! |---|---|---|
//! | Overlay (`TwinNet`) | `100.64.0.0/12` | the half a lab control plane allocates `/22`s from |
//! | Carrier NAT underlay | `100.80.0.0/12` | RFC 6598 as §3.2 requires, provably disjoint from the overlay half |
//!
//! [`AddressPlan::check_underlay`] enforces disjointness against the overlay
//! allocation **in force**, which is the assertion §3.2 actually needs, and it
//! still refuses RFC 1918 and documentation-space misuse. `S-COLL-*` opts out
//! explicitly through [`AddressPlan::collision_family`], so the one family whose
//! purpose is the collision can produce it — and cannot do so by accident.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::LabError;

/// An IPv4 CIDR, kept as a pair so no dependency is needed for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct V4Prefix {
    /// The network address.
    pub addr: Ipv4Addr,
    /// The prefix length in bits.
    pub len: u8,
}

impl V4Prefix {
    /// A prefix. `len` above 32 is clamped, because a nonsensical length must
    /// not silently widen containment.
    #[must_use]
    pub const fn new(addr: Ipv4Addr, len: u8) -> Self {
        Self {
            addr,
            len: if len > 32 { 32 } else { len },
        }
    }

    const fn mask(self) -> u32 {
        if self.len == 0 {
            0
        } else {
            u32::MAX << (32 - self.len)
        }
    }

    /// Whether `ip` falls inside this prefix.
    #[must_use]
    pub const fn contains(self, ip: Ipv4Addr) -> bool {
        (ip.to_bits() & self.mask()) == (self.addr.to_bits() & self.mask())
    }

    /// Whether two prefixes share any address.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        let m = if self.len < other.len {
            self.mask()
        } else {
            other.mask()
        };
        (self.addr.to_bits() & m) == (other.addr.to_bits() & m)
    }
}

/// An IPv6 CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct V6Prefix {
    /// The network address.
    pub addr: Ipv6Addr,
    /// The prefix length in bits.
    pub len: u8,
}

impl V6Prefix {
    /// A prefix. `len` above 128 is clamped.
    #[must_use]
    pub const fn new(addr: Ipv6Addr, len: u8) -> Self {
        Self {
            addr,
            len: if len > 128 { 128 } else { len },
        }
    }

    const fn mask(self) -> u128 {
        if self.len == 0 {
            0
        } else {
            u128::MAX << (128 - self.len)
        }
    }

    /// Whether `ip` falls inside this prefix.
    #[must_use]
    pub const fn contains(self, ip: Ipv6Addr) -> bool {
        (ip.to_bits() & self.mask()) == (self.addr.to_bits() & self.mask())
    }
}

/// Where an address sits in the lab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Tier {
    /// The "public" Internet between sites — documentation space.
    Public,
    /// The carrier-NAT tier — RFC 6598.
    Carrier,
    /// Behind a CPE — RFC 1918.
    Subscriber,
    /// The `TwinNet` overlay itself.
    Overlay,
}

/// §3.2's address plan, with the disjointness the rule actually needs.
#[derive(Debug, Clone, Copy)]
pub struct AddressPlan {
    /// The half of RFC 6598 a lab control plane allocates overlay `/22`s from.
    pub overlay_v4: V4Prefix,
    /// The `TwinNet` ULA (`docs/networking.md` §2.1, ADR-0010 §11.1).
    pub overlay_v6: V6Prefix,
    /// The carrier-NAT underlay half, disjoint from `overlay_v4`.
    pub carrier_v4: V4Prefix,
    /// Whether this plan is the `S-COLL-*` family, which exists to reproduce the
    /// §7.5 overlay/underlay collision and therefore opts out of disjointness.
    pub collision_family: bool,
}

/// The documentation prefixes §3.2 mandates for the "public" side.
pub const PUBLIC_V4_A: V4Prefix = V4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
/// The second documentation prefix (TEST-NET-3).
pub const PUBLIC_V4_B: V4Prefix = V4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
/// The IPv6 documentation prefix.
pub const PUBLIC_V6: V6Prefix = V6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32);
/// RFC 1918's three blocks, for the subscriber tier behind a CPE.
pub const RFC1918: [V4Prefix; 3] = [
    V4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8),
    V4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12),
    V4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16),
];

impl Default for AddressPlan {
    fn default() -> Self {
        Self {
            overlay_v4: V4Prefix::new(Ipv4Addr::new(100, 64, 0, 0), 12),
            overlay_v6: V6Prefix::new(Ipv6Addr::new(0xfd7c, 0x9e5d, 0x2a10, 0, 0, 0, 0, 0), 48),
            carrier_v4: V4Prefix::new(Ipv4Addr::new(100, 80, 0, 0), 12),
            collision_family: false,
        }
    }
}

impl AddressPlan {
    /// The `S-COLL-*` plan: the carrier tier is deliberately inside the overlay
    /// prefix, which is the collision `docs/networking.md` §7.5 and **R-17**
    /// exist to detect.
    #[must_use]
    pub fn collision() -> Self {
        Self {
            carrier_v4: V4Prefix::new(Ipv4Addr::new(100, 64, 0, 0), 12),
            collision_family: true,
            ..Self::default()
        }
    }

    /// Checks an underlay address against §3.2's realism rule.
    ///
    /// # Errors
    ///
    /// [`LabError::Addressing`] when the address is in the wrong space for its
    /// tier, or when an underlay address falls inside the overlay allocation in
    /// force and this is not the `S-COLL-*` family.
    pub fn check_underlay(self, tier: Tier, ip: Ipv4Addr) -> Result<(), LabError> {
        let in_overlay = self.overlay_v4.contains(ip);
        if in_overlay && tier != Tier::Overlay && !self.collision_family {
            return Err(LabError::Addressing {
                detail: format!(
                    "{ip} is inside the TwinNet overlay allocation {:?}/{}; §3.2 forbids reusing \
                 overlay prefixes for underlay addressing outside the S-COLL-* family",
                    self.overlay_v4.addr, self.overlay_v4.len
                ),
            });
        }
        match tier {
            Tier::Public => {
                if PUBLIC_V4_A.contains(ip) || PUBLIC_V4_B.contains(ip) {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!(
                            "{ip} is not documentation space; §3.2 requires 198.51.100.0/24 or \
                         203.0.113.0/24 on the public side so a lab address can never be \
                         mistaken for a real one"
                        ),
                    })
                }
            }
            Tier::Carrier => {
                if self.carrier_v4.contains(ip) {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!(
                            "{ip} is not in the carrier tier {:?}/{}",
                            self.carrier_v4.addr, self.carrier_v4.len
                        ),
                    })
                }
            }
            Tier::Subscriber => {
                if RFC1918.iter().any(|p| p.contains(ip)) {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!("{ip} is not RFC 1918 space behind a CPE"),
                    })
                }
            }
            Tier::Overlay => {
                if in_overlay {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!("{ip} is not inside the TwinNet overlay allocation"),
                    })
                }
            }
        }
    }

    /// Checks an IPv6 underlay address. **L-5 requires every family**, so this is
    /// not an optional counterpart to [`AddressPlan::check_underlay`].
    ///
    /// # Errors
    ///
    /// [`LabError::Addressing`] as above.
    pub fn check_underlay_v6(self, tier: Tier, ip: Ipv6Addr) -> Result<(), LabError> {
        let in_overlay = self.overlay_v6.contains(ip);
        if in_overlay && tier != Tier::Overlay && !self.collision_family {
            return Err(LabError::Addressing {
                detail: format!("{ip} is inside the TwinNet ULA; §3.2 forbids that as underlay"),
            });
        }
        match tier {
            Tier::Overlay => {
                if in_overlay {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!("{ip} is not inside the TwinNet ULA"),
                    })
                }
            }
            // Every non-overlay v6 tier is documentation space: there is no
            // carrier-grade NAT for IPv6 in the lab, which is exactly
            // `docs/networking.md` §3.2's last row.
            _ => {
                if PUBLIC_V6.contains(ip) {
                    Ok(())
                } else {
                    Err(LabError::Addressing {
                        detail: format!("{ip} is not inside 2001:db8::/32"),
                    })
                }
            }
        }
    }

    /// The disjointness §3.2's rule is actually asking for.
    #[must_use]
    pub fn overlay_and_carrier_are_disjoint(self) -> bool {
        !self.overlay_v4.overlaps(self.carrier_v4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_plan_keeps_overlay_and_carrier_disjoint() {
        assert!(AddressPlan::default().overlay_and_carrier_are_disjoint());
    }

    #[test]
    fn the_collision_family_is_the_only_plan_that_overlaps() {
        // If this ever passed for the default plan, every CGNAT scenario would be
        // silently reproducing §7.5's collision instead of CGNAT.
        assert!(!AddressPlan::collision().overlay_and_carrier_are_disjoint());
    }

    #[test]
    fn a_carrier_address_inside_the_overlay_is_refused() {
        let plan = AddressPlan::default();
        let err = plan
            .check_underlay(Tier::Carrier, Ipv4Addr::new(100, 64, 1, 1))
            .expect_err("100.64.1.1 is inside the overlay half");
        assert!(err.to_string().contains("overlay"), "{err}");
    }

    #[test]
    fn the_collision_family_may_produce_exactly_that_address() {
        // Negative control for the test above: the rule has an opt-out and it is
        // explicit, so `S-COLL-*` can reproduce the real defect.
        AddressPlan::collision()
            .check_underlay(Tier::Carrier, Ipv4Addr::new(100, 64, 1, 1))
            .expect("S-COLL-* exists to reproduce this collision");
    }

    #[test]
    fn a_public_address_outside_documentation_space_is_refused() {
        let plan = AddressPlan::default();
        assert!(plan
            .check_underlay(Tier::Public, Ipv4Addr::new(8, 8, 8, 8))
            .is_err());
        plan.check_underlay(Tier::Public, Ipv4Addr::new(198, 51, 100, 7))
            .expect("documentation space is permitted");
        plan.check_underlay(Tier::Public, Ipv4Addr::new(203, 0, 113, 7))
            .expect("TEST-NET-3 is permitted");
    }

    #[test]
    fn both_families_are_checked_and_v6_is_not_an_afterthought() {
        // L-5: a family with only a v4 instantiation fails review, so the v6
        // checker must refuse the same class of mistake.
        let plan = AddressPlan::default();
        assert!(plan
            .check_underlay_v6(Tier::Public, "fd7c:9e5d:2a10::1".parse().unwrap())
            .is_err());
        plan.check_underlay_v6(Tier::Public, "2001:db8:1::1".parse().unwrap())
            .expect("2001:db8::/32 is documentation space");
        plan.check_underlay_v6(Tier::Overlay, "fd7c:9e5d:2a10::1".parse().unwrap())
            .expect("the ULA is the overlay");
    }

    #[test]
    fn prefix_containment_is_not_accidentally_always_true() {
        assert!(PUBLIC_V4_A.contains(Ipv4Addr::new(198, 51, 100, 255)));
        assert!(!PUBLIC_V4_A.contains(Ipv4Addr::new(198, 51, 101, 0)));
        assert!(PUBLIC_V6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!PUBLIC_V6.contains("2001:db9::1".parse().unwrap()));
    }
}
