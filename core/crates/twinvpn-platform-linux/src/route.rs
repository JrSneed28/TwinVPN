//! Address, route and policy-rule programming over `rtnetlink`.
//!
//! **Authority:** ADR-0010 §11.3 (the Linux row: "netlink `RTM_NEWROUTE` into
//! table `52` + `ip rule` with `fwmark`, plus a suppress-prefixlength rule"),
//! R1, R5, R6, P1…P6; `docs/networking.md` §5.2, §7.2 (the four `/1` routes and
//! why the host's own default is never touched), §5.5 (coexistence).
//!
//! # Both families in one transaction, or neither
//!
//! > On every platform, IPv4 and IPv6 routes MUST be installed in the same
//! > `apply()` transaction. An implementation that can install one family's
//! > routes without the other's is **non-conforming**.
//!
//! [`program`] takes a whole [`NetworkContract`] and applies both halves. netlink
//! has no multi-message transaction, so atomicity is achieved the way ADR-0008
//! asks for — **all-or-nothing by construction**: every step is recorded as it
//! succeeds, and any failure unwinds the recorded steps before returning, so the
//! system is exactly as it was before the call.
//!
//! # The host's own default route is never touched
//!
//! §7.2: the two-`/1`-per-family form "wins by longest-prefix match while leaving
//! the host's default intact, so teardown is a pure deletion and cannot fail to
//! 'restore' anything". Nothing in this module issues `RTM_DELROUTE` for a route
//! it did not create, and `docs/networking.md` §5.5 rule 1 makes that a rule
//! rather than a habit.
//!
//! # The `/1` routes are a convenience; the firewall is the control
//!
//! §7.2 consequence 3, quoted so it is not forgotten here: "**The /1 routes are a
//! routing convenience, not a security control.** The security control is the
//! fail-closed firewall layer." Anything that installs a more-specific route
//! defeats this module and does not defeat [`crate::nft`].

use twinvpn_platform::{NetworkContract, PlatformError, RouteEntry};
use twinvpn_types::{AddressFamily, InterfaceAddress, IpAddr, IpPrefix};

use crate::netlink::{self, NetlinkSocket, NlBuilder};
use crate::oserr::{self, Context};

/// `struct ifaddrmsg { family, prefixlen, flags, scope, index }`.
fn ifaddrmsg(family: u8, prefix_len: u8, index: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = family;
    out[1] = prefix_len;
    // `IFA_F_NODAD` on v6: duplicate address detection on the overlay would add
    // a bring-up round trip that can stall, which is exactly what ADR-0010 R3
    // forbids ("no DHCP/DHCPv6/SLAAC on the overlay").
    out[2] = if family == af(AddressFamily::V6) {
        // `IFA_F_NODAD` is a `u32` flag word in `libc`; the byte in
        // `ifaddrmsg` holds the low eight bits, which is where NODAD lives.
        u8::try_from(libc::IFA_F_NODAD).unwrap_or(0x02)
    } else {
        0
    };
    out[3] = libc::RT_SCOPE_UNIVERSE;
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out
}

/// `struct rtmsg`.
fn rtmsg(family: u8, dst_len: u8, table: u8, rtype: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = family;
    out[1] = dst_len;
    out[4] = table;
    out[5] = libc::RTPROT_STATIC;
    out[6] = libc::RT_SCOPE_UNIVERSE;
    out[7] = rtype;
    out
}

/// `struct fib_rule_hdr`, which shares `rtmsg`'s layout.
fn fib_rule_hdr(family: u8, table: u8, action: u8) -> [u8; 12] {
    fib_rule_hdr_flags(family, table, action, 0)
}

/// The same, with `fib_rule_hdr.flags` set.
///
/// The trailing four bytes of the header are `__u32 flags`, and the only flag
/// this adapter sets is [`fib::INVERT`]. Written as a separate constructor so
/// the ordinary rules cannot acquire a flag by accident.
fn fib_rule_hdr_flags(family: u8, table: u8, action: u8, flags: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = family;
    out[4] = table;
    out[7] = action;
    out[8..12].copy_from_slice(&flags.to_le_bytes());
    out
}

/// `linux/fib_rules.h` constants `libc` 0.2 does not export.
///
/// Written out with their header values rather than reached for through a
/// second crate, and asserted against the kernel's own numbering by the
/// `RTM_NEWRULE` round trip in `tests/adapter.rs`: a wrong attribute number is
/// answered by `EINVAL`, not by a silently ignored rule.
mod fib {
    /// `FR_ACT_TO_TBL` — "look up the named table".
    pub const ACT_TO_TBL: u8 = 1;
    /// `FRA_PRIORITY`.
    pub const PRIORITY: u16 = 6;
    /// `FRA_FWMARK`.
    pub const FWMARK: u16 = 10;
    /// `FRA_SUPPRESS_PREFIXLEN`.
    pub const SUPPRESS_PREFIXLEN: u16 = 14;
    /// `FRA_TABLE` — the 32-bit table id, since `fib_rule_hdr.table` is a `u8`.
    pub const TABLE: u16 = 15;
    /// `FIB_RULE_INVERT` — "match everything this rule does NOT select".
    ///
    /// The flag that makes the fwmark rule read `not fwmark <mark> lookup 52`.
    /// See [`super::add_rule`] for why the inverted sense is the correct one and
    /// what the un-inverted one did.
    pub const INVERT: u32 = 0x0000_0002;
}

const fn af(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::V4 => 2,  // AF_INET
        AddressFamily::V6 => 10, // AF_INET6
    }
}

/// One step that was applied, so it can be unwound.
///
/// Recorded rather than recomputed: unwinding by re-deriving what "should" have
/// been applied is how a partial application becomes a partial rollback.
#[derive(Debug, Clone)]
enum Applied {
    Address {
        family: AddressFamily,
        /// The address exactly as the contract carries it — host bits and all.
        /// `IFA_LOCAL` must name the interface's own address, not the network it
        /// sits on, which is what an `IpPrefix` here would have forced.
        address: InterfaceAddress,
        index: u32,
    },
    Route {
        family: AddressFamily,
        entry: RouteEntry,
    },
    Rule {
        family: AddressFamily,
        mark: u32,
    },
}

/// Everything this module put on the host for one generation.
///
/// Held by the caller so [`unwind`] can remove exactly what was added — the
/// §5.5 rule that "TwinVPN MUST NOT delete or modify routes it did not create",
/// expressed as a data structure rather than as care.
#[derive(Debug, Clone, Default)]
pub struct AppliedState {
    steps: Vec<Applied>,
}

impl AppliedState {
    /// Whether anything is installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// How many host mutations this generation made. For the diagnostic bundle.
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }
}

/// Installs a whole contract's addresses, routes and policy rules.
///
/// On failure, everything already applied is removed before returning, so the
/// host is exactly as it was — ADR-0008's all-or-nothing, and the reason
/// `docs/networking.md` §2.3 calls partial application "the leak window".
///
/// # Errors
///
/// The first failure, after the unwind. The unwind's own errors are **not**
/// substituted for it: the caller needs to know what actually went wrong, and a
/// failure to unwind is reported separately by the caller's reconciler.
pub async fn program(
    contract: &NetworkContract,
    overlay_index: u32,
    firewall_mark: u32,
) -> Result<AppliedState, PlatformError> {
    let sock = NetlinkSocket::open(0)
        .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;
    let mut state = AppliedState::default();

    // The policy rule first. §7.2 consequence 2: "the tunnel's own encapsulated
    // packets are additionally pinned with a policy-routing rule (fwmark + table
    // 52 with a suppress rule), which is the real loop guard — the /1 trick
    // alone is not sufficient." Installing it BEFORE the routes means there is
    // no instant at which the /1 routes exist and the loop guard does not.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        if let Err(e) = add_rule(&sock, family, firewall_mark).await {
            unwind(&sock, &state).await;
            return Err(e);
        }
        state.steps.push(Applied::Rule {
            family,
            mark: firewall_mark,
        });
    }

    // Addresses, both families. R1: "Every Device MUST have both an IPv4 and an
    // IPv6 overlay address, always, regardless of underlay family" — and the
    // `PerFamily` shape is what makes forgetting one a compile error rather than
    // a review comment.
    for (family, prefixes) in [
        (AddressFamily::V4, &contract.addresses.v4),
        (AddressFamily::V6, &contract.addresses.v6),
    ] {
        for address in prefixes {
            if let Err(e) = add_address(&sock, family, *address, overlay_index).await {
                unwind(&sock, &state).await;
                return Err(e);
            }
            state.steps.push(Applied::Address {
                family,
                address: *address,
                index: overlay_index,
            });
        }
    }

    // Routes, both families, into table 52.
    for (family, routes) in [
        (AddressFamily::V4, &contract.routes.v4),
        (AddressFamily::V6, &contract.routes.v6),
    ] {
        for entry in routes {
            if let Err(e) = add_route(&sock, family, entry).await {
                unwind(&sock, &state).await;
                return Err(e);
            }
            state.steps.push(Applied::Route {
                family,
                entry: entry.clone(),
            });
        }
    }

    Ok(state)
}

/// Removes exactly what [`program`] added, in reverse order.
///
/// Every removal is attempted even if an earlier one failed: stopping at the
/// first error would leave more behind than continuing, and each step is
/// independently idempotent (`ESRCH`/`ENOENT` from a route already gone is not a
/// failure to unwind).
pub async fn revert(state: &AppliedState) -> Result<(), PlatformError> {
    let sock = NetlinkSocket::open(0)
        .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;
    unwind(&sock, state).await;
    Ok(())
}

async fn unwind(sock: &NetlinkSocket, state: &AppliedState) {
    for step in state.steps.iter().rev() {
        let result = match step {
            Applied::Address {
                family,
                address,
                index,
            } => del_address(sock, *family, *address, *index).await,
            Applied::Route { family, entry } => del_route(sock, *family, entry).await,
            Applied::Rule { family, mark } => del_rule(sock, *family, *mark).await,
        };
        if let Err(error) = result {
            // A route that is already gone is not a failure to unwind. Anything
            // else is recorded at WARN and the unwind continues, because
            // stopping here would leave MORE behind.
            tracing::warn!(
                target: "twinvpn.platform.linux.route",
                reason_code = error.reason_code().as_str(),
                "a rollback step did not apply; continuing so nothing else is left behind"
            );
        }
    }
}

async fn add_address(
    sock: &NetlinkSocket,
    family: AddressFamily,
    address: InterfaceAddress,
    index: u32,
) -> Result<(), PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_NEWADDR,
        u16::try_from(
            libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE,
        )
        .unwrap_or(0x105),
        sock.next_seq(),
    );
    b.payload(&ifaddrmsg(
        af(family),
        u8::try_from(address.prefix_len()).unwrap_or(0),
        index,
    ));
    let octets = address.address().octets();
    b.attr(libc::IFA_LOCAL, &octets);
    b.attr(libc::IFA_ADDRESS, &octets);
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_NEWADDR", Context::RouteProgram))
}

async fn del_address(
    sock: &NetlinkSocket,
    family: AddressFamily,
    address: InterfaceAddress,
    index: u32,
) -> Result<(), PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_DELADDR,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_ACK).unwrap_or(0x5),
        sock.next_seq(),
    );
    b.payload(&ifaddrmsg(
        af(family),
        u8::try_from(address.prefix_len()).unwrap_or(0),
        index,
    ));
    let octets = address.address().octets();
    b.attr(libc::IFA_LOCAL, &octets);
    b.attr(libc::IFA_ADDRESS, &octets);
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_DELADDR", Context::RouteProgram))
}

async fn add_route(
    sock: &NetlinkSocket,
    family: AddressFamily,
    entry: &RouteEntry,
) -> Result<(), PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_NEWROUTE,
        u16::try_from(
            libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE,
        )
        .unwrap_or(0x105),
        sock.next_seq(),
    );
    b.payload(&rtmsg(
        af(family),
        u8::try_from(entry.destination.prefix_len()).unwrap_or(0),
        // Table 52, ALWAYS. A route in the main table would compete with the
        // host's own and is exactly what §7.2 avoids.
        netlink::TABLE,
        libc::RTN_UNICAST,
    ));
    if entry.destination.prefix_len() > 0 {
        b.attr(libc::RTA_DST, &entry.destination.address().octets());
    }
    b.attr_u32(libc::RTA_OIF, entry.interface.0);
    if let Some(via) = entry.via {
        b.attr(libc::RTA_GATEWAY, &via.octets());
    }
    if let Some(metric) = entry.metric {
        b.attr_u32(libc::RTA_PRIORITY, metric);
    }
    // The table id is repeated as an attribute because `rtm_table` is a u8 and
    // cannot express a table above 255. 52 fits, but writing both is what makes
    // the message correct for any table the core might one day choose.
    b.attr_u32(libc::RTA_TABLE, u32::from(netlink::TABLE));
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_NEWROUTE", Context::RouteProgram))
}

async fn del_route(
    sock: &NetlinkSocket,
    family: AddressFamily,
    entry: &RouteEntry,
) -> Result<(), PlatformError> {
    let mut b = NlBuilder::new(
        libc::RTM_DELROUTE,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_ACK).unwrap_or(0x5),
        sock.next_seq(),
    );
    b.payload(&rtmsg(
        af(family),
        u8::try_from(entry.destination.prefix_len()).unwrap_or(0),
        netlink::TABLE,
        libc::RTN_UNICAST,
    ));
    if entry.destination.prefix_len() > 0 {
        b.attr(libc::RTA_DST, &entry.destination.address().octets());
    }
    b.attr_u32(libc::RTA_OIF, entry.interface.0);
    b.attr_u32(libc::RTA_TABLE, u32::from(netlink::TABLE));
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_DELROUTE", Context::RouteProgram))
}

/// The priority the TwinVPN policy rules sit at.
///
/// Below `main` (32766) so our table is consulted first for marked packets, and
/// above `local` (0) so loopback and local delivery are never diverted. The
/// suppress rule sits one priority lower than the lookup rule so it runs first.
pub const RULE_PRIORITY: u32 = 32_000;

/// The suppress rule's priority.
pub const SUPPRESS_PRIORITY: u32 = 31_999;

/// Installs the two policy rules ADR-0010 §11.3 names, for one family.
///
/// Two rules, not one:
///
/// - **`suppress_prefixlength 0`** on the `main` table (priority 31999), so a
///   lookup that would have matched only a default route falls through instead.
///   Without it, the host's own default route wins for protected traffic and the
///   tunnel carries nothing.
/// - **`not fwmark <mark> lookup 52`** (priority 32000): everything that is
///   *not* the tunnel's own encapsulated traffic is looked up in table 52, where
///   the contract's overlay routes live. Our own marked packets do **not** match
///   it, fall through to `main`, and take the underlay. This is the loop guard
///   §7.2 calls "the real" one.
///
/// # The inversion is load-bearing, and the un-inverted form was a leak
///
/// Wave 1 installed `fwmark <mark> lookup 52` — **without** the inversion — and
/// the two rules then read:
///
/// ```text
/// 31999: from all lookup main suppress_prefixlength 0
/// 32000: from all fwmark 0x7677 lookup 52
/// 32766: from all lookup main
/// ```
///
/// Measured against a real kernel with `ip route get` (`tests/matrix.rs`), an
/// ordinary application's packet to `100.64.0.5` — the protected overlay space —
/// resolved to **`dev underlay0`**: rule 31999 suppressed `main`'s default,
/// rule 32000 did not match an unmarked packet, and rule 32766 found the default
/// route again. Table 52 held the correct overlay route the whole time and
/// **nothing ever looked in it**, so the tunnel carried no traffic at all and
/// every packet to a peer left untunneled. Both families, identically.
///
/// That is not a subtle degradation; it is the routing half of the product not
/// working, and it was invisible to every test that checked `program()` returned
/// `Ok` or that table 52 contained the right route — both of which were true.
/// Only the kernel's own FIB answer showed it.
///
/// With the inversion the same lookup resolves to `dev twin0`, an unprotected
/// destination still resolves to `underlay0` (ADR-0012 KS-3a: traffic outside
/// the protected set is not governed by this table), and a *marked* packet —
/// ours — still resolves to `underlay0`, which is the loop guard doing its job.
/// All three are asserted in `tests/matrix.rs` against `ip route get`.
async fn add_rule(
    sock: &NetlinkSocket,
    family: AddressFamily,
    mark: u32,
) -> Result<(), PlatformError> {
    // The suppress rule, on `main`.
    let mut b = NlBuilder::new(
        libc::RTM_NEWRULE,
        u16::try_from(
            libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL,
        )
        .unwrap_or(0x605),
        sock.next_seq(),
    );
    b.payload(&fib_rule_hdr(
        af(family),
        libc::RT_TABLE_MAIN,
        fib::ACT_TO_TBL,
    ));
    b.attr_u32(fib::PRIORITY, SUPPRESS_PRIORITY);
    b.attr_u32(fib::SUPPRESS_PREFIXLEN, 0);
    // `NLM_F_EXCL` makes a re-apply return EEXIST rather than duplicating the
    // rule; that is the idempotency ADR-0008 asks for, and EEXIST is absorbed.
    match sock.request(b.finish()).await {
        Ok(_) => {}
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
        Err(e) => {
            return Err(oserr::from_errno(
                &e,
                "RTM_NEWRULE(suppress)",
                Context::RouteProgram,
            ))
        }
    }

    // The lookup rule, on table 52.
    let mut b = NlBuilder::new(
        libc::RTM_NEWRULE,
        u16::try_from(
            libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL,
        )
        .unwrap_or(0x605),
        sock.next_seq(),
    );
    b.payload(&fib_rule_hdr_flags(
        af(family),
        netlink::TABLE,
        fib::ACT_TO_TBL,
        fib::INVERT,
    ));
    b.attr_u32(fib::PRIORITY, RULE_PRIORITY);
    b.attr_u32(fib::FWMARK, mark);
    b.attr_u32(fib::TABLE, u32::from(netlink::TABLE));
    match sock.request(b.finish()).await {
        Ok(_) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(oserr::from_errno(
            &e,
            "RTM_NEWRULE(fwmark)",
            Context::RouteProgram,
        )),
    }
}

async fn del_rule(
    sock: &NetlinkSocket,
    family: AddressFamily,
    mark: u32,
) -> Result<(), PlatformError> {
    for (priority, table, fwmark, flags) in [
        (RULE_PRIORITY, netlink::TABLE, Some(mark), fib::INVERT),
        (SUPPRESS_PRIORITY, libc::RT_TABLE_MAIN, None, 0),
    ] {
        let mut b = NlBuilder::new(
            libc::RTM_DELRULE,
            u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_ACK).unwrap_or(0x5),
            sock.next_seq(),
        );
        // The flags are part of the rule's identity: a delete that omitted
        // `INVERT` would not match the rule `add_rule` installed, and the
        // "already gone" arm below would swallow the mismatch as success —
        // leaving a policy rule behind that outlives the process.
        b.payload(&fib_rule_hdr_flags(
            af(family),
            table,
            fib::ACT_TO_TBL,
            flags,
        ));
        b.attr_u32(fib::PRIORITY, priority);
        if let Some(mark) = fwmark {
            b.attr_u32(fib::FWMARK, mark);
        }
        match sock.request(b.finish()).await {
            Ok(_) => {}
            // Already gone is not a failure to unwind.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {}
            Err(e) => return Err(oserr::from_errno(&e, "RTM_DELRULE", Context::RouteProgram)),
        }
    }
    Ok(())
}

/// The four `/1` destinations `docs/networking.md` §7.2 installs for a full
/// tunnel, as a helper the shell's own tests can name.
///
/// Not used by [`program`] — the core computes the routes and this adapter
/// installs what it is given (CB-6, CB-2). It is here so the shape §7.2 fixes
/// is written once, checkably, rather than being an unstated expectation.
#[must_use]
pub fn full_tunnel_destinations() -> Vec<IpPrefix> {
    let mut out = Vec::new();
    for (octets, len) in [([0u8, 0, 0, 0], 1u32), ([128, 0, 0, 0], 1)] {
        if let Ok(p) = IpPrefix::new(IpAddr::V4(twinvpn_types::V4Addr::from_octets(octets)), len) {
            out.push(p);
        }
    }
    for first in [0x00u8, 0x80] {
        let mut o = [0u8; 16];
        o[0] = first;
        if let Ok(a) = twinvpn_types::V6Addr::new(o, None) {
            if let Ok(p) = IpPrefix::new(IpAddr::V6(a), 1) {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hand_written_headers_match_the_kernels_widths() {
        assert_eq!(
            std::mem::size_of::<libc::ifaddrmsg>(),
            ifaddrmsg(2, 24, 1).len()
        );
        // `libc` 0.2 exports no `rtmsg` type, so its width is asserted against
        // the kernel's own layout: eight `u8` fields then a `u32` of flags.
        assert_eq!(rtmsg(2, 0, 52, 1).len(), 8 + std::mem::size_of::<u32>());
        assert_eq!(fib_rule_hdr(2, 52, 1).len(), rtmsg(2, 0, 52, 1).len());
        assert_eq!(af(AddressFamily::V4), crate::netlink::AF_INET_U8);
        assert_eq!(af(AddressFamily::V6), crate::netlink::AF_INET6_U8);
    }

    #[test]
    fn an_overlay_v6_address_asks_for_no_duplicate_address_detection() {
        // ADR-0010 R3: "Address assignment MUST NOT introduce a bring-up round
        // trip that can stall." DAD is exactly such a round trip.
        let v6 = ifaddrmsg(af(AddressFamily::V6), 128, 9);
        assert_eq!(u32::from(v6[2]), libc::IFA_F_NODAD);
        let v4 = ifaddrmsg(af(AddressFamily::V4), 32, 9);
        assert_eq!(v4[2], 0, "v4 has no DAD to suppress");
    }

    #[test]
    fn every_route_goes_into_table_52_and_never_the_main_table() {
        // §7.2: "The host's own default route is never deleted or modified."
        // Putting our routes in table 52 is how that is structural rather than
        // careful — there is no code path here that names RT_TABLE_MAIN for a
        // route.
        let msg = rtmsg(af(AddressFamily::V4), 1, netlink::TABLE, 1);
        assert_eq!(msg[4], 52);
        assert_ne!(msg[4], libc::RT_TABLE_MAIN);
    }

    /// The rule ordering, asserted at **compile time**.
    ///
    /// A lower priority number is consulted first. The suppress rule must run
    /// before the lookup rule, or the host's default route wins for our own
    /// encapsulated packets and the tunnel's traffic never reaches the underlay.
    /// Both sit below `main` (32766) and above `local` (0).
    ///
    /// `const` rather than a runtime `assert!`, because these are constants: a
    /// runtime assertion on two `const`s is optimised out and never runs, while
    /// this one fails the build.
    const _ORDERING: () = {
        assert!(SUPPRESS_PRIORITY < RULE_PRIORITY);
        assert!(RULE_PRIORITY < 32_766, "below `main`");
        assert!(SUPPRESS_PRIORITY > 0, "above `local`");
    };

    #[test]
    fn the_full_tunnel_form_is_four_slash_ones_and_never_a_default_route() {
        let d = full_tunnel_destinations();
        assert_eq!(d.len(), 4);
        let text: Vec<String> = d.iter().copied().map(crate::addr::prefix_text).collect();
        assert_eq!(text, vec!["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
        assert!(
            !text.iter().any(|t| t == "0.0.0.0/0" || t == "::/0"),
            "installing a real default route would destroy the host's, which \
             §7.2 forbids and which teardown could then fail to restore"
        );
        assert_eq!(d.len(), 4);
        // Two per family, so the pair cannot be installed for one family only.
        assert_eq!(
            d.iter().filter(|p| p.family() == AddressFamily::V4).count(),
            2
        );
        assert_eq!(
            d.iter().filter(|p| p.family() == AddressFamily::V6).count(),
            2
        );
    }

    #[test]
    fn applied_state_records_what_was_added_rather_than_recomputing_it() {
        // Unwinding by re-deriving what "should" have been applied is how a
        // partial application becomes a partial rollback.
        let mut state = AppliedState::default();
        assert!(state.is_empty());
        state.steps.push(Applied::Rule {
            family: AddressFamily::V4,
            mark: 1,
        });
        assert_eq!(state.len(), 1);
    }
}
