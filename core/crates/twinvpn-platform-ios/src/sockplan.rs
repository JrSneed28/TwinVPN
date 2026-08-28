//! The socket-option **plan**: which `setsockopt` calls a [`SocketOptions`] means
//! on Darwin. Target-free, so it is tested here.
//!
//! **Authority:** `docs/networking.md` §3 (candidate gathering, the disco probe,
//! port prediction), §6.2 (1280 floor + DPLPMTUD), §8 (LAN discovery);
//! ADR-0010 R8; [`twinvpn_platform::socket`];
//! `docs/implementation/ownership.md` §10.3.
//!
//! # Why the plan is separate from the syscall
//!
//! The seam is explicit that options are applied **at open** and that "an option
//! that silently failed to apply is a NAT ladder that behaves differently from
//! the one that was tested". Which options a given [`SocketOptions`] means is
//! therefore load-bearing, and it is a *decision over plain data*: no socket is
//! needed to compute it. So it lives here and is tested on the Linux build host;
//! only the `setsockopt` itself is Darwin-only.
//!
//! # Every constant is Darwin's, transcribed
//!
//! And several **differ from Linux's**, which is why importing them from `libc`
//! would be worse than useless on this crate's host-test path:
//!
//! | Option | Darwin | Linux |
//! |---|---|---|
//! | `IPV6_V6ONLY` | 27 | 26 |
//! | `IP_TOS` | 3 | 1 |
//! | `IPV6_TCLASS` | 36 | 67 |
//! | `IP_MULTICAST_TTL` | 10 | 33 |
//! | don't-fragment | `IP_DONTFRAG` 67 / `IPV6_DONTFRAG` 62 | `IP_MTU_DISCOVER` 10 |
//! | bind to interface | `IP_BOUND_IF` 25 / `IPV6_BOUND_IF` 125 | `SO_BINDTODEVICE` 25 (a *name*, not an index) |
//!
//! A build that took Linux's numbers would set `IP_TOS` where it meant
//! `IP_HDRINCL`. None of these fails loudly.
//!
//! # What this platform has no answer for
//!
//! `SocketOptions::firewall_mark` is Linux's `SO_MARK`, and
//! `docs/networking.md` §5.2 uses it to route TwinVPN's own traffic through
//! policy table 52. **iOS has no equivalent and needs none**: KS-9(1)'s iOS
//! clause makes the exemption implicit — "the provider's own sockets are excluded
//! from its own tunnel by construction". A mark is therefore reported as an
//! unrepresentable residual rather than silently ignored, so a caller that set
//! one learns that it did nothing.

use twinvpn_platform::{FragmentPolicy, SocketFamily, SocketOptions};

/// `SOL_SOCKET`.
pub const SOL_SOCKET: i32 = 0xffff;
/// `SO_REUSEADDR`.
pub const SO_REUSEADDR: i32 = 0x0004;
/// `SO_REUSEPORT`.
pub const SO_REUSEPORT: i32 = 0x0200;
/// `SO_SNDBUF`.
pub const SO_SNDBUF: i32 = 0x1001;
/// `SO_RCVBUF`.
pub const SO_RCVBUF: i32 = 0x1002;

/// `IPPROTO_IP`.
pub const IPPROTO_IP: i32 = 0;
/// `IPPROTO_IPV6`.
pub const IPPROTO_IPV6: i32 = 41;

/// `IP_TOS` — **3** on Darwin, 1 on Linux.
pub const IP_TOS: i32 = 3;
/// `IP_TTL`.
pub const IP_TTL: i32 = 4;
/// `IP_MULTICAST_TTL` — **10** on Darwin, 33 on Linux.
pub const IP_MULTICAST_TTL: i32 = 10;
/// `IP_MULTICAST_LOOP`.
pub const IP_MULTICAST_LOOP: i32 = 11;
/// `IP_BOUND_IF` — Darwin's bind-to-interface, taking an **index**.
pub const IP_BOUND_IF: i32 = 25;
/// `IP_RECVPKTINFO`.
pub const IP_RECVPKTINFO: i32 = 26;
/// `IP_DONTFRAG`.
pub const IP_DONTFRAG: i32 = 67;

/// `IPV6_V6ONLY` — **27** on Darwin, 26 on Linux.
pub const IPV6_V6ONLY: i32 = 27;
/// `IPV6_UNICAST_HOPS`.
pub const IPV6_UNICAST_HOPS: i32 = 4;
/// `IPV6_MULTICAST_HOPS`.
pub const IPV6_MULTICAST_HOPS: i32 = 10;
/// `IPV6_MULTICAST_LOOP`.
pub const IPV6_MULTICAST_LOOP: i32 = 11;
/// `IPV6_TCLASS` — **36** on Darwin, 67 on Linux.
pub const IPV6_TCLASS: i32 = 36;
/// `IPV6_DONTFRAG`.
pub const IPV6_DONTFRAG: i32 = 62;
/// `IPV6_RECVPKTINFO`.
pub const IPV6_RECVPKTINFO: i32 = 61;
/// `IPV6_BOUND_IF` — Darwin's bind-to-interface for v6, taking an **index**.
pub const IPV6_BOUND_IF: i32 = 125;

/// One `setsockopt` call, as plain data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SockOpt {
    /// The level.
    pub level: i32,
    /// The option name.
    pub name: i32,
    /// The value, as the `int` every option here takes.
    pub value: i32,
    /// A stable, non-localised tag naming the option, for a failure's evidence.
    pub tag: &'static str,
}

/// Something a caller asked for that this platform cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionResidual {
    /// `SocketOptions::firewall_mark` was set. iOS has no `SO_MARK`.
    FirewallMarkUnrepresentable {
        /// The mark the caller supplied.
        mark: u32,
    },
}

/// The rendered plan for one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPlan {
    /// The shape to open.
    pub family: SocketFamily,
    /// The options, in the order they must be applied.
    pub options: Vec<SockOpt>,
    /// What could not be expressed.
    pub residuals: Vec<OptionResidual>,
}

/// Renders the plan for `family` and `options`.
///
/// Order matters and is deterministic: `IPV6_V6ONLY` is applied **first**,
/// because on Darwin it can only be set before the socket is bound, and setting
/// it after another option has caused an implicit bind silently leaves a
/// "v6-only" socket accepting v4-mapped traffic — which `common.proto` rejects
/// everywhere else, and which ADR-0010 R8's "MUST NOT stall on a broken family"
/// depends on not happening.
#[must_use]
pub fn plan(family: SocketFamily, options: &SocketOptions) -> SocketPlan {
    let mut out = Vec::new();
    let mut residuals = Vec::new();
    let v6 = matches!(family, SocketFamily::V6Only | SocketFamily::V6DualStack);

    if v6 {
        out.push(SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_V6ONLY,
            value: i32::from(family == SocketFamily::V6Only),
            tag: "IPV6_V6ONLY",
        });
    }

    if options.reuse_address {
        out.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_REUSEADDR,
            value: 1,
            tag: "SO_REUSEADDR",
        });
    }
    if options.reuse_port {
        // §3.6's birthday-paradox port prediction opens many sockets at once.
        out.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_REUSEPORT,
            value: 1,
            tag: "SO_REUSEPORT",
        });
    }

    if options.fragment_policy == FragmentPolicy::DontFragment {
        // §6.2: DPLPMTUD needs DF set so a too-large probe is dropped rather
        // than fragmented. Darwin spells it as a plain boolean per family, not
        // as Linux's `IP_MTU_DISCOVER` mode enum.
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_DONTFRAG,
                value: 1,
                tag: "IPV6_DONTFRAG",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_DONTFRAG,
                value: 1,
                tag: "IP_DONTFRAG",
            }
        });
    }

    plan_per_packet(&mut out, v6, options);
    plan_scope(&mut out, v6, options);
    plan_multicast(&mut out, v6, options);
    plan_buffers(&mut out, options);

    if let Some(mark) = options.firewall_mark {
        // Reported, not ignored. A caller that set a mark learns that it did
        // nothing on this platform, and KS-9(1)'s iOS clause is why nothing is
        // needed.
        residuals.push(OptionResidual::FirewallMarkUnrepresentable { mark });
    }

    SocketPlan {
        family,
        options: out,
        residuals,
    }
}

/// Hop limit and DSCP — the two per-packet header fields a caller may set.
fn plan_per_packet(out: &mut Vec<SockOpt>, v6: bool, options: &SocketOptions) {
    if let Some(hops) = options.hop_limit {
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_UNICAST_HOPS,
                value: i32::from(hops),
                tag: "IPV6_UNICAST_HOPS",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_TTL,
                value: i32::from(hops),
                tag: "IP_TTL",
            }
        });
    }

    if let Some(dscp) = options.dscp {
        // DSCP occupies the top six bits of the TOS / traffic-class octet, so the
        // caller's six-bit value is shifted here rather than in Swift or at every
        // call site. Writing it unshifted sets ECN bits instead, which a middlebox
        // reads as congestion.
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_TCLASS,
                value: i32::from(dscp) << 2,
                tag: "IPV6_TCLASS",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_TOS,
                value: i32::from(dscp) << 2,
                tag: "IP_TOS",
            }
        });
    }
}

/// Arrival attribution and interface scoping.
fn plan_scope(out: &mut Vec<SockOpt>, v6: bool, options: &SocketOptions) {
    if options.receive_packet_info {
        // Without it a wildcard-bound socket cannot tell which of its addresses
        // a probe arrived on (§3.4). `crate::cmsg` parses what this turns on.
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_RECVPKTINFO,
                value: 1,
                tag: "IPV6_RECVPKTINFO",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_RECVPKTINFO,
                value: 1,
                tag: "IP_RECVPKTINFO",
            }
        });
    }

    if let Some(interface) = options.bind_to_interface {
        // Darwin takes an interface **index**; Linux's `SO_BINDTODEVICE` takes a
        // name. Required for a link-local v6 candidate and for LAN discovery on a
        // multi-homed host.
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_BOUND_IF,
                value: i32::try_from(interface.0).unwrap_or(i32::MAX),
                tag: "IPV6_BOUND_IF",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_BOUND_IF,
                value: i32::try_from(interface.0).unwrap_or(i32::MAX),
                tag: "IP_BOUND_IF",
            }
        });
    }
}

/// Multicast hop limit and loopback, for LAN discovery (§8).
fn plan_multicast(out: &mut Vec<SockOpt>, v6: bool, options: &SocketOptions) {
    if let Some(multicast) = &options.multicast {
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_MULTICAST_HOPS,
                value: i32::from(multicast.hop_limit),
                tag: "IPV6_MULTICAST_HOPS",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_MULTICAST_TTL,
                value: i32::from(multicast.hop_limit),
                tag: "IP_MULTICAST_TTL",
            }
        });
        out.push(if v6 {
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_MULTICAST_LOOP,
                value: i32::from(multicast.loopback),
                tag: "IPV6_MULTICAST_LOOP",
            }
        } else {
            SockOpt {
                level: IPPROTO_IP,
                name: IP_MULTICAST_LOOP,
                value: i32::from(multicast.loopback),
                tag: "IP_MULTICAST_LOOP",
            }
        });
    }
}

/// Send and receive buffer sizes, where the caller had a reason to set them.
fn plan_buffers(out: &mut Vec<SockOpt>, options: &SocketOptions) {
    if let Some(bytes) = options.send_buffer_bytes {
        out.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_SNDBUF,
            value: i32::try_from(bytes).unwrap_or(i32::MAX),
            tag: "SO_SNDBUF",
        });
    }
    if let Some(bytes) = options.receive_buffer_bytes {
        out.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_RCVBUF,
            value: i32::try_from(bytes).unwrap_or(i32::MAX),
            tag: "SO_RCVBUF",
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::{InterfaceIndex, MulticastOptions};
    use twinvpn_types::{IpAddr, V4Addr};

    fn find(plan: &SocketPlan, tag: &str) -> Option<SockOpt> {
        plan.options.iter().copied().find(|o| o.tag == tag)
    }

    #[test]
    fn v6_only_and_dual_stack_are_two_values_of_one_option_and_it_goes_first() {
        // "we forgot to set it" is how a v6 socket silently starts accepting
        // v4-mapped traffic that common.proto rejects everywhere else — and on
        // Darwin it can only be set before the bind.
        let only = plan(SocketFamily::V6Only, &SocketOptions::default());
        assert_eq!(only.options[0].tag, "IPV6_V6ONLY");
        assert_eq!(only.options[0].value, 1);

        let dual = plan(SocketFamily::V6DualStack, &SocketOptions::default());
        assert_eq!(dual.options[0].tag, "IPV6_V6ONLY");
        assert_eq!(dual.options[0].value, 0);

        // A v4 socket has no such option at all.
        assert!(find(
            &plan(SocketFamily::V4, &SocketOptions::default()),
            "IPV6_V6ONLY"
        )
        .is_none());
    }

    #[test]
    fn the_darwin_option_numbers_are_not_linuxs() {
        // A build that took Linux's numbers would set IP_TOS where it meant
        // IP_HDRINCL, and none of these fails loudly.
        assert_eq!(IPV6_V6ONLY, 27);
        assert_ne!(IPV6_V6ONLY, libc::IPV6_V6ONLY);
        assert_eq!(IP_TOS, 3);
        assert_ne!(IP_TOS, libc::IP_TOS);
        assert_eq!(IPV6_TCLASS, 36);
        assert_ne!(IPV6_TCLASS, libc::IPV6_TCLASS);
        assert_eq!(IP_MULTICAST_TTL, 10);
        assert_ne!(IP_MULTICAST_TTL, libc::IP_MULTICAST_TTL);
        assert_eq!(SOL_SOCKET, 0xffff);
        assert_ne!(SOL_SOCKET, libc::SOL_SOCKET);
    }

    #[test]
    fn the_gathering_default_sets_df_and_packet_info_for_both_families() {
        // §6.2 needs DF for DPLPMTUD; §3.4 needs packet info to attribute a
        // reflexive candidate. Both are on by default in the seam's own
        // `SocketOptions::default`.
        let v4 = plan(SocketFamily::V4, &SocketOptions::default());
        assert_eq!(find(&v4, "IP_DONTFRAG").map(|o| o.value), Some(1));
        assert_eq!(find(&v4, "IP_RECVPKTINFO").map(|o| o.value), Some(1));

        let v6 = plan(SocketFamily::V6Only, &SocketOptions::default());
        assert_eq!(find(&v6, "IPV6_DONTFRAG").map(|o| o.value), Some(1));
        assert_eq!(find(&v6, "IPV6_RECVPKTINFO").map(|o| o.value), Some(1));
    }

    #[test]
    fn darwin_spells_dont_fragment_as_a_boolean_and_not_as_linuxs_mode_enum() {
        let v4 = plan(SocketFamily::V4, &SocketOptions::default());
        assert_eq!(find(&v4, "IP_DONTFRAG").map(|o| o.name), Some(67));
        // Not IP_MTU_DISCOVER, which does not exist on Darwin.
        assert!(v4.options.iter().all(|o| o.tag != "IP_MTU_DISCOVER"));
    }

    #[test]
    fn dscp_occupies_the_top_six_bits_and_is_shifted_here() {
        // Writing it unshifted sets ECN bits instead, which a middlebox reads as
        // congestion.
        let options = SocketOptions {
            dscp: Some(46), // EF
            ..SocketOptions::default()
        };
        assert_eq!(
            find(&plan(SocketFamily::V4, &options), "IP_TOS").map(|o| o.value),
            Some(46 << 2)
        );
        assert_eq!(
            find(&plan(SocketFamily::V6Only, &options), "IPV6_TCLASS").map(|o| o.value),
            Some(46 << 2)
        );
    }

    #[test]
    fn bind_to_interface_carries_an_index_because_darwin_takes_one() {
        let options = SocketOptions {
            bind_to_interface: Some(InterfaceIndex(9)),
            ..SocketOptions::default()
        };
        assert_eq!(
            find(&plan(SocketFamily::V4, &options), "IP_BOUND_IF").map(|o| o.value),
            Some(9)
        );
        assert_eq!(
            find(&plan(SocketFamily::V6Only, &options), "IPV6_BOUND_IF").map(|o| o.value),
            Some(9)
        );
    }

    #[test]
    fn a_firewall_mark_is_reported_as_unrepresentable_and_never_silently_dropped() {
        // KS-9(1)'s iOS clause makes the exemption implicit, so nothing is
        // needed — but a caller that set a mark must learn it did nothing.
        let options = SocketOptions {
            firewall_mark: Some(0x7677),
            ..SocketOptions::default()
        };
        let plan = plan(SocketFamily::V4, &options);
        assert_eq!(
            plan.residuals,
            vec![OptionResidual::FirewallMarkUnrepresentable { mark: 0x7677 }]
        );
        assert!(plan.options.iter().all(|o| o.tag != "SO_MARK"));
    }

    #[test]
    fn multicast_carries_a_hop_limit_of_one_for_the_local_segment() {
        // §8.2's privacy discussion assumes the announcement stays on the local
        // segment.
        let options = SocketOptions {
            multicast: Some(MulticastOptions {
                group: IpAddr::V4(V4Addr::from_octets([239, 0, 0, 1])),
                interface: InterfaceIndex(1),
                loopback: false,
                hop_limit: 1,
            }),
            ..SocketOptions::default()
        };
        let v4 = plan(SocketFamily::V4, &options);
        assert_eq!(find(&v4, "IP_MULTICAST_TTL").map(|o| o.value), Some(1));
        assert_eq!(find(&v4, "IP_MULTICAST_LOOP").map(|o| o.value), Some(0));
    }

    #[test]
    fn the_plan_is_a_pure_function_of_the_options() {
        let options = SocketOptions {
            reuse_port: true,
            dscp: Some(10),
            ..SocketOptions::default()
        };
        assert_eq!(
            plan(SocketFamily::V6Only, &options),
            plan(SocketFamily::V6Only, &options)
        );
        assert_ne!(
            plan(SocketFamily::V6Only, &options),
            plan(SocketFamily::V4, &options)
        );
    }

    #[test]
    fn every_planned_option_names_itself_for_a_failures_evidence() {
        let options = SocketOptions {
            reuse_address: true,
            reuse_port: true,
            hop_limit: Some(64),
            dscp: Some(0),
            send_buffer_bytes: Some(65_536),
            receive_buffer_bytes: Some(65_536),
            ..SocketOptions::default()
        };
        for family in [
            SocketFamily::V4,
            SocketFamily::V6Only,
            SocketFamily::V6DualStack,
        ] {
            for option in plan(family, &options).options {
                assert!(!option.tag.is_empty());
                assert!(option
                    .tag
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
            }
        }
    }
}
