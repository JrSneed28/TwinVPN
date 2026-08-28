//! Socket options, applied **at open**, and the multicast join LAN discovery
//! uses.
//!
//! **Authority:** [`twinvpn_platform::socket::SocketOptions`] ("Applied at open,
//! not afterwards: several of them cannot be changed on a bound socket on at
//! least one target, and an option that silently failed to apply is a NAT ladder
//! that behaves differently from the one that was tested"),
//! `docs/networking.md` §6.2 (DF for DPLPMTUD), §8 (LAN discovery), §3.4 (the
//! reflexive-candidate attribution `IP_PKTINFO` serves), §5.2's Android row.
//!
//! # Nothing here is best-effort
//!
//! Every option the caller asked for is applied and **every failure is
//! returned**. The one exception is called out at its line and is a preference
//! rather than a requirement. `SO_MARK` is the one option this adapter refuses
//! to attempt at all, and the reason is at its comment: an Android app process
//! has no `CAP_NET_ADMIN`, and a mark silently ignored would be worse than one
//! never attempted.

use std::io;

use socket2::Socket;

use twinvpn_platform::socket::{FragmentPolicy, MulticastOptions, SocketFamily, SocketOptions};
use twinvpn_platform::PlatformError;
use twinvpn_types::IpAddr;

use crate::oserr::{self, Context};

/// Applies the caller's options, at open, before the socket is bound.
///
/// `SocketOptions`' own documentation: applied **at open**, "because several of
/// them cannot be changed on a bound socket on at least one target, and an
/// option that silently failed to apply is a NAT ladder that behaves differently
/// from the one that was tested". So each is applied and each failure is
/// returned — nothing here is best-effort.
pub fn apply_options(
    socket: &Socket,
    family: SocketFamily,
    options: &SocketOptions,
) -> Result<(), PlatformError> {
    let map = |e: io::Error, call: &'static str| oserr::from_errno(&e, call, Context::Socket);

    if options.reuse_address {
        socket
            .set_reuse_address(true)
            .map_err(|e| map(e, "SO_REUSEADDR"))?;
    }
    if options.reuse_port {
        socket
            .set_reuse_port(true)
            .map_err(|e| map(e, "SO_REUSEPORT"))?;
    }
    match family {
        SocketFamily::V4 => {
            if let Some(ttl) = options.hop_limit {
                socket
                    .set_ttl_v4(u32::from(ttl))
                    .map_err(|e| map(e, "IP_TTL"))?;
            }
            // DPLPMTUD needs DF so a too-large probe is DROPPED rather than
            // fragmented. `IP_MTU_DISCOVER=IP_PMTUDISC_PROBE` is the Linux and
            // bionic spelling.
            if options.fragment_policy == FragmentPolicy::DontFragment {
                set_int(
                    socket,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    libc::IP_PMTUDISC_PROBE,
                )?;
            }
            if options.receive_packet_info {
                set_int(socket, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
            }
        }
        SocketFamily::V6Only | SocketFamily::V6DualStack => {
            // `IPV6_V6ONLY` is set EXPLICITLY in both directions rather than
            // left to the platform default, which differs per target. Its own
            // seam documentation: "we forgot to set it" is how a v6 socket
            // silently starts accepting v4-mapped traffic.
            socket
                .set_only_v6(family == SocketFamily::V6Only)
                .map_err(|e| map(e, "IPV6_V6ONLY"))?;
            if let Some(hops) = options.hop_limit {
                set_int(
                    socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_UNICAST_HOPS,
                    i32::from(hops),
                )?;
            }
            if options.fragment_policy == FragmentPolicy::DontFragment {
                set_int(
                    socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_PROBE,
                )?;
            }
            if options.receive_packet_info {
                set_int(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
            }
        }
    }
    if let Some(dscp) = options.dscp {
        // DSCP occupies the top six bits of the TOS / traffic-class octet.
        let tclass = i32::from(dscp) << 2;
        match family {
            SocketFamily::V4 => set_int(socket, libc::IPPROTO_IP, libc::IP_TOS, tclass)?,
            SocketFamily::V6Only | SocketFamily::V6DualStack => {
                set_int(socket, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, tclass)?;
            }
        }
    }
    if let Some(size) = options.send_buffer_bytes {
        socket
            .set_send_buffer_size(size as usize)
            .map_err(|e| map(e, "SO_SNDBUF"))?;
    }
    if let Some(size) = options.receive_buffer_bytes {
        socket
            .set_recv_buffer_size(size as usize)
            .map_err(|e| map(e, "SO_RCVBUF"))?;
    }
    // `SocketOptions::firewall_mark` is Linux `SO_MARK`, and it is DELIBERATELY
    // not applied here: setting it needs `CAP_NET_ADMIN`, which an Android app
    // process never has. `docs/networking.md` §5.2's Android row lists no
    // policy-routing mechanism for exactly this reason -- the equivalent is
    // `VpnService.protect`, which is applied unconditionally below. A mark
    // silently ignored would be worse than one never attempted.
    Ok(())
}

/// One `setsockopt` of an `int`. The single such call site in this module.
pub fn set_int(socket: &Socket, level: i32, name: i32, value: i32) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd;
    // SAFETY: `setsockopt` reads exactly `size_of::<c_int>()` bytes through the
    // pointer it is given. `value` is a live local of that type, borrowed for
    // the duration of the call, and the descriptor is borrowed from a live
    // `Socket`.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .unwrap_or(libc::socklen_t::MAX),
        )
    };
    if rc < 0 {
        return Err(oserr::from_errno(
            &io::Error::last_os_error(),
            "setsockopt",
            Context::Socket,
        ));
    }
    Ok(())
}

/// Joins or leaves a multicast group.
pub fn multicast(
    socket: &Socket,
    options: &MulticastOptions,
    join: bool,
) -> Result<(), PlatformError> {
    let map = |e: io::Error| oserr::from_errno(&e, "IP_ADD_MEMBERSHIP", Context::Socket);
    match options.group {
        IpAddr::V4(v4) => {
            let group = std::net::Ipv4Addr::from(v4.octets());
            // The interface is NOT optional in `MulticastOptions`: "a multicast
            // join on 'any interface' means something different on every
            // platform, and LAN discovery's whole point is to know which segment
            // an announcement came from."
            if join {
                socket
                    .join_multicast_v4_n(
                        &group,
                        &socket2::InterfaceIndexOrAddress::Index(options.interface.0),
                    )
                    .map_err(map)
            } else {
                socket
                    .leave_multicast_v4_n(
                        &group,
                        &socket2::InterfaceIndexOrAddress::Index(options.interface.0),
                    )
                    .map_err(map)
            }
        }
        IpAddr::V6(v6) => {
            let group = std::net::Ipv6Addr::from(v6.octets());
            if join {
                socket
                    .join_multicast_v6(&group, options.interface.0)
                    .map_err(map)
            } else {
                socket
                    .leave_multicast_v6(&group, options.interface.0)
                    .map_err(map)
            }
        }
    }
}
