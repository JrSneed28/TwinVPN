//! UDP sockets: v4, v6-only, dual-stack, multicast, and the per-socket options
//! the NAT ladder and DPLPMTUD need.
//!
//! **Authority:** [`twinvpn_platform::socket`], `docs/networking.md` §3
//! (candidate gathering, the disco probe, birthday-paradox port prediction), §6.2
//! (1280 floor + DPLPMTUD), §8 (LAN discovery), ADR-0004 (the NAT ladder),
//! ADR-0010 R1 and R8, ADR-0012 KS-9a, ADR-0018 CD-1, CD-2, DP-4.
//!
//! # W-25: this is one of the two surfaces the C ABI does not have
//!
//! `core/ffi/include/twinvpn.h`'s F-9 vtable has **no socket provider**, while
//! ADR-0018 §11.2 row 2.10 puts all NAT traversal in the core "with sockets via
//! the adapter". A shell binding only the C ABI therefore cannot do NAT
//! traversal at all. `shells/windows` binds this crate as a **Rust crate**,
//! which is why the whole [`SocketProvider`] exists here and works.
//!
//! # KS-9a: registration is an intra-process call, never IPC
//!
//! ADR-0012 KS-9a is explicit that on host class HC-1 — which
//! `docs/application-architecture.md` §7 assigns to Windows — the sockets and
//! the enforcement layer are in the **same process** (ADR-0016 PS-1), so
//! registering a socket with the enforcement layer "MUST NOT be specified as
//! IPC". That rule is satisfied here structurally rather than by discipline:
//! **this module opens no listener, exposes no endpoint, and has no
//! registration API at all.** On Windows the enforcement predicate is
//! `FWPM_CONDITION_ALE_APP_ID` plus `FWPM_CONDITION_ALE_USER_ID`
//! ([`crate::wfp::filters`]), both of which the kernel evaluates against the
//! calling process. There is nothing for a socket to register *with*, so there
//! is no local endpoint whose purpose is granting egress exemptions, and none
//! can be added without adding it here first.
//!
//! The cost of that mechanism — WFP's ALE conditions identify a process and not
//! a socket, so KS-10's socket classes collapse into one — is
//! [`crate::wfp::filters::Ks9Residual`], reported as a value rather than
//! papered over.
//!
//! # The split: what runs here, and what has never run anywhere
//!
//! **This host is Linux and nothing in this crate has been linked or run.** So
//! every layer that can be target-free is:
//!
//! | Layer | Target-free | Tested on this host |
//! |---|---|---|
//! | `SocketOptions` → the `setsockopt` programme | yes | yes |
//! | the Winsock option numbers themselves | yes | yes, and asserted against `windows-sys` under `cfg(windows)` |
//! | `sockaddr` rendering and parsing, with the v4-mapped un-mapping | yes | yes |
//! | the `WSAMSG` control-buffer walk for `IP_PKTINFO` | yes | yes |
//! | the multicast option encodings | yes | yes |
//! | `WSASocketW`, `bind`, `setsockopt`, `WSARecvMsg`, `sendto` | **no** | **no** |
//!
//! # Readiness, not blocking
//!
//! Every socket is put into non-blocking mode with `ioctlsocket(FIONBIO)` and
//! driven by `tokio::net::UdpSocket`'s readiness, so an I/O call never occupies
//! an executor thread. Cancellation is dropping the future — the readiness
//! guard is released and no syscall is in flight, so nothing is held. **No
//! deadline is imposed here:** timeouts are the core's, composed from
//! `twinvpn_env::Timer` on the injected monotonic clock, and an adapter-imposed
//! one would put a deadline outside CD-1's reach.

use std::sync::atomic::{AtomicBool, Ordering};

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    Datagram, FragmentPolicy, InterfaceIndex, MulticastOptions, PlatformError, SocketCapabilities,
    SocketFamily, SocketOptions, SocketProvider, SupportedFamilies, UdpBindSpec, UdpSocket,
};
use twinvpn_types::{Endpoint, IpAddr, Port, V4Addr, V6Addr, ZoneIndex};

use crate::oserr::{self, Context, Win32Error};
use crate::shutdown::ShutdownLatch;

// ---------------------------------------------------------------------------
// The Winsock numbers, as target-free literals
// ---------------------------------------------------------------------------
//
// Literals rather than `windows-sys` imports, for the reason `oserr` gives: the
// layer that decides *which* option to set has no reason to need the OS that
// will set it, and a constant that only exists under `cfg(windows)` is a
// constant no test on this host can check. `win_constants` below asserts every
// one of them against `windows-sys`'s own value under `cfg(windows)`, so a
// drifted number fails `make cross-check` rather than silently configuring the
// wrong option.

/// `SOL_SOCKET`.
pub const SOL_SOCKET: i32 = 65535;
/// `IPPROTO_IP`.
pub const IPPROTO_IP: i32 = 0;
/// `IPPROTO_IPV6`.
pub const IPPROTO_IPV6: i32 = 41;

/// `SO_REUSEADDR`.
pub const SO_REUSEADDR: i32 = 4;
/// `SO_SNDBUF`.
pub const SO_SNDBUF: i32 = 4097;
/// `SO_RCVBUF`.
pub const SO_RCVBUF: i32 = 4098;

/// `IP_TOS`.
pub const IP_TOS: i32 = 3;
/// `IP_TTL`.
pub const IP_TTL: i32 = 4;
/// `IP_MULTICAST_IF`.
pub const IP_MULTICAST_IF: i32 = 9;
/// `IP_MULTICAST_TTL`.
pub const IP_MULTICAST_TTL: i32 = 10;
/// `IP_MULTICAST_LOOP`.
pub const IP_MULTICAST_LOOP: i32 = 11;
/// `IP_ADD_MEMBERSHIP`.
pub const IP_ADD_MEMBERSHIP: i32 = 12;
/// `IP_DROP_MEMBERSHIP`.
pub const IP_DROP_MEMBERSHIP: i32 = 13;
/// `IP_DONTFRAGMENT`.
pub const IP_DONTFRAGMENT: i32 = 14;
/// `IP_PKTINFO`.
pub const IP_PKTINFO: i32 = 19;
/// `IP_UNICAST_IF`.
pub const IP_UNICAST_IF: i32 = 31;

/// `IPV6_UNICAST_HOPS`.
pub const IPV6_UNICAST_HOPS: i32 = 4;
/// `IPV6_MULTICAST_IF`.
pub const IPV6_MULTICAST_IF: i32 = 9;
/// `IPV6_MULTICAST_HOPS`.
pub const IPV6_MULTICAST_HOPS: i32 = 10;
/// `IPV6_MULTICAST_LOOP`.
pub const IPV6_MULTICAST_LOOP: i32 = 11;
/// `IPV6_ADD_MEMBERSHIP`.
pub const IPV6_ADD_MEMBERSHIP: i32 = 12;
/// `IPV6_DROP_MEMBERSHIP`.
pub const IPV6_DROP_MEMBERSHIP: i32 = 13;
/// `IPV6_DONTFRAG`.
pub const IPV6_DONTFRAG: i32 = 14;
/// `IPV6_PKTINFO`.
pub const IPV6_PKTINFO: i32 = 19;
/// `IPV6_V6ONLY`.
pub const IPV6_V6ONLY: i32 = 27;
/// `IPV6_UNICAST_IF`.
pub const IPV6_UNICAST_IF: i32 = 31;
/// `IPV6_TCLASS`.
pub const IPV6_TCLASS: i32 = 39;

/// One `setsockopt` call, as data.
///
/// The whole point of the type: [`render_options`] decides *what* to set with no
/// socket in hand, so the decision is a value a test on this host can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockOpt {
    /// The option level.
    pub level: i32,
    /// The option name.
    pub name: i32,
    /// The option value, in the width and byte order Winsock expects.
    pub value: OptValue,
    /// A stable, non-localised tag for the failure this call would produce.
    ///
    /// Not user-visible text: it is the `call` an [`crate::oserr::Win32Error`]
    /// carries, so a support case can see *which* option Windows refused rather
    /// than only that one did.
    pub call: &'static str,
}

/// A `setsockopt` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptValue {
    /// A 32-bit integer in host byte order — the ordinary case.
    Int(i32),
    /// Raw bytes, for the options whose value is a struct.
    Bytes(Vec<u8>),
}

impl OptValue {
    /// The bytes Winsock is handed.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            OptValue::Int(v) => v.to_ne_bytes().to_vec(),
            OptValue::Bytes(b) => b.clone(),
        }
    }
}

/// An option the caller asked for that Windows has no equivalent of.
///
/// **Named, never silently dropped.** `SocketOptions`' own documentation is the
/// reason: "an option that silently failed to apply is a NAT ladder that behaves
/// differently from the one that was tested".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// `SO_REUSEPORT`. Windows has no such option, in any version.
    ///
    /// `docs/networking.md` §3.6's birthday-paradox port prediction opens many
    /// sockets at once and on Linux that needs it. See this module's report: the
    /// nearest Windows behaviour is not equivalent and is not substituted.
    ReusePort,
    /// `SO_MARK`. Windows has no socket mark.
    ///
    /// On Linux it is half of KS-9(1)'s bootstrap predicate and the §5.2
    /// policy-routing key. On Windows the predicate is `ALE_APP_ID` plus
    /// `ALE_USER_ID` and there is no routing mark, so a caller asking for one is
    /// asking for something this host cannot do.
    FirewallMark,
}

impl Unsupported {
    /// The stable, non-localised tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Unsupported::ReusePort => "SO_REUSEPORT",
            Unsupported::FirewallMark => "SO_MARK",
        }
    }
}

/// Everything one `UdpBindSpec` asks of `setsockopt`, plus what it asked for
/// that cannot be done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionProgramme {
    /// The calls, **in the order they must be made**. `IPV6_V6ONLY` is first
    /// because it cannot be changed after `bind` on any supported version, and
    /// the whole reason [`SocketFamily::V6Only`] and
    /// [`SocketFamily::V6DualStack`] are different values rather than a flag is
    /// that "we forgot to set it" is how a v6 socket silently starts accepting
    /// v4-mapped traffic that `common.proto` rejects everywhere else.
    pub calls: Vec<SockOpt>,
    /// What was asked for and cannot be supplied.
    pub unsupported: Vec<Unsupported>,
}

/// Renders the `setsockopt` programme for one bind.
///
/// **A pure function.** No socket, no I/O, no ambient state — which is what
/// makes the contents of the programme a checked property on a host with no
/// Winsock at all.
#[must_use]
pub fn render_options(family: SocketFamily, options: &SocketOptions) -> OptionProgramme {
    let is_v6 = !matches!(family, SocketFamily::V4);
    let mut calls = Vec::new();
    let mut unsupported = Vec::new();

    // First, and before `bind`.
    if let Some(option) = v6only(family) {
        calls.push(option);
    }

    if options.reuse_address {
        calls.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_REUSEADDR,
            value: OptValue::Int(1),
            call: "SO_REUSEADDR",
        });
    }
    if options.reuse_port {
        unsupported.push(Unsupported::ReusePort);
    }

    if matches!(options.fragment_policy, FragmentPolicy::DontFragment) {
        calls.push(dont_fragment(is_v6));
    }
    if let Some(hops) = options.hop_limit {
        calls.push(hop_limit(is_v6, hops));
    }
    if let Some(dscp) = options.dscp {
        calls.push(traffic_class(is_v6, dscp));
    }
    if let Some(index) = options.bind_to_interface {
        calls.push(unicast_if(is_v6, index));
    }
    if options.receive_packet_info {
        calls.push(packet_info(is_v6));
    }

    if options.firewall_mark.is_some() {
        unsupported.push(Unsupported::FirewallMark);
    }

    if let Some(bytes) = options.send_buffer_bytes {
        calls.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_SNDBUF,
            value: OptValue::Int(clamp_buffer(bytes)),
            call: "SO_SNDBUF",
        });
    }
    if let Some(bytes) = options.receive_buffer_bytes {
        calls.push(SockOpt {
            level: SOL_SOCKET,
            name: SO_RCVBUF,
            value: OptValue::Int(clamp_buffer(bytes)),
            call: "SO_RCVBUF",
        });
    }

    OptionProgramme { calls, unsupported }
}

/// `IPV6_V6ONLY`, or nothing at all on a v4 socket.
///
/// The whole reason [`SocketFamily::V6Only`] and [`SocketFamily::V6DualStack`]
/// are different values rather than a flag is that "we forgot to set it" is how
/// a v6 socket silently starts accepting v4-mapped traffic that `common.proto`
/// rejects everywhere else. An `Option` from one function is what makes "the v4
/// case sets nothing" a single reviewable line rather than an empty match arm.
#[must_use]
pub const fn v6only(family: SocketFamily) -> Option<SockOpt> {
    let value = match family {
        SocketFamily::V6Only => 1,
        SocketFamily::V6DualStack => 0,
        SocketFamily::V4 => return None,
    };
    Some(SockOpt {
        level: IPPROTO_IPV6,
        name: IPV6_V6ONLY,
        value: OptValue::Int(value),
        call: "IPV6_V6ONLY",
    })
}

/// The don't-fragment option for a family.
///
/// DPLPMTUD (`docs/networking.md` §6.2): "success is inferred from an
/// acknowledgement, not from the absence of an ICMP error", which requires the
/// too-large probe to be **dropped** rather than fragmented. Windows expresses
/// that as a plain don't-fragment flag; it has no `IP_PMTUDISC_PROBE`
/// equivalent, so it also keeps its own path-MTU bookkeeping and will act on an
/// ICMP "packet too big" that RFC 8899 says to ignore. That difference is a
/// reported finding, not something this function papers over.
#[must_use]
pub const fn dont_fragment(is_v6: bool) -> SockOpt {
    if is_v6 {
        SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_DONTFRAG,
            value: OptValue::Int(1),
            call: "IPV6_DONTFRAG",
        }
    } else {
        SockOpt {
            level: IPPROTO_IP,
            name: IP_DONTFRAGMENT,
            value: OptValue::Int(1),
            call: "IP_DONTFRAGMENT",
        }
    }
}

/// `IP_TTL` or `IPV6_UNICAST_HOPS`.
///
/// One field on the seam and not two, "because a socket has exactly one family
/// and carrying both would make *which one applies* a question the core has to
/// answer".
#[must_use]
pub const fn hop_limit(is_v6: bool, hops: u8) -> SockOpt {
    let value = OptValue::Int(hops as i32);
    if is_v6 {
        SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_UNICAST_HOPS,
            value,
            call: "IPV6_UNICAST_HOPS",
        }
    } else {
        SockOpt {
            level: IPPROTO_IP,
            name: IP_TTL,
            value,
            call: "IP_TTL",
        }
    }
}

/// `IP_TOS` or `IPV6_TCLASS`.
///
/// The seam carries the DSCP **code point**; the wire field is the full TOS /
/// traffic-class octet, so the shift happens here rather than in the core, where
/// it would be a platform fact above the adapter.
#[must_use]
pub const fn traffic_class(is_v6: bool, dscp: u8) -> SockOpt {
    let value = OptValue::Int((dscp as i32) << 2);
    if is_v6 {
        SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_TCLASS,
            value,
            call: "IPV6_TCLASS",
        }
    } else {
        SockOpt {
            level: IPPROTO_IP,
            name: IP_TOS,
            value,
            call: "IP_TOS",
        }
    }
}

/// `IP_PKTINFO` or `IPV6_PKTINFO`.
///
/// Without it a wildcard-bound socket cannot tell which of its addresses a probe
/// arrived on, which is what `docs/networking.md` §3.4's disco probe needs to
/// attribute a reflexive candidate correctly.
#[must_use]
pub const fn packet_info(is_v6: bool) -> SockOpt {
    if is_v6 {
        SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_PKTINFO,
            value: OptValue::Int(1),
            call: "IPV6_PKTINFO",
        }
    } else {
        SockOpt {
            level: IPPROTO_IP,
            name: IP_PKTINFO,
            value: OptValue::Int(1),
            call: "IP_PKTINFO",
        }
    }
}

/// `IP_UNICAST_IF` / `IPV6_UNICAST_IF`, whose byte orders differ.
///
/// **A documented Windows asymmetry, encoded once.** `IP_UNICAST_IF` takes the
/// interface index in **network** byte order; `IPV6_UNICAST_IF` takes it in
/// **host** byte order. Getting it backwards binds the socket to an interface
/// index that is almost certainly not present, so the send fails rather than
/// going out the wrong link — the safe direction, and still wrong.
#[must_use]
pub fn unicast_if(is_v6: bool, index: InterfaceIndex) -> SockOpt {
    if is_v6 {
        SockOpt {
            level: IPPROTO_IPV6,
            name: IPV6_UNICAST_IF,
            value: OptValue::Bytes(index.0.to_ne_bytes().to_vec()),
            call: "IPV6_UNICAST_IF",
        }
    } else {
        SockOpt {
            level: IPPROTO_IP,
            name: IP_UNICAST_IF,
            value: OptValue::Bytes(index.0.to_be_bytes().to_vec()),
            call: "IP_UNICAST_IF",
        }
    }
}

/// `SO_SNDBUF` and `SO_RCVBUF` are `int` on Winsock.
///
/// A request beyond `i32::MAX` is clamped rather than refused: a buffer size is
/// a hint the stack is free to round in either direction, so there is no
/// behaviour to preserve by failing, and refusing a bind over one would turn a
/// tuning value into an outage.
fn clamp_buffer(bytes: u32) -> i32 {
    i32::try_from(bytes).unwrap_or(i32::MAX)
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// The shape a `SOCKADDR_INET` carries, as plain data.
///
/// Defined here rather than imported from `windows-sys` so the conversion — the
/// part where an un-mapping can be forgotten — is testable on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSockAddr {
    /// `SOCKADDR_IN`.
    V4 {
        /// The address, in network byte order as it sits on the wire.
        octets: [u8; 4],
        /// The port, in host byte order.
        port: u16,
    },
    /// `SOCKADDR_IN6`.
    V6 {
        /// The address, in network byte order.
        octets: [u8; 16],
        /// The port, in host byte order.
        port: u16,
        /// `sin6_scope_id`. Zero means "absent", which is what makes a
        /// zoneless link-local address a rejection rather than a guess.
        scope_id: u32,
    },
}

/// The widest `sockaddr` this module renders: `SOCKADDR_IN6` is 28 bytes.
pub const SOCKADDR_MAX: usize = 28;

/// Renders an endpoint as the bytes `bind` and `sendto` take.
///
/// Returns the buffer and the length Winsock must be told, because a
/// `SOCKADDR_IN` passed with a `SOCKADDR_IN6` length is `WSAEFAULT` and a
/// `SOCKADDR_IN6` passed with a `SOCKADDR_IN` length silently loses the scope.
#[must_use]
pub fn render_sockaddr(endpoint: Endpoint) -> ([u8; SOCKADDR_MAX], i32) {
    let mut out = [0u8; SOCKADDR_MAX];
    match endpoint.address {
        IpAddr::V4(a) => {
            // `sin_family` is `AF_INET` (2) as a native-endian `u16`; the port
            // and address are network byte order.
            out[0..2].copy_from_slice(&2u16.to_ne_bytes());
            out[2..4].copy_from_slice(&endpoint.port.get().to_be_bytes());
            out[4..8].copy_from_slice(&a.octets());
            (out, 16)
        }
        IpAddr::V6(a) => {
            // `sin6_family` is `AF_INET6` (23) on Windows — **not** Linux's 10.
            out[0..2].copy_from_slice(&23u16.to_ne_bytes());
            out[2..4].copy_from_slice(&endpoint.port.get().to_be_bytes());
            // `sin6_flowinfo` stays zero: it is not a field the core carries and
            // a non-zero value there is a flow label we never negotiated.
            out[8..24].copy_from_slice(&a.octets());
            out[24..28].copy_from_slice(&a.zone().map_or(0, ZoneIndex::get).to_ne_bytes());
            (out, 28)
        }
    }
}

/// Renders the wildcard address for a family: any address, ephemeral port.
///
/// Separate from [`render_sockaddr`] because [`twinvpn_types::Port`] rejects
/// zero — correctly, since `common.proto` calls a zero port malformed — so an
/// ephemeral bind cannot be expressed as an [`Endpoint`] at all. Port zero is
/// meaningful to exactly one caller, `bind`, and this is that caller's function.
#[must_use]
pub fn render_wildcard(family: SocketFamily) -> ([u8; SOCKADDR_MAX], i32) {
    let mut out = [0u8; SOCKADDR_MAX];
    match family {
        SocketFamily::V4 => {
            out[0..2].copy_from_slice(&2u16.to_ne_bytes());
            (out, 16)
        }
        SocketFamily::V6Only | SocketFamily::V6DualStack => {
            out[0..2].copy_from_slice(&23u16.to_ne_bytes());
            (out, 28)
        }
    }
}

/// Parses the bytes `recvfrom` filled in.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on a family Winsock should not have
/// produced, or a buffer shorter than the family's own `sockaddr`. A short
/// buffer is an adapter malfunction and never something to pad: a padded address
/// matches the wrong peer.
pub fn parse_sockaddr(bytes: &[u8], call: &'static str) -> Result<RawSockAddr, PlatformError> {
    if bytes.len() < 2 {
        return Err(oserr::unavailable(call));
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        2 if bytes.len() >= 16 => Ok(RawSockAddr::V4 {
            octets: [bytes[4], bytes[5], bytes[6], bytes[7]],
            port: u16::from_be_bytes([bytes[2], bytes[3]]),
        }),
        23 if bytes.len() >= 28 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Ok(RawSockAddr::V6 {
                octets,
                port: u16::from_be_bytes([bytes[2], bytes[3]]),
                scope_id: u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            })
        }
        _ => Err(oserr::unavailable(call)),
    }
}

/// Converts an OS address to canonical form, **un-mapping** a v4-mapped v6
/// address on the way.
///
/// `twinvpn_platform::socket`'s contract: "the adapter un-maps before this
/// crosses the seam", because `V6Addr::new` rejects `::ffff:0:0/96` — accepting
/// it would let one logical address arrive under two encodings and defeat every
/// set-membership and prefix-match check that depends on a canonical form. A
/// [`SocketFamily::V6DualStack`] socket is the only way that shape arrives, and
/// it must not reach the core.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] if the address cannot be put in
/// canonical form — a link-local v6 address with no scope, principally.
pub fn address_from_raw(raw: RawSockAddr, call: &'static str) -> Result<IpAddr, PlatformError> {
    match raw {
        RawSockAddr::V4 { octets, .. } => Ok(IpAddr::V4(V4Addr::from_octets(octets))),
        RawSockAddr::V6 {
            octets, scope_id, ..
        } => {
            if let Some(v4) = unmap_v4(octets) {
                return Ok(IpAddr::V4(V4Addr::from_octets(v4)));
            }
            V6Addr::new(octets, ZoneIndex::new(scope_id))
                .map(IpAddr::V6)
                .map_err(|_| oserr::unavailable(call))
        }
    }
}

/// The `::ffff:0:0/96` un-mapping, as its own function so it is one place.
#[must_use]
pub fn unmap_v4(octets: [u8; 16]) -> Option<[u8; 4]> {
    if octets[..10].iter().all(|b| *b == 0) && octets[10] == 0xff && octets[11] == 0xff {
        Some([octets[12], octets[13], octets[14], octets[15]])
    } else {
        None
    }
}

/// Converts an OS socket address to a canonical endpoint, un-mapping as above.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] on port zero — which `common.proto`
/// calls malformed — or on a non-canonical address.
pub fn endpoint_from_raw(raw: RawSockAddr, call: &'static str) -> Result<Endpoint, PlatformError> {
    let port = match raw {
        RawSockAddr::V4 { port, .. } | RawSockAddr::V6 { port, .. } => port,
    };
    let address = address_from_raw(raw, call)?;
    let port = Port::new(port).map_err(|_| oserr::unavailable(call))?;
    Ok(Endpoint::new(address, port))
}

// ---------------------------------------------------------------------------
// The control-message walk
// ---------------------------------------------------------------------------

/// What `IP_PKTINFO` / `IPV6_PKTINFO` reported about one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PktInfo {
    /// Which of our addresses the datagram arrived on.
    pub destination: RawSockAddr,
    /// Which interface it arrived on.
    pub interface: u32,
}

/// `sizeof(WSACMSGHDR)` for a given pointer width.
///
/// `CMSGHDR` is `{ cmsg_len: SIZE_T, cmsg_level: INT, cmsg_type: INT }`, so its
/// size and alignment follow the pointer width. Parameterised rather than taken
/// from `size_of::<usize>()` so both widths are exercised on this host — a
/// 32-bit service is outside the ADR-0018 §11.9 matrix, but a walk that is only
/// correct for one width is a walk nobody has checked.
#[must_use]
pub const fn cmsg_header_len(word: usize) -> usize {
    align_up(word + 8, word)
}

const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// Walks a `WSAMSG` control buffer for the packet-info ancillary datum.
///
/// A pure function over bytes, which is the whole reason it is separate from the
/// `WSARecvMsg` that fills them: the walk is where a length check can be
/// forgotten, and this one is checked on every iteration on this host.
///
/// Returns `None` when the buffer carries no packet info — which is a normal
/// state (the caller did not ask, or the stack did not supply it) and never an
/// error.
#[must_use]
pub fn parse_pktinfo(control: &[u8], word: usize) -> Option<PktInfo> {
    let header = cmsg_header_len(word);
    let mut offset = 0usize;
    while offset + header <= control.len() {
        let len_bytes = control.get(offset..offset + word)?;
        let mut len_buf = [0u8; 8];
        len_buf[..word.min(8)].copy_from_slice(&len_bytes[..word.min(8)]);
        let cmsg_len = usize::try_from(u64::from_ne_bytes(len_buf)).ok()?;
        // A length shorter than the header, or one that runs past the buffer,
        // is a malformed control block. Stopping is the only safe answer: a walk
        // that "recovered" would be reading whatever follows in memory.
        if cmsg_len < header || offset + cmsg_len > control.len() {
            return None;
        }
        let level = i32::from_ne_bytes(
            control
                .get(offset + word..offset + word + 4)?
                .try_into()
                .ok()?,
        );
        let kind = i32::from_ne_bytes(
            control
                .get(offset + word + 4..offset + word + 8)?
                .try_into()
                .ok()?,
        );
        let data = control.get(offset + header..offset + cmsg_len)?;

        // `IN_PKTINFO` is `{ ipi_addr: IN_ADDR, ipi_ifindex: ULONG }` — 8 bytes.
        if level == IPPROTO_IP && kind == IP_PKTINFO && data.len() >= 8 {
            return Some(PktInfo {
                destination: RawSockAddr::V4 {
                    octets: [data[0], data[1], data[2], data[3]],
                    port: 0,
                },
                interface: u32::from_ne_bytes([data[4], data[5], data[6], data[7]]),
            });
        }
        // `IN6_PKTINFO` is `{ ipi6_addr: IN6_ADDR, ipi6_ifindex: ULONG }` — 20.
        if level == IPPROTO_IPV6 && kind == IPV6_PKTINFO && data.len() >= 20 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[..16]);
            let interface = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
            return Some(PktInfo {
                destination: RawSockAddr::V6 {
                    octets,
                    port: 0,
                    scope_id: interface,
                },
                interface,
            });
        }
        offset += align_up(cmsg_len, word);
    }
    None
}

// ---------------------------------------------------------------------------
// Multicast
// ---------------------------------------------------------------------------

/// The `setsockopt` calls one multicast join needs, in order.
///
/// # A platform limitation, reported rather than hidden
///
/// [`MulticastOptions::interface`] is an [`InterfaceIndex`], and the seam is
/// explicit that it is "not optional … LAN discovery's whole point is to know
/// which segment an announcement came from". Windows' `IP_ADD_MEMBERSHIP` takes
/// an `ip_mreq`, whose `imr_interface` is an **IPv4 address**, not an index —
/// so selecting the interface by index is not something the documented v4 join
/// can express. What is encoded below is the index in network byte order, which
/// Microsoft documents for `IP_MULTICAST_IF` and which the join is *believed* to
/// accept in the same form. **That belief has never been tested**, and it is a
/// finding rather than a fact. The v6 join has no such problem:
/// `IPV6_ADD_MEMBERSHIP` takes an index.
#[must_use]
pub fn render_join(options: &MulticastOptions) -> Vec<SockOpt> {
    match options.group {
        IpAddr::V4(group) => {
            let mut mreq = Vec::with_capacity(8);
            mreq.extend_from_slice(&group.octets());
            mreq.extend_from_slice(&options.interface.0.to_be_bytes());
            vec![
                SockOpt {
                    level: IPPROTO_IP,
                    name: IP_ADD_MEMBERSHIP,
                    value: OptValue::Bytes(mreq),
                    call: "IP_ADD_MEMBERSHIP",
                },
                SockOpt {
                    level: IPPROTO_IP,
                    name: IP_MULTICAST_IF,
                    value: OptValue::Bytes(options.interface.0.to_be_bytes().to_vec()),
                    call: "IP_MULTICAST_IF",
                },
                SockOpt {
                    level: IPPROTO_IP,
                    name: IP_MULTICAST_LOOP,
                    value: OptValue::Int(i32::from(options.loopback)),
                    call: "IP_MULTICAST_LOOP",
                },
                // hop_limit 1 keeps an announcement on the local segment, which
                // is what §8.2's privacy discussion assumes and what ADR-0012
                // §11.2 class 10 matches on.
                SockOpt {
                    level: IPPROTO_IP,
                    name: IP_MULTICAST_TTL,
                    value: OptValue::Int(i32::from(options.hop_limit)),
                    call: "IP_MULTICAST_TTL",
                },
            ]
        }
        IpAddr::V6(group) => {
            let mut mreq = Vec::with_capacity(20);
            mreq.extend_from_slice(&group.octets());
            mreq.extend_from_slice(&options.interface.0.to_ne_bytes());
            vec![
                SockOpt {
                    level: IPPROTO_IPV6,
                    name: IPV6_ADD_MEMBERSHIP,
                    value: OptValue::Bytes(mreq),
                    call: "IPV6_ADD_MEMBERSHIP",
                },
                SockOpt {
                    level: IPPROTO_IPV6,
                    name: IPV6_MULTICAST_IF,
                    value: OptValue::Int(i32::try_from(options.interface.0).unwrap_or(0)),
                    call: "IPV6_MULTICAST_IF",
                },
                SockOpt {
                    level: IPPROTO_IPV6,
                    name: IPV6_MULTICAST_LOOP,
                    value: OptValue::Int(i32::from(options.loopback)),
                    call: "IPV6_MULTICAST_LOOP",
                },
                SockOpt {
                    level: IPPROTO_IPV6,
                    name: IPV6_MULTICAST_HOPS,
                    value: OptValue::Int(i32::from(options.hop_limit)),
                    call: "IPV6_MULTICAST_HOPS",
                },
            ]
        }
    }
}

/// The one `setsockopt` call a multicast leave needs.
#[must_use]
pub fn render_leave(options: &MulticastOptions) -> SockOpt {
    match options.group {
        IpAddr::V4(group) => {
            let mut mreq = Vec::with_capacity(8);
            mreq.extend_from_slice(&group.octets());
            mreq.extend_from_slice(&options.interface.0.to_be_bytes());
            SockOpt {
                level: IPPROTO_IP,
                name: IP_DROP_MEMBERSHIP,
                value: OptValue::Bytes(mreq),
                call: "IP_DROP_MEMBERSHIP",
            }
        }
        IpAddr::V6(group) => {
            let mut mreq = Vec::with_capacity(20);
            mreq.extend_from_slice(&group.octets());
            mreq.extend_from_slice(&options.interface.0.to_ne_bytes());
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_DROP_MEMBERSHIP,
                value: OptValue::Bytes(mreq),
                call: "IPV6_DROP_MEMBERSHIP",
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------

/// Which socket shapes a Windows host offers.
///
/// **Declared rather than probed, and the reason is stated.** `dual_stack_socket`
/// follows `v6`: every Windows version in ADR-0018 §11.9's support matrix lets
/// `IPV6_V6ONLY` be cleared on an `AF_INET6` datagram socket, so a host that can
/// open a v6 socket can open a dual-stack one. The residual — a host where a
/// policy has disabled the v4-mapped path — would report `true` here and fail at
/// `setsockopt`, which surfaces as `PLATFORM.OS_UNSUPPORTED` at bind rather than
/// as a silently v6-only session.
#[must_use]
pub const fn families_from_probe(v4: bool, v6: bool) -> SupportedFamilies {
    SupportedFamilies {
        v4,
        v6,
        dual_stack_socket: v6,
    }
}

/// Opens Windows UDP sockets.
pub struct WindowsSocketProvider {
    shutdown: ShutdownLatch,
}

impl WindowsSocketProvider {
    /// Binds the provider to the adapter's shutdown latch.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }
}

impl SocketProvider for WindowsSocketProvider {
    /// **Windows has neither**, and this adapter substitutes nothing for either.
    ///
    /// - `SO_REUSEPORT`: no equivalent. `SO_REUSEADDR` is **not** one, because it
    ///   lets a *different process* bind the identical address and port and take
    ///   over delivery — a security difference, not a spelling one. So
    ///   `docs/networking.md` §3.6's gathering strategy needs a Windows-specific
    ///   answer that is not in the corpus, and this is where the core learns it
    ///   must find one rather than discovering it at the first refused bind.
    /// - `SO_MARK`: no routing mark exists. KS-9(1)'s predicate here is app-id
    ///   plus SID (ADR-0012 KS-9b), which is a different mechanism satisfying the
    ///   same rule at process granularity.
    ///
    /// `bind_udp` below still refuses either option by name if one is set — the
    /// capability is the advance notice, not a replacement for the refusal.
    fn socket_capabilities(&self) -> SocketCapabilities {
        SocketCapabilities {
            reuse_port: false,
            firewall_mark: false,
        }
    }

    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let programme = render_options(spec.family, &spec.options);
            // An option Windows cannot supply is a **fact about the host**,
            // reported so the core can decide — exactly as an unsupported family
            // is. Applying the rest and continuing would be the silent
            // degradation `SocketOptions` names: "a NAT ladder that behaves
            // differently from the one that was tested".
            if let Some(missing) = programme.unsupported.first() {
                return Err(PlatformError::OsUnsupported(Some(
                    twinvpn_platform::OsDetail {
                        code: i64::from(oserr::WSAENOPROTOOPT),
                        call: missing.as_str(),
                    },
                )));
            }
            imp::bind(spec, &programme, self.shutdown.clone()).await
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(imp::probe_families())
        })
    }
}

/// Whether a socket that has been closed may still be used.
///
/// It may not, and the answer is a named condition rather than a Winsock error:
/// a closed socket is a state the caller asked for.
fn closed(call: &'static str) -> PlatformError {
    oserr::from_status(
        Win32Error(oserr::ERROR_INVALID_HANDLE),
        call,
        Context::Socket,
    )
}

#[cfg(windows)]
mod imp;

#[cfg(not(windows))]
mod imp {
    //! The non-Windows stand-in.
    //!
    //! This adapter opens no socket on a host that is not Windows, and says so
    //! by name rather than by panicking or by returning something that looks
    //! like a socket. It exists so the target-free layers above — the option
    //! programme, the address conversions, the control-message walk — compile
    //! and run their tests on the Linux host this crate was written on.

    use super::{families_from_probe, OptionProgramme};
    use crate::shutdown::ShutdownLatch;
    use futures_core::future::BoxFuture;
    use twinvpn_platform::{PlatformError, SupportedFamilies, UdpBindSpec, UdpSocket};

    pub(super) fn probe_families() -> SupportedFamilies {
        families_from_probe(false, false)
    }

    pub(super) fn bind<'a>(
        _spec: &'a UdpBindSpec,
        _programme: &'a OptionProgramme,
        _shutdown: ShutdownLatch,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            Err(crate::oserr::from_status(
                crate::oserr::Win32Error(crate::oserr::ERROR_NOT_SUPPORTED),
                "WSASocketW",
                crate::oserr::Context::Socket,
            ))
        })
    }
}

/// A bound Windows UDP socket, as the seam sees it.
///
/// The concrete type lives in `imp` because it holds a `SOCKET`; what is here
/// is the shutdown latch and the closed flag, which are the two facts the trait
/// contract turns on and which are the same on every target.
#[derive(Debug)]
pub struct SocketState {
    family: SocketFamily,
    /// Whether `IP_PKTINFO` / `IPV6_PKTINFO` was requested at open.
    ///
    /// Recorded so [`Datagram::destination`] is `None` because the caller did
    /// not ask, never because the control-message walk quietly found nothing.
    want_pktinfo: bool,
    closed: AtomicBool,
    shutdown: ShutdownLatch,
}

impl SocketState {
    /// Records what one socket was opened with.
    #[must_use]
    pub const fn new(family: SocketFamily, want_pktinfo: bool, shutdown: ShutdownLatch) -> Self {
        Self {
            family,
            want_pktinfo,
            closed: AtomicBool::new(false),
            shutdown,
        }
    }

    /// The socket's family.
    #[must_use]
    pub const fn family(&self) -> SocketFamily {
        self.family
    }

    /// Whether packet info was asked for at open.
    #[must_use]
    pub const fn want_pktinfo(&self) -> bool {
        self.want_pktinfo
    }

    /// The guard every fallible call starts with.
    ///
    /// # Errors
    ///
    /// [`PlatformError::ShuttingDown`] once the adapter has begun shutting down,
    /// and the closed condition once [`Self::close`] has run.
    pub fn check(&self, call: &'static str) -> Result<(), PlatformError> {
        self.shutdown.check()?;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed(call));
        }
        Ok(())
    }

    /// Marks the socket closed. Returns whether this call was the one that did
    /// it, so the caller can make `close` idempotent without a second flag.
    pub fn close(&self) -> bool {
        !self.closed.swap(true, Ordering::AcqRel)
    }
}

/// Builds the `Datagram` the seam receives.
///
/// Separate from the receive so the assembly — where a truncation flag or an
/// un-mapping can be dropped — is testable on this host.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] if the peer address is not canonical.
pub fn assemble_datagram(
    len: usize,
    source: RawSockAddr,
    pktinfo: Option<PktInfo>,
    truncated: bool,
    call: &'static str,
) -> Result<Datagram, PlatformError> {
    let source = endpoint_from_raw(source, call)?;
    // A destination that will not canonicalise is dropped rather than reported
    // wrong: `Datagram::destination` is an `Option`, and a wrong address there
    // would attribute a reflexive candidate to the wrong local interface.
    let destination = pktinfo.and_then(|p| address_from_raw(p.destination, call).ok());
    Ok(Datagram {
        len,
        source,
        destination,
        interface: pktinfo.map(|p| InterfaceIndex(p.interface)),
        // **Reported, never silent.** A silently truncated datagram is a message
        // that fails authentication for a reason nobody can see.
        truncated,
    })
}

/// The Winsock numbers this module hard-codes, checked against `windows-sys`.
///
/// A drifted number configures the wrong option, which on `IPV6_V6ONLY` is a v6
/// socket silently accepting v4-mapped traffic. Asserting it at compile time
/// means `make cross-check` catches it rather than a user.
#[cfg(windows)]
mod win_constants {
    use windows_sys::Win32::Networking::WinSock as ws;

    const _: () = {
        assert!(super::SOL_SOCKET == ws::SOL_SOCKET);
        assert!(super::IPPROTO_IP == ws::IPPROTO_IP);
        assert!(super::IPPROTO_IPV6 == ws::IPPROTO_IPV6);
        assert!(super::SO_REUSEADDR == ws::SO_REUSEADDR);
        assert!(super::SO_SNDBUF == ws::SO_SNDBUF);
        assert!(super::SO_RCVBUF == ws::SO_RCVBUF);
        assert!(super::IP_TOS == ws::IP_TOS);
        assert!(super::IP_TTL == ws::IP_TTL);
        assert!(super::IP_MULTICAST_IF == ws::IP_MULTICAST_IF);
        assert!(super::IP_MULTICAST_TTL == ws::IP_MULTICAST_TTL);
        assert!(super::IP_MULTICAST_LOOP == ws::IP_MULTICAST_LOOP);
        assert!(super::IP_ADD_MEMBERSHIP == ws::IP_ADD_MEMBERSHIP);
        assert!(super::IP_DROP_MEMBERSHIP == ws::IP_DROP_MEMBERSHIP);
        assert!(super::IP_DONTFRAGMENT == ws::IP_DONTFRAGMENT);
        assert!(super::IP_PKTINFO == ws::IP_PKTINFO);
        assert!(super::IP_UNICAST_IF == ws::IP_UNICAST_IF);
        assert!(super::IPV6_UNICAST_HOPS == ws::IPV6_UNICAST_HOPS);
        assert!(super::IPV6_MULTICAST_IF == ws::IPV6_MULTICAST_IF);
        assert!(super::IPV6_MULTICAST_HOPS == ws::IPV6_MULTICAST_HOPS);
        assert!(super::IPV6_MULTICAST_LOOP == ws::IPV6_MULTICAST_LOOP);
        assert!(super::IPV6_ADD_MEMBERSHIP == ws::IPV6_ADD_MEMBERSHIP);
        assert!(super::IPV6_DROP_MEMBERSHIP == ws::IPV6_DROP_MEMBERSHIP);
        assert!(super::IPV6_DONTFRAG == ws::IPV6_DONTFRAG);
        assert!(super::IPV6_PKTINFO == ws::IPV6_PKTINFO);
        assert!(super::IPV6_V6ONLY == ws::IPV6_V6ONLY);
        assert!(super::IPV6_UNICAST_IF == ws::IPV6_UNICAST_IF);
        assert!(super::IPV6_TCLASS == ws::IPV6_TCLASS);
        // `AF_INET` and `AF_INET6` are 2 and 23 on Windows — the second is
        // Linux's 10, and `render_sockaddr` writes 23.
        assert!(ws::AF_INET == 2);
        assert!(ws::AF_INET6 == 23);
        // The control-message header this module walks by hand.
        assert!(
            super::cmsg_header_len(core::mem::size_of::<usize>())
                == core::mem::size_of::<ws::CMSGHDR>()
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(text: &str) -> [u8; 16] {
        text.parse::<std::net::Ipv6Addr>()
            .expect("literal")
            .octets()
    }

    fn defaults() -> SocketOptions {
        SocketOptions::default()
    }

    #[test]
    fn a_v6_only_socket_sets_v6only_and_a_dual_stack_socket_clears_it() {
        // The two are different VALUES rather than a flag precisely because
        // "we forgot to set it" is how a v6 socket silently starts accepting
        // v4-mapped traffic that `common.proto` rejects everywhere else.
        let only = render_options(SocketFamily::V6Only, &defaults());
        assert_eq!(
            only.calls[0],
            SockOpt {
                level: IPPROTO_IPV6,
                name: IPV6_V6ONLY,
                value: OptValue::Int(1),
                call: "IPV6_V6ONLY",
            }
        );
        let dual = render_options(SocketFamily::V6DualStack, &defaults());
        assert_eq!(dual.calls[0].value, OptValue::Int(0));
        // ...and a v4 socket never mentions it at all.
        let v4 = render_options(SocketFamily::V4, &defaults());
        assert!(!v4.calls.iter().any(|c| c.name == IPV6_V6ONLY));
    }

    #[test]
    fn v6only_is_set_before_anything_else_because_bind_freezes_it() {
        for family in [SocketFamily::V6Only, SocketFamily::V6DualStack] {
            let mut options = defaults();
            options.reuse_address = true;
            options.hop_limit = Some(64);
            let programme = render_options(family, &options);
            assert_eq!(programme.calls[0].name, IPV6_V6ONLY, "{family:?}");
        }
    }

    #[test]
    fn every_family_picks_its_own_option_name_and_never_the_other_familys() {
        let mut options = defaults();
        options.hop_limit = Some(32);
        options.dscp = Some(46);
        let v4 = render_options(SocketFamily::V4, &options);
        let names: Vec<i32> = v4.calls.iter().map(|c| c.name).collect();
        assert!(names.contains(&IP_TTL) && names.contains(&IP_TOS));
        assert!(names.contains(&IP_DONTFRAGMENT) && names.contains(&IP_PKTINFO));
        assert!(v4.calls.iter().all(|c| c.level != IPPROTO_IPV6));

        let v6 = render_options(SocketFamily::V6Only, &options);
        let names: Vec<i32> = v6.calls.iter().map(|c| c.name).collect();
        assert!(names.contains(&IPV6_UNICAST_HOPS) && names.contains(&IPV6_TCLASS));
        assert!(names.contains(&IPV6_DONTFRAG) && names.contains(&IPV6_PKTINFO));
        assert!(v6.calls.iter().all(|c| c.level != IPPROTO_IP));
    }

    #[test]
    fn the_gathering_default_sets_df_and_packet_info_and_nothing_else() {
        // `SocketOptions::default` is documented as the gathering default: DF
        // set for DPLPMTUD, packet info on so a reflexive candidate can be
        // attributed, everything else left to the platform.
        let programme = render_options(SocketFamily::V4, &defaults());
        assert!(programme.unsupported.is_empty());
        let names: Vec<i32> = programme.calls.iter().map(|c| c.name).collect();
        assert_eq!(names, vec![IP_DONTFRAGMENT, IP_PKTINFO]);
    }

    #[test]
    fn so_reuseport_is_named_as_unsupported_and_never_silently_dropped() {
        let mut options = defaults();
        options.reuse_port = true;
        let programme = render_options(SocketFamily::V4, &options);
        assert_eq!(programme.unsupported, vec![Unsupported::ReusePort]);
        assert_eq!(Unsupported::ReusePort.as_str(), "SO_REUSEPORT");
        // And nothing was substituted for it: `SO_REUSEADDR` on Windows has
        // different semantics and is NOT an equivalent.
        assert!(!programme.calls.iter().any(|c| c.name == SO_REUSEADDR));
    }

    #[test]
    fn a_firewall_mark_is_named_as_unsupported_because_windows_has_no_socket_mark() {
        let mut options = defaults();
        options.firewall_mark = Some(0x7677);
        let programme = render_options(SocketFamily::V6Only, &options);
        assert_eq!(programme.unsupported, vec![Unsupported::FirewallMark]);
        assert_eq!(Unsupported::FirewallMark.as_str(), "SO_MARK");
    }

    #[test]
    fn the_unicast_if_byte_order_differs_between_the_families() {
        // A documented Windows asymmetry: `IP_UNICAST_IF` is network byte order
        // and `IPV6_UNICAST_IF` is host byte order. Getting it backwards binds
        // to an index that is almost certainly absent.
        let index = InterfaceIndex(0x0000_0007);
        assert_eq!(
            unicast_if(false, index).value,
            OptValue::Bytes(vec![0, 0, 0, 7]),
            "IP_UNICAST_IF is big-endian"
        );
        assert_eq!(
            unicast_if(true, index).value,
            OptValue::Bytes(0x0000_0007u32.to_ne_bytes().to_vec()),
            "IPV6_UNICAST_IF is native"
        );
    }

    #[test]
    fn the_dscp_code_point_is_shifted_into_the_tos_octet_at_the_seam() {
        // The seam carries the code point; the wire field is the whole octet.
        // Doing the shift in the core would be a platform fact above the adapter.
        let mut options = defaults();
        options.dscp = Some(46); // EF
        let programme = render_options(SocketFamily::V4, &options);
        let tos = programme
            .calls
            .iter()
            .find(|c| c.name == IP_TOS)
            .expect("set");
        assert_eq!(tos.value, OptValue::Int(46 << 2));
    }

    #[test]
    fn a_buffer_request_beyond_an_int_is_clamped_rather_than_refusing_the_bind() {
        let mut options = defaults();
        options.send_buffer_bytes = Some(u32::MAX);
        let programme = render_options(SocketFamily::V4, &options);
        let snd = programme
            .calls
            .iter()
            .find(|c| c.name == SO_SNDBUF)
            .expect("set");
        assert_eq!(snd.value, OptValue::Int(i32::MAX));
        assert!(programme.unsupported.is_empty(), "a hint is not a refusal");
    }

    #[test]
    fn a_v4_mapped_source_is_unmapped_before_it_crosses_the_seam() {
        // ::ffff:192.0.2.1 — what a V6DualStack socket receives for a v4 peer.
        let raw = RawSockAddr::V6 {
            octets: v6("::ffff:192.0.2.1"),
            port: 51820,
            scope_id: 0,
        };
        let endpoint = endpoint_from_raw(raw, "WSARecvMsg").expect("un-maps");
        assert_eq!(endpoint.address.family(), twinvpn_types::AddressFamily::V4);
        assert_eq!(endpoint.address.octets(), vec![192, 0, 2, 1]);
        assert_eq!(endpoint.port.get(), 51820);
    }

    #[test]
    fn a_link_local_source_keeps_its_zone_and_a_zoneless_one_is_refused() {
        let zoned = RawSockAddr::V6 {
            octets: v6("fe80::1"),
            port: 1234,
            scope_id: 7,
        };
        let endpoint = endpoint_from_raw(zoned, "WSARecvMsg").expect("canonical");
        match endpoint.address {
            IpAddr::V6(a) => assert_eq!(a.zone().map(ZoneIndex::get), Some(7)),
            IpAddr::V4(_) => panic!("a link-local v6 address must stay v6"),
        }

        let zoneless = RawSockAddr::V6 {
            octets: v6("fe80::1"),
            port: 1234,
            scope_id: 0,
        };
        let err = endpoint_from_raw(zoneless, "WSARecvMsg").expect_err("refused");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(err.os_detail().map(|d| d.call), Some("WSARecvMsg"));
    }

    #[test]
    fn port_zero_is_malformed_and_is_reported_by_name() {
        let raw = RawSockAddr::V4 {
            octets: [192, 0, 2, 1],
            port: 0,
        };
        let err = endpoint_from_raw(raw, "recvfrom").expect_err("port 0 is malformed");
        assert_eq!(err.os_detail().map(|d| d.call), Some("recvfrom"));
    }

    #[test]
    fn a_sockaddr_round_trips_in_both_families_with_the_windows_family_numbers() {
        for (address, port, scope) in [
            (
                IpAddr::V4(V4Addr::from_octets([192, 0, 2, 1])),
                443u16,
                0u32,
            ),
            (
                IpAddr::V6(V6Addr::new(v6("2001:db8::1"), None).expect("literal")),
                51820,
                0,
            ),
            (
                IpAddr::V6(V6Addr::new(v6("fe80::1"), ZoneIndex::new(9)).expect("literal")),
                5353,
                9,
            ),
        ] {
            let endpoint = Endpoint::new(address, Port::new(port).expect("port"));
            let (bytes, len) = render_sockaddr(endpoint);
            let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
            assert_eq!(
                family,
                if address.family() == twinvpn_types::AddressFamily::V4 {
                    2
                } else {
                    23
                },
                "AF_INET6 is 23 on Windows, not Linux's 10"
            );
            let parsed = parse_sockaddr(&bytes[..usize::try_from(len).expect("len")], "test")
                .expect("parses");
            assert_eq!(
                endpoint_from_raw(parsed, "test").expect("canonical"),
                endpoint
            );
            if let RawSockAddr::V6 { scope_id, .. } = parsed {
                assert_eq!(scope_id, scope);
            }
        }
    }

    #[test]
    fn a_short_or_unknown_sockaddr_is_a_typed_reject_and_never_padded() {
        // A padded address matches the wrong peer.
        assert!(parse_sockaddr(&[], "test").is_err());
        assert!(
            parse_sockaddr(&[2, 0], "test").is_err(),
            "AF_INET, too short"
        );
        assert!(
            parse_sockaddr(&[23, 0, 0, 0, 0, 0, 0, 0], "test").is_err(),
            "AF_INET6, too short"
        );
        let mut linux_af_inet6 = [0u8; 28];
        linux_af_inet6[0] = 10;
        assert!(
            parse_sockaddr(&linux_af_inet6, "test").is_err(),
            "10 is Linux's AF_INET6 and is not a family Winsock produces"
        );
    }

    /// Builds a control buffer the way the stack does, for the walk to read.
    fn cmsg(word: usize, level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
        let header = cmsg_header_len(word);
        let len = header + data.len();
        let mut out = vec![0u8; align_up(len, word)];
        out[..word].copy_from_slice(&(len as u64).to_ne_bytes()[..word]);
        out[word..word + 4].copy_from_slice(&level.to_ne_bytes());
        out[word + 4..word + 8].copy_from_slice(&kind.to_ne_bytes());
        out[header..header + data.len()].copy_from_slice(data);
        out
    }

    #[test]
    fn the_control_walk_finds_packet_info_at_both_pointer_widths() {
        for word in [4usize, 8] {
            let mut data = Vec::new();
            data.extend_from_slice(&[10, 0, 0, 5]);
            data.extend_from_slice(&11u32.to_ne_bytes());
            let control = cmsg(word, IPPROTO_IP, IP_PKTINFO, &data);
            let info = parse_pktinfo(&control, word).expect("found");
            assert_eq!(info.interface, 11);
            assert_eq!(
                info.destination,
                RawSockAddr::V4 {
                    octets: [10, 0, 0, 5],
                    port: 0
                }
            );
        }
    }

    #[test]
    fn the_control_walk_skips_an_unrelated_datum_and_finds_the_v6_one_after_it() {
        let word = 8usize;
        let mut control = cmsg(word, IPPROTO_IP, 1, &[0u8; 4]);
        let mut data = Vec::new();
        data.extend_from_slice(&v6("2001:db8::5"));
        data.extend_from_slice(&23u32.to_ne_bytes());
        control.extend_from_slice(&cmsg(word, IPPROTO_IPV6, IPV6_PKTINFO, &data));
        let info = parse_pktinfo(&control, word).expect("found");
        assert_eq!(info.interface, 23);
        assert_eq!(
            info.destination,
            RawSockAddr::V6 {
                octets: v6("2001:db8::5"),
                port: 0,
                scope_id: 23
            }
        );
    }

    #[test]
    fn a_malformed_control_block_stops_the_walk_rather_than_reading_past_it() {
        let word = 8usize;
        // A cmsg_len shorter than the header, and one that runs past the end.
        for bogus in [0u64, 4, 1 << 20] {
            let mut control = vec![0u8; 32];
            control[..word].copy_from_slice(&bogus.to_ne_bytes()[..word]);
            control[word..word + 4].copy_from_slice(&IPPROTO_IP.to_ne_bytes());
            control[word + 4..word + 8].copy_from_slice(&IP_PKTINFO.to_ne_bytes());
            assert_eq!(parse_pktinfo(&control, word), None, "{bogus}");
        }
        // An empty buffer, and one shorter than a header.
        assert_eq!(parse_pktinfo(&[], word), None);
        assert_eq!(parse_pktinfo(&[0u8; 8], word), None);
    }

    #[test]
    fn a_truncated_packet_info_datum_is_ignored_rather_than_half_read() {
        let word = 8usize;
        // `IN6_PKTINFO` is 20 bytes; supply 16 and the walk must not invent an
        // interface index out of whatever follows.
        let control = cmsg(word, IPPROTO_IPV6, IPV6_PKTINFO, &v6("2001:db8::5"));
        assert_eq!(parse_pktinfo(&control, word), None);
    }

    #[test]
    fn the_datagram_reports_truncation_and_never_swallows_it() {
        // A silently truncated datagram is a message that fails authentication
        // for a reason nobody can see.
        let source = RawSockAddr::V4 {
            octets: [192, 0, 2, 9],
            port: 51820,
        };
        let datagram = assemble_datagram(1200, source, None, true, "WSARecvMsg").expect("built");
        assert!(datagram.truncated);
        assert_eq!(datagram.len, 1200);
        assert_eq!(datagram.destination, None, "the caller did not ask");
        assert_eq!(datagram.interface, None);
    }

    #[test]
    fn a_datagram_carries_the_arrival_interface_when_packet_info_was_asked_for() {
        let source = RawSockAddr::V4 {
            octets: [192, 0, 2, 9],
            port: 51820,
        };
        let info = PktInfo {
            destination: RawSockAddr::V4 {
                octets: [10, 0, 0, 5],
                port: 0,
            },
            interface: 11,
        };
        let datagram =
            assemble_datagram(64, source, Some(info), false, "WSARecvMsg").expect("built");
        assert_eq!(datagram.interface, Some(InterfaceIndex(11)));
        assert_eq!(
            datagram.destination,
            Some(IpAddr::V4(V4Addr::from_octets([10, 0, 0, 5])))
        );
    }

    #[test]
    fn a_multicast_join_names_its_interface_in_every_call_it_makes() {
        // The seam: the interface is "not optional … LAN discovery's whole point
        // is to know which segment an announcement came from".
        let v4 = MulticastOptions {
            group: IpAddr::V4(V4Addr::from_octets([239, 255, 0, 1])),
            interface: InterfaceIndex(7),
            loopback: false,
            hop_limit: 1,
        };
        let calls = render_join(&v4);
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].name, IP_ADD_MEMBERSHIP);
        assert_eq!(
            calls[0].value,
            OptValue::Bytes(vec![239, 255, 0, 1, 0, 0, 0, 7])
        );
        assert_eq!(
            calls[1].value,
            OptValue::Bytes(vec![0, 0, 0, 7]),
            "IP_MULTICAST_IF takes the index in network byte order"
        );
        // hop_limit 1 keeps the announcement on the local segment.
        assert_eq!(calls[3].value, OptValue::Int(1));
    }

    #[test]
    fn a_v6_multicast_join_uses_the_index_directly_because_ipv6_takes_one() {
        let v6opts = MulticastOptions {
            group: IpAddr::V6(V6Addr::new(v6("ff02::fb"), None).expect("literal")),
            interface: InterfaceIndex(7),
            loopback: true,
            hop_limit: 1,
        };
        let calls = render_join(&v6opts);
        assert_eq!(calls[0].name, IPV6_ADD_MEMBERSHIP);
        match &calls[0].value {
            OptValue::Bytes(b) => {
                assert_eq!(b.len(), 20);
                assert_eq!(&b[..16], &v6("ff02::fb"));
                assert_eq!(&b[16..], &7u32.to_ne_bytes());
            }
            OptValue::Int(_) => panic!("an ipv6_mreq is a struct"),
        }
        assert_eq!(calls[1].value, OptValue::Int(7));
        assert_eq!(calls[2].value, OptValue::Int(1), "loopback was requested");
    }

    #[test]
    fn a_leave_names_the_same_group_and_interface_the_join_did() {
        for group in [
            IpAddr::V4(V4Addr::from_octets([239, 255, 0, 1])),
            IpAddr::V6(V6Addr::new(v6("ff02::fb"), None).expect("literal")),
        ] {
            let options = MulticastOptions {
                group,
                interface: InterfaceIndex(7),
                loopback: false,
                hop_limit: 1,
            };
            let join = render_join(&options);
            let leave = render_leave(&options);
            assert_eq!(leave.level, join[0].level);
            assert_eq!(leave.value, join[0].value, "same group, same interface");
            assert_ne!(leave.name, join[0].name);
        }
    }

    #[test]
    fn dual_stack_is_reported_from_the_v6_probe_and_never_independently_guessed() {
        assert_eq!(
            families_from_probe(true, true),
            SupportedFamilies {
                v4: true,
                v6: true,
                dual_stack_socket: true
            }
        );
        // A host with no v6 stack has no dual-stack socket either, which is a
        // different answer from "this host has no dual-stack sockets".
        assert_eq!(
            families_from_probe(true, false),
            SupportedFamilies {
                v4: true,
                v6: false,
                dual_stack_socket: false
            }
        );
    }

    #[test]
    fn a_closed_socket_reports_a_named_condition_and_close_is_idempotent() {
        let state = SocketState::new(SocketFamily::V4, true, ShutdownLatch::new());
        state.check("WSARecvMsg").expect("open");
        assert!(state.close(), "the first close is the one that closed it");
        assert!(!state.close(), "and the second changes nothing");
        let err = state.check("WSARecvMsg").expect_err("closed");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }

    #[test]
    fn a_shutting_down_adapter_refuses_before_it_looks_at_the_socket() {
        let latch = ShutdownLatch::new();
        let state = SocketState::new(SocketFamily::V4, false, latch.clone());
        latch.begin();
        assert!(matches!(
            state.check("sendto").expect_err("shutting down"),
            PlatformError::ShuttingDown
        ));
        assert!(!state.want_pktinfo());
        assert_eq!(state.family(), SocketFamily::V4);
    }
}
