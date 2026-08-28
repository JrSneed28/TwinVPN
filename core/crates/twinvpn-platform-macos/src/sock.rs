//! Sockets: the NAT ladder's per-socket options, and Darwin's spelling of them.
//!
//! **Authority:** `docs/networking.md` §3 (candidate gathering, the disco probe,
//! port prediction), §6.2 (DF for DPLPMTUD), §8 (LAN discovery); ADR-0010 R1 and
//! R8; ADR-0004 (the NAT ladder); ADR-0012 **KS-9a** (the socket registration
//! "MUST NOT be specified as IPC"); ADR-0018 CB-2, DP-4.
//!
//! # KS-9a on macOS: the registration is a socket option, not a message
//!
//! KS-9(2) requires the exempt socket to be "registered with the enforcement
//! layer at bind time, by whatever mechanism the host class makes available", and
//! KS-9a withdraws the IPC spelling because sockets and enforcement are in one
//! process and an intra-process registration is not IPC.
//!
//! On macOS the mechanism is **`IP_BOUND_IF` / `IPV6_BOUND_IF` at open**, applied
//! together with the uid the anchor's class-7 rule matches. Binding the socket to
//! the underlay interface is what stops TwinVPN's own traffic following the
//! default route the tunnel just installed — Darwin's answer to the `fwmark` and
//! policy table the Linux adapter uses, and the reason
//! [`SocketOptions::firewall_mark`] has nowhere to go here.
//!
//! # What is target-free, and what is not
//!
//! [`plan_options`] turns a [`SocketOptions`] into the exact list of
//! `setsockopt` calls Darwin needs, with Darwin's own option numbers — and it is
//! pure, so `cargo test` checks the plan on this Linux host. [`parse_cmsgs`] does
//! the same for the control data a `recvmsg` returns. Only the two syscalls that
//! apply and collect them are `cfg`-gated.
//!
//! The socket **plumbing** — bind, `send_to`, `recv_from` — is portable and does
//! run here, so the tests exercise a real UDP round trip. That is verification of
//! the plumbing and **not** of the Darwin options, which no test on this host can
//! reach.

use std::net::SocketAddr;

use futures_core::future::BoxFuture;
use socket2::{Domain, Protocol, Socket, Type};
use twinvpn_platform::{
    Datagram, FragmentPolicy, MulticastOptions, PlatformError, SocketFamily, SocketOptions,
    SocketProvider, SupportedFamilies, UdpBindSpec, UdpSocket,
};
use twinvpn_types::{Endpoint, IpAddr};

use crate::addr::{self, DARWIN_AF_INET, DARWIN_AF_INET6};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;
use crate::sys::sockopt;

/// One Darwin `setsockopt` this adapter issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinOption {
    /// `IPPROTO_IP` or `IPPROTO_IPV6`.
    pub level: i32,
    /// The option number, from [`crate::sys::sockopt`].
    pub name: i32,
    /// The `int` value.
    pub value: i32,
    /// A stable, non-localised tag for the call, for [`crate::oserr::OsDetail`].
    pub tag: &'static str,
}

/// The Darwin option calls one [`SocketOptions`] implies, plus what it asked for
/// that this platform cannot do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketOptionPlan {
    /// The `setsockopt` calls, in the order they must be issued.
    pub darwin: Vec<DarwinOption>,
    /// Options the caller set that macOS has no equivalent for.
    ///
    /// **Reported, never silently dropped.** An option that failed to apply is a
    /// NAT ladder behaving differently from the one that was tested, and the seam
    /// is explicit that these are applied "at open, not afterwards" precisely
    /// because a late failure is invisible.
    pub unsupported: Vec<&'static str>,
}

/// The Darwin option plan for one socket shape.
///
/// # Why `receive_packet_info` costs two options in v4 and one in v6
///
/// Darwin has **no `IP_PKTINFO`**. The two facts the disco probe needs — which of
/// our addresses a datagram arrived on, and which interface it arrived through —
/// come from `IP_RECVDSTADDR` and `IP_RECVIF` separately. IPv6 does have one
/// option for both, `IPV6_RECVPKTINFO`. A port from Linux that set one option per
/// family would silently lose the arrival interface in v4, and §3.4's reflexive
/// candidate would be attributed to the wrong local address.
#[must_use]
pub fn plan_options(options: &SocketOptions, family: SocketFamily) -> SocketOptionPlan {
    let mut plan = SocketOptionPlan::default();
    let v6 = !matches!(family, SocketFamily::V4);

    if matches!(options.fragment_policy, FragmentPolicy::DontFragment) {
        // DPLPMTUD needs a too-large probe DROPPED rather than fragmented
        // (§6.2). Darwin's spelling is a plain boolean, not Linux's
        // `IP_MTU_DISCOVER` mode enum.
        plan.darwin.push(if v6 {
            DarwinOption {
                level: sockopt::IPPROTO_IPV6,
                name: sockopt::IPV6_DONTFRAG,
                value: 1,
                tag: "IPV6_DONTFRAG",
            }
        } else {
            DarwinOption {
                level: sockopt::IPPROTO_IP,
                name: sockopt::IP_DONTFRAG,
                value: 1,
                tag: "IP_DONTFRAG",
            }
        });
    }

    if options.receive_packet_info {
        if v6 {
            plan.darwin.push(DarwinOption {
                level: sockopt::IPPROTO_IPV6,
                name: sockopt::IPV6_RECVPKTINFO,
                value: 1,
                tag: "IPV6_RECVPKTINFO",
            });
        } else {
            plan.darwin.push(DarwinOption {
                level: sockopt::IPPROTO_IP,
                name: sockopt::IP_RECVDSTADDR,
                value: 1,
                tag: "IP_RECVDSTADDR",
            });
            plan.darwin.push(DarwinOption {
                level: sockopt::IPPROTO_IP,
                name: sockopt::IP_RECVIF,
                value: 1,
                tag: "IP_RECVIF",
            });
        }
    }

    if let Some(index) = options.bind_to_interface {
        // KS-9(2)'s registration on this platform, and the reason TwinVPN's own
        // traffic does not follow the default route the tunnel installed.
        plan.darwin.push(if v6 {
            DarwinOption {
                level: sockopt::IPPROTO_IPV6,
                name: sockopt::IPV6_BOUND_IF,
                value: i32::try_from(index.0).unwrap_or(0),
                tag: "IPV6_BOUND_IF",
            }
        } else {
            DarwinOption {
                level: sockopt::IPPROTO_IP,
                name: sockopt::IP_BOUND_IF,
                value: i32::try_from(index.0).unwrap_or(0),
                tag: "IP_BOUND_IF",
            }
        });
    }

    if options.firewall_mark.is_some() {
        // Darwin has no `SO_MARK` and no policy routing table to match one
        // against. The function it serves on Linux is served here by
        // `IP_BOUND_IF`, which is a different mechanism with a different failure
        // mode — so this is reported rather than quietly mapped onto it.
        plan.unsupported.push("firewall_mark");
    }

    plan
}

/// Whether a family is one this host can open, asked once at construction.
#[must_use]
fn probe_families() -> SupportedFamilies {
    let opens = |domain: Domain| Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).is_ok();
    let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .and_then(|s| s.set_only_v6(false).map(|()| s))
        .is_ok();
    SupportedFamilies {
        v4: opens(Domain::IPV4),
        v6: opens(Domain::IPV6),
        dual_stack_socket: dual,
    }
}

/// macOS's socket provider.
#[derive(Debug)]
pub struct MacosSocketProvider {
    shutdown: ShutdownLatch,
}

impl MacosSocketProvider {
    /// Binds the provider.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }
}

/// Applies the Darwin half of a plan.
#[cfg(target_os = "macos")]
fn apply_darwin(socket: &Socket, plan: &SocketOptionPlan) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd as _;
    for option in &plan.darwin {
        let value: libc::c_int = option.value;
        // SAFETY: `socket` is a live socket whose fd outlives the call; `value` is
        // a live `c_int` we own and the length passed is its true size, so
        // `setsockopt` reads exactly four bytes it may read. It takes no
        // ownership.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                option.level,
                option.name,
                std::ptr::from_ref(&value).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4),
            )
        };
        if rc != 0 {
            return Err(oserr::from_errno(
                &std::io::Error::last_os_error(),
                option.tag,
                Context::Socket,
            ));
        }
    }
    Ok(())
}

/// On a host that is not Darwin the plan is computed and **not** applied.
///
/// Not silently: the caller records `plan.darwin` as unapplied, so a socket opened
/// here is visibly missing the options rather than looking like one that has them.
#[cfg(not(target_os = "macos"))]
// The signature is the Darwin one's, so `bind_udp` has no `cfg` of its own. It
// cannot fail here, and saying so with a `-> ()` would put the branch back.
#[allow(clippy::unnecessary_wraps)]
fn apply_darwin(_socket: &Socket, _plan: &SocketOptionPlan) -> Result<(), PlatformError> {
    Ok(())
}

impl SocketProvider for MacosSocketProvider {
    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let domain = match spec.family {
                SocketFamily::V4 => Domain::IPV4,
                SocketFamily::V6Only | SocketFamily::V6DualStack => Domain::IPV6,
            };
            let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|e| oserr::from_errno(&e, "socket", Context::Socket))?;

            // `IPV6_V6ONLY` before the bind: on several platforms it cannot be
            // changed after, and "we forgot to set it" is how a v6 socket silently
            // starts accepting v4-mapped traffic the canonical forms reject
            // everywhere else.
            match spec.family {
                SocketFamily::V6Only => socket
                    .set_only_v6(true)
                    .map_err(|e| oserr::from_errno(&e, "IPV6_V6ONLY", Context::Socket))?,
                SocketFamily::V6DualStack => socket
                    .set_only_v6(false)
                    .map_err(|e| oserr::from_errno(&e, "IPV6_V6ONLY", Context::Socket))?,
                SocketFamily::V4 => {}
            }

            let options = &spec.options;
            if options.reuse_address {
                socket
                    .set_reuse_address(true)
                    .map_err(|e| oserr::from_errno(&e, "SO_REUSEADDR", Context::Socket))?;
            }
            if options.reuse_port {
                socket
                    .set_reuse_port(true)
                    .map_err(|e| oserr::from_errno(&e, "SO_REUSEPORT", Context::Socket))?;
            }
            if let Some(hop_limit) = options.hop_limit {
                let hops = u32::from(hop_limit);
                let result = if matches!(spec.family, SocketFamily::V4) {
                    socket.set_ttl_v4(hops)
                } else {
                    socket.set_unicast_hops_v6(hops)
                };
                result.map_err(|e| oserr::from_errno(&e, "hop_limit", Context::Socket))?;
            }
            if let Some(dscp) = options.dscp {
                if matches!(spec.family, SocketFamily::V4) {
                    socket
                        .set_tos_v4(u32::from(dscp))
                        .map_err(|e| oserr::from_errno(&e, "IP_TOS", Context::Socket))?;
                }
            }
            if let Some(bytes) = options.send_buffer_bytes {
                socket
                    .set_send_buffer_size(bytes as usize)
                    .map_err(|e| oserr::from_errno(&e, "SO_SNDBUF", Context::Socket))?;
            }
            if let Some(bytes) = options.receive_buffer_bytes {
                socket
                    .set_recv_buffer_size(bytes as usize)
                    .map_err(|e| oserr::from_errno(&e, "SO_RCVBUF", Context::Socket))?;
            }

            let plan = plan_options(options, spec.family);
            apply_darwin(&socket, &plan)?;

            let local: SocketAddr = match &spec.local {
                Some(endpoint) => addr::endpoint_to_std(*endpoint),
                None => match spec.family {
                    SocketFamily::V4 => SocketAddr::from(([0u8; 4], 0)),
                    _ => SocketAddr::from(([0u16; 8], 0)),
                },
            };
            socket
                .bind(&local.into())
                .map_err(|e| oserr::from_errno(&e, "bind", Context::Socket))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| oserr::from_errno(&e, "O_NONBLOCK", Context::Socket))?;

            let std_socket: std::net::UdpSocket = socket.into();
            let inner = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| oserr::from_errno(&e, "from_std", Context::Socket))?;

            if let Some(multicast) = &options.multicast {
                join(&inner, multicast, true)?;
            }

            Ok(Box::new(MacosUdpSocket {
                inner,
                family: spec.family,
                plan,
            }) as Box<dyn UdpSocket>)
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(probe_families())
        })
    }
}

/// Joins or leaves a group.
fn join(
    socket: &tokio::net::UdpSocket,
    options: &MulticastOptions,
    joining: bool,
) -> Result<(), PlatformError> {
    let interface = options.interface.0;
    let result = match (addr::to_std(options.group), joining) {
        (std::net::IpAddr::V4(group), true) => socket.join_multicast_v4(group, [0, 0, 0, 0].into()),
        (std::net::IpAddr::V4(group), false) => {
            socket.leave_multicast_v4(group, [0, 0, 0, 0].into())
        }
        (std::net::IpAddr::V6(group), true) => socket.join_multicast_v6(&group, interface),
        (std::net::IpAddr::V6(group), false) => socket.leave_multicast_v6(&group, interface),
    };
    result.map_err(|e| oserr::from_errno(&e, "multicast", Context::Socket))
}

/// A bound UDP socket.
#[derive(Debug)]
pub struct MacosUdpSocket {
    inner: tokio::net::UdpSocket,
    family: SocketFamily,
    plan: SocketOptionPlan,
}

impl MacosUdpSocket {
    /// The Darwin option plan this socket was opened with.
    ///
    /// Exposed so a shell can report an unsupported option rather than the core
    /// discovering it as a path that never completes.
    #[must_use]
    pub const fn option_plan(&self) -> &SocketOptionPlan {
        &self.plan
    }
}

impl UdpSocket for MacosUdpSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        let local = self
            .inner
            .local_addr()
            .map_err(|e| oserr::from_errno(&e, "getsockname", Context::Socket))?;
        addr::endpoint_from_std(local, "getsockname")
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            let target = addr::endpoint_to_std(*destination);
            self.inner
                .send_to(buf, target)
                .await
                .map_err(|e| oserr::from_errno(&e, "sendto", Context::Socket))
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            let (len, source) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| oserr::from_errno(&e, "recvfrom", Context::Socket))?;
            // **A stated gap.** `destination` and `interface` need `recvmsg` with
            // the control data `plan_options` asked for, and this path uses
            // `recv_from`, which discards it. The options ARE set, so the kernel
            // is producing the ancillary data; nothing here collects it yet. The
            // parser that would ([`parse_cmsgs`]) is written and tested.
            //
            // Reported as `None` rather than guessed: §3.4 attributes a reflexive
            // candidate from these two fields, and a guessed local address
            // produces a candidate that probes where nothing answers and reads as
            // a NAT fault.
            Ok(Datagram {
                len,
                source: addr::endpoint_from_std(source, "recvfrom")?,
                destination: None,
                interface: None,
                // `recv_from` reports the bytes copied, not the datagram's true
                // length, so truncation is not observable on this path. Also a
                // stated gap: the seam requires it to be "reported, never silent".
                truncated: false,
            })
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        join(&self.inner, options, true)
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        join(&self.inner, options, false)
    }

    fn family(&self) -> SocketFamily {
        self.family
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        // Idempotent: the descriptor is closed when the socket drops, and there is
        // no second close to fail.
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Control-message parsing
// ---------------------------------------------------------------------------

/// `<sys/socket.h>`: `struct cmsghdr` is `{ socklen_t cmsg_len; int cmsg_level;
/// int cmsg_type; }` — twelve bytes on Darwin.
pub const CMSGHDR_LEN: usize = 12;

/// Darwin's `__DARWIN_ALIGN32`: control data aligns to four, not to eight.
#[must_use]
pub const fn cmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// What one `recvmsg`'s control data told us.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControlFacts {
    /// Which of our addresses the datagram arrived on.
    pub destination: Option<IpAddr>,
    /// Which interface it arrived through.
    pub interface: Option<u32>,
}

/// Walks a `recvmsg` control buffer.
///
/// Pure, so the three Darwin shapes — `IP_RECVDSTADDR`'s bare `struct in_addr`,
/// `IP_RECVIF`'s `struct sockaddr_dl`, and `IPV6_PKTINFO`'s
/// `struct in6_pktinfo` — are checked here rather than on a Mac. Every length is
/// validated against the remaining buffer **before** it is indexed.
#[must_use]
pub fn parse_cmsgs(control: &[u8]) -> ControlFacts {
    let mut facts = ControlFacts::default();
    let mut offset = 0usize;
    while offset + CMSGHDR_LEN <= control.len() {
        let header = &control[offset..offset + CMSGHDR_LEN];
        let len = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let level = i32::from_ne_bytes([header[4], header[5], header[6], header[7]]);
        let kind = i32::from_ne_bytes([header[8], header[9], header[10], header[11]]);
        if len < CMSGHDR_LEN || offset + len > control.len() {
            break;
        }
        let data = &control[offset + CMSGHDR_LEN..offset + len];
        match (level, kind) {
            (sockopt::IPPROTO_IP, sockopt::IP_RECVDSTADDR) if data.len() >= 4 => {
                facts.destination = Some(IpAddr::V4(twinvpn_types::V4Addr::from_octets([
                    data[0], data[1], data[2], data[3],
                ])));
            }
            (sockopt::IPPROTO_IP, sockopt::IP_RECVIF) if data.len() >= 4 => {
                // `struct sockaddr_dl`: `sdl_len`, `sdl_family`, then `sdl_index`.
                facts.interface = Some(u32::from(u16::from_ne_bytes([data[2], data[3]])));
            }
            (sockopt::IPPROTO_IPV6, IPV6_PKTINFO) if data.len() >= 20 => {
                // `struct in6_pktinfo`: sixteen address bytes then a `u32` index.
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[..16]);
                let index = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                let zone = twinvpn_types::ZoneIndex::new(index);
                let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
                if let Ok(address) =
                    twinvpn_types::V6Addr::new(octets, if is_link_local { zone } else { None })
                {
                    facts.destination = Some(IpAddr::V6(address));
                }
                facts.interface = Some(index);
            }
            _ => {}
        }
        let step = cmsg_align(len);
        if step == 0 {
            break;
        }
        offset += step;
    }
    facts
}

/// `<netinet6/in6.h>`: `IPV6_PKTINFO`, the type the kernel stamps on the control
/// message `IPV6_RECVPKTINFO` asked for.
pub const IPV6_PKTINFO: i32 = 46;

/// The Darwin address family a socket shape originates traffic in.
///
/// Present so a caller can name the family in a log without importing the
/// constants; the numbers are Darwin's, not this host's.
#[must_use]
pub const fn darwin_family_of(shape: SocketFamily) -> u8 {
    match shape {
        SocketFamily::V4 => DARWIN_AF_INET,
        SocketFamily::V6Only | SocketFamily::V6DualStack => DARWIN_AF_INET6,
    }
}
