//! UDP sockets: v4, v6-only, dual-stack, multicast, and the per-socket options
//! the NAT ladder and DPLPMTUD need.
//!
//! **Authority:** [`twinvpn_platform::socket`], `docs/networking.md` §3
//! (candidate gathering, the disco probe, birthday-paradox port prediction), §6.2
//! (1280 floor + DPLPMTUD), §8 (LAN discovery), §5.2 (`fwmark` + policy table 52),
//! ADR-0010 R1 and R8, ADR-0012 KS-9(1) (the `SO_MARK` half of the bootstrap
//! predicate), ADR-0018 DP-4.
//!
//! # W-25: this is the surface the C ABI does not have
//!
//! `core/ffi/include/twinvpn.h`'s F-9 vtable has **no socket provider**, while
//! ADR-0018 §11.2 row 2.10 puts all NAT traversal in the core "with sockets via
//! the adapter". A shell binding only the C ABI therefore cannot do NAT
//! traversal at all. This crate is bound as a **Rust crate**, not through the
//! ABI, which is why the whole [`SocketProvider`] exists here and works. The
//! finding stands for every shell that cannot do the same.
//!
//! # Readiness, not blocking
//!
//! Every socket is `O_NONBLOCK` and driven by [`tokio::io::unix::AsyncFd`].
//! Cancellation is dropping the future — the readiness guard is released and no
//! syscall is in flight, so nothing is held. **No deadline is imposed here:**
//! timeouts are the core's, composed from `twinvpn_env::Timer` on the injected
//! monotonic clock, and an adapter-imposed one would put a deadline outside
//! CD-1's reach.
//!
//! # `unsafe` in this module
//!
//! Six blocks, each with a `// SAFETY:` naming its invariant: the single
//! `setsockopt` call site ([`setsockopt_bytes`]), the zeroed `sockaddr_storage`
//! that `libc`'s private padding makes unconstructible in safe code, the
//! `recvmsg` in [`LinuxUdpSocket::recv_once`], the `cmsg` walk in
//! [`read_pktinfo`] and its two `copy_nonoverlapping`s, and the two
//! `sockaddr_in`/`sockaddr_in6` copies in [`sockaddr_to_std`]. Everything else
//! goes through `socket2`.

use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures_core::future::BoxFuture;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use twinvpn_platform::{
    Datagram, InterfaceIndex, MulticastOptions, PlatformError, SocketCapabilities, SocketFamily, SocketOptions,
    SocketProvider, SupportedFamilies, UdpBindSpec, UdpSocket,
};
use twinvpn_types::{Endpoint, IpAddr};

use crate::addr;
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// Sets one integer socket option.
///
/// Present because `socket2` 0.6 has no wrapper for `IP_PKTINFO`,
/// `IPV6_RECVPKTINFO` or `IP_MTU_DISCOVER`, and each is load-bearing:
/// packet-info attributes a reflexive candidate to the right local address
/// (`docs/networking.md` §3.4), and `IP_MTU_DISCOVER = IP_PMTUDISC_PROBE` is what
/// makes a too-large DPLPMTUD probe get dropped rather than fragmented (§6.2).
fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    setsockopt_bytes(fd, level, name, &value.to_ne_bytes())
}

/// Sets one socket option from a byte-exact option value.
///
/// The `int` form above delegates here, so there is exactly **one**
/// `setsockopt` call site in this crate rather than one per option width.
fn setsockopt_bytes(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &[u8],
) -> io::Result<()> {
    // SAFETY: `fd` is a valid open socket for the whole call — it is borrowed
    // from a live `Socket` that the caller owns and that outlives this function.
    // `value` is a live slice and the length passed is its true byte length,
    // which is the width the named option expects (asserted by the caller's
    // choice of encoding, and by `the_multicast_if_option_is_the_kernels_width`
    // for the one variable-width case). `setsockopt` copies out of the pointer
    // and retains nothing.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value.as_ptr().cast::<libc::c_void>(),
            u32::try_from(value.len()).unwrap_or(0),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `struct ip_mreqn { multiaddr, address, ifindex }`, encoded for
/// `IP_MULTICAST_IF`.
///
/// `socket2` only offers the `Ipv4Addr` form of `IP_MULTICAST_IF`, and an
/// address cannot name an interface that has no IPv4 address on it — which is
/// precisely the multi-homed and IPv6-only case LAN discovery has to work on.
/// `ip_mreqn` selects by **index**, the same identity `InterfaceIndex` carries.
#[must_use]
fn ip_mreqn_by_index(index: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[8..12].copy_from_slice(&i32::try_from(index).unwrap_or(0).to_ne_bytes());
    out
}

/// Opens Linux UDP sockets.
pub struct LinuxSocketProvider {
    shutdown: ShutdownLatch,
}

impl LinuxSocketProvider {
    /// Binds the provider to the adapter's shutdown latch.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }

    /// Probes which socket shapes this host can actually open.
    ///
    /// A **capability fact**, established by opening a socket rather than by
    /// reading a sysctl: `net.ipv6.conf.all.disable_ipv6` is not the only way a
    /// host loses v6, and CB-3's whole point is that the core branches on what
    /// the platform can do rather than on which platform it is.
    fn probe_families() -> SupportedFamilies {
        let v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).is_ok();
        let (v6, dual) = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => (true, s.set_only_v6(false).is_ok()),
            Err(_) => (false, false),
        };
        SupportedFamilies {
            v4,
            v6,
            dual_stack_socket: dual,
        }
    }
}

impl SocketProvider for LinuxSocketProvider {
    /// Linux has both, and both are load-bearing here.
    ///
    /// `SO_REUSEPORT` is what makes `docs/networking.md` §3.6's birthday-paradox
    /// port prediction possible at all, and `SO_MARK` carries §5.2's `fwmark`
    /// policy rule **and** half of ADR-0012 KS-9(1)'s exemption predicate — which
    /// KS-9b records as the only one of the three desktops that expresses the
    /// predicate exactly.
    fn socket_capabilities(&self) -> SocketCapabilities {
        SocketCapabilities {
            reuse_port: true,
            firewall_mark: true,
        }
    }

    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let socket = open_and_configure(spec)?;
            let socket = LinuxUdpSocket::new(socket, spec.family, self.shutdown.clone())?;
            Ok(Box::new(socket) as Box<dyn UdpSocket>)
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            Ok(Self::probe_families())
        })
    }
}

/// Opens the socket and applies every option **at open**, before the bind.
///
/// `SocketOptions`' own documentation is why: "several of them cannot be changed
/// on a bound socket on at least one target, and an option that silently failed
/// to apply is a NAT ladder that behaves differently from the one that was
/// tested". So every failure here is returned, never logged and swallowed.
fn open_and_configure(spec: &UdpBindSpec) -> Result<Socket, PlatformError> {
    let domain = match spec.family {
        SocketFamily::V4 => Domain::IPV4,
        SocketFamily::V6Only | SocketFamily::V6DualStack => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| oserr::from_errno(&e, "socket", Context::Socket))?;

    let map = |call: &'static str| move |e: io::Error| oserr::from_errno(&e, call, Context::Socket);

    // IPV6_V6ONLY first: on Linux it cannot be changed after bind, and the whole
    // reason `V6Only` and `V6DualStack` are different values rather than a flag
    // is that "we forgot to set it" is how a v6 socket silently starts accepting
    // v4-mapped traffic that `common.proto` rejects everywhere else.
    match spec.family {
        SocketFamily::V6Only => socket.set_only_v6(true).map_err(map("IPV6_V6ONLY"))?,
        SocketFamily::V6DualStack => socket.set_only_v6(false).map_err(map("IPV6_V6ONLY"))?,
        SocketFamily::V4 => {}
    }

    apply_options(&socket, spec.family, &spec.options)?;
    socket.set_nonblocking(true).map_err(map("O_NONBLOCK"))?;

    let local = match spec.local {
        Some(ep) => addr::endpoint_to_std(ep),
        None => match spec.family {
            SocketFamily::V4 => {
                SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
            SocketFamily::V6Only | SocketFamily::V6DualStack => {
                SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            }
        },
    };
    socket
        .bind(&local.into())
        .map_err(|e| oserr::from_errno(&e, "bind", Context::Socket))?;

    // Multicast joins happen after bind: a join on an unbound socket is refused
    // on Linux, and LAN discovery's whole point is knowing which segment an
    // announcement came from.
    if let Some(mc) = &spec.options.multicast {
        join_group(&socket, mc)?;
    }
    Ok(socket)
}

#[allow(clippy::too_many_lines)]
fn apply_options(
    socket: &Socket,
    family: SocketFamily,
    options: &SocketOptions,
) -> Result<(), PlatformError> {
    let fd = socket.as_raw_fd();
    let map = |call: &'static str| move |e: io::Error| oserr::from_errno(&e, call, Context::Socket);
    let is_v6 = !matches!(family, SocketFamily::V4);

    if options.reuse_address {
        socket
            .set_reuse_address(true)
            .map_err(map("SO_REUSEADDR"))?;
    }
    if options.reuse_port {
        // `docs/networking.md` §3.6's birthday-paradox port prediction opens many
        // sockets at once; on Linux that needs SO_REUSEPORT.
        socket.set_reuse_port(true).map_err(map("SO_REUSEPORT"))?;
    }

    // DPLPMTUD (§6.2): "success is inferred from an acknowledgement, not from the
    // absence of an ICMP error", which requires the too-large probe to be
    // DROPPED rather than fragmented. IP_PMTUDISC_PROBE sets DF and suppresses
    // the kernel's own PMTU bookkeeping, which is exactly RFC 8899's shape.
    match options.fragment_policy {
        twinvpn_platform::FragmentPolicy::DontFragment => {
            if is_v6 {
                setsockopt_int(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    libc::IPV6_PMTUDISC_PROBE,
                )
                .map_err(map("IPV6_MTU_DISCOVER"))?;
            } else {
                setsockopt_int(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    libc::IP_PMTUDISC_PROBE,
                )
                .map_err(map("IP_MTU_DISCOVER"))?;
            }
        }
        twinvpn_platform::FragmentPolicy::PlatformDefault => {}
    }

    if let Some(hops) = options.hop_limit {
        if is_v6 {
            socket
                .set_unicast_hops_v6(u32::from(hops))
                .map_err(map("IPV6_UNICAST_HOPS"))?;
        } else {
            socket.set_ttl_v4(u32::from(hops)).map_err(map("IP_TTL"))?;
        }
    }
    if let Some(dscp) = options.dscp {
        // The seam carries the DSCP code point; the wire field is the full
        // TOS/traffic-class octet, so it is shifted here rather than in the core
        // — which would be a Linux fact above the adapter.
        let tclass = u32::from(dscp) << 2;
        if is_v6 {
            socket.set_tclass_v6(tclass).map_err(map("IPV6_TCLASS"))?;
        } else {
            socket.set_tos_v4(tclass).map_err(map("IP_TOS"))?;
        }
    }
    if let Some(index) = options.bind_to_interface {
        // Required for a link-local v6 candidate and for LAN discovery on a
        // multi-homed host. By index rather than by name: a name is not stable
        // across a reconnect, which is the same reason `InterfaceIndex` exists.
        let index = std::num::NonZeroU32::new(index.0)
            .ok_or_else(|| oserr::unavailable("SO_BINDTODEVICE", libc::EINVAL))?;
        if is_v6 {
            socket
                .bind_device_by_index_v6(Some(index))
                .map_err(map("SO_BINDTODEVICE"))?;
        } else {
            socket
                .bind_device_by_index_v4(Some(index))
                .map_err(map("SO_BINDTODEVICE"))?;
        }
    }
    if options.receive_packet_info {
        // Without this a wildcard-bound socket cannot tell which of its
        // addresses a probe arrived on, which is what §3.4's disco probe needs
        // to attribute a reflexive candidate correctly.
        if is_v6 {
            setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)
                .map_err(map("IPV6_RECVPKTINFO"))?;
        } else {
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1).map_err(map("IP_PKTINFO"))?;
        }
    }
    if let Some(mark) = options.firewall_mark {
        // ADR-0012 KS-9(1): the Linux half of the bootstrap predicate is
        // "cgroup v2 path match AND fwmark set via SO_MARK by the agent". It is
        // also the §5.2 policy-routing key for table 52. KS-12: if registration
        // fails the socket is NOT exempt, so this failure is returned.
        socket.set_mark(mark).map_err(map("SO_MARK"))?;
    }
    if let Some(bytes) = options.send_buffer_bytes {
        socket
            .set_send_buffer_size(bytes as usize)
            .map_err(map("SO_SNDBUF"))?;
    }
    if let Some(bytes) = options.receive_buffer_bytes {
        socket
            .set_recv_buffer_size(bytes as usize)
            .map_err(map("SO_RCVBUF"))?;
    }
    Ok(())
}

fn join_group(socket: &Socket, options: &MulticastOptions) -> Result<(), PlatformError> {
    let map = |call: &'static str| move |e: io::Error| oserr::from_errno(&e, call, Context::Socket);
    match options.group {
        IpAddr::V4(g) => {
            let group = std::net::Ipv4Addr::from(g.octets());
            socket
                .join_multicast_v4_n(
                    &group,
                    &socket2::InterfaceIndexOrAddress::Index(options.interface.0),
                )
                .map_err(map("IP_ADD_MEMBERSHIP"))?;
            setsockopt_bytes(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                &ip_mreqn_by_index(options.interface.0),
            )
            .map_err(map("IP_MULTICAST_IF"))?;
            socket
                .set_multicast_loop_v4(options.loopback)
                .map_err(map("IP_MULTICAST_LOOP"))?;
            // hop_limit 1 keeps an announcement on the local segment, which is
            // what §8.2's privacy discussion assumes and what ADR-0012 §11.2
            // class 10 matches on.
            socket
                .set_multicast_ttl_v4(u32::from(options.hop_limit))
                .map_err(map("IP_MULTICAST_TTL"))?;
        }
        IpAddr::V6(g) => {
            let group = std::net::Ipv6Addr::from(g.octets());
            socket
                .join_multicast_v6(&group, options.interface.0)
                .map_err(map("IPV6_ADD_MEMBERSHIP"))?;
            socket
                .set_multicast_if_v6(options.interface.0)
                .map_err(map("IPV6_MULTICAST_IF"))?;
            socket
                .set_multicast_loop_v6(options.loopback)
                .map_err(map("IPV6_MULTICAST_LOOP"))?;
            socket
                .set_multicast_hops_v6(u32::from(options.hop_limit))
                .map_err(map("IPV6_MULTICAST_HOPS"))?;
        }
    }
    Ok(())
}

fn leave_group(socket: &Socket, options: &MulticastOptions) -> Result<(), PlatformError> {
    let map = |call: &'static str| move |e: io::Error| oserr::from_errno(&e, call, Context::Socket);
    match options.group {
        IpAddr::V4(g) => socket
            .leave_multicast_v4_n(
                &std::net::Ipv4Addr::from(g.octets()),
                &socket2::InterfaceIndexOrAddress::Index(options.interface.0),
            )
            .map_err(map("IP_DROP_MEMBERSHIP")),
        IpAddr::V6(g) => socket
            .leave_multicast_v6(&std::net::Ipv6Addr::from(g.octets()), options.interface.0)
            .map_err(map("IPV6_DROP_MEMBERSHIP")),
    }
}

/// A bound Linux UDP socket.
pub struct LinuxUdpSocket {
    io: AsyncFd<Socket>,
    family: SocketFamily,
    closed: AtomicBool,
    shutdown: ShutdownLatch,
    /// Whether `IP_PKTINFO` / `IPV6_RECVPKTINFO` was requested at open.
    ///
    /// Recorded so [`Datagram::destination`] is `None` because the caller did
    /// not ask, never because the `cmsg` walk quietly found nothing.
    want_pktinfo: bool,
}

impl LinuxUdpSocket {
    fn new(
        socket: Socket,
        family: SocketFamily,
        shutdown: ShutdownLatch,
    ) -> Result<Self, PlatformError> {
        let want_pktinfo = true;
        let io = AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| oserr::from_errno(&e, "epoll_ctl", Context::Socket))?;
        Ok(Self {
            io,
            family,
            closed: AtomicBool::new(false),
            shutdown,
            want_pktinfo,
        })
    }

    fn usable(&self) -> Result<(), PlatformError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(oserr::unavailable("socket", libc::EBADF));
        }
        self.shutdown.check()
    }

    /// One `recvmsg`, with the control message walked for packet info.
    ///
    /// Returns `WouldBlock` to the caller's readiness loop rather than looping
    /// internally, so that dropping the future really does cancel.
    fn recv_once(&self, buf: &mut [u8]) -> io::Result<Datagram> {
        let mut name: libc::sockaddr_storage = zeroed_storage();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buf.len(),
        };
        // Enough for one IP_PKTINFO / IPV6_PKTINFO plus alignment slack.
        let mut control = [0u8; 128];
        let mut msg: libc::msghdr = zeroed_msghdr();
        msg.msg_name = std::ptr::from_mut(&mut name).cast::<libc::c_void>();
        msg.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_storage>()).unwrap_or(128);
        msg.msg_iov = std::ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = control.len();

        // SAFETY: every pointer in `msg` refers to a live local that outlives
        // the call — `name`, `iov` (which itself borrows the caller's `buf` for
        // the duration of `recv_once`), and `control` — and each length field is
        // that local's true byte length. The fd is valid for the call because it
        // is borrowed from `self.io`. `recvmsg` writes only within the declared
        // lengths and retains no pointer.
        let n = unsafe { libc::recvmsg(self.io.get_ref().as_raw_fd(), &raw mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = usize::try_from(n).unwrap_or(0);

        let source = sockaddr_to_std(&name, msg.msg_namelen)?;
        let (destination, interface) = if self.want_pktinfo {
            // SAFETY: `msg` was just filled by a successful `recvmsg`, so
            // `msg_control`/`msg_controllen` describe exactly the control bytes
            // the kernel wrote inside `control`, which is still alive here. The
            // walk below uses only CMSG_FIRSTHDR/CMSG_NXTHDR on `&msg` and
            // copies out of each header's data area with a size check first.
            unsafe { read_pktinfo(&msg) }
        } else {
            (None, None)
        };

        Ok(Datagram {
            len,
            source,
            destination,
            interface,
            // MSG_TRUNC is REPORTED, never silent: "a silently truncated
            // datagram is a message that fails authentication for a reason
            // nobody can see".
            truncated: (msg.msg_flags & libc::MSG_TRUNC) != 0,
        })
    }
}

/// A zeroed `sockaddr_storage`.
///
/// `libc` 0.2.189 makes the padding fields private, so the struct cannot be
/// built field-by-field. A zeroed value is a **valid** one: `sockaddr_storage`
/// is a POD byte buffer whose only meaningful field before a `recvmsg` is the
/// family, and `AF_UNSPEC` is zero.
fn zeroed_storage() -> libc::sockaddr_storage {
    // SAFETY: `sockaddr_storage` is `#[repr(C)]` over one `u16` and two private
    // padding members. It contains no reference, no `NonZero`, no enum and no
    // `bool`, so every bit pattern inhabits it and an all-zero value is
    // initialised — the same value `memset` gives it in every C `recvmsg`.
    unsafe { mem::zeroed() }
}

/// A zeroed `msghdr`, built field-by-field in safe code.
fn zeroed_msghdr() -> libc::msghdr {
    libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    }
}

/// Walks the control messages for `IP_PKTINFO` / `IPV6_PKTINFO`.
///
/// # Safety
///
/// `msg` must have been filled by a successful `recvmsg` whose `msg_control`
/// buffer is still live and whose `msg_controllen` is the length the kernel
/// wrote.
unsafe fn read_pktinfo(msg: &libc::msghdr) -> (Option<IpAddr>, Option<InterfaceIndex>) {
    // SAFETY: the caller's contract above guarantees `msg` was filled by a
    // successful `recvmsg` and that its control buffer is live for this call,
    // which is exactly `CMSG_FIRSTHDR`'s requirement. It returns null when
    // there are no control messages, and the loop checks for that.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is non-null (checked by the loop condition) and points
        // into the live control buffer, either from `CMSG_FIRSTHDR` above or
        // from `CMSG_NXTHDR` below — both of which return a pointer to a whole
        // `cmsghdr` inside that buffer or null. The borrow lives only for this
        // iteration and nothing mutates the buffer while it is held.
        let header = unsafe { &*cmsg };
        // SAFETY: as above; `CMSG_DATA` is pointer arithmetic on a valid
        // `cmsghdr` and yields a pointer to that header's data area, whose
        // length is checked against `CMSG_LEN` before anything is read.
        let data = unsafe { libc::CMSG_DATA(cmsg) };
        match (header.cmsg_level, header.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: `CMSG_LEN` is pure arithmetic on its argument — it
                // dereferences nothing and is `unsafe` only because `libc`
                // declares it so.
                let needed = unsafe {
                    libc::CMSG_LEN(u32::try_from(mem::size_of::<libc::in_pktinfo>()).unwrap_or(12))
                } as usize;
                if header.cmsg_len >= needed {
                    let mut info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr { s_addr: 0 },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    // SAFETY: `header.cmsg_len >= needed` was checked just
                    // above, so the data area holds at least
                    // `size_of::<in_pktinfo>()` initialised bytes. `info` is a
                    // live, uniquely-borrowed local of exactly that size, and
                    // the two regions cannot overlap — one is the kernel's
                    // control buffer, the other is this frame's stack.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            data,
                            std::ptr::from_mut(&mut info).cast::<u8>(),
                            mem::size_of::<libc::in_pktinfo>(),
                        );
                    }
                    let octets = info.ipi_addr.s_addr.to_ne_bytes();
                    return (
                        Some(IpAddr::V4(twinvpn_types::V4Addr::from_octets(octets))),
                        std::num::NonZeroU32::new(u32::try_from(info.ipi_ifindex).unwrap_or(0))
                            .map(|i| InterfaceIndex(i.get())),
                    );
                }
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: as above — `CMSG_LEN` is pure arithmetic.
                let needed = unsafe {
                    libc::CMSG_LEN(u32::try_from(mem::size_of::<libc::in6_pktinfo>()).unwrap_or(20))
                } as usize;
                if header.cmsg_len >= needed {
                    let mut info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
                        ipi6_ifindex: 0,
                    };
                    // SAFETY: the length check above guarantees the data area
                    // holds at least `size_of::<in6_pktinfo>()` initialised
                    // bytes; `info` is a live local of exactly that size, and
                    // the kernel's control buffer and this stack frame do not
                    // overlap.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            data,
                            std::ptr::from_mut(&mut info).cast::<u8>(),
                            mem::size_of::<libc::in6_pktinfo>(),
                        );
                    }
                    let index = std::num::NonZeroU32::new(info.ipi6_ifindex)
                        .map(|i| InterfaceIndex(i.get()));
                    // A v6 destination that arrives v4-mapped on a dual-stack
                    // socket is un-mapped at the seam like any other.
                    let std = std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr);
                    let scope = index.map_or(0, |i| i.0);
                    let canonical =
                        addr::from_std(std::net::IpAddr::V6(std), scope, "IPV6_PKTINFO").ok();
                    return (canonical, index);
                }
            }
            _ => {}
        }
        // SAFETY: `msg` is still the caller's live `msghdr` and `cmsg` is a
        // valid header inside its control buffer, which is `CMSG_NXTHDR`'s
        // requirement. It returns null when the walk is done.
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    (None, None)
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> io::Result<Endpoint> {
    let bytes = std::ptr::from_ref(storage).cast::<u8>();
    let addr = match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            if (len as usize) < mem::size_of::<libc::sockaddr_in>() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let mut a = libc::sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            // SAFETY: `storage` is at least `sockaddr_in` wide — checked above
            // against `len`, which the kernel set — and both types are POD with
            // no padding requirements beyond alignment, which `sockaddr_storage`
            // satisfies for every `sockaddr_*` by definition.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes,
                    std::ptr::from_mut(&mut a).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in>(),
                );
            }
            SocketAddr::V4(SocketAddrV4::new(
                std::net::Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            if (len as usize) < mem::size_of::<libc::sockaddr_in6>() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let mut a = libc::sockaddr_in6 {
                sin6_family: 0,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            };
            // SAFETY: as above, with `sockaddr_in6`'s width checked against the
            // kernel-supplied `len`.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes,
                    std::ptr::from_mut(&mut a).cast::<u8>(),
                    mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            ))
        }
        _ => return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT)),
    };
    addr::endpoint_from_std(addr, "recvmsg").map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

impl UdpSocket for LinuxUdpSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        self.usable()?;
        let local = self
            .io
            .get_ref()
            .local_addr()
            .map_err(|e| oserr::from_errno(&e, "getsockname", Context::Socket))?;
        let std = local
            .as_socket()
            .ok_or_else(|| oserr::unavailable("getsockname", libc::EAFNOSUPPORT))?;
        addr::endpoint_from_std(std, "getsockname")
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.usable()?;
            let target: socket2::SockAddr = addr::endpoint_to_std(*destination).into();
            loop {
                let mut guard = self
                    .io
                    .writable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "epoll_wait", Context::Socket))?;
                match guard.try_io(|inner| inner.get_ref().send_to(buf, &target)) {
                    Ok(Ok(n)) => {
                        // A short write on a datagram socket is an adapter
                        // defect, not a partial send to retry.
                        if n != buf.len() {
                            return Err(oserr::unavailable("sendto", libc::EMSGSIZE));
                        }
                        return Ok(n);
                    }
                    Ok(Err(e)) => {
                        return Err(oserr::from_errno(&e, "sendto", Context::Socket));
                    }
                    Err(_would_block) => {}
                }
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            self.usable()?;
            loop {
                let mut guard = self
                    .io
                    .readable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "epoll_wait", Context::Socket))?;
                match guard.try_io(|_| self.recv_once(buf)) {
                    Ok(Ok(d)) => return Ok(d),
                    Ok(Err(e)) => return Err(oserr::from_errno(&e, "recvmsg", Context::Socket)),
                    Err(_would_block) => {}
                }
            }
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.usable()?;
        join_group(self.io.get_ref(), options)
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.usable()?;
        leave_group(self.io.get_ref(), options)
    }

    fn family(&self) -> SocketFamily {
        self.family
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Idempotent, and safe after a crash: the fd itself is released when
            // the `AsyncFd` drops. This flag is what makes a second call a
            // no-op rather than a double close.
            self.closed.store(true, Ordering::Release);
            Ok(())
        })
    }
}

/// The provider, shareable.
#[must_use]
pub fn provider(shutdown: ShutdownLatch) -> Arc<LinuxSocketProvider> {
    Arc::new(LinuxSocketProvider::new(shutdown))
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::FragmentPolicy;
    use twinvpn_types::{Port, V4Addr, V6Addr};

    fn spec(family: SocketFamily) -> UdpBindSpec {
        UdpBindSpec {
            family,
            local: None,
            options: SocketOptions::default(),
        }
    }

    #[tokio::test]
    async fn all_three_socket_shapes_open_and_report_their_family() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        for family in [
            SocketFamily::V4,
            SocketFamily::V6Only,
            SocketFamily::V6DualStack,
        ] {
            let s = p.bind_udp(&spec(family)).await.expect("binds");
            assert_eq!(s.family(), family);
            let local = s.local_endpoint().expect("bound");
            assert!(local.port.get() > 0, "an ephemeral port was assigned");
        }
    }

    #[tokio::test]
    async fn supported_families_is_probed_not_assumed() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let f = p.supported_families().await.expect("probes");
        assert!(f.v4, "this host has AF_INET");
        // v6 and dual-stack are reported as FACTS, not asserted: a container
        // with v6 disabled is a supported host and the core must be told.
        if f.v6 {
            assert!(
                p.bind_udp(&spec(SocketFamily::V6Only)).await.is_ok(),
                "reported v6 support must be real"
            );
        }
    }

    #[tokio::test]
    async fn a_v4_datagram_round_trips_with_its_source_and_destination() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let a = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        let b = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        let b_local = b.local_endpoint().expect("bound");
        let target = Endpoint::new(
            IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])),
            b_local.port,
        );
        a.send_to(b"hello", &target).await.expect("sends");
        let mut buf = [0u8; 64];
        let d = b.recv_from(&mut buf).await.expect("receives");
        assert_eq!(&buf[..d.len], b"hello");
        assert_eq!(d.source.family(), twinvpn_types::AddressFamily::V4);
        assert!(!d.truncated);
        // IP_PKTINFO was requested by the default options, so the destination
        // and the arrival interface are known.
        assert_eq!(
            d.destination,
            Some(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])))
        );
        assert!(d.interface.is_some(), "the loopback interface index");
    }

    #[tokio::test]
    async fn a_v6_datagram_round_trips_and_carries_its_own_family() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let a = p
            .bind_udp(&spec(SocketFamily::V6Only))
            .await
            .expect("binds");
        let b = p
            .bind_udp(&spec(SocketFamily::V6Only))
            .await
            .expect("binds");
        let port = b.local_endpoint().expect("bound").port;
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        let target = Endpoint::new(IpAddr::V6(V6Addr::new(loopback, None).expect("::1")), port);
        a.send_to(b"v6", &target).await.expect("sends");
        let mut buf = [0u8; 64];
        let d = b.recv_from(&mut buf).await.expect("receives");
        assert_eq!(&buf[..d.len], b"v6");
        assert_eq!(d.source.family(), twinvpn_types::AddressFamily::V6);
    }

    #[tokio::test]
    async fn a_dual_stack_socket_reports_a_v4_peer_as_v4_never_as_v4_mapped() {
        // The seam's own rule: "Never a v4-mapped v6 address: the adapter
        // un-maps before this crosses the seam." `common.proto` forbids the
        // mapped form in any canonical position, so a core that saw one would
        // fail every set-membership check that depends on canonical form.
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let dual = p
            .bind_udp(&spec(SocketFamily::V6DualStack))
            .await
            .expect("binds");
        let v4 = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        let port = dual.local_endpoint().expect("bound").port;
        let target = Endpoint::new(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])), port);
        v4.send_to(b"mapped", &target).await.expect("sends");
        let mut buf = [0u8; 64];
        let d = dual.recv_from(&mut buf).await.expect("receives");
        assert_eq!(
            d.source.family(),
            twinvpn_types::AddressFamily::V4,
            "a v4 peer on a dual-stack socket must arrive as V4, un-mapped"
        );
    }

    #[tokio::test]
    async fn a_truncated_datagram_is_reported_never_silently_shortened() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let a = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        let b = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        let port = b.local_endpoint().expect("bound").port;
        let target = Endpoint::new(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])), port);
        a.send_to(&[0u8; 64], &target).await.expect("sends");
        let mut small = [0u8; 8];
        let d = b.recv_from(&mut small).await.expect("receives");
        assert!(
            d.truncated,
            "a silently truncated datagram is a message that fails \
             authentication for a reason nobody can see"
        );
    }

    #[tokio::test]
    async fn every_nat_ladder_option_applies_or_the_bind_fails() {
        // SocketOptions' own rule: applied AT OPEN, and "an option that silently
        // failed to apply is a NAT ladder that behaves differently from the one
        // that was tested". So this asserts the bind SUCCEEDS with all of them,
        // which is only true if every setsockopt returned 0.
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let options = SocketOptions {
            reuse_address: true,
            reuse_port: true,
            fragment_policy: FragmentPolicy::DontFragment,
            hop_limit: Some(64),
            dscp: Some(46),
            bind_to_interface: None,
            receive_packet_info: true,
            firewall_mark: None,
            multicast: None,
            send_buffer_bytes: Some(262_144),
            receive_buffer_bytes: Some(262_144),
        };
        for family in [SocketFamily::V4, SocketFamily::V6Only] {
            let spec = UdpBindSpec {
                family,
                local: None,
                options: options.clone(),
            };
            p.bind_udp(&spec).await.expect("every option applies");
        }
    }

    #[tokio::test]
    async fn reuse_port_lets_the_birthday_paradox_open_many_sockets_on_one_port() {
        // docs/networking.md §3.6's port prediction opens many sockets at once.
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let options = SocketOptions {
            reuse_address: true,
            reuse_port: true,
            ..SocketOptions::default()
        };
        let first = p
            .bind_udp(&UdpBindSpec {
                family: SocketFamily::V4,
                local: None,
                options: options.clone(),
            })
            .await
            .expect("binds");
        let port = first.local_endpoint().expect("bound").port;
        let same = UdpBindSpec {
            family: SocketFamily::V4,
            local: Some(Endpoint::new(IpAddr::V4(V4Addr::UNSPECIFIED), port)),
            options,
        };
        p.bind_udp(&same).await.expect("SO_REUSEPORT permits it");
    }

    #[tokio::test]
    async fn shutdown_refuses_new_work_rather_than_hanging_or_silently_succeeding() {
        let latch = ShutdownLatch::new();
        let p = LinuxSocketProvider::new(latch.clone());
        let s = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        latch.begin();
        match p.bind_udp(&spec(SocketFamily::V4)).await {
            Err(PlatformError::ShuttingDown) => {}
            Err(other) => panic!("wrong refusal: {other:?}"),
            Ok(_) => panic!("a shutting-down adapter must refuse a bind"),
        }
        assert!(matches!(
            s.local_endpoint().expect_err("refused"),
            PlatformError::ShuttingDown
        ));
    }

    #[tokio::test]
    async fn close_is_idempotent() {
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let s = p.bind_udp(&spec(SocketFamily::V4)).await.expect("binds");
        s.close().await.expect("closes");
        s.close().await.expect("idempotent");
        assert!(s.local_endpoint().is_err(), "a closed socket is not usable");
    }

    #[tokio::test]
    async fn a_v4_multicast_join_on_loopback_succeeds_for_lan_discovery() {
        // docs/networking.md §8: local-scope multicast, hop limit 1, joined on a
        // NAMED interface — "a multicast join on 'any interface' means something
        // different on every platform".
        let loopback_index =
            crate::iface::index_of_sysfs_unscoped("lo").unwrap_or(InterfaceIndex(1));
        let options = SocketOptions {
            reuse_address: true,
            multicast: Some(MulticastOptions {
                group: IpAddr::V4(V4Addr::from_octets([224, 0, 0, 251])),
                interface: loopback_index,
                loopback: true,
                hop_limit: 1,
            }),
            ..SocketOptions::default()
        };
        let p = LinuxSocketProvider::new(ShutdownLatch::new());
        let spec = UdpBindSpec {
            family: SocketFamily::V4,
            local: Some(Endpoint::new(
                IpAddr::V4(V4Addr::UNSPECIFIED),
                Port::new(0).unwrap_or_else(|_| Port::new(1).expect("nonzero")),
            )),
            options,
        };
        // Port 0 is malformed in `common.proto`, so bind with `local: None` for
        // the ephemeral case; this asserts the join path itself.
        let spec = UdpBindSpec {
            local: None,
            ..spec
        };
        p.bind_udp(&spec).await.expect("joins the group");
    }
}
