//! [`SocketProvider`]: the NAT ladder's sockets, and the `VpnService.protect`
//! call without which every one of them loops into our own tunnel.
//!
//! **Authority:** `docs/networking.md` §3 (candidate gathering, the disco probe,
//! port prediction), §6.2 (DF for DPLPMTUD), §8 (LAN discovery); ADR-0012
//! **KS-9(1)**; `docs/implementation/ownership.md` §10.4 (sockets stay in Rust
//! on both mobile targets); [`twinvpn_platform::socket`].
//!
//! # Every socket is protected, before it is used
//!
//! KS-9(1) says of Android that the provider's own sockets are excluded from its
//! own tunnel *"by construction"*. **They are not.** An Android `VpnService`
//! claiming `0.0.0.0/0` captures its own process's traffic like any other app's;
//! the exclusion is an explicit `VpnService.protect(int)` per descriptor. A
//! socket that misses it sends its packets into the tunnel those very packets
//! are trying to establish.
//!
//! So [`AndroidSocketProvider::bind_udp`] protects the descriptor **between
//! creating it and binding it**, and a failure to protect is a failure to bind:
//! the socket is closed and the error is returned. There is no path by which an
//! unprotected socket reaches the core. This is reported as a finding against
//! KS-9(1)'s Android clause.
//!
//! # Nothing here decides anything
//!
//! Which candidates to gather, which pairs to race, when to punch, when to give
//! up and take a relay — all `twinvpn-path`'s. This module opens what it is told
//! to open, with the options it is told to use, and reports what it observes.

pub mod addr;
pub mod cmsg;
pub mod opts;

use std::sync::Arc;

use futures_core::future::BoxFuture;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use twinvpn_platform::socket::{
    Datagram, MulticastOptions, SocketCapabilities, SocketFamily, SocketProvider,
    SupportedFamilies, UdpBindSpec, UdpSocket,
};
use twinvpn_platform::PlatformError;
use twinvpn_types::{Endpoint, IpAddr};

use crate::hostcall::{RawFd, TunnelController};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// Opens UDP sockets, protected from our own tunnel.
#[derive(Debug, Clone)]
pub struct AndroidSocketProvider {
    controller: Arc<dyn TunnelController>,
    shutdown: ShutdownLatch,
}

impl AndroidSocketProvider {
    /// Builds the provider.
    #[must_use]
    pub fn new(controller: Arc<dyn TunnelController>, shutdown: ShutdownLatch) -> Self {
        Self {
            controller,
            shutdown,
        }
    }
}

/// A bound, protected UDP socket.
#[derive(Debug)]
pub struct AndroidUdpSocket {
    fd: AsyncFd<Socket>,
    family: SocketFamily,
    shutdown: ShutdownLatch,
}

impl AndroidUdpSocket {
    fn raw(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.fd.get_ref().as_raw_fd()
    }
}

impl UdpSocket for AndroidUdpSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        let local = self
            .fd
            .get_ref()
            .local_addr()
            .map_err(|e| oserr::from_errno(&e, "getsockname", Context::Socket))?;
        let std_addr = local
            .as_socket()
            .ok_or_else(|| oserr::unavailable("getsockname", libc::EAFNOSUPPORT))?;
        endpoint_from_std(std_addr)
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let target = socket2::SockAddr::from(std_from_endpoint(destination));
            loop {
                let mut ready = self
                    .fd
                    .writable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "socket.writable", Context::Socket))?;
                match ready.try_io(|inner| inner.get_ref().send_to(buf, &target)) {
                    // Stale readiness: fall out and wait again.
                    Err(_would_block) => {}
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => {
                        return Err(oserr::from_errno(&e, "sendto", Context::Socket));
                    }
                }
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            loop {
                let mut ready = self
                    .fd
                    .readable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "socket.readable", Context::Socket))?;
                let fd = self.raw();
                match ready.try_io(|_| cmsg::recvmsg(fd, buf)) {
                    Err(_would_block) => {}
                    Ok(Ok(meta)) => return datagram_from_meta(&meta),
                    Ok(Err(e)) => {
                        return Err(oserr::from_errno(&e, "recvmsg", Context::Socket));
                    }
                }
            }
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        opts::multicast(self.fd.get_ref(), options, true)
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        opts::multicast(self.fd.get_ref(), options, false)
    }

    fn family(&self) -> SocketFamily {
        self.family
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        // Idempotent by construction: the descriptor is owned by the `Socket`
        // inside the `AsyncFd` and is closed exactly once when this value drops.
        // There is nothing for a second `close` to do, and nothing for it to
        // close twice.
        Box::pin(async move { Ok(()) })
    }
}

/// Turns one `recvmsg` result into the seam's [`Datagram`].
fn datagram_from_meta(meta: &cmsg::RecvMeta) -> Result<Datagram, PlatformError> {
    let source = match meta.source {
        cmsg::SourceAddr::V4 { octets, port } => addr::v4_endpoint(octets, port),
        cmsg::SourceAddr::V6 { octets, zone, port } => addr::v6_endpoint(octets, zone, port),
    }
    .map_err(|_| oserr::unavailable("recvmsg.source", libc::EINVAL))?;

    Ok(Datagram {
        len: meta.len,
        source,
        destination: meta.destination,
        interface: meta.interface,
        truncated: meta.truncated,
    })
}

/// The seam's [`Endpoint`] from a `std` socket address.
fn endpoint_from_std(address: std::net::SocketAddr) -> Result<Endpoint, PlatformError> {
    let built = match address {
        std::net::SocketAddr::V4(v4) => addr::v4_endpoint(v4.ip().octets(), v4.port()),
        std::net::SocketAddr::V6(v6) => {
            addr::v6_endpoint(v6.ip().octets(), v6.scope_id(), v6.port())
        }
    };
    built.map_err(|_| oserr::unavailable("endpoint", libc::EINVAL))
}

/// A `std` socket address from the seam's [`Endpoint`].
fn std_from_endpoint(endpoint: &Endpoint) -> std::net::SocketAddr {
    match endpoint.address {
        IpAddr::V4(v4) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(v4.octets()),
            endpoint.port.get(),
        )),
        IpAddr::V6(v6) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(v6.octets()),
            endpoint.port.get(),
            0,
            v6.zone_index_wire(),
        )),
    }
}

impl SocketProvider for AndroidSocketProvider {
    /// **W-24's getter**, answered for Android.
    ///
    /// `reuse_port` is `SO_REUSEPORT`, which bionic has. `firewall_mark` is
    /// `false` and is the load-bearing half: `SO_MARK` needs `CAP_NET_ADMIN`,
    /// which an app does not hold, so an app cannot mark a socket at all.
    ///
    /// **KS-9c is what Android satisfies KS-9 with instead**, and the
    /// difference matters: ADR-0012 KS-9(1) originally grouped iOS and Android
    /// as *"the provider's own sockets are excluded from its own tunnel by
    /// construction"*. That is exact on iOS and the opposite of the truth here
    /// — a `VpnService` claiming `0.0.0.0/0` captures the agent's own sockets,
    /// and exclusion is an explicit `VpnService.protect(int)` per descriptor.
    /// Reporting `true` here would tell the core it could mark its way out of a
    /// capture that only `protect()` escapes.
    fn socket_capabilities(&self) -> SocketCapabilities {
        SocketCapabilities {
            reuse_port: true,
            firewall_mark: false,
        }
    }

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

            // ---- KS-9(1) on Android, before the socket can send anything ----
            //
            // Protected BEFORE bind and before any option that could cause a
            // packet: an unprotected socket in a process holding a 0.0.0.0/0
            // claim sends into our own tunnel. A protect failure closes the
            // socket (by dropping it here) rather than returning it.
            {
                use std::os::fd::AsRawFd;
                self.controller.protect_socket(socket.as_raw_fd())?;
            }

            opts::apply_options(&socket, spec.family, &spec.options)?;
            socket
                .set_nonblocking(true)
                .map_err(|e| oserr::from_errno(&e, "O_NONBLOCK", Context::Socket))?;

            if let Some(interface) = spec.options.bind_to_interface {
                // `SO_BINDTODEVICE` needs a device NAME on Linux and bionic and
                // `CAP_NET_RAW` besides, neither of which an Android app has.
                // The v6 equivalent that IS available is the scope zone on a
                // link-local address, which `V6Addr` already carries -- so an
                // interface bind is honoured through the address rather than
                // through the socket option, and is refused when it cannot be.
                let honoured = matches!(
                    spec.local.map(|e| e.address),
                    Some(IpAddr::V6(v6)) if v6.zone().map(twinvpn_types::ZoneIndex::get) == Some(interface.0)
                );
                if !honoured {
                    return Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
                        i32::try_from(interface.0).unwrap_or(i32::MAX),
                        "SO_BINDTODEVICE",
                    ))));
                }
            }

            let local = spec
                .local
                .as_ref()
                .map_or_else(|| wildcard(spec.family), std_from_endpoint);
            socket
                .bind(&socket2::SockAddr::from(local))
                .map_err(|e| oserr::from_errno(&e, "bind", Context::Socket))?;

            if let Some(multicast_options) = &spec.options.multicast {
                // Loopback is a preference, not a requirement: it is `false` in
                // production and `true` only for a single-host test, so a
                // platform that refuses it must not fail the bind. The JOIN
                // below is a requirement and its failure IS returned.
                let _ = socket.set_multicast_loop_v4(multicast_options.loopback);
                opts::multicast(&socket, multicast_options, true)?;
            }

            let fd = AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)
                .map_err(|e| oserr::from_errno(&e, "AsyncFd::new(udp)", Context::Socket))?;
            Ok(Box::new(AndroidUdpSocket {
                fd,
                family: spec.family,
                shutdown: self.shutdown.clone(),
            }) as Box<dyn UdpSocket>)
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // Probed by opening, because that is the only honest question: an
            // Android device on a v4-only carrier still has an IPv6 stack, and
            // asking the kernel whether it *has* one answers a different
            // question from whether we can *open* one.
            let v4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).is_ok();
            let v6_socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP));
            let dual = v6_socket
                .as_ref()
                .is_ok_and(|s| s.set_only_v6(false).is_ok());
            Ok(SupportedFamilies {
                v4,
                v6: v6_socket.is_ok(),
                dual_stack_socket: dual,
            })
        })
    }
}

/// The wildcard address for a family, with an ephemeral port.
fn wildcard(family: SocketFamily) -> std::net::SocketAddr {
    match family {
        SocketFamily::V4 => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )),
        SocketFamily::V6Only | SocketFamily::V6DualStack => std::net::SocketAddr::V6(
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
        ),
    }
}

#[cfg(test)]
mod tests;
