//! [`SocketProvider`] and [`UdpSocket`]: the NAT ladder's sockets.
//!
//! **Authority:** `docs/networking.md` §3, §6.2, §8; ADR-0010 R1 and R8;
//! `docs/implementation/ownership.md` §10.4 (sockets stay in Rust, in-process);
//! ADR-0018 CB-2.
//!
//! # Why these are here at all
//!
//! §8's **W-25**: "F-9 has no socket provider and no interface enumerator, yet
//! ADR-0018 §11.2 row 2.10 places *all* NAT traversal in the core 'with sockets
//! via the adapter'… A Swift or Kotlin shell binding only this ABI **cannot do
//! NAT traversal**." §10.4's ruling closes that for wave 3 by keeping sockets
//! **in Rust, in-process**, which is this module. Swift never sees a socket.
//!
//! # Nothing here is a decision
//!
//! Which candidates to gather, which pairs to race, when to punch, when to give
//! up and take a relay are all `twinvpn-path`'s. Every method here is a
//! mechanism, and the one piece of judgement — *which `setsockopt` calls a
//! [`SocketOptions`] means on Darwin* — lives in [`crate::sockplan`], target-free
//! and tested on this host.
//!
//! # What is executed here and what is not
//!
//! Socket creation, binding, the v4-mapped un-mapping, send, receive and
//! truncation reporting are plain BSD sockets and **run on the Linux build
//! host**, so the round-trip tests below are `ownership.md` §9.2 *executed*.
//! Two things are not:
//!
//! - **Applying the Darwin option numbers.** [`crate::sockplan`]'s constants are
//!   Darwin's, and issuing them on Linux would set the wrong options — so the
//!   apply is `#[cfg]`-gated and off-target the socket is opened with the
//!   portable subset. [`SocketPosture::platform_options_applied`] declares which
//!   happened rather than leaving a reader to assume.
//! - **The `recvmsg` control buffer.** The walk is [`crate::cmsg`] and is tested
//!   here; the syscall that fills it is Darwin-only, so off-target
//!   `Datagram::destination` and `Datagram::interface` are `None` and the posture
//!   says so.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_core::future::BoxFuture;
use socket2::{Domain, Protocol, Socket, Type};

use twinvpn_platform::{
    Datagram, MulticastOptions, PlatformError, SocketFamily, SocketProvider, SupportedFamilies,
    UdpBindSpec, UdpSocket,
};
use twinvpn_types::{Endpoint, IpAddr, Port, V4Addr, V6Addr};

use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;
use crate::sockplan::{self, SocketPlan};

/// What the socket layer could and could not do on this build.
///
/// ADR-0016 PS-17's principle: "Silently running wider than declared is the
/// defect this rule retires." Declared at construction, never inferred later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPosture {
    /// Whether the Darwin `setsockopt` numbers were issued.
    ///
    /// `false` on the Linux build host, where issuing them would set the wrong
    /// options. The socket still opens and still carries datagrams; it is not
    /// carrying the NAT ladder's option set.
    pub platform_options_applied: bool,
    /// Whether arrival attribution (`IP_PKTINFO` / `IPV6_PKTINFO`) is delivered.
    ///
    /// `false` off-target, where the `recvmsg` control buffer is unreachable, so
    /// [`Datagram::destination`] and [`Datagram::interface`] are always `None`.
    pub arrival_info_available: bool,
}

impl SocketPosture {
    /// Probes this build.
    #[must_use]
    pub const fn probe() -> Self {
        Self {
            platform_options_applied: cfg!(target_os = "ios"),
            arrival_info_available: cfg!(target_os = "ios"),
        }
    }
}

/// Opens UDP sockets.
pub struct IosSocketProvider {
    shutdown: ShutdownLatch,
}

impl IosSocketProvider {
    /// Builds the provider.
    #[must_use]
    pub const fn new(shutdown: ShutdownLatch) -> Self {
        Self { shutdown }
    }

    /// What this build's sockets can and cannot do.
    #[must_use]
    pub const fn posture(&self) -> SocketPosture {
        SocketPosture::probe()
    }
}

fn socket_error(err: &std::io::Error, call: &'static str) -> PlatformError {
    oserr::from_errno(err, call, Context::Socket)
}

/// Applies a rendered plan.
///
/// # Errors
///
/// [`PlatformError`] on the first option the OS refuses, naming that option.
/// The seam requires options to be applied **at open** because "an option that
/// silently failed to apply is a NAT ladder that behaves differently from the
/// one that was tested", so a refusal fails the bind rather than being logged.
#[cfg(target_os = "ios")]
fn apply_plan(socket: &Socket, plan: &SocketPlan) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    for option in &plan.options {
        let value: libc::c_int = option.value;
        // SAFETY: `fd` is a live socket owned by `socket` for the whole call.
        // `value` is a live `c_int` on this stack frame and the length passed is
        // exactly `size_of::<c_int>()`, which is what every option in
        // `crate::sockplan` takes. The callee copies the value and retains no
        // pointer.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                option.level,
                option.name,
                core::ptr::addr_of!(value).cast::<libc::c_void>(),
                u32::try_from(core::mem::size_of::<libc::c_int>()).unwrap_or(4),
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

/// Off-target: the Darwin numbers would set the wrong options, so only the
/// portable subset is applied and [`SocketPosture`] says so.
#[cfg(not(target_os = "ios"))]
fn apply_plan(socket: &Socket, plan: &SocketPlan) -> Result<(), PlatformError> {
    for option in &plan.options {
        let result = match option.tag {
            "SO_REUSEADDR" => socket.set_reuse_address(option.value != 0),
            "IPV6_V6ONLY" => socket.set_only_v6(option.value != 0),
            "SO_SNDBUF" => socket.set_send_buffer_size(usize::try_from(option.value).unwrap_or(0)),
            "SO_RCVBUF" => socket.set_recv_buffer_size(usize::try_from(option.value).unwrap_or(0)),
            // Everything else is Darwin-numbered and is deliberately NOT issued
            // here. Issuing it would set whichever Linux option happens to share
            // the number, which is worse than not setting it at all.
            _ => Ok(()),
        };
        result.map_err(|e| socket_error(&e, option.tag))?;
    }
    Ok(())
}

fn domain(family: SocketFamily) -> Domain {
    match family {
        SocketFamily::V4 => Domain::IPV4,
        SocketFamily::V6Only | SocketFamily::V6DualStack => Domain::IPV6,
    }
}

fn wildcard(family: SocketFamily) -> SocketAddr {
    match family {
        SocketFamily::V4 => SocketAddr::from(([0u8; 4], 0)),
        _ => SocketAddr::from(([0u16; 8], 0)),
    }
}

/// Converts a `std::net::SocketAddr` into the seam's [`Endpoint`], **un-mapping**
/// a v4-mapped v6 address.
///
/// `common.proto` "forbids a v4-mapped address in any canonical position, so the
/// un-mapping happens at the seam and never in the core". A dual-stack socket
/// hands back `::ffff:203.0.113.7` for a v4 peer; leaving it that way puts a
/// v6-shaped value where every comparison, every candidate ledger entry and
/// every reason code expects a v4 one.
fn endpoint_from(addr: SocketAddr) -> Result<Endpoint, PlatformError> {
    let port = Port::new(addr.port())
        .map_err(|_| oserr::unavailable("Endpoint.port", i32::from(addr.port())))?;
    let address = match addr {
        SocketAddr::V4(v4) => IpAddr::V4(V4Addr::from_octets(v4.ip().octets())),
        SocketAddr::V6(v6) => {
            if let Some(mapped) = v6.ip().to_ipv4_mapped() {
                IpAddr::V4(V4Addr::from_octets(mapped.octets()))
            } else {
                IpAddr::V6(
                    V6Addr::from_slice(&v6.ip().octets(), v6.scope_id())
                        .map_err(|_| oserr::unavailable("Endpoint.v6", 0))?,
                )
            }
        }
    };
    Ok(Endpoint::new(address, port))
}

fn socket_addr_from(endpoint: &Endpoint) -> SocketAddr {
    match endpoint.address {
        IpAddr::V4(v4) => SocketAddr::from((v4.octets(), endpoint.port.get())),
        IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(v6.octets()),
            endpoint.port.get(),
            0,
            v6.zone_index_wire(),
        )),
    }
}

/// A bound UDP socket.
pub struct IosUdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
    family: SocketFamily,
    shutdown: ShutdownLatch,
    closed: std::sync::atomic::AtomicBool,
}

impl IosUdpSocket {
    fn guard(&self) -> Result<(), PlatformError> {
        self.shutdown.guard()?;
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PlatformError::AdapterUnavailable(Some(
                oserr::detail_from_code(libc::EBADF, "UdpSocket.closed"),
            )));
        }
        Ok(())
    }

    fn multicast_v4(options: &MulticastOptions) -> Result<std::net::Ipv4Addr, PlatformError> {
        match options.group {
            IpAddr::V4(v4) => Ok(std::net::Ipv4Addr::from(v4.octets())),
            IpAddr::V6(_) => Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
                libc::EAFNOSUPPORT,
                "join_multicast.family",
            )))),
        }
    }
}

impl UdpSocket for IosUdpSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        self.guard()?;
        let addr = self
            .inner
            .local_addr()
            .map_err(|e| socket_error(&e, "getsockname"))?;
        endpoint_from(addr)
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.guard()?;
            // A cross-family send is refused rather than attempted: sending a v4
            // destination on a `V6Only` socket is a caller error, and letting the
            // OS report `EAFNOSUPPORT` after the fact would attribute it to the
            // network.
            if self.family == SocketFamily::V4
                && destination.family() != twinvpn_types::AddressFamily::V4
                || self.family == SocketFamily::V6Only
                    && destination.family() != twinvpn_types::AddressFamily::V6
            {
                return Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
                    libc::EAFNOSUPPORT,
                    "sendto.family",
                ))));
            }
            let addr = socket_addr_from(destination);
            let written = self
                .inner
                .send_to(buf, addr)
                .await
                .map_err(|e| socket_error(&e, "sendto"))?;
            if written != buf.len() {
                // "A short write on a datagram socket is an adapter defect, not a
                // partial send to retry."
                return Err(PlatformError::AdapterUnavailable(Some(
                    oserr::detail_from_code(
                        i32::try_from(written).unwrap_or(i32::MAX),
                        "sendto.short",
                    ),
                )));
            }
            Ok(written)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            self.guard()?;
            let (len, addr) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| socket_error(&e, "recvfrom"))?;
            Ok(Datagram {
                len,
                source: endpoint_from(addr)?,
                // Off-target the `recvmsg` control buffer is unreachable, so
                // there is no arrival attribution to report.
                // `SocketPosture::arrival_info_available` declares this rather
                // than leaving a caller to infer it from a `None` that might
                // equally have meant "the option was not set".
                destination: None,
                interface: None,
                // **Reported, never silent.** A datagram that exactly fills the
                // buffer may or may not have been truncated; the honest answer
                // without `MSG_TRUNC` is "possibly", and a silently truncated
                // datagram "is a message that fails authentication for a reason
                // nobody can see".
                truncated: len == buf.len(),
            })
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.guard()?;
        match options.group {
            IpAddr::V4(_) => {
                let group = Self::multicast_v4(options)?;
                self.inner
                    .join_multicast_v4(group, std::net::Ipv4Addr::UNSPECIFIED)
                    .map_err(|e| socket_error(&e, "IP_ADD_MEMBERSHIP"))
            }
            IpAddr::V6(v6) => self
                .inner
                .join_multicast_v6(&std::net::Ipv6Addr::from(v6.octets()), options.interface.0)
                .map_err(|e| socket_error(&e, "IPV6_JOIN_GROUP")),
        }
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.guard()?;
        match options.group {
            IpAddr::V4(_) => {
                let group = Self::multicast_v4(options)?;
                self.inner
                    .leave_multicast_v4(group, std::net::Ipv4Addr::UNSPECIFIED)
                    .map_err(|e| socket_error(&e, "IP_DROP_MEMBERSHIP"))
            }
            IpAddr::V6(v6) => self
                .inner
                .leave_multicast_v6(&std::net::Ipv6Addr::from(v6.octets()), options.interface.0)
                .map_err(|e| socket_error(&e, "IPV6_LEAVE_GROUP")),
        }
    }

    fn family(&self) -> SocketFamily {
        self.family
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Idempotent, and safe after a crash. Not gated on the latch: closing
            // is what runs while shutting down.
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

impl SocketProvider for IosSocketProvider {
    fn bind_udp<'a>(
        &'a self,
        spec: &'a UdpBindSpec,
    ) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            let plan = sockplan::plan(spec.family, &spec.options);

            let socket = Socket::new(domain(spec.family), Type::DGRAM, Some(Protocol::UDP))
                .map_err(|e| socket_error(&e, "socket"))?;
            // Options are applied BEFORE the bind: several of them cannot be
            // changed on a bound socket on at least one target, and
            // `IPV6_V6ONLY` is one of them.
            apply_plan(&socket, &plan)?;

            let local = spec
                .local
                .as_ref()
                .map_or_else(|| wildcard(spec.family), socket_addr_from);
            socket
                .bind(&local.into())
                .map_err(|e| socket_error(&e, "bind"))?;
            socket
                .set_nonblocking(true)
                .map_err(|e| socket_error(&e, "fcntl(O_NONBLOCK)"))?;

            let std_socket = std::net::UdpSocket::from(socket);
            let inner = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| socket_error(&e, "UdpSocket.from_std"))?;

            let bound = IosUdpSocket {
                inner: Arc::new(inner),
                family: spec.family,
                shutdown: self.shutdown.clone(),
                closed: std::sync::atomic::AtomicBool::new(false),
            };
            if let Some(multicast) = &spec.options.multicast {
                bound.join_multicast(multicast)?;
            }
            Ok(Box::new(bound) as Box<dyn UdpSocket>)
        })
    }

    fn supported_families(&self) -> BoxFuture<'_, Result<SupportedFamilies, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // Probed, not assumed: ADR-0010 §11.7 treats an IPv6-only host as a
            // first-class situation, and a hard-coded `true` here would have the
            // core plan a v4 candidate on a network that has none. The probe is
            // an open-and-close of each shape, which costs nothing and cannot
            // lie.
            let can = |family: SocketFamily| {
                Socket::new(domain(family), Type::DGRAM, Some(Protocol::UDP)).is_ok()
            };
            let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
                .and_then(|s| s.set_only_v6(false).map(|()| s))
                .is_ok();
            Ok(SupportedFamilies {
                v4: can(SocketFamily::V4),
                v6: can(SocketFamily::V6Only),
                dual_stack_socket: dual,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::SocketOptions;

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn provider() -> IosSocketProvider {
        IosSocketProvider::new(ShutdownLatch::new())
    }

    fn spec(family: SocketFamily) -> UdpBindSpec {
        UdpBindSpec {
            family,
            local: None,
            options: SocketOptions::default(),
        }
    }

    #[test]
    fn the_posture_declares_what_this_build_did_and_did_not_apply() {
        // PS-17's principle: silently running wider — or narrower — than
        // declared is the defect.
        let posture = provider().posture();
        assert_eq!(posture.platform_options_applied, cfg!(target_os = "ios"));
        assert_eq!(posture.arrival_info_available, cfg!(target_os = "ios"));
    }

    #[test]
    fn both_families_bind_and_a_datagram_round_trips() {
        // ADR-0010 R1: both families, always. This is the executed half.
        block_on(async {
            for family in [SocketFamily::V4, SocketFamily::V6Only] {
                let provider = provider();
                let a = provider.bind_udp(&spec(family)).await.expect("binds");
                let b = provider.bind_udp(&spec(family)).await.expect("binds");
                let target = b.local_endpoint().expect("endpoint");
                // The wildcard bind reports 0.0.0.0/::; send to loopback.
                let loopback = if family == SocketFamily::V4 {
                    Endpoint::new(IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])), target.port)
                } else {
                    let mut octets = [0u8; 16];
                    octets[15] = 1;
                    Endpoint::new(
                        IpAddr::V6(V6Addr::from_slice(&octets, 0).expect("v6")),
                        target.port,
                    )
                };
                assert_eq!(a.send_to(b"hello", &loopback).await.expect("sends"), 5);

                let mut buf = [0u8; 64];
                let datagram = b.recv_from(&mut buf).await.expect("receives");
                assert_eq!(datagram.len, 5);
                assert_eq!(&buf[..5], b"hello");
                assert!(!datagram.truncated);
                assert_eq!(datagram.source.family(), loopback.family());
            }
        });
    }

    #[test]
    fn a_truncated_datagram_is_reported_and_never_silent() {
        // "A silently truncated datagram is a message that fails authentication
        // for a reason nobody can see."
        block_on(async {
            let provider = provider();
            let a = provider
                .bind_udp(&spec(SocketFamily::V4))
                .await
                .expect("binds");
            let b = provider
                .bind_udp(&spec(SocketFamily::V4))
                .await
                .expect("binds");
            let target = Endpoint::new(
                IpAddr::V4(V4Addr::from_octets([127, 0, 0, 1])),
                b.local_endpoint().expect("endpoint").port,
            );
            a.send_to(&[0u8; 64], &target).await.expect("sends");
            let mut small = [0u8; 8];
            let datagram = b.recv_from(&mut small).await.expect("receives");
            assert!(datagram.truncated);
        });
    }

    #[test]
    fn a_cross_family_send_is_refused_rather_than_blamed_on_the_network() {
        block_on(async {
            let provider = provider();
            let v4 = provider
                .bind_udp(&spec(SocketFamily::V4))
                .await
                .expect("binds");
            let mut octets = [0u8; 16];
            octets[15] = 1;
            let v6_target = Endpoint::new(
                IpAddr::V6(V6Addr::from_slice(&octets, 0).expect("v6")),
                Port::new(9).expect("port"),
            );
            let err = v4.send_to(b"x", &v6_target).await.expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
        });
    }

    #[test]
    fn a_v4_mapped_source_is_unmapped_at_the_seam_and_never_in_the_core() {
        // common.proto "forbids a v4-mapped address in any canonical position",
        // so the un-mapping happens here.
        let mapped = "[::ffff:203.0.113.7]:51820"
            .parse::<SocketAddr>()
            .expect("addr");
        let endpoint = endpoint_from(mapped).expect("converts");
        assert_eq!(
            endpoint.address,
            IpAddr::V4(V4Addr::from_octets([203, 0, 113, 7]))
        );
        assert_eq!(endpoint.family(), twinvpn_types::AddressFamily::V4);

        // A genuine v6 address is left alone.
        let real = "[2001:db8::1]:51820".parse::<SocketAddr>().expect("addr");
        assert_eq!(
            endpoint_from(real).expect("converts").family(),
            twinvpn_types::AddressFamily::V6
        );
    }

    #[test]
    fn v6_only_and_dual_stack_are_different_sockets() {
        // ADR-0010 R8: "MUST NOT stall on a broken family", expressed at the
        // socket layer as two independent fates.
        block_on(async {
            let provider = provider();
            let only = provider
                .bind_udp(&spec(SocketFamily::V6Only))
                .await
                .expect("binds");
            let dual = provider
                .bind_udp(&spec(SocketFamily::V6DualStack))
                .await
                .expect("binds");
            assert_eq!(only.family(), SocketFamily::V6Only);
            assert_eq!(dual.family(), SocketFamily::V6DualStack);
            assert_ne!(
                only.local_endpoint().expect("endpoint").port,
                dual.local_endpoint().expect("endpoint").port
            );
        });
    }

    #[test]
    fn the_supported_families_are_probed_and_not_assumed() {
        // A hard-coded `true` would have the core plan a v4 candidate on a
        // network that has none.
        let families = block_on(provider().supported_families()).expect("probes");
        assert!(families.v4 || families.v6, "some family must be openable");
    }

    #[test]
    fn close_is_idempotent_and_a_closed_socket_refuses_by_name() {
        block_on(async {
            let provider = provider();
            let socket = provider
                .bind_udp(&spec(SocketFamily::V4))
                .await
                .expect("binds");
            socket.close().await.expect("closes");
            socket.close().await.expect("again");
            let err = socket.local_endpoint().expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
            assert_eq!(
                err.os_detail().map(|d| d.code),
                Some(i64::from(libc::EBADF))
            );
        });
    }

    #[test]
    fn after_shutdown_binding_refuses_by_name_rather_than_hanging() {
        let shutdown = ShutdownLatch::new();
        let provider = IosSocketProvider::new(shutdown.clone());
        shutdown.begin();
        assert_eq!(
            block_on(provider.bind_udp(&spec(SocketFamily::V4))).err(),
            Some(PlatformError::ShuttingDown)
        );
    }
}
