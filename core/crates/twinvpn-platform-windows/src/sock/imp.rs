//! The Winsock shim: the only part of [`crate::sock`] that needs Windows.
//!
//! **Authority:** ADR-0018 DP-4 (this crate is on the `unsafe` allowlist), CB-3;
//! [`twinvpn_platform::socket`]'s cancellation, timeout and shutdown contract.
//!
//! # What is here, and what is deliberately not
//!
//! Everything above this module — which option to set, how to render a
//! `sockaddr`, how to walk a control buffer, what a status number means — is in
//! [`crate::sock`] and [`crate::oserr`], target-free and tested on the Linux host
//! this crate was written on. What is here is the calls themselves, and
//! **none of it has ever executed**: `make cross-check` type-checks it against
//! the real `windows-sys` and that is a compile proof, not a behaviour proof.
//!
//! # `tokio` where it suffices, `windows-sys` where it does not
//!
//! `tokio::net::UdpSocket` owns the readiness loop, so no call here occupies an
//! executor thread and dropping a future releases the readiness guard with no
//! syscall in flight — the seam's cancellation contract, obtained rather than
//! re-implemented. `send_to` and the plain `recv_from` are tokio's.
//!
//! Two things tokio cannot do, and each is why the raw path exists:
//!
//! - **Options must be applied at open, before `bind`.** `IPV6_V6ONLY` cannot be
//!   changed on a bound socket, and `SocketOptions`' own documentation says an
//!   option that silently failed to apply "is a NAT ladder that behaves
//!   differently from the one that was tested". So the socket is created with
//!   `WSASocketW`, configured, and only then bound and handed to tokio.
//! - **`IP_PKTINFO` needs `WSARecvMsg`.** `recvfrom` cannot report which of our
//!   addresses a datagram arrived on, which is what `docs/networking.md` §3.4's
//!   disco probe needs to attribute a reflexive candidate correctly.
//!
//! # The seven `unsafe` blocks
//!
//! | Where | What |
//! |---|---|
//! | [`create_socket`] | `WSASocketW` — returns a fresh owned handle |
//! | [`set_option`] | the single `setsockopt` call site |
//! | [`bind_socket`] | `bind` over a live buffer of its declared length |
//! | [`load_recvmsg`] | `WSAIoctl` writing one function pointer |
//! | [`adopt`] | `from_raw_socket`, taking ownership of a handle nothing else holds |
//! | [`recv_msg`] | `WSARecvMsg` over live buffers of their declared lengths |
//! | [`close_socket`] | `closesocket`, guarded so it runs at most once |

use std::os::windows::io::{AsRawSocket, FromRawSocket};

use futures_core::future::BoxFuture;
use tokio::io::Interest;
use twinvpn_platform::{
    Datagram, MulticastOptions, PlatformError, SocketFamily, SupportedFamilies, UdpBindSpec,
    UdpSocket,
};
use twinvpn_types::{Endpoint, IpAddr, ZoneIndex};
use windows_sys::Win32::Networking::WinSock as ws;

use super::{
    assemble_datagram, families_from_probe, parse_pktinfo, parse_sockaddr, render_join,
    render_leave, render_sockaddr, render_wildcard, OptionProgramme, RawSockAddr, SockOpt,
    SocketState, SOCKADDR_MAX,
};
use crate::oserr::{self, Context, Win32Error};
use crate::shutdown::ShutdownLatch;

/// How much room the control buffer gets.
///
/// **A decision recorded as one.** `IN6_PKTINFO` plus its header is 36 bytes on
/// a 64-bit host; 256 leaves room for whatever else the stack chooses to attach
/// without the walk ever having to deal with a truncated control block. A
/// too-small control buffer sets `MSG_CTRUNC` and drops the packet info
/// silently, which would make a reflexive candidate unattributable for a reason
/// nobody could see.
const CONTROL_BYTES: usize = 256;

/// A `sockaddr` buffer with a `sockaddr`'s alignment.
///
/// [`render_sockaddr`] returns plain bytes so that its tests can read them, and
/// a `[u8; 28]` is only byte-aligned. Handing Winsock a `SOCKADDR *` that points
/// at an odd address is undefined behaviour on a platform that cares, so the
/// bytes are copied into this before the pointer is taken — the cast is then
/// from an 8-aligned pointee and is sound by construction rather than by luck.
#[repr(C, align(8))]
struct Aligned([u8; SOCKADDR_MAX]);

/// The last Winsock error, as a named condition.
fn last_error(call: &'static str) -> PlatformError {
    // SAFETY: `WSAGetLastError` reads thread-local state and touches no pointer
    // this crate supplies. It is sound to call at any time.
    let status = unsafe { ws::WSAGetLastError() };
    oserr::from_status(Win32Error::from_i32(status), call, Context::Socket)
}

/// Opens one raw datagram socket.
fn create_socket(family: SocketFamily) -> Result<ws::SOCKET, PlatformError> {
    let af = match family {
        SocketFamily::V4 => i32::from(ws::AF_INET),
        SocketFamily::V6Only | SocketFamily::V6DualStack => i32::from(ws::AF_INET6),
    };
    // SAFETY: every argument is a plain integer except `lpprotocolinfo`, which
    // is documented to accept a null pointer meaning "no template". The call
    // returns a fresh handle this function then owns; nothing else refers to it.
    let socket = unsafe {
        ws::WSASocketW(
            af,
            ws::SOCK_DGRAM,
            ws::IPPROTO_UDP,
            std::ptr::null(),
            0,
            ws::WSA_FLAG_OVERLAPPED,
        )
    };
    if socket == ws::INVALID_SOCKET {
        return Err(last_error("WSASocketW"));
    }
    Ok(socket)
}

/// Closes a socket. Guarded by the caller so it runs at most once.
fn close_socket(socket: ws::SOCKET) {
    // SAFETY: `socket` is a handle this crate opened and has not yet closed —
    // the callers each hold it exclusively at this point. `closesocket` takes
    // ownership; the handle is not used again.
    unsafe {
        ws::closesocket(socket);
    }
}

/// The single `setsockopt` call site in this crate.
fn set_option(socket: ws::SOCKET, option: &SockOpt) -> Result<(), PlatformError> {
    let value = option.value.as_bytes();
    let len = i32::try_from(value.len()).unwrap_or(0);
    // SAFETY: `socket` is a live handle the caller owns for the whole call.
    // `value` is a live slice and `len` is its true byte length, which is the
    // width the named option expects — the widths are chosen by
    // `crate::sock::render_options` and checked by its tests. `setsockopt`
    // copies out of the pointer and retains nothing.
    let rc = unsafe { ws::setsockopt(socket, option.level, option.name, value.as_ptr(), len) };
    if rc == ws::SOCKET_ERROR {
        // KS-12's discipline generalised: an option that did not apply is
        // returned, never logged and swallowed.
        return Err(last_error(option.call));
    }
    Ok(())
}

/// Binds the socket to its local address, or to the family's wildcard.
fn bind_socket(socket: ws::SOCKET, spec: &UdpBindSpec) -> Result<(), PlatformError> {
    let (bytes, len) = match spec.local {
        Some(endpoint) => render_sockaddr(endpoint),
        None => render_wildcard(spec.family),
    };
    let aligned = Aligned(bytes);
    // SAFETY: `aligned` is a live 28-byte buffer at `sockaddr` alignment, and
    // `len` is the length the renderer declared for the family it wrote — 16 for
    // `SOCKADDR_IN` and 28 for `SOCKADDR_IN6`, both within the buffer. `bind`
    // reads that many bytes and retains nothing.
    let rc = unsafe { ws::bind(socket, (&raw const aligned).cast::<ws::SOCKADDR>(), len) };
    if rc == ws::SOCKET_ERROR {
        return Err(last_error("bind"));
    }
    Ok(())
}

/// Puts the socket into non-blocking mode, so tokio's readiness drives it.
fn set_nonblocking(socket: ws::SOCKET) -> Result<(), PlatformError> {
    let mut one: u32 = 1;
    // SAFETY: `argp` must point at a live `u_long` for the duration of the
    // call; `one` is a local that outlives it. `FIONBIO` reads the value and
    // writes nothing back.
    let rc = unsafe { ws::ioctlsocket(socket, ws::FIONBIO, &raw mut one) };
    if rc == ws::SOCKET_ERROR {
        return Err(last_error("FIONBIO"));
    }
    Ok(())
}

/// Retrieves the `WSARecvMsg` entry point, which is not exported by `ws2_32`.
fn load_recvmsg(socket: ws::SOCKET) -> Result<ws::LPFN_WSARECVMSG, PlatformError> {
    let guid = ws::WSAID_WSARECVMSG;
    let mut function: ws::LPFN_WSARECVMSG = None;
    let mut returned: u32 = 0;
    let guid_len = u32::try_from(size_of::<windows_sys::core::GUID>()).unwrap_or(16);
    let out_len = u32::try_from(size_of::<ws::LPFN_WSARECVMSG>()).unwrap_or(8);
    // SAFETY: `guid` and `function` are live locals of exactly the declared
    // lengths, `returned` is a live `u32`, and the overlapped and completion
    // arguments are null/None which `SIO_GET_EXTENSION_FUNCTION_POINTER`
    // documents as the synchronous form. The call writes one function pointer
    // into `function` and nothing else.
    let rc = unsafe {
        ws::WSAIoctl(
            socket,
            ws::SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&raw const guid).cast::<core::ffi::c_void>(),
            guid_len,
            (&raw mut function).cast::<core::ffi::c_void>(),
            out_len,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == ws::SOCKET_ERROR {
        return Err(last_error("SIO_GET_EXTENSION_FUNCTION_POINTER"));
    }
    Ok(function)
}

/// Which socket shapes this host can open.
pub(super) fn probe_families() -> SupportedFamilies {
    let can_open = |family| match create_socket(family) {
        Ok(socket) => {
            close_socket(socket);
            true
        }
        Err(_) => false,
    };
    families_from_probe(can_open(SocketFamily::V4), can_open(SocketFamily::V6Only))
}

/// Opens, configures, binds and adopts one socket.
pub(super) fn bind<'a>(
    spec: &'a UdpBindSpec,
    programme: &'a OptionProgramme,
    shutdown: ShutdownLatch,
) -> BoxFuture<'a, Result<Box<dyn UdpSocket>, PlatformError>> {
    Box::pin(async move {
        let socket = create_socket(spec.family)?;
        // From here every failure path must close the handle: a leaked socket
        // holds a port that the birthday-paradox gathering of §3.6 will try to
        // reuse, and the leak would look like port exhaustion.
        let configured = (|| -> Result<(), PlatformError> {
            for option in &programme.calls {
                set_option(socket, option)?;
            }
            set_nonblocking(socket)?;
            bind_socket(socket, spec)?;
            // Joins happen after bind: a join on an unbound socket is refused,
            // and LAN discovery's whole point is knowing which segment an
            // announcement came from.
            if let Some(multicast) = &spec.options.multicast {
                for option in render_join(multicast) {
                    set_option(socket, &option)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = configured {
            close_socket(socket);
            return Err(error);
        }

        let recvmsg = if spec.options.receive_packet_info {
            match load_recvmsg(socket) {
                Ok(function) => function,
                Err(error) => {
                    close_socket(socket);
                    return Err(error);
                }
            }
        } else {
            None
        };

        let io = match adopt(socket) {
            Ok(io) => io,
            Err(error) => {
                close_socket(socket);
                return Err(error);
            }
        };

        Ok(Box::new(WindowsUdpSocket {
            io,
            recvmsg,
            state: SocketState::new(spec.family, spec.options.receive_packet_info, shutdown),
        }) as Box<dyn UdpSocket>)
    })
}

/// Hands the configured handle to tokio.
fn adopt(socket: ws::SOCKET) -> Result<tokio::net::UdpSocket, PlatformError> {
    let raw = u64::try_from(socket).map_err(|_| oserr::unavailable("SOCKET"))?;
    // SAFETY: `socket` is a handle this function's caller owns and does not use
    // again — ownership transfers here, and the caller's error paths run only
    // when this call has not been reached. The handle is a bound, non-blocking
    // datagram socket, which is what `UdpSocket` requires.
    let std_socket = unsafe { std::net::UdpSocket::from_raw_socket(raw) };
    tokio::net::UdpSocket::from_std(std_socket).map_err(|e| map_io(&e, "UdpSocket::from_std"))
}

/// An `io::Error` from tokio, as a named condition.
fn map_io(error: &std::io::Error, call: &'static str) -> PlatformError {
    let raw = error.raw_os_error().unwrap_or(0);
    oserr::from_status(Win32Error::from_i32(raw), call, Context::Socket)
}

/// A bound Windows UDP socket.
struct WindowsUdpSocket {
    io: tokio::net::UdpSocket,
    /// `None` when the caller did not ask for packet info, so a `Datagram`'s
    /// absent destination is because it was not requested rather than because
    /// the control walk quietly found nothing.
    recvmsg: ws::LPFN_WSARECVMSG,
    state: SocketState,
}

impl WindowsUdpSocket {
    /// The handle, narrowed once rather than at every call site.
    fn raw(&self) -> ws::SOCKET {
        ws::SOCKET::try_from(self.io.as_raw_socket()).unwrap_or(ws::INVALID_SOCKET)
    }

    /// One `WSARecvMsg`, on a socket tokio has already reported readable.
    fn recv_msg(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, RawSockAddr, bool, Option<super::PktInfo>)> {
        let Some(recvmsg) = self.recvmsg else {
            return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        };
        let mut name = Aligned([0u8; SOCKADDR_MAX]);
        let mut control = [0u8; CONTROL_BYTES];
        let mut wsabuf = ws::WSABUF {
            len: u32::try_from(buf.len()).unwrap_or(u32::MAX),
            buf: buf.as_mut_ptr(),
        };
        let mut msg = ws::WSAMSG {
            name: (&raw mut name).cast::<ws::SOCKADDR>(),
            namelen: i32::try_from(SOCKADDR_MAX).unwrap_or(28),
            lpBuffers: &raw mut wsabuf,
            dwBufferCount: 1,
            Control: ws::WSABUF {
                len: u32::try_from(control.len()).unwrap_or(0),
                buf: control.as_mut_ptr(),
            },
            dwFlags: 0,
        };
        let mut received: u32 = 0;
        // SAFETY: every pointer in `msg` refers to a local that outlives the
        // call, and every declared length is the true length of the buffer it
        // describes. The overlapped and completion arguments are null/None,
        // which is the synchronous form; the socket is non-blocking, so the call
        // either completes or reports `WSAEWOULDBLOCK` and writes nothing.
        let rc = unsafe {
            recvmsg(
                self.raw(),
                &raw mut msg,
                &raw mut received,
                std::ptr::null_mut(),
                None,
            )
        };
        if rc == ws::SOCKET_ERROR {
            // SAFETY: as in `last_error` — thread-local state only.
            let status = unsafe { ws::WSAGetLastError() };
            return Err(std::io::Error::from_raw_os_error(status));
        }
        let len = usize::try_from(received).unwrap_or(0);
        let truncated = msg.dwFlags & ws::MSG_TRUNC != 0;
        let namelen = usize::try_from(msg.namelen).unwrap_or(0).min(SOCKADDR_MAX);
        let source = parse_sockaddr(&name.0[..namelen], "WSARecvMsg")
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        // A truncated control block means the packet info was dropped, so the
        // walk is not run over a partial datum: `MSG_CTRUNC` is the stack saying
        // "there was more", and inventing an interface from what fits would
        // attribute a reflexive candidate to the wrong link.
        let control_len = usize::try_from(msg.Control.len)
            .unwrap_or(0)
            .min(CONTROL_BYTES);
        let info = if msg.dwFlags & ws::MSG_CTRUNC == 0 {
            parse_pktinfo(&control[..control_len], size_of::<usize>())
        } else {
            None
        };
        Ok((len, source, truncated, info))
    }
}

impl UdpSocket for WindowsUdpSocket {
    fn local_endpoint(&self) -> Result<Endpoint, PlatformError> {
        self.state.check("getsockname")?;
        let address = self
            .io
            .local_addr()
            .map_err(|e| map_io(&e, "getsockname"))?;
        super::endpoint_from_raw(raw_from_std(address), "getsockname")
    }

    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        destination: &'a Endpoint,
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.state.check("sendto")?;
            // No deadline: timeouts are the core's, composed from
            // `twinvpn_env::Timer`. Dropping this future cancels the send with
            // no syscall in flight.
            let written = self
                .io
                .send_to(buf, std_from_endpoint(*destination))
                .await
                .map_err(|e| map_io(&e, "sendto"))?;
            Ok(written)
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<Datagram, PlatformError>> {
        Box::pin(async move {
            self.state.check("recvfrom")?;
            if !self.state.want_pktinfo() {
                let (len, source) = self
                    .io
                    .recv_from(buf)
                    .await
                    .map_err(|e| map_io(&e, "recvfrom"))?;
                return assemble_datagram(len, raw_from_std(source), None, false, "recvfrom");
            }
            loop {
                self.io
                    .readable()
                    .await
                    .map_err(|e| map_io(&e, "readable"))?;
                match self.io.try_io(Interest::READABLE, || self.recv_msg(buf)) {
                    Ok((len, source, truncated, info)) => {
                        return assemble_datagram(len, source, info, truncated, "WSARecvMsg");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(map_io(&e, "WSARecvMsg")),
                }
            }
        })
    }

    fn join_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.state.check("IP_ADD_MEMBERSHIP")?;
        let socket = self.raw();
        for option in render_join(options) {
            set_option(socket, &option)?;
        }
        Ok(())
    }

    fn leave_multicast(&self, options: &MulticastOptions) -> Result<(), PlatformError> {
        self.state.check("IP_DROP_MEMBERSHIP")?;
        set_option(self.raw(), &render_leave(options))
    }

    fn family(&self) -> SocketFamily {
        self.state.family()
    }

    fn close(&self) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Idempotent, and safe after a crash: the flag is what makes a
            // second call a no-op rather than a double close. The handle itself
            // is dropped with `self.io`, so nothing here closes it twice.
            let _ = self.state.close();
            Ok(())
        })
    }
}

/// A `std` socket address as the plain shape the conversions take.
fn raw_from_std(address: std::net::SocketAddr) -> RawSockAddr {
    match address {
        std::net::SocketAddr::V4(v4) => RawSockAddr::V4 {
            octets: v4.ip().octets(),
            port: v4.port(),
        },
        std::net::SocketAddr::V6(v6) => RawSockAddr::V6 {
            octets: v6.ip().octets(),
            port: v6.port(),
            scope_id: v6.scope_id(),
        },
    }
}

/// A canonical endpoint as `std`'s.
fn std_from_endpoint(endpoint: Endpoint) -> std::net::SocketAddr {
    match endpoint.address {
        IpAddr::V4(a) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(a.octets()),
            endpoint.port.get(),
        )),
        IpAddr::V6(a) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(a.octets()),
            endpoint.port.get(),
            0,
            a.zone().map_or(0, ZoneIndex::get),
        )),
    }
}
