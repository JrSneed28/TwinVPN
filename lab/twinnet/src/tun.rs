//! A real TUN device, and the smallest real tunnel that can carry protected
//! traffic off an interface.
//!
//! **Why the laboratory needs a tunnel of its own.** The fail-closed oracle in
//! [`crate::observer`] asks one question: *did protected addressing appear in
//! the clear on the underlay?* That question has no meaning unless there is a
//! path on which protected addressing is supposed to travel, and a route that
//! sends it there. A TUN device with a route pointed at it is that path, and it
//! is a real one: the kernel makes the routing decision, the kernel writes the
//! packet, and nothing in the test can make a packet appear or disappear.
//!
//! # What this tunnel is and is not
//!
//! It is a real datagram tunnel: real routing, real encapsulation, real UDP on
//! the underlay. It is **not** a cryptographic one — it does not implement
//! ADR-0001, and CD-I2 forbids a second cryptographic implementation anyway.
//!
//! The consequence is stated rather than left to be assumed: this tunnel makes
//! **encapsulation** real, so the oracle's question "did a protected address
//! appear as an outer source or destination" is answered by the wire. It does
//! **not** make confidentiality real, so no test built on it may claim the
//! payload was unreadable. That claim belongs to the product's own tunnel and to
//! `tests/integration/tunnel_wire_agreement.rs`.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{NetError, Result};

/// `IFF_TUN | IFF_NO_PI` — a layer-3 device with no packet-information prefix,
/// so what is read is exactly an IP packet.
const IFF_TUN_NO_PI: libc::c_short = 0x0001 | 0x1000;
/// `TUNSETIFF`.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Opens `/dev/net/tun` and attaches it to a device named `name`.
///
/// The device comes up unconfigured: addressing and routing are the fabric's
/// job, because a tunnel that configured its own routes would be a tunnel whose
/// routing table the test could not state.
///
/// # Errors
///
/// [`NetError::Unavailable`] if `/dev/net/tun` is absent or refused — a host
/// without it cannot run a tunnel scenario, and that must be reported as a
/// missing facility rather than as a sealed tunnel.
pub fn open(name: &str) -> Result<File> {
    if name.len() >= 16 {
        return Err(NetError::Malformed(format!(
            "`{name}` is too long for an interface name"
        )));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| NetError::Unavailable {
            facility: "tun",
            detail: format!("/dev/net/tun could not be opened: {e}"),
        })?;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req = IfReq {
        name: [0; 16],
        flags: IFF_TUN_NO_PI,
        _pad: [0; 22],
    };
    let cname = CString::new(name)
        .map_err(|_| NetError::Malformed(format!("interface name `{name}` contains a nul")))?;
    for (slot, byte) in req.name.iter_mut().zip(cname.as_bytes()) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `req` is a correctly sized `ifreq` on this stack frame and the
    // descriptor is one this function just opened. `TUNSETIFF` reads the
    // structure and does not retain the pointer.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, std::ptr::addr_of_mut!(req)) };
    if rc != 0 {
        return Err(NetError::Unavailable {
            facility: "tun",
            detail: format!(
                "TUNSETIFF for `{name}` failed: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    Ok(file)
}

/// Runs a datagram tunnel between a TUN device and a UDP endpoint.
///
/// Every IP packet the kernel routes into `dev` is sent to the peer as a UDP
/// payload; every payload received is written back into `dev`.
///
/// # Learning the peer
///
/// `peer` is `None` for the far end of a tunnel whose near end is behind a NAT.
/// The near end's *mapped* endpoint is allocated by the middlebox and cannot be
/// configured in advance — that is what a NAT is — so the far end waits and
/// learns it from the first datagram that arrives.
///
/// This is not a convenience. Without it, a scenario whose device sits behind
/// the `N-EIM-APDF` middlebox its own document declares could not be run at all,
/// and the choice would be between running it on a topology that is not the one
/// the scenario describes, or not running it.
///
/// # Errors
///
/// [`NetError::Unavailable`] if the TUN device cannot be created;
/// [`NetError::Os`] if the underlay socket cannot be bound.
pub fn run(
    dev: &str,
    bind: SocketAddr,
    peer: Option<SocketAddr>,
    duration: Duration,
) -> Result<()> {
    let tun = open(dev)?;
    let sock = UdpSocket::bind(bind)
        .map_err(|e| NetError::os(format!("binding the tunnel underlay to {bind}"), e))?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| NetError::os("setting the tunnel read timeout", e))?;
    set_nonblocking_read_timeout(&tun);

    let started = Instant::now();
    let mut tun_read = tun;
    // SAFETY: `dup` takes a descriptor this function owns and returns an
    // integer; it is checked below before anything is built from it.
    let cloned = unsafe { libc::dup(tun_read.as_raw_fd()) };
    if cloned < 0 {
        return Err(NetError::os(
            "duplicating the tunnel descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: `dup` returned a fresh descriptor, so this `File` is its only
    // owner and closing it does not touch `tun_read`'s. Both handles are
    // dropped at the end of this function and neither outlives it.
    let mut tun_write = unsafe { File::from_raw_fd(cloned) };
    // `None` until the far end learns where its peer actually is.
    let learned: Mutex<Option<SocketAddr>> = Mutex::new(peer);

    std::thread::scope(|scope| {
        let sock_out = &sock;
        let learned_out = &learned;
        scope.spawn(move || {
            let mut buf = [0u8; 65_536];
            while started.elapsed() < duration {
                // A zero-length read and an interrupted read are both "nothing
                // to forward this time round"; the loop's own deadline is what
                // ends it.
                if let Ok(n) = tun_read.read(&mut buf) {
                    if n > 0 {
                        // A packet with nowhere to go is DROPPED, not queued: a
                        // far end that buffered until it learned its peer would
                        // deliver a burst of stale packets on the first inbound
                        // datagram, and a scenario measuring "did the gap end"
                        // would see the gap end early.
                        if let Some(to) = *learned_out.lock().expect("the peer lock") {
                            let _ = sock_out.send_to(&buf[..n], to);
                        }
                    }
                }
            }
        });
        let sock_in = &sock;
        let learned_in = &learned;
        scope.spawn(move || {
            let mut buf = [0u8; 65_536];
            while started.elapsed() < duration {
                if let Ok((n, from)) = sock_in.recv_from(&mut buf) {
                    if peer.is_none() {
                        *learned_in.lock().expect("the peer lock") = Some(from);
                    }
                    let _ = tun_write.write_all(&buf[..n]);
                }
            }
        });
    });
    Ok(())
}

/// Bounds a TUN read, so a tunnel whose peer went away still notices its own
/// deadline.
fn set_nonblocking_read_timeout(tun: &File) {
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    // SAFETY: `tv` lives on this stack frame and the length passed is its size.
    // A TUN character device accepts `SO_RCVTIMEO` on some kernels and refuses
    // it on others; the refusal is ignored deliberately, because the fallback —
    // a blocking read that ends when the process is killed — is the behaviour a
    // scenario's teardown already relies on.
    unsafe {
        libc::setsockopt(
            tun.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}
