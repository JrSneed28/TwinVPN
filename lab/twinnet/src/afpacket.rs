//! `AF_PACKET` sockets — the second and last `unsafe` surface in `/lab/`.
//!
//! **Why raw sockets.** Two of this laboratory's obligations cannot be met any
//! other way on a host without `nftables`:
//!
//! 1. **§3.3's NAT personalities.** A middlebox that translates addresses and
//!    ports has to see and re-emit whole IP packets. [`crate::nat`] does that
//!    over a pair of these.
//! 2. **Rule PT-2's wire oracle.** `docs/testing-strategy.md` §4 requires that
//!    every security property be corroborated by an *independent wire capture*,
//!    "because a system reporting on itself is not sufficient evidence for a
//!    security property". A deny-counter read out of the system under test is
//!    exactly the insufficient evidence PT-2 names. [`crate::observer`] reads
//!    the wire instead.
//!
//! # What is and is not unsafe here
//!
//! Every `unsafe` block is one libc call with a stack-allocated argument whose
//! lifetime obviously covers it. There is no allocation, no pointer arithmetic
//! beyond `as_mut_ptr` on a caller-owned slice, and no `transmute`. The file is
//! short on purpose: a reviewer should be able to read all of it.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::time::Duration;

use crate::error::{NetError, Result};

/// A packet socket bound to one interface.
///
/// Dropped sockets close their descriptor; there is no other resource.
#[derive(Debug)]
pub struct PacketSocket {
    fd: RawFd,
    ifindex: i32,
    ignore_outgoing: bool,
}

/// Linux's `PACKET_OUTGOING`. A frame this socket itself transmitted is looped
/// back to it, and a middlebox that forwarded its own output would build an
/// infinite loop out of one packet.
const PACKET_OUTGOING: u8 = 4;

impl PacketSocket {
    /// Opens a raw packet socket bound to `ifname`, seeing every ethertype.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] when the host refuses `AF_PACKET` at all —
    /// which is the honest answer for a seccomp-confined runner, and is never a
    /// passing scenario.
    pub fn open(ifname: &str) -> Result<Self> {
        let name = CString::new(ifname)
            .map_err(|_| NetError::Malformed(format!("interface name `{ifname}` has a nul")))?;
        // SAFETY: `if_nametoindex` reads the null-terminated string it is given.
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if ifindex == 0 {
            return Err(NetError::os(
                format!("looking up interface `{ifname}`"),
                std::io::Error::last_os_error(),
            ));
        }
        let proto = i32::from((libc::ETH_P_ALL as u16).to_be());
        // SAFETY: `socket` takes three integers and returns a descriptor.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(NetError::Unavailable {
                facility: "af-packet",
                detail: format!("socket(AF_PACKET, SOCK_RAW) failed: {err}"),
            });
        }
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex as i32;
        // SAFETY: `addr` is a correctly initialised `sockaddr_ll` living on this
        // stack frame, and the length passed is its own size.
        let rc = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: closing a descriptor this function opened and owns.
            unsafe { libc::close(fd) };
            return Err(NetError::os(format!("binding to `{ifname}`"), err));
        }
        Ok(PacketSocket {
            fd,
            ifindex: ifindex as i32,
            // Kept by default. A capture that dropped what this host
            // TRANSMITTED would be blind to every packet the device itself
            // leaked, which is the majority of what a fail-closed oracle is
            // looking for. Only a forwarding middlebox wants the other
            // setting, and it has to ask.
            ignore_outgoing: false,
        })
    }

    /// Puts the interface into promiscuous mode for this socket.
    ///
    /// The observer needs it: a capture that only saw frames addressed to the
    /// capturing host would miss precisely the leak it is looking for.
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] if the kernel refuses the membership.
    pub fn set_promiscuous(&self) -> Result<()> {
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = self.ifindex;
        mreq.mr_type = libc::PACKET_MR_PROMISC as u16;
        // SAFETY: `mreq` is a correctly initialised `packet_mreq` on this stack
        // frame and the length passed is its own size.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                std::ptr::addr_of!(mreq).cast(),
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(NetError::os(
                "entering promiscuous mode",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Drops frames this socket itself transmitted.
    ///
    /// A middlebox MUST set this: `AF_PACKET` loops a transmitted frame back to
    /// the socket that sent it, and a forwarder that forwarded its own output
    /// would build an infinite loop out of one packet.
    ///
    /// An observer MUST NOT: the frames a device transmits are exactly the ones
    /// a leak oracle exists to judge, and a capture that silently omitted them
    /// would report a sealed tunnel for a host that was shouting.
    pub fn ignore_outgoing(&mut self, ignore: bool) {
        self.ignore_outgoing = ignore;
    }

    /// Bounds how long [`PacketSocket::recv`] blocks.
    ///
    /// Every read in this laboratory is bounded. An unbounded read in a chaos
    /// test whose whole point is that the other end stopped answering hangs the
    /// suite instead of failing it.
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] if the kernel refuses the option.
    pub fn set_read_timeout(&self, d: Duration) -> Result<()> {
        let tv = libc::timeval {
            tv_sec: d.as_secs() as libc::time_t,
            tv_usec: i64::from(d.subsec_micros()) as libc::suseconds_t,
        };
        // SAFETY: `tv` is a correctly initialised `timeval` on this stack frame.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(NetError::os(
                "setting the capture read timeout",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Receives one frame.
    ///
    /// Returns `Ok(None)` on timeout, and skips frames this socket transmitted.
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] for any read failure that is not a timeout.
    pub fn recv(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        loop {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            // SAFETY: `buf` is a caller-owned slice whose length is passed
            // exactly, and `addr`/`len` live on this stack frame.
            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    std::ptr::addr_of_mut!(addr).cast::<libc::sockaddr>(),
                    std::ptr::addr_of_mut!(len),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                return match err.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Ok(None),
                    std::io::ErrorKind::Interrupted => continue,
                    _ => Err(NetError::os("receiving a frame", err)),
                };
            }
            if self.ignore_outgoing && addr.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            return Ok(Some(n as usize));
        }
    }

    /// Transmits one complete Ethernet frame on the bound interface.
    ///
    /// # Errors
    ///
    /// [`NetError::Os`] for any write failure.
    pub fn send(&self, frame: &[u8]) -> Result<usize> {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        if frame.len() >= 6 {
            addr.sll_addr[..6].copy_from_slice(&frame[..6]);
        }
        // SAFETY: `frame` is a caller-owned slice whose length is passed
        // exactly, and `addr` lives on this stack frame.
        let n = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr().cast(),
                frame.len(),
                0,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(NetError::os(
                "transmitting a frame",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(n as usize)
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        // SAFETY: closing a descriptor this type opened and exclusively owns.
        unsafe { libc::close(self.fd) };
    }
}

/// Whether this host will give out an `AF_PACKET` socket at all.
///
/// Probed by opening one on `lo`, because a capability table that reports what a
/// `uname` implies rather than what the kernel did is the failure mode §3.1
/// exists to prevent.
pub fn available() -> std::result::Result<(), String> {
    match PacketSocket::open("lo") {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
