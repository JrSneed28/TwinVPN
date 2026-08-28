//! `rtnetlink` — the transport under interface enumeration, change notification,
//! and address/route/rule programming.
//!
//! **Authority:** `docs/networking.md` §5.2 Linux row ("netlink (`rtnetlink`,
//! `RTM_NEWADDR`/`RTM_NEWROUTE`), policy routing table `52` + `fwmark`";
//! "`RTNETLINK` multicast groups (`RTNLGRP_LINK`, `IPV4_IFADDR`, `IPV6_IFADDR`,
//! `IPV4_ROUTE`, `IPV6_ROUTE`)"), ADR-0010 §11.3, ADR-0018 DP-4.
//!
//! # Why netlink and not `ip(8)`
//!
//! Three reasons, in order of weight. **Events**: `docs/networking.md` §5.1
//! requires change notification to be "event-driven, never polled", and a poll
//! interval is added directly to `T_FAILOVER_TARGET` — there is no `ip` command
//! that delivers an event. **Atomicity**: `apply` is all-or-nothing per contract
//! generation, and a sequence of `ip` invocations has a failure point between
//! every pair. **Errors**: netlink returns an `errno` per message, which maps
//! onto a registered `reason_code`; `ip`'s exit status does not.
//!
//! # Encoding is done by hand, in safe Rust
//!
//! Every netlink structure is a fixed little-endian C layout with documented
//! alignment. Encoding them by writing bytes into a `Vec<u8>` — rather than
//! transmuting `#[repr(C)]` structs — means the whole message-building and
//! message-parsing surface is **safe code**, and the `unsafe` in this module is
//! confined to the four socket syscalls. Field offsets are asserted against
//! `libc`'s own `size_of` in this module's tests, so a hand-written offset that
//! drifts from the kernel's layout fails the build rather than corrupting a
//! route.
//!
//! # `unsafe` in this module
//!
//! Five blocks: `socket`, `bind`, `send`, `recv`, and the zeroed `sockaddr_nl`
//! that `libc`'s private padding field makes unconstructible in safe code. Each
//! has a `// SAFETY:` comment naming its invariant.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

/// The routing table TwinVPN programs into.
///
/// `docs/networking.md` §5.2 and ADR-0010 §11.3 both fix it at **52**. It is the
/// one number those documents pin; the `fwmark` value is not pinned anywhere in
/// the corpus, which is reported as a gap and chosen in [`crate::route`].
pub const TABLE: u8 = 52;

/// `AF_INET` as the `u8` every `rtnetlink` header carries it in.
///
/// `libc`'s own constant is a `c_int`; the netlink structures declare the family
/// as a single byte. Converted once, as a `const`, rather than at every
/// comparison — a cast in a comparison is where a width error hides.
// The casts below are narrowing by design: every one of these constants is a
// small positive value fixed by the kernel's own headers, and the tests in this
// module assert each against `libc`'s value so a widening would fail the build
// rather than truncate silently.
#[allow(clippy::cast_possible_truncation)]
pub const AF_INET_U8: u8 = libc::AF_INET as u8;

/// `AF_INET6`, likewise.
#[allow(clippy::cast_possible_truncation)]
pub const AF_INET6_U8: u8 = libc::AF_INET6 as u8;

/// `NLM_F_REQUEST`, narrowed to the `u16` the header field actually is.
#[allow(clippy::cast_possible_truncation)]
pub const REQUEST: u16 = libc::NLM_F_REQUEST as u16;

/// `NLM_F_DUMP`.
#[allow(clippy::cast_possible_truncation)]
pub const DUMP: u16 = libc::NLM_F_DUMP as u16;

/// `NLM_F_ACK`.
#[allow(clippy::cast_possible_truncation)]
pub const ACK: u16 = libc::NLM_F_ACK as u16;

/// `NLM_F_CREATE`.
#[allow(clippy::cast_possible_truncation)]
pub const CREATE: u16 = libc::NLM_F_CREATE as u16;

/// `NLM_F_REPLACE`.
#[allow(clippy::cast_possible_truncation)]
pub const REPLACE: u16 = libc::NLM_F_REPLACE as u16;

/// `NLM_F_EXCL`.
#[allow(clippy::cast_possible_truncation)]
pub const EXCL: u16 = libc::NLM_F_EXCL as u16;

/// `NLMSG_ALIGNTO`, and the alignment for every netlink header and attribute.
const ALIGN: usize = 4;

/// The `nlmsghdr` width: `len` `type` `flags` `seq` `pid`.
pub const NLMSGHDR_LEN: usize = 16;

/// The `rtattr` header width: `len` `type`.
pub const RTATTR_HDR_LEN: usize = 4;

/// Rounds `n` up to the netlink alignment.
#[must_use]
pub const fn align(n: usize) -> usize {
    (n + ALIGN - 1) & !(ALIGN - 1)
}

/// A netlink message under construction.
///
/// The header's `len` is written last, by [`NlBuilder::finish`], so it cannot
/// disagree with the body — the single most common hand-rolled-netlink defect,
/// and one the kernel answers with a bare `EINVAL` that says nothing about
/// which message was wrong.
#[derive(Debug, Clone)]
pub struct NlBuilder {
    buf: Vec<u8>,
}

impl NlBuilder {
    /// Starts a message of `msg_type` with `flags`, leaving room for the header.
    #[must_use]
    pub fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // len, patched in finish()
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: the kernel fills it
        Self { buf }
    }

    /// Appends raw payload bytes and pads to the netlink alignment.
    pub fn payload(&mut self, bytes: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    /// Appends one `rtattr`.
    pub fn attr(&mut self, attr_type: u16, value: &[u8]) -> &mut Self {
        let len = RTATTR_HDR_LEN + value.len();
        let len16 = u16::try_from(len).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len16.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(value);
        self.pad();
        self
    }

    /// Appends a `u32`-valued attribute.
    pub fn attr_u32(&mut self, attr_type: u16, value: u32) -> &mut Self {
        self.attr(attr_type, &value.to_ne_bytes())
    }

    /// Appends a `u8`-valued attribute.
    pub fn attr_u8(&mut self, attr_type: u16, value: u8) -> &mut Self {
        self.attr(attr_type, &[value])
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(ALIGN) {
            self.buf.push(0);
        }
    }

    /// Writes the length and yields the encoded message.
    #[must_use]
    pub fn finish(mut self) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// One received netlink message: its type and its payload after the header.
#[derive(Debug, Clone)]
pub struct NlMessage {
    /// `nlmsg_type`.
    pub msg_type: u16,
    /// `nlmsg_flags`.
    pub flags: u16,
    /// Everything after the 16-byte header.
    pub body: Vec<u8>,
}

/// Splits a receive buffer into whole messages.
///
/// A message whose declared length is short, over-long, or would run past the
/// buffer is **refused**, not truncated: the kernel is trusted, but a length
/// arriving from a socket is still a declared length, and `ownership.md` §6 rule
/// 9 makes an unbounded allocation from one a defect wherever it comes from.
#[must_use]
pub fn parse_messages(buf: &[u8]) -> Vec<NlMessage> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + NLMSGHDR_LEN <= buf.len() {
        let len = u32::from_ne_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as usize;
        if len < NLMSGHDR_LEN || at + len > buf.len() {
            break;
        }
        let msg_type = u16::from_ne_bytes([buf[at + 4], buf[at + 5]]);
        let flags = u16::from_ne_bytes([buf[at + 6], buf[at + 7]]);
        out.push(NlMessage {
            msg_type,
            flags,
            body: buf[at + NLMSGHDR_LEN..at + len].to_vec(),
        });
        at += align(len);
    }
    out
}

/// Walks the `rtattr` list starting at `offset` within a message body.
///
/// Yields `(type, value)` pairs. A malformed attribute stops the walk rather
/// than being guessed at.
#[must_use]
pub fn parse_attrs(body: &[u8], offset: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = offset;
    while at + RTATTR_HDR_LEN <= body.len() {
        let len = u16::from_ne_bytes([body[at], body[at + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([body[at + 2], body[at + 3]]);
        if len < RTATTR_HDR_LEN || at + len > body.len() {
            break;
        }
        out.push((attr_type, &body[at + RTATTR_HDR_LEN..at + len]));
        at += align(len);
    }
    out
}

/// Reads the `errno` an `NLMSG_ERROR` message carries.
///
/// The kernel encodes it as a **negative** `i32` followed by the offending
/// header. Zero means "this is an ack", not an error — the distinction that
/// makes `NLM_F_ACK` usable as a completion signal.
#[must_use]
pub fn error_code(body: &[u8]) -> Option<i32> {
    if body.len() < 4 {
        return None;
    }
    let raw = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
    Some(-raw)
}

/// A bound `AF_NETLINK` socket.
pub struct NetlinkSocket {
    io: AsyncFd<OwnedFd>,
    seq: AtomicU32,
}

impl NetlinkSocket {
    /// Opens a `NETLINK_ROUTE` socket, subscribing to `groups`.
    ///
    /// `groups` is the legacy 32-bit mask in `sockaddr_nl.nl_groups`; every
    /// group this crate needs (`RTNLGRP_LINK` … `RTNLGRP_IPV6_ROUTE`) is inside
    /// it, so the `NETLINK_ADD_MEMBERSHIP` path is not needed.
    ///
    /// # Errors
    ///
    /// The OS error, for [`crate::oserr`] to name.
    pub fn open(groups: u32) -> io::Result<Self> {
        // SAFETY: `socket` takes three integers and returns a new fd or -1. No
        // pointer is involved. The fd is immediately wrapped in an `OwnedFd`
        // below, so it is closed exactly once.
        let fd: RawFd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid, owned file descriptor that nothing
        // else holds, which is exactly `OwnedFd::from_raw_fd`'s contract.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut sa: libc::sockaddr_nl = zeroed_sockaddr_nl();
        sa.nl_family = u16::try_from(libc::AF_NETLINK).unwrap_or(16);
        sa.nl_groups = groups;
        // SAFETY: `owned` is a valid netlink socket for the duration of the
        // call; `&sa` points to one initialised `sockaddr_nl` and the length
        // passed is exactly its size. `bind` copies out of the pointer and
        // retains nothing.
        let rc = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                std::ptr::from_ref(&sa).cast::<libc::sockaddr>(),
                u32::try_from(mem::size_of::<libc::sockaddr_nl>()).unwrap_or(12),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        let io = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)?;
        Ok(Self {
            io,
            seq: AtomicU32::new(1),
        })
    }

    /// The next sequence number.
    pub fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends one encoded message.
    async fn send(&self, msg: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.io.writable().await?;
            let result = guard.try_io(|inner| {
                // SAFETY: `msg` is a live slice for the whole call and the
                // length passed is its true byte length; `inner` holds a valid
                // netlink fd. `send` reads from the pointer and retains nothing.
                let n = unsafe {
                    libc::send(
                        inner.get_ref().as_raw_fd(),
                        msg.as_ptr().cast::<libc::c_void>(),
                        msg.len(),
                        0,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match result {
                Ok(r) => return r,
                Err(_would_block) => {}
            }
        }
    }

    /// Receives one datagram's worth of messages.
    ///
    /// The buffer is 32 KiB — the size a full `RTM_GETLINK` dump reply needs on
    /// a host with many interfaces, and the size `iproute2` itself uses. A
    /// truncated dump would silently lose interfaces, so `MSG_TRUNC` is checked
    /// and reported rather than absorbed.
    pub async fn recv(&self) -> io::Result<Vec<NlMessage>> {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let mut guard = self.io.readable().await?;
            let result = guard.try_io(|inner| {
                // SAFETY: `buf` is a live, uniquely-borrowed allocation of the
                // length passed; `inner` holds a valid netlink fd. `recv` writes
                // at most `buf.len()` bytes into it and retains no pointer.
                let n = unsafe {
                    libc::recv(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                        libc::MSG_TRUNC,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = usize::try_from(n).unwrap_or(0);
                if n > buf.len() {
                    // The kernel had more than the buffer held. Reporting is the
                    // only honest answer: a truncated dump is a missing
                    // interface, and a missing interface is a route programmed
                    // through the wrong link.
                    return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
                }
                Ok(n)
            });
            match result {
                Ok(Ok(n)) => return Ok(parse_messages(&buf[..n])),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => {}
            }
        }
    }

    /// Sends a request and collects the reply, stopping at `NLMSG_DONE` or the
    /// terminating `NLMSG_ERROR`.
    ///
    /// # Errors
    ///
    /// The kernel's own `errno`, taken from the `NLMSG_ERROR` message, so the
    /// caller can map it onto a registered `reason_code` rather than reporting
    /// "netlink failed".
    pub async fn request(&self, message: Vec<u8>) -> io::Result<Vec<NlMessage>> {
        self.send(&message).await?;
        let mut out = Vec::new();
        loop {
            let batch = self.recv().await?;
            if batch.is_empty() {
                return Ok(out);
            }
            for msg in batch {
                match msg.msg_type {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let code = error_code(&msg.body).unwrap_or(libc::EIO);
                        if code == 0 {
                            // An ack: the request succeeded and there is no
                            // dump to collect.
                            return Ok(out);
                        }
                        return Err(io::Error::from_raw_os_error(code));
                    }
                    NLMSG_NOOP | NLMSG_OVERRUN => {}
                    _ => out.push(msg),
                }
            }
        }
    }
}

/// A zeroed `sockaddr_nl`.
///
/// `libc` 0.2.189 makes the padding field private, so the struct cannot be
/// built field-by-field. A zeroed value is a **valid** one: `sockaddr_nl` is a
/// plain C aggregate of integers with no niche, no reference and no enum, so
/// every bit pattern — including all-zero — inhabits the type, and all-zero is
/// the same initial value `memset` gives it in every C netlink example.
fn zeroed_sockaddr_nl() -> libc::sockaddr_nl {
    // SAFETY: `sockaddr_nl` is `#[repr(C)]` over `u16`/`u32` fields and one
    // private integer pad. It contains no reference, no `NonZero`, no enum and
    // no `bool`, so it has no invalid bit pattern and an all-zero value is
    // inhabited and initialised.
    unsafe { mem::zeroed() }
}

/// `nlmsg_type` is a `u16` on the wire; `libc` declares these as `c_int`.
///
/// Converted once, here, as `const`, rather than casting at every match arm —
/// a cast in a match arm is where a sign error hides.
#[allow(clippy::cast_possible_truncation)]
const NLMSG_DONE: u16 = libc::NLMSG_DONE as u16;
#[allow(clippy::cast_possible_truncation)]
const NLMSG_ERROR: u16 = libc::NLMSG_ERROR as u16;
#[allow(clippy::cast_possible_truncation)]
const NLMSG_NOOP: u16 = libc::NLMSG_NOOP as u16;
#[allow(clippy::cast_possible_truncation)]
const NLMSG_OVERRUN: u16 = libc::NLMSG_OVERRUN as u16;

/// The multicast groups `docs/networking.md` §5.2 names, as a `nl_groups` mask.
///
/// `RTNLGRP_*` values are group *numbers*; the legacy mask wants `1 << (n - 1)`.
#[must_use]
pub const fn change_groups() -> u32 {
    const fn bit(group: u32) -> u32 {
        1 << (group - 1)
    }
    bit(libc::RTNLGRP_LINK)
        | bit(libc::RTNLGRP_IPV4_IFADDR)
        | bit(libc::RTNLGRP_IPV6_IFADDR)
        | bit(libc::RTNLGRP_IPV4_ROUTE)
        | bit(libc::RTNLGRP_IPV6_ROUTE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_narrowed_constants_still_equal_the_kernels_own_values() {
        // The `as` casts above are narrowing by design; this is what makes that
        // safe rather than assumed.
        assert_eq!(i32::from(AF_INET_U8), libc::AF_INET);
        assert_eq!(i32::from(AF_INET6_U8), libc::AF_INET6);
        assert_eq!(i32::from(NLMSG_DONE), libc::NLMSG_DONE);
        assert_eq!(i32::from(NLMSG_ERROR), libc::NLMSG_ERROR);
        assert_eq!(i32::from(NLMSG_NOOP), libc::NLMSG_NOOP);
        assert_eq!(i32::from(NLMSG_OVERRUN), libc::NLMSG_OVERRUN);
    }

    #[test]
    fn the_hand_written_header_widths_match_the_kernels() {
        // The whole reason this module encodes by hand rather than by transmute
        // is that the layouts are fixed. This test is what makes that a checked
        // claim: a hand-written offset that drifts fails here rather than
        // corrupting a route.
        assert_eq!(NLMSGHDR_LEN, mem::size_of::<libc::nlmsghdr>());
        assert_eq!(RTATTR_HDR_LEN, mem::size_of::<libc::rtattr>());
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
    }

    #[test]
    fn a_built_message_declares_its_own_true_length() {
        let mut b = NlBuilder::new(libc::RTM_GETLINK, REQUEST, 7);
        b.attr_u32(libc::IFLA_MTU, 1280);
        let msg = b.finish();
        let declared = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(declared, msg.len(), "len must be patched in finish()");
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), libc::RTM_GETLINK);
        assert_eq!(u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]), 7);
    }

    #[test]
    fn attributes_round_trip_through_the_parser() {
        let mut b = NlBuilder::new(libc::RTM_NEWROUTE, 0, 1);
        b.payload(&[0u8; 12]);
        b.attr_u32(libc::RTA_OIF, 42);
        b.attr(libc::RTA_DST, &[10, 0, 0, 0]);
        let msg = b.finish();
        let parsed = parse_messages(&msg);
        assert_eq!(parsed.len(), 1);
        let attrs = parse_attrs(&parsed[0].body, 12);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, libc::RTA_OIF);
        assert_eq!(attrs[0].1, 42u32.to_ne_bytes());
        assert_eq!(attrs[1].0, libc::RTA_DST);
        assert_eq!(attrs[1].1, [10, 0, 0, 0]);
    }

    #[test]
    fn a_message_declaring_more_than_the_buffer_holds_is_refused_not_truncated() {
        let mut msg = NlBuilder::new(libc::RTM_NEWLINK, 0, 1).finish();
        msg[..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(
            parse_messages(&msg).is_empty(),
            "an over-long declared length must not drive a read past the buffer"
        );
        // And a length below the header width is equally refused.
        msg[..4].copy_from_slice(&3u32.to_ne_bytes());
        assert!(parse_messages(&msg).is_empty());
    }

    #[test]
    fn an_ack_is_distinguished_from_an_error() {
        assert_eq!(error_code(&0i32.to_ne_bytes()), Some(0));
        assert_eq!(error_code(&(-libc::EPERM).to_ne_bytes()), Some(libc::EPERM));
        assert_eq!(error_code(&[1, 2]), None);
    }

    #[test]
    fn the_change_group_mask_covers_every_group_networking_md_names() {
        let mask = change_groups();
        for group in [
            libc::RTNLGRP_LINK,
            libc::RTNLGRP_IPV4_IFADDR,
            libc::RTNLGRP_IPV6_IFADDR,
            libc::RTNLGRP_IPV4_ROUTE,
            libc::RTNLGRP_IPV6_ROUTE,
        ] {
            assert_ne!(mask & (1 << (group - 1)), 0, "group {group} is missing");
        }
    }

    #[tokio::test]
    async fn a_link_dump_returns_at_least_the_loopback_interface() {
        let sock = NetlinkSocket::open(0).expect("netlink is available unprivileged");
        let mut b = NlBuilder::new(libc::RTM_GETLINK, REQUEST | DUMP, sock.next_seq());
        // struct ifinfomsg: family, pad, type, index, flags, change.
        b.payload(&[0u8; 16]);
        let replies = sock.request(b.finish()).await.expect("dump succeeds");
        assert!(!replies.is_empty(), "every host has at least `lo`");
        assert!(replies.iter().all(|m| m.msg_type == libc::RTM_NEWLINK));
    }
}
