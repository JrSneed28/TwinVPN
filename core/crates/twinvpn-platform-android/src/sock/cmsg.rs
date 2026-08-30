//! The `recvmsg` control-message walk: which of our addresses a datagram arrived
//! on, and which interface it came in through.
//!
//! **Authority:** `docs/networking.md` §3.4 (the disco probe attributes a
//! reflexive candidate by arrival address), [`twinvpn_platform::socket`]'s
//! `receive_packet_info` and [`twinvpn_platform::socket::Datagram`]; ADR-0018 DP-4.
//!
//! # Why `recvmsg` and not `recv_from`
//!
//! A socket bound to the wildcard cannot tell which of its addresses a probe
//! arrived on, and §3.4's reflexive-candidate attribution needs exactly that.
//! `IP_PKTINFO` / `IPV6_RECVPKTINFO` answer it, and they arrive as ancillary
//! data on `recvmsg` — there is no other way to ask.
//!
//! The truncation flag comes from the same call: `MSG_TRUNC` in `msg_flags` is
//! how the kernel says the datagram did not fit. [`twinvpn_platform::socket::Datagram::truncated`] is
//! documented as *"Reported, never silent. A silently truncated datagram is a
//! message that fails authentication for a reason nobody can see."*
//!
//! # The `unsafe` in this module, and the rule each block obeys
//!
//! | Block | What it is | The invariant |
//! |---|---|---|
//! | the zeroed `sockaddr_storage`, `iovec` and `msghdr` | `libc`'s private padding makes these unconstructible in safe code | all three are plain-old-data with no invalid bit pattern; every field the kernel reads is set before the call |
//! | the `recvmsg` | one syscall | the buffers are live, exclusively borrowed, and of exactly their declared lengths |
//! | the `cmsg` walk | `CMSG_FIRSTHDR` / `CMSG_NXTHDR` / `CMSG_DATA` | **every read is length-checked against `CMSG_LEN` first**, so a hostile or truncated control buffer cannot drive a read past its end |
//! | the two payload copies | `copy_nonoverlapping` out of the control buffer | each is guarded by the length check above and copies exactly `size_of::<T>()` bytes into a local of that type |
//!
//! # Widths, and why not one of them is written as a literal type
//!
//! ADR-0018 §11.9 row 3 requires **four** ABIs, and two of them are 32-bit. The
//! C types this module touches are not all the same width across them:
//!
//! | Field | 32-bit bionic | 64-bit bionic | How this module handles it |
//! |---|---|---|---|
//! | `msghdr::msg_namelen` | `socklen_t` = **`int`** | `socklen_t` = **`unsigned int`** | [`socklen`] — names `libc::socklen_t`, refuses rather than truncating |
//! | `msghdr::msg_controllen`, `msghdr::msg_iovlen`, `cmsghdr::cmsg_len` | `size_t` | `size_t` | assigned and compared as `usize`, with **no cast**, so a future narrowing is a compile error |
//! | `in_pktinfo::ipi_ifindex`, `in6_pktinfo::ipi6_ifindex` | `int` (bionic) / `unsigned int` (glibc) | same | [`ifindex`] — generic over the width, absence is a value |
//! | `CMSG_LEN`'s argument and result | `c_uint` | `c_uint` | [`cmsg_len`] — saturates in the **reject** direction |
//!
//! The rule the table encodes: **name the destination type, never a width**, and
//! where a conversion can fail, fail toward refusing the datagram. A cast would
//! have compiled on all four ABIs and reinterpreted on two of them, which is
//! strictly worse than the build error that exposed this — the build error was
//! the one telling the truth.

use std::io;
use std::mem::{size_of, MaybeUninit};

use twinvpn_platform::iface::InterfaceIndex;
use twinvpn_types::IpAddr;

use super::addr;
use crate::hostcall::RawFd;

/// What one `recvmsg` told us, beyond the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    /// Bytes written into the caller's buffer.
    pub len: usize,
    /// The source address octets, as the kernel reported them.
    pub source: SourceAddr,
    /// Which of our own addresses it arrived on, when `receive_packet_info` was
    /// set and the kernel supplied it.
    pub destination: Option<IpAddr>,
    /// Which interface it arrived on, when known.
    pub interface: Option<InterfaceIndex>,
    /// Whether the datagram did not fit. **Reported, never silent.**
    pub truncated: bool,
}

/// The source as the kernel gave it, before the seam's un-mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAddr {
    /// From a `sockaddr_in`.
    V4 {
        /// The four octets.
        octets: [u8; 4],
        /// The source port.
        port: u16,
    },
    /// From a `sockaddr_in6`. May be v4-mapped; [`super::addr`] un-maps it.
    V6 {
        /// The sixteen octets.
        octets: [u8; 16],
        /// The scope zone, or `0` for none.
        zone: u32,
        /// The source port.
        port: u16,
    },
}

/// The control buffer. Large enough for both `IP_PKTINFO` and `IPV6_PKTINFO`
/// with their alignment padding, and **fixed** — it is a stack array, so no
/// untrusted length drives an allocation here (`ownership.md` §6 rule 10).
const CONTROL_BYTES: usize = 128;

/// Receives one datagram into `buf`, with its ancillary data.
///
/// # Errors
///
/// The raw `io::Error`; the caller maps it through [`crate::oserr`].
pub fn recvmsg(fd: RawFd, buf: &mut [u8]) -> io::Result<RecvMeta> {
    // SAFETY: `sockaddr_storage`, `iovec`, `msghdr` and the control buffer are
    // plain-old-data with no invalid bit pattern, so an all-zero value is a
    // valid instance of each. They are zeroed rather than constructed field by
    // field because `libc`'s private padding makes them unconstructible in safe
    // code, and because the kernel reads fields we would otherwise leave
    // uninitialised.
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control = [0u8; CONTROL_BYTES];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // SAFETY: as above.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(name).cast::<libc::c_void>();
    msg.msg_namelen = socklen(size_of::<libc::sockaddr_storage>());
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    // `msg_iovlen` is a `size_t` on bionic and on glibc alike, and this is a
    // literal rather than a conversion, so there is no width to get wrong.
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    // No cast, deliberately. `msg_controllen` is a `size_t` on every target this
    // crate builds for, so a plain `usize` assigns directly — and if some future
    // target narrows it, that becomes a COMPILE ERROR rather than a control
    // buffer whose declared length is smaller than the one `recvmsg` was handed.
    // The `as _` this replaces would have silently adapted to either.
    msg.msg_controllen = control.len();

    // SAFETY: every pointer in `msg` refers to a live local of exactly the
    // declared length, all of them borrowed for the duration of this call, and
    // `fd` is borrowed from a live socket by the caller. `MSG_TRUNC` asks the
    // kernel to report the true datagram length rather than the copied length,
    // which is what makes the truncation flag meaningful.
    let received = unsafe { libc::recvmsg(fd, std::ptr::addr_of_mut!(msg), libc::MSG_TRUNC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let true_len = usize::try_from(received).unwrap_or(0);
    let truncated = true_len > buf.len() || (msg.msg_flags & libc::MSG_TRUNC) != 0;

    let source = read_source(&name, msg.msg_namelen)?;
    let (destination, interface) = read_pktinfo(&msg);

    Ok(RecvMeta {
        len: true_len.min(buf.len()),
        source,
        destination,
        interface,
        truncated,
    })
}

/// Narrows a kernel-supplied interface index to the seam's `u32`.
///
/// # Why this is a function and not a cast
///
/// **`in6_pktinfo.ipi6_ifindex` is `unsigned int` on glibc and `int` on
/// bionic**, so the same field is `u32` on the host build and `i32` on the
/// Android build. A cast would compile on both and hide the difference; a
/// `try_into().unwrap()` would compile on both and put a **panic on a
/// kernel-supplied value in the middle of the receive path**, which is the one
/// place a panic must not be — `twinvpn.h` F-7 contains a core panic, but the
/// containment costs the instance.
///
/// So the conversion is total and the failure is a value: a negative index (or
/// one wider than the seam's) is **not an interface**, and neither is zero,
/// which is what the kernel writes when it did not supply one. `None` flows on
/// to [`RecvMeta::interface`], where the seam already documents the field as
/// optional, and to [`super::addr::v6_from_kernel`], which refuses a link-local
/// address with no zone and reports it as a registered `reason_code` — the same
/// treatment this module already gives a short `msg_namelen`.
///
/// Generic over the integer width so one function serves both C definitions
/// without a `#[cfg]`, which is CB-3's direction: branch on the declared fact,
/// not on which OS it is.
fn ifindex<T: TryInto<u32>>(raw: T) -> Option<u32> {
    raw.try_into().ok().filter(|index| *index != 0)
}

/// The total control-message length a payload of `payload` bytes occupies,
/// including the header and its alignment padding.
///
/// Wraps `CMSG_LEN` so the width conversions live in one place and every caller
/// compares two `usize`s. A payload larger than `u32::MAX` is impossible here --
/// both call sites pass a `size_of` of a fixed C struct -- and is saturated
/// rather than truncated, which makes the guard reject rather than admit.
fn cmsg_len(payload: usize) -> usize {
    let payload = u32::try_from(payload).unwrap_or(u32::MAX);
    // SAFETY: `CMSG_LEN` is a pure arithmetic macro over its argument; it reads
    // no memory.
    let total = unsafe { libc::CMSG_LEN(payload) };
    usize::try_from(total).unwrap_or(usize::MAX)
}

/// A buffer length of `len` bytes as a `socklen_t`, refusing rather than
/// truncating.
///
/// # Why this is a function and not a cast, and not `u32` either
///
/// **`socklen_t` is `int` on 32-bit bionic and `unsigned int` on 64-bit**, so
/// `msghdr::msg_namelen` is `i32` on `armv7-linux-androideabi` and
/// `i686-linux-android` and `u32` on the two 64-bit ABIs — all four of which
/// ADR-0018 §11.9 row 3 requires. Naming `u32` compiled on the ABIs that were
/// built and failed the two that were not, which is the honest failure; naming
/// `libc::socklen_t` is CB-3's direction, the same one [`ifindex`] above already
/// takes: **branch on the declared fact, not on which OS it is.**
///
/// An `as` cast would have compiled on all four and been the *worse* outcome,
/// because it would have silently reinterpreted rather than refused.
///
/// # Why the refusal is zero and never a saturation
///
/// `msg_namelen` is an **in-out** parameter: it tells the kernel how many bytes
/// of `msg_name` it may write. A saturated `socklen_t::MAX` would claim a
/// two-gigabyte buffer for a 128-byte stack local, so an over-large input would
/// become a write past the end of `name` rather than a wrong number — the one
/// direction this must not fail in. Zero tells the kernel to write no address at
/// all, and [`read_source`] then refuses the short result through the path it
/// already has for a short `msg_namelen`.
///
/// The bound is never reached in fact: the only caller passes
/// `size_of::<libc::sockaddr_storage>()`, which is **128** on all four ABIs.
/// `a_peer_address_length_is_declared_not_saturated` below asserts both halves —
/// that the real length survives the conversion, and that an over-large one
/// refuses instead of saturating.
fn socklen(len: usize) -> libc::socklen_t {
    libc::socklen_t::try_from(len).unwrap_or(0)
}

/// Decodes the kernel-supplied peer address, width-checked before it is read.
///
/// `namelen` is a `libc::socklen_t` rather than a `u32`, for [`socklen`]'s
/// reason: on the two 32-bit ABIs it is **signed**, so "a negative length" is a
/// representable input here rather than a theoretical one. `try_from` maps it to
/// zero, which every arm below then refuses — the same treatment a short length
/// already gets, and for the same reason.
fn read_source(name: &libc::sockaddr_storage, namelen: libc::socklen_t) -> io::Result<SourceAddr> {
    let namelen = usize::try_from(namelen).unwrap_or(0);
    match i32::from(name.ss_family) {
        libc::AF_INET if namelen >= size_of::<libc::sockaddr_in>() => {
            let mut sin = MaybeUninit::<libc::sockaddr_in>::zeroed();
            // SAFETY: the width check above proves the kernel wrote at least a
            // whole `sockaddr_in`, and `ss_family` says that is what it is.
            // Exactly `size_of::<sockaddr_in>()` bytes are copied from a live
            // source into a local of that type, and the two do not overlap.
            let sin = unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(name).cast::<u8>(),
                    sin.as_mut_ptr().cast::<u8>(),
                    size_of::<libc::sockaddr_in>(),
                );
                sin.assume_init()
            };
            Ok(SourceAddr::V4 {
                octets: sin.sin_addr.s_addr.to_ne_bytes(),
                port: u16::from_be(sin.sin_port),
            })
        }
        libc::AF_INET6 if namelen >= size_of::<libc::sockaddr_in6>() => {
            let mut sin6 = MaybeUninit::<libc::sockaddr_in6>::zeroed();
            // SAFETY: as above, for `sockaddr_in6`.
            let sin6 = unsafe {
                std::ptr::copy_nonoverlapping(
                    std::ptr::from_ref(name).cast::<u8>(),
                    sin6.as_mut_ptr().cast::<u8>(),
                    size_of::<libc::sockaddr_in6>(),
                );
                sin6.assume_init()
            };
            Ok(SourceAddr::V6 {
                octets: sin6.sin6_addr.s6_addr,
                zone: sin6.sin6_scope_id,
                port: u16::from_be(sin6.sin6_port),
            })
        }
        // A family we did not ask for, or a short write. Refused rather than
        // guessed: an address read out of a buffer the kernel did not fill is a
        // peer identity invented by uninitialised memory.
        _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

/// Walks the control messages for `IP_PKTINFO` / `IPV6_PKTINFO`.
///
/// Every read is length-checked against `CMSG_LEN` **first**.
fn read_pktinfo(msg: &libc::msghdr) -> (Option<IpAddr>, Option<InterfaceIndex>) {
    let mut destination = None;
    let mut interface = None;

    // SAFETY: `CMSG_FIRSTHDR` reads only `msg_control` and `msg_controllen`,
    // both of which describe the live, fixed-size control buffer the caller
    // passed to `recvmsg`.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(std::ptr::from_ref(msg)) };
    while !header.is_null() {
        // SAFETY: `CMSG_FIRSTHDR`/`CMSG_NXTHDR` return either null or a pointer
        // to a whole `cmsghdr` inside the control buffer, and the loop condition
        // has already excluded null.
        let (level, ctype, len) = unsafe {
            (
                (*header).cmsg_level,
                (*header).cmsg_type,
                (*header).cmsg_len,
            )
        };

        match (level, ctype) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: `CMSG_LEN` computes the total length a payload of this
                // size occupies, including the header and its padding. The check
                // proves the kernel wrote at least that much, so the copy below
                // stays inside the control buffer.
                let need = cmsg_len(size_of::<libc::in_pktinfo>());
                if len >= need {
                    let mut info = MaybeUninit::<libc::in_pktinfo>::zeroed();
                    // SAFETY: guarded by the length check immediately above.
                    // Exactly `size_of::<in_pktinfo>()` bytes are copied from
                    // `CMSG_DATA(header)` into a local of that type.
                    let info = unsafe {
                        std::ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(header),
                            info.as_mut_ptr().cast::<u8>(),
                            size_of::<libc::in_pktinfo>(),
                        );
                        info.assume_init()
                    };
                    destination = Some(addr::v4_address(info.ipi_addr.s_addr.to_ne_bytes()));
                    interface = ifindex(info.ipi_ifindex).map(InterfaceIndex);
                }
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: as above, for `in6_pktinfo`.
                let need = cmsg_len(size_of::<libc::in6_pktinfo>());
                if len >= need {
                    let mut info = MaybeUninit::<libc::in6_pktinfo>::zeroed();
                    // SAFETY: guarded by the length check immediately above.
                    let info = unsafe {
                        std::ptr::copy_nonoverlapping(
                            libc::CMSG_DATA(header),
                            info.as_mut_ptr().cast::<u8>(),
                            size_of::<libc::in6_pktinfo>(),
                        );
                        info.assume_init()
                    };
                    let arrival = ifindex(info.ipi6_ifindex);
                    destination =
                        addr::v6_from_kernel(info.ipi6_addr.s6_addr, arrival.unwrap_or(0)).ok();
                    interface = arrival.map(InterfaceIndex);
                }
            }
            _ => {}
        }

        // SAFETY: both arguments are live for the duration of the call —
        // `msg` is borrowed, and `header` is a non-null pointer inside its
        // control buffer, as established above.
        header = unsafe { libc::CMSG_NXTHDR(std::ptr::from_ref(msg), header) };
    }
    (destination, interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `sa_family_t` from `libc`'s `AF_*` constant, which is an `i32`.
    fn family(af: i32) -> libc::sa_family_t {
        libc::sa_family_t::try_from(af).expect("AF_* fits sa_family_t")
    }

    /// A width-checked decode over a genuinely kernel-shaped buffer, without a
    /// syscall: the check that a short `msg_namelen` is refused rather than read
    /// out of a zeroed `sockaddr_storage`.
    #[test]
    fn a_short_peer_address_is_refused_rather_than_read_from_padding() {
        // SAFETY: `sockaddr_storage` is plain-old-data; an all-zero value is a
        // valid instance.
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        name.ss_family = family(libc::AF_INET);
        let short = socklen(size_of::<libc::sockaddr_in>() - 1);
        assert!(read_source(&name, short).is_err());
        assert!(read_source(&name, socklen(size_of::<libc::sockaddr_in>())).is_ok());
    }

    #[test]
    fn an_unexpected_address_family_is_refused_rather_than_guessed() {
        // SAFETY: as above.
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        name.ss_family = family(libc::AF_UNIX);
        assert!(read_source(&name, 128).is_err());
    }

    #[test]
    fn a_v4_peer_decodes_to_its_octets_and_host_order_port() {
        // SAFETY: as above.
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let sin = libc::sockaddr_in {
            sin_family: family(libc::AF_INET),
            sin_port: 51820u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([198, 51, 100, 7]),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: exactly `size_of::<sockaddr_in>()` bytes are copied from a
        // live local into a `sockaddr_storage`, which is strictly larger; the
        // two do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(&sin).cast::<u8>(),
                std::ptr::from_mut(&mut name).cast::<u8>(),
                size_of::<libc::sockaddr_in>(),
            );
        }
        let got = read_source(&name, socklen(size_of::<libc::sockaddr_in>())).expect("decodes");
        assert_eq!(
            got,
            SourceAddr::V4 {
                octets: [198, 51, 100, 7],
                port: 51820,
            }
        );
    }

    /// The hand-written C layouts are asserted against `libc`'s own `size_of`,
    /// so a drifting offset fails the build rather than corrupting a candidate.
    /// The bionic/glibc width difference, made a value rather than a panic.
    #[test]
    fn a_kernel_interface_index_narrows_totally_and_absence_is_a_value() {
        assert_eq!(ifindex(7_i32), Some(7));
        assert_eq!(ifindex(7_u32), Some(7));
        // Zero is what the kernel writes when it did not supply one.
        assert_eq!(ifindex(0_i32), None);
        assert_eq!(ifindex(0_u32), None);
        // Negative is impossible from a healthy kernel and is refused rather
        // than reinterpreted as a very large index.
        assert_eq!(ifindex(-1_i32), None);
        assert_eq!(ifindex(i32::MIN), None);
        // And the widest legitimate value still passes. `unsigned_abs` rather
        // than `as u32` for the same reason as everything else in this module:
        // a total conversion, not a reinterpretation that happens to be exact.
        assert_eq!(ifindex(i32::MAX), Some(i32::MAX.unsigned_abs()));
    }

    /// The width class this module is built against, pinned on whichever ABI the
    /// test happens to run on.
    ///
    /// **`socklen_t` is `i32` on the two 32-bit Android ABIs and `u32` on the two
    /// 64-bit ones**, which is what broke `armv7-linux-androideabi` when this
    /// length was written as a `u32`. The assertions below hold on all four
    /// because none of them names a width — they name the real bound (128 bytes
    /// of `sockaddr_storage`) and the refusal direction.
    #[test]
    fn a_peer_address_length_is_declared_not_saturated() {
        // The only real caller's value survives intact on every ABI.
        let real = size_of::<libc::sockaddr_storage>();
        assert_eq!(real, 128, "sockaddr_storage is 128 bytes on all four ABIs");
        assert_eq!(usize::try_from(socklen(real)).unwrap_or(0), real);

        // And an impossible one REFUSES rather than saturating. A saturated
        // `socklen_t::MAX` would tell the kernel it may write two gigabytes into
        // a 128-byte stack local; zero tells it to write no address at all.
        assert_eq!(socklen(usize::MAX), 0);
        // Which `read_source` then refuses, rather than reading a peer identity
        // out of a buffer the kernel never filled.
        // SAFETY: `sockaddr_storage` is plain-old-data; an all-zero value is a
        // valid instance.
        let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        name.ss_family = family(libc::AF_INET);
        assert!(read_source(&name, socklen(usize::MAX)).is_err());
    }

    /// A link-local arrival address with no interface index is refused, which is
    /// what makes the `None` above safe rather than merely quiet.
    #[test]
    fn a_link_local_arrival_with_no_interface_is_refused_not_zoneless() {
        let mut octets = [0u8; 16];
        octets[0] = 0xfe;
        octets[1] = 0x80;
        octets[15] = 3;
        assert!(addr::v6_from_kernel(octets, 0).is_err());
        assert!(addr::v6_from_kernel(octets, 4).is_ok());
    }

    #[test]
    fn the_control_buffer_holds_both_pktinfo_shapes_with_room_for_alignment() {
        let v4 = cmsg_len(size_of::<libc::in_pktinfo>());
        let v6 = cmsg_len(size_of::<libc::in6_pktinfo>());
        assert!(
            v4 + v6 <= CONTROL_BYTES,
            "both families must fit: v4 {v4}, v6 {v6}, buffer {CONTROL_BYTES}"
        );
        assert_eq!(size_of::<libc::in_pktinfo>(), 12);
        assert_eq!(size_of::<libc::in6_pktinfo>(), 20);
    }
}
