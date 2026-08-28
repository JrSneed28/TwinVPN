//! The Darwin constants and C layouts this adapter needs, written out once.
//!
//! **Authority:** ADR-0018 CB-3 and DP-4 (this crate is where `cfg` and `unsafe`
//! are permitted); `docs/implementation/ownership.md` §6.
//!
//! # Why the numbers are here rather than taken from `libc`
//!
//! Two reasons, and the first is the important one.
//!
//! 1. **They must be readable on a Linux host.** `AF_INET6` is 10 on Linux and 30
//!    on Darwin; `IP_DONTFRAG` does not exist on Linux at all. The decoders and
//!    option planners that use these constants are target-free precisely so
//!    `cargo test` executes them here, and a constant taken from `libc` would be
//!    the *host's* value in exactly the tests that are supposed to check the
//!    Darwin behaviour.
//! 2. **`libc`'s Darwin coverage of the `PF_SYSTEM` control API is not something
//!    to depend on silently.** `ctl_info`, `sockaddr_ctl` and `CTLIOCGINFO` are
//!    declared here with their `<sys/kern_control.h>` definitions and their sizes
//!    asserted in tests, so a drifting layout fails the build rather than
//!    corrupting a `connect`.
//!
//! Every constant carries the header it came from. Nothing here is guessed; where
//! a value could not be confirmed from a header, it is **absent** rather than
//! approximated.
//!
//! # A stated limit
//!
//! These values were written from the Darwin headers as documented, and **no
//! Darwin machine was available to check them against a running kernel**. The
//! layout assertions below check internal consistency (sizes, offsets, the
//! `_IOWR` encoding) — they cannot check that Apple's number for
//! `IPV6_BOUND_IF` is 125. That is a compile-and-review claim, not a runtime one,
//! and it is listed as a gap in `shells/macos/README.md` §7.

/// `<sys/socket.h>`: the `PF_SYSTEM` protocol family, the door to `utun`.
pub const PF_SYSTEM: libc::c_int = 32;

/// `<sys/socket.h>`: `AF_SYSTEM`, the same number in its address-family spelling.
pub const AF_SYSTEM: u8 = 32;

/// `<sys/kern_control.h>`: `SYSPROTO_CONTROL`.
pub const SYSPROTO_CONTROL: libc::c_int = 2;

/// `<sys/sys_domain.h>`: `AF_SYS_CONTROL`, the `ss_sysaddr` value.
pub const AF_SYS_CONTROL: u16 = 2;

/// `<sys/kern_control.h>`: `MAX_KCTL_NAME`.
pub const MAX_KCTL_NAME: usize = 96;

/// `<net/if_utun.h>`: `UTUN_OPT_IFNAME`, the `getsockopt` that reveals which
/// `utunN` the kernel gave us.
pub const UTUN_OPT_IFNAME: libc::c_int = 2;

/// `<sys/kern_control.h>`: `CTLIOCGINFO`, `_IOWR('N', 3, struct ctl_info)`.
///
/// The encoding is checked in this module's tests rather than trusted: an `ioctl`
/// number that is wrong by one bit fails at runtime on a machine nobody here has.
pub const CTLIOCGINFO: libc::c_ulong = iowr(b'N', 3, core::mem::size_of::<CtlInfo>());

/// `<sys/ioccom.h>`'s `_IOWR(g, n, t)`.
///
/// `IOC_INOUT` is `0xC000_0000`, the length occupies bits 16..29 masked by
/// `IOCPARM_MASK` (`0x1fff`), the group is bits 8..15 and the number is bits
/// 0..7.
const fn iowr(group: u8, number: u8, size: usize) -> libc::c_ulong {
    const IOC_INOUT: u64 = 0xC000_0000;
    const IOCPARM_MASK: u64 = 0x1fff;
    (IOC_INOUT | (((size as u64) & IOCPARM_MASK) << 16) | ((group as u64) << 8) | (number as u64))
        as libc::c_ulong
}

/// `<sys/kern_control.h>`: `struct ctl_info`.
///
/// 100 bytes: a `u32` id followed by a 96-byte NUL-terminated name.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CtlInfo {
    /// Filled in by `CTLIOCGINFO`.
    pub ctl_id: u32,
    /// The control name, NUL-padded. `com.apple.net.utun_control` for `utun`.
    pub ctl_name: [libc::c_char; MAX_KCTL_NAME],
}

impl Default for CtlInfo {
    fn default() -> Self {
        Self {
            ctl_id: 0,
            ctl_name: [0; MAX_KCTL_NAME],
        }
    }
}

impl CtlInfo {
    /// A `ctl_info` naming `name`, or `None` if the name does not fit.
    ///
    /// Refuses rather than truncating: a truncated control name resolves to a
    /// different kernel control, or to none, and both are worse than a refusal.
    #[must_use]
    // `ctl_name` is `char[96]`, and `c_char` is signed on every target this crate
    // builds for. A UTF-8 byte above 127 wraps to a negative `c_char`, which is
    // exactly the byte the kernel expects to read back.
    #[allow(clippy::cast_possible_wrap)]
    pub fn named(name: &str) -> Option<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= MAX_KCTL_NAME {
            return None;
        }
        let mut info = Self::default();
        for (slot, byte) in info.ctl_name.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        Some(info)
    }
}

/// `<sys/kern_control.h>`: `struct sockaddr_ctl`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockaddrCtl {
    /// `sizeof(struct sockaddr_ctl)`.
    pub sc_len: u8,
    /// [`AF_SYSTEM`].
    pub sc_family: u8,
    /// [`AF_SYS_CONTROL`].
    pub ss_sysaddr: u16,
    /// The control id from `CTLIOCGINFO`.
    pub sc_id: u32,
    /// The unit. `0` means "any free one"; `N + 1` asks for `utunN`.
    pub sc_unit: u32,
    /// Reserved; must be zero.
    pub sc_reserved: [u32; 5],
}

impl SockaddrCtl {
    /// The address that connects to control `id`, unit `unit`.
    ///
    /// `unit` is the **kernel's** convention: `0` is "allocate a free one", and
    /// `utun7` is unit `8`. [`crate::utun::unit_for_index`] is where that off-by-
    /// one lives, once.
    #[must_use]
    pub fn new(id: u32, unit: u32) -> Self {
        Self {
            sc_len: u8::try_from(core::mem::size_of::<Self>()).unwrap_or(32),
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        }
    }
}

/// Darwin socket options that either do not exist on Linux or carry a different
/// number there. `<netinet/in.h>`, `<netinet6/in6.h>`.
pub mod sockopt {
    /// `IPPROTO_IP`.
    pub const IPPROTO_IP: i32 = 0;
    /// `IPPROTO_IPV6`.
    pub const IPPROTO_IPV6: i32 = 41;

    /// `IP_BOUND_IF` — bind a socket to one interface by index. Darwin's answer
    /// to `SO_BINDTODEVICE`, and the mechanism KS-9(2)'s "registered with the
    /// enforcement layer at bind time" reduces to here.
    pub const IP_BOUND_IF: i32 = 25;
    /// `IPV6_BOUND_IF`.
    pub const IPV6_BOUND_IF: i32 = 125;
    /// `IP_DONTFRAG` — Darwin's DF bit. Not Linux's `IP_MTU_DISCOVER`.
    pub const IP_DONTFRAG: i32 = 28;
    /// `IPV6_DONTFRAG`.
    pub const IPV6_DONTFRAG: i32 = 62;
    /// `IP_RECVDSTADDR` — half of Darwin's `IP_PKTINFO` equivalent.
    pub const IP_RECVDSTADDR: i32 = 7;
    /// `IP_RECVIF` — the other half. Darwin has **no** `IP_PKTINFO`, so
    /// [`twinvpn_platform::SocketOptions::receive_packet_info`] costs two options
    /// in v4 and one in v6.
    pub const IP_RECVIF: i32 = 20;
    /// `IPV6_RECVPKTINFO` — v6 does have one option for both facts.
    pub const IPV6_RECVPKTINFO: i32 = 61;
}

/// `<mach/mach_time.h>`: `struct mach_timebase_info`.
///
/// Declared here rather than taken from `libc`, whose Darwin `mach_timebase_info`
/// is **deprecated** in favour of the `mach2` crate — which `core/Cargo.toml`
/// does not carry and which this domain may not add. The struct is two `u32`s and
/// has been for the life of the API.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MachTimebaseInfo {
    /// The numerator.
    pub numer: u32,
    /// The denominator.
    pub denom: u32,
}

#[cfg(target_os = "macos")]
extern "C" {
    /// Suspend-**EXCLUSIVE** mach ticks — ADR-0022 LC-8's `MonotonicClock` row.
    pub fn mach_absolute_time() -> u64;

    /// Fills in the tick→nanosecond ratio. Returns `KERN_SUCCESS` (0) on success.
    pub fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;

    /// Suspend-**INCLUSIVE** mach ticks — ADR-0022 LC-8's `ElapsedClock` row.
    ///
    /// Declared here rather than taken from `libc` because `libc`'s Darwin
    /// coverage of it is not guaranteed, and because the pair it belongs to is
    /// the one LC-8 says is invisible when it is wrong: `mach_absolute_time`
    /// stops during sleep, `mach_continuous_time` does not. See [`crate::clock`],
    /// where the choice is made once.
    pub fn mach_continuous_time() -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_c_layouts_are_the_sizes_the_headers_declare() {
        // A drifting layout must fail the build rather than corrupt a `connect`
        // on a machine nobody here has.
        assert_eq!(core::mem::size_of::<CtlInfo>(), 100);
        assert_eq!(core::mem::align_of::<CtlInfo>(), 4);
        assert_eq!(core::mem::size_of::<SockaddrCtl>(), 32);
        let sa = SockaddrCtl::new(9, 8);
        assert_eq!(sa.sc_len, 32);
        assert_eq!(sa.sc_family, AF_SYSTEM);
        assert_eq!(sa.ss_sysaddr, AF_SYS_CONTROL);
        assert_eq!(sa.sc_reserved, [0; 5]);
    }

    #[test]
    fn the_ioctl_number_is_the_iowr_encoding_and_not_a_copied_constant() {
        // `_IOWR('N', 3, struct ctl_info)` with sizeof == 100:
        //   0xC0000000 | (100 << 16) | ('N' << 8) | 3 == 0xC0644E03
        assert_eq!(CTLIOCGINFO, 0xC064_4E03);
        assert_eq!(iowr(b'N', 3, 100), 0xC064_4E03);
    }

    #[test]
    fn a_control_name_that_does_not_fit_is_refused_and_never_truncated() {
        let info = CtlInfo::named("com.apple.net.utun_control").expect("fits");
        let name: Vec<u8> = info
            .ctl_name
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| u8::from_ne_bytes(c.to_ne_bytes()))
            .collect();
        assert_eq!(name, b"com.apple.net.utun_control");
        // A truncated control name resolves to a different kernel control, or to
        // none. Both are worse than a refusal.
        assert!(CtlInfo::named(&"a".repeat(MAX_KCTL_NAME)).is_none());
        assert!(CtlInfo::named(&"a".repeat(MAX_KCTL_NAME - 1)).is_some());
    }

    #[test]
    fn the_darwin_option_numbers_are_darwins() {
        // `IP_DONTFRAG` does not exist on Linux; `IPV6_BOUND_IF` is 125 on Darwin
        // and nothing on Linux. Reading either from `libc` here would compile and
        // be wrong.
        assert_eq!(sockopt::IP_DONTFRAG, 28);
        assert_eq!(sockopt::IPV6_DONTFRAG, 62);
        assert_eq!(sockopt::IP_BOUND_IF, 25);
        assert_eq!(sockopt::IPV6_BOUND_IF, 125);
        assert_eq!(sockopt::IPPROTO_IPV6, 41);
    }
}
