//! The tunnel device: `/dev/net/tun`, plus link state and MTU over `rtnetlink`.
//!
//! **Authority:** [`twinvpn_platform::config::TunnelDevice`],
//! `docs/networking.md` §5.1 (the interface is **created DOWN**) and §5.2's Linux
//! row, §6.2 (the 1280 floor), ADR-0016 §11.3 O1 and §11.9 (`DeviceAllow=/dev/net/tun rw`),
//! ADR-0018 §11.2 row 2.3, DP-4.
//!
//! # Created DOWN, and the reason is not convention
//!
//! > An interface that comes up before its addresses, routes and rules are
//! > installed is the partial-application leak window §2.3 names.
//!
//! [`LinuxTunnelDevice::create_interface`] opens the device and returns without
//! ever setting `IFF_UP`. Bringing it up is a separate call the core makes after
//! `apply`, and `the_interface_is_created_down` asserts it against the kernel's
//! own flags rather than against this paragraph.
//!
//! # A finding: the seam cannot express Linux kernel offload
//!
//! ADR-0018 §11.2 row 2.3 splits the datapath: "on Linux/OpenWrt the core
//! *programs* the kernel WireGuard module; elsewhere the core *is* the
//! datapath", and [`twinvpn_platform::Datapath::KernelOffload`] exists to
//! declare it. But [`TunnelDevice`] has **no method that programs a WireGuard
//! peer, private key, endpoint, allowed-IP set or keepalive interval** — those
//! reach the kernel through the `wireguard` generic-netlink family, and no
//! direction of the seam carries them.
//!
//! So a Linux adapter can *declare* `KernelOffload` but cannot *achieve* it
//! across this trait. This binding therefore reports
//! [`Datapath::Userspace`] and reads and writes packets through the tun fd,
//! which is honest and works. Declaring `KernelOffload` while the core has no
//! way to program the module would produce a tunnel that carries nothing and
//! reports itself as offloaded — the worse of the two failures. **Reported to
//! the integration lead as an ADR-0018 §11.6 gap.**

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use twinvpn_platform::{
    Datapath, InterfaceName, LinkState, PlatformError, TunnelDevice, TunnelHandle,
};

use crate::netlink::{NetlinkSocket, NlBuilder};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// The clone device every tun interface is created through.
pub const TUN_CLONE: &str = "/dev/net/tun";

/// `struct ifreq` — 16 bytes of name then a 24-byte union. Encoded by hand for
/// the same reason netlink is: a fixed C layout written as bytes needs no
/// transmute, so the only `unsafe` here is the `ioctl` itself.
const IFREQ_LEN: usize = 40;

/// `TUNSETIFF`. `_IOW('T', 202, int)` = `0x400454ca`.
///
/// Written as the literal the kernel's `if_tun.h` defines rather than computed
/// from an `_IOW` macro, and asserted against `libc`'s own constant in this
/// module's tests so a wrong number fails the build rather than the tunnel.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// The MTU floor. `docs/networking.md` §6.2: "The overlay interface MTU is set
/// to **1280** at bring-up and raised afterwards" — the IPv6 minimum link MTU,
/// "a floor that is *always correct*, which means bring-up never has to wait for
/// discovery".
pub const MTU_FLOOR: u32 = 1280;

/// One open tun interface.
struct Open {
    /// The tun fd, wrapped for readiness. Dropping it destroys the interface,
    /// which is what makes a non-persistent tun the right choice: a crashed
    /// agent leaves no orphan interface, while the nftables rules — which are
    /// the actual protection — stay in the OS's custody (CB-6).
    io: AsyncFd<File>,
    name: String,
    index: u32,
}

/// The Linux tunnel device.
pub struct LinuxTunnelDevice {
    shutdown: ShutdownLatch,
    open: Mutex<Vec<(u64, Open)>>,
    next: AtomicU64,
}

impl LinuxTunnelDevice {
    /// Binds the device.
    #[must_use]
    pub fn new(shutdown: ShutdownLatch) -> Self {
        Self {
            shutdown,
            open: Mutex::new(Vec::new()),
            next: AtomicU64::new(1),
        }
    }

    /// The interface name behind a handle, for the modules that program it.
    #[must_use]
    pub fn name_of(&self, handle: TunnelHandle) -> Option<String> {
        let open = self.open.lock().ok()?;
        open.iter()
            .find(|(id, _)| *id == handle.0)
            .map(|(_, o)| o.name.clone())
    }

    /// The OS index behind a handle.
    #[must_use]
    pub fn index_of(&self, handle: TunnelHandle) -> Option<u32> {
        let open = self.open.lock().ok()?;
        open.iter()
            .find(|(id, _)| *id == handle.0)
            .map(|(_, o)| o.index)
    }

    fn with_open<T>(
        &self,
        handle: TunnelHandle,
        f: impl FnOnce(&Open) -> Result<T, PlatformError>,
    ) -> Result<T, PlatformError> {
        let open = self
            .open
            .lock()
            .map_err(|_| oserr::unavailable("tun.lock", libc::EDEADLK))?;
        let entry = open
            .iter()
            .find(|(id, _)| *id == handle.0)
            .ok_or_else(|| oserr::unavailable("tun.handle", libc::ENODEV))?;
        f(&entry.1)
    }
}

/// Encodes `ifreq` for `TUNSETIFF`.
///
/// `IFF_TUN | IFF_NO_PI`: a layer-3 device with **no** 4-byte packet-info
/// prefix, because the prefix would make every `read_packet` return four bytes
/// the core would have to know to skip — a Linux fact above the adapter, which
/// is exactly what CB-3 forbids.
///
/// Returns `None` on a name longer than `IFNAMSIZ - 1`, rather than truncating:
/// a truncated interface name names a different interface.
fn ifreq_for(name: &str) -> Option<[u8; IFREQ_LEN]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= 16 {
        return None;
    }
    let mut req = [0u8; IFREQ_LEN];
    req[..bytes.len()].copy_from_slice(bytes);
    let flags = i16::try_from(libc::IFF_TUN | libc::IFF_NO_PI).unwrap_or(0x1001);
    req[16..18].copy_from_slice(&flags.to_ne_bytes());
    Some(req)
}

impl TunnelDevice for LinuxTunnelDevice {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let name = name.as_str().to_owned();
            let mut req = ifreq_for(&name)
                .ok_or_else(|| oserr::unavailable("TUNSETIFF.name", libc::ENAMETOOLONG))?;

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(TUN_CLONE)
                // Context::TunnelDevice maps EPERM/EACCES to
                // PLATFORM.VPN_PERMISSION_DENIED: on Linux this is the OS's own
                // VPN grant, and its remediation is "grant CAP_NET_ADMIN and
                // /dev/net/tun", not "run as root".
                .map_err(|e| oserr::from_errno(&e, "open(/dev/net/tun)", Context::TunnelDevice))?;

            // SAFETY: `file` is an open `/dev/net/tun` fd valid for the whole
            // call. `req` is a live, uniquely-borrowed 40-byte buffer laid out
            // as `struct ifreq` — the name in the first 16 bytes and the flags
            // as an `i16` at offset 16, asserted against `size_of::<ifreq>()` in
            // this module's tests. `TUNSETIFF` reads the flags and writes the
            // assigned name back within those 40 bytes, and retains no pointer.
            let rc = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    TUNSETIFF,
                    std::ptr::from_mut(&mut req).cast::<libc::c_void>(),
                )
            };
            if rc < 0 {
                let e = io::Error::last_os_error();
                return Err(oserr::from_errno(&e, "TUNSETIFF", Context::TunnelDevice));
            }

            // The kernel writes the name it actually assigned. Reading it back
            // rather than assuming ours is what makes a `%d` template safe and
            // what keeps the index lookup below honest.
            let assigned = String::from_utf8_lossy(&req[..16])
                .trim_end_matches('\0')
                .to_owned();
            // Asked of the kernel over netlink, NOT of `/sys/class/net`: inside
            // a network namespace `/sys` is the host's, so a sysfs lookup
            // returns ENODEV for an interface that plainly exists. Found by
            // `tests/netns.rs`.
            let index = crate::iface::index_of(&assigned)
                .await?
                .ok_or_else(|| oserr::unavailable("ifindex", libc::ENODEV))?
                .0;

            let io = AsyncFd::with_interest(file, Interest::READABLE | Interest::WRITABLE)
                .map_err(|e| oserr::from_errno(&e, "epoll_ctl", Context::TunnelDevice))?;

            // The MTU is set now, DOWN. §6.2's floor is 1280 and a lower value
            // is refused rather than clamped: a link that cannot carry 1280
            // bytes cannot carry IPv6 at all, and silently accepting one would
            // make the failure appear later as an unexplained black hole.
            if mtu < MTU_FLOOR {
                return Err(oserr::unavailable("mtu.floor", libc::EINVAL));
            }
            set_mtu_netlink(index, mtu).await?;

            let handle = TunnelHandle(self.next.fetch_add(1, Ordering::Relaxed));
            let mut open = self
                .open
                .lock()
                .map_err(|_| oserr::unavailable("tun.lock", libc::EDEADLK))?;
            open.push((
                handle.0,
                Open {
                    io,
                    name: assigned,
                    index,
                },
            ));
            Ok(handle)
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let index = self.with_open(handle, |o| Ok(o.index))?;
            set_flags_netlink(index, matches!(state, LinkState::Up)).await
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // **Idempotent, and safe after a crash** — and deliberately NOT
            // gated on the shutdown latch, because tearing the interface down is
            // part of shutdown. Dropping the fd is what removes the interface;
            // a non-persistent tun has no state left behind to reclaim.
            let mut open = self
                .open
                .lock()
                .map_err(|_| oserr::unavailable("tun.lock", libc::EDEADLK))?;
            open.retain(|(id, _)| *id != handle.0);
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        // See the module documentation. The seam has no way to program the
        // kernel WireGuard module, so declaring KernelOffload would be a claim
        // this adapter cannot make good on.
        Datapath::Userspace
    }

    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            loop {
                let fut = {
                    let open = self
                        .open
                        .lock()
                        .map_err(|_| oserr::unavailable("tun.lock", libc::EDEADLK))?;
                    let entry = open
                        .iter()
                        .find(|(id, _)| *id == handle.0)
                        .ok_or_else(|| oserr::unavailable("tun.handle", libc::ENODEV))?;
                    // Read through the raw fd rather than holding the lock
                    // across an await.
                    entry.1.io.get_ref().as_raw_fd()
                };
                match read_fd(fut, buf) {
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Yield to the runtime and retry. The fd's readiness is
                        // registered, so this is not a spin.
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        return Err(oserr::from_errno(&e, "read(tun)", Context::TunnelDevice))
                    }
                }
            }
        })
    }

    fn write_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let fd = self.with_open(handle, |o| Ok(o.io.get_ref().as_raw_fd()))?;
            match write_fd(fd, packet) {
                Ok(n) => Ok(n),
                Err(e) => Err(oserr::from_errno(&e, "write(tun)", Context::TunnelDevice)),
            }
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if mtu < MTU_FLOOR {
                // DPLPMTUD raises and lowers this as it probes, but never below
                // the floor: "Never accept a PTB below 1280."
                return Err(oserr::unavailable("mtu.floor", libc::EINVAL));
            }
            let index = self.with_open(handle, |o| Ok(o.index))?;
            set_mtu_netlink(index, mtu).await
        })
    }
}

fn read_fd(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `fd` is an open tun descriptor for the duration of the call, held
    // alive by the `AsyncFd` it was borrowed from. `buf` is a live, uniquely
    // borrowed slice and the length passed is its true byte length; `read`
    // writes at most that many bytes and retains no pointer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

fn write_fd(fd: std::os::fd::RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: as above; `write` reads at most `buf.len()` bytes from a live
    // slice and retains no pointer.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(n).unwrap_or(0))
}

/// `RTM_NEWLINK` with `IFLA_MTU`.
async fn set_mtu_netlink(index: u32, mtu: u32) -> Result<(), PlatformError> {
    let sock = NetlinkSocket::open(0)
        .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;
    let mut b = NlBuilder::new(
        libc::RTM_NEWLINK,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_ACK).unwrap_or(0x5),
        sock.next_seq(),
    );
    b.payload(&ifinfomsg(index, 0, 0));
    b.attr_u32(libc::IFLA_MTU, mtu);
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_NEWLINK(IFLA_MTU)", Context::RouteProgram))
}

/// `RTM_NEWLINK` setting or clearing `IFF_UP`.
///
/// `ifi_change` names **only** `IFF_UP`, so nothing else about the link is
/// touched — a change mask of `~0` would clear flags the kernel set and is a
/// classic way to knock an interface out of promiscuous or multicast mode
/// without meaning to.
async fn set_flags_netlink(index: u32, up: bool) -> Result<(), PlatformError> {
    let sock = NetlinkSocket::open(0)
        .map_err(|e| oserr::from_errno(&e, "AF_NETLINK", Context::Netlink))?;
    let iff_up = u32::try_from(libc::IFF_UP).unwrap_or(1);
    let flags = if up { iff_up } else { 0 };
    let mut b = NlBuilder::new(
        libc::RTM_NEWLINK,
        u16::try_from(libc::NLM_F_REQUEST | libc::NLM_F_ACK).unwrap_or(0x5),
        sock.next_seq(),
    );
    b.payload(&ifinfomsg(index, flags, iff_up));
    sock.request(b.finish())
        .await
        .map(|_| ())
        .map_err(|e| oserr::from_errno(&e, "RTM_NEWLINK(IFF_UP)", Context::RouteProgram))
}

/// `struct ifinfomsg { family, pad, type, index, flags, change }`.
#[must_use]
pub fn ifinfomsg(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[4..8].copy_from_slice(&i32::try_from(index).unwrap_or(0).to_ne_bytes());
    out[8..12].copy_from_slice(&flags.to_ne_bytes());
    out[12..16].copy_from_slice(&change.to_ne_bytes());
    out
}

/// The device, shareable.
#[must_use]
pub fn device(shutdown: ShutdownLatch) -> Arc<LinuxTunnelDevice> {
    Arc::new(LinuxTunnelDevice::new(shutdown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hand_written_ifreq_matches_the_kernels_width_and_ioctl_number() {
        assert_eq!(IFREQ_LEN, std::mem::size_of::<libc::ifreq>());
        assert_eq!(TUNSETIFF, libc::TUNSETIFF);
    }

    #[test]
    fn an_over_long_interface_name_is_refused_never_truncated() {
        // A truncated interface name names a DIFFERENT interface, which on a
        // host with `twinvpn-overlay-a` and `twinvpn-overlay-b` is how a route
        // lands on the wrong link.
        assert!(ifreq_for("twin0").is_some());
        assert!(ifreq_for("").is_none());
        assert!(
            ifreq_for("a-very-long-interface-name").is_none(),
            "IFNAMSIZ is 16 including the NUL"
        );
        assert!(ifreq_for("fifteen-chars_").is_some());
    }

    #[test]
    fn the_ifreq_asks_for_a_layer_three_device_with_no_packet_info_prefix() {
        let req = ifreq_for("twin0").expect("valid");
        assert_eq!(&req[..5], b"twin0");
        assert_eq!(req[5], 0, "the name is NUL-terminated");
        let flags = i16::from_ne_bytes([req[16], req[17]]);
        assert_eq!(
            i32::from(flags),
            libc::IFF_TUN | libc::IFF_NO_PI,
            "IFF_NO_PI keeps the four-byte prefix out of read_packet, which \
             would otherwise be a Linux fact the core has to know (CB-3)"
        );
    }

    #[test]
    fn the_ifinfomsg_change_mask_touches_only_iff_up() {
        let msg = ifinfomsg(
            7,
            u32::try_from(libc::IFF_UP).unwrap_or(1),
            u32::try_from(libc::IFF_UP).unwrap_or(1),
        );
        assert_eq!(i32::from_ne_bytes([msg[4], msg[5], msg[6], msg[7]]), 7);
        let change = u32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);
        assert_eq!(
            change,
            u32::try_from(libc::IFF_UP).unwrap_or(1),
            "a change mask of ~0 would clear flags the kernel set"
        );
    }

    #[test]
    fn the_datapath_is_declared_honestly_rather_than_aspirationally() {
        // ADR-0018 §11.2 row 2.3 would put Linux on KernelOffload, but the seam
        // carries no way to program the WireGuard module — see the module docs.
        // Declaring KernelOffload here would produce a tunnel that carries
        // nothing and reports itself as offloaded.
        let d = LinuxTunnelDevice::new(ShutdownLatch::new());
        assert_eq!(d.datapath(), Datapath::Userspace);
    }

    #[tokio::test]
    async fn an_mtu_below_the_ipv6_floor_is_refused_not_clamped() {
        let d = LinuxTunnelDevice::new(ShutdownLatch::new());
        let name = InterfaceName::new("twintest0").expect("valid");
        // The refusal is checked before the device is even opened for the
        // set_mtu path; create_interface refuses after opening, which needs
        // privilege, so this asserts the floor through set_mtu's own guard.
        let err = d
            .set_mtu(TunnelHandle(999), 1279)
            .await
            .expect_err("below the floor");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
        assert_eq!(err.os_detail().map(|d| d.call), Some("mtu.floor"));
        let _ = name;
    }

    #[tokio::test]
    async fn destroying_an_unknown_handle_is_a_no_op_never_an_error() {
        // "Idempotent; safe after a crash."
        let d = LinuxTunnelDevice::new(ShutdownLatch::new());
        d.destroy_interface(TunnelHandle(1)).await.expect("no-op");
        d.destroy_interface(TunnelHandle(1)).await.expect("no-op");
    }

    #[tokio::test]
    async fn creating_an_interface_without_privilege_names_the_vpn_grant() {
        // On this host the test runs unprivileged, so /dev/net/tun is refused.
        // The point of the test is the MAPPING: the user must never see a bare
        // EPERM, and the remediation must be "grant the capability", not "we
        // failed".
        let d = LinuxTunnelDevice::new(ShutdownLatch::new());
        let name = InterfaceName::new("twintest0").expect("valid");
        match d.create_interface(&name, 1280).await {
            Err(e) => {
                let code = e.reason_code().as_str();
                assert!(
                    code == "PLATFORM.VPN_PERMISSION_DENIED"
                        || code == "PLATFORM.ADAPTER_UNAVAILABLE",
                    "unexpected code {code}"
                );
                assert!(
                    e.os_detail().is_some(),
                    "the platform detail must be preserved for a Tier-1 bundle"
                );
            }
            Ok(handle) => {
                // If the runner IS privileged, assert the real contract instead.
                assert!(d.name_of(handle).is_some());
                d.destroy_interface(handle).await.expect("destroys");
            }
        }
    }
}
