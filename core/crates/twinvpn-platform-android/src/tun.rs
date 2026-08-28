//! [`TunnelDevice`]: the `ParcelFileDescriptor` the system hands back from
//! `VpnService.Builder.establish()`, detached to a raw descriptor.
//!
//! **Authority:** ADR-0018 **PB-1** (Android: *"`ParcelFileDescriptor` detached
//! to a raw fd at setup — **0** per-packet crossings; one JNI call at setup,
//! then direct reads"*), §11.2 row 2.3, DP-4; `docs/networking.md` §5.1 and
//! §5.2's Android row; ADR-0012 §11.6.
//!
//! # "Created DOWN" on a platform where creation *is* configuration
//!
//! `docs/networking.md` §5.1 requires `create_interface` to yield an interface
//! that is **down**, because *"an interface that comes up before its addresses,
//! routes and rules are installed is the partial-application leak window"*.
//! Android has no such call: `VpnService.Builder` accumulates addresses, routes,
//! DNS and MTU and then `establish()` creates a fully configured, already-live
//! interface in one step. There is no moment at which an unconfigured Android
//! tun exists.
//!
//! The rule is therefore honoured by **splitting it the other way**:
//!
//! | Seam call | Android |
//! |---|---|
//! | `create_interface(name, mtu)` | **reserves a handle and records the request. Nothing is established, so nothing exists to leak through** |
//! | `apply(contract)` | renders the programme ([`crate::builder`]) and calls `establish()` once, with addresses, routes, DNS and the claim already complete |
//! | `set_link(Up/Down)` | flips whether the datapath forwards. **The claim is untouched** — see [`crate::posture`] |
//! | `destroy_interface` | closes the descriptor. Idempotent; safe after a crash |
//!
//! The property §5.1 is protecting — no traffic crosses a half-configured
//! interface — holds more strongly here than on Linux, because there is no
//! interval in which a partially configured interface exists at all.
//!
//! # `set_mtu` after establish, and the tradeoff taken
//!
//! `docs/networking.md` §6.2's DPLPMTUD *"raises and lowers this as it probes"*.
//! Android cannot: `Builder.setMtu` is only readable at `establish()`, so
//! changing it means establishing again — which tears the route claim down and
//! rebuilds it, opening the window with **nothing claimed** that
//! [`crate::posture`] exists to keep closed. Between a probeable MTU and a
//! leak-free swap, this adapter takes the leak-free swap and reports
//! [`PlatformError::OsUnsupported`], which is the seam's documented way to state
//! a host fact.
//!
//! The consequence is stated rather than hidden: **on Android the tunnel MTU is
//! fixed for the life of a generation.** DPLPMTUD still functions — it is the
//! *outer* path that it probes, and the core clamps its own payload — but the
//! inner interface MTU cannot follow it downward without a new generation. This
//! is reported as a finding.
//!
//! # The `unsafe` in this module
//!
//! Two blocks, both on an open descriptor with a live slice of its true length:
//! the `read` and the `write` that carry packets. Everything else — the
//! readiness wait, the fd's lifetime, the handle table — is safe Rust.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use twinvpn_platform::iface::InterfaceName;
use twinvpn_platform::{Datapath, LinkState, PlatformError, TunnelDevice, TunnelHandle};

use crate::hostcall::{RawFd, TunnelController};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// One reserved tunnel.
#[derive(Debug)]
struct Slot {
    name: InterfaceName,
    mtu: u32,
    link: LinkState,
    fd: Option<Arc<AsyncFd<OwnedTun>>>,
}

/// A descriptor this crate owns, closed exactly once on drop.
///
/// A newtype rather than a bare `RawFd` so the close is tied to the value's
/// lifetime: a double close on a descriptor the JVM has already recycled would
/// close **somebody else's** file, which on a process holding the tun and every
/// protected socket is the worst possible aliasing bug.
#[derive(Debug)]
pub struct OwnedTun {
    fd: RawFd,
}

impl OwnedTun {
    /// Takes ownership of a descriptor detached from a `ParcelFileDescriptor`.
    #[must_use]
    pub const fn from_raw(fd: RawFd) -> Self {
        Self { fd }
    }

    /// The descriptor, for a call that does not take ownership.
    #[must_use]
    pub const fn as_raw(&self) -> RawFd {
        self.fd
    }
}

impl std::os::fd::AsRawFd for OwnedTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for OwnedTun {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: `self.fd` was detached from a `ParcelFileDescriptor` (or,
            // in a test, from a `socketpair`) and is owned solely by this value
            // — `OwnedTun` is neither `Clone` nor `Copy`, and the only
            // constructor takes the descriptor by value. Drop runs once, so the
            // descriptor is closed once.
            unsafe { libc::close(self.fd) };
        }
    }
}

/// The tunnel device, and the registry [`crate::netcfg`] shares with it.
#[derive(Debug, Clone)]
pub struct AndroidTunnelDevice {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    controller: Arc<dyn TunnelController>,
    slots: Mutex<BTreeMap<u64, Slot>>,
    next: AtomicU64,
    shutdown: ShutdownLatch,
}

impl AndroidTunnelDevice {
    /// Builds the device over `controller`.
    #[must_use]
    pub fn new(controller: Arc<dyn TunnelController>, shutdown: ShutdownLatch) -> Self {
        Self {
            inner: Arc::new(Inner {
                controller,
                slots: Mutex::new(BTreeMap::new()),
                // Handle 0 is never issued: a zero handle is what an uninitialised
                // `uint64_t` looks like across `twinvpn.h`'s F-9 vtable, and a
                // table that answers to it would accept a caller that never
                // created anything.
                next: AtomicU64::new(1),
                shutdown,
            }),
        }
    }

    /// Establishes the interface for `handle` from a rendered programme.
    ///
    /// Called by [`crate::netcfg`] inside `apply`, because on Android the
    /// programme *is* the configuration and there is no earlier moment at which
    /// an interface could exist. Replaces any descriptor already held for the
    /// handle, closing it — which is what `establish()` does on the platform
    /// side too.
    ///
    /// # Errors
    ///
    /// Whatever [`TunnelController::establish`] reports, plus
    /// [`PlatformError::AdapterUnavailable`] if the handle is unknown or the
    /// descriptor cannot be driven.
    pub fn establish(
        &self,
        handle: TunnelHandle,
        programme: &crate::builder::Programme,
    ) -> Result<(), PlatformError> {
        self.inner.shutdown.check()?;
        let fd = self.inner.controller.establish(programme)?;
        if fd < 0 {
            return Err(oserr::unavailable(
                "VpnService.Builder.establish",
                libc::EBADF,
            ));
        }
        let owned = OwnedTun::from_raw(fd);
        set_nonblocking(&owned)?;
        let driven = AsyncFd::with_interest(owned, Interest::READABLE | Interest::WRITABLE)
            .map_err(|e| oserr::from_errno(&e, "AsyncFd::new(tun)", Context::TunnelDevice))?;
        let mut slots = self.slots()?;
        let slot = slots
            .get_mut(&handle.0)
            .ok_or_else(|| oserr::unavailable("tun.handle", libc::ENODEV))?;
        slot.fd = Some(Arc::new(driven));
        Ok(())
    }

    /// Whether the OS still holds a live descriptor for `handle`.
    ///
    /// This is the **OS-observed half** of the enforcement read-back described
    /// in [`crate::posture`]: the system closes the descriptor on `onRevoke()`,
    /// when another app takes the VPN slot, and on process death, so its
    /// validity is the platform's own answer to "is our claim still in force"
    /// rather than this process's belief.
    #[must_use]
    pub fn claim_in_force(&self, handle: TunnelHandle) -> bool {
        let Ok(slots) = self.slots() else {
            return false;
        };
        let Some(slot) = slots.get(&handle.0) else {
            return false;
        };
        let Some(fd) = slot.fd.as_ref() else {
            return false;
        };
        // `fcntl(F_GETFD)` is the cheapest question the kernel answers about a
        // descriptor and it does not disturb it. A descriptor the system has
        // reclaimed answers EBADF.
        //
        // SAFETY: `fcntl` with `F_GETFD` reads a flag word for the given
        // descriptor and touches no caller memory. The descriptor is borrowed
        // from a live `AsyncFd<OwnedTun>` for the duration of the call.
        let rc = unsafe { libc::fcntl(fd.get_ref().as_raw(), libc::F_GETFD) };
        rc >= 0
    }

    /// The interface name the core asked for, for a diagnostic that must name
    /// the interface it is talking about.
    ///
    /// `InterfaceName`'s `Debug` is redacted (ADR-0015 §11.4 classes an
    /// interface name `SENSITIVE`), so this is for a caller that has a reason,
    /// not for a log line.
    #[must_use]
    pub fn interface_name(&self, handle: TunnelHandle) -> Option<InterfaceName> {
        self.slots()
            .ok()?
            .get(&handle.0)
            .map(|slot| slot.name.clone())
    }

    /// The handle currently established, if any.
    #[must_use]
    pub fn established_handle(&self) -> Option<TunnelHandle> {
        let slots = self.slots().ok()?;
        slots
            .iter()
            .find(|(_, slot)| slot.fd.is_some())
            .map(|(id, _)| TunnelHandle(*id))
    }

    fn slots(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<u64, Slot>>, PlatformError> {
        self.inner
            .slots
            .lock()
            .map_err(|_| oserr::unavailable("tun.lock", libc::EDEADLK))
    }

    fn descriptor(&self, handle: TunnelHandle) -> Result<Arc<AsyncFd<OwnedTun>>, PlatformError> {
        let slots = self.slots()?;
        slots
            .get(&handle.0)
            .and_then(|slot| slot.fd.clone())
            .ok_or(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                libc::ENODEV,
                "tun.descriptor",
            ))))
    }
}

/// Puts a descriptor into non-blocking mode.
///
/// The programme already asks `Builder.setBlocking(false)`, but a descriptor
/// that arrived from somewhere else — a test `socketpair`, a future OEM path —
/// must not silently park a runtime worker, so it is asserted rather than
/// assumed.
fn set_nonblocking(tun: &OwnedTun) -> Result<(), PlatformError> {
    // SAFETY: both `fcntl` calls read and write only the descriptor's own flag
    // word and touch no caller memory. `tun` is a live owned descriptor for the
    // duration of both calls.
    let flags = unsafe { libc::fcntl(tun.as_raw(), libc::F_GETFL) };
    if flags < 0 {
        return Err(oserr::from_errno(
            &io::Error::last_os_error(),
            "fcntl(F_GETFL, tun)",
            Context::TunnelDevice,
        ));
    }
    // SAFETY: as above.
    let rc = unsafe { libc::fcntl(tun.as_raw(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(oserr::from_errno(
            &io::Error::last_os_error(),
            "fcntl(F_SETFL, tun)",
            Context::TunnelDevice,
        ));
    }
    Ok(())
}

impl TunnelDevice for AndroidTunnelDevice {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            self.inner.shutdown.check()?;
            let handle = TunnelHandle(self.inner.next.fetch_add(1, Ordering::SeqCst));
            self.slots()?.insert(
                handle.0,
                Slot {
                    name: name.clone(),
                    mtu,
                    // Created DOWN, and on Android that is not a claim about a
                    // link state the OS holds: no interface exists yet at all,
                    // which is a stronger form of the same guarantee.
                    link: LinkState::Down,
                    fd: None,
                },
            );
            Ok(handle)
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.inner.shutdown.check()?;
            let mut slots = self.slots()?;
            let slot = slots
                .get_mut(&handle.0)
                .ok_or_else(|| oserr::unavailable("tun.handle", libc::ENODEV))?;
            // The descriptor and the claim are NOT touched. `LinkState`'s own
            // documentation: "Enforcement rules stay installed — the two are
            // separate facts, which is why they are separate calls."
            slot.link = state;
            Ok(())
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // NOT gated on the shutdown latch: destroy is idempotent and safe
            // after a crash by its own contract, and refusing it during shutdown
            // would leak a descriptor for the life of the process.
            let removed = self.slots()?.remove(&handle.0);
            if let Some(slot) = removed {
                if let Some(fd) = slot.fd {
                    let raw = fd.get_ref().as_raw();
                    drop(fd);
                    // Tell the JVM as well, so its `ParcelFileDescriptor`
                    // bookkeeping matches ours. An error here is not fatal: the
                    // descriptor is already closed on our side.
                    let _ = self.inner.controller.close_tun(raw);
                }
            }
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        // ADR-0018 §11.2 row 2.3: the kernel WireGuard module is a Linux and
        // OpenWrt fact. On Android the core IS the datapath, reading and writing
        // the tun descriptor itself.
        Datapath::Userspace
    }

    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.inner.shutdown.check()?;
            let fd = self.descriptor(handle)?;
            loop {
                let mut ready = fd
                    .readable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "tun.readable", Context::TunnelDevice))?;
                let attempt = ready.try_io(|inner| {
                    // SAFETY: `read` writes at most `buf.len()` bytes through the
                    // pointer it is given. `buf` is a live, exclusively borrowed
                    // slice of exactly that length, and the descriptor is
                    // borrowed from a live `AsyncFd<OwnedTun>`.
                    let n = unsafe {
                        libc::read(
                            inner.get_ref().as_raw(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n.unsigned_abs())
                    }
                });
                match attempt {
                    // The readiness was stale; wait again.
                    // Stale readiness: fall out of the match and wait again.
                    Err(_would_block) => {}
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => {
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
            self.inner.shutdown.check()?;
            let fd = self.descriptor(handle)?;
            loop {
                let mut ready = fd
                    .writable()
                    .await
                    .map_err(|e| oserr::from_errno(&e, "tun.writable", Context::TunnelDevice))?;
                let attempt = ready.try_io(|inner| {
                    // SAFETY: `write` reads at most `packet.len()` bytes through
                    // the pointer it is given. `packet` is a live, shared-borrowed
                    // slice of exactly that length, and the descriptor is
                    // borrowed from a live `AsyncFd<OwnedTun>`.
                    let n = unsafe {
                        libc::write(
                            inner.get_ref().as_raw(),
                            packet.as_ptr().cast::<libc::c_void>(),
                            packet.len(),
                        )
                    };
                    if n < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(n.unsigned_abs())
                    }
                });
                match attempt {
                    // Stale readiness: fall out of the match and wait again.
                    Err(_would_block) => {}
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => {
                        return Err(oserr::from_errno(&e, "write(tun)", Context::TunnelDevice))
                    }
                }
            }
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.inner.shutdown.check()?;
            let recorded = self.slots()?.get(&handle.0).map(|slot| slot.mtu);
            // Idempotence is free and worth having: DPLPMTUD re-asserting the
            // value already in force must not be reported as a platform failure.
            if recorded == Some(mtu) {
                return Ok(());
            }
            // See the module documentation. Refused, with the fact stated, and
            // never emulated by a re-`establish()` that would drop the claim.
            Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
                i32::try_from(mtu).unwrap_or(i32::MAX),
                "VpnService.Builder.setMtu",
            ))))
        })
    }
}

#[cfg(test)]
mod tests;
