//! The tunnel device: the Wintun NDIS adapter, loaded dynamically.
//!
//! **Authority:** [`twinvpn_platform::config::TunnelDevice`],
//! `docs/networking.md` §5.1 (the interface is **created DOWN**), §5.3's Windows
//! row (ship Wintun app-locally, reclaim orphaned adapters rather than
//! duplicating them, set the interface metric explicitly), §6.2 (the 1280
//! floor); ADR-0016 §11.3 O1/O11 and §10 ("driver lifecycle is Windows-shaped
//! and is owned by the installer, not the service"); ADR-0018 §11.2 row 2.3,
//! §11.15's Windows row, DP-4; ADR-0022 LC-26.
//!
//! # Loaded dynamically, and the reason is not taste
//!
//! ADR-0016 §10: "WinTun's DLL and driver ship in the application directory,
//! versioned with the app; the service compares versions at startup and emits
//! `NET.DRIVER_REPLACED`; the uninstaller removes the adapter."
//!
//! A static import would make a missing or mismatched `wintun.dll` a **loader**
//! failure — the process fails to start with a Windows dialog nobody sees, and
//! the service reports nothing. ADR-0016 PS-18 wants the opposite: a named
//! startup refusal the diagnostic bundle carries. So the DLL is opened with
//! `LoadLibraryExW` and every entry point resolved with `GetProcAddress`, and a
//! failure at either step is a `reason_code`.
//!
//! # Reclaimed, never duplicated
//!
//! `docs/networking.md` §5.3: "on start, orphaned TwinVPN adapters (same GUID
//! namespace, no owning process) are **reclaimed rather than duplicated**", and
//! ADR-0022 LC-26 says the same of what a crash leaves behind. So
//! [`WindowsTunnelDevice::create_interface`] calls `WintunOpenAdapter` **before**
//! `WintunCreateAdapter`, and [`adapter_action`] is that ordering as a pure
//! function a test can exercise — because getting it backwards leaves a host
//! with two TwinVPN adapters, of which the older one still holds the routes the
//! previous generation installed.
//!
//! # Created DOWN, and the reason is not convention
//!
//! > An interface that comes up before its addresses, routes and rules are
//! > installed is the partial-application leak window §2.3 names.
//!
//! Wintun makes this the easy path rather than a discipline: creating an adapter
//! does not start a session, and an adapter with no session carries nothing. The
//! link comes up when [`TunnelDevice::set_link`] starts one, which is after the
//! core has applied a generation.
//!
//! # What is target-free here, and what is not
//!
//! **This host is Linux, and nothing in this crate can be linked or run on it.**
//! So the device is written against a [`TunnelDriver`], and the reclaim
//! ordering, the MTU floor, the handle lifecycle, the idempotent destroy, the
//! shutdown behaviour and the driver-version verdict all execute under
//! `cargo test` here. Only [`WintunDriver`] needs Windows, and it has **never
//! been executed** — `make cross-check` type-checks it and proves nothing about
//! its behaviour.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    Datapath, InterfaceName, LinkState, PlatformError, TunnelDevice, TunnelHandle,
};

use crate::oserr::{self, Context, Win32Error};
use crate::route::{InterfaceLuid, OverlayLuid};
use crate::shutdown::ShutdownLatch;

/// The DLL the installer places beside the service binary.
///
/// A bare name rather than a path: [`WintunDriver::load`] passes
/// `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, so the loader looks in the
/// application directory **and nowhere else**. ADR-0016 §11.9's
/// `ProcessImageLoadPolicy{NoRemoteImages, PreferSystem32}` is the same
/// intention at the process level: a `wintun.dll` on the search path is
/// somebody else's code running as `LocalSystem`.
pub const WINTUN_DLL: &str = "wintun.dll";

/// The tunnel type Wintun stamps on the adapter, visible in Network Connections.
pub const TUNNEL_TYPE: &str = "TwinVPN";

/// The MTU floor.
///
/// `docs/networking.md` §6.2: the overlay MTU "is set to **1280** at bring-up
/// and raised afterwards" — the IPv6 minimum link MTU, "a floor that is *always
/// correct*, which means bring-up never has to wait for discovery". A value
/// below it is **refused, never clamped**: a link that cannot carry 1280 bytes
/// cannot carry IPv6 at all, and silently accepting one makes the failure appear
/// later as an unexplained black hole.
pub const MTU_FLOOR: u32 = 1280;

/// The receive ring's capacity, in bytes.
///
/// **A decision recorded as one.** Wintun requires a power of two between 128
/// KiB and 64 MiB and the corpus pins no value. 4 MiB is Wintun's own
/// recommended default and holds roughly 2 800 full-MTU packets, which is about
/// 30 ms of a gigabit link — long enough that an ordinary scheduling delay does
/// not drop a packet, short enough that the buffer is not a latency store.
pub const RING_CAPACITY: u32 = 4 * 1024 * 1024;

/// `ERROR_NO_MORE_ITEMS` — Wintun's "the ring is empty" answer.
///
/// Defined here rather than in [`crate::oserr`] because it is not an error: it
/// is the ordinary empty-ring result, and putting it in the error table would
/// invite somebody to map it to a `reason_code`.
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

/// What a start should do about an adapter of this name.
///
/// A two-valued enum rather than a `bool`, so the call site reads as the rule it
/// implements rather than as a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterAction {
    /// One already exists: take it over. `docs/networking.md` §5.3's "reclaimed
    /// rather than duplicated", and ADR-0022 LC-26's "virtual interface
    /// reclaimed not duplicated".
    Reclaim,
    /// None exists: make one.
    Create,
}

/// The reclaim-before-create ordering, as a decision.
///
/// Trivial, and deliberately extracted: getting it backwards leaves a host with
/// two TwinVPN adapters after a crash, of which the older one still holds the
/// routes the previous generation installed — and the failure is invisible until
/// traffic takes the wrong one. A pure function is a thing a test can pin.
#[must_use]
pub const fn adapter_action(an_adapter_of_this_name_exists: bool) -> AdapterAction {
    if an_adapter_of_this_name_exists {
        AdapterAction::Reclaim
    } else {
        AdapterAction::Create
    }
}

/// What the startup version comparison found.
///
/// ADR-0016 §10: "the service compares versions at startup and emits
/// `NET.DRIVER_REPLACED`".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverVerdict {
    /// The running driver is the one this build ships.
    Current,
    /// It is not, and the installer must replace it.
    ///
    /// **Not this service's work.** ADR-0016 §10 puts the driver lifecycle with
    /// the installer, so the service *reports* and does not install: a service
    /// that replaced a kernel-mode driver at start would be doing an
    /// `ADMINISTER`-class act on every restart.
    Mismatched {
        /// What is loaded.
        running: u32,
        /// What this build ships.
        shipped: u32,
    },
    /// No driver is loaded yet, which is the ordinary first-start state.
    NotLoaded,
}

/// Compares the running driver against the shipped one.
#[must_use]
pub const fn driver_verdict(running: u32, shipped: u32) -> DriverVerdict {
    if running == 0 {
        DriverVerdict::NotLoaded
    } else if running == shipped {
        DriverVerdict::Current
    } else {
        DriverVerdict::Mismatched { running, shipped }
    }
}

/// The Wintun operations this adapter uses.
///
/// A trait for the reason the module documentation gives: it is the boundary
/// between what can be tested on the host this crate was written on and what
/// cannot. Everything above it is ordinary Rust.
///
/// The handles are `u64` rather than typed pointers so the trait itself is
/// target-free; [`WintunDriver`] casts at its own boundary, which is the only
/// place that knows they are pointers.
pub trait TunnelDriver: Send + Sync + std::fmt::Debug {
    /// Whether an adapter of this name already exists, and its handle if so.
    ///
    /// `Ok(None)` is "no such adapter", which is a normal first-start state and
    /// not an error — the same distinction `secure_item_read` draws.
    fn open_adapter(&self, name: &str) -> Result<Option<u64>, PlatformError>;

    /// Creates an adapter.
    fn create_adapter(&self, name: &str) -> Result<u64, PlatformError>;

    /// Closes an adapter handle, removing the adapter.
    fn close_adapter(&self, adapter: u64);

    /// The adapter's `NET_LUID`.
    fn adapter_luid(&self, adapter: u64) -> Result<InterfaceLuid, PlatformError>;

    /// Starts a session — which is what makes the link carry traffic.
    fn start_session(&self, adapter: u64, capacity: u32) -> Result<u64, PlatformError>;

    /// Ends a session, leaving the adapter in place.
    fn end_session(&self, session: u64);

    /// Takes one packet from the receive ring into `buf`.
    ///
    /// `Ok(None)` means the ring is empty, which is not an error.
    fn receive(&self, session: u64, buf: &mut [u8]) -> Result<Option<usize>, PlatformError>;

    /// Puts one packet into the send ring.
    fn send(&self, session: u64, packet: &[u8]) -> Result<usize, PlatformError>;

    /// Sets the interface MTU, **both families**.
    fn set_mtu(&self, luid: InterfaceLuid, mtu: u32) -> Result<(), PlatformError>;

    /// The running driver's version, or `0` if none is loaded.
    fn running_version(&self) -> u32;
}

/// One adapter this device holds.
#[derive(Debug)]
struct Open {
    adapter: u64,
    /// `Some` once the link is up. An adapter with no session carries nothing,
    /// which is what makes "created DOWN" the easy path rather than a
    /// discipline.
    session: Option<u64>,
    luid: InterfaceLuid,
    name: String,
}

/// The Windows tunnel device.
#[derive(Debug)]
pub struct WindowsTunnelDevice {
    driver: Arc<dyn TunnelDriver>,
    shutdown: ShutdownLatch,
    open: Mutex<Vec<(u64, Open)>>,
    next: AtomicU64,
    /// Where the overlay's LUID is published, so [`crate::netcfg`] programs the
    /// interface that exists rather than the `0` a shell had to inject before it
    /// did.
    overlay: OverlayLuid,
}

impl WindowsTunnelDevice {
    /// Binds the device to a driver.
    ///
    /// CD-2: the driver is taken at construction. There is no ambient loader and
    /// no lazy global — a `OnceCell<WintunDriver>` would make "which DLL is
    /// loaded" a process-wide fact nothing could re-derive after an update.
    ///
    /// `overlay` is the cell [`crate::netcfg::WindowsNetworkConfig`] reads. It is
    /// taken here rather than discovered there, because this is the only object
    /// that knows the LUID and it knows it exactly once — at
    /// `create_interface`.
    #[must_use]
    pub fn new(
        driver: Arc<dyn TunnelDriver>,
        shutdown: ShutdownLatch,
        overlay: OverlayLuid,
    ) -> Self {
        Self {
            driver,
            shutdown,
            open: Mutex::new(Vec::new()),
            next: AtomicU64::new(1),
            overlay,
        }
    }

    /// The adapter LUID behind a handle.
    ///
    /// The seam deliberately hides the OS handle, but the enforcement layer's
    /// Tier-2 permit and the route table both key on the **LUID** — and
    /// rediscovering it by name would turn a rename in Network Connections into
    /// a permit on the wrong interface.
    #[must_use]
    pub fn luid_of(&self, handle: TunnelHandle) -> Option<InterfaceLuid> {
        let open = self.open.lock().ok()?;
        open.iter()
            .find(|(id, _)| *id == handle.0)
            .map(|(_, o)| o.luid)
    }

    /// The adapter name behind a handle.
    #[must_use]
    pub fn name_of(&self, handle: TunnelHandle) -> Option<String> {
        let open = self.open.lock().ok()?;
        open.iter()
            .find(|(id, _)| *id == handle.0)
            .map(|(_, o)| o.name.clone())
    }

    /// Whether the link is up — that is, whether a session is running.
    #[must_use]
    pub fn is_up(&self, handle: TunnelHandle) -> Option<bool> {
        let open = self.open.lock().ok()?;
        open.iter()
            .find(|(id, _)| *id == handle.0)
            .map(|(_, o)| o.session.is_some())
    }

    /// The startup driver-version comparison of ADR-0016 §10.
    #[must_use]
    pub fn driver_verdict(&self, shipped: u32) -> DriverVerdict {
        driver_verdict(self.driver.running_version(), shipped)
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Vec<(u64, Open)>>, PlatformError> {
        self.open
            .lock()
            .map_err(|_| oserr::unavailable("wintun.lock"))
    }

    fn session_of(&self, handle: TunnelHandle) -> Result<u64, PlatformError> {
        let open = self.locked()?;
        let entry = open
            .iter()
            .find(|(id, _)| *id == handle.0)
            .ok_or_else(|| oserr::unavailable("wintun.handle"))?;
        entry.1.session.ok_or_else(|| {
            // The link is down. Reported as the interface being down rather than
            // as a generic failure, because that is the condition and its
            // remediation is "bring the link up", not "reinstall".
            oserr::from_status(
                Win32Error(oserr::ERROR_NOT_READY),
                "WintunReceivePacket(no session)",
                Context::TunnelDevice,
            )
        })
    }
}

impl TunnelDevice for WindowsTunnelDevice {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if mtu < MTU_FLOOR {
                return Err(oserr::unavailable("mtu.floor"));
            }
            let name = name.as_str().to_owned();

            // Reclaim before create. See the module documentation: the other
            // order leaves two adapters after a crash, and the older one still
            // holds the previous generation's routes.
            let existing = self.driver.open_adapter(&name)?;
            let adapter = match adapter_action(existing.is_some()) {
                AdapterAction::Reclaim => existing.ok_or_else(|| {
                    // Unreachable by construction; named rather than unwrapped so
                    // a future refactor that separates the probe from the use
                    // fails loudly instead of panicking in a service.
                    oserr::unavailable("wintun.reclaim")
                })?,
                AdapterAction::Create => self.driver.create_adapter(&name)?,
            };

            let luid = match self.driver.adapter_luid(adapter) {
                Ok(luid) => luid,
                Err(e) => {
                    // An adapter we cannot identify is worse than none: every
                    // route and every filter keys on the LUID.
                    self.driver.close_adapter(adapter);
                    return Err(e);
                }
            };
            if let Err(e) = self.driver.set_mtu(luid, mtu) {
                self.driver.close_adapter(adapter);
                return Err(e);
            }

            // **No session is started here.** The adapter exists and carries
            // nothing, which is `docs/networking.md` §5.1's "created DOWN".
            let handle = TunnelHandle(self.next.fetch_add(1, Ordering::Relaxed));
            self.locked()?.push((
                handle.0,
                Open {
                    adapter,
                    session: None,
                    luid,
                    name,
                },
            ));
            // Published only once the adapter is recorded, so nothing can read a
            // LUID for a handle this device does not hold. It is published on the
            // created-DOWN adapter rather than at `set_link`, because the
            // enforcement layer has to be able to name the interface **before**
            // traffic can reach it — the other order is `docs/networking.md`
            // §2.3's partial-application window with the filters on the wrong
            // side of it.
            self.overlay.set(luid);
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
            // The adapter is read under the lock and the session is started
            // outside it: `start_session` is a driver call, and holding a mutex
            // across one is how a slow driver becomes a stalled adapter.
            let (adapter, running) = {
                let open = self.locked()?;
                let entry = open
                    .iter()
                    .find(|(id, _)| *id == handle.0)
                    .ok_or_else(|| oserr::unavailable("wintun.handle"))?;
                (entry.1.adapter, entry.1.session)
            };

            match (state, running) {
                // Idempotent in both directions: the core may re-assert a link
                // state it already holds, and an adapter with two sessions is a
                // second ring nothing drains.
                (LinkState::Up, Some(_)) | (LinkState::Down, None) => Ok(()),
                (LinkState::Up, None) => {
                    let session = self.driver.start_session(adapter, RING_CAPACITY)?;
                    let mut open = self.locked()?;
                    if let Some((_, entry)) = open.iter_mut().find(|(id, _)| *id == handle.0) {
                        entry.session = Some(session);
                        Ok(())
                    } else {
                        // The handle was destroyed while the session was
                        // starting. End it rather than leak it.
                        self.driver.end_session(session);
                        Err(oserr::unavailable("wintun.handle"))
                    }
                }
                (LinkState::Down, Some(session)) => {
                    // Clear the record BEFORE ending the session, so a
                    // concurrent `read_packet` sees the link as down rather
                    // than reaching for a session that is being torn down.
                    if let Some((_, entry)) =
                        self.locked()?.iter_mut().find(|(id, _)| *id == handle.0)
                    {
                        entry.session = None;
                    }
                    self.driver.end_session(session);
                    Ok(())
                }
            }
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // **Idempotent, and safe after a crash** — and deliberately NOT
            // gated on the shutdown latch, because tearing the interface down is
            // part of shutdown. CB-6 is unaffected: the WFP filters are BFE's
            // and nothing here touches them.
            let removed = {
                let mut open = self.locked()?;
                open.iter()
                    .position(|(id, _)| *id == handle.0)
                    .map(|index| open.remove(index).1)
            };
            if let Some(entry) = removed {
                if let Some(session) = entry.session {
                    self.driver.end_session(session);
                }
                self.driver.close_adapter(entry.adapter);
                // Only if this was the adapter the enforcement layer is keyed
                // on. Windows reassigns nothing about a LUID, but a second
                // interface's destroy must not un-publish the live one's.
                if self.overlay.get() == entry.luid {
                    self.overlay.clear();
                }
            }
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        // ADR-0018 §11.2 row 2.3: "on Linux/OpenWrt the core *programs* the
        // kernel WireGuard module; **elsewhere the core *is* the datapath**".
        // Wintun is a ring buffer this process reads and writes, so `Userspace`
        // is the fact and not a fallback.
        Datapath::Userspace
    }

    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let session = self.session_of(handle)?;
            loop {
                if let Some(n) = self.driver.receive(session, buf)? {
                    return Ok(n);
                }
                // The ring is empty. Yielding rather than blocking keeps the
                // runtime's worker free; **cancellation is dropping this
                // future**, and dropping it here releases nothing the driver
                // holds, because a packet is only borrowed for the width of
                // `receive`.
                //
                // A readiness integration over `WintunGetReadWaitEvent` would be
                // strictly better and is **not in this build** — see this
                // domain's report.
                tokio::task::yield_now().await;
                self.shutdown.check()?;
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
            let session = self.session_of(handle)?;
            self.driver.send(session, packet)
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if mtu < MTU_FLOOR {
                // DPLPMTUD raises and lowers this as it probes, but never below
                // the floor: `docs/networking.md` §6.2's "never accept a PTB
                // below 1280".
                return Err(oserr::unavailable("mtu.floor"));
            }
            let luid = self
                .luid_of(handle)
                .ok_or_else(|| oserr::unavailable("wintun.handle"))?;
            self.driver.set_mtu(luid, mtu)
        })
    }
}

pub use platform::WintunDriver;

#[cfg(windows)]
mod platform;

#[cfg(not(windows))]
mod platform {
    //! The non-Windows counterpart.
    //!
    //! It exists so the target-free layers above can be compiled and tested on
    //! the host this crate was written on. **It refuses to load.** A stub that
    //! pretended to create an adapter would make a passing test on this host
    //! mean nothing.

    use super::{InterfaceLuid, PlatformError, TunnelDriver};
    use crate::oserr::{self, Context, Win32Error};

    /// Wintun, on a host that does not have it.
    #[derive(Debug, Clone, Copy)]
    pub struct WintunDriver;

    impl WintunDriver {
        /// Loads `wintun.dll`. Off Windows there is nothing to load.
        ///
        /// # Errors
        ///
        /// Always [`PlatformError::AdapterUnavailable`], carrying
        /// `ERROR_MOD_NOT_FOUND` — the same status a Windows host with no DLL
        /// beside the binary produces, so the refusal reads identically in a
        /// bundle from either.
        pub fn load() -> Result<Self, PlatformError> {
            Err(oserr::from_status(
                Win32Error(oserr::ERROR_MOD_NOT_FOUND),
                "LoadLibraryExW(wintun.dll)",
                Context::TunnelDevice,
            ))
        }
    }

    impl TunnelDriver for WintunDriver {
        fn open_adapter(&self, _name: &str) -> Result<Option<u64>, PlatformError> {
            Err(unsupported("WintunOpenAdapter"))
        }
        fn create_adapter(&self, _name: &str) -> Result<u64, PlatformError> {
            Err(unsupported("WintunCreateAdapter"))
        }
        fn close_adapter(&self, _adapter: u64) {}
        fn adapter_luid(&self, _adapter: u64) -> Result<InterfaceLuid, PlatformError> {
            Err(unsupported("WintunGetAdapterLUID"))
        }
        fn start_session(&self, _adapter: u64, _capacity: u32) -> Result<u64, PlatformError> {
            Err(unsupported("WintunStartSession"))
        }
        fn end_session(&self, _session: u64) {}
        fn receive(&self, _session: u64, _buf: &mut [u8]) -> Result<Option<usize>, PlatformError> {
            Err(unsupported("WintunReceivePacket"))
        }
        fn send(&self, _session: u64, _packet: &[u8]) -> Result<usize, PlatformError> {
            Err(unsupported("WintunSendPacket"))
        }
        fn set_mtu(&self, _luid: InterfaceLuid, _mtu: u32) -> Result<(), PlatformError> {
            Err(unsupported("SetIpInterfaceEntry"))
        }
        fn running_version(&self) -> u32 {
            0
        }
    }

    fn unsupported(call: &'static str) -> PlatformError {
        oserr::from_status(
            Win32Error(oserr::ERROR_NOT_SUPPORTED),
            call,
            Context::TunnelDevice,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// An in-memory driver, so the device's own behaviour is testable here.
    ///
    /// It models the two Wintun properties the device depends on: an adapter of
    /// a given name either exists or does not, and a session is what makes the
    /// link carry traffic. It does **not** model the ring's contents beyond one
    /// queued packet — a fake that reimplemented the ring would be testing this
    /// file against a model written here rather than against Wintun.
    #[derive(Debug, Default)]
    struct FakeDriver {
        state: Mutex<FakeState>,
    }

    #[derive(Debug, Default)]
    struct FakeState {
        /// Adapters by name, as if they had survived a crash.
        existing: HashMap<String, u64>,
        /// Adapters currently open, by handle.
        adapters: HashMap<u64, String>,
        sessions: Vec<u64>,
        next: u64,
        mtu: HashMap<u64, u32>,
        queued: Vec<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        creates: usize,
        version: u32,
        fail_luid: bool,
    }

    impl FakeDriver {
        fn with_orphan(name: &str) -> Self {
            let driver = Self::default();
            {
                let mut state = driver.lock();
                state.next += 1;
                let handle = state.next;
                state.existing.insert(name.to_owned(), handle);
            }
            driver
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn creates(&self) -> usize {
            self.lock().creates
        }

        fn live_sessions(&self) -> usize {
            self.lock().sessions.len()
        }

        fn live_adapters(&self) -> usize {
            self.lock().adapters.len()
        }
    }

    impl TunnelDriver for FakeDriver {
        fn open_adapter(&self, name: &str) -> Result<Option<u64>, PlatformError> {
            let mut state = self.lock();
            match state.existing.get(name).copied() {
                Some(handle) => {
                    state.adapters.insert(handle, name.to_owned());
                    Ok(Some(handle))
                }
                None => Ok(None),
            }
        }
        fn create_adapter(&self, name: &str) -> Result<u64, PlatformError> {
            let mut state = self.lock();
            state.next += 1;
            let handle = state.next;
            state.creates += 1;
            state.existing.insert(name.to_owned(), handle);
            state.adapters.insert(handle, name.to_owned());
            Ok(handle)
        }
        fn close_adapter(&self, adapter: u64) {
            let mut state = self.lock();
            if let Some(name) = state.adapters.remove(&adapter) {
                state.existing.remove(&name);
            }
        }
        fn adapter_luid(&self, adapter: u64) -> Result<InterfaceLuid, PlatformError> {
            if self.lock().fail_luid {
                return Err(oserr::unavailable("WintunGetAdapterLUID"));
            }
            Ok(InterfaceLuid(adapter))
        }
        fn start_session(&self, adapter: u64, _capacity: u32) -> Result<u64, PlatformError> {
            let mut state = self.lock();
            state.next += 1;
            let session = state.next;
            let _ = adapter;
            state.sessions.push(session);
            Ok(session)
        }
        fn end_session(&self, session: u64) {
            self.lock().sessions.retain(|s| *s != session);
        }
        fn receive(&self, _session: u64, buf: &mut [u8]) -> Result<Option<usize>, PlatformError> {
            let mut state = self.lock();
            match state.queued.pop() {
                Some(packet) => {
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    Ok(Some(n))
                }
                None => Ok(None),
            }
        }
        fn send(&self, _session: u64, packet: &[u8]) -> Result<usize, PlatformError> {
            self.lock().sent.push(packet.to_vec());
            Ok(packet.len())
        }
        fn set_mtu(&self, luid: InterfaceLuid, mtu: u32) -> Result<(), PlatformError> {
            self.lock().mtu.insert(luid.0, mtu);
            Ok(())
        }
        fn running_version(&self) -> u32 {
            self.lock().version
        }
    }

    fn device(driver: Arc<FakeDriver>) -> WindowsTunnelDevice {
        WindowsTunnelDevice::new(driver, ShutdownLatch::new(), unpublished())
    }

    /// The cell a shell starts with: `0`, because the adapter does not exist.
    fn unpublished() -> OverlayLuid {
        OverlayLuid::new(InterfaceLuid(0))
    }

    fn name() -> InterfaceName {
        InterfaceName::new("TwinVPN").expect("valid")
    }

    #[test]
    fn the_reclaim_ordering_is_a_decision_a_test_can_pin() {
        // Getting this backwards leaves two TwinVPN adapters after a crash, of
        // which the older one still holds the previous generation's routes.
        assert_eq!(adapter_action(true), AdapterAction::Reclaim);
        assert_eq!(adapter_action(false), AdapterAction::Create);
    }

    #[tokio::test]
    async fn an_orphaned_adapter_is_reclaimed_and_never_duplicated() {
        // `docs/networking.md` §5.3 and ADR-0022 LC-26.
        let driver = Arc::new(FakeDriver::with_orphan("TwinVPN"));
        let device = device(driver.clone());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        assert_eq!(
            driver.creates(),
            0,
            "an adapter already existed; creating a second is the defect"
        );
        assert_eq!(driver.live_adapters(), 1);
        assert!(device.luid_of(handle).is_some());
    }

    /// The enforcement facts a shell injects **before** the adapter exists.
    ///
    /// `overlay_luid: 0` is what `shells/windows/twinvpnsvc` really passes, and
    /// the whole point of this test is that the rendered set must not keep it.
    fn preadapter_enforcement() -> crate::wfp::EnforcementConfig {
        crate::wfp::EnforcementConfig {
            overlay_luid: 0,
            service_app_id: r"\device\harddiskvolume3\program files\twinvpn\twinvpnsvc.exe",
            service_sid: "S-1-5-80-0",
            local_network_access: true,
            on_link_prefixes: Vec::new(),
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
            doh_endpoints: Vec::new(),
        }
    }

    fn stub_addresses() -> crate::dns::StubAddresses {
        let mut anycast6 = [0u8; 16];
        anycast6[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
        anycast6[6] = 0xff;
        anycast6[7] = 0xff;
        anycast6[15] = 0x53;
        let mut loop6 = [0u8; 16];
        loop6[15] = 1;
        crate::dns::StubAddresses {
            loopback_v4: twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([
                127, 0, 0, 53,
            ])),
            loopback_v6: twinvpn_types::IpAddr::V6(
                twinvpn_types::V6Addr::new(loop6, None).expect("::1"),
            ),
            anycast_v4: twinvpn_types::IpAddr::V4(twinvpn_types::V4Addr::from_octets([
                100, 127, 255, 53,
            ])),
            anycast_v6: twinvpn_types::IpAddr::V6(
                twinvpn_types::V6Addr::new(anycast6, None).expect("the service anycast"),
            ),
        }
    }

    #[tokio::test]
    async fn the_created_adapters_luid_reaches_the_filter_render() {
        // ADR-0012 §11.1: Tier 2 is interface-scoped, and the overlay permit is
        // the ONLY difference between `Protected` and `Blocked`. The shell has
        // to inject `overlay_luid: 0` because the adapter does not exist at
        // construction, so before this propagation existed the permit matched no
        // interface — a `Protected` posture that permitted nothing — and every
        // `NotLocalInterface(0)` complement was true on the overlay too.
        let system = Arc::new(crate::sys::fake::FakeSystem::new(InterfaceLuid(0)));
        let network = crate::netcfg::WindowsNetworkConfig::new(crate::netcfg::NetworkConfigParts {
            system,
            enforcement: preadapter_enforcement(),
            stub: stub_addresses(),
            restore_point_path: std::path::PathBuf::from("unused-by-render"),
            shutdown: ShutdownLatch::new(),
        });
        assert_eq!(
            network.overlay(),
            InterfaceLuid(0),
            "before the adapter exists the injected value is the honest one"
        );

        // `adapter_luid` in `FakeDriver` answers the adapter handle, so the LUID
        // is whatever the driver assigned rather than a number this test chose.
        let driver = Arc::new(FakeDriver::default());
        let device = WindowsTunnelDevice::new(driver, ShutdownLatch::new(), network.overlay_luid());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        let luid = device.luid_of(handle).expect("the device knows its LUID");
        assert_ne!(luid, InterfaceLuid(0), "the fake must assign a real LUID");
        assert_eq!(network.overlay(), luid, "the device publishes what it made");

        let contract = crate::netcfg::prearming_contract();
        let set = network.render(&contract, twinvpn_platform::Ruleset::Protected);

        let overlay_permits: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == crate::wfp::TrafficClass::OverlayEgress)
            .collect();
        assert_eq!(overlay_permits.len(), 2, "one per layer, v4 and v6");
        for filter in overlay_permits {
            assert_eq!(
                filter.conditions,
                vec![crate::wfp::Condition::LocalInterface(luid.0)],
                "the Tier-2 permit must name the interface that exists"
            );
        }

        let containment: Vec<_> = set
            .filters
            .iter()
            .filter(|f| f.class == crate::wfp::TrafficClass::DnsContainment)
            .collect();
        assert!(!containment.is_empty(), "class 6 is unconditional");
        for filter in containment {
            assert!(
                filter
                    .conditions
                    .contains(&crate::wfp::Condition::NotLocalInterface(luid.0)),
                "DNS containment must exempt the overlay by its real LUID, not by 0"
            );
        }

        // Destroying it puts the injected value back, so a torn-down overlay
        // never leaves the enforcement layer keyed on a LUID nothing holds.
        device.destroy_interface(handle).await.expect("destroys");
        assert_eq!(network.overlay(), InterfaceLuid(0));
    }

    #[tokio::test]
    async fn a_first_start_creates_exactly_one_adapter() {
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver.clone());
        device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        assert_eq!(driver.creates(), 1);
        assert_eq!(driver.live_adapters(), 1);
    }

    #[tokio::test]
    async fn the_interface_is_created_down_and_carries_nothing_until_the_link_is_up() {
        // "An interface that comes up before its addresses, routes and rules are
        // installed is the partial-application leak window." On Wintun an
        // adapter with no session carries nothing, so this is a property of the
        // mechanism rather than a discipline.
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver.clone());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        assert_eq!(device.is_up(handle), Some(false));
        assert_eq!(driver.live_sessions(), 0);

        // ...and a read before the link is up is a named condition, not a hang.
        let mut buf = [0u8; 64];
        let err = device
            .read_packet(handle, &mut buf)
            .await
            .expect_err("no session");
        assert_eq!(err.reason_code().as_str(), "NET.IFACE_DOWN");

        device
            .set_link(handle, LinkState::Up)
            .await
            .expect("brings up");
        assert_eq!(device.is_up(handle), Some(true));
        assert_eq!(driver.live_sessions(), 1);
    }

    #[tokio::test]
    async fn set_link_is_idempotent_in_both_directions() {
        // An adapter with two sessions is a second ring nothing drains.
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver.clone());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");

        device.set_link(handle, LinkState::Up).await.expect("up");
        device.set_link(handle, LinkState::Up).await.expect("again");
        assert_eq!(driver.live_sessions(), 1);

        device
            .set_link(handle, LinkState::Down)
            .await
            .expect("down");
        device
            .set_link(handle, LinkState::Down)
            .await
            .expect("again");
        assert_eq!(driver.live_sessions(), 0);
    }

    #[tokio::test]
    async fn destroying_an_unknown_handle_is_a_no_op_never_an_error() {
        // "Idempotent; safe after a crash."
        let device = device(Arc::new(FakeDriver::default()));
        device
            .destroy_interface(TunnelHandle(1))
            .await
            .expect("no-op");
        device
            .destroy_interface(TunnelHandle(1))
            .await
            .expect("no-op");
    }

    #[tokio::test]
    async fn destroying_an_interface_ends_the_session_and_closes_the_adapter() {
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver.clone());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        device.set_link(handle, LinkState::Up).await.expect("up");

        device.destroy_interface(handle).await.expect("destroys");
        assert_eq!(driver.live_sessions(), 0);
        assert_eq!(driver.live_adapters(), 0);
        // Idempotent after the fact.
        device.destroy_interface(handle).await.expect("no-op");
    }

    #[tokio::test]
    async fn destroy_works_after_shutdown_because_teardown_is_part_of_shutdown() {
        let latch = ShutdownLatch::new();
        let driver = Arc::new(FakeDriver::default());
        let device = WindowsTunnelDevice::new(driver.clone(), latch.clone(), unpublished());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        latch.begin();
        device
            .destroy_interface(handle)
            .await
            .expect("still tears down");
        assert_eq!(driver.live_adapters(), 0);
    }

    #[tokio::test]
    async fn an_mtu_below_the_ipv6_floor_is_refused_and_never_clamped() {
        // A link that cannot carry 1280 bytes cannot carry IPv6 at all.
        let device = device(Arc::new(FakeDriver::default()));
        let err = device
            .create_interface(&name(), MTU_FLOOR - 1)
            .await
            .expect_err("below the floor");
        assert_eq!(err.os_detail().map(|d| d.call), Some("mtu.floor"));

        let handle = device
            .create_interface(&name(), MTU_FLOOR)
            .await
            .expect("exactly at the floor is accepted");
        let err = device
            .set_mtu(handle, 1279)
            .await
            .expect_err("below the floor");
        assert_eq!(err.os_detail().map(|d| d.call), Some("mtu.floor"));
        device.set_mtu(handle, 1500).await.expect("raises");
    }

    #[tokio::test]
    async fn an_adapter_whose_luid_cannot_be_read_is_closed_rather_than_kept() {
        // Every route and every filter keys on the LUID, so an adapter we cannot
        // identify is worse than none — and leaving it behind is the orphan the
        // reclaim path then has to clean up.
        let driver = Arc::new(FakeDriver::default());
        driver.lock().fail_luid = true;
        let device = device(driver.clone());
        device
            .create_interface(&name(), 1420)
            .await
            .expect_err("no LUID");
        assert_eq!(driver.live_adapters(), 0);
    }

    #[tokio::test]
    async fn a_packet_round_trips_through_the_rings() {
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver.clone());
        let handle = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        device.set_link(handle, LinkState::Up).await.expect("up");

        driver.lock().queued.push(vec![9u8; 40]);
        let mut buf = [0u8; 64];
        assert_eq!(
            device.read_packet(handle, &mut buf).await.expect("reads"),
            40
        );
        assert_eq!(&buf[..40], &[9u8; 40]);

        assert_eq!(
            device
                .write_packet(handle, &[1u8; 20])
                .await
                .expect("writes"),
            20
        );
        assert_eq!(driver.lock().sent, vec![vec![1u8; 20]]);
    }

    #[tokio::test]
    async fn the_device_refuses_new_work_after_shutdown() {
        let latch = ShutdownLatch::new();
        let device = WindowsTunnelDevice::new(Arc::new(FakeDriver::default()), latch.clone(), unpublished());
        latch.begin();
        match device.create_interface(&name(), 1420).await {
            Err(PlatformError::ShuttingDown) => {}
            other => panic!("expected ShuttingDown, got {other:?}"),
        }
    }

    #[test]
    fn the_datapath_is_declared_as_the_fact_it_is() {
        // ADR-0018 §11.2 row 2.3: elsewhere the core IS the datapath.
        assert_eq!(
            device(Arc::new(FakeDriver::default())).datapath(),
            Datapath::Userspace
        );
    }

    #[test]
    fn the_driver_verdict_distinguishes_absent_from_mismatched() {
        // ADR-0016 §10 puts the replacement with the installer, so the service
        // has to be able to say which of the two it found: "no driver yet" is
        // the ordinary first start, "the wrong driver" is an install action.
        assert_eq!(driver_verdict(0, 0x0001_0000), DriverVerdict::NotLoaded);
        assert_eq!(
            driver_verdict(0x0001_0000, 0x0001_0000),
            DriverVerdict::Current
        );
        assert_eq!(
            driver_verdict(0x0000_0E00, 0x0001_0000),
            DriverVerdict::Mismatched {
                running: 0x0000_0E00,
                shipped: 0x0001_0000
            }
        );
    }

    #[test]
    fn the_device_reports_the_verdict_from_the_driver_it_was_given() {
        let driver = Arc::new(FakeDriver::default());
        driver.lock().version = 0x0001_0000;
        let device = device(driver);
        assert_eq!(device.driver_verdict(0x0001_0000), DriverVerdict::Current);
        assert!(matches!(
            device.driver_verdict(0x0002_0000),
            DriverVerdict::Mismatched { .. }
        ));
    }

    #[test]
    fn the_ring_capacity_is_a_power_of_two_inside_wintuns_declared_range() {
        assert!(RING_CAPACITY.is_power_of_two());
        assert!((128 * 1024..=64 * 1024 * 1024).contains(&RING_CAPACITY));
    }

    #[tokio::test]
    async fn two_interfaces_get_distinct_handles_and_distinct_luids() {
        let driver = Arc::new(FakeDriver::default());
        let device = device(driver);
        let a = device
            .create_interface(&name(), 1420)
            .await
            .expect("creates");
        let b = device
            .create_interface(&InterfaceName::new("TwinVPN-2").expect("valid"), 1420)
            .await
            .expect("creates");
        assert_ne!(a, b);
        assert_ne!(device.luid_of(a), device.luid_of(b));
        assert_eq!(device.name_of(a).as_deref(), Some("TwinVPN"));
    }
}
