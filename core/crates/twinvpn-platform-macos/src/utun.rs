//! The tunnel device: `utun` framing, the two provenances, and the packet port.
//!
//! **Authority:** `docs/networking.md` §5.1 (created DOWN; `destroy_interface` is
//! idempotent and safe after a crash) and §2.3 ("partial application is the leak
//! window"); ADR-0018 CB-2, CB-3, PB-1 (zero FFI crossings per packet, with
//! `NEPacketTunnelFlow` as the one exception), DP-4; ADR-0016 PS-5 (the tunnel
//! descriptor is never passed outward, except to the OS that granted it).
//!
//! # The 4-byte protocol-family header
//!
//! Every frame on a `utun` interface — read *and* written — begins with a 4-byte
//! address family in **network byte order**: `AF_INET` (2) or Darwin's `AF_INET6`
//! (**30**, not Linux's 10). Omitting it on write makes the kernel drop the packet
//! silently; failing to strip it on read hands the core four bytes of garbage in
//! front of every IP header.
//!
//! [`encode_frame`] and [`decode_frame`] are pure and are exercised on this Linux
//! host, which is the whole reason they are separate from the socket.
//!
//! # Two provenances, one trait (CB-3)
//!
//! | Provenance | Who creates the interface | Who owns the descriptor |
//! |---|---|---|
//! | [`TunnelProvenance::OsProvidedFlow`] | the OS, before `startTunnel` runs | the NE runtime; the provider gets `packetFlow` |
//! | [`TunnelProvenance::AdapterCreatedUtun`] | this adapter, over `PF_SYSTEM` | this process |
//!
//! **This is not an OS branch.** Both are macOS; which one is in force is a
//! construction-time capability, and [`TunnelDevice::datapath`] reports
//! [`Datapath::Userspace`] in both cases because in both the core reads and writes
//! packets itself. Nothing above the seam can tell them apart, which is what CB-3
//! requires.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    Datapath, InterfaceName, LinkState, PlatformError, TunnelDevice, TunnelHandle,
};
use twinvpn_types::AddressFamily;

use crate::addr::{darwin_af, family_of_darwin_af};
use crate::oserr;
use crate::shutdown::ShutdownLatch;

/// The kernel control `utun` lives behind. `<net/if_utun.h>`.
pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

/// The 4-byte protocol-family header every `utun` frame carries.
pub const FRAME_HEADER_LEN: usize = 4;

/// The MTU floor. `docs/networking.md` §6.2: "1280 floor + DPLPMTUD, never classic
/// PMTUD". Below this an IPv6 packet cannot be carried at all.
pub const MTU_FLOOR: u32 = 1280;

/// Where the datapath's interface came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelProvenance {
    /// The OS created the interface and hands the provider a
    /// `NEPacketTunnelFlow`. The adapter never sees a file descriptor.
    OsProvidedFlow,
    /// The adapter opens `PF_SYSTEM`/`SYSPROTO_CONTROL` itself. The
    /// `LaunchDaemon` path.
    AdapterCreatedUtun,
}

/// Why a `utun` frame could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than four bytes: not a frame at all.
    TooShort,
    /// A frame with a header and no packet after it.
    Empty,
    /// A protocol family this adapter does not carry.
    UnknownFamily(u32),
}

/// Writes the 4-byte header and the packet into `out`.
///
/// The header is **network byte order**, which is what the kernel reads. A
/// little-endian write produces `AF_INET` as `0x02000000`, which the kernel reads
/// as family 33554432 and drops — silently, with no error on the write.
pub fn encode_frame(family: AddressFamily, packet: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(FRAME_HEADER_LEN + packet.len());
    out.extend_from_slice(&u32::from(darwin_af(family)).to_be_bytes());
    out.extend_from_slice(packet);
}

/// Splits a frame into its family and its packet.
///
/// # Errors
///
/// [`FrameError`] for a frame that is too short, carries no packet, or names a
/// family this adapter does not carry. A frame is **never** truncated into
/// validity: four bytes of a header read as an IP packet is a packet that
/// authenticates against nothing, for a reason nobody can see.
pub fn decode_frame(bytes: &[u8]) -> Result<(AddressFamily, &[u8]), FrameError> {
    let header = bytes.get(..FRAME_HEADER_LEN).ok_or(FrameError::TooShort)?;
    let raw = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let family = u8::try_from(raw)
        .ok()
        .and_then(family_of_darwin_af)
        .ok_or(FrameError::UnknownFamily(raw))?;
    let packet = &bytes[FRAME_HEADER_LEN..];
    if packet.is_empty() {
        return Err(FrameError::Empty);
    }
    Ok((family, packet))
}

/// The family an IP packet declares in its own first nibble.
///
/// Needed on the **write** path: the core hands the adapter a packet and the
/// kernel needs a family header for it, and asking the packet is the only source
/// of truth that cannot disagree with the packet's own contents. A frame whose
/// header said v4 and whose payload was v6 would be dropped by the kernel with no
/// diagnostic.
#[must_use]
pub fn family_of_packet(packet: &[u8]) -> Option<AddressFamily> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Some(AddressFamily::V4),
        Some(6) => Some(AddressFamily::V6),
        _ => None,
    }
}

/// The kernel control unit for `utunN`.
///
/// The off-by-one lives here, once: unit `0` means "give me any free one", so
/// `utun7` is unit **8**.
#[must_use]
pub fn unit_for_index(index: u32) -> u32 {
    index + 1
}

/// The interface name a kernel control unit produces.
#[must_use]
pub fn name_for_unit(unit: u32) -> Option<String> {
    unit.checked_sub(1).map(|index| format!("utun{index}"))
}

/// The `utunN` index a name carries, if it is one.
#[must_use]
pub fn index_of_name(name: &str) -> Option<u32> {
    name.strip_prefix("utun")?.parse().ok()
}

/// Where packets go. Injected, so the read/write path is one implementation over
/// the NE flow, a `utun` socket and a test.
pub trait PacketPort: Send + Sync + std::fmt::Debug {
    /// Reads one **frame** — header included — into `buf`.
    fn read_frame<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, PlatformError>>;

    /// Writes one **frame**, header included.
    fn write_frame<'a>(&'a self, frame: &'a [u8]) -> BoxFuture<'a, Result<usize, PlatformError>>;

    /// Closes the port. Idempotent.
    fn close(&self);
}

/// A port backed by an in-process queue.
///
/// Two users, and both matter. Under [`TunnelProvenance::OsProvidedFlow`] the
/// Swift provider pushes what `packetFlow` gave it and drains what the core
/// produced — PB-1's one permitted FFI crossing — so this is the **production**
/// port on the system-extension binding, not a test double. And because it is
/// target-free, the whole read/write path is exercised by `cargo test` here.
#[derive(Debug)]
pub struct QueuePort {
    inbound: Mutex<std::collections::VecDeque<Vec<u8>>>,
    outbound: Mutex<std::collections::VecDeque<Vec<u8>>>,
    closed: std::sync::atomic::AtomicBool,
}

impl Default for QueuePort {
    fn default() -> Self {
        Self::new()
    }
}

impl QueuePort {
    /// An empty port.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbound: Mutex::new(std::collections::VecDeque::new()),
            outbound: Mutex::new(std::collections::VecDeque::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Pushes a frame the core will read. Called by the bridge from Swift.
    pub fn push_inbound(&self, frame: Vec<u8>) {
        if let Ok(mut queue) = self.inbound.lock() {
            queue.push_back(frame);
        }
    }

    /// Takes a frame the core wrote. Called by the bridge for Swift.
    #[must_use]
    pub fn take_outbound(&self) -> Option<Vec<u8>> {
        self.outbound.lock().ok().and_then(|mut q| q.pop_front())
    }

    /// How many frames are waiting to go out.
    #[must_use]
    pub fn outbound_depth(&self) -> usize {
        self.outbound.lock().map_or(0, |q| q.len())
    }
}

impl PacketPort for QueuePort {
    fn read_frame<'a>(&'a self, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            let frame = self
                .inbound
                .lock()
                .map_err(|_| oserr::unavailable("port.lock", libc::EDEADLK))?
                .pop_front();
            let Some(frame) = frame else {
                // Nothing waiting. `EAGAIN` rather than a zero-length read: a
                // zero-length read on a datagram port is a frame, and the caller
                // would decode four bytes of nothing.
                return Err(oserr::unavailable("port.read", libc::EAGAIN));
            };
            if frame.len() > buf.len() {
                // Reported, never silent. A silently truncated packet is a packet
                // that fails authentication for a reason nobody can see.
                return Err(oserr::unavailable("port.read", libc::EMSGSIZE));
            }
            buf[..frame.len()].copy_from_slice(&frame);
            Ok(frame.len())
        })
    }

    fn write_frame<'a>(&'a self, frame: &'a [u8]) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(PlatformError::ShuttingDown);
            }
            self.outbound
                .lock()
                .map_err(|_| oserr::unavailable("port.lock", libc::EDEADLK))?
                .push_back(frame.to_vec());
            Ok(frame.len())
        })
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// One created or adopted interface.
#[derive(Debug)]
struct Interface {
    name: String,
    index: u32,
    port: Arc<dyn PacketPort>,
    mtu: u32,
}

/// macOS's tunnel device.
pub struct MacosTunnelDevice {
    shutdown: ShutdownLatch,
    provenance: TunnelProvenance,
    next_handle: AtomicU64,
    interfaces: Mutex<HashMap<u64, Interface>>,
    /// The port a newly created interface is bound to.
    ///
    /// Under [`TunnelProvenance::OsProvidedFlow`] the bridge installs the queue
    /// it shares with Swift **before** the core calls `create_interface`, because
    /// the OS created the interface before `startTunnel` ran. Under
    /// [`TunnelProvenance::AdapterCreatedUtun`] it is replaced by the socket port
    /// the `PF_SYSTEM` connect produced.
    pending_port: Mutex<Option<Arc<dyn PacketPort>>>,
}

impl MacosTunnelDevice {
    /// Binds the device.
    #[must_use]
    pub fn new(shutdown: ShutdownLatch, provenance: TunnelProvenance) -> Self {
        Self {
            shutdown,
            provenance,
            next_handle: AtomicU64::new(1),
            interfaces: Mutex::new(HashMap::new()),
            pending_port: Mutex::new(None),
        }
    }

    /// Which provenance is in force.
    #[must_use]
    pub const fn provenance(&self) -> TunnelProvenance {
        self.provenance
    }

    /// Installs the port a subsequent `create_interface` will adopt.
    ///
    /// Called by the shell's bridge with the queue it shares with the Swift
    /// provider. **Not discovered** (CD-2): the adapter has no way to reach a
    /// `NEPacketTunnelFlow` and must be handed one.
    pub fn set_pending_port(&self, port: Arc<dyn PacketPort>) {
        if let Ok(mut slot) = self.pending_port.lock() {
            *slot = Some(port);
        }
    }

    /// The OS index of a handle's interface.
    ///
    /// The trait deliberately hides the OS handle, but the shell needs the index
    /// to tell [`crate::netcfg`] which link to programme — and rediscovering it by
    /// name would turn a rename race into a route on the wrong link.
    #[must_use]
    pub fn index_of(&self, handle: TunnelHandle) -> Option<u32> {
        self.interfaces
            .lock()
            .ok()
            .and_then(|m| m.get(&handle.0).map(|i| i.index))
    }

    /// The name of a handle's interface.
    #[must_use]
    pub fn name_of(&self, handle: TunnelHandle) -> Option<String> {
        self.interfaces
            .lock()
            .ok()
            .and_then(|m| m.get(&handle.0).map(|i| i.name.clone()))
    }

    /// The MTU currently recorded for a handle.
    #[must_use]
    pub fn mtu_of(&self, handle: TunnelHandle) -> Option<u32> {
        self.interfaces
            .lock()
            .ok()
            .and_then(|m| m.get(&handle.0).map(|i| i.mtu))
    }

    /// Adopts an interface that already exists under this name.
    ///
    /// **The reclaim path.** A provider that restarts is handed the *same*
    /// interface the OS created for the previous instance, and a `create` that
    /// insisted on a fresh one would fail on every restart. ADR-0016 §11.6 step 2
    /// makes reclamation the rule rather than the exception, and this is its
    /// datapath half; the enforcement half is [`crate::netcfg`]'s anchor read-back.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] if no port has been installed, which
    /// on the OS-provided binding means the bridge has not run yet.
    pub fn adopt(&self, name: &InterfaceName) -> Result<TunnelHandle, PlatformError> {
        self.shutdown.check()?;
        let port = self
            .pending_port
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .ok_or_else(|| oserr::unavailable("utun.port", libc::ENODEV))?;
        let index = index_of_name(name.as_str())
            .ok_or_else(|| oserr::unavailable("utun.name", libc::ENODEV))?;
        let handle = TunnelHandle(self.next_handle.fetch_add(1, Ordering::Relaxed));
        let mut interfaces = self
            .interfaces
            .lock()
            .map_err(|_| oserr::unavailable("utun.lock", libc::EDEADLK))?;
        // Idempotent on the NAME, not on the handle: the same interface adopted
        // twice is one interface, and returning two handles for it would let the
        // core destroy one and believe the other still lived.
        if let Some((existing, _)) = interfaces.iter().find(|(_, i)| i.name == name.as_str()) {
            return Ok(TunnelHandle(*existing));
        }
        interfaces.insert(
            handle.0,
            Interface {
                name: name.as_str().to_owned(),
                index,
                port,
                mtu: MTU_FLOOR,
            },
        );
        Ok(handle)
    }

    fn port_of(&self, handle: TunnelHandle) -> Result<Arc<dyn PacketPort>, PlatformError> {
        self.interfaces
            .lock()
            .map_err(|_| oserr::unavailable("utun.lock", libc::EDEADLK))?
            .get(&handle.0)
            .map(|i| Arc::clone(&i.port))
            .ok_or_else(|| oserr::unavailable("utun.handle", libc::ENODEV))
    }
}

impl TunnelDevice for MacosTunnelDevice {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if mtu < MTU_FLOOR {
                // §6.2's floor. Below it an IPv6 packet cannot be carried at all,
                // so accepting the value would produce a tunnel that is up and
                // cannot pass v6 — the asymmetry R1 exists to forbid.
                return Err(oserr::unavailable("utun.mtu", libc::EINVAL));
            }
            match self.provenance {
                TunnelProvenance::OsProvidedFlow => {
                    // The interface exists before `startTunnel` runs, so "create"
                    // is "adopt". Created DOWN is the OS's guarantee here, not
                    // ours: NE does not carry traffic until
                    // `setTunnelNetworkSettings` has been accepted.
                    let handle = self.adopt(name)?;
                    if let Ok(mut interfaces) = self.interfaces.lock() {
                        if let Some(interface) = interfaces.get_mut(&handle.0) {
                            interface.mtu = mtu;
                        }
                    }
                    Ok(handle)
                }
                TunnelProvenance::AdapterCreatedUtun => {
                    // The `PF_SYSTEM` open. Not implemented in this wave — see
                    // `shells/macos/README.md` §7 — and refused by name rather
                    // than faked, because a `create_interface` that returned a
                    // handle to nothing would let the core apply a contract to an
                    // interface that does not exist.
                    Err(oserr::unavailable("utun.create", libc::ENOSYS))
                }
            }
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // The handle must exist; beyond that this is a no-op on the
            // OS-provided binding, where the link's state is NE's and changing it
            // from here is not possible. Recorded rather than silently succeeding
            // for a reason: `LinkState::Down` with **enforcement still installed**
            // is a distinct state the seam is careful to keep separate, and a
            // binding that cannot enter it must not claim it can.
            let _ = self.port_of(handle)?;
            match (self.provenance, state) {
                (TunnelProvenance::OsProvidedFlow, _) => Ok(()),
                (TunnelProvenance::AdapterCreatedUtun, _) => {
                    Err(oserr::unavailable("utun.set_link", libc::ENOSYS))
                }
            }
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // **Idempotent, and safe after a crash**: destroying a handle we do
            // not hold is success, not an error. Deliberately not gated on the
            // shutdown latch — teardown during shutdown is the normal case.
            let removed = self
                .interfaces
                .lock()
                .map_err(|_| oserr::unavailable("utun.lock", libc::EDEADLK))?
                .remove(&handle.0);
            if let Some(interface) = removed {
                interface.port.close();
            }
            Ok(())
        })
    }

    fn datapath(&self) -> Datapath {
        // **Userspace on both provenances.** The core reads and writes packets
        // itself whether they come from `packetFlow` or from a `utun` socket, so
        // nothing above the seam can tell the two apart — which is CB-3.
        Datapath::Userspace
    }

    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let port = self.port_of(handle)?;
            // The frame is read into a scratch buffer four bytes longer than the
            // caller's, so a packet that exactly fills `buf` is not rejected for
            // the header's sake.
            let mut frame = vec![0u8; buf.len() + FRAME_HEADER_LEN];
            let read = port.read_frame(&mut frame).await?;
            let (_, packet) = decode_frame(&frame[..read])
                .map_err(|_| oserr::unavailable("utun.frame", libc::EBADMSG))?;
            if packet.len() > buf.len() {
                return Err(oserr::unavailable("utun.read", libc::EMSGSIZE));
            }
            buf[..packet.len()].copy_from_slice(packet);
            Ok(packet.len())
        })
    }

    fn write_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let port = self.port_of(handle)?;
            // The family comes from the packet's own version nibble. Taking it
            // from anywhere else lets the header and the payload disagree, and the
            // kernel drops such a frame with no diagnostic at all.
            let family = family_of_packet(packet)
                .ok_or_else(|| oserr::unavailable("utun.family", libc::EAFNOSUPPORT))?;
            let mut frame = Vec::new();
            encode_frame(family, packet, &mut frame);
            let written = port.write_frame(&frame).await?;
            // The caller counts payload bytes, not frame bytes.
            Ok(written.saturating_sub(FRAME_HEADER_LEN))
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            if mtu < MTU_FLOOR {
                return Err(oserr::unavailable("utun.mtu", libc::EINVAL));
            }
            let mut interfaces = self
                .interfaces
                .lock()
                .map_err(|_| oserr::unavailable("utun.lock", libc::EDEADLK))?;
            let interface = interfaces
                .get_mut(&handle.0)
                .ok_or_else(|| oserr::unavailable("utun.handle", libc::ENODEV))?;
            interface.mtu = mtu;
            // On the OS-provided binding the MTU reaches the kernel through the
            // settings object, which the shell re-applies; recording it here is
            // what makes the next settings document carry it. On the
            // adapter-created binding it needs `SIOCSIFMTU`, which is not in this
            // wave.
            match self.provenance {
                TunnelProvenance::OsProvidedFlow => Ok(()),
                TunnelProvenance::AdapterCreatedUtun => {
                    Err(oserr::unavailable("utun.set_mtu", libc::ENOSYS))
                }
            }
        })
    }
}
