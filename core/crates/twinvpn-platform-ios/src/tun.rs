//! [`TunnelDevice`] over `NEPacketTunnelFlow` — PB-1's one conceded FFI crossing.
//!
//! **Authority:** ADR-0018 §11.13's **PB-1** and **PB-2**, §11.2 row 2.3,
//! `docs/networking.md` §5.1 and §5.2's iOS row; ADR-0012 KS-17.
//!
//! # PB-1, quoted, because the cost is budgeted rather than avoidable
//!
//! | Target | Datapath | Per-packet crossings | Why |
//! |---|---|---|---|
//! | iOS, iPadOS, macOS app-extension | `NEPacketTunnelFlow` | **1 per batch, + 1 copy per packet** | "the API is Swift/Objective-C only and hands the caller `Data`; there is no fd. Unavoidable, therefore budgeted" |
//!
//! There is no file descriptor to hand the core, so §11.13's zero-crossing story
//! does not apply here and PB-2 adds "Apple platforms add the one forced `Data`
//! copy". [`IosTunnelDevice::read_batch`] and [`IosTunnelDevice::write_batch`]
//! are the shapes that meet that budget, and `shells/ios`' pump calls them.
//!
//! # The per-packet trait methods, and a stated tension
//!
//! [`TunnelDevice::read_packet`] and [`TunnelDevice::write_packet`] are
//! **one packet per call**. Reading is fine: a batch is fetched once and drained
//! packet by packet from an in-process queue, so the crossing count is PB-1's.
//! Writing has no such shape — the trait offers no flush, so a batching
//! implementation would have to return `Ok` for a packet that has not reached the
//! OS, which is a lie about delivery of exactly W-28's kind.
//!
//! This crate refuses to tell it. [`TunnelDevice::write_packet`] writes
//! immediately, at one crossing per packet, and [`IosTunnelDevice::write_batch`]
//! exists beside it for the pump that wants PB-1's figure. **The seam having no
//! batched write is reported as a finding**, not resolved by a silent buffer.
//!
//! # Which family each packet is
//!
//! `NEPacketTunnelFlow.writePackets(_:withProtocols:)` takes an
//! `AF_INET`/`AF_INET6` number per packet. Deriving it from the IP version nibble
//! is a decision, so it is made here — [`packet_family`] — and Swift is handed the
//! answer. A packet whose version nibble is neither 4 nor 6 is **refused**, not
//! defaulted to v4: guessing would hand the OS a v6 packet labelled v4, which it
//! drops silently, and the resulting "the tunnel is up but v6 does not work" is
//! the asymmetry ADR-0010 R1 exists to forbid.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;

use twinvpn_platform::{
    Datapath, InterfaceName, LinkState, PlatformError, TunnelDevice, TunnelHandle,
};

use crate::host::{HostStatus, ProviderHost};
use crate::netcfg::{status_error, AppliedSettings};
use crate::oserr::{self, Context};
use crate::shutdown::ShutdownLatch;

/// `AF_INET`, as `NEPacketTunnelFlow` takes it.
pub const AF_INET_PROTOCOL: i32 = 2;
/// `AF_INET6`, as `NEPacketTunnelFlow` takes it on Darwin.
///
/// 30 on Darwin, and **not** Linux's 10. Transcribed here rather than taken from
/// `libc` so the value is the Darwin one even when this crate is compiled for the
/// Linux build host — where `libc::AF_INET6` is 10 and would make every host-run
/// test assert the wrong number.
pub const AF_INET6_PROTOCOL: i32 = 30;

/// How many packets one drained batch may hold before the queue refuses more.
///
/// `ownership.md` §6 rule 10: bound every allocation an untrusted input can
/// drive. Inbound packets are as untrusted as input gets, and an unbounded queue
/// inside a provider with a 12 MB budget is a jetsam kill waiting for a burst.
pub const MAX_QUEUED_PACKETS: usize = 512;

/// The maximum packet this device will read or write.
///
/// Sized from the largest MTU the settings object can carry plus room for a
/// jumbo frame the OS should never hand us; anything larger is refused rather
/// than allocated for.
pub const MAX_PACKET_BYTES: usize = 65_535;

/// The tunnel device.
pub struct IosTunnelDevice {
    host: Arc<dyn ProviderHost>,
    shutdown: ShutdownLatch,
    settings: AppliedSettings,
    state: Mutex<TunnelState>,
}

#[derive(Default)]
struct TunnelState {
    /// The one interface, if created. `NEPacketTunnelProvider` is a singleton
    /// per profile, so there is never a second.
    interface: Option<(String, u32, LinkState)>,
    handle: u64,
    inbound: VecDeque<Vec<u8>>,
    /// How many batches were dropped because the queue was full.
    ///
    /// Counted rather than silently discarded: a caller that is not draining
    /// needs to know it lost packets, for the same reason
    /// [`twinvpn_platform::NetworkChange::EventsLost`] exists.
    dropped_batches: u64,
}

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The `AF_*` protocol number for one packet, from its IP version nibble.
///
/// # Errors
///
/// [`PlatformError::OsUnsupported`] on an empty packet or a version nibble that
/// is neither 4 nor 6. Defaulting to v4 would label a v6 packet wrongly, the OS
/// would drop it without a word, and the tunnel would appear up with IPv6
/// broken — the exact "we have a v4 story and a weaker v6 story" asymmetry
/// ADR-0010 R1 forbids.
pub fn packet_family(packet: &[u8]) -> Result<i32, PlatformError> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Ok(AF_INET_PROTOCOL),
        Some(6) => Ok(AF_INET6_PROTOCOL),
        other => Err(PlatformError::OsUnsupported(Some(oserr::detail_from_code(
            i32::from(other.unwrap_or(0)),
            "NEPacketTunnelFlow.writePackets.protocol",
        )))),
    }
}

impl IosTunnelDevice {
    /// Builds the device.
    #[must_use]
    pub fn new(
        host: Arc<dyn ProviderHost>,
        shutdown: ShutdownLatch,
        settings: AppliedSettings,
    ) -> Self {
        Self {
            host,
            shutdown,
            settings,
            state: Mutex::new(TunnelState::default()),
        }
    }

    /// Drains one batch from `NEPacketTunnelFlow` — PB-1's **one** crossing.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the flow is unavailable.
    pub fn read_batch(&self) -> Result<usize, PlatformError> {
        self.shutdown.guard()?;
        let packets = self.host.read_packets().map_err(|s| {
            status_error(s, "NEPacketTunnelFlow.readPackets", Context::TunnelDevice)
        })?;
        let mut state = guard(&self.state);
        let mut accepted = 0usize;
        for packet in packets {
            if packet.len() > MAX_PACKET_BYTES || state.inbound.len() >= MAX_QUEUED_PACKETS {
                state.dropped_batches += 1;
                continue;
            }
            state.inbound.push_back(packet);
            accepted += 1;
        }
        Ok(accepted)
    }

    /// Writes a whole batch — PB-1's **one** crossing per batch.
    ///
    /// The families are derived here and handed to Swift, so the shell chooses
    /// nothing. A packet whose family cannot be determined fails the **whole**
    /// batch rather than being dropped from it: a silently short batch is a
    /// packet that vanished, which is indistinguishable on the wire from a
    /// network fault and would be debugged as one.
    ///
    /// # Errors
    ///
    /// [`PlatformError::OsUnsupported`] on an undeterminable family;
    /// [`PlatformError`] if the flow refuses.
    pub fn write_batch(&self, packets: &[Vec<u8>]) -> Result<usize, PlatformError> {
        self.shutdown.guard()?;
        if packets.is_empty() {
            return Ok(0);
        }
        let families = packets
            .iter()
            .map(|p| packet_family(p))
            .collect::<Result<Vec<_>, _>>()?;
        let total = packets.iter().map(Vec::len).sum();
        match self.host.write_packets(packets, &families) {
            HostStatus::Ok => Ok(total),
            other => Err(status_error(
                other,
                "NEPacketTunnelFlow.writePackets",
                Context::TunnelDevice,
            )),
        }
    }

    /// How many packets were dropped because the caller was not draining.
    #[must_use]
    pub fn dropped_packets(&self) -> u64 {
        guard(&self.state).dropped_batches
    }

    /// The link state, for the shell's own bring-up sequence.
    #[must_use]
    pub fn link_state(&self) -> Option<LinkState> {
        guard(&self.state).interface.as_ref().map(|(_, _, s)| *s)
    }
}

impl TunnelDevice for IosTunnelDevice {
    fn create_interface<'a>(
        &'a self,
        name: &'a InterfaceName,
        mtu: u32,
    ) -> BoxFuture<'a, Result<TunnelHandle, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // There is nothing to create. `NEPacketTunnelProvider` *is* the
            // interface, and the OS created it before this process was started —
            // which is CB-1 (b), "must execute inside an OS-imposed process,
            // extension or service that the OS itself starts". So this records
            // the name and the MTU the core chose and returns the handle.
            //
            // Created **DOWN**, per `docs/networking.md` §5.1: on this platform
            // "down" means the packet pump forwards nothing, and it is not the
            // same as having no settings installed. Coming up before addresses,
            // routes and rules are in place is §2.3's partial-application window.
            let mut state = guard(&self.state);
            if state.interface.is_some() {
                // A second create with the provider already representing one
                // interface is an adapter defect, not an OS condition. Reporting
                // it beats handing out a second handle that names the same
                // singleton.
                return Err(PlatformError::AdapterUnavailable(Some(
                    oserr::detail_from_code(0, "NEPacketTunnelProvider.singleton"),
                )));
            }
            state.handle += 1;
            state.interface = Some((name.as_str().to_owned(), mtu, LinkState::Down));
            Ok(TunnelHandle(state.handle))
        })
    }

    fn set_link(
        &self,
        handle: TunnelHandle,
        state: LinkState,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            let mut guarded = guard(&self.state);
            if guarded.handle != handle.0 || guarded.interface.is_none() {
                return Err(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                    0,
                    "NEPacketTunnelProvider.handle",
                ))));
            }
            // Purely a local state change, and deliberately so. `set_link(Down)`
            // MUST NOT clear the tunnel settings: the seam's own contract says
            // "enforcement rules stay installed — the two are separate facts,
            // which is why they are separate calls", and on this platform
            // clearing the settings is what `destroy_interface` and `rollback`
            // do. The packet pump reads this and forwards nothing while it is
            // Down, which is the disposition half of the mechanism
            // `crate::enforce` documents.
            if let Some(entry) = guarded.interface.as_mut() {
                entry.2 = state;
            }
            Ok(())
        })
    }

    fn destroy_interface(&self, handle: TunnelHandle) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // **Idempotent; safe after a crash** — and deliberately NOT gated on
            // the shutdown latch, because teardown is exactly what runs while
            // shutting down.
            {
                let mut state = guard(&self.state);
                if state.handle != handle.0 || state.interface.is_none() {
                    return Ok(());
                }
                state.interface = None;
                state.inbound.clear();
            }
            match self.host.clear_settings() {
                HostStatus::Ok | HostStatus::NotAttached => Ok(()),
                other => Err(status_error(
                    other,
                    "setTunnelNetworkSettings(nil)",
                    Context::TunnelDevice,
                )),
            }
        })
    }

    fn datapath(&self) -> Datapath {
        // ADR-0018 §11.2 row 2.3: "on Linux/OpenWrt the core *programs* the
        // kernel WireGuard module; elsewhere the core *is* the datapath". There
        // is no kernel WireGuard on iOS and no offload to declare — and W-37
        // records that declaring an offload one cannot achieve "would produce a
        // tunnel that carries nothing and calls itself offloaded".
        Datapath::Userspace
    }

    fn read_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            {
                let state = guard(&self.state);
                if state.handle != handle.0 || state.interface.is_none() {
                    return Err(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                        0,
                        "NEPacketTunnelProvider.handle",
                    ))));
                }
            }
            // Drain the in-process queue first; fetch a new batch only when it
            // is empty. That is PB-1's "1 per batch" on the read side.
            let packet = {
                let mut state = guard(&self.state);
                state.inbound.pop_front()
            };
            let packet = if let Some(packet) = packet {
                packet
            } else {
                if self.read_batch()? == 0 {
                    return Ok(0);
                }
                let Some(packet) = guard(&self.state).inbound.pop_front() else {
                    return Ok(0);
                };
                packet
            };
            if packet.len() > buf.len() {
                // A truncated packet is a packet that fails authentication for a
                // reason nobody can see. Refused, with the size as evidence.
                return Err(PlatformError::AdapterUnavailable(Some(
                    oserr::detail_from_code(
                        i32::try_from(packet.len()).unwrap_or(i32::MAX),
                        "NEPacketTunnelFlow.readPackets.truncated",
                    ),
                )));
            }
            buf[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        })
    }

    fn write_packet<'a>(
        &'a self,
        handle: TunnelHandle,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<usize, PlatformError>> {
        Box::pin(async move {
            {
                let state = guard(&self.state);
                if state.handle != handle.0 || state.interface.is_none() {
                    return Err(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                        0,
                        "NEPacketTunnelProvider.handle",
                    ))));
                }
            }
            // Immediately, not buffered — see the module header. Returning `Ok`
            // for a packet still sitting in a queue would be a lie about
            // delivery, and the trait offers no flush with which to make it true.
            self.write_batch(core::slice::from_ref(&packet.to_vec()))
        })
    }

    fn set_mtu(&self, handle: TunnelHandle, mtu: u32) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            {
                let mut state = guard(&self.state);
                if state.handle != handle.0 {
                    return Err(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                        0,
                        "NEPacketTunnelProvider.handle",
                    ))));
                }
                match state.interface.as_mut() {
                    Some(entry) => entry.1 = mtu,
                    None => {
                        return Err(PlatformError::InterfaceDown(Some(oserr::detail_from_code(
                            0,
                            "NEPacketTunnelProvider.handle",
                        ))))
                    }
                }
            }
            // There is no `set_mtu` on this platform. The MTU lives inside the
            // settings object, so DPLPMTUD raising or lowering it (§6.2) means
            // re-applying the *whole* object with one field changed. Re-deriving
            // the object from scratch would risk a different render; this
            // re-applies the exact bytes last installed with the MTU replaced,
            // so nothing else can drift under a probe.
            let Some(mut programme) = self.settings.get() else {
                // No settings installed yet. The MTU is recorded and will be
                // carried by the next apply; refusing here would make DPLPMTUD
                // fail during bring-up for no reason.
                return Ok(());
            };
            programme.mtu = mtu;
            match self.host.apply_settings(&programme.to_json()) {
                HostStatus::Ok => {
                    self.settings.set(programme);
                    Ok(())
                }
                other => Err(status_error(
                    other,
                    "setTunnelNetworkSettings.mtu",
                    Context::RouteProgram,
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::RecordingHost;

    fn build() -> (Arc<RecordingHost>, IosTunnelDevice, AppliedSettings) {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let settings = AppliedSettings::default();
        let device = IosTunnelDevice::new(host.clone(), ShutdownLatch::new(), settings.clone());
        (host, device, settings)
    }

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn created(device: &IosTunnelDevice) -> TunnelHandle {
        block_on(device.create_interface(&InterfaceName::new("twin0").expect("name"), 1280))
            .expect("creates")
    }

    fn v4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet
    }

    fn v6_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet
    }

    #[test]
    fn the_darwin_af_inet6_number_is_thirty_and_not_linuxs_ten() {
        // Transcribed rather than taken from `libc`, because on the Linux build
        // host `libc::AF_INET6` is 10 and every host-run test would assert the
        // wrong number while the device silently dropped every v6 packet.
        assert_eq!(AF_INET6_PROTOCOL, 30);
        assert_eq!(AF_INET_PROTOCOL, 2);
        assert_ne!(AF_INET6_PROTOCOL, libc::AF_INET6);
    }

    #[test]
    fn the_family_comes_from_the_version_nibble_and_is_never_guessed() {
        assert_eq!(packet_family(&v4_packet()), Ok(AF_INET_PROTOCOL));
        assert_eq!(packet_family(&v6_packet()), Ok(AF_INET6_PROTOCOL));
        // Guessing v4 here labels a v6 packet wrongly; the OS drops it in
        // silence and the tunnel looks up with IPv6 broken — the exact R1
        // asymmetry.
        for bad in [vec![], vec![0x00], vec![0x50], vec![0xf0]] {
            let err = packet_family(&bad).expect_err("refuses");
            assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
        }
    }

    #[test]
    fn the_interface_is_created_down() {
        // networking.md §5.1: "created DOWN". Coming up before addresses, routes
        // and rules are installed is the partial-application leak window.
        let (_host, device, _settings) = build();
        let handle = created(&device);
        assert_eq!(device.link_state(), Some(LinkState::Down));
        block_on(device.set_link(handle, LinkState::Up)).expect("up");
        assert_eq!(device.link_state(), Some(LinkState::Up));
    }

    #[test]
    fn set_link_down_does_not_clear_the_tunnel_settings() {
        // The seam: "Enforcement rules stay installed — the two are separate
        // facts, which is why they are separate calls."
        let (host, device, _settings) = build();
        let handle = created(&device);
        block_on(device.set_link(handle, LinkState::Up)).expect("up");
        block_on(device.set_link(handle, LinkState::Down)).expect("down");
        assert_eq!(host.state().settings_cleared, 0);
    }

    #[test]
    fn the_provider_is_a_singleton_and_a_second_create_is_refused() {
        let (_host, device, _settings) = build();
        created(&device);
        let err =
            block_on(device.create_interface(&InterfaceName::new("twin1").expect("name"), 1280))
                .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }

    #[test]
    fn destroy_is_idempotent_and_safe_after_a_crash() {
        let (host, device, _settings) = build();
        let handle = created(&device);
        block_on(device.destroy_interface(handle)).expect("destroys");
        block_on(device.destroy_interface(handle)).expect("again");
        block_on(device.destroy_interface(TunnelHandle(999))).expect("a stale handle too");
        assert_eq!(host.state().settings_cleared, 1);
    }

    #[test]
    fn destroy_still_runs_while_shutting_down() {
        // Teardown is exactly what runs during shutdown; gating it on the latch
        // would leave the settings object installed by the process that is
        // going away.
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let shutdown = ShutdownLatch::new();
        let device =
            IosTunnelDevice::new(host.clone(), shutdown.clone(), AppliedSettings::default());
        let handle = created(&device);
        shutdown.begin();
        block_on(device.destroy_interface(handle)).expect("destroys");
        assert_eq!(host.state().settings_cleared, 1);
    }

    #[test]
    fn the_datapath_is_userspace_because_the_core_is_the_datapath_here() {
        // W-37: declaring an offload one cannot achieve "would produce a tunnel
        // that carries nothing and calls itself offloaded".
        let (_host, device, _settings) = build();
        assert_eq!(device.datapath(), Datapath::Userspace);
    }

    #[test]
    fn one_batch_is_fetched_and_then_drained_packet_by_packet() {
        // PB-1's "1 per batch": three packets cost one crossing, not three.
        let (host, device, _settings) = build();
        let handle = created(&device);
        host.state().inbound = vec![v4_packet(), v6_packet(), v4_packet()];

        let mut buf = [0u8; 2048];
        let mut lengths = Vec::new();
        for _ in 0..3 {
            lengths.push(block_on(device.read_packet(handle, &mut buf)).expect("reads"));
        }
        assert_eq!(lengths, vec![20, 40, 20]);
        // The queue is empty; the next read fetches a new (empty) batch and
        // reports zero rather than blocking or inventing a packet.
        assert_eq!(
            block_on(device.read_packet(handle, &mut buf)).expect("reads"),
            0
        );
    }

    #[test]
    fn a_packet_too_large_for_the_callers_buffer_is_refused_and_never_truncated() {
        let (host, device, _settings) = build();
        let handle = created(&device);
        host.state().inbound = vec![v4_packet()];
        let mut small = [0u8; 4];
        let err = block_on(device.read_packet(handle, &mut small)).expect_err("refuses");
        assert_eq!(err.os_detail().map(|d| d.code), Some(20));
        assert_eq!(
            err.os_detail().map(|d| d.call),
            Some("NEPacketTunnelFlow.readPackets.truncated")
        );
    }

    #[test]
    fn an_oversized_or_flooding_batch_is_dropped_with_a_count_and_not_silently() {
        let (host, device, _settings) = build();
        created(&device);
        host.state().inbound = vec![vec![0x45; MAX_PACKET_BYTES + 1]];
        assert_eq!(device.read_batch().expect("reads"), 0);
        assert_eq!(device.dropped_packets(), 1);

        host.state().inbound = (0..MAX_QUEUED_PACKETS + 10).map(|_| v4_packet()).collect();
        assert_eq!(device.read_batch().expect("reads"), MAX_QUEUED_PACKETS);
        assert_eq!(device.dropped_packets(), 11);
    }

    #[test]
    fn a_written_batch_carries_the_right_family_per_packet() {
        let (host, device, _settings) = build();
        created(&device);
        device
            .write_batch(&[v4_packet(), v6_packet()])
            .expect("writes");
        let outbound = host.state().outbound.clone();
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].1, AF_INET_PROTOCOL);
        assert_eq!(outbound[1].1, AF_INET6_PROTOCOL);
    }

    #[test]
    fn one_undeterminable_packet_fails_the_whole_batch_rather_than_vanishing() {
        // A silently short batch is a packet that disappeared, which on the wire
        // is indistinguishable from a network fault and gets debugged as one.
        let (host, device, _settings) = build();
        created(&device);
        let err = device
            .write_batch(&[v4_packet(), vec![0x00; 8], v6_packet()])
            .expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.OS_UNSUPPORTED");
        assert!(host.state().outbound.is_empty(), "nothing was written");
    }

    #[test]
    fn a_write_before_the_interface_exists_is_a_named_refusal() {
        let (_host, device, _settings) = build();
        let err =
            block_on(device.write_packet(TunnelHandle(1), &v4_packet())).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "NET.IFACE_DOWN");
    }

    #[test]
    fn set_mtu_reapplies_the_exact_bytes_last_installed_with_one_field_changed() {
        // DPLPMTUD raises and lowers this as it probes (§6.2). Re-deriving the
        // whole settings object would let something else drift under a probe.
        let (host, device, settings) = build();
        let handle = created(&device);

        let mut programme = crate::settings::TunnelSettingsProgramme {
            tunnel_remote_address: "100.64.0.1".to_owned(),
            ipv4: crate::settings::FamilySettings::default(),
            ipv6: crate::settings::FamilySettings::default(),
            dns: crate::settings::DnsProgramme::default(),
            mtu: 1280,
            residuals: Vec::new(),
        };
        programme.ipv4.addresses = vec!["100.64.0.7".to_owned()];
        settings.set(programme);

        block_on(device.set_mtu(handle, 1400)).expect("sets");
        let applied = host
            .state()
            .settings_applied
            .last()
            .cloned()
            .expect("applied");
        assert!(applied.contains("\"mtu\":1400"));
        assert!(
            applied.contains("100.64.0.7"),
            "everything else is byte-identical to what was installed"
        );
        assert_eq!(settings.get().map(|p| p.mtu), Some(1400));
    }

    #[test]
    fn set_mtu_before_any_settings_exist_records_it_rather_than_failing_bring_up() {
        let (host, device, _settings) = build();
        let handle = created(&device);
        block_on(device.set_mtu(handle, 1400)).expect("records");
        assert!(host.state().settings_applied.is_empty());
    }

    #[test]
    fn after_shutdown_the_datapath_refuses_by_name_rather_than_hanging() {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let shutdown = ShutdownLatch::new();
        let device =
            IosTunnelDevice::new(host.clone(), shutdown.clone(), AppliedSettings::default());
        let handle = created(&device);
        shutdown.begin();
        let mut buf = [0u8; 64];
        assert_eq!(
            block_on(device.read_packet(handle, &mut buf)),
            Err(PlatformError::ShuttingDown)
        );
        assert_eq!(
            device.write_batch(&[v4_packet()]),
            Err(PlatformError::ShuttingDown)
        );
    }
}
