//! `TvbExt` — one running extension instance, and everything the C surface is a
//! thin wrapper over.
//!
//! **Authority:** ADR-0018 CB-2 (the shell holds no decision), CB-6 (the OS
//! holds the rule set), F-6; ADR-0022 (sleep/wake — the adapter reports the
//! fact, the core decides); ADR-0015 §6 rule 6.
//!
//! # Where the decisions are, and are not
//!
//! Nothing in this file decides anything about a TwinVPN domain fact. The
//! settings document is rendered by
//! [`twinvpn_platform_macos::nesettings::render_json`] from a
//! [`NetworkContract`] the **core** computed; the sleep and wake transitions are
//! interpreted by [`PowerJournal`], which lives in the adapter and is tested
//! there; the packet framing is the adapter's [`encode_frame`]/[`decode_frame`].
//! This file marshals, locks and hands over.
//!
//! # What is NOT wired in this wave, stated once
//!
//! There is **no `twinvpn-core` handle**. `shells/macos` has no core-hosting
//! runtime yet, so no `NetworkContract` is ever computed and
//! [`TvbExt::next_settings`] refuses by name on every call.
//!
//! The refusal is placed at `next_settings` rather than at `tvb_ext_start`, and
//! that is a deliberate choice with a consequence worth stating plainly:
//! `PacketTunnelProvider.swift`'s `startTunnel` **completes only once a settings
//! document has arrived and NE has accepted it**, so refusing here refuses the
//! start from the OS's point of view exactly as refusing at `start` would — and
//! it leaves the datapath, the lifecycle facts, the buffer discipline and the
//! panic containment reachable through the real C surface, where they are
//! tested. Refusing at `start` would have made all of that unreachable and
//! untested.
//!
//! [`TvbExt::publish_settings`] is the entry the day a core is wired. It is not
//! dead code kept for tidiness: it is the shape the wiring plugs into, and it is
//! exercised by this crate's tests.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use twinvpn_platform::{NetworkChange, NetworkContract};
use twinvpn_platform_macos::iface::MacosInterfaceProvider;
use twinvpn_platform_macos::power::{PowerEvent, PowerJournal};
use twinvpn_platform_macos::utun::{decode_frame, encode_frame, PacketPort as _};
use twinvpn_platform_macos::ShutdownLatch;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, AddressFamily, Component, Diagnostic};

use crate::correlation::CorrelationId;
use crate::port::BridgePort;

/// How many settings documents are held before the producer blocks.
///
/// Small on purpose. A settings document is the **current** desired state, and a
/// deep queue would let the provider apply a stale one after a newer one had
/// been computed — which is a tunnel configured for a network it has already
/// left.
pub const SETTINGS_CAPACITY: usize = 4;

/// `TVB_FAMILY_V4`, as the header defines it.
pub const FAMILY_V4: i32 = 4;

/// `TVB_FAMILY_V6`.
pub const FAMILY_V6: i32 = 6;

/// The product-neutral family tag for a wire value.
///
/// Deliberately not `AF_INET`/`AF_INET6`: those are 2 and 30 on Darwin and 2 and
/// 10 on Linux, so a constant taken from `libc` would be the *host's* value in
/// exactly the tests meant to check the Darwin behaviour. The adapter's
/// `addr::darwin_af` is the one place a Darwin number appears.
#[must_use]
pub const fn family_of_wire(value: i32) -> Option<AddressFamily> {
    match value {
        FAMILY_V4 => Some(AddressFamily::V4),
        FAMILY_V6 => Some(AddressFamily::V6),
        _ => None,
    }
}

/// The wire value for a family.
#[must_use]
pub const fn wire_of_family(family: AddressFamily) -> i32 {
    match family {
        AddressFamily::V4 => FAMILY_V4,
        AddressFamily::V6 => FAMILY_V6,
    }
}

/// The log tag for a family. `&'static str`, so it cannot carry an address.
#[must_use]
pub const fn family_tag(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::V4 => "v4",
        AddressFamily::V6 => "v6",
    }
}

/// Whether a core is wired to compute contracts.
///
/// **One gate, in one place.** The day `shells/macos` hosts a core, this becomes
/// a second variant holding the handle and every refusal below turns into a
/// call. Making it an enum rather than an `Option<()>` is what keeps the day-one
/// state a named condition rather than an absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreHandle {
    /// No core hosts this extension. Every operation that needs a
    /// `NetworkContract` refuses by name.
    Unwired,
}

/// One running extension instance.
///
/// `Send + Sync` because Swift calls three of its entry points from three tasks
/// at once. Every field below is either `Sync` on its own or behind a lock, and
/// the three hot paths take three different locks so none blocks another.
#[derive(Debug)]
pub struct TvbExt {
    core: CoreHandle,
    port: Arc<BridgePort>,
    settings_tx: SyncSender<Vec<u8>>,
    /// Behind a mutex because `Receiver` is `Send` but not `Sync`, and because
    /// there is exactly one settings consumer — the provider's settings task.
    settings_rx: Mutex<Receiver<Vec<u8>>>,
    journal: Mutex<PowerJournal>,
    interfaces: Arc<MacosInterfaceProvider>,
    shutdown: ShutdownLatch,
    stopped: Mutex<bool>,
}

impl TvbExt {
    /// Builds an instance.
    ///
    /// Everything is constructed here and nothing is discovered from the
    /// environment (CD-2).
    #[must_use]
    pub fn new(core: CoreHandle) -> Self {
        let (settings_tx, settings_rx) = sync_channel(SETTINGS_CAPACITY);
        let shutdown = ShutdownLatch::new();
        Self {
            core,
            port: Arc::new(BridgePort::new()),
            settings_tx,
            settings_rx: Mutex::new(settings_rx),
            journal: Mutex::new(PowerJournal::new()),
            interfaces: Arc::new(MacosInterfaceProvider::new(shutdown.clone())),
            shutdown,
            stopped: Mutex::new(false),
        }
    }

    /// The packet port, so the shell can hand it to the adapter's tunnel device
    /// with `set_pending_port` the day a core is wired.
    #[must_use]
    pub fn port(&self) -> Arc<BridgePort> {
        Arc::clone(&self.port)
    }

    /// The interface provider the lifecycle facts are published into.
    ///
    /// The core subscribes to this; the bridge only ever publishes.
    #[must_use]
    pub fn interfaces(&self) -> Arc<MacosInterfaceProvider> {
        Arc::clone(&self.interfaces)
    }

    /// Whether `stop` has been reported.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.lock().is_ok_and(|s| *s)
    }

    /// Reports a stop.
    ///
    /// Closes the datapath and **touches no enforcement**. CB-6 puts the
    /// installed rule set in the OS's custody precisely so the core going away
    /// does not drop protection; this type holds no `NetworkConfig` at all, which
    /// is the strongest available form of that guarantee.
    pub fn stop(&self, reason: i32, correlation: &CorrelationId) {
        if let Ok(mut stopped) = self.stopped.lock() {
            *stopped = true;
        }
        self.shutdown.begin();
        self.port.close();
        // The OS's own stop reason, widened without a sign loss: a negative
        // value is not one NE documents, and silently reinterpreting it as a
        // huge unsigned number would put a nonsense figure in a support bundle.
        crate::log::counted(
            "tvb_ext_stop",
            "stop_reason",
            u64::try_from(reason).unwrap_or(u64::MAX),
            correlation,
        );
    }

    /// Hands the core one packet read from `packetFlow`.
    ///
    /// # Errors
    ///
    /// A `PROTO.MALFORMED_MESSAGE` diagnostic when `family` is neither
    /// `TVB_FAMILY_V4` nor `TVB_FAMILY_V6`. **Not a guess**: the family decides
    /// which 4-byte header the frame carries, and inventing one produces a frame
    /// the kernel drops with no diagnostic at all.
    ///
    /// The same code for an **empty** packet. A zero-length packet framed for
    /// `utun` is four bytes of header and nothing else, which the adapter's
    /// `decode_frame` reports as `FrameError::Empty` — so accepting it here would
    /// queue a frame the core is guaranteed to reject, one hop later and with
    /// less context.
    pub fn inject_inbound(&self, packet: &[u8], family: i32) -> Result<(), Diagnostic> {
        if packet.is_empty() {
            return Err(Diagnostic::builder(
                codes::PROTO_MALFORMED_MESSAGE,
                Component::TunnelEngine,
            )
            .evidence("cap_violated", EvidenceValue::Text("packet_len".to_owned()))
            .evidence("observed", EvidenceValue::Uint(0))
            .evidence("limit", EvidenceValue::Uint(1))
            .build());
        }
        let Some(family) = family_of_wire(family) else {
            return Err(Diagnostic::builder(
                codes::PROTO_MALFORMED_MESSAGE,
                Component::TunnelEngine,
            )
            .evidence("cap_violated", EvidenceValue::Text("family".to_owned()))
            .evidence("observed", EvidenceValue::Int(i64::from(family)))
            .evidence("limit", EvidenceValue::Int(i64::from(FAMILY_V6)))
            .build());
        };
        let mut frame = Vec::new();
        // The adapter's own framing, so there is no second copy of the `utun`
        // header to get wrong.
        encode_frame(family, packet, &mut frame);
        crate::log::packet("tvb_ext_inject_inbound", family_tag(family), packet.len());
        self.port.inject_inbound(frame);
        Ok(())
    }

    /// The next packet the core wants written, or `None` on timeout.
    ///
    /// # Errors
    ///
    /// A `PROTO.MALFORMED_MESSAGE` diagnostic when a queued frame does not
    /// decode — which would be a defect in this crate's own framing, and is
    /// reported rather than passed to Swift as a packet with four bytes of
    /// garbage in front of its IP header.
    pub fn next_outbound(&self, timeout: Duration) -> Result<Option<(Vec<u8>, i32)>, Diagnostic> {
        let Some(frame) = self.port.next_outbound(timeout) else {
            return Ok(None);
        };
        let Ok((family, packet)) = decode_frame(&frame) else {
            return Err(Diagnostic::builder(
                codes::PROTO_MALFORMED_MESSAGE,
                Component::TunnelEngine,
            )
            .evidence("cap_violated", EvidenceValue::Text("utun_frame".to_owned()))
            .evidence("observed", EvidenceValue::Uint(frame.len() as u64))
            .evidence("limit", EvidenceValue::Uint(4))
            .build());
        };
        crate::log::packet("tvb_ext_next_outbound", family_tag(family), packet.len());
        Ok(Some((packet.to_vec(), wire_of_family(family))))
    }

    /// Publishes a settings document the core computed.
    ///
    /// **The entry the wiring plugs into.** It renders through
    /// [`twinvpn_platform_macos::nesettings::render_json`], so the whole
    /// `NEPacketTunnelNetworkSettings` object — both families, the netmasks, the
    /// match domains with `.local` excluded — is computed on this side of the
    /// boundary and Swift copies fields.
    ///
    /// # Errors
    ///
    /// Whatever the renderer reports, as a diagnostic. A full queue is **not** an
    /// error: the oldest pending document is dropped, because a settings document
    /// is the current desired state and applying a stale one is worse than
    /// skipping it.
    pub fn publish_settings(
        &self,
        contract: &NetworkContract,
        tunnel_remote_address: &str,
    ) -> Result<(), Diagnostic> {
        let document =
            twinvpn_platform_macos::nesettings::render_json(contract, tunnel_remote_address)
                .map_err(|error| error.diagnostic(Component::RoutingEngine))?;
        // `try_send` rather than `send`: blocking here would block whatever
        // computed the contract, and the core's reconciler is not something to
        // stall on a Swift task that is slow to read.
        let _ = self.settings_tx.try_send(document.into_bytes());
        Ok(())
    }

    /// The next settings document, or `None` on timeout.
    ///
    /// # Errors
    ///
    /// A `PLATFORM.ADAPTER_UNAVAILABLE` diagnostic while no core is wired — see
    /// the module documentation for why the refusal is here and not at `start`.
    pub fn next_settings(&self, timeout: Duration) -> Result<Option<Vec<u8>>, Diagnostic> {
        match self.core {
            CoreHandle::Unwired => {
                // A document that WAS published — by a test today, by the wiring
                // tomorrow — is served normally, so the gate is the only thing
                // this arm adds. Waiting out the timeout before refusing is
                // deliberate: an immediate refusal would turn every `startTunnel`
                // into an instant failure even on a build where the core is
                // seconds from producing its first contract.
                if let Some(document) = self.await_settings(timeout) {
                    return Ok(Some(document));
                }
                Err(Diagnostic::builder(
                    codes::PLATFORM_ADAPTER_UNAVAILABLE,
                    Component::TunnelEngine,
                )
                .build())
            }
        }
    }

    /// The settings document a wired core would produce, blocking up to
    /// `timeout`.
    ///
    /// Separate from [`Self::next_settings`] so the blocking read is testable
    /// without the gate. The day a core is wired, `next_settings` becomes this.
    #[must_use]
    pub fn await_settings(&self, timeout: Duration) -> Option<Vec<u8>> {
        let receiver = self.settings_rx.lock().ok()?;
        // Both `Timeout` and `Disconnected` are "nothing to apply": a closed
        // channel means the producer is gone, which the caller handles the same
        // way it handles a quiet interval.
        receiver.recv_timeout(timeout).ok()
    }

    /// Reports that the OS is about to suspend the provider.
    ///
    /// ADR-0022: the adapter reports the fact and the core decides. Nothing here
    /// tears anything down.
    pub fn report_sleep(&self, correlation: &CorrelationId) {
        self.observe(PowerEvent::WillSleep, "tvb_ext_sleep", correlation);
    }

    /// Reports that the OS has resumed the provider.
    ///
    /// The resulting `EventsLost` reaches every subscriber **before** the posture
    /// change, which is what stops a core rendering a confident, stale green: the
    /// gap forces a re-enumeration.
    pub fn report_wake(&self, correlation: &CorrelationId) {
        self.observe(PowerEvent::HasPoweredOn, "tvb_ext_wake", correlation);
    }

    /// Reports that the underlying path changed.
    ///
    /// **A reported gap.** [`NetworkChange`] has variants for interfaces,
    /// addresses, default routes, resolvers, NAT64 and link posture, and none
    /// for "the path changed and I cannot say how" — which is the only thing NE's
    /// path callback actually tells a provider. [`NetworkChange::EventsLost`] is
    /// the nearest true statement: the stream is not complete, so re-enumerate.
    /// It is the same gap [`PowerJournal`] records against a resume.
    pub fn report_network_changed(&self, correlation: &CorrelationId) {
        let published = self
            .interfaces
            .publish(NetworkChange::EventsLost { count: None });
        crate::log::counted(
            "tvb_ext_network_changed",
            "subscribers",
            published as u64,
            correlation,
        );
    }

    fn observe(&self, event: PowerEvent, call: &'static str, correlation: &CorrelationId) {
        let changes = match self.journal.lock() {
            Ok(mut journal) => journal.observe(event),
            // A poisoned journal means a panic happened mid-transition. The fact
            // still has to reach the core, and the safe direction is the one that
            // forces a re-enumeration.
            Err(_) => vec![NetworkChange::EventsLost { count: None }],
        };
        let count = changes.len();
        self.interfaces.publish_all(changes);
        crate::log::counted(call, "changes", count as u64, correlation);
    }
}

#[cfg(test)]
#[path = "ext_tests.rs"]
mod tests;
