//! The userspace packet path: TUN in, tunnel out, and back.
//!
//! **Owner:** `core-composition`. Scaffolded by the integration lead; the
//! implementation is this module's own.
//!
//! **Authority:** ADR-0018 §11.2 row 2.3 ("on Linux/OpenWrt the core *programs*
//! the kernel WireGuard module; elsewhere the core *is* the datapath"), CB-1
//! (the packet path reaches the OS only through the adapter), CB-2 (the core
//! decides), CD-1/CD-2 (clocks and `Env` are injected);
//! `twinvpn_platform::config::{Datapath, TunnelDevice}`.
//!
//! # The blocker this module closes
//!
//! Every platform adapter in the tree — linux, windows, macos, ios, android —
//! declares [`Datapath::Userspace`], which by row 2.3 means **the core is the
//! datapath**. All five implement `TunnelDevice::read_packet` and
//! `write_packet`. Until this module existed, nothing in `core/` or in any shell
//! called either one: the tunnel had real keys, the sockets were gathered and
//! probed, and no code carried an IP packet between the TUN device and the
//! network. [`Pump`] is that code.
//!
//! # What a pump is
//!
//! One direction of one tunnel, and nothing else:
//!
//! | Direction | The five steps |
//! |---|---|
//! | Outbound | `TunnelDevice::read_packet` → `Tunnel::seal` → prepend the 16-byte header → `UdpSocket::send_to` to the **authoritative** endpoint |
//! | Inbound | `UdpSocket::recv_from` → parse the header → `Tunnel::open` at its counter → `TunnelDevice::write_packet` |
//!
//! It takes every input as a parameter — `Env`, the adapter, the handle, the
//! socket, the tunnel, the MTU — and reaches into no session state, so it is
//! exercisable against `twinvpn_platform::mock` with no live session and the
//! wiring into `session.connect` stays one integration-owned edit.
//!
//! # It refuses the wrong datapath rather than discovering it
//!
//! [`Pump::new`] reads `TunnelDevice::datapath` and returns
//! [`Refused::KernelOffload`] on a kernel-offload target **before** any adapter
//! call. On such a target `read_packet` answers `PlatformError::OsUnsupported`
//! and PB-1 counts zero crossings per packet, so a pump that started anyway
//! would spin on an error for the life of the session. Every adapter is
//! `Userspace` today; the seam allows both, and the pump does not assume.
//!
//! # Every buffer is bounded by the interface, never by the peer
//!
//! [`Budget`] is derived from the overlay MTU the core itself programmed, plus
//! `networking.md` §6.1's fixed 32-byte overhead. A peer's declared length is
//! only ever *compared* against a capacity that already exists — it is never an
//! input to an allocation — and a datagram that does not fit is
//! [`Reject::Oversize`] or [`Reject::Truncated`], never a truncation and never a
//! panic. That is `ownership.md` §6 rules 9 and 10 expressed in the type: the
//! only way to get a [`Buffers`] is through a [`Budget`], and the only way to
//! get a [`Budget`] is from an MTU that passed its bounds.
//!
//! # One bad datagram is not a teardown
//!
//! The classification lives in [`outcome`] and the reasoning is there, but the
//! shape of it belongs in this summary: a [`Reject`] is something an untrusted
//! peer did to one datagram and the pump keeps running; a [`Fault`] is
//! something about our own state and the pump stops. `Reject::tears_down`
//! answers `false` for every variant, including [`Reject::Replay`], whose
//! registry row is `FATAL`/`CRITICAL` and **`terminal = false`**.
//!
//! # Time, randomness and payloads
//!
//! CD-2: the [`Env`] arrives at construction. CD-1: the only wait this module
//! schedules is on `twinvpn_env::Timer`, on the injected monotonic clock. CD-3:
//! nothing here reads a clock or a random source directly. And `ownership.md`
//! §6 rule 11: the pump counts packets, bytes and rejects — it never records,
//! renders or logs a payload byte.

pub mod cancel;
pub mod frame;
pub mod outcome;

use core::time::Duration;
use std::sync::{Arc, Mutex};

use twinvpn_env::Env;
use twinvpn_platform::config::{Datapath, TunnelHandle};
use twinvpn_platform::error::PlatformError;
use twinvpn_platform::socket::UdpSocket;
use twinvpn_platform::PlatformAdapter;
use twinvpn_tunnel::{Tunnel, TunnelError};

pub use cancel::{race, Cancel, Cancelled, Race, Raced};
pub use frame::{
    Budget, Buffers, DataHeader, ReceiverIndex, ResumeHeader, DATAGRAM_CEILING, HEADER_BYTES,
    OVERHEAD_BYTES, OVERLAY_MTU_FLOOR, RESUME_HEADER_BYTES, TAG_BYTES, TYPE_RESUME,
    TYPE_TRANSPORT_DATA,
};
pub use outcome::{Counters, Fault, Refused, Reject, Report, Step, Stop, COMPONENT};

/// How long a direction waits when it has nothing to do.
///
/// It exists only because `TunnelDevice::read_packet` is permitted to report
/// "nothing available" rather than block — `twinvpn_platform::mock` answers
/// `PlatformError::Transient` on an empty queue — and a pump that retried such
/// an answer immediately would burn a core. An adapter that blocks never
/// reaches this. Short enough not to add measurable latency to the first packet
/// after an idle period, long enough not to be a spin, and measured on the
/// **injected monotonic clock** (CD-1) rather than the runtime's own timer.
pub const IDLE_BACKOFF: Duration = Duration::from_millis(1);

/// Everything a pump needs, supplied by the composition root.
pub struct PumpParts {
    /// CD-2: the capability set, bound at construction.
    pub env: Env,
    /// The adapter the packet path reaches the OS through (CB-1).
    pub adapter: Arc<dyn PlatformAdapter>,
    /// The overlay interface.
    pub handle: TunnelHandle,
    /// The underlay socket this tunnel is carried on.
    pub socket: Arc<dyn UdpSocket>,
    /// The tunnel. Shared because `seal` and `open` both need `&mut`, and the
    /// two directions are two tasks; the lock is held across the crypto call
    /// and **never across an await**.
    pub tunnel: Arc<Mutex<Tunnel>>,
    /// The index a peer stamps on frames addressed to us.
    pub local_receiver: ReceiverIndex,
    /// The index we stamp on frames addressed to the peer.
    pub peer_receiver: ReceiverIndex,
    /// The overlay interface MTU, which fixes every buffer bound.
    pub overlay_mtu: u32,
    /// The shutdown request. Shared with whatever will trip it.
    pub cancel: Cancel,
}

/// One direction-agnostic packet pump for one tunnel.
///
/// Both directions are driven from one instance so that a caller cannot wire
/// the outbound half to one tunnel and the inbound half to another.
pub struct Pump {
    env: Env,
    adapter: Arc<dyn PlatformAdapter>,
    handle: TunnelHandle,
    socket: Arc<dyn UdpSocket>,
    tunnel: Arc<Mutex<Tunnel>>,
    local_receiver: ReceiverIndex,
    peer_receiver: ReceiverIndex,
    budget: Budget,
    cancel: Cancel,
    /// The one datagram the inbound direction recognised as a resume and did
    /// not carry. See [`Pump::take_resume`].
    resume: Mutex<Option<Vec<u8>>>,
}

impl Pump {
    /// Builds a pump, or refuses.
    ///
    /// # Errors
    ///
    /// [`Refused::KernelOffload`] where the kernel carries packets and the core
    /// must never touch one; [`Refused::MtuBelowFloor`] and
    /// [`Refused::MtuAboveCeiling`] where the MTU cannot bound a buffer.
    /// **No adapter call happens before these checks**, so a refusal has no
    /// side effect to undo.
    pub fn new(parts: PumpParts) -> Result<Self, Refused> {
        if parts.adapter.tunnel().datapath() != Datapath::Userspace {
            return Err(Refused::KernelOffload);
        }
        let budget = Budget::new(parts.overlay_mtu)?;
        Ok(Self {
            env: parts.env,
            adapter: parts.adapter,
            handle: parts.handle,
            socket: parts.socket,
            tunnel: parts.tunnel,
            local_receiver: parts.local_receiver,
            peer_receiver: parts.peer_receiver,
            budget,
            cancel: parts.cancel,
            resume: Mutex::new(None),
        })
    }

    /// **Takes** the resume datagram the inbound direction set aside, if any.
    ///
    /// [`crate::execute::carriage::step`] drains this every tick and hands what
    /// it finds to `SessionRuntime::resume_on_wire`. It is a take, not a read:
    /// one datagram is delivered to the state machine exactly once.
    ///
    /// # Why the pump does not handle it itself
    ///
    /// A resume ends in a **transition** — `docs/reliability.md` §4.5 T35 — and
    /// ADR-0015 O-05 makes `SessionRuntime` the only object permitted to move
    /// the machine. The pump holds a `Tunnel` and a socket and has no route to
    /// the session table, deliberately: giving the datapath one would put the
    /// state machine underneath it. So the pump recognises and sets aside, and
    /// the layer that already owns both the `Core` and the runtime dispatches.
    ///
    /// # One slot, and why that is enough
    ///
    /// A second resume arriving before the first is claimed **replaces** it. A
    /// resume is a rare, idempotent-in-effect event and RS-4 makes `path_epoch`
    /// the arbiter regardless: of two offers the older one would be refused as
    /// replayed the moment the newer was accepted. An unbounded queue here
    /// would instead be a memory sink an off-path attacker fills for free, since
    /// nothing at this point has authenticated anything.
    #[must_use]
    pub fn take_resume(&self) -> Option<Vec<u8>> {
        // A poisoned slot holds an unauthenticated datagram, not key material.
        // Refusing to take it back would mean one panic elsewhere permanently
        // disabled resumption on this `Session`.
        self.resume
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// The bounds every buffer is sized from.
    #[must_use]
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// A handle on the shutdown request, so a caller that did not build the
    /// token can still stop this pump.
    #[must_use]
    pub fn cancel_handle(&self) -> Cancel {
        self.cancel.clone()
    }

    /// Buffers sized for this pump.
    #[must_use]
    pub fn buffers(&self) -> Buffers {
        Buffers::new(self.budget)
    }

    /// Carries one plaintext packet from the TUN to the network.
    ///
    /// Cancellation is honoured at the read — where all the waiting is — and
    /// **not** afterwards: once a packet has been taken off the interface and a
    /// counter consumed, the step finishes, because a cancellation between
    /// `seal` and `send_to` would abandon a nonce and drop a packet the OS
    /// believes was accepted.
    pub async fn step_outbound(&self, buffers: &mut Buffers) -> Step {
        if self.cancel.is_cancelled() {
            return Step::Stopped(Stop::Cancelled);
        }
        let capacity = self.budget.plaintext_capacity();
        buffers.packet.resize(capacity, 0);

        let read = {
            let device = self.adapter.tunnel();
            let work = device.read_packet(self.handle, &mut buffers.packet[..capacity]);
            match race(work, self.cancel.cancelled()).await {
                Raced::Cancelled => return Step::Stopped(Stop::Cancelled),
                Raced::Completed(read) => read,
            }
        };
        let length = match read {
            Ok(length) => length,
            Err(error) => return classify_adapter(error),
        };
        if length == 0 {
            return Step::Idle;
        }
        if length > capacity {
            // The adapter reported more bytes than the buffer it was given. A
            // defect on the far side of the seam; refused rather than trusted,
            // because trusting it is a read past the end of the buffer.
            return Step::Rejected(Reject::Truncated);
        }

        let (destination, counter) = {
            let Ok(mut tunnel) = self.tunnel.lock() else {
                return Step::Stopped(Stop::Fault(Fault::KeyStateUnusable));
            };
            // ADR-0001 §7.6: bulk traffic goes to the authoritative endpoint and
            // nowhere else. Read per packet rather than captured at
            // construction, so a committed migration takes effect with no
            // change here — and a staged, unvalidated candidate never does.
            let Some(destination) = tunnel.authoritative_endpoint() else {
                return Step::Stopped(Stop::Fault(Fault::NoAuthoritativeEndpoint));
            };
            match tunnel.seal(&buffers.packet[..length], &mut buffers.record) {
                Ok(counter) => (destination, counter),
                Err(error) => return Step::Stopped(seal_fault(error)),
            }
        };

        buffers.wire.clear();
        DataHeader {
            receiver: self.peer_receiver,
            counter,
        }
        .write(&mut buffers.wire);
        buffers.wire.extend_from_slice(&buffers.record);

        match self.socket.send_to(&buffers.wire, &destination).await {
            Ok(_) => Step::Moved(length),
            Err(error) => classify_adapter(error),
        }
    }

    /// Carries one datagram from the network to the TUN.
    ///
    /// The receive is raced against cancellation, which is what lets an idle
    /// tunnel shut down promptly instead of holding the runtime open for as
    /// long as the peer stays silent.
    pub async fn step_inbound(&self, buffers: &mut Buffers) -> Step {
        if self.cancel.is_cancelled() {
            return Step::Stopped(Stop::Cancelled);
        }
        let capacity = self.budget.datagram_capacity();
        // Back to the bound, not beyond it: the receive buffer's length IS the
        // cap an untrusted datagram is measured against.
        buffers.wire.resize(capacity, 0);

        let received = {
            let work = self.socket.recv_from(&mut buffers.wire[..capacity]);
            match race(work, self.cancel.cancelled()).await {
                Raced::Cancelled => return Step::Stopped(Stop::Cancelled),
                Raced::Completed(received) => received,
            }
        };
        let datagram = match received {
            Ok(datagram) => datagram,
            Err(error) => return classify_adapter(error),
        };
        if datagram.truncated {
            // "Reported, never silent" on the adapter's side; a typed reject on
            // ours. The peer sent more than the MTU allows and nothing was
            // allocated to hold it.
            return Step::Rejected(Reject::Truncated);
        }
        if datagram.len > capacity {
            return Step::Rejected(Reject::Oversize);
        }

        // The demux, before the data path sees anything. ADR-0001 §7.2 permits
        // "multiplexing a small disco message type on the same socket", and a
        // resume is exactly that: a datagram on this socket that is not L-DATA
        // traffic and must not be measured against L-DATA's rules. Selected on
        // the type octet alone, so nothing below accepts one byte more than it
        // did before.
        if buffers.wire.first() == Some(&TYPE_RESUME) {
            return self.divert_resume(&buffers.wire[..datagram.len]);
        }

        let (header, record_len) = match DataHeader::parse(&buffers.wire[..datagram.len]) {
            Ok((header, record)) => (header, record.len()),
            Err(reject) => return Step::Rejected(reject),
        };
        if header.receiver != self.local_receiver {
            return Step::Rejected(Reject::ForeignReceiver);
        }
        // The source endpoint is deliberately NOT checked. §7.6 constrains where
        // bulk traffic may be **sent**; a frame that authenticates is ours
        // wherever it arrived from, and refusing one from an unfamiliar source
        // would break roaming for exactly the peers that need it.

        let record_start = HEADER_BYTES;
        let record_end = record_start + record_len;
        {
            let Ok(mut tunnel) = self.tunnel.lock() else {
                return Step::Stopped(Stop::Fault(Fault::KeyStateUnusable));
            };
            match tunnel.open(
                header.counter,
                &buffers.wire[record_start..record_end],
                &mut buffers.packet,
            ) {
                Ok(()) => {}
                // The two an untrusted peer can reach. Neither ends the session.
                Err(TunnelError::Replay) => return Step::Rejected(Reject::Replay),
                Err(TunnelError::Crypto) => return Step::Rejected(Reject::Unauthenticated),
                Err(error) => return Step::Stopped(seal_fault(error)),
            }
        }
        if buffers.packet.len() > self.budget.plaintext_capacity() {
            // Unreachable with a conforming AEAD — the plaintext is shorter than
            // the record that carried it — and refused rather than asserted,
            // because the alternative is handing the interface a packet longer
            // than its MTU.
            return Step::Rejected(Reject::Oversize);
        }

        let length = buffers.packet.len();
        match self
            .adapter
            .tunnel()
            .write_packet(self.handle, &buffers.packet)
            .await
        {
            Ok(_) => Step::Moved(length),
            Err(error) => classify_adapter(error),
        }
    }

    /// Sets one recognised resume datagram aside for the session layer.
    ///
    /// **Nothing here authenticates anything, and nothing here may.** The
    /// resumption MAC is keyed by a secret this module does not hold and must
    /// not; `crate::resume::ResumeState::accept` verifies it, and commits the
    /// `path_epoch` only afterwards. So the two checks below are the same two
    /// the data path makes before *its* AEAD, and for the same reason: they
    /// shed obvious noise cheaply, and getting either wrong costs a dropped
    /// datagram and nothing else.
    ///
    /// The L-DATA replay window is not touched on this path. A resume frame is
    /// never opened under the transport keys, so no quantity of forged resumes
    /// can advance the window the data frames depend on.
    fn divert_resume(&self, datagram: &[u8]) -> Step {
        let Ok((header, payload)) = ResumeHeader::parse(datagram) else {
            return Step::Rejected(Reject::Malformed);
        };
        if header.receiver != self.local_receiver {
            return Step::Rejected(Reject::ForeignReceiver);
        }
        // Bounded by the receive buffer, which was sized from the MTU budget
        // before this datagram existed: §6 rule 10's "no allocation driven by a
        // declared length".
        *self
            .resume
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(payload.to_vec());
        Step::Diverted
    }

    /// Runs the outbound direction until it is stopped.
    pub async fn run_outbound(&self) -> Report {
        let mut buffers = self.buffers();
        let mut counters = Counters::default();
        loop {
            let step = self.step_outbound(&mut buffers).await;
            if let Some(report) = self.absorb(step, &mut counters).await {
                return report;
            }
        }
    }

    /// Runs the inbound direction until it is stopped.
    pub async fn run_inbound(&self) -> Report {
        let mut buffers = self.buffers();
        let mut counters = Counters::default();
        loop {
            let step = self.step_inbound(&mut buffers).await;
            if let Some(report) = self.absorb(step, &mut counters).await {
                return report;
            }
        }
    }

    /// Folds one step into the counters, waiting where the step asked for it.
    ///
    /// `Some` ends the loop. The two directions share this so that a reject can
    /// never end one loop and not the other.
    async fn absorb(&self, step: Step, counters: &mut Counters) -> Option<Report> {
        match step {
            Step::Moved(bytes) => {
                counters.record_moved(bytes);
                None
            }
            Step::Diverted => {
                counters.record_diverted();
                // No backoff: a datagram arrived, so the socket is live and the
                // next one may already be waiting.
                None
            }
            Step::Rejected(reject) => {
                counters.record(reject);
                // The property, stated where the loop continues rather than
                // only in the enum's documentation.
                debug_assert!(!reject.tears_down());
                None
            }
            Step::Idle | Step::Deferred => {
                if matches!(step, Step::Deferred) {
                    counters.adapter_transient = counters.adapter_transient.saturating_add(1);
                }
                counters.idle_waits = counters.idle_waits.saturating_add(1);
                if self.wait_or_stop().await {
                    None
                } else {
                    Some(Report {
                        stop: Stop::Cancelled,
                        counters: *counters,
                    })
                }
            }
            Step::Stopped(reason) => Some(Report {
                stop: reason,
                counters: *counters,
            }),
        }
    }

    /// Waits out one idle interval, or gives up if cancellation arrives first.
    ///
    /// Returns whether the loop should continue. The wait is itself raced, so a
    /// shutdown request never has to sit through a backoff.
    async fn wait_or_stop(&self) -> bool {
        let sleep = self.env.timer().sleep(IDLE_BACKOFF);
        matches!(
            race(sleep, self.cancel.cancelled()).await,
            Raced::Completed(())
        )
    }
}

/// Maps a `TunnelError` from `seal` or `open` onto the pump's own stop reason.
///
/// [`TunnelError::Replay`] and [`TunnelError::Crypto`] never reach here: they
/// are the two an untrusted peer can provoke, and the inbound step handles them
/// as [`Reject`]s before this is called. Everything left is about our own state.
fn seal_fault(error: TunnelError) -> Stop {
    match error {
        TunnelError::NotEstablished => Stop::Fault(Fault::NotEstablished),
        // Not a failure: ADR-0001 §7.2 forbids the counter to wrap because it is
        // the AEAD nonce, so the generation is simply used up and a rekey is
        // owed.
        TunnelError::CounterExhausted => Stop::RekeyRequired,
        TunnelError::TranscriptMismatch => Stop::Fault(Fault::TranscriptMismatch),
        // `Crypto` and `Replay` are the two an untrusted peer can provoke and
        // the inbound step has already handled them as rejects, so reaching
        // either here is a defect. `TunnelError` is also `#[non_exhaustive]`,
        // and a variant this build has never seen is not classifiable —
        // guessing at a disposition for one is how a future security event
        // becomes a dropped packet. Both stop, and the code says so.
        _ => Stop::Fault(Fault::KeyStateUnusable),
    }
}

/// Maps a `PlatformError` onto the pump's own step outcome.
///
/// # Why the variant, and why there is no longer an alternative
///
/// This used to read "why the variant and not `PlatformError::is_retryable`",
/// and named that function as a defect: it asked the **registry** whether the
/// mapped code's class was `TRANSIENT`, while `PlatformError::Transient` maps
/// onto `PLATFORM.ADAPTER_UNAVAILABLE`, whose class is `PERSISTENT` — so it
/// answered `false` for the one variant whose name said otherwise.
///
/// **`is_retryable` is now deleted**, and for a better reason than the mismatch:
/// `docs/reliability.md` §3.1 says the retry policy, the backoff regime and the
/// circuit breaker are all driven by `class`, "**never guessed from an error
/// type**" — and a predicate on an error enum is exactly that guess. Correcting
/// it to read the variant would have stood a second retry authority beside §6's
/// governor. A caller that wants the answer reads
/// [`PlatformError::reason_code`]`().class()`, which is the field §6 is
/// specified to read and keeps all four classes apart; a `bool` could not.
///
/// The pump still matches on the variant, because the variant is what the
/// adapter actually stated and CB-2 leaves the decision to the core.
fn classify_adapter(error: PlatformError) -> Step {
    match error {
        PlatformError::Cancelled => Step::Stopped(Stop::Cancelled),
        PlatformError::ShuttingDown => Step::Stopped(Stop::ShuttingDown),
        // Also the mock's answer for "no packet is queued", which is why this is
        // a wait rather than an error.
        PlatformError::Transient(_) => Step::Deferred,
        other => Step::Stopped(Stop::Fault(Fault::Device(other))),
    }
}
