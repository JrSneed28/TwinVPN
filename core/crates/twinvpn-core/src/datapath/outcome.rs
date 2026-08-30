//! What the pump does about each thing that can go wrong, and why.
//!
//! **Authority:** `docs/implementation/ownership.md` §4.2 (the frozen
//! `DOMAIN.CONDITION` taxonomy; every code here exists in
//! `contracts/registry/reason_codes.json`), §6 rule 9 (a cap violation is a
//! typed reject, never a truncation), rule 11 (never log a tunnel payload) and
//! rule 12 (registered codes, never a raw internal error); ADR-0001 §7.2 (no
//! response to unauthenticated packets); ADR-0015 §11.2 (class, severity and
//! `terminal` are the registry's, not this module's).
//!
//! # The distinction this module exists to hold
//!
//! An attacker who can inject **one** datagram must not be able to tear a
//! tunnel down. That is the whole reason [`Reject`] and [`Fault`] are two types
//! rather than one enum with a severity field:
//!
//! - a [`Reject`] is something an **untrusted peer** did to one datagram. It is
//!   counted, the datagram is discarded, and the pump keeps running.
//!   [`Reject::tears_down`] answers `false` for every variant, and it is a
//!   function rather than a comment so a test can assert it;
//! - a [`Fault`] is something about **our own** state — the keys are gone, the
//!   interface is gone, the tunnel is not established. Nothing an attacker
//!   sends can produce one, so stopping the pump on one is safe.
//!
//! `CRYPTO.REPLAY_DETECTED` sits exactly on that line and the registry settles
//! it: `class = FATAL`, `severity = CRITICAL`, **`terminal = false`**, scope
//! `SESSION`. It is a security event, reported with its full weight — and it
//! does not end the session, because a replay is a datagram anyone who can
//! observe the wire can produce, and the alternative is a one-packet remote
//! teardown. See [`Reject::Replay`].

use twinvpn_platform::error::PlatformError;
use twinvpn_types::{codes, Component, Diagnostic, ReasonCode};

/// The component every diagnostic from this module is attributed to.
///
/// The pump is the L-DATA data path, so a bundle reads `TunnelEngine` whether
/// the frame was refused by the replay window or by the length cap.
pub const COMPONENT: Component = Component::TunnelEngine;

/// Why a pump refused to start at all.
///
/// Every variant is checked in [`super::Pump::new`], **before** any adapter
/// call, so a refusal costs no packet and no side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refused {
    /// The adapter declares [`twinvpn_platform::config::Datapath::KernelOffload`].
    ///
    /// ADR-0018 §11.2 row 2.3: on such a target "the core *programs* the kernel
    /// WireGuard module" and never sees a packet, and PB-1 counts **zero**
    /// crossings per packet there. Refusing here rather than discovering it at
    /// the first `read_packet` matters: the adapter answers that call with
    /// `PlatformError::OsUnsupported`, so a pump that started anyway would spin
    /// on an error for the life of the session instead of saying, once, that it
    /// is the wrong datapath.
    #[error("this adapter's datapath is KernelOffload; the core must not carry packets")]
    KernelOffload,
    /// The overlay MTU is below the 1280-byte floor.
    ///
    /// `docs/networking.md` §6.2 sets the overlay interface to 1280 at bring-up
    /// and raises it by DPLPMTUD afterwards; 1280 is RFC 8200's IPv6 minimum
    /// link MTU and nothing below it is a conforming overlay.
    #[error("overlay MTU {mtu} is below the 1280-byte floor")]
    MtuBelowFloor {
        /// The refused MTU.
        mtu: u32,
    },
    /// The overlay MTU plus the L-DATA overhead exceeds the largest datagram a
    /// UDP socket can carry.
    ///
    /// An untrusted or merely wrong MTU must not become a multi-megabyte
    /// buffer, which is §6 rule 10 applied to the one number the pump sizes
    /// everything from.
    #[error("overlay MTU {mtu} exceeds what a UDP datagram can carry")]
    MtuAboveCeiling {
        /// The refused MTU.
        mtu: u32,
    },
}

impl Refused {
    /// The registered `reason_code`.
    ///
    /// [`Refused::KernelOffload`] deliberately carries the **same** code the
    /// adapter would have returned from `read_packet` on that target
    /// (`PlatformError::OsUnsupported` maps to it too), so refusing early and
    /// discovering late are indistinguishable to anything downstream. Refusing
    /// early is then purely a saving, never a different story.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        match self {
            Refused::KernelOffload => codes::PLATFORM_OS_UNSUPPORTED,
            Refused::MtuBelowFloor { .. } => codes::NET_MTU_TOO_SMALL,
            Refused::MtuAboveCeiling { .. } => codes::PROTO_SIZE_EXCEEDED,
        }
    }

    /// The registered diagnostic.
    #[must_use]
    pub fn diagnostic(self) -> Diagnostic {
        Diagnostic::builder(self.reason_code(), COMPONENT).build()
    }
}

/// One datagram or one packet, discarded. **Never a session teardown.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reject {
    /// Too short to hold an L-DATA header and a tag, or not a transport-data
    /// frame, or its reserved bytes were not zero.
    ///
    /// ADR-0001 §7.2 permits "multiplexing a small disco message type on the
    /// same socket", so a datagram that is not ours is an ordinary event on a
    /// shared socket rather than an error.
    Malformed,
    /// Addressed to a receiver index that is not this tunnel's.
    ///
    /// A cheap pre-AEAD shed, in WireGuard's own demux position. Getting it
    /// wrong costs nothing but a dropped packet, and getting it right keeps an
    /// unrelated flow's frames out of the authentication-failure counter.
    ForeignReceiver,
    /// Larger than the buffer the MTU budget allows.
    ///
    /// §6 rule 9's "typed reject … never a truncation, never a pad, never a
    /// silent accept". The buffer was sized from the **interface MTU**, so the
    /// declared length of an untrusted datagram never drove an allocation: it
    /// is compared against a bound that already existed.
    Oversize,
    /// The adapter reported that the datagram did not fit.
    ///
    /// `Datagram::truncated` is "reported, never silent" precisely so this is a
    /// reject rather than a message that fails authentication for a reason
    /// nobody can see.
    Truncated,
    /// The AEAD refused it.
    ///
    /// **A silent, counted drop.** It is the only reject with no reason code,
    /// for two reasons that point the same way. ADR-0001 §7.2 requires no
    /// response to unauthenticated packets, and `CryptoUnavailable`'s own
    /// documentation calls a distinguishable failure "an oracle"; and emitting
    /// a diagnostic per forged datagram would hand any off-path attacker a
    /// log-amplification lever. The observable is
    /// [`Counters::rejected_unauthenticated`] — a count, never a byte.
    ///
    /// There is also a **registry gap** here, reported rather than patched:
    /// no `CRYPTO.*` code covers a transport-data authentication failure, and
    /// the nearest, `CRYPTO.HANDSHAKE_REJECTED`, is about the handshake and is
    /// `terminal = true`. `contracts/` is frozen (`ownership.md` §3), so this
    /// follows the precedent `twinvpn_platform::error` set for its own gap.
    Unauthenticated,
    /// The anti-replay window refused the counter.
    ///
    /// `CRYPTO.REPLAY_DETECTED`, whose registry row is `class = FATAL`,
    /// `severity = CRITICAL` and **`terminal = false`**. Reported with that
    /// weight and **not** a teardown: the datagram was refused by
    /// `Tunnel::open`'s non-mutating `would_accept` check *before* an AEAD was
    /// spent on it, so nothing moved; and treating it as terminal would mean
    /// anyone who can capture one genuine datagram can end the session by
    /// sending it again.
    Replay,
}

impl Reject {
    /// The registered `reason_code`, where one exists.
    ///
    /// `None` for [`Reject::Unauthenticated`] alone; see its documentation.
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Reject::Malformed | Reject::ForeignReceiver => Some(codes::PROTO_UNPARSEABLE_ENVELOPE),
            Reject::Oversize | Reject::Truncated => Some(codes::PROTO_SIZE_EXCEEDED),
            Reject::Unauthenticated => None,
            Reject::Replay => Some(codes::CRYPTO_REPLAY_DETECTED),
        }
    }

    /// Whether this reject ends the session.
    ///
    /// **Always `false`.** Written as a function rather than left implicit so
    /// that "one injected datagram cannot tear down a tunnel" is a property a
    /// test asserts over every variant, and so adding a variant that *does*
    /// tear down would be a deliberate edit here rather than an accident in a
    /// match arm somewhere else.
    #[must_use]
    pub const fn tears_down(self) -> bool {
        false
    }

    /// Whether the occurrence should be surfaced as a security event rather
    /// than only counted.
    ///
    /// True for [`Reject::Replay`] and nothing else: it is the one reject whose
    /// registry row is `FATAL`/`CRITICAL`, and the one that says something
    /// about an adversary rather than about a malformed byte.
    #[must_use]
    pub const fn is_security_event(self) -> bool {
        matches!(self, Reject::Replay)
    }

    /// The registered diagnostic, where a code exists.
    #[must_use]
    pub fn diagnostic(self) -> Option<Diagnostic> {
        Some(Diagnostic::builder(self.reason_code()?, COMPONENT).build())
    }
}

/// Something about **our own** state that the pump cannot continue past.
///
/// Nothing a peer can send produces one of these, which is what makes stopping
/// on them safe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Fault {
    /// The tunnel is not in a state that carries traffic.
    #[error("the tunnel is not established")]
    NotEstablished,
    /// The tunnel has no authoritative endpoint to send to.
    ///
    /// ADR-0001 §7.6 makes the authoritative endpoint the only one bulk traffic
    /// may go to; its absence on an established tunnel is a composition defect,
    /// not a network condition.
    #[error("the tunnel has no authoritative endpoint")]
    NoAuthoritativeEndpoint,
    /// Sealing failed with keys present, or the tunnel's lock was poisoned.
    ///
    /// Both are defects. A poisoned lock means a panic ran while key state was
    /// being mutated, and there is no reading of that state it is safe to seal
    /// under — `twinvpn_tunnel::bind::SessionKeys` fails closed for the same
    /// reason.
    #[error("the tunnel's own key state is unusable")]
    KeyStateUnusable,
    /// `NegotiationConfirm` did not match. A **security event, not a network
    /// error** (ADR-0014 D2), and terminal.
    #[error("the negotiation transcript did not match")]
    TranscriptMismatch,
    /// The adapter refused in a way the backoff regime cannot retry.
    #[error("the platform refused: {0}")]
    Device(#[from] PlatformError),
}

impl Fault {
    /// The registered `reason_code`.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            // A pump asked to carry traffic on a tunnel that does not carry
            // traffic is a transition requested from a state that does not
            // permit it, which is exactly what this code names.
            Fault::NotEstablished | Fault::NoAuthoritativeEndpoint => {
                codes::INTERNAL_UNEXPECTED_STATE
            }
            Fault::KeyStateUnusable => codes::INTERNAL_INVARIANT_VIOLATED,
            Fault::TranscriptMismatch => codes::PROTO_TRANSCRIPT_MISMATCH,
            // The adapter already owns its mapping; re-deriving one here is how
            // two components come to report the same OS condition differently.
            Fault::Device(error) => error.reason_code(),
        }
    }

    /// The registered diagnostic, carrying the adapter's own evidence where the
    /// fault came from the adapter.
    #[must_use]
    pub fn diagnostic(&self) -> Diagnostic {
        match self {
            Fault::Device(error) => error.diagnostic(COMPONENT),
            other => Diagnostic::builder(other.reason_code(), COMPONENT).build(),
        }
    }
}

/// Why a pump loop returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stop {
    /// The cancellation token was tripped. The clean, expected exit.
    Cancelled,
    /// The adapter has begun graceful shutdown and will accept no new work.
    ShuttingDown,
    /// The send counter is exhausted for this key generation.
    ///
    /// **Not a fault.** The tunnel is intact and its keys are sound; ADR-0001
    /// §7.2 forbids the counter to wrap because it is the AEAD nonce, so the
    /// only way forward is a rekey. It carries **no reason code** on purpose:
    /// `CRYPTO.REKEY_FAILED` is "in-place rekey did not complete", and claiming
    /// a failure that has not happened would send a caller looking for a
    /// problem instead of calling `Tunnel::begin_rekey`.
    RekeyRequired,
    /// Something about our own state stopped it.
    Fault(Fault),
}

impl Stop {
    /// The registered `reason_code`, where one exists.
    ///
    /// `None` for the two ordinary exits and for [`Stop::RekeyRequired`], which
    /// are outcomes rather than errors.
    #[must_use]
    pub const fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Stop::Cancelled | Stop::ShuttingDown | Stop::RekeyRequired => None,
            Stop::Fault(fault) => Some(fault.reason_code()),
        }
    }

    /// Whether the pump stopped because it was asked to.
    #[must_use]
    pub const fn is_graceful(&self) -> bool {
        matches!(self, Stop::Cancelled | Stop::ShuttingDown)
    }
}

/// What one pump step did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// One packet crossed, carrying this many **plaintext** bytes.
    ///
    /// A length, never a payload: §6 rule 11 and the observability gate forbid
    /// telemetry to capture tunnel payloads, and a byte count is the most this
    /// module will ever say about one.
    Moved(usize),
    /// Nothing was available. The caller waits before asking again.
    Idle,
    /// The adapter refused in a way the backoff regime can retry.
    ///
    /// Distinct from [`Step::Idle`] so that "the tunnel was quiet" and "the
    /// adapter is refusing" are different facts in the counters. Rounding them
    /// together is how a failing adapter comes to look like an idle link.
    Deferred,
    /// One datagram was recognised as **not** L-DATA traffic and handed to the
    /// component that owns it, rather than carried or discarded.
    ///
    /// Today that is exactly one thing: an ADR-0001 §7.3.2 `ResumeSession`,
    /// moved into the pump's resume inbox for
    /// [`crate::execute::carriage::step`] to hand to
    /// `SessionRuntime::resume_on_wire`.
    ///
    /// # Why this is neither `Moved` nor `Rejected`
    ///
    /// `Moved` carries a plaintext byte count and increments the *packet*
    /// counter, and no packet crossed. `Rejected` means discarded, and this
    /// datagram was not discarded — reporting it as one would put a genuine
    /// resume into the same counter as a forgery, and that counter is a
    /// security signal. The pump continues either way; what differs is what an
    /// operator reads afterwards.
    ///
    /// **A `Diverted` datagram is still unauthenticated.** Nothing has verified
    /// it at this point; the diversion is a demux, and the MAC check happens in
    /// `crate::resume`.
    Diverted,
    /// One datagram was discarded. The pump continues.
    Rejected(Reject),
    /// The loop should end.
    Stopped(Stop),
}

/// Everything one pump direction counted.
///
/// **Counters and lengths only.** Nothing here can hold a payload byte, an
/// address or a key, which is what makes it safe to attach to a diagnostic
/// bundle without a redaction pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    /// Packets carried end to end.
    pub packets: u64,
    /// Plaintext bytes carried.
    pub bytes: u64,
    /// Times the direction had nothing to do and waited.
    pub idle_waits: u64,
    /// Datagrams that were not L-DATA transport frames.
    pub rejected_malformed: u64,
    /// Frames addressed to another receiver index.
    pub rejected_foreign_receiver: u64,
    /// Datagrams refused by the MTU-derived cap, truncation included.
    pub rejected_oversize: u64,
    /// Datagrams the AEAD refused. The observable behind [`Reject::Unauthenticated`].
    pub rejected_unauthenticated: u64,
    /// Frames the anti-replay window refused. A security counter.
    pub rejected_replay: u64,
    /// Retryable adapter refusals absorbed under the backoff regime.
    pub adapter_transient: u64,
    /// Datagrams handed to another component — see [`Step::Diverted`].
    ///
    /// Deliberately outside [`Counters::rejected_total`]: a diverted datagram
    /// was not discarded, and folding it into the reject total would make a
    /// roaming peer look like an attacker.
    pub diverted: u64,
}

impl Counters {
    /// Records one reject.
    pub fn record(&mut self, reject: Reject) {
        let slot = match reject {
            Reject::Malformed => &mut self.rejected_malformed,
            Reject::ForeignReceiver => &mut self.rejected_foreign_receiver,
            Reject::Oversize | Reject::Truncated => &mut self.rejected_oversize,
            Reject::Unauthenticated => &mut self.rejected_unauthenticated,
            Reject::Replay => &mut self.rejected_replay,
        };
        *slot = slot.saturating_add(1);
    }

    /// Records one datagram handed to another component.
    pub fn record_diverted(&mut self) {
        self.diverted = self.diverted.saturating_add(1);
    }

    /// Records one carried packet.
    pub fn record_moved(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes as u64);
    }

    /// Every datagram this direction discarded.
    #[must_use]
    pub const fn rejected_total(&self) -> u64 {
        self.rejected_malformed
            .saturating_add(self.rejected_foreign_receiver)
            .saturating_add(self.rejected_oversize)
            .saturating_add(self.rejected_unauthenticated)
            .saturating_add(self.rejected_replay)
    }
}

/// What one pump direction did before it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Why it stopped.
    pub stop: Stop,
    /// What it counted.
    pub counters: Counters,
}

#[cfg(test)]
mod tests {
    use super::{Counters, Fault, Refused, Reject, Stop};
    use twinvpn_types::{codes, ErrorClass, ErrorSeverity};

    /// Every reject variant, so a new one cannot escape the properties below.
    const EVERY_REJECT: [Reject; 6] = [
        Reject::Malformed,
        Reject::ForeignReceiver,
        Reject::Oversize,
        Reject::Truncated,
        Reject::Unauthenticated,
        Reject::Replay,
    ];

    #[test]
    fn no_reject_tears_down_a_tunnel() {
        // The single property that decides whether one injected datagram is a
        // dropped packet or a remote teardown.
        for reject in EVERY_REJECT {
            assert!(!reject.tears_down(), "{reject:?}");
        }
    }

    #[test]
    fn replay_is_the_registrys_fatal_critical_and_still_not_terminal() {
        let code = Reject::Replay.reason_code().expect("replay has a code");
        assert_eq!(code, codes::CRYPTO_REPLAY_DETECTED);
        assert_eq!(code.class(), ErrorClass::Fatal);
        assert_eq!(code.severity(), ErrorSeverity::Critical);
        // The registry's own answer to "does a replay end the session".
        assert!(!code.terminal());
        assert!(Reject::Replay.is_security_event());
    }

    #[test]
    fn an_authentication_failure_is_the_one_silent_reject() {
        assert_eq!(Reject::Unauthenticated.reason_code(), None);
        assert!(!Reject::Unauthenticated.is_security_event());
        for reject in EVERY_REJECT {
            if reject != Reject::Unauthenticated {
                assert!(reject.reason_code().is_some(), "{reject:?}");
            }
        }
    }

    #[test]
    fn a_size_violation_is_a_proto_reject() {
        // §6 rule 9: a cap violation is a typed reject with a PROTO.* code.
        for reject in [Reject::Oversize, Reject::Truncated] {
            assert_eq!(reject.reason_code(), Some(codes::PROTO_SIZE_EXCEEDED));
        }
    }

    #[test]
    fn refusing_a_kernel_offload_adapter_carries_the_adapters_own_code() {
        // The refusal and the `read_packet` the pump avoided are the same story.
        assert_eq!(
            Refused::KernelOffload.reason_code(),
            codes::PLATFORM_OS_UNSUPPORTED
        );
        assert_eq!(
            Refused::MtuBelowFloor { mtu: 1279 }.reason_code(),
            codes::NET_MTU_TOO_SMALL
        );
    }

    #[test]
    fn the_ordinary_exits_carry_no_error_code() {
        assert!(Stop::Cancelled.is_graceful());
        assert!(Stop::ShuttingDown.is_graceful());
        assert_eq!(Stop::Cancelled.reason_code(), None);
        // A rekey is owed, not a failure to report.
        assert!(!Stop::RekeyRequired.is_graceful());
        assert_eq!(Stop::RekeyRequired.reason_code(), None);
        assert_eq!(
            Stop::Fault(Fault::TranscriptMismatch).reason_code(),
            Some(codes::PROTO_TRANSCRIPT_MISMATCH)
        );
    }

    #[test]
    fn counters_bucket_every_reject() {
        let mut counters = Counters::default();
        for reject in EVERY_REJECT {
            counters.record(reject);
        }
        assert_eq!(counters.rejected_total(), EVERY_REJECT.len() as u64);
        assert_eq!(counters.rejected_replay, 1);
        assert_eq!(counters.rejected_oversize, 2);
    }
}
