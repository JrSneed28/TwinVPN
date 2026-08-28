//! The L-CONTROL transport seam: the four-rung ladder, and the 0-RTT prohibition
//! made structural.
//!
//! **Authority:** ADR-0001 §11 item 3 (L-CONTROL is QUIC + TLS 1.3 with mutual
//! RFC 7250 raw-public-key authentication to `DeviceIdentityKey`, server auth
//! against a pinned key set, **0-RTT prohibited**), ADR-0002 §11.2 (the ladder),
//! §11.7 (reconnect discipline), §11.10 (the mobile rule), `docs/protocol.md`
//! §4.1 (Happy Eyeballs v2 with a 250 ms IPv6 bias), ADR-0010 R1.
//!
//! # Why this is still a trait now that rung 1 is implemented
//!
//! [`crate::quic::QuicControlTransport`] is the production rung-1 binding, and it
//! lives beside this module rather than in it. What stays here is the *policy* —
//! which rung, in what order, with which budget, emitting which code — which is
//! fully testable with no socket, and what stays a trait is the *binding*,
//! supplied at construction exactly as [`twinvpn_env::Env`] supplies the clock.
//!
//! That split is not merely tidiness. Rungs 2, 3 and 4 are HTTP over TCP and are
//! **not implemented anywhere yet**; a device that cannot reach UDP:443 still has
//! no control channel, and the ladder above says so honestly instead of the type
//! system implying otherwise. And the trait is what lets `src/testing.rs` drive
//! an eight-hour outage on a virtual clock, which no real transport can do.
//!
//! `ownership.md` §8 **W-12** is what made the rung-1 implementation legal in
//! this crate: `quinn` is a transport-protocol implementation that takes its
//! cryptography from rustls and implements none itself, so CD-I2 does not reach
//! it. See [`crate::quic`] for the full argument and for what a composition root
//! must supply.
//!
//! # 0-RTT
//!
//! ADR-0001 R8 prohibits TLS 1.3 early data, and ADR-0002 §S-5 explains what that
//! buys: it "removes the replayable-early-data vector entirely", which matters
//! because a replayed early-data C1 request is a replayed *ceremony*.
//!
//! The prohibition is expressed as [`EarlyData`], an enum with exactly one
//! variant and no `Permitted`. [`TransportConfig`] carries one, exposes it
//! through [`TransportConfig::early_data`], and has **no setter**. A binding that
//! wanted early data would have to invent a value of a type whose only inhabitant
//! is `Prohibited` — so "enable 0-RTT" is not a configuration a caller can
//! express, which is the difference between a prohibition and a default.

use core::time::Duration;

use futures_core::future::BoxFuture;
use twinvpn_schema::Reject;
use twinvpn_types::{codes, ReasonCode};

use crate::error::CpError;
use crate::octets::ReceivedOctets;

/// TLS 1.3 early-data posture on L-CONTROL.
///
/// One variant. There is no `Permitted`, no `From<bool>`, and no `Default` that
/// could be overridden — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EarlyData {
    /// ADR-0001 R8. The **only** value that exists.
    Prohibited,
}

/// One rung of the ADR-0002 §11.2 ladder.
///
/// Rungs are tried in order. Within rung 1 the two address families are raced per
/// Happy Eyeballs v2 with a 250 ms IPv6 bias — IPv4 and IPv6 are co-equal
/// (ADR-0010 R1) and the ladder is per-connection, never per-family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rung {
    /// QUIC + HTTP/3 on UDP:443, mTLS 1.3 raw public key. Budget 3 s.
    Quic,
    /// HTTP/2 over TLS 1.3 on TCP:443. Budget 5 s. Loses connection migration
    /// and cross-stream head-of-line independence.
    Http2Tcp,
    /// HTTP/1.1 long-poll over TLS 1.3 on TCP:443, 25 s server hold. Budget 5 s.
    /// Loses multiplexing and sub-second event latency.
    Http1LongPoll,
    /// Rung 2 or 3 through the OS-configured HTTP CONNECT proxy. Budget 10 s.
    Proxy,
}

impl Rung {
    /// The ladder, in the order ADR-0002 §11.2 fixes.
    pub const LADDER: [Rung; 4] = [Rung::Quic, Rung::Http2Tcp, Rung::Http1LongPoll, Rung::Proxy];

    /// The rung's 1-based number, as the `rung` evidence field carries it.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Rung::Quic => 1,
            Rung::Http2Tcp => 2,
            Rung::Http1LongPoll => 3,
            Rung::Proxy => 4,
        }
    }

    /// The per-rung attempt budget. Summing the ladder gives ADR-0002 §9's
    /// "≤ 23 s to `CONTROL.UNREACHABLE`" — 3 + 5 + 5 + 10.
    #[must_use]
    pub const fn budget(self) -> Duration {
        match self {
            Rung::Quic => Duration::from_secs(3),
            Rung::Http2Tcp | Rung::Http1LongPoll => Duration::from_secs(5),
            Rung::Proxy => Duration::from_secs(10),
        }
    }

    /// The code emitted on **entering** this rung, per ADR-0002 §11.2. Rung 1 is
    /// the undegraded case and emits nothing.
    #[must_use]
    pub const fn entry_code(self) -> Option<ReasonCode> {
        match self {
            Rung::Quic => None,
            Rung::Http2Tcp => Some(codes::CONTROL_TRANSPORT_DEGRADED_TCP),
            Rung::Http1LongPoll => Some(codes::CONTROL_TRANSPORT_DEGRADED_POLL),
            Rung::Proxy => Some(codes::CONTROL_TRANSPORT_VIA_PROXY),
        }
    }

    /// [`Rung::entry_code`] with rung 1 folded onto `CONTROL.UNREACHABLE`, for
    /// the one call site — [`CpError::reason_code`] — that needs a total
    /// function. Rung 1 never constructs a `TransportDegraded`.
    #[must_use]
    pub(crate) const fn entry_code_or_unreachable(self) -> ReasonCode {
        match self.entry_code() {
            Some(code) => code,
            None => codes::CONTROL_UNREACHABLE,
        }
    }

    /// Whether QUIC connection migration survives a roam on this rung.
    ///
    /// Only rung 1. ADR-0002 §13 item 3: on rungs 2–4 "the control channel drops
    /// on every roam and pays a full mTLS handshake to reattach", and that is
    /// bounded by I5 — the data plane does not notice.
    #[must_use]
    pub const fn survives_roam(self) -> bool {
        matches!(self, Rung::Quic)
    }

    /// Whether this rung may hold the control channel in **background** on a
    /// mobile device.
    ///
    /// ADR-0002 §11.2 prohibits rung 3 there: it is the only rung that costs a
    /// radio wake per interval, which collides with RQ-12 and
    /// `reliability.md` §6.6's coalesced-wake budget. A device that can only
    /// reach rung 3 drops the control channel in background and relies on C3
    /// wake — which is safe precisely because of I5.
    #[must_use]
    pub const fn permitted_as_mobile_background(self) -> bool {
        !matches!(self, Rung::Http1LongPoll)
    }

    /// The C2 backlog watermark for this rung, in bytes and in events.
    ///
    /// ADR-0002 §11.6: 256 KiB / 512 events, **halved on rung 2** because TCP
    /// head-of-line blocking makes a backlog costlier. Rungs 3 and 4 are also
    /// TCP, so they inherit the halved figure.
    #[must_use]
    pub const fn backlog_watermark(self) -> (usize, usize) {
        match self {
            Rung::Quic => (
                twinvpn_schema::limits::C2_BACKLOG_WATERMARK_BYTES,
                twinvpn_schema::limits::C2_BACKLOG_WATERMARK_EVENTS,
            ),
            Rung::Http2Tcp | Rung::Http1LongPoll | Rung::Proxy => (
                twinvpn_schema::limits::C2_BACKLOG_WATERMARK_BYTES / 2,
                twinvpn_schema::limits::C2_BACKLOG_WATERMARK_EVENTS / 2,
            ),
        }
    }

    /// The next rung down, or `None` when the ladder is exhausted.
    #[must_use]
    pub const fn next(self) -> Option<Rung> {
        match self {
            Rung::Quic => Some(Rung::Http2Tcp),
            Rung::Http2Tcp => Some(Rung::Http1LongPoll),
            Rung::Http1LongPoll => Some(Rung::Proxy),
            Rung::Proxy => None,
        }
    }
}

/// Which address families the host has, and the NAT64 prefix if one is present.
///
/// ADR-0010 R1: there is no "v4 story and a v6 story". The ladder races both
/// families on rung 1 and a v6-only host with a NAT64 prefix reaches a v4-only
/// front-end through it. Family is carried here as *data*, never as a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachFamilies {
    /// Whether the host has usable IPv4.
    pub v4: bool,
    /// Whether the host has usable IPv6.
    pub v6: bool,
    /// Whether a NAT64 prefix was discovered (RFC 7050 / PREF64).
    pub nat64: bool,
}

impl AttachFamilies {
    /// The Happy Eyeballs v2 bias `docs/protocol.md` §4.1 fixes: IPv6 is tried
    /// first and IPv4 follows 250 ms later, rather than the two racing evenly.
    pub const V6_BIAS: Duration = Duration::from_millis(250);

    /// Whether any attach is possible at all.
    ///
    /// A v6-only host with a NAT64 prefix can still reach a v4-only front-end,
    /// which is why `nat64` counts.
    #[must_use]
    pub const fn can_attach(self) -> bool {
        self.v4 || self.v6 || self.nat64
    }
}

/// Everything the binding needs to attach, and nothing it could use to weaken
/// the connection.
///
/// There is no field for a cipher list, no field for a TLS version, no field for
/// certificate validation and **no field for early data** — those are ADR-0001's
/// and are not configuration. What is here is placement (which names to resolve,
/// which families exist) and the two facts the ladder needs.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// The coordination endpoints, as **names**, resolved in the bootstrap DNS
    /// scope (ADR-0011 DN-0). Names rather than literals so GeoDNS works.
    pub coordination_endpoints: Vec<String>,
    /// Which families the host has.
    pub families: AttachFamilies,
    /// Which rung to attempt.
    pub rung: Rung,
    /// Whether the process is in mobile background. Rung 3 is refused here.
    pub mobile_background: bool,
    early_data: EarlyData,
}

impl TransportConfig {
    /// Builds a config. Early data is `Prohibited` and cannot be set otherwise.
    #[must_use]
    pub fn new(
        coordination_endpoints: Vec<String>,
        families: AttachFamilies,
        rung: Rung,
        mobile_background: bool,
    ) -> Self {
        Self {
            coordination_endpoints,
            families,
            rung,
            mobile_background,
            early_data: EarlyData::Prohibited,
        }
    }

    /// The early-data posture. Always [`EarlyData::Prohibited`] — there is no
    /// other value of the type, and no setter.
    #[must_use]
    pub const fn early_data(&self) -> EarlyData {
        self.early_data
    }

    /// Whether this rung may be used under these conditions.
    ///
    /// # Errors
    ///
    /// [`CpError::Unreachable`] when no family is usable, or when the config asks
    /// for rung 3 in mobile background (ADR-0002 §11.2).
    pub fn admissible(&self) -> Result<(), CpError> {
        if !self.families.can_attach() {
            return Err(CpError::Unreachable);
        }
        if self.mobile_background && !self.rung.permitted_as_mobile_background() {
            return Err(CpError::Unreachable);
        }
        Ok(())
    }
}

/// Why a transport attempt ended.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The rung did not come up inside its budget, or the network refused it.
    /// The ladder falls through.
    #[error("rung {0:?} did not attach")]
    RungFailed(Rung),
    /// mTLS was refused: unknown or revoked device key, or a pin mismatch.
    #[error("the handshake was rejected")]
    HandshakeRejected,
    /// The accept limiter engaged; honour `retry_after_ms`, never a bare retry.
    #[error("admission deferred")]
    AdmissionDeferred {
        /// How long to wait.
        retry_after_ms: u64,
    },
    /// An older connection for this identity was closed (ADR-0002 N-1).
    #[error("superseded")]
    Superseded,
    /// The connection went away mid-stream. The cursor resumes it.
    #[error("the connection closed")]
    Closed,
    /// A graceful drain: HTTP/3 `GOAWAY` carrying a deadline. Each client picks
    /// its reattach instant uniformly from `[0, deadline)`.
    #[error("draining within {drain_deadline_ms} ms")]
    Draining {
        /// The drain deadline the server advertised. Default 120 s.
        drain_deadline_ms: u64,
    },
    /// The peer declared a length or a shape the frozen registry forbids.
    ///
    /// A transport reads a `u32` length off the wire before it can size a
    /// buffer, and that length is untrusted input like any other:
    /// `ownership.md` §6 rules 9 and 10 require the cap to be applied **before**
    /// the allocation, and rule 12 requires the refusal to name a registered
    /// `PROTO.*` code rather than being flattened into "the connection closed".
    /// Carrying the [`Reject`] verbatim is what keeps the violated registry key
    /// nameable this far down the stack.
    #[error(transparent)]
    Rejected(Reject),
}

impl From<TransportError> for CpError {
    fn from(value: TransportError) -> Self {
        match value {
            // A drain lands here too: it is the control plane going away in an
            // orderly fashion, which is still "the control plane is not
            // available to me right now" and still nothing else (I5). The
            // *scheduling* difference — reattach uniformly inside the window
            // rather than under backoff — is `Drain`'s, not this mapping's.
            TransportError::RungFailed(_)
            | TransportError::Closed
            | TransportError::Draining { .. } => CpError::Unreachable,
            TransportError::HandshakeRejected => CpError::HandshakeRejected,
            TransportError::AdmissionDeferred { retry_after_ms } => {
                CpError::AdmissionDeferred { retry_after_ms }
            }
            TransportError::Superseded => CpError::SupersededByNewAttach,
            // The registry key survives the conversion rather than being
            // collapsed into `Unreachable`: a peer that declared 4 GiB and a
            // peer that went away are different facts, and only one of them is
            // a `PROTO.SIZE_EXCEEDED` worth alerting on.
            TransportError::Rejected(reject) => CpError::Rejected(reject),
        }
    }
}

/// The L-CONTROL binding, supplied at construction.
///
/// An implementation MUST be QUIC + TLS 1.3 with mutual RFC 7250 raw-public-key
/// authentication on rung 1, MUST pin the server key set, and MUST NOT enable
/// TLS 1.3 early data — which [`TransportConfig`] makes unexpressible.
pub trait ControlTransport: Send + Sync {
    /// Attaches one control connection carrying both C1 and C2 (ADR-0002 N-1).
    fn attach<'a>(
        &'a self,
        config: &'a TransportConfig,
    ) -> BoxFuture<'a, Result<Box<dyn ControlConnection>, TransportError>>;
}

/// One live control connection.
///
/// **One connection per `Device`, carrying both C1 and C2** (ADR-0002 N-1). C2
/// gets its own stream so an event backlog cannot consume the RPC window
/// (§11.6).
pub trait ControlConnection: Send + Sync {
    /// The RFC 9266 `tls-exporter` value of *this* connection: 32 bytes, label
    /// `EXPORTER-Channel-Binding`, empty context.
    ///
    /// This is what makes protocol.md §3 Rule A safe, and what a receiver checks
    /// `Auth.channel_binding` against.
    fn channel_binding(&self) -> twinvpn_types::ChannelBinding;

    /// Which rung this connection came up on.
    fn rung(&self) -> Rung;

    /// The control-plane API epoch this connection agreed at setup.
    ///
    /// ADR-0014 §11.1 V-3: fixed for the life of the connection. A version change
    /// is a coordinated reconnect, never an in-place upgrade.
    fn proto_version(&self) -> u32;

    /// One C1 request/response round trip on a bidirectional stream.
    ///
    /// The response arrives as [`ReceivedOctets`] rather than a decoded message,
    /// so verification and forwarding happen over the bytes that arrived.
    fn request<'a>(
        &'a self,
        body: &'a [u8],
    ) -> BoxFuture<'a, Result<ReceivedOctets, TransportError>>;

    /// Opens or resumes the C2 stream from `from_net_seq`.
    fn subscribe(
        &self,
        from_net_seq: u64,
    ) -> BoxFuture<'_, Result<Box<dyn EventStream>, TransportError>>;

    /// Closes gracefully.
    fn close(&self) -> BoxFuture<'_, ()>;
}

/// The C2 event stream.
pub trait EventStream: Send {
    /// The next event's octets, or `None` at end of stream.
    fn next(&mut self) -> BoxFuture<'_, Option<Result<ReceivedOctets, TransportError>>>;
}

#[cfg(test)]
mod tests {
    use super::{AttachFamilies, EarlyData, Rung, TransportConfig};
    use core::time::Duration;

    fn dual() -> AttachFamilies {
        AttachFamilies {
            v4: true,
            v6: true,
            nat64: false,
        }
    }

    #[test]
    fn the_ladder_sums_to_the_adr_0002_budget() {
        let total: Duration = Rung::LADDER.iter().map(|r| r.budget()).sum();
        assert_eq!(total, Duration::from_secs(23));
    }

    #[test]
    fn only_rung_one_is_undegraded_and_only_rung_one_survives_a_roam() {
        assert!(Rung::Quic.entry_code().is_none());
        assert!(Rung::Quic.survives_roam());
        for rung in [Rung::Http2Tcp, Rung::Http1LongPoll, Rung::Proxy] {
            assert!(rung.entry_code().is_some(), "{rung:?} must name its cost");
            assert!(!rung.survives_roam());
        }
    }

    #[test]
    fn rung_three_is_refused_as_a_mobile_background_binding() {
        assert!(!Rung::Http1LongPoll.permitted_as_mobile_background());
        let cfg =
            TransportConfig::new(vec!["cp.example".into()], dual(), Rung::Http1LongPoll, true);
        assert!(cfg.admissible().is_err());
        let foreground = TransportConfig::new(
            vec!["cp.example".into()],
            dual(),
            Rung::Http1LongPoll,
            false,
        );
        assert!(foreground.admissible().is_ok());
    }

    #[test]
    fn the_tcp_rungs_halve_the_backlog_watermark() {
        let (quic_bytes, quic_events) = Rung::Quic.backlog_watermark();
        for rung in [Rung::Http2Tcp, Rung::Http1LongPoll, Rung::Proxy] {
            let (bytes, events) = rung.backlog_watermark();
            assert_eq!(bytes * 2, quic_bytes);
            assert_eq!(events * 2, quic_events);
        }
    }

    #[test]
    fn early_data_is_prohibited_and_the_config_carries_no_other_value() {
        let cfg = TransportConfig::new(vec!["cp.example".into()], dual(), Rung::Quic, false);
        assert_eq!(cfg.early_data(), EarlyData::Prohibited);
    }

    #[test]
    fn a_v6_only_host_with_nat64_can_still_attach() {
        let v6_only_nat64 = AttachFamilies {
            v4: false,
            v6: true,
            nat64: true,
        };
        assert!(v6_only_nat64.can_attach());
        let nothing = AttachFamilies {
            v4: false,
            v6: false,
            nat64: false,
        };
        assert!(!nothing.can_attach());
        let cfg = TransportConfig::new(vec!["cp.example".into()], nothing, Rung::Quic, false);
        assert!(cfg.admissible().is_err());
    }

    #[test]
    fn the_ladder_walks_down_and_then_ends() {
        let mut rung = Some(Rung::Quic);
        let mut seen = Vec::new();
        while let Some(r) = rung {
            seen.push(r);
            rung = r.next();
        }
        assert_eq!(seen, Rung::LADDER.to_vec());
    }
}
