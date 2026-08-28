//! What a relay said, as typed outcomes — never as one error.
//!
//! **Authority:** ADR-0005 §11.5 (*"overload is never silent (I6, RQ9)"*, and
//! the `RELAY_STATUS{reason_code, retry_after_ms, suggested_alternatives[]}`
//! that carries it), §11.7 (the conditions); ADR-0006 §11.7 rule 3 (the device
//! MUST honour `retry_after_ms`, MUST try a suggested alternative first, and
//! MUST ignore any suggestion absent from the verified map); ADR-0015 §11.2
//! (the `DOMAIN.CONDITION` taxonomy and rule 5's degrade-on-domain);
//! `ownership.md` §4.2 and §6 rule 12.
//!
//! # Four refusals, four outcomes, four registered codes
//!
//! `services/relay/src/resource.rs` is the table the relay enforces:
//!
//! | Limit | Refusal | Registered code |
//! |---|---|---|
//! | concurrent half-flows per `relay_sub` | `FlowLimitReached` | `RELAY.FLOW_LIMIT_REACHED` |
//! | `BIND`/min per `relay_sub` | `BindRateLimited` | `RELAY.BIND_RATE_LIMITED` |
//! | bitrate per subject or per half-flow | `RateLimited` | `RELAY.RATE_LIMITED` |
//! | bytes/hour per `relay_sub` | `QuotaExceeded` | `RELAY.QUOTA_EXCEEDED` |
//!
//! They are four **different** facts with four different remediations — a flow
//! ceiling wants a different relay, a bind-rate limit wants the minute it is
//! measured over, an hourly quota wants an hour — so collapsing them into one
//! error would leave a listening device retrying against a relay that will
//! never admit it. All four codes are in
//! `contracts/registry/reason_codes.json`, so each outcome names its own.
//!
//! # The relay this tree ships degrades all four onto one code, and that is
//! recorded rather than guessed around
//!
//! `services/relay/src/condition.rs` maps `FlowLimitReached`,
//! `BindRateLimited`, `RateLimited` and `QuotaExceeded` all onto
//! `RELAY.CAPACITY_REJECTED`, under a module note that begins *"the registry
//! contains **twelve** `RELAY.*` codes"*. The frozen registry now carries the
//! four exact codes above, so that premise no longer holds — but the relay's
//! behaviour is what it is, and this module must read the wire it actually
//! meets.
//!
//! So the mapping is exact where the relay is exact and **honest where it is
//! not**: an exact spelling produces its own variant, and the degraded code
//! produces [`Refusal::CapacityUnspecified`], which says plainly that the relay
//! refused for capacity and did not say which capacity. It is not
//! back-inferred from `retry_after_ms`. The relay's own `retry_after_for` maps
//! four distinct conditions onto 5 000 ms, so such an inference would be right
//! sometimes and undetectably wrong the rest of the time — and a wrong
//! diagnosis is worse than an admitted coarse one. Recorded as an integration
//! item for `relay-plane`.

use core::time::Duration;

use twinvpn_types::{codes as reg, ObservedReasonCode, ReasonCode, RelayId};

/// Why this module refused something it was given or was sent.
///
/// Every variant carries a **registered** code (`ownership.md` §6 rule 12), and
/// every one is a refusal rather than a truncation or a silent accept: a
/// datagram that violates a bound is dropped whole, because half of an
/// authenticated frame is not a smaller authentic frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelayReject {
    /// A payload exceeded ADR-0005 §9.2's derived relay-leg ceiling.
    #[error("payload {observed} B exceeds the {limit} B relay-leg ceiling")]
    PayloadTooLarge {
        /// What arrived, or what a caller offered.
        observed: usize,
        /// The ceiling.
        limit: usize,
    },
    /// A body was shorter than its own fixed-width prefix, or a fixed field
    /// held a reserved value.
    #[error("relay control body malformed")]
    Malformed,
    /// A body **declared** a count or a length past its ceiling.
    ///
    /// Refused before the count is used to size anything, which is the whole
    /// point of separating it from [`RelayReject::Malformed`]: this is the
    /// variant an attacker reaches for, and it must be answerable without
    /// having allocated.
    #[error("relay control body declared {declared} items, ceiling is {ceiling}")]
    DeclaredCountTooLarge {
        /// The count the body claimed.
        declared: usize,
        /// The ceiling from ADR-0005 §11.5 / `services/relay/src/control.rs`.
        ceiling: usize,
    },
    /// The `ver` nibble named a version this build does not speak.
    #[error("relay frame version unsupported")]
    VersionUnsupported,
    /// The frame's MAC did not verify under `K_leg`, or its counter replayed.
    #[error("relay frame authentication failed")]
    AuthenticationFailed,
    /// A frame arrived from the side of the protocol that may not send it.
    ///
    /// W-32's condition, and the serious one: the frame authenticated under
    /// `K_leg`, so a genuinely keyed relay sent a device a frame only a device
    /// sends. That is the confused-deputy shape, not a forgery.
    #[error("relay sent a frame only a device may send")]
    WrongDirection,
    /// The leg handshake did not complete.
    ///
    /// One variant for every cause, matching
    /// `twinvpn_crypto::relay_leg`'s single `HandshakeRejected`: a prober must
    /// not learn *which* check refused it.
    #[error("relay leg handshake refused")]
    HandshakeRefused,
    /// A `DRAIN` or `RELAY_STATUS` named a relay this device has not verified.
    ///
    /// ADR-0006 §11.7 rule 3: a device *"MUST ignore any suggestion absent from
    /// the verified map"*, and `relay.proto` is explicit that a relay *"can ASK
    /// a device to leave but can NEVER REDIRECT A SESSION BY ITSELF"*.
    #[error("relay suggested a relay absent from the verified map")]
    SuggestionUnverified,
}

impl RelayReject {
    /// The registered `reason_code` this refusal surfaces as.
    ///
    /// `PROTO.*` for a malformed or oversized message, `RELAY.*` for a
    /// condition about the relay itself, and `CRYPTO.REPLAY_DETECTED` for a
    /// failed MAC — the same three families
    /// `twinvpn_relay_client::frame::FrameError::reason_code` already chose, so
    /// one condition cannot surface as two different codes depending on which
    /// layer noticed it.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            RelayReject::PayloadTooLarge { .. } | RelayReject::DeclaredCountTooLarge { .. } => {
                reg::PROTO_SIZE_EXCEEDED
            }
            RelayReject::Malformed => reg::PROTO_MALFORMED_MESSAGE,
            RelayReject::VersionUnsupported => reg::RELAY_VERSION_UNSUPPORTED,
            RelayReject::AuthenticationFailed => reg::CRYPTO_REPLAY_DETECTED,
            // `RELAY.FRAME_WRONG_DIRECTION` is the spelling W-32 wants and the
            // registry does not carry; `twinvpn_relay_client::codes::UNREGISTERED`
            // records the substitution, and this repeats its choice rather than
            // making a second one.
            RelayReject::WrongDirection => reg::RELAY_MAP_UNVERIFIED,
            RelayReject::HandshakeRefused => reg::RELAY_TOKEN_INVALID,
            RelayReject::SuggestionUnverified => reg::RELAY_SELECT_SUGGESTION_UNKNOWN,
        }
    }
}

/// A relay's refusal, one variant per condition it can actually refuse with.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// `max_concurrent_flows` for this `relay_sub` is reached.
    ///
    /// A ceiling on this relay, not a fault: the device's answer is the next
    /// relay in the ordering, not a retry here.
    FlowLimitReached {
        /// The relay's own `retry_after_ms`, which ADR-0006 §11.7 rule 3 makes
        /// binding.
        retry_after: Duration,
    },
    /// `max_binds_per_min` for this `relay_sub` is reached.
    ///
    /// The one a *listening* device meets: ADR-0006 §11.5 re-`BIND`s the top
    /// `k_rdv` = 2 relays per `TrustedPeer` every ≤ 30 s, which is what makes
    /// the 30 binds/min limit reachable at all.
    BindRateLimited {
        /// The relay's `retry_after_ms`.
        retry_after: Duration,
    },
    /// A token bucket throttled — per-subject or per-half-flow bitrate.
    RateLimited {
        /// The relay's `retry_after_ms`.
        retry_after: Duration,
    },
    /// `max_bytes_per_hour` for this `relay_sub` is spent.
    QuotaExceeded {
        /// The relay's `retry_after_ms`.
        retry_after: Duration,
    },
    /// The relay refused for capacity and **did not say which capacity**.
    ///
    /// What the relay in this tree actually emits for all four conditions
    /// above; see this module's note. Distinct from every one of them on
    /// purpose — "we were refused, coarsely" is a different fact from any of
    /// the four, and rendering it as one of them would be a guess.
    CapacityUnspecified {
        /// The relay's `retry_after_ms`.
        retry_after: Duration,
    },
    /// The relay is draining (ADR-0005 §8).
    ///
    /// Not a capacity refusal: the device is meant to **leave**, not to retry,
    /// which is why `retry_after_for(Draining)` is zero on the relay side.
    Draining {
        /// The announced deadline, from the `RELAY_STATUS` or `DRAIN` body.
        deadline: Duration,
    },
    /// A registered or syntactically valid code this build does not map.
    ///
    /// ADR-0015 §11.2 rule 5: a receiver meeting an unknown code *"must hold
    /// its text and degrade on the `DOMAIN`, never swallow it"*. The text is
    /// held in `observed` and nothing is invented.
    Other {
        /// The code exactly as it arrived.
        observed: ObservedReasonCode,
        /// The relay's `retry_after_ms`.
        retry_after: Duration,
    },
}

impl Refusal {
    /// The registered `reason_code` for this refusal.
    ///
    /// Each of the four resource refusals names **its own** registered code —
    /// which is the whole reason they are four variants — and
    /// [`Refusal::Other`] returns whatever the registry knows about the code
    /// that arrived, or `None` for one shipped after this build.
    #[must_use]
    pub fn reason_code(&self) -> Option<ReasonCode> {
        match self {
            Refusal::FlowLimitReached { .. } => Some(reg::RELAY_FLOW_LIMIT_REACHED),
            Refusal::BindRateLimited { .. } => Some(reg::RELAY_BIND_RATE_LIMITED),
            Refusal::RateLimited { .. } => Some(reg::RELAY_RATE_LIMITED),
            Refusal::QuotaExceeded { .. } => Some(reg::RELAY_QUOTA_EXCEEDED),
            Refusal::CapacityUnspecified { .. } => Some(reg::RELAY_CAPACITY_REJECTED),
            Refusal::Draining { .. } => Some(reg::RELAY_DRAINING),
            Refusal::Other { observed, .. } => observed.registered(),
        }
    }

    /// How long the device must wait before retrying **this** relay.
    ///
    /// ADR-0006 §11.7 rule 3 makes it binding, so it is on the type rather than
    /// buried in a variant a caller has to match to reach.
    #[must_use]
    pub const fn retry_after(&self) -> Duration {
        match self {
            Refusal::FlowLimitReached { retry_after }
            | Refusal::BindRateLimited { retry_after }
            | Refusal::RateLimited { retry_after }
            | Refusal::QuotaExceeded { retry_after }
            | Refusal::CapacityUnspecified { retry_after }
            | Refusal::Other { retry_after, .. } => *retry_after,
            // A drain is not a retry. The device leaves.
            Refusal::Draining { .. } => Duration::ZERO,
        }
    }

    /// Maps one on-wire `reason_code` string onto a refusal.
    ///
    /// The four exact spellings map to their own variants; the degraded
    /// `RELAY.CAPACITY_REJECTED` maps to [`Refusal::CapacityUnspecified`]; a
    /// code that does not parse at all is **not** turned into a refusal, since
    /// ADR-0015 §11.2's syntax rules exist precisely so that a receiver refuses
    /// to guess at a first segment outside the closed domain set.
    ///
    /// # Errors
    ///
    /// [`RelayReject::Malformed`] for a code that fails ADR-0015 §11.2's format
    /// rules.
    pub fn from_wire(
        code: &str,
        retry_after: Duration,
        deadline: Duration,
    ) -> Result<Self, RelayReject> {
        let observed = ObservedReasonCode::parse(code).map_err(|_| RelayReject::Malformed)?;
        Ok(match observed.as_str() {
            "RELAY.FLOW_LIMIT_REACHED" => Refusal::FlowLimitReached { retry_after },
            "RELAY.BIND_RATE_LIMITED" => Refusal::BindRateLimited { retry_after },
            "RELAY.RATE_LIMITED" => Refusal::RateLimited { retry_after },
            "RELAY.QUOTA_EXCEEDED" => Refusal::QuotaExceeded { retry_after },
            "RELAY.CAPACITY_REJECTED" => Refusal::CapacityUnspecified { retry_after },
            "RELAY.DRAINING" => Refusal::Draining { deadline },
            _ => Refusal::Other {
                observed,
                retry_after,
            },
        })
    }
}

/// What a `BIND` produced.
///
/// ADR-0005 §11.1(3)/(4): *"the **FIRST** `BIND` creates a pending slot; the
/// **SECOND** on the same tag binds it."* Those are two different states and a
/// device schedules different work from each, so they are two variants and not
/// a boolean on one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindOutcome {
    /// A pending slot exists and the partner has not arrived.
    ///
    /// The listening posture of ADR-0006 §11.5 re-`BIND`s at this cadence.
    Pending {
        /// The relay-assigned handle.
        flow_id: u32,
        /// The slot's lifetime **as the relay reports it**, so the re-`BIND` is
        /// scheduled from the relay's number rather than a compiled-in copy.
        pending_ttl: Duration,
    },
    /// Both half-flows are present and the flow carries traffic.
    Bound {
        /// The relay-assigned handle.
        flow_id: u32,
    },
    /// The relay refused, with a reason. **Never silence** — ADR-0005 §11.5:
    /// *"a relay that drops without a status frame is a defect."*
    Refused(Refusal),
}

/// What one authenticated inbound frame meant.
#[derive(Debug)]
#[non_exhaustive]
pub enum Inbound {
    /// A sealed datagram from the peer, forwarded byte for byte.
    Data(super::Sealed),
    /// The relay answered a `BIND`.
    Bound(BindOutcome),
    /// The relay is shedding, throttling or draining.
    Status(Refusal),
    /// The relay asked this device to leave, by a deadline.
    Drain(super::DrainNotice),
    /// Leg liveness. ADR-0006 §11.15(c) makes this observable **independently**
    /// of any half-flow, which is what §11.4's attribution rests on.
    Ping,
    /// The reply to our `PING`.
    Pong,
    /// The relay's capability set (ADR-0005 §10).
    Caps(super::codec::CapsBody),
}

/// Which relays a hint named, once checked against the verified map.
///
/// ADR-0006 §11.7 rule 3 and `relay.proto` agree: a suggestion is a **hint**,
/// the device re-ranks against its own map, and one absent from that map is
/// inert. Filtering here rather than at the call site means a caller cannot
/// forget to.
#[must_use]
pub fn admissible(suggested: &[RelayId], verified: &[RelayId]) -> Vec<RelayId> {
    suggested
        .iter()
        .copied()
        .filter(|s| verified.contains(s))
        .collect()
}
