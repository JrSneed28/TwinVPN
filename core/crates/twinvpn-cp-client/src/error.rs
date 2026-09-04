//! The one failure carrier for the control-plane client.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 12 ("expose
//! registered `reason_code`s, never raw internal errors"), ADR-0002 §11.11 (the
//! `CONTROL.*` contribution), ADR-0015 §11.2 (the registry).
//!
//! Every variant maps to a code that exists in
//! `contracts/registry/reason_codes.json`, and every variant attaches the
//! evidence that code *declares*. There is no `Other(String)` and no
//! `#[from] std::io::Error`: an unregistered failure has nowhere to go, which is
//! how **I6** is a compile-time property here rather than a review comment.

use twinvpn_env::EnvError;
use twinvpn_schema::Reject;
use twinvpn_types::evidence::EvidenceValue;
use twinvpn_types::{codes, Component, Diagnostic, ReasonCode};

use crate::transport::Rung;

/// The component every diagnostic this crate emits is observed by.
///
/// ADR-0015 §11.3: the field names the **observer**, not the blamed party. A
/// control-plane failure seen here is `COMPONENT_CONTROL_PLANE_CLIENT` even when
/// the `reason_code` blames the coordination service.
pub const COMPONENT: Component = Component::ControlPlaneClient;

/// A control-plane client failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CpError {
    // -- transport ladder ---------------------------------------------------
    /// Every ladder rung was exhausted. **Established sessions are unaffected**
    /// (I5); this is `TRANSIENT`/`WARN` and informational, and surfacing it as a
    /// terminal connection failure is a defect (`reliability.md` §9.4).
    #[error("the control plane is unreachable on every rung")]
    Unreachable,

    /// The connection fell to a degraded rung. Carries which one.
    #[error("control channel degraded to rung {rung:?}")]
    TransportDegraded {
        /// The rung now in use.
        rung: Rung,
    },

    /// The control-channel mTLS handshake was refused: an unknown or revoked
    /// device key, or a server pin mismatch. Distinct from
    /// `CRYPTO.HANDSHAKE_REJECTED`, which is the tunnel.
    #[error("the control-channel handshake was rejected")]
    HandshakeRejected,

    /// The accept limiter engaged. `retry_after_ms` **must** be honoured
    /// (ADR-0002 §11.7 rule 3).
    #[error("admission deferred for {retry_after_ms} ms")]
    AdmissionDeferred {
        /// How long the front-end asked us to wait.
        retry_after_ms: u64,
    },

    /// An older control connection for this identity was closed (ADR-0002 N-1).
    #[error("superseded by a newer control connection")]
    SupersededByNewAttach,

    // -- security events ----------------------------------------------------
    /// `Auth.channel_binding` did not match our own RFC 9266 exporter.
    /// **A security event, never a parse error** (ADR-0002 N-2).
    #[error("channel binding mismatch")]
    ChannelBindingMismatch,

    /// A durable event arrived from a principal that is not its sole publisher
    /// (protocol.md §7). **A security event** (ADR-0002 S-4).
    #[error("event {event_type} arrived from publisher {observed_publisher}")]
    EventWrongPublisher {
        /// The event's oneof variant name.
        event_type: &'static str,
        /// The `EventPublisher` the wire claimed.
        observed_publisher: &'static str,
    },

    /// A trust floor — `trust_epoch`, `generation`, `tk_generation` — offered
    /// below our durable mark. Refused, never applied (ADR-0007 N-26). A document
    /// is [`CpError::VersionRollbackRejected`], a cursor [`CpError::ReplicaBehindCursor`] (W-11).
    #[error("trust-epoch rollback: offered {offered_epoch}, high water {high_water_epoch}")]
    TrustEpochRollback {
        /// What the control plane offered.
        offered_epoch: u64,
        /// What we already hold.
        high_water_epoch: u64,
    },

    /// Two different trust records at one epoch, or a broken `prev_entry_hash`
    /// (ADR-0007 N-26, S-32). Nothing in this crate produces it today; a forked
    /// *document* history is [`CpError::ForkedHistoryDetected`].
    #[error("forked trust history at epoch {epoch}")]
    TrustHistoryForked {
        /// The epoch at which the fork was seen.
        epoch: u64,
    },

    /// A document offered below its stored `doc_version` high-water mark
    /// (ADR-0009 R-5). Refused, never applied; a security event.
    #[error("version rollback: offered {offered_version}, high water {high_water_version}")]
    VersionRollbackRejected {
        /// What was offered.
        offered_version: u64,
        /// What we already hold.
        high_water_version: u64,
    },

    /// Two different contents at one `doc_version` — the client-side detector
    /// for E-1(c) (ADR-0009 R-4). A security event.
    #[error("forked history at version {version}")]
    ForkedHistoryDetected {
        /// The version at which the fork was seen.
        version: u64,
    },

    /// `RegisterDeviceResponse.device_id_echo` disagreed with our own derivation.
    /// The echo is **an echo, never an assignment**: registration aborts and the
    /// server's value is not adopted (protocol.md §8.1).
    #[error("device_id echo does not match the locally derived value")]
    IdentityMismatch,

    /// A signed statement's own validity window has closed.
    #[error("{statement_type} expired at {not_after_ms}")]
    StatementExpired {
        /// Which CDDL statement type.
        statement_type: &'static str,
        /// The window's upper bound.
        not_after_ms: u64,
        /// The skew allowance that was applied.
        skew_allowance_ms: u64,
    },

    /// A signed statement did not verify against the Owner chain or the signer's
    /// device key. **The transport being authenticated is not verification.**
    #[error("{statement_type} failed signature verification")]
    StatementUnverified {
        /// Which CDDL statement type.
        statement_type: &'static str,
    },

    /// The element-resident identity key could not sign: a locked device, a
    /// revoked entitlement, an element that lost its backing.
    #[error("the identity key is unavailable for signing")]
    KeyUnavailable,

    // -- stream and cursor --------------------------------------------------
    /// The server shed our C2 backlog. A **deliberate**, in-band, in-order gap
    /// (ADR-0002 N-8); the recovery is a declarative re-read.
    #[error("stream compacted up to net_seq {up_to_net_seq}")]
    StreamCompacted {
        /// The position the cursor now lands on.
        up_to_net_seq: u64,
    },

    /// Our cursor fell below the retention floor. A full declarative re-snapshot
    /// is required, and is always correct because every durable event is
    /// independently applicable (ADR-0002 N-5).
    #[error("cursor {cursor} is below the retention floor {retention_floor}")]
    CursorTooOld {
        /// Where we were.
        cursor: u64,
        /// The floor the server reported.
        retention_floor: u64,
    },

    /// A replica could not satisfy our monotonic-read token. Refusal is the
    /// correct answer (ADR-0009 §11.2): a device told "I cannot serve you yet"
    /// keeps running on its cache and retries.
    #[error("replica is behind our cursor; retry after {retry_after_ms} ms")]
    ReadTooStale {
        /// How long to wait.
        retry_after_ms: u64,
    },

    /// The replica's applied position is below the cursor we presented.
    #[error("replica at {replica_net_seq} is behind our minimum {min_net_seq}")]
    ReplicaBehindCursor {
        /// What we required.
        min_net_seq: u64,
        /// What it had.
        replica_net_seq: u64,
    },

    /// No valid, unexpired `LogHead` within three intervals. Cached documents
    /// are now treated as approaching expiry. **`LogHead` is not trust**
    /// (ADR-0002 S-3).
    #[error("no freshness proof for {intervals_missed} intervals")]
    FreshnessProofMissing {
        /// How many 60 s intervals were missed.
        intervals_missed: u64,
    },

    // -- write-path refusals ------------------------------------------------
    /// The per-`TwinNet` durable-write budget was exceeded; the write was
    /// refused, not queued.
    #[error("durable event rate exceeded")]
    EventRateExceeded,

    /// The `TwinNet` write leader is failing over. Mutations defer.
    #[error("the TwinNet write leader is unavailable")]
    WriteLeaderUnavailable,

    /// An E-1-class mutation could not reach quorum and was **refused, not
    /// partially applied** — a forked revocation history is what E-1 forbids.
    #[error("quorum unavailable for an E-1-class mutation")]
    QuorumUnavailable,

    // -- staleness ----------------------------------------------------------
    /// Operating from cached signed documents past half their TTL.
    #[error("operating on stale policy, age {document_age_ms} ms")]
    StalePolicyInUse {
        /// How old the governing document is.
        document_age_ms: u64,
    },

    /// A cached document entered the STALE band (ADR-0009 §11.4). It **governs
    /// fully**; only refresh escalates.
    #[error("{doc_type} is stale at {age_ms} ms")]
    DocumentStale {
        /// Which document type.
        doc_type: &'static str,
        /// Its age.
        age_ms: u64,
    },

    /// The trust list passed `not_after`. Denials remain in force **permanently**;
    /// a `TrustedPeer` known only from an expired membership document is not
    /// admitted.
    #[error("the trust list expired {age_ms} ms ago")]
    TrustListExpired {
        /// How long past `not_after`.
        age_ms: u64,
    },

    /// Trust state crossed `T_TRUST_HARD`. Every *granted* authority suspends;
    /// every denial persists; **baseline peer connectivity is untouched**.
    #[error("trust state expired at age {age_ms} ms")]
    TrustStateExpired {
        /// The trust state's age.
        age_ms: u64,
    },

    /// The Owner-signed policy bundle passed its own `not_after_ms`. Grants
    /// suspend, denials persist, and **no `Session` is torn down** (I5).
    #[error("policy bundle {policy_version} expired at {not_after_ms}")]
    PolicyBundleExpired {
        /// The version that expired.
        policy_version: u64,
        /// Its own upper bound.
        not_after_ms: u64,
    },

    // -- validation ---------------------------------------------------------
    /// Untrusted input failed a `limits.json` cap or a canonical-form rule.
    /// Carries the typed [`Reject`] verbatim, so the violated **registry key** is
    /// named rather than described.
    #[error(transparent)]
    Rejected(#[from] Reject),

    /// The peer's `proto_version` range and ours do not intersect. The range
    /// comes from the local build plus local policy only and **is not narrowable
    /// by the control plane** (ADR-0014 N-2, ADR-0001 D4).
    #[error("no mutually supported protocol epoch")]
    VersionUnsupported {
        /// Our floor.
        local_min: u32,
        /// Our ceiling.
        local_max: u32,
        /// Theirs.
        peer_min: u32,
        /// Theirs.
        peer_max: u32,
    },

    /// An injected environment capability failed — entropy, a spawn, a
    /// derivation. Carries the `Env`'s own registered code.
    #[error("environment capability failed")]
    Env(
        /// The code `twinvpn-env` assigned.
        ReasonCode,
    ),
}

impl From<EnvError> for CpError {
    fn from(value: EnvError) -> Self {
        CpError::Env(value.reason_code())
    }
}

impl CpError {
    /// The registered `reason_code`.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        match self {
            CpError::Unreachable => codes::CONTROL_UNREACHABLE,
            CpError::TransportDegraded { rung } => rung.entry_code_or_unreachable(),
            CpError::HandshakeRejected => codes::CONTROL_HANDSHAKE_REJECTED,
            CpError::AdmissionDeferred { .. } => codes::CONTROL_ADMISSION_DEFERRED,
            CpError::SupersededByNewAttach => codes::CONTROL_SUPERSEDED_BY_NEW_ATTACH,
            CpError::ChannelBindingMismatch => codes::CONTROL_CHANNEL_BINDING_MISMATCH,
            CpError::EventWrongPublisher { .. } => codes::CONTROL_EVENT_WRONG_PUBLISHER,
            CpError::TrustEpochRollback { .. } => codes::AUTH_TRUST_EPOCH_ROLLBACK,
            CpError::TrustHistoryForked { .. } => codes::AUTH_TRUST_HISTORY_FORKED,
            CpError::VersionRollbackRejected { .. } => {
                codes::CONTROL_CONSISTENCY_VERSION_ROLLBACK_REJECTED
            }
            CpError::ForkedHistoryDetected { .. } => {
                codes::CONTROL_CONSISTENCY_FORKED_HISTORY_DETECTED
            }
            CpError::IdentityMismatch => codes::AUTH_IDENTITY_MISMATCH,
            CpError::StatementExpired { .. } => codes::AUTH_STATEMENT_EXPIRED,
            CpError::StatementUnverified { .. } => codes::AUTH_BINDING_INVALID,
            CpError::KeyUnavailable => codes::AUTH_KEY_UNAVAILABLE,
            CpError::StreamCompacted { .. } => codes::CONTROL_STREAM_COMPACTED,
            CpError::CursorTooOld { .. } => codes::CONTROL_CURSOR_TOO_OLD,
            CpError::ReadTooStale { .. } => codes::CONTROL_READ_TOO_STALE,
            CpError::ReplicaBehindCursor { .. } => codes::CONTROL_CONSISTENCY_REPLICA_BEHIND_CURSOR,
            CpError::FreshnessProofMissing { .. } => codes::CONTROL_FRESHNESS_PROOF_MISSING,
            CpError::EventRateExceeded => codes::CONTROL_EVENT_RATE_EXCEEDED,
            CpError::WriteLeaderUnavailable => codes::CONTROL_WRITE_LEADER_UNAVAILABLE,
            CpError::QuorumUnavailable => codes::CONTROL_QUORUM_UNAVAILABLE,
            CpError::StalePolicyInUse { .. } => codes::CONTROL_STALE_POLICY_IN_USE,
            CpError::DocumentStale { .. } => codes::CONTROL_STALENESS_DOCUMENT_STALE,
            CpError::TrustListExpired { .. } => codes::CONTROL_STALENESS_TRUST_LIST_EXPIRED,
            CpError::TrustStateExpired { .. } => codes::AUTH_TRUST_STATE_EXPIRED,
            CpError::PolicyBundleExpired { .. } => codes::POLICY_EXPIRY_BUNDLE_EXPIRED,
            CpError::Rejected(reject) => reject.reason_code(),
            CpError::VersionUnsupported { .. } => codes::PROTO_VERSION_UNSUPPORTED,
            CpError::Env(code) => *code,
        }
    }

    /// Whether this condition is a **security event** and must be reported as
    /// one rather than as a parse or connection error.
    ///
    /// The three the corpus names explicitly are channel-binding mismatch
    /// (ADR-0002 N-2), wrong publisher (S-4), and a monotone rollback (ADR-0008
    /// §7.1); ADR-0009 R-4 and R-5 add the document fork and rollback. Each
    /// means an authenticated peer said something it must not have been able to say.
    #[must_use]
    pub const fn is_security_event(&self) -> bool {
        matches!(
            self,
            CpError::ChannelBindingMismatch
                | CpError::EventWrongPublisher { .. }
                | CpError::TrustEpochRollback { .. }
                | CpError::TrustHistoryForked { .. }
                | CpError::VersionRollbackRejected { .. }
                | CpError::ForkedHistoryDetected { .. }
                | CpError::IdentityMismatch
                | CpError::StatementUnverified { .. }
        )
    }

    /// Whether a control-plane outage of this shape still permits the data plane
    /// to re-establish a session with an already-known `TrustedPeer`.
    ///
    /// Everything this crate can produce answers `true` except a trust-epoch
    /// rollback and a forged statement, which are *authoritative instructions
    /// that trust has ended* rather than unavailability (`architecture.md`
    /// §4.5(2)); that distinction is the whole of I5 (`reliability.md` §9.2).
    /// A refused *document* (R-4/R-5) is neither: the device keeps its version.
    #[must_use]
    pub const fn permits_offline_reconnect(&self) -> bool {
        !matches!(
            self,
            CpError::TrustEpochRollback { .. } | CpError::TrustHistoryForked { .. }
        )
    }

    /// The registered diagnostic, with the code's declared evidence attached.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn diagnostic(&self) -> Diagnostic {
        let b = Diagnostic::builder(self.reason_code(), COMPONENT);
        match self {
            // These carry no declared evidence in the registry, so the code and
            // the component are the whole diagnostic.
            //
            // `AUTH.IDENTITY_MISMATCH` is in this group deliberately: its
            // declared evidence is `{derived, echoed}`, and both are device
            // identifiers. The mismatch is the fact worth recording; the two
            // values are already in the local store, and putting a `device_id`
            // into a diagnostic that reaches a support bundle is exactly what
            // `DeviceId`'s redacted `Debug` exists to prevent.
            CpError::Unreachable
            | CpError::HandshakeRejected
            | CpError::SupersededByNewAttach
            | CpError::ChannelBindingMismatch
            | CpError::IdentityMismatch
            | CpError::StatementUnverified { .. }
            | CpError::KeyUnavailable
            | CpError::VersionRollbackRejected { .. }
            | CpError::ForkedHistoryDetected { .. }
            | CpError::EventRateExceeded
            | CpError::WriteLeaderUnavailable
            | CpError::QuorumUnavailable
            | CpError::Env(_) => b.build(),
            CpError::TransportDegraded { rung } => b
                .evidence("rung", EvidenceValue::Uint(u64::from(rung.number())))
                .build(),
            CpError::AdmissionDeferred { retry_after_ms }
            | CpError::ReadTooStale { retry_after_ms } => b
                .evidence("retry_after_ms", EvidenceValue::DurationMs(*retry_after_ms))
                .build(),
            CpError::EventWrongPublisher {
                event_type,
                observed_publisher,
            } => b
                .evidence("event_type", EvidenceValue::Text((*event_type).to_owned()))
                .evidence(
                    "observed_publisher",
                    EvidenceValue::Text((*observed_publisher).to_owned()),
                )
                .build(),
            CpError::TrustEpochRollback {
                offered_epoch,
                high_water_epoch,
            } => b
                .evidence("offered_epoch", EvidenceValue::Uint(*offered_epoch))
                .evidence("high_water_epoch", EvidenceValue::Uint(*high_water_epoch))
                .build(),
            CpError::TrustHistoryForked { epoch } => {
                b.evidence("epoch", EvidenceValue::Uint(*epoch)).build()
            }
            CpError::StatementExpired {
                statement_type,
                not_after_ms,
                skew_allowance_ms,
            } => b
                .evidence(
                    "statement_type",
                    EvidenceValue::Text((*statement_type).to_owned()),
                )
                .evidence("not_after_ms", EvidenceValue::Uint(*not_after_ms))
                .evidence(
                    "skew_allowance_ms",
                    EvidenceValue::DurationMs(*skew_allowance_ms),
                )
                .build(),
            CpError::StreamCompacted { up_to_net_seq } => b
                .evidence("up_to_net_seq", EvidenceValue::Uint(*up_to_net_seq))
                .build(),
            CpError::CursorTooOld {
                cursor,
                retention_floor,
            } => b
                .evidence("cursor", EvidenceValue::Uint(*cursor))
                .evidence("retention_floor", EvidenceValue::Uint(*retention_floor))
                .build(),
            CpError::ReplicaBehindCursor {
                min_net_seq,
                replica_net_seq,
            } => b
                .evidence("min_net_seq", EvidenceValue::Uint(*min_net_seq))
                .evidence("replica_net_seq", EvidenceValue::Uint(*replica_net_seq))
                .build(),
            CpError::FreshnessProofMissing { intervals_missed } => b
                .evidence("intervals_missed", EvidenceValue::Uint(*intervals_missed))
                .build(),
            CpError::StalePolicyInUse { document_age_ms } => b
                .evidence(
                    "document_age_ms",
                    EvidenceValue::DurationMs(*document_age_ms),
                )
                .build(),
            CpError::DocumentStale { doc_type, age_ms } => b
                .evidence("doc_type", EvidenceValue::Text((*doc_type).to_owned()))
                .evidence("age_ms", EvidenceValue::DurationMs(*age_ms))
                .build(),
            CpError::TrustListExpired { age_ms } | CpError::TrustStateExpired { age_ms } => b
                .evidence("age_ms", EvidenceValue::DurationMs(*age_ms))
                .build(),
            CpError::PolicyBundleExpired {
                policy_version,
                not_after_ms,
            } => b
                .evidence("policy_version", EvidenceValue::Uint(*policy_version))
                .evidence("not_after_ms", EvidenceValue::Uint(*not_after_ms))
                .build(),
            CpError::Rejected(reject) => reject.diagnostic(COMPONENT),
            CpError::VersionUnsupported {
                local_min,
                local_max,
                peer_min,
                peer_max,
            } => b
                .evidence("local_min", EvidenceValue::Uint(u64::from(*local_min)))
                .evidence("local_max", EvidenceValue::Uint(u64::from(*local_max)))
                .evidence("peer_min", EvidenceValue::Uint(u64::from(*peer_min)))
                .evidence("peer_max", EvidenceValue::Uint(u64::from(*peer_max)))
                .build(),
        }
    }
}

/// A convenient alias for this crate's fallible operations.
pub type CpResult<T> = Result<T, CpError>;
