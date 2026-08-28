//! The telemetry attribute vocabulary, transcribed from the one place it is
//! already enforced.
//!
//! **Authority:** `infra/otel/collector-config.yaml` (`redaction/allowlist`
//! `allowed_keys` and `filter/forbidden`), `infra/README.md` §6.3, ADR-0015
//! §11.1/§11.4/§9, ADR-0018 VR-2 consequence 3.
//!
//! # Why this list is duplicated here at all
//!
//! It is not a second authority; it is the *emit-time* half of a control the
//! collector enforces again at export time, and ADR-0015 O-14 requires the
//! emit-time half to exist:
//!
//! > redaction at EMIT time by schema-level field classification, NOT at export
//! > time by pattern matching over rendered text.
//!
//! The collector's allowlist would silently delete a leaked key; its
//! forbidden-key filter drops the whole record and increments a counter. This
//! module makes both outcomes *unreachable from a well-typed call site*: an
//! [`AttrKey`] has no `From<&str>`, so the ordinary way to name an attribute is
//! to name one of the constants below, and the only runtime constructor,
//! [`AttrKey::checked`], refuses a forbidden key and refuses an unknown one.
//!
//! `attribute_vocabulary_matches_the_collector` in `tests/` re-parses
//! `infra/otel/collector-config.yaml` and fails if the two ever diverge, so this
//! transcription cannot rot silently.

use std::fmt;

// ---------------------------------------------------------------------------
// The allowlist, in the collector's own grouping and order.
// ---------------------------------------------------------------------------

/// Every attribute key the collector's `redaction/allowlist` admits.
///
/// Anything else is deleted before it reaches a backend, so emitting it is
/// wasted work at best and an unreviewed field at worst.
pub const ALLOWED_KEYS: &[&str] = &[
    // provenance (ADR-0018 S-46 CoreBuildIdentity)
    "service.name",
    "service.version",
    "service.instance.id",
    "deployment.environment",
    "twinvpn.observability_tier",
    "twinvpn.component",
    "twinvpn.core_version",
    "twinvpn.protocol_epoch",
    "twinvpn.schema_digest",
    "twinvpn.reason_registry_version",
    "twinvpn.crypto_provider",
    "twinvpn.profile",
    "twinvpn.target_triple",
    "twinvpn.source_commit",
    "twinvpn.abi_major",
    "twinvpn.abi_minor",
    // correlation and causation, preserved end to end
    "twinvpn.correlation_id",
    "twinvpn.causation_id",
    "twinvpn.message_id",
    "twinvpn.idempotency_key",
    // reason code and its registry attributes (ADR-0015 §11.2 rule 5)
    "twinvpn.reason_code",
    "twinvpn.reason_domain",
    "twinvpn.reason_class",
    "twinvpn.severity",
    "twinvpn.terminal",
    "twinvpn.user_actionable",
    "twinvpn.remediation_class",
    "twinvpn.scope",
    "twinvpn.doc_anchor",
    "twinvpn.evidence_key",
    // the §9 Prometheus label allowlist, verbatim
    "twinvpn.relay_region",
    "twinvpn.protocol_version",
    "twinvpn.outcome",
    "twinvpn.address_family",
    // aggregate-only dimensions (§11.1 Tier-2 tuple)
    "twinvpn.nat_class",
    "twinvpn.nat_class_local",
    "twinvpn.nat_class_remote",
    "twinvpn.platform_class",
    "twinvpn.day_bucket",
    // state machine (O-05 TransitionEvent)
    "twinvpn.state_from",
    "twinvpn.state_to",
    "twinvpn.trigger",
    "twinvpn.connection_state",
    // transport and relay shape
    "twinvpn.transport_rung",
    "twinvpn.carriage",
    "twinvpn.failure_domain",
    "twinvpn.admin_state",
    "twinvpn.load_class",
    "twinvpn.health_state",
    // observability self-reporting (ADR-0015 §8)
    "twinvpn.dropped_events",
    "twinvpn.ring",
    // narrow semconv: status codes only, never addresses or URLs
    "http.request.method",
    "http.response.status_code",
    "rpc.system",
    "rpc.method",
    "rpc.grpc.status_code",
    "error.type",
    "exception.type",
    "otel.status_code",
];

/// Every key the collector's `filter/forbidden` drops the **whole record** for.
///
/// These are ADR-0015 §11.4's `SECRET` class plus the `SENSITIVE` identifiers
/// O-13 forbids infrastructure from retaining. A `SECRET`-classified field "has
/// no rendering path at all, in any build"; if one of these ever appears, a code
/// path exists that should not, and that is a defect to surface rather than a
/// value to scrub.
pub const FORBIDDEN_KEYS: &[&str] = &[
    // per-session / per-peer identifiers (O-13)
    "twinvpn.session_id",
    "twinvpn.path_id",
    "twinvpn.pair_tag",
    "twinvpn.flow_id",
    "twinvpn.device_id",
    "twinvpn.identity_id",
    "twinvpn.peer_id",
    "twinvpn.owner_id",
    "twinvpn.pairing_id",
    "twinvpn.twinnet_id",
    // key material and credentials (SECRET)
    "twinvpn.pair_secret",
    "twinvpn.psk",
    "twinvpn.private_key",
    "twinvpn.session_key",
    "twinvpn.leg_key",
    "twinvpn.rlk",
    "twinvpn.auth_token",
    "authorization",
    "cookie",
    // payload and content
    "twinvpn.payload",
    "twinvpn.packet",
    "twinvpn.plaintext",
    "twinvpn.dns_query_name",
    "twinvpn.destination",
    "http.request.body",
    "exception.stacktrace",
    // endpoints and addresses (SENSITIVE)
    "twinvpn.endpoint",
    "twinvpn.ssid",
    "twinvpn.interface_name",
    "net.peer.ip",
    "net.peer.name",
    "client.address",
    "server.address",
    "url.full",
];

/// The exact Tier-2 tuple of ADR-0015 §11.1, and nothing else.
///
/// > Coarse, IDENTIFIER-FREE, k-anonymous counters:
/// > `{reason_code, outcome, address_family, nat_class, protocol_version,
/// > platform_class, day_bucket}`
///
/// ADR-0018 VR-2 consequence 3 additionally forbids `abi_*` here: "an ABI pair
/// is build-identifying and has no aggregate meaning". The tuple is a `const`
/// array rather than a builder default so that adding a dimension is an edit to
/// this line, reviewable as one.
pub const TIER2_TUPLE: [&str; 7] = [
    "twinvpn.reason_code",
    "twinvpn.outcome",
    "twinvpn.address_family",
    "twinvpn.nat_class",
    "twinvpn.protocol_version",
    "twinvpn.platform_class",
    "twinvpn.day_bucket",
];

// ---------------------------------------------------------------------------
// Named constants — the ordinary way to name an attribute.
// ---------------------------------------------------------------------------

macro_rules! keys {
    ($($ident:ident => $lit:literal),* $(,)?) => {
        $(
            #[doc = concat!("The `", $lit, "` attribute.")]
            pub const $ident: AttrKey = AttrKey($lit);
        )*
    };
}

keys! {
    SERVICE_NAME            => "service.name",
    SERVICE_VERSION         => "service.version",
    SERVICE_INSTANCE_ID     => "service.instance.id",
    CORE_VERSION            => "twinvpn.core_version",
    PROTOCOL_EPOCH          => "twinvpn.protocol_epoch",
    SCHEMA_DIGEST           => "twinvpn.schema_digest",
    REASON_REGISTRY_VERSION => "twinvpn.reason_registry_version",
    CRYPTO_PROVIDER         => "twinvpn.crypto_provider",
    PROFILE                 => "twinvpn.profile",
    TARGET_TRIPLE           => "twinvpn.target_triple",
    SOURCE_COMMIT           => "twinvpn.source_commit",
    ABI_MAJOR               => "twinvpn.abi_major",
    ABI_MINOR               => "twinvpn.abi_minor",
    DEPLOYMENT_ENVIRONMENT  => "deployment.environment",
    OBSERVABILITY_TIER      => "twinvpn.observability_tier",
    COMPONENT               => "twinvpn.component",
    CORRELATION_ID          => "twinvpn.correlation_id",
    CAUSATION_ID            => "twinvpn.causation_id",
    MESSAGE_ID              => "twinvpn.message_id",
    IDEMPOTENCY_KEY         => "twinvpn.idempotency_key",
    REASON_CODE             => "twinvpn.reason_code",
    REASON_DOMAIN           => "twinvpn.reason_domain",
    REASON_CLASS            => "twinvpn.reason_class",
    SEVERITY                => "twinvpn.severity",
    TERMINAL                => "twinvpn.terminal",
    USER_ACTIONABLE         => "twinvpn.user_actionable",
    REMEDIATION_CLASS       => "twinvpn.remediation_class",
    SCOPE                   => "twinvpn.scope",
    DOC_ANCHOR              => "twinvpn.doc_anchor",
    EVIDENCE_KEY            => "twinvpn.evidence_key",
    RELAY_REGION            => "twinvpn.relay_region",
    PROTOCOL_VERSION        => "twinvpn.protocol_version",
    OUTCOME                 => "twinvpn.outcome",
    ADDRESS_FAMILY          => "twinvpn.address_family",
    NAT_CLASS               => "twinvpn.nat_class",
    PLATFORM_CLASS          => "twinvpn.platform_class",
    DAY_BUCKET              => "twinvpn.day_bucket",
    STATE_FROM              => "twinvpn.state_from",
    STATE_TO                => "twinvpn.state_to",
    TRIGGER                 => "twinvpn.trigger",
    CONNECTION_STATE        => "twinvpn.connection_state",
    TRANSPORT_RUNG          => "twinvpn.transport_rung",
    CARRIAGE                => "twinvpn.carriage",
    FAILURE_DOMAIN          => "twinvpn.failure_domain",
    ADMIN_STATE             => "twinvpn.admin_state",
    LOAD_CLASS              => "twinvpn.load_class",
    HEALTH_STATE            => "twinvpn.health_state",
    DROPPED_EVENTS          => "twinvpn.dropped_events",
    RING                    => "twinvpn.ring",
    HTTP_REQUEST_METHOD     => "http.request.method",
    HTTP_RESPONSE_STATUS    => "http.response.status_code",
    RPC_SYSTEM              => "rpc.system",
    RPC_METHOD              => "rpc.method",
    ERROR_TYPE              => "error.type",
    OTEL_STATUS_CODE        => "otel.status_code",
}

// ---------------------------------------------------------------------------
// AttrKey
// ---------------------------------------------------------------------------

/// An attribute name that has been proved to be on the collector's allowlist.
///
/// There is no `From<&str>`, no `new`, and no public tuple constructor. The only
/// runtime path is [`AttrKey::checked`], which refuses a forbidden key with a
/// distinct error so a caller cannot confuse "I made that name up" with "that
/// name is a security defect".
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttrKey(&'static str);

impl AttrKey {
    /// The attribute name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// Resolves `name` against the allowlist.
    ///
    /// # Errors
    ///
    /// [`AttrError::Forbidden`] if `name` is on the collector's forbidden list —
    /// the record would be dropped whole and an alert would fire.
    /// [`AttrError::NotAllowlisted`] if `name` is simply unknown — the collector
    /// would delete it silently, so emitting it is a no-op with a cost.
    pub fn checked(name: &str) -> Result<Self, AttrError> {
        if let Some(k) = FORBIDDEN_KEYS.iter().find(|k| **k == name) {
            return Err(AttrError::Forbidden { key: k });
        }
        ALLOWED_KEYS
            .iter()
            .find(|k| **k == name)
            .map(|k| Self(k))
            .ok_or(AttrError::NotAllowlisted)
    }
}

impl fmt::Debug for AttrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Display for AttrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Why an attribute name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttrError {
    /// The name is on `filter/forbidden`. The collector would drop the entire
    /// record and raise `TwinVPNObservabilityForbiddenAttributeObserved`, which
    /// `infra/README.md` §8 classifies as **a security defect in the emitting
    /// service**, not a collector tuning problem.
    #[error("{key} is a forbidden telemetry attribute (ADR-0015 O-12/O-13)")]
    Forbidden {
        /// The forbidden key, from the static list — never the caller's string,
        /// so an attacker-influenced name cannot reach a log through this error.
        key: &'static str,
    },

    /// The name is not on the collector's allowlist, so it would be deleted
    /// before reaching a backend. Add it to `redaction/allowlist` **and** justify
    /// its classification (`infra/README.md` §8) before emitting it.
    #[error("attribute is not on the collector allowlist")]
    NotAllowlisted,
}

/// Classification of an arbitrary attribute name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyVerdict {
    /// On the allowlist; safe to emit.
    Allowed,
    /// On `filter/forbidden`; emitting it drops the whole record.
    Forbidden,
    /// Neither; the collector deletes it silently.
    Unknown,
}

/// Classifies `name` exactly as the collector would.
#[must_use]
pub fn verdict(name: &str) -> KeyVerdict {
    if FORBIDDEN_KEYS.contains(&name) {
        KeyVerdict::Forbidden
    } else if ALLOWED_KEYS.contains(&name) {
        KeyVerdict::Allowed
    } else {
        KeyVerdict::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forbidden_key_is_refused_with_its_own_error() {
        assert_eq!(
            AttrKey::checked("twinvpn.session_id"),
            Err(AttrError::Forbidden {
                key: "twinvpn.session_id"
            })
        );
        assert_eq!(
            AttrKey::checked("twinvpn.private_key"),
            Err(AttrError::Forbidden {
                key: "twinvpn.private_key"
            })
        );
        assert_eq!(
            AttrKey::checked("authorization"),
            Err(AttrError::Forbidden {
                key: "authorization"
            })
        );
    }

    #[test]
    fn an_unknown_key_is_refused_separately_from_a_forbidden_one() {
        assert_eq!(
            AttrKey::checked("twinvpn.my_new_idea"),
            Err(AttrError::NotAllowlisted)
        );
    }

    #[test]
    fn the_deliberate_absences_are_absent() {
        // ADR-0015 §11.2 rule 5: a carrier MUST NOT add a localized text field.
        for absent in [
            "summary",
            "message",
            "title",
            "exception.message",
            "exception.stacktrace",
        ] {
            assert_ne!(
                verdict(absent),
                KeyVerdict::Allowed,
                "{absent} must never be allowlisted"
            );
        }
    }

    #[test]
    fn correlation_and_causation_survive() {
        for k in [
            "twinvpn.correlation_id",
            "twinvpn.causation_id",
            "twinvpn.message_id",
            "twinvpn.idempotency_key",
        ] {
            assert_eq!(verdict(k), KeyVerdict::Allowed, "{k}");
        }
    }

    #[test]
    fn the_tier2_tuple_is_exactly_seven_allowlisted_dimensions() {
        assert_eq!(TIER2_TUPLE.len(), 7);
        for k in TIER2_TUPLE {
            assert_eq!(verdict(k), KeyVerdict::Allowed, "{k}");
        }
        // ADR-0018 VR-2 consequence 3.
        assert!(!TIER2_TUPLE.contains(&"twinvpn.abi_major"));
        assert!(!TIER2_TUPLE.contains(&"twinvpn.abi_minor"));
    }

    #[test]
    fn every_named_constant_is_allowlisted() {
        for k in [
            SERVICE_NAME,
            COMPONENT,
            CORRELATION_ID,
            CAUSATION_ID,
            REASON_CODE,
            OUTCOME,
            DAY_BUCKET,
            HEALTH_STATE,
            OTEL_STATUS_CODE,
        ] {
            assert_eq!(verdict(k.as_str()), KeyVerdict::Allowed, "{k}");
        }
    }

    #[test]
    fn no_key_is_both_allowed_and_forbidden() {
        for k in ALLOWED_KEYS {
            assert!(!FORBIDDEN_KEYS.contains(k), "{k} is in both lists");
        }
    }
}
