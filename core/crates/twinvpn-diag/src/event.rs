//! Emission of the **local, device-authoritative** session events.
//!
//! **Authority:** `contracts/docs/contract-matrix.md` §4.4,
//! `contracts/proto/twinvpn/v1/diagnostics.proto`'s file header, ADR-0015 §11.3
//! and §11.4, `docs/protocol.md` §7.
//!
//! # These are not control-plane events, and this module is where that is kept
//! true
//!
//! `contracts/docs/contract-matrix.md` §4.4 lists fourteen bodies —
//! `ConnectionRequested`, `ConnectionNegotiated`, `CandidateUpdated`,
//! `DirectPathEstablished`, `RelayBindRequested`, `RelayBound`,
//! `RelayUnavailable`, `RelayChanged`, `SessionStarted`, `SessionResumed`,
//! `SessionEnded`, `PathChanged`, `TunnelStateChanged`,
//! `ConnectionHealthChanged` — and says of all of them that they are
//! *device-authoritative, ephemeral, Tier-0 local ledger*. `diagnostics.proto`'s
//! header says why: if the coordination service were authoritative for `Session`
//! state, a control-plane outage would eventually tear tunnels down.
//!
//! This crate therefore has **no dependency on `twinvpn-cp-client`** and no way
//! to acquire one: `twinvpn-diag` sits above the composition root in ADR-0018
//! §11.7's arrows and names neither plane. An emitter that wanted to publish one
//! of these on C2 would have to add the dependency, and `cargo run -p xtask --
//! lint` is what stops that.
//!
//! # Correlation is carried, never invented
//!
//! `ownership.md` §6 rule 6 requires `correlation_id` and `causation_id` to be
//! preserved across every component boundary. [`Emitter`] takes them as explicit
//! parameters and copies them into every `DiagnosticContext` it builds; it never
//! mints one, because a correlation id minted at the point of emission correlates
//! a record with nothing.

use prost::Message as _;
use twinvpn_env::MonotonicInstant;
use twinvpn_schema::v1;
use twinvpn_types::{
    CausationId, Component, CorrelationId, Diagnostic, EvidenceValue, Identifier, PathId, SessionId,
};

use crate::redact::{redact, Pseudonymizer, RedactedValue};
use crate::tier::Tier;

/// The correlation pair every emitted record carries.
///
/// Both halves are optional because not every local observation answers a
/// message — a link-down notification from the OS has no causing message — but
/// where one exists it is carried, never dropped and never regenerated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Correlation {
    /// The `message_id` that started the chain this record belongs to.
    pub correlation_id: Option<CorrelationId>,
    /// The `message_id` that directly caused this record.
    pub causation_id: Option<CausationId>,
}

/// Builds the frozen wire forms of local diagnostics and session events.
///
/// Stateless apart from the component identity it stamps, so it is cheap to hold
/// one per component and there is no shared mutable emitter to serialize on.
#[derive(Debug, Clone, Copy)]
pub struct Emitter {
    component: Component,
    tier: Tier,
}

impl Emitter {
    /// An emitter for one component, writing at one tier.
    #[must_use]
    pub const fn new(component: Component, tier: Tier) -> Self {
        Self { component, tier }
    }

    /// The component this emitter stamps.
    #[must_use]
    pub const fn component(&self) -> Component {
        self.component
    }

    /// The tier it writes at.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        self.tier
    }

    /// Builds a `DiagnosticContext` for one observation.
    ///
    /// `pseudonyms` is `Some` exactly when the tier is [`Tier::Bundle`]; at
    /// [`Tier::Aggregate`] the identifiers are emitted **empty**, which is what
    /// `diagnostics.proto` requires in terms ("In `OBSERVABILITY_TIER_AGGREGATE`
    /// both MUST be empty").
    #[must_use]
    // Eight parameters, and every one is a fact the emitter cannot invent: the
    // two identifiers, the state, the observation instant, the correlation pair,
    // the evidence, and the pseudonym mapping. Bundling them into a struct would
    // add a type whose only job is to be destructured here, and would let a
    // caller build a half-filled one — which is the CD-2 failure this signature
    // exists to prevent.
    #[allow(clippy::too_many_arguments)]
    pub fn context(
        &self,
        session_id: Option<SessionId>,
        path_id: Option<PathId>,
        state: Option<twinvpn_types::ConnectionState>,
        observed_at: MonotonicInstant,
        correlation: Correlation,
        evidence: &[twinvpn_types::Evidence],
        mut pseudonyms: Option<&mut Pseudonymizer>,
    ) -> v1::DiagnosticContext {
        let ids_allowed = self.tier != Tier::Aggregate;
        let session_bytes = if ids_allowed {
            session_id
                .map(|s| self.identifier_bytes(s.as_bytes(), "session", pseudonyms.as_deref_mut()))
        } else {
            None
        };
        let path_bytes = if ids_allowed {
            path_id.map(|p| self.identifier_bytes(p.as_bytes(), "path", pseudonyms.as_deref_mut()))
        } else {
            None
        };

        let mut out_evidence = Vec::with_capacity(evidence.len());
        for e in evidence {
            let r = redact(e, self.tier, pseudonyms.as_deref_mut());
            let Some(value) = r.value else { continue };
            out_evidence.push(encode_evidence(r.key, r.classification, &value));
        }

        v1::DiagnosticContext {
            tier: self.tier.to_wire(),
            session_id: session_bytes.unwrap_or_default(),
            path_id: path_bytes.unwrap_or_default(),
            // Correlation ids are `SENSITIVE` and local-only (ADR-0015 §11.3
            // marks `correlation_id` "never transmitted off-device"), so they are
            // carried whole in Tier 0 and dropped entirely above it rather than
            // pseudonymized: a token would still be a join key across records in
            // a shared bundle.
            correlation_id: if self.tier == Tier::LocalLedger {
                correlation
                    .correlation_id
                    .map(|c| c.as_bytes().to_vec())
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            causation_id: if self.tier == Tier::LocalLedger {
                correlation
                    .causation_id
                    .map(|c| c.as_bytes().to_vec())
                    .unwrap_or_default()
            } else {
                Vec::new()
            },
            state: state.map_or(0, twinvpn_types::ConnectionState::to_wire),
            component: self.component.to_wire(),
            observed_at: Some(v1::MonotonicMicros {
                value: observed_at.as_micros(),
            }),
            evidence: out_evidence,
        }
    }

    /// An identifier, pseudonymized where the tier requires it.
    fn identifier_bytes(
        self,
        bytes: &[u8],
        kind: &'static str,
        pseudonyms: Option<&mut Pseudonymizer>,
    ) -> Vec<u8> {
        match self.tier {
            Tier::LocalLedger => bytes.to_vec(),
            // A bundle carries the *token*, as UTF-8, in the same field. The
            // field is `bytes`, so this is representable without a schema change,
            // and a reader can tell the two apart because a real identifier is a
            // fixed width the token never is.
            Tier::Bundle => pseudonyms
                .map(|p| p.token(kind, &hex(bytes)).into_bytes())
                .unwrap_or_default(),
            Tier::Aggregate => Vec::new(),
        }
    }

    /// Wraps one of §4.4's bodies as a `SessionEvent`.
    #[must_use]
    pub fn session_event(
        &self,
        session_id: Option<SessionId>,
        context: v1::DiagnosticContext,
        body: v1::session_event::Event,
    ) -> v1::SessionEvent {
        v1::SessionEvent {
            session_id: if self.tier == Tier::Aggregate {
                Vec::new()
            } else {
                context.session_id.clone()
            },
            context: Some(context),
            event: Some(body),
        }
        .with_session_fallback(session_id, self.tier)
    }

    /// Encodes a `Diagnostic` into its frozen `ErrorEnvelope` form, with this
    /// tier's redaction already applied.
    #[must_use]
    pub fn error_envelope(
        &self,
        diagnostic: &Diagnostic,
        mut pseudonyms: Option<&mut Pseudonymizer>,
    ) -> v1::ErrorEnvelope {
        let mut envelope = twinvpn_schema::envelope::encode(diagnostic);
        envelope.evidence.clear();
        for e in diagnostic.evidence().entries() {
            let r = redact(e, self.tier, pseudonyms.as_deref_mut());
            let Some(value) = r.value else { continue };
            envelope
                .evidence
                .push(encode_evidence(r.key, r.classification, &value));
        }
        if self.tier != Tier::LocalLedger {
            // §11.3 marks `correlation_id` "never transmitted off-device".
            envelope.correlation_id = Vec::new();
        }
        envelope
    }
}

trait SessionFallback {
    fn with_session_fallback(self, session_id: Option<SessionId>, tier: Tier) -> Self;
}

impl SessionFallback for v1::SessionEvent {
    /// `SessionEvent.session_id` mirrors the context's. Where the context could
    /// not carry one (no pseudonymizer at bundle tier), the event does not
    /// invent one either — an event whose two identifier fields disagree is
    /// worse than one that carries neither.
    fn with_session_fallback(mut self, session_id: Option<SessionId>, tier: Tier) -> Self {
        if self.session_id.is_empty() && tier == Tier::LocalLedger {
            if let Some(s) = session_id {
                self.session_id = s.as_bytes().to_vec();
            }
        }
        self
    }
}

fn encode_evidence(
    key: &'static str,
    classification: twinvpn_types::FieldClassification,
    value: &RedactedValue,
) -> v1::Evidence {
    let mut out = v1::Evidence {
        key: key.to_owned(),
        classification: classification as i32,
        value: None,
    };
    out.value = Some(match value {
        RedactedValue::Pseudonym(t) => v1::evidence::Value::StringValue(t.clone()),
        RedactedValue::Bucket(t) => v1::evidence::Value::StringValue((*t).to_owned()),
        RedactedValue::Typed(v) => match v {
            EvidenceValue::Text(s) => v1::evidence::Value::StringValue(s.clone()),
            EvidenceValue::Int(n) => v1::evidence::Value::IntValue(*n),
            EvidenceValue::Uint(n) => v1::evidence::Value::UintValue(*n),
            EvidenceValue::Bool(b) => v1::evidence::Value::BoolValue(*b),
            EvidenceValue::Address(a) => {
                v1::evidence::Value::AddressValue(twinvpn_schema::envelope::encode_address(*a))
            }
            EvidenceValue::Prefix(p) => v1::evidence::Value::PrefixValue(v1::IpPrefix {
                address: Some(twinvpn_schema::envelope::encode_address(p.address())),
                prefix_len: p.prefix_len(),
            }),
            EvidenceValue::Family(f) => v1::evidence::Value::FamilyValue(match f {
                twinvpn_types::AddressFamily::V4 => 1,
                twinvpn_types::AddressFamily::V6 => 2,
            }),
            EvidenceValue::DurationMs(ms) => v1::evidence::Value::DurationMsValue(*ms),
        },
    });
    out
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Encodes a `SessionEvent` for the ledger or a bundle.
#[must_use]
pub fn encode(event: &v1::SessionEvent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(event.encoded_len());
    event.encode(&mut buf).expect("a Vec never fails to grow");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{codes, Evidence, IpAddr, V4Addr};

    fn session() -> SessionId {
        SessionId::from_slice(&[9u8; 16]).expect("16 bytes")
    }

    fn sensitive() -> Evidence {
        Evidence::new(
            codes::ROUTE_ADDRESS_COLLISION,
            "address",
            EvidenceValue::Address(IpAddr::V4(
                V4Addr::from_slice(&[198, 51, 100, 4]).expect("v4"),
            )),
        )
        .expect("declared")
    }

    #[test]
    fn tier_two_carries_no_identifier_at_all() {
        let e = Emitter::new(Component::TunnelEngine, Tier::Aggregate);
        let ctx = e.context(
            Some(session()),
            None,
            None,
            MonotonicInstant::from_micros(1),
            Correlation::default(),
            &[sensitive()],
            None,
        );
        assert!(ctx.session_id.is_empty());
        assert!(ctx.path_id.is_empty());
        assert!(ctx.correlation_id.is_empty());
        assert!(
            ctx.evidence.is_empty(),
            "a SENSITIVE address must never reach Tier 2"
        );
    }

    #[test]
    fn a_bundle_pseudonymizes_the_session_identifier() {
        let e = Emitter::new(Component::TunnelEngine, Tier::Bundle);
        let mut p = Pseudonymizer::with_salt([3; 16]);
        let ctx = e.context(
            Some(session()),
            None,
            None,
            MonotonicInstant::from_micros(1),
            Correlation::default(),
            &[],
            Some(&mut p),
        );
        assert_ne!(ctx.session_id, session().as_bytes().to_vec());
        assert_eq!(
            String::from_utf8(ctx.session_id).expect("utf8"),
            "session-1"
        );
    }

    #[test]
    fn tier_zero_carries_correlation_and_the_real_identifier() {
        let e = Emitter::new(Component::TunnelEngine, Tier::LocalLedger);
        let corr = Correlation {
            correlation_id: Some(CorrelationId::from_slice(&[1u8; 16]).expect("16")),
            causation_id: Some(CausationId::from_slice(&[2u8; 16]).expect("16")),
        };
        let ctx = e.context(
            Some(session()),
            None,
            None,
            MonotonicInstant::from_micros(7),
            corr,
            &[sensitive()],
            None,
        );
        assert_eq!(ctx.session_id, session().as_bytes().to_vec());
        assert_eq!(ctx.correlation_id.len(), 16);
        assert_eq!(ctx.causation_id.len(), 16);
        assert_eq!(ctx.evidence.len(), 1);
        assert_eq!(ctx.observed_at.expect("stamped").value, 7);
    }

    #[test]
    fn correlation_never_leaves_the_device() {
        let e = Emitter::new(Component::TunnelEngine, Tier::Bundle);
        let mut p = Pseudonymizer::with_salt([3; 16]);
        let corr = Correlation {
            correlation_id: Some(CorrelationId::from_slice(&[1u8; 16]).expect("16")),
            causation_id: Some(CausationId::from_slice(&[2u8; 16]).expect("16")),
        };
        let ctx = e.context(
            None,
            None,
            None,
            MonotonicInstant::from_micros(1),
            corr,
            &[],
            Some(&mut p),
        );
        assert!(ctx.correlation_id.is_empty());
        assert!(ctx.causation_id.is_empty());
    }

    #[test]
    fn a_session_event_round_trips_through_the_frozen_encoding() {
        let e = Emitter::new(Component::TunnelEngine, Tier::LocalLedger);
        let ctx = e.context(
            Some(session()),
            None,
            None,
            MonotonicInstant::from_micros(1),
            Correlation::default(),
            &[],
            None,
        );
        let ev = e.session_event(
            Some(session()),
            ctx,
            v1::session_event::Event::ConnectionRequested(v1::ConnectionRequested {
                peer_device_id: vec![4u8; 32],
                trigger: "user".to_owned(),
            }),
        );
        let bytes = encode(&ev);
        let back = <v1::SessionEvent as prost::Message>::decode(&bytes[..]).expect("decodes");
        assert_eq!(back, ev);
    }
}
