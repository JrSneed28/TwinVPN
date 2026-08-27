//! `correlation_id` and `causation_id`, preserved across every hop.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/common.proto` `MessageMetadata`,
//! `docs/implementation/ownership.md` §6 rule 6 ("Preserve `correlation_id` and
//! `causation_id` across every component boundary"), `infra/README.md` §6.3
//! ("Correlation and causation, across every hop"), ADR-0015 O-13 (the relay is
//! the one exception, and the severing is the collector's job, not a relay's).
//!
//! # The two ids are different facts
//!
//! `common.proto` is precise, and getting this wrong quietly destroys a causal
//! chain:
//!
//! > `correlation_id` answers "what is this a reply to"; `causation_id` answers
//! > "what made this happen". … Set by the emitter from the message it is
//! > currently processing. **Never invented, never inherited transitively** — a
//! > causation chain is reconstructed by following one link at a time, which is
//! > what keeps it a chain rather than a claim.
//!
//! [`Correlation::reply_to`] and [`Correlation::caused_by`] are therefore two
//! different methods with two different results, and neither one copies the
//! other's field. [`Correlation::derive_consequence`] is the second-order case
//! `common.proto`'s worked example describes: a route withdrawal triggered by
//! processing a `DeviceRevoked` carries the revocation event's id in
//! `causation_id` and **no** `correlation_id` at all.
//!
//! # Why there is a task-local
//!
//! A service that has to thread a `Correlation` through every call will
//! eventually not. [`scope`] binds one for the duration of a future and
//! [`current`] reads it, so an error raised four layers down still carries the
//! ids. The span fields recorded by [`Correlation::record_on_current_span`] are
//! then inherited by every event inside that span
//! (`crate::obs::layer::RedactingLayer` walks the span scope), which is the
//! mechanism that makes "a service cannot accidentally drop them" true.
//!
//! # A note on the *other* `correlation_id`
//!
//! ADR-0015 §11.3 has a `correlation_id` classified `SENSITIVE` that "never
//! leaves the device". That is the **local ledger's** incident id and is a
//! different fact from the wire linkage here, which is already on the wire and
//! therefore leaks nothing new (`errors.proto`, and `infra/README.md` §6.3 say
//! so explicitly). Only the wire one is allowlisted and only the wire one is
//! modelled in this crate.

use std::future::Future;

use twinvpn_schema::v1;
use twinvpn_schema::Reject;
use twinvpn_types::{CausationId, CorrelationId, IdempotencyKey, Identifier, MessageId};

use crate::redact::{hex_decode_bounded, hex_lower};

/// HTTP header carrying `MessageMetadata.correlation_id`, lowercase hex.
pub const HEADER_CORRELATION_ID: &str = "x-twinvpn-correlation-id";
/// HTTP header carrying `MessageMetadata.causation_id`, lowercase hex.
pub const HEADER_CAUSATION_ID: &str = "x-twinvpn-causation-id";
/// HTTP header carrying `MessageMetadata.message_id`, lowercase hex.
pub const HEADER_MESSAGE_ID: &str = "x-twinvpn-message-id";

/// The protocol correlation carried by one message.
///
/// The field names are `common.proto`'s, verbatim. `clippy::struct_field_names`
/// would have `correlation_id` renamed because it repeats the type name; the
/// wire contract wins over the lint, because a field called `id` here would
/// stop matching the schema it exists to carry.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Correlation {
    message_id: Option<MessageId>,
    correlation_id: Option<CorrelationId>,
    causation_id: Option<CausationId>,
    idempotency_key: Option<IdempotencyKey>,
}

impl Correlation {
    /// An empty correlation — an origin message that answers nothing and was
    /// caused by nothing this process observed.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            message_id: None,
            correlation_id: None,
            causation_id: None,
            idempotency_key: None,
        }
    }

    /// Reads the four fields out of a received `MessageMetadata`.
    ///
    /// Every width is validated by the `twinvpn-types` constructor before the
    /// value is retained, so a 4 KiB `correlation_id` on the wire is a typed
    /// reject rather than a stored blob (`ownership.md` §6 rule 9). An **absent**
    /// field is absent; only a present-but-wrong-width field is a reject.
    ///
    /// # Errors
    ///
    /// [`Reject::Malformed`] naming the `limits.json` key that was violated.
    pub fn from_metadata(md: &v1::MessageMetadata) -> Result<Self, Reject> {
        fn opt<T: Identifier>(
            bytes: &[u8],
            key: &'static str,
            f: impl Fn(&[u8]) -> Result<T, twinvpn_types::TypeError>,
        ) -> Result<Option<T>, Reject> {
            if bytes.is_empty() {
                return Ok(None);
            }
            f(bytes).map(Some).map_err(|e| Reject::malformed(key, e))
        }

        Ok(Self {
            message_id: opt(&md.message_id, "message_id_bytes", MessageId::from_slice)?,
            correlation_id: opt(
                &md.correlation_id,
                "correlation_id_bytes",
                CorrelationId::from_slice,
            )?,
            causation_id: opt(
                &md.causation_id,
                "causation_id_bytes",
                CausationId::from_slice,
            )?,
            idempotency_key: opt(
                &md.idempotency_key,
                "idempotency_key_max_bytes",
                IdempotencyKey::from_slice,
            )?,
        })
    }

    /// Writes the four fields onto an outgoing `MessageMetadata`.
    ///
    /// Only the four correlation fields are touched; `proto_version`,
    /// `twinnet_id`, `net_seq`, `causality_token` and `auth` belong to the
    /// service and are left exactly as they were.
    pub fn apply_to_metadata(&self, md: &mut v1::MessageMetadata) {
        md.message_id = self
            .message_id
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        md.correlation_id = self
            .correlation_id
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        md.causation_id = self
            .causation_id
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        md.idempotency_key = self
            .idempotency_key
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
    }

    /// The id of the message this correlation describes.
    #[must_use]
    pub const fn message_id(&self) -> Option<MessageId> {
        self.message_id
    }
    /// What this message is a reply to.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<CorrelationId> {
        self.correlation_id
    }
    /// What made this message happen.
    #[must_use]
    pub const fn causation_id(&self) -> Option<CausationId> {
        self.causation_id
    }
    /// The caller's idempotency key, when the request carried one.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<IdempotencyKey> {
        self.idempotency_key
    }

    /// Sets this message's own id.
    #[must_use]
    pub const fn with_message_id(mut self, id: MessageId) -> Self {
        self.message_id = Some(id);
        self
    }

    /// Builds the correlation for a **direct response** to `self`.
    ///
    /// `common.proto`: "Responses MUST echo the request's `message_id`."
    /// `causation_id` is the same message here, because the request both
    /// prompted the reply and is what the reply answers.
    #[must_use]
    pub fn reply_to(&self, response_message_id: MessageId) -> Self {
        let request = self.message_id;
        Self {
            message_id: Some(response_message_id),
            correlation_id: request.and_then(|m| CorrelationId::from_slice(m.as_bytes()).ok()),
            causation_id: request.and_then(|m| CausationId::from_slice(m.as_bytes()).ok()),
            // An idempotency key belongs to the request, never to the response.
            idempotency_key: None,
        }
    }

    /// Builds the correlation for a message emitted **while processing** `self`
    /// that is not a reply to it.
    ///
    /// This is `common.proto`'s worked second-order case: "a route withdrawal
    /// triggered by processing a `DeviceRevoked` carries the revocation event's
    /// id in `causation_id` and **no** `correlation_id` at all". Setting
    /// `correlation_id` here would assert a reply relationship that does not
    /// exist.
    #[must_use]
    pub fn derive_consequence(&self, new_message_id: MessageId) -> Self {
        Self {
            message_id: Some(new_message_id),
            correlation_id: None,
            causation_id: self
                .message_id
                .and_then(|m| CausationId::from_slice(m.as_bytes()).ok()),
            idempotency_key: None,
        }
    }

    /// Marks `self` as caused by `cause`, without claiming it answers it.
    ///
    /// Deliberately takes the *causing message's* id rather than the causing
    /// message's own `causation_id`: "never inherited transitively".
    #[must_use]
    pub fn caused_by(mut self, cause: MessageId) -> Self {
        self.causation_id = CausationId::from_slice(cause.as_bytes()).ok();
        self
    }

    /// Records the ids as fields on `span`.
    ///
    /// The span must have been created with these fields declared as
    /// `tracing::field::Empty`, which is what `#[instrument]` and
    /// [`request_span`] do.
    pub fn record_on(&self, span: &tracing::Span) {
        if let Some(v) = self.correlation_id {
            span.record("twinvpn.correlation_id", hex_lower(v.as_bytes()));
        }
        if let Some(v) = self.causation_id {
            span.record("twinvpn.causation_id", hex_lower(v.as_bytes()));
        }
        if let Some(v) = self.message_id {
            span.record("twinvpn.message_id", hex_lower(v.as_bytes()));
        }
    }

    /// Records the ids on the current span.
    pub fn record_on_current_span(&self) {
        self.record_on(&tracing::Span::current());
    }

    /// Renders the three ids as HTTP headers, for the hops that are HTTP.
    ///
    /// Only the four allowlisted correlation attributes are ever rendered;
    /// `idempotency_key` is not put in a header because it is a request-scoped
    /// authorization-adjacent value that ADR-0008 §7.3 keeps scoped to the
    /// authenticated caller, and a header is a place it would be copied.
    #[must_use]
    pub fn to_headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::with_capacity(3);
        if let Some(v) = self.message_id {
            out.push((HEADER_MESSAGE_ID, hex_lower(v.as_bytes())));
        }
        if let Some(v) = self.correlation_id {
            out.push((HEADER_CORRELATION_ID, hex_lower(v.as_bytes())));
        }
        if let Some(v) = self.causation_id {
            out.push((HEADER_CAUSATION_ID, hex_lower(v.as_bytes())));
        }
        out
    }

    /// Reads the ids back out of headers.
    ///
    /// A malformed or over-long header value yields `None` for that field rather
    /// than an error: a correlation is diagnostic linkage, and refusing a
    /// request because a *header* was malformed would let an attacker turn a
    /// header into a denial of service. The bound is enforced before any
    /// allocation ([`hex_decode_bounded`]).
    #[must_use]
    pub fn from_headers(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let get16 = |name: &str| lookup(name).and_then(|v| hex_decode_bounded(&v, 16));
        Self {
            message_id: get16(HEADER_MESSAGE_ID).and_then(|b| MessageId::from_slice(&b).ok()),
            correlation_id: get16(HEADER_CORRELATION_ID)
                .and_then(|b| CorrelationId::from_slice(&b).ok()),
            causation_id: get16(HEADER_CAUSATION_ID).and_then(|b| CausationId::from_slice(&b).ok()),
            idempotency_key: None,
        }
    }
}

tokio::task_local! {
    static CURRENT: Correlation;
}

/// Runs `fut` with `correlation` bound as the ambient correlation.
pub async fn scope<F: Future>(correlation: Correlation, fut: F) -> F::Output {
    CURRENT.scope(correlation, fut).await
}

/// The ambient correlation, or [`Correlation::empty`] outside a [`scope`].
#[must_use]
pub fn current() -> Correlation {
    CURRENT
        .try_with(|c| *c)
        .unwrap_or_else(|_| Correlation::empty())
}

/// Creates a request span with the three correlation fields declared and
/// recorded.
///
/// Every event emitted inside this span inherits the fields, which is what makes
/// the ids survive a hop without each handler remembering to attach them.
#[must_use]
pub fn request_span(name: &'static str, correlation: &Correlation) -> tracing::Span {
    let span = tracing::info_span!(
        "twinvpn.request",
        otel.name = name,
        twinvpn.correlation_id = tracing::field::Empty,
        twinvpn.causation_id = tracing::field::Empty,
        twinvpn.message_id = tracing::field::Empty,
    );
    correlation.record_on(&span);
    span
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(b: u8) -> MessageId {
        MessageId::from_slice(&[b; 16]).expect("16 bytes")
    }

    #[test]
    fn correlation_survives_a_metadata_round_trip() {
        let c = Correlation::empty()
            .with_message_id(mid(1))
            .reply_to(mid(2));
        let mut md = v1::MessageMetadata {
            proto_version: 1,
            ..Default::default()
        };
        c.apply_to_metadata(&mut md);
        // Fields the correlation does not own are untouched.
        assert_eq!(md.proto_version, 1);

        let back = Correlation::from_metadata(&md).expect("valid");
        assert_eq!(back, c);
    }

    #[test]
    fn a_reply_echoes_the_request_id_in_both_fields() {
        let request = Correlation::empty().with_message_id(mid(7));
        let reply = request.reply_to(mid(9));
        assert_eq!(reply.message_id(), Some(mid(9)));
        assert_eq!(
            reply.correlation_id().unwrap().as_bytes(),
            mid(7).as_bytes()
        );
        assert_eq!(reply.causation_id().unwrap().as_bytes(), mid(7).as_bytes());
    }

    #[test]
    fn a_second_order_consequence_has_causation_and_no_correlation() {
        // common.proto's worked example: a route withdrawal triggered by
        // processing a DeviceRevoked.
        let revocation = Correlation::empty().with_message_id(mid(3));
        let withdrawal = revocation.derive_consequence(mid(4));
        assert_eq!(withdrawal.correlation_id(), None, "not a reply to anything");
        assert_eq!(
            withdrawal.causation_id().unwrap().as_bytes(),
            mid(3).as_bytes()
        );
    }

    #[test]
    fn causation_is_never_inherited_transitively() {
        let a = Correlation::empty().with_message_id(mid(1));
        let b = a.derive_consequence(mid(2));
        let c = b.derive_consequence(mid(3));
        // c's causation is b, not a. One link at a time.
        assert_eq!(c.causation_id().unwrap().as_bytes(), mid(2).as_bytes());
    }

    #[test]
    fn a_wrong_width_correlation_id_is_a_typed_reject() {
        let md = v1::MessageMetadata {
            correlation_id: vec![0u8; 31],
            ..Default::default()
        };
        let e = Correlation::from_metadata(&md).expect_err("must reject");
        assert_eq!(
            e.reason_code(),
            twinvpn_types::codes::PROTO_MALFORMED_MESSAGE
        );
    }

    #[test]
    fn an_absent_field_is_absent_not_an_error() {
        let md = v1::MessageMetadata::default();
        assert_eq!(
            Correlation::from_metadata(&md).unwrap(),
            Correlation::empty()
        );
    }

    #[test]
    fn correlation_survives_an_http_header_round_trip() {
        let c = Correlation::empty()
            .with_message_id(mid(0xab))
            .reply_to(mid(0xcd));
        let headers = c.to_headers();
        let back = Correlation::from_headers(|name| {
            headers
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
        });
        assert_eq!(back.message_id(), c.message_id());
        assert_eq!(back.correlation_id(), c.correlation_id());
        assert_eq!(back.causation_id(), c.causation_id());
    }

    #[test]
    fn a_hostile_header_yields_none_rather_than_an_allocation() {
        let back = Correlation::from_headers(|_| Some("ff".repeat(100_000)));
        assert_eq!(back, Correlation::empty());
    }

    #[tokio::test]
    async fn the_ambient_correlation_reaches_a_nested_call() {
        fn deep() -> Correlation {
            current()
        }
        let c = Correlation::empty().with_message_id(mid(5));
        let seen = scope(c, async { deep() }).await;
        assert_eq!(seen, c);
        assert_eq!(current(), Correlation::empty(), "no leak outside the scope");
    }

    #[test]
    fn the_idempotency_key_is_not_copied_onto_a_response() {
        let mut md = v1::MessageMetadata {
            message_id: vec![1u8; 16],
            idempotency_key: vec![9u8; 16],
            ..Default::default()
        };
        let request = Correlation::from_metadata(&md).unwrap();
        assert!(request.idempotency_key().is_some());
        let reply = request.reply_to(mid(2));
        assert!(reply.idempotency_key().is_none());
        md.idempotency_key.clear();
        assert!(Correlation::from_metadata(&md)
            .unwrap()
            .idempotency_key()
            .is_none());
    }
}
