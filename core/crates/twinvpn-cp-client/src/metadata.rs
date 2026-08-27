//! The C1/C2 envelope: minting outbound `MessageMetadata`, and validating
//! inbound.
//!
//! **Authority:** `docs/protocol.md` §2 (the envelope and its normative field
//! rules), §3 (Rule A / Rule B), §5.2 (`causality_token` is echoed, never
//! parsed), `contracts/proto/twinvpn/v1/common.proto`,
//! `contracts/docs/identifiers.md`, ADR-0002 N-2, ADR-0014 §11.1 V-3.
//!
//! # The four rules this module makes mechanical
//!
//! 1. **`message_id` is unique per *emission*, `idempotency_key` is stable per
//!    *operation*.** That separation is what lets a support bundle distinguish
//!    "the client retried once" from "the network duplicated it". A fresh
//!    `message_id` is minted on every call to [`MetadataFactory::mint`],
//!    including retries.
//! 2. **`proto_version` is fixed for the life of the connection** (ADR-0014 V-3),
//!    so it is a field of the factory, not a parameter of each call.
//! 3. **`causality_token` is opaque.** The factory takes bytes and emits bytes;
//!    `twinvpn_types::CausalityToken` exposes only `octets_to_echo`, so there is
//!    no accessor inviting a device to look inside.
//! 4. **`channel_binding` is verified against our own exporter**, and a mismatch
//!    is `CONTROL.CHANNEL_BINDING_MISMATCH` — "a security event, never a parse
//!    error".
//!
//! # `correlation_id` versus `causation_id`
//!
//! `common.proto`: *"`correlation_id` answers 'what is this a reply to';
//! `causation_id` answers 'what made this happen'."* They differ whenever a
//! message is a second-order consequence, and this crate preserves both across
//! every boundary (`ownership.md` §6 rule 6).

use twinvpn_env::{ConsumerId, Env};
use twinvpn_schema::v1;
use twinvpn_types::{ChannelBinding, Identifier, MessageId, TwinnetId};

use crate::error::{CpError, CpResult};
use crate::idempotency::MESSAGE_ID_STREAM;

/// The causal links a message carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct Causality {
    /// The `message_id` this responds to. `None` on an origin message.
    pub correlation_id: Option<MessageId>,
    /// The `message_id` whose *processing* produced this one.
    ///
    /// Set by the emitter from the message it is currently processing.
    /// **Never invented, never inherited transitively** — a causation chain is
    /// reconstructed one link at a time, which is what keeps it a chain rather
    /// than a claim.
    pub causation_id: Option<MessageId>,
}

/// Mints envelope metadata for one control connection.
///
/// Holds the two facts that are constant for the connection's life and nothing
/// that is not.
pub struct MetadataFactory {
    env: Env,
    proto_version: u32,
    twinnet_id: TwinnetId,
    sender_id: String,
    message_id_stream: ConsumerId,
}

impl MetadataFactory {
    /// Binds a factory to one connection.
    ///
    /// `sender_id` is the device's `"twd1…"` text form — `DeviceId::text_form()`
    /// — or, for infrastructure, one of the fixed principals. It is a
    /// presentation form, and `common.proto` allows it in exactly this field.
    #[must_use]
    pub fn new(env: Env, proto_version: u32, twinnet_id: TwinnetId, sender_id: String) -> Self {
        Self {
            env,
            proto_version,
            twinnet_id,
            sender_id,
            message_id_stream: MESSAGE_ID_STREAM,
        }
    }

    /// The connection's fixed control-plane API epoch.
    #[must_use]
    pub const fn proto_version(&self) -> u32 {
        self.proto_version
    }

    /// Mints one envelope. A **fresh `message_id` every call**, retries included.
    ///
    /// `sender_time_ms` is filled from the wall clock only when it has resolved:
    /// CD-1a's `Unset` state carries no timestamp, and the field is advisory
    /// anyway — `common.proto` forbids it as a guard, so an absent value costs
    /// nothing and a fabricated 1970 costs a misleading support bundle.
    ///
    /// # Errors
    ///
    /// [`CpError::Env`] if the entropy behind the `message_id` stream fails.
    pub fn mint(
        &self,
        causality: Causality,
        causality_token: Option<&[u8]>,
        idempotency_key: Option<&[u8]>,
        channel_binding: &ChannelBinding,
    ) -> CpResult<v1::MessageMetadata> {
        let mut rng = self.env.rng_for(self.message_id_stream)?;
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);

        Ok(v1::MessageMetadata {
            proto_version: self.proto_version,
            message_id: id.to_vec(),
            correlation_id: causality
                .correlation_id
                .map(|c| c.as_bytes().to_vec())
                .unwrap_or_default(),
            causation_id: causality
                .causation_id
                .map(|c| c.as_bytes().to_vec())
                .unwrap_or_default(),
            causality_token: causality_token.map(<[u8]>::to_vec).unwrap_or_default(),
            sender_time_ms: wall_millis(&self.env).unwrap_or(0),
            twinnet_id: self.twinnet_id.as_str().to_owned(),
            sender_id: self.sender_id.clone(),
            // NON-ZERO ONLY on a durable C2 event. A device never mints one.
            net_seq: 0,
            idempotency_key: idempotency_key.map(<[u8]>::to_vec).unwrap_or_default(),
            auth: Some(v1::Auth {
                // Rule A: channel-authenticated. The per-message signature is
                // attached separately by the signer for the Rule B carriers.
                channel_binding: channel_binding.as_bytes().to_vec(),
                ..Default::default()
            }),
        })
    }
}

/// The wall clock as advisory milliseconds, or `None` when it has not resolved.
fn wall_millis(env: &Env) -> Option<u64> {
    match env.now_wall() {
        twinvpn_env::WallClockReading::Unset => None,
        twinvpn_env::WallClockReading::Offset { millis, .. }
        | twinvpn_env::WallClockReading::Trusted { millis } => Some(millis.as_millis()),
    }
}

/// What an inbound envelope told us, once validated.
#[derive(Debug, Clone)]
pub struct InboundMetadata {
    /// The emitter's `message_id`.
    pub message_id: MessageId,
    /// The `message_id` this answers, if any.
    pub correlation_id: Option<MessageId>,
    /// The durable log position. Non-zero only on a durable C2 event.
    pub net_seq: u64,
    /// The newest `causality_token` for this `TwinNet`, to store and echo.
    pub causality_token: Option<Vec<u8>>,
    /// The scope.
    pub twinnet_id: TwinnetId,
}

/// Validates an inbound envelope, including the channel binding.
///
/// Every field is validated against `limits.json` **before** anything
/// proportional to a declared length is allocated — the widths are the exact ones
/// `contracts/docs/identifiers.md` §5 requires, and a length mismatch is a reject
/// rather than a truncation or a pad.
///
/// # Errors
///
/// [`CpError::ChannelBindingMismatch`] — a **security event** — when
/// `Auth.channel_binding` does not match our own exporter, and
/// [`CpError::Rejected`] for any width, cap or scope violation.
pub fn validate_inbound(
    metadata: &v1::MessageMetadata,
    local_binding: &ChannelBinding,
    expected_twinnet: &TwinnetId,
) -> CpResult<InboundMetadata> {
    use twinvpn_schema::validate;

    let twinnet_id = validate::twinnet_id(&metadata.twinnet_id)?;
    if twinnet_id.as_str() != expected_twinnet.as_str() {
        // "Every message is TwinNet-scoped; there is no cross-TwinNet message."
        return Err(CpError::Rejected(twinvpn_schema::Reject::cap(
            "twinnet_id_max_bytes",
            twinnet_id.as_str().len(),
            expected_twinnet.as_str().len(),
        )));
    }

    let message_id = validate::message_id(&metadata.message_id)?;
    let correlation_id = if metadata.correlation_id.is_empty() {
        None
    } else {
        Some(validate::correlation_id(&metadata.correlation_id).map(|c| {
            // A CorrelationId and a MessageId are the same 16-byte width; the
            // caller wants the emitter-scoped form.
            MessageId::from_slice(c.as_bytes()).unwrap_or(message_id)
        })?)
    };

    let causality_token = if metadata.causality_token.is_empty() {
        None
    } else {
        // Validated BEFORE it allocates: the cap is checked against the slice
        // length, not against a declared one.
        Some(
            validate::causality_token(&metadata.causality_token)
                .map(|t| t.octets_to_echo().to_vec())?,
        )
    };

    // ADR-0002 N-2. Checked last only because the cheap shape checks bound the
    // work an attacker can drive; the verdict itself is never downgraded to a
    // parse error.
    let auth = metadata
        .auth
        .as_ref()
        .ok_or(CpError::ChannelBindingMismatch)?;
    let carried = validate::channel_binding(&auth.channel_binding)
        .map_err(|_| CpError::ChannelBindingMismatch)?;
    if !carried.verify_against(local_binding) {
        return Err(CpError::ChannelBindingMismatch);
    }

    Ok(InboundMetadata {
        message_id,
        correlation_id,
        net_seq: metadata.net_seq,
        causality_token,
        twinnet_id,
    })
}

#[cfg(test)]
mod tests {
    use super::{validate_inbound, Causality, MetadataFactory};
    use twinvpn_types::{ChannelBinding, Identifier, TwinnetId};

    fn binding(fill: u8) -> ChannelBinding {
        ChannelBinding::from_array([fill; 32])
    }

    fn factory() -> MetadataFactory {
        MetadataFactory::new(
            crate::testing::test_env(),
            7,
            TwinnetId::new("tn-alpha").expect("valid"),
            "twd1abc".to_owned(),
        )
    }

    #[test]
    fn a_retry_mints_a_fresh_message_id_but_keeps_the_idempotency_key() {
        let f = factory();
        let cb = binding(0x11);
        let key = [9u8; 32];
        let first = f
            .mint(Causality::default(), None, Some(&key), &cb)
            .expect("mint");
        let retry = f
            .mint(Causality::default(), None, Some(&key), &cb)
            .expect("mint");
        assert_ne!(
            first.message_id, retry.message_id,
            "message_id is unique per EMISSION"
        );
        assert_eq!(
            first.idempotency_key, retry.idempotency_key,
            "idempotency_key is stable per OPERATION"
        );
    }

    #[test]
    fn a_device_never_mints_a_net_seq() {
        let f = factory();
        let m = f
            .mint(Causality::default(), None, None, &binding(1))
            .expect("mint");
        assert_eq!(m.net_seq, 0, "net_seq is allocated by the log, not by us");
    }

    #[test]
    fn the_proto_version_is_fixed_for_the_connection() {
        let f = factory();
        let a = f
            .mint(Causality::default(), None, None, &binding(1))
            .expect("mint");
        let b = f
            .mint(Causality::default(), None, None, &binding(1))
            .expect("mint");
        assert_eq!(a.proto_version, 7);
        assert_eq!(b.proto_version, 7);
        assert_eq!(f.proto_version(), 7);
    }

    #[test]
    fn a_channel_binding_mismatch_is_a_security_event_not_a_parse_error() {
        let f = factory();
        let ours = binding(0xAA);
        let theirs = binding(0xBB);
        let m = f
            .mint(Causality::default(), None, None, &theirs)
            .expect("mint");
        let twinnet = TwinnetId::new("tn-alpha").expect("valid");
        let err = validate_inbound(&m, &ours, &twinnet).expect_err("must reject");
        assert_eq!(
            err.reason_code().as_str(),
            "CONTROL.CHANNEL_BINDING_MISMATCH"
        );
        assert!(err.is_security_event());
        assert!(err.reason_code().terminal());
    }

    #[test]
    fn a_matching_binding_and_scope_validates() {
        let f = factory();
        let cb = binding(0xAA);
        let m = f
            .mint(Causality::default(), Some(&[1, 2, 3]), None, &cb)
            .expect("mint");
        let twinnet = TwinnetId::new("tn-alpha").expect("valid");
        let inbound = validate_inbound(&m, &binding(0xAA), &twinnet).expect("valid");
        assert_eq!(inbound.causality_token.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(inbound.twinnet_id.as_str(), "tn-alpha");
    }

    #[test]
    fn a_cross_twinnet_message_is_rejected() {
        let f = factory();
        let cb = binding(0xAA);
        let m = f.mint(Causality::default(), None, None, &cb).expect("mint");
        let other = TwinnetId::new("tn-beta").expect("valid");
        assert!(validate_inbound(&m, &binding(0xAA), &other).is_err());
    }

    #[test]
    fn an_oversized_causality_token_is_rejected_before_it_allocates() {
        let f = factory();
        let cb = binding(0xAA);
        let mut m = f.mint(Causality::default(), None, None, &cb).expect("mint");
        m.causality_token = vec![0u8; twinvpn_schema::limits::CAUSALITY_TOKEN_MAX_BYTES + 1];
        let twinnet = TwinnetId::new("tn-alpha").expect("valid");
        let err = validate_inbound(&m, &binding(0xAA), &twinnet).expect_err("over cap");
        assert_eq!(err.reason_code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }

    #[test]
    fn a_wrong_width_message_id_is_rejected() {
        let f = factory();
        let cb = binding(0xAA);
        let mut m = f.mint(Causality::default(), None, None, &cb).expect("mint");
        m.message_id = vec![0u8; 15];
        let twinnet = TwinnetId::new("tn-alpha").expect("valid");
        assert!(validate_inbound(&m, &binding(0xAA), &twinnet).is_err());
    }

    #[test]
    fn causality_links_are_preserved_across_the_boundary() {
        use twinvpn_types::MessageId;
        let f = factory();
        let request = MessageId::from_array([3u8; 16]);
        let cause = MessageId::from_array([4u8; 16]);
        let m = f
            .mint(
                Causality {
                    correlation_id: Some(request),
                    causation_id: Some(cause),
                },
                None,
                None,
                &binding(1),
            )
            .expect("mint");
        assert_eq!(m.correlation_id, request.as_bytes());
        assert_eq!(m.causation_id, cause.as_bytes());
    }
}
