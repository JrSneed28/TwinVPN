//! One C1 frame in, one response out — with the dedup log consulted **before**
//! any handler runs and the write budget applied **before** any durable append.
//!
//! **Authority:** ADR-0008 N-4/N-5/N-6, ADR-0002 §11.6 (the per-`TwinNet` write
//! budget), `ownership.md` §6 rules 9 and 10 (bound the input before decoding).
//!
//! # The order is the design
//!
//! ```text
//!   bound the octets ──▶ decode ──▶ dedup ──▶ budget ──▶ handler ──▶ record
//!        (§6 r9)                  (N-5)     (§11.6)               (N-5)
//! ```
//!
//! Dedup **before** the budget, deliberately: a retry of a ceremony that already
//! committed must not be refused with `CONTROL.EVENT_RATE_EXCEEDED`. It appends
//! nothing, so it costs nothing, and charging it would make a client's correct
//! retry behaviour look like a flood.

use twinvpn_schema::{v1, Channel};
use twinvpn_service_common::forward::Verbatim;
use twinvpn_service_common::transport::WriteBudget;
use twinvpn_service_common::{Correlation, ServiceError};

use crate::domain::{advertise, device, idem, pairing, policy, read, Ctx, Outcome};
use crate::{Command, CommandCode, NetTx};

/// Retains the untrusted body with the C1 caps applied **before** anything
/// proportional to a declared length is allocated.
///
/// [`Verbatim::from_received`] applies `envelope.c1_c2_c7_max_bytes` and
/// `max_depth` to the raw octets, so a hostile declared length never reaches
/// `prost`. It is the right primitive here — this body *is* a protobuf message —
/// and it is deliberately not the primitive used for a COSE_Sign1 statement; see
/// [`crate::verify::opaque_statement`] for why.
fn retain(body: &[u8]) -> Result<Verbatim, ServiceError> {
    Verbatim::from_received(
        bytes::Bytes::copy_from_slice(body),
        Channel::ControlAndTelemetry,
    )
    .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))
}

/// Decodes an already-bounded body.
fn decode<M: prost::Message + Default>(body: &Verbatim) -> Result<M, ServiceError> {
    twinvpn_schema::validate::decode::<M>(body.as_bytes(), Channel::ControlAndTelemetry)
        .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))
}

/// Reads the `idempotency_key` out of a request's metadata.
fn key_of(metadata: Option<&v1::MessageMetadata>) -> Vec<u8> {
    metadata
        .map(|m| m.idempotency_key.clone())
        .unwrap_or_default()
}

/// Executes one C1 frame inside `tx`.
///
/// `budget` is the per-`TwinNet` durable-write budget; it is consulted once, for
/// commands that may append, and a refusal happens **before** the handler runs
/// so a refused write leaves no partial state.
///
/// # Errors
///
/// Any registered `reason_code` a handler, a validator or the budget produces.
pub fn execute(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    code: CommandCode,
    body: &[u8],
    budget: &mut WriteBudget,
    now: std::time::Instant,
) -> Result<Outcome, ServiceError> {
    let command = code.command();

    // 0. Bound the octets. Every cap is applied to the raw bytes before prost
    //    sees them (ownership.md §6 rules 9 and 10).
    let body = retain(body)?;
    let body = &body;

    // 0b. Correlation, from the request's own envelope. Every event this
    //     transaction appends carries this request's `message_id` as
    //     `causation_id` (`ownership.md` §6 rule 6). The C1→C2 boundary is the
    //     seam where a trace is normally lost: the event is emitted after the
    //     response that caused it has already returned.
    //
    //     A width the envelope does not satisfy is a REJECT, not a silently
    //     dropped id — `Correlation::from_metadata` validates each one.
    let metadata = metadata_of(code, body)?;
    if let Some(md) = metadata.as_ref() {
        let request = Correlation::from_metadata(md)
            .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
        request.record_on_current_span();
        // `caused_by`, not `reply_to`: an event emitted while processing a
        // request is a CONSEQUENCE of it, not an answer to it. Setting
        // `correlation_id` would tell every other device in the `TwinNet` that
        // this event replies to a message they never sent. Causation is also
        // never inherited transitively — one link at a time is what keeps a
        // chain a chain.
        if let Some(id) = request.message_id() {
            tx.set_cause(Correlation::empty().caused_by(id));
        }
    }

    // 1. Dedup, for CEREMONY commands only. ADR-0008 N-9 forbids a dedup log
    //    anywhere else, so this branch is on the class rather than on a list
    //    somebody has to keep in step.
    let pending_key = if command.class().requires_idempotency_key() {
        let key = key_of(metadata.as_ref());
        match idem::admit(tx, ctx, command, &key)? {
            idem::Admitted::Replay {
                response,
                committed_at_net_seq,
            } => {
                return Ok(Outcome {
                    first: response.clone(),
                    replay: response,
                    committed_at_net_seq,
                    replayed: true,
                })
            }
            idem::Admitted::Fresh { key } => Some(key),
        }
    } else {
        None
    };

    // 2. The write budget: ≤ 1 durable event/s sustained, burst 20. Over budget
    //    the write is REFUSED, not queued — "a queued over-budget write is the
    //    flood, delayed".
    if command.may_append_durable() {
        budget
            .try_write(now)
            .map_err(|code| ServiceError::new(code, crate::COMPONENT).build())?;
    }

    // 3. The handler.
    let outcome = run(tx, ctx, code, body)?;

    // 4. Record the outcome, in the SAME transaction as the effect. A dedup
    //    record written afterwards is a dual write, and the crash between the
    //    two loses exactly the record a retry needs.
    if let Some(key) = pending_key {
        idem::record_outcome(tx, ctx, command, key, &outcome);
    }
    Ok(outcome)
}

/// Extracts `MessageMetadata` from an untrusted C1 body.
///
/// The transport layer needs three things out of the envelope **before** the
/// store is entered: the `TwinNet` scope the request is for, the RFC 9266
/// channel binding to check against the live connection, and the correlation to
/// put on the request span. [`crate::serve`] takes them from here rather than
/// re-deriving a second decoder, so there is one arm table and not two.
///
/// The body is bounded before it is decoded, exactly as [`execute`] bounds it.
///
/// # Errors
///
/// `PROTO.UNPARSEABLE_ENVELOPE` or a cap violation.
pub fn envelope_of(
    code: CommandCode,
    body: &[u8],
) -> Result<Option<v1::MessageMetadata>, ServiceError> {
    metadata_of(code, &retain(body)?)
}

/// Extracts `MessageMetadata` without running the handler.
///
/// Every command has an arm: the metadata carries both the `idempotency_key`
/// (needed before the handler runs) and the correlation ids (needed for every
/// event the handler appends), so a `_ => None` arm would silently drop a trace
/// for the commands it covered.
fn metadata_of(
    code: CommandCode,
    body: &Verbatim,
) -> Result<Option<v1::MessageMetadata>, ServiceError> {
    Ok(match code {
        CommandCode::RegisterDevice => decode::<v1::RegisterDeviceRequest>(body)?.metadata,
        CommandCode::RevokeDevice => decode::<v1::RevokeDeviceRequest>(body)?.metadata,
        CommandCode::RotateDeviceCredential => {
            decode::<v1::RotateDeviceCredentialRequest>(body)?.metadata
        }
        CommandCode::BeginPairing => decode::<v1::BeginPairingRequest>(body)?.metadata,
        CommandCode::CompletePairing => decode::<v1::CompletePairingRequest>(body)?.metadata,
        CommandCode::CancelPairing => decode::<v1::CancelPairingRequest>(body)?.metadata,
        CommandCode::RevokePairing => decode::<v1::RevokePairingRequest>(body)?.metadata,
        CommandCode::PutPolicy => decode::<v1::PutPolicyRequest>(body)?.metadata,
        CommandCode::UpdateDeviceMetadata => {
            decode::<v1::UpdateDeviceMetadataRequest>(body)?.metadata
        }
        CommandCode::DiscoverPeers => decode::<v1::DiscoverPeersRequest>(body)?.metadata,
        CommandCode::PublishPresence => decode::<v1::PublishPresenceRequest>(body)?.metadata,
        CommandCode::PutRouteAdvertisement => {
            decode::<v1::PutRouteAdvertisementRequest>(body)?.metadata
        }
        CommandCode::WithdrawRouteAdvertisement => {
            decode::<v1::WithdrawRouteAdvertisementRequest>(body)?.metadata
        }
        CommandCode::PutExitNodeOffer => decode::<v1::PutExitNodeOfferRequest>(body)?.metadata,
        CommandCode::WithdrawExitNodeOffer => {
            decode::<v1::WithdrawExitNodeOfferRequest>(body)?.metadata
        }
        CommandCode::SubscribeEvents => decode::<v1::SubscribeEventsRequest>(body)?.metadata,
        CommandCode::GetStateDocument => decode::<v1::GetStateDocumentRequest>(body)?.metadata,
    })
}

/// The handler table.
fn run(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    code: CommandCode,
    body: &Verbatim,
) -> Result<Outcome, ServiceError> {
    match code {
        CommandCode::RegisterDevice => device::register(tx, ctx, &decode(body)?),
        CommandCode::UpdateDeviceMetadata => device::update_metadata(tx, ctx, &decode(body)?),
        CommandCode::RevokeDevice => device::revoke(tx, ctx, &decode(body)?),
        CommandCode::RotateDeviceCredential => device::rotate_credential(tx, ctx, &decode(body)?),
        CommandCode::BeginPairing => pairing::begin(tx, ctx, &decode(body)?),
        CommandCode::CompletePairing => pairing::complete(tx, ctx, &decode(body)?),
        CommandCode::CancelPairing => pairing::cancel(tx, ctx, &decode(body)?),
        CommandCode::RevokePairing => pairing::revoke_pairing(tx, ctx, &decode(body)?),
        CommandCode::DiscoverPeers => read::discover_peers(tx, ctx, &decode(body)?),
        CommandCode::PublishPresence => read::publish_presence(tx, ctx, &decode(body)?),
        CommandCode::PutRouteAdvertisement => advertise::put_route(tx, ctx, &decode(body)?),
        CommandCode::WithdrawRouteAdvertisement => {
            advertise::withdraw_route(tx, ctx, &decode(body)?)
        }
        CommandCode::PutExitNodeOffer => advertise::put_offer(tx, ctx, &decode(body)?),
        CommandCode::WithdrawExitNodeOffer => advertise::withdraw_offer(tx, ctx, &decode(body)?),
        CommandCode::PutPolicy => policy::put(tx, ctx, &decode(body)?),
        CommandCode::SubscribeEvents => read::subscribe(tx, ctx, &decode(body)?),
        CommandCode::GetStateDocument => read::get_state_document(tx, ctx, &decode(body)?),
    }
}

/// Whether a command reaches the dedup log. Exposed so the session layer can
/// label its metrics without re-deriving the class.
#[must_use]
pub const fn is_ceremony(command: Command) -> bool {
    command.class().requires_idempotency_key()
}

#[cfg(test)]
mod tests {
    use super::{is_ceremony, metadata_of, retain};
    use crate::{Command, CommandCode};

    #[test]
    fn every_ceremony_can_have_its_key_read_without_running_the_handler() {
        // The dedup check must be able to answer BEFORE the handler runs; if a
        // ceremony's metadata were unreachable here, its retry would execute.
        for c in Command::ALL {
            if !is_ceremony(c) {
                continue;
            }
            let code = CommandCode::of(c);
            // An empty body decodes to a default message with no metadata, which
            // is enough to prove the arm exists rather than falling through.
            let empty = retain(&[]).expect("an empty body is within every cap");
            let md = metadata_of(code, &empty).expect("decodes");
            assert!(md.is_none(), "{}", c.as_str());
        }
    }

    #[test]
    fn a_non_ceremony_has_no_dedup_path() {
        for c in Command::ALL {
            if is_ceremony(c) {
                continue;
            }
            assert!(!c.class().has_dedup_log(), "{}", c.as_str());
        }
    }
}
