//! The pairing ceremonies. **Every one is single-use, and every replay returns
//! the original outcome.**
//!
//! **Authority:** `docs/protocol.md` §8.2; `control_commands.proto`'s
//! `BeginPairing`/`CompletePairing`/`CancelPairing`/`RevokePairing`; ADR-0007
//! N-17 (the 120 s window, enforced independently by both devices *and* the
//! rendezvous — and here); ADR-0008 §11.3 (RQ-3); `limits.json pairing`.
//!
//! # Why this file is where asymmetric trust is prevented
//!
//! `contract-matrix.md` §3: *"a replay returns the **original outcome** — this is
//! what prevents asymmetric trust."* ADR-0009 §5 row S-04 states the failure:
//! *"Non-linearizable commit ⇒ asymmetric trust: A trusts B, B does not ⇒ every
//! handshake fails with a misleading crypto error."*
//!
//! Three separate mechanisms make a second outcome unreachable:
//!
//! 1. **The dedup log answers first.** [`super::idem::admit`] returns the
//!    recorded octets before [`complete`] is called at all.
//! 2. **The pairing state is terminal.** Once a `pairing_id` leaves
//!    [`PairingState::Pending`] every handler here refuses it, so a duplicate
//!    that outlived the 24 h window still cannot produce a second outcome.
//! 3. **The recorded outcome is the answer.** When a completed pairing is
//!    re-presented, [`complete`] returns
//!    [`PairingRecord::outcome`](crate::model::PairingRecord::outcome) — the
//!    octets recorded at commit — rather than re-deriving a `PairingResult` from
//!    the request it was handed.

use twinvpn_schema::v1;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::event::DurableEvent;
use crate::model::{PairingRecord, PairingState};
use crate::verify::{self, StatementKind};
use crate::{Command, NetTx};
use twinvpn_schema::v1::control_event::Event as EventBody;

use super::device::check_precondition;
use super::{fixed, mutation_result, record, require_not_revoked, require_quorum, Ctx, Outcome};

/// `limits.json pairing.ceremony_expiry_ms` — ADR-0007 N-17.
pub const CEREMONY_EXPIRY_MS: u64 = 120_000;
/// `limits.json pairing.max_failed_runs`.
pub const MAX_FAILED_RUNS: u32 = 5;

/// `BeginPairing` — `CEREMONY`, linearizable. A duplicate returns the
/// **original** `pairing_id`, never a second one.
///
/// # Errors
///
/// `PROTO.MALFORMED_MESSAGE` on a malformed `pairing_id`;
/// `AUTH.PAIRING_NOT_AUTHORIZED` when the id is already in use for a *different*
/// ceremony; `CONTROL.QUORUM_UNAVAILABLE` — `BeginPairing` is not E-1-class, so
/// this cannot fire, and `require_quorum` is called anyway so a future
/// reclassification is honoured without a code change.
pub fn begin(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::BeginPairingRequest,
) -> Result<Outcome, ServiceError> {
    require_quorum(ctx, Command::BeginPairing)?;
    require_not_revoked(tx, ctx)?;

    let pairing = req
        .pairing
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let pairing_id = fixed::<16>("pairing_id_bytes", &pairing.pairing_id)?;

    // The duplicate case. `idem::admit` handles a duplicate carrying the same
    // key; this handles a duplicate carrying the same *id*, which is what a
    // client that regenerated its key but reused its ceremony looks like.
    if let Some(existing) = tx.state().pairings.get(&pairing_id) {
        if existing.initiator != ctx.caller {
            return Err(codes::bare(
                twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED,
            ));
        }
        // ADR-0008 §11.3: "Duplicate initiate MUST return the original
        // pairing_id, never mint a second."
        let resp = begin_response(existing, tx.state().trust_epoch, 0);
        return Ok(record(&resp, 0, set_begin_replay));
    }

    let expires_at_ms = ctx.now_ms.saturating_add(CEREMONY_EXPIRY_MS);
    let row = PairingRecord {
        pairing_id,
        state: PairingState::Pending,
        version: 1,
        expires_at_ms,
        initiator: ctx.caller,
        outcome: None,
        failed_attempts: 0,
    };

    let net_seq = tx.append(&DurableEvent::new(EventBody::PairingRequested(
        v1::PairingRequested {
            pairing: Some(v1::Pairing {
                pairing_id: pairing_id.to_vec(),
                ..Default::default()
            }),
        },
    ))?)?;
    tx.put_pairing(row.clone());

    let resp = begin_response(&row, tx.state().trust_epoch, net_seq);
    Ok(record(&resp, net_seq, set_begin_replay))
}

fn set_begin_replay(m: &mut v1::BeginPairingResponse) {
    if let Some(r) = m.result.as_mut() {
        r.idempotent_replay = true;
    }
}

fn begin_response(
    row: &PairingRecord,
    revocation_epoch: u64,
    net_seq: u64,
) -> v1::BeginPairingResponse {
    v1::BeginPairingResponse {
        pairing_id: row.pairing_id.to_vec(),
        expires_at_ms: row.expires_at_ms,
        result: Some(mutation_result(net_seq, revocation_epoch)),
        error: None,
        // `verification_words[]` is deliberately absent: a SAS is displayed
        // AFTER completion for recognition and is explicitly not a security
        // gate. The PAKE is the gate.
    }
}

/// `CompletePairing` — `CEREMONY` + `if_version`, E-1-class, linearizable.
///
/// # Errors
///
/// `AUTH.PAIRING_EXPIRED` past the 120 s window; `AUTH.PAIRING_ATTEMPTS_EXCEEDED`
/// past five failed runs; the interim precondition code on a version mismatch;
/// `CONTROL.QUORUM_UNAVAILABLE` when quorum is unreachable.
pub fn complete(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::CompletePairingRequest,
) -> Result<Outcome, ServiceError> {
    require_quorum(ctx, Command::CompletePairing)?;
    require_not_revoked(tx, ctx)?;
    let pairing_id = fixed::<16>("pairing_id_bytes", &req.pairing_id)?;

    let row = tx
        .state()
        .pairings
        .get(&pairing_id)
        .cloned()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED))?;

    // Mechanism 3. A ceremony that already has an outcome answers with THAT
    // outcome, whatever this request says — including a request whose
    // attestation differs. Re-deriving here is precisely how the two devices end
    // up disagreeing about whether they trust each other.
    if row.state == PairingState::Completed {
        if let Some(recorded) = row.outcome.clone() {
            return Ok(Outcome {
                first: recorded.clone(),
                replay: recorded,
                committed_at_net_seq: 0,
                replayed: true,
            });
        }
    }
    if row.state.is_terminal() {
        return Err(terminal_error(row.state));
    }
    if ctx.now_ms >= row.expires_at_ms {
        // The window is enforced here as well as at both devices and the
        // rendezvous. ADR-0007 N-17 wants it enforced independently, which means
        // a control plane that trusted the devices' own timers would be one of
        // three enforcers missing.
        let expired = PairingRecord {
            state: PairingState::Expired,
            version: row.version + 1,
            ..row
        };
        let net_seq = tx.append(&DurableEvent::new(EventBody::PairingExpired(
            v1::PairingExpired {
                pairing_id: pairing_id.to_vec(),
                expired_at_ms: ctx.now_ms,
            },
        ))?)?;
        let _ = net_seq;
        tx.put_pairing(expired);
        return Err(codes::bare(twinvpn_types::codes::AUTH_PAIRING_EXPIRED));
    }
    if row.failed_attempts >= MAX_FAILED_RUNS {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_PAIRING_ATTEMPTS_EXCEEDED,
        ));
    }

    check_precondition(req.precondition.as_ref(), row.version)?;

    // The attestation is device-signed and this service cannot forge it. It is
    // verified over the received octets and forwarded verbatim.
    let attestation = req
        .attestation
        .as_ref()
        .and_then(|a| a.statement.as_ref())
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let octets = verify::opaque_statement(bytes::Bytes::from(attestation.cose_sign1.clone()))
        .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
    let signer = super::caller_key(tx, ctx)?;
    let verified = verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::PairingAttestation,
        ctx.now_ms,
        verify::SignerKey::Device(&signer),
    )?;

    // ==================================================================
    // THE ATTESTATION MUST BE AN ATTESTATION FOR *THIS* CEREMONY.
    // ==================================================================
    // `PairingRequest` names no responder — ADR-0007 locates the joining device
    // out of band — so this service cannot know in advance which second device
    // is entitled to complete a pairing, and a check of the form
    // `caller == responder` has nothing to compare against.
    //
    // What it can check is the binding the attestation itself carries. Without
    // it, any registered device could complete any pending ceremony by signing
    // an attestation of its own for some *other* pairing: the signature would
    // verify (it is the caller's own key), the `pairing_id` in the request would
    // select the victim's row, and the two would never be compared. That is
    // trust injection by a member, and `pairing.proto` is explicit that the
    // coordination service "TRANSPORTS attestations it CANNOT FORGE" precisely
    // so that it cannot inject a `TrustedPeer`. Forging is not the only way to
    // inject one; mis-routing a genuine attestation is the other, and this is
    // where it is refused.
    //
    // A verifier that reports no `pairing_id` for a `PairingAttestation` fails
    // this check rather than passing it: the check is fail-closed, so a binding
    // that cannot be read is a binding that is not established.
    if verified.pairing_id != Some(pairing_id) {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED,
        ));
    }

    let result_detail = v1::PairingResult {
        pairing_id: pairing_id.to_vec(),
        ..Default::default()
    };

    let net_seq = tx.append(&DurableEvent::new(EventBody::PairingApproved(
        v1::PairingApproved {
            result: Some(result_detail.clone()),
        },
    ))?)?;

    let resp = v1::CompletePairingResponse {
        result_detail: Some(result_detail),
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    let outcome = record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    });

    // Mechanism 2 + 3: the state becomes terminal and the REPLAY form is what is
    // recorded, so every later presentation — inside the dedup window or long
    // outside it — answers with these exact octets.
    tx.put_pairing(PairingRecord {
        state: PairingState::Completed,
        version: row.version + 1,
        outcome: Some(outcome.replay.clone()),
        ..row
    });
    let _ = verified;

    Ok(outcome)
}

/// `CancelPairing` — burns the `pairing_id`. It is single-use, and a cancelled
/// id is **never reissued**: reissuing it would reset the five-attempt budget.
///
/// # Errors
///
/// `AUTH.PAIRING_NOT_AUTHORIZED` for an unknown id or a caller that is not the
/// initiator; a terminal-state error for an id already burnt.
pub fn cancel(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::CancelPairingRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let pairing_id = fixed::<16>("pairing_id_bytes", &req.pairing_id)?;
    let row = tx
        .state()
        .pairings
        .get(&pairing_id)
        .cloned()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED))?;

    // Only the device that opened the ceremony may close it. Cancelling is not
    // a harmless operation: it burns the `pairing_id` permanently (a cancelled
    // id is terminal and a later `CompletePairing` on it is refused), so a
    // member that could cancel another member's ceremony could deny pairing to
    // the whole `TwinNet` one id at a time and leave a `PairingRejected` in the
    // durable log attributing it to nobody.
    //
    // The initiator is the only participant this service knows: `PairingRequest`
    // names no responder. A device that never sees its own row is refused with
    // the same code as one asking about a ceremony that does not exist, which
    // is deliberate — the existence of another device's pairing is not this
    // caller's to learn.
    if row.initiator != ctx.caller {
        return Err(codes::bare(
            twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED,
        ));
    }
    if row.state.is_terminal() {
        return Err(terminal_error(row.state));
    }

    let net_seq = tx.append(&DurableEvent::new(EventBody::PairingRejected(
        v1::PairingRejected {
            pairing_id: pairing_id.to_vec(),
            error: None,
        },
    ))?)?;
    tx.put_pairing(PairingRecord {
        state: PairingState::Cancelled,
        version: row.version + 1,
        ..row
    });

    let resp = v1::CancelPairingResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// `RevokePairing` — withdraws one confirmed relationship.
///
/// **Distinct from device revocation**: it removes one relationship and revokes
/// nobody. It does not touch the trust epoch and does not add to the revoked
/// set, and conflating the two would make "unfriend" and "this laptop was
/// stolen" the same operation.
///
/// # Errors
///
/// `AUTH.PAIRING_NOT_AUTHORIZED` for an unknown pairing;
/// `AUTH.BINDING_INVALID` when the revocation statement does not verify.
pub fn revoke_pairing(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::RevokePairingRequest,
) -> Result<Outcome, ServiceError> {
    require_not_revoked(tx, ctx)?;
    let revocation = req
        .revocation
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let pairing_id = fixed::<16>("pairing_id_bytes", &revocation.pairing_id)?;
    let row = tx
        .state()
        .pairings
        .get(&pairing_id)
        .cloned()
        .ok_or_else(|| codes::bare(twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED))?;

    if let Some(statement) = revocation.statement.as_ref() {
        let octets = verify::opaque_statement(bytes::Bytes::from(statement.cose_sign1.clone()))
            .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
        // Owner authority: "A device MUST NOT be able to revoke a pairing on
        // its own authority any more than it can revoke a peer."
        verify::admit(
            ctx.verifier,
            &octets,
            StatementKind::PairingRevocation,
            ctx.now_ms,
            verify::SignerKey::OwnerAnchors,
        )?;
    } else {
        return Err(codes::bare(codes::SIGNATURE_INVALID));
    }

    let net_seq = tx.append(&DurableEvent::new(EventBody::PairingRevoked(
        v1::PairingRevoked {
            revocation: Some(revocation.clone()),
        },
    ))?)?;
    tx.put_pairing(PairingRecord {
        state: PairingState::Revoked,
        version: row.version + 1,
        ..row
    });

    let resp = v1::RevokePairingResponse {
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// The registered code for acting on an already-terminal ceremony.
fn terminal_error(state: PairingState) -> ServiceError {
    match state {
        PairingState::Expired => codes::bare(twinvpn_types::codes::AUTH_PAIRING_EXPIRED),
        _ => codes::bare(twinvpn_types::codes::AUTH_PAIRING_NOT_AUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::{terminal_error, CEREMONY_EXPIRY_MS, MAX_FAILED_RUNS};
    use crate::model::PairingState;

    #[test]
    fn the_ceremony_bounds_are_the_frozen_ones() {
        let json = twinvpn_schema::limits::LIMITS_JSON;
        assert!(json.contains("\"ceremony_expiry_ms\": 120000"));
        assert!(json.contains("\"max_failed_runs\": 5"));
        assert_eq!(CEREMONY_EXPIRY_MS, 120_000);
        assert_eq!(MAX_FAILED_RUNS, 5);
    }

    #[test]
    fn every_terminal_state_names_a_registered_code() {
        for s in [
            PairingState::Completed,
            PairingState::Rejected,
            PairingState::Cancelled,
            PairingState::Expired,
            PairingState::Revoked,
        ] {
            let e = terminal_error(s);
            assert!(
                twinvpn_types::ReasonCode::lookup(e.code().as_str()).is_some(),
                "{s:?}"
            );
        }
    }
}
