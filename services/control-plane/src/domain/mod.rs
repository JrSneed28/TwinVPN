//! What each C1 command actually does, as a pure function of the transaction
//! and the request.
//!
//! **Authority:** `contracts/docs/contract-matrix.md` §3, `docs/protocol.md`
//! §8–§13, ADR-0008 §11.3, ADR-0009 §11.
//!
//! # Why the domain is synchronous and the store is not
//!
//! Every handler here takes a [`crate::NetTx`] — a working copy plus a journal —
//! and returns an [`Outcome`]. Nothing here opens a socket, reads a clock or
//! awaits anything, so the security properties are testable without a database,
//! a runtime or a network, and the *same* functions run under
//! [`crate::store::mem::MemStore`] and [`crate::store::pg::PgStore`]. That is
//! what stops the two stores from acquiring two different answers to "may this
//! epoch go backwards".

pub mod addressing;
pub mod advertise;
pub mod device;
pub mod idem;
pub mod pairing;
pub mod policy;
pub mod read;

use twinvpn_schema::v1;
use twinvpn_service_common::{Correlation, ServiceError};

use crate::model::DeviceKey;
use crate::verify::StatementVerifier;

/// Everything a handler needs that is not in the transaction.
pub struct Ctx<'a> {
    /// The **authenticated** device this request arrived from — the mTLS peer
    /// identity, not a field in the body. `Auth`'s Rule A: the message travels
    /// only over the mutually authenticated channel, so the caller is the
    /// connection's identity and a `sender_id` in the body is a claim.
    pub caller: DeviceKey,
    /// The `TwinNet` scope. Every message is `TwinNet`-scoped.
    pub twinnet_id: &'a str,
    /// Wall-clock milliseconds, **passed in** rather than read, so a decision is
    /// reproducible from its inputs.
    pub now_ms: u64,
    /// The signature verifier. Fail-closed by default.
    pub verifier: &'a dyn StatementVerifier,
    /// Whether an E-1-class write may commit.
    ///
    /// ADR-0002 §11.3: with quorum unreachable the operation is **refused**,
    /// never "committed locally with a promise to reconcile, because a forked
    /// revocation history is exactly what E-1 forbids".
    pub quorum_available: bool,
    /// `correlation_id` / `causation_id`, preserved across the hop.
    pub correlation: Correlation,
    /// Where to reach the control plane, as **names** so GeoDNS works, resolved
    /// in the bootstrap DNS scope (ADR-0011 DN-0). Returned by
    /// `RegisterDevice`.
    pub coordination_endpoints: &'a [String],
    /// How the v6 overlay address is derived. See
    /// [`addressing::Ipv6Derivation`].
    pub v6_derivation: addressing::Ipv6Derivation,
}

/// What a handler produced.
///
/// Two encodings of the same response: `first` is returned to the caller that
/// executed the effect, `replay` is what a later duplicate receives. They differ
/// in exactly one bit — `MutationResult.idempotent_replay` — and storing the
/// *replay* form is what lets ADR-0008 N-5's "replay the recorded response
/// **verbatim**" be literally true, with no decode-and-re-encode on the replay
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The response as the executing caller sees it.
    pub first: Vec<u8>,
    /// The response as a duplicate sees it.
    pub replay: Vec<u8>,
    /// The position the effect committed at, `0` for a read.
    pub committed_at_net_seq: u64,
    /// Whether this response is a **recorded** outcome served to a duplicate
    /// rather than a freshly executed one.
    ///
    /// Observable to the caller through `MutationResult.idempotent_replay`; kept
    /// here as well so the metric ADR-0008 §10.2 asks for
    /// (`idempotent_replay_served`) does not have to re-decode the response to
    /// learn what happened.
    pub replayed: bool,
}

impl Outcome {
    /// A read-only or `REGISTER`-class response: no dedup record, no replay
    /// form, no log position.
    #[must_use]
    pub fn read_only(encoded: Vec<u8>) -> Self {
        Self {
            first: encoded.clone(),
            replay: encoded,
            committed_at_net_seq: 0,
            replayed: false,
        }
    }
}

/// Builds the two encodings of a mutating response.
///
/// `set_replay` flips `MutationResult.idempotent_replay` on a clone. The caller
/// supplies it because the field sits at a different path in each response
/// message and the frozen contracts declare no common interface over them.
pub fn record<M: prost::Message + Clone>(
    msg: &M,
    committed_at_net_seq: u64,
    set_replay: impl FnOnce(&mut M),
) -> Outcome {
    let first = msg.encode_to_vec();
    let mut replayed = msg.clone();
    set_replay(&mut replayed);
    Outcome {
        first,
        replay: replayed.encode_to_vec(),
        committed_at_net_seq,
        replayed: false,
    }
}

/// The `MutationResult` every mutating response carries.
///
/// `revocation_epoch` is on **every** C1 response "so a device detects it is
/// behind without draining the log" — which is what makes the security-critical
/// fact arrive in RTT 1 regardless of queue depth (ADR-0002 §11.6).
#[must_use]
pub fn mutation_result(committed_at_net_seq: u64, revocation_epoch: u64) -> v1::MutationResult {
    v1::MutationResult {
        committed_at_net_seq,
        revocation_epoch,
        idempotent_replay: false,
    }
}

/// Refuses an E-1-class write that cannot reach quorum.
///
/// # Errors
///
/// `CONTROL.QUORUM_UNAVAILABLE`.
pub fn require_quorum(ctx: &Ctx<'_>, command: crate::Command) -> Result<(), ServiceError> {
    if command.is_e1_class() && !ctx.quorum_available {
        return Err(crate::codes::quorum_unavailable());
    }
    Ok(())
}

/// Refuses a request from a device in the never-shrinking revoked set.
///
/// ADR-0009 §11.4: "every denial remains in force permanently — denials are
/// monotone accumulations, not leases."
///
/// # Errors
///
/// `AUTH.DEVICE_REVOKED`, which is terminal.
pub fn require_not_revoked(tx: &crate::NetTx, ctx: &Ctx<'_>) -> Result<(), ServiceError> {
    if tx.state().is_revoked(&ctx.caller) {
        return Err(crate::codes::device_revoked(tx.state().trust_epoch));
    }
    Ok(())
}

/// Reads a fixed-width identifier out of an untrusted `bytes` field.
///
/// # Errors
///
/// [`ServiceError`] carrying `PROTO.MALFORMED_MESSAGE` with the `limits.json`
/// key that was violated. Never a truncation, never a pad.
pub fn fixed<const N: usize>(field: &'static str, value: &[u8]) -> Result<[u8; N], ServiceError> {
    <[u8; N]>::try_from(value).map_err(|_| {
        ServiceError::from_reject(
            &twinvpn_schema::Reject::CapViolated {
                cap_violated: field,
                observed: value.len() as u64,
                limit: N as u64,
            },
            crate::COMPONENT,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{fixed, mutation_result, record, Outcome};
    use prost::Message;
    use twinvpn_schema::v1;

    #[test]
    fn the_replay_form_differs_from_the_first_form_in_exactly_the_flag() {
        let msg = v1::CancelPairingResponse {
            result: Some(mutation_result(42, 7)),
            error: None,
        };
        let out = record(&msg, 42, |m| {
            if let Some(r) = m.result.as_mut() {
                r.idempotent_replay = true;
            }
        });
        assert_ne!(out.first, out.replay);

        let first = v1::CancelPairingResponse::decode(out.first.as_slice()).expect("decodes");
        let replay = v1::CancelPairingResponse::decode(out.replay.as_slice()).expect("decodes");
        let f = first.result.expect("result");
        let r = replay.result.expect("result");
        assert!(!f.idempotent_replay);
        assert!(r.idempotent_replay, "ADR-0008 §10.2's observable");
        assert_eq!(f.committed_at_net_seq, r.committed_at_net_seq);
        assert_eq!(f.revocation_epoch, r.revocation_epoch);
    }

    #[test]
    fn a_read_only_outcome_has_no_position_and_no_distinct_replay() {
        let out = Outcome::read_only(vec![1, 2, 3]);
        assert_eq!(out.committed_at_net_seq, 0);
        assert_eq!(out.first, out.replay);
    }

    #[test]
    fn a_wrong_width_identifier_is_a_typed_reject_not_a_pad() {
        let err = fixed::<32>("device_id_bytes", &[0u8; 31]).expect_err("short");
        assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
        let err = fixed::<32>("device_id_bytes", &[0u8; 33]).expect_err("long");
        assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
        assert!(fixed::<32>("device_id_bytes", &[0u8; 32]).is_ok());
    }
}
