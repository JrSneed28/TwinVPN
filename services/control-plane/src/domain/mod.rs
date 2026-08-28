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
    /// The COSE_Key the caller **proved possession of** in the TLS handshake,
    /// converted from its RFC 7250 raw public key.
    ///
    /// Not a claim: TLS 1.3's `CertificateVerify` is a signature over the
    /// handshake transcript, so this is the one key on the connection that is
    /// cryptographically established rather than asserted.
    ///
    /// It exists because of rotation. `RotateDeviceCredential` moves a device's
    /// `identity_id` to the successor the signed `IdentitySuccession` names, but
    /// the succession carries **no public key**, so the device record cannot
    /// hold the successor's key. [`caller_key`] closes that with a check rather
    /// than a write: if this key derives to the `identity_id` the record names,
    /// it *is* that identity, and it is the key a device-signed statement must
    /// be verified against.
    ///
    /// `None` on a path with no connection behind it — a test, or a future
    /// admin caller — and then [`caller_key`] falls back to the recorded key,
    /// which is the pre-rotation behaviour unchanged.
    pub caller_identity_key: Option<&'a [u8]>,
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

/// The calling device's `DeviceIdentityKey`, as COSE_Key octets.
///
/// **Never the one the request carried.** A handler that took the key out of the
/// body would be verifying a device-signed statement against a key the same body
/// chose, which verifies nothing at all. Two sources are permitted, and both are
/// established rather than asserted:
///
/// 1. the key this service **recorded at registration**, or
/// 2. the key the caller **proved possession of on this connection**, and then
///    only when it derives to the `identity_id` the record itself names.
///
/// (2) exists for exactly one case: a device that has rotated its identity key.
/// Its record's `identity_id` was moved to the successor by a signed
/// `IdentitySuccession` — an authorisation this service verified against the
/// *old* key — but that statement carries no public key, so the record still
/// holds the predecessor's. The successor arrives on the wire, in the handshake,
/// and `derive_identity_id(channel_key) == record.identity_id` is the proof that
/// it is the key the old key nominated. Without this, every device-signed
/// command from a rotated device would fail `AUTH.BINDING_INVALID` for ever.
///
/// # Errors
///
/// `AUTH.PEER_UNTRUSTED` when the caller is not a member.
pub fn caller_key(tx: &crate::NetTx, ctx: &Ctx<'_>) -> Result<Vec<u8>, ServiceError> {
    let record = tx
        .state()
        .devices
        .get(&ctx.caller)
        .ok_or_else(|| crate::codes::bare(twinvpn_types::codes::AUTH_PEER_UNTRUSTED))?;
    if let Some(channel) = ctx.caller_identity_key {
        // `derive_identity_id` and not the checked form: these octets were
        // produced by `binding::spki::spki_to_es256_cose_key`, which built them
        // canonically from a P-256 point rustls had already accepted, so the
        // canonicality the checked form proves is established at the conversion.
        if twinvpn_crypto::deviceid::derive_identity_id(channel).to_array() == record.identity_id {
            return Ok(channel.to_vec());
        }
    }
    Ok(record.identity_public_key.clone())
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
    use super::{caller_key, fixed, mutation_result, record, Ctx, Outcome};
    use crate::model::{DeviceRecord, NetState};
    use crate::tx::{NetTx, WriteLease};
    use crate::verify::RefuseUnverifiable;

    /// A `TwinNet` holding one device whose recorded key is `recorded` and whose
    /// `identity_id` is `identity_id`.
    fn one_device(recorded: &[u8], identity_id: [u8; 32]) -> NetTx {
        let mut state = NetState::new("twn_test");
        state.devices.insert(
            [1u8; 32],
            DeviceRecord {
                device_id: [1u8; 32],
                identity_id,
                identity_public_key: recorded.to_vec(),
                generation: 0,
                tk_generation: 0,
                label: String::new(),
                version: 1,
                membership_epoch: 1,
                twinnet_addr_v4: [10, 0, 0, 1],
                twinnet_addr_v6: [0u8; 16],
                encoded: Vec::new(),
                revoked: false,
                net_seq: 1,
                created_at_ms: 0,
            },
        );
        NetTx::open(state, WriteLease { shard_epoch: 1 }, 0).expect("opens")
    }

    fn ctx<'a>(channel: Option<&'a [u8]>, verifier: &'a RefuseUnverifiable) -> Ctx<'a> {
        Ctx {
            caller: [1u8; 32],
            caller_identity_key: channel,
            twinnet_id: "twn_test",
            now_ms: 0,
            verifier,
            quorum_available: true,
            correlation: twinvpn_service_common::Correlation::empty(),
            coordination_endpoints: &[],
        }
    }

    #[test]
    fn without_a_channel_key_the_recorded_key_is_the_signer() {
        let tx = one_device(b"recorded", [9u8; 32]);
        let v = RefuseUnverifiable;
        assert_eq!(
            caller_key(&tx, &ctx(None, &v)).expect("a member"),
            b"recorded".to_vec()
        );
    }

    #[test]
    fn a_channel_key_that_is_not_the_recorded_identity_is_ignored() {
        // THE IMPORTANT HALF. A connection's key does not get to displace the
        // recorded one just by being present: it is admitted only when it
        // derives to the `identity_id` the record itself names. Otherwise any
        // member could have its own statements checked against its own key while
        // the record said something else.
        let tx = one_device(b"recorded", [9u8; 32]);
        let v = RefuseUnverifiable;
        let impostor = twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"impostor").cose_key();
        assert_eq!(
            caller_key(&tx, &ctx(Some(&impostor), &v)).expect("a member"),
            b"recorded".to_vec(),
            "the recorded key still wins"
        );
    }

    #[test]
    fn a_successors_channel_key_is_admitted_because_the_record_names_it() {
        // The rotation case. `IdentitySuccession` moved `identity_id` to the
        // successor and carried no public key, so the record still holds the
        // predecessor's — and the successor is the key on the wire. Without
        // this, every device-signed command from a rotated device would fail
        // AUTH.BINDING_INVALID for ever.
        let successor =
            twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"successor").cose_key();
        let successor_id = twinvpn_crypto::deviceid::derive_identity_id(&successor).to_array();
        let tx = one_device(b"predecessor", successor_id);
        let v = RefuseUnverifiable;
        assert_eq!(
            caller_key(&tx, &ctx(Some(&successor), &v)).expect("a member"),
            successor,
            "the proven successor is the signer the record named"
        );
    }

    #[test]
    fn a_non_member_has_no_key_whatever_it_presented() {
        let mut state = NetState::new("twn_test");
        state.trust_epoch = 1;
        let tx = NetTx::open(state, WriteLease { shard_epoch: 1 }, 0).expect("opens");
        let v = RefuseUnverifiable;
        let key = twinvpn_crypto::testkit::FixtureIdentity::from_seed(b"stranger").cose_key();
        let err = caller_key(&tx, &ctx(Some(&key), &v)).expect_err("not a member");
        assert_eq!(err.code().as_str(), "AUTH.PEER_UNTRUSTED");
    }

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
