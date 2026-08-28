//! `PutPolicy` — the **only** policy mutation in the contract set.
//!
//! **Authority:** `docs/protocol.md` §13.4; `control_commands.proto`
//! ("THIS IS THE ONLY POLICY MUTATION COMMAND IN THE CONTRACT SET");
//! `policy.proto` ("AUTHORED by the Owner authority … the control plane
//! WAREHOUSES AND DISTRIBUTES; IT CANNOT AUTHOR"); `architecture.md` §5 rows
//! S-06/S-07; ADR-0009 §11.3 R-2…R-5; ADR-0002 §11.3 (E-1-class, quorum before
//! responding).
//!
//! # Four things must all hold, and each has its own failure
//!
//! | Requirement | Where | Failure if dropped |
//! |---|---|---|
//! | `Owner` signature over the received octets | [`verify::admit`] | this service could author policy |
//! | `if_version` precondition | [`check_precondition`] | lost update: two Owners' edits, one survives silently |
//! | monotone version, fork-detected | [`crate::NetTx::put_document`] | policy rollback attack — "a silent authorization hole" |
//! | quorum before responding | [`require_quorum`] | a forked policy history, which E-1 forbids |
//!
//! # Peer permissions, route policy and DNS policy travel inside this bundle
//!
//! There is no `UpdatePeerPermissions`, no `UpdateRoutePolicy` and no
//! `UpdateDNSPolicy`, "and adding one would create a second policy author — the
//! exact capability Rule B removes from the infrastructure".
//! [`crate::command::Command`] has no variant for any of them and
//! `put_policy_is_the_only_policy_mutation` asserts it.

use twinvpn_schema::v1;
use twinvpn_service_common::ServiceError;

use crate::codes;
use crate::event::DurableEvent;
use crate::model::{DocumentRecord, DocumentType};
use crate::verify::{self, StatementKind};
use crate::wire;
use crate::{Command, NetTx};
use twinvpn_schema::v1::control_event::Event as EventBody;

use super::device::check_precondition;
use super::{mutation_result, record, require_quorum, Ctx, Outcome};

/// `PutPolicy` — `CEREMONY` + `if_version`, linearizable, quorum-committed.
///
/// # Errors
///
/// `CONTROL.QUORUM_UNAVAILABLE`; `AUTH.KEY_UNAVAILABLE` with no anchor bound;
/// `AUTH.UNEXPECTED_DELEGATION` when the bundle verified against a device key
/// rather than the `Owner` chain; the interim precondition code on a version
/// mismatch or a rollback; `AUTH.TRUST_HISTORY_FORKED` on an equal version with
/// different content.
pub fn put(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    req: &v1::PutPolicyRequest,
) -> Result<Outcome, ServiceError> {
    require_quorum(ctx, Command::PutPolicy)?;

    let bundle = req
        .bundle
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;

    // The Owner signs. A bundle that verified against anything else is not a
    // policy bundle, however well-formed it is.
    let statement = bundle
        .signed
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let octets = verify::opaque_statement(bytes::Bytes::from(statement.cose_sign1.clone()))
        .map_err(|r| ServiceError::from_reject(&r, crate::COMPONENT))?;
    let verified = verify::admit(
        ctx.verifier,
        &octets,
        StatementKind::PolicyBundle,
        ctx.now_ms,
        verify::SignerKey::OwnerAnchors,
    )?;

    // THE VERSION COMES FROM INSIDE THE SIGNATURE (R-4).
    //
    // `bundle.policy_version` is an UNSIGNED WIRE FIELD, and the monotone floor
    // used to be advanced from it. Two attacks followed, both from bundles this
    // service would happily verify:
    //
    //   * re-wrap last year's signed bundle with a HIGHER wire version — the
    //     floor advances and the rollback is accepted as an advance, which is
    //     exactly the "silent authorization hole" this module's own table names;
    //   * re-wrap any of them with `u64::MAX` — the floor advances past every
    //     version the Owner can ever sign again, permanently bricking policy.
    //
    // The CDDL requires `policy_version` in the `crit` set, so a bundle that
    // verified has committed to one. A payload that did not decode is refused
    // rather than falling back to the wire's number.
    let claims = verified
        .policy
        .as_ref()
        .ok_or_else(|| codes::bare(codes::SIGNATURE_INVALID))?;
    let policy_version = claims.policy_version;
    // The wire field stays in the message as a routing hint, so a caller that
    // disagrees with what it forwarded is a defect worth naming rather than
    // silently overriding.
    if bundle.policy_version != policy_version {
        return Err(codes::bare(codes::SIGNATURE_INVALID));
    }

    // N-2. The current version is 0 before the first bundle, which is what
    // `if_absent` matches.
    check_precondition(req.precondition.as_ref(), tx.state().policy_version)?;

    let digest = content_digest(verified.octets.as_bytes());
    let net_seq_slot = tx.state().next_net_seq;
    tx.put_document(
        DocumentType::PolicyBundle,
        DocumentRecord {
            version: policy_version,
            content_digest: digest,
            octets: verified.octets.as_bytes().to_vec(),
            net_seq: net_seq_slot,
            trust_epoch: tx.state().trust_epoch,
            issued_at_ms: ctx.now_ms,
        },
    )?;
    tx.advance_policy_version(policy_version);

    // ADR-0002 §11.4: inline below the 16 KiB cap, by reference above it. The
    // reference form is what makes a large bundle unable to monopolise a stream,
    // and pull is always sufficient either way.
    let inline = wire::fits_inline(verified.octets.as_bytes());
    let reference = v1::StateDocumentRef {
        doc_type: DocumentType::PolicyBundle.to_wire(),
        version: policy_version,
        size_bytes: verified.octets.len() as u64,
        digest: digest.to_vec(),
    };

    let net_seq = tx.append(&DurableEvent::new(EventBody::PolicyBundleUpdated(
        v1::PolicyBundleUpdated {
            policy_version,
            bundle: inline.then(|| bundle.clone()),
            reference: Some(reference),
        },
    ))?)?;

    let resp = v1::PutPolicyResponse {
        policy_version,
        result: Some(mutation_result(net_seq, tx.state().trust_epoch)),
        error: None,
    };
    Ok(record(&resp, net_seq, |m| {
        if let Some(r) = m.result.as_mut() {
            r.idempotent_replay = true;
        }
    }))
}

/// SHA-256 over the **verified octets**, as `StateDocumentRef.digest` requires.
///
/// `policy.proto`: "SHA-256 of the document bytes, exactly 32 bytes. Verified
/// ALONGSIDE the signature, not instead of it: the digest proves the pull
/// returned what was announced, the signature proves the `Owner` authored it."
///
/// It is `twinvpn-crypto`'s SHA-256 — the audited provider — for the same reason
/// the v6 derivation is: a device verifies this digest against one it computed
/// itself, so a second implementation inside the services workspace would be the
/// DP-8 second provider whose agreement is untested. The same value serves
/// ADR-0009 R-4's equal-version fork detection.
#[must_use]
pub fn content_digest(octets: &[u8]) -> [u8; 32] {
    twinvpn_crypto::sha256(octets)
}

#[cfg(test)]
mod tests {
    use super::content_digest;

    #[test]
    fn the_digest_is_sha_256_and_not_a_lookalike() {
        // The bug this replaced: a 256-bit FNV-1a fold has the right WIDTH and
        // separates content, and a device verifying an announced digest against
        // its own SHA-256 fails every single time.
        assert_eq!(
            content_digest(b"twinvpn"),
            twinvpn_crypto::sha256(b"twinvpn")
        );

        // RFC 6234's vector for the empty string, so this is pinned to SHA-256
        // itself and not merely to whatever the provider currently returns.
        let empty = content_digest(b"");
        assert_eq!(
            &empty[..4],
            &[0xe3, 0xb0, 0xc4, 0x42],
            "SHA-256(\"\") begins e3b0c442"
        );
        assert_eq!(empty.len(), 32, "policy.proto: exactly 32 bytes");
    }

    #[test]
    fn the_fork_detector_separates_different_content() {
        // ADR-0009 R-4 needs "same version, different bytes" to be detectable.
        assert_eq!(content_digest(b"a"), content_digest(b"a"));
        assert_ne!(content_digest(b"a"), content_digest(b"b"));
        assert_ne!(content_digest(b"ab"), content_digest(b"ba"));
        assert_ne!(content_digest(b""), content_digest(b"\0"));
        assert_ne!(content_digest(b"a"), content_digest(b"aa"));
    }
}
