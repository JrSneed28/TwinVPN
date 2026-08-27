//! Applying a C2 event: verify, check monotone, then say what must be written.
//!
//! **Authority:** ADR-0009 R-1 … R-9 (the signed-document model), ADR-0002 N-5
//! (independent applicability), `contracts/docs/contract-matrix.md` §4.1 (which
//! events carry a statement coordination cannot forge),
//! `contracts/docs/trust-boundaries.md` §3.
//!
//! # Why this returns an effect instead of performing one
//!
//! **ADR-0009 R-9.** High-water marks "are durable and MUST be written **before**
//! the document they admit is acted upon, so a crash between the two cannot lose
//! the floor." A function that verified, wrote, and applied in one step would
//! have that ordering as an internal detail nobody could test. So [`plan`] is a
//! **pure** function that produces an [`Effect`] naming the writes in order, and
//! the caller performs them through [`crate::ports::ControlPlaneStore`].
//!
//! It is also what keeps this crate honest about CD-I5: the effect is data, and
//! the only thing that can act on it is the store.
//!
//! # Verification order
//!
//! 1. **Admit** — publisher, then durability, then position ([`crate::events::admit`]).
//! 2. **Verify the signature over the received octets**, for every event
//!    `contract-matrix.md` §4.1 marks as carrying one. R-1: "A device MUST verify
//!    the signature offline before any other check. An unverifiable document is
//!    discarded and **never compared against the high-water mark**" — because
//!    comparing first would let an unsigned forgery advance a floor.
//! 3. **Check the required authority.** Verifying is not enough: a `PolicyBundle`
//!    signed by a device key verified fine and is still not a policy bundle.
//! 4. **Monotone check**, then the writes.

use crate::error::CpError;
use crate::events::{carries_signed_statement, Admitted};
use crate::octets::ReceivedOctets;
use crate::ports::{StatementKind, StatementVerifier, VerifiedStatement, VerifyFailure};
use crate::revocation::TrustEpoch;
use crate::state::DocumentType;

/// What admitting one event obliges the store to do, **in this order**.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Effect {
    /// Advance the `trust_epoch` floor, then apply the revocation. The floor
    /// first: R-9.
    AdvanceTrustEpoch {
        /// The admitted epoch.
        epoch: u64,
        /// The log position to commit the cursor to afterwards.
        net_seq: u64,
    },
    /// Store a verified document at a new version, then advance the cursor.
    PutDocument {
        /// Which document.
        doc_type: DocumentType,
        /// Its monotone version.
        version: u64,
        /// The log position.
        net_seq: u64,
    },
    /// A durable event with no document of its own — a peer-set change, a
    /// pairing outcome. Apply it, then advance the cursor.
    ApplyAndAdvance {
        /// The log position.
        net_seq: u64,
    },
    /// A deliberate, announced gap. Advance the cursor to the stated position
    /// and perform a **declarative re-read**; never a silent skip.
    CompactThenReread {
        /// Where the cursor lands.
        up_to_net_seq: u64,
        /// The position of the announcement itself.
        net_seq: u64,
    },
    /// An ephemeral event. **Nothing durable happens.** It is not logged, not
    /// resumable, and must not survive its TTL.
    Ephemeral,
    /// A freshness proof. Records liveness and **grants nothing**.
    RecordFreshness,
    /// A document above the inline cap exists; pull it via `GetStateDocument`.
    /// Push is only a latency optimisation — pull alone always converges.
    PullDocument {
        /// Which document.
        doc_type: DocumentType,
        /// The announced version.
        version: u64,
    },
}

impl Effect {
    /// Whether this effect writes anything durable.
    #[must_use]
    pub const fn is_durable(&self) -> bool {
        !matches!(self, Effect::Ephemeral | Effect::RecordFreshness)
    }

    /// The position the cursor advances to once the effect is applied, if any.
    #[must_use]
    pub const fn cursor_advances_to(&self) -> Option<u64> {
        match self {
            Effect::AdvanceTrustEpoch { net_seq, .. }
            | Effect::PutDocument { net_seq, .. }
            | Effect::ApplyAndAdvance { net_seq }
            | Effect::CompactThenReread { net_seq, .. } => Some(*net_seq),
            Effect::Ephemeral | Effect::RecordFreshness | Effect::PullDocument { .. } => None,
        }
    }
}

/// The statement an event carries, if it carries one.
///
/// Returns the octets **as they arrived** — never a re-encode, because prost
/// 0.13 drops unknown fields and a re-encoded COSE_Sign1 stops verifying.
#[must_use]
pub fn statement_of(
    event: &twinvpn_schema::v1::control_event::Event,
) -> Option<(StatementKind, ReceivedOctets)> {
    use twinvpn_schema::v1::control_event::Event as E;
    let (kind, cose) = match event {
        E::DeviceRevoked(e) => (
            StatementKind::RevocationEntry,
            e.revocation_entry.as_ref()?.cose_sign1.clone(),
        ),
        E::DeviceCredentialRotated(e) => (
            StatementKind::IdentitySuccession,
            e.rotation_statement.as_ref()?.cose_sign1.clone(),
        ),
        E::PolicyBundleUpdated(e) => (
            StatementKind::PolicyBundle,
            e.bundle.as_ref()?.signed.as_ref()?.cose_sign1.clone(),
        ),
        E::RouteAdvertised(e) => (
            StatementKind::RouteAdvertisement,
            e.advertisement
                .as_ref()?
                .signed
                .as_ref()?
                .cose_sign1
                .clone(),
        ),
        E::RouteWithdrawn(e) => (
            StatementKind::RouteAdvertisement,
            e.signed.as_ref()?.cose_sign1.clone(),
        ),
        E::ExitNodeAdvertised(e) => (
            StatementKind::ExitNodeOffer,
            e.offer.as_ref()?.signed.as_ref()?.cose_sign1.clone(),
        ),
        E::ExitNodeWithdrawn(e) => (
            StatementKind::ExitNodeOffer,
            e.signed.as_ref()?.cose_sign1.clone(),
        ),
        E::RelayEpochFloorAdvanced(e) => (
            StatementKind::RelayEpochFloor,
            e.relay_epoch_floor.as_ref()?.cose_sign1.clone(),
        ),
        E::LogHead(e) => (
            StatementKind::LogHead,
            e.statement.as_ref()?.cose_sign1.clone(),
        ),
        // `PairingApproved` carries two `PairingAttestation`s inside a
        // `PairingResult`, and both are verified by `twinvpn-trust` against the
        // two signing devices rather than as one statement here. It is folded
        // into the wildcard deliberately.
        _ => return None,
    };
    Some((kind, ReceivedOctets::from_wire_owned(cose)))
}

/// Plans the effect of one admitted event.
///
/// # Errors
///
/// [`CpError::StatementUnverified`] when a carrier's signature does not verify or
/// chains to the wrong authority — **the transport being authenticated is not
/// verification** — and [`CpError::TrustEpochRollback`] when the epoch regresses.
pub fn plan(
    admitted: &Admitted,
    body: &twinvpn_schema::v1::control_event::Event,
    verifier: &dyn StatementVerifier,
    trust_epoch: TrustEpoch,
) -> Result<Effect, CpError> {
    use twinvpn_schema::v1::control_event::Event as E;

    // Step 2 and 3: verify BEFORE any high-water comparison (R-1).
    let statement = if carries_signed_statement(body) {
        let (kind, octets) = statement_of(body).ok_or(CpError::StatementUnverified {
            statement_type: "missing",
        })?;
        Some(verify(verifier, &octets, kind)?)
    } else {
        None
    };

    let Some(net_seq) = admitted.net_seq() else {
        // Ephemeral. Nothing durable, ever.
        return Ok(match body {
            E::LogHead(_) => Effect::RecordFreshness,
            E::StateDocumentAvailable(e) => {
                let reference =
                    e.reference
                        .as_ref()
                        .ok_or(CpError::Rejected(twinvpn_schema::Reject::cap(
                            "state_document_ref",
                            0,
                            1,
                        )))?;
                let doc_type = DocumentType::from_wire(reference.doc_type).ok_or(
                    CpError::Rejected(twinvpn_schema::Reject::cap("doc_type", 0, 1)),
                )?;
                Effect::PullDocument {
                    doc_type,
                    version: reference.version,
                }
            }
            _ => Effect::Ephemeral,
        });
    };

    Ok(match body {
        E::DeviceRevoked(e) => {
            // Step 4: the epoch is checked only now, and only because the Owner
            // signature already verified. `admit` refuses any regression.
            let _ = trust_epoch.admit(e.trust_epoch)?;
            Effect::AdvanceTrustEpoch {
                epoch: e.trust_epoch,
                net_seq,
            }
        }
        E::PolicyBundleUpdated(e) => {
            debug_assert!(
                statement.is_some(),
                "policy.proto: until `signed` verifies, every field is a VIEW"
            );
            Effect::PutDocument {
                doc_type: DocumentType::PolicyBundle,
                version: e.policy_version,
                net_seq,
            }
        }
        E::RelayEpochFloorAdvanced(e) => Effect::PutDocument {
            doc_type: DocumentType::RelayEpochFloor,
            version: e.epoch,
            net_seq,
        },
        E::StreamCompacted(e) => Effect::CompactThenReread {
            up_to_net_seq: e.up_to_net_seq,
            net_seq,
        },
        _ => Effect::ApplyAndAdvance { net_seq },
    })
}

/// Verifies one statement and checks it chains to the authority its **type**
/// requires.
fn verify(
    verifier: &dyn StatementVerifier,
    octets: &ReceivedOctets,
    kind: StatementKind,
) -> Result<VerifiedStatement, CpError> {
    let outcome = verifier
        .verify(octets, kind)
        .map_err(|failure| map_verify_failure(failure, kind))?;
    if outcome.authority != outcome.kind.required_authority() {
        // Verified against *a* key, but not the one that may author this. A
        // `RouteAdvertisement` chaining to the Owner is coordination minting
        // routes; a `PolicyBundle` chaining to a device is a second policy author.
        return Err(CpError::StatementUnverified {
            statement_type: kind.as_str(),
        });
    }
    Ok(outcome)
}

const fn map_verify_failure(failure: VerifyFailure, kind: StatementKind) -> CpError {
    match failure {
        VerifyFailure::NonCanonical => {
            // Rejected, never normalized: normalizing attacker input before
            // verifying is a signature-bypass pattern.
            CpError::Rejected(twinvpn_schema::Reject::Unparseable {
                parser_id: "cose_sign1",
            })
        }
        _ => CpError::StatementUnverified {
            statement_type: kind.as_str(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{plan, statement_of, Effect};
    use crate::events::admit;
    use crate::ports::{StatementKind, VerifyFailure};
    use crate::revocation::TrustEpoch;
    use crate::testing::ScriptedVerifier;
    use twinvpn_schema::v1;
    use twinvpn_schema::v1::control_event::Event as E;

    fn signed(bytes: &[u8]) -> v1::SignedStatement {
        v1::SignedStatement {
            cose_sign1: bytes.to_vec(),
            statement_type: 2,
        }
    }

    fn event(body: E, net_seq: u64) -> v1::ControlEvent {
        let class = crate::events::classify(&body);
        v1::ControlEvent {
            metadata: Some(v1::MessageMetadata {
                net_seq,
                ..Default::default()
            }),
            durability: class.durability.to_wire(),
            publisher: class.publisher.to_wire(),
            event: Some(body),
        }
    }

    #[test]
    fn a_revocation_advances_the_epoch_only_after_the_signature_verifies() {
        let body = E::DeviceRevoked(v1::DeviceRevoked {
            revocation_entry: Some(signed(&[0xd2, 0x84, 0x01])),
            trust_epoch: 9,
            trust_epoch_bundle: None,
        });
        let ev = event(body.clone(), 40);
        let admitted = admit(&ev, 39).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::RevocationEntry);
        let effect = plan(&admitted, &body, &verifier, TrustEpoch::restored(8)).expect("planned");
        assert_eq!(
            effect,
            Effect::AdvanceTrustEpoch {
                epoch: 9,
                net_seq: 40
            }
        );
        assert!(effect.is_durable());
        assert_eq!(effect.cursor_advances_to(), Some(40));
    }

    #[test]
    fn an_unverified_revocation_never_reaches_the_high_water_comparison() {
        // ADR-0009 R-1: "An unverifiable document is discarded and NEVER compared
        // against the high-water mark." A forgery must not be able to advance a
        // floor even by being refused in the right order.
        let body = E::DeviceRevoked(v1::DeviceRevoked {
            revocation_entry: Some(signed(&[0xff])),
            trust_epoch: 99,
            trust_epoch_bundle: None,
        });
        let ev = event(body.clone(), 40);
        let admitted = admit(&ev, 39).expect("admitted");
        let verifier = ScriptedVerifier::refusing(VerifyFailure::BadSignature);
        let err = plan(&admitted, &body, &verifier, TrustEpoch::restored(8))
            .expect_err("no signature, no effect");
        assert_eq!(err.reason_code().as_str(), "AUTH.BINDING_INVALID");
        assert!(err.is_security_event());
    }

    #[test]
    fn a_verified_statement_signed_by_the_wrong_authority_is_still_refused() {
        // The transport was authenticated and the signature verified. Neither
        // makes coordination able to author policy.
        let body = E::PolicyBundleUpdated(v1::PolicyBundleUpdated {
            policy_version: 5,
            bundle: Some(v1::PolicyBundle {
                signed: Some(signed(&[1, 2, 3])),
                ..Default::default()
            }),
            reference: None,
        });
        let ev = event(body.clone(), 41);
        let admitted = admit(&ev, 40).expect("admitted");
        // The verifier claims it is a RouteAdvertisement — a device-authored
        // type — so `plan` dispatches PolicyBundle and gets a type mismatch.
        let verifier = ScriptedVerifier::accepting(StatementKind::RouteAdvertisement);
        let err = plan(&admitted, &body, &verifier, TrustEpoch::GENESIS).expect_err("refused");
        assert_eq!(err.reason_code().as_str(), "AUTH.BINDING_INVALID");
    }

    #[test]
    fn a_regressed_epoch_is_refused_even_with_a_good_signature() {
        let body = E::DeviceRevoked(v1::DeviceRevoked {
            revocation_entry: Some(signed(&[1])),
            trust_epoch: 3,
            trust_epoch_bundle: None,
        });
        let ev = event(body.clone(), 60);
        let admitted = admit(&ev, 59).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::RevocationEntry);
        let err =
            plan(&admitted, &body, &verifier, TrustEpoch::restored(12)).expect_err("rollback");
        assert_eq!(err.reason_code().as_str(), "AUTH.TRUST_EPOCH_ROLLBACK");
    }

    #[test]
    fn a_compaction_plans_a_declarative_reread_at_a_named_position() {
        let body = E::StreamCompacted(v1::StreamCompacted {
            up_to_net_seq: 9_000,
        });
        let ev = event(body.clone(), 70);
        let admitted = admit(&ev, 69).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::LogHead);
        let effect = plan(&admitted, &body, &verifier, TrustEpoch::GENESIS).expect("planned");
        assert_eq!(
            effect,
            Effect::CompactThenReread {
                up_to_net_seq: 9_000,
                net_seq: 70
            }
        );
    }

    #[test]
    fn an_ephemeral_event_plans_nothing_durable() {
        let body = E::PresenceUpdated(v1::PresenceUpdated::default());
        let ev = event(body.clone(), 0);
        let admitted = admit(&ev, 500).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::LogHead);
        let effect = plan(&admitted, &body, &verifier, TrustEpoch::GENESIS).expect("planned");
        assert_eq!(effect, Effect::Ephemeral);
        assert!(!effect.is_durable());
        assert_eq!(effect.cursor_advances_to(), None);
    }

    #[test]
    fn a_log_head_records_freshness_and_grants_nothing() {
        let body = E::LogHead(v1::LogHead {
            statement: Some(signed(&[9])),
            net_seq: 1_000,
            revocation_epoch: 4,
            not_after_ms: 99,
        });
        let ev = event(body.clone(), 0);
        let admitted = admit(&ev, 500).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::LogHead);
        let effect = plan(&admitted, &body, &verifier, TrustEpoch::GENESIS).expect("planned");
        assert_eq!(effect, Effect::RecordFreshness);
        assert!(!effect.is_durable());
        assert!(!StatementKind::LogHead.required_authority().confers_trust());
    }

    #[test]
    fn an_oversized_document_is_announced_and_pulled() {
        // ADR-0002 §11.4: > 16 KiB is a reference, and pull is always sufficient.
        let body = E::StateDocumentAvailable(v1::StateDocumentAvailable {
            reference: Some(v1::StateDocumentRef {
                doc_type: 1,
                version: 77,
                digest: vec![0u8; 32],
                size_bytes: 40_000,
            }),
        });
        let ev = event(body.clone(), 0);
        let admitted = admit(&ev, 10).expect("admitted");
        let verifier = ScriptedVerifier::accepting(StatementKind::LogHead);
        let effect = plan(&admitted, &body, &verifier, TrustEpoch::GENESIS).expect("planned");
        assert_eq!(
            effect,
            Effect::PullDocument {
                doc_type: crate::state::DocumentType::PolicyBundle,
                version: 77
            }
        );
    }

    #[test]
    fn statement_extraction_never_re_encodes() {
        let cose = vec![0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26];
        let body = E::RouteAdvertised(v1::RouteAdvertised {
            advertisement: Some(v1::RouteAdvertisement {
                signed: Some(signed(&cose)),
                ..Default::default()
            }),
        });
        let (kind, octets) = statement_of(&body).expect("carries one");
        assert_eq!(kind, StatementKind::RouteAdvertisement);
        assert_eq!(octets.as_slice(), cose.as_slice());
    }
}
