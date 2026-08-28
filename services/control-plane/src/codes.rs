//! Every failure this service can produce, named by a **registered**
//! `reason_code` with that code's *declared* evidence attached.
//!
//! **Authority:** `ownership.md` §6 rule 12 ("expose registered `reason_code`s,
//! never raw internal errors"), CF-4 (no message string on the wire), ADR-0002
//! §11.11, ADR-0009 §11, `contracts/registry/reason_codes.json`.
//!
//! # Two codes ADR-0008 asks for, and the half of them Amendment 1 registered
//!
//! [ADR-0008](../../../../docs/adr/ADR-0008-idempotency.md) §11.2 requires of
//! **ADR-0003** — the *network* contract, which is this service's wire — "a
//! `precondition_failed` **and** a `duplicate_replayed` outcome in the
//! `reason_code` registry".
//!
//! Registry version 1 declared neither. **Amendment 1 (`registry_version` 2,
//! 201 -> 454 codes) declared both, in the `MGMT` domain, and the registry says
//! at `MGMT.DUPLICATE_REPLAYED` that it "supplies the *local half* of ADR-0008
//! §11.2's `duplicate_replayed` requirement".** That is exact and it is the
//! whole point: both new codes are
//! [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)'s,
//! §11's MI table owns them, and they answer for the agent's **local**
//! management interface. ADR-0008 §11.2 addresses **ADR-0003**. The remote half
//! — a conditional-write refusal a *control-plane client* receives — is still
//! not declared in any domain a control-plane response may carry.
//!
//! So the disposition below is unchanged in substance, and the reason it is
//! unchanged has moved from "the code does not exist" to "the code that exists
//! is the other half". Both halves are stated rather than hidden:
//!
//! - `duplicate_replayed` needs no code at all **here**.
//!   `MutationResult.idempotent_replay` is a **success** flag on a successful
//!   response; a reason code would imply a failure. It is emitted as the
//!   structured event ADR-0008 §10.2 asks for
//!   (`twinvpn_cp_idempotent_replay_total` plus an `INFO` line) and nothing on
//!   the wire changes. **No defect in practice.**
//! - `precondition_failed` has no such escape, and
//!   **`MGMT.PRECONDITION_FAILED` is not the repoint the tripwire was written
//!   to catch, for two independent reasons.** (1) Its declared evidence list is
//!   **empty**, so `offered_epoch` and `high_water_epoch` would be attached and
//!   then silently dropped — the exact W-6 failure mode [`carries`] exists to
//!   prevent — leaving a client told only *"someone else changed this"* with no
//!   version to re-read from. (2) `MGMT` on a control-plane response asserts to
//!   a remote client that the failure came from its own local agent, which is a
//!   worse lie than a wrong condition. It is therefore still mapped onto
//!   [`PRECONDITION_FAILED`] = `AUTH.TRUST_EPOCH_ROLLBACK`, whose declared
//!   evidence (`offered_epoch`, `high_water_epoch`) is exactly the pair a
//!   precondition failure carries. The cost is real and unchanged: a caller
//!   cannot distinguish "you raced another writer on a device label" from "you
//!   tried to roll the trust epoch back", and ADR-0015 §11.2's
//!   prefix-degradation story degrades a *consistency* failure into an *auth*
//!   one. **Still reported to the integration lead; Amendment 1 narrowed it
//!   rather than closing it.**

use twinvpn_service_common::ServiceError;
use twinvpn_types::{codes, EvidenceValue, ReasonCode};

use crate::COMPONENT;

/// ADR-0008 N-2's conditional-write refusal.
///
/// See the module docs: the registry declares no `precondition_failed` code
/// **that a control-plane response may carry** — Amendment 1 added ADR-0017's
/// local-MI pair and nothing for ADR-0003's wire — so this is still the interim
/// mapping, and it is deliberately a single named constant rather than a literal
/// at every call site: when the registry gains the remote half, one line changes.
pub const PRECONDITION_FAILED: ReasonCode = codes::AUTH_TRUST_EPOCH_ROLLBACK;

/// ADR-0009 R-4's fork detector, applied at the writer.
pub const FORKED_HISTORY: ReasonCode = codes::AUTH_TRUST_HISTORY_FORKED;

/// Nothing `Owner`-signed can be admitted because no trust anchor is bound.
///
/// **Fail closed.** A control plane that admitted an unverifiable
/// `RevocationStatement` or `PolicyBundle` would be granting authority it does
/// not have, which `lib.rs` calls a defect rather than a tradeoff.
pub const NO_TRUST_ANCHOR: ReasonCode = codes::AUTH_KEY_UNAVAILABLE;

/// A signature did not verify over the received octets.
pub const SIGNATURE_INVALID: ReasonCode = codes::AUTH_BINDING_INVALID;

/// The signer is not permitted to author this statement type — an `Owner`-only
/// statement signed by a device, or a device statement signed by the `Owner`
/// chain (which would be coordination minting routes).
pub const WRONG_SIGNING_AUTHORITY: ReasonCode = codes::AUTH_UNEXPECTED_DELEGATION;

/// Builds a `CONTROL.ADMISSION_DEFERRED` carrying the number the caller must
/// honour.
///
/// ADR-0002 §11.7 rule 3 / **S-6**: over-limit attaches receive an
/// application-level deferral with `retry_after_ms`. A TCP reset or a silent
/// drop is **prohibited**, and returning a typed error with the number in it is
/// how that prohibition is discharged.
#[must_use]
pub fn admission_deferred(retry_after_ms: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_ADMISSION_DEFERRED, COMPONENT)
        .evidence("retry_after_ms", EvidenceValue::DurationMs(retry_after_ms))
        .build()
}

/// `CONTROL.EVENT_RATE_EXCEEDED` — the per-`TwinNet` durable write budget.
///
/// ADR-0002 §11.6: the write is **refused**, not queued. "A queued over-budget
/// write is the flood, delayed."
#[must_use]
pub fn event_rate_exceeded() -> ServiceError {
    ServiceError::new(codes::CONTROL_EVENT_RATE_EXCEEDED, COMPONENT).build()
}

/// `CONTROL.WRITE_LEADER_UNAVAILABLE` — ADR-0002 N-4.
///
/// "A service without the lease MUST refuse the write … rather than writing
/// optimistically."
#[must_use]
pub fn write_leader_unavailable() -> ServiceError {
    ServiceError::new(codes::CONTROL_WRITE_LEADER_UNAVAILABLE, COMPONENT).build()
}

/// `CONTROL.QUORUM_UNAVAILABLE` — an E-1-class mutation that cannot reach
/// quorum is **refused, never partially applied**.
#[must_use]
pub fn quorum_unavailable() -> ServiceError {
    ServiceError::new(codes::CONTROL_QUORUM_UNAVAILABLE, COMPONENT).build()
}

/// `CONTROL.CURSOR_TOO_OLD` — the cursor is below the retention floor and the
/// device must re-snapshot declaratively (always correct, by N-5).
#[must_use]
pub fn cursor_too_old(cursor: u64, retention_floor: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_CURSOR_TOO_OLD, COMPONENT)
        .evidence("cursor", EvidenceValue::Uint(cursor))
        .evidence("retention_floor", EvidenceValue::Uint(retention_floor))
        .build()
}

/// `CONTROL.READ_TOO_STALE` — this replica cannot satisfy the caller's
/// `causality_token` and **MUST NOT serve a read it cannot satisfy**.
#[must_use]
pub fn read_too_stale(retry_after_ms: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_READ_TOO_STALE, COMPONENT)
        .evidence("retry_after_ms", EvidenceValue::DurationMs(retry_after_ms))
        .build()
}

/// `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR` — ADR-0009 §11.2 E-1(c).
#[must_use]
pub fn replica_behind_cursor(min_net_seq: u64, replica_net_seq: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_CONSISTENCY_REPLICA_BEHIND_CURSOR, COMPONENT)
        .evidence("min_net_seq", EvidenceValue::Uint(min_net_seq))
        .evidence("replica_net_seq", EvidenceValue::Uint(replica_net_seq))
        .build()
}

/// `CONTROL.CHANNEL_BINDING_MISMATCH` — ADR-0002 N-2. A **security event**.
#[must_use]
pub fn channel_binding_mismatch() -> ServiceError {
    ServiceError::new(codes::CONTROL_CHANNEL_BINDING_MISMATCH, COMPONENT).build()
}

/// `CONTROL.EVENT_WRONG_PUBLISHER` — protocol.md §7 / ADR-0002 S-4, enforced
/// **at the log**. A **security event**.
#[must_use]
pub fn wrong_publisher(event_type: &'static str, observed_publisher: &'static str) -> ServiceError {
    ServiceError::new(codes::CONTROL_EVENT_WRONG_PUBLISHER, COMPONENT)
        .evidence("event_type", EvidenceValue::Text(event_type.to_owned()))
        .evidence(
            "observed_publisher",
            EvidenceValue::Text(observed_publisher.to_owned()),
        )
        .build()
}

/// `CONTROL.STREAM_COMPACTED` — the backlog was shed; the gap is announced
/// **in band and in order** (N-8). Silent omission is prohibited.
#[must_use]
pub fn stream_compacted(up_to_net_seq: u64) -> ServiceError {
    ServiceError::new(codes::CONTROL_STREAM_COMPACTED, COMPONENT)
        .evidence("up_to_net_seq", EvidenceValue::Uint(up_to_net_seq))
        .build()
}

/// ADR-0008 N-2's refusal, with the pair the registry declares.
#[must_use]
pub fn precondition_failed(offered: u64, current: u64) -> ServiceError {
    ServiceError::new(PRECONDITION_FAILED, COMPONENT)
        .evidence("offered_epoch", EvidenceValue::Uint(offered))
        .evidence("high_water_epoch", EvidenceValue::Uint(current))
        .build()
}

/// ADR-0009 R-4: equal version, different content.
#[must_use]
pub fn forked_history(version: u64) -> ServiceError {
    ServiceError::new(FORKED_HISTORY, COMPONENT)
        .evidence("epoch", EvidenceValue::Uint(version))
        .build()
}

/// A revoked device presenting itself. `AUTH.DEVICE_REVOKED` is terminal.
#[must_use]
pub fn device_revoked(trust_epoch: u64) -> ServiceError {
    ServiceError::new(codes::AUTH_DEVICE_REVOKED, COMPONENT)
        .evidence("trust_epoch", EvidenceValue::Uint(trust_epoch))
        .build()
}

/// A bare registered code with no evidence, for the conditions whose registry
/// entry declares none.
#[must_use]
pub fn bare(code: ReasonCode) -> ServiceError {
    ServiceError::new(code, COMPONENT).build()
}

/// Whether `error` actually **carries** every key its constructor offered.
///
/// `twinvpn_types`' diagnostic builder attaches a key only if the registry
/// declares it for that code, and says nothing when it does not. So "I attached
/// evidence" and "the diagnosis carries evidence" are different facts, and only
/// the second reaches a bundle. This is the check that keeps them the same fact
/// here — the W-6 failure mode caught at the source rather than discovered when
/// a diagnostic bundle turns out to be empty.
#[must_use]
pub fn carries(error: &ServiceError, expected: &[&str]) -> bool {
    let set = error.diagnostic().evidence();
    expected
        .iter()
        .all(|key| error.code().declares_evidence(key) && set.get(key).is_some())
}

#[cfg(test)]
mod tests {
    use super::{
        admission_deferred, carries, cursor_too_old, device_revoked, forked_history,
        precondition_failed, read_too_stale, replica_behind_cursor, stream_compacted,
        wrong_publisher, NO_TRUST_ANCHOR, PRECONDITION_FAILED, SIGNATURE_INVALID,
        WRONG_SIGNING_AUTHORITY,
    };

    #[test]
    fn every_constructor_actually_carries_the_evidence_it_offers() {
        assert!(carries(&admission_deferred(750), &["retry_after_ms"]));
        assert!(carries(
            &cursor_too_old(4, 1_000_000),
            &["cursor", "retention_floor"]
        ));
        assert!(carries(&read_too_stale(250), &["retry_after_ms"]));
        assert!(carries(
            &replica_behind_cursor(90, 12),
            &["min_net_seq", "replica_net_seq"]
        ));
        assert!(carries(
            &wrong_publisher("device_revoked", "originating_device"),
            &["event_type", "observed_publisher"]
        ));
        assert!(carries(&stream_compacted(900), &["up_to_net_seq"]));
        assert!(carries(
            &precondition_failed(3, 7),
            &["offered_epoch", "high_water_epoch"]
        ));
        assert!(carries(&forked_history(7), &["epoch"]));
        assert!(carries(&device_revoked(42), &["trust_epoch"]));
    }

    #[test]
    fn the_security_events_are_terminal_and_critical() {
        // A wrong publisher and a channel-binding mismatch are the two
        // conditions ADR-0002 §11.11 marks FATAL/CRITICAL. If either ever
        // degrades to a warning, a receiver stops treating it as an attack.
        let wrong = wrong_publisher("device_revoked", "originating_device");
        assert!(wrong.code().terminal());
        assert_eq!(
            wrong.code().severity(),
            twinvpn_types::ErrorSeverity::Critical
        );
        let mismatch = super::channel_binding_mismatch();
        assert!(mismatch.code().terminal());
        assert_eq!(
            mismatch.code().severity(),
            twinvpn_types::ErrorSeverity::Critical
        );
    }

    #[test]
    fn the_interim_mappings_are_registered_codes() {
        // The whole point of §4.2: a code with no registry entry fails the
        // contract tests. These four are interim mappings, and an interim
        // mapping onto an UNREGISTERED code would be worse than the gap.
        for code in [
            PRECONDITION_FAILED,
            NO_TRUST_ANCHOR,
            SIGNATURE_INVALID,
            WRONG_SIGNING_AUTHORITY,
        ] {
            assert!(
                twinvpn_types::ReasonCode::lookup(code.as_str()).is_some(),
                "{} is not in the frozen registry",
                code.as_str()
            );
        }
    }

    /// Every registered code whose CONDITION segment is one of the two names
    /// ADR-0008 §11.2 asks for.
    ///
    /// `NET.SESSION.RETRY_PRECONDITION_MET` also contains "PRECONDITION" and is
    /// a different thing entirely, so the match is on the condition segment
    /// rather than on a substring.
    fn adr_0008_named_codes() -> impl Iterator<Item = twinvpn_types::ReasonCode> {
        twinvpn_types::ReasonCode::all().filter(|c| {
            let condition = c.as_str().rsplit('.').next().unwrap_or("");
            condition == "PRECONDITION_FAILED" || condition == "DUPLICATE_REPLAYED"
        })
    }

    #[test]
    fn the_registry_still_declares_no_precondition_failure_code_for_this_wire() {
        // The finding this module documents, NARROWED by Amendment 1 rather
        // than closed by it.
        //
        // Amendment 1 registered `MGMT.PRECONDITION_FAILED` and
        // `MGMT.DUPLICATE_REPLAYED`. Both are ADR-0017's, both answer for the
        // agent's LOCAL management interface, and the registry says so itself
        // at `MGMT.DUPLICATE_REPLAYED` ("the local half"). ADR-0008 §11.2
        // addresses ADR-0003 -- this service's wire. So the tripwire is
        // inverted rather than removed: it now fires the day a code lands in a
        // domain a control-plane RESPONSE may actually carry, which is the day
        // `PRECONDITION_FAILED` should be repointed.
        let found = adr_0008_named_codes().find(|c| c.as_str().split('.').next() != Some("MGMT"));
        assert!(
            found.is_none(),
            "the registry now declares {:?} outside MGMT; repoint PRECONDITION_FAILED",
            found.map(twinvpn_types::ReasonCode::as_str)
        );
    }

    #[test]
    fn the_mgmt_half_still_cannot_carry_the_version_pair() {
        // The SECOND reason `MGMT.PRECONDITION_FAILED` is not the repoint, and
        // the one that would survive even if the domain objection were waived:
        // its registry entry declares NO evidence, so `offered_epoch` and
        // `high_water_epoch` would be attached by the constructor and dropped
        // by the builder -- W-6, which `carries` exists to prevent. A client
        // would be told "someone else changed this" with no version to re-read
        // from.
        //
        // If Amendment 2 gives it the pair, this fails and the domain objection
        // becomes the only one left to argue.
        let mgmt: Vec<_> = adr_0008_named_codes()
            .filter(|c| c.as_str().split('.').next() == Some("MGMT"))
            .collect();
        assert!(
            !mgmt.is_empty(),
            "Amendment 1's MGMT half vanished; the module docs are now wrong"
        );
        for code in mgmt {
            assert!(
                !code.declares_evidence("offered_epoch")
                    && !code.declares_evidence("high_water_epoch"),
                "{} now declares the version pair; re-argue the repoint",
                code.as_str()
            );
        }
    }
}
