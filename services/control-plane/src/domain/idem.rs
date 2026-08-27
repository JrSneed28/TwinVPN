//! Server-side dedup on `idempotency_key`: **exactly-once effect, never
//! exactly-once delivery.**
//!
//! **Authority:** ADR-0008 N-4, N-5, N-6, N-9; `contract-matrix.md` §5 ("no hop
//! claims exactly-once delivery — it is unachievable over an unreliable
//! network"); `limits.json identifiers.idempotency_key_{min,max}_bytes`;
//! `control_commands.proto`'s `MutationResult.idempotent_replay`.
//!
//! # The single most important behaviour in this service
//!
//! > *A `CEREMONY` replay must return the **original outcome** —
//! > `CompletePairing` replaying to a new outcome is what produces asymmetric
//! > trust.*
//!
//! So [`admit`] answers before any handler runs, and [`Admitted::Replay`] hands
//! back **stored octets**, not a re-derivation. There is no path on which a
//! duplicate re-executes a ceremony inside the window, because there is no call
//! to the handler on that path.
//!
//! # The window's expiry cliff, and what actually closes it
//!
//! ADR-0008 N-6: a duplicate arriving **after** the 24 h window "MUST be
//! evaluated against the version precondition (N-2) and therefore MUST fail
//! rather than re-execute. The expiry cliff is closed by N-2, not by a longer
//! window." This module therefore does *not* extend the window, refuse
//! late duplicates, or keep a tombstone. It reports [`Admitted::Fresh`] and lets
//! the handler's own precondition and terminal-state checks refuse — which they
//! do, and `an_expired_duplicate_is_refused_by_the_precondition_not_the_window`
//! in `tests/idempotency_ceremony.rs` is the evidence.

use twinvpn_service_common::{Reject, ServiceError};

use crate::config::IDEMPOTENCY_WINDOW_MS;
use crate::model::IdempotencyRecord;
use crate::{Command, NetTx};

use super::{Ctx, Outcome};

/// `limits.json identifiers.idempotency_key_min_bytes` — ADR-0008 N-4's ≥128
/// bits.
pub const KEY_MIN_BYTES: usize = 16;
/// `limits.json identifiers.idempotency_key_max_bytes`.
pub const KEY_MAX_BYTES: usize = 64;

/// What the dedup log said about this request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    /// Execute. The key is recorded when the handler succeeds.
    Fresh {
        /// The validated key, to record the outcome under.
        key: Vec<u8>,
    },
    /// Do **not** execute. Return these octets.
    Replay {
        /// The recorded response, byte for byte.
        response: Vec<u8>,
        /// The position the *original* effect committed at.
        committed_at_net_seq: u64,
    },
}

/// Validates the key and consults the dedup log.
///
/// # Errors
///
/// - `PROTO.MALFORMED_MESSAGE` when a `CEREMONY` carries no key, or one outside
///   `[16, 64]` bytes. ADR-0008 N-4 makes the key **required**, and a ceremony
///   admitted without one is a ceremony whose retry duplicates it.
/// - `PROTO.MALFORMED_MESSAGE` when the key was already used for a *different*
///   command. Serving the other command's recorded response would answer a
///   question that was not asked.
pub fn admit(
    tx: &NetTx,
    ctx: &Ctx<'_>,
    command: Command,
    key: &[u8],
) -> Result<Admitted, ServiceError> {
    debug_assert!(
        command.class().requires_idempotency_key(),
        "admit is for CEREMONY commands; ADR-0008 N-9 forbids a dedup log elsewhere"
    );

    if key.len() < KEY_MIN_BYTES || key.len() > KEY_MAX_BYTES {
        return Err(ServiceError::from_reject(
            &Reject::CapViolated {
                cap_violated: "idempotency_key_bytes",
                observed: key.len() as u64,
                limit: KEY_MAX_BYTES as u64,
            },
            crate::COMPONENT,
        ));
    }

    // N-4: scoped to the authenticated DeviceIdentity, so one device cannot
    // replay another's ceremony by guessing its key.
    let lookup = (ctx.caller, key.to_vec());
    match tx.state().idempotency.get(&lookup) {
        None => Ok(Admitted::Fresh { key: key.to_vec() }),
        Some(record) if record.command != command => Err(ServiceError::from_reject(
            &Reject::CapViolated {
                cap_violated: "idempotency_key_reused_across_commands",
                observed: 1,
                limit: 0,
            },
            crate::COMPONENT,
        )),
        Some(record) => {
            if within_window(record, ctx.now_ms) {
                Ok(Admitted::Replay {
                    response: record.response.clone(),
                    committed_at_net_seq: record.committed_at_net_seq,
                })
            } else {
                // N-6. Not a refusal here: the handler's precondition refuses.
                Ok(Admitted::Fresh { key: key.to_vec() })
            }
        }
    }
}

/// Whether a record is still inside the 24 h window.
///
/// A record stamped *after* `now_ms` — a clock that went backwards across a
/// failover — is treated as inside the window rather than outside it. Erring
/// toward replay is the safe direction: replaying a recorded outcome is always
/// correct, re-executing a ceremony is what produces asymmetric trust.
#[must_use]
pub fn within_window(record: &IdempotencyRecord, now_ms: u64) -> bool {
    now_ms.saturating_sub(record.stored_at_ms) < IDEMPOTENCY_WINDOW_MS
}

/// Records the outcome of a freshly executed ceremony.
///
/// The **replay** form is what is stored, so a duplicate is answered with the
/// recorded octets literally verbatim — no decode, no re-encode, no chance of
/// the replay differing from what was promised.
pub fn record_outcome(
    tx: &mut NetTx,
    ctx: &Ctx<'_>,
    command: Command,
    key: Vec<u8>,
    outcome: &Outcome,
) {
    let record = IdempotencyRecord {
        command,
        response: outcome.replay.clone(),
        committed_at_net_seq: outcome.committed_at_net_seq,
        stored_at_ms: ctx.now_ms,
    };
    tx.put_idempotency(ctx.caller, key, record);
}

#[cfg(test)]
mod tests {
    use super::{admit, record_outcome, within_window, Admitted, KEY_MAX_BYTES, KEY_MIN_BYTES};
    use crate::config::IDEMPOTENCY_WINDOW_MS;
    use crate::domain::{Ctx, Outcome};
    use crate::model::{IdempotencyRecord, NetState};
    use crate::tx::WriteLease;
    use crate::verify::RefuseUnverifiable;
    use crate::{Command, NetTx};
    use twinvpn_service_common::Correlation;

    const V: RefuseUnverifiable = RefuseUnverifiable;

    fn ctx(now_ms: u64) -> Ctx<'static> {
        Ctx {
            caller: [3u8; 32],
            twinnet_id: "tn",
            now_ms,
            verifier: &V,
            quorum_available: true,
            correlation: Correlation::empty(),
            coordination_endpoints: &[],
            v6_derivation: crate::domain::addressing::Ipv6Derivation::DeviceIdTruncation,
        }
    }

    fn tx(state: NetState, now_ms: u64) -> NetTx {
        NetTx::open(state, WriteLease { shard_epoch: 1 }, now_ms).expect("lease")
    }

    fn key() -> Vec<u8> {
        vec![9u8; KEY_MIN_BYTES]
    }

    #[test]
    fn a_ceremony_without_a_key_of_the_right_width_is_refused() {
        let t = tx(NetState::new("tn"), 0);
        for bad in [
            Vec::new(),
            vec![1u8; KEY_MIN_BYTES - 1],
            vec![1u8; KEY_MAX_BYTES + 1],
        ] {
            let err = admit(&t, &ctx(0), Command::CompletePairing, &bad)
                .expect_err("ADR-0008 N-4 makes the key required");
            assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
        }
        assert!(admit(&t, &ctx(0), Command::CompletePairing, &key()).is_ok());
    }

    #[test]
    fn a_duplicate_inside_the_window_replays_the_recorded_octets_verbatim() {
        let mut t = tx(NetState::new("tn"), 100);
        let outcome = Outcome {
            first: vec![0xaa, 0x01],
            replay: vec![0xaa, 0x02],
            committed_at_net_seq: 77,
            replayed: false,
        };
        record_outcome(&mut t, &ctx(100), Command::CompletePairing, key(), &outcome);

        match admit(&t, &ctx(200), Command::CompletePairing, &key()).expect("admits") {
            Admitted::Replay {
                response,
                committed_at_net_seq,
            } => {
                assert_eq!(
                    response, outcome.replay,
                    "the RECORDED outcome, not a re-derivation"
                );
                assert_eq!(committed_at_net_seq, 77);
            }
            Admitted::Fresh { .. } => panic!("a duplicate must not re-execute"),
        }
    }

    #[test]
    fn one_device_cannot_replay_anothers_ceremony() {
        // N-4: the key is scoped to the authenticated DeviceIdentity.
        let mut t = tx(NetState::new("tn"), 0);
        let outcome = Outcome {
            first: vec![1],
            replay: vec![2],
            committed_at_net_seq: 1,
            replayed: false,
        };
        record_outcome(&mut t, &ctx(0), Command::BeginPairing, key(), &outcome);

        let other = Ctx {
            caller: [4u8; 32],
            ..ctx(0)
        };
        assert!(matches!(
            admit(&t, &other, Command::BeginPairing, &key()).expect("admits"),
            Admitted::Fresh { .. }
        ));
    }

    #[test]
    fn a_key_reused_across_commands_is_refused_rather_than_cross_served() {
        let mut t = tx(NetState::new("tn"), 0);
        let outcome = Outcome {
            first: vec![1],
            replay: vec![2],
            committed_at_net_seq: 1,
            replayed: false,
        };
        record_outcome(&mut t, &ctx(0), Command::BeginPairing, key(), &outcome);
        let err = admit(&t, &ctx(0), Command::RevokeDevice, &key())
            .expect_err("a revocation must not be answered with a pairing's response");
        assert_eq!(err.code().as_str(), "PROTO.MALFORMED_MESSAGE");
    }

    #[test]
    fn the_window_is_the_frozen_twenty_four_hours_and_a_backwards_clock_still_replays() {
        let record = IdempotencyRecord {
            command: Command::PutPolicy,
            response: Vec::new(),
            committed_at_net_seq: 1,
            stored_at_ms: 1_000_000,
        };
        assert!(within_window(&record, 1_000_000));
        assert!(within_window(
            &record,
            1_000_000 + IDEMPOTENCY_WINDOW_MS - 1
        ));
        assert!(!within_window(&record, 1_000_000 + IDEMPOTENCY_WINDOW_MS));
        // A clock that went backwards across a failover errs toward replay.
        assert!(within_window(&record, 1));
    }

    #[test]
    fn a_duplicate_outside_the_window_is_fresh_and_n_2_is_what_refuses_it() {
        let mut t = tx(NetState::new("tn"), 0);
        let outcome = Outcome {
            first: vec![1],
            replay: vec![2],
            committed_at_net_seq: 1,
            replayed: false,
        };
        record_outcome(&mut t, &ctx(0), Command::CompletePairing, key(), &outcome);
        let late = ctx(IDEMPOTENCY_WINDOW_MS + 1);
        assert!(
            matches!(
                admit(&t, &late, Command::CompletePairing, &key()).expect("admits"),
                Admitted::Fresh { .. }
            ),
            "N-6: the expiry cliff is closed by the precondition, not by this module"
        );
    }
}
