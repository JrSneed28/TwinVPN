//! The C2 cursor (S-27), and the compaction gap.
//!
//! **Authority:** ADR-0002 §11.7 rule 4 ("**Resume, do not reload**"), N-8
//! (compaction is announced in band and in order; silent omission is
//! prohibited), §11.10 row S-27, ADR-0009 R-8, R-9,
//! `contracts/proto/twinvpn/v1/control_commands.proto`
//! (`SubscribeEventsRequest.from_net_seq`).
//!
//! # The three rules
//!
//! 1. **The cursor is durable and local-authority.** S-27's conflict rule is
//!    "local wins; a server-offered cursor below the local high-water MUST be
//!    rejected". A control plane that offers us a lower position is either
//!    behind or hostile, and either way we do not go backwards. The refusal is
//!    `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR` — E-1(c)'s code for a replica
//!    whose position cannot satisfy our causality token, declaring exactly the
//!    two `net_seq` values — and not `AUTH.TRUST_EPOCH_ROLLBACK`, which is
//!    ADR-0007 N-26's code for a different fact (W-11).
//! 2. **Resume, never reload.** Re-snapshotting on every reconnect converts a
//!    reconnect storm into a bandwidth storm. A full re-snapshot happens only on
//!    `CONTROL.CURSOR_TOO_OLD` or a rebuilt log.
//! 3. **A gap is announced, never inferred.** `StreamCompacted` is an ordinary
//!    in-order event; it advances the cursor to a stated position and demands a
//!    declarative re-read. Because every durable event is independently
//!    applicable (N-5), "re-read the current documents" is always sufficient.
//!
//! ADR-0009 R-9 is why [`Cursor::advance_to`] returns the *intended* position
//! rather than mutating first: the durable write must land **before** the
//! document it admits is acted on, so a crash between the two cannot lose the
//! floor. The caller writes, then calls [`Cursor::commit`].

use crate::error::CpError;

/// The device's durable C2 high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    high_water: u64,
}

impl Cursor {
    /// A device that has never attached. `0` means "full snapshot", and it is
    /// the only value that legitimately requests one.
    pub const COLD_START: Cursor = Cursor { high_water: 0 };

    /// Restores from the durable store.
    #[must_use]
    pub const fn restored(high_water: u64) -> Self {
        Self { high_water }
    }

    /// The position to resume from, as `SubscribeEventsRequest.from_net_seq`.
    #[must_use]
    pub const fn from_net_seq(self) -> u64 {
        self.high_water
    }

    /// Whether this is a cold start that legitimately needs a full snapshot.
    #[must_use]
    pub const fn is_cold(self) -> bool {
        self.high_water == 0
    }

    /// Checks a server-offered resume position.
    ///
    /// # Errors
    ///
    /// [`CpError::ReplicaBehindCursor`] when the server offers a position below
    /// our durable mark. S-27: "a server-offered cursor below the local
    /// high-water MUST be rejected".
    pub const fn accept_server_position(self, offered: u64) -> Result<(), CpError> {
        if offered < self.high_water {
            return Err(CpError::ReplicaBehindCursor {
                min_net_seq: self.high_water,
                replica_net_seq: offered,
            });
        }
        Ok(())
    }

    /// The position this cursor would move to for an admitted event.
    ///
    /// # Errors
    ///
    /// [`CpError::ReplicaBehindCursor`] on a regression — the stream served at
    /// or below our mark. The caller persists the returned value, then calls
    /// [`Cursor::commit`] — ADR-0009 R-9's ordering.
    pub const fn advance_to(self, net_seq: u64) -> Result<u64, CpError> {
        if net_seq <= self.high_water {
            return Err(CpError::ReplicaBehindCursor {
                min_net_seq: self.high_water,
                replica_net_seq: net_seq,
            });
        }
        Ok(net_seq)
    }

    /// Moves the in-memory mark, **after** the durable write succeeded.
    pub const fn commit(&mut self, net_seq: u64) {
        if net_seq > self.high_water {
            self.high_water = net_seq;
        }
    }
}

/// What the stream told us to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeOutcome {
    /// The cursor is within the retention floor. Resume from it.
    Resume {
        /// The position to resume from.
        from_net_seq: u64,
    },
    /// A cold start. A full declarative snapshot is correct here and only here.
    ColdSnapshot,
    /// `CONTROL.CURSOR_TOO_OLD`: the cursor fell below the retention floor. A
    /// full declarative re-snapshot is required, and is always correct because
    /// every durable event is independently applicable (ADR-0002 N-5).
    ResnapshotStaleCursor {
        /// Where we were.
        cursor: u64,
        /// The floor the server reported.
        retention_floor: u64,
    },
    /// A deliberate, announced gap. The cursor lands exactly here and the device
    /// re-reads declaratively. **This is not a silent skip**, and the difference
    /// is the whole of N-8.
    CompactionGap {
        /// The position the cursor now holds.
        up_to_net_seq: u64,
    },
    /// ADR-0009 R-8: `shard_epoch` changed and `net_seq` came back below our
    /// cursor, so the log was rebuilt. The cursor is discarded and a full
    /// re-read follows — but **no `doc_version` or `trust_epoch` high-water mark
    /// is discarded with it**: R-5 and R-6 still bind, which is what stops a
    /// restore-from-backup from rewinding a device.
    LogRebuilt {
        /// The shard epoch we now see.
        shard_epoch: u64,
    },
}

impl ResumeOutcome {
    /// Whether this outcome requires a full declarative re-read.
    #[must_use]
    pub const fn needs_declarative_reread(self) -> bool {
        !matches!(self, ResumeOutcome::Resume { .. })
    }

    /// Whether any monotone high-water mark may be reset by this outcome.
    ///
    /// Always `false`. ADR-0009 R-8 is explicit even in the one case that
    /// discards a cursor: the device "MUST NOT discard any `doc_version` or
    /// `trust_epoch` high-water mark when doing so". A restore of an older
    /// control-plane backup therefore **strands** devices rather than rewinding
    /// them, which is the operational consequence
    /// `contracts/docs/idempotency.md` §5 calls "sharp and correct".
    #[must_use]
    pub const fn may_reset_monotone_marks(self) -> bool {
        false
    }
}

/// Decides how to open the stream given the durable cursor.
#[must_use]
pub const fn plan_resume(cursor: Cursor) -> ResumeOutcome {
    if cursor.is_cold() {
        ResumeOutcome::ColdSnapshot
    } else {
        ResumeOutcome::Resume {
            from_net_seq: cursor.from_net_seq(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_resume, Cursor, ResumeOutcome};

    #[test]
    fn a_warm_cursor_resumes_and_does_not_reload() {
        // ADR-0002 §11.7 rule 4: re-snapshotting on every reconnect is
        // PROHIBITED.
        let cursor = Cursor::restored(4_211);
        assert_eq!(
            plan_resume(cursor),
            ResumeOutcome::Resume {
                from_net_seq: 4_211
            }
        );
        assert!(!plan_resume(cursor).needs_declarative_reread());
    }

    #[test]
    fn only_a_cold_start_asks_for_a_snapshot() {
        assert_eq!(plan_resume(Cursor::COLD_START), ResumeOutcome::ColdSnapshot);
        assert!(Cursor::COLD_START.is_cold());
        assert!(!Cursor::restored(1).is_cold());
    }

    #[test]
    fn a_server_offered_cursor_below_the_local_mark_is_rejected() {
        let cursor = Cursor::restored(900);
        assert!(cursor.accept_server_position(900).is_ok());
        assert!(cursor.accept_server_position(1_000).is_ok());
        let err = cursor
            .accept_server_position(899)
            .expect_err("S-27: local wins");
        // E-1(c)'s code, carrying its declared evidence — not the trust-epoch
        // code, which would degrade to "authentication problem" (W-11).
        assert_eq!(
            err.reason_code().as_str(),
            "CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR"
        );
        assert!(!err.is_security_event());
        assert!(
            err.permits_offline_reconnect(),
            "we keep running on the cache"
        );
        let evidence = err.diagnostic();
        assert!(evidence.evidence().get("min_net_seq").is_some());
        assert!(evidence.evidence().get("replica_net_seq").is_some());
        assert_eq!(
            cursor.advance_to(900).expect_err("a replay").reason_code(),
            err.reason_code()
        );
    }

    #[test]
    fn advance_refuses_a_regression_and_commit_is_monotone() {
        let mut cursor = Cursor::restored(10);
        assert!(cursor.advance_to(10).is_err());
        assert!(cursor.advance_to(9).is_err());
        let next = cursor.advance_to(11).expect("forward");
        cursor.commit(next);
        assert_eq!(cursor.from_net_seq(), 11);
        // A late duplicate cannot pull the mark back.
        cursor.commit(3);
        assert_eq!(cursor.from_net_seq(), 11);
    }

    #[test]
    fn no_outcome_may_reset_a_monotone_mark() {
        for outcome in [
            ResumeOutcome::Resume { from_net_seq: 1 },
            ResumeOutcome::ColdSnapshot,
            ResumeOutcome::ResnapshotStaleCursor {
                cursor: 1,
                retention_floor: 9,
            },
            ResumeOutcome::CompactionGap { up_to_net_seq: 9 },
            ResumeOutcome::LogRebuilt { shard_epoch: 4 },
        ] {
            assert!(
                !outcome.may_reset_monotone_marks(),
                "ADR-0009 R-8 keeps doc_version and trust_epoch even when the cursor goes"
            );
        }
    }

    #[test]
    fn a_compaction_gap_is_surfaced_not_swallowed() {
        let gap = ResumeOutcome::CompactionGap {
            up_to_net_seq: 5_000,
        };
        assert!(gap.needs_declarative_reread());
        match gap {
            ResumeOutcome::CompactionGap { up_to_net_seq } => assert_eq!(up_to_net_seq, 5_000),
            other => panic!("the gap must name its position, got {other:?}"),
        }
    }
}
