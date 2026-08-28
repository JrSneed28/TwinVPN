//! Herd-safe drain, and the `pair_tag` bucket both peers must compute alike.
//!
//! **Authority:** ADR-0005 §8 (`DRAIN`), §11.1(3) (the bucket);
//! ADR-0006 §11.7 (stampede control); `docs/reliability.md` §8.3 and transition
//! T37; ADR-0018 CD-1, CD-1a, CD-4; `contracts/docs/timestamps.md`.
//!
//! # The division of work, and why the client's half is a pure function
//!
//! `docs/reliability.md` §8.3 is explicit about where herd safety comes from:
//!
//! > devices move at a time drawn uniformly from `[0, deadline − 60 s]`.
//! > **Herd safety comes from the relay honouring the deadline it announced,
//! > not from client heuristics.**
//!
//! So the load-bearing half is the relay's, and the client's obligation is
//! narrow and exactly specified: draw uniformly from that interval. Parsing and
//! drawing are therefore separate here — a [`DrainNotice`] is *what arrived*
//! and [`DrainNotice::schedule_migration`] is *what this device decided* —
//! because a pure function of `(deadline, draw)` is the only form in which "a
//! drain does not stampede" is testable rather than asserted. The relay's own
//! `services/relay/src/drain.rs` splits it the same way, for the same reason.

use core::time::Duration;

use twinvpn_env::{Env, MonotonicInstant};
use twinvpn_types::RelayId;

/// A relay asking this device to leave, by a deadline.
///
/// Parsing and the entropy draw are deliberately separate: `docs/reliability.md`
/// §8.3 makes the *relay's* honouring of the deadline the load-bearing half,
/// and the client's half is a pure function of `(deadline, draw)` — which is
/// the only form in which "a drain does not stampede" is testable rather than
/// asserted. So a `DrainNotice` is what arrived, and
/// [`DrainNotice::schedule_migration`] is what this device decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainNotice {
    /// Which relay is draining.
    pub relay: RelayId,
    /// The announced deadline.
    pub deadline: Duration,
    /// Suggested alternates. A **hint**: check them against the verified map
    /// with [`super::admissible`] before binding one.
    pub suggested: Vec<RelayId>,
}

/// When this device will move off a draining relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationSchedule {
    /// The offset drawn from `[0, deadline − 60 s]`.
    pub offset: Duration,
    /// The instant to move, on the **injected monotonic clock** (CD-1).
    pub at: MonotonicInstant,
}

impl DrainNotice {
    /// Draws this device's migration instant.
    ///
    /// `docs/reliability.md` §8.3 and ADR-0006 §11.7: the instant is drawn
    /// uniformly from `[0, deadline − 60 s]`, so a fleet leaving a draining
    /// relay spreads across the drain window instead of arriving at its
    /// replacement together. The 60 s reserve exists so a device whose
    /// migration fails still has a full `T_MIGRATE` budget and one retry.
    ///
    /// The draw is `twinvpn_relay_client::failover::drain_offset`, which takes
    /// the [`Env`] and reads CD-4's `relay/region-spread` stream. **Not** a
    /// thread-local RNG: every device drawing the same offset is exactly the
    /// herd this exists to prevent, and a stream that cannot be seeded cannot
    /// be tested for that.
    ///
    /// # Errors
    ///
    /// Propagates the entropy or derivation failure rather than substituting a
    /// fixed offset — a substituted constant is the herd, silently.
    pub fn schedule_migration(
        &self,
        env: &Env,
    ) -> Result<MigrationSchedule, twinvpn_env::EnvError> {
        let offset = twinvpn_relay_client::failover::drain_offset(env, self.deadline)?;
        Ok(MigrationSchedule {
            offset,
            at: env.now_monotonic().saturating_add(offset),
        })
    }
}

/// The `pair_tag` bucket for the current wall-clock reading.
///
/// The bucket is a value **both peers must compute alike**, so it is neither
/// monotonic (a process-local origin two devices could never agree on) nor
/// elapsed (whose origin is equally host-local). It is
/// `seconds_since_epoch / 600`, and the relay computes exactly the same
/// quotient from its own clock — `services/relay/src/admit.rs` divides
/// `now_ms / 1_000 / pair_tag_bucket_seconds`.
///
/// `None` when the wall clock is `Unset`, which is CD-1a's **deferral** path
/// and not a defect: an RTC-less device between power-on and its first offset
/// is in a normal operating state, and ADR-0005's relay-supplied offset and
/// ADR-0009 K-2/K-6 resolve it. Answering `None` is how "not yet" stays
/// different from "no", where inventing a bucket would derive a `pair_tag` the
/// peer cannot match and produce an unexplainable `RELAY.PAIR_UNMATCHED`.
#[must_use]
pub fn pair_tag_bucket(env: &Env) -> Option<u64> {
    let clock = twinvpn_env::ValidityClock::try_from_reading(env.now_wall())?;
    Some(twinvpn_relay_client::bind::bucket_for(
        clock.millis().as_millis() / 1_000,
    ))
}

/// Re-exported so a caller need not reach past this module for the one constant
/// that decides whether a re-`BIND` cadence is legal.
pub use twinvpn_relay_client::bind::{ACCEPTED_BUCKET_SKEW, BUCKET_SECONDS, K_RENDEZVOUS};

/// Whether a bucket a peer used is inside the accepted skew.
///
/// Delegated rather than reimplemented: it is written as two comparisons rather
/// than a subtraction because the bucket is a `u64` and an underflow would
/// silently accept everything, and a second copy is a second place for that
/// to be got wrong.
#[must_use]
pub fn bucket_accepted(current: u64, received: u64) -> bool {
    twinvpn_relay_client::bind::bucket_accepted(current, received)
}

/// The codec's suggestion ceiling, for a caller sizing its own buffer.
pub use super::codec::MAX_SUGGESTED_RELAYS;
