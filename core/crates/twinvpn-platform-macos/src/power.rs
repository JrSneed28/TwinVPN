//! Sleep and wake: IOKit's power messages, turned into facts the core consumes.
//!
//! **Authority:** ADR-0022 (lifecycle, background execution, sleep/wake), LC-8's
//! clock table, LC-17a; ADR-0018 CB-2 ("the shell holds no decision");
//! [`twinvpn_platform::NetworkChange`].
//!
//! # The rule this module exists to hold
//!
//! > A resume must not render a confident, stale green.
//!
//! The adapter's job is to report the fact; the core decides what it means. So
//! nothing here asks whether the tunnel is still good, nothing here re-validates a
//! path, and nothing here touches the `pf` anchor. [`PowerJournal::observe`]
//! turns one IOKit message into the [`NetworkChange`] events the core must see,
//! and the core's own reconciler does the rest.
//!
//! # The gap this module reported is closed
//!
//! Wave 2 reported that [`NetworkChange`] had variants for interfaces,
//! addresses, default routes, resolvers, NAT64 and link posture and **none for a
//! suspend/resume boundary**. [`NetworkChange::EventsLost`] was true and
//! sufficient for the stream — while the machine is asleep the `PF_ROUTE` socket
//! is not being read and Darwin's routing socket has a finite kernel buffer, so
//! events genuinely **are** lost across a sleep — but it could not say *"the
//! machine was off for nine hours"*, which is a different fact with different
//! consequences for `T_TRUST_HARD` and for NAT binding lifetime.
//!
//! The seam now carries [`NetworkChange::SystemResumed`] with
//! [`twinvpn_platform::ResumeFacts`], and this journal fills it. Both events are
//! emitted on a wake, in that order, because they are **two facts and not one**:
//! the stream has a hole, *and* wall time passed that no monotonic clock saw.
//!
//! The gap is measured on the **suspend-inclusive** clock
//! ([`crate::clock::ContinuousElapsedClock`], `mach_continuous_time`), which is
//! LC-8's `ElapsedClock` row and the only clock that advances while the machine
//! is asleep. Measuring it on `MonotonicClock` would report zero — which is
//! precisely the stale green this module exists to prevent.

use twinvpn_env::{BootId, ElapsedInstant};
use twinvpn_platform::{NetworkChange, ResumeFacts};

/// `<IOKit/IOMessage.h>`: the system-power messages this adapter reacts to.
///
/// `iokit_common_msg(x)` is `sys_iokit | sub_iokit_common | x`, i.e.
/// `0xE000_0000 | x`. Written out rather than taken from a crate: `IOKit` is not
/// a dependency of this crate, and these five numbers are the whole of the API
/// surface that matters.
pub mod msg {
    /// `kIOMessageCanSystemSleep` — an *advisory* query, and the one message
    /// this adapter must **not** answer with a veto. ADR-0022 does not license
    /// holding the machine awake for a VPN, and an `IOCancelPowerChange` here
    /// would do exactly that.
    pub const CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
    /// `kIOMessageSystemWillSleep` — sleep is committed and cannot be vetoed.
    pub const SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
    /// `kIOMessageSystemWillNotSleep` — a veto by somebody else; the machine
    /// stays awake.
    pub const SYSTEM_WILL_NOT_SLEEP: u32 = 0xE000_0290;
    /// `kIOMessageSystemWillPowerOn` — waking, but the drivers are not up yet.
    pub const SYSTEM_WILL_POWER_ON: u32 = 0xE000_0320;
    /// `kIOMessageSystemHasPoweredOn` — awake, and the network stack is usable.
    pub const SYSTEM_HAS_POWERED_ON: u32 = 0xE000_0300;
    /// `kIOMessageSystemWillPowerOff` — shutdown, not sleep.
    pub const SYSTEM_WILL_POWER_OFF: u32 = 0xE000_0250;
    /// `kIOMessageSystemWillRestart`.
    pub const SYSTEM_WILL_RESTART: u32 = 0xE000_0310;
}

/// One IOKit power message, named.
///
/// A closed enum rather than a raw `u32`, so a caller cannot invent a transition
/// the OS never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PowerEvent {
    /// The system asked whether it may sleep. Advisory; never vetoed here.
    MaySleep,
    /// Sleep is committed.
    WillSleep,
    /// A sleep somebody else vetoed.
    WillNotSleep,
    /// Waking; drivers not yet up.
    WillPowerOn,
    /// Awake; the network stack is usable again.
    HasPoweredOn,
    /// The machine is going down, not to sleep.
    WillPowerOff,
    /// The machine is restarting.
    WillRestart,
}

impl PowerEvent {
    /// The event a raw IOKit message names, or `None` for one we do not react to.
    #[must_use]
    pub const fn from_message(message: u32) -> Option<Self> {
        match message {
            msg::CAN_SYSTEM_SLEEP => Some(PowerEvent::MaySleep),
            msg::SYSTEM_WILL_SLEEP => Some(PowerEvent::WillSleep),
            msg::SYSTEM_WILL_NOT_SLEEP => Some(PowerEvent::WillNotSleep),
            msg::SYSTEM_WILL_POWER_ON => Some(PowerEvent::WillPowerOn),
            msg::SYSTEM_HAS_POWERED_ON => Some(PowerEvent::HasPoweredOn),
            msg::SYSTEM_WILL_POWER_OFF => Some(PowerEvent::WillPowerOff),
            msg::SYSTEM_WILL_RESTART => Some(PowerEvent::WillRestart),
            _ => None,
        }
    }

    /// Whether IOKit requires an `IOAllowPowerChange` acknowledgement.
    ///
    /// **`kIOMessageSystemWillSleep` must be acknowledged or the machine stalls
    /// for thirty seconds and then sleeps anyway**, so the shell has to answer it
    /// even though this adapter has nothing to decide. `kIOMessageCanSystemSleep`
    /// must also be answered — with *allow*, always: a VPN that vetoed sleep
    /// would drain a laptop, and ADR-0022 licenses no such thing.
    #[must_use]
    pub const fn needs_acknowledgement(self) -> bool {
        matches!(self, PowerEvent::MaySleep | PowerEvent::WillSleep)
    }
}

/// Where the machine is in the sleep cycle, as far as IOKit has said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerPhase {
    /// Running normally.
    #[default]
    Awake,
    /// Sleep is committed; the network stack is about to stop.
    Sleeping,
    /// Waking; drivers not yet up, so any network fact is untrustworthy.
    Waking,
}

/// The power-event state machine.
///
/// Holds the phase, and one counter per boundary so a diagnostic bundle can say
/// how many times this process has been suspended — ADR-0015's question, not a
/// decision.
#[derive(Debug, Clone, Copy, Default)]
pub struct PowerJournal {
    phase: PowerPhase,
    sleeps: u64,
    wakes: u64,
    /// Whether the most recent wake followed a committed sleep, as opposed to a
    /// `WillPowerOn` with no preceding `WillSleep` — which happens on a cold boot
    /// and on a dark wake.
    slept_across_last_wake: bool,
    /// The suspend-inclusive clock reading taken when sleep was committed.
    ///
    /// `None` until a `WillSleep` is observed with a clock, and cleared on each
    /// wake so a second wake cannot re-report the first sleep's gap.
    slept_at: Option<ElapsedInstant>,
}

impl PowerJournal {
    /// A journal in the awake phase.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: PowerPhase::Awake,
            sleeps: 0,
            wakes: 0,
            slept_across_last_wake: false,
            slept_at: None,
        }
    }

    /// The current phase.
    #[must_use]
    pub const fn phase(&self) -> PowerPhase {
        self.phase
    }

    /// How many committed sleeps this process has seen.
    #[must_use]
    pub const fn sleeps(&self) -> u64 {
        self.sleeps
    }

    /// How many wakes.
    #[must_use]
    pub const fn wakes(&self) -> u64 {
        self.wakes
    }

    /// Whether the last wake followed a committed sleep.
    ///
    /// Kept as a counter-style fact for a diagnostic bundle. The load-bearing
    /// version of it now crosses the seam inside
    /// [`NetworkChange::SystemResumed`], where the core can act on it.
    #[must_use]
    pub const fn slept_across_last_wake(&self) -> bool {
        self.slept_across_last_wake
    }

    /// The suspend-inclusive reading taken when sleep was committed, if any.
    #[must_use]
    pub const fn slept_at(&self) -> Option<ElapsedInstant> {
        self.slept_at
    }

    /// Observes one event and reports the changes the core must see.
    ///
    /// # What each transition reports, and why
    ///
    /// | Event | Reported | Why |
    /// |---|---|---|
    /// | `MaySleep` | nothing | advisory; the shell acknowledges and this adapter has nothing to say |
    /// | `WillSleep` | `LinkPostureChanged { low_power: true }` | the one true fact available before the stack stops. **No teardown**: CB-6 puts the ruleset in the OS's custody and a sleep must not drop protection |
    /// | `WillNotSleep` | `LinkPostureChanged { low_power: false }` | the posture the previous message announced did not happen |
    /// | `WillPowerOn` | nothing | drivers are not up; every network fact readable here is stale by construction |
    /// | `HasPoweredOn` | `EventsLost`, then `SystemResumed`, then `LinkPostureChanged { low_power: false }` | the routing socket was not drained while asleep, so events **were** lost; and wall time passed that no monotonic clock saw. Two facts, both reported |
    /// | `WillPowerOff` / `WillRestart` | nothing | the process is about to end; an event nobody will drain is not a report |
    ///
    /// **`EventsLost` comes first, deliberately.** A core that processed the
    /// posture change before the gap would have a moment in which it believed a
    /// fresh, low-power-cleared, otherwise-unchanged picture — which is the stale
    /// green ADR-0022 forbids.
    // `MaySleep` and the two shutdown events all report nothing, and each is
    // written out rather than merged: they report nothing for three DIFFERENT
    // reasons, named in the table above, and merging them would hide it when one
    // of them changes.
    ///
    /// This form reports [`ResumeFacts`] with **no measured gap**, because it has
    /// no clock. [`PowerJournal::observe_at`] is the one that measures, and a
    /// caller that has a [`crate::clock::ContinuousElapsedClock`] should use it —
    /// `suspended_for: None` is honest ("we do not know how long") and is not the
    /// same answer as `Some(ZERO)`, but it tells the core less than it could.
    #[allow(clippy::match_same_arms)]
    pub fn observe(&mut self, event: PowerEvent) -> Vec<NetworkChange> {
        self.observe_at(event, None, None)
    }

    /// Observes one event with a **suspend-inclusive** clock reading and, on a
    /// wake, the boot identity.
    ///
    /// `now` must come from `mach_continuous_time` — LC-8's `ElapsedClock` row —
    /// and never from `mach_absolute_time`, which does not advance while the
    /// machine is asleep and would report every nine-hour sleep as zero.
    ///
    /// `boot_id` is carried, not compared: LC-24 step 1 makes "the boot identity
    /// changed, so this is a cold start and not a resume" a **core** decision,
    /// and an adapter that decided it would be holding one (CB-2).
    #[allow(clippy::match_same_arms)]
    pub fn observe_at(
        &mut self,
        event: PowerEvent,
        now: Option<ElapsedInstant>,
        boot_id: Option<BootId>,
    ) -> Vec<NetworkChange> {
        match event {
            PowerEvent::MaySleep => Vec::new(),
            PowerEvent::WillSleep => {
                self.phase = PowerPhase::Sleeping;
                self.sleeps = self.sleeps.saturating_add(1);
                // The reading is taken HERE, in the bounded pre-sleep window
                // LC-25 describes, because it is the last moment at which a
                // clock can be read before the gap begins.
                self.slept_at = now;
                vec![NetworkChange::LinkPostureChanged {
                    metered: false,
                    low_power: true,
                }]
            }
            PowerEvent::WillNotSleep => {
                self.phase = PowerPhase::Awake;
                vec![NetworkChange::LinkPostureChanged {
                    metered: false,
                    low_power: false,
                }]
            }
            PowerEvent::WillPowerOn => {
                self.phase = PowerPhase::Waking;
                Vec::new()
            }
            PowerEvent::HasPoweredOn => {
                self.slept_across_last_wake = !matches!(self.phase, PowerPhase::Awake);
                self.phase = PowerPhase::Awake;
                self.wakes = self.wakes.saturating_add(1);
                let suspended_for = match (self.slept_at.take(), now) {
                    (Some(went), Some(back)) => Some(back.duration_since(went)),
                    // Either end of the measurement is missing: a wake with no
                    // preceding sleep (a dark wake, a cold boot), or a caller
                    // with no clock. `None` says "we do not know how long",
                    // which is a different answer from `Some(ZERO)` and the one
                    // that keeps the core from treating a nine-hour sleep as an
                    // instant.
                    _ => None,
                };
                vec![
                    // The count is genuinely unknown: Darwin's routing socket
                    // drops silently when its buffer fills and does not say how
                    // many. `None` is the honest answer, and the seam has a
                    // spelling for it.
                    NetworkChange::EventsLost { count: None },
                    NetworkChange::SystemResumed(ResumeFacts {
                        suspended_for,
                        boot_id,
                        // IOKit told us. This is not an inference from a clock
                        // divergence, and the core is entitled to know which.
                        announced_by_os: true,
                        // Darwin's power messages do not distinguish S3 from S4:
                        // `kIOMessageSystemHasPoweredOn` is the same message for
                        // a sleep and for a hibernate, so LC-24 step 5's
                        // `PLATFORM.LIFECYCLE.HIBERNATE_RESUMED` is not
                        // answerable here. `None`, never a guess.
                        hibernated: None,
                    }),
                    NetworkChange::LinkPostureChanged {
                        metered: false,
                        low_power: false,
                    },
                ]
            }
            PowerEvent::WillPowerOff | PowerEvent::WillRestart => Vec::new(),
        }
    }

    /// The same, from a raw IOKit message.
    ///
    /// Returns `(events, needs_acknowledgement)`. The shell must call
    /// `IOAllowPowerChange` when the second is `true`, and must do so **whatever
    /// the first contains** — a VPN that stalled a sleep for thirty seconds and
    /// then let it happen anyway would be worse than one that never registered.
    pub fn observe_message(&mut self, message: u32) -> (Vec<NetworkChange>, bool) {
        self.observe_message_at(message, None, None)
    }

    /// The same, with a suspend-inclusive clock reading and the boot identity.
    pub fn observe_message_at(
        &mut self,
        message: u32,
        now: Option<ElapsedInstant>,
        boot_id: Option<BootId>,
    ) -> (Vec<NetworkChange>, bool) {
        match PowerEvent::from_message(message) {
            Some(event) => (
                self.observe_at(event, now, boot_id),
                event.needs_acknowledgement(),
            ),
            None => (Vec::new(), false),
        }
    }
}

/// The `ResumeFacts` a wake with no measurement can report.
///
/// Named rather than written inline so that "we could not measure it" is one
/// value with one meaning, and a reader can grep for every place that admits it.
#[must_use]
pub const fn unmeasured_resume() -> ResumeFacts {
    ResumeFacts {
        suspended_for: None,
        boot_id: None,
        announced_by_os: true,
        hibernated: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    #[test]
    fn the_iokit_message_numbers_are_the_common_msg_encoding() {
        // `iokit_common_msg(x)` is `err_system(0x38) | sub_iokit_common | x`,
        // i.e. `0xE0000000 | x`. Written out rather than depended on, so a typo
        // is visible in one place.
        assert_eq!(msg::SYSTEM_WILL_SLEEP, 0xE000_0000 | 0x280);
        assert_eq!(msg::SYSTEM_HAS_POWERED_ON, 0xE000_0000 | 0x300);
        assert_eq!(msg::SYSTEM_WILL_POWER_ON, 0xE000_0000 | 0x320);
        assert_eq!(msg::CAN_SYSTEM_SLEEP, 0xE000_0000 | 0x270);
        assert_eq!(msg::SYSTEM_WILL_NOT_SLEEP, 0xE000_0000 | 0x290);
    }

    #[test]
    fn a_message_we_do_not_react_to_is_ignored_and_not_acknowledged() {
        let mut journal = PowerJournal::new();
        let (events, ack) = journal.observe_message(0xE000_0010);
        assert!(events.is_empty());
        assert!(!ack);
        assert_eq!(journal.phase(), PowerPhase::Awake);
    }

    #[test]
    fn a_committed_sleep_must_be_acknowledged_and_an_advisory_one_too() {
        // `kIOMessageSystemWillSleep` unacknowledged stalls the machine for
        // thirty seconds and then sleeps anyway; `kIOMessageCanSystemSleep`
        // unanswered does the same. Both must be answered even though this
        // adapter decides nothing.
        assert!(PowerEvent::WillSleep.needs_acknowledgement());
        assert!(PowerEvent::MaySleep.needs_acknowledgement());
        assert!(!PowerEvent::HasPoweredOn.needs_acknowledgement());
        assert!(!PowerEvent::WillPowerOn.needs_acknowledgement());
    }

    #[test]
    fn a_resume_reports_the_gap_before_it_reports_the_posture() {
        // A core that processed the posture change first would have a moment in
        // which it believed a fresh, low-power-cleared, otherwise-unchanged
        // picture. That moment is the stale green ADR-0022 forbids.
        let mut journal = PowerJournal::new();
        journal.observe(PowerEvent::WillSleep);
        journal.observe(PowerEvent::WillPowerOn);
        let events = journal.observe(PowerEvent::HasPoweredOn);
        assert_eq!(events[0], NetworkChange::EventsLost { count: None });
        assert!(matches!(events[1], NetworkChange::SystemResumed(_)));
        assert_eq!(
            events[2],
            NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: false,
            }
        );
    }

    /// **"The machine was off for nine hours" — the fact `EventsLost` could not
    /// carry.**
    ///
    /// Measured on `mach_continuous_time`, which is LC-8's `ElapsedClock` row and
    /// the only clock that advances while the machine is asleep. The same nine
    /// hours read from `mach_absolute_time` would be zero.
    #[test]
    fn a_measured_resume_carries_the_gap_the_monotonic_clock_cannot_see() {
        let mut journal = PowerJournal::new();
        let asleep_at = ElapsedInstant::from_micros(1_000_000);
        let awake_at = asleep_at.saturating_add(Duration::from_secs(9 * 3600));

        journal.observe_at(PowerEvent::WillSleep, Some(asleep_at), None);
        journal.observe_at(PowerEvent::WillPowerOn, None, None);
        let boot = BootId::from_array([7u8; 16]);
        let events = journal.observe_at(PowerEvent::HasPoweredOn, Some(awake_at), Some(boot));

        let NetworkChange::SystemResumed(facts) = events[1] else {
            panic!("a wake reports a resume");
        };
        assert_eq!(facts.suspended_for, Some(Duration::from_secs(9 * 3600)));
        assert_eq!(facts.boot_id, Some(boot));
        assert!(facts.announced_by_os, "IOKit told us; we did not infer it");
        assert_eq!(
            facts.hibernated, None,
            "Darwin's power messages do not distinguish S3 from S4"
        );
    }

    /// **`None` is not `Some(ZERO)`.**
    ///
    /// A wake with no preceding sleep — a dark wake, or a process that started
    /// after the sleep began — cannot measure the gap. Reporting zero would tell
    /// the core no time had passed, which is exactly the confident stale green.
    #[test]
    fn an_unmeasurable_gap_is_none_and_never_zero() {
        let mut journal = PowerJournal::new();
        let events = journal.observe_at(
            PowerEvent::HasPoweredOn,
            Some(ElapsedInstant::from_micros(5_000_000)),
            None,
        );
        let NetworkChange::SystemResumed(facts) = events[1] else {
            panic!("a wake reports a resume");
        };
        assert_eq!(facts.suspended_for, None);
        assert_ne!(facts.suspended_for, Some(Duration::ZERO));
    }

    /// A second wake must not re-report the first sleep's gap.
    #[test]
    fn the_measurement_is_consumed_by_the_wake_that_reports_it() {
        let mut journal = PowerJournal::new();
        let asleep_at = ElapsedInstant::from_micros(1_000_000);
        journal.observe_at(PowerEvent::WillSleep, Some(asleep_at), None);
        let first = journal.observe_at(
            PowerEvent::HasPoweredOn,
            Some(asleep_at.saturating_add(Duration::from_secs(60))),
            None,
        );
        let NetworkChange::SystemResumed(a) = first[1] else {
            panic!("resume");
        };
        assert_eq!(a.suspended_for, Some(Duration::from_secs(60)));

        let second = journal.observe_at(
            PowerEvent::HasPoweredOn,
            Some(asleep_at.saturating_add(Duration::from_secs(600))),
            None,
        );
        let NetworkChange::SystemResumed(b) = second[1] else {
            panic!("resume");
        };
        assert_eq!(
            b.suspended_for, None,
            "a wake with no sleep behind it has nothing to measure"
        );
    }

    #[test]
    fn the_dropped_event_count_is_none_because_darwin_does_not_say() {
        let mut journal = PowerJournal::new();
        journal.observe(PowerEvent::WillSleep);
        let events = journal.observe(PowerEvent::HasPoweredOn);
        assert_eq!(
            events[0],
            NetworkChange::EventsLost { count: None },
            "a fabricated count would be worse than an honest absence"
        );
    }

    #[test]
    fn a_full_sleep_cycle_walks_the_phases_and_counts_both_boundaries() {
        let mut journal = PowerJournal::new();
        assert_eq!(journal.phase(), PowerPhase::Awake);
        journal.observe(PowerEvent::MaySleep);
        assert_eq!(journal.phase(), PowerPhase::Awake, "advisory only");
        journal.observe(PowerEvent::WillSleep);
        assert_eq!(journal.phase(), PowerPhase::Sleeping);
        journal.observe(PowerEvent::WillPowerOn);
        assert_eq!(journal.phase(), PowerPhase::Waking);
        journal.observe(PowerEvent::HasPoweredOn);
        assert_eq!(journal.phase(), PowerPhase::Awake);
        assert_eq!(journal.sleeps(), 1);
        assert_eq!(journal.wakes(), 1);
        assert!(journal.slept_across_last_wake());
    }

    #[test]
    fn a_vetoed_sleep_returns_to_awake_and_does_not_count_as_a_sleep_cycle() {
        let mut journal = PowerJournal::new();
        journal.observe(PowerEvent::MaySleep);
        let events = journal.observe(PowerEvent::WillNotSleep);
        assert_eq!(journal.phase(), PowerPhase::Awake);
        assert_eq!(journal.sleeps(), 0);
        assert_eq!(journal.wakes(), 0);
        assert_eq!(
            events,
            vec![NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: false,
            }]
        );
    }

    #[test]
    fn a_dark_wake_with_no_preceding_sleep_is_reported_as_not_having_slept() {
        // A cold boot and a dark wake both deliver `HasPoweredOn` with no
        // preceding `WillSleep`. The gap must still be reported — the routing
        // socket was not being drained either way — but the shell should be able
        // to tell the two apart in a log.
        let mut journal = PowerJournal::new();
        let events = journal.observe(PowerEvent::HasPoweredOn);
        assert_eq!(events[0], NetworkChange::EventsLost { count: None });
        assert!(!journal.slept_across_last_wake());
        assert_eq!(journal.sleeps(), 0);
        assert_eq!(journal.wakes(), 1);
    }

    #[test]
    fn nothing_in_the_journal_tears_anything_down_on_sleep() {
        // CB-6 puts the installed ruleset in the OS's custody precisely so the
        // core going quiet does not drop protection. A sleep is the core going
        // quiet, so it must produce a FACT and nothing else.
        let mut journal = PowerJournal::new();
        let events = journal.observe(PowerEvent::WillSleep);
        assert_eq!(
            events,
            vec![NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: true,
            }],
            "a sleep reports a posture and instructs nothing"
        );
    }

    #[test]
    fn shutdown_and_restart_report_nothing_because_nobody_will_drain_it() {
        let mut journal = PowerJournal::new();
        assert!(journal.observe(PowerEvent::WillPowerOff).is_empty());
        assert!(journal.observe(PowerEvent::WillRestart).is_empty());
    }

    #[test]
    fn repeated_sleep_cycles_accumulate_rather_than_resetting() {
        let mut journal = PowerJournal::new();
        for _ in 0..3 {
            journal.observe(PowerEvent::WillSleep);
            journal.observe(PowerEvent::HasPoweredOn);
        }
        assert_eq!(journal.sleeps(), 3);
        assert_eq!(journal.wakes(), 3);
    }
}
