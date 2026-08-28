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
//! # A reported gap: the seam has no "the system resumed" fact
//!
//! [`NetworkChange`] is `#[non_exhaustive]` and has variants for interfaces,
//! addresses, default routes, resolvers, NAT64 and link posture — and **none for
//! a suspend/resume boundary**. The nearest true statement the seam can carry is
//! [`NetworkChange::EventsLost`], whose documented meaning is "the stream dropped
//! events because the core was not draining" and whose documented consequence is
//! exactly right here: *"an adapter that reports the gap lets the core
//! re-enumerate and recover."*
//!
//! While the machine is asleep the `PF_ROUTE` socket is not being read, and
//! Darwin's routing socket has a finite kernel buffer, so events **are** lost
//! across a sleep — this is not a metaphor for the resume, it is a literal
//! description of it. Emitting `EventsLost` on wake is therefore both true and
//! sufficient: it forces the re-enumeration that stops a stale green.
//!
//! It is still less than the core deserves. A `SystemResumed { slept_for }`
//! variant would let the core distinguish "we missed some events" from "the
//! machine was off for nine hours", which are different facts with different
//! consequences for `T_TRUST_HARD` and for NAT binding lifetime. The seam is
//! frozen, so this is **reported to the integration lead, not patched**, and
//! [`PowerJournal::slept_across_last_wake`] carries the extra fact for a shell to
//! log until the seam can carry it.

use twinvpn_platform::NetworkChange;

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
    /// The fact the seam cannot carry — see the module documentation. A shell logs
    /// it; nothing branches on it.
    #[must_use]
    pub const fn slept_across_last_wake(&self) -> bool {
        self.slept_across_last_wake
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
    /// | `HasPoweredOn` | `EventsLost`, then `LinkPostureChanged { low_power: false }` | the routing socket was not drained while asleep, so events **were** lost; reporting the gap is what makes the core re-enumerate instead of trusting what it last saw |
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
    #[allow(clippy::match_same_arms)]
    pub fn observe(&mut self, event: PowerEvent) -> Vec<NetworkChange> {
        match event {
            PowerEvent::MaySleep => Vec::new(),
            PowerEvent::WillSleep => {
                self.phase = PowerPhase::Sleeping;
                self.sleeps = self.sleeps.saturating_add(1);
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
                vec![
                    // The count is genuinely unknown: Darwin's routing socket
                    // drops silently when its buffer fills and does not say how
                    // many. `None` is the honest answer, and the seam has a
                    // spelling for it.
                    NetworkChange::EventsLost { count: None },
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
        match PowerEvent::from_message(message) {
            Some(event) => (self.observe(event), event.needs_acknowledgement()),
            None => (Vec::new(), false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            events[1],
            NetworkChange::LinkPostureChanged {
                metered: false,
                low_power: false,
            }
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
