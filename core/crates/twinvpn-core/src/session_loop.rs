//! The `Env`-driven loop that actually fires `twinvpn-session`'s transitions.
//!
//! **Authority:** `docs/reliability.md` §4 (the state machine), §5 (the timer
//! register), §5.3.1 (which clock each constant reads), §11 (background and
//! suspended operation); [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CD-1, CD-2, CB-2, F-9; ADR-0022 via §11.16 (e).
//!
//! # What `core-dataplane` deliberately left undone
//!
//! `twinvpn_session::SessionMachine` ships every §4.5 transition
//! **synchronously**, taking `now` as a parameter, with no async and no I/O —
//! which is what makes the table testable as a pure function. The consequence is
//! that nothing in that crate ever *fires* a timer or *observes* a network
//! change. This module is the missing half: it arms deadlines on the injected
//! [`twinvpn_env::Timer`], turns platform facts into `§4.3` events, and calls
//! `apply`.
//!
//! # CD-1's third reason, made structural
//!
//! Every deadline here is computed from [`twinvpn_env::MonotonicInstant`] and
//! waited on with [`twinvpn_env::Timer::sleep_until`]. **No timer takes the
//! elapsed clock.** §5.3.1 puts the elapsed clock only on constants that *bound a
//! granted authority*, and [`Timers::arm`] refuses a constant whose declared
//! `ClockClass` is not `Monotonic` — so the rule is checked at the arming site
//! rather than trusted at the call site.
//!
//! # CB-2, at the one place a decision could leak
//!
//! [`event_for_change`] is where an OS fact becomes a TwinVPN domain event. The
//! adapter reports *"interface 3 went away"*; the **core** decides that this is
//! `EV_LINK_DOWN{Wi-Fi}` and that `EV_LINK_DOWN` in `STEADY` means T19 or T20
//! depending on whether an alternate exists. A shell that made that mapping would
//! be holding a branch on a domain fact, which CB-2 forbids and the falsification
//! test in `tests/falsification.rs` is what proves it does not.

use core::time::Duration;

use twinvpn_env::{BootId, Env, MonotonicInstant};
use twinvpn_platform::iface::{InterfaceFacts, LinkClass, NetworkChange, ResumeFacts};
use twinvpn_session::event::{Event, LinkKind, TimerId, Trigger};
use twinvpn_session::state::SessionState;
use twinvpn_session::timers::{self, ClockClass, TimerConstant};
use twinvpn_session::{Context, Guards, Outcome, SessionMachine};

/// The deadlines one `Session` currently has armed.
///
/// A map rather than a list of futures: `docs/reliability.md` §5 registers each
/// timer by name and at most one of each is live per `Session`, so re-arming
/// `T_CONNECT` must *replace* the outstanding deadline rather than add a second
/// one. A second `T_CONNECT` is how a `Session` acquires two contradictory
/// timeouts and takes whichever fires first.
#[derive(Debug, Default)]
pub struct Timers {
    /// A small sorted vector rather than a map: `TimerId` is deliberately not
    /// `Ord` in `twinvpn-session` (ordering timers is not a domain fact), at most
    /// eight can be armed at once, and a linear scan over eight entries is
    /// cheaper than a tree. Ordering for `fire_due` comes from [`order`], which
    /// is exhaustive and therefore stable.
    armed: Vec<(TimerId, MonotonicInstant)>,
}

/// A deterministic order for two timers expiring in the same tick.
///
/// Exhaustive over [`TimerId`], so a new timer must be given a position rather
/// than inheriting one — a lab replay that reordered two same-tick expiries
/// would produce a different transition sequence for the same seed.
const fn order(id: TimerId) -> u8 {
    match id {
        TimerId::Discover => 0,
        TimerId::Negotiate => 1,
        TimerId::Connect => 2,
        TimerId::Migrate => 3,
        TimerId::ReconnectGrace => 4,
        TimerId::ReconnectMax => 5,
        TimerId::DegradedMax => 6,
        TimerId::Backoff => 7,
        // `TimerId` is `#[non_exhaustive]`. A timer this build does not know
        // sorts last rather than panicking: refusing to fire a known timer
        // because an unknown one exists would be the worse failure.
        _ => u8::MAX,
    }
}

impl Timers {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms `id` for `constant`'s default, from `now`.
    ///
    /// # Panics
    ///
    /// If `constant` does not declare [`ClockClass::Monotonic`]. That is
    /// deliberate and it is CD-1's third reason: a timer on the elapsed clock
    /// fires immediately after an eight-hour suspend, tearing down a `Session`
    /// that was merely asleep. `docs/reliability.md` §5.3.1 declares the class
    /// per constant, so arming the wrong one is a programming error this catches
    /// at the call site rather than a behaviour that shows up only on a phone.
    pub fn arm(&mut self, id: TimerId, constant: TimerConstant, now: MonotonicInstant) {
        assert!(
            constant.clock == ClockClass::Monotonic,
            "{} declares {:?}; every TIMER takes the MONOTONIC clock (ADR-0018 CD-1). A \
             constant on the elapsed clock bounds a granted authority and is evaluated, \
             never slept on.",
            constant.name,
            constant.clock
        );
        self.set(id, now.saturating_add(constant.default));
    }

    /// Arms `id` for an explicit duration on the monotonic clock.
    ///
    /// Used by the backoff tick, whose interval is computed rather than
    /// registered.
    pub fn arm_for(&mut self, id: TimerId, delay: core::time::Duration, now: MonotonicInstant) {
        self.set(id, now.saturating_add(delay));
    }

    /// Replaces (never duplicates) one deadline.
    fn set(&mut self, id: TimerId, deadline: MonotonicInstant) {
        if let Some(slot) = self.armed.iter_mut().find(|(existing, _)| *existing == id) {
            slot.1 = deadline;
        } else {
            self.armed.push((id, deadline));
        }
    }

    /// Cancels one deadline. Idempotent.
    pub fn cancel(&mut self, id: TimerId) {
        self.armed.retain(|(existing, _)| *existing != id);
    }

    /// Cancels every deadline.
    pub fn cancel_all(&mut self) {
        self.armed.clear();
    }

    /// The earliest armed deadline, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonotonicInstant> {
        self.armed.iter().map(|(_, d)| *d).min()
    }

    /// Every timer due at `now`, removed from the armed set.
    ///
    /// Returned in `TimerId` order so two timers expiring in the same tick fire
    /// deterministically — a lab replay that reordered them would produce a
    /// different transition sequence for the same seed.
    pub fn fire_due(&mut self, now: MonotonicInstant) -> Vec<TimerId> {
        let mut due: Vec<TimerId> = self
            .armed
            .iter()
            .filter(|(_, deadline)| now.reached(*deadline))
            .map(|(id, _)| *id)
            .collect();
        due.sort_unstable_by_key(|id| order(*id));
        self.armed.retain(|(id, _)| !due.contains(id));
        due
    }

    /// How many deadlines are armed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.armed.len()
    }

    /// Whether nothing is armed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.armed.is_empty()
    }

    /// Whether `id` is armed.
    #[must_use]
    pub fn is_armed(&self, id: TimerId) -> bool {
        self.armed.iter().any(|(existing, _)| *existing == id)
    }
}

/// The timers a state owns, per `docs/reliability.md` §5.
///
/// Exhaustive over [`SessionState`]: a thirteenth state would fail to compile
/// here rather than silently acquire no timeout, which is how a `Session` gets
/// stuck forever in a state nobody bounded.
#[must_use]
pub fn timers_for(state: SessionState) -> &'static [(TimerId, TimerConstant)] {
    match state {
        SessionState::Discovering => &[(TimerId::Discover, timers::T_DISCOVER)],
        SessionState::Negotiating => &[(TimerId::Negotiate, timers::T_NEGOTIATE)],
        SessionState::Connecting => &[(TimerId::Connect, timers::T_CONNECT)],
        SessionState::Migrating { .. } => &[(TimerId::Migrate, timers::T_MIGRATE)],
        SessionState::Reconnecting { .. } => &[
            (TimerId::ReconnectGrace, timers::T_RECONNECT_GRACE),
            (TimerId::ReconnectMax, timers::T_RECONNECT_MAX),
        ],
        SessionState::Degraded { .. } => &[(TimerId::DegradedMax, timers::T_DEGRADED_MAX)],
        // `BLOCKED`'s loop is T31's backoff tick, whose interval is computed from
        // `twinvpn_session::backoff` and therefore armed with `arm_for`.
        SessionState::Blocked
        | SessionState::Disconnected
        | SessionState::Steady(_)
        | SessionState::Failed => &[],
    }
}

/// One `Session`, driven.
pub struct SessionRuntime {
    machine: SessionMachine,
    timers: Timers,
    env: Env,
}

impl SessionRuntime {
    /// Wraps a machine with its deadline set.
    ///
    /// Takes `Env` at construction (CD-2). There is no `Default`, no global and
    /// no lazily-initialised clock anywhere on this path.
    #[must_use]
    pub fn new(env: Env, machine: SessionMachine) -> Self {
        Self {
            machine,
            timers: Timers::new(),
            env,
        }
    }

    /// The machine, for reads.
    #[must_use]
    pub const fn machine(&self) -> &SessionMachine {
        &self.machine
    }

    /// The armed deadlines.
    #[must_use]
    pub const fn timers(&self) -> &Timers {
        &self.timers
    }

    /// Applies a trigger and re-arms the deadlines the new state owns.
    ///
    /// The re-arm is here rather than at each call site for the same reason
    /// ADR-0015 O-05 puts the transition event inside `apply`: a state entered by
    /// a path that forgot to arm its timeout is a `Session` with no upper bound,
    /// and R5 forbids unbounded degradation.
    pub fn apply(&mut self, trigger: Trigger, guards: Guards, ctx: Context) -> Outcome {
        let before = self.machine.state();
        let outcome = self.machine.apply(trigger, guards, ctx);
        let after = self.machine.state();

        if before != after {
            self.rearm(after);
            return outcome;
        }

        // **W-34.** The state did not change, and if the trigger was a TIMER
        // then `fire_due` has already consumed its deadline — so nothing is left
        // to bound the state.
        //
        // §4.4 bounds every transient state deliberately: `DISCOVERING` by
        // `T_DISCOVER`, `CONNECTING` by `T_CONNECT`, `RECONNECTING` by
        // `T_RECONNECT_GRACE`. A timer that fires and matches no §4.5 row would
        // leave the machine in one of them with **no deadline at all**, which is
        // the unbounded state those constants exist to prevent. It is not
        // reachable from a driver that delivers `EV_CANDIDATES_READY` promptly,
        // and it is exactly the shape that becomes reachable the moment a guard
        // is false for a reason nobody anticipated.
        //
        // Re-arming rather than leaving it bare is the safe direction: the worst
        // case is one extra timeout on a state that was going to time out
        // anyway, and the alternative is a `Session` that waits forever.
        if matches!(trigger, Trigger::Timer(_)) {
            self.rearm_missing(after);
        }
        outcome
    }

    /// Re-arms any deadline `state` owns that is not currently armed.
    ///
    /// Distinct from [`SessionRuntime::rearm`], which cancels first: this one
    /// **must not** disturb a deadline that is still running, because a state
    /// with two live timers is only in trouble if one of them is a duplicate of
    /// the other.
    fn rearm_missing(&mut self, state: SessionState) {
        let now = self.env.now_monotonic();
        for (id, constant) in timers_for(state) {
            if !self.timers.is_armed(*id) {
                self.timers.arm(*id, *constant, now);
            }
        }
    }

    /// Re-arms for `state`, cancelling everything the previous state owned.
    fn rearm(&mut self, state: SessionState) {
        let now = self.env.now_monotonic();
        self.timers.cancel_all();
        for (id, constant) in timers_for(state) {
            self.timers.arm(*id, *constant, now);
        }
    }

    /// Fires every timer due now, in order, and returns the outcomes.
    ///
    /// `guards` and `ctx` are supplied by the caller because the machine cannot
    /// invent them: `docs/reliability.md` §4.5 evaluates guards *in the order
    /// written*, and the values are accumulated by `twinvpn-path`,
    /// `twinvpn-relay-client` and `twinvpn-tunnel` as they work.
    pub fn tick(&mut self, guards: Guards, ctx: Context) -> Vec<Outcome> {
        let now = self.env.now_monotonic();
        let due = self.timers.fire_due(now);
        due.into_iter()
            .map(|id| self.apply(Trigger::Timer(id), guards, ctx))
            .collect()
    }

    /// Sleeps until the next deadline, on the **monotonic** clock.
    ///
    /// Returns `false` when nothing is armed, so a caller can park on its event
    /// source instead of spinning. Cancellation is dropping the returned future,
    /// which `twinvpn_env::Timer` requires a binding to honour.
    pub async fn sleep_to_next_deadline(&self) -> bool {
        let Some(deadline) = self.timers.next_deadline() else {
            return false;
        };
        self.env.timer().sleep_until(deadline).await;
        true
    }
}

/// **CB-2's boundary, in one function.** An OS fact becomes a domain event.
///
/// `NetworkChange` is documented as *"a fact, never an instruction: the adapter
/// reports what happened and the core decides what it means"*. This is that
/// decision, and it lives in the core so that six shells cannot each make it
/// differently (R-31).
///
/// `facts` is the interface the change refers to, where the core still has it.
/// It is what turns a bare index into `EV_LINK_DOWN{Wi-Fi}` versus
/// `EV_LINK_DOWN{Cellular}` — a distinction T20's `caused_by` evidence needs and
/// that the index alone cannot supply.
#[must_use]
// Several arms answer `EV_ADDR_CHANGED`, and three answer `None`. Merging them
// would collapse §4.3's distinctions into one line and lose the reason each
// change maps where it does — which is the whole content of this function.
#[allow(clippy::match_same_arms)]
pub fn event_for_change(change: &NetworkChange, facts: Option<&InterfaceFacts>) -> Option<Event> {
    let kind = facts.map_or(LinkKind::Unknown, |f| link_kind(f.link_class));
    match change {
        NetworkChange::InterfaceRemoved(_) => Some(Event::LinkDown(kind)),
        NetworkChange::InterfaceAdded(_) => Some(Event::LinkUp(kind)),
        NetworkChange::LinkStateChanged { is_up, .. } => Some(if *is_up {
            Event::LinkUp(kind)
        } else {
            Event::LinkDown(kind)
        }),
        // An address change is `EV_ADDR_CHANGED` and NOT a link event: §4.3
        // separates them because T21 turns on "the local address changed (as
        // opposed to the interface)", and collapsing them loses exactly that
        // guard.
        NetworkChange::AddressAdded { .. } | NetworkChange::AddressRemoved { .. } => {
            Some(Event::AddrChanged)
        }
        // A default route arriving or leaving for ONE family is an address-level
        // change, per ADR-0010 R6's case: "IPv6 appears *after* the tunnel is up".
        // It is not a link event, because the link did not move.
        NetworkChange::DefaultRouteChanged { .. } | NetworkChange::Nat64PrefixChanged(_) => {
            Some(Event::AddrChanged)
        }
        // The host came back. §4.3 has an event for exactly this and
        // `host.lifecycle` also carries it, which is not a duplication: that
        // command carries a one-byte PHASE and this carries the MEASUREMENT, and
        // the machine needs both — T35's guards are read from
        // `ResumeVerdict` below.
        NetworkChange::SystemResumed(_) => Some(Event::Resume),
        // These three carry no §4.3 event. They are facts other components read —
        // the resolver set, the metering posture, and the adapter's own dropped-
        // event report — and inventing a transition for them would move the
        // machine on something the table does not name.
        NetworkChange::ResolversChanged
        | NetworkChange::LinkPostureChanged { .. }
        | NetworkChange::EventsLost { .. } => None,
        // `NetworkChange` is `#[non_exhaustive]`. A variant this build does not
        // know is NOT mapped to a plausible event: guessing would move the state
        // machine on a fact we cannot read. The caller records it instead.
        _ => None,
    }
}

/// What the core decides a resume means.
///
/// **Authority:** ADR-0022 LC-24 step 1 (classify the resume), LC-8's finding F2
/// (long-horizon deadlines read the elapsed clock), `docs/reliability.md` §11.3
/// (compare the gap against the rekey window).
///
/// # This is the decision, and it is here
///
/// [`ResumeFacts`] is a *fact*: how long the host was away, which boot session
/// it came back in, and whether the OS said so or the adapter inferred it. What
/// that means — cold start or resume, rekey or resume the session, trust the
/// assertion we are holding or not — is the core's, and CB-2's falsification
/// test is what keeps it here rather than in three shells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeVerdict {
    /// **This was not a resume at all.** LC-24 step 1: a changed boot identity
    /// means the machine rebooted, and the whole of LC-4 runs as a cold start.
    pub cold_start: bool,
    /// The gap exceeded the rekey window, so a full handshake is forced.
    ///
    /// `docs/reliability.md` §11.3, measured on the **elapsed** clock. LC-8's
    /// finding F3 is explicit that the wall clock is the wrong measure: a
    /// wall-clock jump across a suspend is also a timezone change, an NTP step,
    /// or a user setting the clock.
    pub rekey_window_exceeded: bool,
    /// Whether the gap is **unknown** rather than short.
    ///
    /// Kept separate from `rekey_window_exceeded` because the two have the same
    /// consequence and different causes, and a support case needs to tell them
    /// apart: "we were asleep for nine hours" and "we cannot say how long we
    /// were asleep" are not the same sentence.
    pub gap_unknown: bool,
}

impl ResumeVerdict {
    /// Decides what a resume means.
    ///
    /// `held_boot_id` is the identity the core was holding before the gap;
    /// `rekey_window` is `docs/reliability.md` §11.3's constant.
    ///
    /// # The safe direction, and why it is the safe one
    ///
    /// **An unmeasured gap counts as exceeded.** `suspended_for: None` says the
    /// adapter could not measure how long the host was away — a wake with no
    /// announced sleep behind it, a process that started mid-suspend, a platform
    /// with no clock to offer. Treating that as "no time passed" is precisely
    /// the confident stale green ADR-0022 forbids: the session would resume on a
    /// key that may be older than the rekey window, and the
    /// `ProtectionAssertion` the UI renders would be one nobody re-checked. The
    /// cost of the safe reading is one unnecessary handshake.
    #[must_use]
    pub fn decide(
        facts: &ResumeFacts,
        held_boot_id: Option<BootId>,
        rekey_window: Duration,
    ) -> Self {
        // LC-24 step 1. Only a KNOWN mismatch is a cold start: if either side is
        // absent we cannot tell, and inventing a cold start would tear down a
        // healthy session on every resume on a platform with no boot identity.
        let cold_start = match (facts.boot_id, held_boot_id) {
            (Some(now), Some(held)) => now != held,
            _ => false,
        };
        let gap_unknown = facts.suspended_for.is_none();
        let rekey_window_exceeded = facts.suspended_for.is_none_or(|gap| gap > rekey_window);
        Self {
            cold_start,
            rekey_window_exceeded,
            gap_unknown,
        }
    }

    /// Whether the `ProtectionAssertion` the core is holding may still be
    /// rendered as-is.
    ///
    /// Always `false`. It is a function rather than a constant because the
    /// *reason* is the point and a reader should meet it here: ADR-0022 LC-24
    /// step 2 puts the enforcement query **before** any packet and before the
    /// wake ladder, and LC-22 makes a re-attaching surface render `UNKNOWN`
    /// rather than the last value it remembers. A resume is the same situation
    /// one level down — the core's picture is as old as the gap — so the
    /// assertion is stale by construction, whatever the gap turned out to be.
    #[must_use]
    pub const fn assertion_is_still_fresh(self) -> bool {
        false
    }
}

/// The `LinkKind` T20's evidence needs, from the adapter's capability fact.
///
/// Branches on `LinkClass`, which is a **declared capability** and not an OS
/// (CB-3).
const fn link_kind(class: LinkClass) -> LinkKind {
    match class {
        LinkClass::WiFi => LinkKind::WiFi,
        LinkClass::Cellular => LinkKind::Cellular,
        LinkClass::Ethernet => LinkKind::Ethernet,
        _ => LinkKind::Unknown,
    }
}

#[cfg(test)]
mod tests {

    fn resume(suspended_for: Option<Duration>, boot_id: Option<BootId>) -> ResumeFacts {
        ResumeFacts {
            suspended_for,
            boot_id,
            announced_by_os: true,
            hibernated: None,
        }
    }

    #[test]
    fn a_resume_is_an_ev_resume_and_the_gap_is_read_separately() {
        // The variant maps to §4.3's event; the MEASUREMENT it carries is what
        // `ResumeVerdict` reads. `EventsLost` still maps to nothing, because a
        // hole in the stream is not a transition.
        assert_eq!(
            event_for_change(
                &NetworkChange::SystemResumed(resume(Some(Duration::from_secs(60)), None)),
                None
            ),
            Some(E::Resume)
        );
        assert_eq!(
            event_for_change(&NetworkChange::EventsLost { count: None }, None),
            None
        );
    }

    #[test]
    fn a_gap_past_the_rekey_window_forces_a_handshake_and_a_short_one_does_not() {
        let window = Duration::from_secs(120);
        let long = ResumeVerdict::decide(
            &resume(Some(Duration::from_secs(9 * 3600)), None),
            None,
            window,
        );
        assert!(long.rekey_window_exceeded);
        assert!(!long.gap_unknown);
        assert!(!long.cold_start);

        let short =
            ResumeVerdict::decide(&resume(Some(Duration::from_secs(5)), None), None, window);
        assert!(!short.rekey_window_exceeded);
    }

    /// **An unmeasured gap is not a short gap.**
    ///
    /// This is the whole point of `suspended_for` being an `Option`. Reading
    /// `None` as "no time passed" would resume a session on a key that may be
    /// older than the rekey window and render an assertion nobody re-checked —
    /// the confident stale green ADR-0022 forbids.
    #[test]
    fn an_unknown_gap_is_treated_as_exceeding_the_window() {
        let v = ResumeVerdict::decide(&resume(None, None), None, Duration::from_secs(120));
        assert!(v.rekey_window_exceeded);
        assert!(v.gap_unknown, "and the two reasons stay distinguishable");
    }

    #[test]
    fn a_changed_boot_identity_is_a_cold_start_and_not_a_resume() {
        // LC-24 step 1: after a reboot both monotonic clocks restart at zero,
        // which is indistinguishable from "no time passed". `boot_id` is the
        // discriminator, and it is compared HERE rather than in the adapter.
        let held = BootId::from_array([1u8; 16]);
        let same = ResumeVerdict::decide(
            &resume(Some(Duration::from_secs(30)), Some(held)),
            Some(held),
            Duration::from_secs(120),
        );
        assert!(!same.cold_start);

        let other = BootId::from_array([2u8; 16]);
        let rebooted = ResumeVerdict::decide(
            &resume(Some(Duration::from_secs(30)), Some(other)),
            Some(held),
            Duration::from_secs(120),
        );
        assert!(rebooted.cold_start);
    }

    #[test]
    fn an_absent_boot_identity_is_never_read_as_a_reboot() {
        // Inventing a cold start on a platform that reports no boot identity
        // would tear down a healthy session on every single resume.
        let held = BootId::from_array([1u8; 16]);
        let w = Duration::from_secs(120);
        assert!(
            !ResumeVerdict::decide(&resume(Some(Duration::ZERO), None), Some(held), w).cold_start
        );
        assert!(
            !ResumeVerdict::decide(&resume(Some(Duration::ZERO), Some(held)), None, w).cold_start
        );
    }

    #[test]
    fn a_resume_never_leaves_the_assertion_fresh() {
        // LC-24 step 2 puts the enforcement query before any packet; LC-22 makes
        // a surface with a stale picture render UNKNOWN rather than its last
        // value. A one-second nap is still a gap the core did not watch.
        let v = ResumeVerdict::decide(
            &resume(Some(Duration::from_secs(1)), None),
            None,
            Duration::from_secs(3600),
        );
        assert!(!v.rekey_window_exceeded, "a one-second nap needs no rekey");
        assert!(
            !v.assertion_is_still_fresh(),
            "and it still must not render a confident green"
        );
    }
    use super::*;
    use twinvpn_session::event::Event as E;
    use twinvpn_types::SessionId;

    fn env() -> (Env, twinvpn_env::virtual_time::VirtualTime) {
        let vt = twinvpn_env::virtual_time::VirtualTime::new(twinvpn_env::WallClockReading::Unset);
        let env = Env::new(twinvpn_env::EnvParts {
            monotonic: vt.monotonic(),
            elapsed: vt.elapsed(),
            wall: vt.wall(),
            timer: vt.timer(),
            runtime: vt.runtime(),
            entropy: std::sync::Arc::new(ZeroEntropy),
            rng: std::sync::Arc::new(twinvpn_env::SystemRngSource::new(std::sync::Arc::new(
                ZeroEntropy,
            ))),
        });
        (env, vt)
    }

    struct ZeroEntropy;
    impl twinvpn_env::Entropy for ZeroEntropy {
        fn fill(&self, dst: &mut [u8]) -> Result<(), twinvpn_env::EnvError> {
            dst.fill(0);
            Ok(())
        }
    }

    fn runtime() -> (SessionRuntime, twinvpn_env::virtual_time::VirtualTime) {
        let (env, vt) = env();
        let machine =
            SessionMachine::new(env.clone(), SessionId::from_slice(&[1; 16]).expect("16"));
        (SessionRuntime::new(env, machine), vt)
    }

    fn connect_guards() -> Guards {
        Guards {
            credentials_valid: true,
            peer_authorized: true,
            ..Guards::default()
        }
    }

    #[test]
    fn entering_discovering_arms_t_discover() {
        let (mut rt, _vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        assert_eq!(rt.machine().state(), SessionState::Discovering);
        assert!(rt.timers().is_armed(TimerId::Discover));
    }

    #[test]
    fn a_due_timer_fires_the_transition_it_names() {
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        vt.advance(timers::T_DISCOVER.default);
        // T04 needs `no_candidate_either_family`; supplying it makes the timer
        // MOVE the machine, which is the case this test is about.
        let guards = Guards {
            no_candidate_either_family: true,
            ..Guards::default()
        };
        let outcomes = rt.tick(guards, Context::default());
        assert_eq!(outcomes.len(), 1, "T_DISCOVER must fire exactly once");
        assert_ne!(
            rt.machine().state(),
            SessionState::Discovering,
            "T04 must have moved the machine"
        );
        assert!(
            !rt.timers().is_armed(TimerId::Discover),
            "a timer that MOVED the machine is disarmed; the new state arms its own"
        );
    }

    #[test]
    fn a_timer_does_not_fire_before_its_deadline() {
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        vt.advance(timers::T_DISCOVER.default / 2);
        assert!(rt.tick(Guards::default(), Context::default()).is_empty());
    }

    #[test]
    fn a_suspend_does_not_fire_a_monotonic_timer() {
        // CD-1's third reason, as a test. Eight hours of suspend advance the
        // ELAPSED clock and not the monotonic one, so a `Session` that was merely
        // asleep is not torn down on wake.
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        vt.suspend(core::time::Duration::from_secs(8 * 3600));
        assert!(
            rt.tick(Guards::default(), Context::default()).is_empty(),
            "a monotonic timer must not fire across a suspend"
        );
    }

    #[test]
    fn re_entering_a_state_replaces_its_deadline_rather_than_adding_one() {
        let (mut rt, _vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        let armed = rt.timers().len();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        assert_eq!(rt.timers().len(), armed);
    }

    #[test]
    #[should_panic(expected = "every TIMER takes the MONOTONIC clock")]
    fn arming_an_authority_constant_as_a_timer_is_refused() {
        // `T_TRUST_HARD` is an ELAPSED constant that bounds a granted authority.
        // Sleeping on it is the defect CD-1 exists to prevent.
        let mut t = Timers::new();
        t.arm(
            TimerId::Discover,
            timers::T_TRUST_HARD,
            MonotonicInstant::ORIGIN,
        );
    }

    #[test]
    fn w34_a_timer_that_matches_no_row_does_not_leave_the_state_unbounded() {
        // `DISCOVERING` is bounded by `T_DISCOVER`. Firing a timer the table has
        // no row for must not consume that bound and leave nothing behind.
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        assert!(rt.timers().is_armed(TimerId::Discover));

        // `T_DEGRADED_MAX` has no row from `DISCOVERING`, so the machine ignores
        // it — and before this fix, `T_DISCOVER` would still have been consumed
        // by the same `fire_due` sweep in a real driver.
        vt.advance(timers::T_DISCOVER.default);
        let outcomes = rt.tick(Guards::default(), Context::default());
        assert!(!outcomes.is_empty());

        // Whatever state the table moved to, it is bounded if §4.4 says it
        // should be.
        let state = rt.machine().state();
        for (id, _) in timers_for(state) {
            assert!(
                rt.timers().is_armed(*id),
                "{state:?} left {} unarmed",
                id.name()
            );
        }
    }

    #[test]
    fn w34_an_ignored_timer_rearms_the_state_it_did_not_move() {
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        // Force the deadline to be consumed while the state does not change: a
        // timer the table has no row for, delivered directly.
        rt.apply(
            Trigger::Timer(TimerId::DegradedMax),
            Guards::default(),
            Context::default(),
        );
        assert_eq!(rt.machine().state(), SessionState::Discovering);
        assert!(
            rt.timers().is_armed(TimerId::Discover),
            "DISCOVERING must still be bounded by T_DISCOVER"
        );
        let _ = vt;
    }

    #[test]
    fn rearming_a_still_running_deadline_does_not_move_it() {
        // `rearm_missing` must not disturb a live deadline: restarting one on
        // every ignored timer would let a state outlive its own bound.
        let (mut rt, vt) = runtime();
        rt.apply(
            Trigger::Event(E::ConnectRequested),
            connect_guards(),
            Context::default(),
        );
        let first = rt.timers().next_deadline();
        vt.advance(core::time::Duration::from_secs(1));
        rt.apply(
            Trigger::Timer(TimerId::DegradedMax),
            Guards::default(),
            Context::default(),
        );
        assert_eq!(
            rt.timers().next_deadline(),
            first,
            "a live T_DISCOVER must keep its original deadline"
        );
    }

    #[test]
    fn every_registered_timer_id_is_armed_by_some_state() {
        // A registered timer no state arms is either a dead constant or a state
        // with no upper bound. Both are worth failing on.
        let ids: std::collections::HashSet<TimerId> = [
            SessionState::Disconnected,
            SessionState::Discovering,
            SessionState::Negotiating,
            SessionState::Connecting,
            SessionState::Steady(twinvpn_types::PathClass::WanDirect),
            SessionState::Migrating {
                from: twinvpn_types::PathClass::Relayed,
                to: twinvpn_types::PathClass::WanDirect,
            },
            SessionState::Degraded {
                carrier: twinvpn_types::PathClass::Relayed,
            },
            SessionState::Reconnecting { parked: false },
            SessionState::Blocked,
            SessionState::Failed,
        ]
        .into_iter()
        .flat_map(|s| timers_for(s).iter().map(|(id, _)| *id))
        .collect();
        for id in [
            TimerId::Discover,
            TimerId::Negotiate,
            TimerId::Connect,
            TimerId::Migrate,
            TimerId::ReconnectGrace,
            TimerId::ReconnectMax,
            TimerId::DegradedMax,
        ] {
            assert!(ids.contains(&id), "{} is armed by no state", id.name());
        }
    }

    #[test]
    fn cb2_the_core_decides_what_an_os_fact_means() {
        assert_eq!(
            event_for_change(
                &NetworkChange::InterfaceRemoved(twinvpn_platform::InterfaceIndex(3)),
                None
            ),
            Some(E::LinkDown(LinkKind::Unknown))
        );
        assert_eq!(
            event_for_change(
                &NetworkChange::AddressRemoved {
                    interface: twinvpn_platform::InterfaceIndex(3),
                    address: twinvpn_types::IpAddr::V4(
                        twinvpn_types::V4Addr::from_slice(&[10, 0, 0, 1]).expect("v4")
                    ),
                },
                None
            ),
            Some(E::AddrChanged),
            "an address change is not a link event; T21 turns on the difference"
        );
        assert_eq!(
            event_for_change(&NetworkChange::ResolversChanged, None),
            None,
            "no §4.3 event names this; inventing one would move the machine on a \
             fact the table does not carry"
        );
    }

    #[test]
    fn a_per_family_default_route_change_is_visible() {
        // ADR-0010 R6: "IPv6 appears *after* the tunnel is up" must be
        // distinguishable from nothing having happened.
        assert_eq!(
            event_for_change(
                &NetworkChange::DefaultRouteChanged {
                    family: twinvpn_types::AddressFamily::V6,
                    present: true,
                },
                None
            ),
            Some(E::AddrChanged)
        );
    }
}
