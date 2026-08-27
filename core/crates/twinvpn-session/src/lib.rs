//! `twinvpn-session` — the authoritative connection state machine
//! (`docs/reliability.md` §4).
//!
//! **Authority:** `docs/reliability.md` §4 (the twelve states, the events, the
//! per-state invariants, the transition table), §5 (timers and constants), §6
//! (recovery semantics), §9 (surviving a control-plane outage), §10 (no silent
//! failure), §11 (background and suspended operation); ADR-0018 §11.7 (the
//! dependency arrows that enforce I5), CD-1/CD-2.
//!
//! **Owner:** `core-dataplane`.
//!
//! # What this crate is
//!
//! The twelve-state machine every other TwinVPN document references and none of
//! them redefines. `twinvpn-types` carries the `ConnectionState` **vocabulary**;
//! this crate carries the **machine** — which transitions exist, what triggers
//! them, which guards they read, and what each one emits.
//!
//! | Module | §  | What it holds |
//! |---|---|---|
//! | [`state`] | §4.1, §4.4, §10.1 | the state value, and the `Target` that makes a code-less entry not compile |
//! | [`event`] | §4.3, §5 | every `EV_*` and the `T_*`s that fire a row |
//! | [`guards`] | §4.5, §5.3, §7.7 | every boolean the `Guard` column reads |
//! | [`table`] | §4.5 | the thirty-eight rows, in the written order |
//! | [`transition`] | §4.5, §10.2 | the record, and the row identifiers |
//! | [`machine`] | §10.1, §10.2 E1 | the single choke point |
//! | [`codes`] | §3.4, §3.5 | which code each row emits, and the substitutions a contract defect forces |
//! | [`timers`] | §5 | every constant, with its §5.3.1 clock class |
//! | [`backoff`] | §6.1 | the two regimes |
//! | [`budget`] | §6.3 | token buckets, breakers, the global brake |
//! | [`liveness`] | §6.4, §7.4 | bidirectional dead-peer detection |
//! | [`keepalive`] | §6.6, §11.1 | the NAT ladder and the coalesced wake window |
//! | [`resumption`] | §6.2, §6.5, §11.3 | what survives, and the recovery ladder |
//! | [`aggregate`] | §4.7 | worst-wins `TwinNet` state |
//! | [`journal`] | §6.5, S-12 | the durable half, behind the narrowest trait |
//!
//! # Three properties worth stating up front
//!
//! 1. **A silent transition is unrepresentable.** [`state::Target`]'s four
//!    reason-bearing variants carry a non-`Option` `ReasonCode`, and
//!    [`machine::SessionMachine::apply`] is the only mutator. §10.1 asks for the
//!    code to be "a **required argument**"; this is that, at the type level.
//! 2. **No `#[cfg(target_os)]`, anywhere.** CB-3. The machine reads *declared
//!    facts* — a [`guards::Guards`] record and a [`timers::TimerProfile`] — and
//!    never asks which OS it is on. That is also what lets CD-5's falsification
//!    test run on a plain Linux CI runner with no VM.
//! 3. **The control plane is not a dependency.** CD-I5: this crate does not name
//!    `twinvpn-cp-client`, directly or transitively. §9's three-way split is
//!    implemented as `Guards` inputs, so a control-plane outage changes which
//!    guards are set and changes nothing about the machine.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
// Product and protocol nouns — TwinVPN, TwinNet, IPv4, IPv6, NAT — appear
// throughout the ADR quotations this crate carries, and back-ticking them would
// make those quotations harder to read than the lint is worth.
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
// Every fallible function here returns one error type whose own documentation
// enumerates its variants; a per-function `# Errors` section would restate that
// table once per constructor.
#![allow(clippy::missing_errors_doc)]

pub mod aggregate;
pub mod backoff;
pub mod budget;
pub mod codes;
pub mod event;
pub mod guards;
pub mod journal;
pub mod keepalive;
pub mod liveness;
pub mod machine;
pub mod resumption;
pub mod state;
pub mod table;
pub mod timers;
pub mod transition;

pub use event::{Event, LinkKind, PolicyViolationKind, QosMetric, TimerId, Trigger};
pub use guards::Guards;
pub use machine::{Outcome, SessionMachine};
pub use state::{EnforcementMode, SessionState, Target};
pub use table::Context;
pub use transition::{Row, TransitionRecord};
