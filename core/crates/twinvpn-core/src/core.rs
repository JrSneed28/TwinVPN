//! The `Core` instance — S-47's `CoreInstanceBinding`, and the command/event
//! port F-5 defines.
//!
//! **Authority:** [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 F-5/F-6/F-7, §11.6, §11.17 S-46/S-47;
//! [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md) MI-20;
//! [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.1, §11.6.
//!
//! # One vocabulary
//!
//! [`Core::submit`] takes a [`twinvpn_mgmt::Submission`] — the *same* type the MI
//! transport carries and the same one `tw_core_submit` encodes. There is no
//! second command enum anywhere in the core, which is MI-20 and ADR-0018
//! §11.16 (b) discharged by construction rather than by review.
//!
//! # S-47, as a field
//!
//! `poisoned` is terminal: once F-7 has caught a panic, **every** subsequent call
//! returns `INTERNAL.CORE_PANIC` and only destroying the instance clears it. The
//! enforcement ruleset is deliberately **not** touched — §7.5 and CB-6 put the
//! installed rules in the OS's custody precisely so a core fault cannot drop
//! protection.

// Three imports and three methods below are `full`-only, and they are gated
// rather than left to warn because `make cross-check` now COMPILES `core-lite`
// (it is the profile that reaches a Darwin or Android target on a host with no
// C toolchain for one -- `ownership.md` §11, G-4/G-6). Until it did, this
// profile was declared and never built, so nothing said so.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "full")]
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_core::future::BoxFuture;
use twinvpn_diag::{Emitter, Ledger, Tier};
use twinvpn_env::Env;
#[cfg(feature = "full")]
use twinvpn_env::MonotonicInstant;
#[cfg(feature = "full")]
use twinvpn_mgmt::CoreCommand;
use twinvpn_mgmt::{catalogue, Submission};
use twinvpn_platform::PlatformAdapter;
use twinvpn_schema::v1;
use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

use crate::bridge::StoreBridge;
use crate::build_identity::CoreBuildIdentity;
#[cfg(feature = "full")]
use crate::dispatch::{self, Disposition, Lifecycle};
use crate::events::{CoreEvent, CoreEventKind, EventStream};
#[cfg(feature = "full")]
use crate::gateway::GatewayState;
#[cfg(feature = "full")]
use crate::journal::CoreSessionJournal;
use crate::planes::{new_shared, ControlPlanePort, DataPlaneView, Shared};
#[cfg(feature = "full")]
use crate::session_table::{SessionEntry, SessionMap};

/// Everything the core takes at construction. **CD-2: no global, no
/// `OnceCell`, no ambient default.**
pub struct CoreParts {
    /// The only source of time, timers, randomness and the runtime.
    pub env: Env,
    /// The platform seam (§11.6). One object, so the core can always say which
    /// adapter it is talking to.
    pub adapter: Arc<dyn PlatformAdapter>,
    /// The shell's compiled `abi_major`, checked at construction (VR-4).
    pub abi_major_expected: u32,
    /// This build's `abi_major`.
    pub abi_major: u32,
    /// This build's `abi_minor`.
    pub abi_minor: u32,
    /// The frozen schema set's content identity (V-1).
    pub schema_digest: Vec<u8>,
    /// A stable tag for the cryptographic provider in force.
    pub crypto_provider: String,
    /// CB-6a's declared per-target custody tag, from `twinvpn_store`.
    pub sek_custody: String,
    /// Whether the identity element is genuinely hardware-backed, reported
    /// **truthfully** by the adapter (§11.16 (l)). The core MUST NOT assume it.
    pub hardware_backed: bool,
    /// The Tier-0 ledger's capacity (ADR-0015 §9's per-class budget).
    pub ledger_capacity: usize,
    /// The event queue's watermark (ADR-0017 §11.10).
    pub event_capacity: usize,
}

/// A live core instance.
///
/// The `Debug` impl below is deliberately shallow: it names the instance and its
/// posture and nothing else. A derived `Debug` would reach into the ledger, the
/// event queue and the bridge state, which hold `SENSITIVE` values — and
/// `ownership.md` §6 rule 11 makes a derive that walks into a secret exactly the
/// accident to prevent.
pub struct Core {
    env: Env,
    adapter: Arc<dyn PlatformAdapter>,
    identity: CoreBuildIdentity,
    ledger: Mutex<Ledger>,
    events: Arc<EventStream>,
    shared: Shared,
    emitter: Emitter,
    poisoned: AtomicBool,
    instance_id: u64,
    generation: AtomicU64,
    /// Every `Session` this device knows about (S-12).
    ///
    /// Absent under `core-lite`: §11.12's profile carries no data-plane crate,
    /// so there is no `SessionMachine` to hold.
    #[cfg(feature = "full")]
    sessions: Mutex<SessionMap>,
    /// ADR-0013's gateway role: the peer table, the capacity reservation and
    /// S-36's live grant set.
    ///
    /// Absent under `core-lite` for the same reason as `sessions`:
    /// `twinvpn-gateway` is a data-plane crate.
    ///
    /// Held here, in the composition root, because ADR-0018 §11.7 puts
    /// `twinvpn-gateway` **below** it — see `crate::gateway`. Until this field
    /// existed, `twinvpn-gateway` had no caller anywhere in the workspace
    /// (`ownership.md` §9.6 X-3) and ADR-0013's G1 was unaddressable rather than
    /// merely unimplemented.
    #[cfg(feature = "full")]
    gateway: Mutex<GatewayState>,
    /// The durable half, once a host has called [`Core::open_store`].
    ///
    /// `None` until then, and [`Core::vault_state`] says so rather than letting
    /// a caller assume otherwise. `Store::open` is `async` and needs a runtime
    /// that is not yet running at construction, which is why this is a second
    /// step rather than part of `create`.
    bridge: Mutex<Option<StoreBridge>>,
    #[cfg(feature = "full")]
    journal: CoreSessionJournal,
    /// Whether a vault has been opened.
    ///
    /// A separate flag from `bridge`, because [`Core::flush`] **takes the bridge
    /// out** of its mutex for the duration of the commit — a `std` `MutexGuard`
    /// held across an `.await` makes the future non-`Send`, and a core whose
    /// flush cannot be spawned is worse than one that needs two fields. Without
    /// this flag a concurrent `vault_state()` would report `Absent` mid-flush,
    /// which is precisely the kind of momentary lie D4 was.
    vault_open: AtomicBool,
    /// S-61's current phase, as `host.lifecycle` last reported it.
    #[cfg(feature = "full")]
    lifecycle: Mutex<Lifecycle>,
    /// **CB-6's second clause** — the composed data plane's enforcement state
    /// (R-2/R-7).
    ///
    /// Held here for the same reason `gateway` is: `twinvpn-route`,
    /// `twinvpn-dns` and `twinvpn-enforce` are data-plane crates, they each
    /// *compute* and none of them *installs*, and this is the only crate
    /// permitted to hold one of them beside a `PlatformAdapter`. Until this
    /// field existed, `PlatformAdapter::apply` and `set_ruleset` had no
    /// production caller anywhere in the tree.
    #[cfg(feature = "full")]
    enforcement: Mutex<crate::enforce::Enforcement>,
    /// The bound L-CONTROL transport (ADR-0002 §11.2 rung 1).
    ///
    /// `None` until a host calls [`Core::bind_control_transport`]. Held **here**
    /// rather than in a shell because CD-I5 makes this the only crate that may
    /// name both planes: a shell holding the transport is a shell holding a
    /// control-plane object beside a data-plane one, and the core could not
    /// reach it to attach. The data plane never sees this field — nothing below
    /// `crate::planes::DataPlaneView` can name it — which is CD-I5's second
    /// arrow kept intact.
    #[cfg(feature = "full")]
    control: Mutex<Option<crate::cp_binding::ControlTransportBinding>>,
    /// **F-2.** The pairing ledger, the dedup log and the offers in flight.
    ///
    /// Held here for the reason `enforcement` and `gateway` are: `twinvpn-trust`
    /// holds the ceremony and `twinvpn-crypto` holds the offer's producers, and
    /// this is the only crate that may hold either beside a `PlatformAdapter`.
    /// One mutex, so ADR-0008's `CEREMONY` idempotency holds under concurrency
    /// rather than by convention — see [`crate::pairing`].
    #[cfg(feature = "full")]
    pairing: Mutex<crate::pairing::PairingCeremonies>,
}

/// Whether the durable store has been opened.
///
/// Reported rather than inferred, because the difference is the whole of D4: a
/// core with no vault answers every durable question from memory and loses it
/// all on exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// No vault has been opened. Every durable operation is refused.
    Absent,
    /// A vault is open and the bridge owns it.
    Open,
}

impl core::fmt::Debug for Core {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core")
            .field("instance_id", &self.instance_id)
            .field("poisoned", &self.is_poisoned())
            .field("generation", &self.generation())
            .field("profile", &self.identity.profile)
            .finish_non_exhaustive()
    }
}

/// The instance counter. S-47's `instance_id` must be unique within one process
/// and **must not survive process exit** — a stale binding would be
/// indistinguishable from a live second writer.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

impl Core {
    /// Creates an instance, checking the ABI first.
    ///
    /// **VR-4.** The `abi_major` check is the first thing that happens, before
    /// any capability is touched: *"It is still checked at `tw_core_create` and
    /// still named (`INTERNAL.ABI_VERSION_MISMATCH`), because the alternative is
    /// undefined behaviour."*
    ///
    /// # Errors
    ///
    /// A [`Diagnostic`] carrying `INTERNAL.ABI_VERSION_MISMATCH` on a version
    /// mismatch, or `INTERNAL.INVARIANT_VIOLATED` if S-46 cannot be assembled.
    pub fn create(parts: CoreParts) -> Result<Self, Box<Diagnostic>> {
        if parts.abi_major_expected != parts.abi_major {
            return Err(Box::new(
                Diagnostic::builder(codes::INTERNAL_ABI_VERSION_MISMATCH, Component::Diagnostics)
                    .evidence(
                        "shell_abi_major",
                        EvidenceValue::Uint(u64::from(parts.abi_major_expected)),
                    )
                    .evidence(
                        "core_abi_min",
                        EvidenceValue::Uint(u64::from(parts.abi_major)),
                    )
                    .evidence(
                        "core_abi_max",
                        EvidenceValue::Uint(u64::from(parts.abi_major)),
                    )
                    .build(),
            ));
        }

        let identity = CoreBuildIdentity::assemble(
            parts.abi_major,
            parts.abi_minor,
            parts.schema_digest,
            parts.crypto_provider,
            parts.hardware_backed,
            parts.sek_custody,
            parts.adapter.binding_name(),
        )
        .map_err(|_| {
            Box::new(Diagnostic::invariant_violated(
                Component::Diagnostics,
                "ADR-0018 VR-3: this core_version has no EPOCH_TABLE row",
            ))
        })?;

        let shared = new_shared();
        Ok(Self {
            env: parts.env,
            adapter: parts.adapter,
            identity,
            ledger: std::sync::Mutex::new(Ledger::new(parts.ledger_capacity)),
            events: Arc::new(EventStream::new(parts.event_capacity)),
            shared: Arc::clone(&shared),
            // Tier 0 is what the core writes into. A bundle re-encodes from it
            // (ADR-0015 §11.1); nothing here writes at Tier 1 or Tier 2.
            emitter: Emitter::new(Component::Diagnostics, Tier::LocalLedger),
            poisoned: AtomicBool::new(false),
            instance_id: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            generation: AtomicU64::new(0),
            #[cfg(feature = "full")]
            sessions: Mutex::new(SessionMap::new()),
            // **Unconfigured**, not "an idle gateway". `max_peers = 0` fails
            // ADR-0013 MG-14's sixteen-peer floor, which is exactly what
            // `gateway.get` should report on a host nobody has set up as one:
            // "this is not a conforming gateway" rather than "this gateway has
            // no peers". `gateway.set` is what would configure it, and it is
            // refused by name until there is a durable store to hold the
            // ceiling — see `dispatch::disposition`.
            #[cfg(feature = "full")]
            gateway: Mutex::new(GatewayState::unconfigured()),
            // Starts BLOCKED. KS-19's direction: "the deny predates the first
            // packet the host can emit", and a core that started with no
            // posture would have an interval in which neither rule set is in
            // force.
            #[cfg(feature = "full")]
            enforcement: Mutex::new(crate::enforce::Enforcement::default()),
            // No transport, and the core says so rather than assuming one. A
            // device that cannot reach UDP:443 has no control channel at all on
            // this build — rungs 2 to 4 of ADR-0002 §11.2's ladder exist
            // nowhere in the workspace — and `has_control_transport` is how a
            // caller tells that from an outage.
            #[cfg(feature = "full")]
            control: Mutex::new(None),
            bridge: Mutex::new(None),
            #[cfg(feature = "full")]
            journal: CoreSessionJournal::new(Arc::clone(&shared), Vec::new()),
            vault_open: AtomicBool::new(false),
            // A core that has not been told its phase is FOREGROUND: it is the
            // only phase in which every timer runs, so assuming it can only
            // cause more work, never less protection.
            #[cfg(feature = "full")]
            lifecycle: Mutex::new(Lifecycle::Foreground),
            // Empty, and `pair.begin` refuses until a shell installs an
            // enrolment record: ADR-0007 §7.4 makes authorization "always
            // required", and a core with no Owner chain has no way to check it.
            #[cfg(feature = "full")]
            pairing: Mutex::new(crate::pairing::PairingCeremonies::new()),
        })
    }

    /// S-46, for the bundle and for `tw_build_identity`.
    #[must_use]
    pub const fn build_identity(&self) -> &CoreBuildIdentity {
        &self.identity
    }

    /// S-47's `instance_id`.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// S-47's `generation`, advanced by each accepted mutating command.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Whether F-7 has poisoned this instance. **Terminal.**
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// The injected environment, for a component the root wires below itself.
    #[must_use]
    pub const fn env(&self) -> &Env {
        &self.env
    }

    /// The platform seam.
    #[must_use]
    pub fn adapter(&self) -> &Arc<dyn PlatformAdapter> {
        &self.adapter
    }

    /// The **write-only** control-plane port. CD-I5's first arrow.
    #[must_use]
    pub fn control_plane_port(&self) -> ControlPlanePort {
        ControlPlanePort::new(Arc::clone(&self.shared))
    }

    /// The **read-only** data-plane view. CD-I5's second arrow.
    #[must_use]
    pub fn data_plane_view(&self) -> DataPlaneView {
        DataPlaneView::new(Arc::clone(&self.shared))
    }

    /// The shared bridge state, for the composition root's own `StoreBridge`.
    #[must_use]
    pub fn shared(&self) -> Shared {
        Arc::clone(&self.shared)
    }

    /// Marks the instance poisoned and publishes `INTERNAL.CORE_PANIC`.
    ///
    /// F-7: *"marks the instance **poisoned**, makes every subsequent call return
    /// that code, and obliges the shell to `tw_core_destroy` and re-create. It
    /// MUST NOT tear down the installed rule set."* Nothing in this method
    /// touches the adapter, which is how the second half is kept true.
    pub fn poison(&self) {
        if self.poisoned.swap(true, Ordering::SeqCst) {
            return;
        }
        let diagnostic =
            Diagnostic::builder(codes::INTERNAL_CORE_PANIC, Component::Diagnostics).build();
        self.record(&diagnostic);
        self.events.publish(
            CoreEventKind::Diagnostic(Box::new(self.emitter.error_envelope(&diagnostic, None))),
            None,
        );
        self.events.close();
    }

    /// **F-5.** Non-blocking. Every outcome, including a rejection, arrives as an
    /// event on the one ordered stream.
    ///
    /// # What it does, and what it refuses
    ///
    /// An admission gate followed by a **dispatcher**: poison check, ADR-0008
    /// precondition, parameter check, [`crate::dispatch::disposition`], then
    /// [`crate::execute`]. An operation this build does not perform is
    /// **refused by name** — never a false success.
    ///
    /// **22 of the 51 catalogue operations execute; 29 are refused**, each with
    /// a registered code and a stated reason ([`unimplemented()`]). An operation
    /// that reports success with zero observable effects is itself reported as
    /// `INTERNAL.INVARIANT_VIOLATED`.
    ///
    /// `disposition` and `execute` are two exhaustive matches over one enum, so
    /// a new operation cannot acquire an empty implementation: it fails to
    /// compile until someone states whether it executes. See this crate's
    /// `README.md` §6.
    ///
    /// # Errors
    ///
    /// A [`Diagnostic`] when the instance is poisoned or the operation is not
    /// one this build offers. The same condition is *also* published as a
    /// `CommandRejected` event, because §11.6 says rejected commands produce an
    /// event and never a silent drop — the return value is the in-process
    /// caller's convenience, not the record.
    pub fn submit(&self, submission: &Submission) -> Result<(), Box<Diagnostic>> {
        if self.is_poisoned() {
            let d = Diagnostic::builder(codes::INTERNAL_CORE_PANIC, Component::Diagnostics).build();
            return Err(Box::new(d));
        }

        let entry = catalogue::entry(submission.op);

        // ADR-0008: an operation declared `key` or `ver` may not be accepted
        // without its precondition. Checking it here, once, is what keeps the two
        // carriages honest — the MI transport does not get to skip it.
        if let Some(code) = missing_precondition(entry, submission) {
            return Err(Box::new(self.reject(submission, code)));
        }

        // core-lite carries no data-plane crate, so it performs NO command.
        // Refusing by name is the honest answer; returning Ok would be the same
        // false success this dispatcher exists to remove.
        #[cfg(not(feature = "full"))]
        {
            let _ = entry;
            return Err(Box::new(
                self.reject(submission, codes::PLATFORM_ADAPTER_UNAVAILABLE),
            ));
        }

        #[cfg(feature = "full")]
        {
            // A malformed submission is refused BEFORE any work, so a command can
            // never be partially applied.
            if let Some(code) = dispatch::missing_parameter(submission.op, submission) {
                return Err(Box::new(self.reject(submission, code)));
            }

            match dispatch::disposition(submission.op) {
                Disposition::NotWired { code, .. } => {
                    return Err(Box::new(self.reject(submission, code)));
                }
                Disposition::Executes => {}
            }

            let outcome = match crate::execute::execute(self, submission) {
                Ok(outcome) => outcome,
                Err(diagnostic) => {
                    self.record(&diagnostic);
                    self.events.publish(
                        CoreEventKind::CommandRejected {
                            op: submission.op.name(),
                            diagnostic: Box::new(self.emitter.error_envelope(&diagnostic, None)),
                        },
                        submission.actor_principal.clone(),
                    );
                    return Err(diagnostic);
                }
            };

            // An executed operation that had no observable effect is a defect, not
            // a success. `INTERNAL.INVARIANT_VIOLATED` is the honest report: the
            // dispatcher said it executes and it did nothing.
            if outcome.effects == 0 {
                let diagnostic = Diagnostic::invariant_violated(
                    Component::ManagementInterface,
                    "an operation dispatch declared EXECUTES produced no observable effect",
                );
                self.record(&diagnostic);
                return Err(Box::new(diagnostic));
            }

            if entry.mutating {
                self.generation.fetch_add(1, Ordering::Relaxed);
            }

            self.events.publish(
                CoreEventKind::CommandCompleted {
                    op: submission.op.name(),
                    result: outcome.result,
                },
                submission.actor_principal.clone(),
            );
            Ok(())
        }
    }

    // -- state the executor reaches -----------------------------------------

    /// The `Session` table.
    #[cfg(feature = "full")]
    pub(crate) fn sessions(&self) -> MutexGuard<'_, SessionMap> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The composed data plane's enforcement state (R-2/R-7).
    ///
    /// `pub` rather than `pub(crate)`: a shell asks a composed core what posture
    /// is in force, and ADR-0015 §11.6 rule 1 makes that question the only
    /// legitimate source of a `ProtectionAssertion`. There is no setter — every
    /// mutation goes through [`crate::enforce`], which is what keeps "the latch
    /// moved" and "the adapter was told" from becoming two facts.
    #[cfg(feature = "full")]
    pub fn enforcement(&self) -> MutexGuard<'_, crate::enforce::Enforcement> {
        self.enforcement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether any `Session` is carrying traffic on a validated path.
    ///
    /// KS-18(a)'s input: *"an authenticated bidirectional path validation"*.
    /// `SessionState::Steady` is the state the §4.5 table enters only through
    /// T08–T10, each of which has `path_validated` as its guard — so reading the
    /// state IS reading the validation, rather than keeping a second belief
    /// about it beside the machine that owns the first.
    ///
    /// `Degraded` counts and `Migrating` does not: a degraded session is still
    /// carrying on a validated path (§4.5 puts the quality objective and the
    /// validation in different columns), while a migration is by definition
    /// between one validated path and another that is not yet.
    #[cfg(feature = "full")]
    #[must_use]
    pub fn any_session_connected(&self) -> bool {
        use twinvpn_session::state::SessionState;
        self.sessions().values().any(|e| {
            matches!(
                e.runtime.machine().state(),
                SessionState::Steady(_) | SessionState::Degraded { .. }
            )
        })
    }

    /// The gateway role's live state (ADR-0013).
    #[cfg(feature = "full")]
    pub(crate) fn gateway(&self) -> MutexGuard<'_, GatewayState> {
        self.gateway
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The durable-session journal.
    #[cfg(feature = "full")]
    pub(crate) const fn journal(&self) -> &CoreSessionJournal {
        &self.journal
    }

    /// The Tier-0 emitter.
    #[cfg(feature = "full")]
    pub(crate) const fn emitter(&self) -> &Emitter {
        &self.emitter
    }

    /// The event stream's next sequence number, for `event.subscribe`.
    #[must_use]
    pub fn event_cursor(&self) -> u64 {
        self.events.cursor()
    }

    /// S-61's current phase.
    #[cfg(feature = "full")]
    #[must_use]
    pub fn lifecycle(&self) -> Lifecycle {
        *self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(feature = "full")]
    pub(crate) fn set_lifecycle(&self, phase: Lifecycle) {
        *self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = phase;
    }

    /// Advances every `Session` by whatever the injected clock now permits.
    ///
    /// **The step a daemon runs on each wake**, and the reason a one-shot
    /// `session.connect` is not enough: §4.4 races candidates staggered by the
    /// family bias, so a v4 candidate is not due until `T_HE_BIAS` after a v6
    /// one. Without a tick the delayed half of the race is never probed.
    ///
    /// Two things happen, in order:
    ///
    /// 1. every timer whose deadline has passed fires its §4.5 transition;
    /// 2. every candidate whose first probe is now due is probed;
    /// 3. **every carrying `Session` moves whatever packets are waiting.**
    ///
    /// Step 3 is a no-op on a runtime that spawned the pump, which is every
    /// production binding: `crate::execute::carriage::step` returns immediately
    /// for a `Session` whose directions are already running, so a daemon's tick
    /// does not become a second reader on the same socket. It does the work on
    /// the virtual-time binding, whose `spawn` runs a future inline — see that
    /// module for why that is a scheduler fact rather than a missing capability.
    ///
    /// Returns `(transitions, probes)`. Nothing here reads the wall clock or
    /// sleeps: the deadline comparison is against the injected `MonotonicClock`,
    /// so a suspended device does not fire a timer on wake (CD-1).
    #[cfg(feature = "full")]
    pub fn tick(&self) -> (usize, usize) {
        use twinvpn_session::{Context, Guards};

        let now = self.env.now_monotonic();
        let ids: Vec<twinvpn_types::SessionId> = self.sessions().keys().copied().collect();
        let mut transitions = 0usize;
        let mut probes = 0usize;

        for id in ids {
            // The transitions first: a timer that moves the machine changes what
            // a probe means, so probing before firing would probe for a state
            // the Session has already left.
            let records = {
                let mut sessions = self.sessions();
                let Some(entry) = sessions.get_mut(&id) else {
                    continue;
                };
                entry
                    .runtime
                    .tick(Guards::default(), Context::default())
                    .iter()
                    .filter_map(|o| o.record().map(twinvpn_session::TransitionRecord::to_proto))
                    .collect::<Vec<_>>()
            };
            for record in records {
                self.publish_transition(record, None);
                transitions += 1;
            }

            let (sockets, race, peer) = {
                let sessions = self.sessions();
                let Some(entry) = sessions.get(&id) else {
                    continue;
                };
                let Some(race) = entry.race.clone() else {
                    continue;
                };
                // The sockets cannot be cloned out, so the probe runs under the
                // guard. That is safe here because `probe` awaits only the
                // adapter, and `block_on_probe` drives it on this thread.
                (entry.sockets.len(), race, entry.peer_endpoint)
            };
            if sockets == 0 || peer.is_none() {
                continue;
            }
            let mut sessions = self.sessions();
            let Some(entry) = sessions.get_mut(&id) else {
                continue;
            };
            let sent = {
                // The ledger is swapped out for the call so the borrow
                // checker sees one mutable borrow of `entry` at a time, then
                // swapped back with whatever the probe recorded.
                let mut ledger = twinvpn_path::ledger::Ledger::new();
                core::mem::swap(&mut ledger, &mut entry.ledger);
                let n = self.block_on_probe(&entry.sockets, &race, &mut ledger, peer, now);
                core::mem::swap(&mut ledger, &mut entry.ledger);
                n
            };
            probes += sent;
        }

        // The packet path. Direct and relayed are the two carriages a `Session`
        // can be on, and a `Session` on neither costs one map lookup.
        let carrying: Vec<twinvpn_types::SessionId> = self
            .sessions()
            .iter()
            .filter(|(_, e)| e.established.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in carrying {
            crate::execute::carriage::step(self, id);
            crate::execute::carriage::relay_step(self, id);
        }
        (transitions, probes)
    }

    /// Installs one peer's L-DATA key material.
    ///
    /// **The seam the handshake was missing.** `session.connect` runs
    /// `Noise_IKpsk2` through `twinvpn_tunnel::bind`, and every input that
    /// handshake needs beyond what this crate holds arrives here: the local
    /// static, the peer's verified tunnel key, the `TwinNetPSK` and the two
    /// bindings the §7.3.1 prologue covers. See
    /// [`crate::session_table::TunnelKeying`] for why each one has to be
    /// injected rather than derived.
    ///
    /// A real entry point rather than a test hook, in the same sense
    /// [`Core::set_peer_endpoint`] is: the pairing ceremony and the control
    /// plane are what will call it, and until one of them exists **no
    /// `Session` on this build can complete a handshake** — which is why
    /// `session.connect` refuses by name instead of reaching CONNECTED.
    ///
    /// Creates the `Session` if it does not exist, because key material can
    /// legitimately arrive before the local user asks to connect.
    #[cfg(feature = "full")]
    pub fn install_tunnel_keying(
        &self,
        peer: twinvpn_types::DeviceId,
        keying: crate::session_table::TunnelKeying,
    ) {
        let session_id = crate::session_table::session_id_for(peer);
        let mut sessions = self.sessions();
        sessions
            .entry(session_id)
            .or_insert_with(|| SessionEntry::new(self.env.clone(), session_id, peer))
            .keying = Some(keying);
    }

    /// Installs the credentials one `Session` presents to a relay.
    ///
    /// The same shape as [`Core::install_tunnel_keying`] and, today, the same
    /// emptiness: a verified `RelayMap`, an `RLK` and a `RelayCapabilityToken`
    /// have no production source anywhere in the workspace, and
    /// [`crate::session_table::RelayAccess`] records exactly which crate would
    /// have to supply each. With nothing installed the relay fallback refuses
    /// with `RELAY.NONE_REACHABLE`, which is the truth: this device knows of no
    /// relay at all.
    #[cfg(feature = "full")]
    pub fn install_relay_access(
        &self,
        peer: twinvpn_types::DeviceId,
        access: crate::session_table::RelayAccess,
    ) {
        let session_id = crate::session_table::session_id_for(peer);
        let mut sessions = self.sessions();
        sessions
            .entry(session_id)
            .or_insert_with(|| SessionEntry::new(self.env.clone(), session_id, peer))
            .relay_access = Some(access);
    }

    // -- F-2: pairing (three methods, one block, see `crate::pairing`) -------

    /// The pairing ledger, the dedup log and the offers in flight.
    #[cfg(feature = "full")]
    pub(crate) fn pairing(&self) -> MutexGuard<'_, crate::pairing::PairingCeremonies> {
        self.pairing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Installs the record ADR-0007 §7.4's "always required" authorization
    /// check reads, so this device may begin a C-B pairing.
    ///
    /// A second step rather than part of `create`, for the reason
    /// [`Core::bind_control_transport`] is: the Owner chain is restored from a
    /// durable store the shell owns, and [`crate::pairing`] records why each of
    /// its parts cannot be read by the core today. Until one is installed,
    /// `pair.begin` refuses `AUTH.PAIRING_NOT_AUTHORIZED` — the fail-closed
    /// direction, and the honest one.
    #[cfg(feature = "full")]
    pub fn install_pairing_enrolment(&self, enrolment: crate::pairing::PairingEnrolment) {
        self.pairing().install(enrolment);
    }

    /// Borrows one in-flight `PairingOffer`, under the lock, for exactly as long
    /// as `f` runs.
    ///
    /// **This is the offer's only exit from the core, and it is not a copy.**
    /// `pairing_offer.cddl` classifies the payload SECRET with no rendering path
    /// into any log at any level, so it must not travel as an `Outcome::result`
    /// — which would put it on the event stream — and must not outlive the
    /// mutex. A shell renders ADR-0023's E1 QR or E2 text from inside `f`
    /// (`twinvpn_crypto::pairing_offer::encode` and `::render_text`) and keeps
    /// nothing.
    ///
    /// `None` when no ceremony with that `pairing_id` is in flight.
    #[cfg(feature = "full")]
    pub fn with_pairing_offer<R>(
        &self,
        pairing_id: &[u8; crate::pairing::PAIRING_ID_BYTES],
        f: impl FnOnce(&twinvpn_crypto::pairing_offer::PairingOffer) -> R,
    ) -> Option<R> {
        self.pairing().offer(pairing_id).map(f)
    }

    /// Binds the L-CONTROL transport this core will use.
    ///
    /// **Held here so the core can use it**, which is the whole point:
    /// [`crate::cp_binding::ControlTransportBinding`] was constructible and had
    /// nowhere to live, so a shell that built one had to keep it and the core
    /// could not reach it. `attach` is `async` and the binding is built by a
    /// shell that has resolved endpoints and holds an element-backed signer, so
    /// this is a second step rather than part of `create` — the same reason
    /// [`Core::open_store`] is.
    ///
    /// A second call **replaces** the binding. Re-binding is what a device does
    /// when its enrolment record changes, and refusing it would leave a core
    /// pinned to a server key set its owner has rotated away from.
    #[cfg(feature = "full")]
    pub fn bind_control_transport(&self, binding: crate::cp_binding::ControlTransportBinding) {
        *self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(binding);
    }

    /// Whether an L-CONTROL transport is bound.
    ///
    /// Reported rather than inferred, for the reason [`Core::vault_state`] is:
    /// the difference between "we have a control channel" and "we have not been
    /// given one" is the difference between `CONTROL.UNREACHABLE` and a
    /// misconfiguration, and ADR-0002's ladder makes an operator act
    /// differently on each.
    #[cfg(feature = "full")]
    #[must_use]
    pub fn has_control_transport(&self) -> bool {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    /// Attaches one control connection carrying both C1 and C2 (ADR-0002 N-1).
    ///
    /// # Errors
    ///
    /// `CONTROL.UNREACHABLE` when no transport has been bound — which is the
    /// honest code for a device that cannot reach a control plane, and is kept
    /// apart from `AUTH.KEY_UNAVAILABLE` for the reason
    /// [`crate::cp_binding`] gives: a single "could not connect" makes a locked
    /// keychain look like an outage. Otherwise, whatever rung 1 reported.
    #[cfg(feature = "full")]
    pub async fn attach_control(
        &self,
        mobile_background: bool,
    ) -> Result<Box<dyn twinvpn_cp_client::transport::ControlConnection>, Box<Diagnostic>> {
        // The transport is an `Arc<dyn ControlTransport>` behind the binding, so
        // the config and the handle are taken out under the lock and the attach
        // itself happens without it — a `std` guard held across an `.await`
        // makes the future non-`Send`, and this one has to be spawnable.
        let attach = {
            let guard = self
                .control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(binding) = guard.as_ref() else {
                return Err(Box::new(
                    Diagnostic::builder(codes::CONTROL_UNREACHABLE, Component::ControlPlaneClient)
                        .build(),
                ));
            };
            (
                binding.transport(),
                binding.attach_config(mobile_background),
            )
        };
        attach
            .0
            .attach(&attach.1)
            .await
            .map_err(|e| Box::new(twinvpn_cp_client::CpError::from(e).diagnostic()))
    }

    /// Records the endpoint a peer is reachable at.
    ///
    /// **The rendezvous seam.** `protocol.md` §10's establishment learns the
    /// peer's candidates over C4, and with no `ControlTransport` in the
    /// workspace (W-12) nothing supplies one on this build. This is where that
    /// answer lands when it exists, and it is a real entry point rather than a
    /// test hook: the probe path already reads it.
    ///
    /// Creates the `Session` if it does not exist, because a rendezvous answer
    /// can legitimately arrive before the local user asks to connect.
    #[cfg(feature = "full")]
    pub fn set_peer_endpoint(
        &self,
        peer: twinvpn_types::DeviceId,
        endpoint: twinvpn_types::Endpoint,
    ) {
        let session_id = crate::session_table::session_id_for(peer);
        let mut sessions = self.sessions();
        sessions
            .entry(session_id)
            .or_insert_with(|| SessionEntry::new(self.env.clone(), session_id, peer))
            .peer_endpoint = Some(endpoint);
    }

    /// Publishes a local, device-authoritative session event.
    #[cfg(feature = "full")]
    pub(crate) fn publish_session_event(&self, event: v1::SessionEvent, actor: Option<String>) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.push(
                self.env.now_monotonic(),
                None,
                twinvpn_diag::Record::SessionEvent(Box::new(event.clone())),
            );
        }
        self.events
            .publish(CoreEventKind::SessionEvent(Box::new(event)), actor);
    }

    /// Runs one adapter call to completion on the injected runtime.
    ///
    /// `submit` is documented non-blocking (F-5), and on the production
    /// work-stealing runtime this returns as soon as the adapter does — the
    /// adapter's own contract bounds it (§11.6, `ApplyBudget`). On the lab's
    /// virtual-time runtime it is inline and deterministic **by that runtime's
    /// design**, which is what makes a scenario reproducible.
    #[cfg(feature = "full")]
    pub(crate) fn block_on_adapter<'a, T: Send + 'static>(
        &'a self,
        make: impl FnOnce(&'a Env, &'a Arc<dyn PlatformAdapter>) -> BoxFuture<'a, T>,
    ) -> T {
        let mut slot: Option<T> = None;
        {
            let future = make(&self.env, &self.adapter);
            self.env.runtime().block_on(Box::pin(async {
                slot = Some(future.await);
            }));
        }
        slot.expect("block_on drives the future to completion")
    }

    /// Runs one probe round to completion.
    #[cfg(feature = "full")]
    pub(crate) fn block_on_probe(
        &self,
        sockets: &[Arc<dyn twinvpn_platform::socket::UdpSocket>],
        race: &twinvpn_path::race::Race,
        ledger: &mut twinvpn_path::ledger::Ledger,
        peer: Option<twinvpn_types::Endpoint>,
        now: MonotonicInstant,
    ) -> usize {
        let mut sent = 0usize;
        self.env.runtime().block_on(Box::pin(async {
            sent = crate::establish::probe(sockets, race, ledger, peer, now).await;
        }));
        sent
    }

    // -- the vault (D4) ------------------------------------------------------

    /// Whether a durable store is open.
    #[must_use]
    pub fn vault_state(&self) -> VaultState {
        if self.vault_open.load(Ordering::Acquire) {
            VaultState::Open
        } else {
            VaultState::Absent
        }
    }

    /// Opens the durable store and hydrates the bridge from it.
    ///
    /// **This is D4's fix.** Until it is called, S-12, S-15, S-27, S-30 and S-37
    /// are memory-only and everything `reliability.md` §9.1 leans on for
    /// "continues indefinitely" is lost at process exit.
    ///
    /// A second call is a no-op that reports the state rather than reopening:
    /// `twinvpn_store` takes a single-opener lock, and a second `open` would
    /// report `STORE.LOCK_CONTENDED` against this very process.
    ///
    /// # Errors
    ///
    /// A [`Diagnostic`] carrying the `STORE.*` code the ladder produced.
    pub async fn open_store(&self) -> Result<VaultState, Box<Diagnostic>> {
        if self.vault_state() == VaultState::Open {
            return Ok(VaultState::Open);
        }
        let identity_present = self.adapter.identity().public_identity().await.is_ok();
        let store = twinvpn_store::Store::open(
            self.env.clone(),
            Arc::new(AdapterSecureStore(Arc::clone(&self.adapter))),
            identity_present,
        )
        .await
        .map_err(|e| Box::new(e.diagnostic(Component::Store)))?;

        let outcome = store.outcome().clone();
        let bridge = StoreBridge::new(store, Arc::clone(&self.shared));
        // ST-24's classification drives behaviour outside the store: a rung that
        // suspends granted authority is a fact the data plane must see, and it
        // crosses as data rather than as a call back into the store.
        if outcome.suspend_granted_authority {
            self.publish_diagnostic(
                &Diagnostic::builder(codes::STORE_CUSTODY_DEGRADED, Component::Store).build(),
            );
        }
        *self
            .bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bridge);
        self.vault_open.store(true, Ordering::Release);

        // §6.5: a restarted client resumes into RECONNECTING for each known
        // peer. Hydration is what makes that true rather than aspirational.
        #[cfg(feature = "full")]
        {
            use twinvpn_session::journal::SessionJournal as _;
            let restored = self.journal.load_all().unwrap_or_default();
            let mut sessions = self.sessions();
            for record in restored {
                sessions
                    .entry(record.session_id)
                    .or_insert_with(|| SessionEntry::resumed(self.env.clone(), &record));
            }
        }
        Ok(VaultState::Open)
    }

    /// Drains every queued durable write into one transaction.
    ///
    /// ADR-0009 R-9 requires the high-water mark to be durable **before** the
    /// document it admits is acted on, and ST-12b requires the whole set to
    /// commit together. Both are the caller's to sequence; this is the step that
    /// makes a queued write durable.
    ///
    /// # Errors
    ///
    /// A [`Diagnostic`] carrying the `STORE.*` code, or
    /// `STORE.CUSTODY_DEGRADED` when no vault has been opened — which is a
    /// **refusal**, not a silent success, so "we flushed" cannot be true of a
    /// core that has nowhere to flush to.
    pub async fn flush(&self) -> Result<usize, Box<Diagnostic>> {
        // The bridge is TAKEN for the duration of the commit rather than
        // borrowed through the guard: holding a `std::sync::MutexGuard` across
        // an `.await` makes the future non-`Send`, and this future has to be
        // spawnable. `vault_open` is what keeps `vault_state()` truthful in the
        // window.
        let taken = self
            .bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut bridge) = taken else {
            return Err(Box::new(
                Diagnostic::builder(codes::STORE_CUSTODY_DEGRADED, Component::Store).build(),
            ));
        };
        let result = bridge.flush().await;
        // Put it back BEFORE propagating the error: a failed flush leaves the
        // queue intact and the vault open, and dropping the bridge here would
        // turn a retryable store error into a permanently closed vault.
        *self
            .bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bridge);
        result.map_err(|e| Box::new(e.diagnostic(Component::Store)))
    }

    /// **F-5.** The one blocking call, with an explicit timeout.
    #[must_use]
    pub fn next_event(&self, timeout: Duration) -> Option<CoreEvent> {
        self.events.next_event(timeout)
    }

    /// Cancels an in-flight [`Core::next_event`]. Callable from any thread.
    pub fn wake(&self) {
        self.events.wake();
    }

    /// Publishes a transition onto the stream and records it in Tier 0.
    ///
    /// One call site, so no code path can move the machine without the event
    /// appearing (ADR-0015 O-05).
    pub fn publish_transition(&self, event: v1::TransitionEvent, actor: Option<String>) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.push(
                self.env.now_monotonic(),
                None,
                twinvpn_diag::Record::Transition(Box::new(event.clone())),
            );
        }
        self.events
            .publish(CoreEventKind::Transition(Box::new(event)), actor);
    }

    /// Records a diagnostic in the Tier-0 ledger and publishes it.
    pub fn publish_diagnostic(&self, diagnostic: &Diagnostic) {
        self.record(diagnostic);
        self.events.publish(
            CoreEventKind::Diagnostic(Box::new(self.emitter.error_envelope(diagnostic, None))),
            None,
        );
    }

    /// The Tier-0 ledger's current depth and drop count.
    #[must_use]
    pub fn ledger_stats(&self) -> (usize, u64) {
        self.ledger
            .lock()
            .map_or((0, 0), |l| (l.len(), l.dropped()))
    }

    /// Begins graceful shutdown. `ownership.md` §6 rule 7.
    ///
    /// Order matters: the runtime stops accepting work, the event stream closes
    /// so a drain thread unblocks, and the adapter is told last — and telling the
    /// adapter **does not** remove the installed ruleset, because CB-6 puts it in
    /// the OS's custody so that the core going away cannot drop protection.
    pub fn begin_shutdown(&self) {
        // The packet path first, and before the runtime stops accepting work: a
        // pump is spawned work, and a runtime that has already refused new
        // spawns cannot be asked to finish the step in flight. Every direction
        // shares its `Session`'s one `Cancel`, so this is one act per session
        // rather than two, and the tunnel's keys are erased with it.
        //
        // The installed rule set is deliberately **not** touched. CB-6 puts it
        // in the OS's custody precisely so the tunnel going away cannot drop
        // protection, and stopping a pump is the tunnel going away.
        #[cfg(feature = "full")]
        crate::execute::carriage::stop_all(self);
        self.events.close();
        self.adapter.begin_shutdown();
        self.env.begin_shutdown();
    }

    /// Graceful shutdown **with** a final durable flush.
    ///
    /// `ownership.md` §6 rule 7, and D4's core half. [`Core::begin_shutdown`] is
    /// synchronous and cannot flush, because flushing is `async`; a host that
    /// only calls it loses every queued durable write. This is the entry point a
    /// host should call, and `begin_shutdown` is what it delegates to once the
    /// vault is safe.
    ///
    /// The order matters: flush **first**, while the runtime still accepts work,
    /// then stop accepting. Reversing it means the flush is refused by the
    /// runtime it needs.
    ///
    /// # Errors
    ///
    /// The flush's [`Diagnostic`]. Shutdown proceeds either way — a store that
    /// cannot be written must not also prevent the process from exiting — and
    /// the error is returned so a host can report it rather than discover it on
    /// the next start.
    pub async fn shutdown(&self) -> Result<usize, Box<Diagnostic>> {
        let flushed = if self.vault_state() == VaultState::Open {
            self.flush().await
        } else {
            Ok(0)
        };
        if let Some(bridge) = self
            .bridge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            // Releases the single-opener lock, so the next start does not report
            // `STORE.LOCK_CONTENDED` against a process that is gone.
            let _ = bridge.close();
        }
        self.vault_open.store(false, Ordering::Release);
        self.begin_shutdown();
        flushed
    }

    fn record(&self, diagnostic: &Diagnostic) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.push(
                self.env.now_monotonic(),
                None,
                twinvpn_diag::Record::Diagnostic(Box::new(diagnostic.clone())),
            );
        }
    }

    fn reject(&self, submission: &Submission, code: ReasonCode) -> Diagnostic {
        let diagnostic = Diagnostic::builder(code, Component::ManagementInterface).build();
        self.record(&diagnostic);
        self.events.publish(
            CoreEventKind::CommandRejected {
                op: submission.op.name(),
                diagnostic: Box::new(self.emitter.error_envelope(&diagnostic, None)),
            },
            submission.actor_principal.clone(),
        );
        diagnostic
    }
}

/// The ADR-0008 precondition a submission is missing, if any.
fn missing_precondition(entry: twinvpn_mgmt::Entry, submission: &Submission) -> Option<ReasonCode> {
    match entry.idempotency {
        twinvpn_mgmt::Idempotency::Key if submission.idempotency_key.is_none() => Some(
            twinvpn_mgmt::codes::substituted("MGMT.PRECONDITION_FAILED")?,
        ),
        twinvpn_mgmt::Idempotency::Version if submission.if_version.is_none() => Some(
            twinvpn_mgmt::codes::substituted("MGMT.PRECONDITION_FAILED")?,
        ),
        _ => None,
    }
}

/// `SecureStore`, forwarded from the platform adapter.
///
/// `twinvpn_store::Store::open` takes an `Arc<dyn SecureStore>` and
/// `PlatformAdapter` vends only `&dyn SecureStore` — deliberately, so an adapter
/// can implement all six capabilities on one object. This is the join, and it is
/// a forwarder with no state of its own: every call goes straight through to the
/// adapter the core was constructed with.
struct AdapterSecureStore(Arc<dyn PlatformAdapter>);

impl twinvpn_platform::custody::SecureStore for AdapterSecureStore {
    fn secure_item_read<'a>(
        &'a self,
        key: &'a twinvpn_platform::custody::SecureItemKey,
    ) -> BoxFuture<
        'a,
        Result<Option<twinvpn_platform::custody::SecureItem>, twinvpn_platform::PlatformError>,
    > {
        self.0.store().secure_item_read(key)
    }

    fn secure_item_write_atomic<'a>(
        &'a self,
        key: &'a twinvpn_platform::custody::SecureItemKey,
        value: &'a twinvpn_platform::custody::SecureItem,
    ) -> BoxFuture<'a, Result<(), twinvpn_platform::PlatformError>> {
        self.0.store().secure_item_write_atomic(key, value)
    }

    fn secure_item_delete<'a>(
        &'a self,
        key: &'a twinvpn_platform::custody::SecureItemKey,
    ) -> BoxFuture<'a, Result<(), twinvpn_platform::PlatformError>> {
        self.0.store().secure_item_delete(key)
    }

    fn store_root(
        &self,
    ) -> BoxFuture<'_, Result<twinvpn_platform::custody::StoreRoot, twinvpn_platform::PlatformError>>
    {
        self.0.store().store_root()
    }

    fn record_aead_custody(&self) -> twinvpn_platform::custody::RecordAeadCustody {
        self.0.store().record_aead_custody()
    }
}

/// Whether this build performs `op`.
///
/// Derived from [`crate::dispatch::disposition`], which is the exhaustive match
/// that decides it. There is no second list to drift.
#[cfg(feature = "full")]
#[must_use]
pub fn executes(op: CoreCommand) -> bool {
    dispatch::disposition(op).executes()
}

/// Every operation the catalogue advertises that this build **refuses**, with
/// the registered code and the reason.
///
/// Derived, not maintained. `tests/command_path.rs` asserts that every entry
/// really is refused and that everything else really does work.
#[cfg(feature = "full")]
#[must_use]
pub fn unimplemented() -> Vec<(CoreCommand, ReasonCode, &'static str)> {
    dispatch::not_wired()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn an_abi_mismatch_is_refused_by_name_before_anything_is_touched() {
        let err = testing::core_with(|p| p.abi_major_expected = 99).expect_err("must refuse");
        assert_eq!(err.code().as_str(), "INTERNAL.ABI_VERSION_MISMATCH");
    }

    #[test]
    fn a_matching_abi_creates_an_instance_that_reports_s46() {
        let core = testing::core().expect("creates");
        assert_eq!(core.build_identity().abi_major, testing::ABI_MAJOR);
        // S-46 records the adapter's OWN name, taken from
        // `PlatformAdapter::binding_name`, so a support case can answer "which
        // adapter was loaded" from the bundle rather than from an inference.
        assert_eq!(core.build_identity().adapter_binding, "mock-in-memory");
        assert!(core.instance_id() >= 1);
    }

    #[test]
    fn a_poisoned_instance_refuses_every_subsequent_call() {
        let core = testing::core().expect("creates");
        assert!(!core.is_poisoned());
        core.poison();
        assert!(core.is_poisoned());
        let err = core
            .submit(&Submission::bare(CoreCommand::StatusGet))
            .expect_err("poisoned");
        assert_eq!(err.code().as_str(), "INTERNAL.CORE_PANIC");
    }

    #[test]
    fn poisoning_does_not_touch_the_installed_ruleset() {
        // F-7 and CB-6: a contained panic MUST NOT tear down enforcement.
        let (core, adapter) = testing::core_and_adapter().expect("creates");
        core.poison();
        assert_eq!(
            adapter.tunnel_mock().destroy_calls(),
            0,
            "poisoning must not destroy the interface"
        );
    }

    #[test]
    fn a_rejected_command_produces_an_event_never_a_silent_drop() {
        let core = testing::core().expect("creates");
        let _ = core.submit(&Submission::bare(CoreCommand::PairBegin));
        let event = core
            .next_event(Duration::ZERO)
            .expect("a rejection must be observable");
        assert!(matches!(event.kind, CoreEventKind::CommandRejected { .. }));
    }

    #[test]
    fn a_key_idempotent_operation_without_a_key_is_refused() {
        let core = testing::core().expect("creates");
        let err = core
            .submit(&Submission::bare(CoreCommand::DiagBundleCreate))
            .expect_err("ADR-0008 requires a CEREMONY key");
        // Was `starts_with("POLICY.")`, which is what the substitution cost:
        // MGMT.PRECONDITION_FAILED was unregistered, so a MANAGEMENT
        // precondition failure arrived in the POLICY domain and degraded, on an
        // older client, to "a protection rule stopped this" rather than "this
        // request was missing its idempotency key". registry_version 2
        // registered it.
        assert_eq!(err.code().as_str(), "MGMT.PRECONDITION_FAILED");
    }

    #[test]
    fn a_completed_command_arrives_on_the_one_ordered_stream() {
        let core = testing::core().expect("creates");
        core.submit(&Submission::bare(CoreCommand::StatusGet))
            .expect("status.get is implemented");
        let event = core.next_event(Duration::ZERO).expect("an event");
        assert!(matches!(
            event.kind,
            CoreEventKind::CommandCompleted {
                op: "status.get",
                ..
            }
        ));
    }

    #[test]
    fn a_mutating_command_advances_the_s47_generation() {
        let (core, adapter) = testing::core_and_adapter().expect("creates");
        let peer = twinvpn_types::DeviceId::from_slice(&[0x11; 32]).expect("32");
        // `session.connect` now READS its T01 guards rather than asserting
        // them, so a test that wants it to execute has to establish the facts:
        // an open vault and an authorized peer. See `testing::authorize_peer`.
        testing::authorize_peer(&core, &adapter, peer).expect("authorizes");
        let before = core.generation();
        let mut connect = Submission::bare(CoreCommand::SessionConnect);
        connect.params = vec![0x11; 32];
        core.submit(&connect).expect("session.connect executes");
        assert_eq!(core.generation(), before + 1);
        core.submit(&Submission::bare(CoreCommand::StatusGet))
            .expect("implemented");
        assert_eq!(core.generation(), before + 1, "a read must not advance it");
    }

    #[test]
    fn the_refused_set_is_a_subset_of_the_catalogue() {
        for (op, _, _) in unimplemented() {
            assert!(
                CoreCommand::ALL.contains(&op),
                "{op} is not a catalogue operation"
            );
        }
    }

    #[test]
    fn a_core_with_no_vault_says_so_rather_than_answering_from_memory() {
        // D4. Until `open_store` runs, S-12/S-15/S-27/S-30/S-37 are memory-only,
        // and a caller has to be able to tell.
        let core = testing::core().expect("creates");
        assert_eq!(core.vault_state(), VaultState::Absent);
    }

    #[test]
    fn flushing_without_a_vault_is_refused_not_a_silent_success() {
        let core = testing::core().expect("creates");
        let env = core.env().clone();
        let mut result = None;
        env.runtime().block_on(Box::pin(async {
            result = Some(core.flush().await.map_err(|d| d.code().as_str()));
        }));
        assert_eq!(result, Some(Err("STORE.CUSTODY_DEGRADED")));
    }

    #[test]
    fn mi_18_attribution_reaches_the_event() {
        let core = testing::core().expect("creates");
        let mut submission = Submission::bare(CoreCommand::StatusGet);
        submission.actor_principal = Some("dana".to_owned());
        core.submit(&submission).expect("implemented");
        let event = core.next_event(Duration::ZERO).expect("an event");
        assert_eq!(event.actor_principal.as_deref(), Some("dana"));
    }

    #[test]
    fn shutdown_closes_the_stream_without_removing_enforcement() {
        let (core, adapter) = testing::core_and_adapter().expect("creates");
        core.begin_shutdown();
        assert!(core.next_event(Duration::ZERO).is_none());
        assert_eq!(adapter.tunnel_mock().destroy_calls(), 0);
    }
}
