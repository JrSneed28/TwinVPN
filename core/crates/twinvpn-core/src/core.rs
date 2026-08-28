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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use twinvpn_diag::{Emitter, Ledger, Tier};
use twinvpn_env::Env;
use twinvpn_mgmt::{catalogue, CoreCommand, Submission};
use twinvpn_platform::PlatformAdapter;
use twinvpn_schema::v1;
use twinvpn_types::{codes, Component, Diagnostic, EvidenceValue, ReasonCode};

use crate::build_identity::CoreBuildIdentity;
use crate::events::{CoreEvent, CoreEventKind, EventStream};
use crate::planes::{new_shared, ControlPlanePort, DataPlaneView, Shared};

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
    ledger: std::sync::Mutex<Ledger>,
    events: Arc<EventStream>,
    shared: Shared,
    emitter: Emitter,
    poisoned: AtomicBool,
    instance_id: u64,
    generation: AtomicU64,
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

        Ok(Self {
            env: parts.env,
            adapter: parts.adapter,
            identity,
            ledger: std::sync::Mutex::new(Ledger::new(parts.ledger_capacity)),
            events: Arc::new(EventStream::new(parts.event_capacity)),
            shared: new_shared(),
            // Tier 0 is what the core writes into. A bundle re-encodes from it
            // (ADR-0015 §11.1); nothing here writes at Tier 1 or Tier 2.
            emitter: Emitter::new(Component::Diagnostics, Tier::LocalLedger),
            poisoned: AtomicBool::new(false),
            instance_id: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            generation: AtomicU64::new(0),
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
    /// # THIS METHOD EXECUTES NOTHING
    ///
    /// It is an admission gate: poison check, ADR-0008 precondition,
    /// [`UNIMPLEMENTED`] check, `generation` bump, `CommandCompleted` with an
    /// **empty** result. No component is called. 33 of the 47 catalogue
    /// operations — `session.connect` among them — pass every check and report
    /// success having done no work.
    ///
    /// `Ok(())` means *"the submission was admissible"* and nothing more. Do not
    /// read it as evidence that anything happened. See this crate's `README.md`
    /// §6.1.
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

        if !is_implemented(submission.op) {
            return Err(Box::new(
                self.reject(submission, twinvpn_mgmt::codes::op_unknown()),
            ));
        }

        if entry.mutating {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }

        self.events.publish(
            CoreEventKind::CommandCompleted {
                op: submission.op.name(),
                result: Vec::new(),
            },
            submission.actor_principal.clone(),
        );
        Ok(())
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
        self.env.begin_shutdown();
        self.events.close();
        self.adapter.begin_shutdown();
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

/// Which operations this build actually executes.
///
/// **Stated as a list rather than hidden behind a `_ =>` arm.** A command the
/// catalogue advertises and the core does not execute is a lie a client cannot
/// detect, so the unimplemented set is enumerable, testable, and reported.
#[must_use]
pub fn is_implemented(op: CoreCommand) -> bool {
    !UNIMPLEMENTED.contains(&op)
}

/// Operations the catalogue names that this build does not yet execute.
///
/// Every one of them needs a component this wave did not wire: pairing needs the
/// C-B ceremony end to end (blocked by `ownership.md` §8 **W-21** —
/// `PairingOffer` appears nowhere in `contracts/`), the update verbs need
/// ADR-0021's delivery path, and the disarm ceremony needs ADR-0016's local
/// authentication, which is a shell capability with no ABI entry yet.
pub const UNIMPLEMENTED: &[CoreCommand] = &[
    CoreCommand::PairBegin,
    CoreCommand::PairConfirm,
    CoreCommand::PairCancel,
    CoreCommand::PairStatus,
    CoreCommand::DeviceRevoke,
    CoreCommand::KeyRotate,
    CoreCommand::UpdateStatus,
    CoreCommand::UpdateCheck,
    CoreCommand::UpdateStage,
    CoreCommand::UpdateApply,
    CoreCommand::UpdateRollback,
    CoreCommand::KillswitchDisarmBegin,
    CoreCommand::KillswitchDisarmCommit,
    CoreCommand::ExitnodeSelect,
];

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
        assert!(err.code().as_str().starts_with("POLICY."));
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
        let core = testing::core().expect("creates");
        let before = core.generation();
        core.submit(&Submission::bare(CoreCommand::SessionConnect))
            .expect("implemented");
        assert_eq!(core.generation(), before + 1);
        core.submit(&Submission::bare(CoreCommand::StatusGet))
            .expect("implemented");
        assert_eq!(core.generation(), before + 1, "a read must not advance it");
    }

    #[test]
    fn the_unimplemented_set_is_a_subset_of_the_catalogue() {
        for op in UNIMPLEMENTED {
            assert!(
                CoreCommand::ALL.contains(op),
                "{op} is not a catalogue operation"
            );
        }
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
