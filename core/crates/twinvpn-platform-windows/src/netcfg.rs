//! The transactional configuration surface: `apply`, `rollback`, `set_ruleset`,
//! and the read-back everything else is derived from.
//!
//! **Authority:** [`twinvpn_platform::NetworkConfig`] and every doc comment on
//! it; `docs/networking.md` §5.1 and §2.3 ("partial application is the leak
//! window"); ADR-0008 (idempotent on the generation id); ADR-0010 R5; ADR-0011
//! DN-18/DN-19/DN-20; ADR-0012 KS-17, KS-18, KS-20, K12; ADR-0015 §11.6 O-17 and
//! O-18; ADR-0016 §11.6 step (2); ADR-0022 LC-4 and LC-24.
//!
//! # The ordering, and why it is the safety property
//!
//! ADR-0022 LC-4 draws a line the code has to draw too:
//!
//! ```text
//! 3. query the enforcement layer for the installed ruleset, BOTH families
//! 4. re-assert RULESET_BLOCKED if the query disagrees
//! ───────────── no packet may be emitted before this line ─────────────
//! 5. open the durable store …
//! ```
//!
//! So inside [`WindowsNetworkConfig::apply`] the enforcement transaction goes
//! **first**, then the routes, then the resolver. An apply that programmed a
//! route before the filters were in force would open exactly the window
//! `docs/networking.md` §2.3 names, and it is a window a reviewer cannot see in a
//! diff unless the order is the code's own structure.
//!
//! # All-or-nothing, on a platform with one transaction and two that are not
//!
//! WFP has a real transaction. **IP Helper and the NRPT registry do not.** So
//! `apply` composes them: each step records what it needs to undo, and a failure
//! at step *n* undoes steps *n−1 … 1* before returning. That is compensation, not
//! atomicity, and the difference is stated rather than glossed:
//! [`ApplyFailure::compensation`] reports whether the undo itself succeeded, and
//! a compensation that failed is a host in a state no generation describes —
//! which the caller must treat as `POLICY.KILLSWITCH.ASSERTION_MISMATCH` and
//! re-assert `BLOCKED` from, rather than retrying the apply.
//!
//! # Nothing here is cached
//!
//! [`WindowsNetworkConfig::installed_ruleset`] and
//! [`WindowsNetworkConfig::current_generation`] both go to the engine. ADR-0012
//! K12: "Enforcement state MUST be observable by querying the installed rules,
//! not by trusting the agent's belief about what it installed." The ledger this
//! module keeps holds only what rollback needs — the state each generation
//! *replaced* — and is never consulted to answer "what is installed now".

use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, LinkFacts, NetworkConfig, NetworkContract,
    PlatformError, RouteCapabilities, Ruleset,
};
use twinvpn_types::{AddressFamily, PerFamily};

use crate::dns::{self, InterfaceDns, NrptRule, RestorePoint, StubAddresses};
use crate::route::{self, InstalledRoutes, InterfaceLuid};
use crate::shutdown::ShutdownLatch;
use crate::sys::SystemOps;
use crate::wfp::canary::{CanaryVerdict, CounterSnapshot};
use crate::wfp::readback::{self, Verdict};
use crate::wfp::{self, EnforcementConfig, FilterSet};

/// What one generation replaced, kept so it can be put back.
///
/// Read from the OS at apply time rather than remembered from the previous
/// apply: R5's reversibility has to survive an unclean exit, and a ledger built
/// from what *we* did is empty after a crash.
#[derive(Debug, Clone)]
struct Superseded {
    contract: NetworkContract,
    routes: InstalledRoutes,
    rules: Vec<NrptRule>,
    interface_dns: InterfaceDns,
}

/// Whether the compensation for a failed apply itself succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compensation {
    /// Nothing had been changed when the failure happened.
    NothingToUndo,
    /// Everything that had been changed was put back.
    Restored,
    /// The undo itself failed. **The host is in a state no generation
    /// describes**, and the caller must re-assert `BLOCKED` rather than retry.
    Failed,
}

/// An apply that did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the apply failed at {step}")]
pub struct ApplyFailure {
    /// Which step.
    pub step: &'static str,
    /// Why.
    pub cause: PlatformError,
    /// Whether the undo succeeded.
    pub compensation: Compensation,
}

impl From<ApplyFailure> for PlatformError {
    /// The seam's `apply` returns a [`PlatformError`], so the richer failure is
    /// reduced at the boundary — and the reduction keeps the **cause**, which is
    /// the part that carries the registered `reason_code` and the `WIN32_ERROR`.
    /// The compensation verdict is not lost: it reaches a caller through
    /// [`WindowsNetworkConfig::last_apply_failure`], because a `PlatformError`
    /// has no field for it and inventing one would be a seam change this domain
    /// does not own.
    fn from(failure: ApplyFailure) -> Self {
        failure.cause
    }
}

/// What the engine says about protection, right now.
///
/// ADR-0015 O-17: "a `ProtectionAssertion` is produced by *querying the
/// enforcement layer* … never of the agent's belief about what it configured".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionAssertion {
    /// The posture the engine holds, or `None` when it holds no ruleset of ours.
    pub posture: Option<Ruleset>,
    /// The generation the engine's provider blob carries.
    pub generation: Option<ContractGeneration>,
    /// Whether each family has a Tier-1 deny installed.
    pub families_covered: PerFamily<bool>,
    /// How many KS-9 bootstrap-exemption filters the engine holds.
    ///
    /// Zero on a host that has booted and not yet started the service: the
    /// exemption is a runtime filter and the KS-19 boot set cannot carry one.
    pub bootstrap_exemptions: usize,
    /// How many owned filters belong to the **runtime** set.
    ///
    /// Separate from the boot artifact's, because a host holding only the KS-19
    /// filters is fail-closed and **not yet running**: the bootstrap exemption
    /// is a runtime filter, so until the runtime set is installed the agent
    /// itself cannot reach the control plane. That is the availability gap
    /// ADR-0012 §11.6's Windows row names, and it is a state
    /// [`WindowsNetworkConfig::reclaim`] has to be able to see in order to leave.
    pub runtime_filters: usize,
    /// How many belong to the KS-19 boot artifact.
    pub boot_filters: usize,
    /// How the engine's contents compare with what was asked for.
    pub verdict: Verdict,
}

impl ProtectionAssertion {
    /// Whether this assertion may be rendered as protecting the host.
    ///
    /// **Both** conditions, and the conjunction is the point: a `Protected`
    /// posture over one family is ADR-0010 R6's leak, and a matching posture at
    /// the wrong generation is a host running policy nobody asked for.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.posture == Some(Ruleset::Protected)
            && self.verdict.is_conforming()
            && *self.families_covered.get(AddressFamily::V4)
            && *self.families_covered.get(AddressFamily::V6)
    }

    /// Whether the host is fail-closed — protected or blocked, but not open.
    #[must_use]
    pub fn is_fail_closed(&self) -> bool {
        self.posture.is_some()
            && *self.families_covered.get(AddressFamily::V4)
            && *self.families_covered.get(AddressFamily::V6)
    }
}

/// Everything the network configuration takes at construction (CD-2).
pub struct NetworkConfigParts {
    /// The system access. `sys::win::WindowsSystem` in production.
    pub system: Arc<dyn SystemOps>,
    /// The enforcement facts the seam does not carry.
    pub enforcement: EnforcementConfig,
    /// The stub's four listening addresses (ADR-0011 §11.2).
    pub stub: StubAddresses,
    /// Where the DN-18 restore point is written.
    ///
    /// Readable by the package-owned restore service with the agent absent
    /// (DN-20), which is why it is a path and not an in-memory value.
    pub restore_point_path: std::path::PathBuf,
    /// The shutdown latch shared with the rest of the adapter.
    pub shutdown: ShutdownLatch,
}

/// The Windows implementation of [`NetworkConfig`].
pub struct WindowsNetworkConfig {
    system: Arc<dyn SystemOps>,
    enforcement: EnforcementConfig,
    stub: StubAddresses,
    restore_point_path: std::path::PathBuf,
    shutdown: ShutdownLatch,
    ledger: Mutex<Ledger>,
}

#[derive(Debug, Default)]
struct Ledger {
    superseded: Vec<(ContractGeneration, Superseded)>,
    last_failure: Option<ApplyFailure>,
}

impl WindowsNetworkConfig {
    /// Builds it.
    #[must_use]
    pub fn new(parts: NetworkConfigParts) -> Self {
        Self {
            system: parts.system,
            enforcement: parts.enforcement,
            stub: parts.stub,
            restore_point_path: parts.restore_point_path,
            shutdown: parts.shutdown,
            ledger: Mutex::new(Ledger::default()),
        }
    }

    /// The overlay this configuration programs.
    #[must_use]
    pub const fn overlay(&self) -> InterfaceLuid {
        InterfaceLuid(self.enforcement.overlay_luid)
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The compensation verdict of the last failed apply, if there was one.
    #[must_use]
    pub fn last_apply_failure(&self) -> Option<ApplyFailure> {
        self.ledger().last_failure.clone()
    }

    /// The **W-24 read-back**: what the engine says, compared against `intended`.
    ///
    /// # Errors
    ///
    /// A failed query is an error, never a remembered value. `Ok` with an absent
    /// posture means "the engine holds no ruleset of ours", which is a different
    /// claim from "we could not ask" — and O-18 makes the difference the
    /// difference between rendering `BLOCKED` and rendering `UNKNOWN`.
    pub fn assert_protection(
        &self,
        intended: Option<&FilterSet>,
    ) -> Result<ProtectionAssertion, PlatformError> {
        self.shutdown.check()?;
        let state = self.system.filters().read()?;
        let installed = readback::parse_installed(&state);
        let verdict = intended.map_or_else(
            || {
                if installed.is_some() {
                    Verdict::Matches
                } else {
                    Verdict::Absent
                }
            },
            |set| readback::compare(&state, set),
        );
        Ok(ProtectionAssertion {
            posture: installed.as_ref().map(|i| i.posture),
            generation: installed.as_ref().map(|i| i.generation),
            families_covered: installed.as_ref().map_or_else(
                || PerFamily::new(false, false),
                |i| {
                    PerFamily::new(
                        *i.scope_denies.get(AddressFamily::V4) > 0,
                        *i.scope_denies.get(AddressFamily::V6) > 0,
                    )
                },
            ),
            bootstrap_exemptions: installed.as_ref().map_or(0, |i| i.bootstrap_exemptions),
            runtime_filters: installed.as_ref().map_or(0, |i| i.owned_filters),
            boot_filters: installed.as_ref().map_or(0, |i| i.boot_filters),
            verdict,
        })
    }

    /// ADR-0016 §11.6 step (1): is the KS-19 boot artifact registered?
    ///
    /// **Verification, never installation** (PS-7).
    pub fn verify_boot_artifact(&self) -> Result<wfp::boot::BootArtifact, PlatformError> {
        self.shutdown.check()?;
        Ok(wfp::boot::verify(&self.system.filters().read()?))
    }

    /// ADR-0016 §11.6 step (2): reclaim the owner-tagged set, and **read it
    /// back**.
    ///
    /// Re-asserts `BLOCKED` when the engine disagrees, which is ADR-0022 LC-4
    /// step 4's "never *remove rules*; atomic swap". The returned assertion is
    /// the one the shell reports; a `false` from
    /// [`ProtectionAssertion::is_fail_closed`] after this call is PS-18's
    /// refuse-to-start condition.
    pub fn reclaim(
        &self,
        contract: Option<&NetworkContract>,
    ) -> Result<ProtectionAssertion, PlatformError> {
        self.shutdown.check()?;
        let blocked = self.render(contract.unwrap_or(&blank_contract()), Ruleset::Blocked);
        let observed = self.assert_protection(Some(&blocked))?;
        // Reclaimed, not recreated (KS-20, PS-8): if the engine already holds a
        // fail-closed **runtime** set, leave it exactly where it is. KS-23
        // forbids remove-then-add, and re-committing on every start would be
        // that, at the moment the host is least defended.
        //
        // `bootstrap_exemptions > 0` is the load-bearing half of the condition. A
        // host that has just booted holds the KS-19 artifact and nothing else —
        // fail-closed, `Blocked`, and **unable to run**, because the bootstrap
        // exemption is a runtime filter. Returning early there would leave the
        // service permanently unable to reach the control plane and reporting
        // itself healthy, which is the availability half of the same defect
        // PS-18 names on the enforcement side.
        if observed.is_fail_closed()
            && observed.posture == Some(Ruleset::Blocked)
            && observed.bootstrap_exemptions > 0
        {
            return Ok(observed);
        }
        self.commit(&blocked)?;
        self.assert_protection(Some(&blocked))
    }

    /// Samples the leak canary's counters (ADR-0012 §11.9).
    pub fn counters(&self) -> Result<CounterSnapshot, PlatformError> {
        self.shutdown.check()?;
        let (events, lost) = self.system.filters().net_events()?;
        Ok(wfp::canary::fold(&events, lost))
    }

    /// Compares two counter samples for one family.
    #[must_use]
    pub fn canary(
        before: &CounterSnapshot,
        after: &CounterSnapshot,
        family: AddressFamily,
    ) -> CanaryVerdict {
        wfp::canary::canary_verdict(before, after, family)
    }

    /// Removes every owner-tagged object.
    ///
    /// The `twinvpn-unblock` path (KS-20a) and PS-21 step 5. **Never** reached by
    /// [`twinvpn_platform::PlatformAdapter::begin_shutdown`]: CB-6 puts the
    /// ruleset in the OS's custody precisely so the core going away does not drop
    /// protection.
    pub fn disarm(&self) -> Result<(), PlatformError> {
        self.system.filters().purge()
    }

    fn render(&self, contract: &NetworkContract, ruleset: Ruleset) -> FilterSet {
        wfp::filters::render(contract, ruleset, &self.enforcement)
    }

    fn commit(&self, set: &FilterSet) -> Result<(), PlatformError> {
        // A set that fails its own validation is a defect in this crate, not a
        // condition the host is in: it is reported as an invariant violation and
        // never sent to the engine.
        set.validate().map_err(|defect| {
            tracing::error!(defect = %defect, "a rendered filter set violated its own invariants");
            PlatformError::AdapterUnavailable(Some(twinvpn_platform::OsDetail {
                code: 0,
                call: "FilterSet::validate",
            }))
        })?;
        self.system.filters().commit(set)
    }

    /// The whole of `apply`, as a fallible sequence with compensation.
    fn apply_inner(&self, contract: &NetworkContract) -> Result<(), ApplyFailure> {
        let overlay = self.overlay();

        // ---- read what we are replacing, from the OS ------------------------
        let routes_before = self
            .system
            .routes()
            .read(overlay)
            .map_err(|cause| self.fail("routes.read", cause, Compensation::NothingToUndo))?;
        let (rules_before, dns_before) = self
            .system
            .resolver()
            .read(overlay)
            .map_err(|cause| self.fail("resolver.read", cause, Compensation::NothingToUndo))?;

        // ---- step 1: enforcement, before any packet can be emitted ----------
        let set = self.render(contract, contract.ruleset);
        let engine_before = self
            .system
            .filters()
            .read()
            .map_err(|cause| self.fail("filters.read", cause, Compensation::NothingToUndo))?;
        self.commit(&set)
            .map_err(|cause| self.fail("filters.commit", cause, Compensation::NothingToUndo))?;

        // From here on a failure has something to undo.
        let undo_filters = || {
            let previous = readback::parse_installed(&engine_before);
            match previous {
                // Put back the posture the engine held. Never `purge`: a
                // compensation that removed the rules would turn a failed apply
                // into an open host, which is the one outcome this whole module
                // exists to prevent.
                Some(installed) => self
                    .commit(&self.render(contract, installed.posture))
                    .is_ok(),
                // There was nothing of ours before. Leave `BLOCKED` installed
                // rather than restoring "no rules": KS-17 has two rulesets and
                // no third value, and a fresh host that failed to arm is
                // fail-closed, not unfiltered.
                None => self
                    .commit(&self.render(contract, Ruleset::Blocked))
                    .is_ok(),
            }
        };

        // ---- step 2: routes and addresses -----------------------------------
        let route_plan = route::plan(&routes_before, contract, overlay);
        if let Err(defect) = route_plan.validate(overlay) {
            tracing::error!(defect = %defect, "a route plan violated its own invariants");
            let compensation = compensation_of(undo_filters());
            return Err(self.fail(
                "routes.validate",
                PlatformError::RouteProgrammingDenied(None),
                compensation,
            ));
        }
        if let Err(cause) = self.system.routes().apply(&route_plan) {
            let compensation = compensation_of(undo_filters());
            return Err(self.fail("routes.apply", cause, compensation));
        }
        let undo_routes = || {
            let back = route::invert_with_metric(&route_plan, &routes_before);
            self.system.routes().apply(&back).is_ok()
        };

        // ---- step 3: the resolver, restore point FIRST (DN-18, PS-6) --------
        let programme = match dns::render(&contract.dns, overlay, &self.stub) {
            Ok(programme) => programme,
            Err(cause) => {
                let compensation = compensation_of(undo_routes() && undo_filters());
                return Err(self.fail("dns.render", cause, compensation));
            }
        };
        if let Err(defect) = programme.validate() {
            tracing::error!(defect = %defect, "a DNS programme violated its own invariants");
            let compensation = compensation_of(undo_routes() && undo_filters());
            return Err(self.fail(
                "dns.validate",
                crate::oserr::unavailable("DnsProgramme::validate"),
                compensation,
            ));
        }
        let point = RestorePoint {
            prior_rules: rules_before.clone(),
            prior_interface: dns_before.clone(),
            restore_token: contract.generation.0,
        };
        if let Err(cause) = self.write_restore_point(&point) {
            // DN-18 is explicit that the restore point is written and flushed
            // **before** the mutation. A restore point we could not write means
            // the mutation must not happen: D7's failure is a host left pointing
            // at a dead resolver, and the only thing that prevents it is this
            // file existing.
            let compensation = compensation_of(undo_routes() && undo_filters());
            return Err(self.fail("dns.restore_point", cause, compensation));
        }
        let dns_plan = dns::plan(&rules_before, &programme);
        if let Err(cause) = self.system.resolver().apply(&dns_plan) {
            let compensation = compensation_of(undo_routes() && undo_filters());
            return Err(self.fail("dns.apply", cause, compensation));
        }

        self.ledger().superseded.push((
            contract.generation,
            Superseded {
                contract: contract.clone(),
                routes: routes_before,
                rules: rules_before,
                interface_dns: dns_before,
            },
        ));
        Ok(())
    }

    fn fail(
        &self,
        step: &'static str,
        cause: PlatformError,
        compensation: Compensation,
    ) -> ApplyFailure {
        let failure = ApplyFailure {
            step,
            cause,
            compensation,
        };
        self.ledger().last_failure = Some(failure.clone());
        failure
    }

    fn write_restore_point(&self, point: &RestorePoint) -> Result<(), PlatformError> {
        crate::restore::write(&self.restore_point_path, point)
    }

    fn rollback_inner(&self, generation: ContractGeneration) -> Result<(), PlatformError> {
        self.shutdown.check()?;
        let entry = {
            let ledger = self.ledger();
            ledger
                .superseded
                .iter()
                .rev()
                .find(|(g, _)| *g == generation)
                .map(|(_, s)| s.clone())
        };
        let Some(entry) = entry else {
            // A generation this process never applied. Not an error and not a
            // silent success: after a crash the ledger is empty by design, and
            // the caller's recovery path is `reclaim` plus a fresh `apply`, not
            // a rollback to a state nobody recorded.
            return Err(PlatformError::AdapterUnavailable(Some(
                twinvpn_platform::OsDetail {
                    code: 0,
                    call: "rollback(unknown generation)",
                },
            )));
        };
        let overlay = self.overlay();

        // The reverse of apply's order: resolver, routes, then enforcement.
        // PS-21's uninstall order is the same shape and for the same reason —
        // the resolver goes back before the interface does, so name resolution
        // is never left pointing at a stub that has gone.
        let currently_ours: Vec<String> = self
            .system
            .resolver()
            .read(overlay)?
            .0
            .into_iter()
            .filter(|r| r.id.starts_with(dns::RULE_PREFIX))
            .map(|r| r.id)
            .collect();
        let point = RestorePoint {
            prior_rules: entry.rules.clone(),
            prior_interface: entry.interface_dns.clone(),
            restore_token: generation.0,
        };
        self.system
            .resolver()
            .apply(&dns::restore_plan(&point, &currently_ours))?;

        // Diffed from what the OS holds **now**, not from inverting the forward
        // plan. Inverting assumes the host is still exactly where that plan left
        // it, which is true in the happy case and false after a crash, after a
        // third-party tool has touched the table, or after two generations. R5
        // requires reversibility "including after an unclean process exit", and
        // the only state a fresh process can trust is the one it read back.
        let now = self.system.routes().read(overlay)?;
        let back = route::plan_to_state(&now, &entry.routes, overlay);
        back.validate(overlay).map_err(|defect| {
            tracing::error!(defect = %defect, "a rollback plan violated its own invariants");
            PlatformError::RouteProgrammingDenied(None)
        })?;
        self.system.routes().apply(&back)?;

        // Enforcement last, and never removed: KS-17 has two rulesets and no
        // third value.
        self.commit(&self.render(&entry.contract, Ruleset::Blocked))?;

        self.ledger().superseded.retain(|(g, _)| *g < generation);
        Ok(())
    }
}

const fn compensation_of(ok: bool) -> Compensation {
    if ok {
        Compensation::Restored
    } else {
        Compensation::Failed
    }
}

/// A contract that describes nothing, for the one caller that has none.
///
/// [`WindowsNetworkConfig::reclaim`] runs at start, before the durable store has
/// been opened, so there is no contract to render from. Rendering from this one
/// still produces a set that denies the overlay space in both families, because
/// [`wfp::baseline_protected`] is a floor beneath every render — which is
/// `desktop-linux`'s R-6 finding, and the reason a blank contract is safe here.
/// The contract in force before any session exists: no addresses, no routes,
/// no resolvers, `Blocked`. What step 5 of the service's start sequence renders
/// and what a caller probing the engine with the runtime set should render too.
#[must_use]
pub fn blank_contract() -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(0),
        addresses: PerFamily::new(Vec::new(), Vec::new()),
        routes: PerFamily::new(Vec::new(), Vec::new()),
        dns: twinvpn_platform::DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset: Ruleset::Blocked,
        mtu: 1280,
        // `Blocked` describes nothing and rides nothing.
        tunnel_remote_address: None,
    }
}

impl NetworkConfig for WindowsNetworkConfig {
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.apply_inner(contract).map_err(PlatformError::from)
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move { self.rollback_inner(generation) })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // From the engine, never from the ledger. After a crash the ledger
            // is empty and the engine still holds the answer, which is the whole
            // reason this is the recovery entry point.
            let state = self.system.filters().read()?;
            Ok(readback::parse_installed(&state).map(|i| i.generation))
        })
    }

    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // Re-render the applied contract at the new posture, so the swap
            // carries the same Tier-1 scope it had. Rendering from a blank
            // contract here would be `desktop-linux`'s R-6: a fail-closed swap
            // that covers nothing.
            let contract = {
                let ledger = self.ledger();
                ledger
                    .superseded
                    .iter()
                    .rev()
                    .find(|(g, _)| *g == generation)
                    .map(|(_, s)| s.contract.clone())
            };
            let contract = contract.unwrap_or_else(blank_contract);
            self.commit(&self.render(&contract, ruleset))
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let state = self.system.filters().read()?;
            Ok(readback::parse_installed(&state).map(|i| i.posture))
        })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        wfp::custody()
    }

    /// Windows has route metrics, so the instruction is honoured.
    ///
    /// `MIB_IPFORWARD_ROW2::Metric` plus the interface metric, both of which
    /// `route::plan` already programs.
    fn route_capabilities(&self) -> RouteCapabilities {
        RouteCapabilities { metric: true }
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            self.system.routes().link_facts(self.overlay())
        })
    }
}
