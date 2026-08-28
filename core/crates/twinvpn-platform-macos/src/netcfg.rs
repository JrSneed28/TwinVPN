//! The transactional network configuration: apply, rollback, the posture swap,
//! and the W-24 read-back.
//!
//! **Authority:** `docs/networking.md` §5.1 (the adapter contract) and §2.3
//! ("partial application is the leak window"); ADR-0008 (idempotent on the
//! generation id); ADR-0010 R5 (reversible "including after an unclean process
//! exit"); ADR-0011 DN-18/DN-19/DN-20; ADR-0012 §11.5 clause 4 (the rules live
//! before the addresses and routes do), KS-17, KS-23; ADR-0015 §11.6 rule 1 (the
//! `ProtectionAssertion` is a query); ADR-0016 PS-21 step 3; ADR-0018 CB-6, CD-2.
//!
//! # Why the carriers are injected
//!
//! macOS runs this adapter in two processes with two entirely different
//! mechanisms — the NE system extension, where the OS installs routes and
//! resolvers from a settings object, and the `LaunchDaemon`, where `route(8)` and
//! `configd` do it. **Neither is an OS branch.** [`NetworkCarriers`] is a
//! construction-time capability (CD-2), so this module's transaction logic is one
//! implementation over both, and a **recording** carrier makes the whole of it —
//! ordering, idempotency, unwind, the posture swap, the read-back — execute under
//! `cargo test` on this Linux host, with no `pfctl` and no kernel.
//!
//! That is the point of the shape. The apply/rollback ordering is where a leak
//! window lives, and it is checkable here.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, RouteCapabilities, LinkFacts, NetworkConfig, NetworkContract,
    PlatformError, Ruleset,
};
use twinvpn_types::{PerFamily, UnderlayFamilies};

use crate::oserr::{self, Context};
use crate::pf::{self, EnforcementConfig};
use crate::pfread::{self, Assertion, Installed, LabelCounters, PfStatus};
use crate::resolver::{self, ResolverCarrier, ResolverPlan, RestorePoint};
use crate::route::{self, RouteCarrier, RouteOp, RouteProgramme};
use crate::shutdown::ShutdownLatch;

/// The `pf` control binary. Absolute, so `PATH` cannot redirect it — ADR-0016 Q10
/// forbids inheriting a search path that could supply executable code to a
/// privileged process.
pub const PFCTL_BIN: &str = "/sbin/pfctl";

/// The route command. Absolute, for the same reason.
pub const ROUTE_BIN: &str = "/sbin/route";

/// Installs the `pf` anchor and reads it back.
///
/// Two separate reads rather than one call returning everything, because
/// [`Assertion`] must be able to say "pf is off" independently of "the anchor is
/// ours": an anchor loaded into a disabled filter is not protection, and a single
/// combined result would let one answer hide the other.
pub trait PfEngine: Send + Sync + std::fmt::Debug {
    /// Loads `body` into `anchor`, as **one** `pfctl -a <anchor> -f -`.
    ///
    /// One invocation, because pf applies a load as a single transaction. A
    /// flush-then-load in two calls would open exactly the window KS-17 exists to
    /// close, and remove-then-add is what KS-23 forbids on update.
    fn load_anchor(&self, anchor: &str, body: &str) -> Result<(), PlatformError>;

    /// Whether the packet filter itself is enabled.
    fn status(&self) -> Result<PfStatus, PlatformError>;

    /// The anchor's marker tables, or `None` when the anchor is not ours.
    fn tables(&self, anchor: &str) -> Result<Option<Installed>, PlatformError>;

    /// The anchor's per-label counters — the leak canary's read (ADR-0012 §11.9).
    fn labels(&self, anchor: &str) -> Result<BTreeMap<String, LabelCounters>, PlatformError>;
}

/// Runs one route operation.
pub trait RouteEngine: Send + Sync + std::fmt::Debug {
    /// Applies `op`.
    fn run(&self, op: &RouteOp) -> Result<(), PlatformError>;
}

/// Programmes and restores the resolver.
pub trait ResolverEngine: Send + Sync + std::fmt::Debug {
    /// Reads what is at the service's DNS key **before** anything is written.
    /// DN-18.
    fn capture(&self, service_id: &str) -> Result<RestorePoint, PlatformError>;

    /// Writes the restore point where it survives this process. PS-6.
    fn persist(&self, point: &RestorePoint) -> Result<(), PlatformError>;

    /// Applies a plan.
    fn apply(&self, plan: &ResolverPlan) -> Result<(), PlatformError>;
}

/// Which mechanisms carry the three programmes on this binding.
///
/// A capability, injected at construction. Nothing above this struct asks which
/// OS or which process it is in.
#[derive(Clone)]
pub struct NetworkCarriers {
    /// The enforcement engine. Present on **both** bindings: ADR-0012 §11.6 puts
    /// the kill switch in `pf` whichever process is running, so there is no
    /// carrier under which enforcement is absent.
    pub pf: Arc<dyn PfEngine>,
    /// The route engine.
    pub route: Arc<dyn RouteEngine>,
    /// The resolver engine.
    pub resolver: Arc<dyn ResolverEngine>,
    /// How routes reach the kernel.
    pub route_carrier: RouteCarrier,
    /// How the resolver is programmed.
    pub resolver_carrier: ResolverCarrier,
    /// The `SCDynamicStore` service id of the overlay's network service.
    ///
    /// **A reported gap:** the seam carries no service identity, and `configd`
    /// keys are per-service. Injected by the shell, which learns it from the
    /// interface it created.
    pub service_id: String,
}

/// What one applied generation left on the host.
struct Generation {
    id: ContractGeneration,
    routes: RouteProgramme,
    restore_point: Option<RestorePoint>,
    /// The contract this generation installed.
    ///
    /// **Held so the posture swap can re-render it.** A swap that rendered a
    /// synthetic empty contract would emit a Tier-2 drop over nothing and its
    /// anchor load would replace the real drops — a "fail-closed" swap that opens
    /// the host. The Tier-1 scope does not change across a swap; only whether the
    /// overlay is an exception to it does, which is what KS-17's "atomic swap
    /// between the two" actually means.
    contract: NetworkContract,
}

/// macOS's transactional network configuration.
pub struct MacosNetworkConfig {
    shutdown: ShutdownLatch,
    enforcement: EnforcementConfig,
    carriers: NetworkCarriers,
    history: Mutex<Vec<Generation>>,
}

impl MacosNetworkConfig {
    /// Binds the configuration surface.
    #[must_use]
    pub fn new(
        shutdown: ShutdownLatch,
        enforcement: EnforcementConfig,
        carriers: NetworkCarriers,
    ) -> Self {
        Self {
            shutdown,
            enforcement,
            carriers,
            history: Mutex::new(Vec::new()),
        }
    }

    /// The enforcement configuration in force.
    #[must_use]
    pub const fn enforcement(&self) -> &EnforcementConfig {
        &self.enforcement
    }

    /// The carriers in force.
    #[must_use]
    pub const fn carriers(&self) -> &NetworkCarriers {
        &self.carriers
    }

    /// The `pfctl` binary this host has, or the registered failure.
    ///
    /// **Never a silent success**: ADR-0012 §8 requires that if the ruleset cannot
    /// be installed the client refuses to enter a protected state.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] when `pfctl(8)` is absent.
    pub fn pfctl_binary() -> Result<&'static str, PlatformError> {
        if Path::new(PFCTL_BIN).exists() {
            Ok(PFCTL_BIN)
        } else {
            Err(oserr::unavailable("pfctl(8)", libc::ENOENT))
        }
    }

    /// The `route` binary, for the `LaunchDaemon` carrier.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] when `route(8)` is absent.
    pub fn route_binary() -> Result<&'static str, PlatformError> {
        if Path::new(ROUTE_BIN).exists() {
            Ok(ROUTE_BIN)
        } else {
            Err(oserr::unavailable("route(8)", libc::ENOENT))
        }
    }

    /// The whole protection assertion, read from pf.
    ///
    /// **This is the W-24 query.** ADR-0015 §11.6 rule 1 requires the
    /// `ProtectionAssertion` to be produced by querying the enforcement layer,
    /// "never of the agent's belief". Nothing here is cached, and a failed query
    /// is an error rather than a remembered value.
    ///
    /// # Errors
    ///
    /// Whatever the engine reports. A failure is **not** turned into "unprotected"
    /// — that is the dangerous direction.
    pub fn assertion(&self) -> Result<Assertion, PlatformError> {
        Ok(Assertion {
            status: self.carriers.pf.status()?,
            installed: self.carriers.pf.tables(pf::ANCHOR)?,
        })
    }

    /// The per-label counters, for the leak canary and KS-11's exempt accounting.
    ///
    /// # Errors
    ///
    /// Whatever the engine reports.
    pub fn counters(&self) -> Result<BTreeMap<String, LabelCounters>, PlatformError> {
        self.carriers.pf.labels(pf::ANCHOR)
    }

    /// The contract currently in force in this process, if any.
    ///
    /// Distinct from [`NetworkConfig::current_generation`], which asks **pf**.
    /// This one is the process's own memory and is used only by the posture swap,
    /// which needs the contract's scope and not just its number.
    #[must_use]
    pub fn applied_contract(&self) -> Option<NetworkContract> {
        self.history
            .lock()
            .ok()
            .and_then(|h| h.last().map(|g| g.contract.clone()))
    }

    /// Runs a route programme, unwinding **exactly** what went in on failure.
    fn run_routes(&self, programme: &RouteProgramme) -> Result<(), PlatformError> {
        for (index, op) in programme.ops.iter().enumerate() {
            if let Err(error) = self.carriers.route.run(op) {
                // §2.3: partial application is the leak window. Unwind precisely
                // the prefix that was applied — deleting an op that never went in
                // would remove a route belonging to the previous generation or to
                // the host.
                for undo in programme.applied_prefix(index).inverse().ops {
                    let _ = self.carriers.route.run(&undo);
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Renders and loads the anchor for `contract` under `ruleset`.
    fn load_anchor(
        &self,
        contract: &NetworkContract,
        ruleset: Ruleset,
    ) -> Result<(), PlatformError> {
        let body = pf::render(contract, ruleset, &self.enforcement);
        self.carriers.pf.load_anchor(pf::ANCHOR, &body)
    }
}

impl NetworkConfig for MacosNetworkConfig {
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;

            // ADR-0008: idempotent on the generation id. Re-applying the
            // generation already in force succeeds and changes nothing, so a
            // retry after a crash converges rather than duplicating routes.
            {
                let history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                if history.last().is_some_and(|g| g.id == contract.generation) {
                    return Ok(());
                }
            }

            // 1. The firewall, FIRST and as one transaction. ADR-0012 §11.5
            //    clause 4: the rules live before the addresses and routes do.
            self.load_anchor(contract, contract.ruleset)?;

            // 2. Routes, both families, unwound on any failure so the host is
            //    exactly as it was.
            let programme = route::programme(
                contract,
                &self.enforcement.overlay_interface,
                self.carriers.route_carrier,
            );
            self.run_routes(&programme)?;

            // 3. The resolver, restore point FIRST (DN-18, PS-6).
            let restore_point = match self.carriers.resolver_carrier {
                ResolverCarrier::TunnelSettings => None,
                ResolverCarrier::DynamicStore => {
                    let point = self.carriers.resolver.capture(&self.carriers.service_id)?;
                    self.carriers.resolver.persist(&point)?;
                    let plan = resolver::plan(&contract.dns, &self.carriers.service_id)?;
                    if let Err(error) = self.carriers.resolver.apply(&plan) {
                        // The routes are unwound so the failure leaves nothing
                        // half-applied. The ANCHOR is deliberately left in place:
                        // CB-6 puts it in the OS's custody, and removing it on a
                        // resolver failure would open the leak window this whole
                        // ordering exists to close.
                        for undo in programme.inverse().ops {
                            let _ = self.carriers.route.run(&undo);
                        }
                        return Err(error);
                    }
                    Some(point)
                }
            };

            let mut history = self
                .history
                .lock()
                .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
            history.push(Generation {
                id: contract.generation,
                routes: programme,
                restore_point,
                contract: contract.clone(),
            });
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Deliberately NOT gated on the shutdown latch: rolling back is part
            // of an orderly stop, and refusing it during shutdown would leave the
            // host mutated.
            let victims = {
                let mut history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                let Some(position) = history.iter().position(|g| g.id == generation) else {
                    // ADR-0010 R5 requires reversibility "including after an
                    // unclean process exit", and a generation this process never
                    // applied is exactly that case. Nothing of ours is on the host
                    // under that id, so there is nothing to undo.
                    return Ok(());
                };
                history.split_off(position)
            };

            // Reverse order, and the RESOLVER FIRST within each generation: DN-19
            // and ADR-0016 PS-21 step 3 both put the resolver restore before the
            // interface goes, "so name resolution is never left pointing at a dead
            // stub".
            for entry in victims.iter().rev() {
                if let Some(point) = &entry.restore_point {
                    if self.carriers.resolver.apply(&point.plan()).is_err() {
                        // DN-20: the device stays fail-closed rather than
                        // regaining an upstream resolver in an unarmed window. The
                        // anchor is untouched here for exactly that reason.
                        tracing::error!(
                            target: "twinvpn.platform.macos.resolver",
                            "the host resolver could not be restored; the device stays fail-closed"
                        );
                    }
                }
                for undo in entry.routes.inverse().ops {
                    self.carriers.route.run(&undo)?;
                }
            }
            Ok(())
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move {
            // **Read from pf, not from this process's history.** This is "the
            // recovery entry point": after a crash the core reads it and decides
            // whether to converge or roll back, and a value remembered in memory
            // is exactly the thing a crash destroys.
            Ok(self
                .carriers
                .pf
                .tables(pf::ANCHOR)?
                .and_then(|i| i.generation))
        })
    }

    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let contract = {
                let history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                history
                    .iter()
                    .rev()
                    .find(|g| g.id == generation)
                    .map(|g| g.contract.clone())
            };
            // **No synthetic contract.** Rendering an empty one would emit a
            // Tier-2 drop over nothing, and the anchor load would replace the real
            // drops with none — a "fail-closed" swap that opens the host. A swap
            // for a generation this process did not apply is refused instead.
            let Some(contract) = contract else {
                return Err(oserr::unavailable("pf.swap.generation", libc::ENOENT));
            };
            self.load_anchor(&contract, ruleset)
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move {
            let assertion = self.assertion()?;
            // pf being off is genuinely "no ruleset installed": the anchor's rules
            // are not being evaluated. That is the one case in which `None` is the
            // truth rather than the dangerous direction, and a caller that needs
            // to tell "off" from "not ours" calls `assertion()` instead.
            if !matches!(assertion.status, PfStatus::Enabled) {
                return Ok(None);
            }
            Ok(assertion.installed.map(|i| i.ruleset))
        })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        pf::custody()
    }

    /// **Darwin has no route metric**, so the capability says so in advance.
    ///
    /// `route(8)` carries none, and preference comes from prefix length and the
    /// network service order. This adapter already refuses a metric it is handed
    /// (`RouteOp::metric_unrepresentable`); declaring the capability is what
    /// lets the core express precedence the way this platform actually has one —
    /// `docs/networking.md` §7.2's split default is a prefix-length technique
    /// and needs no metric — rather than issuing an instruction that will be
    /// refused.
    fn route_capabilities(&self) -> RouteCapabilities {
        RouteCapabilities { metric: false }
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            // **Not implemented against a live Darwin kernel in this wave.**
            // `LinkFacts` needs the underlay's MTU, its families, its per-family
            // default routes, its resolvers and its power posture — five reads
            // across `getifaddrs`, the `PF_ROUTE` table dump and `SCDynamicStore`,
            // none of which can be exercised here. Reporting invented facts would
            // be worse than reporting none: `UnderlayFamilies` in particular is
            // the value ADR-0010 §11.7 branches three ways on, and a wrong answer
            // there is a v6-only network silently treated as dual-stack.
            //
            // So this returns the registered "the adapter cannot answer" condition
            // and `shells/macos/README.md` §7 names it as a gap. The shape below
            // is the one a real implementation fills in.
            Err(oserr::unavailable("query_link_facts", libc::ENOSYS))
        })
    }
}

/// The facts a real [`NetworkConfig::query_link_facts`] must report.
///
/// Present as a named value so the gap above is a *shape* rather than a hole: a
/// shell can construct one from its own enumeration today, and the day the
/// adapter can read them the type does not change.
#[must_use]
pub fn link_facts_from(
    mtu: u32,
    families: UnderlayFamilies,
    default_routes: PerFamily<bool>,
    resolvers: PerFamily<Vec<twinvpn_types::IpAddr>>,
    metered: bool,
    low_power: bool,
) -> LinkFacts {
    LinkFacts {
        mtu,
        families,
        default_routes,
        resolvers,
        metered,
        low_power,
    }
}

// ---------------------------------------------------------------------------
// The Darwin engines
//
// Process-spawning, so their ARGUMENT CONSTRUCTION is target-free and tested
// here; only the execution needs a Mac. `pfctl` and `route` are absent on this
// host, so every one of these returns the registered "absent" condition under
// `cargo test` — which is itself the behaviour ADR-0012 §8 requires.
// ---------------------------------------------------------------------------

/// `pfctl(8)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PfctlEngine;

impl PfctlEngine {
    /// The argument vector for a load. Exposed so it is testable without `pfctl`.
    #[must_use]
    pub fn load_argv(anchor: &str) -> Vec<String> {
        vec![
            "-a".to_owned(),
            anchor.to_owned(),
            "-f".to_owned(),
            "-".to_owned(),
        ]
    }

    /// The argument vector for each of the three reads.
    #[must_use]
    pub fn show_argv(anchor: Option<&str>, what: &str) -> Vec<String> {
        let mut argv = Vec::new();
        if let Some(anchor) = anchor {
            argv.push("-a".to_owned());
            argv.push(anchor.to_owned());
        }
        argv.push("-s".to_owned());
        argv.push(what.to_owned());
        argv
    }

    fn run(argv: &[String], stdin_text: Option<&str>) -> Result<String, PlatformError> {
        let binary = MacosNetworkConfig::pfctl_binary()?;
        run_tool(binary, argv, stdin_text, Context::Enforcement)
    }
}

impl PfEngine for PfctlEngine {
    fn load_anchor(&self, anchor: &str, body: &str) -> Result<(), PlatformError> {
        Self::run(&Self::load_argv(anchor), Some(body)).map(|_| ())
    }

    fn status(&self) -> Result<PfStatus, PlatformError> {
        Ok(pfread::parse_status(&Self::run(
            &Self::show_argv(None, "info"),
            None,
        )?))
    }

    fn tables(&self, anchor: &str) -> Result<Option<Installed>, PlatformError> {
        Ok(pfread::parse_tables(&Self::run(
            &Self::show_argv(Some(anchor), "Tables"),
            None,
        )?))
    }

    fn labels(&self, anchor: &str) -> Result<BTreeMap<String, LabelCounters>, PlatformError> {
        Ok(pfread::parse_labels(&Self::run(
            &Self::show_argv(Some(anchor), "labels"),
            None,
        )?))
    }
}

/// `route(8)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RouteCommandEngine;

impl RouteEngine for RouteCommandEngine {
    fn run(&self, op: &RouteOp) -> Result<(), PlatformError> {
        let binary = MacosNetworkConfig::route_binary()?;
        run_tool(binary, &op.argv(), None, Context::RouteProgram).map(|_| ())
    }
}

/// Runs a tool with **no inherited environment**.
///
/// ADR-0016 Q10 forbids inheriting a search path, preload variable or plugin
/// directory that could supply executable code to a privileged process — and on
/// Darwin `DYLD_INSERT_LIBRARIES` is exactly that. `env_clear` is the mechanism,
/// and the binary path is absolute so `PATH` is not consulted at all.
fn run_tool(
    binary: &str,
    argv: &[String],
    stdin_text: Option<&str>,
    context: Context,
) -> Result<String, PlatformError> {
    use std::io::Write as _;

    let mut command = Command::new(binary);
    command
        .args(argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    command.stdin(if stdin_text.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command
        .spawn()
        .map_err(|e| oserr::from_errno(&e, "spawn", context))?;
    if let Some(text) = stdin_text {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| oserr::unavailable("tool.stdin", libc::EPIPE))?;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| oserr::from_errno(&e, "write", context))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| oserr::from_errno(&e, "wait", context))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    // The tool's own diagnostic goes to the log at ERROR, never to the user:
    // §4.2 requires a registered reason code as the user-facing error, and the
    // tool's text is platform detail for a support case.
    tracing::error!(
        target: "twinvpn.platform.macos.tool",
        binary,
        exit = output.status.code().unwrap_or(-1),
        detail = %String::from_utf8_lossy(&output.stderr).trim(),
        "a privileged tool refused the request"
    );
    Err(oserr::unavailable(
        "tool.exit",
        output.status.code().unwrap_or(libc::EIO),
    ))
}
