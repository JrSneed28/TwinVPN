//! An in-memory [`SystemOps`] that models the Windows semantics the layers above
//! it depend on.
//!
//! **Behind the `test-support` feature, and unreachable from a production
//! build.** [`crate::WindowsPlatformAdapter::new`] constructs
//! [`super::win::WindowsSystem`] unconditionally; the only way to bind this is
//! `with_system`, which is itself feature-gated.
//!
//! # What it models, and why each is load-bearing
//!
//! | Behaviour | Why the tests above need it |
//! |---|---|
//! | a commit **replaces** the owner-tagged object graph in one step | KS-17's atomic swap: a test that observed an intermediate state would be testing something WFP does not do |
//! | objects with another provider key are untouched by a commit | K11's coexistence, and the read-back's owner-tag discipline |
//! | a route apply is all-or-nothing under an injected failure | R5's reversibility, exercised rather than asserted |
//! | NRPT rules that are not owner-tagged survive everything | ADR-0011's "restore, not revert" |
//! | filters survive `begin_shutdown` and the adapter being dropped | CB-6: the OS holds the ruleset |
//!
//! # What it deliberately does **not** model
//!
//! It does not evaluate filters against packets. A fake that decided whether a
//! packet would be permitted would be a second implementation of WFP's matching
//! semantics, and a test that passed against it would prove that this crate
//! agrees with a model somebody here wrote — not that it agrees with Windows.
//! The leak tests above therefore assert over the **constructed filter set**
//! (which the ADR specifies) rather than over simulated packets.

use std::pin::Pin;
use std::sync::Mutex;

use futures_core::Stream;
use twinvpn_platform::{InterfaceFacts, LinkFacts, NetworkChange, PlatformError};
use twinvpn_types::{PerFamily, UnderlayFamilies};

use crate::dns::{DnsPlan, InterfaceDns, NrptRule, RULE_PREFIX};
use crate::oserr;
use crate::route::{InstalledRoutes, InterfaceLuid, RoutePlan};
use crate::wfp::canary::NetEvent;
use crate::wfp::readback::{EngineState, InstalledFilter};
use crate::wfp::FilterSet;

use super::{FilterEngine, InterfaceTable, Resolver, RouteTable, SystemOps};

/// A failure a test asks the fake to produce.
///
/// Named per operation rather than as one flag, because "the route apply failed"
/// and "the filter commit failed" put the caller on entirely different recovery
/// paths and a test that could not distinguish them would be checking neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Faults {
    /// `FwpmTransactionCommit0` fails.
    pub filter_commit: Option<PlatformFault>,
    /// The engine enumeration fails.
    pub filter_read: Option<PlatformFault>,
    /// The route apply fails **after** `succeed_first` rows.
    pub route_apply: Option<PlatformFault>,
    /// How many route operations succeed before `route_apply` fires.
    pub route_apply_succeeds_first: usize,
    /// The resolver apply fails.
    pub resolver_apply: Option<PlatformFault>,
}

/// Which condition an injected fault produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformFault {
    /// The OS refused.
    NotPermitted,
    /// Another product holds the object.
    ThirdParty,
    /// A transient condition.
    Transient,
}

impl PlatformFault {
    /// The error the **real** shim would return for this condition.
    ///
    /// Routed through [`crate::oserr`] with the calling context rather than
    /// constructed by hand, so a test asserting a `reason_code` is asserting the
    /// code the production path produces. A fake that invented its own error
    /// vocabulary would let a test pass on a mapping the shim does not have.
    fn as_error(self, call: &'static str, context: oserr::Context) -> PlatformError {
        let status = match self {
            PlatformFault::NotPermitted => oserr::ERROR_ACCESS_DENIED,
            PlatformFault::ThirdParty => oserr::FWP_E_ALREADY_EXISTS,
            PlatformFault::Transient => oserr::ERROR_BUSY,
        };
        oserr::from_status(oserr::Win32Error(status), call, context)
    }
}

/// The mutable host state the fake stands in for.
#[derive(Debug, Default)]
struct HostState {
    engine: EngineState,
    events: Vec<NetEvent>,
    events_lost: bool,
    routes: InstalledRoutes,
    rules: Vec<NrptRule>,
    interface_dns: Option<InterfaceDns>,
    faults: Faults,
    commits: usize,
    route_applies: usize,
}

/// The in-memory system.
#[derive(Debug)]
pub struct FakeSystem {
    state: Mutex<HostState>,
    interfaces: Vec<InterfaceFacts>,
    overlay: InterfaceLuid,
}

impl FakeSystem {
    /// A host with nothing installed.
    #[must_use]
    pub fn new(overlay: InterfaceLuid) -> Self {
        Self {
            state: Mutex::new(HostState::default()),
            interfaces: Vec::new(),
            overlay,
        }
    }

    /// A host whose interface table reports `interfaces`.
    #[must_use]
    pub fn with_interfaces(mut self, interfaces: Vec<InterfaceFacts>) -> Self {
        self.interfaces = interfaces;
        self
    }

    /// A host holding NRPT rules somebody else installed.
    #[must_use]
    pub fn with_foreign_rules(self, rules: Vec<NrptRule>) -> Self {
        self.lock().rules = rules;
        self
    }

    /// A host whose routing table already holds `routes`.
    #[must_use]
    pub fn with_routes(self, routes: InstalledRoutes) -> Self {
        self.lock().routes = routes;
        self
    }

    /// Injects failures.
    pub fn set_faults(&self, faults: Faults) {
        self.lock().faults = faults;
    }

    /// Clears every injected failure.
    pub fn clear_faults(&self) {
        self.lock().faults = Faults::default();
    }

    /// Queues net events for the next [`FilterEngine::net_events`].
    pub fn push_events(&self, events: Vec<NetEvent>, lost: bool) {
        let mut state = self.lock();
        state.events.extend(events);
        state.events_lost = lost;
    }

    /// How many filter transactions have committed.
    ///
    /// A test asserting KS-17's *atomicity* cannot observe an intermediate
    /// state — there is none — so it asserts the count instead: a posture swap
    /// is one commit, never a delete followed by an add.
    #[must_use]
    pub fn commit_count(&self) -> usize {
        self.lock().commits
    }

    /// How many route transactions have been applied.
    #[must_use]
    pub fn route_apply_count(&self) -> usize {
        self.lock().route_applies
    }

    /// The rules the host currently holds, ours and not.
    #[must_use]
    pub fn rules(&self) -> Vec<NrptRule> {
        self.lock().rules.clone()
    }

    /// The interface DNS settings currently in force.
    #[must_use]
    pub fn interface_dns(&self) -> Option<InterfaceDns> {
        self.lock().interface_dns.clone()
    }

    /// The routing state currently in force.
    #[must_use]
    pub fn routes_now(&self) -> InstalledRoutes {
        self.lock().routes.clone()
    }

    /// Installs filters as if another product had, so a test can check that we
    /// leave them alone.
    pub fn add_foreign_filter(&self, filter: InstalledFilter) {
        let mut state = self.lock();
        state.engine.filters.push(InstalledFilter {
            provider_owned: false,
            ..filter
        });
        state.engine.sublayer_present = true;
    }

    /// Removes one of our filters behind the adapter's back, as a tamper or a
    /// third-party cleanup tool would.
    pub fn remove_filter(&self, predicate: impl Fn(&InstalledFilter) -> bool) {
        let mut state = self.lock();
        state.engine.filters.retain(|f| !predicate(f));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HostState> {
        // A poisoned lock means a test panicked while holding it; recovering the
        // guard keeps the panic that caused it as the reported failure rather
        // than replacing it with an unrelated one.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl FilterEngine for FakeSystem {
    fn commit(&self, set: &FilterSet) -> Result<(), PlatformError> {
        let mut state = self.lock();
        if let Some(fault) = state.faults.filter_commit {
            return Err(fault.as_error("FwpmTransactionCommit0", oserr::Context::Enforcement));
        }
        // One step: every owner-tagged object is replaced — **except** the KS-19
        // boot artifact, which survives a runtime commit. There is no
        // intermediate state in which the host holds neither set, which is what
        // KS-17 asks of the real engine, and the boot filters are still there
        // afterwards, which is what PS-7 asks of us.
        state
            .engine
            .filters
            .retain(|f| !f.provider_owned || crate::wfp::boot::is_boot_filter(f.key));
        // A key the incoming set also carries is replaced rather than
        // duplicated: `FwpmFilterAdd0` on an existing key is a replace.
        state
            .engine
            .filters
            .retain(|f| !set.filters.iter().any(|s| s.key == f.key));
        state
            .engine
            .filters
            .extend(set.filters.iter().map(|f| InstalledFilter {
                key: f.key,
                layer: f.layer,
                action: f.action,
                provider_owned: true,
            }));
        state.engine.sublayer_present = true;
        state.engine.provider_data = Some(set.generation.to_be_bytes().to_vec());
        state.commits += 1;
        Ok(())
    }

    fn read(&self) -> Result<EngineState, PlatformError> {
        let state = self.lock();
        if let Some(fault) = state.faults.filter_read {
            return Err(fault.as_error("FwpmFilterEnum0", oserr::Context::Enforcement));
        }
        Ok(state.engine.clone())
    }

    fn net_events(&self) -> Result<(Vec<NetEvent>, bool), PlatformError> {
        let mut state = self.lock();
        let lost = state.events_lost;
        state.events_lost = false;
        Ok((std::mem::take(&mut state.events), lost))
    }

    fn purge(&self) -> Result<(), PlatformError> {
        let mut state = self.lock();
        state.engine.filters.retain(|f| !f.provider_owned);
        state.engine.provider_data = None;
        state.engine.sublayer_present = false;
        Ok(())
    }
}

impl RouteTable for FakeSystem {
    fn read(&self, overlay: InterfaceLuid) -> Result<InstalledRoutes, PlatformError> {
        let state = self.lock();
        let mut routes = state.routes.clone();
        routes.rows.retain(|r| r.luid == overlay);
        routes.addresses.retain(|a| a.luid == overlay);
        Ok(routes)
    }

    fn apply(&self, plan: &RoutePlan) -> Result<(), PlatformError> {
        let mut state = self.lock();
        state.route_applies += 1;
        let fault = state.faults.route_apply;
        let succeed_first = state.faults.route_apply_succeeds_first;
        // The all-or-nothing property, modelled the way IP Helper actually
        // behaves: the calls happen one at a time, and an implementation that
        // fails partway has to undo what it did. The fake performs the whole
        // plan on a copy and discards it on failure, which is the behaviour the
        // real shim must reproduce by compensation.
        let mut rows = state.routes.rows.clone();
        let mut addresses = state.routes.addresses.clone();
        let mut performed = 0usize;
        let step = |performed: &mut usize| -> Result<(), PlatformError> {
            *performed += 1;
            match fault {
                Some(f) if *performed > succeed_first => {
                    Err(f.as_error("CreateIpForwardEntry2", oserr::Context::RouteProgram))
                }
                _ => Ok(()),
            }
        };
        for row in &plan.deletes {
            step(&mut performed)?;
            rows.retain(|r| r != row);
        }
        for row in &plan.addresses.deletes {
            step(&mut performed)?;
            addresses.retain(|a| a != row);
        }
        for row in &plan.addresses.adds {
            step(&mut performed)?;
            if !addresses.contains(row) {
                addresses.push(*row);
            }
        }
        for row in &plan.adds {
            step(&mut performed)?;
            if !rows.contains(row) {
                rows.push(*row);
            }
        }
        rows.sort_unstable();
        addresses.sort_unstable();
        state.routes.rows = rows;
        state.routes.addresses = addresses;
        let metric = plan.addresses.interface_metric;
        for family in [
            twinvpn_types::AddressFamily::V4,
            twinvpn_types::AddressFamily::V6,
        ] {
            if let Some(value) = *metric.get(family) {
                *state.routes.interface_metric.get_mut(family) = Some(value);
            }
        }
        Ok(())
    }

    fn link_facts(&self, _overlay: InterfaceLuid) -> Result<LinkFacts, PlatformError> {
        Ok(LinkFacts {
            mtu: 1500,
            families: UnderlayFamilies::DualStack,
            default_routes: PerFamily::new(true, true),
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            metered: false,
            low_power: false,
        })
    }
}

impl Resolver for FakeSystem {
    fn read(&self, overlay: InterfaceLuid) -> Result<(Vec<NrptRule>, InterfaceDns), PlatformError> {
        let state = self.lock();
        let interface = state.interface_dns.clone().unwrap_or(InterfaceDns {
            luid: overlay,
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_list: Vec::new(),
            register_adapter_name: false,
        });
        Ok((state.rules.clone(), interface))
    }

    fn apply(&self, plan: &DnsPlan) -> Result<(), PlatformError> {
        let mut state = self.lock();
        if let Some(fault) = state.faults.resolver_apply {
            return Err(fault.as_error("RegSetValueExW", oserr::Context::Resolver));
        }
        for id in &plan.rule_deletes {
            // The fake refuses what the real shim refuses: a plan that names a
            // rule we do not own never reaches the registry.
            assert!(
                id.starts_with(RULE_PREFIX),
                "a plan tried to delete a foreign rule: {id}"
            );
            state.rules.retain(|r| &r.id != id);
        }
        for rule in &plan.rule_writes {
            assert!(
                rule.id.starts_with(RULE_PREFIX),
                "a plan tried to write a foreign rule: {}",
                rule.id
            );
            state.rules.retain(|r| r.id != rule.id);
            state.rules.push(rule.clone());
        }
        state.rules.sort();
        if let Some(interface) = plan.interface.clone() {
            state.interface_dns = Some(interface);
        }
        Ok(())
    }
}

impl InterfaceTable for FakeSystem {
    fn enumerate(&self) -> Result<Vec<InterfaceFacts>, PlatformError> {
        Ok(self.interfaces.clone())
    }

    fn subscribe(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = NetworkChange> + Send>>, PlatformError> {
        // An empty stream rather than a channel: a test that wants to drive
        // changes constructs the stream it wants and passes it to the component
        // under test, which is CD-2's direction. A fake that owned a global
        // sender would be an ambient default.
        Ok(Box::pin(Quiescent))
    }
}

/// A stream that never yields and never ends.
///
/// `Pending` rather than `Ready(None)`: a change subscription that *ended* would
/// tell a caller the platform had stopped reporting changes, and a caller that
/// believed it would stop reacting to the network. A quiet network and a dead
/// subscription must not look the same.
struct Quiescent;

impl Stream for Quiescent {
    type Item = NetworkChange;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}

impl SystemOps for FakeSystem {
    fn filters(&self) -> &dyn FilterEngine {
        self
    }
    fn routes(&self) -> &dyn RouteTable {
        self
    }
    fn resolver(&self) -> &dyn Resolver {
        self
    }
    fn interfaces(&self) -> &dyn InterfaceTable {
        self
    }
}

impl FakeSystem {
    /// The overlay this fake was built for.
    #[must_use]
    pub const fn overlay(&self) -> InterfaceLuid {
        self.overlay
    }
}
