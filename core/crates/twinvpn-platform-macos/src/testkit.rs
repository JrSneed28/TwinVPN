//! Contract fixtures, shared by this crate's unit tests and its integration
//! tests.
//!
//! `#[doc(hidden)]` and unconditional rather than `#[cfg(test)]`: an integration
//! test in `tests/` links the library as an ordinary dependency and cannot see a
//! `cfg(test)` module, and a second copy of these builders in `tests/common/`
//! would be a second definition of "what a TwinVPN contract looks like" — the
//! shape MI-20 forbids for the command catalogue and that is no better here.
//!
//! Nothing in this module is used by the adapter itself.
//!
//! # The recording carriers are the point
//!
//! [`RecordingPf`] does not merely remember what it was handed: it **parses the
//! anchor body it was given** with the same [`crate::pfread`] the real
//! [`crate::netcfg::PfctlEngine`] uses on `pfctl -s Tables` output. So a test
//! that applies a contract and then asks `installed_ruleset()` exercises the
//! renderer *and* the read-back parser end to end, and W-24's "the assertion is a
//! query" is a checked property on a host with no `pfctl` at all.

use twinvpn_platform::{
    ContractGeneration, DnsConfig, InterfaceIndex, NetworkContract, RouteEntry, Ruleset,
};
use twinvpn_types::{InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

/// A canonical IPv4 prefix. Panics on a non-canonical one, which is a test bug.
#[must_use]
pub fn v4(octets: [u8; 4], len: u32) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(V4Addr::from_octets(octets)), len).expect("canonical v4 prefix")
}

/// A canonical IPv6 prefix from its first two octets.
#[must_use]
pub fn v6(first: u8, second: u8, len: u32) -> IpPrefix {
    let mut octets = [0u8; 16];
    octets[0] = first;
    octets[1] = second;
    IpPrefix::new(
        IpAddr::V6(V6Addr::new(octets, None).expect("valid v6 address")),
        len,
    )
    .expect("canonical v6 prefix")
}

/// An interface address with its host bits, for the overlay's own addresses.
#[must_use]
pub fn iface_v4(octets: [u8; 4], len: u32) -> InterfaceAddress {
    InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets(octets)), len)
        .expect("valid v4 interface address")
}

/// The same for IPv6, from its first two octets.
#[must_use]
pub fn iface_v6(first: u8, second: u8, len: u32) -> InterfaceAddress {
    let mut octets = [0u8; 16];
    octets[0] = first;
    octets[1] = second;
    InterfaceAddress::new(
        IpAddr::V6(V6Addr::new(octets, None).expect("valid v6 address")),
        len,
    )
    .expect("valid v6 interface address")
}

/// A one-route-per-family contract at `generation`, in `Ruleset::Protected`.
#[must_use]
pub fn contract(generation: u64) -> NetworkContract {
    contract_with(generation, Ruleset::Protected)
}

/// The same, with the posture chosen.
#[must_use]
pub fn contract_with(generation: u64, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation: ContractGeneration(generation),
        addresses: PerFamily::new(
            vec![iface_v4([100, 64, 0, 2], 32)],
            vec![iface_v6(0xfd, 0x7c, 128)],
        ),
        routes: PerFamily::new(
            vec![RouteEntry {
                destination: v4([100, 64, 0, 0], 10),
                via: None,
                interface: InterfaceIndex(9),
                metric: None,
            }],
            vec![RouteEntry {
                destination: v6(0xfd, 0x7c, 48),
                via: None,
                interface: InterfaceIndex(9),
                metric: None,
            }],
        ),
        dns: DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: 1280,
        // A fixture contract rides a fixed remote, so
        // `nesettings::render` has the `tunnelRemoteAddress` NE requires.
        tunnel_remote_address: Some(IpAddr::V4(V4Addr::from_octets([198, 51, 100, 7]))),
    }
}

/// A full-tunnel contract: the four `/1` routes of `docs/networking.md` §7.2.
#[must_use]
pub fn full_tunnel_contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
    let mut c = contract_with(generation, ruleset);
    let mut v4_routes = Vec::new();
    let mut v6_routes = Vec::new();
    for destination in crate::route::full_tunnel_destinations() {
        let entry = RouteEntry {
            destination,
            via: None,
            interface: InterfaceIndex(9),
            metric: None,
        };
        match destination.family() {
            twinvpn_types::AddressFamily::V4 => v4_routes.push(entry),
            twinvpn_types::AddressFamily::V6 => v6_routes.push(entry),
        }
    }
    c.routes = PerFamily::new(v4_routes, v6_routes);
    c
}

/// An enforcement configuration with both KS-9 halves present.
#[must_use]
pub fn enforcement() -> crate::pf::EnforcementConfig {
    crate::pf::EnforcementConfig {
        overlay_interface: "utun7".to_owned(),
        exempt: crate::pf::ExemptPredicate::ProviderUidAndSocketSet { uid: 501 },
        local_network_access: true,
        // A ULA rather than `fe80::/10`: `twinvpn-types` cannot represent a
        // link-local PREFIX at all — `V6Addr::new` requires a zone on `fe80::/10`
        // and `IpPrefix::new` rejects one. The class-9 link-local allowance is
        // emitted as a literal in `pf::render` for exactly that reason.
        on_link_prefixes: vec![v4([192, 168, 1, 0], 24), v6(0xfd, 0x00, 8)],
        doh_endpoints: vec![v4([1, 1, 1, 1], 32)],
    }
}

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use twinvpn_platform::PlatformError;

use crate::netcfg::{NetworkCarriers, PfEngine, ResolverEngine, RouteEngine};
use crate::pfread::{Installed, LabelCounters, PfStatus};
use crate::resolver::{ResolverCarrier, ResolverPlan, RestorePoint};
use crate::route::{RouteCarrier, RouteOp};

/// The table names a rendered anchor declares, in the shape
/// `pfctl -a twinvpn -s Tables` prints them.
///
/// This is what makes [`RecordingPf`] a real read-back rather than an echo: the
/// body goes in, the *names* come out, and [`crate::pfread::parse_tables`] reads
/// them exactly as it reads `pfctl`'s.
#[must_use]
pub fn table_names_in(anchor_body: &str) -> String {
    let mut out = String::new();
    for line in anchor_body.lines() {
        let Some(rest) = line.trim_start().strip_prefix("table <") else {
            continue;
        };
        if let Some((name, _)) = rest.split_once('>') {
            out.push_str(name);
            out.push('\n');
        }
    }
    out
}

/// A `pf` engine that holds what it was loaded, and answers a read-back from it.
#[derive(Debug)]
pub struct RecordingPf {
    /// Every anchor body loaded, in order.
    pub loads: Mutex<Vec<String>>,
    /// What `pfctl -s info` answers.
    pub status: Mutex<PfStatus>,
    /// Per-label counters, for the leak canary.
    pub labels: Mutex<BTreeMap<String, LabelCounters>>,
    /// How many more loads to refuse. ADR-0012 §8: arming must never fail open,
    /// so a test needs to be able to make it fail.
    pub fail_loads: AtomicUsize,
}

impl Default for RecordingPf {
    fn default() -> Self {
        Self {
            loads: Mutex::new(Vec::new()),
            status: Mutex::new(PfStatus::Enabled),
            labels: Mutex::new(BTreeMap::new()),
            fail_loads: AtomicUsize::new(0),
        }
    }
}

impl RecordingPf {
    /// The most recent anchor body, if any.
    #[must_use]
    pub fn last_load(&self) -> Option<String> {
        self.loads.lock().ok().and_then(|l| l.last().cloned())
    }

    /// How many loads have been performed.
    #[must_use]
    pub fn load_count(&self) -> usize {
        self.loads.lock().map_or(0, |l| l.len())
    }

    /// Makes the next `n` loads fail.
    pub fn fail_next_loads(&self, n: usize) {
        self.fail_loads.store(n, Ordering::Release);
    }

    /// Sets what `pfctl -s info` answers.
    pub fn set_status(&self, status: PfStatus) {
        if let Ok(mut slot) = self.status.lock() {
            *slot = status;
        }
    }

    /// Records a packet against a label, as a real drop would.
    pub fn bump(&self, label: &str, packets: u64) {
        if let Ok(mut labels) = self.labels.lock() {
            let entry = labels.entry(label.to_owned()).or_default();
            entry.packets += packets;
            entry.evaluations += packets;
            entry.bytes += packets * 64;
        }
    }

    /// **Simulates a reboot or a crash**: the process's memory goes, and the
    /// anchor stays. That asymmetry is CB-6, and a test that cleared both would
    /// not be testing it.
    #[must_use]
    pub fn survive_process_exit(&self) -> Self {
        Self {
            loads: Mutex::new(self.loads.lock().map(|l| l.clone()).unwrap_or_default()),
            status: Mutex::new(*self.status.lock().expect("status")),
            labels: Mutex::new(self.labels.lock().map(|l| l.clone()).unwrap_or_default()),
            fail_loads: AtomicUsize::new(0),
        }
    }
}

impl PfEngine for RecordingPf {
    fn load_anchor(&self, _anchor: &str, body: &str) -> Result<(), PlatformError> {
        if self
            .fail_loads
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(crate::oserr::unavailable("pfctl -f", libc::EPERM));
        }
        self.loads
            .lock()
            .map_err(|_| crate::oserr::unavailable("pf.lock", libc::EDEADLK))?
            .push(body.to_owned());
        Ok(())
    }

    fn status(&self) -> Result<PfStatus, PlatformError> {
        Ok(*self
            .status
            .lock()
            .map_err(|_| crate::oserr::unavailable("pf.lock", libc::EDEADLK))?)
    }

    fn tables(&self, _anchor: &str) -> Result<Option<Installed>, PlatformError> {
        let Some(body) = self.last_load() else {
            return Ok(None);
        };
        Ok(crate::pfread::parse_tables(&table_names_in(&body)))
    }

    fn labels(&self, _anchor: &str) -> Result<BTreeMap<String, LabelCounters>, PlatformError> {
        Ok(self
            .labels
            .lock()
            .map_err(|_| crate::oserr::unavailable("pf.lock", libc::EDEADLK))?
            .clone())
    }
}

/// A route engine that records every operation and can refuse the Nth.
#[derive(Debug, Default)]
pub struct RecordingRoute {
    /// Every operation attempted, including the ones that failed.
    pub attempted: Mutex<Vec<RouteOp>>,
    /// Every operation that succeeded — the host's actual state.
    pub applied: Mutex<Vec<RouteOp>>,
    /// Which attempt (1-based) refuses. `0` means none.
    pub fail_at: AtomicUsize,
}

impl RecordingRoute {
    /// Makes the `n`th operation refuse.
    pub fn fail_at(&self, n: usize) {
        self.fail_at.store(n, Ordering::Release);
    }

    /// The destinations currently installed, after adds and deletes cancel.
    #[must_use]
    pub fn live_destinations(&self) -> Vec<twinvpn_types::IpPrefix> {
        let mut live: Vec<twinvpn_types::IpPrefix> = Vec::new();
        for op in self.applied.lock().map(|a| a.clone()).unwrap_or_default() {
            match op.action {
                crate::route::RouteAction::Add => live.push(op.destination),
                crate::route::RouteAction::Delete => {
                    if let Some(at) = live.iter().position(|d| *d == op.destination) {
                        live.remove(at);
                    }
                }
            }
        }
        live
    }
}

impl RouteEngine for RecordingRoute {
    fn run(&self, op: &RouteOp) -> Result<(), PlatformError> {
        let mut attempted = self
            .attempted
            .lock()
            .map_err(|_| crate::oserr::unavailable("route.lock", libc::EDEADLK))?;
        attempted.push(op.clone());
        let n = attempted.len();
        drop(attempted);
        if self.fail_at.load(Ordering::Acquire) == n {
            return Err(crate::oserr::unavailable("route", libc::EPERM));
        }
        self.applied
            .lock()
            .map_err(|_| crate::oserr::unavailable("route.lock", libc::EDEADLK))?
            .push(op.clone());
        Ok(())
    }
}

/// A resolver engine that records the plans it applied.
#[derive(Debug, Default)]
pub struct RecordingResolver {
    /// Every plan applied, in order.
    pub plans: Mutex<Vec<ResolverPlan>>,
    /// Every restore point persisted.
    pub persisted: Mutex<Vec<RestorePoint>>,
    /// What the host looked like before we touched it.
    pub prior: Mutex<Option<RestorePoint>>,
    /// Whether `apply` refuses.
    pub fail_apply: AtomicUsize,
}

impl RecordingResolver {
    /// Sets what a capture will find.
    pub fn set_prior(&self, point: RestorePoint) {
        if let Ok(mut slot) = self.prior.lock() {
            *slot = Some(point);
        }
    }

    /// Makes the next `n` applies refuse.
    pub fn fail_next_applies(&self, n: usize) {
        self.fail_apply.store(n, Ordering::Release);
    }

    /// The most recent plan applied.
    #[must_use]
    pub fn last_plan(&self) -> Option<ResolverPlan> {
        self.plans.lock().ok().and_then(|p| p.last().cloned())
    }
}

impl ResolverEngine for RecordingResolver {
    fn capture(&self, service_id: &str) -> Result<RestorePoint, PlatformError> {
        Ok(self
            .prior
            .lock()
            .ok()
            .and_then(|p| p.clone())
            .unwrap_or_else(|| RestorePoint::absent(service_id)))
    }

    fn persist(&self, point: &RestorePoint) -> Result<(), PlatformError> {
        self.persisted
            .lock()
            .map_err(|_| crate::oserr::unavailable("resolver.lock", libc::EDEADLK))?
            .push(point.clone());
        Ok(())
    }

    fn apply(&self, plan: &ResolverPlan) -> Result<(), PlatformError> {
        if self
            .fail_apply
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(crate::oserr::unavailable(
                "SCDynamicStoreSetValue",
                libc::EPERM,
            ));
        }
        self.plans
            .lock()
            .map_err(|_| crate::oserr::unavailable("resolver.lock", libc::EDEADLK))?
            .push(plan.clone());
        Ok(())
    }
}

/// The three recording carriers, kept so a test can inspect them after the
/// adapter has been handed `Arc`s of them.
pub struct Recorders {
    /// The `pf` engine.
    pub pf: Arc<RecordingPf>,
    /// The route engine.
    pub route: Arc<RecordingRoute>,
    /// The resolver engine.
    pub resolver: Arc<RecordingResolver>,
}

/// Recording carriers on the **`LaunchDaemon`** binding: `route(8)` and
/// `SCDynamicStore` both do real work.
#[must_use]
pub fn daemon_carriers() -> (NetworkCarriers, Recorders) {
    carriers(RouteCarrier::Command, ResolverCarrier::DynamicStore)
}

/// Recording carriers on the **system-extension** binding: the OS installs the
/// routes and the resolver from the settings object, so neither carrier does
/// anything and the anchor is the only thing this adapter programmes.
#[must_use]
pub fn extension_carriers() -> (NetworkCarriers, Recorders) {
    carriers(
        RouteCarrier::TunnelSettings,
        ResolverCarrier::TunnelSettings,
    )
}

fn carriers(
    route_carrier: RouteCarrier,
    resolver_carrier: ResolverCarrier,
) -> (NetworkCarriers, Recorders) {
    let pf = Arc::new(RecordingPf::default());
    let route = Arc::new(RecordingRoute::default());
    let resolver = Arc::new(RecordingResolver::default());
    (
        NetworkCarriers {
            pf: pf.clone(),
            route: route.clone(),
            resolver: resolver.clone(),
            route_carrier,
            resolver_carrier,
            service_id: "TEST-SERVICE".to_owned(),
        },
        Recorders {
            pf,
            route,
            resolver,
        },
    )
}
