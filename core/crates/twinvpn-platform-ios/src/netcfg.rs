//! [`NetworkConfig`]: the transactional half of the seam, on a platform where
//! the whole transaction is one `setTunnelNetworkSettings` call.
//!
//! **Authority:** `docs/networking.md` §5.1 and §5.2's iOS row; ADR-0008
//! (idempotency); ADR-0010 R5; ADR-0012 KS-17, KS-18, W-24; ADR-0018 CB-6;
//! ADR-0022 LC-4 step 3.
//!
//! # Why `apply` is all-or-nothing here even though it makes two host calls
//!
//! `docs/networking.md` §2.3: "partial application is the leak window." Two calls
//! cross the bridge — the enforcement programme and the settings programme — and
//! the **order** is what makes the pair safe rather than a compensating
//! transaction:
//!
//! 1. **Enforcement first.** `includeAllNetworks` and the on-demand rules are the
//!    *capture* half. Installing them first means that from this instant every
//!    packet the device emits reaches the provider, which is fail-closed
//!    regardless of what happens next.
//! 2. **Settings second.** If this fails, the previous generation's settings are
//!    restored and enforcement is left exactly as step 1 put it. The system is
//!    then in the state KS-17 calls `RULESET_BLOCKED`: capturing everything,
//!    forwarding nothing. Leaving enforcement installed on a failure path is not
//!    an oversight; the opposite would open the window the ordering closes.
//!
//! This is KS-17's arm sequence read forwards: "`RULESET_BLOCKED` live ─► create
//! iface (DOWN) ─► apply(contract_gen) ─► link up ─► … ─► atomic swap ─►
//! `RULESET_PROTECTED`."
//!
//! # W-24 on this platform
//!
//! `installed_ruleset` and `current_generation` are **queries**, not caches. On a
//! host with a packet filter the query goes to the filter; here there is none, so
//! it goes to the only enforcement layer that exists — `NETunnelProviderManager`'s
//! saved configuration, which the OS holds across a provider restart. That is
//! what makes them work as ADR-0022 LC-4 step 3 needs them to: after a jetsam
//! kill the new provider process reads what is installed rather than what it
//! remembers, because it remembers nothing.
//!
//! A read-back this build cannot parse produces a **typed refusal**, never
//! `Ok(None)`. W-24's disposition fixes the direction: `Ok(None)` "would read as
//! 'no ruleset installed' — the opposite of the truth, and the dangerous
//! direction", and O-18 requires the indicator to fail toward `UNKNOWN`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;

use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, LinkFacts, NetworkConfig, NetworkContract,
    PlatformError, RouteCapabilities, Ruleset,
};

use crate::enforce::{self, EnforcementPosture, EnforcementProgramme};
use crate::host::{HostStatus, ProviderHost};
use crate::oserr::{self, Context};
use crate::pathmon::{ObservedPath, PathSnapshot};
use crate::settings::{self, TunnelSettingsProgramme};
use crate::shutdown::ShutdownLatch;

/// How many generations are retained for rollback.
///
/// ADR-0010 R5 requires installation to be "fully reversible, including after an
/// unclean process exit", and `rollback(generation)` names the generation to
/// restore rather than meaning "undo the last thing". A bounded history is still
/// required: an unbounded map is an allocation the core's own generation counter
/// drives, and `ownership.md` §6 rule 10 bounds those.
pub const RETAINED_GENERATIONS: usize = 8;

/// The settings programme currently installed, shared with [`crate::tun`].
///
/// # Why this cell exists
///
/// The MTU lives **inside** `NEPacketTunnelNetworkSettings`, so
/// [`twinvpn_platform::TunnelDevice::set_mtu`] — which DPLPMTUD calls as it
/// probes (`docs/networking.md` §6.2) — has to re-apply the whole settings
/// object. Re-deriving it from the contract would risk a different render under
/// a probe; re-applying the exact bytes last installed, with one field changed,
/// cannot. The seam splits `NetworkConfig` and `TunnelDevice` into two traits, so
/// the two implementations share this cell rather than one guessing what the
/// other installed.
#[derive(Debug, Clone, Default)]
pub struct AppliedSettings(Arc<Mutex<Option<TunnelSettingsProgramme>>>);

impl AppliedSettings {
    /// The programme most recently installed, if any.
    #[must_use]
    pub fn get(&self) -> Option<TunnelSettingsProgramme> {
        guard(&self.0).clone()
    }

    /// Records a programme as installed.
    pub fn set(&self, programme: TunnelSettingsProgramme) {
        *guard(&self.0) = Some(programme);
    }

    /// Records that no programme is installed.
    pub fn clear(&self) {
        *guard(&self.0) = None;
    }
}

/// The iOS network configuration surface.
pub struct IosNetworkConfig {
    host: Arc<dyn ProviderHost>,
    shutdown: ShutdownLatch,
    posture: EnforcementPosture,
    applied_settings: AppliedSettings,
    observed: ObservedPath,
    state: Mutex<NetcfgState>,
}

#[derive(Default)]
struct NetcfgState {
    /// Rendered settings per generation, for rollback.
    settings: BTreeMap<u64, TunnelSettingsProgramme>,
    /// The generation this process most recently applied.
    applied: Option<ContractGeneration>,
    /// The ruleset this process most recently swapped to.
    ruleset: Option<Ruleset>,
}

fn guard<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl IosNetworkConfig {
    /// Builds the surface.
    ///
    /// Everything is injected (CD-2): the host bridge and the enforcement
    /// posture the core computed. Nothing is discovered from the environment.
    ///
    /// **The tunnel remote address is no longer among them (M-15).** It arrived
    /// here as a constructor parameter and was held for the life of the
    /// process, so a contract whose remote had moved rendered against the old
    /// one — the disagreement `NetworkContract::tunnel_remote_address` exists
    /// to prevent, in its most durable form. It comes from the contract now,
    /// per generation.
    #[must_use]
    pub fn new(
        host: Arc<dyn ProviderHost>,
        shutdown: ShutdownLatch,
        posture: EnforcementPosture,
        applied_settings: AppliedSettings,
        observed: ObservedPath,
    ) -> Self {
        Self {
            host,
            shutdown,
            posture,
            applied_settings,
            observed,
            state: Mutex::new(NetcfgState::default()),
        }
    }

    /// The residuals the most recent render could not express.
    ///
    /// Reported so a shell can log them once at apply time rather than a
    /// reviewer discovering that a route metric silently vanished.
    #[must_use]
    pub fn residuals(&self, generation: ContractGeneration) -> Vec<settings::SettingsResidual> {
        guard(&self.state)
            .settings
            .get(&generation.0)
            .map(|p| p.residuals.clone())
            .unwrap_or_default()
    }

    /// The enforcement programme currently installed, read back from the OS.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if the read-back is unavailable or unparseable. See the
    /// module header for why an unparseable read-back is not `Ok(None)`.
    pub fn read_installed(&self) -> Result<Option<EnforcementProgramme>, PlatformError> {
        match self.host.installed_enforcement() {
            Ok(None) => Ok(None),
            Ok(Some(json)) => EnforcementProgramme::parse(&json).map(Some).ok_or_else(|| {
                // Not `Ok(None)`. Something is installed and this build cannot
                // read it — most likely another product holding the profile, or
                // a downgrade. Either way the honest answer is "unknown", and
                // `ThirdPartyFilterSuspected` is the registered condition for
                // "another product appears to be claiming the same resource".
                PlatformError::ThirdPartyFilterSuspected(Some(oserr::detail_from_code(
                    0,
                    "NETunnelProviderManager.protocolConfiguration",
                )))
            }),
            Err(status) => Err(status_error(
                status,
                "NETunnelProviderManager.loadFromPreferences",
                Context::Enforcement,
            )),
        }
    }

    fn install_enforcement(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> Result<(), PlatformError> {
        let programme = self.posture.programme(generation, ruleset);
        match self.host.apply_enforcement(&programme.to_json()) {
            HostStatus::Ok => Ok(()),
            other => Err(status_error(
                other,
                "NETunnelProviderManager.saveToPreferences",
                Context::Enforcement,
            )),
        }
    }

    fn install_settings(&self, programme: &TunnelSettingsProgramme) -> Result<(), PlatformError> {
        match self.host.apply_settings(&programme.to_json()) {
            HostStatus::Ok => Ok(()),
            other => Err(status_error(
                other,
                "setTunnelNetworkSettings",
                Context::RouteProgram,
            )),
        }
    }
}

/// Maps a host status onto the seam's failure vocabulary.
///
/// Three number spaces reach one place, which is the whole point of
/// [`crate::oserr`]: whichever the OS produced, the caller gets a registered
/// name and the number survives as evidence.
pub(crate) fn status_error(
    status: HostStatus,
    call: &'static str,
    context: Context,
) -> PlatformError {
    match status {
        // Not reachable through the error paths above, but mapping it keeps this
        // function total: a caller that passes Ok gets a named internal state
        // rather than an invented failure.
        HostStatus::Ok => PlatformError::AdapterUnavailable(None),
        HostStatus::Errno(code) => {
            oserr::from_errno(&std::io::Error::from_raw_os_error(code), call, context)
        }
        HostStatus::OsStatus(status) => match oserr::from_os_status(status, call, context) {
            oserr::SecOutcome::Failed(err) => err,
            // A success or an absent item reaching an error path is an adapter
            // defect, not an OS condition; it is named rather than swallowed.
            oserr::SecOutcome::Ok | oserr::SecOutcome::Absent => {
                PlatformError::AdapterUnavailable(Some(oserr::detail_from_code(status, call)))
            }
        },
        HostStatus::NeVpnError(code) => oserr::from_ne_vpn_error(code, call),
        // The provider is not running. This is not an OS refusal and must not be
        // reported as one: `AdapterUnavailable` is the registered condition for
        // "the adapter itself could not be opened or has gone away".
        HostStatus::NotAttached => {
            PlatformError::AdapterUnavailable(Some(oserr::detail_from_code(0, call)))
        }
    }
}

impl NetworkConfig for IosNetworkConfig {
    /// **No metric on this platform, and that is not a gap.**
    ///
    /// iOS installs routes by handing `NEPacketTunnelNetworkSettings` an
    /// `NEIPv4Route`/`NEIPv6Route` list; neither type carries a metric and the
    /// OS decides precedence itself. A core that has read `false` expresses
    /// precedence through the prefixes it installs — §7.2's split default
    /// (`0.0.0.0/1` + `128.0.0.0/1`) is exactly that technique — rather than
    /// through a number this platform would discard. `shells/macos` answers the
    /// same way for the same reason.
    fn route_capabilities(&self) -> RouteCapabilities {
        RouteCapabilities { metric: false }
    }

    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;

            // ADR-0008: idempotent on the generation id, so a retry after a
            // crash converges rather than duplicating anything. Checked before
            // any host call, so the retry is also free.
            if guard(&self.state).applied == Some(contract.generation) {
                return Ok(());
            }

            // Render first. A limit violation or an unrepresentable route is
            // refused before a single host call, which is the cheapest possible
            // form of all-or-nothing.
            let programme = settings::render(contract)?;

            // The ruleset this generation is applied under. The core states it
            // in the contract; `set_ruleset` performs the swap afterwards.
            let ruleset = contract.ruleset;

            // 1. Capture half first — see the module header.
            self.install_enforcement(contract.generation, ruleset)?;

            // 2. Settings second.
            if let Err(err) = self.install_settings(&programme) {
                // Restore the previous generation's settings. Enforcement is
                // left installed on purpose: the resulting state captures
                // everything and forwards nothing, which is fail-closed.
                // One acquisition. `std::sync::Mutex` is not reentrant, and
                // nesting two `guard(&self.state)` calls here deadlocks the
                // provider on exactly the failure path that most needs to make
                // progress.
                let previous = {
                    let state = guard(&self.state);
                    state
                        .applied
                        .and_then(|gen| state.settings.get(&gen.0).cloned())
                };
                if let Some(previous) = previous {
                    let _ = self.install_settings(&previous);
                    self.applied_settings.set(previous);
                } else {
                    let _ = self.host.clear_settings();
                    self.applied_settings.clear();
                }
                return Err(err);
            }

            self.applied_settings.set(programme.clone());
            let mut state = guard(&self.state);
            state.settings.insert(contract.generation.0, programme);
            state.applied = Some(contract.generation);
            state.ruleset = Some(ruleset);
            // Bounded history: keep the newest `RETAINED_GENERATIONS`.
            while state.settings.len() > RETAINED_GENERATIONS {
                let oldest = *state.settings.keys().next().expect("non-empty");
                state.settings.remove(&oldest);
            }
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // "Restores the generation before `generation`, exactly." The
            // predecessor is the greatest retained generation strictly below it,
            // which is not necessarily `generation - 1`: the core allocates the
            // ids and need not allocate them densely.
            let previous = guard(&self.state)
                .settings
                .range(..generation.0)
                .next_back()
                .map(|(id, programme)| (*id, programme.clone()));

            match previous {
                Some((id, programme)) => {
                    // Enforcement is re-stamped with the restored generation so
                    // a subsequent read-back reports the generation actually in
                    // force, not the one that was rolled back.
                    let ruleset = guard(&self.state).ruleset.unwrap_or(Ruleset::Blocked);
                    self.install_enforcement(ContractGeneration(id), ruleset)?;
                    self.install_settings(&programme)?;
                    self.applied_settings.set(programme);
                    let mut state = guard(&self.state);
                    state.applied = Some(ContractGeneration(id));
                    state.settings.retain(|k, _| *k <= id);
                    Ok(())
                }
                None => {
                    // Nothing to restore. Clearing the settings leaves the
                    // provider with no addresses and no routes while
                    // `includeAllNetworks` still captures — fail-closed, and NOT
                    // a removal of enforcement (CB-6).
                    match self.host.clear_settings() {
                        HostStatus::Ok => {
                            self.applied_settings.clear();
                            let mut state = guard(&self.state);
                            state.applied = None;
                            state.settings.clear();
                            Ok(())
                        }
                        other => Err(status_error(
                            other,
                            "setTunnelNetworkSettings(nil)",
                            Context::RouteProgram,
                        )),
                    }
                }
            }
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move {
            // Read from the OS, not from `state.applied`. This is ADR-0022
            // LC-4 step 3's entry point, and after a jetsam kill the new process
            // has no `state.applied` to read — which is precisely the case it
            // exists for.
            Ok(self.read_installed()?.map(|p| p.generation))
        })
    }

    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // KS-17: an atomic swap between two values, never a removal. One
            // host call installs the whole programme; there is no intermediate
            // in which the profile carries neither ruleset.
            self.install_enforcement(generation, ruleset)?;
            guard(&self.state).ruleset = Some(ruleset);
            Ok(())
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move { Ok(self.read_installed()?.map(|p| p.ruleset)) })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        enforce::custody()
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            self.shutdown.guard()?;
            // The observation `crate::iface` most recently delivered, so
            // `enumerate` and this call describe the SAME instant. Falling back
            // to the host's current path only when nothing has been delivered
            // yet — at which point there is no enumerate to disagree with.
            if let Some(snapshot) = self.observed.get() {
                return Ok(snapshot.link_facts());
            }
            match self.host.path_snapshot() {
                Ok(Some(json)) => Ok(PathSnapshot::parse(&json)?.link_facts()),
                // The monitor has not fired yet. Reporting a fabricated set of
                // facts — "dual stack, 1500 byte MTU" — would have the core plan
                // a contract for a network nobody has observed.
                Ok(None) => Err(PlatformError::AdapterUnavailable(Some(
                    oserr::detail_from_code(0, "NWPathMonitor.currentPath"),
                ))),
                Err(status) => Err(status_error(
                    status,
                    "NWPathMonitor.currentPath",
                    Context::Interfaces,
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_platform::{DnsConfig, InterfaceIndex, RouteEntry};
    use twinvpn_types::{InterfaceAddress, IpAddr, IpPrefix, PerFamily, V4Addr, V6Addr};

    use crate::host::RecordingHost;

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(V4Addr::from_octets([a, b, c, d])), len).expect("prefix")
    }

    fn v6zero(len: u32) -> IpPrefix {
        IpPrefix::new(IpAddr::V6(V6Addr::prefix_base([0; 16]).expect("v6")), len).expect("prefix")
    }

    /// An interface's OWN address. Distinct from `v4`/`v6zero` above, which name
    /// route destinations: X-10 split the two because a host address's bits are
    /// the whole point and `IpPrefix` requires them to be zero.
    fn addr_v4(a: u8, b: u8, c: u8, d: u8, len: u32) -> InterfaceAddress {
        InterfaceAddress::new(IpAddr::V4(V4Addr::from_octets([a, b, c, d])), len).expect("address")
    }

    fn addr_v6zero(len: u32) -> InterfaceAddress {
        InterfaceAddress::new(IpAddr::V6(V6Addr::prefix_base([0; 16]).expect("v6")), len)
            .expect("address")
    }

    fn contract(generation: u64, ruleset: Ruleset) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(generation),
            addresses: PerFamily::new(vec![addr_v4(100, 64, 0, 7, 32)], vec![addr_v6zero(128)]),
            routes: PerFamily::new(
                vec![RouteEntry {
                    destination: v4(0, 0, 0, 0, 0),
                    via: None,
                    interface: InterfaceIndex(0),
                    metric: None,
                }],
                vec![RouteEntry {
                    destination: v6zero(0),
                    via: None,
                    interface: InterfaceIndex(0),
                    metric: None,
                }],
            ),
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: true,
            },
            ruleset,
            // A protected generation asserts a validated path, and a validated
            // path has a remote. `None` is the `Blocked` shape and is exercised
            // by its own test below.
            tunnel_remote_address: Some(IpAddr::V4(V4Addr::from_octets([198, 51, 100, 7]))),
            mtu: 1280,
        }
    }

    fn build() -> (Arc<RecordingHost>, IosNetworkConfig) {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let config = IosNetworkConfig::new(
            host.clone(),
            ShutdownLatch::new(),
            EnforcementPosture::default(),
            AppliedSettings::default(),
            ObservedPath::default(),
        );
        (host, config)
    }

    fn block_on<T>(future: impl core::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    #[test]
    fn enforcement_is_installed_before_settings_so_a_failure_is_fail_closed() {
        // networking.md §2.3: "partial application is the leak window." If
        // settings could land before capture, the window would be open for the
        // duration of the second call.
        let (host, config) = build();
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        let state = host.state();
        assert_eq!(state.enforcement_applied.len(), 1);
        assert_eq!(state.settings_applied.len(), 1);
        assert!(
            state.enforcement_applied[0].contains("include_all_networks\":true"),
            "capture is in force"
        );
    }

    #[test]
    fn a_settings_failure_leaves_enforcement_installed_and_restores_the_last_settings() {
        // The interesting failure is the SECOND host call: capture is already in
        // force and the settings that would let traffic through did not land.
        // The device must be left capturing everything and forwarding nothing.
        let (host, config) = build();
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        let generation_one_settings = host.state().settings_applied[0].clone();
        host.state().settings_applied.clear();

        host.fail_settings_next(HostStatus::Errno(libc::EINVAL));
        let err = block_on(config.apply(&contract(2, Ruleset::Blocked))).expect_err("refuses");
        assert_eq!(
            err.reason_code().as_str(),
            "ROUTE.PROGRAMMING_DENIED",
            "setTunnelNetworkSettings IS route programming on this platform"
        );

        // Enforcement was NOT removed on the failure path. CB-6: the OS holds
        // the rules precisely so a failure cannot drop protection, and removing
        // them here would open the window the ordering exists to close.
        assert!(host.state().installed_enforcement.is_some());
        // Generation 1's settings were restored EXACTLY, so the tunnel is not
        // left carrying half of generation 2.
        assert_eq!(host.state().settings_applied, vec![generation_one_settings],);
        // The applied generation did not advance, so a retry of 2 is not
        // swallowed by the idempotence check.
        assert_eq!(guard(&config.state).applied, Some(ContractGeneration(1)));
        block_on(config.apply(&contract(2, Ruleset::Blocked))).expect("the retry converges");
    }

    #[test]
    fn a_first_generation_settings_failure_clears_rather_than_restoring_nothing() {
        // With no previous generation there is nothing to restore, and leaving
        // a half-applied settings object in place would be the partial state
        // §2.3 calls the leak window.
        let (host, config) = build();
        host.fail_settings_next(HostStatus::Errno(libc::EINVAL));
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect_err("refuses");
        assert_eq!(host.state().settings_cleared, 1);
        assert!(host.state().installed_enforcement.is_some());
        assert_eq!(guard(&config.state).applied, None);
    }

    #[test]
    fn apply_is_idempotent_on_the_generation_id() {
        // ADR-0008 and networking.md §5.1: "a retry after a crash converges
        // rather than duplicating routes."
        let (host, config) = build();
        block_on(config.apply(&contract(3, Ruleset::Protected))).expect("applies");
        block_on(config.apply(&contract(3, Ruleset::Protected))).expect("applies again");
        block_on(config.apply(&contract(3, Ruleset::Protected))).expect("and again");
        assert_eq!(host.state().settings_applied.len(), 1);
        assert_eq!(host.state().enforcement_applied.len(), 1);
    }

    #[test]
    fn a_limit_violation_is_refused_before_any_host_call_is_made() {
        let (host, config) = build();
        let mut over = contract(1, Ruleset::Blocked);
        over.dns.search_domains = vec!["a.example".to_owned(); settings::MAX_SEARCH_DOMAINS + 1];
        block_on(config.apply(&over)).expect_err("refuses");
        assert!(host.state().settings_applied.is_empty());
        assert!(
            host.state().enforcement_applied.is_empty(),
            "the cheapest all-or-nothing is the one that never calls out"
        );
    }

    #[test]
    fn the_installed_ruleset_is_a_query_and_survives_a_process_restart() {
        // W-24: the assertion must be produced by querying the enforcement
        // layer, "never of the agent's belief". This models a jetsam kill: the
        // host (the OS) keeps the profile, a brand-new config object with empty
        // state reads it back.
        let (host, config) = build();
        block_on(config.apply(&contract(5, Ruleset::Protected))).expect("applies");
        block_on(config.set_ruleset(ContractGeneration(5), Ruleset::Protected)).expect("swaps");
        drop(config);

        let restarted = IosNetworkConfig::new(
            host.clone(),
            ShutdownLatch::new(),
            EnforcementPosture::default(),
            AppliedSettings::default(),
            ObservedPath::default(),
        );
        assert_eq!(
            block_on(restarted.installed_ruleset()).expect("reads"),
            Some(Ruleset::Protected)
        );
        assert_eq!(
            block_on(restarted.current_generation()).expect("reads"),
            Some(ContractGeneration(5)),
            "LC-4 step 3's recovery entry point works with no in-process memory"
        );
    }

    #[test]
    fn an_unreadable_read_back_is_never_reported_as_no_ruleset_installed() {
        // W-24's disposition: `Ok(None)` "would read as 'no ruleset installed' —
        // the opposite of the truth, and the dangerous direction".
        let (host, config) = build();
        host.state().installed_enforcement = Some("{\"someone else's profile\":1}".to_owned());
        let err = block_on(config.installed_ruleset()).expect_err("refuses");
        assert_eq!(
            err.reason_code().as_str(),
            "PLATFORM.THIRD_PARTY_FILTER_SUSPECTED"
        );
    }

    #[test]
    fn nothing_installed_is_a_genuine_none() {
        let (_host, config) = build();
        assert_eq!(block_on(config.installed_ruleset()).expect("reads"), None);
        assert_eq!(block_on(config.current_generation()).expect("reads"), None);
    }

    #[test]
    fn the_ruleset_swap_is_one_call_and_never_leaves_the_profile_without_one() {
        // KS-17: "rules are NEVER absent while the latch is UP."
        let (host, config) = build();
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        host.state().enforcement_applied.clear();
        block_on(config.set_ruleset(ContractGeneration(1), Ruleset::Protected)).expect("swaps");
        let applied = host.state().enforcement_applied.clone();
        assert_eq!(applied.len(), 1, "one call, not a remove-then-add");
        assert!(applied[0].contains("PROTECTED"));
        assert_eq!(
            block_on(config.installed_ruleset()).expect("reads"),
            Some(Ruleset::Protected)
        );
    }

    #[test]
    fn rollback_restores_the_generation_before_the_one_named() {
        let (host, config) = build();
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        block_on(config.apply(&contract(4, Ruleset::Protected))).expect("applies");
        let first = host.state().settings_applied[0].clone();

        host.state().settings_applied.clear();
        block_on(config.rollback(ContractGeneration(4))).expect("rolls back");
        assert_eq!(
            host.state().settings_applied,
            vec![first],
            "restored EXACTLY, byte for byte — not re-derived"
        );
        assert_eq!(
            block_on(config.current_generation()).expect("reads"),
            Some(ContractGeneration(1))
        );
    }

    #[test]
    fn rollback_past_the_first_generation_clears_settings_but_never_enforcement() {
        let (host, config) = build();
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        block_on(config.rollback(ContractGeneration(1))).expect("rolls back");
        assert_eq!(host.state().settings_cleared, 1);
        assert!(
            host.state().installed_enforcement.is_some(),
            "CB-6: enforcement is the OS's and a rollback does not remove it"
        );
    }

    #[test]
    fn the_retained_history_is_bounded() {
        let (_host, config) = build();
        for generation in 1..=(RETAINED_GENERATIONS as u64 + 4) {
            block_on(config.apply(&contract(generation, Ruleset::Protected))).expect("applies");
        }
        assert_eq!(guard(&config.state).settings.len(), RETAINED_GENERATIONS);
    }

    #[test]
    fn the_custody_declaration_is_the_platforms_and_not_an_optimistic_default() {
        let (_host, config) = build();
        let custody = config.enforcement_custody();
        assert!(!custody.survives_core_exit());
        assert!(custody.ruleset_custody.os_rearms(), "iOS is the ◐ case");
        assert!(custody.swap_is_atomic);
    }

    #[test]
    fn link_facts_are_refused_rather_than_fabricated_before_the_monitor_fires() {
        let (host, config) = build();
        let err = block_on(config.query_link_facts()).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");

        host.state().path_snapshot = Some(
            r#"{"interfaces":[{"index":1,"name":"en0","interface_type":"wifi","is_up":true,
                "mtu":1500}],"supports_v4":true,"supports_v6":true,"supports_dns":true,
                "metered":false,"constrained":false}"#
                .to_owned(),
        );
        let facts = block_on(config.query_link_facts()).expect("reads");
        assert_eq!(facts.mtu, 1500);
        assert_eq!(facts.default_routes, PerFamily::new(true, true));
    }

    #[test]
    fn after_shutdown_every_mutating_call_is_a_named_refusal_and_not_a_hang() {
        let host = Arc::new(RecordingHost::new("/tmp/twinvpn-ios"));
        let shutdown = ShutdownLatch::new();
        let config = IosNetworkConfig::new(
            host.clone(),
            shutdown.clone(),
            EnforcementPosture::default(),
            AppliedSettings::default(),
            ObservedPath::default(),
        );
        block_on(config.apply(&contract(1, Ruleset::Blocked))).expect("applies");
        shutdown.begin();
        assert_eq!(
            block_on(config.apply(&contract(2, Ruleset::Blocked))),
            Err(PlatformError::ShuttingDown)
        );
        assert_eq!(
            block_on(config.set_ruleset(ContractGeneration(1), Ruleset::Protected)),
            Err(PlatformError::ShuttingDown)
        );
        // But the read-backs still answer: a shutting-down adapter must still be
        // able to say what is installed, or the last ProtectionAssertion before
        // exit is unproducible.
        assert_eq!(
            block_on(config.installed_ruleset()).expect("reads"),
            Some(Ruleset::Blocked)
        );
    }

    #[test]
    fn a_detached_host_is_reported_as_an_absent_adapter_and_not_as_an_os_refusal() {
        let config = IosNetworkConfig::new(
            Arc::new(crate::host::DetachedHost),
            ShutdownLatch::new(),
            EnforcementPosture::default(),
            AppliedSettings::default(),
            ObservedPath::default(),
        );
        let err = block_on(config.apply(&contract(1, Ruleset::Blocked))).expect_err("refuses");
        assert_eq!(err.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
    }
}
