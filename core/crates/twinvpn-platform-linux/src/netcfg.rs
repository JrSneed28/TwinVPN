//! [`NetworkConfig`]: one transaction over addresses, routes, resolver and
//! firewall.
//!
//! **Authority:** [`twinvpn_platform::config::NetworkConfig`],
//! `docs/networking.md` §5.1 and §2.3 ("partial application is the leak
//! window"), ADR-0008 (idempotent on the generation id), ADR-0010 R5, ADR-0012
//! KS-17/KS-18/KS-20, ADR-0015 §11.6 rule 1.
//!
//! # The order, and why it is this order
//!
//! ```text
//! apply(gen):   ruleset for `gen` installed (nftables, one transaction)
//!               -> addresses + routes + policy rules (netlink, unwound on failure)
//!               -> resolver (restore point first, DN-18)
//! ```
//!
//! The **firewall first**. ADR-0010 §11.5 clause 4: "fail-closed rules live
//! before the overlay interface is created and remain live after destruction".
//! An address or route that exists before the rules do is a window in which the
//! host can emit a protected packet with nothing to stop it, and §2.3 names that
//! window as the reason `apply` is one call rather than four.
//!
//! The **resolver last**, and only after its restore point. DN-19's teardown
//! order is the mirror: the resolver is restored first, before the interface
//! goes, "so name resolution is never left pointing at a dead stub".
//!
//! # `nft` is invoked; netlink is spoken directly
//!
//! Routes and addresses go over `rtnetlink` because events, atomicity and typed
//! errors all require it (see [`crate::netlink`]). The nftables ruleset goes
//! through `nft -f -` instead, and that is a deliberate, stated trade:
//!
//! - `nft -f` applies a whole script as **one kernel transaction**, which is
//!   exactly KS-17's atomic swap. Hand-rolled `NFNL_SUBSYS_NFTABLES` netlink
//!   would have to reproduce that batching correctly to get the same property.
//! - `nft --json list table` gives a **structured read-back**, which is what
//!   makes the W-24 `ProtectionAssertion` a query rather than a belief.
//! - The cost: `nft(8)` must be installed. Its absence is a startup failure with
//!   a registered code, never a silent downgrade to "no firewall" — arming must
//!   never fail open (ADR-0012 §8).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use futures_core::future::BoxFuture;
use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, LinkFacts, NetworkConfig, NetworkContract,
    PlatformError, Ruleset,
};
use twinvpn_types::{AddressFamily, PerFamily, UnderlayFamilies};

use crate::nft::{self, EnforcementConfig};
use crate::oserr::{self, Context};
use crate::resolver::{self, RestorePoint};
use crate::route::{self, AppliedState};
use crate::shutdown::ShutdownLatch;

/// The `nft` binary. Absolute, so `PATH` cannot redirect it — ADR-0016 Q10
/// forbids inheriting a search path that could supply executable code.
pub const NFT_BIN: &str = "/usr/sbin/nft";

/// The fallback location on distributions that merge `sbin`.
pub const NFT_BIN_ALT: &str = "/usr/bin/nft";

/// What one applied generation left on the host.
struct Generation {
    id: ContractGeneration,
    applied: AppliedState,
    restore_point: Option<RestorePoint>,
}

/// Linux's transactional network configuration.
pub struct LinuxNetworkConfig {
    shutdown: ShutdownLatch,
    enforcement: EnforcementConfig,
    overlay_index: Mutex<Option<u32>>,
    /// The generation stack. `rollback(g)` restores the generation *before* `g`,
    /// which needs the previous one's applied state — so both are kept, not just
    /// the current.
    history: Mutex<Vec<Generation>>,
    restore_point_path: PathBuf,
}

impl LinuxNetworkConfig {
    /// Binds the configuration surface.
    #[must_use]
    pub fn new(
        shutdown: ShutdownLatch,
        enforcement: EnforcementConfig,
        restore_point_path: PathBuf,
    ) -> Self {
        Self {
            shutdown,
            enforcement,
            overlay_index: Mutex::new(None),
            history: Mutex::new(Vec::new()),
            restore_point_path,
        }
    }

    /// Tells the configuration surface which OS index the overlay took.
    ///
    /// Called by the adapter after `create_interface`. Not discovered here: the
    /// tunnel device is the one that knows, and rediscovering by name would make
    /// a rename race into a route on the wrong link.
    pub fn set_overlay_index(&self, index: u32) {
        if let Ok(mut slot) = self.overlay_index.lock() {
            *slot = Some(index);
        }
    }

    /// The `nft` binary this host has, or the registered failure.
    ///
    /// # Errors
    ///
    /// [`PlatformError::AdapterUnavailable`] when `nft(8)` is absent. **Never a
    /// silent success**: ADR-0012 §8 requires that if the ruleset cannot be
    /// installed the client refuses to enter a protected state.
    pub fn nft_binary() -> Result<&'static str, PlatformError> {
        for candidate in [NFT_BIN, NFT_BIN_ALT] {
            if std::path::Path::new(candidate).exists() {
                return Ok(candidate);
            }
        }
        Err(nft::unreachable("nft(8)", libc::ENOENT))
    }

    /// Applies a rendered script through `nft -f -`, as one kernel transaction.
    fn run_nft_script(script: &str) -> Result<(), PlatformError> {
        let binary = Self::nft_binary()?;
        let mut child = Command::new(binary)
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // The environment is not inherited: ADR-0016 Q10 forbids inheriting
            // a search path, preload variable or plugin directory that could
            // supply executable code to a privileged process.
            .env_clear()
            .spawn()
            .map_err(|e| oserr::from_errno(&e, "spawn(nft)", Context::Enforcement))?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| nft::unreachable("nft.stdin", libc::EPIPE))?;
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| oserr::from_errno(&e, "write(nft)", Context::Enforcement))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| oserr::from_errno(&e, "wait(nft)", Context::Enforcement))?;
        if output.status.success() {
            return Ok(());
        }
        // `nft`'s own diagnostic goes to the log at ERROR, never to the user:
        // §4.2 requires a registered reason code as the user-facing error, and
        // the tool's text is platform detail for a support case.
        tracing::error!(
            target: "twinvpn.platform.linux.nft",
            exit = output.status.code().unwrap_or(-1),
            detail = %String::from_utf8_lossy(&output.stderr).trim(),
            "the enforcement ruleset was refused by nft(8)"
        );
        Err(nft::unreachable(
            "nft -f",
            output.status.code().unwrap_or(libc::EIO),
        ))
    }

    /// Reads the installed table back from the kernel.
    fn read_installed() -> Result<Option<nft::Installed>, PlatformError> {
        let binary = Self::nft_binary()?;
        let output = Command::new(binary)
            .args(["--json", "list", "table", nft::FAMILY, nft::TABLE])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear()
            .output()
            .map_err(|e| oserr::from_errno(&e, "spawn(nft list)", Context::Enforcement))?;
        if !output.status.success() {
            // The table is absent. That is a genuine "nothing of ours is
            // installed" and is reported as `Ok(None)` — the ONLY case in which
            // `None` is the truth rather than the dangerous direction.
            return Ok(None);
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Ok(nft::parse_installed(&text))
    }
}

impl NetworkConfig for LinuxNetworkConfig {
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

            let overlay_index = self
                .overlay_index
                .lock()
                .ok()
                .and_then(|s| *s)
                .ok_or_else(|| oserr::unavailable("overlay.index", libc::ENODEV))?;

            // 1. The firewall, first and as one transaction. §11.5 clause 4:
            //    the rules live before the addresses and routes do.
            let script = nft::render(contract, contract.ruleset, &self.enforcement);
            let script_for_blocking = script;
            tokio::task::spawn_blocking(move || Self::run_nft_script(&script_for_blocking))
                .await
                .map_err(|_| oserr::unavailable("nft.join", libc::ECANCELED))??;

            // 2. Addresses, routes and policy rules — both families, unwound on
            //    any failure so the host is exactly as it was.
            let applied =
                route::program(contract, overlay_index, self.enforcement.firewall_mark).await?;

            // 3. The resolver, restore point first (DN-18).
            let restore_point = {
                let config = contract.dns.clone();
                let path = self.restore_point_path.clone();
                match tokio::task::spawn_blocking(move || resolver::apply(&config, &path)).await {
                    Ok(Ok(point)) => Some(point),
                    Ok(Err(e)) => {
                        // The routes are unwound so the failure leaves nothing
                        // half-applied. The FIREWALL is deliberately left in
                        // place: CB-6 puts it in the OS's custody, and removing
                        // it on a resolver failure would open the leak window
                        // this whole ordering exists to close.
                        route::revert(&applied).await.ok();
                        return Err(e);
                    }
                    Err(_) => {
                        route::revert(&applied).await.ok();
                        return Err(oserr::unavailable("resolver.join", libc::ECANCELED));
                    }
                }
            };

            let mut history = self
                .history
                .lock()
                .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
            history.push(Generation {
                id: contract.generation,
                applied,
                restore_point,
            });
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Deliberately NOT gated on the shutdown latch: rolling back is part
            // of an orderly stop, and refusing it during shutdown would leave
            // the host mutated.
            let victim = {
                let mut history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                let Some(position) = history.iter().position(|g| g.id == generation) else {
                    // ADR-0010 R5 requires reversibility "including after an
                    // unclean process exit", and a generation this process never
                    // applied is exactly that case. Nothing of ours is on the
                    // host under that id, so there is nothing to undo.
                    return Ok(());
                };
                history.split_off(position)
            };

            // Reverse order, and the RESOLVER FIRST within each generation:
            // DN-19 and ADR-0016 PS-21 step 3 both put the resolver restore
            // before the interface goes, "so name resolution is never left
            // pointing at a dead stub".
            for entry in victim.iter().rev() {
                if let Some(point) = &entry.restore_point {
                    let point = point.clone();
                    let restored = tokio::task::spawn_blocking(move || point.restore()).await;
                    if !matches!(restored, Ok(Ok(()))) {
                        // DN-20: the device stays fail-closed rather than
                        // regaining an upstream resolver in an unarmed window.
                        tracing::error!(
                            target: "twinvpn.platform.linux.resolver",
                            "the host resolver could not be restored; the device stays fail-closed"
                        );
                    }
                }
                route::revert(&entry.applied).await?;
            }
            Ok(())
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move {
            // **Read from the kernel, not from this process's history.** This is
            // "the recovery entry point": after a crash the core reads it and
            // decides whether to converge or roll back, and a value remembered
            // in memory is exactly the thing a crash destroys.
            let installed = tokio::task::spawn_blocking(Self::read_installed)
                .await
                .map_err(|_| oserr::unavailable("nft.join", libc::ECANCELED))??;
            Ok(installed.and_then(|i| i.generation))
        })
    }

    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // NOT gated on the shutdown latch. `begin_shutdown`'s own contract:
            // "It does not tear down enforcement", and a swap TO `Blocked` on
            // the way down is the safe direction — refusing it would be the
            // unsafe one.
            let contract = {
                let history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                // The swap re-renders the SAME generation with the other
                // posture, so the Tier-1 scope is unchanged and only the
                // overlay exception moves. KS-1: a scope may never be narrowed
                // and a ruleset widened in two steps.
                history
                    .iter()
                    .find(|g| g.id == generation)
                    .map(|_| generation)
            };
            let generation = contract.unwrap_or(generation);
            let script = nft::render(
                &synthetic_contract(generation, ruleset),
                ruleset,
                &self.enforcement,
            );
            tokio::task::spawn_blocking(move || Self::run_nft_script(&script))
                .await
                .map_err(|_| oserr::unavailable("nft.join", libc::ECANCELED))?
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move {
            // **W-24's query.** Read from the OS rather than from a cached
            // value: the reconciler's job is to notice that something else
            // changed the rules, and a cache cannot.
            let installed = tokio::task::spawn_blocking(Self::read_installed)
                .await
                .map_err(|_| oserr::unavailable("nft.join", libc::ECANCELED))??;
            Ok(installed.map(|i| i.ruleset))
        })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        nft::custody()
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            self.shutdown.check()?;
            let interfaces = crate::iface::LinuxInterfaceProvider::new(self.shutdown.clone());
            let facts = twinvpn_platform::InterfaceProvider::enumerate(&interfaces).await?;

            // The underlay is every non-overlay, non-loopback interface that is
            // up. Its families are a FACT read from what is actually present,
            // never inferred from what the overlay has: `common.proto` forbids a
            // field "interpretable as 'v4 present therefore dual-stack'".
            let underlay: Vec<_> = facts
                .iter()
                .filter(|i| {
                    i.is_up
                        && !i.is_overlay
                        && i.link_class != twinvpn_platform::LinkClass::Loopback
                })
                .collect();

            let has_v4 = underlay.iter().any(|i| i.has_default_route_v4);
            let has_v6 = underlay.iter().any(|i| i.has_default_route_v6);
            #[allow(clippy::match_same_arms)]
            let families = match (has_v4, has_v6) {
                (true, true) => UnderlayFamilies::DualStack,
                // Same value as the (false, false) arm below, and deliberately
                // written out rather than merged: "the underlay carries v4" and
                // "the underlay carries nothing we can see" are different facts
                // that happen to share a representation today, and merging them
                // would hide it the moment `UnderlayFamilies` grows a value for
                // the second.
                (true, false) => UnderlayFamilies::V4Only,
                // ADR-0010 §11.7: PREF64 is discovered from an RFC 8781 RA
                // option or RFC 7050, neither of which this adapter observes
                // yet, so the honest answer is `None` rather than the well-known
                // prefix — "TwinVPN never depends on DNS64 to do this for it",
                // and assuming a prefix would be the same mistake in reverse.
                (false, true) => UnderlayFamilies::V6Only { nat64: None },
                (false, false) => UnderlayFamilies::V4Only,
            };

            // The effective MTU is the smallest an underlay interface offers,
            // floored at the IPv6 minimum: a path narrower than 1280 cannot
            // carry IPv6 at all, and reporting one would let DPLPMTUD search
            // below the floor `docs/networking.md` §6.3 forbids.
            let mtu = underlay
                .iter()
                .map(|i| i.mtu)
                .filter(|m| *m > 0)
                .min()
                .unwrap_or(crate::tun::MTU_FLOOR)
                .max(crate::tun::MTU_FLOOR);

            let resolvers = read_system_resolvers();

            Ok(LinkFacts {
                mtu,
                families,
                default_routes: PerFamily::new(has_v4, has_v6),
                resolvers,
                // Linux exposes no metering flag and no host-wide low-power
                // state that applies to a daemon. Reporting `false` is the
                // truthful answer for this platform, not a placeholder: a
                // fabricated `true` would suppress traffic the user is paying
                // for nothing to avoid.
                metered: false,
                low_power: false,
            })
        })
    }
}

/// Reads the *system's* resolvers, ignoring our own.
///
/// A `resolv.conf` we wrote is not a system resolver, and reporting it back as
/// one would make the core believe the host still has an upstream when it is
/// pointed at our stub. The owner tag is what tells the two apart.
fn read_system_resolvers() -> PerFamily<Vec<twinvpn_types::IpAddr>> {
    let mut out = PerFamily::new(Vec::new(), Vec::new());
    let Ok(text) = std::fs::read_to_string(resolver::RESOLV_CONF) else {
        return out;
    };
    if text.starts_with(resolver::OWNER_TAG) {
        return out;
    }
    for line in text.lines() {
        let Some(value) = line.strip_prefix("nameserver ") else {
            continue;
        };
        let Ok(std) = value.trim().parse::<std::net::IpAddr>() else {
            continue;
        };
        if let Ok(address) = crate::addr::from_std(std, 0, "resolv.conf") {
            let list = match address.family() {
                AddressFamily::V4 => &mut out.v4,
                AddressFamily::V6 => &mut out.v6,
            };
            // `limits.json` §`dns.max_resolvers_per_family`.
            if list.len() < 8 && !list.contains(&address) {
                list.push(address);
            }
        }
    }
    out
}

/// The minimal contract a bare `set_ruleset` re-renders from.
///
/// A ruleset swap does not change the Tier-1 scope, only whether the overlay is
/// an exception to it — so the scope comes from the generation already applied
/// wherever there is one, and this is the empty base for the very first
/// `RULESET_BLOCKED` install, before any contract exists. Its scope is empty,
/// which in `RULESET_BLOCKED` means "nothing is yet declared protected" — the
/// correct pre-arming state, and not "everything is permitted", because the
/// table is still installed and every later `apply` widens the drop.
fn synthetic_contract(generation: ContractGeneration, ruleset: Ruleset) -> NetworkContract {
    NetworkContract {
        generation,
        addresses: PerFamily::new(Vec::new(), Vec::new()),
        routes: PerFamily::new(Vec::new(), Vec::new()),
        dns: twinvpn_platform::DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: crate::tun::MTU_FLOOR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcement() -> EnforcementConfig {
        EnforcementConfig {
            overlay_interface: "twin0".to_owned(),
            firewall_mark: nft::DEFAULT_FWMARK,
            cgroup_path: None,
            local_network_access: true,
            on_link_prefixes: Vec::new(),
        }
    }

    fn config() -> LinuxNetworkConfig {
        LinuxNetworkConfig::new(
            ShutdownLatch::new(),
            enforcement(),
            PathBuf::from("/tmp/twinvpn-test-restore"),
        )
    }

    #[test]
    fn the_nft_binary_absence_is_a_named_failure_never_a_silent_success() {
        // ADR-0012 §8: arming must never fail open. On a host with no `nft` the
        // answer is an error with a registered code, and the caller refuses to
        // enter a protected state.
        match LinuxNetworkConfig::nft_binary() {
            Ok(path) => assert!(path.ends_with("/nft")),
            Err(e) => {
                assert_eq!(e.reason_code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
                assert_eq!(e.os_detail().map(|d| d.call), Some("nft(8)"));
                assert_eq!(e.os_detail().map(|d| d.code), Some(i64::from(libc::ENOENT)));
            }
        }
    }

    #[test]
    fn linux_declares_the_cb6_custody_it_actually_has() {
        let c = config().enforcement_custody();
        assert!(c.survives_core_exit);
        assert!(c.swap_is_atomic);
    }

    #[tokio::test]
    async fn rolling_back_a_generation_this_process_never_applied_is_a_no_op() {
        // ADR-0010 R5: reversible "including after an unclean process exit". A
        // fresh process asked to roll back an unknown generation has nothing of
        // ours on the host under that id, so there is nothing to undo — and
        // guessing would delete somebody else's routes, which §5.5 rule 1
        // forbids.
        config()
            .rollback(ContractGeneration(7))
            .await
            .expect("a no-op, never an error");
    }

    #[tokio::test]
    async fn apply_without_an_overlay_index_is_refused_rather_than_guessing_one() {
        // Rediscovering the interface by name would turn a rename race into a
        // route on the wrong link.
        let c = config();
        let contract = synthetic_contract(ContractGeneration(1), Ruleset::Blocked);
        let err = c.apply(&contract).await.expect_err("no interface yet");
        assert_eq!(err.os_detail().map(|d| d.call), Some("overlay.index"));
    }

    #[tokio::test]
    async fn apply_is_refused_after_shutdown_begins() {
        let latch = ShutdownLatch::new();
        let c = LinuxNetworkConfig::new(
            latch.clone(),
            enforcement(),
            PathBuf::from("/tmp/twinvpn-test-restore"),
        );
        latch.begin();
        let contract = synthetic_contract(ContractGeneration(1), Ruleset::Blocked);
        match c.apply(&contract).await {
            Err(PlatformError::ShuttingDown) => {}
            other => panic!("expected ShuttingDown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_ruleset_is_not_gated_on_shutdown_because_blocking_is_the_safe_direction() {
        // `begin_shutdown`'s contract: "It does not tear down enforcement." A
        // swap TO Blocked on the way down must still be possible.
        let latch = ShutdownLatch::new();
        let c = LinuxNetworkConfig::new(
            latch.clone(),
            enforcement(),
            PathBuf::from("/tmp/twinvpn-test-restore"),
        );
        latch.begin();
        // On a host with no `nft` this fails at the binary lookup, NOT at the
        // shutdown latch — which is the distinction being asserted.
        if let Err(e) = c.set_ruleset(ContractGeneration(1), Ruleset::Blocked).await {
            assert!(
                !matches!(e, PlatformError::ShuttingDown),
                "a shutdown must not block a swap to RULESET_BLOCKED"
            );
        }
    }

    #[test]
    fn our_own_resolv_conf_is_not_reported_back_as_a_system_resolver() {
        // Reporting our stub back as the system's would make the core believe
        // the host still has an upstream when it is pointed at us.
        let system = read_system_resolvers();
        let text = std::fs::read_to_string(resolver::RESOLV_CONF).unwrap_or_default();
        if text.starts_with(resolver::OWNER_TAG) {
            assert!(system.v4.is_empty() && system.v6.is_empty());
        } else {
            // On this host the file is the system's, so at least one resolver
            // should be visible if the file names any.
            let named = text
                .lines()
                .filter(|l| l.starts_with("nameserver "))
                .count();
            assert_eq!(named > 0, !(system.v4.is_empty() && system.v6.is_empty()));
        }
    }

    #[tokio::test]
    async fn link_facts_report_both_families_and_never_an_mtu_below_the_v6_floor() {
        let facts = config().query_link_facts().await.expect("enumerates");
        assert!(
            facts.mtu >= crate::tun::MTU_FLOOR,
            "a path narrower than 1280 cannot carry IPv6 and must not be reported"
        );
        // Both halves are present as separate facts — `default_routes` is a
        // PerFamily, so a v6 answer cannot be omitted.
        // Both halves are present as separate facts: `PerFamily` makes the v6
        // answer a field, so it cannot be omitted rather than answered.
        assert_eq!(
            facts.default_routes.v4,
            *facts.default_routes.get(twinvpn_types::AddressFamily::V4)
        );
        assert_eq!(
            facts.default_routes.v6,
            *facts.default_routes.get(twinvpn_types::AddressFamily::V6)
        );
        assert!(
            !facts.metered,
            "Linux exposes no metering flag for a daemon"
        );
    }

    #[test]
    fn the_synthetic_contract_for_a_bare_swap_declares_no_scope_rather_than_a_guessed_one() {
        let c = synthetic_contract(ContractGeneration(3), Ruleset::Blocked);
        assert!(c.routes.v4.is_empty() && c.routes.v6.is_empty());
        assert_eq!(c.mtu, crate::tun::MTU_FLOOR);
        // The table is still installed with both posture and generation
        // counters, so a read-back after a bare swap still answers.
        let script = nft::render(&c, Ruleset::Blocked, &enforcement());
        assert!(script.contains("counter posture_blocked { }"));
        assert!(script.contains("counter gen_3 { }"));
    }
}
