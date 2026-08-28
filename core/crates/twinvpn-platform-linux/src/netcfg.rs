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
    PlatformError, RouteCapabilities, Ruleset,
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
    /// The contract this generation installed.
    ///
    /// **Held so `set_ruleset` can re-render it.** Review finding **R-6**: a
    /// posture swap that rendered a *synthetic empty* contract emitted zero
    /// Tier-2 drop rules and its `delete table` then replaced the real ones. The
    /// Tier-1 scope does not change across a swap — only whether the overlay is
    /// an exception to it — so the swap must re-render **this**, which is what
    /// KS-17's "atomic swap between the two" actually means.
    contract: NetworkContract,
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
    pub(crate) fn run_nft_script(script: &str) -> Result<(), PlatformError> {
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
    pub(crate) fn read_installed() -> Result<Option<nft::Installed>, PlatformError> {
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

/// Reads the owner-tagged table back from the kernel, with no adapter in hand.
///
/// **ADR-0012 KS-20a's offline path needs this to be a free function.** The
/// recovery command exists for the case "the authority will not start", so it
/// cannot construct a [`LinuxNetworkConfig`] — that would mean constructing an
/// adapter, which means an `Env`, which means the runtime whose failure may be
/// the very thing being recovered from. Reading the kernel needs none of that.
///
/// `Ok(None)` is the one place `None` is the truth rather than the dangerous
/// direction: `nft list table` exits non-zero when the table does not exist, and
/// "nothing of ours is installed" is exactly what that means.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] when `nft(8)` is absent, or the errno
/// of a failed spawn. **Never a silent `None`** for either: O-18's fail-safe
/// direction is that an assertion which cannot be produced is not an assertion
/// that protection is absent.
pub fn read_owner_tagged_table() -> Result<Option<nft::Installed>, PlatformError> {
    LinuxNetworkConfig::read_installed()
}

/// Deletes the owner-tagged table, and **confirms it is gone from the kernel**.
///
/// ADR-0012 KS-20a: "privileged, local, network-independent, removing the
/// owner-tagged rule set and clearing the latch".
///
/// # Two things it deliberately does not do
///
/// 1. **It does not flush the ruleset.** `nft flush ruleset` would remove the
///    host's own firewall, which is not ours to remove. KS-20's reclamation is
///    scoped to what we tagged, and so is this.
/// 2. **It does not trust the exit code.** The delete is followed by a read-back,
///    for the same reason ADR-0016 §11.6 step (2) reads the ruleset back after
///    arming it: the kernel's answer is the fact, and "the command returned zero"
///    is not. A delete that reported success over a table that is still installed
///    would tell an operator their host is unblocked when it is not — and they
///    would then go looking for the problem somewhere else entirely.
///
/// Deleting a table that is not there is **not** an error: the command is for a
/// host in an unknown state, and refusing because the work was already done
/// would be the least useful possible answer.
///
/// # Errors
///
/// [`PlatformError::AdapterUnavailable`] when `nft(8)` is absent, the errno of a
/// failed spawn, or — after a delete that reported success — the table still
/// being present in the read-back.
pub fn remove_owner_tagged_table() -> Result<(), PlatformError> {
    // Already absent: nothing to do, and that is a success.
    if LinuxNetworkConfig::read_installed()?.is_none() {
        return Ok(());
    }
    // One `delete table`, scoped by name. Written as a script through the same
    // `nft -f -` path the install uses, so the environment is cleared the same
    // way (ADR-0016 Q10) and there is one place that spawns `nft`.
    let script = format!("delete table {} {}\n", nft::FAMILY, nft::TABLE);
    LinuxNetworkConfig::run_nft_script(&script)?;

    // The read-back. Not optional.
    match LinuxNetworkConfig::read_installed()? {
        None => Ok(()),
        Some(_) => Err(nft::unreachable(
            "nft delete table (read-back)",
            libc::EBUSY,
        )),
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
                contract: contract.clone(),
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
            // **R-6.** The swap re-renders the SAME generation's contract with
            // the other posture, so the Tier-1 scope is unchanged and only the
            // overlay exception moves. Rendering a synthetic empty contract here
            // — which this did — emits zero drop rules and the script's `delete
            // table` then replaces the real ones: a "fail-closed" swap that
            // opens the host.
            //
            // KS-1 is the rule that makes re-rendering mandatory rather than
            // tidy: a scope may never be narrowed and a ruleset widened in two
            // steps, and a swap that forgot the scope is exactly that narrowing.
            let contract = {
                let history = self
                    .history
                    .lock()
                    .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))?;
                history.iter().find(|g| g.id == generation).map_or_else(
                    // No contract has been applied under this id. The baseline
                    // in `nft::render` is what keeps even this table
                    // fail-closed: it drops the product's own address space in
                    // both families rather than nothing.
                    || baseline_contract(generation, ruleset),
                    |g| g.contract.clone(),
                )
            };
            let script = nft::render(&contract, ruleset, &self.enforcement);
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

    /// Linux has route metrics, so the instruction is honoured rather than
    /// refused.
    ///
    /// `RTA_PRIORITY` on an `RTM_NEWROUTE`, which is what lets §7.2 install a
    /// default route "without destroying the host's default route".
    fn route_capabilities(&self) -> RouteCapabilities {
        RouteCapabilities { metric: true }
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

/// The contract a `set_ruleset` renders from when **no contract has been
/// applied yet** — the very first arm, at startup, before the core has computed
/// anything.
///
/// Its routes are [`nft::baseline_protected`]'s: the product's own overlay
/// address space, both families, which is the same pair
/// `packaging/killswitch.nft` carries and is a constant of the product rather
/// than a scope this adapter chose (ADR-0010 §11.1, AP-1).
///
/// **It is never empty.** Review finding R-6: an empty scope renders a table
/// with zero drop rules under `policy accept`, and the script's `delete table`
/// replaces whatever was protecting the host with it. A pre-arming table that
/// drops the overlay space is the honest floor; a pre-arming table that drops
/// nothing is a hole with a `posture_blocked` counter on it.
fn baseline_contract(generation: ContractGeneration, ruleset: Ruleset) -> NetworkContract {
    let baseline = nft::baseline_protected();
    let route_for = |family: AddressFamily| -> Vec<twinvpn_platform::RouteEntry> {
        baseline
            .iter()
            .filter(|p| p.family() == family)
            .map(|destination| twinvpn_platform::RouteEntry {
                destination: *destination,
                via: None,
                // No overlay interface exists before the first `apply`, and the
                // Tier-2 drop does not read the interface — only the
                // `RULESET_PROTECTED` exception does, and that names the
                // interface by NAME from `EnforcementConfig`, not by index.
                interface: twinvpn_platform::InterfaceIndex(0),
                metric: None,
            })
            .collect()
    };
    NetworkContract {
        generation,
        addresses: PerFamily::new(Vec::new(), Vec::new()),
        routes: PerFamily::new(route_for(AddressFamily::V4), route_for(AddressFamily::V6)),
        dns: twinvpn_platform::DnsConfig {
            resolvers: PerFamily::new(Vec::new(), Vec::new()),
            search_domains: Vec::new(),
            split_domains: Vec::new(),
            is_default_resolver: false,
        },
        ruleset,
        mtu: crate::tun::MTU_FLOOR,
        // No path is validated before the first `apply`, so there is no remote
        // the tunnel is riding. `None` is the fact, not a placeholder.
        tunnel_remote_address: None,
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
    fn the_offline_unblock_path_needs_no_adapter_and_no_env() {
        // **KS-20a's whole point**: the recovery command runs when the authority
        // will not start, so the read and the delete must be reachable without
        // constructing an adapter, an `Env` or a runtime. This test calls them
        // as free functions — if either ever needed a `&self`, this stops
        // compiling, which is the assertion.
        // `nft(8)` is absent on this host, so the honest answer is a NAMED
        // failure rather than `Ok(None)`. Reporting "no table installed" when we
        // cannot look would tell an operator the host is unblocked when we have
        // no idea — O-18's dangerous direction.
        if let Err(error) = read_owner_tagged_table() {
            assert!(error.os_detail().is_some());
        }
    }

    #[test]
    fn removing_the_owner_tagged_table_names_only_our_own_table() {
        // The rendered script is `delete table inet twinvpn` and nothing else.
        // A `flush ruleset` here would remove the HOST's firewall, which is not
        // ours to remove: KS-20's reclamation is scoped to what we tagged.
        let script = format!("delete table {} {}\n", nft::FAMILY, nft::TABLE);
        assert_eq!(script, "delete table inet twinvpn\n");
        assert!(!script.contains("flush"));
        assert!(!script.contains("ruleset"));
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
        assert!(c.survives_core_exit());
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
        let contract = baseline_contract(ContractGeneration(1), Ruleset::Blocked);
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
        let contract = baseline_contract(ContractGeneration(1), Ruleset::Blocked);
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

    /// **R-6, as the assertion that would have caught it.**
    ///
    /// The pre-arming table is rendered before any contract exists. It must
    /// still DROP something: a table with zero Tier-2 rules under `policy
    /// accept` protects nothing, and the script's `delete table` replaces
    /// whatever was there with it.
    #[test]
    fn the_pre_arming_table_drops_the_overlay_space_rather_than_nothing() {
        let c = baseline_contract(ContractGeneration(3), Ruleset::Blocked);
        assert!(
            !c.routes.v4.is_empty() && !c.routes.v6.is_empty(),
            "an empty scope renders zero drop rules — R-6"
        );
        let script = nft::render(&c, Ruleset::Blocked, &enforcement());
        assert!(script.contains("counter posture_blocked { }"));
        assert!(script.contains("counter gen_3 { }"));
        // Both families, and the product's own address space in each.
        assert!(script.contains("ip daddr 100.64.0.0/10 counter name \"deny_v4\" drop"));
        assert!(script.contains("ip6 daddr fd7c:9e5d:2a10::/48 counter name \"deny_v6\" drop"));
        // And the read-back can SEE the cardinality, so "BLOCKED over nothing"
        // is a value rather than an invisible state.
        assert!(script.contains("counter scope_v4_1 { }"));
        assert!(script.contains("counter scope_v6_1 { }"));
    }

    /// **R-6's core case.** A posture swap must not narrow the scope.
    #[test]
    fn a_posture_swap_re_renders_the_applied_contracts_scope_and_never_an_empty_one() {
        let applied = contract_with_scope(ContractGeneration(7));
        let protected = nft::render(&applied, Ruleset::Protected, &enforcement());
        // The swap renders the SAME contract with the other posture...
        let mut blocked_contract = applied.clone();
        blocked_contract.ruleset = Ruleset::Blocked;
        let blocked = nft::render(&blocked_contract, Ruleset::Blocked, &enforcement());

        for script in [&protected, &blocked] {
            assert!(
                script.contains("ip daddr 0.0.0.0/1 counter name \"deny_v4\" drop"),
                "the swap dropped the contract's own scope"
            );
            assert!(script.contains("ip6 daddr ::/1 counter name \"deny_v6\" drop"));
            assert!(script.contains("counter scope_v4_2 { }"));
            assert!(script.contains("counter scope_v6_2 { }"));
        }
        // ...and the ONLY difference is whether the overlay is an exception.
        assert!(protected.contains("oifname \"twin0\" ip daddr 0.0.0.0/1 accept"));
        assert!(!blocked.contains("oifname \"twin0\" ip daddr 0.0.0.0/1 accept"));
    }

    /// A full-tunnel contract, as `docs/networking.md` §7.2's four `/1` routes.
    fn contract_with_scope(generation: ContractGeneration) -> NetworkContract {
        let mut contract = baseline_contract(generation, Ruleset::Protected);
        let route = |destination| twinvpn_platform::RouteEntry {
            destination,
            via: None,
            interface: twinvpn_platform::InterfaceIndex(9),
            metric: None,
        };
        contract.routes = PerFamily::new(
            crate::route::full_tunnel_destinations()
                .into_iter()
                .filter(|p| p.family() == AddressFamily::V4)
                .map(route)
                .collect(),
            crate::route::full_tunnel_destinations()
                .into_iter()
                .filter(|p| p.family() == AddressFamily::V6)
                .map(route)
                .collect(),
        );
        contract
    }
}
