//! [`NetworkConfig`]: `apply`, `rollback`, the atomic ruleset swap, the
//! read-back, and the link facts.
//!
//! **Authority:** `docs/networking.md` §5.1 (the transactional contract), §2.3
//! ("partial application is the leak window"), §5.2's Android row, §5.4's
//! roaming row (`setUnderlyingNetworks` kept current), §5.5 (coexistence);
//! ADR-0008 (idempotency on the generation id); ADR-0010 R1 and R5; ADR-0012
//! **KS-17**; ADR-0018 CB-6, CB-6a.
//!
//! # `apply` is one call on Android, which makes all-or-nothing easy and
//! rollback hard
//!
//! On Linux `apply` is a firewall transaction, then addresses and routes, then
//! the resolver, with an unwind path at each step. On Android it is a single
//! `VpnService.Builder.establish()` that carries the addresses, the routes, the
//! DNS servers and the claim together. The **all-or-nothing** half of §5.1 is
//! therefore free: `establish()` either returns a descriptor with the whole
//! programme in force, or it throws and nothing changed.
//!
//! What is *not* free is **§5.1's `rollback(generation)`**, and this is stated
//! rather than pretended: re-establishing an earlier generation is a fresh
//! `establish()`, which tears the previous claim down and rebuilds it. Between
//! the two there is an interval with **no claim**, and on Android there is no
//! firewall behind the claim to catch what escapes. So:
//!
//! - **`rollback` to a generation this adapter still holds re-establishes it**,
//!   and the window is real and is reported.
//! - **`rollback` to a generation it does not hold is refused**, rather than
//!   approximated by "the nearest one we remember", which would install a
//!   contract the core never asked for.
//!
//! ADR-0010 R5 asks for installation to be "fully reversible, including after an
//! unclean process exit". On Android the second half is satisfied by the
//! platform itself and not by us: the descriptor dies with the process and the
//! claim goes with it, so an unclean exit *is* the reversal. That is the same
//! fact as [`crate::posture`]'s `survives_core_exit: false`, seen from the other
//! side, and it is why the two must be read together.
//!
//! # KS-17: the swap that is not a re-establish
//!
//! [`NetworkConfig::set_ruleset`] changes an atomic, and touches nothing else.
//! The claim is identical in both postures ([`crate::builder`] rule 2), so there
//! is no moment at which rules are absent. See [`crate::posture`] for the whole
//! argument.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use futures_core::future::BoxFuture;

use twinvpn_platform::{
    ContractGeneration, EnforcementCustody, LinkFacts, NetworkConfig, NetworkContract,
    PlatformError, Ruleset, TunnelHandle,
};
use twinvpn_types::{AddressFamily, PerFamily, UnderlayFamilies};

use crate::builder::{self, Programme, VpnConfig};
use crate::hostcall::TunnelController;
use crate::iface::AndroidInterfaceProvider;
use crate::netchange::TransportSet;
use crate::oserr;
use crate::posture::{EnforcementView, LockdownPosture};
use crate::shutdown::ShutdownLatch;
use crate::tun::AndroidTunnelDevice;

/// How many applied generations are remembered for `rollback`.
///
/// `rollback` names the generation **before** a given one, so at least two are
/// needed; four gives room for a retry ladder without letting the history grow
/// with uptime. Exceeding it drops the oldest, and a `rollback` to a generation
/// that has aged out is **refused** rather than approximated.
pub const GENERATION_HISTORY: usize = 4;

/// One applied generation, kept so it can be re-established.
#[derive(Debug, Clone)]
struct Applied {
    id: ContractGeneration,
    programme: Programme,
}

/// The transactional configuration surface.
#[derive(Debug, Clone)]
pub struct AndroidNetworkConfig {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    controller: Arc<dyn TunnelController>,
    tunnel: AndroidTunnelDevice,
    interfaces: AndroidInterfaceProvider,
    config: VpnConfig,
    history: Mutex<Vec<Applied>>,
    handle: Mutex<Option<TunnelHandle>>,
    /// The BLOCKED/PROTECTED disposition. **One atomic, so the swap is a single
    /// store** — KS-17's "rules are never absent" made structural.
    disposition: AtomicU8,
    lockdown: Mutex<LockdownPosture>,
    shutdown: ShutdownLatch,
}

const DISPOSITION_BLOCKED: u8 = 0;
const DISPOSITION_PROTECTED: u8 = 1;

impl AndroidNetworkConfig {
    /// Builds the configuration surface.
    #[must_use]
    pub fn new(
        controller: Arc<dyn TunnelController>,
        tunnel: AndroidTunnelDevice,
        interfaces: AndroidInterfaceProvider,
        config: VpnConfig,
        shutdown: ShutdownLatch,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                controller,
                tunnel,
                interfaces,
                config,
                history: Mutex::new(Vec::new()),
                handle: Mutex::new(None),
                // BLOCKED until something says otherwise. The fail-closed
                // direction, and the state ADR-0022 LC-4 step 4 requires an
                // agent to re-assert before any packet is emitted.
                disposition: AtomicU8::new(DISPOSITION_BLOCKED),
                lockdown: Mutex::new(LockdownPosture::default()),
                shutdown,
            }),
        }
    }

    /// Records which tunnel handle `apply` should establish.
    ///
    /// The shell creates the interface (reserving a handle) and then hands it
    /// here, because on Android `apply` is what actually establishes it.
    pub fn bind_handle(&self, handle: TunnelHandle) {
        if let Ok(mut slot) = self.inner.handle.lock() {
            *slot = Some(handle);
        }
    }

    /// Records the always-on posture a DPC or managed configuration reported.
    ///
    /// `None` is [`LockdownPosture::Unverified`], which presents as unprotected
    /// (LC-40). There is deliberately no probe: see [`crate::posture`].
    pub fn set_lockdown_report(&self, reported: Option<bool>) {
        if let Ok(mut slot) = self.inner.lockdown.lock() {
            *slot = LockdownPosture::from_managed_report(reported);
        }
    }

    /// The always-on posture as it stands.
    #[must_use]
    pub fn lockdown(&self) -> LockdownPosture {
        self.inner
            .lockdown
            .lock()
            .map_or(LockdownPosture::Unverified, |p| *p)
    }

    /// Keeps `setUnderlyingNetworks` current across a Wi-Fi↔cellular handoff.
    ///
    /// `docs/networking.md` §5.4: *"`setUnderlyingNetworks` kept current so the
    /// system accounts and routes correctly across Wi-Fi/cellular handoff"*.
    /// The set is derived from the snapshot the JNI layer already maintains —
    /// every live non-VPN network, in handle order — so no second source of
    /// truth exists to drift.
    ///
    /// # Errors
    ///
    /// Whatever [`TunnelController::set_underlying_networks`] reports.
    pub fn refresh_underlying_networks(&self) -> Result<(), PlatformError> {
        let snapshot = self.inner.interfaces.snapshot()?;
        let handles: Vec<u64> = snapshot
            .networks()
            .iter()
            .filter(|n| n.is_up && !n.transports.has(TransportSet::VPN))
            .map(|n| n.handle)
            .collect();
        self.inner.controller.set_underlying_networks(&handles)
    }

    /// The enforcement view [`installed_ruleset`] and the `ProtectionAssertion`
    /// are both answered from.
    ///
    /// [`installed_ruleset`]: NetworkConfig::installed_ruleset
    #[must_use]
    pub fn enforcement_view(&self) -> EnforcementView {
        let handle = self.inner.handle.lock().ok().and_then(|slot| *slot);
        let claim_in_force = handle.is_some_and(|h| self.inner.tunnel.claim_in_force(h));
        let claims_default = self
            .inner
            .history
            .lock()
            .ok()
            .and_then(|h| h.last().map(|a| a.programme.claims_default))
            .unwrap_or(PerFamily::new(false, false));
        EnforcementView::from_claim(
            claim_in_force,
            claims_default,
            self.disposition(),
            self.lockdown(),
        )
    }

    /// The disposition currently in force.
    #[must_use]
    pub fn disposition(&self) -> Ruleset {
        if self.inner.disposition.load(Ordering::Acquire) == DISPOSITION_PROTECTED {
            Ruleset::Protected
        } else {
            Ruleset::Blocked
        }
    }

    fn history(&self) -> Result<std::sync::MutexGuard<'_, Vec<Applied>>, PlatformError> {
        self.inner
            .history
            .lock()
            .map_err(|_| oserr::unavailable("netcfg.lock", libc::EDEADLK))
    }

    /// Establishes `programme` under `id` and records it.
    ///
    /// `ruleset` is the disposition the contract asked for — `NetworkContract`'s
    /// own field is "which ruleset to hold **for this generation**", so an
    /// `apply` installs it rather than leaving the previous generation's
    /// disposition in force. [`NetworkConfig::set_ruleset`] is the separate,
    /// atomic swap *within* a generation.
    fn install(
        &self,
        id: ContractGeneration,
        ruleset: Ruleset,
        programme: Programme,
    ) -> Result<(), PlatformError> {
        let handle = self
            .inner
            .handle
            .lock()
            .ok()
            .and_then(|slot| *slot)
            .ok_or_else(|| oserr::unavailable("netcfg.handle", libc::ENODEV))?;

        self.inner.tunnel.establish(handle, &programme)?;
        self.inner.disposition.store(
            match ruleset {
                Ruleset::Blocked => DISPOSITION_BLOCKED,
                Ruleset::Protected => DISPOSITION_PROTECTED,
            },
            Ordering::Release,
        );

        {
            let mut history = self.history()?;
            history.retain(|a| a.id != id);
            history.push(Applied { id, programme });
            if history.len() > GENERATION_HISTORY {
                history.remove(0);
            }
        }
        // The underlying-network set is refreshed on every install, because a
        // generation applied during a handoff must not carry the previous
        // underlay. A failure here is NOT fatal to the apply: the claim is in
        // force either way, and the consequence is system accounting rather
        // than a leak.
        let _ = self.refresh_underlying_networks();
        Ok(())
    }
}

impl NetworkConfig for AndroidNetworkConfig {
    fn apply<'a>(
        &'a self,
        contract: &'a NetworkContract,
    ) -> BoxFuture<'a, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown_check()?;

            // ADR-0008: idempotent on the generation id. Re-applying the
            // generation already in force succeeds and changes nothing, so a
            // retry after a crash converges rather than establishing twice --
            // which on Android would take the platform's single VPN slot away
            // from itself for the duration of the second establish.
            if self
                .history()?
                .last()
                .is_some_and(|a| a.id == contract.generation)
                && self.enforcement_view().claim_in_force
            {
                return Ok(());
            }

            // Rendered BEFORE anything is touched, so a contract that cannot be
            // expressed fails with nothing applied. This is where ADR-0010 R1's
            // both-families rule and every `limits.json` bound are enforced.
            let programme = builder::render(contract, &self.inner.config)?;
            self.install(contract.generation, contract.ruleset, programme)?;
            Ok(())
        })
    }

    fn rollback(&self, generation: ContractGeneration) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            self.shutdown_check()?;
            // "Restores the generation BEFORE `generation`, exactly." A
            // generation this adapter no longer holds is REFUSED rather than
            // approximated: installing the nearest remembered contract would
            // put the device into a state the core never asked for, and the
            // core's reconciler would then be comparing against a fiction.
            let (previous, ruleset) = {
                let history = self.history()?;
                let at = history
                    .iter()
                    .position(|a| a.id == generation)
                    .ok_or_else(|| oserr::unavailable("netcfg.rollback", libc::ENOENT))?;
                let index = at
                    .checked_sub(1)
                    .ok_or_else(|| oserr::unavailable("netcfg.rollback", libc::ENOENT))?;
                (history[index].clone(), self.disposition())
            };
            // Re-establishing opens a window with no claim. It is real, it is
            // the platform's, and it is not hidden: see the module docs.
            self.install(previous.id, ruleset, previous.programme)?;
            self.history()?.retain(|a| a.id <= previous.id);
            Ok(())
        })
    }

    fn current_generation(
        &self,
    ) -> BoxFuture<'_, Result<Option<ContractGeneration>, PlatformError>> {
        Box::pin(async move {
            // NOT gated on the shutdown latch: ADR-0022 LC-4 makes this the
            // recovery entry point, and a recovering process must be able to ask
            // what is in force even while the previous one is on its way out.
            Ok(self.history()?.last().map(|a| a.id))
        })
    }

    fn set_ruleset(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> BoxFuture<'_, Result<(), PlatformError>> {
        Box::pin(async move {
            // Deliberately NOT gated on the shutdown latch when BLOCKING.
            // Refusing to block during shutdown would be a refusal in the
            // dangerous direction; refusing to *unblock* is safe.
            if ruleset == Ruleset::Protected {
                self.shutdown_check()?;
            }
            // The generation must be one we hold, so a stale caller cannot
            // unblock against a contract that is no longer installed.
            if !self.history()?.iter().any(|a| a.id == generation) {
                return Err(oserr::unavailable("netcfg.set_ruleset", libc::ENOENT));
            }
            // KS-17: ONE atomic store. The claim is identical in both postures,
            // so there is no interval in which rules are absent.
            self.inner.disposition.store(
                match ruleset {
                    Ruleset::Blocked => DISPOSITION_BLOCKED,
                    Ruleset::Protected => DISPOSITION_PROTECTED,
                },
                Ordering::Release,
            );
            Ok(())
        })
    }

    fn installed_ruleset(&self) -> BoxFuture<'_, Result<Option<Ruleset>, PlatformError>> {
        Box::pin(async move { Ok(self.enforcement_view().installed_ruleset()) })
    }

    fn enforcement_custody(&self) -> EnforcementCustody {
        self.enforcement_view().custody()
    }

    fn query_link_facts(&self) -> BoxFuture<'_, Result<LinkFacts, PlatformError>> {
        Box::pin(async move {
            self.shutdown_check()?;
            let snapshot = self.inner.interfaces.snapshot()?;
            let underlays: Vec<_> = snapshot
                .networks()
                .iter()
                .filter(|n| n.is_up && !n.transports.has(TransportSet::VPN))
                .collect();

            let v4 = snapshot.underlay_has_default(AddressFamily::V4);
            let v6 = snapshot.underlay_has_default(AddressFamily::V6);
            let nat64 = underlays.iter().find_map(|n| n.nat64);

            // ADR-0010 §11.7 keeps V4Only, V6Only-with-NAT64, V6Only-without and
            // 464XLAT as FOUR distinct situations. 464XLAT is deliberately not
            // synthesised here: it presents to an app as plain IPv4 with a
            // CLAT interface, and `LinkProperties` gives an app no reliable way
            // to distinguish it from native v4 -- so reporting `Xlat464` would
            // be a guess, and `UnderlayFamilies` treats the two as different
            // precisely because their consequences differ.
            let families = match (v4, v6) {
                (true, true) => UnderlayFamilies::DualStack,
                (false, true) => UnderlayFamilies::V6Only { nat64 },
                // No default route in either family is reported as `V4Only`
                // rather than as an error: it is an ordinary, named condition
                // (`NET.NO_USABLE_CANDIDATES`) and the core decides.
                _ => UnderlayFamilies::V4Only,
            };

            let mut resolvers = PerFamily::new(Vec::new(), Vec::new());
            for network in &underlays {
                for address in &network.resolvers {
                    resolvers.get_mut(address.family()).push(*address);
                }
            }

            Ok(LinkFacts {
                // The smallest live underlay MTU, or the §6.2 floor when the OS
                // does not say. The smallest, because a tunnel sized to the
                // largest black-holes on the other one during a handoff.
                mtu: underlays
                    .iter()
                    .map(|n| n.mtu)
                    .filter(|m| *m > 0)
                    .min()
                    .unwrap_or(builder::MTU_FLOOR),
                families,
                default_routes: PerFamily::new(v4, v6),
                resolvers,
                metered: snapshot.metered(),
                low_power: snapshot.low_power(),
            })
        })
    }
}

impl AndroidNetworkConfig {
    fn shutdown_check(&self) -> Result<(), PlatformError> {
        self.inner.shutdown.check()
    }
}

#[cfg(test)]
mod tests;
