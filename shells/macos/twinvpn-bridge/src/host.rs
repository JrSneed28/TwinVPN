//! The authority: the `Env`, the adapter, the hosted `Core`, and the MI.
//!
//! **Authority:** ADR-0016 §11.2's macOS row and its amendment **PS-22**,
//! §11.6 (the start sequence), §11.14 (a), (f), (g), (m), §11.16 (a), PS-1,
//! PS-3, PS-7, PS-8, PS-11, PS-17, PS-18; ADR-0018 CD-2, CB-6, S-47, VR-4;
//! ADR-0022 LC-8; ADR-0012 KS-20; `ownership.md` §8 **W-24**, **W-43**, §9.6
//! **X-7**.
//!
//! # This file is what X-7 moved
//!
//! It was `shells/macos/twinvpnd/src/main.rs`. PS-22 puts the core, the key
//! handle and the management interface inside the NE system extension, and the
//! argument is physical rather than editorial:
//!
//! > `NEPacketTunnelProvider.packetFlow` exists only inside the provider
//! > process. The datapath must therefore be in the extension; the core owns the
//! > datapath; and §11.16 (a) / S-47 permit **exactly one process** to hold a
//! > mutating core handle.
//!
//! So there is no `main` here. The lifetime of this object is the lifetime of
//! `tvb_ext_start` … `tvb_ext_free`, and `launchd` is not involved.
//!
//! # CD-2, and the one thing it forbids that is tempting here
//!
//! Every capability is constructed and injected. The `Env` is built once, in
//! [`Host::start`], and handed to `Core::create`; nothing below reaches for a
//! clock, a runtime or an RNG of its own. **Timeouts are the core's** and
//! **cancellation is dropping the future** — there is no timeout constant in
//! this file and no cancellation token.
//!
//! # CB-6, restated because this file is where it could be broken
//!
//! `begin_shutdown` sets a latch and touches no enforcement. The pf anchor
//! stays loaded when this process goes away — that is the whole reason CB-6
//! puts the rule set in the OS's custody — and nothing in [`Host`]'s drop path
//! removes it.

use std::sync::Arc;

use twinvpn_env::{Env, EnvParts};
use twinvpn_mgmt::Submission;
use twinvpn_platform_macos::MacosPlatformAdapter;

use crate::config::{self, ExtensionConfig};
use crate::mgmt::{server, CommandSink, ServerContext};
use crate::port::BridgePort;
use crate::probes::ExtensionProbes;
use crate::start::{self, StartSequence};

/// One running authority.
///
/// **S-47's single mutating handle, as an owned value.** There is exactly one
/// of these per extension instance, it is created by `tvb_ext_start` and
/// dropped by `tvb_ext_free`, and nothing hands the core out:
/// [`Host::context`]'s `CommandSink` is the only way to reach it, and it takes
/// PS-4's typed vocabulary.
pub struct Host {
    adapter: Arc<MacosPlatformAdapter>,
    port: Arc<BridgePort>,
    context: ServerContext,
    sequence: StartSequence,
    env: Env,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No core, no adapter and no context in the output: a `Debug` that
        // printed the store root or the group policy would put installation
        // facts into a log line that ADR-0015 §11.4 does not classify.
        f.debug_struct("Host")
            .field("ready", &self.sequence.is_ready())
            .field("steps", &self.sequence.steps().len())
            .finish_non_exhaustive()
    }
}

impl Host {
    /// Runs §11.6's start sequence and, if it passes, hands back the authority.
    ///
    /// The sequence is run **incrementally**: each probe is filled in as the
    /// thing it describes is attempted, and [`start::run`] is called once at the
    /// end over the facts. That ordering matters — a sequence run before
    /// anything was attempted would be reporting on a host rather than on a
    /// start.
    ///
    /// # Errors
    ///
    /// The [`StartSequence`] that refused, so the caller can name the step. PS-18
    /// forbids starting "in a mode that cannot arm enforcement while reporting
    /// itself as running", and a refusal that did not say which step refused
    /// would leave a support case with nothing.
    pub fn start(config: &ExtensionConfig) -> Result<Self, Box<StartSequence>> {
        let mut probes = ExtensionProbes::new(config.clone());

        // --- ADR-0022 LC-8's three clocks, the CSPRNG, and the boot identity --
        let elapsed = twinvpn_platform_macos::ContinuousElapsedClock::from_kernel();
        let entropy = Arc::new(twinvpn_platform_macos::SystemEntropy::new());
        let boot_id = twinvpn_platform_macos::clock::BootSessionId::read();
        let runtime = twinvpn_env::binding::tokio_rt::TokioRuntime::work_stealing();
        probes.with_clocks(elapsed.is_some() && entropy.probe().is_ok() && boot_id.is_ok());
        // **W-43.** `twinvpn-env`'s `TokioRuntime` once built with `enable_time()`
        // and not `enable_io()`, so no socket could be opened at all. Fixed; the
        // probe stays, because PS-18's rule is to refuse at startup rather than
        // report a running authority that can do nothing — and this process now
        // opens the MI socket itself, so the probe guards more than it did.
        probes.with_runtime_io(runtime.is_ok());

        let (Some(elapsed), Ok(runtime)) = (elapsed, runtime) else {
            return Err(Box::new(start::run(&probes)));
        };
        let elapsed: Arc<dyn twinvpn_env::ElapsedClock> = Arc::new(elapsed);
        let monotonic: Arc<dyn twinvpn_env::MonotonicClock> =
            Arc::new(twinvpn_env::binding::system::SystemMonotonicClock::new());
        let timer = runtime.timer(monotonic.clone());
        let env = Env::new(EnvParts {
            monotonic,
            elapsed: elapsed.clone(),
            // CD-1a: the wall clock is EVIDENCE ONLY, never a timer input, and a
            // three-state value. macOS does not expose whether `ntpd` has
            // synchronised the clock through any API this crate can reach, so
            // the honest declaration is `Unsynchronised` — a reading is reported
            // as `Offset`, never as `Trusted`. Named as a gap in the README.
            wall: Arc::new(twinvpn_env::binding::system::SystemWallClock::new(
                twinvpn_env::binding::system::WallClockTrust::Unsynchronised(
                    twinvpn_env::OffsetSource::PersistedLastKnown,
                ),
            )),
            timer,
            runtime: Arc::new(runtime),
            entropy: entropy.clone(),
            rng: Arc::new(twinvpn_env::SystemRngSource::new(entropy)),
        });

        // --- the adapter, and its declared posture ---------------------------
        //
        // **No `cfg(target_os)` here any more, and that is a consequence of the
        // move rather than a tidy-up.** The daemon binding had to choose an
        // `SCDynamicStore` engine behind a `cfg`, because it programmed the
        // resolver itself. Under `ResolverCarrier::TunnelSettings` the OS
        // installs the resolver from the settings document, so the engine is
        // never called and the honest one to inject is the one that refuses by
        // name.
        let carriers = config::extension_carriers(Arc::new(NoResolver), String::new());
        let adapter = config::build_adapter(config, carriers);
        probes.with_posture(adapter.posture());

        // --- the datapath, handed to the adapter (PB-1) -----------------------
        let port = Arc::new(BridgePort::new());
        adapter.tunnel_device().set_pending_port(port.clone());

        // --- §11.6 (2): reclaim, then **read back** (KS-20, PS-8, W-24) -------
        //
        // The read-back is the only thing that sets the probe. A flag set
        // because a load returned `Ok` is exactly what W-24 rejects.
        //
        // **§11.14 (m) still holds after the move, and this is where to check
        // it:** the assertion is produced by asking `pfctl` what is loaded, from
        // this process, with no UI process running and no daemon involved. The
        // extension is started by `systemextensionsd`/NE, not by a console
        // session, so "the authority alone" is if anything more true here than
        // it was in the `LaunchDaemon`.
        if let Ok(assertion) = adapter.network().assertion() {
            probes.with_read_back(&assertion);
        }

        // --- §11.6 (5): the core, ABI-checked first (VR-4) --------------------
        let core = host_core(env.clone(), &adapter);
        probes.with_core(core.is_some());

        // --- §11.6 (6): the MI endpoint (MI-A3) -------------------------------
        let listener = crate::mgmt::endpoint::bind(&config.socket_path, config.groups.observe);
        probes.with_endpoint(listener.is_ok());

        let sequence = start::run(&probes);
        let (Some(core), Ok(listener)) = (core, listener) else {
            return Err(Box::new(sequence));
        };
        if !sequence.is_ready() {
            return Err(Box::new(sequence));
        }

        let context = ServerContext {
            core,
            policy: config.groups,
            os_version: os_version(),
            elapsed,
        };
        let host = Self {
            adapter,
            port,
            context,
            sequence,
            env,
        };
        host.accept_management(listener);
        Ok(host)
    }

    /// The packet port the datapath reads and writes.
    #[must_use]
    pub fn port(&self) -> Arc<BridgePort> {
        Arc::clone(&self.port)
    }

    /// The platform adapter, so the ABI can publish lifecycle facts into the
    /// **core's own** interface provider rather than into a second one.
    #[must_use]
    pub const fn adapter(&self) -> &Arc<MacosPlatformAdapter> {
        &self.adapter
    }

    /// What each start step found. Carried so a diagnostic bundle can show how
    /// far the authority got rather than only that it started.
    #[must_use]
    pub const fn sequence(&self) -> &StartSequence {
        &self.sequence
    }

    /// The management context both carriages share.
    #[must_use]
    pub const fn context(&self) -> &ServerContext {
        &self.context
    }

    /// Reports a stop.
    ///
    /// **CB-6.** Sets the adapter's shutdown latch and closes the datapath, and
    /// touches no enforcement: the pf anchor stays loaded, which is the whole
    /// reason the OS holds it. Nothing here removes a rule, a route or a
    /// resolver entry.
    pub fn begin_shutdown(&self) {
        use twinvpn_platform::PlatformAdapter as _;
        use twinvpn_platform_macos::utun::PacketPort as _;
        self.adapter.begin_shutdown();
        // Refuse new spawns and let running work finish (`ownership.md` §6
        // rule 7). Not an abort: a cancelled MI connection mid-reply is a
        // client that cannot tell a refusal from a crash.
        self.env.runtime().begin_shutdown();
        self.port.close();
    }

    /// Spawns MI-A3's accept loop for the socket carriage.
    ///
    /// **PS-3**: a client going away changes nothing. Each connection is served
    /// on its own task and its failure is logged, never propagated — the loss of
    /// the last management client must not change `session_intent`, the
    /// enforcement mode, the installed rule set or the `ConnectionState`.
    fn accept_management(&self, listener: std::os::unix::net::UnixListener) {
        let context = self.context.clone();
        let spawned = self.env.runtime().spawn(Box::pin(async move {
            // The conversion happens **inside** the runtime, because
            // `tokio::net::UnixListener::from_std` needs a reactor and there is
            // none at the point the endpoint is bound. The bind itself is a
            // plain `std` call and MI-A3's rename is complete before this task
            // exists, so nothing is racing on the path either way.
            let Ok(listener) = crate::mgmt::endpoint::into_tokio(listener) else {
                tracing::error!(
                    target: "twinvpn.mi",
                    "the endpoint could not be attached to the runtime's reactor"
                );
                return;
            };
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let context = context.clone();
                        tokio::spawn(async move {
                            let ending = server::serve(stream, &context).await;
                            tracing::debug!(
                                target: "twinvpn.mi",
                                ?ending,
                                "a management connection ended"
                            );
                        });
                    }
                    Err(error) => {
                        // A failed accept is not a reason to stop accepting: the
                        // authority's job outlives any one client, and exiting
                        // here would make a transient fd exhaustion into a
                        // dropped tunnel.
                        tracing::warn!(target: "twinvpn.mi", %error, "accept failed");
                    }
                }
            }
        }));
        if spawned.is_err() {
            tracing::error!(
                target: "twinvpn.mi",
                "the management accept loop could not be spawned"
            );
        }
    }
}

/// Constructs the core, ABI-checked first (**VR-4**).
///
/// `None` makes §11.6's `Core` step refuse, which is the honest outcome: an
/// authority that accepted connections with nothing behind them would be
/// reporting itself as running while answering nothing, which is exactly
/// PS-18's condition.
fn host_core(env: Env, adapter: &Arc<MacosPlatformAdapter>) -> Option<Arc<dyn CommandSink>> {
    /// The one edge from the management interface to the core (**PS-4**).
    struct CoreSink(twinvpn_core::Core);

    impl CommandSink for CoreSink {
        fn submit(&self, submission: &Submission) -> Result<(), Box<twinvpn_types::Diagnostic>> {
            self.0.submit(submission)
        }
    }

    let core = twinvpn_core::Core::create(twinvpn_core::CoreParts {
        env,
        adapter: adapter.clone(),
        abi_major_expected: twinvpn_core::ABI_MAJOR,
        abi_major: twinvpn_core::ABI_MAJOR,
        abi_minor: twinvpn_core::ABI_MINOR,
        schema_digest: Vec::new(),
        crypto_provider: "twinvpn-crypto".to_owned(),
        sek_custody: "core-held:unreported".to_owned(),
        // §11.16 (l): the attestation is the adapter's to report truthfully.
        // Until it has been queried, `false` is the honest answer and the core
        // MUST NOT assume otherwise.
        hardware_backed: false,
        ledger_capacity: twinvpn_diag::ring::DEFAULT_CAPACITY,
        event_capacity: twinvpn_core::events::DEFAULT_CAPACITY,
    })
    .ok()?;
    Some(Arc::new(CoreSink(core)))
}

/// This host's OS version, for MI-C3's `platform_ctx`.
///
/// **A stated gap:** the real answer is `sysctl kern.osproductversion`, which is
/// Darwin-only. An empty string is what a client receives until that is wired,
/// and MI-C3 requires the client to use it **verbatim** — so an empty value
/// renders as unknown rather than as a wrong version, which is the right
/// failure.
fn os_version() -> String {
    String::new()
}

/// The resolver engine of the **system-extension** binding.
///
/// Not a stub for a missing implementation: under
/// [`twinvpn_platform_macos::resolver::ResolverCarrier::TunnelSettings`] the OS
/// installs the resolver from the settings document, so there is nothing for an
/// engine to do and the correct behaviour for one that is asked anyway is to
/// refuse by name. A `DynamicStoreEngine` here would be a **second writer** for
/// a fact `NEPacketTunnelNetworkSettings.dnsSettings` already owns, which is the
/// I8 defect rather than a belt-and-braces measure.
#[derive(Debug)]
pub struct NoResolver;

impl twinvpn_platform_macos::netcfg::ResolverEngine for NoResolver {
    fn capture(
        &self,
        _service_id: &str,
    ) -> Result<twinvpn_platform_macos::resolver::RestorePoint, twinvpn_platform::PlatformError>
    {
        Err(twinvpn_platform::PlatformError::OsUnsupported(None))
    }

    fn persist(
        &self,
        _point: &twinvpn_platform_macos::resolver::RestorePoint,
    ) -> Result<(), twinvpn_platform::PlatformError> {
        Err(twinvpn_platform::PlatformError::OsUnsupported(None))
    }

    fn apply(
        &self,
        _plan: &twinvpn_platform_macos::resolver::ResolverPlan,
    ) -> Result<(), twinvpn_platform::PlatformError> {
        Err(twinvpn_platform::PlatformError::OsUnsupported(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_on_a_host_that_is_not_darwin_refuses_and_names_the_step() {
        // Not a Darwin test dressed up as a Linux one: the point is that a
        // refusal is a NAMED sequence rather than a panic or a half-built
        // authority.
        //
        // **Which** step refuses depends on the runner, and that is why it is
        // not pinned: an unprivileged runner stops at the privilege posture, and
        // a root one gets to the clocks, where
        // `ContinuousElapsedClock::from_kernel()` returns `None` off Darwin
        // because a clock with a guessed timebase is wrong by 41x on Apple
        // silicon. What is asserted is the property PS-18 actually states — it
        // did not reach `ready`, and it says which step stopped it.
        let sequence = Host::start(&ExtensionConfig::defaults()).expect_err("no Darwin here");
        assert!(!sequence.is_ready());
        let (step, code) = sequence.refusal().expect("a named refusal");
        assert!(
            matches!(step, start::Step::PrivilegePosture | start::Step::Clocks),
            "{step:?} is not a step this host could fail at"
        );
        assert!(code.as_str().contains('.'), "a registered code");
        // PS-18 again: the steps AFTER the refusal are absent rather than
        // recorded as passed, so a bundle shows how far it got.
        assert!(sequence.steps().len() < start::Step::ALL.len());
    }

    #[test]
    fn the_resolver_engine_of_this_binding_refuses_rather_than_writing_a_second_time() {
        // I8: `NEPacketTunnelNetworkSettings.dnsSettings` owns the resolver on
        // this carriage. An engine that also wrote `SCDynamicStore` would be a
        // second writer for one fact.
        use twinvpn_platform_macos::netcfg::ResolverEngine as _;
        assert!(NoResolver.capture("service").is_err());
        assert!(NoResolver
            .apply(&twinvpn_platform_macos::resolver::ResolverPlan::default())
            .is_err());
    }
}
