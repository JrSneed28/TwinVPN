//! `twinvpnd` — the macOS `LaunchDaemon`.
//!
//! **Authority:** ADR-0016 §11.6 (the start sequence), §11.5's macOS supervisor
//! row, PS-1, PS-3, PS-11, PS-17, PS-18; ADR-0018 CD-2; ADR-0022 LC-8;
//! `docs/implementation/ownership.md` §6 rule 7 (graceful shutdown).
//!
//! # What `main` does, and what it deliberately does not
//!
//! It builds the `Env`, builds the adapter, runs [`twinvpnd::agent::start`]'s
//! sequence, and either accepts connections or exits naming the step that
//! refused. **It contains no decision**: every branch here is on a
//! [`twinvpnd::agent::start::Outcome`] the sequence computed, and the sequence's
//! own branches are on facts the probes reported.
//!
//! # Nothing here has run
//!
//! This binary has never been linked. `make cross-check` type-checks it for
//! `aarch64-apple-darwin` with `-D warnings`; `cargo test` runs the modules it
//! calls, not this file. On a host that is not Darwin it refuses at the clock
//! step, which is correct: `ContinuousElapsedClock::from_kernel()` returns `None`
//! there, and a clock with a guessed timebase is wrong by 41x on Apple silicon.

use std::sync::Arc;

use twinvpn_env::{Env, EnvParts};
use twinvpnd::agent::{self, server, start};

/// The exit code a refused start produces.
///
/// **Not one of ADR-0017 §11.12's**: those are the CLI's, and a daemon that
/// exited 3 would be telling `launchd` something §11.12 never meant. `1` is what
/// a supervisor reads, and `KeepAlive={SuccessfulExit: false}` in the plist is
/// what turns it into a restart.
const EXIT_REFUSED: i32 = 1;

fn main() {
    let posture = agent::logging::install();
    if !posture.level_recognised {
        tracing::warn!(
            target: "twinvpn.agent",
            variable = agent::logging::LOG_LEVEL_ENV,
            fell_back_to = posture.level,
            "the configured log level was not recognised; a logging \
             misconfiguration must not be why a VPN agent will not run"
        );
    }
    if !posture.supervised {
        // PS-11: an unsupervised authority does not claim supervised guarantees.
        tracing::warn!(
            target: "twinvpn.agent",
            "no recognised supervisor started this process; the restart, throttle \
             and crash-loop guarantees of the LaunchDaemon plist do not apply"
        );
    }

    let config = agent::AgentConfig::from_env();
    match bring_up(&config) {
        Ok((sequence, context, listener)) => {
            report(&sequence);
            tracing::info!(
                target: "twinvpn.agent",
                version = twinvpnd::AGENT_VERSION,
                profile = twinvpnd::build_profile(),
                endpoint = %config.socket_path.display(),
                "ready"
            );
            accept_forever(listener, context);
        }
        Err(sequence) => {
            report(&sequence);
            std::process::exit(EXIT_REFUSED);
        }
    }
}

/// Logs what the sequence found.
fn report(sequence: &start::StartSequence) {
    for (step, code) in sequence.degradations() {
        tracing::warn!(
            target: "twinvpn.agent",
            step = step.tag(),
            reason_code = code.as_str(),
            "a start-sequence step reported a degradation; running wider than \
             declared is the defect PS-17 retires"
        );
    }
    if let Some((step, code)) = sequence.refusal() {
        tracing::error!(
            target: "twinvpn.agent",
            step = step.tag(),
            reason_code = code.as_str(),
            steps_completed = sequence.steps().len(),
            "the start sequence refused; PS-18 forbids running in a mode that \
             cannot arm enforcement while reporting itself as running"
        );
    }
}

/// Runs §11.6's sequence and, if it passes, hands back what it built.
///
/// The sequence is run **incrementally**: each probe is filled in as the thing it
/// describes is attempted, and [`start::run`] is called once at the end over the
/// facts. That ordering matters — a sequence run before anything was attempted
/// would be reporting on a host rather than on a start.
#[allow(clippy::type_complexity)]
fn bring_up(
    config: &agent::AgentConfig,
) -> Result<
    (
        start::StartSequence,
        server::ServerContext,
        tokio::net::UnixListener,
    ),
    start::StartSequence,
> {
    let mut probes = agent::DarwinProbes::new(config.clone());

    // --- ADR-0022 LC-8's three clocks, the CSPRNG, and the boot identity -----
    let elapsed = twinvpn_platform_macos::ContinuousElapsedClock::from_kernel();
    let entropy = Arc::new(twinvpn_platform_macos::SystemEntropy::new());
    let boot_id = twinvpn_platform_macos::clock::BootSessionId::read();
    let runtime = twinvpn_env::binding::tokio_rt::TokioRuntime::work_stealing();
    probes.with_clocks(elapsed.is_some() && entropy.probe().is_ok() && boot_id.is_ok());
    // **W-43.** `twinvpn-env`'s `TokioRuntime` once built with `enable_time()` and
    // not `enable_io()`, so no socket could be opened at all and the agent
    // panicked on a client's first command. Fixed; the probe stays, because
    // PS-18's rule is to refuse at startup rather than report a running agent
    // that can do nothing.
    probes.with_runtime_io(runtime.is_ok());

    let (Some(elapsed), Ok(runtime)) = (elapsed, runtime) else {
        return Err(start::run(&probes));
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
        // synchronised the clock through any API this crate can reach, so the
        // honest declaration is `Unsynchronised` — a reading is reported as
        // `Offset`, never as `Trusted`, and nothing that needs a trusted wall
        // clock silently gets an untrusted one. Named as a gap in the README.
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

    // --- the adapter, and its declared posture ------------------------------
    //
    // `SCDynamicStore` is Darwin-only, so the engine is chosen behind the one
    // `cfg` this crate has. It is here rather than in `agent::daemon_carriers`
    // deliberately: a `cfg` in a library function would be an OS branch in a
    // shell module, and one in `main` is the process choosing its own carrier.
    #[cfg(target_os = "macos")]
    let resolver: Arc<dyn twinvpn_platform_macos::netcfg::ResolverEngine> =
        Arc::new(twinvpn_platform_macos::dynstore::DynamicStoreEngine::new(
            twinvpn_platform_macos::resolver::RESTORE_POINT_PATH.into(),
        ));
    #[cfg(not(target_os = "macos"))]
    let resolver: Arc<dyn twinvpn_platform_macos::netcfg::ResolverEngine> = Arc::new(NoResolver);

    let carriers = agent::daemon_carriers(resolver, String::new());
    let adapter = agent::build_adapter(config, carriers);
    probes.with_posture(adapter.posture());

    // --- §11.6 (2): reclaim, then **read back** (KS-20, PS-8, W-24) ----------
    //
    // The read-back is the only thing that sets the probe. A flag set because a
    // load returned `Ok` is exactly what W-24 rejects.
    if let Ok(assertion) = adapter.network().assertion() {
        probes.with_read_back(&assertion);
    }

    // --- §11.6 (5): the core, ABI-checked first (VR-4) ----------------------
    let core = host_core(env, &adapter);
    probes.with_core(core.is_some());

    // --- §11.6 (6): the MI endpoint (MI-A3) ---------------------------------
    let listener = agent::endpoint::bind(&config.socket_path, config.groups.observe);
    probes.with_endpoint(listener.is_ok());

    let sequence = start::run(&probes);
    match (sequence.is_ready(), core, listener) {
        (true, Some(core), Ok(listener)) => Ok((
            sequence,
            server::ServerContext {
                core,
                policy: config.groups,
                os_version: os_version(),
                elapsed,
            },
            listener,
        )),
        _ => Err(sequence),
    }
}

/// Constructs the core, ABI-checked first (**VR-4**).
///
/// `None` makes §11.6's `Core` step refuse, which is the honest outcome in a
/// build compiled without `core-host`: an agent that accepted connections with
/// nothing behind them would be reporting itself as running while answering
/// nothing, which is exactly PS-18's condition.
#[cfg(feature = "core-host")]
fn host_core(
    env: Env,
    adapter: &Arc<twinvpn_platform_macos::MacosPlatformAdapter>,
) -> Option<Arc<dyn server::CommandSink>> {
    struct CoreSink(twinvpn_core::Core);

    impl server::CommandSink for CoreSink {
        fn submit(
            &self,
            submission: &twinvpn_mgmt::Submission,
        ) -> Result<(), Box<twinvpn_types::Diagnostic>> {
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

/// The same, in a build that does not host a core.
///
/// Refuses by name rather than accepting connections with nothing behind them.
#[cfg(not(feature = "core-host"))]
fn host_core(
    _env: Env,
    _adapter: &Arc<twinvpn_platform_macos::MacosPlatformAdapter>,
) -> Option<Arc<dyn server::CommandSink>> {
    None
}

/// A resolver engine on a host with no `SCDynamicStore`.
///
/// Present so `main` compiles off Darwin. It is unreachable there in practice —
/// the sequence refuses at the clock step first — and every method refuses by
/// name rather than succeeding quietly.
#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct NoResolver;

#[cfg(not(target_os = "macos"))]
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

/// This host's OS version, for MI-C3's `platform_ctx`.
///
/// **A stated gap:** the real answer is `sysctl kern.osproductversion`, which is
/// Darwin-only. An empty string is what a client receives until that is wired,
/// and MI-C3 requires the client to use it **verbatim** — so an empty value
/// renders as unknown rather than as a wrong version, which is the right failure.
fn os_version() -> String {
    String::new()
}

/// Accepts connections until the process ends.
///
/// **PS-3**: a client going away changes nothing. Each connection is served on
/// its own task and its failure is logged, never propagated — the loss of the
/// last management client must not change `session_intent`, the enforcement mode,
/// the installed rule set or the `ConnectionState`.
fn accept_forever(listener: tokio::net::UnixListener, context: server::ServerContext) -> ! {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| {
            tracing::error!(target: "twinvpn.agent", %error, "the accept runtime failed to build");
            std::process::exit(EXIT_REFUSED);
        });
    runtime.block_on(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let context = context.clone();
                    tokio::spawn(async move {
                        let ending = server::serve(stream, &context).await;
                        // Every ending is a log line and nothing else. PS-3.
                        tracing::debug!(
                            target: "twinvpn.mi",
                            ?ending,
                            "a management connection ended"
                        );
                    });
                }
                Err(error) => {
                    // A failed accept is not a reason to stop accepting: the
                    // authority's job outlives any one client, and exiting here
                    // would make a transient fd exhaustion into a dropped tunnel.
                    tracing::warn!(target: "twinvpn.mi", %error, "accept failed");
                }
            }
        }
    })
}
