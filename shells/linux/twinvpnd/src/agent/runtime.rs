//! Building the `Env`, the adapter and the core — and taking them down again.
//!
//! **Authority:** ADR-0018 CD-1 (the three clocks), CD-2 (every component takes
//! its `Env` at construction), CD-3, §11.3 (the two runtime bindings), §11.16
//! (a) (S-47: exactly one process holds a mutating core handle);
//! ADR-0022 LC-8; ADR-0016 §11.6 (the start order); `ownership.md` §6 rule 7 and
//! §8 **W-7** and **W-28**.
//!
//! # W-7: this is where the three clocks are bound, together
//!
//! `twinvpn-env` ships no production `ElapsedClock` and no production `Entropy`,
//! because reaching either needs `unsafe` or an OS branch. [`build_env`] is the
//! one place all three clocks are named at once, so a reviewer asking "does this
//! build have the suspend-inclusive clock" reads one function:
//!
//! | Capability | Binding | Suspend |
//! |---|---|---|
//! | `MonotonicClock` | `SystemMonotonicClock` (`CLOCK_MONOTONIC`) | **excluded** |
//! | `ElapsedClock` | `BootTimeElapsedClock` (`CLOCK_BOOTTIME`) | **included** |
//! | `WallClock` | `SystemWallClock` | evidence only |
//!
//! Substituting the monotonic clock for the elapsed one "compiles, passes every
//! test that does not suspend, and fails only on a device that actually sleeps".
//! [`build_env`]'s own test reads both and asserts their origins differ.
//!
//! # W-28: the crash window, stated
//!
//! `CoreSessionJournal` is **write-behind**: a successful `persist` means
//! *queued*, not durable, and `StoreBridge::flush` drains the queue into one
//! transaction. So the agent's shutdown path must flush, and
//! [`Agent::shutdown`] does — before the runtime stops accepting work, because a
//! flush scheduled after that would never run.
//!
//! **The crash window this build actually has:** every session transition
//! between the last successful flush and an abrupt `SIGKILL` or a power loss is
//! lost. A `SIGTERM` is flushed (that is what [`Agent::shutdown`] is for), and
//! `docs/reliability.md` §6.5's resumption guarantee survives either way,
//! because resumption re-derives from the control plane rather than from the
//! journal. What is lost is the *local* record of the most recent transitions —
//! which is a diagnostics loss, not a correctness one. Stated rather than
//! implied.

use std::sync::Arc;

use twinvpn_env::binding::system::{SystemMonotonicClock, SystemWallClock, WallClockTrust};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{
    ElapsedClock, Env, EnvError, EnvParts, MonotonicClock, OffsetSource, SystemRngSource,
};
use twinvpn_platform_linux::{BootTimeElapsedClock, LinuxPlatformAdapter, SystemEntropy};

/// Why the agent could not start.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// A capability could not be bound.
    #[error("an environment capability could not be bound")]
    Env(#[from] EnvError),
    /// The core refused to be created.
    ///
    /// **VR-4**: an `abi_major` mismatch "is a **packaging defect**, not an
    /// operating state — but it is still checked, because the alternative is
    /// undefined behaviour".
    #[error("the core refused to be created: {code}")]
    Core {
        /// The registered code the core named.
        code: String,
    },
}

/// Binds all three clocks, the timer, the runtime and the two randomness
/// sources.
///
/// # Errors
///
/// [`EnvError`] if the OS refuses the runtime's threads or the CSPRNG cannot be
/// read. **The entropy source is probed here**, not on first use: a CSPRNG that
/// fails mid-stream poisons the core (F-7), and finding out at startup is
/// strictly better than finding out during a handshake.
pub fn build_env() -> Result<(Env, Arc<TokioRuntime>), EnvError> {
    let monotonic: Arc<dyn MonotonicClock> = Arc::new(SystemMonotonicClock::new());
    // **W-7's whole point.** `CLOCK_BOOTTIME`, not `CLOCK_MONOTONIC`.
    let elapsed: Arc<dyn ElapsedClock> = BootTimeElapsedClock::shared();

    let entropy = Arc::new(SystemEntropy::new());
    entropy.probe()?;
    let entropy: Arc<dyn twinvpn_env::Entropy> = entropy;

    // ADR-0018 §11.3: the **work-stealing** binding on Linux.
    let runtime = Arc::new(TokioRuntime::work_stealing()?);
    let timer = runtime.timer(Arc::clone(&monotonic));

    let env = Env::new(EnvParts {
        monotonic,
        elapsed,
        // CD-1a: the platform's synchronisation claim is a CONSTRUCTOR ARGUMENT,
        // never an assumption. A shell that cannot answer "is this clock
        // synchronised" passes `Unsynchronised`, and the reading is reported as
        // an offset rather than as trusted. This build does not query
        // `timedatectl`, so the honest answer is that it makes no claim.
        // `PersistedLastKnown` is the honest source tag: the value comes from
        // `CLOCK_REALTIME`, which on a host with an RTC is exactly "persisted
        // from a previous run of this device" and on one without is below the
        // plausibility floor and reported as `Unset` regardless.
        wall: Arc::new(SystemWallClock::new(WallClockTrust::Unsynchronised(
            OffsetSource::PersistedLastKnown,
        ))),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn twinvpn_env::Runtime>,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    Ok((env, runtime))
}

/// Whether the injected runtime can register a file descriptor.
///
/// # W-43: `twinvpn-env`'s production runtime has no I/O driver
///
/// `twinvpn_env::binding::tokio_rt::TokioRuntime`'s two constructors both build
/// with `.enable_time()` and **not** `.enable_io()`. `tokio` then panics —
/// *"A Tokio 1.x context was found, but IO is disabled"* — the first time
/// anything registers an fd on that runtime.
///
/// Every socket this adapter opens goes through `tokio::io::unix::AsyncFd`: the
/// UDP sockets the NAT ladder needs, the `rtnetlink` sockets that enumerate
/// interfaces and program routes, and the tun device itself. So on a production
/// `Env` **none of them can be opened**, and `twinvpnd` panics the first time a
/// command reaches the adapter. Measured, not inferred: the panic reproduces
/// through `SocketProvider::bind_udp` on an `Env` built by [`build_env`].
///
/// `twinvpn-env` is `core-foundation`'s and the fix is one line there
/// (`.enable_io()`, or `.enable_all()`). **This shell does not supply a second
/// runtime binding to work around it** — ADR-0018 §11.3 fixes the two bindings
/// that ship, and a shell-local third would be exactly the duplicate the rule
/// exists to prevent.
///
/// What the shell owes instead is PS-18's shape: *"The authority MUST NOT start
/// in a mode that cannot arm enforcement while reporting itself as running."* A
/// runtime that cannot open a socket cannot do anything, so this turns a
/// mid-flight panic on a client's first command into a **refusal at startup**,
/// which is the difference between a diagnosable failure and a mystery.
///
/// The panic is caught rather than predicted: `catch_unwind` here is the same
/// containment F-7 uses at the ABI boundary, and it means this probe keeps
/// working if the failure mode ever changes shape.
#[must_use]
pub fn runtime_can_drive_io(env: &Env) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut opened = false;
        twinvpn_env::Runtime::block_on(
            env.runtime().as_ref(),
            Box::pin(async {
                let provider = twinvpn_platform_linux::sock::LinuxSocketProvider::new(
                    twinvpn_platform_linux::ShutdownLatch::new(),
                );
                opened = twinvpn_platform::SocketProvider::bind_udp(
                    &provider,
                    &twinvpn_platform::UdpBindSpec {
                        family: twinvpn_platform::SocketFamily::V4,
                        local: None,
                        options: twinvpn_platform::SocketOptions::default(),
                    },
                )
                .await
                .is_ok();
            }),
        );
        opened
    }))
    .unwrap_or(false)
}

/// Why the owner-tagged ruleset could not be armed.
#[derive(Debug, thiserror::Error)]
pub enum ArmError {
    /// The install was refused.
    #[error("the enforcement ruleset could not be armed: {0}")]
    Install(twinvpn_platform::PlatformError),
    /// The install reported success and the kernel holds no TwinVPN table.
    #[error("the ruleset install reported success and the kernel holds no TwinVPN table")]
    NotInstalled,
    /// The installed ruleset could not be read back.
    ///
    /// O-18's fail-safe direction: an assertion that cannot be produced is not
    /// an assertion that protection holds.
    #[error("the installed ruleset could not be read back: {0}")]
    Unreadable(twinvpn_platform::PlatformError),
}

impl ArmError {
    /// The registered code.
    ///
    /// ADR-0012 §11.12 contributes `POLICY.KILLSWITCH.ARM_FAILED`, which **is**
    /// registered (FATAL / CRITICAL) — so it is emitted directly rather than
    /// substituted.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "POLICY.KILLSWITCH.ARM_FAILED"
    }
}

/// §11.6 step (2): reclaim or re-assert the owner-tagged ruleset, and **verify
/// it took**.
///
/// # Review finding R-7
///
/// This step used to set a flag to `true` and do nothing, on the reasoning that
/// "the core's own first `apply` installs the rules". `apply` had **no caller
/// anywhere in the product**, so on a Linux host the KS-19 boot table was the
/// only enforcement that ever existed — and its scope is the overlay space
/// alone. On a full-tunnel host that means all Internet traffic egressed
/// untunneled, from boot, indefinitely. **I3 did not hold for the composed
/// product.**
///
/// §11.6 step (2) is unambiguous that this is the AUTHORITY's job and not the
/// core's: "the owner-tagged rule set is **reclaimed or re-asserted** (KS-20,
/// PS-8)" is listed among the things that must happen *before* it accepts
/// management connections.
///
/// # Three things happen, and the third is the one that matters
///
/// 1. `set_ruleset(generation 0, BLOCKED)` — an atomic swap into the posture
///    ADR-0012 §11.8's boot row fixes. **Reclamation rather than creation**: the
///    script's `add table` / `delete table` / `table {` replaces whatever this
///    host already had under our owner tag, including a table a crashed
///    predecessor left (KS-20).
/// 2. `installed_ruleset()` — the **W-24 query**, read from the kernel's own
///    answer rather than from the fact that step 1 returned `Ok`.
/// 3. The read-back must report a posture. Review finding **R-6** is why that is
///    checked separately: a table can hold `posture_blocked` and drop nothing,
///    and step 1 would return `Ok` for it.
///
/// Arming `RULESET_BLOCKED` is **not a decision** (CB-2): ADR-0012 §11.8's boot
/// row fixes the posture a host starts in, and the scope comes from
/// `nft::baseline_protected`, which is the product's own address space and the
/// same pair the boot artifact carries.
///
/// # Errors
///
/// [`ArmError`], which the caller makes **fatal**. ADR-0012 §8: if the ruleset
/// cannot be installed the client refuses to enter a protected state, and PS-18
/// forbids starting "in a mode that cannot arm enforcement while reporting
/// itself as running". Continuing would report a running agent on an unprotected
/// host, which is the single worst outcome available.
pub fn arm_owner_tagged_ruleset(
    runtime: &Arc<TokioRuntime>,
    adapter: &Arc<LinuxPlatformAdapter>,
) -> Result<(), ArmError> {
    use twinvpn_platform::{ContractGeneration, Ruleset};

    let mut outcome: Result<(), ArmError> = Ok(());
    {
        let slot = &mut outcome;
        let adapter = Arc::clone(adapter);
        twinvpn_env::Runtime::block_on(
            runtime.as_ref(),
            Box::pin(async move {
                let network = twinvpn_platform::PlatformAdapter::network_config(adapter.as_ref());
                // Generation 0: no contract has been applied.
                if let Err(error) = twinvpn_platform::NetworkConfig::set_ruleset(
                    network,
                    ContractGeneration(0),
                    Ruleset::Blocked,
                )
                .await
                {
                    *slot = Err(ArmError::Install(error));
                    return;
                }
                match twinvpn_platform::NetworkConfig::installed_ruleset(network).await {
                    Ok(Some(posture)) => tracing::info!(
                        target: "twinvpn.enforce",
                        ?posture,
                        "the owner-tagged ruleset is armed, and was read back from the kernel"
                    ),
                    Ok(None) => *slot = Err(ArmError::NotInstalled),
                    Err(error) => *slot = Err(ArmError::Unreadable(error)),
                }
            }),
        );
    }
    outcome
}

/// Why the durable store could not be opened at startup (R-10).
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The store's own ladder refused, naming a `STORE.*` code.
    #[error("the durable store could not be opened: {0}")]
    Open(String),
}

impl VaultError {
    /// The registered code this refusal carries.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            // The whole `STORE.*` ladder collapses onto the one code the
            // startup refusal table knows. The store's own code is carried in
            // `detail`, so nothing is lost.
            VaultError::Open(_) => "STORE.CUSTODY_DEGRADED",
        }
    }
}

/// **§11.6 step (4b) — open the durable store.**
///
/// # Review finding R-10
///
/// `Core::open_store` existed, worked, and had **only test callers**. The agent
/// set `state_rehydrated = true` and opened nothing, so S-12, S-15, S-27, S-30
/// and S-37 were memory-only for the life of the process and W-28's crash
/// window was the whole process lifetime. Two domains each documented that the
/// *other* end was wired.
///
/// This is that call. It runs **before** the endpoint accepts connections, so
/// no management command can observe a core whose persistence is not yet
/// established, and it hydrates §6.5's resumed sessions in the same step.
///
/// # Why a failure is a refusal rather than a warning
///
/// PS-18 forbids starting "in a mode that cannot arm enforcement while
/// reporting itself as running", and the same reasoning applies to the store: a
/// daemon that came up with a silently memory-only vault would report every
/// write as durable, accept a revocation, and lose the never-shrinking set on
/// the next restart. The store's own ST-24 ladder already distinguishes a
/// degraded-but-usable rung — which opens successfully and publishes
/// `STORE.CUSTODY_DEGRADED` — from an unusable one, so what reaches here is
/// the second kind.
///
/// # Errors
///
/// [`VaultError::Open`] carrying the `STORE.*` code the ladder produced.
pub fn open_vault_at_startup(
    runtime: &Arc<TokioRuntime>,
    core: &Arc<twinvpn_core::Core>,
) -> Result<(), VaultError> {
    let mut outcome: Result<(), VaultError> = Ok(());
    {
        let slot = &mut outcome;
        let core = Arc::clone(core);
        twinvpn_env::Runtime::block_on(
            runtime.as_ref(),
            Box::pin(async move {
                match core.open_store().await {
                    Ok(state) => tracing::info!(
                        target: "twinvpn.store",
                        ?state,
                        "the durable store is open; S-12/S-15/S-27/S-30/S-37 survive a restart"
                    ),
                    Err(diagnostic) => {
                        *slot = Err(VaultError::Open(diagnostic.code().as_str().to_owned()));
                    }
                }
            }),
        );
    }
    outcome
}

/// The running agent: one `Env`, one adapter, one core.
///
/// **S-47**: "exactly **one process** \[holds\] a mutating core handle at a time",
/// and one adapter object, "because a core that assembled its platform from six
/// independently-supplied pieces could not state which adapter it was talking
/// to".
pub struct Agent {
    /// The injected environment.
    pub env: Env,
    /// The platform seam.
    pub adapter: Arc<LinuxPlatformAdapter>,
    /// The hosted core.
    pub core: Arc<twinvpn_core::Core>,
}

impl Agent {
    /// Begins graceful shutdown, in the order `ownership.md` §6 rule 7 and
    /// [`twinvpn_core::Core::begin_shutdown`] fix.
    ///
    /// > the runtime stops accepting work, the event stream closes so a drain
    /// > thread unblocks, and the adapter is told last — and telling the adapter
    /// > **does not** remove the installed ruleset, because CB-6 puts it in the
    /// > OS's custody so that the core going away cannot drop protection.
    ///
    /// # W-28's flush
    ///
    /// The journal is write-behind, so a successful `persist` means *queued*.
    /// The drain has to happen **before** the runtime stops accepting work, or
    /// the flush is scheduled onto a runtime that will not run it. The core's
    /// own `begin_shutdown` does the rest in the right order.
    pub fn shutdown(&self) {
        tracing::info!(
            target: "twinvpn.agent",
            "shutting down: draining the write-behind journal, then closing the event stream"
        );
        // The core owns the bridge and its flush; calling `begin_shutdown` is
        // how the shell asks for the whole sequence rather than reaching past it
        // into the store, which would be a second writer (CD-I5's direction
        // applied to the store).
        self.core.begin_shutdown();
        tracing::info!(
            target: "twinvpn.agent",
            custody_survives_exit = twinvpn_platform::NetworkConfig::enforcement_custody(
                self.adapter.network()
            )
            .survives_core_exit(),
            "the installed enforcement ruleset is left in the OS's custody (CB-6)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_clocks_are_bound_and_the_elapsed_one_is_not_the_monotonic_one() {
        // W-7, and LC-8's invisible-on-CI failure. `SystemMonotonicClock` zeroes
        // at construction; the elapsed clock is absolute since boot. A build
        // that substituted one for the other would read near zero here.
        let (env, _runtime) = build_env().expect("binds every capability");
        let monotonic = env.now_monotonic().as_micros();
        let elapsed = env.now_elapsed().as_micros();
        assert!(
            monotonic < 1_000_000,
            "monotonic zeroes at construction: {monotonic}"
        );
        assert!(
            elapsed > 1_000_000,
            "the elapsed clock must be CLOCK_BOOTTIME, absolute since boot: {elapsed}"
        );
        // And the wall clock is a three-state value, never a bare timestamp.
        assert!(!matches!(
            env.now_wall(),
            twinvpn_env::WallClockReading::Trusted { .. }
        ));
    }

    #[test]
    fn the_randomness_is_not_deterministic_in_production() {
        // TwinLab asserts `is_deterministic()` before declaring a BIT class, so
        // a production `Env` that claimed determinism would let a determinism
        // claim be made about a production run by mistake.
        let (env, _runtime) = build_env().expect("binds");
        assert!(!env.is_deterministic());
        let mut rng = env
            .rng_for(twinvpn_env::consumers::BACKOFF_JITTER)
            .expect("a stream");
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        assert_ne!(a, b);
    }

    /// **R-7.** The arm is a real call whose failure is fatal, not a flag.
    ///
    /// On this host `nft(8)` is absent, so the install fails — which is the
    /// assertion: arming reports a **named** failure rather than the `true` the
    /// old code returned unconditionally. On a host with `nft` the same call
    /// installs the table and reads it back.
    #[test]
    fn arming_is_a_real_call_and_its_failure_is_named() {
        let (env, tokio_runtime) = build_env().expect("binds");
        let _ = env;
        let adapter = Arc::new(LinuxPlatformAdapter::new(
            twinvpn_platform_linux::LinuxAdapterParts {
                enforcement: twinvpn_platform_linux::EnforcementConfig {
                    overlay_interface: "twin0".to_owned(),
                    firewall_mark: twinvpn_platform_linux::DEFAULT_FWMARK,
                    cgroup_path: None,
                    local_network_access: true,
                    on_link_prefixes: Vec::new(),
                    doh_endpoints: Vec::new(),
                },
                store_root: std::env::temp_dir().join("twinvpn-arm-test"),
                resolver_restore_point: std::env::temp_dir().join("twinvpn-arm-test.restore"),
                identity_element: Arc::new(twinvpn_platform_linux::AbsentElement),
            },
        ));

        match arm_owner_tagged_ruleset(&tokio_runtime, &adapter) {
            Ok(()) => {
                // `nft(8)` is present and the table installed AND read back.
                assert!(adapter.posture().nft_present);
            }
            Err(error) => {
                // ADR-0012 §11.12's code, which IS registered — emitted directly
                // rather than substituted.
                assert_eq!(error.reason_code(), "POLICY.KILLSWITCH.ARM_FAILED");
                assert!(
                    twinvpn_types::ReasonCode::lookup(error.reason_code()).is_some(),
                    "the arm failure must name a registered code"
                );
                // And it is FATAL/CRITICAL, which is what makes the caller's
                // refusal to start the right response (PS-18).
                let code =
                    twinvpn_types::ReasonCode::lookup(error.reason_code()).expect("registered");
                assert_eq!(code.class(), twinvpn_types::ErrorClass::Fatal);
            }
        }
    }

    #[test]
    fn the_entropy_source_is_probed_at_startup_not_on_first_use() {
        // A CSPRNG that fails mid-stream poisons the instance (F-7). Finding out
        // at startup is strictly better than finding out during a handshake.
        SystemEntropy::new()
            .probe()
            .expect("the platform CSPRNG is seeded");
    }
}
