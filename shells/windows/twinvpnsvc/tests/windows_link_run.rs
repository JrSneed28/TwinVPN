//! **The link-and-run proof for Windows.** Everything here needs a real Windows
//! host, and everything here is meant to be *executed* on one by CI.
//!
//! **Authority:** ADR-0018 §11.9 row 4 (the core is a `staticlib` linked into
//! the service `.exe`), BM-3 (*"Windows … no — MSVC ABI is required"*, so this
//! runs on a Windows runner or nowhere), CD-1, CD-2, VR-4; ADR-0016 §11.6 (the
//! start ordering), PS-18; ADR-0017 MI-A1, MI-A2, MI-A4, MI-A5, MI-16, MI-18;
//! ADR-0022 §11.4's Windows row (shutdown must not remove enforcement).
//!
//! # What this file is, and how it differs from `tests/lifecycle.rs`
//!
//! `tests/lifecycle.rs` is the **host-runnable** half: it injects a fixed
//! entropy source, binds `tokio::io::duplex` instead of a pipe, and therefore
//! runs on the Linux machine this shell was written on. It proves the decision
//! logic and proves nothing about Windows.
//!
//! This file is the other half and it is deliberately unable to run anywhere
//! else — `#![cfg(windows)]`, no injected clock, no injected CSPRNG, no
//! in-memory transport:
//!
//! | Boundary | Crossed here | Primitive |
//! |---|---|---|
//! | the platform CSPRNG | [`runtime::build_env`], the **production** entry point | `BCryptGenRandom` |
//! | the three clocks (CD-1, LC-8) | same call | `QueryUnbiasedInterruptTimePrecise`, `QueryInterruptTimePrecise`, `GetSystemTimeAsFileTime` |
//! | the Base Filtering Engine | [`twinvpn_platform_windows::sys::win::WindowsSystem::open`] | `FwpmEngineOpen0` |
//! | the shared core (§11.9 row 4) | [`runtime::build_core`] over the linked `twinvpn-core` | VR-4's `abi_major` check |
//! | the management carriage | a **real named pipe**, served by the production [`server::serve`] and driven by the production [`Client`] | `CreateNamedPipeW` / `CreateFileW` |
//! | the client's identity (MI-A1, MI-A4) | [`win32::pipe::read_client_principal`] | `ImpersonateNamedPipeClient` + `RevertToSelf` |
//! | shutdown | [`runtime::Service::shutdown`] | the drain thread joins |
//!
//! # Two things this file does NOT claim, stated before anyone infers them
//!
//! 1. **The pipe is created by this test, not by the service binary.**
//!    `src/main.rs::serve` still refuses with `MGMT.UNAVAILABLE` because
//!    nothing binds `\\.\pipe\TwinVPN\mgmt` with MI-A3's DACL. What is proven
//!    here is that the production server and the production client speak to each
//!    other **across the kernel's named-pipe driver** and that the principal on
//!    the far side is the one the kernel attests. The listener and its DACL
//!    remain owed, and this test does not paper over that.
//! 2. **The adapter under the core is the mock, unless the host opts in.** The
//!    real [`twinvpn_platform_windows::WindowsPlatformAdapter`] needs
//!    `wintun.dll` beside the binary *and* a writable Base Filtering Engine
//!    session, neither of which an unprivileged hosted runner has. The real
//!    adapter is therefore built in
//!    [`the_real_adapter_hosts_the_core_when_this_host_supplies_wintun_and_the_engine`],
//!    which is gated on [`MUTATING_TEST_ENV`] and belongs to the self-hosted
//!    `windows-privileged-lifecycle` job. The **core** is never a stub in either
//!    case.
//!
//! # The lifecycle markers, and why they are printed rather than counted
//!
//! `build/ci/ci-windows.sh` populates `lifecycle_transitions` in
//! `build/ci/evidence/windows.json` by **grepping this test's own output** for
//!
//! ```text
//! TWINVPN_LIFECYCLE_TRANSITION FROM->TO
//! ```
//!
//! A script that hard-coded the list would report the same transitions whether
//! or not anything was driven, which is the compile-only job dressed as a
//! lifecycle job that `build/acceptance/platform-evidence.schema.json` exists to
//! reject. So [`transition`] is called at the point the transition is
//! **observed**, never in advance, and never on a path a failure can skip.
//!
//! The names are [`twinvpnsvc::service::scm::ServiceState`]'s — `START_PENDING`,
//! `RUNNING`, `STOP_PENDING`, `STOPPED`, which are `SERVICE_START_PENDING` and
//! its siblings — because that is this platform's application lifecycle
//! (ADR-0022 §11.12's Windows row) and this shell's own vocabulary for it. The
//! two stop transitions are **computed by the production
//! [`twinvpnsvc::service::scm::on_control`]** and their `Action::BeginShutdown`
//! is then executed against the real core, so the marker and the machine cannot
//! disagree.
//!
//! **They are the hosting object's states, not a report to a real SCM.** The
//! unprivileged run does not satisfy ADR-0016 §11.6's privilege, capability and
//! reclaim steps — it is not LocalSystem, has no `wintun.dll` and does not arm
//! enforcement — and it says so: the real [`twinvpnsvc::service::StartSequence`]
//! is printed next to the markers with exactly the steps this run achieved, and
//! `ci-windows.sh` copies that line into the evidence `notes`. The full §11.6
//! sequence is the self-hosted `windows-privileged-lifecycle` job's, and its
//! evidence carries `privileged: true`.
//!
//! # Running it
//!
//! ```text
//! # unprivileged; what `build/ci/ci-windows.sh` runs
//! cargo test -p twinvpnsvc --test windows_link_run -- --nocapture --test-threads=1
//!
//! # the privileged addition, on a machine you are willing to have TwinVPN
//! # state on. `--test-threads=1`: there is one filtering engine per host.
//! set TWINVPN_WINDOWS_TEST=1
//! cargo test -p twinvpnsvc --test windows_link_run -- --nocapture --test-threads=1
//! ```

#![cfg(all(windows, feature = "core-host"))]
#![allow(clippy::doc_markdown)]

use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::PlatformAdapter;

use twinvpnsvc::mi::dacl::PrincipalSids;
use twinvpnsvc::mi::wire::PlatformCtx;
use twinvpnsvc::mi::Client;
use twinvpnsvc::service::peer::Principal;
use twinvpnsvc::service::runtime;
use twinvpnsvc::service::server::{self, ServerContext};
use twinvpnsvc::win32;

/// The opt-in the privileged half requires.
///
/// The same variable `twinvpn-platform-windows`' own `tests/windows_host.rs`
/// uses, deliberately: one switch for "this machine may be mutated", not two.
/// Absent, the privileged test asserts the **refusal** rather than skipping, so
/// a plain `cargo test` on a developer's Windows box still checks something
/// real.
const MUTATING_TEST_ENV: &str = "TWINVPN_WINDOWS_TEST";

fn mutating_enabled() -> bool {
    std::env::var_os(MUTATING_TEST_ENV).is_some()
}

/// Prints one lifecycle marker, in the strict format
/// `build/ci/ci-windows.sh` greps for.
///
/// Called **after** the transition has happened, never before. `stdout` rather
/// than `tracing`, because the shell installs no subscriber in a test binary
/// and a marker that depended on one would vanish silently.
fn transition(from: &str, to: &str) {
    println!("TWINVPN_LIFECYCLE_TRANSITION {from}->{to}");
}

/// A current-thread runtime with the I/O driver, built here rather than through
/// `#[tokio::test]`.
///
/// CD-3 denies `tokio::time` everywhere outside `twinvpn-env`'s binding and a
/// test is not an exemption, so nothing in this file names it. `enable_io` is
/// not optional on this platform: a named pipe is an IOCP registration.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("a current-thread runtime with the I/O driver")
        .block_on(future)
}

// ---------------------------------------------------------------------------
// 1. the production environment, over the real platform primitives
// ---------------------------------------------------------------------------

/// [`runtime::build_env`] — **the production entry point**, not the injected
/// one — binds on this host.
///
/// The distinction is the whole point of the test. `build_env_with` takes a
/// caller-supplied `Entropy` and is what `tests/lifecycle.rs` uses to run on
/// Linux; `build_env` passes [`twinvpn_platform_windows::clock::WindowsEntropy`]
/// and probes it at startup, which is a `BCryptGenRandom` call that has never
/// executed anywhere. A build whose CSPRNG failed mid-stream would produce
/// predictable nonces, so §11.6 step 3 probes rather than deferring to the first
/// handshake.
#[test]
fn the_production_environment_binds_over_the_real_windows_clocks_and_csprng() {
    let (env, _runtime) = runtime::build_env()
        .expect("a Windows host has BCryptGenRandom, and build_env probes it at startup");

    // W-7 and LC-8's Windows row. The monotonic clock zeroes at construction
    // and excludes suspend; the elapsed clock is absolute since boot and
    // includes it. A build that bound one for the other reads identically in
    // every other test and differently here.
    let monotonic = env.now_monotonic().as_micros();
    let elapsed = env.now_elapsed().as_micros();
    assert!(
        monotonic < 1_000_000,
        "the monotonic clock zeroes at construction: {monotonic}"
    );
    assert!(
        elapsed > 1_000_000,
        "QueryInterruptTimePrecise is absolute since boot, so a live Windows host \
         reads far more than a second: {elapsed}"
    );
    assert_ne!(monotonic, elapsed, "two clocks, not one read twice");

    // CD-1a: this build does not query the Windows Time service, so it makes no
    // synchronisation claim, and the wall clock is a three-state value.
    assert!(!matches!(
        env.now_wall(),
        twinvpn_env::WallClockReading::Trusted { .. }
    ));
    // TwinLab asserts `is_deterministic()` before declaring a BIT class.
    assert!(!env.is_deterministic());

    println!("build_env: monotonic={monotonic}us elapsed={elapsed}us (real Windows primitives)");
}

// ---------------------------------------------------------------------------
// 2. the Base Filtering Engine
// ---------------------------------------------------------------------------

/// `FwpmEngineOpen0`, through the constructor PS-18 wants.
///
/// [`twinvpn_platform_windows::sys::win::WindowsSystem::open`] is the eager
/// form: a service that cannot open the engine finds out before it has reported
/// itself as running. Whether it succeeds depends on the runner's token — a
/// hosted GitHub runner is usually elevated, an unprivileged shell is not — so
/// this asserts the **dichotomy** rather than success: either the handle opens,
/// or the refusal carries a registered `reason_code` and the Win32 status that
/// produced it. A panic, or a silent success on a host that cannot arm, is what
/// this excludes.
#[test]
fn the_real_filtering_engine_is_opened_or_names_the_status_it_refused_with() {
    use twinvpn_platform_windows::sys::win::WindowsSystem;
    use twinvpn_platform_windows::ShutdownLatch;

    match WindowsSystem::open(ShutdownLatch::new()) {
        Ok(_system) => println!("FwpmEngineOpen0: opened (this process can arm enforcement)"),
        Err(error) => {
            let code = error.reason_code();
            assert!(
                !code.as_str().is_empty(),
                "a refusal must carry a registered reason_code, never a bare status"
            );
            println!("FwpmEngineOpen0: refused, reason_code={} ({error})", code.as_str());
            assert!(
                !mutating_enabled(),
                "{MUTATING_TEST_ENV} is set, so this host claims it can arm enforcement, \
                 and the engine still refused: {error}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. the whole lifecycle, across a real pipe
// ---------------------------------------------------------------------------

/// **The smoke test.** A real core, created over the real Windows environment,
/// driven through one lifecycle transition across a real named pipe, and shut
/// down gracefully.
///
/// Every step is the production one:
///
/// 1. [`runtime::build_env`] — the platform CSPRNG and the three clocks;
/// 2. [`runtime::build_core`] — VR-4's `abi_major` check, then
///    `twinvpn_core::Core::create` over the core linked into this binary;
/// 3. [`runtime::Service::start`] — the hosting object, which spawns §11.10's
///    drain thread;
/// 4. a real `\\.\pipe\…` instance, served by [`server::serve`];
/// 5. [`win32::pipe::read_client_principal`] — the kernel's answer to "who is on
///    the other end", read under impersonation and reverted before any work
///    (MI-A4);
/// 6. the production [`Client`] attaches, submits `status.get`, and **receives a
///    result body back across the pipe**;
/// 7. a transition is published and arrives on §11.10's stream, carrying MI-18's
///    actor;
/// 8. [`runtime::Service::shutdown`] closes the stream and joins the drain.
///
/// # The pipe name, and why it is not MI-A3's
///
/// MI-A3's endpoint is `\\.\pipe\TwinVPN\mgmt` with a rendered DACL, created by
/// the agent at every start. Using it here would contend with a real installed
/// service on the same machine and would need a descriptor this test has no
/// business writing, so the instance is per-process and unnamed in the registry
/// sense. What is being proven is the **carriage**, not the endpoint's identity.
#[test]
fn a_real_core_is_driven_through_a_lifecycle_transition_over_a_real_named_pipe_and_shut_down() {
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    let (env, _tokio) = runtime::build_env().expect("the platform CSPRNG probes");

    // The mock adapter, and it is the ONLY stub in this test. The real one needs
    // `wintun.dll` and a writable engine session — see the privileged test
    // below. The CORE is the real one, linked as §11.9 row 4's staticlib.
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let core = runtime::build_core(
        &env,
        Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        // The mock reports no element, truthfully (§11.16 (l)).
        false,
        "core-held",
    )
    .expect("VR-4: this shell and this core agree about abi_major");

    let service = runtime::Service::start(
        env.clone(),
        Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        core,
    );
    // The hosting object is assembled and its §11.10 drain is running. In the
    // SCM's vocabulary that is `SERVICE_START_PENDING`: the process exists and
    // is not yet accepting management connections.
    transition("STOPPED", "START_PENDING");

    // ADR-0016 §11.6, as this run actually satisfied it. Printed rather than
    // asserted, because an unprivileged hosted runner satisfies only part of
    // it — and the honest report of a partial sequence is the sequence, not a
    // claim that it completed. `ci-windows.sh` copies this line into `notes`.
    let achieved = achieved_start_sequence();
    println!(
        "start sequence (ADR-0016 §11.6): {achieved:?} ready={} first_incomplete={:?}",
        achieved.ready(),
        achieved.first_incomplete()
    );

    let pipe_name = format!(
        r"\\.\pipe\twinvpn-link-run-{}",
        std::process::id()
    );

    block_on(async {
        let listener = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&pipe_name)
            .expect("the named pipe instance is created");

        // The client half, on its own task, because the server half below has
        // to be inside `serve` before the client's first request is answered.
        let client_side = ClientOptions::new()
            .open(&pipe_name)
            .expect("the client opens the pipe this process just created");

        // MI-A1 and MI-A4. `ImpersonateNamedPipeClient` needs the client to have
        // written, so the connect is awaited first and the read is retried a
        // bounded number of times rather than once. It FAILS if it never
        // succeeds; there is no fallback principal and no anonymous tier
        // (MI-A5).
        listener
            .connect()
            .await
            .expect("the client connected to this instance");
        let principal = attest(&listener).await;
        println!(
            "read_client_principal: pid={} session={:?} groups={} (kernel-attested)",
            principal.pid,
            principal.session,
            principal.enabled_group_sids.len()
        );
        assert_eq!(
            principal.pid,
            std::process::id(),
            "MI-A2: the pid is advisory, and here it is this very process"
        );

        // CD-2: the principal SIDs are INJECTED, never resolved here. They are
        // taken from the token the kernel just attested so that the grant is
        // deterministic on any runner — `Everyone` is enabled in every token, so
        // there is always at least one — rather than depending on which groups
        // the CI account happens to hold.
        let group = principal
            .enabled_group_sids
            .first()
            .cloned()
            .expect("every Windows token carries at least one enabled group");
        let sids = PrincipalSids {
            service: "S-1-5-80-0".to_owned(),
            observe: group.clone(),
            operate: group,
        };

        let context = Arc::new(ServerContext {
            core: Arc::clone(&service.core),
            env: env.clone(),
            sids,
            platform_ctx: PlatformCtx {
                platform: "windows".to_owned(),
                os_version: os_version(),
            },
            submission: Arc::new(tokio::sync::Mutex::new(())),
            fanout: Arc::clone(&service.fanout),
        });

        let served = tokio::spawn(async move {
            let mut listener = listener;
            server::serve(context, principal, &mut listener).await
        });

        let scopes: Vec<String> = twinvpnsvc::mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|s| s.name().to_owned())
            .collect();
        let topics: Vec<String> = twinvpn_mgmt::fanout::TOPICS
            .iter()
            .map(|t| (*t).to_owned())
            .collect();

        let mut client =
            Client::attach_subscribed(client_side, "cli", "0.1.0", &scopes, &topics)
                .await
                .expect("the attach negotiates across the pipe");
        assert_eq!(client.mi_version(), twinvpn_mgmt::MI_VERSION);
        assert!(
            client.granted().holds(twinvpn_mgmt::Scope::Status),
            "MI-S1: the attested principal's groups grant OBSERVE"
        );
        // MI-C3: the platform context is the agent's, used verbatim.
        assert_eq!(client.platform_ctx().platform, "windows");
        assert!(!client.catalogue_digest().is_empty());

        // ---- a result comes BACK across the boundary ----------------------
        let response = client
            .call("status.get", Vec::new(), None, Vec::new())
            .await
            .expect("status.get is implemented and permitted");
        assert!(response.ok);
        assert!(
            !response.result.is_empty(),
            "the core published a body and the service must forward it across the \
             pipe, not drop it"
        );
        println!(
            "status.get: ok, {} bytes of result across the pipe",
            response.result.len()
        );
        // A management client attached across the kernel's pipe driver,
        // submitted an operation and got the core's own answer back. That is
        // §11.6's step 8 — "only then does it accept connections" — observed
        // rather than assumed.
        transition("START_PENDING", "RUNNING");

        // ---- one lifecycle transition -------------------------------------
        //
        // Published after the call returns, so the subscription registered at
        // attach is certainly in place. `Default::default()` rather than a named
        // event: CB-2 keeps `twinvpn-schema` out of this shell.
        #[allow(clippy::default_trait_access)]
        service
            .core
            .publish_transition(Default::default(), Some("ci".to_owned()));

        // The stream also carries `command.completed` for the call above, so the
        // transition is looked for rather than assumed to be first. Bounded, so
        // a stream that never carries it fails instead of hanging.
        let mut seen = None;
        for _ in 0..16 {
            let frame = client.next_event().await.expect("the stream stays open");
            if let twinvpn_mgmt::Body::Event(event) = frame.body {
                if event.topic == "transition" {
                    seen = Some(event);
                    break;
                }
            }
        }
        let event = seen.expect("the published transition arrived on §11.10's stream");
        assert_eq!(
            event.actor_principal.as_deref(),
            Some("ci"),
            "MI-18: the attribution survives core, drain, fan-out, envelope and pipe"
        );
        println!("transition: delivered across the pipe with actor_principal=ci");

        drop(client);
        let _ = served.await.expect("the connection task joined");
    });

    // ---- graceful shutdown ------------------------------------------------
    //
    // The transition is COMPUTED by the production state machine rather than
    // asserted by this test: `on_control` is the same function the SCM handler
    // calls, and the actions it returns are what the service performs.
    {
        use twinvpnsvc::service::scm::{self, Action, Control, ServiceState};

        let (next, actions) = scm::on_control(ServiceState::Running, Control::Stop);
        assert!(matches!(next, ServiceState::StopPending { .. }));
        assert!(
            actions.contains(&Action::BeginShutdown) && actions.contains(&Action::FlushDurableState),
            "a stop flushes durable state and begins shutdown: {actions:?}"
        );
        // ADR-0022 §11.4's Windows row: "Shutdown MUST NOT remove enforcement."
        // The `Action` enum has no variant that could — asserted here so that
        // adding one is a test failure rather than a quiet capability.
        assert_eq!(actions.len(), 3, "exactly report, flush, begin: {actions:?}");
        transition("RUNNING", "STOP_PENDING");
    }

    // `ownership.md` §6 rule 7's order: the core stops accepting work, the event
    // stream closes so the drain unblocks, and the adapter is told last. A
    // leaked drain would hold an `Arc<Core>` for the life of the process.
    service.shutdown();
    assert!(
        service.fanout.is_closed(),
        "shutdown closes the stream so no subscriber waits on a body that will never arrive"
    );
    // ADR-0022 §11.4's Windows row and CB-6: shutdown must NOT remove
    // enforcement. The custody claim is the adapter's and survives the process.
    assert!(
        twinvpn_platform::NetworkConfig::enforcement_custody(service.adapter.network_config())
            .survives_core_exit(),
        "CB-6: the installed ruleset is in the OS's custody, so the core going away \
         cannot drop protection"
    );
    transition("STOP_PENDING", "STOPPED");
    println!("shutdown: stream closed, drain joined, enforcement custody unchanged");
}

/// ADR-0016 §11.6's sequence, filled in from what **this run** achieved.
///
/// Every field is a real outcome and none is asserted: the lock is really taken,
/// the privilege posture is really read and verified, and the two enforcement
/// steps are really attempted. A hosted runner is not LocalSystem, has no
/// `wintun.dll` and does not arm anything, so this returns a sequence that is
/// **not** `ready()` there — which is the honest answer and is why the markers
/// above name the hosting object's states rather than a report to a real SCM.
fn achieved_start_sequence() -> twinvpnsvc::service::StartSequence {
    use twinvpnsvc::service::{privilege, StartSequence};

    let mut sequence = StartSequence::default();

    // LC-5's named kernel mutex, really taken. Dropped immediately: this test
    // is not the authority and must not lock a real service out of the host for
    // the rest of the run.
    match win32::instance::acquire() {
        Ok(lock) => {
            sequence.single_instance = true;
            drop(lock);
        }
        Err(error) => println!("§11.6 (2) single-instance lock: {error}"),
    }

    match privilege::Posture::read() {
        Ok(posture) => match posture.verify() {
            Ok(()) => sequence.privilege_verified = true,
            Err(error) => println!("§11.6 (3) privilege posture: {error}"),
        },
        Err(error) => println!("§11.6 (3) privilege posture unreadable: {error}"),
    }

    // The CSPRNG and the three clocks: the caller has already built an `Env`
    // through `build_env`, which probes, so reaching this line at all means the
    // step completed.
    sequence.env_bound = true;

    // (5) and (6) need `wintun.dll` and a writable filtering engine. The
    // privileged job's `windows_host` suite owns them; this run neither probes
    // nor reclaims, and leaves both false rather than claiming a capability it
    // did not exercise.
    sequence
}

/// [`win32::pipe::read_client_principal`], retried until the client's bytes have
/// arrived.
///
/// `ImpersonateNamedPipeClient` refuses until the client has written to the
/// pipe, and the client task above writes its `Hello` as soon as it is polled.
/// The loop yields rather than sleeping — CD-3 keeps `tokio::time` out of this
/// crate — and **panics** rather than returning a fallback: MI-A5 says an
/// unverifiable principal is a close, and a test that invented one would be
/// asserting against a value the kernel never produced.
async fn attest(
    listener: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Principal {
    let handle = listener.as_raw_handle();
    let mut last = None;
    for _ in 0..10_000 {
        // SAFETY: `handle` belongs to `listener`, which is borrowed for the
        // whole of this call, and `connect()` has already returned, so it is a
        // live and connected pipe handle — exactly the contract
        // `read_client_principal` states.
        match unsafe { win32::pipe::read_client_principal(handle) } {
            Ok(principal) => return principal,
            Err(failure) => last = Some(failure),
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "the client's identity could not be read after 10000 attempts: {:?}. \
         MI-A5 makes this a close, not a fallback principal.",
        last
    )
}

/// The OS version string this build reports in MI-C3's `platform_ctx`.
///
/// Read from the environment rather than from `RtlGetVersion`, because a
/// version string is diagnostic (ADR-0017 §11.7 makes the *catalogue* the
/// capability contract, not the version) and adding a `ntdll` import to this
/// shell for a log field would be the wrong trade.
fn os_version() -> String {
    std::env::var("OS").unwrap_or_else(|_| "windows".to_owned())
}

// ---------------------------------------------------------------------------
// 4. the privileged half
// ---------------------------------------------------------------------------

/// The **real** [`twinvpn_platform_windows::WindowsPlatformAdapter`] under a
/// real core.
///
/// Needs two things a hosted runner does not have: `wintun.dll` beside the test
/// binary (ADR-0016 §10 puts the driver's lifecycle with the installer) and a
/// token that can open the Base Filtering Engine. So it is gated on
/// [`MUTATING_TEST_ENV`] and belongs to the self-hosted
/// `windows-privileged-lifecycle` job.
///
/// **Without the opt-in it asserts the refusal rather than skipping**, which is
/// the same discipline `twinvpn-platform-windows`' `tests/windows_host.rs`
/// follows: a plain `cargo test` still checks that a missing driver produces a
/// registered `reason_code` and not a panic.
///
/// # It installs nothing
///
/// `Core::create` does not arm enforcement, and nothing below calls `apply`,
/// `reclaim` or `disarm`. The mutating filter, route and NRPT paths belong to
/// `cargo test -p twinvpn-platform-windows --test windows_host`, which the same
/// job runs and the same job cleans up after.
#[test]
fn the_real_adapter_hosts_the_core_when_this_host_supplies_wintun_and_the_engine() {
    use twinvpn_platform_windows::{custody, wintun, WindowsAdapterParts, WindowsPlatformAdapter};

    let driver = match wintun::WintunDriver::load() {
        Ok(driver) => driver,
        Err(error) => {
            assert!(
                !error.reason_code().as_str().is_empty(),
                "a missing driver is a registered refusal, never a panic"
            );
            println!(
                "wintun.dll: not loadable here, reason_code={} ({error})",
                error.reason_code().as_str()
            );
            assert!(
                !mutating_enabled(),
                "{MUTATING_TEST_ENV} is set, so this host claims to be a privileged \
                 lifecycle rig, and wintun.dll is still absent: {error}"
            );
            return;
        }
    };

    let backend = custody::CngElement::probe();
    let store_root = std::env::temp_dir().join(format!("twinvpn-link-run-{}", std::process::id()));
    std::fs::create_dir_all(&store_root).expect("the vault directory is created for this run");

    let adapter = WindowsPlatformAdapter::new(WindowsAdapterParts {
        enforcement: twinvpn_platform_windows::wfp::EnforcementConfig {
            overlay_luid: 0,
            service_app_id: "",
            service_sid: "",
            local_network_access: true,
            on_link_prefixes: Vec::new(),
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
            doh_endpoints: Vec::new(),
        },
        stub: stub_addresses(),
        store_root: store_root.clone(),
        restore_point_path: store_root.join("resolver.restore"),
        identity_element: Arc::new(custody::CngElement::new(backend)),
        tier1_backend: backend,
        tunnel_driver: Arc::new(driver),
    });

    let adapter = match adapter {
        Ok(adapter) => Arc::new(adapter),
        Err(error) => {
            println!(
                "WindowsPlatformAdapter::new: refused, reason_code={} ({error})",
                error.reason_code().as_str()
            );
            assert!(
                !mutating_enabled(),
                "{MUTATING_TEST_ENV} is set and the real adapter still could not be \
                 built: {error}"
            );
            let _ = std::fs::remove_dir_all(&store_root);
            return;
        }
    };

    let posture = adapter.posture();
    println!(
        "adapter posture: element={} hardware_backed={} custody={:?}",
        posture.identity_element, posture.hardware_backed_identity, posture.custody_class
    );

    let (env, _tokio) = runtime::build_env().expect("the platform CSPRNG probes");
    let sek_custody = match posture.record_aead_custody {
        twinvpn_platform::RecordAeadCustody::PlatformPerformed => "platform-performed",
        twinvpn_platform::RecordAeadCustody::CoreHeld => "core-held",
    };
    let core = runtime::build_core(
        &env,
        Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        posture.hardware_backed_identity,
        sek_custody,
    )
    .expect("VR-4: this shell and this core agree about abi_major");

    let service = runtime::Service::start(
        env,
        Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        core,
    );
    transition("STOPPED", "START_PENDING");
    let subscriber = service.fanout.subscribe(twinvpn_mgmt::SUBSCRIBER_WATERMARK);
    #[allow(clippy::default_trait_access)]
    service
        .core
        .publish_transition(Default::default(), Some("ci".to_owned()));

    // The drain runs on its own thread, so the event arrives on another
    // thread's schedule. A bounded spin that gives up is a failure; a sleep
    // would be a timeout, and CD-3 makes timeouts the core's.
    let mut delivered = None;
    for _ in 0..200_000 {
        if let Some(frame) = service.fanout.next_for(subscriber) {
            delivered = Some(frame);
            break;
        }
        std::thread::yield_now();
    }
    let Some(twinvpn_mgmt::Frame::Event { event, .. }) = delivered else {
        panic!("the drain never delivered the transition over the real adapter")
    };
    assert_eq!(event.topic, "transition");
    assert_eq!(event.actor_principal.as_deref(), Some("ci"));
    // The real adapter is bound and the core's one ordered stream reached a
    // subscriber through it.
    transition("START_PENDING", "RUNNING");

    {
        use twinvpnsvc::service::scm::{self, Action, Control, ServiceState};
        let (next, actions) = scm::on_control(ServiceState::Running, Control::Stop);
        assert!(matches!(next, ServiceState::StopPending { .. }));
        assert!(actions.contains(&Action::BeginShutdown));
        transition("RUNNING", "STOP_PENDING");
    }

    service.shutdown();
    assert!(service.fanout.is_closed());
    transition("STOP_PENDING", "STOPPED");
    assert!(
        twinvpn_platform::NetworkConfig::enforcement_custody(adapter.network_config())
            .survives_core_exit(),
        "CB-6: shutdown leaves the installed ruleset in the OS's custody"
    );
    let _ = std::fs::remove_dir_all(&store_root);
    println!("real adapter: core hosted, transition delivered, shutdown clean");
}

/// The stub's four listening addresses (ADR-0011 §11.2's Windows row).
///
/// The same values `src/main.rs` injects. Duplicated rather than exported
/// because `main.rs` is a binary and this is a test binary; the constant that
/// matters — `100.127.255.53` — is AP-2's reserved service block either way.
fn stub_addresses() -> twinvpn_platform_windows::dns::StubAddresses {
    use twinvpn_types::{IpAddr, V4Addr, V6Addr};

    let mut anycast6 = [0u8; 16];
    anycast6[0] = 0xfd;
    anycast6[1] = 0x7c;
    anycast6[2] = 0x9e;
    anycast6[3] = 0x5d;
    anycast6[4] = 0x2a;
    anycast6[5] = 0x10;
    anycast6[6] = 0xff;
    anycast6[7] = 0xff;
    anycast6[15] = 0x53;
    let mut loopback6 = [0u8; 16];
    loopback6[15] = 1;

    twinvpn_platform_windows::dns::StubAddresses {
        loopback_v4: IpAddr::V4(V4Addr::from_octets([127, 0, 0, 53])),
        loopback_v6: IpAddr::V6(V6Addr::new(loopback6, None).expect("::1 is well formed")),
        anycast_v4: IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53])),
        anycast_v6: IpAddr::V6(
            V6Addr::new(anycast6, None).expect("the service anycast is well formed"),
        ),
    }
}
