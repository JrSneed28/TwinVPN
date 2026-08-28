//! `twinvpnd` — the privileged Linux agent.
//!
//! **Authority:** [ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2 (Linux, normatively), §11.6 (the start ordering), PS-1, PS-3, PS-11,
//! PS-17, PS-18; ADR-0018 CB-2, CB-6, §11.16 (a); `ownership.md` §6 rule 7.
//!
//! # The start order is §11.6's, and it is not rearranged for convenience
//!
//! ```text
//! 1.  verify the KS-19 boot artifact        (PS-7; CRITICAL, never fatal)
//! 2.  verify the privilege posture          (§11.2; FATAL when wrong)
//! 3.  bind the three clocks and the runtime (CD-1, CD-2)
//! 3b. verify the runtime can drive I/O      (W-43; FATAL — PS-18)
//! 4.  build the adapter and probe it        (the capability probe)
//! 4b. reclaim/re-assert the owner-tagged
//!     ruleset, and READ IT BACK             (§11.6 step 2; KS-20, PS-8; FATAL)
//! 5.  create the core                       (VR-4 checks abi_major FIRST)
//! 6.  bind the management endpoint          (MI-A3, bind-and-rename)
//! 7.  accept connections                    (only now — §11.6)
//! ```
//!
//! Steps **3b** and **4b** are review findings W-43 and R-7. 4b in particular
//! used to be a flag set to `true`: `apply` had no caller anywhere in the
//! product, so the KS-19 boot table was the only enforcement that existed, and
//! on a full-tunnel host all Internet traffic egressed untunneled from boot.
//!
//! # PS-1: this process is the only authority
//!
//! > Exactly one process per host is the network and policy authority… A second
//! > process claiming any of them is `INTERNAL.INVARIANT_VIOLATED`.
//!
//! Step **3c** is where that becomes true. Wave 1 relied on the endpoint's
//! bind-and-rename, which is atomic on the *name* — so a second agent reaching
//! step 6 **won** the name while the first kept its listening socket, its
//! `CAP_NET_ADMIN` and its belief that it was the authority. Two processes were
//! then programming one host's `table inet twinvpn` and one routing table 52.
//!
//! [`authority::take`] is a crash-surviving `flock(2)` on a file in the runtime
//! directory, taken **before** the first privileged mutation of host state. The
//! kernel releases it when the holder dies by any route, so no cleanup step
//! stands between a crash and the successor's start (ADR-0012 KS-20).

#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpnd::agent::{
    authority, boot_artifact_present, conn, endpoint, events, health, logging, peer, privilege,
    runtime, server, StartSequence,
};
use twinvpnd::mi;

fn main() -> std::process::ExitCode {
    // The shell installs the subscriber, because the core deliberately installs
    // none: it is a process-global side effect and there may be two cores in one
    // process.
    if let Err(reason) = logging::install() {
        eprintln!("twinvpnd: {reason}");
        return std::process::ExitCode::from(70);
    }

    match start() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(reason) => {
            // Never a bare message: the registered code is the contract, and the
            // sentence is for a human reading a journal.
            tracing::error!(
                target: "twinvpn.agent",
                reason_code = reason.code,
                specified_code = reason.specified,
                "the agent cannot start"
            );
            eprintln!("twinvpnd: {}: {}", reason.code, reason.detail);
            std::process::ExitCode::from(reason.exit)
        }
    }
}

/// A refusal to start, with the code that names it.
struct StartupRefusal {
    code: &'static str,
    specified: &'static str,
    detail: String,
    exit: u8,
}

#[allow(clippy::too_many_lines)]
fn start() -> Result<(), StartupRefusal> {
    // ---- 1. the KS-19 boot artifact (PS-7) --------------------------------
    // CRITICAL and **not** fatal: PS-7 makes it package-owned and says the
    // authority "MUST NOT be a prerequisite for it to apply". Refusing to start
    // would leave the host with neither the boot ruleset nor an agent.
    let mut sequence = StartSequence {
        boot_artifact_present: boot_artifact_present(),
        ..StartSequence::default()
    };
    if !sequence.boot_artifact_present {
        tracing::error!(
            target: "twinvpn.agent",
            specified_code = "PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED",
            reason_code = "PLATFORM.ADAPTER_UNAVAILABLE",
            unit = twinvpnd::agent::BOOT_ARTIFACT_UNIT,
            ruleset = twinvpnd::agent::BOOT_ARTIFACT_RULESET,
            "the KS-19 boot artifact is not installed: the interval between the network \
             stack coming up and this agent starting is UNPROTECTED"
        );
    }

    // ---- 2. the privilege posture (§11.2) ---------------------------------
    // **Fatal.** "The authority MUST NOT continue as root 'just this once'."
    let posture = privilege::Posture::read().map_err(|e| StartupRefusal {
        code: e.reason_code(),
        specified: e.specified_code(),
        detail: e.to_string(),
        exit: 71,
    })?;
    posture.verify().map_err(|e| StartupRefusal {
        code: e.reason_code(),
        specified: e.specified_code(),
        detail: e.to_string(),
        exit: 71,
    })?;
    sequence.privilege_verified = true;

    // PS-11: an unsupervised authority does not claim supervised guarantees.
    if !posture.supervised {
        tracing::warn!(
            target: "twinvpn.agent",
            specified_code = "PLATFORM.SERVICE.SUPERVISOR_ABSENT",
            "no recognised supervisor started this process; R-25's restart guarantee is a \
             property of the supervisor, not of this binary, and is NOT in force"
        );
    }
    // PS-17: every §11.9 directive that did not apply is named, at WARN.
    // "Silently running wider than declared is the defect this rule retires."
    for directive in posture.degradations() {
        tracing::warn!(
            target: "twinvpn.agent",
            reason_code = "PLATFORM.PRIV.SANDBOX_DEGRADED",
            directive,
            "a §11.9 hardening directive is not in force"
        );
    }

    // ---- 3. the three clocks, the timer and the runtime (CD-1, CD-2) ------
    let (env, tokio_runtime) = runtime::build_env().map_err(|e| StartupRefusal {
        code: "PLATFORM.ADAPTER_UNAVAILABLE",
        specified: "PLATFORM.ADAPTER_UNAVAILABLE",
        detail: e.to_string(),
        exit: 71,
    })?;

    // ---- 3b. the runtime's I/O driver (W-43) ------------------------------
    //
    // PS-18: "The authority MUST NOT start in a mode that cannot arm enforcement
    // while reporting itself as running." A runtime with no I/O driver cannot
    // open a socket, so it cannot arm anything, gather anything or program
    // anything — it panics on the first command instead. Refusing here turns
    // that into a diagnosable startup failure.
    if !runtime::runtime_can_drive_io(&env) {
        return Err(StartupRefusal {
            code: "PLATFORM.ADAPTER_UNAVAILABLE",
            specified: "PLATFORM.ADAPTER_UNAVAILABLE",
            detail: "the injected runtime has no I/O driver, so no socket, netlink \
                     channel or tun device can be opened (W-43: twinvpn-env's \
                     TokioRuntime builds with enable_time() and not enable_io())"
                .to_owned(),
            exit: 71,
        });
    }

    // ---- 3c. PS-1's lock --------------------------------------------------
    //
    // **Before the first privileged mutation of host state**, which is step 4b's
    // arm. Two agents arming one host's nftables table is the race PS-1 exists
    // to prevent, so the lock has to be held before the arm rather than before
    // the endpoint bind. It is taken *after* the privilege check so that a host
    // which would be refused for running as root is refused for that reason,
    // rather than for a lock it could not have taken anyway.
    //
    // Bound to a NAMED local: `let _ = ...` would drop the guard immediately and
    // release the exclusion in the same statement that acquired it.
    let _authority = authority::take(&runtime_dir()).map_err(|e| StartupRefusal {
        code: e.reason_code(),
        specified: e.specified_code(),
        detail: e.to_string(),
        exit: 71,
    })?;

    // ---- 4. the adapter, and the capability probe -------------------------
    let adapter = Arc::new(build_adapter());
    let adapter_posture = adapter.posture();
    tracing::info!(
        target: "twinvpn.agent",
        nft = adapter_posture.nft_present,
        tun = adapter_posture.tun_present,
        tpm = adapter_posture.tpm_present,
        hardware_backed_identity = adapter_posture.hardware_backed_identity,
        resolved_in_force = adapter_posture.resolved_in_force,
        "the adapter's posture, declared rather than discovered later"
    );
    if !adapter_posture.nft_present {
        // ADR-0012 §8: arming must never fail open. Without `nft(8)` the client
        // cannot enter a protected state, and PS-18 forbids starting "in a mode
        // that cannot arm enforcement while reporting itself as running".
        return Err(StartupRefusal {
            code: "PLATFORM.ADAPTER_UNAVAILABLE",
            specified: "PLATFORM.PRIV.CAPABILITY_MISSING",
            detail: "nft(8) is not installed; enforcement cannot be armed".to_owned(),
            exit: 71,
        });
    }
    if adapter_posture.tpm_present && !adapter_posture.hardware_backed_identity {
        tracing::warn!(
            target: "twinvpn.agent",
            specified_code = "STORE.CUSTODY_DEGRADED",
            "this host has a TPM resource manager and this build cannot use it; the \
             identity is reported as NOT hardware-backed, truthfully (§11.16 (l))"
        );
    }
    sequence.capabilities_probed = true;

    // ---- 4b. reclaim or re-assert the owner-tagged ruleset ----------------
    //
    // **Review finding R-7.** This step used to set its flag to `true` and do
    // nothing, on the reasoning that "the core's own first `apply` installs the
    // rules". `apply` had no caller anywhere in the product, so on a Linux host
    // the KS-19 boot table was the *only* enforcement that ever existed — and
    // its scope is the overlay space alone. On a full-tunnel host that means all
    // Internet traffic egressed untunneled, from boot, indefinitely. **I3 did
    // not hold for the composed product.**
    //
    // §11.6 step (2) is unambiguous that this is the AUTHORITY's job and not the
    // core's: "the owner-tagged rule set is **reclaimed or re-asserted** (KS-20,
    // PS-8)" is listed among the things that must happen *before* it accepts
    // management connections. KS-20: "all rule state is owner-tagged and
    // reclaimable by a fresh process after an unclean exit. A crash must leave
    // the host blocked, never open."
    //
    // Arming `RULESET_BLOCKED` is not a decision (CB-2): ADR-0012 §11.8's boot
    // row fixes the posture a host starts in, and the scope comes from
    // `nft::baseline_protected`, which is the product's own address space and
    // the same pair the boot artifact carries.
    sequence.ruleset_reclaimed = arm_at_startup(&tokio_runtime, &adapter)?;
    sequence.state_rehydrated = true;

    // ---- 5. the core (VR-4 first) -----------------------------------------
    let core = Arc::new(build_core(&env, Arc::clone(&adapter))?);

    // ---- 5b. open the durable store ---------------------------------------
    //
    // **Review finding R-10.** `sequence.state_rehydrated` above was set to
    // `true` having rehydrated nothing: `Core::open_store` had only test
    // callers, so the composed daemon ran with a MEMORY-ONLY vault and W-28's
    // crash window was the entire process lifetime. Every durable claim
    // S-12/S-15/S-27/S-30/S-37 make was true of the type and false of the
    // product.
    //
    // Before the endpoint, so no management command can observe a core whose
    // persistence is not yet established; after the core, because the store is
    // opened THROUGH it (CB-7 splits the store at the CB-1 line and the core
    // owns the bridge).
    open_vault(&tokio_runtime, &core)?;

    let agent = runtime::Agent {
        env: env.clone(),
        adapter: Arc::clone(&adapter),
        core: Arc::clone(&core),
    };

    if !sequence.ready() {
        return Err(StartupRefusal {
            code: "INTERNAL.INVARIANT_VIOLATED",
            specified: "PLATFORM.SERVICE.START_TIMEOUT",
            detail: "the §11.6 start sequence did not complete".to_owned(),
            exit: 71,
        });
    }

    // ---- 6 and 7. the endpoint, then connections --------------------------
    let groups = Arc::new(peer::GroupSource::load());
    if !groups.is_authoritative() {
        tracing::warn!(
            target: "twinvpn.agent",
            specified_code = "PLATFORM.PRIV.SANDBOX_DEGRADED",
            "group membership is read from /etc/group only; a directory-service \
             membership will NOT be seen, and a principal will hold FEWER scopes than \
             intended. This fails closed."
        );
    }
    // **§11.10's event stream.** One fan-out for the process, because F-5 gives
    // the core exactly one ordered stream and `next_event` pops from it — so
    // there is exactly one reader, and it is the drain thread below.
    let fanout = Arc::new(events::Fanout::new());
    let context = Arc::new(server::ServerContext {
        core: Arc::clone(&core),
        env,
        groups,
        platform_ctx: platform_ctx(),
        // F-6 / S-47: exactly one thread holds the core for mutation at a time.
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::clone(&fanout),
    });

    // A `std::thread`, not a `tokio::spawn`: `Core::next_event` blocks on a
    // condvar, and blocking a runtime worker on a condvar is how a runtime
    // deadlocks. The core's own documentation says the same — "called from the
    // shell's drain thread, which is not inside the core's runtime".
    let drain = {
        let core = Arc::clone(&core);
        let fanout = Arc::clone(&fanout);
        std::thread::Builder::new()
            .name("twinvpn-drain".to_owned())
            .spawn(move || events::drain(&core, &fanout, DRAIN_TIMEOUT))
            .map_err(|e| StartupRefusal {
                code: "PLATFORM.ADAPTER_UNAVAILABLE",
                specified: "PLATFORM.ADAPTER_UNAVAILABLE",
                detail: e.to_string(),
                exit: 71,
            })?
    };

    // The daemon's `main` is the one place `block_on` is legitimate:
    // `twinvpn_env::Runtime`'s own documentation says so ("The entry point the
    // FFI boundary and the daemon's `main` use"), and a component inside the
    // core never calls it. There is exactly ONE runtime in this process — the
    // one `build_env` created and injected — so nothing here creates a second.
    let mut outcome = Ok(());
    {
        let slot = &mut outcome;
        let context = Arc::clone(&context);
        twinvpn_env::Runtime::block_on(
            tokio_runtime.as_ref(),
            Box::pin(async move {
                *slot = serve_forever(context, agent).await;
            }),
        );
    }

    // The drain is joined rather than detached: `serve_forever` closed the
    // fan-out on its way out, and a drain still inside `next_event` would
    // otherwise be reading a core the process is about to drop.
    fanout.close();
    core.wake();
    let _ = drain.join();
    outcome
}

/// How long the drain thread sits in one `Core::next_event` call.
///
/// **Not a timeout on anything the core decides.** CD-2 makes timeouts the
/// core's, and this is not one: `next_event` has no deadline semantics — it is a
/// blocking read that returns `None` on timeout, on wake, or on close, and the
/// core's own documentation says a caller distinguishes those "by asking again".
/// The value bounds how long the thread sits in one call so that shutdown is
/// observed promptly, and nothing else depends on it.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// The runtime directory, from the endpoint's own parent.
///
/// CB-7: the path is **injected**, never discovered — it is
/// `RuntimeDirectory=twinvpn`'s, reached through the same
/// `TWINVPN_MGMT_SOCKET` the endpoint uses, so the lock and the endpoint can
/// never end up in different directories.
fn runtime_dir() -> std::path::PathBuf {
    mi::socket_path()
        .parent()
        .map_or_else(|| std::path::PathBuf::from(mi::SOCKET_DIR), Into::into)
}
/// §11.6 step (5b), delegated to the library so it is testable (R-10).
fn open_vault(
    runtime: &Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>,
    core: &Arc<twinvpn_core::Core>,
) -> Result<(), StartupRefusal> {
    runtime::open_vault_at_startup(runtime, core).map_err(|error| StartupRefusal {
        code: error.reason_code(),
        specified: "STORE.CUSTODY_DEGRADED",
        detail: error.to_string(),
        exit: 71,
    })
}

/// §11.6 step (2), delegated to the library so it is testable.
fn arm_at_startup(
    runtime: &Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>,
    adapter: &Arc<twinvpn_platform_linux::LinuxPlatformAdapter>,
) -> Result<bool, StartupRefusal> {
    runtime::arm_owner_tagged_ruleset(runtime, adapter)
        .map(|()| true)
        .map_err(|error| StartupRefusal {
            code: error.reason_code(),
            specified: "POLICY.KILLSWITCH.ARM_FAILED",
            detail: error.to_string(),
            exit: 71,
        })
}

/// Builds the adapter from injected configuration. **Nothing is discovered.**
fn build_adapter() -> twinvpn_platform_linux::LinuxPlatformAdapter {
    twinvpn_platform_linux::LinuxPlatformAdapter::new(twinvpn_platform_linux::LinuxAdapterParts {
        enforcement: twinvpn_platform_linux::EnforcementConfig {
            overlay_interface: overlay_interface(),
            firewall_mark: twinvpn_platform_linux::DEFAULT_FWMARK,
            cgroup_path: cgroup_path(),
            // ADR-0012 KS-4: `ALLOW` is the default in all three routing
            // modes. The setting itself is S-24's and reaches the adapter
            // through a later `apply`; this is the pre-arming value.
            local_network_access: true,
            on_link_prefixes: Vec::new(),
        },
        store_root: state_dir(),
        resolver_restore_point: state_dir().join("resolver.restore"),
        // §11.16 (l): no element means `false`, truthfully, and NO
        // file-backed substitute.
        identity_element: Arc::new(twinvpn_platform_linux::AbsentElement),
    })
}

fn build_core(
    env: &twinvpn_env::Env,
    adapter: Arc<twinvpn_platform_linux::LinuxPlatformAdapter>,
) -> Result<twinvpn_core::Core, StartupRefusal> {
    twinvpn_core::Core::create(twinvpn_core::CoreParts {
        env: env.clone(),
        adapter,
        // VR-4: `TW_ABI_MAJOR` as THIS shell compiled it. A mismatch is a
        // packaging defect and is refused by name.
        abi_major_expected: twinvpn_core::ABI_MAJOR,
        abi_major: twinvpn_core::ABI_MAJOR,
        abi_minor: twinvpn_core::ABI_MINOR,
        schema_digest: Vec::new(),
        crypto_provider: "twinvpn-crypto".to_owned(),
        sek_custody: "core-held".to_owned(),
        // Reported by the adapter, truthfully. The core MUST NOT assume it.
        hardware_backed: false,
        ledger_capacity: 1024,
        event_capacity: 256,
    })
    .map_err(|diagnostic| StartupRefusal {
        code: "INTERNAL.ABI_VERSION_MISMATCH",
        specified: "INTERNAL.ABI_VERSION_MISMATCH",
        detail: diagnostic.code().as_str().to_owned(),
        exit: 71,
    })
}

/// **MI-C3.** Built once, by the agent, and handed to every client verbatim.
fn platform_ctx() -> mi::PlatformCtx {
    mi::PlatformCtx {
        platform: "linux".to_owned(),
        os_version: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|v| v.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned()),
    }
}

fn overlay_interface() -> String {
    std::env::var("TWINVPN_OVERLAY_INTERFACE").unwrap_or_else(|_| "twin0".to_owned())
}

fn state_dir() -> std::path::PathBuf {
    // `systemd` sets `STATE_DIRECTORY` from `StateDirectory=twinvpn`, which is
    // ADR-0016 O8's 0700 directory. CB-7: the path is INJECTED, never
    // discovered — and an environment variable the supervisor sets is an
    // injection, not a discovery.
    std::env::var_os("STATE_DIRECTORY")
        .map_or_else(|| std::path::PathBuf::from("/var/lib/twinvpn"), Into::into)
}

/// The agent's own cgroup v2 path, for KS-9(1)'s first half.
///
/// `/proc/self/cgroup` under a unified hierarchy is `0::/system.slice/twinvpnd.service`.
/// `None` where it cannot be read, which [`twinvpn_platform_linux::EnforcementConfig::ks9_complete`]
/// then reports as a **weaker** bootstrap predicate rather than an equivalent one.
fn cgroup_path() -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(path.trim().trim_start_matches('/').to_owned())
}

async fn serve_forever(
    context: Arc<server::ServerContext>,
    agent: runtime::Agent,
) -> Result<(), StartupRefusal> {
    let path = mi::socket_path();
    let gid = endpoint::group_gid(mi::SOCKET_GROUP);
    if gid.is_none() {
        tracing::warn!(
            target: "twinvpn.mi",
            group = mi::SOCKET_GROUP,
            "the endpoint group does not exist; every OBSERVE principal will be locked out"
        );
    }
    let listener = endpoint::bind(&path, gid).map_err(|e| StartupRefusal {
        code: e.reason_code(),
        specified: e.specified_code(),
        detail: e.to_string(),
        exit: 71,
    })?;

    tracing::info!(
        target: "twinvpn.agent",
        endpoint = %path.display(),
        "ready; accepting management connections"
    );

    // **ADR-0023 §11.16's unattended-operation channels**, now that the agent is
    // actually ready. This host is H-SRV: "the distinguishing property is 'no
    // user ever logs in'", so a condition not written where a monitoring system
    // can read it has not been reported at all.
    //
    // The `ProtectionAssertion` is the **W-24 read-back**, not a belief:
    // ADR-0015 §11.6 rule 1 makes the indicator "a pure function of the most
    // recent assertion, never of the agent's belief", and O-18 makes an
    // assertion that cannot be produced `UNKNOWN` rather than "unprotected".
    let assertion = protection_assertion(&agent).await;
    let report = health::Report {
        // CB-2: the state is the CORE's, never derived here. This build reports
        // the one fact the shell legitimately owns — that it reached `ready` —
        // and `worst_reason_code` is filled from the enforcement read-back
        // rather than from a `ConnectionState` the shell would have to compute.
        state: "READY",
        worst_reason_code: if assertion {
            "NONE"
        } else {
            "POLICY.KILLSWITCH.ARM_FAILED"
        },
        as_of_ms: context.as_of_ms(),
        protection_asserted: assertion,
    };
    // **EM-69 names `$STATE_DIR/health` and then says `(tmpfs)`, and on a
    // `systemd` host those two halves disagree**: `StateDirectory=` is
    // `/var/lib`, which is persistent, and `RuntimeDirectory=` is `/run`, which
    // is the tmpfs. The parenthetical is the load-bearing half — a health line
    // that survives a reboot is a monitoring system told a falsehood by a file,
    // which is the exact failure the file exists to prevent — so it is written
    // to the runtime directory. Reported rather than silently resolved.
    let state_dir = runtime_dir();
    if let Err(error) = health::write(&state_dir, &report) {
        // Logged and continued: a health file that cannot be written is a
        // degraded observability channel, not a reason to stop being a VPN, and
        // EM-69 has four other channels.
        tracing::warn!(
            target: "twinvpn.agent",
            specified_code = "PLATFORM.EMBEDDED.SAFE_HOLD",
            path = %state_dir.join(health::HEALTH_FILE).display(),
            detail = %error,
            "the EM-69 health file could not be written; the journal and \
             sd_notify channels remain"
        );
    }
    if let Err(error) = health::notify_ready(&report) {
        tracing::warn!(target: "twinvpn.agent", detail = %error, "sd_notify(READY=1) failed");
    }
    // **EM-70.** The first watchdog ping, and it is refused unless the
    // assertion above was fresh: "a watchdog fed by a timer thread proves that
    // the timer thread is alive, which is not the property anybody wants."
    match health::notify_watchdog(assertion) {
        Ok(true) => {}
        Ok(false) => tracing::warn!(
            target: "twinvpn.agent",
            specified_code = "POLICY.KILLSWITCH.ASSERTION_MISMATCH",
            "the watchdog was NOT fed: no fresh ProtectionAssertion could be \
             obtained (EM-70). systemd will restart this agent, which is the \
             intended outcome"
        ),
        Err(error) => {
            tracing::warn!(target: "twinvpn.agent", detail = %error, "sd_notify(WATCHDOG=1) failed");
        }
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| StartupRefusal {
            code: "PLATFORM.ADAPTER_UNAVAILABLE",
            specified: "PLATFORM.ADAPTER_UNAVAILABLE",
            detail: e.to_string(),
            exit: 71,
        })?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| StartupRefusal {
            code: "PLATFORM.ADAPTER_UNAVAILABLE",
            specified: "PLATFORM.ADAPTER_UNAVAILABLE",
            detail: e.to_string(),
            exit: 71,
        })?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let context = Arc::clone(&context);
                        tokio::spawn(async move {
                            if let Err(error) = conn::serve(context, stream).await {
                                tracing::debug!(
                                    target: "twinvpn.mi",
                                    reason_code = error.reason_code().as_str(),
                                    "a management connection ended"
                                );
                            }
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "twinvpn.mi",
                            detail = %error,
                            "an accept failed; the agent continues"
                        );
                    }
                }
            }
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
    }

    // `ownership.md` §6 rule 7, and W-28's flush. The endpoint is removed FIRST
    // so a client that connects during the drain gets `MGMT.UNAVAILABLE` rather
    // than a successful connect and a hang (§10.3).
    // **EM-71's distinction.** `STOPPING=1` is what lets `systemd` tell a clean
    // stop from a crash, and the crash-loop ladder — held, with enforcement
    // still installed — is only reachable if it can.
    let _ = health::notify_stopping();

    endpoint::remove(&path);
    // A stale "READY" line outliving the agent is a monitoring system told a
    // falsehood by a file, and the file is the channel that is supposed to be
    // authoritative when nobody is watching.
    health::retract(&state_dir);

    // The event stream closes before the core does, so every per-connection pump
    // wakes, finds it closed and returns — and every dispatcher still waiting
    // for a command body is settled rather than left hanging. CB-6 is untouched:
    // this closes queues, not the installed ruleset.
    context.fanout.close();
    agent.shutdown();
    Ok(())
}

/// The **W-24 read-back**, as a boolean the health channels can carry.
///
/// ADR-0015 §11.6 rule 1: the `ProtectionAssertion` is produced by **querying
/// the enforcement layer**, and the indicator is "a pure function of the most
/// recent assertion, **never of the agent's belief**".
///
/// `false` means the query failed or reported no table — which O-18 makes
/// `UNKNOWN` rather than "unprotected", and which [`health::Report`] carries as
/// the word `unknown` for exactly that reason. The two are different facts and a
/// monitoring system must be able to tell them apart.
async fn protection_assertion(agent: &runtime::Agent) -> bool {
    matches!(
        twinvpn_platform::NetworkConfig::installed_ruleset(agent.adapter.network()).await,
        Ok(Some(_))
    )
}
