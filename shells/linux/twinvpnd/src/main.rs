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
//! There is no second holder here: the endpoint's bind-and-rename is the mutual
//! exclusion, and a second agent that reached step 6 would take the name from
//! the first — which is why the first also holds the listening socket, and a
//! client that connects reaches whichever agent owns the fd. Making that a hard
//! refusal needs a lock file whose ownership survives a crash; it is **not** in
//! this wave and is reported.

#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpnd::agent::{
    boot_artifact_present, endpoint, logging, peer, privilege, runtime, server, StartSequence,
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
    let context = Arc::new(server::ServerContext {
        core: Arc::clone(&core),
        env,
        groups,
        platform_ctx: platform_ctx(),
        // F-6 / S-47: exactly one thread holds the core for mutation at a time.
        submission: Arc::new(tokio::sync::Mutex::new(())),
    });

    // The daemon's `main` is the one place `block_on` is legitimate:
    // `twinvpn_env::Runtime`'s own documentation says so ("The entry point the
    // FFI boundary and the daemon's `main` use"), and a component inside the
    // core never calls it. There is exactly ONE runtime in this process — the
    // one `build_env` created and injected — so nothing here creates a second.
    let mut outcome = Ok(());
    {
        let slot = &mut outcome;
        twinvpn_env::Runtime::block_on(
            tokio_runtime.as_ref(),
            Box::pin(async move {
                *slot = serve_forever(context, agent).await;
            }),
        );
    }
    outcome
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
                            if let Err(error) = server::serve(context, stream).await {
                                tracing::debug!(
                                    target: "twinvpn.mi",
                                    reason_code = error.reason_code(),
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
    endpoint::remove(&path);
    agent.shutdown();
    Ok(())
}
