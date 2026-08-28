//! `twinvpnsvc` — `TwinVPNService`, the privileged Windows authority.
//!
//! **Authority:** [ADR-0016](../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2's Windows row, §11.6 (the start ordering), PS-1, PS-3, PS-7, PS-11,
//! PS-17, PS-18; ADR-0018 CB-2, CB-6, §11.16 (a); ADR-0022 LC-4, LC-5, LC-12;
//! `ownership.md` §6 rule 7.
//!
//! # The start order is §11.6's, and it is not rearranged for convenience
//!
//! ```text
//! 1.  take the single-instance lock         (LC-5; FATAL — PS-1)
//! 2.  verify the privilege posture          (§11.9; FATAL)
//! 3.  bind the three clocks and the runtime (CD-1, CD-2), probing the CSPRNG
//! 4.  build the adapter and probe it        (the capability probe; FATAL)
//! 4b. verify the KS-19 boot artifact        (PS-7; CRITICAL, never fatal)
//! 5.  reclaim the owner-tagged WFP state
//!     and READ IT BACK                      (§11.6 step 2; KS-20, PS-8; FATAL)
//! 6.  create the core                       (VR-4 checks abi_major FIRST)
//! 7.  bind the management endpoint          (MI-A3: the DACL at every start)
//! 8.  accept connections                    (only now — §11.6)
//! ```
//!
//! §11.6 lists the boot-artifact check first. It runs at 4b here for a mechanical
//! reason and not a policy one: the check is a query against the filtering
//! engine, and the engine handle is the adapter's. Since PS-7 makes the result
//! **never fatal**, moving it after the adapter changes nothing a caller can
//! observe — and the alternative, a second engine handle opened before the
//! adapter, would be a second writer to the object PS-1 says has one owner.
//!
//! # PS-1: this process is the only authority
//!
//! LC-5's named kernel mutex is the mechanism, and on this platform it is a
//! complete one: the handle is released when the process ends however it ends,
//! so a crashed predecessor never blocks a restart and a live one always does.
//! `shells/linux/README.md` §7 item 7 records that Linux has no equivalent.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use twinvpnsvc::service::{logging, privilege, runtime, start, StartSequence, StartupRefusal};

fn main() -> std::process::ExitCode {
    // PS-11: whether the SCM started us decides both the log format and whether
    // this build may claim a restart guarantee. Read before the subscriber is
    // installed, because it selects the subscriber.
    let supervised = started_by_scm();

    // The shell installs the subscriber, because the core deliberately installs
    // none: it is a process-global side effect and there may be two cores in one
    // process.
    if let Err(reason) = logging::install(supervised) {
        eprintln!("twinvpnsvc: {reason}");
        return std::process::ExitCode::from(70);
    }

    if !supervised {
        tracing::warn!(
            target: "twinvpn.service",
            specified_code = "PLATFORM.SERVICE.SUPERVISOR_ABSENT",
            reason_code = start::emitted_for("PLATFORM.SERVICE.SUPERVISOR_ABSENT"),
            "the SCM did not start this process; R-25's restart guarantee is a property of \
             the service control manager, not of this binary, and is NOT in force"
        );
    }

    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(refusal) => {
            // Never a bare message: the registered code is the contract, and the
            // sentence is for a human reading the Event Log.
            tracing::error!(
                target: "twinvpn.service",
                reason_code = refusal.code,
                specified_code = refusal.specified,
                "the service cannot start"
            );
            eprintln!("twinvpnsvc: {}: {}", refusal.code, refusal.detail);
            std::process::ExitCode::from(refusal.exit)
        }
    }
}

/// Whether the SCM started this process.
#[cfg(windows)]
fn started_by_scm() -> bool {
    twinvpnsvc::win32::scm::started_by_scm()
}

/// The non-Windows answer.
///
/// There is no SCM here, and saying so is the honest posture: this binary
/// compiles on a Linux host so its decision logic can be tested, and a `true`
/// would make it claim a supervisor it does not have.
#[cfg(not(windows))]
fn started_by_scm() -> bool {
    false
}

/// §11.6's sequence.
#[allow(clippy::too_many_lines)]
fn run() -> Result<(), StartupRefusal> {
    let mut sequence = StartSequence::default();

    // ---- 1. the single-instance lock (LC-5, PS-1) -------------------------
    //
    // The guard is held for the whole of `run`: LC-5's property is that a LIVE
    // process holds it, and the kernel releases it at exit however that exit
    // happens. Dropping it early would let a second authority start while this
    // one was still programming routes.
    let lock = acquire_instance_lock()?;
    sequence.single_instance = true;

    // ---- 2. the privilege posture (§11.9) ---------------------------------
    let posture = privilege::Posture::read().map_err(|e| refusal_from_privilege(&e))?;
    posture.verify().map_err(|e| refusal_from_privilege(&e))?;
    sequence.privilege_verified = true;

    // PS-17: every §11.9 directive that did not apply is named, at WARN.
    // "Silently running wider than declared is the defect this rule retires."
    for directive in posture.degradations() {
        tracing::warn!(
            target: "twinvpn.service",
            reason_code = "PLATFORM.PRIV.SANDBOX_DEGRADED",
            directive,
            "a §11.9 hardening directive is not in force"
        );
    }

    // ---- 3. the three clocks, the timer, the runtime and the CSPRNG -------
    //
    // The CSPRNG is **probed here**, not on first use: a source that fails
    // mid-stream poisons the instance, and finding out at startup is strictly
    // better than finding out during a handshake.
    let (env, tokio_runtime) = runtime::build_env().map_err(|error| {
        StartupRefusal::platform(
            "PLATFORM.ADAPTER_UNAVAILABLE",
            "PLATFORM.ADAPTER_UNAVAILABLE",
            error.to_string(),
        )
    })?;
    sequence.env_bound = true;

    // ---- 4. the adapter, and the capability probe -------------------------
    let adapter = Arc::new(build_adapter()?);
    let adapter_posture = adapter.posture();
    tracing::info!(
        target: "twinvpn.service",
        custody_class = ?adapter_posture.custody_class,
        hardware_backed_identity = adapter_posture.hardware_backed_identity,
        identity_element = adapter_posture.identity_element,
        record_aead_custody = ?adapter_posture.record_aead_custody,
        store_root_prepared = adapter_posture.store_root_prepared,
        "the adapter's posture, declared rather than discovered later"
    );
    if !adapter_posture.hardware_backed_identity {
        // ADR-0018 §11.16 (l) and ADR-0020 ST-11: a degraded custody class is a
        // named transition, not a silent fallback. WARN and continue — a host
        // with no TPM is a supported configuration whose residual is stated.
        tracing::warn!(
            target: "twinvpn.service",
            reason_code = "STORE.CUSTODY_DEGRADED",
            custody_class = ?adapter_posture.custody_class,
            "the identity is NOT hardware-backed on this host; reported truthfully rather \
             than substituted with a file-backed signer"
        );
    }
    if !adapter_posture.store_root_prepared {
        return Err(StartupRefusal::platform(
            "AUTH.KEY_STORE_UNAVAILABLE",
            "STORE.PATH_UNSUITABLE",
            "the vault directory is absent or does not carry ADR-0020 §11.9's ACL; the \
             installer creates it and the service does not"
                .to_owned(),
        ));
    }
    sequence.capabilities_probed = true;

    // ---- 4b. the KS-19 boot artifact (PS-7) -------------------------------
    //
    // CRITICAL and **not** fatal: PS-7 makes it package-owned and says the
    // authority "MUST NOT be a prerequisite for it to apply". Refusing to start
    // would leave the host with neither the boot filters nor an authority.
    match adapter.network().verify_boot_artifact() {
        Ok(artifact) if artifact.is_registered() => {
            sequence.boot_artifact_present = true;
        }
        Ok(artifact) => {
            tracing::error!(
                target: "twinvpn.service",
                specified_code = "PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED",
                reason_code = start::emitted_for("PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED"),
                v4 = artifact.v4_deny,
                v6 = artifact.v6_deny,
                "the KS-19 boot filters are not installed: the interval between the Base \
                 Filtering Engine coming up and this service starting is UNPROTECTED"
            );
        }
        Err(error) => {
            tracing::error!(
                target: "twinvpn.service",
                specified_code = "PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED",
                reason_code = error.reason_code().as_str(),
                "the KS-19 boot filters could not be queried"
            );
        }
    }

    // ---- 5. reclaim the owner-tagged WFP state, and read it back ----------
    //
    // §11.6 step (2): "the owner-tagged rule set is **reclaimed or re-asserted**
    // (KS-20, PS-8)", before management connections are accepted. The read-back
    // is the W-24 query — `ProtectionAssertion` derived from what the Base
    // Filtering Engine says it holds, not from the fact that an install returned
    // `Ok`.
    let assertion = adapter.network().reclaim(None).map_err(|error| {
        StartupRefusal::platform(
            "POLICY.KILLSWITCH.ARM_FAILED",
            "POLICY.KILLSWITCH.ARM_FAILED",
            error.to_string(),
        )
    })?;
    if !assertion.is_fail_closed() {
        // ADR-0012 §8: arming must never fail open, and PS-18 forbids starting
        // "in a mode that cannot arm enforcement while reporting itself as
        // running". A posture that covers one family is KS-5's non-conforming
        // case and is refused here rather than reported as protection.
        return Err(StartupRefusal::platform(
            "POLICY.KILLSWITCH.ARM_FAILED",
            "POLICY.KILLSWITCH.ARM_FAILED",
            format!(
                "the engine reports posture {:?} with families {:?}; both must be covered",
                assertion.posture, assertion.families_covered
            ),
        ));
    }
    tracing::info!(
        target: "twinvpn.service",
        posture = ?assertion.posture,
        generation = ?assertion.generation,
        "the owner-tagged ruleset is armed, and was read back from the filtering engine"
    );
    sequence.ruleset_reclaimed = true;

    // ---- 6. the core (VR-4 first) -----------------------------------------
    let sek_custody = match adapter_posture.record_aead_custody {
        twinvpn_platform::RecordAeadCustody::PlatformPerformed => "platform-performed",
        twinvpn_platform::RecordAeadCustody::CoreHeld => "core-held",
    };
    let core = Arc::new(runtime::build_core(
        &env,
        Arc::clone(&adapter) as Arc<dyn twinvpn_platform::PlatformAdapter>,
        adapter_posture.hardware_backed_identity,
        sek_custody,
    )?);
    // LC-4 steps 5-9 are the core's own rehydration, which this build reaches
    // through `Core::create`; there is no separate durable-store open here.
    sequence.state_rehydrated = true;

    if !sequence.ready() {
        return Err(StartupRefusal::internal(format!(
            "the §11.6 start sequence did not complete: {:?} outstanding",
            sequence.first_incomplete()
        )));
    }

    // ---- 7 and 8. the endpoint, then connections --------------------------
    // The guard is passed in rather than dropped early: LC-5's property is that
    // a LIVE authority holds it for as long as it is one, and passing it makes
    // the lifetime a thing the compiler enforces rather than a comment.
    serve(&env, &tokio_runtime, &adapter, &core, lock)
}

/// Steps 7 and 8: bind the pipe with its DACL, then accept.
///
/// # The gap, named
///
/// MI-A3 requires **the agent** to create the endpoint and write its DACL at
/// every start, and [`twinvpnsvc::mi::dacl::pipe_sddl`] renders the descriptor.
/// What is missing is the two calls between them:
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, and a
/// `tokio::net::windows::named_pipe::ServerOptions` accept loop with
/// `.first_pipe_instance(true)`, `.reject_remote_clients(true)` and
/// `.pipe_mode(PipeMode::Message)`.
///
/// The server itself is written and tested —
/// [`twinvpnsvc::service::server::serve`] is generic over the transport and its
/// tests drive a real client against it through `tokio::io::duplex`. What has
/// not been written is the listener that supplies a real pipe.
///
/// PS-18's shape applies: a service that reached `SERVICE_RUNNING` with no
/// management endpoint would be reporting itself as running while being
/// unmanageable, so this refuses by name.
fn serve(
    _env: &twinvpn_env::Env,
    _runtime: &Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>,
    _adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
    _core: &Arc<twinvpn_core::Core>,
    _lock: InstanceLock,
) -> Result<(), StartupRefusal> {
    Err(StartupRefusal::platform(
        "MGMT.UNAVAILABLE",
        "MGMT.UNAVAILABLE",
        "the named-pipe listener is not implemented: the DACL is rendered and the server \
         is written, and nothing binds \\\\.\\pipe\\TwinVPN\\mgmt. Refusing rather than \
         reporting a running service with no management endpoint (PS-18)."
            .to_owned(),
    ))
}

fn refusal_from_privilege(error: &privilege::PrivilegeError) -> StartupRefusal {
    StartupRefusal::platform(
        error.reason_code(),
        error.specified_code(),
        error.to_string(),
    )
}

/// LC-5's guard, under one name on both platforms.
///
/// The alias exists so `run` holds a guard whose `drop` means the same thing
/// wherever it is compiled — a unit on one side and a kernel handle on the other
/// would make the release point invisible on the host this crate is read on.
#[cfg(windows)]
type InstanceLock = twinvpnsvc::win32::instance::InstanceLock;

/// The non-Windows stand-in. **Never constructed**: `acquire_instance_lock`
/// always refuses off Windows, because there is no `Global\` namespace to
/// contend in.
#[cfg(not(windows))]
#[derive(Debug)]
struct InstanceLock(());

/// Takes LC-5's lock.
#[cfg(windows)]
fn acquire_instance_lock() -> Result<InstanceLock, StartupRefusal> {
    twinvpnsvc::win32::instance::acquire().map_err(|error| StartupRefusal {
        code: start::emitted_for("PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT"),
        specified: "PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT",
        detail: error.to_string(),
        exit: 71,
    })
}

/// The non-Windows answer: there is no kernel mutex here.
#[cfg(not(windows))]
fn acquire_instance_lock() -> Result<InstanceLock, StartupRefusal> {
    Err(StartupRefusal::platform(
        "PLATFORM.OS_UNSUPPORTED",
        "PLATFORM.OS_UNSUPPORTED",
        "this binary targets Windows; there is no SCM and no Global\\ namespace here".to_owned(),
    ))
}

/// Builds the adapter from **injected** configuration. Nothing is discovered.
///
/// CD-2, and CB-7's "the path is vended, never discovered": every path and every
/// principal below comes from the installer's own environment block or from a
/// documented default, and none is probed.
#[cfg(windows)]
fn build_adapter() -> Result<twinvpn_platform_windows::WindowsPlatformAdapter, StartupRefusal> {
    // `dns` and `wfp` are NOT imported here: `stub_addresses` and
    // `enforcement_config` name those modules by full path. Until the `ring`
    // edge was removed from `snow` this function could not be compiled for
    // x86_64-pc-windows-msvc at all, and the two dead imports sat here unseen.
    use twinvpn_platform_windows::{custody, wintun, WindowsAdapterParts};

    // ADR-0016 §10 puts the driver's lifecycle with the installer: the DLL ships
    // in the application directory, versioned with the app. A missing one is a
    // packaging failure and PS-18 makes it a refusal.
    let driver = wintun::WintunDriver::load().map_err(|error| {
        StartupRefusal::platform(
            error.reason_code().as_str(),
            "PLATFORM.PRIV.CAPABILITY_MISSING",
            format!("wintun.dll could not be loaded: {error}"),
        )
    })?;

    let backend = custody::CngElement::probe();
    // Fallible: `WindowsPlatformAdapter::new` opens the WFP engine, and PS-18
    // makes an absent capability a **startup** failure rather than a
    // degradation. ADR-0012 §8 is the other half — arming must never fail open,
    // so a service that could not open the engine must not reach `ready`.
    twinvpn_platform_windows::WindowsPlatformAdapter::new(WindowsAdapterParts {
        enforcement: enforcement_config(),
        stub: stub_addresses(),
        store_root: store_root(),
        restore_point_path: store_root().join("resolver.restore"),
        identity_element: Arc::new(custody::CngElement::new(backend)),
        tier1_backend: backend,
        tunnel_driver: Arc::new(driver),
    })
    .map_err(|error| {
        StartupRefusal::platform(
            error.reason_code().as_str(),
            "PLATFORM.PRIV.CAPABILITY_MISSING",
            format!("the WFP engine could not be opened: {error}"),
        )
    })
}

/// The non-Windows answer.
#[cfg(not(windows))]
fn build_adapter() -> Result<twinvpn_platform_windows::WindowsPlatformAdapter, StartupRefusal> {
    Err(StartupRefusal::platform(
        "PLATFORM.OS_UNSUPPORTED",
        "PLATFORM.OS_UNSUPPORTED",
        "WindowsPlatformAdapter::new is #[cfg(windows)]: there is no Wintun, no WFP engine \
         and no CNG here, and a constructor that pretended otherwise would bind an \
         enforcement engine that lives in a HashMap"
            .to_owned(),
    ))
}

/// The vault directory. ADR-0020 §11.9's Windows row.
#[cfg(windows)]
fn store_root() -> std::path::PathBuf {
    // The installer sets it; the default is the production value
    // (`infra/README.md`'s convention). CB-7: injected, never discovered — and
    // an environment variable the installer wrote is an injection.
    std::env::var_os("TWINVPN_STORE_ROOT").map_or_else(
        || std::path::PathBuf::from(twinvpn_platform_windows::custody::DEFAULT_STORE_ROOT),
        Into::into,
    )
}

/// The enforcement facts the seam does not carry.
#[cfg(windows)]
fn enforcement_config() -> twinvpn_platform_windows::wfp::EnforcementConfig {
    twinvpn_platform_windows::wfp::EnforcementConfig {
        // Zero until the tunnel device is created: the Tier-2 permit is
        // interface-scoped and the interface does not exist yet, so a
        // pre-arming render carries no overlay permit at all — which is
        // `RULESET_BLOCKED` by construction and the correct posture for step 5.
        overlay_luid: 0,
        service_app_id: "",
        service_sid: "",
        // ADR-0012 KS-4: `ALLOW` is the default in all three routing modes. The
        // setting itself is S-24's and reaches the adapter through a later
        // `apply`; this is the pre-arming value.
        local_network_access: true,
        on_link_prefixes: Vec::new(),
        updater_app_id: None,
        update_origins: Vec::new(),
        portal_grant: Vec::new(),
    }
}

/// The stub's four listening addresses (ADR-0011 §11.2's Windows row).
#[cfg(windows)]
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
        // AP-2's reserved service block.
        anycast_v4: IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53])),
        anycast_v6: IpAddr::V6(
            V6Addr::new(anycast6, None).expect("the service anycast is well formed"),
        ),
    }
}
