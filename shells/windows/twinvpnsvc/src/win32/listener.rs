//! Step 8 of ADR-0016 §11.6: accept on the endpoint [`super::endpoint`] bound,
//! and the hosting the served connections need.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.6 steps (7) and (8), PS-3, PS-13, PS-18;
//! [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7, §11.10, MI-A1, MI-A3, MI-A4, MI-A5, MI-C3;
//! [ADR-0022](../../../../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
//! §11.4 and LC-5; ADR-0018 CD-2, CD-3, CB-6, F-6; `ownership.md` §6 rule 7.
//!
//! # The instance cap is ours, not the kernel's
//!
//! [`crate::mi::MAX_PIPE_INSTANCES`] bounds the agent's own memory. It is
//! enforced with a semaphore and **not** with `nMaxInstances`, for one reason:
//! the kernel's cap answers `ERROR_PIPE_BUSY`, and CD-3 keeps `tokio::time` out
//! of this crate, so there would be no way to wait it out that is not a spin. A
//! permit is exactly the wait that a busy status is not.
//!
//! # This module names the core, so it has no Windows compile proof here
//!
//! `ring` reaches this crate through `twinvpn-core`, and its build script
//! refuses a GNU compiler for `x86_64-pc-windows-msvc` — so on a Linux host
//! **nothing in this file can be type-checked for Windows**. That is why
//! [`super::endpoint`] is a separate module: every `unsafe` block and every
//! `windows-sys` signature lives there, where `--features service` does check it.
//! What is left here is ordinary `tokio`, and it is first compiled by the hosted
//! `windows-link-run` job.

use std::os::windows::io::AsRawHandle as _;
use std::sync::Arc;

use tokio::io::Interest;
use tokio::net::windows::named_pipe::NamedPipeServer;
use twinvpn_platform::PlatformAdapter as _;

use crate::mi::codec::write_frame;
use crate::mi::dacl::{self, BindRefusal};
use crate::mi::wire::{Body, PlatformCtx};
use crate::service::server::{self, ServerContext};
use crate::service::{events, StartupRefusal};

use super::endpoint::{self, instance};
use super::Failure;

/// How long the drain thread sits in one `Core::next_event` call.
///
/// **Not a deadline for anything.** CD-3 makes timeouts the core's; this bounds
/// how long the thread is unresponsive to a shutdown that has already been
/// requested, which is a property of this thread and of no protocol.
/// `service::runtime` and `shells/linux/twinvpnd` carry the same value for the
/// same reason.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Steps 7 and 8, from the caller's thread.
///
/// # The ordering the SCM half depends on
///
/// 1. resolve PS-12a's principals and render the descriptor;
/// 2. start §11.10's drain, so a result is never an empty body;
/// 3. **bind** the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`;
/// 4. call `on_ready` — §11.6's "**only then** does it accept management
///    connections", and the point at which `SERVICE_RUNNING` becomes true;
/// 5. accept until `stop`.
///
/// `on_ready` is called on **this** thread, between the bind and the first
/// accept, and never at all if the bind failed. That is why the bind and the
/// accept are two `block_on` calls rather than one: `&mut dyn FnMut()` is not
/// `Send`, and `twinvpn_env::Runtime::block_on` takes a `Send` future.
///
/// # LC-5
///
/// `lock` is moved in and dropped on the way out. A live authority holds it for
/// as long as it is one, and making that a move rather than a comment is what
/// stops an early release.
///
/// # Errors
///
/// [`StartupRefusal`] carrying `MGMT.LISTEN_FAILED` when the endpoint cannot be
/// created — PS-18: a service that reached `SERVICE_RUNNING` with no management
/// endpoint would be reporting itself as running while being unmanageable.
pub fn serve(
    env: &twinvpn_env::Env,
    runtime: &Arc<twinvpn_env::binding::tokio_rt::TokioRuntime>,
    adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
    core: &Arc<twinvpn_core::Core>,
    lock: super::instance::InstanceLock,
    stop: tokio::sync::watch::Receiver<bool>,
    on_ready: &mut dyn FnMut(),
) -> Result<(), StartupRefusal> {
    let sids = endpoint::principals().map_err(refusal)?;
    let sddl = dacl::pipe_sddl(&sids);
    // PS-17's discipline, applied to a descriptor this build wrote itself:
    // refusing rather than warning, because installing one that does not match
    // PS-12a would make every later authorization decision rest on an ACL nobody
    // had checked.
    if !dacl::matches_ps12a(&sddl, &sids) {
        return Err(StartupRefusal::internal(format!(
            "the rendered pipe descriptor does not match ADR-0016 PS-12a: {sddl}"
        )));
    }
    let name = crate::mi::pipe_name();

    // §11.10's stream, and the thread that feeds it. Started BEFORE the endpoint
    // exists: a client that attached to a service with no drain would be told
    // `ok: true` with an empty body, because `Core::submit` publishes an
    // operation's outcome as an event before it returns.
    let fanout = Arc::new(events::Fanout::new());
    let drain = std::thread::Builder::new()
        .name("twinvpn-mi-drain".to_owned())
        .spawn({
            let core = Arc::clone(core);
            let fanout = Arc::clone(&fanout);
            move || events::drain(&core, &fanout, DRAIN_TIMEOUT)
        })
        .map_err(|error| {
            StartupRefusal::platform(
                dacl::LISTEN_FAILED,
                dacl::LISTEN_FAILED,
                format!("the event drain thread could not be spawned: {error}"),
            )
        })?;

    let context = Arc::new(ServerContext {
        core: Arc::clone(core),
        env: env.clone(),
        sids,
        // **MI-C3**: built once and handed to every client verbatim.
        platform_ctx: PlatformCtx {
            platform: "windows".to_owned(),
            os_version: os_version(),
        },
        // **F-6 / S-47.** One mutex for the whole process, so two clients cannot
        // submit concurrently.
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::clone(&fanout),
    });

    // ---- 7. bind ---------------------------------------------------------
    let mut bound = None;
    {
        let slot = &mut bound;
        let (name, sddl) = (&name, &sddl);
        twinvpn_env::Runtime::block_on(
            runtime.as_ref(),
            Box::pin(async move {
                *slot = Some(instance(name, sddl, true));
            }),
        );
    }
    let listening = match bound {
        Some(Ok(server)) => server,
        Some(Err(bind)) => {
            close(&fanout, core, drain, adapter);
            return Err(refusal(bind));
        }
        None => {
            close(&fanout, core, drain, adapter);
            return Err(StartupRefusal::internal(
                "block_on returned without driving the bind".to_owned(),
            ));
        }
    };
    tracing::info!(
        target: "twinvpn.mi",
        endpoint = %name,
        owner = %context.sids.service,
        created_by = %endpoint::own_user_sid().unwrap_or_else(|error| error.to_string()),
        "the management endpoint is bound with the DACL this start wrote (MI-A3)"
    );

    // ---- §11.6's line ----------------------------------------------------
    on_ready();

    // ---- 8. accept -------------------------------------------------------
    let mut outcome = Ok(());
    {
        let slot = &mut outcome;
        let context = Arc::clone(&context);
        let (name, sddl) = (name.clone(), sddl.clone());
        twinvpn_env::Runtime::block_on(
            runtime.as_ref(),
            Box::pin(async move {
                *slot = accept(listening, name, sddl, context, stop).await;
            }),
        );
    }

    close(&fanout, core, drain, adapter);
    // LC-5, explicitly rather than by falling off the end: the release point is
    // the thing a reader is looking for.
    drop(lock);
    outcome
}

/// §11.6 step 8, until `stop`.
///
/// `pub` because it is the half of the seam `scm-coder`'s stop channel drives,
/// and `tests/mgmt_listener.rs` is what pins that contract: a stop must end this
/// loop, and it must end it without waiting for a client. [`serve`] is not
/// testable on a CI runner — it needs the WFP engine and LC-5's `Global\` mutex
/// — so the contract is asserted here instead of nowhere.
pub async fn accept(
    first: NamedPipeServer,
    name: String,
    sddl: String,
    context: Arc<ServerContext>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<(), StartupRefusal> {
    let cap = usize::try_from(crate::mi::MAX_PIPE_INSTANCES).unwrap_or(usize::MAX);
    let permits = Arc::new(tokio::sync::Semaphore::new(cap));
    let mut listening = first;
    // The listening instance holds a permit of its own, so the cap counts every
    // instance that exists rather than only the connected ones.
    let Ok(mut permit) = Arc::clone(&permits).acquire_owned().await else {
        return Ok(());
    };

    loop {
        let connected = tokio::select! {
            // `connect()` is cancel safe: if the other arm wins, no connection
            // event has been lost.
            () = stopped(&mut stop) => break,
            result = listening.connect() => result,
        };
        // Either way this instance is spent — it is now a connection, or a
        // listener that failed. The replacement is created before the old one is
        // handed off, so there is no window in which nothing is listening.
        let next_permit = tokio::select! {
            () = stopped(&mut stop) => break,
            permit = Arc::clone(&permits).acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let next = instance(&name, &sddl, false).map_err(refusal)?;
        let spent = std::mem::replace(&mut listening, next);
        let spent_permit = std::mem::replace(&mut permit, next_permit);

        match connected {
            Ok(()) => {
                // PS-13: concurrent clients are **served**, not serialised. F-6's
                // one-submission-at-a-time rule lives in `ServerContext`, not
                // here.
                let context = Arc::clone(&context);
                tokio::spawn(async move {
                    attach(context, spent).await;
                    drop(spent_permit);
                });
            }
            Err(error) => {
                tracing::warn!(
                    target: "twinvpn.mi",
                    detail = %error,
                    "an accept failed; the agent continues on a fresh instance"
                );
                drop(spent);
                drop(spent_permit);
            }
        }
    }

    // PS-3, on the way out: nothing here touches `session_intent`, the
    // enforcement mode, the installed rule set or any `ConnectionState`. The
    // listening instance is dropped, in-flight connections end on their own, and
    // `serve` closes the event stream so their pumps wake and return.
    tracing::info!(
        target: "twinvpn.mi",
        "the SCM asked this service to stop; the endpoint is closed to new clients"
    );
    Ok(())
}

/// One connection: attest the client, then hand it to the server.
async fn attach(context: Arc<ServerContext>, mut stream: NamedPipeServer) {
    let principal = match attest(&stream).await {
        Ok(principal) => principal,
        Err(failure) => {
            tracing::warn!(
                target: "twinvpn.mi",
                reason_code = "MGMT.PRINCIPAL_UNVERIFIABLE",
                detail = %failure,
                "the client's identity could not be read; the connection is closed (MI-A5)"
            );
            // Answered, THEN closed. §11.7 forbids a silent close: it is
            // indistinguishable from "the agent is not running", and sends the
            // user to reinstall rather than to their administrator.
            let reject = server::envelope(
                context.as_of_ms(),
                Body::Reject(server::diagnostic(
                    "MGMT.PRINCIPAL_UNVERIFIABLE",
                    "PERSISTENT",
                    "ERROR",
                    true,
                )),
            );
            let _ = write_frame(&mut stream, &reject).await;
            return;
        }
    };

    if let Err(error) = server::serve(context, principal, &mut stream).await {
        tracing::debug!(
            target: "twinvpn.mi",
            reason_code = error.reason_code().as_str(),
            "a management connection ended"
        );
    }
}

/// **MI-A1 and MI-A4**: the client's kernel-attested identity, tried before any
/// wait and retried once after one.
///
/// `ImpersonateNamedPipeClient` captures the client's context at connect for a
/// **local** pipe, which `PIPE_REJECT_REMOTE_CLIENTS` makes the only kind this
/// endpoint has — so the first attempt is expected to succeed and the fast path
/// is one syscall. Its documented caveat, that a server must first read from the
/// pipe, applies to a client reached over SMB; the retry honours it anyway rather
/// than depending on which reading is right, and it costs nothing when the first
/// attempt works.
///
/// The retry waits for **readability** rather than spinning: every client's first
/// act is its `Hello` (§11.7), so it is a wait that ends, and CD-3 leaves no
/// timer in this crate to bound a spin with. A client that connects and never
/// writes therefore parks one instance — which is the local denial of
/// *management* ADR-0017's threat table already accepts, in the fail-closed
/// direction.
///
/// # Errors
///
/// The [`Failure`] the second attempt reported. There is no fallback principal
/// and no anonymous tier (MI-A5).
async fn attest(stream: &NamedPipeServer) -> Result<crate::service::peer::Principal, Failure> {
    // SAFETY: the handle belongs to `stream`, which is borrowed for the whole
    // call, and `connect()` returned before this task was spawned — so it is a
    // live, connected pipe handle, which is exactly the contract
    // `read_client_principal` states.
    let first = unsafe { super::pipe::read_client_principal(stream.as_raw_handle()) };
    let Err(_) = first else {
        return first;
    };
    stream
        .ready(Interest::READABLE)
        .await
        .map_err(|_| Failure::of("ImpersonateNamedPipeClient"))?;
    // SAFETY: as above; the handle is unchanged and still owned by `stream`.
    unsafe { super::pipe::read_client_principal(stream.as_raw_handle()) }
}

/// Resolves when the SCM has asked this service to stop.
///
/// Level-triggered rather than edge-triggered: the value is read before the wait,
/// so a stop that arrived before this future existed is not missed. A **dropped**
/// sender is a stop too — the half that would have flipped it is gone, and
/// continuing to accept would leave a service nobody can stop.
async fn stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    while !*stop.borrow_and_update() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// `ownership.md` §6 rule 7's shutdown order, minus the step that is the
/// listener's own.
///
/// > the runtime stops accepting work, the event stream closes so a drain thread
/// > unblocks, and the adapter is told last — and telling the adapter **does
/// > not** remove the installed ruleset.
///
/// ADR-0022 §11.4's Windows row is the same sentence in the SCM's vocabulary:
/// "Shutdown MUST NOT remove enforcement — persistent WFP filters stay." Nothing
/// on this path calls `disarm`.
fn close(
    fanout: &Arc<events::Fanout>,
    core: &Arc<twinvpn_core::Core>,
    drain: std::thread::JoinHandle<()>,
    adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
) {
    fanout.close();
    // `close` sets the flag; `wake` cancels the `next_event` the drain is already
    // inside, so the join costs nothing rather than up to `DRAIN_TIMEOUT` — which
    // is what keeps the whole stop inside ADR-0022 §11.4's 2000 ms budget.
    core.wake();
    let _ = drain.join();
    tracing::info!(
        target: "twinvpn.service",
        custody_survives_exit = twinvpn_platform::NetworkConfig::enforcement_custody(
            adapter.network_config()
        )
        .survives_core_exit(),
        "the management endpoint is closed; the installed enforcement ruleset is left in \
         the OS's custody (CB-6)"
    );
}

/// The OS version this build reports in MI-C3's `platform_ctx`.
///
/// Read from the environment rather than from `RtlGetVersion`, because a version
/// string is **diagnostic** — ADR-0017 §11.7 makes the *catalogue* the capability
/// contract, not the version — and adding an `ntdll` import to this shell for one
/// log field would be the wrong trade. `tests/windows_link_run.rs` records the
/// same decision and this is the production half of it.
fn os_version() -> String {
    std::env::var("OS").unwrap_or_else(|_| "windows".to_owned())
}

/// A [`BindRefusal`] as the refusal `main` reports.
fn refusal(bind: BindRefusal) -> StartupRefusal {
    StartupRefusal::platform(
        bind.reason_code(),
        bind.reason_code(),
        bind.detail().to_owned(),
    )
}
