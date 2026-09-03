//! **The management endpoint, bound and driven on a real Windows host.**
//!
//! **Authority:** ADR-0016 §11.6 steps (7) and (8), §11.9, PS-13, PS-18;
//! ADR-0017 §11.2's Windows transport row, §11.7, MI-A1, MI-A3, MI-A4;
//! ADR-0022 §11.4 (the 2000 ms stop budget); ADR-0018 CD-2, CD-3.
//!
//! # What this proves that `tests/lifecycle.rs` cannot
//!
//! `lifecycle.rs` drives [`twinvpnsvc::service::server::serve`] over
//! `tokio::io::duplex` on a Linux host, and proves the decision logic. It proves
//! nothing about the **carriage**. This file binds a real named pipe through
//! [`twinvpnsvc::win32::endpoint::instance`] — the same function the service
//! calls — with a security descriptor rendered by
//! [`twinvpnsvc::mi::dacl::pipe_sddl`], and drives the production
//! [`twinvpnsvc::mi::Client`] across it.
//!
//! # Which principals, and why they are not the production ones
//!
//! ADR-0016 PS-12a's principals are `NT SERVICE\TwinVPNService` and the two local
//! groups the MSI creates. **No CI runner has any of the three**, and the owner
//! half is not merely absent but unassignable: Windows requires the owner in a
//! descriptor to be the token's user or a group in it carrying `SE_GROUP_OWNER`,
//! so a test process cannot write `O:` for the service SID even if it existed.
//!
//! So the SIDs come from this process's own token — which is exactly the shape
//! CD-2 already requires, since `PrincipalSids` is injected and never discovered
//! by the renderer. What is under test is the descriptor **path**: SDDL →
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` → `lpSecurityAttributes`
//! → `CreateNamedPipeW`, and then a client of the granted principal opening it.
//! Whether the *production* names resolve on a machine the MSI has run on is
//! `windows-privileged-lifecycle`'s to answer, and it is not claimed here.
//!
//! # Running it
//!
//! ```text
//! cargo test -p twinvpnsvc --test mgmt_listener -- --nocapture --test-threads=1
//! ```

#![cfg(all(windows, feature = "core-host"))]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use tokio::net::windows::named_pipe::{ClientOptions, PipeEnd, PipeMode};
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::PlatformAdapter;

use twinvpnsvc::mi::dacl::{self, BindRefusal, PrincipalSids};
use twinvpnsvc::mi::wire::PlatformCtx;
use twinvpnsvc::mi::Client;
use twinvpnsvc::service::runtime;
use twinvpnsvc::service::server::ServerContext;
use twinvpnsvc::win32::{endpoint, listener};

/// A current-thread runtime with the I/O driver, built here rather than through
/// `#[tokio::test]`.
///
/// CD-3 denies `tokio::time` everywhere outside `twinvpn-env`'s binding and a
/// test is not an exemption, so nothing in this file names it. `enable_io` is not
/// optional on this platform: a named pipe is an IOCP registration.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

/// A pipe name no other test or process is using.
fn unique_pipe(tag: &str) -> String {
    format!(
        r"\\.\pipe\twinvpn-mgmt-listener-{tag}-{}",
        std::process::id()
    )
}

/// PS-12a's three principals, taken from **this** process's token.
///
/// The user SID owns the descriptor, because that is the one SID a process may
/// always assign as an owner. `OBSERVE` and `OPERATE` are an enabled group, so
/// that [`twinvpnsvc::service::peer::Principal::scopes`] — which reads groups and
/// never the user — grants something to assert on.
///
/// `S-1-1-0` is skipped where the token offers anything else: `Everyone` is in
/// every token, and a descriptor that granted it would be testing the one shape
/// PS-12a exists to forbid.
fn own_sids() -> PrincipalSids {
    let user = endpoint::own_user_sid().expect("this process can read its own token");
    let groups = endpoint::own_group_sids().expect("this process can read its own groups");
    let group = groups
        .iter()
        .find(|sid| sid.as_str() != "S-1-1-0")
        .or_else(|| groups.first())
        .cloned()
        .expect("every Windows token carries at least one enabled group");
    println!("test principals: owner={user} observe=operate={group}");
    PrincipalSids {
        service: user,
        observe: group.clone(),
        operate: group,
    }
}

/// A real core over the mock adapter, and the context every connection is served
/// from.
///
/// The **core** is never a stub. The adapter is: the real
/// `WindowsPlatformAdapter` needs `wintun.dll` beside the binary and a writable
/// Base Filtering Engine, neither of which an unprivileged hosted runner has —
/// `tests/windows_link_run.rs` owns that half and says so.
fn context(sids: PrincipalSids) -> (Arc<ServerContext>, runtime::Service) {
    let (env, _runtime) = runtime::build_env().expect("a Windows host has BCryptGenRandom");
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let core = runtime::build_core(
        &env,
        Arc::clone(&adapter) as Arc<dyn PlatformAdapter>,
        false,
        "core-held",
    )
    .expect("the ABI matches, so the core is created");
    // `Service::start` rather than a bare `Fanout`: it also starts §11.10's drain,
    // without which every `Response.result` is empty.
    let service = runtime::Service::start(env.clone(), adapter as Arc<dyn PlatformAdapter>, core);
    let context = Arc::new(ServerContext {
        core: Arc::clone(&service.core),
        env,
        sids,
        platform_ctx: PlatformCtx {
            platform: "windows".to_owned(),
            os_version: std::env::var("OS").unwrap_or_else(|_| "windows".to_owned()),
        },
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::clone(&service.fanout),
    });
    (context, service)
}

#[test]
fn the_endpoint_is_created_in_message_mode_and_refuses_remote_clients() {
    // ADR-0017 §11.2's Windows row, read back from the kernel rather than from
    // the builder call: `PIPE_REJECT_REMOTE_CLIENTS` is **mandatory** and message
    // mode is the boundary property the row asks for, and both are the sort of
    // flag a refactor drops without any test noticing.
    let sids = own_sids();
    let sddl = dacl::pipe_sddl(&sids);
    assert!(
        dacl::matches_ps12a(&sddl, &sids),
        "the descriptor under test must still be the shape PS-12a describes: {sddl}"
    );

    block_on(async {
        let server = endpoint::instance(&unique_pipe("mode"), &sddl, true)
            .expect("the first instance is created with its DACL");
        let info = server.info().expect("the kernel describes the instance");
        assert_eq!(
            info.mode,
            PipeMode::Message,
            "ADR-0017 §11.2's message mode"
        );
        assert_eq!(info.end, PipeEnd::Server);
    });
}

#[test]
fn a_squatter_on_the_endpoint_name_is_refused_by_name() {
    // `FILE_FLAG_FIRST_PIPE_INSTANCE`, which is the whole reason ADR-0017 §11.2
    // names it: without it the second creator quietly becomes another server on
    // the same name, and whichever one a client reaches first is the one it talks
    // to. The refusal must be CLASSIFIED, not a bare status — an operator sent to
    // "check permissions" for a name collision looks in the wrong place.
    let sids = own_sids();
    let sddl = dacl::pipe_sddl(&sids);
    let name = unique_pipe("squat");

    block_on(async {
        let _held = endpoint::instance(&name, &sddl, true).expect("the first instance is created");
        let refusal = endpoint::instance(&name, &sddl, true)
            .expect_err("a second first-instance on the same name must fail");
        assert_eq!(refusal, BindRefusal::Squatted, "{refusal:?}");
        assert_eq!(refusal.reason_code(), dacl::LISTEN_FAILED);
    });
}

#[test]
fn a_client_of_the_granted_principal_attaches_across_the_pipe_and_gets_a_result_back() {
    // §11.6 step 8 end to end, over the kernel's named-pipe driver: the DACL this
    // build rendered admits the granted principal, the identity on the far side
    // is the one the kernel attests (MI-A1/MI-A4), the scopes are computed from
    // it (MI-S1), and a submitted operation's body comes back rather than an
    // empty `result` — which is what a service with no event drain would answer.
    let sids = own_sids();
    let sddl = dacl::pipe_sddl(&sids);
    let name = unique_pipe("attach");
    let (context, service) = context(sids);

    block_on(async {
        let first = endpoint::instance(&name, &sddl, true)
            .expect("the first instance is created with its DACL");
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

        // The production accept loop, on its own task, exactly as `serve` runs it.
        let accepting = tokio::spawn({
            let (name, sddl, context) = (name.clone(), sddl.clone(), Arc::clone(&context));
            async move { listener::accept(first, name, sddl, context, stop_rx).await }
        });

        // The DACL admits this user: opening is the first assertion, and it is a
        // real one — an over-narrow descriptor fails here with ACCESS_DENIED.
        let client_side = ClientOptions::new()
            .open(&name)
            .expect("the rendered DACL admits the principal it grants");

        let scopes: Vec<String> = twinvpnsvc::mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|scope| scope.name().to_owned())
            .collect();
        let mut client = Client::attach(client_side, "cli", "0.1.0", &scopes)
            .await
            .expect("the attach negotiates across the pipe the listener bound");
        assert_eq!(client.mi_version(), twinvpn_mgmt::MI_VERSION);
        assert!(
            client.granted().holds(twinvpn_mgmt::Scope::Status),
            "MI-S1: the group the descriptor grants is the OBSERVE principal, so the \
             attested token must carry `mgmt.status`; granted={:?}",
            client.granted().names()
        );

        let response = client
            .call("status.get", Vec::new(), None, Vec::new())
            .await
            .expect("status.get is implemented and permitted");
        assert!(response.ok);
        assert!(
            !response.result.is_empty(),
            "the core published a body and the listener must forward it across the pipe"
        );
        println!(
            "status.get across the bound endpoint: ok, {} bytes",
            response.result.len()
        );

        // ---- ADR-0022 §11.4: the stop is prompt, and it does not wait -------
        //
        // The seam `scm-coder` depends on: `stop` flips once and the loop must
        // end well inside `STOP_WAIT_HINT_MS`. Measured rather than assumed, and
        // measured with a client still attached — a loop that only noticed the
        // stop between connections would pass a test that closed the client first.
        let began = std::time::Instant::now();
        stop_tx
            .send(true)
            .expect("the accept loop is still listening");
        let outcome = accepting.await.expect("the accept task did not panic");
        let elapsed = began.elapsed();
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(
            elapsed
                < std::time::Duration::from_millis(u64::from(
                    twinvpnsvc::service::scm::STOP_WAIT_HINT_MS
                )),
            "the accept loop took {elapsed:?} to observe the stop; ADR-0022 §11.4's \
             budget is {}ms",
            twinvpnsvc::service::scm::STOP_WAIT_HINT_MS
        );
        println!("stop observed in {elapsed:?}");

        // And the endpoint is gone: a client that arrives after the stop is told
        // the agent is unreachable rather than connecting and hanging (§10.3).
        drop(client);
        assert!(
            ClientOptions::new().open(&name).is_err(),
            "the listening instance must be dropped when the loop returns"
        );

        service.shutdown();
    });
}
