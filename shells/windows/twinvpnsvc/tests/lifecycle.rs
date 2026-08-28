//! The shell's share of the required matrix, driven end to end on this host.
//!
//! **Authority:** the wave-2 objective's test matrix — startup, shutdown,
//! **UI/service separation**, network change, **suspend/resume**, service
//! restart — plus ADR-0016 PS-3, PS-14, §11.6; ADR-0017 MI-S1, MI-S2, MI-3,
//! §11.7; ADR-0022 LC-4, LC-19, LC-20, LC-22, LC-24; ADR-0015 O-18.
//!
//! # What these tests are, and what they are not
//!
//! **This host is Linux.** `twinvpnsvc` cannot be linked or run as a Windows
//! service here, so none of these tests touches the SCM, a named pipe or a
//! client token. What they do exercise is everything above those three:
//!
//! - the **MI end to end** — a real [`twinvpnsvc::mi::Client`] against the real
//!   [`twinvpnsvc::service::server::serve`], over `tokio::io::duplex`, with a
//!   real [`twinvpn_core::Core`] bound to the **mock adapter**. That is CD-5's
//!   payoff: "100% of the decision logic on a Linux CI runner with no VM and no
//!   device farm";
//! - the **start sequence** and the **SCM status machine**, as values;
//! - the **resume ordering** and LC-22's no-stale-green rule.
//!
//! The enforcement, route, DNS and leak half of the matrix belongs to the
//! adapter and is in `core/crates/twinvpn-platform-windows/tests/enforcement.rs`.
//! It is not duplicated here.
//!
//! Everything that genuinely needs Windows — the pipe listener, the token read,
//! the power events — is `#[cfg(windows)]`, compiles under `make cross-check`,
//! and **has never executed**.

#![cfg(feature = "core-host")]

use std::sync::Arc;

use twinvpn_env::{Entropy, Env, EnvError};
use twinvpn_mgmt::Scope;
use twinvpn_platform::mock::{MockAdapter, MockOptions};
use twinvpn_platform::PlatformAdapter;

use twinvpnsvc::mi::dacl::PrincipalSids;
use twinvpnsvc::mi::wire::PlatformCtx;
use twinvpnsvc::mi::Client;
use twinvpnsvc::service::peer::{Principal, SessionKind};
use twinvpnsvc::service::power::{
    classify_wake, ProtectionIndicator, ResumeSequence, WakeClassification,
};
use twinvpnsvc::service::scm::{self, Action, Control, ServiceState};
use twinvpnsvc::service::server::{self, ServerContext};
use twinvpnsvc::service::{runtime, StartSequence};

/// The one thing a host that is not Windows cannot supply.
///
/// `BCryptGenRandom` refuses off Windows — deliberately, because a fixed
/// "random" value is indistinguishable from working and produces predictable
/// nonces. So a test that needs an `Env` injects its own and says so;
/// `runtime::build_env` passes the platform CSPRNG and nothing else.
struct FixedEntropy;

impl Entropy for FixedEntropy {
    fn fill(&self, dst: &mut [u8]) -> Result<(), EnvError> {
        for (index, byte) in dst.iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap_or(0);
        }
        Ok(())
    }
}

fn sids() -> PrincipalSids {
    PrincipalSids {
        service: "S-1-5-80-4242".to_owned(),
        observe: "S-1-5-21-1-2-3-1001".to_owned(),
        operate: "S-1-5-21-1-2-3-1002".to_owned(),
    }
}

fn operator() -> Principal {
    Principal {
        user_sid: "S-1-5-21-1-2-3-1050".to_owned(),
        enabled_group_sids: vec![sids().operate.clone()],
        session: SessionKind::Console,
        pid: 4242,
        account: Some("dana".to_owned()),
    }
}

/// A real core over the mock adapter, and the context that serves it.
fn context(env: &Env, adapter: &Arc<MockAdapter>) -> Arc<ServerContext> {
    let core = runtime::build_core(
        env,
        Arc::clone(adapter) as Arc<dyn PlatformAdapter>,
        // The mock reports no element, truthfully.
        false,
        "core-held",
    )
    .expect("the ABI matches, so the core is created");
    Arc::new(ServerContext {
        core: Arc::new(core),
        env: env.clone(),
        sids: sids(),
        platform_ctx: PlatformCtx {
            platform: "windows".to_owned(),
            os_version: "10.0.26100".to_owned(),
        },
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::new(twinvpnsvc::service::events::Fanout::new()),
    })
}

fn env() -> Env {
    runtime::build_env_with(Arc::new(FixedEntropy))
        .expect("the runtime binds")
        .0
}

/// A current-thread runtime, built here rather than through `#[tokio::test]` so
/// nothing in this file names the runtime's time module — CD-3 denies
/// `tokio::time` everywhere outside `twinvpn-env`'s binding, and a test is not
/// an exemption.
fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("a current-thread runtime")
        .block_on(future)
}

// ---------------------------------------------------------------------------
// UI / service separation — PS-3, LC-19, LC-20
// ---------------------------------------------------------------------------

#[test]
fn a_client_attaches_negotiates_and_is_granted_its_principals_scopes() {
    // MI-S1 end to end: `policy(principal) ∩ requested`, computed at attach from
    // an OS fact, over a real client and a real server.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });

        let requested: Vec<String> = twinvpnsvc::mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|s| s.name().to_owned())
            .collect();
        let client = Client::attach(client_side, "cli", "0.1.0", &requested)
            .await
            .expect("the attach succeeds");

        let granted = client.granted();
        // An operator holds OBSERVE and OPERATE...
        assert!(granted.holds(Scope::Status));
        assert!(granted.holds(Scope::Connect));
        assert!(granted.holds(Scope::Settings));
        // ...and not ADMINISTER, which it did not request and does not hold.
        assert!(!granted.holds(Scope::Admin));
        assert!(!granted.holds(Scope::Disarm), "never granted at attach");

        // MI-C3: the platform context is the AGENT's, used verbatim.
        assert_eq!(client.platform_ctx().platform, "windows");
        // §11.7: the catalogue, not the version, is the capability contract.
        assert!(!client.catalogue_digest().is_empty());

        drop(client);
        served
            .await
            .expect("the task joined")
            .expect("a clean close");
    });
}

#[test]
fn ps3_a_client_detaching_changes_nothing() {
    // "Loss of the last management client MUST NOT change `session_intent`,
    // enforcement mode, the installed rule set, or any `ConnectionState`."
    // LC-20 calls it "the single most important rule in this subsection".
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    let before = block_on(async {
        twinvpn_platform::NetworkConfig::installed_ruleset(adapter.network_config())
            .await
            .expect("the mock answers")
    });
    let generation_before = context.core.generation();

    block_on({
        let context = Arc::clone(&context);
        let adapter = Arc::clone(&adapter);
        async move {
            let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
            let served = tokio::spawn({
                let context = Arc::clone(&context);
                async move { server::serve(context, operator(), &mut server_side).await }
            });
            let client = Client::attach(client_side, "gui", "0.1.0", &[])
                .await
                .expect("attaches");
            // The client dies. Not a `Goodbye` — a drop, which is what a UI
            // crashing looks like.
            drop(client);
            served
                .await
                .expect("the task joined")
                .expect("a detach is a clean close, not an error");

            let after =
                twinvpn_platform::NetworkConfig::installed_ruleset(adapter.network_config())
                    .await
                    .expect("the mock answers");
            assert_eq!(after, before, "the installed ruleset is unchanged");
        }
    });

    assert_eq!(
        context.core.generation(),
        generation_before,
        "no state changed because a client went away"
    );
    // And the adapter still reports the same enforcement custody: LC-19 makes
    // the daemon the authority and the UI a replica, so a replica dying is not
    // an event the authority acts on.
    assert!(
        twinvpn_platform::NetworkConfig::enforcement_custody(adapter.network_config())
            .survives_core_exit()
    );
}

#[test]
fn mi3_a_client_that_sends_an_agent_only_body_is_answered_and_closed() {
    // "The agent MUST NOT initiate a request" has a mirror: a client that sends
    // a *response* has broken the protocol, and §11.7 forbids a silent close.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    block_on(async move {
        let (mut client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });

        // A `Response` as the FIRST message, where a `Hello` belongs.
        let envelope = twinvpnsvc::mi::wire::MgmtEnvelope {
            mi_version: twinvpnsvc::mi::MI_VERSION,
            request_id: vec![1; 16],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: twinvpnsvc::mi::wire::Body::Response(twinvpnsvc::mi::wire::Response {
                ok: true,
                result: Vec::new(),
                diagnostic: None,
                committed_at_net_seq: None,
            }),
        };
        twinvpnsvc::mi::codec::write_frame(&mut client_side, &envelope)
            .await
            .expect("writes");

        // The server answers before it closes — a silent close is
        // indistinguishable from "the agent is not running".
        let reply = twinvpnsvc::mi::codec::read_frame(&mut client_side)
            .await
            .expect("the server answered rather than closing silently");
        match reply.body {
            twinvpnsvc::mi::wire::Body::Reject(diagnostic) => {
                assert_eq!(diagnostic.reason_code, "PROTO.UNPARSEABLE_ENVELOPE");
            }
            other => panic!("expected a Reject, got {other:?}"),
        }
        served.await.expect("joined").expect("closed cleanly");
    });
}

#[test]
fn an_unknown_operation_is_a_typed_rejection_and_never_a_parse_failure() {
    // §11.7: "Never a parse error, never a hang, never a generic failure."
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let mut client = Client::attach(client_side, "cli", "0.1.0", &[])
            .await
            .expect("attaches");
        let error = client
            .call("status.gett", Vec::new(), None, Vec::new())
            .await
            .expect_err("an unknown name is refused");
        assert_eq!(error.reason_code(), "PROTO.CAPABILITY_MISSING");
        drop(client);
        served.await.expect("joined").expect("closed");
    });
}

#[test]
fn a_principal_with_no_scope_is_told_rather_than_rejected_and_then_denied() {
    // MI-S1: "a status-only client should still work", so a scope the principal
    // lacks is WITHHELD and named rather than being a hard rejection — and the
    // operation it would have needed is then denied by name.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    let stranger = Principal {
        enabled_group_sids: Vec::new(),
        ..operator()
    };

    block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, stranger, &mut server_side).await }
        });
        let requested: Vec<String> = twinvpnsvc::mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|s| s.name().to_owned())
            .collect();
        let mut client = Client::attach(client_side, "cli", "0.1.0", &requested)
            .await
            .expect("the attach still succeeds");
        assert!(
            client.granted().names().is_empty(),
            "a principal in no group holds nothing"
        );
        assert_eq!(
            client.withheld().len(),
            requested.len(),
            "every requested scope is named as withheld"
        );

        let error = client
            .call("status.get", Vec::new(), None, Vec::new())
            .await
            .expect_err("denied");
        assert_eq!(
            error.reason_code(),
            twinvpnsvc::service::start::emitted_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED")
        );
        drop(client);
        served.await.expect("joined").expect("closed");
    });
}

#[test]
fn an_administer_operation_is_refused_even_at_the_console_with_an_elevated_token() {
    // §11.5's third consequence: holding `mgmt.admin` is necessary and NOT
    // sufficient. There is no §11.14 ceremony in this build, so the safe
    // direction is to refuse.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    let administrator = Principal {
        enabled_group_sids: vec![twinvpnsvc::service::peer::ADMINISTRATORS_SID.to_owned()],
        session: SessionKind::Console,
        ..operator()
    };

    block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, administrator, &mut server_side).await }
        });
        let mut client = Client::attach(
            client_side,
            "cli",
            "0.1.0",
            &[Scope::Admin.name().to_owned()],
        )
        .await
        .expect("attaches");
        assert!(client.granted().holds(Scope::Admin), "the scope is held");

        let administer = twinvpn_mgmt::catalogue::catalogue()
            .into_iter()
            .find(|entry| entry.administer)
            .expect("the catalogue has at least one ADMINISTER operation");
        let error = client
            .call(administer.op.name(), Vec::new(), None, Vec::new())
            .await
            .expect_err("refused");
        assert_eq!(error.reason_code(), "MGMT.DISARM_REQUIRES_LOCAL_AUTH");
        drop(client);
        served.await.expect("joined").expect("closed");
    });
}

#[test]
fn ps14_an_administer_operation_from_a_remote_session_names_the_session_as_the_reason() {
    // An administrator on RDP must be told to go to the console, not to
    // re-elevate — so the refusal is the session one and not the scope one.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    let remote = Principal {
        enabled_group_sids: vec![twinvpnsvc::service::peer::ADMINISTRATORS_SID.to_owned()],
        session: SessionKind::Remote,
        ..operator()
    };

    block_on(async move {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, remote, &mut server_side).await }
        });
        let mut client = Client::attach(
            client_side,
            "cli",
            "0.1.0",
            &[Scope::Admin.name().to_owned()],
        )
        .await
        .expect("attaches");
        let administer = twinvpn_mgmt::catalogue::catalogue()
            .into_iter()
            .find(|entry| entry.administer)
            .expect("at least one");
        let error = client
            .call(administer.op.name(), Vec::new(), None, Vec::new())
            .await
            .expect_err("refused");
        assert_eq!(
            error.reason_code(),
            twinvpnsvc::service::start::emitted_for("PLATFORM.PRIV.REMOTE_ADMIN_REFUSED")
        );
        drop(client);
        served.await.expect("joined").expect("closed");
    });
}

#[test]
fn mi_s2_a_membership_change_takes_effect_on_the_next_attach_and_not_the_current_one() {
    // S-44: the granted set is re-derived at every attach and never cached
    // across attaches. Two attaches by two principals over one server context
    // must see two different grants.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    block_on(async move {
        for (principal, expects_connect) in [
            (operator(), true),
            (
                Principal {
                    enabled_group_sids: vec![sids().observe.clone()],
                    ..operator()
                },
                false,
            ),
        ] {
            let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
            let served = tokio::spawn({
                let context = Arc::clone(&context);
                async move { server::serve(context, principal, &mut server_side).await }
            });
            let requested: Vec<String> = twinvpnsvc::mi::CLI_REQUESTED_SCOPES
                .iter()
                .map(|s| s.name().to_owned())
                .collect();
            let client = Client::attach(client_side, "cli", "0.1.0", &requested)
                .await
                .expect("attaches");
            assert_eq!(client.granted().holds(Scope::Connect), expects_connect);
            drop(client);
            served.await.expect("joined").expect("closed");
        }
    });
}

// ---------------------------------------------------------------------------
// startup, shutdown, service restart
// ---------------------------------------------------------------------------

#[test]
fn startup_does_not_accept_connections_until_every_precondition_holds() {
    // §11.6: "Only then does it accept management connections."
    let mut sequence = StartSequence::default();
    assert!(!sequence.ready());
    sequence.single_instance = true;
    sequence.privilege_verified = true;
    sequence.env_bound = true;
    sequence.capabilities_probed = true;
    assert!(!sequence.ready(), "the ruleset has not been read back");
    sequence.ruleset_reclaimed = true;
    sequence.state_rehydrated = true;
    assert!(sequence.ready());
}

#[test]
fn a_shutdown_flushes_before_it_stops_and_never_removes_enforcement() {
    // ADR-0022 §11.4's Windows row: "Shutdown MUST NOT remove enforcement —
    // persistent WFP filters stay." There is no `Action` for removing it, in
    // any state.
    let (state, actions) = scm::on_control(ServiceState::Running, Control::PreShutdown);
    assert_eq!(state, ServiceState::StopPending { checkpoint: 1 });
    assert!(actions.contains(&Action::FlushDurableState));
    assert!(actions.contains(&Action::BeginShutdown));
    let flush = actions
        .iter()
        .position(|a| *a == Action::FlushDurableState)
        .expect("flushes");
    let shutdown = actions
        .iter()
        .position(|a| *a == Action::BeginShutdown)
        .expect("shuts down");
    assert!(flush < shutdown, "a flush after the drain never runs");
}

#[test]
fn a_service_restart_re_runs_the_whole_sequence_rather_than_resuming_it() {
    // ADR-0022 LC-26 and §11.6: a restarted service has no validated path, so it
    // re-asserts BLOCKED and re-reads. `StartSequence::default()` is what a
    // restart begins from — there is no constructor that carries a previous
    // run's flags forward.
    let restarted = StartSequence::default();
    assert!(!restarted.ready());
    assert!(!restarted.may_emit_a_packet());
    assert_eq!(restarted.first_incomplete(), Some("single-instance lock"));
}

// ---------------------------------------------------------------------------
// suspend / resume
// ---------------------------------------------------------------------------

#[test]
fn lc24_the_resume_ordering_puts_enforcement_before_the_sockets() {
    // "no packet may be emitted before this line", and the ADR restates the
    // ordering because "the temptation to re-open sockets first is strong".
    let classified = ResumeSequence {
        classified: true,
        ..ResumeSequence::default()
    };
    assert!(!classified.may_emit_a_packet());
    let verified = ResumeSequence {
        enforcement_verified: true,
        ..classified
    };
    assert!(verified.may_emit_a_packet());
    let sequence = verified;
    assert_eq!(
        sequence.next_step(),
        Some("re-acquire sockets, interface handles and subscriptions")
    );
}

#[test]
fn lc22_a_resume_publishes_unknown_and_never_a_remembered_green() {
    // The mechanism is that `resumed` consumes the indicator. There is no
    // expression that produces a post-resume `Asserted` from a pre-suspend one.
    let before = ProtectionIndicator::renew(true, true, 1_000_000);
    assert!(before.is_protected());
    let after = before.resumed();
    assert!(!after.is_protected());
    assert_eq!(after, ProtectionIndicator::Unknown);

    // Only a fresh query brings it back.
    let renewed = ProtectionIndicator::renew(true, true, 28_800_000_000);
    assert!(renewed.is_protected());
}

#[test]
fn a_reboot_is_classified_as_a_cold_start_and_not_as_a_resume() {
    // LC-24 step 1, and the reason it is first: a monotonic gap and a reboot
    // look identical, and only the boot identity separates them.
    assert_eq!(
        classify_wake([1; 16], [2; 16], 0, 28_800_000_000),
        WakeClassification::ColdStart
    );
    assert_eq!(
        classify_wake([1; 16], [1; 16], 1_000_000, 28_801_000_000),
        WakeClassification::Resume {
            gap_micros: 28_800_000_000
        }
    );
}

#[test]
fn the_gap_a_resume_reports_comes_from_the_suspend_inclusive_clock() {
    // LC-8: the monotonic clock is paused across a suspend and would report
    // zero. The two clocks are bound separately and read differently, which is
    // what makes the gap measurable at all.
    let env = env();
    let monotonic = env.now_monotonic().as_micros();
    let elapsed = env.now_elapsed().as_micros();
    assert!(
        elapsed > monotonic,
        "the elapsed clock is absolute since boot and the monotonic one zeroes \
         at construction: elapsed={elapsed} monotonic={monotonic}"
    );
}

// ---------------------------------------------------------------------------
// §11.10's event stream. `ownership.md` §10.8 M-12.
//
// This service built a core and never called `next_event`. Every test below
// failed outright before the drain existed, because there was nothing to drain:
// no client could be told that anything had changed, `event.resync` refused
// unconditionally, and every `Response.result` was empty.
// ---------------------------------------------------------------------------

use twinvpnsvc::service::events as server_events;

/// The drain, on its own thread, exactly as the service runs it.
///
/// Returned as a handle the test joins, so a leaked thread cannot make a later
/// test flaky by draining its core.
fn spawn_drain(context: &Arc<ServerContext>) -> std::thread::JoinHandle<()> {
    let core = Arc::clone(&context.core);
    let fanout = Arc::clone(&context.fanout);
    std::thread::spawn(move || {
        server_events::drain(&core, &fanout, std::time::Duration::from_millis(20));
    })
}

/// The topics a subscribing client names. §11.10 has no wildcard.
fn all_topics() -> Vec<String> {
    twinvpn_mgmt::fanout::TOPICS
        .iter()
        .map(|t| (*t).to_owned())
        .collect()
}

fn cli_scopes() -> Vec<String> {
    twinvpnsvc::mi::CLI_REQUESTED_SCOPES
        .iter()
        .map(|s| s.name().to_owned())
        .collect()
}

/// Stops the drain and joins it, so no test leaks a thread onto the next.
fn stop(context: &Arc<ServerContext>, drain: std::thread::JoinHandle<()>) {
    context.fanout.close();
    context.core.begin_shutdown();
    drain.join().expect("the drain thread joined");
}

#[test]
fn a_subscribed_client_receives_the_events_the_core_publishes() {
    // **F-5 end to end on Windows.** "All state changes arrive as events on
    // exactly one totally ordered stream per instance" — and until M-12's work
    // that stream stopped inside the core, because nothing read it.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);
    let drain = spawn_drain(&context);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });

        let mut client =
            Client::attach_subscribed(client_side, "gui", "0.1.0", &cli_scopes(), &all_topics())
                .await
                .expect("the attach succeeds");

        // A transition the core publishes on its own, with MI-18's actor.
        // `Default::default()`: this shell has no `twinvpn-schema` dependency
        // and must not acquire one (CB-2).
        #[allow(clippy::default_trait_access)]
        context
            .core
            .publish_transition(Default::default(), Some("dana".to_owned()));

        let frame = client.next_event().await.expect("an event arrives");
        let twinvpn_mgmt::Body::Event(event) = frame.body else {
            panic!("an event, not a marker")
        };
        assert_eq!(event.topic, "transition");
        // **MI-18.** "The tunnel went down" and "Dana took the tunnel down" are
        // different facts, and the attribution survives the whole path: core,
        // drain, fan-out, envelope, socket, client.
        assert_eq!(event.actor_principal.as_deref(), Some("dana"));

        drop(client);
        let _ = served.await.expect("the task joined");
    });

    stop(&context, drain);
}

#[test]
fn an_unsubscribed_client_is_not_sent_events_it_did_not_ask_for() {
    // The other half: §11.10 has no wildcard, so a client that named no topic
    // is on no stream. Without this, "subscribed" would not be a state.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);
    let drain = spawn_drain(&context);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let mut client = Client::attach(client_side, "cli", "0.1.0", &cli_scopes())
            .await
            .expect("attaches");

        #[allow(clippy::default_trait_access)]
        context.core.publish_transition(Default::default(), None);

        // The subscriber count is the fact itself rather than a proxy for it.
        let _ = client.call("version.get", Vec::new(), None, Vec::new()).await;
        assert_eq!(
            context.fanout.subscriber_count(),
            0,
            "a client that named no topic is on no stream"
        );

        drop(client);
        let _ = served.await.expect("the task joined");
    });

    stop(&context, drain);
}

#[test]
fn a_submitted_command_answers_with_the_body_the_core_published() {
    // Every `Response.result` on this platform was `Vec::new()`. `Core::submit`
    // publishes the outcome as a `command.completed` event before it returns
    // `Ok(())`, so a service that never drained the stream threw the answer away
    // and reported `ok: true` with nothing in it.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);
    let drain = spawn_drain(&context);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let mut client = Client::attach(client_side, "cli", "0.1.0", &cli_scopes())
            .await
            .expect("attaches");

        let response = client
            .call("status.get", Vec::new(), None, Vec::new())
            .await
            .expect("status.get is implemented and permitted");
        assert!(response.ok);
        assert!(
            !response.result.is_empty(),
            "the core published a body and the service must forward it, not drop it"
        );

        drop(client);
        let _ = served.await.expect("the task joined");
    });

    stop(&context, drain);
}

#[test]
fn event_resync_answers_with_a_snapshot_instead_of_refusing() {
    // It returned `MGMT.STREAM_COMPACTED` unconditionally, with a comment
    // saying "this build has no subscribed-topic snapshot to take" — true, and
    // the visible end of M-12.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);
    let drain = spawn_drain(&context);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let mut client =
            Client::attach_subscribed(client_side, "gui", "0.1.0", &cli_scopes(), &all_topics())
                .await
                .expect("attaches");

        #[allow(clippy::default_trait_access)]
        context.core.publish_transition(Default::default(), None);
        // Consume it, so the snapshot rather than the live stream is what
        // answers below.
        let _ = client.next_event().await.expect("the live event");

        let response = client
            .call("event.resync", Vec::new(), None, Vec::new())
            .await
            .expect("a subscribed client may resync");
        assert!(response.ok, "no longer an unconditional refusal");
        let body: serde_json::Value =
            serde_json::from_slice(&response.result).expect("the snapshot is JSON");
        assert!(
            body["cursor"].as_u64().expect("a cursor") >= 1,
            "MI-9's cursor is assigned inside the snapshot's lock"
        );
        assert!(
            body["rows"]
                .as_array()
                .expect("rows")
                .iter()
                .any(|r| r["topic"] == "transition"),
            "the latest event on each topic that has one"
        );

        drop(client);
        let _ = served.await.expect("the task joined");
    });

    stop(&context, drain);
}

#[test]
fn an_unsubscribed_resync_is_refused_by_its_own_name() {
    // MI-9a: "the stream dropped events, resnapshot" and "your cursor cannot be
    // serviced" are different recoveries. They were the same code until
    // `registry_version` 2 registered `MGMT.RESYNC_REQUIRED` — X-1 called this
    // pair the worst of the sixteen substitutions.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let mut client = Client::attach(client_side, "cli", "0.1.0", &cli_scopes())
            .await
            .expect("attaches");

        let refused = client
            .call("event.resync", Vec::new(), None, Vec::new())
            .await
            .expect_err("a client on no stream has no gap to recover from");
        let twinvpnsvc::mi::ClientError::Failed(diagnostic) = refused else {
            panic!("a typed failure, not a transport error: {refused:?}")
        };
        assert_eq!(diagnostic.reason_code, "MGMT.RESYNC_REQUIRED");
        assert_ne!(
            diagnostic.reason_code, "MGMT.STREAM_COMPACTED",
            "MI-9a's two conditions must stay two codes"
        );

        drop(client);
        let _ = served.await.expect("the task joined");
    });
}

#[test]
fn ps3_still_holds_with_a_stream_attached() {
    // The regression the whole of M-12's work could plausibly cause. PS-3: "Loss
    // of the last management client MUST NOT change `session_intent`,
    // enforcement mode, the installed rule set, or any `ConnectionState`." A
    // subscriber is a queue, and unsubscribing removes a queue.
    let env = env();
    let adapter = Arc::new(MockAdapter::new(&MockOptions::default()));
    let context = context(&env, &adapter);
    let drain = spawn_drain(&context);

    block_on(async {
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn({
            let context = Arc::clone(&context);
            async move { server::serve(context, operator(), &mut server_side).await }
        });
        let client =
            Client::attach_subscribed(client_side, "gui", "0.1.0", &cli_scopes(), &all_topics())
                .await
                .expect("attaches");
        let generation = context.core.generation();

        drop(client);
        let _ = served.await.expect("the task joined");

        assert_eq!(
            context.fanout.subscriber_count(),
            0,
            "the queue is released"
        );
        assert_eq!(
            context.core.generation(),
            generation,
            "and nothing else changed"
        );
        assert!(!context.core.is_poisoned());
    });

    stop(&context, drain);
}
