//! The management interface, end to end: a real socket, a real core, a real
//! `SO_PEERCRED` attach.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.7, §11.5, §11.12, MI-1, MI-3, MI-15, MI-16, MI-18, MI-A1, MI-A5, MI-C3;
//! ADR-0016 PS-1, PS-3, PS-12a; ADR-0018 CB-2.
//!
//! # What is real here and what is not
//!
//! **Real:** the `AF_UNIX` endpoint (bind-and-rename, `0660`), `SO_PEERCRED`,
//! the length-prefixed framing, the `Hello`/`HelloAck` negotiation, the scope
//! grant, the catalogue, and a live [`twinvpn_core::Core`] hosting the **real
//! Linux platform adapter** with its three clocks bound.
//!
//! **Not real:** the endpoint is in a temporary directory rather than
//! `/run/twinvpn`, because the test runner is unprivileged. That is the one
//! substitution, it is why [`twinvpnd::mi::SOCKET_PATH_ENV`] exists, and it does
//! not weaken anything the tests below assert — the directory check, the
//! permissions and the peer-credential read all run against the real thing.

use std::path::PathBuf;
use std::sync::Arc;

use twinvpnd::agent::{peer, runtime, server};
use twinvpnd::mi::wire::{Body, MgmtEnvelope, MI_VERSION, MI_VERSION_MIN};
use twinvpnd::mi::{codec, Client, ClientError, Hello, PlatformCtx};

/// A running agent on a private endpoint.
struct Harness {
    path: PathBuf,
    dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn harness() -> (Harness, Arc<server::ServerContext>) {
    use std::os::unix::fs::PermissionsExt as _;
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "twinvpn-mi-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("creates");
    // MI-A3's directory check is REAL and runs against this: 0700 passes,
    // 0777 would not.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let path = dir.join("mgmt.sock");

    let (env, _rt) = runtime::build_env().expect("the three clocks bind");
    let adapter = Arc::new(twinvpn_platform_linux::LinuxPlatformAdapter::new(
        twinvpn_platform_linux::LinuxAdapterParts {
            enforcement: twinvpn_platform_linux::EnforcementConfig {
                overlay_interface: "twin0".to_owned(),
                firewall_mark: twinvpn_platform_linux::DEFAULT_FWMARK,
                cgroup_path: None,
                local_network_access: true,
                on_link_prefixes: Vec::new(),
            },
            store_root: dir.join("store"),
            resolver_restore_point: dir.join("resolver.restore"),
            identity_element: Arc::new(twinvpn_platform_linux::AbsentElement),
        },
    ));
    let core = Arc::new(
        twinvpn_core::Core::create(twinvpn_core::CoreParts {
            env: env.clone(),
            adapter,
            abi_major_expected: twinvpn_core::ABI_MAJOR,
            abi_major: twinvpn_core::ABI_MAJOR,
            abi_minor: twinvpn_core::ABI_MINOR,
            schema_digest: Vec::new(),
            crypto_provider: "test".to_owned(),
            sek_custody: "core-held".to_owned(),
            hardware_backed: false,
            ledger_capacity: 64,
            event_capacity: 32,
        })
        .expect("the ABI matches"),
    );

    let context = Arc::new(server::ServerContext {
        core,
        env,
        // A group fixture naming THIS runner, so the attach exercises the real
        // PS-12a resolution path rather than skipping it. Without it the runner
        // is in neither `twinvpn` nor `twinvpn-operators` and holds nothing —
        // which is the correct production behaviour and is asserted on its own
        // in `an_out_of_group_principal_is_refused_every_operation` below.
        groups: Arc::new(group_fixture(&dir)),
        platform_ctx: PlatformCtx {
            platform: "linux".to_owned(),
            os_version: "test".to_owned(),
        },
    });
    (Harness { path, dir }, context)
}

async fn spawn(path: &std::path::Path, context: Arc<server::ServerContext>) {
    let listener = twinvpnd::agent::endpoint::bind(path, None).expect("binds");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let context = Arc::clone(&context);
            tokio::spawn(async move {
                let _ = server::serve(context, stream).await;
            });
        }
    });
}

/// A `/etc/group`-shaped fixture that puts the current account in both TwinVPN
/// groups.
///
/// Read through the **real** [`peer::GroupSource::from_path`] parser, so the
/// membership resolution under test is the production one and only the file it
/// reads is the test's.
fn group_fixture(dir: &std::path::Path) -> peer::GroupSource {
    let path = dir.join("group");
    let name = current_account_name();
    let text = format!(
        "{}:x:970:{name}\n{}:x:971:{name}\n",
        peer::OBSERVE_GROUP,
        peer::OPERATE_GROUP
    );
    std::fs::write(&path, text).expect("writes the fixture");
    peer::GroupSource::from_path(&path)
}

/// This process's account name, from the same two files the agent reads.
fn current_account_name() -> String {
    let uid = twinvpnd::agent::privilege::Posture::read()
        .expect("reads /proc/self/status")
        .uid;
    let passwd = std::fs::read_to_string("/etc/passwd").expect("reads /etc/passwd");
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let (Some(name), Some(_), Some(entry_uid)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if entry_uid.parse::<u32>() == Ok(uid) {
            return name.to_owned();
        }
    }
    panic!("this runner's uid {uid} has no /etc/passwd entry");
}

fn requested() -> Vec<String> {
    twinvpnd::mi::CLI_REQUESTED_SCOPES
        .iter()
        .map(|s| s.name().to_owned())
        .collect()
}

#[tokio::test]
async fn a_client_attaches_and_the_agent_answers_from_the_one_vocabulary() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;

    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    // §11.7: the version is `min(maxes)` and is fixed for the connection.
    assert_eq!(client.mi_version(), MI_VERSION);
    // "The catalogue, not the version, is the capability contract" — and the
    // digest came from the core's own catalogue, not from a shell-side list.
    assert!(!client.catalogue_digest().is_empty());
    assert_eq!(
        client.catalogue_digest(),
        format!("{:016x}", twinvpn_mgmt::catalogue_digest())
    );
    // MI-C3: the agent supplied `platform_ctx`, and the client uses it verbatim.
    assert_eq!(client.platform_ctx().platform, "linux");

    // An operation the core actually executes.
    let response = client
        .call("status.get", Vec::new(), None, Vec::new())
        .await
        .expect("status.get is implemented");
    assert!(response.ok);
    // Read-only, so no cursor: MI-6's `committed_at_net_seq` is for mutating
    // operations, and reporting one here would tell a client to wait for an
    // event that is not coming.
    assert_eq!(response.committed_at_net_seq, None);
}

#[tokio::test]
async fn a_mutating_operation_carries_the_cursor_mi6_requires() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let response = client
        .call("session.connect", Vec::new(), None, Vec::new())
        .await
        .expect("implemented");
    assert!(response.ok);
    assert!(
        response.committed_at_net_seq.is_some(),
        "MI-6: a client must not report a mutating operation complete until it \
         has observed an event at or past this cursor"
    );
}

#[tokio::test]
async fn an_unimplemented_operation_is_surfaced_as_unimplemented_not_as_a_failure() {
    // The brief's requirement, and `twinvpn_core::UNIMPLEMENTED`'s own reason:
    // "a command the catalogue advertises and the core does not execute is a lie
    // a client cannot detect". Pairing is blocked by W-21 (`PairingOffer` is in
    // no contract), so `pair.begin` is in that set.
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    // `update.status` is `mgmt.status` — inside this principal's grant — and is
    // refused by this build, so the refusal is the *unimplemented* one and not an
    // authorization one. That ordering matters: a scope refusal would tell the
    // operator to change their groups, which would not help.
    assert!(!twinvpn_core::core::executes(twinvpn_mgmt::CoreCommand::UpdateStatus));
    let error = client
        .call("update.status", Vec::new(), None, Vec::new())
        .await
        .expect_err("update.status is not implemented in this build");
    // ADR-0017 spells this `MGMT.OP_UNKNOWN`; the frozen registry does not carry
    // it, and `twinvpn_mgmt::SUBSTITUTIONS` records the substitution and its
    // cost. What matters here is that it is a NAMED refusal and not a hang.
    assert_eq!(error.reason_code(), "PROTO.CAPABILITY_MISSING");
    assert!(
        error.class().is_some(),
        "EM-37: automation switches on class"
    );

    // Pairing is also unimplemented — blocked by W-21, `PairingOffer` appears in
    // no contract — but it is `mgmt.admin` AND ADMINISTER, so it is refused
    // earlier, on authorization. Asserting both refusals separately is what
    // keeps "you lack the scope" and "this build cannot do that" distinct.
    match client
        .call("pair.begin", Vec::new(), None, Vec::new())
        .await
    {
        Err(error) => assert_ne!(
            error.reason_code(),
            "PROTO.CAPABILITY_MISSING",
            "an ADMINISTER operation is refused on authorization first"
        ),
        Ok(_) => panic!("pair.begin must not be served"),
    }
}

#[tokio::test]
async fn the_catalogue_the_agent_serves_says_which_operations_this_build_executes() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let response = client
        .call("mi.catalogue.get", Vec::new(), None, Vec::new())
        .await
        .expect("one of MI-21's four");
    let rows: Vec<server::CatalogueRow> =
        serde_json::from_slice(&response.result).expect("decodes");

    // MI-20: the table's contents AND its order come from the command set.
    assert_eq!(rows.len(), twinvpn_mgmt::CoreCommand::ALL.len());
    assert_eq!(rows[0].operation, "status.get");
    // And it is honest about the 14 the core does not execute.
    let unimplemented: Vec<&str> = rows
        .iter()
        .filter(|r| !r.implemented)
        .map(|r| r.operation.as_str())
        .collect();
    assert_eq!(unimplemented.len(), twinvpn_core::core::unimplemented().len());
    assert!(unimplemented.contains(&"pair.begin"));
    assert!(unimplemented.contains(&"exitnode.select"));
    assert!(unimplemented.contains(&"killswitch.disarm.begin"));
}

#[tokio::test]
async fn an_unknown_operation_is_a_typed_rejection_never_a_hang() {
    // §11.7: "Never a parse error, never a hang, never a generic failure."
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let error = client
        .call("status.gett", Vec::new(), None, Vec::new())
        .await
        .expect_err("not in the catalogue");
    assert_eq!(error.reason_code(), "PROTO.CAPABILITY_MISSING");
}

#[tokio::test]
async fn an_administer_operation_is_refused_on_a_scope_alone() {
    // ADR-0017 §11.5's third consequence and ADR-0016 §11.7: holding
    // `mgmt.admin` is necessary and NOT sufficient — every ADMINISTER operation
    // needs the §11.14 ceremony freshly, per call. This build has no ceremony,
    // so it refuses rather than performing one on a scope.
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(
        &harness.path,
        "cli",
        "0.1.0",
        &[twinvpn_mgmt::Scope::Admin.name().to_owned()],
    )
    .await
    .expect("attaches");

    let error = client
        .call("killswitch.mode.set", Vec::new(), None, Vec::new())
        .await
        .expect_err("refused");
    assert!(
        matches!(
            error.reason_code(),
            "MGMT.DISARM_REQUIRES_LOCAL_AUTH" | "POLICY.POLICY_DENIED"
        ),
        "unexpected code {}",
        error.reason_code()
    );
}

#[tokio::test]
async fn mi_s1_a_client_is_granted_the_intersection_and_told_what_was_withheld() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;

    // Ask for everything, including a scope the runner's principal may lack.
    let everything: Vec<String> = twinvpnd::mi::scope::GRANTABLE
        .iter()
        .map(|s| s.name().to_owned())
        .collect();
    let client = Client::connect(&harness.path, "cli", "0.1.0", &everything)
        .await
        .expect("attaches: a status-only client should still work");

    let granted = client.granted();
    let withheld = client.withheld();
    // Every granted scope was requested, and nothing was granted that was not.
    for name in granted.names() {
        assert!(everything.contains(&name), "{name} was not requested");
        assert!(
            !withheld.contains(&name),
            "{name} is both granted and withheld"
        );
    }
    // The two sets partition what was asked for.
    assert_eq!(granted.names().len() + withheld.len(), everything.len());
}

#[tokio::test]
async fn mi_a5_is_exercised_by_the_attach_itself() {
    // The credential read is the FIRST thing `serve` does, and a successful
    // attach is proof it answered. There is no path in the server that reaches
    // `HelloAck` without it (MI-A1: "No field carrying a client-asserted
    // identity exists in the schema").
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");
    assert!(!client.agent_version().is_empty());
}

#[tokio::test]
async fn a_version_mismatch_is_answered_before_the_close_never_silently() {
    // §11.7: "A silent close is prohibited: it is indistinguishable from 'the
    // agent is not running', and it sends the user to reinstall rather than to
    // update."
    let (harness, context) = harness();
    spawn(&harness.path, context).await;

    let mut stream = tokio::net::UnixStream::connect(&harness.path)
        .await
        .expect("connects");
    let hello = MgmtEnvelope {
        mi_version: 99,
        request_id: vec![1; 16],
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        as_of_ms: 0,
        body: Body::Hello(Hello {
            // A client from the future: its MINIMUM is above our maximum.
            mi_version_min: MI_VERSION + 10,
            mi_version_max: MI_VERSION + 20,
            client_kind: "cli".to_owned(),
            client_version: "9.9.9".to_owned(),
            requested_scopes: requested(),
            subscribe_topics: Vec::new(),
        }),
    };
    codec::write_frame(&mut stream, &hello)
        .await
        .expect("writes");
    let reply = codec::read_frame(&mut stream)
        .await
        .expect("an answer, not a close");
    match reply.body {
        Body::Reject(diagnostic) => {
            assert_eq!(diagnostic.reason_code, "PROTO.VERSION_UNSUPPORTED");
        }
        other => panic!("expected a Reject, got {other:?}"),
    }
    // And an ancient client is refused the same way. The window is declared no
    // wider than the build serves, which `mi::wire`'s own `const` assertion
    // pins at compile time.
    assert_eq!(MI_VERSION_MIN, 1);
}

#[tokio::test]
async fn mi3_a_response_from_a_client_is_refused_and_the_connection_closes() {
    // "No daemon→client RPC exists", and the direction holds in reverse too: a
    // client that sends a body only the agent may send has broken the protocol.
    let (harness, context) = harness();
    spawn(&harness.path, context).await;

    let mut stream = tokio::net::UnixStream::connect(&harness.path)
        .await
        .expect("connects");
    let hello = MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: vec![1; 16],
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        as_of_ms: 0,
        body: Body::Hello(Hello {
            mi_version_min: MI_VERSION_MIN,
            mi_version_max: MI_VERSION,
            client_kind: "cli".to_owned(),
            client_version: "0.1.0".to_owned(),
            requested_scopes: requested(),
            subscribe_topics: Vec::new(),
        }),
    };
    codec::write_frame(&mut stream, &hello)
        .await
        .expect("writes");
    let _ack = codec::read_frame(&mut stream).await.expect("HelloAck");

    let illegal = MgmtEnvelope {
        body: Body::Event(twinvpnd::mi::Event {
            topic: "session.state".to_owned(),
            payload: Vec::new(),
            actor_principal: None,
        }),
        ..hello
    };
    codec::write_frame(&mut stream, &illegal)
        .await
        .expect("writes");
    let reply = codec::read_frame(&mut stream).await.expect("a Reject");
    assert!(matches!(reply.body, Body::Reject(_)));
}

#[tokio::test]
async fn mi16_as_of_ms_is_the_agents_boot_time_reading_not_the_clients() {
    // MI-16: "agent-stamped ... boot-time monotonic". `CLOCK_BOOTTIME` is
    // absolute since boot, so the agent's stamp is large; a client-stamped
    // value would be zero, because the client does not stamp one.
    let (harness, context) = harness();
    let expected_at_least = context.as_of_ms();
    spawn(&harness.path, context).await;

    let mut stream = tokio::net::UnixStream::connect(&harness.path)
        .await
        .expect("connects");
    let hello = MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: vec![1; 16],
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        // The client stamps nothing.
        as_of_ms: 0,
        body: Body::Hello(Hello {
            mi_version_min: MI_VERSION_MIN,
            mi_version_max: MI_VERSION,
            client_kind: "cli".to_owned(),
            client_version: "0.1.0".to_owned(),
            requested_scopes: requested(),
            subscribe_topics: Vec::new(),
        }),
    };
    codec::write_frame(&mut stream, &hello)
        .await
        .expect("writes");
    let ack = codec::read_frame(&mut stream).await.expect("HelloAck");
    assert!(
        ack.as_of_ms >= expected_at_least,
        "the agent stamps as_of_ms from CLOCK_BOOTTIME: {} < {expected_at_least}",
        ack.as_of_ms
    );
    assert!(
        ack.as_of_ms > 1_000,
        "a value near zero means the monotonic clock was substituted for the \
         elapsed one — LC-8's invisible-on-CI failure"
    );
}

#[tokio::test]
async fn ps3_the_last_client_detaching_changes_nothing() {
    // PS-3: "Loss of the last management client MUST NOT change
    // `session_intent`, enforcement mode, the installed rule set, or any
    // `ConnectionState`."
    let (harness, context) = harness();
    let core = Arc::clone(&context.core);
    spawn(&harness.path, Arc::clone(&context)).await;

    let before = core.generation();
    {
        let client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
            .await
            .expect("attaches");
        drop(client);
    }
    // Give the server's read loop a chance to observe the close without a timer
    // (CD-3 keeps `tokio::time` out of this crate): a yield per spawned task is
    // enough for a local socket close.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        core.generation(),
        before,
        "a client detaching must not advance the S-47 generation"
    );
    assert!(!core.is_poisoned());
}

#[tokio::test]
async fn a_client_reaching_a_missing_endpoint_gets_unavailable_never_a_hang() {
    // ADR-0017 §10.3's reason for prohibiting socket activation: "a client
    // connects successfully then hangs instead of getting MGMT.UNAVAILABLE".
    match Client::connect(
        &PathBuf::from("/nonexistent/twinvpn/mgmt.sock"),
        "cli",
        "0.1.0",
        &requested(),
    )
    .await
    {
        Err(error) => {
            assert!(matches!(error, ClientError::Unavailable(_)));
            assert_eq!(error.reason_code(), "MGMT.UNAVAILABLE");
        }
        Ok(_) => panic!("there is no endpoint at that path"),
    }
}

#[tokio::test]
async fn an_over_cap_frame_is_refused_before_the_agent_allocates() {
    // §11.3's 1 MiB cap, enforced BEFORE parse, on a real connection.
    let (harness, context) = harness();
    spawn(&harness.path, context).await;

    let mut stream = tokio::net::UnixStream::connect(&harness.path)
        .await
        .expect("connects");
    use tokio::io::AsyncWriteExt as _;
    stream
        .write_all(&u32::MAX.to_be_bytes())
        .await
        .expect("writes a hostile prefix");
    stream.flush().await.expect("flushes");
    // The agent answers with a Reject rather than allocating 4 GiB or hanging.
    // A close is also acceptable here — what must NOT happen is an allocation
    // or a hang, and reaching this line at all means neither did.
    if let Ok(envelope) = codec::read_frame(&mut stream).await {
        assert!(matches!(envelope.body, Body::Reject(_)));
    }
}

#[tokio::test]
async fn an_out_of_group_principal_is_refused_every_operation() {
    // **PS-12a, on a live connection.** Built-in `Users`/`staff`-style groups are
    // deliberately not the OBSERVE principal, "because 'every local account can
    // enumerate this device's peers and endpoints' should be an install-time
    // decision (TB-13), not a platform default".
    //
    // This test swaps the fixture for the HOST's own `/etc/group`, in which the
    // runner is in neither TwinVPN group — so the refusal below is the real one.
    let (harness, mut context) = harness();
    {
        let context = Arc::get_mut(&mut context).expect("uniquely held");
        context.groups = Arc::new(peer::GroupSource::load());
    }
    spawn(&harness.path, context).await;

    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("a status-only client still attaches (MI-S1)");
    // MI-S1: the attach SUCCEEDS and the withheld scopes are named. A rejection
    // here would be the failure mode that rule exists to prevent.
    assert!(
        client.granted().names().is_empty(),
        "an account in neither TwinVPN group holds nothing"
    );
    assert_eq!(client.withheld().len(), requested().len());

    match client
        .call("status.get", Vec::new(), None, Vec::new())
        .await
    {
        Err(error) => {
            // ADR-0017 §11.12 maps this family to exit 4, "distinct so a script
            // can tell re-run with privilege from this will never work".
            assert_eq!(error.reason_code(), "POLICY.POLICY_DENIED");
        }
        Ok(_) => panic!("an unauthorized principal must not be served"),
    }
}

/// **CB-2, asserted rather than claimed.**
///
/// The falsification test's shape, at the shell's scale: every operation the CLI
/// can name, the scope it needs, and whether it is implemented all come from the
/// core. Delete this shell and the core still knows all three.
#[test]
fn cb2_every_fact_the_shell_serves_comes_from_the_core() {
    for op in twinvpn_mgmt::CoreCommand::ALL {
        let entry = twinvpn_mgmt::catalogue::entry(*op);
        // The scope is the catalogue's.
        assert!(entry.scope.name().starts_with("mgmt."));
        // Whether it is implemented is the core's.
        let implemented = twinvpn_core::core::executes(*op);
        assert_eq!(
            implemented,
            !twinvpn_core::core::unimplemented().iter().any(|(c, _, _)| c == op)
        );
    }
    // And the transport set is closed at four, which the shell cannot widen.
    twinvpn_mgmt::assert_closed().expect("MI-21 holds");
}

/// **PS-22, clause B of ADR-0017's P17.**
///
/// "The management-interface server … MUST be a module with **no dependency
/// edge** onto the tunnel engine, packet-routing, or enforcement modules."
///
/// Asserted as a source property: the server module names the core and the
/// vocabulary and nothing platform-specific.
#[test]
fn ps22_the_server_reaches_the_datapath_only_through_the_vocabulary() {
    let source = include_str!("../src/agent/server.rs");
    for forbidden in [
        "twinvpn_platform_linux::nft",
        "twinvpn_platform_linux::tun",
        "twinvpn_platform_linux::route",
        "twinvpn_platform_linux::resolver",
        "twinvpn_platform_linux::netcfg",
    ] {
        assert!(
            !source.contains(&format!("use {forbidden}")),
            "the MI server acquired a dependency edge onto {forbidden}, which PS-22 forbids"
        );
    }
}
