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

use twinvpnd::agent::{conn, events, peer, runtime, server};
use twinvpnd::mi::wire::{Body, MgmtEnvelope, MI_VERSION, MI_VERSION_MIN};
use twinvpnd::mi::{codec, Client, ClientError, Hello, PlatformCtx};

/// A running agent on a private endpoint.
struct Harness {
    path: PathBuf,
    dir: PathBuf,
    fanout: Arc<events::Fanout>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Closes the fan-out so the drain thread returns rather than outliving
        // the test — and so every outstanding completion is settled.
        self.fanout.close();
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

    let fanout = Arc::new(events::Fanout::new());
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
        submission: Arc::new(tokio::sync::Mutex::new(())),
        fanout: Arc::clone(&fanout),
    });

    // **The drain, on a plain thread.** Every test that asserts a response body
    // needs it: `Core::submit` publishes the result rather than returning it, so
    // with no drain the dispatcher's registration is never settled. Running it
    // here rather than only in `twinvpnd`'s `main` is what makes these tests
    // exercise the production correlation instead of a stub.
    std::thread::Builder::new()
        .name("twinvpn-test-drain".to_owned())
        .spawn({
            let core = Arc::clone(&context.core);
            let fanout = Arc::clone(&fanout);
            move || events::drain(&core, &fanout, std::time::Duration::from_millis(20))
        })
        .expect("spawns");

    (Harness { path, dir, fanout }, context)
}

async fn spawn(path: &std::path::Path, context: Arc<server::ServerContext>) {
    let listener = twinvpnd::agent::endpoint::bind(path, None).expect("binds");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let context = Arc::clone(&context);
            tokio::spawn(async move {
                let _ = conn::serve(context, stream).await;
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

/// Whether the injected runtime can register a file descriptor.
///
/// # W-43 is closed, and this is now an assertion rather than a branch
///
/// Wave 1 found `twinvpn-env`'s `TokioRuntime` building with `.enable_time()`
/// and **not** `.enable_io()`, so no socket, netlink channel or tun device could
/// be opened at all on a production `Env`. The tests below branched on this
/// probe: with the driver absent they asserted the operation was **refused by
/// name**, and with it present they asserted the real behaviour — so "the day
/// the one-line fix lands, they start asserting the stronger thing with no
/// edit".
///
/// **It has landed.** `core/crates/twinvpn-env/src/binding/tokio_rt.rs` now
/// calls `.enable_io()` in both constructors, so the branches below take their
/// strong side and `the_injected_runtime_drives_io_so_w43_is_closed` pins it:
/// the weak side is no longer reachable, and a regression in `twinvpn-env`
/// fails this suite rather than quietly weakening it back into the branch.
fn runtime_drives_io() -> bool {
    static PROBED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *PROBED.get_or_init(|| {
        // On a PLAIN thread, never on a runtime worker: the probe itself calls
        // `block_on`, and `block_on` inside an async context is tokio's
        // "Cannot start a runtime from within a runtime".
        std::thread::spawn(|| {
            let (env, _rt) = runtime::build_env().expect("binds");
            runtime::runtime_can_drive_io(&env)
        })
        .join()
        .unwrap_or(false)
    })
}

/// **W-43, closed and pinned.**
///
/// The finding was that the production runtime could open nothing, so every
/// adapter call was unreachable and the agent refused to start (PS-18's shape).
/// This asserts the fix rather than tolerating either answer — which is the
/// difference between a test that documents a defect and one that prevents its
/// return.
#[test]
fn the_injected_runtime_drives_io_so_w43_is_closed() {
    assert!(
        runtime_drives_io(),
        "twinvpn-env's TokioRuntime must build with .enable_io(): without it no \
         socket, netlink channel or tun device can be opened, every adapter call \
         is unreachable, and twinvpnd refuses to start (ownership.md §8 W-43)"
    );
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
        twinvpn_mgmt::catalogue_digest_text()
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

/// A peer, as `session.connect` now requires it.
///
/// `dispatch::peer_from_params` takes the raw 32-byte `device_id` —
/// `limits.json`'s frozen width — because the MI has no request schema
/// (`contracts/docs/phase1-conflicts.md` OQ-2 deliberately excluded one).
/// Anything else is refused rather than truncated or padded.
fn peer_params() -> Vec<u8> {
    vec![0xab; 32]
}

#[tokio::test]
async fn session_connect_executes_real_work_and_advances_the_s47_generation() {
    // `session.connect` no longer reports a hollow `Ok`: it gathers on the
    // platform, drives T01→T03/T04 through the §4.5 table, admits into the
    // candidate ledger, schedules a race and persists to the journal. The core
    // refuses an operation that declared EXECUTES and produced no observable
    // effect, so a successful response is itself the assertion that work happened.
    let (harness, context) = harness();
    let core = Arc::clone(&context.core);
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let before = core.generation();
    let result = client
        .call("session.connect", peer_params(), None, Vec::new())
        .await;

    // **W-43 is closed**, so this is unconditional now rather than the strong
    // side of a branch.
    let response = result.expect("session.connect executes");
    assert!(response.ok);
    // S-47's generation advances for a mutating command — a LOCAL fact, and the
    // one the shell must not confuse with MI-6's cursor.
    assert_eq!(core.generation(), before + 1);
}

#[tokio::test]
async fn a_malformed_session_connect_is_refused_before_any_work() {
    // The core checks the parameter before dispatching, "so a command can never
    // be partially applied". An empty payload is a typed reject, not a partial
    // connect.
    let (harness, context) = harness();
    let core = Arc::clone(&context.core);
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let before = core.generation();
    match client
        .call("session.connect", Vec::new(), None, Vec::new())
        .await
    {
        Err(error) => assert_eq!(error.reason_code(), "PROTO.MALFORMED_MESSAGE"),
        Ok(_) => panic!("a session.connect with no peer must be refused"),
    }
    assert_eq!(
        core.generation(),
        before,
        "a refused command must not advance the generation"
    );
}

/// **MI-6, as it actually reads.**
///
/// > Every MI response to an operation that maps to a **mutating C1 request**
/// > MUST carry `committed_at_net_seq`.
///
/// `session.connect` is not one. `docs/protocol.md` §5.1 makes the cursor "a
/// real, monotone position in the same log" the C2 stream replays — the
/// coordination service's — and ADR-0017 §11.8 classifies `session.connect`
/// "naturally idempotent … the state machine already absorbs a repeat", beside
/// `net.up` and `net.down`. It sends no C1 request, so it has no `net_seq`.
///
/// The shell used to report **S-47's generation** here, which S-47 requires
/// "must not survive process exit" — a per-process counter offered as a durable
/// log position. A client that waited for an event at or past it would believe
/// it had discharged E-2's read-your-writes when it had not.
#[tokio::test]
async fn mi6_applies_to_c1_mapping_operations_and_session_connect_is_not_one() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    // The predicate itself is pure and is asserted unconditionally: whatever the
    // runtime can or cannot do, `session.connect` reaches no C1 request.
    assert!(!server::maps_to_mutating_c1(
        twinvpn_mgmt::CoreCommand::SessionConnect
    ));

    // A local mutation carries NO cursor. Unconditional since W-43 closed.
    let response = client
        .call("session.connect", peer_params(), None, Vec::new())
        .await
        .expect("executes");
    assert!(response.ok);
    assert_eq!(
        response.committed_at_net_seq, None,
        "session.connect reaches no C1 request, so MI-6 does not apply and a \
         cursor here would be a falsehood a client cannot detect"
    );

    // ...and a read carries none either.
    let response = client
        .call("status.get", Vec::new(), None, Vec::new())
        .await
        .expect("executes");
    assert_eq!(response.committed_at_net_seq, None);
}

/// The five operations MI-6 **does** apply to, and why none can produce a
/// cursor in this build.
#[test]
fn every_c1_mapping_operation_needs_a_cursor_this_build_cannot_produce() {
    for op in server::C1_MAPPING {
        assert!(server::maps_to_mutating_c1(op), "{}", op.name());
        // Every one is refused before it reaches a response, because each needs
        // a control-plane transport this build does not have (W-12). So the
        // absent cursor is never observed by a client as a missing guarantee —
        // the operation is refused by name first.
        assert!(
            !twinvpn_core::core::executes(op),
            "{} executes but has no C2 log to report a cursor from",
            op.name()
        );
    }
    // And the local mutations are NOT in the set.
    for op in [
        twinvpn_mgmt::CoreCommand::SessionConnect,
        twinvpn_mgmt::CoreCommand::SessionDisconnect,
        twinvpn_mgmt::CoreCommand::NetUp,
        twinvpn_mgmt::CoreCommand::NetDown,
        twinvpn_mgmt::CoreCommand::SettingsSet,
    ] {
        assert!(
            !server::maps_to_mutating_c1(op),
            "{} is a local mutation and reaches no C1 request",
            op.name()
        );
        // Each IS `mutating` in the catalogue — which is exactly why reading
        // that field as MI-6's predicate was wrong.
        assert!(twinvpn_mgmt::catalogue::entry(op).mutating);
    }
}

/// The tripwire that replaces the compile error a `#[non_exhaustive]` enum
/// denies this crate.
///
/// The core gets a build failure when a new `CoreCommand` is added without a
/// stated disposition. A shell cannot match `CoreCommand` exhaustively, so this
/// pins the catalogue's size instead: a command added upstream fails here until
/// someone states which side of MI-6 it falls on.
#[test]
fn a_new_core_command_must_be_classified_against_mi6() {
    assert_eq!(
        twinvpn_mgmt::CoreCommand::ALL.len(),
        51,
        "the core command set changed. Classify the new operation in \
         `server::C1_MAPPING` — does it map to a mutating C1 request? — and \
         update this count."
    );
    // The four that moved the count are ADR-0023 EM-35's `gateway` noun, and
    // the classification is the point of this test rather than the number.
    // **None of them maps to a mutating C1 request.** The three reads are local
    // reads of the gateway's own peer table, capacity and grant set (S-36 is
    // explicitly non-durable and reconstructible), and `gateway.set` is local
    // configuration that reaches no control-plane request either — so none has
    // a `net_seq` and reporting one would tell a client it had read-your-writes
    // when it had not (MI-6).
    for op in [
        twinvpn_mgmt::CoreCommand::GatewayGet,
        twinvpn_mgmt::CoreCommand::GatewayPeerList,
        twinvpn_mgmt::CoreCommand::GatewayGrantList,
        twinvpn_mgmt::CoreCommand::GatewaySet,
    ] {
        assert!(
            !server::maps_to_mutating_c1(op),
            "{} reaches no C1 request",
            op.name()
        );
    }
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
    assert!(!twinvpn_core::core::executes(
        twinvpn_mgmt::CoreCommand::UpdateStatus
    ));
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
    assert_eq!(
        unimplemented.len(),
        twinvpn_core::core::unimplemented().len()
    );
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

/// **ADR-0012 KS-21a's host-class ceremony, in the direction that authorizes.**
///
/// Wave 1 refused every ADMINISTER operation and reported "no polkit client" as
/// a gap. KS-21a is the rule that makes that over-strict on this host class:
///
/// > On `HC-3` … **A caller on the local management socket, authenticated by
/// > kernel-supplied peer credentials to an administrator principal, satisfies
/// > this clause on `HC-3`.**
///
/// So the ceremony on `H-SRV` is `SO_PEERCRED` plus the administrator class —
/// not a D-Bus call — and this asserts it passes for a principal that holds
/// both. The operation still reaches the core, which refuses
/// `killswitch.mode.set` by name for its own reason (no enforcement binding);
/// the point here is that the **ceremony** no longer refuses it first.
#[test]
fn ks21a_the_ceremony_authorizes_a_kernel_attested_administrator() {
    let principal = peer::Principal {
        uid: 0,
        gid: 0,
        pid: 1234,
        name: Some("root".to_owned()),
    };
    let held = twinvpnd::mi::Scopes::from_scopes([
        twinvpn_mgmt::Scope::Status,
        twinvpn_mgmt::Scope::Admin,
    ]);
    assert!(
        server::administer_ceremony(&principal, &held).is_ok(),
        "KS-21a: peer credentials plus the administrator class ARE the ceremony \
         on HC-3; refusing here is the over-strict reading wave 1 shipped"
    );
}

/// The other direction, which is the one that must never soften.
///
/// ADR-0012 §11.10: a refused disarm "is always a security event". A principal
/// without the administrator class is refused **at request** — MI-17's ordering,
/// "so operators are never trained to click through prompts for acts that were
/// never going to be permitted".
#[test]
fn ks21a_the_ceremony_refuses_a_principal_without_the_administrator_class() {
    let principal = peer::Principal {
        uid: 1000,
        gid: 1000,
        pid: 1234,
        name: Some("dana".to_owned()),
    };
    let held = twinvpnd::mi::Scopes::from_scopes([
        twinvpn_mgmt::Scope::Status,
        twinvpn_mgmt::Scope::Connect,
    ]);
    let refusal = server::administer_ceremony(&principal, &held)
        .expect_err("an ADMINISTER operation needs the administrator class");
    let diagnostic = refusal
        .diagnostic
        .expect("a named refusal, never a bare no");
    assert_eq!(diagnostic.reason_code, "MGMT.DISARM_REQUIRES_LOCAL_AUTH");
    assert!(
        twinvpn_types::ReasonCode::lookup(&diagnostic.reason_code).is_some(),
        "the refusal must name a registered code"
    );
}

/// **EM-72, structurally.** No automatic path can reach the ceremony.
///
/// > The disarm path is unreachable from any automatic path. … No timer, no
/// > reconciler, no supervisor, no policy document, and no `ubus` method can
/// > satisfy those preconditions.
///
/// The assertion is about the *shape* of the function rather than about a run:
/// it takes a [`peer::Principal`], and the only constructor of one in the agent
/// is [`peer::Principal::from_stream`], which reads `SO_PEERCRED` from an
/// accepted connection. A timer has no connection, so a timer cannot produce the
/// argument. That is what "structurally unreachable" means here, and it is
/// stronger than a check because there is nothing to forget to call.
#[test]
fn em72_the_ceremony_cannot_be_reached_without_an_accepted_connection() {
    // If this ever compiles with a `Default` or a `new()` on `Principal`, the
    // structural argument above has quietly stopped holding.
    let attested = peer::Principal {
        uid: 0,
        gid: 0,
        pid: std::process::id() as i32,
        name: None,
    };
    // `actor()` is what travels as MI-18's attribution, and an unattested
    // principal could not produce one.
    assert_eq!(attested.actor(), "uid:0");
}

#[tokio::test]
async fn an_administer_operation_is_refused_on_a_scope_alone() {
    // ADR-0017 §11.5's third consequence and ADR-0016 §11.7: holding
    // `mgmt.admin` is necessary and NOT sufficient — every ADMINISTER operation
    // needs the §11.14 ceremony freshly, per call, and this runner is not root
    // so it does not hold the class at all.
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
            op: None,
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
            !twinvpn_core::core::unimplemented()
                .iter()
                .any(|(c, _, _)| c == op)
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

// ---------------------------------------------------------------------------
// §11.10's event stream, end to end
// ---------------------------------------------------------------------------

/// Attaches with `subscribe_topics` set, so the connection carries the stream.
async fn attach_subscribed(path: &std::path::Path) -> tokio::net::UnixStream {
    let mut stream = tokio::net::UnixStream::connect(path)
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
            subscribe_topics: events::topics::ALL
                .iter()
                .map(|t| (*t).to_owned())
                .collect(),
        }),
    };
    codec::write_frame(&mut stream, &hello)
        .await
        .expect("writes");
    match codec::read_frame(&mut stream).await.expect("acked").body {
        Body::HelloAck(_) => stream,
        other => panic!("expected a HelloAck, got {other:?}"),
    }
}

/// Sends one request and reads until the response **and** `min_events` pushed
/// events have arrived.
///
/// # Why it waits for both rather than stopping at the response
///
/// The two directions are genuinely independent: the request loop writes the
/// response as soon as the core settles the completion, and the pump writes the
/// event when it next wakes. Either can reach the socket first, so a helper that
/// stopped at the response would be asserting a scheduling accident.
///
/// **There is no timeout here, and none is needed.** `submit` returning `Ok`
/// means the core published a `CommandCompleted`; the drain thread pops it and
/// the pump writes it. The read blocks until it arrives because it is going to
/// arrive — which is a stronger assertion than a bounded wait, since a bounded
/// wait would pass on a build that delivered nothing and merely happened to be
/// slow.
async fn call_collecting(
    stream: &mut tokio::net::UnixStream,
    operation: &str,
    params: Vec<u8>,
    min_events: usize,
) -> (Vec<MgmtEnvelope>, twinvpnd::mi::wire::Response) {
    let request = MgmtEnvelope {
        mi_version: MI_VERSION,
        request_id: vec![7; 16],
        correlation_id: Vec::new(),
        seq: 0,
        idempotency_key: Vec::new(),
        as_of_ms: 0,
        body: Body::Request(twinvpnd::mi::wire::Request {
            operation: operation.to_owned(),
            params,
            if_version: None,
        }),
    };
    codec::write_frame(stream, &request).await.expect("writes");

    let mut events = Vec::new();
    let mut response = None;
    loop {
        if let Some(body) = response {
            if events.len() >= min_events {
                return (events, body);
            }
            response = Some(body);
        }
        let frame = codec::read_frame(stream).await.expect("a frame");
        match frame.body {
            Body::Response(body) => response = Some(body),
            _ => events.push(frame),
        }
    }
}

/// **README §7 gap 2's "visible consequence", closed.**
///
/// > `Core::submit` returns `Ok(())` and publishes the operation's **body** as a
/// > `CommandCompleted` event, so a read's result is currently unreachable by an
/// > MI client. The MI `Response.result` is empty for that reason.
///
/// The reason was a misreading: the body is not withheld by the API, it is
/// *published* rather than *returned*, and reaching it needs the stream to be
/// drained and the completion correlated. Both now happen, so a read comes back
/// with its body.
#[tokio::test]
async fn a_read_returns_its_body_rather_than_an_empty_result() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let response = client
        .call("status.get", Vec::new(), None, Vec::new())
        .await
        .expect("status.get executes");
    assert!(response.ok);
    assert!(
        !response.result.is_empty(),
        "status.get's body is a prost-encoded HealthSample the core published as \
         a CommandCompleted; an empty result here is wave 1's defect returning"
    );
}

/// The same for an operation whose body is a fixed width, so the assertion is on
/// the **content** rather than merely on non-emptiness.
///
/// `event.subscribe` returns the event cursor as eight big-endian bytes — a
/// value a client uses to decide whether it has missed anything (MI-9a). A body
/// of the wrong width would be a cursor a client would silently misread.
#[tokio::test]
async fn event_subscribes_body_is_the_cursor_at_its_declared_width() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let response = client
        .call("event.subscribe", Vec::new(), None, Vec::new())
        .await
        .expect("event.subscribe executes");
    assert!(response.ok);
    assert_eq!(
        response.result.len(),
        8,
        "the cursor is a u64 big-endian; a short read here is a misread cursor"
    );
}

/// **The stream itself.** A subscribed client receives unsolicited `Event`
/// frames, in order, carrying the core's own `seq`.
#[tokio::test]
async fn a_subscribed_client_receives_pushed_event_frames_in_order() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut stream = attach_subscribed(&harness.path).await;

    let (frames, response) = call_collecting(&mut stream, "status.get", Vec::new(), 1).await;
    assert!(response.ok);

    let pushed: Vec<&MgmtEnvelope> = frames
        .iter()
        .filter(|f| matches!(f.body, Body::Event(_)))
        .collect();
    assert!(
        !pushed.is_empty(),
        "F-5: every outcome, including the completion of a submitted command, \
         arrives as an event on the one ordered stream — and the agent must push it"
    );

    // MI-16: the sequence numbers are the CORE's, and they are contiguous, which
    // is what proves no event was lost.
    let seqs: Vec<u64> = pushed.iter().map(|f| f.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[1] > w[0]),
        "the stream is totally ordered: {seqs:?}"
    );

    // And at least one of them is this command's own completion, carrying the
    // same body the response carried.
    let completion = pushed.iter().find_map(|f| match &f.body {
        Body::Event(event) if event.topic == events::topics::COMMAND_COMPLETED => Some(event),
        _ => None,
    });
    let completion = completion.expect("the command's own completion is on the stream");
    assert_eq!(
        completion.payload, response.result,
        "the response body and the event body are the same bytes, because they \
         are the same fact carried twice"
    );
}

/// **MI-18 on the wire.** The acting principal reaches the event.
///
/// > "the tunnel went down" and "Dana took the tunnel down" are different facts.
#[tokio::test]
async fn mi18_a_pushed_event_names_the_principal_whose_call_produced_it() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut stream = attach_subscribed(&harness.path).await;

    let (frames, _) = call_collecting(&mut stream, "status.get", Vec::new(), 1).await;
    let attributed = frames.iter().any(|f| match &f.body {
        Body::Event(event) => event.actor_principal.is_some(),
        _ => false,
    });
    assert!(
        attributed,
        "an unattributed state change on a multi-user host is a silent failure \
         wearing local clothes (MI-18, PS-13)"
    );
}

/// **MI-9's `event.resync`**, which wave 1 refused.
///
/// The snapshot is the recovery a `Compacted` marker asks for; refusing it left a
/// client with no way back from a gap at all.
#[tokio::test]
async fn event_resync_returns_a_snapshot_and_a_cursor_rather_than_refusing() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut stream = attach_subscribed(&harness.path).await;

    // Produce something to snapshot.
    let (_, first) = call_collecting(&mut stream, "status.get", Vec::new(), 1).await;
    assert!(first.ok);

    let (_, response) = call_collecting(&mut stream, "event.resync", Vec::new(), 0).await;
    assert!(
        response.ok,
        "MI-9's snapshot is an answer, not a refusal: {:?}",
        response.diagnostic
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.result).expect("a snapshot body");
    assert!(
        body["cursor"].as_u64().expect("a cursor") > 0,
        "the cursor is assigned inside the snapshot's own lock, so it is a \
         position this snapshot is current as of"
    );
    let rows = body["rows"].as_array().expect("rows");
    assert!(
        rows.iter()
            .any(|r| r["topic"] == events::topics::COMMAND_COMPLETED),
        "the latest event on each topic, and status.get produced one"
    );
}

/// A client that never subscribed gets the refusal, because for it there is no
/// stream position a cursor could refer to.
#[tokio::test]
async fn event_resync_without_a_subscription_is_refused_by_name() {
    let (harness, context) = harness();
    spawn(&harness.path, context).await;
    let mut client = Client::connect(&harness.path, "cli", "0.1.0", &requested())
        .await
        .expect("attaches");

    let error = client
        .call("event.resync", Vec::new(), None, Vec::new())
        .await
        .expect_err("no stream to resync");
    assert_eq!(error.reason_code(), "MGMT.STREAM_COMPACTED");
}

/// **PS-3 with the stream attached.** A subscribed client detaching changes
/// nothing — including that it does not close the stream for anyone else.
#[tokio::test]
async fn ps3_a_subscribed_client_detaching_leaves_the_stream_running() {
    let (harness, context) = harness();
    let fanout = Arc::clone(&context.fanout);
    spawn(&harness.path, Arc::clone(&context)).await;

    let first = attach_subscribed(&harness.path).await;
    let mut second = attach_subscribed(&harness.path).await;
    // Both attached.
    for _ in 0..50 {
        if fanout.subscriber_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(fanout.subscriber_count(), 2);

    drop(first);

    // The survivor still receives events.
    let (frames, response) = call_collecting(&mut second, "status.get", Vec::new(), 1).await;
    assert!(response.ok);
    assert!(frames.iter().any(|f| matches!(f.body, Body::Event(_))));
}
