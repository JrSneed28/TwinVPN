//! `mgmt::server`'s tests.
//!
//! Split out of `server.rs` to keep both files under the 500-line rule in
//! `CLAUDE.md` — the same `#[path]` shape `ext_tests.rs` uses, so the tests stay
//! `mod tests` inside `server` and reach its private items exactly as an inline
//! `#[cfg(test)]` block would. `include_str!("server.rs")` still resolves, which
//! matters: two of these tests are source scans over that file.

use super::*;

#[test]
fn ps22_this_module_has_no_edge_onto_the_datapath() {
    // "a module with no dependency edge onto the tunnel, routing or
    // enforcement modules". Asserted over the source, so the day somebody
    // reaches for `pf::render` from a request handler the build says so
    // rather than a reviewer having to notice.
    let code = executable_source(include_str!("server.rs"));
    for forbidden in [
        "twinvpn_platform_macos",
        "twinvpn_platform::",
        "twinvpn_core",
        "pf::",
        "netcfg",
        "utun",
        "route::",
        // Added when PS-22's §11.2 amendment moved the authority into the
        // system extension: the datapath is now in THIS CRATE, so the
        // module-graph edge these two names would create is the one
        // ADR-0017 A-12 says the check is now about.
        "crate::ext",
        "crate::port",
        "TvbExt",
        "BridgePort",
    ] {
        assert!(
            !code.contains(forbidden),
            "the MI server reached for {forbidden}, which PS-22 forbids"
        );
    }
    // The one edge that IS permitted, and it is a trait over PS-4's
    // vocabulary rather than a concrete type.
    assert!(code.contains("trait CommandSink"));
    assert!(code.contains("fn submit(&self, submission: &Submission)"));
}

use testing::{with_sink as context, RecordingSink};

fn request(operation: &str) -> twinvpn_mi::wire::Request {
    twinvpn_mi::wire::Request {
        operation: operation.to_owned(),
        params: Vec::new(),
        if_version: None,
    }
}

fn credentials(uid: u32) -> PeerCredentials {
    PeerCredentials {
        uid,
        groups: Vec::new(),
        groups_possibly_truncated: false,
    }
}

#[test]
fn an_operation_the_catalogue_does_not_know_is_a_typed_rejection() {
    // §11.7: "**Never** a parse error, never a hang, never a generic
    // failure." And nothing reaches the sink.
    let sink = Arc::new(RecordingSink::default());
    let granted = Scopes::from_scopes(twinvpn_mi::scope::GRANTABLE);
    let response = handle(
        &request("/bin/sh"),
        &granted,
        &credentials(501),
        None,
        &context(sink.clone()),
    );
    assert!(!response.ok);
    assert_eq!(
        response.diagnostic.expect("named").reason_code,
        twinvpn_mgmt::codes::op_unknown().as_str()
    );
    assert!(sink.submitted.lock().expect("lock").is_empty());
}

#[test]
fn a_scope_the_connection_was_not_granted_refuses_before_the_core_sees_it() {
    // MI-S1's grant, applied. The requirement is the CATALOGUE's.
    let sink = Arc::new(RecordingSink::default());
    let status_only = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
    let response = handle(
        &request("session.connect"),
        &status_only,
        &credentials(501),
        None,
        &context(sink.clone()),
    );
    assert!(!response.ok);
    assert!(
        sink.submitted.lock().expect("lock").is_empty(),
        "an unauthorised operation must not reach the core at all"
    );
}

#[test]
fn an_administer_operation_is_refused_rather_than_performed_on_a_scope_alone() {
    // §11.5's third consequence, and the safe direction: holding
    // `mgmt.admin` is necessary and not sufficient, and the §11.14 ceremony
    // is not wired in this wave.
    let sink = Arc::new(RecordingSink::default());
    let everything = Scopes::from_scopes(twinvpn_mi::scope::GRANTABLE);
    let administer: Vec<CoreCommand> = CoreCommand::ALL
        .iter()
        .copied()
        .filter(|op| twinvpn_mgmt::catalogue::entry(*op).administer)
        .collect();
    assert!(!administer.is_empty(), "the catalogue has ADMINISTER rows");
    for op in administer {
        let response = handle(
            &request(op.name()),
            &everything,
            &credentials(501),
            None,
            &context(sink.clone()),
        );
        assert!(!response.ok, "{} was performed", op.name());
    }
    assert!(sink.submitted.lock().expect("lock").is_empty());
}

#[test]
fn an_unauthorised_operation_is_named_as_an_authorization_refusal() {
    // `registry_version` 2 registered `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` and
    // emptied every substitution table. The code this returns must be the one
    // that means "this client may not do that" and not the one that means "the
    // installed authority binary is not the one we recorded" — they have
    // different next actions, and the CLI maps both to exit 4, which is exactly
    // why the wrong one would be invisible in a script and visible only to a
    // person reading the message.
    let sink = Arc::new(RecordingSink::default());
    let status_only = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
    let response = handle(
        &request("session.connect"),
        &status_only,
        &credentials(501),
        None,
        &context(sink),
    );
    assert_eq!(
        response.diagnostic.expect("named").reason_code,
        "PLATFORM.PRIV.CLIENT_UNAUTHORIZED"
    );
}

#[test]
fn an_authorised_operation_reaches_the_core_carrying_its_actor() {
    // **MI-18.** "The tunnel went down" and "Dana took the tunnel down" are
    // different facts, so the principal travels with the command.
    let sink = Arc::new(RecordingSink::default());
    let granted = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
    let response = handle(
        &request("status.get"),
        &granted,
        &credentials(501),
        None,
        &context(sink.clone()),
    );
    assert!(response.ok);
    let submitted = sink.submitted.lock().expect("lock");
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0].op, CoreCommand::StatusGet);
    assert_eq!(submitted[0].actor_principal.as_deref(), Some("uid:501"));
}

#[test]
fn mi6_a_locally_mutating_operation_reports_no_net_seq_rather_than_a_fake_one() {
    // The cursor is "a real, monotone position in the same log" the C2 stream
    // replays. A per-process counter here would tell a client it had
    // read-your-writes when it had not.
    let sink = Arc::new(RecordingSink::default());
    let granted = Scopes::from_scopes([twinvpn_mgmt::Scope::Status]);
    let response = handle(
        &request("status.get"),
        &granted,
        &credentials(501),
        None,
        &context(sink),
    );
    assert_eq!(response.committed_at_net_seq, None);
}

#[test]
fn mi21_the_catalogue_operation_is_answered_without_reaching_the_core() {
    // One of the four transport-layer operations, which have no core
    // counterpart and MUST NOT acquire one.
    let sink = Arc::new(RecordingSink::default());
    let response = handle(
        &request("mi.catalogue.get"),
        &Scopes::empty(),
        &credentials(501),
        None,
        &context(sink.clone()),
    );
    assert!(response.ok);
    assert!(sink.submitted.lock().expect("lock").is_empty());
    assert_eq!(
        String::from_utf8(response.result).expect("utf8"),
        twinvpn_mgmt::catalogue_digest_text()
    );
}

#[test]
fn ps4_no_operation_name_reaches_anything_that_is_not_a_catalogue_entry() {
    // The closed enum is the mechanism: an unrecognised name cannot become a
    // path, a command line or a rule, because there is nothing for it to
    // become.
    let unknown = twinvpn_mi::wire::Request {
        operation: "/bin/sh".to_owned(),
        params: Vec::new(),
        if_version: None,
    };
    assert!(CoreCommand::ALL
        .iter()
        .all(|op| op.name() != unknown.operation));
}

#[test]
fn every_core_command_has_a_name_and_no_two_share_one() {
    // MI-20's derivation is only safe if the wire names are unique, since the
    // wire carries a string.
    let mut names: Vec<&str> = CoreCommand::ALL.iter().map(|op| op.name()).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count);
}

#[test]
fn the_catalogue_digest_is_the_catalogues_and_not_a_constant() {
    // §11.7: "the catalogue, not the version, is the capability contract."
    // Taking the digest from anywhere but the catalogue would let a `HelloAck`
    // advertise a contract the agent does not serve.
    assert_ne!(twinvpn_mgmt::catalogue_digest(), 0);
    assert_eq!(
        twinvpn_mgmt::catalogue_digest(),
        twinvpn_mgmt::catalogue_digest()
    );
}

// ---------------------------------------------------------------------------
// §11.10's event stream. `ownership.md` §10.8 M-1.
//
// The bridge built a core, wrapped it in a `CommandSink` that exposes only
// `submit`, and dropped the handle — so the event stream was unreachable BY
// CONSTRUCTION: `next_event` appeared nowhere in this crate, no client could be
// told anything had changed, and every `Response.result` was empty.
//
// **What these tests can and cannot reach on this host.** `serve` begins with
// `PeerCredentials::read`, which returns `None` off Darwin — MI-A5, deliberately
// — so the attach itself is not runnable here and neither is the `SO_PEERCRED`
// half. Everything *after* the attach is, because `request_loop` is generic over
// the transport for exactly this reason. What is asserted below is therefore the
// loop, the pump, the ordering and the snapshot; what is not is the credential
// read, which is `#[cfg(target_os = "macos")]` and has never executed.
// ---------------------------------------------------------------------------

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime")
}

fn ctx() -> ServerContext {
    context(std::sync::Arc::new(RecordingSink::default()))
}

async fn read_one<S>(stream: &mut S) -> MgmtEnvelope
where
    S: tokio::io::AsyncRead + Unpin,
{
    twinvpn_mi::codec::read_frame(stream)
        .await
        .expect("a frame")
        .expect("not a clean close")
}

/// Drives [`request_loop`] over an in-memory duplex, with the client half
/// returned so a test can read what the agent pushed.
fn drive(
    context: ServerContext,
    subscription: Option<u64>,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Ending>) {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let granted = Scopes::from_scopes(twinvpn_mi::scope::GRANTABLE);
    let credentials = credentials(501);
    let handle = tokio::spawn(async move {
        request_loop(&mut server, &granted, &credentials, subscription, &context).await
    });
    (client, handle)
}

#[test]
fn a_subscribed_client_receives_the_events_the_fanout_publishes() {
    // **F-5 end to end on the macOS socket carriage.** "All state changes arrive
    // as events on exactly one totally ordered stream per instance" — and that
    // stream used to stop inside the core, because nothing read it.
    runtime().block_on(async {
        let context = ctx();
        let fanout = std::sync::Arc::clone(&context.fanout);
        let id = fanout.subscribe(64);
        let (mut client, served) = drive(context, Some(id));

        fanout.publish(
            7,
            &twinvpn_mi::wire::Event {
                topic: "transition".to_owned(),
                payload: vec![1, 2, 3],
                actor_principal: Some("dana".to_owned()),
                op: None,
            },
        );

        let frame = read_one(&mut client).await;
        let Body::Event(event) = frame.body else {
            panic!("an event, not a marker")
        };
        assert_eq!(event.topic, "transition");
        assert_eq!(event.payload, vec![1, 2, 3]);
        // **MI-18.** "The tunnel went down" and "Dana took the tunnel down" are
        // different facts, and the attribution survives the whole path.
        assert_eq!(event.actor_principal.as_deref(), Some("dana"));
        // **MI-16.** The core's own sequence number, carried unchanged — a
        // contiguous `seq` is what proves no event was lost.
        assert_eq!(frame.seq, 7);
        // **MI-16's stamp comes from the INJECTED clock**, which this testkit
        // fixes at zero. Asserting the fixed value rather than "not zero" is
        // the stronger check: a stamp read from the wall would be a large
        // number here, and MI-16 forbids a wall clock because it can go
        // backwards.
        assert_eq!(frame.as_of_ms, 0, "stamped from the injected clock");

        drop(client);
        let _ = served.await.expect("the task joined");
    });
}

#[test]
fn a_gap_reaches_the_client_as_an_ordered_marker() {
    // MI-19: a drop is a recorded gap, never a silence, and the marker keeps the
    // `up_to_seq` that makes the gap resyncable. It used to be synthesized into
    // a diagnostic on the C ABI and did not exist at all here.
    runtime().block_on(async {
        let context = ctx();
        let fanout = std::sync::Arc::clone(&context.fanout);
        let id = fanout.subscribe(64);
        let (mut client, served) = drive(context, Some(id));

        fanout.publish_gap(11, &[("transition".to_owned(), 4)]);

        let frame = read_one(&mut client).await;
        let Body::Compacted(marker) = frame.body else {
            panic!("MI-19's marker is its own body, not a diagnostic")
        };
        assert_eq!(marker.up_to_seq, 11);
        assert_eq!(marker.dropped_by_topic, vec![("transition".to_owned(), 4)]);

        drop(client);
        let _ = served.await.expect("the task joined");
    });
}

#[test]
fn a_client_on_no_stream_is_sent_nothing_and_still_answers_requests() {
    // §11.10 has no wildcard: a client that named no topic is on no stream.
    // Without this, "subscribed" would not be a state — and the loop must still
    // serve requests, which is the regression the `select!` could cause.
    use tokio::io::AsyncWriteExt as _;

    runtime().block_on(async {
        let context = ctx();
        let fanout = std::sync::Arc::clone(&context.fanout);
        let (mut client, served) = drive(context, None);

        // Published with nobody subscribed: it must reach no wire at all.
        fanout.publish(
            1,
            &twinvpn_mi::wire::Event {
                topic: "transition".to_owned(),
                payload: Vec::new(),
                actor_principal: None,
                op: None,
            },
        );

        let request = twinvpn_mi::codec::encode_frame(&MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![9],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Request(twinvpn_mi::wire::Request {
                operation: "mi.catalogue.get".to_owned(),
                params: Vec::new(),
                if_version: None,
            }),
        })
        .expect("encodes");
        client.write_all(&request).await.expect("writes");

        // The FIRST frame back is the response, not the event. If the pump had
        // fired for an unsubscribed connection this would be an `Event`.
        let frame = read_one(&mut client).await;
        assert!(
            matches!(frame.body, Body::Response(ref r) if r.ok),
            "an unsubscribed client gets its answer and no stream: {:?}",
            frame.body
        );

        drop(client);
        let _ = served.await.expect("the task joined");
    });
}

#[test]
fn an_event_never_overtakes_the_response_to_an_earlier_request() {
    // The ordering property the interleaving could break. A client that saw a
    // state change before the acknowledgement of the command that caused it
    // would have to reason about a future it had not been told about yet.
    use tokio::io::AsyncWriteExt as _;

    runtime().block_on(async {
        let context = ctx();
        let fanout = std::sync::Arc::clone(&context.fanout);
        let id = fanout.subscribe(64);
        let (mut client, served) = drive(context, Some(id));

        let request = twinvpn_mi::codec::encode_frame(&MgmtEnvelope {
            mi_version: MI_VERSION,
            request_id: vec![9],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Request(twinvpn_mi::wire::Request {
                operation: "mi.catalogue.get".to_owned(),
                params: Vec::new(),
                if_version: None,
            }),
        })
        .expect("encodes");
        client.write_all(&request).await.expect("writes");

        let first = read_one(&mut client).await;
        assert!(
            matches!(first.body, Body::Response(_)),
            "the response to a request that preceded any publish comes first"
        );

        fanout.publish(
            2,
            &twinvpn_mi::wire::Event {
                topic: "session".to_owned(),
                payload: Vec::new(),
                actor_principal: None,
                op: None,
            },
        );
        let second = read_one(&mut client).await;
        assert!(matches!(second.body, Body::Event(_)), "then the event");

        drop(client);
        let _ = served.await.expect("the task joined");
    });
}

#[test]
fn an_unsubscribed_resync_is_refused_by_its_own_name() {
    // MI-9a: "the stream dropped events, resnapshot" and "your cursor cannot be
    // serviced" are different recoveries. They were the same code until
    // `registry_version` 2 registered `MGMT.RESYNC_REQUIRED` — X-1 called this
    // pair the worst of the sixteen substitutions.
    let granted = Scopes::from_scopes(twinvpn_mi::scope::GRANTABLE);
    let response = handle(
        &twinvpn_mi::wire::Request {
            operation: "event.resync".to_owned(),
            params: Vec::new(),
            if_version: None,
        },
        &granted,
        &credentials(501),
        None,
        &ctx(),
    );
    assert!(!response.ok);
    let diagnostic = response.diagnostic.expect("named");
    assert_eq!(diagnostic.reason_code, "MGMT.RESYNC_REQUIRED");
    assert_ne!(
        diagnostic.reason_code, "MGMT.STREAM_COMPACTED",
        "MI-9a's two conditions must stay two codes"
    );
}

#[test]
fn a_subscribed_resync_answers_with_the_snapshot() {
    // It refused unconditionally before, because there was no stream to
    // snapshot. An empty `rows` is now a truthful answer and is distinguishable
    // from a refusal; what MI-9a forbids is an empty snapshot that hides a gap,
    // and the cursor beside it is what tells a client whether one occurred.
    let context = ctx();
    let id = context.fanout.subscribe(64);
    context.fanout.publish(
        3,
        &twinvpn_mi::wire::Event {
            topic: "transition".to_owned(),
            payload: vec![9],
            actor_principal: None,
            op: None,
        },
    );
    let granted = Scopes::from_scopes(twinvpn_mi::scope::GRANTABLE);
    let response = handle(
        &twinvpn_mi::wire::Request {
            operation: "event.resync".to_owned(),
            params: Vec::new(),
            if_version: None,
        },
        &granted,
        &credentials(501),
        Some(id),
        &context,
    );
    assert!(response.ok, "no longer an unconditional refusal");
    let body: ResyncBody = serde_json::from_slice(&response.result).expect("the snapshot");
    assert_eq!(body.cursor, 4, "MI-9's cursor, assigned inside the lock");
    assert_eq!(body.rows.len(), 1);
    assert_eq!(body.rows[0].topic, "transition");
}

#[test]
fn the_xpc_carriage_carries_no_stream_and_says_so_by_name() {
    // Swift owns the XPC listener and hands this crate one message at a time
    // through the C ABI, so there is nowhere to push an unsolicited frame from.
    // `None` is the truth rather than an omission, and a resync on that carriage
    // is refused by name instead of answered with a snapshot of a stream the
    // client is not on.
    let source = executable_source(include_str!("session.rs"));
    assert!(
        source.contains("None,"),
        "the XPC session must pass no subscription"
    );
    assert!(
        !source.contains("fanout"),
        "and must not acquire one: there is no place to push from"
    );
}
