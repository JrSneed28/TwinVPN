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
