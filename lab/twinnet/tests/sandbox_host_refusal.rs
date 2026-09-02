//! What the sandbox concludes when its agent dies before it can work.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1 — "this host cannot produce
//! the condition" and "the condition did not hold" are different answers.
//!
//! # Why this is a test and not a comment
//!
//! The classification these assertions pin down cannot be exercised by running
//! the laboratory: it needs a host that forbids unprivileged user namespaces,
//! and a developer laptop, a WSL2 kernel and most runners all permit them. It
//! went untested for exactly that reason, and on 2026-09-02 the first
//! `ubuntu-24.04` runner to reach the T1 tier produced the case — four
//! scenarios *failed* a suite they should have *skipped*, because a dead agent
//! was reported as `NetError::Agent` ("the agent closed its pipe; it probably
//! could not unshare") and `common::or_skip` panics on anything that is not
//! `Unavailable`.
//!
//! So the agent is stood in for here. Each test is a three-line script that
//! ends the way a refused agent ends, and the assertion is on what
//! [`Sandbox::start_with`] makes of it. Every host can run that, which is the
//! point.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use twinnet::Sandbox;

/// The exact line the agent writes when this host denies it the capabilities of
/// the namespace it just created. Copied from a real refusal (job
/// 100262708025), so a change to the message shape shows up here.
const REFUSAL: &str =
    "denying setgroups in the new user namespace: Permission denied (os error 13)";

/// Writes an executable stand-in for the agent and returns its path.
fn fake_agent(name: &str, script: &str) -> PathBuf {
    let path = twinnet::rigs::scratch(name).join("twinnet");
    std::fs::write(&path, script).expect("a scratch directory is writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("its permissions are ours to set");
    path
}

#[test]
fn a_refused_agent_reaches_the_test_as_the_errno_that_refused_it() {
    // `head -n 1` consumes the probe request the sandbox always sends first,
    // which makes this exchange an exchange rather than a race with our exit.
    let agent = fake_agent(
        "refusal-spoken",
        &format!(
            "#!/bin/sh\nhead -n 1 >/dev/null\n\
             printf '%s\\n' '{{\"kind\":\"error\",\"message\":\"{REFUSAL}\",\
             \"unavailable\":true}}'\nexit 3\n"
        ),
    );

    let err = Sandbox::start_with(&agent).expect_err("the agent refused");
    assert!(
        err.is_unavailable(),
        "a host that will not grant a user namespace is a facility this host \
         cannot provide, and a test must skip rather than fail on it: {err}"
    );
    assert!(
        err.to_string().contains(REFUSAL),
        "the refusal the agent reported has to survive the pipe — a test that \
         skips without the errno cannot tell a restricted runner from a broken \
         one: {err}"
    );
}

#[test]
fn an_agent_that_dies_before_it_speaks_is_still_the_host() {
    // No output at all: the case where the agent is killed, or loses the race
    // to say anything. The exit code is the whole evidence, and `twinnet`
    // reserves 3 for `NetError::Unavailable`.
    let agent = fake_agent("refusal-silent", "#!/bin/sh\nexit 3\n");

    let err = Sandbox::start_with(&agent).expect_err("the agent refused");
    assert!(
        err.is_unavailable(),
        "exit {} is this binary's code for a facility the host cannot provide, \
         whether or not the agent lived long enough to say so: {err}",
        twinnet::UNAVAILABLE_EXIT_CODE
    );
}

#[test]
fn an_agent_that_dies_of_a_defect_is_never_a_skip() {
    // The fail-closed half. A rig that is broken must keep panicking the suite:
    // a defect that buys itself a skip is a suite that goes quiet, which is the
    // failure `common::or_skip` exists to prevent.
    for (name, script) in [
        ("defect-exit-1", "#!/bin/sh\nexit 1\n"),
        ("defect-exit-0", "#!/bin/sh\nexit 0\n"),
        ("defect-garbage", "#!/bin/sh\necho not-json\nexit 0\n"),
    ] {
        let err =
            Sandbox::start_with(&fake_agent(name, script)).expect_err("no sandbox comes of this");
        assert!(
            !err.is_unavailable(),
            "`{name}` is a broken agent, not a restricted host; calling it \
             unavailable would turn a defect into a silent skip: {err}"
        );
    }
}
