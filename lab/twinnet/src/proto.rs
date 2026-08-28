//! The line-delimited JSON protocol between a test and the sandbox agent.
//!
//! **Why there is a protocol at all.** A Linux user namespace is entered by a
//! *process*, not by a library call that a later call can undo: `unshare(2)`
//! with `CLONE_NEWUSER` is refused in a multi-threaded process, and a test
//! harness is multi-threaded by the time it runs its first test. So the
//! laboratory's privileged half lives in a separate single-threaded process
//! that unshares at `main` before it has spawned anything, and the test drives
//! it over a pipe.
//!
//! The consequence worth naming: **the namespaces outlive individual commands**.
//! A topology built by one request is still there for the next one, which is
//! what makes a scenario a sequence of steps rather than one enormous shell
//! line.

use serde::{Deserialize, Serialize};

/// What a test asks the sandbox to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Report what this host can actually realize, by doing it.
    Probe,
    /// Run a command to completion, optionally inside a named namespace.
    Run {
        /// The program and its arguments.
        argv: Vec<String>,
        /// The namespace to enter first, if any.
        netns: Option<String>,
        /// Bytes to write to the child's standard input.
        #[serde(default)]
        stdin: Option<String>,
    },
    /// Start a long-lived process and return a handle to it.
    Spawn {
        /// The program and its arguments.
        argv: Vec<String>,
        /// The namespace to enter first, if any.
        netns: Option<String>,
        /// Where to append the child's stdout and stderr. A file rather than a
        /// pipe because a chaos test kills the agent's children and then reads
        /// what they had said, and a pipe dies with the reader.
        log: Option<String>,
    },
    /// Send a signal to a spawned process. The chaos primitive: `SIGKILL` is
    /// relay termination, `SIGTERM` is a graceful gateway restart's first half.
    Signal {
        /// The handle returned by [`Request::Spawn`].
        id: u64,
        /// The signal number.
        sig: i32,
    },
    /// Reap a spawned process, waiting up to `timeout_ms`.
    Wait {
        /// The handle.
        id: u64,
        /// How long to wait before reporting that it is still running.
        timeout_ms: u64,
    },
    /// Tear the sandbox down. Every namespace dies with the agent regardless;
    /// this makes the teardown observable rather than incidental.
    Shutdown,
}

/// What the sandbox answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// The realized-facility report.
    Probe {
        /// Facility name to evidence. A facility that is absent is present in
        /// this map with the evidence of its absence, never missing from it.
        facts: Vec<Fact>,
    },
    /// A completed command.
    Ran {
        /// Exit status, `None` if signalled.
        status: Option<i32>,
        /// Standard output.
        stdout: String,
        /// Standard error.
        stderr: String,
    },
    /// A started process.
    Spawned {
        /// The handle.
        id: u64,
        /// The child's pid inside the sandbox's pid namespace (which is the
        /// host's — this crate does not unshare pids).
        pid: i32,
    },
    /// A signalled process.
    Signalled {
        /// Whether the process was still alive to receive it.
        delivered: bool,
    },
    /// A reaped process.
    Waited {
        /// Exit status, `None` if it was signalled or is still running.
        status: Option<i32>,
        /// Whether it had exited within the timeout.
        exited: bool,
    },
    /// The agent is going away.
    Bye,
    /// The request could not be carried out.
    Error {
        /// What went wrong.
        message: String,
        /// Whether this is "the host cannot do it" rather than "it failed".
        unavailable: bool,
    },
}

/// One probed facility, with the evidence that produced the answer.
///
/// The evidence field is not decoration. A capability table that says
/// `bridge: false` and nothing else cannot be argued with; one that says
/// `bridge: false — "RTNETLINK answers: Operation not permitted"` tells the
/// reader whether to install a package or ask for a different runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// The facility name, matching `twinlab::capability::Facility`'s spelling
    /// where one exists.
    pub facility: String,
    /// Whether the probe succeeded.
    pub available: bool,
    /// What the probe observed, success or failure.
    pub evidence: String,
}

impl Fact {
    /// A successful probe.
    #[must_use]
    pub fn ok(facility: &str, evidence: impl Into<String>) -> Self {
        Fact {
            facility: facility.to_owned(),
            available: true,
            evidence: evidence.into(),
        }
    }

    /// A failed probe.
    #[must_use]
    pub fn no(facility: &str, evidence: impl Into<String>) -> Self {
        Fact {
            facility: facility.to_owned(),
            available: false,
            evidence: evidence.into(),
        }
    }
}
