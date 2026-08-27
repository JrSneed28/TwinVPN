//! Running a real command in a real namespace, and refusing to pretend.
//!
//! **Authority:** `docs/testing-strategy.md` §3.1's realization principle.
//!
//! Every condition TwinLab reproduces is produced by a real mechanism, which in
//! practice means `ip`, `tc`, `nft`, `sysctl` and `unshare` executed inside a
//! namespace. This module is the single place those processes are spawned, so
//! that the run record (§3.6) can name every command the rig actually ran.
//!
//! # Two rules this module enforces
//!
//! 1. **A missing tool is not a passing test.** [`Runner::run`] distinguishes
//!    `ExecError::ToolMissing` from a non-zero exit, and
//!    [`crate::outcome::Verdict`] gives the first its own non-passing variant.
//!    A rig that cannot produce a condition reports that it could not; it never
//!    reports that the condition held.
//! 2. **Nothing sensitive is logged.** Commands are network plumbing and carry
//!    no key material, but the argv is still recorded through
//!    [`Invocation::redacted_argv`] so a future argument carrying a secret has a
//!    place to be excluded rather than a habit to be broken.

use std::ffi::OsStr;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use crate::error::LabError;

/// Argument names whose *values* are never recorded.
///
/// Empty today and deliberately present: the plumbing this module runs takes no
/// secret, and the moment one is added the exclusion must already exist. A
/// redaction list invented on the day a secret appears is added after the leak.
const REDACTED_ARG_NAMES: &[&str] = &["--key", "--psk", "--secret", "--token"];

/// One executed command, as the §3.6 run record carries it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Invocation {
    /// The program.
    pub program: String,
    /// The arguments, with any value following a [`REDACTED_ARG_NAMES`] name
    /// replaced.
    pub argv: Vec<String>,
    /// The namespace the command ran in, if any.
    pub netns: Option<String>,
    /// The process exit status, or `None` if the program could not be spawned.
    pub status: Option<i32>,
    /// Wall-clock microseconds. Evidence only — never an assertion input in a
    /// `BIT` scenario (§3.5).
    pub micros: u64,
}

impl Invocation {
    /// Redacts argument values by name.
    #[must_use]
    pub fn redacted_argv<S: AsRef<OsStr>>(args: &[S]) -> Vec<String> {
        let mut out = Vec::with_capacity(args.len());
        let mut redact_next = false;
        for a in args {
            let s = a.as_ref().to_string_lossy().into_owned();
            if redact_next {
                out.push("<redacted>".to_owned());
                redact_next = false;
                continue;
            }
            redact_next = REDACTED_ARG_NAMES.contains(&s.as_str());
            out.push(s);
        }
        out
    }
}

/// Why a command did not produce a usable result.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The program is not installed on this host.
    ///
    /// Distinct from a failure on purpose: this is the condition under which
    /// TwinLab must decline to produce a verdict rather than produce a green one.
    #[error("tool `{program}` is not installed on this host")]
    ToolMissing {
        /// The program that was not found.
        program: String,
    },
    /// The program ran and failed.
    #[error("`{program}` exited {status:?}: {stderr}")]
    Failed {
        /// The program.
        program: String,
        /// Its exit code.
        status: Option<i32>,
        /// Its standard error, trimmed.
        stderr: String,
    },
    /// The program could not be spawned for a reason other than absence.
    #[error("spawning `{program}` failed: {source}")]
    Spawn {
        /// The program.
        program: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl From<ExecError> for LabError {
    fn from(e: ExecError) -> Self {
        match e {
            ExecError::ToolMissing { program } => LabError::FacilityUnavailable {
                facility: "external tool",
                detail: program,
            },
            other => LabError::Mechanism {
                detail: other.to_string(),
            },
        }
    }
}

/// Spawns commands and records what it spawned.
#[derive(Debug, Default)]
pub struct Runner {
    log: Vec<Invocation>,
}

impl Runner {
    /// A runner with an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything this runner has executed, in order.
    #[must_use]
    pub fn log(&self) -> &[Invocation] {
        &self.log
    }

    /// Runs `program` with `args`, capturing output.
    ///
    /// # Errors
    ///
    /// [`ExecError::ToolMissing`] when the program is not installed,
    /// [`ExecError::Failed`] on a non-zero exit, [`ExecError::Spawn`] otherwise.
    pub fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, ExecError> {
        self.run_in(None, program, args)
    }

    /// Runs `program` inside the named network namespace, or on the host when
    /// `netns` is `None`.
    ///
    /// # Errors
    ///
    /// As [`Runner::run`].
    pub fn run_in(
        &mut self,
        netns: Option<&str>,
        program: &str,
        args: &[&str],
    ) -> Result<Output, ExecError> {
        let (prog, full): (&str, Vec<String>) = match netns {
            Some(ns) => (
                "ip",
                std::iter::once("netns".to_owned())
                    .chain(std::iter::once("exec".to_owned()))
                    .chain(std::iter::once(ns.to_owned()))
                    .chain(std::iter::once(program.to_owned()))
                    .chain(args.iter().map(|a| (*a).to_owned()))
                    .collect(),
            ),
            None => (program, args.iter().map(|a| (*a).to_owned()).collect()),
        };

        let started = Instant::now();
        let result = Command::new(prog)
            .args(&full)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);

        match result {
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                self.log.push(Invocation {
                    program: prog.to_owned(),
                    argv: Invocation::redacted_argv(&full),
                    netns: netns.map(ToOwned::to_owned),
                    status: None,
                    micros,
                });
                Err(ExecError::ToolMissing {
                    program: prog.to_owned(),
                })
            }
            Err(source) => Err(ExecError::Spawn {
                program: prog.to_owned(),
                source,
            }),
            Ok(out) => {
                self.log.push(Invocation {
                    program: prog.to_owned(),
                    argv: Invocation::redacted_argv(&full),
                    netns: netns.map(ToOwned::to_owned),
                    status: out.status.code(),
                    micros,
                });
                if out.status.success() {
                    Ok(out)
                } else {
                    Err(ExecError::Failed {
                        program: prog.to_owned(),
                        status: out.status.code(),
                        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                    })
                }
            }
        }
    }

    /// Whether `program` resolves on this host, without running it.
    #[must_use]
    pub fn tool_present(program: &str) -> bool {
        std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(program);
                candidate.is_file()
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_tool_is_its_own_error_and_not_a_failure() {
        let mut r = Runner::new();
        let err = r
            .run("twinlab-no-such-program-9f1c", &[])
            .expect_err("must not succeed");
        assert!(
            matches!(err, ExecError::ToolMissing { .. }),
            "a missing tool must be distinguishable from a failing one: {err}"
        );
    }

    #[test]
    fn a_failing_tool_is_not_reported_as_missing() {
        // Negative control for the test above: `false` exists and exits 1, so
        // the two conditions must not collapse into one variant.
        let mut r = Runner::new();
        match r.run("false", &[]) {
            Err(ExecError::Failed { status, .. }) => assert_eq!(status, Some(1)),
            Err(ExecError::ToolMissing { .. }) => {
                // `false` genuinely absent — the host cannot run this control.
                // Say so rather than passing.
                panic!("/bin/false is absent; the negative control cannot run");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn secret_argument_values_are_redacted() {
        let argv = Invocation::redacted_argv(&["set", "--psk", "hunter2", "--mtu", "1280"]);
        assert_eq!(argv, ["set", "--psk", "<redacted>", "--mtu", "1280"]);
    }

    #[test]
    fn tool_present_agrees_with_execution() {
        assert!(Runner::tool_present("sh"), "sh must exist");
        assert!(!Runner::tool_present("twinlab-no-such-program-9f1c"));
    }
}
