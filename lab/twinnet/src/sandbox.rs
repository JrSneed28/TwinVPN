//! The test-side handle on the laboratory's privileged half.
//!
//! A [`Sandbox`] is one running agent process. Everything the fabric does — a
//! namespace, a `veth`, a `netem` qdisc, a middlebox, a capture, a killed relay
//! — is a request on this handle, and every namespace it creates lives exactly
//! as long as it does.
//!
//! # Teardown is not best-effort
//!
//! [`Sandbox`] tears down in `Drop`, and the kernel tears down *again*
//! underneath it: a network namespace with no process in it and no bind mount
//! holding it open is reclaimed, and the agent's mount namespace held the only
//! bind mounts. So a test that panics mid-scenario leaks nothing, which is the
//! property that makes it safe to run this suite on a shared runner.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::error::{NetError, Result};
use crate::proto::{Fact, Request, Response};

/// A handle on a spawned process inside the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcHandle {
    /// The agent-side identifier.
    pub id: u64,
    /// The pid, for a report. Never used to signal — the agent owns that, so
    /// that a reaped-and-recycled pid can never be signalled by a test.
    pub pid: i32,
}

/// The result of a command run inside the sandbox.
#[derive(Debug, Clone)]
pub struct Ran {
    /// Exit status, `None` if signalled.
    pub status: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl Ran {
    /// Whether the command exited zero.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == Some(0)
    }
}

/// One running laboratory.
#[derive(Debug)]
pub struct Sandbox {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    facts: Vec<Fact>,
    agent: PathBuf,
}

impl Sandbox {
    /// Starts a sandbox using the `twinnet` agent binary found on this host.
    ///
    /// The search order is `TWINNET_AGENT`, then a `twinnet` beside the current
    /// executable, then one directory up from it — which is where cargo puts a
    /// binary target relative to a test binary in `deps/`.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] when the agent cannot be found or refuses to
    /// unshare. Both are "this host cannot run the laboratory", never a pass.
    pub fn start() -> Result<Self> {
        let agent = locate_agent()?;
        Self::start_with(&agent)
    }

    /// Starts a sandbox using a specific agent binary.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] if the agent cannot start or unshare;
    /// [`NetError::Agent`] if it starts and then speaks something unexpected.
    pub fn start_with(agent: &Path) -> Result<Self> {
        let mut child = Command::new(agent)
            .arg("agent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| NetError::Unavailable {
                facility: "network-namespaces",
                detail: format!(
                    "the twinnet agent at {} could not start: {e}",
                    agent.display()
                ),
            })?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        let mut sandbox = Sandbox {
            child,
            stdin,
            stdout,
            facts: Vec::new(),
            agent: agent.to_path_buf(),
        };
        sandbox.facts = match sandbox.request(&Request::Probe)? {
            Response::Probe { facts } => facts,
            other => {
                return Err(NetError::Agent(format!(
                    "expected a probe report, got {other:?}"
                )))
            }
        };
        Ok(sandbox)
    }

    /// The agent binary this sandbox is running, so a middlebox or observer can
    /// be spawned from the same build.
    #[must_use]
    pub fn agent_path(&self) -> &Path {
        &self.agent
    }

    /// The realized-facility report, probed at start.
    #[must_use]
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// Whether a facility was realized. A name this host never probed answers
    /// `false`, because an unprobed facility is not an available one.
    #[must_use]
    pub fn has(&self, facility: &str) -> bool {
        self.facts
            .iter()
            .any(|f| f.facility == facility && f.available)
    }

    /// The evidence recorded for a facility, present or absent.
    #[must_use]
    pub fn evidence(&self, facility: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.facility == facility)
            .map(|f| f.evidence.as_str())
    }

    /// Refuses to continue unless every named facility was realized.
    ///
    /// This is the single guard that keeps §3.1 honest at a call site: a
    /// scenario states what it needs, and a host that cannot supply it produces
    /// [`NetError::Unavailable`] — which the caller converts into
    /// `Verdict::Unavailable`, never into a pass.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] naming the first missing facility and the
    /// evidence of its absence.
    pub fn require(&self, facilities: &[&'static str]) -> Result<()> {
        for f in facilities {
            if !self.has(f) {
                return Err(NetError::Unavailable {
                    facility: f,
                    detail: self
                        .evidence(f)
                        .unwrap_or("this facility was never probed")
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Sends one request and reads its response.
    ///
    /// # Errors
    ///
    /// [`NetError::Agent`] if the pipe closes or the answer is undecodable.
    pub fn request(&mut self, req: &Request) -> Result<Response> {
        let line = serde_json::to_string(req).expect("Request is always encodable");
        writeln!(self.stdin, "{line}").map_err(|e| NetError::os("writing to the agent", e))?;
        self.stdin
            .flush()
            .map_err(|e| NetError::os("flushing to the agent", e))?;
        let mut buf = String::new();
        let n = self
            .stdout
            .read_line(&mut buf)
            .map_err(|e| NetError::os("reading from the agent", e))?;
        if n == 0 {
            return Err(NetError::Agent(
                "the agent closed its pipe; it probably could not unshare".to_owned(),
            ));
        }
        serde_json::from_str(&buf)
            .map_err(|e| NetError::Agent(format!("undecodable response `{}`: {e}", buf.trim())))
    }

    /// Runs a command, optionally inside a namespace, and returns what it did.
    ///
    /// A non-zero exit is a [`Ran`], not an error: a scenario that asserts a
    /// command *fails* is a normal scenario.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] if the program is not installed; other variants
    /// for a control-channel failure.
    pub fn run(&mut self, netns: Option<&str>, argv: &[&str]) -> Result<Ran> {
        let req = Request::Run {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            netns: netns.map(str::to_owned),
            stdin: None,
        };
        match self.request(&req)? {
            Response::Ran {
                status,
                stdout,
                stderr,
            } => Ok(Ran {
                status,
                stdout,
                stderr,
            }),
            Response::Error {
                message,
                unavailable: true,
            } => Err(NetError::Unavailable {
                facility: "external tool",
                detail: message,
            }),
            Response::Error { message, .. } => Err(NetError::Agent(message)),
            other => Err(NetError::Agent(format!("expected Ran, got {other:?}"))),
        }
    }

    /// Runs a command and fails if it did not exit zero.
    ///
    /// # Errors
    ///
    /// [`NetError::Mechanism`] carrying the program, the argv and the stderr, so
    /// a topology failure names the exact `ip` line that produced it.
    pub fn must(&mut self, netns: Option<&str>, argv: &[&str]) -> Result<String> {
        let ran = self.run(netns, argv)?;
        if ran.ok() {
            return Ok(ran.stdout);
        }
        Err(NetError::Mechanism {
            program: argv.first().map_or_else(String::new, |s| (*s).to_owned()),
            argv: argv.join(" "),
            status: ran.status,
            stderr: ran.stderr.trim().to_owned(),
        })
    }

    /// Starts a long-lived process inside the sandbox.
    ///
    /// # Errors
    ///
    /// [`NetError::Unavailable`] if the program is not installed.
    pub fn spawn(
        &mut self,
        netns: Option<&str>,
        argv: &[&str],
        log: Option<&Path>,
    ) -> Result<ProcHandle> {
        let req = Request::Spawn {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            netns: netns.map(str::to_owned),
            log: log.map(|p| p.display().to_string()),
        };
        match self.request(&req)? {
            Response::Spawned { id, pid } => Ok(ProcHandle { id, pid }),
            Response::Error {
                message,
                unavailable: true,
            } => Err(NetError::Unavailable {
                facility: "external tool",
                detail: message,
            }),
            Response::Error { message, .. } => Err(NetError::Agent(message)),
            other => Err(NetError::Agent(format!("expected Spawned, got {other:?}"))),
        }
    }

    /// Signals a spawned process. The chaos primitive.
    ///
    /// # Errors
    ///
    /// [`NetError::Agent`] if the handle is unknown.
    pub fn signal(&mut self, handle: ProcHandle, sig: i32) -> Result<bool> {
        match self.request(&Request::Signal { id: handle.id, sig })? {
            Response::Signalled { delivered } => Ok(delivered),
            Response::Error { message, .. } => Err(NetError::Agent(message)),
            other => Err(NetError::Agent(format!(
                "expected Signalled, got {other:?}"
            ))),
        }
    }

    /// Waits for a spawned process, up to `timeout_ms`.
    ///
    /// # Errors
    ///
    /// [`NetError::Agent`] if the handle is unknown.
    pub fn wait(&mut self, handle: ProcHandle, timeout_ms: u64) -> Result<(bool, Option<i32>)> {
        match self.request(&Request::Wait {
            id: handle.id,
            timeout_ms,
        })? {
            Response::Waited { status, exited } => Ok((exited, status)),
            Response::Error { message, .. } => Err(NetError::Agent(message)),
            other => Err(NetError::Agent(format!("expected Waited, got {other:?}"))),
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "{{\"op\":\"shutdown\"}}");
        let _ = self.stdin.flush();
        // A bounded wait: an agent wedged on a child that ignores SIGKILL must
        // not wedge the test suite behind it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                _ => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Finds the `twinnet` agent binary.
fn locate_agent() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("TWINNET_AGENT") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(NetError::Unavailable {
            facility: "network-namespaces",
            detail: format!(
                "TWINNET_AGENT points at {}, which is not a file",
                path.display()
            ),
        });
    }
    let exe =
        std::env::current_exe().map_err(|e| NetError::os("locating the current executable", e))?;
    let mut tried = Vec::new();
    for dir in exe
        .parent()
        .into_iter()
        .chain(exe.parent().and_then(Path::parent))
    {
        let candidate = dir.join("twinnet");
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate.display().to_string());
    }
    Err(NetError::Unavailable {
        facility: "network-namespaces",
        detail: format!(
            "no `twinnet` agent binary found (tried {}); set TWINNET_AGENT",
            tried.join(", ")
        ),
    })
}
