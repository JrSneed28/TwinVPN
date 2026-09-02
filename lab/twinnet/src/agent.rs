//! The privileged half of the laboratory: one single-threaded process that
//! unshares into its own user, mount and network namespaces and then does as it
//! is told.
//!
//! **Authority:** `docs/testing-strategy.md` §3.2 — "the unit of a node is a
//! Linux network namespace".
//!
//! # Why this is unprivileged and still a real namespace
//!
//! `ip netns add` needs `CAP_NET_ADMIN`, and this laboratory has to run on a
//! developer laptop and an unprivileged CI runner. Both of those grant
//! `CLONE_NEWUSER`, and a process that is root *inside* a user namespace holds
//! the full capability set *inside* the network and mount namespaces it then
//! creates. Nothing here is emulated by that: the namespaces, the `veth` pairs,
//! the bridges, the `netem` qdiscs and the raw sockets are the same kernel
//! objects a root-owned laboratory would get.
//!
//! One thing genuinely differs and is stated rather than hidden: `/run` is not
//! writable, so `ip netns`'s bind-mount directory does not exist. The agent
//! mounts a `tmpfs` over `/run` **inside its own mount namespace**, which is why
//! `CLONE_NEWNS` is in the unshare set. Nothing outside the agent sees it.
//!
//! # The unsafe surface
//!
//! [`enter`] is one of the two functions in `/lab/` that contain `unsafe`. It is
//! six libc calls with no pointer arithmetic and no lifetimes: `getuid`,
//! `getgid`, `unshare`, `mount` twice, and `kill`. Everything else in this
//! module is safe Rust over `std::process`.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};

use crate::error::{NetError, Result};
use crate::probe;
use crate::proto::{Request, Response};

/// Unshares into a user, mount and network namespace and prepares `/run/netns`.
///
/// MUST be called before the process spawns a thread: the kernel refuses
/// `CLONE_NEWUSER` from a multi-threaded process, and the failure mode is an
/// `EINVAL` that reads like a kernel-support problem rather than a
/// this-is-thread-three problem. The binary that calls this calls it as the
/// first statement of `main`.
///
/// # Errors
///
/// [`NetError::Unavailable`] when this host refuses the namespace — at the
/// `unshare` itself, or at one of the privileged steps inside it, which is
/// where a host that restricts unprivileged user namespaces actually says no
/// (see [`refused`]). A host this laboratory cannot run on must never be
/// reported as a passing scenario.
pub fn enter() -> Result<()> {
    // SAFETY: `getuid`/`getgid` cannot fail and take no arguments.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    // SAFETY: `unshare` takes an integer flag set and touches no memory this
    // process owns. The three flags are the documented constants.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET) };
    if rc != 0 {
        return Err(NetError::Unavailable {
            facility: "network-namespaces",
            detail: format!(
                "unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET) failed: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    // The identity map. `setgroups` MUST be denied first: an unprivileged
    // process may not write `gid_map` while `setgroups` is permitted, because
    // that would let it drop out of a group it was confined to.
    fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| refused("denying setgroups in the new user namespace", e))?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
        .map_err(|e| refused("writing uid_map", e))?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
        .map_err(|e| refused("writing gid_map", e))?;

    make_run_writable()?;

    // `lo` is down in a fresh namespace, and a service that binds a loopback
    // address fails with `EADDRNOTAVAIL` rather than anything that names the
    // cause. Bringing it up here means no topology has to remember to.
    let _ = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status();
    Ok(())
}

/// Classifies a step that only succeeds if the new user namespace granted this
/// process the capabilities of its root.
///
/// **A permission error here is the host, not this code.** A kernel that
/// restricts unprivileged user namespaces need not refuse the `unshare` itself:
/// on the `ubuntu-24.04` runner it does not. The namespace is created, the
/// process is left in it holding nothing, and the refusal surfaces at the first
/// privileged step — `setgroups` answered `EACCES` for this agent (job
/// 100262708025) and `uid_map` answered `EPERM` for `util-linux`'s `unshare`
/// on the same runner (job 100262707810). That is [`NetError::Unavailable`] by
/// §3.1: a facility this host cannot provide, which a test skips on.
///
/// Everything else stays [`NetError::Os`], which panics a test rather than
/// skipping it. A `uid_map` this code wrote in the wrong format fails `EINVAL`,
/// and a defect must never be able to buy itself a quiet suite.
fn refused(step: &'static str, e: std::io::Error) -> NetError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        return NetError::Unavailable {
            facility: "network-namespaces",
            detail: format!(
                "{step}: {e}. The unshare itself succeeded, so this host creates the \
                 namespace and then denies it the capabilities that make it usable; \
                 `kernel.apparmor_restrict_unprivileged_userns=0` restores them."
            ),
        };
    }
    NetError::os(step, e)
}

/// Mounts a private `tmpfs` over `/run` and creates `/run/netns`.
fn make_run_writable() -> Result<()> {
    let root = CString::new("/").expect("no interior nul");
    let run = CString::new("/run").expect("no interior nul");
    let tmpfs = CString::new("tmpfs").expect("no interior nul");

    // SAFETY: both calls pass null-terminated strings that outlive the call and
    // null for the two arguments the flags make unused.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(refused(
            "making the mount namespace private",
            std::io::Error::last_os_error(),
        ));
    }
    // SAFETY: as above.
    let rc = unsafe {
        libc::mount(
            tmpfs.as_ptr(),
            run.as_ptr(),
            tmpfs.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(NetError::Unavailable {
            facility: "network-namespaces",
            detail: format!(
                "mounting a tmpfs over /run failed, so `ip netns` has nowhere to bind: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    fs::create_dir_all("/run/netns").map_err(|e| NetError::os("creating /run/netns", e))?;
    Ok(())
}

/// One spawned child and the log it is writing to.
struct Spawned {
    child: Child,
    /// Retained so a `Wait` after an exit still answers from the recorded status
    /// rather than from a second `wait` that would fail with `ECHILD`.
    exited: Option<Exited>,
}

/// How a spawned process ended.
///
/// Three states, kept apart on purpose: still running, exited with a code, and
/// **killed by a signal**. The third is the normal outcome of every chaos
/// scenario in this laboratory, and folding it into "no exit code" would make a
/// relay this suite deliberately `SIGKILL`ed indistinguishable from one that is
/// still alive.
#[derive(Debug, Clone, Copy)]
enum Exited {
    /// The process exited with this status.
    Code(i32),
    /// The process was terminated by a signal.
    Signalled,
}

impl Exited {
    const fn code(self) -> Option<i32> {
        match self {
            Exited::Code(c) => Some(c),
            Exited::Signalled => None,
        }
    }
}

/// Serves [`Request`]s from `input`, writing one [`Response`] line each to
/// `output`, until `Shutdown` or end of input.
///
/// # Errors
///
/// Only for an I/O failure on the control pipe itself. A failed *command* is a
/// [`Response::Error`], not an error from this function: a scenario that kills a
/// relay expects the next command against it to fail, and a control channel that
/// died at the first such failure could not express a chaos test.
pub fn serve<R: BufRead, W: Write>(input: R, mut output: W) -> Result<()> {
    let mut table: HashMap<u64, Spawned> = HashMap::new();
    let mut next_id: u64 = 1;

    for line in input.lines() {
        let line = line.map_err(|e| NetError::os("reading the agent control pipe", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(Request::Shutdown) => {
                for (_, mut s) in table.drain() {
                    let _ = s.child.kill();
                    let _ = s.child.wait();
                }
                write_line(&mut output, &Response::Bye)?;
                return Ok(());
            }
            Ok(req) => dispatch(req, &mut table, &mut next_id),
            Err(e) => Response::Error {
                message: format!("undecodable request: {e}"),
                unavailable: false,
            },
        };
        write_line(&mut output, &response)?;
    }
    for (_, mut s) in table.drain() {
        let _ = s.child.kill();
        let _ = s.child.wait();
    }
    Ok(())
}

/// Writes one response line to the control pipe.
///
/// Public because the binary uses it for the one response the serving loop
/// cannot produce: the failure of [`enter`] itself, which happens before there
/// is a loop to be in.
///
/// # Errors
///
/// [`NetError::Os`] if the pipe cannot be written or flushed.
pub fn write_line<W: Write>(output: &mut W, response: &Response) -> Result<()> {
    let encoded = serde_json::to_string(response).expect("Response is always encodable");
    writeln!(output, "{encoded}").map_err(|e| NetError::os("writing an agent response", e))?;
    output
        .flush()
        .map_err(|e| NetError::os("flushing an agent response", e))
}

fn dispatch(req: Request, table: &mut HashMap<u64, Spawned>, next_id: &mut u64) -> Response {
    match req {
        Request::Shutdown => Response::Bye,
        Request::Probe => Response::Probe {
            facts: probe::probe_all(),
        },
        Request::Run { argv, netns, stdin } => run(&argv, netns.as_deref(), stdin.as_deref()),
        Request::Spawn { argv, netns, log } => {
            spawn(&argv, netns.as_deref(), log.as_deref(), table, next_id)
        }
        Request::Signal { id, sig } => signal(id, sig, table),
        Request::Wait { id, timeout_ms } => wait(id, timeout_ms, table),
    }
}

/// Prefixes `argv` with `ip netns exec <ns>` when a namespace is named.
#[must_use]
pub fn in_netns(argv: &[String], netns: Option<&str>) -> Vec<String> {
    match netns {
        None => argv.to_vec(),
        Some(ns) => {
            let mut out = vec![
                "ip".to_owned(),
                "netns".to_owned(),
                "exec".to_owned(),
                ns.to_owned(),
            ];
            out.extend_from_slice(argv);
            out
        }
    }
}

fn run(argv: &[String], netns: Option<&str>, stdin: Option<&str>) -> Response {
    let full = in_netns(argv, netns);
    let Some((program, rest)) = full.split_first() else {
        return Response::Error {
            message: "an empty argv".to_owned(),
            unavailable: false,
        };
    };
    let mut cmd = Command::new(program);
    cmd.args(rest)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Response::Error {
                message: format!("`{program}` is not installed on this host"),
                unavailable: true,
            }
        }
        Err(e) => {
            return Response::Error {
                message: format!("spawning `{program}`: {e}"),
                unavailable: false,
            }
        }
    };
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = pipe.write_all(bytes.as_bytes());
    }
    match child.wait_with_output() {
        Ok(out) => Response::Ran {
            status: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Err(e) => Response::Error {
            message: format!("waiting for `{program}`: {e}"),
            unavailable: false,
        },
    }
}

fn spawn(
    argv: &[String],
    netns: Option<&str>,
    log: Option<&str>,
    table: &mut HashMap<u64, Spawned>,
    next_id: &mut u64,
) -> Response {
    let full = in_netns(argv, netns);
    let Some((program, rest)) = full.split_first() else {
        return Response::Error {
            message: "an empty argv".to_owned(),
            unavailable: false,
        };
    };
    let (out, err) = match log {
        None => (Stdio::null(), Stdio::null()),
        Some(path) => {
            let open = |p: &str| {
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map(Stdio::from)
            };
            match (open(path), open(path)) {
                (Ok(a), Ok(b)) => (a, b),
                _ => (Stdio::null(), Stdio::null()),
            }
        }
    };
    let child = Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn();
    match child {
        Ok(child) => {
            let pid = child.id() as i32;
            let id = *next_id;
            *next_id += 1;
            table.insert(
                id,
                Spawned {
                    child,
                    exited: None,
                },
            );
            Response::Spawned { id, pid }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::Error {
            message: format!("`{program}` is not installed on this host"),
            unavailable: true,
        },
        Err(e) => Response::Error {
            message: format!("spawning `{program}`: {e}"),
            unavailable: false,
        },
    }
}

fn signal(id: u64, sig: i32, table: &mut HashMap<u64, Spawned>) -> Response {
    let Some(entry) = table.get_mut(&id) else {
        return Response::Error {
            message: format!("no spawned process {id}"),
            unavailable: false,
        };
    };
    if entry.exited.is_some() {
        return Response::Signalled { delivered: false };
    }
    let pid = entry.child.id() as libc::pid_t;
    // SAFETY: `kill` takes two integers. The pid is one this process spawned and
    // has not reaped, so it cannot have been recycled.
    let rc = unsafe { libc::kill(pid, sig) };
    Response::Signalled { delivered: rc == 0 }
}

fn wait(id: u64, timeout_ms: u64, table: &mut HashMap<u64, Spawned>) -> Response {
    let Some(entry) = table.get_mut(&id) else {
        return Response::Error {
            message: format!("no spawned process {id}"),
            unavailable: false,
        };
    };
    if let Some(status) = entry.exited {
        return Response::Waited {
            status: status.code(),
            exited: true,
        };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        match entry.child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code();
                entry.exited = Some(code.map_or(Exited::Signalled, Exited::Code));
                return Response::Waited {
                    status: code,
                    exited: true,
                };
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    return Response::Waited {
                        status: None,
                        exited: false,
                    };
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => {
                return Response::Error {
                    message: format!("waiting for {id}: {e}"),
                    unavailable: false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::refused;

    #[test]
    fn a_denied_privileged_step_is_the_host_and_skips() {
        let e = refused("writing uid_map", Error::from(ErrorKind::PermissionDenied));
        assert!(
            e.is_unavailable(),
            "a host that denies the uid_map write forbids unprivileged user \
             namespaces, and a test must skip on that rather than panic: {e}"
        );
        assert!(
            e.to_string().contains("writing uid_map"),
            "the skip has to name the step that was refused: {e}"
        );
    }

    #[test]
    fn any_other_failure_stays_a_defect() {
        for kind in [ErrorKind::InvalidInput, ErrorKind::NotFound] {
            let e = refused("writing uid_map", Error::from(kind));
            assert!(
                !e.is_unavailable(),
                "{kind:?} is not a host refusal; calling it one would let a defect \
                 buy itself a quiet suite"
            );
        }
    }
}
