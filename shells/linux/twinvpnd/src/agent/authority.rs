//! **PS-1's lock**: exactly one process per host is the authority.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! PS-1, §11.6; ADR-0012 KS-20.
//!
//! > Exactly one process per host is the network and policy authority… A second
//! > process claiming any of them is `INTERNAL.INVARIANT_VIOLATED`.
//!
//! # What wave 1 had, and why it was not enough
//!
//! The endpoint's bind-and-rename was the only mutual exclusion. It is atomic on
//! the *name*, which means a second agent that reached step 6 **won**: it took
//! `/run/twinvpn/mgmt.sock` from the first, and the first kept its listening
//! socket, kept `CAP_NET_ADMIN`, and went on believing it was the authority. A
//! client then reached whichever process happened to own the fd, and two
//! processes were programming one host's `table inet twinvpn` and one host's
//! routing table 52. That is exactly the state PS-1 exists to make impossible,
//! and a filesystem name is the wrong object to hold it in: names are
//! transferable and authority is not.
//!
//! # The mechanism is `flock(2)`; the policy is here
//!
//! [`twinvpn_platform_linux::lock`] holds the syscall (CB-1, DP-4) and states why
//! `flock` rather than a pid file. This module holds the three things that are
//! the shell's: **where** the lock lives, **which** registered code a contended
//! lock reports, and **where in the start ordering** it is taken.
//!
//! The pid is written into the file, but as **evidence for an operator**, never
//! as the lock. "Who holds it" is useful in a journal line and is not what makes
//! the exclusion correct — [`a_stale_lock_file_from_a_dead_predecessor_does_not_block_a_start`]
//! is the test that keeps the two from being confused.
//!
//! # Where it sits in ADR-0016 §11.6's ordering
//!
//! **Between step 3 (the clocks and the runtime) and step 4b (arming the
//! ruleset)** — that is, before the first privileged mutation of host state.
//! Two agents arming one host's nftables table is the race, so the lock must be
//! held before the arm, not before the endpoint bind. §11.6 names no step for it
//! because §11.6 *assumes* PS-1 rather than establishing it.
//!
//! It is deliberately taken **after** the privilege check, so a misconfigured
//! host that would be refused for running as root is refused for that reason
//! rather than for a lock it could not have taken anyway.
//!
//! [`a_stale_lock_file_from_a_dead_predecessor_does_not_block_a_start`]: self

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

/// The lock file's name inside the runtime directory.
///
/// The **runtime** directory rather than the state directory: `RuntimeDirectory=`
/// is `tmpfs` and is cleared at boot, so the file can never outlive the boot that
/// created it. In `StateDirectory=` it would persist across a reboot — harmless
/// with `flock`, and confusing to anyone reading the directory.
pub const LOCK_FILE: &str = "authority.lock";

/// The lock file's mode. No group and no world access: this is not an interface.
pub const LOCK_MODE: u32 = 0o600;

/// Why the authority lock could not be taken.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another live process holds it. **This is PS-1's violation.**
    #[error("another process (pid {holder}) is already this host's authority")]
    Held {
        /// The pid the incumbent recorded, or `0` where the file carried none.
        ///
        /// Evidence for an operator. The exclusion is the `flock`, not this.
        holder: i32,
    },
    /// The lock file could not be created, or `flock` failed for an unrelated
    /// reason.
    #[error("the authority lock could not be taken")]
    Io(#[from] io::Error),
}

impl LockError {
    /// The registered `reason_code`.
    ///
    /// PS-1 names the first condition itself — "A second process claiming any of
    /// them is `INTERNAL.INVARIANT_VIOLATED`" — and that code **is** registered,
    /// so it is emitted directly rather than substituted. That is unusual for a
    /// `MGMT`-adjacent condition in this shell and is worth noticing: it means
    /// the ADR and the frozen registry agree here.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            LockError::Held { .. } => "INTERNAL.INVARIANT_VIOLATED",
            LockError::Io(_) => "MGMT.UNAVAILABLE",
        }
    }

    /// The spelling ADR-0016 uses for the second case.
    #[must_use]
    pub const fn specified_code(&self) -> &'static str {
        match self {
            LockError::Held { .. } => "INTERNAL.INVARIANT_VIOLATED",
            LockError::Io(_) => "PLATFORM.SERVICE.START_TIMEOUT",
        }
    }
}

/// The held lock. Dropping it releases the lock by closing the descriptor.
///
/// Held for the process's whole life, which is why `main` binds it to a **named**
/// local rather than to `_`: `let _ = take(..)` drops the value immediately and
/// would take the exclusion away in the same statement that acquired it.
#[derive(Debug)]
pub struct AuthorityLock {
    file: fs::File,
    path: PathBuf,
}

impl AuthorityLock {
    /// Where the lock lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This process's pid, as recorded in the file.
    #[must_use]
    pub fn holder(&self) -> i32 {
        // `std::process::id` is a `u32` the kernel guarantees fits a `pid_t`.
        i32::try_from(std::process::id()).unwrap_or(0)
    }
}

impl Drop for AuthorityLock {
    fn drop(&mut self) {
        // The file is deliberately NOT removed. `flock` is per-inode, so
        // unlinking a locked file lets a second agent create a fresh inode and
        // lock *that* one while a third still holds the original — which is how
        // a lock file stops being a lock. It is a zero-length file in a tmpfs;
        // leaving it costs nothing. The lock goes away with the descriptor.
        let _ = &self.file;
    }
}

/// Takes the authority lock, or names who holds it.
///
/// # Errors
///
/// [`LockError::Held`] when another live process is the authority, which `main`
/// makes **fatal**: the alternative is two processes programming one host's
/// `table inet twinvpn` and one host's routing table 52.
pub fn take(dir: &Path) -> Result<AuthorityLock, LockError> {
    let path = dir.join(LOCK_FILE);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // NOT `truncate`: truncating before the lock is taken would destroy the
        // incumbent's recorded pid, so a refused start could not name who holds
        // it. The file is truncated after the lock is ours.
        .truncate(false)
        .open(&path)?;
    // The mode is written at every start, for the same reason ADR-0017 MI-A3
    // clause 4 makes the agent write the endpoint's: an installer-written mode
    // is stale after the first restart.
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(LOCK_MODE));

    if !twinvpn_platform_linux::lock::take_exclusive(&file)? {
        return Err(LockError::Held {
            holder: read_holder(&path),
        });
    }

    // Ours. The pid is written **after** the lock is held, so the file can never
    // name a process that does not hold it.
    let _ = write_holder(&file);
    Ok(AuthorityLock { file, path })
}

/// Reads the incumbent's pid, for the error message only.
fn read_holder(path: &Path) -> i32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(0)
}

/// Records this process's pid inside the locked file.
fn write_holder(file: &fs::File) -> io::Result<()> {
    use std::io::{Seek as _, Write as _};
    let mut file = file;
    file.rewind()?;
    file.set_len(0)?;
    writeln!(file, "{}", std::process::id())?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "twinvpn-authority-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("creates");
        dir
    }
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn the_first_agent_takes_the_lock_and_records_its_pid() {
        let dir = temp_dir("first");
        let lock = take(&dir).expect("the first agent is the authority");
        assert_eq!(lock.path(), dir.join(LOCK_FILE));
        assert_eq!(
            lock.holder(),
            i32::try_from(std::process::id()).expect("a pid fits")
        );
        assert_eq!(read_holder(&dir.join(LOCK_FILE)), lock.holder());
        let mode = fs::metadata(lock.path())
            .expect("exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, LOCK_MODE);
        assert_eq!(mode & 0o077, 0, "the lock is not an interface");
        drop(lock);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_authority_is_refused_and_names_the_incumbent() {
        // **PS-1, as an executed assertion rather than a comment.** `flock` is
        // per open-file-description, so a second `take` in this process contends
        // exactly as a second `twinvpnd` would — which is what makes the rule
        // testable without spawning a privileged process.
        let dir = temp_dir("second");
        let first = take(&dir).expect("the first agent is the authority");
        let error = take(&dir).expect_err("PS-1: exactly one authority per host");
        match error {
            LockError::Held { holder } => {
                assert_eq!(holder, first.holder(), "the incumbent is named");
            }
            LockError::Io(ref e) => panic!("expected Held, got {e:?}"),
        }
        assert_eq!(
            error.reason_code(),
            "INTERNAL.INVARIANT_VIOLATED",
            "PS-1 names this condition itself"
        );
        drop(first);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn releasing_the_lock_lets_the_next_agent_take_it() {
        // The restart case and the crash case are one case: the kernel drops the
        // lock when the descriptor closes, by any route including SIGKILL.
        let dir = temp_dir("restart");
        let first = take(&dir).expect("first");
        drop(first);
        let second = take(&dir).expect("the successor takes it with no cleanup step");
        drop(second);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_lock_file_from_a_dead_predecessor_does_not_block_a_start() {
        // The pid-file failure mode, asserted as NOT happening. A file naming a
        // pid that no longer exists — or worse, one that has been reused by an
        // unrelated process — must not keep the successor out. The lock is the
        // `flock`, never the contents.
        let dir = temp_dir("stale");
        fs::write(dir.join(LOCK_FILE), b"999999\n").expect("writes a stale file");
        let lock = take(&dir).expect("a stale file is not a held lock");
        assert_eq!(read_holder(lock.path()), lock.holder(), "rewritten");
        drop(lock);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unwritable_directory_is_an_io_error_and_not_a_ps1_violation() {
        // Distinguishing the two is the point: reporting "another process is the
        // authority" for a packaging problem would send an operator hunting a
        // process that does not exist.
        let error = take(Path::new("/proc/definitely/not/writable"))
            .expect_err("the lock file cannot be created");
        assert!(matches!(error, LockError::Io(_)));
        assert_eq!(error.reason_code(), "MGMT.UNAVAILABLE");
    }

    #[test]
    fn every_code_this_module_emits_is_registered() {
        for code in ["INTERNAL.INVARIANT_VIOLATED", "MGMT.UNAVAILABLE"] {
            assert!(
                twinvpn_types::ReasonCode::lookup(code).is_some(),
                "{code} is not in the frozen registry"
            );
        }
    }
}
