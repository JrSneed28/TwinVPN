//! `flock(2)`: the crash-surviving exclusion ADR-0016 **PS-1** needs.
//!
//! **Authority:** ADR-0016 PS-1; ADR-0018 CB-1 and DP-4.
//!
//! > Exactly one process per host is the network and policy authority… A second
//! > process claiming any of them is `INTERNAL.INVARIANT_VIOLATED`.
//!
//! # Why this is in the adapter and not in the shell
//!
//! CB-1 puts code in the adapter when it "must call a platform API with no
//! stable C-callable form", and `flock(2)` is one: `std::fs::File::lock_shared`
//! and friends are not stable on the pinned 1.90 toolchain, and both Linux
//! binaries carry `#![forbid(unsafe_code)]`. So the syscall lives here — this
//! crate is the DP-4 `unsafe` allowlist member — and the shell binds a safe
//! type.
//!
//! **What is here is the mechanism, not the policy.** Where the lock file lives,
//! which `reason_code` a contended lock reports, and where in ADR-0016 §11.6's
//! start ordering it is taken are all the shell's; `shells/linux/twinvpnd/src/agent/authority.rs`
//! holds them.
//!
//! # Why `flock` and not a pid file
//!
//! 1. **The kernel releases it when the holder dies**, by any route, including
//!    `SIGKILL`, an OOM kill and a power loss. A pid file survives its writer and
//!    then has to be disambiguated from a live one by reading `/proc`, which
//!    races with pid reuse.
//! 2. **It is atomic.** There is no test-then-take window for a second process to
//!    start in.
//! 3. **It needs no cleanup path.** Nothing has to run on the way out for the
//!    next start to succeed — which matters, because the way out is sometimes a
//!    crash, and ADR-0012 KS-20 already tells us to design for that exit.
//!
//! The lock is **advisory**, which is the correct kind here: it coordinates
//! cooperating instances of one program, and a mandatory lock would not stop an
//! uncooperative process from writing nftables anyway.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd as _;

/// Takes an exclusive, non-blocking `flock` on `file`.
///
/// `Ok(true)` — taken. `Ok(false)` — somebody else holds it. `Err` — anything
/// else, and it is deliberately not collapsed into `Ok(false)`: reporting PS-1's
/// violation for a permission problem would send an operator hunting a process
/// that does not exist, and reporting a held lock as a transient error would let
/// the second authority start.
///
/// The lock is released when `file` is closed, which includes every abnormal
/// exit. It is **not** released by this crate.
///
/// # Errors
///
/// The `errno`, as an [`io::Error`], for every failure other than
/// `EWOULDBLOCK`.
pub fn take_exclusive(file: &File) -> Result<bool, io::Error> {
    flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
}

/// Releases an `flock` held on `file`, without closing it.
///
/// Present for the test that asserts a released lock is retakeable in one
/// process; production never calls it, because dropping the `File` is the
/// release and there is no path that wants the descriptor to outlive the lock.
///
/// # Errors
///
/// The `errno`.
pub fn release(file: &File) -> Result<(), io::Error> {
    flock(file.as_raw_fd(), libc::LOCK_UN).map(|_| ())
}

/// The one `flock(2)` call site.
fn flock(fd: std::os::unix::io::RawFd, operation: libc::c_int) -> Result<bool, io::Error> {
    // SAFETY: `flock` takes two `c_int`s by value, dereferences nothing, and
    // cannot violate memory safety for any argument value. `fd` is borrowed from
    // a live `File` for the duration of the call, so it is open and is not
    // reused. The return code is checked before anything is concluded from it.
    let rc = unsafe { libc::flock(fd, operation) };
    if rc == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        // The "held" answer, and the ONLY errno that is not a failure. On Linux
        // `EWOULDBLOCK` and `EAGAIN` are the same value; both spellings are
        // matched so a libc that ever separates them still reads correctly.
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(false),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str) -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "twinvpn-flock-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let file = File::create(&path).expect("creates");
        (path, file)
    }
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn the_first_holder_takes_it() {
        let (path, file) = temp_file("first");
        assert!(take_exclusive(&file).expect("no errno"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_second_open_of_the_same_inode_is_refused_and_is_not_an_error() {
        // `flock` is per open-file-description, so a second `open` of one path in
        // one process contends exactly as a second process does. That is what
        // makes PS-1's exclusion testable without spawning one — and it is why
        // `EWOULDBLOCK` must be `Ok(false)` rather than an `Err`.
        let (path, first) = temp_file("second");
        assert!(take_exclusive(&first).expect("no errno"));
        let second = File::open(&path).expect("opens");
        assert!(
            !take_exclusive(&second).expect("EWOULDBLOCK is not an error"),
            "a held lock must refuse, not fail"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn releasing_lets_the_next_holder_take_it() {
        // The restart case, and the crash case: the kernel does this for us when
        // the descriptor closes, by any route including SIGKILL.
        let (path, first) = temp_file("release");
        assert!(take_exclusive(&first).expect("no errno"));
        release(&first).expect("releases");
        let second = File::open(&path).expect("opens");
        assert!(
            take_exclusive(&second).expect("no errno"),
            "no cleanup step stands between a crash and the successor's start"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn closing_the_file_releases_the_lock() {
        let (path, first) = temp_file("close");
        assert!(take_exclusive(&first).expect("no errno"));
        drop(first);
        let second = File::open(&path).expect("opens");
        assert!(take_exclusive(&second).expect("no errno"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_closed_descriptor_is_an_errno_and_never_a_silent_false() {
        // EBADF must not read as "somebody else holds it": that would report
        // PS-1's violation for a programming error, and an operator would go
        // looking for a second agent that does not exist.
        let (path, file) = temp_file("ebadf");
        let fd = file.as_raw_fd();
        drop(file);
        let error = flock(fd, libc::LOCK_EX | libc::LOCK_NB).expect_err("EBADF");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        let _ = std::fs::remove_file(&path);
    }
}
