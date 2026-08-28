//! Binding the MI endpoint, MI-A3's way.
//!
//! **Authority:** ADR-0017 MI-A3 ("the endpoint MUST be created such that no
//! lower-privileged process can win a race for its path"; bind-then-rename;
//! `unlink()`-then-`bind()` **prohibited**; socket activation MUST NOT be used),
//! §11.2 (the mode and the owning group); ADR-0016 PS-12a.
//!
//! # The race MI-A3 closes, and how
//!
//! `unlink()` then `bind()` leaves a window in which the path does not exist. A
//! process that can write the directory creates its own socket there, and every
//! client that connects afterwards is talking to it. So the sequence here is:
//!
//! 1. **verify the directory** — it must exist, be a real directory (not a
//!    symlink), be owned by root, and be unwritable by group and other;
//! 2. bind a **temporary, unpredictable** name inside it;
//! 3. set the mode and the owning group on that name;
//! 4. `rename` it over the real path, which is **atomic** and leaves no window.
//!
//! `unlink` appears nowhere in this module, and its absence is the mechanism.
//!
//! # Where macOS is weaker than Linux, stated
//!
//! `systemd` has `RuntimeDirectory=`, which recreates `/run/twinvpn` with the
//! right owner and mode on **every** start. `launchd` has no equivalent. So the
//! directory is the **installer's**, created once, and this module **verifies and
//! refuses** rather than creating it: an agent that created its own endpoint
//! directory could be raced by whatever created it first after a `/var/run` wipe,
//! which is the same race one level up. The installer runs once and the
//! supervisor runs every boot, so this is genuinely weaker, and it is named in
//! `shells/macos/README.md` §7.

use std::path::{Path, PathBuf};

/// Why the endpoint could not be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The directory does not exist. **The installer's job, not the agent's.**
    #[error("the endpoint directory does not exist")]
    DirectoryMissing,
    /// The path is not a directory, or is a symlink to one.
    ///
    /// A symlink is the race in another shape: whoever controls the link
    /// controls where the socket lands.
    #[error("the endpoint directory is not a real directory")]
    DirectoryNotADirectory,
    /// Somebody other than root owns it.
    #[error("the endpoint directory is not owned by root")]
    DirectoryNotRootOwned,
    /// Group or other can write it, so a lower-privileged process can win the
    /// race for the path.
    #[error("the endpoint directory is writable by a lower-privileged principal")]
    DirectoryWritable,
    /// The bind itself failed.
    #[error("the endpoint could not be bound")]
    BindFailed,
}

impl EndpointError {
    /// The registered code.
    ///
    /// All five are `MGMT.UNAVAILABLE`, because from a client's side they are one
    /// condition — the channel is not there — and §11.12 gives that exit code 3.
    /// The *distinction* lives in the log line and in the diagnostic bundle,
    /// where an operator can act on it.
    #[must_use]
    pub fn reason_code(self) -> twinvpn_types::ReasonCode {
        twinvpn_mgmt::codes::unavailable()
    }
}

/// What a directory must satisfy before anything binds inside it.
///
/// A pure function over the facts, so MI-A3's four conditions are checkable on
/// this Linux host — which matters, because they are the security property and
/// not the plumbing.
///
/// # Errors
///
/// [`EndpointError`], naming which condition failed.
pub fn check_directory_facts(
    exists: bool,
    is_dir: bool,
    is_symlink: bool,
    uid: u32,
    mode: u32,
) -> Result<(), EndpointError> {
    if !exists {
        return Err(EndpointError::DirectoryMissing);
    }
    if !is_dir || is_symlink {
        return Err(EndpointError::DirectoryNotADirectory);
    }
    if uid != 0 {
        return Err(EndpointError::DirectoryNotRootOwned);
    }
    // Group-write **or** other-write is enough to lose the race: either lets a
    // process that is not the authority create a path inside the directory.
    if mode & 0o022 != 0 {
        return Err(EndpointError::DirectoryWritable);
    }
    Ok(())
}

/// Verifies the directory on disk.
///
/// # Errors
///
/// [`EndpointError`]. **Never creates it**: see the module documentation.
pub fn verify_directory(path: &Path) -> Result<(), EndpointError> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    // `symlink_metadata`, not `metadata`: the question is what the PATH is, and
    // `metadata` follows the link and would answer about the target.
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Err(EndpointError::DirectoryMissing);
    };
    check_directory_facts(
        true,
        meta.is_dir(),
        meta.file_type().is_symlink(),
        meta.uid(),
        meta.permissions().mode(),
    )
}

/// The temporary name a bind lands on before the rename.
///
/// Includes the pid so two agents racing each other cannot collide on the
/// temporary either — which would turn MI-A3's race into a different one.
#[must_use]
pub fn staging_path(final_path: &Path, pid: u32) -> PathBuf {
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{pid}.staging"));
    final_path.with_file_name(name)
}

/// Binds the endpoint.
///
/// Returns the **`std`** listener, not the `tokio` one, and that split is not
/// cosmetic: `tokio::net::UnixListener::from_std` registers with the reactor and
/// therefore requires a runtime context, while the bind, the mode, the group and
/// MI-A3's rename need none. Binding first and attaching later means the
/// endpoint exists at its final path with its final mode **before** any task is
/// spawned, and it means this function is callable from the start sequence
/// rather than only from inside the runtime. [`into_tokio`] is the second half.
///
/// (Wave 2 called `from_std` here, outside any runtime. On a Mac that would have
/// been a panic on the first start — the same shape of defect as W-43, found by
/// moving the code rather than by running it.)
///
/// # Errors
///
/// [`EndpointError`].
pub fn bind(path: &Path, group: u32) -> Result<std::os::unix::net::UnixListener, EndpointError> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = path.parent().ok_or(EndpointError::DirectoryMissing)?;
    verify_directory(directory)?;

    let staging = staging_path(path, std::process::id());
    // The staging name is ours and nobody else's; removing a leftover from a
    // previous crash is not the prohibited `unlink()` — that prohibition is about
    // the FINAL path, which nothing here ever unlinks.
    let _ = std::fs::remove_file(&staging);

    let listener =
        std::os::unix::net::UnixListener::bind(&staging).map_err(|_| EndpointError::BindFailed)?;
    // Mode and group BEFORE the rename, so the socket is never briefly visible at
    // its real path with a wider mode than §11.2's.
    std::fs::set_permissions(
        &staging,
        std::fs::Permissions::from_mode(twinvpn_mi::SOCKET_MODE),
    )
    .map_err(|_| EndpointError::BindFailed)?;
    chown_group(&staging, group)?;
    std::fs::rename(&staging, path).map_err(|_| EndpointError::BindFailed)?;

    listener
        .set_nonblocking(true)
        .map_err(|_| EndpointError::BindFailed)?;
    Ok(listener)
}

/// Attaches a bound endpoint to the running runtime's reactor.
///
/// **Must be called from inside the runtime**; see [`bind`].
///
/// # Errors
///
/// [`EndpointError::BindFailed`].
pub fn into_tokio(
    listener: std::os::unix::net::UnixListener,
) -> Result<tokio::net::UnixListener, EndpointError> {
    tokio::net::UnixListener::from_std(listener).map_err(|_| EndpointError::BindFailed)
}

/// `chown(path, -1, group)`, through `std` rather than through `libc`.
///
/// `std::os::unix::fs::chown` takes `Option`s, so "leave the owner alone" is
/// `None` rather than a `-1` cast — and this crate carries
/// `#![forbid(unsafe_code)]`, which the `libc` call would have broken for one
/// line that `std` already has.
fn chown_group(path: &Path, group: u32) -> Result<(), EndpointError> {
    std::os::unix::fs::chown(path, None, Some(group)).map_err(|_| EndpointError::BindFailed)
}

/// The non-comment, non-test source of a module, for the two structural tests
/// below.
///
/// Comments are stripped because both tests name the thing they forbid in their
/// own prose, and the test module is stripped because it names it in an
/// assertion — a source scan that matched its own description would be a test
/// that can only fail.
#[cfg(test)]
fn executable_source(source: &str) -> String {
    source
        .lines()
        .take_while(|line| !line.trim_start().starts_with("mod tests"))
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("#[cfg(test)]")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_mi_a3_condition_is_a_separate_named_refusal() {
        assert_eq!(
            check_directory_facts(false, true, false, 0, 0o755),
            Err(EndpointError::DirectoryMissing)
        );
        assert_eq!(
            check_directory_facts(true, false, false, 0, 0o755),
            Err(EndpointError::DirectoryNotADirectory)
        );
        assert_eq!(
            check_directory_facts(true, true, true, 0, 0o755),
            Err(EndpointError::DirectoryNotADirectory),
            "a symlink is the race in another shape"
        );
        assert_eq!(
            check_directory_facts(true, true, false, 501, 0o755),
            Err(EndpointError::DirectoryNotRootOwned)
        );
        assert_eq!(check_directory_facts(true, true, false, 0, 0o755), Ok(()));
    }

    #[test]
    fn group_write_and_other_write_both_lose_the_race() {
        // Either lets a process that is not the authority create a path inside
        // the directory, which is the whole of what MI-A3 forbids.
        for mode in [0o775, 0o757, 0o777, 0o737, 0o772] {
            assert_eq!(
                check_directory_facts(true, true, false, 0, mode),
                Err(EndpointError::DirectoryWritable),
                "mode {mode:o} was accepted"
            );
        }
        for mode in [0o755, 0o750, 0o700, 0o711] {
            assert_eq!(
                check_directory_facts(true, true, false, 0, mode),
                Ok(()),
                "mode {mode:o} was refused"
            );
        }
    }

    #[test]
    fn a_missing_directory_is_a_refusal_and_never_a_creation() {
        // `launchd` has no `RuntimeDirectory=`, so the directory is the
        // installer's. An agent that created its own could be raced by whatever
        // created it first after a `/var/run` wipe.
        let missing = std::env::temp_dir().join("twinvpn-no-such-directory-ever");
        let _ = std::fs::remove_dir_all(&missing);
        assert_eq!(
            verify_directory(&missing),
            Err(EndpointError::DirectoryMissing)
        );
        assert!(!missing.exists(), "verification must not have created it");
    }

    #[test]
    fn the_staging_name_is_inside_the_verified_directory_and_carries_the_pid() {
        // Inside, because a staging path elsewhere could not be renamed atomically
        // onto the final one — `rename(2)` is atomic only within a filesystem, and
        // "the same directory" is the only way to be sure.
        let final_path = Path::new("/var/run/twinvpn/mgmt.sock");
        let staging = staging_path(final_path, 4242);
        assert_eq!(staging.parent(), final_path.parent());
        assert!(staging.to_string_lossy().contains("4242"));
        assert_ne!(staging, final_path);
    }

    #[test]
    fn two_agents_cannot_collide_on_the_staging_name() {
        let final_path = Path::new("/var/run/twinvpn/mgmt.sock");
        assert_ne!(staging_path(final_path, 1), staging_path(final_path, 2));
    }

    #[test]
    fn every_endpoint_failure_reaches_the_client_as_the_channel_being_unavailable() {
        // From a client's side the five conditions are one fact — the channel is
        // not there — and §11.12 gives that exit code 3. The distinction is in the
        // agent's log, where an operator can act on it.
        for error in [
            EndpointError::DirectoryMissing,
            EndpointError::DirectoryNotADirectory,
            EndpointError::DirectoryNotRootOwned,
            EndpointError::DirectoryWritable,
            EndpointError::BindFailed,
        ] {
            assert_eq!(error.reason_code().as_str(), "MGMT.UNAVAILABLE");
        }
    }

    #[test]
    fn the_word_unlink_appears_nowhere_in_this_module() {
        // MI-A3 prohibits `unlink()`-then-`bind()` on the endpoint path, and the
        // mechanism for that prohibition is that the call is not written. Asserted
        // over the source so a future edit that adds one fails here rather than in
        // review.
        let code = executable_source(include_str!("endpoint.rs"));
        assert!(
            !code.contains("unlink"),
            "an unlink on the endpoint path reopens the race MI-A3 closes"
        );
        // The one removal in this module is on the STAGING name, which is ours;
        // the final path is only ever reached by `rename`.
        assert!(code.contains("remove_file(&staging)"));
        assert!(code.contains("rename(&staging, path)"));
    }
}
