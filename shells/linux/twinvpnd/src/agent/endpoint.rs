//! Creating the MI endpoint: MI-A3's bind-and-rename, and the checks before it.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-A3, §11.2, §10.1, §10.3; ADR-0022 I-02 (a); ADR-0016 §11.9 (`UMask=0077`,
//! `RuntimeDirectory=twinvpn`).
//!
//! # MI-A3, clause by clause
//!
//! 1. **The directory is the init system's.** "The agent MUST verify the
//!    directory's ownership and mode before binding and MUST refuse to bind into
//!    a directory it does not own." [`verify_directory`].
//! 2. **Bind-and-rename, never unlink-and-bind.** `unlink()`-then-`bind()` opens
//!    a window in which any process that can write the directory can create the
//!    socket first and receive our clients' connections. [`bind`] binds a fresh
//!    temporary name and `rename`s it into place, which is atomic.
//! 3. **The agent writes the permissions at every start.** "An installer-written
//!    endpoint ACL would be stale after the first restart."
//! 4. **Socket activation MUST NOT be used.** There is no `.socket` unit in
//!    `packaging/`, and nothing in this module reads `LISTEN_FDS`. §10.3's three
//!    reasons, the sharpest being that "the activation socket **outlives the
//!    agent**, so a client connects successfully then hangs instead of getting
//!    `MGMT.UNAVAILABLE`".

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

/// Why the endpoint could not be created.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The containing directory is not one this agent owns, or is writable by
    /// somebody who is not privileged.
    ///
    /// MI-A3: "MUST refuse to bind into a directory it does not own".
    #[error("the endpoint directory {path} is not safe to bind into: {reason}")]
    Directory {
        /// Which directory.
        path: PathBuf,
        /// Which check failed.
        reason: &'static str,
    },
    /// The bind, rename, chmod or chown failed.
    #[error("the endpoint could not be created")]
    Io(#[from] std::io::Error),
}

impl EndpointError {
    /// The `reason_code`. ADR-0017 spells this `MGMT.LISTEN_FAILED`, which the
    /// frozen registry does not carry; `MGMT.UNAVAILABLE` is the nearest
    /// registered code and keeps the domain.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        "MGMT.UNAVAILABLE"
    }

    /// The spelling ADR-0017 uses.
    #[must_use]
    pub const fn specified_code(&self) -> &'static str {
        "MGMT.LISTEN_FAILED"
    }
}

/// Checks the containing directory before anything is bound into it.
///
/// Three properties, and each has a way to fail that matters:
///
/// - **It exists and is a directory.** A path that is a symlink to somewhere
///   else is a redirection.
/// - **It is owned by this process's uid or by root.** Anything else means
///   somebody who is not the init system created it.
/// - **It is not group- or world-writable.** A writable directory lets another
///   local user `rename` their own socket over ours between our bind and a
///   client's connect, which is the attack MI-A3's whole clause exists to close.
///
/// # Errors
///
/// [`EndpointError::Directory`], naming which check failed.
pub fn verify_directory(dir: &Path) -> Result<(), EndpointError> {
    let metadata = fs::symlink_metadata(dir).map_err(|_| EndpointError::Directory {
        path: dir.to_path_buf(),
        reason: "it does not exist; the init system creates it (RuntimeDirectory=twinvpn)",
    })?;
    if !metadata.is_dir() {
        return Err(EndpointError::Directory {
            path: dir.to_path_buf(),
            reason: "it is not a directory (a symlink here is a redirection)",
        });
    }
    let owner = metadata.uid();
    let us = rustix_free_uid();
    if owner != 0 && owner != us {
        return Err(EndpointError::Directory {
            path: dir.to_path_buf(),
            reason: "it is owned by neither root nor this agent",
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(EndpointError::Directory {
            path: dir.to_path_buf(),
            reason: "it is group- or world-writable, so another local user could rename a \
                     socket of their own over ours",
        });
    }
    Ok(())
}

/// This process's effective uid, read from `/proc/self/status`.
///
/// `getuid(2)` would need `unsafe`, and this crate carries
/// `#![forbid(unsafe_code)]`. `/proc/self/status` is the same answer from the
/// same kernel, and [`super::privilege::Posture`] already parses it for the
/// privilege check — so this is one more read of a file the agent reads anyway.
fn rustix_free_uid() -> u32 {
    super::privilege::Posture::read().map_or(u32::MAX, |p| p.uid)
}

/// Binds the endpoint by **bind-and-rename**.
///
/// The temporary name is in the same directory, so the `rename` is within one
/// filesystem and is therefore atomic. Its name carries this process's pid so
/// two agents racing (which PS-1 forbids, but which a misconfiguration can
/// still produce) do not collide on the temporary itself.
///
/// # Errors
///
/// [`EndpointError::Directory`] from the pre-check, or the OS error.
pub fn bind(path: &Path, group_gid: Option<u32>) -> Result<UnixListener, EndpointError> {
    let dir = path.parent().ok_or_else(|| EndpointError::Directory {
        path: path.to_path_buf(),
        reason: "the endpoint path has no parent directory",
    })?;
    verify_directory(dir)?;

    let temp = dir.join(format!(".mgmt.sock.{}", std::process::id()));
    // A leftover temporary from a previous crash is ours by name and is removed;
    // the ENDPOINT is never unlinked before a bind, which is the clause that
    // matters.
    let _ = fs::remove_file(&temp);
    let listener = UnixListener::bind(&temp)?;

    // The permissions are written by the AGENT, at every start (MI-A3 clause 4).
    // Applied to the temporary before the rename, so the endpoint is never
    // visible at its real name with the wrong mode.
    fs::set_permissions(&temp, fs::Permissions::from_mode(crate::mi::SOCKET_MODE))?;
    if let Some(gid) = group_gid {
        // `std::os::unix::fs::chown` rather than `libc::chown`: same syscall,
        // no `unsafe`. `None` for the uid leaves the owner alone.
        std::os::unix::fs::chown(&temp, None, Some(gid))?;
    }

    // The atomic step. `unlink()`-then-`bind()` is prohibited.
    fs::rename(&temp, path)?;
    Ok(listener)
}

/// The gid of a named group, from `/etc/group`.
///
/// `None` where the group does not exist, which the caller reports rather than
/// silently binding a socket the `twinvpn` group cannot reach: an endpoint owned
/// by the wrong group is an endpoint every OBSERVE principal is locked out of.
#[must_use]
pub fn group_gid(name: &str) -> Option<u32> {
    let text = fs::read_to_string(super::peer::GROUP_FILE).ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let group = fields.next()?;
        let _passwd = fields.next();
        let gid = fields.next();
        if group == name {
            return gid.and_then(|g| g.parse().ok());
        }
    }
    None
}

/// Removes the endpoint on shutdown.
///
/// §10.3: "The endpoint is created by the running agent, at every start, and
/// **ceases to exist when the agent does**." A client that connects to a stale
/// endpoint gets a successful connect and then a hang, which is strictly worse
/// than `MGMT.UNAVAILABLE`.
pub fn remove(path: &Path) {
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(mode: u32) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "twinvpn-endpoint-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("creates");
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).expect("chmod");
        dir
    }
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn a_world_writable_directory_is_refused() {
        // The attack MI-A3 closes: another local user renames their own socket
        // over ours between our bind and a client's connect.
        let dir = temp_dir(0o777);
        let err = verify_directory(&dir).expect_err("refused");
        match err {
            EndpointError::Directory { reason, .. } => {
                assert!(reason.contains("writable"), "{reason}");
            }
            EndpointError::Io(e) => panic!("expected a directory refusal, got {e:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_names_the_init_system_rather_than_creating_it() {
        // MI-A3: the containing directory is created by the init system, "not by
        // the agent". Creating it here would be the agent granting itself the
        // ownership the rule exists to check.
        let err = verify_directory(Path::new("/nonexistent/twinvpn")).expect_err("refused");
        match err {
            EndpointError::Directory { reason, .. } => {
                assert!(reason.contains("RuntimeDirectory"), "{reason}");
            }
            EndpointError::Io(e) => panic!("expected a directory refusal, got {e:?}"),
        }
    }

    #[test]
    fn a_correctly_owned_private_directory_passes() {
        let dir = temp_dir(0o700);
        verify_directory(&dir).expect("owned by us, not writable by others");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_endpoint_is_bound_and_renamed_never_unlinked_and_rebound() {
        let dir = temp_dir(0o700);
        let path = dir.join("mgmt.sock");

        // A pre-existing endpoint — the crash case. Bind-and-rename REPLACES it
        // atomically; there is no instant at which the name is absent.
        fs::write(&path, b"stale").expect("writes");
        let listener = bind(&path, None).expect("binds");
        assert!(path.exists());

        let mode = fs::metadata(&path).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode, crate::mi::SOCKET_MODE, "the agent writes the mode");
        assert_eq!(mode & 0o007, 0, "no world bit");

        // And no temporary is left behind.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("reads")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".mgmt.sock"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the temporary was renamed, not copied"
        );

        drop(listener);
        remove(&path);
        assert!(
            !path.exists(),
            "§10.3: it ceases to exist when the agent does"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_bound_endpoint_accepts_a_local_connection() {
        let dir = temp_dir(0o700);
        let path = dir.join("mgmt.sock");
        let listener = bind(&path, None).expect("binds");
        let client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connects");
        let (server, _) = listener.accept().await.expect("accepts");
        // And SO_PEERCRED answers on the accepted side, which is what every
        // authorization decision in `peer` rests on.
        let principal = super::super::peer::Principal::from_stream(&server)
            .expect("the kernel attests the caller");
        assert_eq!(principal.uid, rustix_free_uid());
        drop(client);
        remove(&path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_group_that_does_not_exist_is_reported_rather_than_guessed() {
        assert_eq!(group_gid("a-group-that-does-not-exist"), None);
        // `root` exists on every Linux host and is gid 0.
        assert_eq!(group_gid("root"), Some(0));
    }
}
