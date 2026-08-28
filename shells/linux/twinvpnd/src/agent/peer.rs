//! Peer-credential authorization: `SO_PEERCRED` → OS principal → scope set.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.14 (a) (the transport must expose the caller's credentials without the
//! client asserting them), PS-12a (the Linux principals), PS-13 (attribution),
//! PS-14 (the attended/headless reading);
//! [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-A1, MI-A2, MI-A5, §11.5; ADR-0023 EM-39.
//!
//! # MI-A1, made structural
//!
//! > The calling principal MUST be obtained from the kernel on the connected
//! > channel. **No field carrying a client-asserted identity exists in the
//! > schema**, in any message, at any version.
//!
//! Look at [`crate::mi::wire::Hello`]: there is no `principal`, no `uid`, no
//! `user`. The only identity in this module comes from `SO_PEERCRED`, and there
//! is no function here that takes one from anywhere else.
//!
//! # MI-A5: fail closed on an unverifiable identity
//!
//! > If peer credentials cannot be obtained for any reason, the agent MUST
//! > reject the attach with `MGMT.PRINCIPAL_UNVERIFIABLE` and close. It MUST NOT
//! > fall back to a default principal, a 'local user' assumption, or an
//! > anonymous read-only tier.
//!
//! [`Principal::from_stream`] returns `Err`, and the server closes. There is no
//! `unwrap_or_default` on this path and no anonymous tier to fall back to.
//!
//! # MI-A2: `/proc` lookups are advisory and gate nothing
//!
//! The pid is read and **used only for the log line**. "Pids are reused;
//! processes can be replaced between the credential read and the lookup", so
//! nothing in [`Principal::scopes`] consults it.
//!
//! # A reported gap: the principal is a uid, not yet a group membership
//!
//! PS-12a names the Linux principals as the local groups `twinvpn` (OBSERVE) and
//! `twinvpn-operators` (OPERATE), with ADMINISTER behind polkit
//! `net.twinvpn.administer`. Resolving a uid to its **supplementary groups**
//! needs `getgrouplist(3)` or an NSS walk — both of which are `libc` calls, and
//! this crate carries `#![forbid(unsafe_code)]`.
//!
//! So this build resolves membership by reading `/etc/group`, which is correct
//! for a local-files NSS configuration and **incomplete** for LDAP, SSSD or
//! `nss-systemd` dynamic users. That incompleteness fails **closed** — an
//! unresolvable membership grants nothing — and is reported by
//! [`GroupSource::is_authoritative`] rather than hidden, so the shell can log
//! `PLATFORM.PRIV.SANDBOX_DEGRADED`'s condition (PS-17: "Silently running wider
//! than declared is the defect this rule retires"; here it runs *narrower*, and
//! says so).

use std::os::fd::AsRawFd;
use std::path::Path;

use tokio::net::UnixStream;
use twinvpn_mgmt::Scope;

use crate::mi::scope::Scopes;

/// PS-12a's `OBSERVE` group.
pub const OBSERVE_GROUP: &str = "twinvpn";

/// PS-12a's `OPERATE` group.
pub const OPERATE_GROUP: &str = "twinvpn-operators";

/// Where group membership is read from.
pub const GROUP_FILE: &str = "/etc/group";

/// The calling process's kernel-attested identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The caller's uid.
    pub uid: u32,
    /// The caller's primary gid.
    pub gid: u32,
    /// The caller's pid. **Advisory only** (MI-A2): logged, never gating.
    pub pid: i32,
    /// The account name, where it resolves. Used for `actor_principal`
    /// (MI-18/PS-13) — "a principal name is loggable, an authentication secret
    /// never is" (PS-23).
    pub name: Option<String>,
}

/// Why an attach could not be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerError {
    /// `SO_PEERCRED` did not answer. **MI-A5**: reject and close.
    #[error("the calling principal could not be verified")]
    Unverifiable,
}

impl PeerError {
    /// The registered `reason_code`. One of ADR-0017's four that IS registered.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        "MGMT.PRINCIPAL_UNVERIFIABLE"
    }
}

impl Principal {
    /// Reads the peer's credentials from the connected socket.
    ///
    /// **The credentials come from the kernel on this channel**, which is
    /// §11.14 (a)'s requirement, and are read in **this process's own
    /// namespace** — ADR-0017 §11.2's container note: "the agent MUST resolve
    /// the principal in **its own** namespace", because a uid is translated by
    /// the userns mapping.
    ///
    /// # Errors
    ///
    /// [`PeerError::Unverifiable`], which the caller turns into a `Reject` and a
    /// close. There is no fallback principal.
    pub fn from_stream(stream: &UnixStream) -> Result<Self, PeerError> {
        // `tokio`'s own `peer_cred` wraps `SO_PEERCRED`, which is what keeps
        // this crate free of `unsafe` while still reading the kernel's answer
        // rather than the client's claim.
        let cred = stream.peer_cred().map_err(|_| PeerError::Unverifiable)?;
        let uid = cred.uid();
        let pid = cred.pid().unwrap_or(0);
        Ok(Self {
            uid,
            gid: cred.gid(),
            pid,
            name: account_name(uid),
        })
    }

    /// The scopes this principal holds, per ADR-0016 PS-12a's class table.
    ///
    /// # This is not a TwinVPN decision
    ///
    /// CB-2 forbids a shell branch on a *domain* fact. Group membership is an
    /// **OS** fact, PS-12a assigns its resolution to the daemon in terms, and
    /// *which* scope an operation needs comes from the core's own catalogue.
    /// The shell reads an OS fact and hands it to the core's table; it decides
    /// nothing about TwinVPN.
    ///
    /// `mgmt.admin` is **granted at attach only to root**, and holding it is
    /// still not sufficient: §11.5's third consequence is that every
    /// ADMINISTER operation needs the §11.14 ceremony "freshly, per call".
    #[must_use]
    pub fn scopes(&self, groups: &GroupSource) -> Scopes {
        let mut held = Vec::new();

        // ADR-0023 EM-39(2): on the headless tier "that is `root` over the local
        // AF_UNIX transport, because §11.10 gives that tier no second identity".
        let is_root = self.uid == 0;

        if is_root || groups.member_of(OBSERVE_GROUP, self.uid) {
            held.push(Scope::Status);
            held.push(Scope::Events);
            held.push(Scope::Diagnostics);
        }
        if is_root || groups.member_of(OPERATE_GROUP, self.uid) {
            held.push(Scope::Connect);
            held.push(Scope::Settings);
        }
        if is_root {
            held.push(Scope::Admin);
        }
        // `mgmt.disarm` is never here: §11.5 says it is "never granted at
        // attach", and `crate::mi::scope::GRANTABLE` does not contain it either.
        Scopes::from_scopes(held)
    }

    /// The value that travels as `actor_principal` (MI-18, PS-13).
    ///
    /// > "the tunnel went down" and "Dana took the tunnel down" are different
    /// > facts.
    ///
    /// The account **name** where it resolves, and `uid:N` where it does not —
    /// never absent, because "an unattributed state change on a multi-user host
    /// is the 'silent failure' `reliability.md` §10 forbids, wearing local
    /// clothes".
    #[must_use]
    pub fn actor(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("uid:{}", self.uid))
    }
}

/// Group membership, read from the local files database.
///
/// See the module documentation: this is correct for `files` NSS and incomplete
/// for a directory service, and it says so rather than pretending otherwise.
#[derive(Debug, Clone, Default)]
pub struct GroupSource {
    /// `(group name, member account names, gid)`.
    entries: Vec<(String, Vec<String>, u32)>,
    authoritative: bool,
}

impl GroupSource {
    /// Reads `/etc/group`.
    #[must_use]
    pub fn load() -> Self {
        Self::from_path(Path::new(GROUP_FILE))
    }

    /// Reads a group database from a path. Separated so the parser is testable
    /// without `/etc`.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            // Unreadable is not "everyone is a member": it grants nothing.
            return Self {
                entries: Vec::new(),
                authoritative: false,
            };
        };
        Self {
            entries: parse_group_file(&text),
            // `nsswitch.conf` naming anything but `files` for `group` means this
            // view is partial. Detected rather than assumed, and reported.
            authoritative: nss_group_is_files_only(),
        }
    }

    /// Whether this view of group membership is complete for this host.
    ///
    /// `false` means an LDAP/SSSD/`nss-systemd` membership will not be seen and
    /// the principal will hold **fewer** scopes than the administrator intended.
    /// The shell logs it at start; nothing silently widens.
    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    /// Whether `uid` is a member of `group`.
    #[must_use]
    pub fn member_of(&self, group: &str, uid: u32) -> bool {
        let Some(name) = account_name(uid) else {
            return false;
        };
        self.entries
            .iter()
            .any(|(g, members, _)| g == group && members.contains(&name))
    }
}

/// Parses `/etc/group`: `name:passwd:gid:member,member`.
fn parse_group_file(text: &str) -> Vec<(String, Vec<String>, u32)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(name), Some(_passwd), Some(gid)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(gid) = gid.parse::<u32>() else {
            continue;
        };
        let members = fields
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect();
        out.push((name.to_owned(), members, gid));
    }
    out
}

/// Whether `nsswitch.conf` resolves groups from local files only.
fn nss_group_is_files_only() -> bool {
    let Ok(text) = std::fs::read_to_string("/etc/nsswitch.conf") else {
        // Absent `nsswitch.conf` means the C library's built-in default, which
        // is `files`. Treating that as authoritative is correct, not optimistic.
        return true;
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(sources) = line.strip_prefix("group:") {
            return sources
                .split_whitespace()
                .all(|s| s == "files" || s.starts_with('[') || s.ends_with(']'));
        }
    }
    true
}

/// The account name for a uid, from `/etc/passwd`.
///
/// Read from the files database for the same reason group membership is: the
/// `getpwuid(3)` call needs `unsafe`. `None` where it does not resolve, and
/// [`Principal::actor`] falls back to `uid:N` so attribution is never absent.
fn account_name(uid: u32) -> Option<String> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _passwd = fields.next()?;
        let entry_uid: u32 = fields.next()?.parse().ok()?;
        if entry_uid == uid {
            return Some(name.to_owned());
        }
    }
    None
}

/// A raw fd, for the log line only.
///
/// Present so the server can name the connection in a trace without reaching
/// into the stream elsewhere.
#[must_use]
pub fn connection_id(stream: &UnixStream) -> i32 {
    stream.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(text: &str) -> GroupSource {
        GroupSource {
            entries: parse_group_file(text),
            authoritative: true,
        }
    }

    #[test]
    fn the_group_file_parses_including_lines_with_no_members() {
        let parsed = parse_group_file(
            "# a comment\nroot:x:0:\ntwinvpn:x:970:dana,sam\ntwinvpn-operators:x:971:dana\nmalformed\n",
        );
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], ("root".to_owned(), Vec::new(), 0));
        assert_eq!(
            parsed[1],
            (
                "twinvpn".to_owned(),
                vec!["dana".to_owned(), "sam".to_owned()],
                970
            )
        );
    }

    #[test]
    fn an_unreadable_group_database_grants_nothing_rather_than_everything() {
        // MI-A5's direction, applied one level down: an unresolvable fact fails
        // closed.
        let missing = GroupSource::from_path(Path::new("/nonexistent/group"));
        assert!(!missing.is_authoritative());
        assert!(!missing.member_of(OBSERVE_GROUP, 1000));
    }

    #[test]
    fn root_holds_every_grantable_scope_on_the_headless_tier() {
        // ADR-0023 EM-39(2): on this tier the principal "is `root` over the
        // local AF_UNIX transport, because §11.10 gives that tier no second
        // identity".
        let root = Principal {
            uid: 0,
            gid: 0,
            pid: 1,
            name: Some("root".to_owned()),
        };
        let scopes = root.scopes(&source(""));
        for scope in crate::mi::scope::GRANTABLE {
            assert!(scopes.holds(scope), "{}", scope.name());
        }
    }

    #[test]
    fn the_disarm_scope_is_never_granted_at_attach_even_to_root() {
        // §11.5: "Never granted at attach. Minted per-operation by the OS
        // ceremony (§11.14)."
        let root = Principal {
            uid: 0,
            gid: 0,
            pid: 1,
            name: Some("root".to_owned()),
        };
        assert!(!root.scopes(&source("")).holds(Scope::Disarm));
    }

    #[test]
    fn an_unprivileged_principal_in_no_group_holds_nothing() {
        // PS-12a: built-in `Users`/`staff`-style groups are deliberately NOT
        // used for OBSERVE, "because 'every local account can enumerate this
        // device's peers and endpoints' should be an install-time decision".
        let nobody = Principal {
            uid: 65_534,
            gid: 65_534,
            pid: 100,
            name: Some("nobody".to_owned()),
        };
        let scopes = nobody.scopes(&source("twinvpn:x:970:dana\n"));
        assert!(scopes.names().is_empty());
    }

    #[test]
    fn attribution_is_never_absent() {
        // PS-13: "an unattributed state change on a multi-user host is the
        // 'silent failure' reliability.md §10 forbids, wearing local clothes."
        let named = Principal {
            uid: 1000,
            gid: 1000,
            pid: 7,
            name: Some("dana".to_owned()),
        };
        assert_eq!(named.actor(), "dana");
        let unnamed = Principal {
            name: None,
            ..named
        };
        assert_eq!(unnamed.actor(), "uid:1000");
        assert!(!unnamed.actor().is_empty());
    }

    #[test]
    fn a_pid_gates_nothing() {
        // MI-A2: "/proc/<pid>/exe etc. is advisory only and MUST NOT gate any
        // scope. Pids are reused."
        let a = Principal {
            uid: 0,
            gid: 0,
            pid: 1,
            name: Some("root".to_owned()),
        };
        let b = Principal {
            pid: 999_999,
            ..a.clone()
        };
        assert_eq!(a.scopes(&source("")), b.scopes(&source("")));
    }

    #[test]
    fn an_unverifiable_principal_names_the_registered_code() {
        assert_eq!(
            PeerError::Unverifiable.reason_code(),
            "MGMT.PRINCIPAL_UNVERIFIABLE"
        );
    }
}
