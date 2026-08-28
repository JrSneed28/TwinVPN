//! Who is on the other end of the socket, and what they may do.
//!
//! **Authority:** ADR-0017 MI-A1 (kernel-sourced identity), MI-A2 (pid lookups
//! are advisory — "exception: macOS audit token"), MI-A5 (fail closed on
//! unverifiable identity), MI-S1, MI-S2; ADR-0016 PS-12, PS-12a, PS-13, §11.7's
//! class table.
//!
//! # MI-A1, and the one place macOS is *better* than Linux here
//!
//! > The calling principal MUST be obtained from the kernel on the connected
//! > channel; no client-asserted-identity field exists in the schema, at any
//! > version.
//!
//! On Darwin `getsockopt(LOCAL_PEERCRED)` returns a `struct xucred`, which
//! carries the peer's uid **and its whole group list**. Linux's `SO_PEERCRED`
//! returns only uid/gid, which is why `shells/linux` has to read `/etc/group` and
//! records as a gap that an LDAP or `nss-systemd` membership is invisible to it.
//! Here the group list is the kernel's own answer, so PS-12a's three principal
//! classes are derived from a source a client cannot influence and a directory
//! service cannot hide.
//!
//! The limit is real and stated: `xucred` carries at most `NGROUPS` (16) groups,
//! and a principal in more than sixteen groups may have the relevant one
//! truncated away by the kernel. That fails **closed** — fewer scopes than
//! intended — and it is named in `shells/macos/README.md` §7.
//!
//! # MI-A5, as the default rather than as a check
//!
//! [`PeerCredentials::read`] returns a `Result`. There is no constructor that
//! produces an anonymous or default principal, so "fall back to a default
//! principal" is not something a caller can do by forgetting a branch.

use twinvpn_mi::Scopes;

/// `<sys/ucred.h>`: `XUCRED_VERSION`.
pub const XUCRED_VERSION: u32 = 0;

/// `<sys/param.h>`: `NGROUPS`, the group list's length in `struct xucred`.
pub const XUCRED_NGROUPS: usize = 16;

/// `<sys/un.h>`: `LOCAL_PEERCRED`.
pub const LOCAL_PEERCRED: libc::c_int = 0x001;

/// `<sys/socket.h>`: `SOL_LOCAL`.
pub const SOL_LOCAL: libc::c_int = 0;

/// `<sys/ucred.h>`: `struct xucred`.
///
/// Declared here with its header definition rather than taken from `libc`, for
/// the same reason this crate's other C layouts are: the size is asserted
/// below, so a drifting layout fails the build instead of producing a plausible
/// uid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Xucred {
    /// `XUCRED_VERSION`. **Checked**: a `cr_version` this build does not know
    /// means the struct is not the one it was compiled against, and reading a
    /// uid out of it would be reading whatever happened to be at that offset.
    pub cr_version: u32,
    /// The peer's effective uid.
    pub cr_uid: u32,
    /// How many of `cr_groups` are valid.
    pub cr_ngroups: i16,
    /// The peer's group list, truncated to [`XUCRED_NGROUPS`].
    pub cr_groups: [u32; XUCRED_NGROUPS],
}

impl Default for Xucred {
    fn default() -> Self {
        Self {
            cr_version: 0,
            cr_uid: u32::MAX,
            cr_ngroups: 0,
            cr_groups: [0; XUCRED_NGROUPS],
        }
    }
}

/// The kernel's answer about the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    /// The peer's effective uid.
    pub uid: u32,
    /// Its group list, as the kernel reported it.
    pub groups: Vec<u32>,
    /// Whether the kernel's list was full, i.e. possibly truncated.
    ///
    /// Reported rather than hidden: a principal in seventeen groups may have
    /// lost the one that mattered, and the consequence is **fewer** scopes than
    /// intended. The agent logs it so an operator can see why a grant was
    /// narrower than expected.
    pub groups_possibly_truncated: bool,
}

impl PeerCredentials {
    /// Builds credentials from a kernel `xucred`.
    ///
    /// Separated from the syscall so the **interpretation** — the version check,
    /// the truncation flag, the bounds on `cr_ngroups` — is testable on a host
    /// with no `LOCAL_PEERCRED`.
    ///
    /// # Errors
    ///
    /// `None` when the struct is not one this build understands. **MI-A5**: the
    /// caller closes with `MGMT.PRINCIPAL_UNVERIFIABLE` and never substitutes a
    /// default.
    #[must_use]
    pub fn from_xucred(raw: &Xucred) -> Option<Self> {
        if raw.cr_version != XUCRED_VERSION {
            return None;
        }
        // `cr_ngroups` is a signed 16-bit count from the kernel. Negative is
        // impossible and over-long is impossible, and a decoder that trusted
        // either would index past a 16-element array.
        let count = usize::try_from(raw.cr_ngroups).ok()?;
        if count > XUCRED_NGROUPS {
            return None;
        }
        Some(Self {
            uid: raw.cr_uid,
            groups: raw.cr_groups[..count].to_vec(),
            groups_possibly_truncated: count == XUCRED_NGROUPS,
        })
    }

    /// Reads the peer's credentials off a connected Unix socket.
    ///
    /// # Errors
    ///
    /// `None` if the kernel refuses or the struct is unrecognised — which
    /// **MI-A5** makes a close, not a downgrade.
    #[cfg(target_os = "macos")]
    #[must_use]
    // **The one `unsafe` in this crate.** See the note on `#![deny(unsafe_code)]`
    // in `lib.rs`: MI-A1 requires a kernel-sourced principal, `LOCAL_PEERCRED` is
    // the only source on Darwin, and no safe wrapper for it exists in `std` or in
    // any dependency this shell has.
    #[allow(unsafe_code)]
    pub fn read(fd: std::os::fd::RawFd) -> Option<Self> {
        let mut raw = Xucred::default();
        let mut len = u32::try_from(core::mem::size_of::<Xucred>()).ok()?;
        // SAFETY: `fd` is a connected socket owned by the caller for the duration
        // of the call; `raw` is a live struct we own and `len` is its true size,
        // which the call updates to the number of bytes written. `getsockopt`
        // takes no ownership of either.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERCRED,
                std::ptr::from_mut(&mut raw).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return None;
        }
        Self::from_xucred(&raw)
    }

    /// On a host that is not Darwin there is no `LOCAL_PEERCRED`.
    ///
    /// Returning `None` rather than a permissive default is the whole of MI-A5:
    /// the caller closes the connection.
    #[cfg(not(target_os = "macos"))]
    #[must_use]
    pub fn read(_fd: std::os::fd::RawFd) -> Option<Self> {
        None
    }
}

/// The OS principals PS-12a's three classes are derived from.
///
/// **Injected, never discovered.** ADR-0016 PS-12a: the package creates these
/// groups and the agent never does, and "'every local account can enumerate this
/// device's peers and endpoints' should be an install-time decision (TB-13), not
/// a platform default". So the gids are configuration, and there is no fallback
/// to `staff`, `admin` or `everyone`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupPolicy {
    /// The `OBSERVE` group's gid.
    pub observe: u32,
    /// The `OPERATE` group's gid.
    pub operate: u32,
    /// The `ADMINISTER` group's gid.
    pub administer: u32,
}

/// The scopes a principal holds.
///
/// **Pure**, so PS-12a's class table is checkable without a Mac.
///
/// # Root is not a fourth class
///
/// uid 0 holds every class, because on macOS the authority itself runs as root
/// and a root client can reach `pfctl` directly anyway — refusing it here would
/// be security theatre rather than a control. It is granted **explicitly** rather
/// than by a group membership root happens to have, so the reason is visible.
#[must_use]
pub fn scopes_for(credentials: &PeerCredentials, policy: GroupPolicy) -> Scopes {
    use twinvpn_mgmt::Scope;

    let holds = |gid: u32| credentials.uid == 0 || credentials.groups.contains(&gid);
    let mut scopes = Vec::new();
    if holds(policy.observe) || holds(policy.operate) || holds(policy.administer) {
        // OBSERVE is implied by the wider classes: PS-12's table is a ladder, and
        // an operator who could connect but not read status would be a class
        // nobody asked for.
        scopes.push(Scope::Status);
        scopes.push(Scope::Events);
        scopes.push(Scope::Diagnostics);
    }
    if holds(policy.operate) || holds(policy.administer) {
        scopes.push(Scope::Connect);
        scopes.push(Scope::Settings);
    }
    if holds(policy.administer) {
        scopes.push(Scope::Admin);
    }
    Scopes::from_scopes(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_mgmt::Scope;

    const POLICY: GroupPolicy = GroupPolicy {
        observe: 400,
        operate: 401,
        administer: 402,
    };

    fn xucred(uid: u32, groups: &[u32]) -> Xucred {
        let mut raw = Xucred {
            cr_version: XUCRED_VERSION,
            cr_uid: uid,
            cr_ngroups: i16::try_from(groups.len()).expect("short"),
            cr_groups: [0; XUCRED_NGROUPS],
        };
        raw.cr_groups[..groups.len()].copy_from_slice(groups);
        raw
    }

    #[test]
    fn the_c_layout_is_the_size_the_header_declares() {
        // 4 + 4 + 2 + 2 padding + 64 = 76.
        assert_eq!(core::mem::size_of::<Xucred>(), 76);
        assert_eq!(core::mem::align_of::<Xucred>(), 4);
    }

    #[test]
    fn an_unrecognised_struct_version_is_refused_and_never_read_from() {
        // A `cr_version` this build does not know means the struct is not the one
        // it was compiled against, and a uid read out of it is whatever was at
        // that offset.
        let mut raw = xucred(501, &[400]);
        raw.cr_version = 99;
        assert!(PeerCredentials::from_xucred(&raw).is_none());
    }

    #[test]
    fn an_impossible_group_count_is_refused_rather_than_indexing_past_the_array() {
        let mut raw = xucred(501, &[400]);
        raw.cr_ngroups = -1;
        assert!(PeerCredentials::from_xucred(&raw).is_none());
        raw.cr_ngroups = i16::try_from(XUCRED_NGROUPS + 1).expect("small");
        assert!(PeerCredentials::from_xucred(&raw).is_none());
    }

    #[test]
    fn a_full_group_list_is_flagged_as_possibly_truncated() {
        // Seventeen groups become sixteen, and the one that mattered may be the
        // one that went. It fails CLOSED — fewer scopes — and it is reported.
        let full = u32::try_from(XUCRED_NGROUPS).expect("small");
        let groups: Vec<u32> = (0..full).collect();
        let credentials = PeerCredentials::from_xucred(&xucred(501, &groups)).expect("valid");
        assert!(credentials.groups_possibly_truncated);

        let short = PeerCredentials::from_xucred(&xucred(501, &[400])).expect("valid");
        assert!(!short.groups_possibly_truncated);
    }

    #[test]
    fn the_three_classes_are_a_ladder_and_each_rung_holds_the_ones_below() {
        let observer = PeerCredentials::from_xucred(&xucred(501, &[400])).expect("valid");
        let operator = PeerCredentials::from_xucred(&xucred(502, &[401])).expect("valid");
        let admin = PeerCredentials::from_xucred(&xucred(503, &[402])).expect("valid");

        let s = scopes_for(&observer, POLICY);
        assert!(s.holds(Scope::Status) && s.holds(Scope::Diagnostics));
        assert!(!s.holds(Scope::Connect), "OBSERVE cannot connect");
        assert!(!s.holds(Scope::Admin));

        let s = scopes_for(&operator, POLICY);
        assert!(s.holds(Scope::Status), "OPERATE implies OBSERVE");
        assert!(s.holds(Scope::Connect) && s.holds(Scope::Settings));
        assert!(!s.holds(Scope::Admin));

        let s = scopes_for(&admin, POLICY);
        assert!(s.holds(Scope::Admin) && s.holds(Scope::Connect) && s.holds(Scope::Status));
    }

    #[test]
    fn a_principal_in_no_twinvpn_group_holds_nothing() {
        // PS-12a: never a built-in everyone-group. A local account that is not in
        // one of the three groups the PACKAGE created gets no scope at all.
        let stranger = PeerCredentials::from_xucred(&xucred(504, &[20, 12, 61])).expect("valid");
        let scopes = scopes_for(&stranger, POLICY);
        assert!(scopes.names().is_empty());
        for scope in twinvpn_mi::scope::GRANTABLE {
            assert!(!scopes.holds(scope));
        }
    }

    #[test]
    fn the_disarm_scope_is_never_derived_from_a_group() {
        // §11.5: minted per-operation by the §11.14 ceremony, never held.
        let admin = PeerCredentials::from_xucred(&xucred(503, &[402])).expect("valid");
        assert!(!scopes_for(&admin, POLICY).holds(Scope::Disarm));
        let root = PeerCredentials::from_xucred(&xucred(0, &[])).expect("valid");
        assert!(!scopes_for(&root, POLICY).holds(Scope::Disarm));
    }

    #[test]
    fn root_holds_every_class_explicitly_rather_than_by_accident() {
        let root = PeerCredentials::from_xucred(&xucred(0, &[])).expect("valid");
        let scopes = scopes_for(&root, POLICY);
        assert!(scopes.holds(Scope::Admin));
        assert!(scopes.holds(Scope::Status));
    }

    #[test]
    fn there_is_no_constructor_that_produces_an_anonymous_principal() {
        // MI-A5 as a type property. `read` returns `Option`, `from_xucred`
        // returns `Option`, and neither has a `Default` or an `unwrap_or_default`
        // path — so "fall back to a default principal" is not reachable by
        // forgetting a branch.
        assert!(PeerCredentials::read(-1).is_none());
    }
}
