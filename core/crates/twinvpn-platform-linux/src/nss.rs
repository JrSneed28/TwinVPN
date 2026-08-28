//! `getgrouplist(3)`: the group memberships `/etc/group` cannot see.
//!
//! **Authority:** ADR-0016 PS-12a (the principal classes and the groups that
//! carry them), S-44 (membership is re-derived at every attach); ADR-0018 CB-1,
//! DP-4.
//!
//! # Why this exists
//!
//! ADR-0016 PS-12a resolves an OS principal to a class by group membership, and
//! the obvious implementation — parse `/etc/group` — sees only *local* groups. A
//! host whose accounts come from LDAP, SSSD, `nss-systemd` or any other NSS
//! module has memberships that are real, that `id(1)` reports, and that a
//! file parser cannot see. The consequence is not a crash: the principal simply
//! holds **fewer** scopes than the operator granted, so `twinvpnctl` reports
//! `POLICY.POLICY_DENIED` for an account that was deliberately authorised.
//!
//! It fails closed, which is the right direction — but it fails closed
//! *invisibly*, and an operator debugging it has no reason to suspect the group
//! database rather than their own `usermod`.
//!
//! `getgrouplist(3)` asks NSS the same question the kernel-adjacent tooling
//! asks, so every configured source answers.
//!
//! # Why it is in the adapter and not in the shell
//!
//! It is `libc` and therefore `unsafe`, and both Linux binaries carry
//! `#![forbid(unsafe_code)]`. CB-1 puts code in the adapter when it "must call a
//! platform API with no stable C-callable form"; `getgrouplist` is a libc
//! function with an out-parameter and a two-call size protocol, which is exactly
//! that. This crate is the DP-4 `unsafe` allowlist member.
//!
//! **The policy stays in the shell.** Which groups mean which scopes is
//! `shells/linux/twinvpnd/src/agent/peer.rs`'s and comes from PS-12a; this
//! module answers only "which groups is this account in", which is an OS fact.
//!
//! # What it does not do
//!
//! It does not cache. S-44 requires membership to be "re-derived at every
//! attach, never cached across attaches", so a `usermod` takes effect on the
//! next connection rather than on the next restart. `getgrouplist` is a lookup
//! per attach, which is what that rule asks for, and NSS does its own caching
//! where the administrator configured one.

use std::ffi::CString;

/// The largest number of groups this will ask for.
///
/// `limits.json` has no entry for this and neither does any ADR, so the bound is
/// stated here rather than left implicit: an untrusted-adjacent input (the group
/// database) must not drive an unbounded allocation, which is `ownership.md`
/// §6 rule 10. Linux's own `NGROUPS_MAX` is 65536; a principal in more than
/// 1024 groups is a misconfiguration, and truncating is safe because the result
/// is only ever used to grant **fewer** scopes.
pub const MAX_GROUPS: usize = 1024;

/// Every group `account` belongs to, according to **NSS**.
///
/// `primary_gid` is the account's own gid, which `getgrouplist` includes in the
/// result whether or not any group file lists it — that is the function's
/// contract, not an accident, and it is why the primary group does not have to
/// be looked up separately.
///
/// Returns `None` when the lookup could not be performed at all: an account name
/// containing an interior NUL, or a `getgrouplist` that failed for a reason
/// other than the buffer being too small. `None` is **not** "no groups": the
/// caller must treat it as "unknown" and fall back, because reporting an empty
/// membership for a failed lookup would silently strip every scope from every
/// principal on a host whose NSS is temporarily unreachable.
#[must_use]
pub fn groups_of(account: &str, primary_gid: libc::gid_t) -> Option<Vec<libc::gid_t>> {
    // An interior NUL cannot reach libc, and is not a lookup failure — it is an
    // account name that cannot exist. Refused rather than truncated at the NUL,
    // which would look up a *different* account.
    let name = CString::new(account).ok()?;

    // `getgrouplist`'s two-call protocol: pass a buffer and its size; on
    // overflow it returns -1 and writes the required size back through the same
    // pointer. Starting at 32 covers essentially every real account in one call.
    let mut count: libc::c_int = 32;
    loop {
        let capacity = usize::try_from(count).ok()?.min(MAX_GROUPS);
        let mut buffer: Vec<libc::gid_t> = vec![0; capacity];
        let mut written: libc::c_int = libc::c_int::try_from(capacity).ok()?;

        // SAFETY: `name` is a live, NUL-terminated C string that outlives the
        // call. `buffer` has `capacity` elements and `written` is set to exactly
        // that, so libc writes at most `capacity` `gid_t`s through the pointer —
        // the bound it is given is the bound that is true. `written` is a live
        // local libc reads and then overwrites with the count it produced. No
        // pointer outlives the call, and the return value is checked before any
        // element is read.
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                primary_gid,
                buffer.as_mut_ptr(),
                &raw mut written,
            )
        };

        if rc >= 0 {
            let produced = usize::try_from(written).ok()?.min(capacity);
            buffer.truncate(produced);
            return Some(buffer);
        }

        // -1 with a larger `written` is "the buffer was too small"; retry once
        // at the size libc asked for. Anything else — including a `written` that
        // did not grow — is a failure, and looping on it would spin.
        let required = usize::try_from(written).ok()?;
        if required <= capacity || capacity >= MAX_GROUPS {
            return None;
        }
        count = libc::c_int::try_from(required.min(MAX_GROUPS)).ok()?;
    }
}

/// Whether `account` is a member of the group with gid `gid`, according to NSS.
///
/// `None` where the lookup could not be performed, which the caller distinguishes
/// from `Some(false)`: "not a member" and "we could not ask" are different facts,
/// and only the first is a reason to withhold a scope.
#[must_use]
pub fn is_member(account: &str, primary_gid: libc::gid_t, gid: libc::gid_t) -> Option<bool> {
    Some(groups_of(account, primary_gid)?.contains(&gid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This process's own account name and primary gid, from `/proc` and
    /// `/etc/passwd` — the same two files the agent already reads.
    fn this_account() -> Option<(String, u32)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let uid: u32 = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _ = fields.next();
            let entry_uid: u32 = fields.next()?.parse().ok()?;
            let gid: u32 = fields.next()?.parse().ok()?;
            if entry_uid == uid {
                return Some((name.to_owned(), gid));
            }
        }
        None
    }

    #[test]
    fn this_account_is_in_its_own_primary_group() {
        // `getgrouplist`'s contract: the primary gid is included whether or not
        // any group file lists it. That is the property that makes a separate
        // primary-group lookup unnecessary, so it is worth pinning.
        let Some((name, gid)) = this_account() else {
            return;
        };
        let groups = groups_of(&name, gid).expect("NSS answers for a real account");
        assert!(
            groups.contains(&gid),
            "the primary gid {gid} is missing from {groups:?}"
        );
        assert_eq!(is_member(&name, gid, gid), Some(true));
    }

    #[test]
    fn an_account_that_does_not_exist_is_not_a_member_of_anything_real() {
        // `getgrouplist` does not fail for an unknown name — it returns the
        // primary gid it was given, which is the caller's own. That is worth an
        // assertion, because a reader might expect `None` and build a "does this
        // account exist" check on top of it that would always say yes.
        let groups = groups_of("a-user-that-does-not-exist-anywhere", 65_534);
        if let Some(groups) = groups {
            assert!(
                groups.iter().all(|g| *g == 65_534),
                "an unknown account resolved to real groups: {groups:?}"
            );
        }
    }

    #[test]
    fn a_name_with_an_interior_nul_is_refused_rather_than_truncated() {
        // Truncating at the NUL would look up a DIFFERENT account, and on a host
        // where the prefix names a privileged one that is a scope escalation
        // driven by a string the caller controls.
        assert_eq!(groups_of("root\0evil", 0), None);
        assert_eq!(is_member("root\0evil", 0, 0), None);
    }

    #[test]
    fn the_result_is_bounded_before_the_allocation() {
        // `ownership.md` §6 rule 10: an untrusted-adjacent input must not drive
        // an unbounded allocation. The bound is stated, not implicit.
        assert_eq!(MAX_GROUPS, 1024);
        if let Some((name, gid)) = this_account() {
            let groups = groups_of(&name, gid).expect("answers");
            assert!(groups.len() <= MAX_GROUPS);
        }
    }

    #[test]
    fn a_failed_lookup_is_none_and_never_an_empty_membership() {
        // The distinction the caller depends on. Reporting an empty membership
        // for a failed lookup would silently strip every scope from every
        // principal on a host whose NSS is temporarily unreachable — a total
        // authorization outage presented as a policy decision.
        assert_eq!(groups_of("a\0b", 0), None);
        // And a successful lookup of a real account is never empty, because the
        // primary gid is always in it.
        if let Some((name, gid)) = this_account() {
            assert!(!groups_of(&name, gid).expect("answers").is_empty());
        }
    }
}
