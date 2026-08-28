//! `audit_token_t` — §11.14 (a)'s macOS spelling of a kernel-sourced principal.
//!
//! **Authority:** ADR-0016 §11.14 (a) ("`audit_token_t` over XPC"), **PS-22**
//! (the extension serves the MI "over XPC with `audit_token_t`"); ADR-0017
//! §11.2's macOS row, MI-A1, MI-A2 ("pid lookups are advisory — *exception:
//! macOS audit token*"), MI-A5; `<bsm/audit.h>`'s `audit_token_t`.
//!
//! # Why the token and not the pid
//!
//! ADR-0017 §11.2's macOS row: *"XPC preferred: audit-token attestation is not
//! pid-based and therefore not TOCTOU-able."* A pid can be reused between the
//! moment a server reads it and the moment it looks the process up; the audit
//! token is a **snapshot of the sending process's credentials taken by the
//! kernel at send time** and carried with the message, so there is no window.
//! MI-A2's parenthesis names this as the one exception to "pid lookups are
//! advisory", and `pidversion` below is why: it disambiguates a reused pid.
//!
//! # The layout, and why it is written out here
//!
//! `audit_token_t` is `struct { unsigned int val[8]; }`, and the meaning of the
//! eight words is fixed by `<bsm/audit.h>`'s `audit_token_to_*` accessors:
//!
//! | word | accessor | meaning |
//! |---|---|---|
//! | 0 | `audit_token_to_auid` | the audit user id — the **login** identity |
//! | 1 | `audit_token_to_euid` | the effective uid **this is the principal** |
//! | 2 | `audit_token_to_egid` | the effective gid |
//! | 3 | `audit_token_to_ruid` | the real uid |
//! | 4 | `audit_token_to_rgid` | the real gid |
//! | 5 | `audit_token_to_pid`  | the pid |
//! | 6 | `audit_token_to_asid` | the audit session id |
//! | 7 | `audit_token_to_pidversion` | the pid generation |
//!
//! Those accessors live in `libbsm`, which is a link-time dependency this crate
//! does not need: the struct is eight plain words and decoding it is arithmetic.
//! Writing the offsets out here rather than linking `libbsm` also puts the
//! layout somewhere a reviewer can check it, which a `dlopen`ed accessor would
//! not.
//!
//! # THE FINDING THIS MODULE RECORDS
//!
//! **An `audit_token_t` carries no supplementary group list.** It carries the
//! effective gid and nothing else — there is no `audit_token_to_groups`, and
//! there is no XPC API that supplies one. `getsockopt(LOCAL_PEERCRED)` on the
//! socket carriage returns a `struct xucred` with up to sixteen groups, which
//! is why `shells/macos` wave 2 recorded macOS as *better* than Linux here.
//!
//! ADR-0016 PS-12a derives the three authorization classes from **group
//! membership**. Over XPC there is one group to derive them from, so an XPC
//! client is admitted to a class only if that class's gid is its **effective**
//! gid. That fails **closed** — fewer scopes than a socket client with the same
//! rights would receive — and it is reported rather than papered over by
//! looking the uid up in the directory: a directory answer is a statement about
//! the *account*, not about the *connected process*, and MI-A1 asks for the
//! latter.
//!
//! See `shells/macos/README.md` §7.

use crate::mgmt::peer::PeerCredentials;

/// The number of 32-bit words in an `audit_token_t`.
pub const AUDIT_TOKEN_WORDS: usize = 8;

/// The number of bytes Swift hands across for one token.
pub const AUDIT_TOKEN_BYTES: usize = AUDIT_TOKEN_WORDS * 4;

/// Word indices, named rather than spelled as literals at the call site.
mod word {
    /// `audit_token_to_auid`.
    pub const AUID: usize = 0;
    /// `audit_token_to_euid`.
    pub const EUID: usize = 1;
    /// `audit_token_to_egid`.
    pub const EGID: usize = 2;
    /// `audit_token_to_pid`.
    pub const PID: usize = 5;
    /// `audit_token_to_asid`.
    pub const ASID: usize = 6;
    /// `audit_token_to_pidversion`.
    pub const PIDVERSION: usize = 7;
}

/// One `audit_token_t`, as the kernel filled it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditToken {
    val: [u32; AUDIT_TOKEN_WORDS],
}

impl AuditToken {
    /// Decodes a token from the 32 bytes Swift copied out of the XPC
    /// connection.
    ///
    /// **Bounds before anything else.** The length is checked against
    /// [`AUDIT_TOKEN_BYTES`] before a word is read, so a short or long buffer
    /// is a refusal rather than a read of whatever followed it — the same
    /// discipline `limits.json` imposes on every declared length.
    ///
    /// # Errors
    ///
    /// `None` for any length other than exactly [`AUDIT_TOKEN_BYTES`].
    /// **MI-A5**: the caller closes the connection and never substitutes a
    /// default principal.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != AUDIT_TOKEN_BYTES {
            return None;
        }
        let mut val = [0u32; AUDIT_TOKEN_WORDS];
        for (slot, chunk) in val.iter_mut().zip(bytes.chunks_exact(4)) {
            // Host byte order: the token is a struct the kernel wrote into this
            // process's address space and Swift copied verbatim. It never
            // crosses a machine boundary, so a network order here would be a
            // byte swap of a value that was never swapped.
            let word: [u8; 4] = chunk.try_into().ok()?;
            *slot = u32::from_ne_bytes(word);
        }
        Some(Self { val })
    }

    /// The effective uid — **the principal**.
    #[must_use]
    pub const fn euid(self) -> u32 {
        self.val[word::EUID]
    }

    /// The effective gid. The only group fact a token carries; see the module
    /// documentation.
    #[must_use]
    pub const fn egid(self) -> u32 {
        self.val[word::EGID]
    }

    /// The audit (login) user id.
    ///
    /// Not the principal: `auid` is the identity a session was *created* by and
    /// survives a `setuid`, which makes it useful for an audit line and wrong
    /// for an authorization decision. ADR-0016 §11.7's class map is about who
    /// is calling now.
    #[must_use]
    pub const fn auid(self) -> u32 {
        self.val[word::AUID]
    }

    /// The sender's pid. **Advisory** (MI-A2) — logged, never authorized on.
    #[must_use]
    pub const fn pid(self) -> u32 {
        self.val[word::PID]
    }

    /// The pid generation, which is what makes the pid non-ambiguous in a log
    /// line even after the pid has been reused.
    #[must_use]
    pub const fn pidversion(self) -> u32 {
        self.val[word::PIDVERSION]
    }

    /// The audit session id.
    #[must_use]
    pub const fn asid(self) -> u32 {
        self.val[word::ASID]
    }

    /// The principal this token names.
    ///
    /// `groups_possibly_truncated` is **always** true: the token carries the
    /// effective gid and the process may hold more groups than that. It is the
    /// same flag the socket carriage sets when the kernel's sixteen-group list
    /// came back full, and it means the same thing — the granted set may be
    /// narrower than intended, and an operator can see why.
    #[must_use]
    pub fn principal(self) -> PeerCredentials {
        PeerCredentials {
            uid: self.euid(),
            groups: vec![self.egid()],
            groups_possibly_truncated: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(words: [u32; AUDIT_TOKEN_WORDS]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_ne_bytes()).collect()
    }

    #[test]
    fn a_token_of_the_wrong_length_is_refused_rather_than_read_short() {
        // The bounds-before-allocate discipline applied to a fixed-size struct:
        // a decoder that read four words out of a sixteen-byte buffer would be
        // reading whatever followed it, and calling the result a uid.
        assert!(AuditToken::from_bytes(&[]).is_none());
        assert!(AuditToken::from_bytes(&[0u8; AUDIT_TOKEN_BYTES - 1]).is_none());
        assert!(AuditToken::from_bytes(&[0u8; AUDIT_TOKEN_BYTES + 1]).is_none());
        assert!(AuditToken::from_bytes(&[0u8; AUDIT_TOKEN_BYTES]).is_some());
    }

    #[test]
    fn every_word_is_read_from_the_offset_the_bsm_accessor_reads_it_from() {
        let raw = token([11, 501, 20, 502, 21, 4242, 100_004, 7]);
        let decoded = AuditToken::from_bytes(&raw).expect("32 bytes");
        assert_eq!(decoded.auid(), 11);
        assert_eq!(decoded.euid(), 501);
        assert_eq!(decoded.egid(), 20);
        assert_eq!(decoded.pid(), 4242);
        assert_eq!(decoded.asid(), 100_004);
        assert_eq!(decoded.pidversion(), 7);
    }

    #[test]
    fn the_principal_is_the_effective_uid_and_never_the_audit_uid() {
        // `auid` survives a setuid, so a process that dropped from an admin
        // login to a service account would still carry the admin's auid. Using
        // it as the principal would grant the class the process no longer holds.
        let decoded = AuditToken::from_bytes(&token([0, 501, 20, 0, 0, 1, 0, 0])).expect("32");
        assert_eq!(decoded.principal().uid, 501);
        assert_ne!(decoded.principal().uid, decoded.auid());
    }

    #[test]
    fn the_group_list_is_the_effective_gid_alone_and_is_flagged_as_partial() {
        // THE FINDING. `audit_token_t` has no supplementary group list, so
        // PS-12a's class map has one gid to work from over XPC where the socket
        // carriage has up to sixteen. It fails closed, and it says so.
        let decoded = AuditToken::from_bytes(&token([0, 501, 402, 0, 0, 1, 0, 0])).expect("32");
        let principal = decoded.principal();
        assert_eq!(principal.groups, vec![402]);
        assert!(
            principal.groups_possibly_truncated,
            "a token cannot report a complete group list, and must not claim to"
        );
    }

    #[test]
    fn an_xpc_principal_reaches_the_class_its_effective_gid_names() {
        use crate::mgmt::peer::{scopes_for, GroupPolicy};
        const POLICY: GroupPolicy = GroupPolicy {
            observe: 400,
            operate: 401,
            administer: 402,
        };
        let admin = AuditToken::from_bytes(&token([0, 503, 402, 0, 0, 1, 0, 0])).expect("32");
        assert!(scopes_for(&admin.principal(), POLICY).holds(twinvpn_mgmt::Scope::Admin));

        // And a principal whose ADMINISTER membership is a SUPPLEMENTARY group
        // rather than its effective gid gets nothing over this carriage. That is
        // the narrowing, asserted so it is visible rather than surprising.
        let supplementary =
            AuditToken::from_bytes(&token([0, 503, 20, 0, 0, 1, 0, 0])).expect("32");
        assert!(scopes_for(&supplementary.principal(), POLICY)
            .names()
            .is_empty());
    }

    #[test]
    fn root_over_xpc_holds_every_class_for_the_same_reason_it_does_on_the_socket() {
        use crate::mgmt::peer::{scopes_for, GroupPolicy};
        const POLICY: GroupPolicy = GroupPolicy {
            observe: 400,
            operate: 401,
            administer: 402,
        };
        let root = AuditToken::from_bytes(&token([0, 0, 0, 0, 0, 1, 0, 0])).expect("32");
        assert!(scopes_for(&root.principal(), POLICY).holds(twinvpn_mgmt::Scope::Admin));
    }
}
