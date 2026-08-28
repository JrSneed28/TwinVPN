//! The pipe's explicit DACL, as a constructed value.
//!
//! **Authority:** ADR-0017 §11.2's Windows row ("explicit DACL granting
//! `TwinVPN Users` group, `FILE_FLAG_FIRST_PIPE_INSTANCE`"), MI-A3 ("**the
//! agent** creates the endpoint and writes its DACL at every start" — an
//! installer-written ACL would be stale after a restart); ADR-0016 §11.9 ("pipe
//! DACL grants connect to `Users`, and every request is authorized by
//! impersonating the client token"), PS-12a (the named principals).
//!
//! # Why a *string* and why it is target-free
//!
//! A DACL is a binary structure, and building one by hand is a long sequence of
//! `InitializeAcl` / `AddAccessAllowedAce` calls whose correctness is invisible
//! in a diff. SDDL is the same information as text, and Windows converts it in
//! one call — `ConvertStringSecurityDescriptorToSecurityDescriptorW` — so the
//! part that decides *who may connect* is a string this module builds, and the
//! part that needs Windows is one conversion.
//!
//! That split is what lets the access-control decision be **tested on a Linux
//! host**: [`pipe_sddl`] is a pure function, and the tests below assert the
//! properties PS-12a actually states — that `Everyone` never appears, that the
//! built-in `Users` group is not the OBSERVE principal, and that the owner is
//! the service and not the installer.
//!
//! # The DACL is not the authorization
//!
//! It is the **first** gate and not the whole one. ADR-0016 §11.9 is explicit:
//! "the pipe DACL grants connect to `Users`, and **every request is authorized
//! by impersonating the client token**". A principal that can connect can send a
//! `Hello`; what it is granted comes from `policy(principal) ∩ requested`
//! (MI-S1), computed per attach from the token the kernel attests. Widening this
//! DACL would let more principals *reach* the endpoint; it would not grant one
//! of them a scope.
//!
//! # ADR-0017's own honest paragraph, restated because it applies here
//!
//! > On Linux, Windows, and the macOS Developer-ID socket variant, **the MI
//! > authenticates a user, not a program.** Any process the authorized user runs
//! > can do everything the GUI can do.
//!
//! Nothing in this module changes that. `ADMINISTER` is bound to an OS
//! re-authentication ceremony (§11.14) precisely because a DACL cannot express
//! it.

/// The SIDs of the three principals ADR-0016 PS-12a names, plus the service's
/// own.
///
/// Taken at construction rather than looked up here (CD-2): resolving a group
/// name to a SID is an OS call, the package creates the groups, and a shell that
/// discovered them would be deciding which principals exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalSids {
    /// `NT SERVICE\TwinVPNService` — the owner.
    pub service: String,
    /// The local group `TwinVPN Users`, PS-12a's `OBSERVE` principal.
    pub observe: String,
    /// The local group `TwinVPN Operators`, PS-12a's `OPERATE` principal.
    pub operate: String,
}

/// `BUILTIN\Administrators`, PS-12a's `ADMINISTER` principal.
///
/// A well-known SID, so it is a constant rather than a lookup — unlike the two
/// groups the package creates, which do not exist until it has run.
pub const ADMINISTRATORS: &str = "BA";

/// `NT AUTHORITY\SYSTEM`.
pub const LOCAL_SYSTEM: &str = "SY";

/// `Everyone`. Present only so [`pipe_sddl`]'s tests can assert its **absence**.
pub const EVERYONE: &str = "WD";

/// The built-in `Users` group. Present for the same reason.
///
/// PS-12a: "'every local account can enumerate this device's peers and
/// endpoints' should be an install-time decision (TB-13), not a platform
/// default." So this SID is named here and never granted.
pub const BUILTIN_USERS: &str = "BU";

/// `ANONYMOUS LOGON`.
pub const ANONYMOUS: &str = "AN";

/// The access mask a client needs to open and use the pipe.
///
/// `GRGW` — generic read and generic write. Deliberately **not** `GA` (generic
/// all): `GA` on a pipe carries `WRITE_DAC`, so a principal that could connect
/// could also rewrite the DACL and grant itself and everyone else access. That
/// is the confused-deputy shape MI-A4 warns about, one layer down.
pub const CLIENT_ACCESS: &str = "GRGW";

/// The access the owner keeps.
pub const OWNER_ACCESS: &str = "GA";

/// Builds the pipe's security descriptor in SDDL.
///
/// The shape is `O:<owner>G:<group>D:<dacl>`, and the DACL is ordered
/// deny-then-allow — which is not cosmetic: Windows evaluates ACEs in order and
/// stops at the first match, so a deny placed after an allow never fires.
///
/// # What it grants, and to whom
///
/// | Principal | Access | Why |
/// |---|---|---|
/// | `NT AUTHORITY\SYSTEM` | `GA` | the service's own token |
/// | `NT SERVICE\TwinVPNService` | `GA` | ADR-0016 §11.2's `SERVICE_SID_TYPE_UNRESTRICTED` service SID |
/// | `BUILTIN\Administrators` | `GRGW` | PS-12a's `ADMINISTER` principal still has to *connect* before the §11.14 ceremony can run |
/// | `TwinVPN Users` | `GRGW` | PS-12a's `OBSERVE` principal |
/// | `TwinVPN Operators` | `GRGW` | PS-12a's `OPERATE` principal |
/// | `ANONYMOUS LOGON` | **denied** | an explicit deny, first, so a null session cannot inherit access from any allow below it |
///
/// `Everyone` and the built-in `Users` group appear nowhere.
#[must_use]
pub fn pipe_sddl(sids: &PrincipalSids) -> String {
    let mut sddl = String::new();
    sddl.push_str("O:");
    sddl.push_str(&sids.service);
    sddl.push_str("G:");
    sddl.push_str(&sids.service);
    // `P` — protected: inheritance is disabled, so a parent object's ACEs
    // cannot widen this one. ADR-0020 §11.9 asks for the same on the store
    // directory and for the same reason.
    sddl.push_str("D:P");
    // The deny comes first. An ACE list is evaluated in order.
    sddl.push_str(&ace("D", ANONYMOUS, "GA"));
    sddl.push_str(&ace("A", LOCAL_SYSTEM, OWNER_ACCESS));
    sddl.push_str(&ace("A", &sids.service, OWNER_ACCESS));
    sddl.push_str(&ace("A", ADMINISTRATORS, CLIENT_ACCESS));
    sddl.push_str(&ace("A", &sids.observe, CLIENT_ACCESS));
    sddl.push_str(&ace("A", &sids.operate, CLIENT_ACCESS));
    sddl
}

/// One ACE: `(type;flags;rights;object;inherit;trustee)`.
fn ace(kind: &str, trustee: &str, rights: &str) -> String {
    format!("({kind};;{rights};;;{trustee})")
}

/// Whether a rendered descriptor grants anything to a principal.
///
/// Used by the tests below, and by the service's own startup self-check: a
/// descriptor is the sort of thing that is right until somebody edits it, and
/// PS-17's "a hardening directive that cannot be applied is reported" is the
/// same discipline applied to one we wrote ourselves.
#[must_use]
pub fn grants_to(sddl: &str, trustee: &str) -> bool {
    sddl.split("(A;")
        .skip(1)
        .any(|ace| ace.split(')').next().is_some_and(|a| a.ends_with(trustee)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sids() -> PrincipalSids {
        PrincipalSids {
            service: "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890".to_owned(),
            observe: "S-1-5-21-1-2-3-1001".to_owned(),
            operate: "S-1-5-21-1-2-3-1002".to_owned(),
        }
    }

    #[test]
    fn everyone_is_never_granted_anything() {
        // PS-12a: "Built-in `users`/`staff` groups are deliberately not used."
        let sddl = pipe_sddl(&sids());
        assert!(!grants_to(&sddl, EVERYONE), "{sddl}");
        assert!(!sddl.contains(";;;WD)"), "{sddl}");
    }

    #[test]
    fn the_builtin_users_group_is_not_the_observe_principal() {
        // "'every local account can enumerate this device's peers and
        // endpoints' should be an install-time decision (TB-13), not a platform
        // default."
        let sddl = pipe_sddl(&sids());
        assert!(!grants_to(&sddl, BUILTIN_USERS), "{sddl}");
        assert!(grants_to(&sddl, &sids().observe));
    }

    #[test]
    fn anonymous_logon_is_denied_before_any_allow_can_reach_it() {
        // Order is the mechanism: Windows evaluates ACEs in sequence and stops
        // at the first match, so a deny placed after an allow never fires.
        let sddl = pipe_sddl(&sids());
        let deny = sddl.find("(D;").expect("a deny ACE");
        let first_allow = sddl.find("(A;").expect("an allow ACE");
        assert!(deny < first_allow, "the deny must come first: {sddl}");
        assert!(sddl.contains(&format!(";;;{ANONYMOUS})")));
    }

    #[test]
    fn a_client_gets_read_and_write_and_never_the_right_to_rewrite_the_dacl() {
        // `GA` on a pipe carries WRITE_DAC. A principal that could connect and
        // also rewrite the descriptor could grant access to everyone, which is
        // the confused-deputy shape one layer down from MI-A4's.
        let sddl = pipe_sddl(&sids());
        for client in [ADMINISTRATORS, &sids().observe, &sids().operate] {
            assert!(
                sddl.contains(&format!("(A;;{CLIENT_ACCESS};;;{client})")),
                "{client} should hold exactly GRGW: {sddl}"
            );
            assert!(
                !sddl.contains(&format!("(A;;{OWNER_ACCESS};;;{client})")),
                "{client} must not hold GA"
            );
        }
    }

    #[test]
    fn the_owner_is_the_service_and_not_whoever_created_the_pipe() {
        // MI-A3: the AGENT creates the endpoint and writes its DACL at every
        // start. An installer-written ACL would be stale after a restart, and an
        // owner that was the installing administrator would let that account
        // rewrite the descriptor later.
        let sddl = pipe_sddl(&sids());
        assert!(sddl.starts_with(&format!("O:{}G:{}", sids().service, sids().service)));
    }

    #[test]
    fn inheritance_is_disabled_so_a_parent_cannot_widen_this_descriptor() {
        assert!(pipe_sddl(&sids()).contains("D:P"), "protected DACL");
    }

    #[test]
    fn every_named_principal_appears_exactly_once() {
        // A duplicate ACE is not wrong, but it is how a widening edit hides: the
        // second one is the one nobody reads.
        let sddl = pipe_sddl(&sids());
        for trustee in [
            LOCAL_SYSTEM,
            ADMINISTRATORS,
            sids().service.as_str(),
            sids().observe.as_str(),
            sids().operate.as_str(),
        ] {
            let suffix = format!(";;;{trustee})");
            assert_eq!(sddl.matches(&suffix).count(), 1, "{trustee} in {sddl}");
        }
    }

    #[test]
    fn the_descriptor_is_deterministic() {
        // The service rewrites the DACL at every start (MI-A3), and a
        // descriptor that differed between starts would make "did somebody
        // change this" unanswerable.
        assert_eq!(pipe_sddl(&sids()), pipe_sddl(&sids()));
    }
}
