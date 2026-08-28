//! Client-token authorization: the kernel's answer → an OS principal → a scope
//! set.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.4 (MI-A1 … MI-A5, and the Windows row of its authentication table),
//! §11.5, §11.14;
//! [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.7 (PS-12, PS-12a's Windows principals), PS-13, PS-14, PS-23;
//! ADR-0018 CB-2.
//!
//! # MI-A1, made structural
//!
//! > The calling principal MUST be obtained from the kernel on the connected
//! > channel. **No field carrying a client-asserted identity exists in the
//! > schema**, in any message, at any version.
//!
//! Look at [`crate::mi::wire::Hello`]: there is no `principal`, no `sid`, no
//! `user`. The only identity in this module comes from the client's token, and
//! there is no function here that takes one from anywhere else.
//!
//! # MI-A4: the impersonation is a read, and it ends before any work
//!
//! > On Windows the server MAY call `ImpersonateNamedPipeClient` only to read
//! > the client's token, and MUST `RevertToSelf` **before** performing any work.
//! > Performing privileged work while impersonating a client is the classic
//! > named-pipe confused deputy.
//!
//! The mechanism is that [`crate::win32::pipe::read_client_principal`] is the
//! only function that impersonates, it returns a plain [`Principal`] — a value
//! with no handle in it — and it reverts on **every** path out, including the
//! error ones. Nothing in this module can be called while impersonating,
//! because nothing in this module is reachable until that function has
//! returned.
//!
//! # MI-A2: the pid is advisory and gates nothing
//!
//! `GetNamedPipeClientProcessId` is read and used **only for the log line**.
//! "Pids are reused; processes can be replaced between the credential read and
//! the lookup", so nothing in [`Principal::scopes`] consults it. An Authenticode
//! check on the image is advisory for the same reason and is not performed.
//!
//! # MI-A5: fail closed on an unverifiable identity
//!
//! > If peer credentials cannot be obtained for any reason, the agent MUST
//! > reject the attach with `MGMT.PRINCIPAL_UNVERIFIABLE` and close. It MUST NOT
//! > fall back to a default principal, a 'local user' assumption, or an
//! > anonymous read-only tier.
//!
//! There is no `unwrap_or_default` on this path and no anonymous tier to fall
//! back to.
//!
//! # ADR-0017's own honest paragraph, which applies here
//!
//! > On Linux, Windows, and the macOS Developer-ID socket variant, **the MI
//! > authenticates a user, not a program.** Any process the authorized user runs
//! > can do everything the GUI can do.
//!
//! That is why `ADMINISTER` is bound to the §11.14 ceremony and why
//! [`Principal::administer_verdict`] refuses a remote session: neither a DACL
//! nor a token check can express "the human at the keyboard meant this".

use twinvpn_mgmt::Scope;

use crate::mi::dacl::PrincipalSids;
use crate::mi::scope::Scopes;

/// `BUILTIN\Administrators`, in full.
///
/// The SDDL abbreviation [`ADMINISTRATORS`] is what a security descriptor
/// carries; a token reports the full SID, and the two are different strings for
/// one principal. Both are named here so a reader can see they are the same.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// Which kind of logon session the client is in.
///
/// **PS-14's discriminator.** ADR-0016 §11.7's HC-1 row: "local interactive
/// action" means a session on the physical console, and `ADMINISTER` from a
/// remote session is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// The physical console seat.
    Console,
    /// An RDP session. PS-14 refuses `ADMINISTER` here.
    Remote,
    /// Session 0 — a service or a scheduled task, with no seat at all.
    Service,
    /// WTS could not say.
    ///
    /// Treated as [`Self::Remote`] for the `ADMINISTER` decision: an
    /// unverifiable seat fails closed, which is MI-A5's direction applied one
    /// level down.
    Unknown,
}

impl SessionKind {
    /// Whether this session satisfies PS-14's "local interactive action".
    #[must_use]
    pub const fn is_console_seat(self) -> bool {
        matches!(self, Self::Console)
    }
}

/// The calling process's kernel-attested identity.
///
/// Every field comes from the token the kernel handed us. There is no
/// constructor that takes a client-supplied value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The user SID.
    pub user_sid: String,
    /// The **enabled** group SIDs in the token.
    ///
    /// Enabled, not merely present: a deny-only or disabled group grants
    /// nothing, and a filtered (non-elevated) administrator token carries
    /// `Administrators` as deny-only. Collapsing the two would grant `mgmt.admin`
    /// to every administrator's ordinary shell.
    pub enabled_group_sids: Vec<String>,
    /// Which session the client is in (PS-14).
    pub session: SessionKind,
    /// The client's pid. **Advisory only** (MI-A2): logged, never gating.
    pub pid: u32,
    /// The account name, where it resolves.
    ///
    /// Used for `actor_principal` (MI-18, PS-13) — "a principal name is
    /// loggable, an authentication secret never is" (PS-23).
    pub account: Option<String>,
}

/// Why an attach could not be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerError {
    /// The client's token could not be read. **MI-A5**: reject and close.
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

/// What §11.14's ceremony would decide, before it is even attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministerVerdict {
    /// The principal holds `mgmt.admin` and is at the console.
    ///
    /// **Still not sufficient**: §11.5's third consequence is that every
    /// `ADMINISTER` operation needs the §11.14 ceremony freshly, per call. This
    /// build has no ceremony, so [`super::server`] refuses regardless — see the
    /// gap list.
    PreconditionsMet,
    /// The token does not carry `Administrators` enabled — an unelevated shell.
    NotElevated,
    /// PS-14: a non-console session.
    RemoteSession,
}

impl AdministerVerdict {
    /// The **registered** code emitted for a refusal.
    #[must_use]
    pub fn reason_code(self) -> Option<&'static str> {
        match self {
            AdministerVerdict::PreconditionsMet => None,
            AdministerVerdict::NotElevated => Some(super::start::emitted_for(
                "PLATFORM.PRIV.CLIENT_UNAUTHORIZED",
            )),
            AdministerVerdict::RemoteSession => Some(super::start::emitted_for(
                "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED",
            )),
        }
    }

    /// The spelling ADR-0016 §11.12 uses.
    #[must_use]
    pub const fn specified_code(self) -> Option<&'static str> {
        match self {
            AdministerVerdict::PreconditionsMet => None,
            AdministerVerdict::NotElevated => Some("PLATFORM.PRIV.CLIENT_UNAUTHORIZED"),
            AdministerVerdict::RemoteSession => Some("PLATFORM.PRIV.REMOTE_ADMIN_REFUSED"),
        }
    }
}

impl Principal {
    /// The scopes this principal holds, per ADR-0016 PS-12a's Windows row.
    ///
    /// | Class | Principal |
    /// |---|---|
    /// | `OBSERVE` | the local group `TwinVPN Users` |
    /// | `OPERATE` | the local group `TwinVPN Operators` |
    /// | `ADMINISTER` | `BUILTIN\Administrators` **enabled** in the token |
    ///
    /// # This is not a TwinVPN decision
    ///
    /// CB-2 forbids a shell branch on a *domain* fact. Group membership is an
    /// **OS** fact, PS-12a assigns its resolution to the authority in terms, and
    /// *which* scope an operation needs comes from the core's own catalogue. The
    /// shell reads an OS fact and hands it to the core's table; it decides
    /// nothing about TwinVPN.
    ///
    /// # PS-12a: the built-in groups are deliberately not used
    ///
    /// `Users` and `Everyone` appear nowhere. "'every local account can
    /// enumerate this device's peers and endpoints' should be an install-time
    /// decision (TB-13), not a platform default." The two groups the package
    /// creates are the principals, and their SIDs are **injected** (CD-2) rather
    /// than resolved here — a shell that looked them up would be deciding which
    /// principals exist.
    ///
    /// `mgmt.disarm` is never here: §11.5 says it is "never granted at attach",
    /// and [`crate::mi::scope::GRANTABLE`] does not contain it either.
    #[must_use]
    pub fn scopes(&self, sids: &PrincipalSids) -> Scopes {
        let mut held = Vec::new();
        let member = |sid: &str| self.enabled_group_sids.iter().any(|s| s == sid);

        // An administrator holds everything an operator does. Written as an
        // inclusion rather than as three independent checks because PS-12's
        // table is a ladder: ADMINISTER contains OPERATE contains OBSERVE.
        let administers = member(ADMINISTRATORS_SID);
        let operates = administers || member(&sids.operate);
        let observes = operates || member(&sids.observe);

        if observes {
            held.push(Scope::Status);
            held.push(Scope::Events);
            held.push(Scope::Diagnostics);
        }
        if operates {
            held.push(Scope::Connect);
            held.push(Scope::Settings);
        }
        if administers {
            held.push(Scope::Admin);
        }
        Scopes::from_scopes(held)
    }

    /// Whether the §11.14 ceremony's preconditions hold.
    ///
    /// PS-14's HC-1 row: `ADMINISTER` from a non-console session is refused,
    /// "and disarm specifically also fires
    /// `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE`".
    ///
    /// The order matters: a remote session is refused **before** elevation is
    /// considered, because an elevated administrator on RDP is exactly the case
    /// PS-14 exists to refuse and telling them "not elevated" would send them to
    /// re-elevate rather than to the console.
    #[must_use]
    pub fn administer_verdict(&self) -> AdministerVerdict {
        if !self.session.is_console_seat() {
            return AdministerVerdict::RemoteSession;
        }
        if self
            .enabled_group_sids
            .iter()
            .any(|s| s == ADMINISTRATORS_SID)
        {
            AdministerVerdict::PreconditionsMet
        } else {
            AdministerVerdict::NotElevated
        }
    }

    /// The value that travels as `actor_principal` (MI-18, PS-13).
    ///
    /// > "the tunnel went down" and "Dana took the tunnel down" are different
    /// > facts.
    ///
    /// The account name where it resolves, and the SID where it does not —
    /// never absent, because "an unattributed state change on a multi-user host
    /// is the 'silent failure' `reliability.md` §10 forbids, wearing local
    /// clothes".
    #[must_use]
    pub fn actor(&self) -> String {
        self.account
            .clone()
            .unwrap_or_else(|| self.user_sid.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mi::dacl::ADMINISTRATORS;

    fn sids() -> PrincipalSids {
        PrincipalSids {
            service: "S-1-5-80-4242".to_owned(),
            observe: "S-1-5-21-1-2-3-1001".to_owned(),
            operate: "S-1-5-21-1-2-3-1002".to_owned(),
        }
    }

    fn principal(groups: &[&str], session: SessionKind) -> Principal {
        Principal {
            user_sid: "S-1-5-21-1-2-3-1050".to_owned(),
            enabled_group_sids: groups.iter().map(|s| (*s).to_owned()).collect(),
            session,
            pid: 4242,
            account: Some("dana".to_owned()),
        }
    }

    #[test]
    fn the_observe_group_holds_exactly_the_three_read_scopes() {
        let scopes = principal(&[&sids().observe], SessionKind::Console).scopes(&sids());
        assert!(scopes.holds(Scope::Status));
        assert!(scopes.holds(Scope::Events));
        assert!(scopes.holds(Scope::Diagnostics));
        assert!(!scopes.holds(Scope::Connect));
        assert!(!scopes.holds(Scope::Settings));
        assert!(!scopes.holds(Scope::Admin));
    }

    #[test]
    fn the_operate_group_contains_observe() {
        // PS-12's table is a ladder, not three independent sets: an operator
        // who could not read status could not check what they had done.
        let scopes = principal(&[&sids().operate], SessionKind::Console).scopes(&sids());
        assert!(scopes.holds(Scope::Status));
        assert!(scopes.holds(Scope::Connect));
        assert!(scopes.holds(Scope::Settings));
        assert!(!scopes.holds(Scope::Admin));
    }

    #[test]
    fn administrators_hold_every_grantable_scope() {
        let scopes = principal(&[ADMINISTRATORS_SID], SessionKind::Console).scopes(&sids());
        for scope in crate::mi::scope::GRANTABLE {
            assert!(scopes.holds(scope), "{}", scope.name());
        }
    }

    #[test]
    fn the_disarm_scope_is_never_granted_at_attach_even_to_an_administrator() {
        // §11.5: "Never granted at attach. Minted per-operation by the OS
        // ceremony (§11.14)."
        let scopes = principal(&[ADMINISTRATORS_SID], SessionKind::Console).scopes(&sids());
        assert!(!scopes.holds(Scope::Disarm));
    }

    #[test]
    fn a_principal_in_no_twinvpn_group_holds_nothing() {
        // PS-12a: the built-in Users group is deliberately NOT the OBSERVE
        // principal, "because 'every local account can enumerate this device's
        // peers and endpoints' should be an install-time decision".
        let scopes = principal(
            &["S-1-5-32-545", "S-1-1-0", "S-1-5-11"],
            SessionKind::Console,
        )
        .scopes(&sids());
        assert!(scopes.names().is_empty());
    }

    #[test]
    fn a_disabled_administrators_group_grants_nothing() {
        // A filtered (non-elevated) administrator token carries Administrators
        // as deny-only. Treating "present" as "enabled" would grant mgmt.admin
        // to every administrator's ordinary shell — which is exactly the UAC
        // boundary §11.14 relies on.
        let unelevated = principal(&[&sids().observe], SessionKind::Console);
        assert!(!unelevated.scopes(&sids()).holds(Scope::Admin));
        assert_eq!(
            unelevated.administer_verdict(),
            AdministerVerdict::NotElevated
        );
    }

    #[test]
    fn ps14_administer_from_a_remote_session_is_refused_by_name() {
        // "`ADMINISTER` from non-console session ⇒
        // `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`."
        let remote = principal(&[ADMINISTRATORS_SID], SessionKind::Remote);
        assert_eq!(
            remote.administer_verdict(),
            AdministerVerdict::RemoteSession
        );
        assert_eq!(
            remote.administer_verdict().specified_code(),
            Some("PLATFORM.PRIV.REMOTE_ADMIN_REFUSED")
        );
    }

    #[test]
    fn a_remote_session_is_refused_before_elevation_is_considered() {
        // Telling an elevated administrator on RDP "not elevated" would send
        // them to re-elevate rather than to the console.
        let elevated_remote = principal(&[ADMINISTRATORS_SID], SessionKind::Remote);
        let unelevated_remote = principal(&[], SessionKind::Remote);
        assert_eq!(
            elevated_remote.administer_verdict(),
            AdministerVerdict::RemoteSession
        );
        assert_eq!(
            unelevated_remote.administer_verdict(),
            AdministerVerdict::RemoteSession
        );
    }

    #[test]
    fn an_unverifiable_session_fails_closed_like_a_remote_one() {
        // MI-A5's direction applied one level down: a seat WTS could not
        // report is not a seat.
        let unknown = principal(&[ADMINISTRATORS_SID], SessionKind::Unknown);
        assert_eq!(
            unknown.administer_verdict(),
            AdministerVerdict::RemoteSession
        );
        assert!(!SessionKind::Unknown.is_console_seat());
        assert!(!SessionKind::Service.is_console_seat());
        assert!(SessionKind::Console.is_console_seat());
    }

    #[test]
    fn the_console_seat_with_an_elevated_token_meets_the_preconditions() {
        assert_eq!(
            principal(&[ADMINISTRATORS_SID], SessionKind::Console).administer_verdict(),
            AdministerVerdict::PreconditionsMet
        );
    }

    #[test]
    fn a_pid_gates_nothing() {
        // MI-A2: "advisory only and MUST NOT gate any scope. Pids are reused."
        let a = principal(&[&sids().operate], SessionKind::Console);
        let b = Principal { pid: 999_999, ..a.clone() };
        assert_eq!(a.scopes(&sids()), b.scopes(&sids()));
        assert_eq!(a.administer_verdict(), b.administer_verdict());
    }

    #[test]
    fn attribution_is_never_absent() {
        // PS-13: "an unattributed state change on a multi-user host is the
        // 'silent failure' reliability.md §10 forbids, wearing local clothes."
        let named = principal(&[], SessionKind::Console);
        assert_eq!(named.actor(), "dana");
        let unnamed = Principal { account: None, ..named };
        assert_eq!(unnamed.actor(), "S-1-5-21-1-2-3-1050");
        assert!(!unnamed.actor().is_empty());
    }

    #[test]
    fn the_sddl_abbreviation_and_the_token_sid_name_one_principal() {
        // `BA` is what a security descriptor carries; `S-1-5-32-544` is what a
        // token reports. Both are named so a reader can see they are the same
        // group and neither is a second definition.
        assert_eq!(ADMINISTRATORS, "BA");
        assert_eq!(ADMINISTRATORS_SID, "S-1-5-32-544");
    }

    #[test]
    fn every_refusal_names_a_registered_code() {
        for verdict in [
            AdministerVerdict::NotElevated,
            AdministerVerdict::RemoteSession,
        ] {
            let code = verdict.reason_code().expect("a refusal names one");
            assert!(
                twinvpn_types::ReasonCode::lookup(code).is_some(),
                "{code} is not registered"
            );
        }
        assert_eq!(AdministerVerdict::PreconditionsMet.reason_code(), None);
    }

    #[test]
    fn an_unverifiable_principal_names_the_registered_code() {
        assert_eq!(
            PeerError::Unverifiable.reason_code(),
            "MGMT.PRINCIPAL_UNVERIFIABLE"
        );
        assert!(twinvpn_types::ReasonCode::lookup("MGMT.PRINCIPAL_UNVERIFIABLE").is_some());
    }
}
