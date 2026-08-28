//! The privilege posture: read from the service's own token, and **fatal** when
//! it is wrong.
//!
//! **Authority:** [ADR-0016](../../../../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
//! §11.2's Windows row, §11.9's Windows hardening paragraph (verbatim below),
//! PS-11, PS-17, PS-18; ADR-0022 LC-5.
//!
//! # §11.9's Windows row, and the three privileges that are the whole of it
//!
//! > Service SID `NT SERVICE\TwinVPNService`, `SERVICE_SID_TYPE_UNRESTRICTED` ·
//! > `RequiredPrivileges` limited to `SeChangeNotifyPrivilege`,
//! > `SeImpersonatePrivilege` (to authorize pipe clients),
//! > `SeLoadDriverPrivilege` (WinTun), `SeAssignPrimaryTokenPrivilege` **not**
//! > required, `SeDebugPrivilege` and `SeTcbPrivilege` **forbidden**.
//!
//! # The trim is performed by the installer, and verified here
//!
//! `RequiredPrivileges` is a service configuration value: the SCM computes the
//! token from it **before the process starts**, so this process never holds a
//! privilege it was not configured with rather than holding one briefly and
//! dropping it. That is the same arrangement `shells/linux` gets from
//! `AmbientCapabilities=`, and it is the stronger one.
//!
//! What it costs is that the guarantee lives in an installer's registry write,
//! which an administrator can change with `sc.exe privs`. So this module
//! **verifies the posture at start and refuses to continue when it is wrong** —
//! turning "somebody widened the service" from an invisible widening into a
//! startup failure. PS-17's principle: "Silently running wider than declared is
//! the defect this rule retires."
//!
//! # Why LocalSystem, and why not the two smaller accounts
//!
//! §11.2 rejects them by name: `LocalService` and `NetworkService` because
//! "neither can open the WFP engine for write, install a device driver, or
//! program the IP Helper interface stack", and `SERVICE_SID_TYPE_RESTRICTED`
//! because "the WFP engine handle and `SwDevice`-based driver installation
//! require access outside a restricted token's reach".
//!
//! So this service is `LocalSystem`, and "still running as root" — the fatal
//! condition on Linux — is **not** the Windows equivalent. Running as
//! `LocalSystem` is the specified posture. The equivalent failure here is
//! holding a privilege §11.9 forbids, which is what [`Posture::verify`] refuses.

/// A privilege this service must hold, or must not.
///
/// A named list rather than a mask, because the log line has to say **which**
/// one: "reinstall the service with `SeLoadDriverPrivilege`" and "remove
/// `SeDebugPrivilege` from the service configuration" are different
/// instructions to an operator, and PS-18 requires the code to carry the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Privilege(pub &'static str);

/// `SeChangeNotifyPrivilege` — traverse checking. §11.9's first.
pub const SE_CHANGE_NOTIFY: Privilege = Privilege("SeChangeNotifyPrivilege");
/// `SeImpersonatePrivilege` — needed to read a pipe client's token (MI-A4).
pub const SE_IMPERSONATE: Privilege = Privilege("SeImpersonatePrivilege");
/// `SeLoadDriverPrivilege` — needed for Wintun.
pub const SE_LOAD_DRIVER: Privilege = Privilege("SeLoadDriverPrivilege");

/// The three §11.9 permits, in the order the ADR lists them.
pub const REQUIRED_PRIVILEGES: [Privilege; 3] = [SE_CHANGE_NOTIFY, SE_IMPERSONATE, SE_LOAD_DRIVER];

/// The two §11.9 forbids **by name**.
pub const FORBIDDEN_PRIVILEGES: [Privilege; 2] = [
    Privilege("SeDebugPrivilege"),
    Privilege("SeTcbPrivilege"),
];

/// `SeAssignPrimaryTokenPrivilege`: "**not** required".
///
/// Not forbidden either, so holding it is a PS-17 degradation rather than a
/// refusal — the distinction §11.9 draws by using two different words for two
/// different privileges, and one this module keeps rather than flattening.
pub const NOT_REQUIRED: Privilege = Privilege("SeAssignPrimaryTokenPrivilege");

/// One privilege as the token reports it.
///
/// Windows distinguishes **held** from **enabled**: a privilege can be present
/// in the token and disabled, in which case an operation that needs it fails.
/// The distinction is load-bearing here — §11.9's "forbidden" is about what the
/// token can *do*, and a disabled `SeDebugPrivilege` can be enabled by the
/// process holding it at any moment, so holding it at all is the condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPrivilege {
    /// Which one.
    pub privilege: Privilege,
    /// Whether `SE_PRIVILEGE_ENABLED` is set.
    pub enabled: bool,
}

/// The service's own token, reduced to what §11.9 talks about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPrivileges {
    /// Every privilege in the token, held or enabled.
    pub privileges: Vec<TokenPrivilege>,
}

impl TokenPrivileges {
    /// Whether the token carries `privilege` at all.
    #[must_use]
    pub fn holds(&self, privilege: Privilege) -> bool {
        self.privileges.iter().any(|p| p.privilege == privilege)
    }

    /// A token holding exactly the three §11.9 permits, all enabled.
    ///
    /// The posture an installer that followed §11.9 produces, written out so a
    /// test can state the expected case rather than construct it by hand each
    /// time.
    #[must_use]
    pub fn as_specified() -> Self {
        Self {
            privileges: REQUIRED_PRIVILEGES
                .into_iter()
                .map(|privilege| TokenPrivilege {
                    privilege,
                    enabled: true,
                })
                .collect(),
        }
    }
}

/// What this process's privilege actually is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posture {
    /// The token's privileges.
    pub token: TokenPrivileges,
    /// Whether the process is running as `LocalSystem` (`S-1-5-18`).
    ///
    /// §11.2 specifies it, and the two smaller service accounts are rejected by
    /// name — so a `false` here is a service somebody installed under the wrong
    /// account, which will fail at the WFP engine open with a status nobody can
    /// interpret. Refusing at start is the diagnosable version of that.
    pub is_local_system: bool,
    /// Whether the SCM started this process (PS-11).
    pub supervised: bool,
}

/// Why the posture is not the one §11.9 requires.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivilegeError {
    /// A privilege §11.9 forbids by name is in the token.
    #[error("the service holds a privilege §11.9 forbids: {privilege:?}")]
    ForbiddenPrivilege {
        /// Which one.
        privilege: Privilege,
    },
    /// A privilege §11.9 requires is absent.
    ///
    /// **PS-18**: "The authority MUST NOT start in a mode that cannot arm
    /// enforcement while reporting itself as running." Without
    /// `SeLoadDriverPrivilege` there is no Wintun adapter and therefore no
    /// overlay interface for Tier 2 to be scoped to.
    #[error("the service lacks a privilege it needs: {privilege:?}")]
    PrivilegeMissing {
        /// Which one.
        privilege: Privilege,
    },
    /// The service is not running as `LocalSystem`.
    #[error("the service is not running as LocalSystem; §11.2 rejects the alternatives by name")]
    NotLocalSystem,
    /// The token could not be read, so the posture is unknown.
    ///
    /// Refused rather than assumed: an unverifiable posture is the same failure
    /// direction as an unverifiable principal (MI-A5).
    #[error("the privilege posture could not be verified")]
    Unverifiable,
}

impl PrivilegeError {
    /// The **registered** code emitted.
    ///
    /// Every one but the last is a substitution; the pairs and their costs are
    /// in [`super::start::SUBSTITUTIONS`].
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        super::start::emitted_for(self.specified_code())
    }

    /// The spelling ADR-0016 §11.12 uses.
    #[must_use]
    pub const fn specified_code(&self) -> &'static str {
        match self {
            PrivilegeError::ForbiddenPrivilege { .. } | PrivilegeError::NotLocalSystem => {
                "PLATFORM.PRIV.DROP_FAILED"
            }
            PrivilegeError::PrivilegeMissing { .. } => "PLATFORM.PRIV.CAPABILITY_MISSING",
            // Registered, so it is emitted DIRECTLY rather than substituted.
            PrivilegeError::Unverifiable => "PLATFORM.PRIV.SANDBOX_DEGRADED",
        }
    }
}

impl Posture {
    /// Checks the posture against §11.9, in the order the ADR states it.
    ///
    /// # Fatal versus degraded, and why the line is where it is
    ///
    /// §11.9 uses two different words for two different privileges.
    /// `SeDebugPrivilege` and `SeTcbPrivilege` are **forbidden**, so holding
    /// either is fatal — either would let this process act outside the boundary
    /// PS-4 and PS-5 draw, and `SeTcbPrivilege` in particular would let it
    /// construct a token for any principal, which defeats the whole of §11.7's
    /// authorization model.
    ///
    /// `SeAssignPrimaryTokenPrivilege` is **not required**, which is a
    /// different statement: holding it is a §11.9 hardening directive that did
    /// not apply, and PS-17 makes that a `PLATFORM.PRIV.SANDBOX_DEGRADED`
    /// **warning** naming the directive rather than a refusal. See
    /// [`Self::degradations`].
    ///
    /// # Errors
    ///
    /// The first violation. Each is **fatal** at startup.
    pub fn verify(&self) -> Result<(), PrivilegeError> {
        if !self.is_local_system {
            return Err(PrivilegeError::NotLocalSystem);
        }
        for privilege in FORBIDDEN_PRIVILEGES {
            if self.token.holds(privilege) {
                return Err(PrivilegeError::ForbiddenPrivilege { privilege });
            }
        }
        for privilege in REQUIRED_PRIVILEGES {
            if !self.token.holds(privilege) {
                return Err(PrivilegeError::PrivilegeMissing { privilege });
            }
        }
        Ok(())
    }

    /// The §11.9 hardening directives that are **not** in force.
    ///
    /// PS-17: "If any directive in this table fails to apply … the authority
    /// MUST emit `PLATFORM.PRIV.SANDBOX_DEGRADED` at `WARN` **naming the
    /// directive**, and the diagnostic bundle MUST carry the effective posture.
    /// Silently running wider than declared is the defect this rule retires."
    ///
    /// Each entry names the directive an operator would edit, not the privilege
    /// — `sc.exe privs TwinVPNService` is the command, and `RequiredPrivileges`
    /// is the value.
    #[must_use]
    pub fn degradations(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.token.holds(NOT_REQUIRED) {
            out.push("RequiredPrivileges (SeAssignPrimaryTokenPrivilege is not required)");
        }
        // A privilege in the token that is neither required nor named by §11.9
        // is the same class of finding: the trim did not happen.
        let widened = self.token.privileges.iter().any(|held| {
            !REQUIRED_PRIVILEGES.contains(&held.privilege)
                && held.privilege != NOT_REQUIRED
                && !FORBIDDEN_PRIVILEGES.contains(&held.privilege)
        });
        if widened {
            out.push("RequiredPrivileges (the token holds privileges §11.9 does not list)");
        }
        out
    }

    /// Reads this process's actual posture.
    ///
    /// # Errors
    ///
    /// [`PrivilegeError::Unverifiable`] when the token cannot be opened or
    /// queried. An unverifiable posture is refused, never assumed.
    #[cfg(windows)]
    pub fn read() -> Result<Self, PrivilegeError> {
        let token = crate::win32::token::process_privileges()
            .map_err(|()| PrivilegeError::Unverifiable)?;
        Ok(Self {
            token,
            is_local_system: crate::win32::token::running_as_local_system()
                .map_err(|()| PrivilegeError::Unverifiable)?,
            supervised: crate::win32::scm::started_by_scm(),
        })
    }

    /// The non-Windows sibling, present only so this crate compiles and its
    /// decision logic runs on the host it was written on.
    ///
    /// It reports [`PrivilegeError::Unverifiable`], which is the honest answer:
    /// there is no Windows token here to read, and returning a synthetic
    /// "correct" posture would make the verification pass on a machine where it
    /// means nothing.
    #[cfg(not(windows))]
    pub fn read() -> Result<Self, PrivilegeError> {
        Err(PrivilegeError::Unverifiable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(token: TokenPrivileges) -> Posture {
        Posture {
            token,
            is_local_system: true,
            supervised: true,
        }
    }

    fn with(extra: &[Privilege]) -> TokenPrivileges {
        let mut token = TokenPrivileges::as_specified();
        for privilege in extra {
            token.privileges.push(TokenPrivilege {
                privilege: *privilege,
                enabled: true,
            });
        }
        token
    }

    #[test]
    fn the_posture_11_9_specifies_passes() {
        let posture = posture(TokenPrivileges::as_specified());
        posture.verify().expect("the §11.9 posture");
        assert!(posture.degradations().is_empty());
    }

    #[test]
    fn every_privilege_11_9_forbids_is_refused_by_name() {
        // "remove SeDebugPrivilege" and "remove SeTcbPrivilege" are different
        // instructions, so the check names which.
        for privilege in FORBIDDEN_PRIVILEGES {
            let posture = posture(with(&[privilege]));
            assert_eq!(
                posture.verify().expect_err("refused"),
                PrivilegeError::ForbiddenPrivilege { privilege }
            );
            assert_eq!(
                posture.verify().unwrap_err().specified_code(),
                "PLATFORM.PRIV.DROP_FAILED"
            );
        }
    }

    #[test]
    fn a_forbidden_privilege_is_fatal_even_when_it_is_disabled() {
        // A disabled privilege can be enabled by the process holding it at any
        // moment. §11.9's "forbidden" is about what the token CAN do.
        let mut token = TokenPrivileges::as_specified();
        token.privileges.push(TokenPrivilege {
            privilege: FORBIDDEN_PRIVILEGES[0],
            enabled: false,
        });
        assert!(matches!(
            posture(token).verify().expect_err("refused"),
            PrivilegeError::ForbiddenPrivilege { .. }
        ));
    }

    #[test]
    fn every_required_privilege_is_checked_and_named_when_missing() {
        // PS-18: without SeLoadDriverPrivilege there is no Wintun adapter and
        // therefore no interface for Tier 2 to be scoped to.
        for privilege in REQUIRED_PRIVILEGES {
            let mut token = TokenPrivileges::as_specified();
            token.privileges.retain(|p| p.privilege != privilege);
            let posture = posture(token);
            assert_eq!(
                posture.verify().expect_err("refused"),
                PrivilegeError::PrivilegeMissing { privilege }
            );
            assert_eq!(
                posture.verify().unwrap_err().specified_code(),
                "PLATFORM.PRIV.CAPABILITY_MISSING"
            );
        }
    }

    #[test]
    fn a_service_installed_under_the_wrong_account_is_refused_at_start() {
        // §11.2 rejects LocalService and NetworkService by name: neither can
        // open the WFP engine for write. Refusing here is the diagnosable
        // version of a failure that would otherwise surface as an
        // uninterpretable status from FwpmEngineOpen0.
        let posture = Posture {
            is_local_system: false,
            ..posture(TokenPrivileges::as_specified())
        };
        assert_eq!(
            posture.verify().expect_err("refused"),
            PrivilegeError::NotLocalSystem
        );
    }

    #[test]
    fn a_privilege_11_9_calls_not_required_is_a_degradation_and_not_a_refusal() {
        // §11.9 uses two different words for two different privileges, and this
        // is where the distinction is kept rather than flattened.
        let posture = posture(with(&[NOT_REQUIRED]));
        posture.verify().expect("not fatal");
        assert_eq!(
            posture.degradations(),
            vec!["RequiredPrivileges (SeAssignPrimaryTokenPrivilege is not required)"],
            "PS-17 requires the directive to be NAMED"
        );
    }

    #[test]
    fn a_token_that_was_never_trimmed_reports_the_directive_that_did_not_apply() {
        // The common misinstall: a LocalSystem service with no
        // `RequiredPrivileges` value at all, so the SCM hands it the full set.
        let posture = posture(with(&[
            Privilege("SeBackupPrivilege"),
            Privilege("SeRestorePrivilege"),
            Privilege("SeTakeOwnershipPrivilege"),
        ]));
        posture.verify().expect("none of those is forbidden by name");
        assert!(posture
            .degradations()
            .contains(&"RequiredPrivileges (the token holds privileges §11.9 does not list)"));
    }

    #[test]
    fn a_forbidden_privilege_is_never_merely_a_degradation() {
        // The one ordering that matters: a token holding both an unlisted
        // privilege and a forbidden one must be refused, not warned about.
        let posture = posture(with(&[Privilege("SeBackupPrivilege"), FORBIDDEN_PRIVILEGES[1]]));
        assert!(posture.verify().is_err());
    }

    #[test]
    fn an_unverifiable_posture_is_refused_rather_than_assumed() {
        // MI-A5's direction applied to the service's own token. On this host
        // there is no Windows token, so `read` reports exactly that.
        let error = Posture::read().expect_err("no Windows token on this host");
        assert_eq!(error, PrivilegeError::Unverifiable);
        // ...and it names a REGISTERED code directly, not a substitution.
        assert_eq!(error.reason_code(), "PLATFORM.PRIV.SANDBOX_DEGRADED");
        assert_eq!(error.specified_code(), error.reason_code());
    }

    #[test]
    fn every_emitted_code_is_registered() {
        let errors = [
            PrivilegeError::NotLocalSystem,
            PrivilegeError::ForbiddenPrivilege {
                privilege: FORBIDDEN_PRIVILEGES[0],
            },
            PrivilegeError::PrivilegeMissing {
                privilege: SE_LOAD_DRIVER,
            },
            PrivilegeError::Unverifiable,
        ];
        for error in errors {
            assert!(
                twinvpn_types::ReasonCode::lookup(error.reason_code()).is_some(),
                "{} is not registered",
                error.reason_code()
            );
        }
    }

    #[test]
    fn the_three_required_privileges_are_11_9s_and_no_others() {
        // A fourth would be a widening this module performed on its own.
        assert_eq!(REQUIRED_PRIVILEGES.len(), 3);
        assert!(REQUIRED_PRIVILEGES.contains(&SE_CHANGE_NOTIFY));
        assert!(REQUIRED_PRIVILEGES.contains(&SE_IMPERSONATE));
        assert!(REQUIRED_PRIVILEGES.contains(&SE_LOAD_DRIVER));
        assert!(!REQUIRED_PRIVILEGES.contains(&NOT_REQUIRED));
    }
}
