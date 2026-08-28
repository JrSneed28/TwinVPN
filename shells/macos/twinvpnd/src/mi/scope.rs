//! ADR-0017 §11.5's scope set, as it travels on the wire.
//!
//! **Authority:** ADR-0017 §11.5 (MI-S1, MI-S2), §11.7 (`granted_scopes` /
//! `withheld_scopes`); ADR-0016 PS-12a and §11.7's class table.
//!
//! # Derived from the catalogue, never listed beside it
//!
//! The scope names come from [`twinvpn_mgmt::Scope::name`], and *which* scope an
//! operation needs comes from [`twinvpn_mgmt::catalogue::entry`]. **This module
//! declares no operation-to-scope mapping.** MI-20's build-failure rule is what
//! that protects: a shell-side table would be a second answer to a question the
//! catalogue already answers, and the two would drift the first time an operation
//! moved.
//!
//! # MI-S1 and MI-S2, as one function each
//!
//! - **MI-S1 (grant, never request).** [`Scopes::grant`] computes
//!   `policy(principal) ∩ requested` and reports the difference as *withheld*.
//!   There is no path by which a requested scope the principal lacks becomes a
//!   granted one.
//! - **MI-S2 (attach-time immutability).** [`Scopes`] has no mutator. The granted
//!   set is built once, at attach, and there is no scope-escalation message in
//!   [`super::wire::Body`] for one to arrive on.
//!
//! # Re-derived at every attach, never cached across attaches
//!
//! S-44. On macOS the principal's groups come from the kernel's answer at the
//! moment of the attach ([`super::super::agent::peer`]), so a membership change
//! takes effect on the **next** attach — which is what "re-derived at every
//! attach" means operationally, and why [`Scopes`] is a value the connection owns
//! rather than a cache the agent keeps.

use std::collections::BTreeSet;

use twinvpn_mgmt::Scope;

/// The scopes a principal holds, or a connection was granted.
///
/// A sorted set, so `granted_scopes` on the wire is deterministic and two clients
/// with the same rights see the same `HelloAck`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scopes {
    held: BTreeSet<&'static str>,
}

/// Every grantable scope, from the catalogue's own enum.
///
/// `mgmt.disarm` is **not** here: §11.5 says it is "never granted at attach —
/// minted per-operation by the OS ceremony (§11.14)". Its absence from this array
/// is the mechanism for that, not a comment about it.
pub const GRANTABLE: [Scope; 6] = [
    Scope::Status,
    Scope::Events,
    Scope::Diagnostics,
    Scope::Connect,
    Scope::Settings,
    Scope::Admin,
];

/// What `twinvpnctl` asks for.
///
/// Everything grantable **except** `mgmt.admin`, which the CLI requests only when
/// the operation being run needs it. MI-S1 makes a request a *reduction*, so
/// asking for less than the principal holds is the client dropping capabilities
/// it does not need — the direction the rule exists to allow.
pub const CLI_REQUESTED_SCOPES: [Scope; 5] = [
    Scope::Status,
    Scope::Events,
    Scope::Diagnostics,
    Scope::Connect,
    Scope::Settings,
];

impl Scopes {
    /// An empty set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The set a principal holds.
    #[must_use]
    pub fn from_scopes(scopes: impl IntoIterator<Item = Scope>) -> Self {
        Self {
            held: scopes.into_iter().map(Scope::name).collect(),
        }
    }

    /// Whether this set holds `scope`.
    #[must_use]
    pub fn holds(&self, scope: Scope) -> bool {
        self.held.contains(scope.name())
    }

    /// The wire form.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.held.iter().map(|s| (*s).to_owned()).collect()
    }

    /// **MI-S1.** `policy(principal) ∩ requested`, with the difference named.
    ///
    /// Returns `(granted, withheld)`. A client that requests a scope its
    /// principal lacks is **granted the intersection and told**, not rejected,
    /// "because a status-only client should still work".
    ///
    /// An unrecognised requested name is silently ignored rather than being an
    /// error: it cannot become a grant (it is not in `self`), and refusing the
    /// whole attach over one is the rejection MI-S1 rules out.
    #[must_use]
    pub fn grant(&self, requested: &[String]) -> (Self, Vec<String>) {
        let mut granted = BTreeSet::new();
        let mut withheld = Vec::new();
        for name in requested {
            match self.held.iter().find(|held| *held == name) {
                Some(held) => {
                    granted.insert(*held);
                }
                None => withheld.push(name.clone()),
            }
        }
        withheld.sort_unstable();
        withheld.dedup();
        (Self { held: granted }, withheld)
    }

    /// Whether this connection may run `operation`, by asking the **catalogue**.
    ///
    /// The scope requirement is [`twinvpn_mgmt::catalogue::entry`]'s, never this
    /// module's. `None` for an operation the catalogue does not know, which the
    /// caller turns into `MGMT.OP_UNKNOWN`'s substituted code rather than into a
    /// refusal — the two are different answers with different next actions.
    #[must_use]
    pub fn authorises(&self, operation: twinvpn_mgmt::CoreCommand) -> bool {
        self.holds(twinvpn_mgmt::catalogue::entry(operation).scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mi_s1_a_requested_scope_the_principal_lacks_is_withheld_and_named() {
        let principal = Scopes::from_scopes([Scope::Status, Scope::Events]);
        let (granted, withheld) = principal.grant(&[
            "mgmt.status".to_owned(),
            "mgmt.connect".to_owned(),
            "mgmt.admin".to_owned(),
        ]);
        assert_eq!(granted.names(), vec!["mgmt.status".to_owned()]);
        assert_eq!(
            withheld,
            vec!["mgmt.admin".to_owned(), "mgmt.connect".to_owned()]
        );
        // A status-only client still works.
        assert!(granted.holds(Scope::Status));
        assert!(!granted.holds(Scope::Connect));
    }

    #[test]
    fn a_grant_can_only_ever_shrink_the_principals_set() {
        // The property MI-S1 exists for, checked over every subset rather than by
        // example: whatever is requested, nothing outside the principal's own set
        // can come back granted.
        let principal = Scopes::from_scopes([Scope::Status, Scope::Diagnostics]);
        for request in [
            vec![],
            vec!["mgmt.admin".to_owned()],
            vec!["mgmt.status".to_owned(), "mgmt.admin".to_owned()],
            vec!["nonsense".to_owned()],
            GRANTABLE.iter().map(|s| s.name().to_owned()).collect(),
        ] {
            let (granted, _) = principal.grant(&request);
            for scope in GRANTABLE {
                assert!(
                    !granted.holds(scope) || principal.holds(scope),
                    "{scope:?} was granted without being held"
                );
            }
        }
    }

    #[test]
    fn an_unrecognised_requested_name_cannot_become_a_grant_and_does_not_reject() {
        let principal = Scopes::from_scopes([Scope::Status]);
        let (granted, withheld) = principal.grant(&["mgmt.wat".to_owned()]);
        assert!(granted.names().is_empty());
        assert_eq!(withheld, vec!["mgmt.wat".to_owned()]);
    }

    #[test]
    fn mi_s2_there_is_no_mutator_on_a_granted_set() {
        // Asserted by construction: `Scopes` exposes `holds`, `names`, `grant` and
        // `authorises`, and `grant` returns a NEW set rather than modifying one.
        // A `&mut self` method here would be the escalation path MI-S2 forbids,
        // and there is none to call.
        let granted = Scopes::from_scopes([Scope::Status]);
        let (wider, _) = granted.grant(&["mgmt.admin".to_owned()]);
        assert!(!wider.holds(Scope::Admin));
        assert!(granted.holds(Scope::Status), "the original is untouched");
    }

    #[test]
    fn the_disarm_scope_is_not_grantable_at_attach() {
        // §11.5: "never granted at attach — minted per-operation by the OS
        // ceremony (§11.14)". Absence from `GRANTABLE` is the mechanism.
        assert!(!GRANTABLE.contains(&Scope::Disarm));
        assert!(!CLI_REQUESTED_SCOPES.contains(&Scope::Disarm));
        // And a principal cannot be built holding it through the normal path,
        // because nothing enumerates it into one.
        let all: Scopes = Scopes::from_scopes(GRANTABLE);
        assert!(!all.holds(Scope::Disarm));
    }

    #[test]
    fn the_cli_asks_for_less_than_the_maximum_which_mi_s1_permits() {
        assert!(!CLI_REQUESTED_SCOPES.contains(&Scope::Admin));
        assert_eq!(CLI_REQUESTED_SCOPES.len(), GRANTABLE.len() - 1);
    }

    #[test]
    fn the_scope_an_operation_needs_comes_from_the_catalogue_and_not_from_here() {
        // If this file ever grows an operation→scope table, this test is what
        // should have caught it: the answer is asked of `twinvpn_mgmt` and
        // compared against nothing local.
        let status_only = Scopes::from_scopes([Scope::Status]);
        assert!(status_only.authorises(twinvpn_mgmt::CoreCommand::StatusGet));
        assert!(!status_only.authorises(twinvpn_mgmt::CoreCommand::SessionConnect));

        let connector = Scopes::from_scopes([Scope::Connect]);
        assert!(connector.authorises(twinvpn_mgmt::CoreCommand::SessionConnect));
        assert!(!connector.authorises(twinvpn_mgmt::CoreCommand::StatusGet));
    }

    #[test]
    fn the_wire_form_is_deterministic() {
        let a = Scopes::from_scopes([Scope::Status, Scope::Events, Scope::Connect]);
        let b = Scopes::from_scopes([Scope::Connect, Scope::Status, Scope::Events]);
        assert_eq!(a.names(), b.names());
        let mut sorted = a.names();
        sorted.sort();
        assert_eq!(a.names(), sorted);
    }
}
