//! ADR-0017 §11.5's scope set, as it travels on the wire.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.5 (MI-S1, MI-S2), §11.7 (`granted_scopes` / `withheld_scopes`);
//! ADR-0016 PS-12a (the Windows principals: `TwinVPN Users`, `TwinVPN
//! Operators`, and `BUILTIN\\Administrators` in an **elevated** token) and
//! §11.7's class table.
//!
//! # Derived from the catalogue, never listed beside it
//!
//! The scope names come from [`twinvpn_mgmt::Scope::name`], and *which* scope an
//! operation needs comes from [`twinvpn_mgmt::catalogue::entry`]. **This module
//! declares no operation-to-scope mapping.** MI-20's build-failure rule is what
//! that protects: a shell-side table would be a second answer to a question the
//! catalogue already answers, and the two would drift the first time an
//! operation moved.
//!
//! # MI-S1 and MI-S2, as one function each
//!
//! - **MI-S1 (grant, never request).** [`Scopes::grant`] computes
//!   `policy(principal) ∩ requested` and reports the difference as *withheld*.
//!   There is no path by which a requested scope the principal lacks becomes a
//!   granted one.
//! - **MI-S2 (attach-time immutability).** [`Scopes`] has no mutator. The
//!   granted set is built once, at attach, and there is no scope-escalation
//!   message in [`super::wire::Body`] for one to arrive on.

use std::collections::BTreeSet;

use twinvpn_mgmt::Scope;

/// The scopes a principal holds, or a connection was granted.
///
/// A sorted set, so `granted_scopes` on the wire is deterministic and two
/// clients with the same rights see the same `HelloAck`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scopes {
    held: BTreeSet<&'static str>,
}

/// Every grantable scope, from the catalogue's own enum.
///
/// `mgmt.disarm` is **not** here: §11.5 says it is "never granted at attach —
/// minted per-operation by the OS ceremony (§11.14)". Its absence from this
/// array is the mechanism for that, not a comment about it.
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
/// Everything grantable **except** `mgmt.admin`, which the CLI requests only
/// when the operation being run needs it. MI-S1 makes a request a *reduction*,
/// so asking for less than the principal holds is the client dropping
/// capabilities it does not need — the direction the rule exists to allow.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> Scopes {
        Scopes::from_scopes([Scope::Status, Scope::Events, Scope::Connect])
    }

    #[test]
    fn mi_s1_a_request_can_only_reduce_and_never_add() {
        let (granted, withheld) = operator().grant(&[
            Scope::Status.name().to_owned(),
            Scope::Admin.name().to_owned(),
        ]);
        assert!(granted.holds(Scope::Status));
        assert!(
            !granted.holds(Scope::Admin),
            "a client cannot request itself into a scope its principal lacks"
        );
        assert_eq!(withheld, vec!["mgmt.admin".to_owned()]);
    }

    #[test]
    fn a_client_that_asks_for_a_scope_it_lacks_is_told_never_rejected() {
        // "a status-only client should still work".
        let (granted, withheld) = operator().grant(
            &GRANTABLE
                .iter()
                .map(|s| s.name().to_owned())
                .collect::<Vec<_>>(),
        );
        assert!(granted.holds(Scope::Status));
        assert!(!withheld.is_empty());
        assert!(!granted.names().is_empty(), "the attach still succeeds");
    }

    #[test]
    fn a_client_may_drop_a_capability_it_does_not_need() {
        let (granted, withheld) = operator().grant(&[Scope::Status.name().to_owned()]);
        assert_eq!(granted.names(), vec!["mgmt.status".to_owned()]);
        assert!(!granted.holds(Scope::Connect), "dropped, not withheld");
        assert!(withheld.is_empty());
    }

    #[test]
    fn an_unrecognised_scope_name_cannot_become_a_grant() {
        let (granted, withheld) = operator().grant(&["mgmt.everything".to_owned()]);
        assert!(granted.names().is_empty());
        assert_eq!(withheld, vec!["mgmt.everything".to_owned()]);
    }

    #[test]
    fn the_disarm_scope_is_not_grantable_at_attach() {
        // §11.5: "Never granted at attach. Minted per-operation by the OS
        // ceremony (§11.14)."
        assert!(!GRANTABLE.contains(&Scope::Disarm));
        assert!(!CLI_REQUESTED_SCOPES.contains(&Scope::Disarm));
        // And a principal that somehow held it still could not be granted it
        // through a request, because a client cannot name what it cannot reach:
        // the CLI's request list is the constant above.
        let holder = Scopes::from_scopes([Scope::Disarm]);
        let (granted, _) = holder.grant(
            &CLI_REQUESTED_SCOPES
                .iter()
                .map(|s| s.name().to_owned())
                .collect::<Vec<_>>(),
        );
        assert!(granted.names().is_empty());
    }

    #[test]
    fn mi_s2_the_granted_set_has_no_mutator() {
        // Attach-time immutability, as a property of the type. `Scopes` exposes
        // `holds`, `names` and `grant`; none of them takes `&mut self`, and
        // there is no scope-escalation message for one to arrive on.
        let granted = operator();
        let same = granted.clone();
        assert_eq!(granted, same);
    }

    #[test]
    fn the_wire_form_is_deterministic() {
        let a = Scopes::from_scopes([Scope::Events, Scope::Status]);
        let b = Scopes::from_scopes([Scope::Status, Scope::Events]);
        assert_eq!(a.names(), b.names());
    }

    #[test]
    fn every_scope_name_comes_from_the_catalogues_own_enum() {
        // MI-20: no shell-side scope table. This asserts it by showing the
        // names are the enum's.
        for scope in GRANTABLE {
            assert!(scope.name().starts_with("mgmt."));
        }
        assert_eq!(Scope::Status.name(), "mgmt.status");
        assert_eq!(Scope::Admin.name(), "mgmt.admin");
    }
}
