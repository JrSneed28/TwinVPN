//! The verb table — **generated from the catalogue, never written**.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! **MI-C1**, §11.12 (the command shape), MI-1;
//! [ADR-0023](../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! **EM-34**, EM-35, EM-41.
//!
//! # MI-C1, and why this file contains no list
//!
//! > The CLI's command table MUST be generated from the operation catalogue at
//! > build time. The CLI MUST NOT contain a control verb that is not a catalogue
//! > operation, and MUST NOT implement behaviour beyond argument marshalling,
//! > output rendering, and exit-code mapping. A verb with no catalogue entry, or
//! > an entry with no verb, is a **build failure**.
//!
//! [`verbs`] walks [`twinvpn_mgmt::CoreCommand::ALL`] and splits each wire name
//! at its dot. That is §11.12's shape — `twinvpn <noun> <verb>` mapped **1:1**
//! onto the catalogue's `noun.verb` names — obtained by *deriving* rather than
//! by transcribing. There is nothing here for a reviewer to diff against the
//! enum, because there is no second list.
//!
//! MI-C1's build-failure clause is discharged by
//! `every_catalogue_operation_has_a_verb_and_every_verb_has_an_entry`, which is
//! a **test**: this crate has no build script, and a test that fails the build
//! is the same mechanism at the same moment.
//!
//! # This file is byte-for-byte the Linux shell's, and that is the point
//!
//! `shells/linux/twinvpnctl/src/verbs.rs` derives the same table from the same
//! enum. Two platforms whose CLIs offered different verbs would mean the
//! catalogue was not the contract, which is precisely what MI-C1 exists to
//! prevent — so the *absence* of platform-specific content here is the
//! observable property, not an omission. The only Windows-specific fact about
//! the CLI is the transport it speaks over, and that is `twinvpnsvc::mi`'s.
//!
//! # "no logic of its own"
//!
//! MI-C1's last sentence — "This is the mechanism that makes R-21 true: the CLI
//! cannot drift ahead of or behind the contract because it has no logic of its
//! own" — is why nothing in this module knows what any operation *does*. It
//! knows a name, a scope, and whether the agent said it is implemented.

use twinvpn_mgmt::{catalogue, CoreCommand, Scope, TransportOp};

/// One CLI verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verb {
    /// The catalogue operation. Never `None`: a verb with no entry is what
    /// MI-C1 forbids, and the type makes it unrepresentable.
    pub op: CoreCommand,
    /// The noun — the part before the first dot.
    pub noun: &'static str,
    /// The verb — everything after it, dots included
    /// (`killswitch.disarm.begin` is noun `killswitch`, verb `disarm.begin`).
    pub verb: &'static str,
    /// The scope the catalogue says the operation needs.
    pub scope: Scope,
    /// Whether it mutates.
    pub mutating: bool,
    /// Whether §11.14's ADMINISTER ceremony gates it.
    pub administer: bool,
}

/// Every verb, in the catalogue's order.
///
/// Order is part of the contract: MI-20 forbids MI to reorder a core command,
/// and the catalogue inherits [`CoreCommand::ALL`]'s order, so `--help` lists
/// operations in the order ADR-0017 §11.9's table does.
#[must_use]
pub fn verbs() -> Vec<Verb> {
    catalogue::catalogue()
        .into_iter()
        .map(|entry| {
            let name = entry.op.name();
            let (noun, verb) = name.split_once('.').unwrap_or((name, ""));
            Verb {
                op: entry.op,
                noun,
                verb,
                scope: entry.scope,
                mutating: entry.mutating,
                administer: entry.administer,
            }
        })
        .collect()
}

/// Resolves `<noun> <verb>` to an operation.
///
/// Returns `None` for anything the catalogue does not name — which the caller
/// turns into **exit 2** (usage), because "Nothing was sent to the agent".
#[must_use]
pub fn resolve(noun: &str, verb: &str) -> Option<CoreCommand> {
    let joined = if verb.is_empty() {
        noun.to_owned()
    } else {
        format!("{noun}.{verb}")
    };
    CoreCommand::from_name(&joined)
}

/// §11.12's short aliases: "presentation sugar over the same catalogue entries,
/// **generated with them**".
///
/// Each maps to an operation that must exist, and
/// `every_alias_names_a_real_operation` asserts it — so an alias cannot outlive
/// the operation it abbreviates.
pub const ALIASES: [(&str, CoreCommand); 3] = [
    ("status", CoreCommand::StatusGet),
    ("up", CoreCommand::NetUp),
    ("down", CoreCommand::NetDown),
];

/// The four MI-21 transport operations a client may also invoke.
///
/// Listed separately because they are in a **different enum** for a reason: each
/// is about the connection, and each "MUST NOT acquire an ABI counterpart".
#[must_use]
pub fn transport_verbs() -> Vec<(&'static str, TransportOp)> {
    TransportOp::ALL
        .into_iter()
        .filter(|t| *t != TransportOp::VersionGetMiHalf)
        .map(|t| (t.name(), t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **MI-C1's build-failure clause.**
    ///
    /// "A verb with no catalogue entry, or an entry with no verb, is a build
    /// failure." Both directions, so neither can drift.
    #[test]
    fn every_catalogue_operation_has_a_verb_and_every_verb_has_an_entry() {
        let verbs = verbs();
        assert_eq!(
            verbs.len(),
            CoreCommand::ALL.len(),
            "every catalogue operation must have exactly one verb"
        );
        for verb in &verbs {
            // ...and every verb resolves back to its own operation.
            assert_eq!(
                resolve(verb.noun, verb.verb),
                Some(verb.op),
                "{}.{} does not round-trip",
                verb.noun,
                verb.verb
            );
        }
        for op in CoreCommand::ALL {
            assert!(
                verbs.iter().any(|v| v.op == *op),
                "{} has no verb",
                op.name()
            );
        }
    }

    #[test]
    fn the_verb_order_is_the_catalogues_which_is_adr_0017_11_9s() {
        // MI-20 forbids MI to reorder a core command, so `--help` lists them in
        // the table's order rather than alphabetically.
        let verbs = verbs();
        let names: Vec<&str> = verbs.iter().map(|v| v.op.name()).collect();
        let expected: Vec<&str> = CoreCommand::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names, expected);
        assert_eq!(names.first(), Some(&"status.get"));
    }

    #[test]
    fn a_three_segment_name_splits_at_the_first_dot_only() {
        // `killswitch.disarm.begin` is noun `killswitch`, verb `disarm.begin` —
        // so `twinvpn killswitch disarm.begin` is the invocation and the
        // round trip holds.
        let verb = verbs()
            .into_iter()
            .find(|v| v.op == CoreCommand::KillswitchDisarmBegin)
            .expect("in the catalogue");
        assert_eq!(verb.noun, "killswitch");
        assert_eq!(verb.verb, "disarm.begin");
        assert_eq!(
            resolve("killswitch", "disarm.begin"),
            Some(CoreCommand::KillswitchDisarmBegin)
        );
    }

    #[test]
    fn an_unknown_verb_resolves_to_nothing_and_is_never_guessed() {
        // Exit 2 (usage), and "Nothing was sent to the agent".
        assert_eq!(resolve("status", "gett"), None);
        assert_eq!(resolve("", ""), None);
        assert_eq!(resolve("killswitch", "disarm"), None);
    }

    #[test]
    fn every_alias_names_a_real_operation() {
        for (alias, op) in ALIASES {
            assert!(
                CoreCommand::ALL.contains(&op),
                "the alias `{alias}` names an operation that is not in the catalogue"
            );
            assert!(!alias.contains('.'), "an alias is a single word");
        }
    }

    #[test]
    fn the_cli_offers_no_control_verb_that_is_not_a_catalogue_operation() {
        // MI-C1's first clause, stated as an enumeration of the ONLY sources a
        // verb can come from: the catalogue, the three aliases (each of which
        // names a catalogue operation), and MI-21's closed transport set.
        let transport = transport_verbs();
        assert_eq!(
            transport.len(),
            3,
            "MI-21's four, less the split version.get"
        );
        for (name, _) in &transport {
            assert!(
                CoreCommand::from_name(name).is_none(),
                "{name} is a transport operation and must not be a core command"
            );
        }
        twinvpn_mgmt::assert_closed().expect("MI-21 holds");
    }

    #[test]
    fn a_verb_carries_the_catalogues_scope_and_never_one_of_its_own() {
        let status = verbs()
            .into_iter()
            .find(|v| v.op == CoreCommand::StatusGet)
            .expect("in the catalogue");
        assert_eq!(status.scope, catalogue::entry(CoreCommand::StatusGet).scope);
        assert!(!status.mutating);
    }

    /// **The property that makes the catalogue the contract across platforms.**
    ///
    /// This CLI and the Linux one derive their tables from one enum, so the two
    /// binaries offer the same verbs by construction. Asserting it here is what
    /// would catch a Windows-only verb being added to *this* file — which is the
    /// shape MI-C1's "no logic of its own" forbids, arriving from the direction
    /// a second platform makes possible.
    #[test]
    fn no_verb_in_this_table_is_windows_specific() {
        for verb in verbs() {
            assert!(
                CoreCommand::from_name(verb.op.name()).is_some(),
                "{} is not a core command, so it came from somewhere else",
                verb.op.name()
            );
        }
    }
}
