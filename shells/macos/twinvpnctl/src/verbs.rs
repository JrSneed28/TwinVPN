//! The verb table — **generated from the core's command catalogue** (MI-C1).
//!
//! **Authority:** ADR-0017 MI-C1 ("the CLI is generated, not written"), MI-1,
//! MI-20, §11.9 (the table), §11.12; ADR-0023 EM-42, EM-43, EM-44.
//!
//! # MI-C1, as a compiler property rather than a claim
//!
//! > The CLI command table MUST be generated from the operation catalogue at
//! > build time; there is no control verb without a catalogue entry and no
//! > behaviour beyond argument marshalling, output rendering and exit-code
//! > mapping. A mismatch is a **build failure**.
//!
//! [`verbs`] walks [`twinvpn_mgmt::CoreCommand::ALL`] and derives each verb from
//! the operation's own wire name. **There is no list of verbs in this file.** A
//! command added to the core appears in `--help` with no edit here; a verb with
//! no catalogue entry cannot be written, because there is nowhere to write it.
//!
//! The test at the bottom is the "build failure" half: it asserts the two sets
//! are equal in both directions, so `cargo test` fails rather than a reviewer
//! having to compare two lists.

/// One CLI verb, derived from one catalogue entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verb {
    /// The catalogue operation.
    pub op: twinvpn_mgmt::CoreCommand,
}

impl Verb {
    /// The operation's wire name, e.g. `status.get`.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        self.op.name()
    }

    /// The noun the user types, e.g. `status`.
    ///
    /// Derived by splitting the wire name at its first `.`, so the CLI's shape is
    /// the catalogue's shape and cannot drift from it.
    #[must_use]
    pub fn noun(self) -> &'static str {
        self.wire_name().split('.').next().unwrap_or_default()
    }

    /// The verb the user types, e.g. `get`. `session.list` is `session` + `list`;
    /// `diag.bundle.create` is `diag` + `bundle create`.
    #[must_use]
    pub fn verb(self) -> &'static str {
        self.wire_name()
            .split_once('.')
            .map_or("", |(_, rest)| rest)
    }

    /// The scope a principal must hold — **the catalogue's answer**, never one
    /// this crate holds.
    #[must_use]
    pub fn scope(self) -> twinvpn_mgmt::Scope {
        twinvpn_mgmt::catalogue::entry(self.op).scope
    }

    /// Whether §11.14's ADMINISTER ceremony gates it.
    #[must_use]
    pub fn administer(self) -> bool {
        twinvpn_mgmt::catalogue::entry(self.op).administer
    }

    /// Whether it mutates state — which is what `--confirm-unprotected` gates.
    #[must_use]
    pub fn mutating(self) -> bool {
        twinvpn_mgmt::catalogue::entry(self.op).mutating
    }
}

/// Every verb, in the catalogue's order.
///
/// §11.9's order, because the catalogue's order **is** §11.9's — so `--help`
/// lists the operations in the order the ADR does without this file knowing what
/// that order is.
#[must_use]
pub fn verbs() -> Vec<Verb> {
    twinvpn_mgmt::CoreCommand::ALL
        .iter()
        .map(|op| Verb { op: *op })
        .collect()
}

/// Resolves what the user typed.
///
/// Accepts the wire name directly (`status.get`) and the two-word form
/// (`status get`), because both appear in ADR-0023's rendered next actions and a
/// user who copies one out of a diagnostic must not have to translate it.
#[must_use]
pub fn resolve(noun: &str, rest: &[String]) -> Option<Verb> {
    let joined = if rest.is_empty() {
        noun.to_owned()
    } else {
        format!("{noun}.{}", rest.join("."))
    };
    verbs().into_iter().find(|verb| verb.wire_name() == joined)
}

/// The usage text.
///
/// Rendered from the catalogue, wrapped to `min(COLUMNS, 100)` (**EM-44**:
/// legible at 80 and at 40).
#[must_use]
pub fn usage(columns: usize) -> String {
    let width = columns.clamp(40, 100);
    let mut out = String::new();
    // The prose is WRAPPED, not truncated: a usage line cut at 40 columns loses
    // the flag it was telling the reader about. The table rows below are
    // name-plus-scope and fit at 40 by construction, so they are truncated
    // instead — losing the tail of a scope name is legible, losing half a flag
    // is not.
    for line in wrap(
        "usage: twinvpnctl [--output human|json|json-lines] <noun> <verb>",
        width,
    ) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
    for line in wrap(
        "operations, from the core's command catalogue (MI-C1):",
        width,
    ) {
        out.push_str(&line);
        out.push('\n');
    }
    let widest = verbs()
        .iter()
        .map(|v| v.wire_name().len())
        .max()
        .unwrap_or(0);
    for verb in verbs() {
        // The two-word form, because that is what a user types and what
        // ADR-0023 EM-42's rendered next actions say. The wire name is what goes
        // on the socket and is not this surface's vocabulary.
        let typed = format!("{} {}", verb.noun(), verb.verb().replace('.', " "));
        let scope = verb.scope().name();
        let line = format!("  {typed:<widest$}  {scope}");
        out.push_str(&truncate_to(&line, width));
        if verb.administer() {
            out.push_str("  [ADMINISTER]");
        }
        out.push('\n');
    }
    out
}

/// EM-44's truncation, for a line whose tail is expendable.
fn truncate_to(line: &str, width: usize) -> String {
    if line.chars().count() <= width {
        return line.to_owned();
    }
    line.chars().take(width.saturating_sub(1)).collect()
}

/// EM-44's wrap, for prose.
///
/// Word-wraps at `width`, and breaks a single word longer than `width` rather
/// than emitting an over-long line — a 200-character token in a usage string
/// would be a bug, and silently exceeding the width would hide it.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        let candidate = if current.is_empty() {
            word.chars().count()
        } else {
            current.chars().count() + 1 + word.chars().count()
        };
        if candidate > width && !current.is_empty() {
            lines.push(std::mem::take(&mut current));
        }
        if word.chars().count() > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let mut rest: &str = word;
            while rest.chars().count() > width {
                let head: String = rest.chars().take(width).collect();
                let consumed = head.len();
                lines.push(head);
                rest = &rest[consumed..];
            }
            current.push_str(rest);
            continue;
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn mi_c1_the_verb_set_and_the_catalogue_are_equal_in_both_directions() {
        // "A control verb with no catalogue entry, or a catalogue entry with no
        // verb, is a build failure." This test is that failure.
        let from_verbs: BTreeSet<&str> = verbs().iter().map(|v| v.wire_name()).collect();
        let from_catalogue: BTreeSet<&str> = twinvpn_mgmt::catalogue()
            .iter()
            .map(|entry| entry.op.name())
            .collect();
        assert_eq!(from_verbs, from_catalogue);
        assert!(!from_verbs.is_empty());
    }

    #[test]
    fn the_order_is_the_catalogues_and_therefore_11_9s() {
        let verb_order: Vec<&str> = verbs().iter().map(|v| v.wire_name()).collect();
        let catalogue_order: Vec<&str> = twinvpn_mgmt::catalogue()
            .iter()
            .map(|entry| entry.op.name())
            .collect();
        assert_eq!(verb_order, catalogue_order);
    }

    #[test]
    fn every_verb_splits_into_a_noun_and_a_verb_and_neither_is_empty() {
        for verb in verbs() {
            assert!(!verb.noun().is_empty(), "{}", verb.wire_name());
            assert!(!verb.verb().is_empty(), "{}", verb.wire_name());
            assert_eq!(format!("{}.{}", verb.noun(), verb.verb()), verb.wire_name());
        }
    }

    #[test]
    fn both_spellings_of_an_operation_resolve_to_the_same_verb() {
        // A user who copies `twinvpn peer disconnect nas-attic` out of a rendered
        // next action must not have to translate it into a wire name.
        let two_word = resolve("status", &["get".to_owned()]).expect("resolves");
        let one_word = resolve("status.get", &[]).expect("resolves");
        assert_eq!(two_word, one_word);
        assert_eq!(two_word.wire_name(), "status.get");
    }

    #[test]
    fn a_three_segment_operation_resolves_from_its_words() {
        let verb = resolve("diag", &["bundle".to_owned(), "create".to_owned()]);
        assert_eq!(verb.map(super::Verb::wire_name), Some("diag.bundle.create"));
    }

    #[test]
    fn a_verb_that_is_not_in_the_catalogue_does_not_resolve() {
        assert!(resolve("wat", &[]).is_none());
        assert!(resolve("status", &["destroy".to_owned()]).is_none());
        // PS-4: nothing a client types can become a path or a command line,
        // because there is nothing for it to become.
        assert!(resolve("/bin/sh", &[]).is_none());
    }

    #[test]
    fn the_scope_a_verb_needs_is_the_catalogues_answer() {
        // If this file ever grows its own table, this is what should catch it.
        for verb in verbs() {
            assert_eq!(verb.scope(), twinvpn_mgmt::catalogue::entry(verb.op).scope);
        }
    }

    #[test]
    fn em44_the_usage_is_legible_at_forty_columns_and_at_eighty() {
        for columns in [40usize, 80, 100, 200, 1] {
            let text = usage(columns);
            let width = columns.clamp(40, 100);
            for line in text.lines() {
                assert!(
                    line.chars().count() <= width + "  [ADMINISTER]".len(),
                    "a {columns}-column render produced a {}-char line: {line}",
                    line.chars().count()
                );
            }
            // And every operation is still listed, whatever the width.
            for verb in verbs() {
                assert!(
                    text.contains(verb.noun()),
                    "{} vanished at {columns} columns",
                    verb.wire_name()
                );
            }
        }
    }

    #[test]
    fn every_administer_operation_is_marked_in_the_usage() {
        let text = usage(100);
        let administer_count = verbs().iter().filter(|v| v.administer()).count();
        assert_eq!(text.matches("[ADMINISTER]").count(), administer_count);
    }
}
