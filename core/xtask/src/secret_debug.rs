//! R-9 — no derived `Debug` on a secret-bearing type.
//!
//! `docs/implementation/ownership.md` R-9 found nine secret-bearing types
//! rendering their secret through a derived `Debug` — a store record's
//! plaintext, a relay token's octets, a server's private key — and one
//! tripwire that "passed because `Vec<u8>` renders as digits". The live cases
//! got hand-written, redacting `Debug` impls, and the row's disposition
//! recommended "one source-scanning lint" so the derive cannot come back
//! unnoticed. This is that lint. It runs over the core workspace, which is the
//! crate set `xtask lint` is defined over; the `services/` workspaces are not
//! scanned here.
//!
//! # What marks a type secret-bearing
//!
//! R-9 names no marker, so the check recognises two, and this file is where
//! the second is documented:
//!
//! 1. the type derives `Zeroize` or `ZeroizeOnDrop`. A type that scrubs
//!    itself on drop has already declared that its bytes must not escape, and
//!    a `Debug` that prints them is the escape;
//! 2. the attribute-comment `// twinvpn: secret`, on a line of its own,
//!    anywhere between the previous item and this one — among the doc
//!    comments and attributes above the `struct`, `enum` or `union`. This is
//!    the convention for a type whose erasure is hand-written
//!    (`impl ZeroizeOnDrop for …`) or absent:
//!
//!    ```text
//!    /// The pre-shared key.
//!    // twinvpn: secret
//!    #[derive(Clone)]
//!    pub struct Psk(Vec<u8>);
//!    ```
//!
//! # The only way out
//!
//! There is no allow-list and no `#[allow]`. The type gets a hand-written
//! `impl Debug` that renders lengths, kinds and identifiers and not the bytes —
//! the style `twinvpn_store::Record` uses, where `value_len` stands in for the
//! plaintext. Rust forbids deriving and implementing the same trait, so the
//! redacting impl *is* the opt-out: once it exists the derive is gone, and
//! the check has nothing to say.
//!
//! # How it reads the source
//!
//! Textually, like CD-3, over the comment-blanked copy: every cluster of
//! stacked outer attributes is read as one unit, so `#[derive(Debug)]` over
//! `#[derive(ZeroizeOnDrop)]` is caught, and so is a test-only
//! `#[cfg_attr(test, derive(Debug))]` — a secret in test output is still a
//! secret in a log. Prose that mentions `derive(Debug)` cannot fire it. The
//! marker is a comment, so it alone is read from the original text.

use crate::checks::Violation;
use crate::source::ScannedFile;

/// The attribute-comment that marks a type secret-bearing when nothing in its
/// derive list does. Must be the whole of its line, trimmed.
pub const R9_MARKER: &str = "// twinvpn: secret";

/// The derives that already declare a type secret-bearing.
pub const R9_SECRET_DERIVES: &[&str] = &["Zeroize", "ZeroizeOnDrop"];

/// Runs R-9 over one file.
#[must_use]
pub fn r9(file: &ScannedFile) -> Vec<Violation> {
    let src = file.blanked.as_str();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = src[cursor..].find("#[") {
        let cluster_start = cursor + found;
        // Walk the whole cluster of stacked outer attributes.
        let mut cluster_end = cluster_start;
        loop {
            let Some(end) = attribute_end(src, cluster_end) else {
                // An unterminated attribute: nothing after it reads as code.
                return out;
            };
            cluster_end = end;
            let next = skip_whitespace(src, cluster_end);
            if src[next..].starts_with("#[") {
                cluster_end = next;
            } else {
                break;
            }
        }
        cursor = cluster_end;

        let head = skip_whitespace(src, cluster_end);
        let Some(item) = item_name(&src[head..]) else {
            continue;
        };
        let cluster = &src[cluster_start..cluster_end];
        let Some(debug_at) = derive_of(cluster, "Debug") else {
            continue;
        };

        let zeroizes = R9_SECRET_DERIVES
            .iter()
            .any(|d| derive_of(cluster, d).is_some());
        // The marker is a comment, blanked in `src`, so it is read from the
        // original text of the same span: from the last code byte before the
        // cluster to the item head.
        let span_start = src[..cluster_start].trim_end().len();
        let marked = file
            .original
            .get(span_start..head)
            .is_some_and(|span| span.lines().any(|l| l.trim() == R9_MARKER));
        let why = if zeroizes {
            "it derives Zeroize or ZeroizeOnDrop"
        } else if marked {
            "it is marked `// twinvpn: secret`"
        } else {
            continue;
        };

        let at = cluster_start + debug_at;
        out.push(Violation {
            rule: "R-9",
            location: format!("{}:{}", file.path, file.line_of(at)),
            detail: format!(
                "`{item}` derives `Debug` but is secret-bearing ({why}); write a redacting \
                 `impl Debug` that renders lengths and identifiers, not the bytes"
            ),
        });
    }
    out
}

/// The offset just past the `]` closing the attribute that opens at `at`.
fn attribute_end(src: &str, at: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, b) in src.bytes().enumerate().skip(at + 1) {
        match b {
            b'[' => depth += 1,
            b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn skip_whitespace(src: &str, at: usize) -> usize {
    src.len() - src[at..].trim_start().len()
}

/// The name of the `struct`, `enum` or `union` whose declaration begins at the
/// start of `rest`, after an optional visibility; `None` for anything else.
fn item_name(rest: &str) -> Option<&str> {
    let mut rest = rest;
    if let Some(after) = rest.strip_prefix("pub") {
        if after.starts_with(|c: char| c.is_whitespace() || c == '(') {
            rest = after.trim_start();
            if rest.starts_with('(') {
                rest = rest[rest.find(')')? + 1..].trim_start();
            }
        }
    }
    for keyword in ["struct", "enum", "union"] {
        let Some(after) = rest.strip_prefix(keyword) else {
            continue;
        };
        if !after.starts_with(char::is_whitespace) {
            continue;
        }
        let after = after.trim_start();
        let len = after
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        if len > 0 {
            return Some(&after[..len]);
        }
    }
    None
}

/// The offset of the first `derive(…)` in `cluster` whose list names `trait_`,
/// with or without a path prefix.
fn derive_of(cluster: &str, trait_: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(found) = cluster[from..].find("derive(") {
        let at = from + found;
        let list_start = at + "derive(".len();
        from = list_start;
        // `derive(` as a token, not the tail of some other identifier.
        let glued = at > 0
            && cluster
                .as_bytes()
                .get(at - 1)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if glued {
            continue;
        }
        let list = &cluster[list_start..paren_end(cluster, list_start)];
        if list
            .split(',')
            .map(str::trim)
            .any(|t| t.rsplit("::").next() == Some(trait_))
        {
            return Some(at);
        }
    }
    None
}

/// The offset of the `)` matching the `(` just before `at`, or the end.
fn paren_end(src: &str, at: usize) -> usize {
    let mut depth = 1usize;
    for (i, b) in src.bytes().enumerate().skip(at) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    src.len()
}
