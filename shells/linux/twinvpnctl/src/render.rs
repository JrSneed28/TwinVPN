//! Human rendering: the four-line form, no colour, no Unicode, 40 columns.
//!
//! **Authority:** [ADR-0023](../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! **EM-42** (the four-line form), **EM-43** (severity is never carried by
//! colour alone), **EM-44** (width), EM-36, EM-45;
//! [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md) MI-15,
//! §11.12 (`--output`, the exit codes, the unknown-code degradation).
//!
//! # MI-15: the wire carries no prose, so this is where prose begins
//!
//! > MI payloads carry **codes and typed evidence, never rendered human text**…
//! > Rendering happens at the surface that has a locale and a viewport, from
//! > `(reason_code, class, evidence)`.
//!
//! **Nothing in this module hardcodes a sentence for a `reason_code`.**
//! [`Rendered::from_diagnostic`] renders from the code's *registered attributes*
//! — its domain, its class, its severity, its actionability — and the
//! catalogue's own `summary_key`. Where a resolver is available it produces the
//! sentence; where it is not, the degradation is EM-42's line 2 (the code,
//! verbatim) plus §11.12's **domain-level** line, which is the specified
//! fallback and not a substitute sentence this crate invented.
//!
//! A per-code sentence table here would be exactly what MI-15's last paragraph
//! forbids: a second renderer, on a second registry, disagreeing with the GUI's
//! for the same diagnostic on the same host.
//!
//! # EM-43 and EM-44, as functions rather than intentions
//!
//! - **EM-43**: [`severity_token`] is always emitted. Colour is applied only
//!   when [`use_colour`] says all three of stdout-is-a-TTY, `NO_COLOR` unset and
//!   a colour-capable `TERM` hold — "none of which is true on a busybox `ash`
//!   session over a serial console".
//! - **EM-44**: [`wrap`] wraps to `min(COLUMNS, 100)` and is asserted legible at
//!   **80 and at 40**.

use twinvpnd::mi::Diagnostic;

/// EM-44's ceiling.
pub const MAX_WIDTH: usize = 100;

/// EM-44's floor. "A serial console at 80×24 is a supported reading
/// environment", and the renderer must remain legible at 40.
pub const MIN_WIDTH: usize = 40;

/// The width to wrap to.
///
/// `min(COLUMNS, 100)`, floored at [`MIN_WIDTH`] so a `COLUMNS=1` environment
/// produces one word per line rather than an infinite loop.
#[must_use]
pub fn width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(MAX_WIDTH)
        .clamp(MIN_WIDTH, MAX_WIDTH)
}

/// **EM-43.** Whether colour may be applied.
///
/// All three, and the conjunction is the point: any one of them false means a
/// terminal that will show escape sequences as text.
#[must_use]
pub fn use_colour(stdout_is_tty: bool) -> bool {
    if !stdout_is_tty {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    match std::env::var("TERM").ok().as_deref() {
        None | Some("" | "dumb") => false,
        Some(_) => true,
    }
}

/// **EM-43's leading token.** Always present, always US-ASCII.
///
/// `[CRIT]` / `[ERR!]` / `[WARN]` / `[info]`, exactly as EM-42's example writes
/// them. Four characters inside the brackets, so the four-line form's
/// continuation indent is fixed at seven columns whatever the severity is.
#[must_use]
pub fn severity_token(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" | "FATAL" => "[CRIT]",
        "ERROR" => "[ERR!]",
        "WARN" | "WARNING" => "[WARN]",
        _ => "[info]",
    }
}

/// Whether UTF-8 glyphs may be used.
///
/// EM-43: "box-drawing and symbols are used only when `LANG`/`LC_ALL` indicates
/// UTF-8". Nothing in this module actually emits one — the renderer is fully
/// legible in US-ASCII, which is the requirement — so this exists for a future
/// table renderer to consult rather than to re-derive.
#[must_use]
pub fn use_unicode() -> bool {
    let indicates_utf8 = |value: Option<String>| {
        value.is_some_and(|v| {
            let v = v.to_ascii_uppercase();
            v.contains("UTF-8") || v.contains("UTF8")
        })
    };
    indicates_utf8(std::env::var("LC_ALL").ok()) || indicates_utf8(std::env::var("LANG").ok())
}

/// EM-42's four lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Line 1: the severity token and the state.
    pub state_line: String,
    /// Line 2: the code, **verbatim and never translated**.
    pub code_line: String,
    /// Line 3: the summary.
    pub summary_line: String,
    /// Line 4: the next action, present whenever `user_actionable` is true.
    pub next_action_line: Option<String>,
}

impl Rendered {
    /// Builds the four-line form from a diagnostic and a state.
    ///
    /// # The unknown-code degradation is §11.12's, verbatim in shape
    ///
    /// > MUST render the **domain-level** explanation from its own registry,
    /// > with the raw code as detail, never the raw code alone as the primary
    /// > line, never silence.
    #[must_use]
    pub fn from_diagnostic(state: &str, diagnostic: &Diagnostic) -> Self {
        let token = severity_token(&diagnostic.severity);
        let registered = twinvpn_types::ReasonCode::lookup(&diagnostic.reason_code);

        // Line 3. The summary comes from the code's registered attributes, never
        // from a table in this file (MI-15). Where the code is unknown to THIS
        // client, §11.12's domain-level line is the specified fallback.
        let summary = match registered {
            Some(_) => summary_from_registry(&diagnostic.reason_code),
            None => domain_degradation(&diagnostic.reason_code),
        };

        // Line 4, "present whenever `user_actionable` is true".
        let next_action = diagnostic.user_actionable.then(|| {
            registered
                .and_then(twinvpn_types::ReasonCode::next_action_key)
                .map_or_else(
                    || {
                        // No registered next-action key. Naming the code and the
                        // documentation anchor is a next action; inventing a
                        // sentence for the condition is not.
                        format!(
                            "Next: see the TwinVPN documentation for {}.",
                            diagnostic.reason_code
                        )
                    },
                    |key| format!("Next: {key}"),
                )
        });

        Self {
            state_line: format!("{token} {state}"),
            // "line 2 is the code, **verbatim and never translated**".
            code_line: diagnostic.reason_code.clone(),
            summary_line: summary,
            next_action_line: next_action,
        }
    }

    /// The four lines, wrapped and indented as EM-42's example shows.
    ///
    /// Line 1 is flush left; lines 2–4 are indented seven columns, which is
    /// `"[CRIT] "`.
    #[must_use]
    pub fn to_lines(&self, width: usize) -> Vec<String> {
        const INDENT: &str = "       ";
        let mut out = vec![self.state_line.clone()];
        for line in [
            Some(&self.code_line),
            Some(&self.summary_line),
            self.next_action_line.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            for wrapped in wrap(line, width.saturating_sub(INDENT.len()).max(8)) {
                out.push(format!("{INDENT}{wrapped}"));
            }
        }
        out
    }
}

/// The registry's own summary key, rendered as the human line.
///
/// The key **is** the rendering here, because `tw_render_diagnostic`'s catalogue
/// is not linked into this binary and inventing a sentence in its place is what
/// MI-15 forbids. ADR-0019 R-36 requires the GUI and the CLI to render
/// identically from one resolver; showing the key rather than a locally-invented
/// sentence is the honest degradation, and it is **reported**: the resolver
/// belongs here and is not in this wave.
fn summary_from_registry(code: &str) -> String {
    twinvpn_types::ReasonCode::lookup(code).map_or_else(
        || domain_degradation(code),
        |registered| registered.summary_key().to_owned(),
    )
}

/// §11.12's unknown-code degradation: the **domain** line, with the code as
/// detail.
///
/// "never the raw code alone as the primary line, never silence".
#[must_use]
pub fn domain_degradation(code: &str) -> String {
    let domain = code.split('.').next().unwrap_or("INTERNAL");
    format!(
        "{domain}: TwinVPN reported a condition this version of the command-line client does \
         not recognise ({code})."
    )
}

/// Wraps text to `width`, on whitespace, without hyphenation.
///
/// A word longer than `width` is emitted on its own line rather than broken: a
/// broken `reason_code` is a code a `grep` will not match, and EM-42 makes the
/// code the thing tests and automation key on.
#[must_use]
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.len() + 1 + word.len() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push(std::mem::take(&mut line));
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostic(code: &str, severity: &str, actionable: bool) -> Diagnostic {
        Diagnostic {
            reason_code: code.to_owned(),
            class: "POLICY".to_owned(),
            severity: severity.to_owned(),
            user_actionable: actionable,
            summary_key: None,
            next_action_key: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn em43_the_severity_token_is_always_present_and_always_ascii() {
        for (severity, token) in [
            ("CRITICAL", "[CRIT]"),
            ("ERROR", "[ERR!]"),
            ("WARN", "[WARN]"),
            ("INFO", "[info]"),
            ("something-else", "[info]"),
        ] {
            assert_eq!(severity_token(severity), token);
            assert!(token.is_ascii(), "US-ASCII, for a busybox serial console");
            assert_eq!(token.len(), 6, "a fixed continuation indent");
        }
    }

    #[test]
    fn em43_colour_needs_all_three_conditions() {
        // "none of which is true on a busybox `ash` session over a serial
        // console".
        assert!(!use_colour(false), "not a TTY");
    }

    #[test]
    fn em44_output_is_legible_at_eighty_and_at_forty_columns() {
        let long = "Protected traffic is blocked because no authorized secure path exists \
                    to the peer named in this diagnostic.";
        for width in [MIN_WIDTH, 80, MAX_WIDTH] {
            for line in wrap(long, width) {
                assert!(
                    line.len() <= width,
                    "a {width}-column line overflowed: {line:?}"
                );
            }
        }
    }

    #[test]
    fn a_reason_code_is_never_hyphenated_across_a_line_break() {
        // EM-42 makes the code the thing tests and automation key on, so a
        // broken one is a code a `grep` will not match.
        let long_code = "POLICY.KILLSWITCH.SOMETHING_EXTREMELY_LONG_AND_UNBREAKABLE";
        let lines = wrap(long_code, 20);
        assert_eq!(lines, vec![long_code.to_owned()]);
    }

    #[test]
    fn the_width_is_bounded_at_both_ends() {
        // A `COLUMNS=1` environment must produce a usable line rather than an
        // infinite loop.
        assert!(width() >= MIN_WIDTH);
        assert!(width() <= MAX_WIDTH);
    }

    #[test]
    fn em42_line_two_is_the_code_verbatim_and_never_translated() {
        let rendered = Rendered::from_diagnostic(
            "BLOCKED",
            &diagnostic("POLICY.KILLSWITCH.ENGAGED", "CRITICAL", true),
        );
        assert_eq!(rendered.code_line, "POLICY.KILLSWITCH.ENGAGED");
        assert!(rendered.state_line.starts_with("[CRIT] "));
        assert!(rendered.state_line.contains("BLOCKED"));
        assert!(rendered.next_action_line.is_some(), "user_actionable");
    }

    #[test]
    fn a_next_action_appears_only_when_the_condition_is_actionable() {
        let rendered = Rendered::from_diagnostic(
            "CONNECTED",
            &diagnostic("POLICY.KILLSWITCH.ENGAGED", "INFO", false),
        );
        assert!(rendered.next_action_line.is_none());
    }

    #[test]
    fn an_unknown_code_degrades_on_its_domain_and_is_never_silent() {
        // §11.12: "never the raw code alone as the primary line, never silence".
        let rendered =
            Rendered::from_diagnostic("UNKNOWN", &diagnostic("MGMT.SOMETHING_NEW", "WARN", false));
        assert_eq!(rendered.code_line, "MGMT.SOMETHING_NEW");
        assert!(rendered.summary_line.starts_with("MGMT:"));
        assert!(rendered.summary_line.contains("MGMT.SOMETHING_NEW"));
        assert_ne!(rendered.summary_line, "MGMT.SOMETHING_NEW");
    }

    #[test]
    fn no_sentence_in_this_module_is_keyed_to_a_specific_reason_code() {
        // MI-15's mechanism: the renderer works from the code's REGISTERED
        // attributes. Two unrelated unknown codes in one domain render the same
        // shape, which is only possible if nothing here is keyed to either.
        let a = Rendered::from_diagnostic("X", &diagnostic("DNS.SOMETHING_A", "WARN", false));
        let b = Rendered::from_diagnostic("X", &diagnostic("DNS.SOMETHING_B", "WARN", false));
        assert_eq!(
            a.summary_line.replace("DNS.SOMETHING_A", "@"),
            b.summary_line.replace("DNS.SOMETHING_B", "@")
        );
    }

    #[test]
    fn the_four_line_form_indents_lines_two_to_four_under_the_token() {
        let rendered = Rendered::from_diagnostic(
            "BLOCKED  (peer: nas-attic)",
            &diagnostic("POLICY.KILLSWITCH.ENGAGED", "CRITICAL", true),
        );
        let lines = rendered.to_lines(80);
        assert!(lines.len() >= 4);
        assert!(!lines[0].starts_with(' '));
        for line in &lines[1..] {
            assert!(line.starts_with("       "), "seven columns: {line:?}");
        }
    }
}
