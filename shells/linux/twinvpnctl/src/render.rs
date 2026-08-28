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
    /// # R-15: the resolver renders this, not a table in this file
    ///
    /// An earlier version returned the registry's `summary_key` **verbatim**, so
    /// a diagnostic read `reason.proto_unparseable_envelope.summary` and
    /// `Next: reason.…next_action`. Its stated excuse — that
    /// `tw_render_diagnostic`'s catalogue "is not linked into this binary" — was
    /// simply wrong: `twinvpnctl` depends on `twinvpn-diag`, whose
    /// [`twinvpn_diag::render`] is the very function `tw_render_diagnostic`
    /// wraps.
    ///
    /// The tell that it was a defect rather than a degradation was sharp: an
    /// **unknown** code rendered better than a known one, because the unknown
    /// path fell through to a real English sentence and the known path did not.
    ///
    /// ADR-0019 **R-36** requires the GUI and the CLI to render identically from
    /// **one** resolver. Calling it is what makes that true; the local fallback
    /// was a second renderer that happened to be worse.
    ///
    /// # The resolver's own guarantees, which this no longer duplicates
    ///
    /// [`twinvpn_diag::Resolved::summary`] is "never empty, never an i18n key,
    /// never the raw code (PC-3)", and it handles §11.12's unknown-code
    /// degradation itself — an unregistered code resolves on its **domain**,
    /// with the real attributes where they exist and a conservative set where
    /// they do not. So there is no unknown-code branch in this function.
    ///
    /// # `locale` and `platform` are parameters, never ambient
    ///
    /// CD-2, and LT-3b for the platform: an empty `platform` resolves to the
    /// **neutral** variant and MUST NOT fall back to the host's own. The
    /// platform comes from the agent's `HelloAck` (MI-C3, used verbatim), not
    /// from this process's build constants.
    #[must_use]
    pub fn from_diagnostic(
        state: &str,
        diagnostic: &Diagnostic,
        locale: &str,
        platform: &twinvpn_diag::PlatformContext,
    ) -> Self {
        let token = severity_token(&diagnostic.severity);

        // The typed evidence the agent sent, bound for substitution into the
        // catalogue pattern's named placeholders.
        //
        // The wire carries a JSON object now rather than pairs of strings —
        // MI-15 says *typed* evidence, and stringifying an integer at the wire
        // makes this client parse it back and guess the type. Each JSON scalar
        // maps to the `EvidenceValue` it already is; anything else is rendered
        // as its JSON text, which is what a `{placeholder}` substitution needs.
        let evidence: Vec<twinvpn_diag::Binding> = diagnostic
            .evidence
            .as_object()
            .map(|map| {
                map.iter()
                    .map(|(key, value)| twinvpn_diag::Binding {
                        key: key.clone(),
                        value: match value {
                            serde_json::Value::String(text) => {
                                twinvpn_types::EvidenceValue::Text(text.clone())
                            }
                            serde_json::Value::Number(n) => n.as_i64().map_or_else(
                                || twinvpn_types::EvidenceValue::Text(n.to_string()),
                                twinvpn_types::EvidenceValue::Int,
                            ),
                            other => twinvpn_types::EvidenceValue::Text(other.to_string()),
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();

        let resolved = twinvpn_diag::render(&diagnostic.reason_code, &evidence, locale, platform);

        // Line 4, "present whenever `user_actionable` is true". The resolver's
        // own actionability is preferred over the wire's: MI-14 has the agent
        // resolve at emission, and the two agree unless the client's registry is
        // older — in which case the resolver is the one that knows what THIS
        // build can render.
        // The AGENT's value, not this client's registry. MI-14 makes the agent
        // resolve at emission and the resolved attributes travel with the code,
        // and the agent is the one that saw the condition. A client that
        // overrode it with its own registry would disagree with the GUI beside
        // it the moment the two were built at different times — the exact
        // divergence R-36 exists to prevent.
        let actionable = diagnostic.user_actionable;
        let next_action = match (&resolved.next_action, actionable) {
            (Some(action), true) => Some(format!("Next: {action}")),
            // Actionable with no registered next action: naming the code and its
            // documentation anchor is a next action; inventing a sentence for
            // the condition is not.
            (None, true) => Some(format!(
                "Next: see {} for {}.",
                resolved.attributes.doc_anchor, diagnostic.reason_code
            )),
            (_, false) => None,
        };

        Self {
            state_line: format!("{token} {state}"),
            // "line 2 is the code, **verbatim and never translated**".
            code_line: diagnostic.reason_code.clone(),
            summary_line: resolved.summary,
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

    fn neutral() -> twinvpn_diag::PlatformContext {
        twinvpn_diag::PlatformContext::neutral()
    }

    fn diagnostic(code: &str, severity: &str, actionable: bool) -> Diagnostic {
        // An unregistered-code shape: the four MI-14 attributes the registry
        // would have supplied are empty rather than guessed, which is exactly
        // what the agent emits for a code it cannot resolve.
        Diagnostic {
            reason_code: code.to_owned(),
            class: "POLICY".to_owned(),
            severity: severity.to_owned(),
            terminal: false,
            user_actionable: actionable,
            remediation_class: String::new(),
            scope: String::new(),
            doc_anchor: String::new(),
            summary_key: None,
            next_action_key: None,
            evidence: serde_json::Value::Null,
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
            "en",
            &neutral(),
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
            "en",
            &neutral(),
        );
        assert!(rendered.next_action_line.is_none());
    }

    #[test]
    fn an_unknown_code_degrades_on_its_domain_and_is_never_silent() {
        // §11.12: "never the raw code alone as the primary line, never silence".
        let rendered = Rendered::from_diagnostic(
            "UNKNOWN",
            &diagnostic("MGMT.SOMETHING_NEW", "WARN", false),
            "en",
            &neutral(),
        );
        assert_eq!(rendered.code_line, "MGMT.SOMETHING_NEW");
        // The resolver's own domain rung produces the sentence — this client no
        // longer has a second degradation of its own (R-36: one resolver).
        assert!(is_a_sentence(&rendered.summary_line));
        assert_ne!(rendered.summary_line, "MGMT.SOMETHING_NEW");
    }

    /// **R-15, as the assertion that would have caught it.**
    ///
    /// The tell was that an **unknown** code rendered better than a known one:
    /// the unknown path fell through to a real sentence and the known path
    /// returned `reason.….summary` verbatim. So the test is the comparison.
    #[test]
    fn a_known_code_renders_at_least_as_well_as_an_unknown_one() {
        let known = Rendered::from_diagnostic(
            "BLOCKED",
            &diagnostic("PROTO.UNPARSEABLE_ENVELOPE", "ERROR", true),
            "en",
            &neutral(),
        );
        let unknown = Rendered::from_diagnostic(
            "BLOCKED",
            &diagnostic("PROTO.SOMETHING_NOBODY_SHIPPED", "ERROR", true),
            "en",
            &neutral(),
        );
        assert!(is_a_sentence(&known.summary_line), "{known:?}");
        assert!(is_a_sentence(&unknown.summary_line), "{unknown:?}");
        // And the next action is prose too, on both paths.
        for rendered in [&known, &unknown] {
            let action = rendered
                .next_action_line
                .as_ref()
                .expect("user_actionable, so EM-42 line 4 is present");
            assert!(action.starts_with("Next: "));
            assert!(
                is_a_sentence(action.trim_start_matches("Next: ")),
                "{action:?}"
            );
        }
    }

    /// Whether a line is prose a human can read, rather than an identifier.
    ///
    /// `twinvpn_diag::render`'s own contract for `summary` is "never empty,
    /// never an i18n key, never the raw code (PC-3)" — this is that, checked.
    fn is_a_sentence(line: &str) -> bool {
        // Prose has spaces. An i18n key (`reason.foo.summary`) and a reason code
        // (`PROTO.UNPARSEABLE_ENVELOPE`) are both single tokens, so the space
        // test excludes them both and the further checks below are what tell a
        // reviewer WHICH two shapes are being excluded.
        let has_spaces = line.contains(' ');
        let is_an_i18n_key = line.contains('.') && !has_spaces;
        let is_a_reason_code = line
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '.' || c == '_');
        !line.is_empty() && has_spaces && !is_an_i18n_key && !is_a_reason_code
    }

    #[test]
    fn no_sentence_in_this_module_is_keyed_to_a_specific_reason_code() {
        // MI-15's mechanism: the renderer works from the code's REGISTERED
        // attributes. Two unrelated unknown codes in one domain render the same
        // shape, which is only possible if nothing here is keyed to either.
        let a = Rendered::from_diagnostic(
            "X",
            &diagnostic("DNS.SOMETHING_A", "WARN", false),
            "en",
            &neutral(),
        );
        let b = Rendered::from_diagnostic(
            "X",
            &diagnostic("DNS.SOMETHING_B", "WARN", false),
            "en",
            &neutral(),
        );
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
            "en",
            &neutral(),
        );
        let lines = rendered.to_lines(80);
        assert!(lines.len() >= 4);
        assert!(!lines[0].starts_with(' '));
        for line in &lines[1..] {
            assert!(line.starts_with("       "), "seven columns: {line:?}");
        }
    }
}
