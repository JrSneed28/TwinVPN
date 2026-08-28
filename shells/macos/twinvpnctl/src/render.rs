//! Rendering, and the exit-code mapping.
//!
//! **Authority:** ADR-0017 §11.12 (the exit codes, and the prohibition on 64+),
//! MI-15 (no rendered text on the wire — so rendering happens *here*), MI-C2;
//! ADR-0023 EM-37 (retry policy is driven by `Diagnostic.class`, not by the exit
//! code), EM-38 (it never prompts), EM-43 (colour and UTF-8 conditions), EM-44.
//!
//! # Why rendering is the CLI's and not the agent's
//!
//! MI-15 keeps every rendered human string off the wire: the agent sends
//! `(reason_code, class, evidence)` and the surface that has a locale and a
//! viewport turns it into a sentence. This module is that surface. It is also why
//! a `summary` field on the wire would be a defect rather than a convenience —
//! two clients would render the same condition differently and one of them would
//! be stale.
//!
//! # EM-37: the class and the exit code are different questions
//!
//! > Automation switches on `class`, not on the exit code.
//!
//! So the `reason_code` and its class go to **stderr in every output mode**,
//! including `--output json`, "so a `set -e` script that does not parse JSON
//! still gets it".

/// ADR-0017 §11.12's exit codes.
///
/// A closed enum, so 64+ is not expressible. §11.12 prohibits it to avoid
/// colliding with `sysexits.h` and with the shell's own 124/125/126/127 and
/// 128+n conventions, and an `i32` would have made the prohibition a review item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The operation succeeded.
    Succeeded,
    /// It failed for a reason the agent named.
    Failed,
    /// Usage error — bad arguments or unknown subcommand. **Nothing was sent to
    /// the agent.**
    Usage,
    /// The management channel is unavailable. Distinct from [`Exit::Failed`],
    /// because "the service isn't running" and "the operation was refused" demand
    /// different automation responses.
    ChannelUnavailable,
    /// Authorization refused. Distinct so a script can tell "re-run with
    /// privilege" from "this will never work".
    Unauthorized,
    /// Version incompatible. Distinct so an installer or a post-install script
    /// can act.
    VersionIncompatible,
}

impl Exit {
    /// The process exit status.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Exit::Succeeded => 0,
            Exit::Failed => 1,
            Exit::Usage => 2,
            Exit::ChannelUnavailable => 3,
            Exit::Unauthorized => 4,
            Exit::VersionIncompatible => 5,
        }
    }

    /// Every code §11.12 defines, in order. Walked by the test that pins the
    /// range, and by nothing else — the range is the property, not the list, so
    /// this exists for the test and is compiled only for it.
    #[cfg(test)]
    pub const ALL: [Self; 6] = [
        Self::Succeeded,
        Self::Failed,
        Self::Usage,
        Self::ChannelUnavailable,
        Self::Unauthorized,
        Self::VersionIncompatible,
    ];
}

/// What this terminal can render. **EM-43**, as a value rather than as four
/// environment lookups scattered through the renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Whether colour may be used.
    pub colour: bool,
    /// Whether UTF-8 glyphs may be used.
    pub utf8: bool,
}

impl Style {
    /// Reads the environment once.
    ///
    /// Deliberately conservative: `is_tty` is passed in rather than probed,
    /// because `isatty` needs `unsafe` and this crate forbids it — and because a
    /// caller that knows it is writing to a pipe should be able to say so.
    #[must_use]
    pub fn from_env(is_tty: bool) -> Self {
        Self {
            colour: colour_allowed(
                is_tty,
                std::env::var_os("NO_COLOR").is_some(),
                std::env::var("TERM").ok().as_deref(),
            ),
            utf8: utf8_allowed(
                std::env::var("LANG").ok().as_deref(),
                std::env::var("LC_ALL").ok().as_deref(),
            ),
        }
    }

    /// The marker a failure line carries.
    ///
    /// Two renderings, both correct: the renderer is fully legible in US-ASCII,
    /// so this chooses between two right answers rather than between a good one
    /// and a broken one.
    #[must_use]
    pub const fn failure_marker(self) -> &'static str {
        if self.utf8 {
            "\u{2717}"
        } else {
            "x"
        }
    }
}

/// The output shapes §11.6 and MI-C2 name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Output {
    /// For a person.
    #[default]
    Human,
    /// One JSON document.
    Json,
    /// One JSON document per line.
    JsonLines,
}

impl Output {
    /// Parses `--output`'s argument.
    ///
    /// # Errors
    ///
    /// `None` for a value this build does not know — which the caller turns into
    /// [`Exit::Usage`], **without sending anything to the agent**.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "human" => Some(Self::Human),
            "json" => Some(Self::Json),
            "json-lines" => Some(Self::JsonLines),
            _ => None,
        }
    }
}

/// Whether colour may be used.
///
/// **EM-43**, all three conditions: a TTY **and** `NO_COLOR` unset **and** a
/// colour-capable `TERM`. Any one of them failing means no colour, which is why
/// this is an `&&` chain and not a preference.
#[must_use]
pub fn colour_allowed(is_tty: bool, no_color_set: bool, term: Option<&str>) -> bool {
    is_tty && !no_color_set && term.is_some_and(|t| !t.is_empty() && t != "dumb")
}

/// Whether UTF-8 glyphs may be used.
///
/// **EM-43**: only where `LANG` or `LC_ALL` indicates UTF-8. The renderer is
/// fully legible in US-ASCII, so this chooses between two correct renderings
/// rather than between a good one and a broken one.
#[must_use]
pub fn utf8_allowed(lang: Option<&str>, lc_all: Option<&str>) -> bool {
    [lc_all, lang]
        .into_iter()
        .flatten()
        .any(|value| value.to_ascii_uppercase().contains("UTF-8"))
}

/// The width to wrap to. **EM-44**: `min(COLUMNS, 100)`, legible at 80 and at 40.
#[must_use]
pub fn wrap_width(columns: Option<usize>) -> usize {
    columns.unwrap_or(80).clamp(40, 100)
}

/// The line that goes to **stderr in every output mode**.
///
/// EM-37: "so a `set -e` script that does not parse JSON still gets it". The
/// class travels with the code because automation switches on the class, and
/// re-deriving it from a registry the client may have an older copy of is how two
/// versions disagree about whether to retry.
#[must_use]
pub fn stderr_line(reason_code: &str, class: &str) -> String {
    format!("{reason_code} class={class}")
}

/// Renders a successful result.
#[must_use]
// `Json` and `JsonLines` render one document identically; they differ only when a
// caller emits several, which this surface does not yet do. Written out rather
// than merged so the day a streaming operation lands, the arm to change is
// already there.
#[allow(clippy::match_same_arms)]
pub fn render_ok(output: Output, result: &[u8]) -> String {
    match output {
        Output::Human => {
            if result.is_empty() {
                "ok\n".to_owned()
            } else {
                format!("{}\n", String::from_utf8_lossy(result))
            }
        }
        Output::Json => format!(
            "{}\n",
            serde_json::json!({ "ok": true, "result": String::from_utf8_lossy(result) })
        ),
        Output::JsonLines => format!(
            "{}\n",
            serde_json::json!({ "ok": true, "result": String::from_utf8_lossy(result) })
        ),
    }
}

/// Renders a refusal.
///
/// **Never invents a sentence for a code it does not know.** The registry's
/// `summary_key` and `next_action_key` are identifiers, and a client that made up
/// prose for an unknown code would be telling a user something nobody wrote.
#[must_use]
pub fn render_error(output: Output, style: Style, reason_code: &str, class: &str) -> String {
    match output {
        Output::Human => format!("{} failed: {reason_code}\n", style.failure_marker()),
        Output::Json | Output::JsonLines => format!(
            "{}\n",
            serde_json::json!({ "ok": false, "reason_code": reason_code, "class": class })
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_codes_are_11_12s_and_64_is_not_expressible() {
        assert_eq!(Exit::Succeeded.code(), 0);
        assert_eq!(Exit::Failed.code(), 1);
        assert_eq!(Exit::Usage.code(), 2);
        assert_eq!(Exit::ChannelUnavailable.code(), 3);
        assert_eq!(Exit::Unauthorized.code(), 4);
        assert_eq!(Exit::VersionIncompatible.code(), 5);
        for exit in Exit::ALL {
            assert!(
                (0..=5).contains(&exit.code()),
                "{exit:?} is outside §11.12's range"
            );
        }
        // The prohibition is a type property: there is no variant for 64+, so a
        // future edit that wanted one would have to add it, which is a diff.
        assert_eq!(Exit::ALL.len(), 6);
    }

    #[test]
    fn an_unknown_output_mode_is_a_usage_error_and_nothing_is_sent() {
        // §11.12's exit 2: "**Nothing was sent to the agent**". The parse happens
        // before any connection, which is what makes that true.
        assert_eq!(Output::parse("yaml"), None);
        assert_eq!(Output::parse(""), None);
        assert_eq!(Output::parse("human"), Some(Output::Human));
        assert_eq!(Output::parse("json"), Some(Output::Json));
        assert_eq!(Output::parse("json-lines"), Some(Output::JsonLines));
    }

    #[test]
    fn em43_colour_needs_all_three_conditions_and_any_one_denies_it() {
        assert!(colour_allowed(true, false, Some("xterm-256color")));
        assert!(!colour_allowed(false, false, Some("xterm-256color")));
        assert!(!colour_allowed(true, true, Some("xterm-256color")));
        assert!(!colour_allowed(true, false, Some("dumb")));
        assert!(!colour_allowed(true, false, None));
        assert!(!colour_allowed(true, false, Some("")));
    }

    #[test]
    fn em43_utf8_glyphs_need_a_locale_that_says_so() {
        assert!(utf8_allowed(Some("en_US.UTF-8"), None));
        assert!(utf8_allowed(None, Some("C.utf-8")));
        assert!(!utf8_allowed(Some("C"), Some("POSIX")));
        assert!(!utf8_allowed(None, None));
    }

    #[test]
    fn em44_the_wrap_is_legible_at_forty_and_at_eighty() {
        assert_eq!(wrap_width(None), 80);
        assert_eq!(wrap_width(Some(40)), 40);
        assert_eq!(wrap_width(Some(10)), 40, "never narrower than legible");
        assert_eq!(wrap_width(Some(200)), 100, "never wider than 100");
        assert_eq!(wrap_width(Some(100)), 100);
    }

    #[test]
    fn em37_the_reason_code_and_its_class_reach_stderr_in_every_output_mode() {
        // "so a `set -e` script that does not parse JSON still gets it".
        let line = stderr_line("MGMT.UNAVAILABLE", "TRANSIENT");
        assert!(line.contains("MGMT.UNAVAILABLE"));
        assert!(line.contains("TRANSIENT"));
        // And the JSON body carries it too, so a parser does not need stderr.
        let style = Style {
            colour: false,
            utf8: false,
        };
        for output in [Output::Json, Output::JsonLines] {
            let body = render_error(output, style, "MGMT.UNAVAILABLE", "TRANSIENT");
            assert!(body.contains("MGMT.UNAVAILABLE"));
            assert!(body.contains("TRANSIENT"));
        }
    }

    #[test]
    fn no_rendered_sentence_is_invented_for_a_code_this_build_does_not_know() {
        // MI-15 keeps prose off the wire; the corollary is that a client must not
        // manufacture it. An unknown code renders as itself.
        let ascii = Style {
            colour: false,
            utf8: false,
        };
        let human = render_error(Output::Human, ascii, "MGMT.SOMETHING_NEW", "PERSISTENT");
        // Both renderings are legible, and neither invents prose.
        let unicode = Style {
            colour: false,
            utf8: true,
        };
        let glyphed = render_error(Output::Human, unicode, "MGMT.SOMETHING_NEW", "PERSISTENT");
        assert!(glyphed.contains("MGMT.SOMETHING_NEW"));
        assert_ne!(ascii.failure_marker(), unicode.failure_marker());
        assert!(human.contains("MGMT.SOMETHING_NEW"));
        assert!(!human.contains("unknown error"));
        assert!(!human.contains("please"));
    }

    #[test]
    fn a_successful_result_renders_in_every_mode() {
        for output in [Output::Human, Output::Json, Output::JsonLines] {
            let rendered = render_ok(output, b"");
            assert!(rendered.ends_with('\n'));
            assert!(!rendered.is_empty());
        }
        assert!(render_ok(Output::Json, b"x").contains("\"ok\":true"));
    }
}
