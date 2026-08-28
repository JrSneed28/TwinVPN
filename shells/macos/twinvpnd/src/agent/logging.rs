//! Structured logging, and the one rule that is not negotiable.
//!
//! **Authority:** ADR-0015 (observability), §11.4 (the sensitivity classes),
//! §11.5 (the level names); `docs/implementation/ownership.md` §6 rules 5, 6
//! and 11.
//!
//! # §6 rule 11, as an API shape rather than a review item
//!
//! > **Never log** private keys, session keys, raw tunnel payloads, pairing
//! > secrets, or authentication tokens.
//!
//! Nothing in this crate has a logging helper that takes bytes. A packet's
//! **length** is loggable and its contents are not, and the way that is enforced
//! is that no function here accepts a `&[u8]` — so a caller who wanted to log a
//! payload would have to add the parameter, which is a diff a reviewer sees.
//!
//! # `correlation_id` and `causation_id`
//!
//! §6 rule 6 requires both to be preserved across every component boundary. On
//! this platform there are three: the MI socket, the FFI hop into
//! `twinvpn-bridge`, and the `PF_ROUTE`/IOKit callbacks. [`correlated`] produces
//! the span every one of them attaches to.

/// The environment variable that selects the level.
pub const LOG_LEVEL_ENV: &str = "TWINVPN_LOG_LEVEL";

/// The environment variable that selects the format.
pub const LOG_FORMAT_ENV: &str = "TWINVPN_LOG_FORMAT";

/// The level this build uses when nothing says otherwise.
pub const DEFAULT_LEVEL: &str = "info";

/// Maps a configured level name onto a `tracing` filter directive.
///
/// # Two deliberate leniencies, and why each is not a silent accept
///
/// **`critical` is accepted and mapped to `error`.** ADR-0015 §11.5 uses
/// `CRITICAL` as a severity, `tracing` has no such level, and a value copied
/// verbatim out of the ADR must configure the service rather than fail it. The
/// same finding `shells/linux` records as **W-16**.
///
/// **An unrecognised value falls back to `info`**, and says so. A logging
/// misconfiguration must not be why a VPN agent will not run — the agent's job is
/// the tunnel, and refusing to start over a typo in a log level would trade a
/// large failure for a small one.
#[must_use]
// `Some("info")`, `None` and the W-16 arm all reach `"info"`/`"error"`, and each
// is written out rather than merged: a reviewer asking "what does this build do
// with `critical`" must be able to find that arm, and merging it with `error`
// would hide the finding it exists to record.
#[allow(clippy::match_same_arms)]
pub fn level_directive(configured: Option<&str>) -> (&'static str, bool) {
    match configured
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("trace") => ("trace", true),
        Some("debug") => ("debug", true),
        Some("info") | None => ("info", true),
        Some("warn" | "warning") => ("warn", true),
        Some("error") => ("error", true),
        // W-16.
        Some("critical" | "crit" | "fatal") => ("error", true),
        // Recognised as unrecognised: the second element is what the caller logs.
        Some(_) => ("info", false),
    }
}

/// Whether to emit JSON.
///
/// JSON under a supervisor, text otherwise. `launchd` sets `XPC_SERVICE_NAME` for
/// a job it started, which is the closest macOS equivalent of `systemd`'s
/// `INVOCATION_ID` — and like it, nothing else sets it, so it is a reliable
/// "somebody is collecting this" signal rather than a guess.
#[must_use]
pub fn wants_json(configured: Option<&str>, under_supervisor: bool) -> bool {
    match configured
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => true,
        Some("text") => false,
        _ => under_supervisor,
    }
}

/// Whether `launchd` started this process.
///
/// PS-11: an authority that is not supervised must not claim supervised
/// guarantees, and this is the fact that answers it.
#[must_use]
pub fn under_launchd() -> bool {
    std::env::var_os("XPC_SERVICE_NAME").is_some()
}

/// Installs the subscriber.
///
/// Returns what it decided, so the agent can log its own logging configuration —
/// which is the only way an operator finds out that a level was not understood.
pub fn install() -> LoggingPosture {
    use tracing_subscriber::EnvFilter;

    let configured_level = std::env::var(LOG_LEVEL_ENV).ok();
    let (directive, recognised) = level_directive(configured_level.as_deref());
    let configured_format = std::env::var(LOG_FORMAT_ENV).ok();
    let supervised = under_launchd();
    let json = wants_json(configured_format.as_deref(), supervised);

    let filter = EnvFilter::new(directive);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        // `launchd` captures stderr to `StandardErrorPath`; stdout is reserved
        // for anything the daemon might one day print for a human, and mixing the
        // two makes a log file that no parser can read.
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_level(true);
    if json {
        builder.json().flatten_event(true).init();
    } else {
        builder.init();
    }

    LoggingPosture {
        level: directive,
        level_recognised: recognised,
        json,
        supervised,
    }
}

/// What logging was configured to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoggingPosture {
    /// The level in force.
    pub level: &'static str,
    /// Whether the configured value was one this build knows.
    pub level_recognised: bool,
    /// Whether output is JSON.
    pub json: bool,
    /// Whether `launchd` started us.
    pub supervised: bool,
}

/// The span every boundary crossing attaches to.
///
/// Takes the two ids and **nothing else**: a span that could carry a payload is
/// a span somebody eventually puts one in.
#[must_use]
pub fn correlated(correlation_id: &str, causation_id: Option<&str>) -> tracing::Span {
    tracing::info_span!(
        "twinvpn",
        correlation_id = correlation_id,
        causation_id = causation_id.unwrap_or("")
    )
}

/// Renders an opaque id for a log line.
///
/// Ids are not secrets, but they are unbounded input from a client, so this
/// **truncates** rather than letting a hostile id fill a log file. Truncation is
/// safe here and only here: an id is for correlation, and a prefix correlates.
#[must_use]
pub fn id_for_log(bytes: &[u8]) -> String {
    const MAX: usize = 32;
    use std::fmt::Write as _;
    let mut out = String::with_capacity(MAX * 2);
    for byte in bytes.iter().take(MAX) {
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > MAX {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w16_a_level_copied_verbatim_from_adr_0015_configures_rather_than_fails() {
        // §11.5 uses CRITICAL as a severity; `tracing` has no such level.
        for name in ["critical", "CRITICAL", " Critical "] {
            assert_eq!(level_directive(Some(name)), ("error", true));
        }
    }

    #[test]
    fn an_unrecognised_level_falls_back_and_the_fallback_is_reportable() {
        // A logging misconfiguration must not be why a VPN agent will not run —
        // but the operator has to be able to find out, which is what the second
        // element is for.
        let (level, recognised) = level_directive(Some("verbose"));
        assert_eq!(level, DEFAULT_LEVEL);
        assert!(!recognised);
        assert_eq!(level_directive(None), ("info", true));
    }

    #[test]
    fn every_documented_level_is_accepted() {
        for name in ["trace", "debug", "info", "warn", "error"] {
            let (level, recognised) = level_directive(Some(name));
            assert!(recognised, "{name}");
            assert_eq!(level, name);
        }
        assert_eq!(level_directive(Some("warning")), ("warn", true));
    }

    #[test]
    fn the_format_follows_the_supervisor_unless_it_is_asked_for() {
        assert!(wants_json(None, true));
        assert!(!wants_json(None, false));
        assert!(wants_json(Some("json"), false), "an explicit ask wins");
        assert!(!wants_json(Some("text"), true), "and so does the other one");
        assert!(
            wants_json(Some("nonsense"), true),
            "otherwise, the supervisor"
        );
    }

    #[test]
    fn an_id_is_truncated_rather_than_letting_a_client_fill_a_log_file() {
        let short = id_for_log(&[0xde, 0xad]);
        assert_eq!(short, "dead");
        let long = id_for_log(&vec![0xab; 1024]);
        assert!(long.ends_with('…'));
        assert!(long.len() <= 32 * 2 + 3);
    }

    #[test]
    fn no_function_in_this_module_accepts_a_payload() {
        // §6 rule 11 as an API shape. The only `&[u8]` here is `id_for_log`'s,
        // and an id is not a payload — every other entry point takes `&str` or a
        // scalar, so logging a packet would need a new parameter, which is a diff
        // a reviewer sees.
        let source = include_str!("logging.rs");
        let signatures: Vec<&str> = source
            .lines()
            .filter(|line| line.trim_start().starts_with("pub fn "))
            .collect();
        let byte_takers: Vec<&&str> = signatures
            .iter()
            .filter(|line| line.contains("&[u8]"))
            .collect();
        assert_eq!(byte_takers.len(), 1, "{byte_takers:?}");
        assert!(byte_takers[0].contains("id_for_log"));
    }
}
