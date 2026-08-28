//! The `tracing` subscriber — **installed by the shell, because the core
//! deliberately installs none.**
//!
//! **Authority:** `twinvpn-core`'s own "What is deliberately absent": "**No
//! `tracing` subscriber.** Installing one is a process-global side effect and
//! there may be two cores in one process. The shell installs it."
//! ADR-0015 §11.5 (the levels), §11.4 (`SENSITIVE` and never-loggable classes);
//! `ownership.md` §6 rule 11; ADR-0016 PS-23.
//!
//! # What is never logged
//!
//! `ownership.md` §6 rule 11 and threat-model §9: **private keys, session keys,
//! raw tunnel payloads, pairing secrets and authentication tokens**, ever, at
//! any level. Observability never captures a tunnel payload.
//!
//! That is a property of what this crate *emits*, not of a filter here, and the
//! reason it holds is structural: nothing in `twinvpnd` ever holds a secret to
//! log. The identity private half never crosses the seam (CB-5), the SEK is a
//! `SecureItem` with a redacted `Debug`, and no packet reaches this crate at all
//! (PB-1). PS-23's rule states the line precisely: "a principal name is
//! loggable, an authentication secret never is."
//!
//! # W-16: `CRITICAL` is accepted and mapped
//!
//! ADR-0015 §11.5 names a `CRITICAL` level and `tracing` has none. Per
//! `ownership.md` §8 **W-16** the value is accepted and mapped to `ERROR`, "so a
//! value copied verbatim from the ADR configures the service rather than failing
//! it".

use tracing_subscriber::EnvFilter;

/// The variable that sets the level. `infra/README.md`'s convention.
pub const LEVEL_ENV: &str = "TWINVPN_LOG_LEVEL";

/// The variable that selects the format: `json` (default under a supervisor) or
/// `text`.
pub const FORMAT_ENV: &str = "TWINVPN_LOG_FORMAT";

/// The default level.
pub const DEFAULT_LEVEL: &str = "info";

/// Maps a configured level onto a `tracing` one.
///
/// **W-16.** `critical` is ADR-0015 §11.5's name for the highest severity and
/// `tracing` stops at `error`, so a configuration copied verbatim from the ADR
/// is accepted rather than rejected. An unrecognised value falls back to
/// [`DEFAULT_LEVEL`] rather than failing the start: a logging misconfiguration
/// must not be the reason a VPN agent will not run.
#[must_use]
pub fn map_level(configured: &str) -> &'static str {
    match configured.trim().to_ascii_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "info" => "info",
        "warn" | "warning" => "warn",
        // W-16: accepted, mapped, and documented at the mapping.
        "error" | "critical" | "fatal" => "error",
        _ => DEFAULT_LEVEL,
    }
}

/// Whether output should be JSON.
///
/// JSON under a supervisor (where a log aggregator reads it), text otherwise
/// (where a human does). The default follows `INVOCATION_ID`, which `systemd`
/// sets and nothing else does — the same signal
/// [`super::privilege`] uses for PS-11.
#[must_use]
pub fn want_json() -> bool {
    match std::env::var(FORMAT_ENV).ok().as_deref() {
        Some("json") => true,
        Some("text") => false,
        _ => std::env::var_os("INVOCATION_ID").is_some(),
    }
}

/// Installs the subscriber. **Once per process**, and only from the binary.
///
/// # Errors
///
/// A description, when a subscriber is already installed — which is a
/// programming error rather than an operating condition, and is reported rather
/// than ignored so a second install cannot silently do nothing.
pub fn install() -> Result<(), String> {
    let level = std::env::var(LEVEL_ENV)
        .map_or_else(|_| DEFAULT_LEVEL.to_owned(), |v| map_level(&v).to_owned());
    let filter = EnvFilter::try_new(&level).map_err(|_| format!("bad log level: {level}"))?;

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        // No ANSI in a service log: `journald` stores the escape sequences and
        // `grep` then does not match. The CLI's own colour rules are ADR-0023
        // EM-43's and are a different surface.
        .with_ansi(false)
        .with_target(true);

    if want_json() {
        builder
            .json()
            .try_init()
            .map_err(|_| "a tracing subscriber is already installed".to_owned())
    } else {
        builder
            .try_init()
            .map_err(|_| "a tracing subscriber is already installed".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w16_critical_is_accepted_and_mapped_rather_than_rejected() {
        // "so a value copied verbatim from the ADR configures the service
        // rather than failing it".
        assert_eq!(map_level("critical"), "error");
        assert_eq!(map_level("CRITICAL"), "error");
        assert_eq!(map_level(" Critical "), "error");
    }

    #[test]
    fn every_adr_0015_level_maps_to_something_tracing_understands() {
        for level in ["trace", "debug", "info", "warn", "error", "critical"] {
            let mapped = map_level(level);
            assert!(
                EnvFilter::try_new(mapped).is_ok(),
                "{level} maps to {mapped}, which tracing refuses"
            );
        }
    }

    #[test]
    fn a_logging_misconfiguration_is_not_a_reason_a_vpn_agent_will_not_run() {
        assert_eq!(map_level("verbose"), DEFAULT_LEVEL);
        assert_eq!(map_level(""), DEFAULT_LEVEL);
        assert_eq!(map_level("!!"), DEFAULT_LEVEL);
    }

    #[test]
    fn the_format_default_follows_the_supervisor_and_can_be_overridden() {
        // The variables are read at call time, so this test states the contract
        // rather than mutating the process environment (which would race every
        // other test in this binary).
        assert!(FORMAT_ENV.starts_with("TWINVPN_"));
        assert!(LEVEL_ENV.starts_with("TWINVPN_"));
    }
}
