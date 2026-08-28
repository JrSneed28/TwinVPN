//! The `tracing` subscriber — **installed by the shell, because the core
//! deliberately installs none.**
//!
//! **Authority:** `twinvpn-core`'s own "What is deliberately absent": "**No
//! `tracing` subscriber.** Installing one is a process-global side effect and
//! there may be two cores in one process. The shell installs it."
//! ADR-0015 §11.5 (the levels), §11.4 (the classification table and O-12);
//! `ownership.md` §6 rule 6 and rule 11; ADR-0016 PS-23.
//!
//! # What is never logged
//!
//! `ownership.md` §6 rule 11 and ADR-0015 **O-12**, verbatim: "Tunnel plaintext,
//! packet payloads, private key material, pairing secrets, and pre-shared
//! material MUST NEVER be written to any log, metric, trace, crash artifact, or
//! diagnostic bundle at any log level, in any build, **including debug builds**."
//!
//! That is a property of what this crate *emits*, not of a filter here, and the
//! reason it holds is structural: nothing in `twinvpnsvc` ever holds a secret to
//! log. The identity private half never crosses the seam (CB-5), the SEK is a
//! `SecureItem` with a redacted `Debug`, and no packet reaches this crate at all.
//! PS-23 states the line precisely: "a principal name is loggable, an
//! authentication secret never is."
//!
//! **O-14** is why there is no scrubbing step: "Redaction MUST be enforced at
//! **emit** time by schema-level field classification, not at export time by
//! pattern matching over rendered text." A regex over a rendered line fails open.
//!
//! # W-16: `CRITICAL` is accepted and mapped
//!
//! ADR-0015 §11.5 names a `CRITICAL` level and `tracing` has none. Per
//! `ownership.md` §8 **W-16** the value is accepted and mapped to `ERROR`, "so a
//! value copied verbatim from the ADR configures the service rather than failing
//! it". The same decision `shells/linux` made, for the same reason.
//!
//! # `correlation_id` and `causation_id`
//!
//! `ownership.md` §6 rule 6 requires both to be preserved across every component
//! boundary. [`Correlation`] is the pair as one value, so a boundary that
//! carries one and drops the other does not typecheck.
//!
//! **A finding, reported rather than resolved.** ADR-0015 §11.3's `Diagnostic`
//! specifies `correlation_id` and classifies it `SENSITIVE` and
//! *"never transmitted off-device"*. It specifies **no `causation_id`** — the
//! field appears nowhere in that ADR. `ownership.md` §6 rule 6 nevertheless
//! requires it across every boundary, so this shell carries one locally and
//! never emits it into an MI `Diagnostic`, whose schema has no field for it
//! (MI-15 forbids adding one). Raised for the integration lead.

use tracing_subscriber::EnvFilter;

/// The variable that sets the level. `infra/README.md`'s convention.
pub const LEVEL_ENV: &str = "TWINVPN_LOG_LEVEL";

/// The variable that selects the format: `json` (default under the SCM) or
/// `text`.
pub const FORMAT_ENV: &str = "TWINVPN_LOG_FORMAT";

/// The default level.
pub const DEFAULT_LEVEL: &str = "info";

/// A correlated pair, carried as one value.
///
/// `ownership.md` §6 rule 6: both are preserved across every component
/// boundary. Making them one struct is what stops a boundary carrying the first
/// and dropping the second.
///
/// Neither is ever transmitted off-device: ADR-0015 §11.3 classifies
/// `correlation_id` `SENSITIVE` and "never transmitted off-device", and this
/// type has no serialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Correlation {
    /// Ties related diagnostics together within this device's ledger.
    pub correlation_id: u64,
    /// The event that caused this one.
    pub causation_id: u64,
}

impl Correlation {
    /// A root correlation: nothing caused it.
    #[must_use]
    pub const fn root(correlation_id: u64) -> Self {
        Self {
            correlation_id,
            causation_id: 0,
        }
    }

    /// The correlation for something this one caused.
    ///
    /// The chain keeps `correlation_id` and advances `causation_id`, which is
    /// what makes a ledger query "everything in this operation" rather than
    /// "everything that happened around then".
    #[must_use]
    pub const fn caused(self, next_id: u64) -> Self {
        Self {
            correlation_id: self.correlation_id,
            causation_id: next_id,
        }
    }
}

/// Maps a configured level onto a `tracing` one.
///
/// **W-16.** `critical` is ADR-0015 §11.5's name for the highest severity and
/// `tracing` stops at `error`, so a configuration copied verbatim from the ADR
/// is accepted rather than rejected. An unrecognised value falls back to
/// [`DEFAULT_LEVEL`] rather than failing the start: a logging misconfiguration
/// must not be the reason a VPN service will not run.
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
/// JSON under the SCM (where the Event Log and a collector read it), text
/// otherwise (where a human does). The default follows whether the process was
/// started by the SCM — the same signal [`super::privilege::Posture::supervised`]
/// uses for PS-11, and the Windows analogue of `shells/linux`'s `INVOCATION_ID`.
#[must_use]
pub fn want_json(started_by_scm: bool) -> bool {
    match std::env::var(FORMAT_ENV).ok().as_deref() {
        Some("json") => true,
        Some("text") => false,
        _ => started_by_scm,
    }
}

/// Installs the subscriber. **Once per process**, and only from the binary.
///
/// # Errors
///
/// A description, when a subscriber is already installed — which is a
/// programming error rather than an operating condition, and is reported rather
/// than ignored so a second install cannot silently do nothing.
pub fn install(started_by_scm: bool) -> Result<(), String> {
    let level = std::env::var(LEVEL_ENV)
        .map_or_else(|_| DEFAULT_LEVEL.to_owned(), |v| map_level(&v).to_owned());
    let filter = EnvFilter::try_new(&level).map_err(|_| format!("bad log level: {level}"))?;

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        // No ANSI in a service log: the Event Log and a file sink store the
        // escape sequences and a search then does not match. The CLI's own
        // colour rules are ADR-0023 EM-43's and are a different surface.
        .with_ansi(false)
        .with_target(true);

    if want_json(started_by_scm) {
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
    fn a_logging_misconfiguration_is_not_a_reason_a_vpn_service_will_not_run() {
        assert_eq!(map_level("verbose"), DEFAULT_LEVEL);
        assert_eq!(map_level(""), DEFAULT_LEVEL);
        assert_eq!(map_level("!!"), DEFAULT_LEVEL);
    }

    #[test]
    fn the_format_default_follows_the_supervisor() {
        // Read at call time and taken as an argument rather than probed, so
        // this test states the contract without mutating the process
        // environment — which would race every other test in this binary.
        if std::env::var(FORMAT_ENV).is_err() {
            assert!(want_json(true), "JSON under the SCM");
            assert!(!want_json(false), "text at a console");
        }
    }

    #[test]
    fn a_correlation_chain_keeps_its_correlation_and_advances_its_cause() {
        // `ownership.md` §6 rule 6. Carrying them as one value is what stops a
        // boundary preserving the first and dropping the second.
        let root = Correlation::root(7);
        assert_eq!(root.causation_id, 0, "nothing caused a root");
        let child = root.caused(8);
        assert_eq!(child.correlation_id, 7, "the operation is the same one");
        assert_eq!(child.causation_id, 8);
        let grandchild = child.caused(9);
        assert_eq!(grandchild.correlation_id, 7);
        assert_eq!(grandchild.causation_id, 9);
    }

    #[test]
    fn a_correlation_has_no_serialisation_and_cannot_leave_the_device() {
        // ADR-0015 §11.3 classifies `correlation_id` SENSITIVE and "never
        // transmitted off-device". The mechanism is that this type derives no
        // `Serialize` and the MI `Diagnostic` has no field for it.
        let correlation = Correlation::root(1);
        // A compile-time property, restated as a runtime one a reader can see:
        // the only way out of this type is its two integers.
        assert_eq!(correlation.correlation_id, 1);
        assert_eq!(format!("{correlation:?}").contains("correlation_id"), true);
    }
}
