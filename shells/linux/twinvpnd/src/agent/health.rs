//! **Unattended operation**: the health file, the watchdog, and what neither of
//! them is allowed to do.
//!
//! **Authority:** [ADR-0023](../../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! §11.16 — EM-68 (what escalates), EM-69 (how), EM-70 (the watchdog credential),
//! EM-71 (a crash loop is held), EM-72 (no automatic path reduces protection);
//! ADR-0012 KS-20, KS-21a; ADR-0015 §11.6 (the `ProtectionAssertion`).
//!
//! This host is ADR-0016 class **HC-3**, profile **H-SRV**: *"the distinguishing
//! property is 'no user ever logs in'"*. Everything in this module exists
//! because of that one fact — there is no notification centre, no dialog and
//! nobody watching, so a condition that is not written somewhere a monitoring
//! system can read has not been reported at all.
//!
//! # EM-69's channels, and which of them are this shell's
//!
//! > Escalation is **pull-first with three local push sinks**, and **no
//! > escalation path may be a TwinVPN-operated network service** (E-03).
//!
//! | Channel | Where it is |
//! |---|---|
//! | syslog/journald at ERROR and CRITICAL, `reason_code` as a structured field | [`super::logging`], and every `tracing` call in this crate carries `reason_code =` |
//! | the health file, one parse-stable line | **here** ([`write`]) |
//! | `twinvpn status get --output json` as an exec check | `twinvpnctl`, keying on `class` per EM-37 |
//! | `sd_notify(STATUS=…)` and systemd `OnFailure=` | **here** ([`notify`]) and `packaging/twinvpnd.service` |
//! | in-band push to the Owner's paired admin devices | the control plane's, and **not** in this build (W-12) |
//!
//! # EM-70: the watchdog credential is a `ProtectionAssertion`, not a heartbeat
//!
//! > The ping MUST be emitted only from a health check that includes a **fresh**
//! > `ProtectionAssertion`… **A watchdog fed by a timer thread proves that the
//! > timer thread is alive, which is not the property anybody wants.**
//!
//! [`notify_watchdog`] takes the assertion as an argument and refuses to ping
//! without one. That is the whole design: the function cannot be called from a
//! timer that has not asked the enforcement layer anything, because it has
//! nothing to pass.
//!
//! # EM-72: nothing here can reduce protection
//!
//! > **The disarm path is unreachable from any automatic path.** … No timer, no
//! > reconciler, no supervisor, no policy document, and no `ubus` method can
//! > satisfy those preconditions.
//!
//! This module writes a file and sends a datagram. It has no reference to the
//! adapter's `NetworkConfig`, no way to reach `set_ruleset`, and takes no
//! `Principal` — so it cannot satisfy KS-21a's ceremony even by accident. There
//! is deliberately **no** "if `BLOCKED` for more than N minutes" anything: EM-72
//! prohibits it by name, and the way to keep a prohibition is to have no code
//! that could express it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The health file's name.
///
/// # A contradiction in EM-69, resolved toward the safe half and reported
///
/// EM-69 names the file `$STATE_DIR/health` **and** says it lives on `tmpfs`.
/// On a `systemd` host those two halves disagree: `StateDirectory=` is
/// `/var/lib/twinvpn`, which is persistent across reboots, and the tmpfs is
/// `RuntimeDirectory=`, i.e. `/run/twinvpn`.
///
/// This build writes it to the **runtime** directory, because the parenthetical
/// is the load-bearing half: a health line that survives a reboot is a
/// monitoring system told a falsehood by a file, which is the precise failure a
/// health file exists to prevent. The other reading — a persistent path — makes
/// the file's staleness undetectable by the reader.
///
/// Flagged for ADR-0023's owner rather than resolved locally: the two spellings
/// cannot both be satisfied, and on OpenWrt (where `$STATE_DIR` is itself on
/// tmpfs) there is no conflict, which is likely why it was not noticed.
pub const HEALTH_FILE: &str = "health";

/// What a monitoring system reads.
///
/// **One parse-stable line**, EM-69's words. Four fields, space-separated, in a
/// fixed order, so an `awk` in a Nagios check does not have to parse JSON — and
/// so the format cannot drift, because a field added in the middle would break
/// every reader silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The derived TwinNet-scope state, EM-45's first line.
    ///
    /// **Supplied by the caller from the core**, never computed here: CB-2 makes
    /// a `ConnectionState` a TwinVPN domain fact, and a shell that derived one
    /// would be holding a decision.
    pub state: &'static str,
    /// The worst active `reason_code`.
    pub worst_reason_code: &'static str,
    /// The agent's own reading, on the boot-time monotonic clock (MI-16).
    pub as_of_ms: u64,
    /// Whether a **fresh** `ProtectionAssertion` was obtained.
    ///
    /// ADR-0015 §11.6 rule 1: the assertion is produced by *querying the
    /// enforcement layer*, and the indicator is "a pure function of the most
    /// recent assertion, **never of the agent's belief**". `false` here means
    /// the query failed, which O-18 makes `UNKNOWN` rather than `unprotected` —
    /// and a monitoring system must be able to tell those apart.
    pub protection_asserted: bool,
}

impl Report {
    /// The one line.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{} {} {} {}\n",
            self.state,
            self.worst_reason_code,
            self.as_of_ms,
            if self.protection_asserted {
                "asserted"
            } else {
                "unknown"
            }
        )
    }
}

/// Writes the health file **atomically**.
///
/// Temp file → `rename`, so a reader never sees a half-written line. A
/// monitoring system that read a truncated `reason_code` would raise an alert
/// naming a code that does not exist, which is worse than raising none.
///
/// # Errors
///
/// The write's error. The caller **logs and continues**: a health file that
/// cannot be written is a degraded observability channel, not a reason to stop
/// being a VPN, and EM-69 has four other channels.
pub fn write(state_dir: &Path, report: &Report) -> std::io::Result<()> {
    let path = state_dir.join(HEALTH_FILE);
    let temp = state_dir.join(".health.tmp");
    {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(report.line().as_bytes())?;
        file.flush()?;
    }
    std::fs::rename(&temp, &path)
}

/// Removes the health file on the way out.
///
/// A stale "healthy" line outliving the agent is a monitoring system told a
/// falsehood by a file — and the file is the channel that is *supposed* to be
/// authoritative when nobody is watching.
pub fn retract(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(HEALTH_FILE));
    let _ = std::fs::remove_file(state_dir.join(".health.tmp"));
}

/// The `sd_notify(3)` socket, from the environment `systemd` sets.
///
/// `None` where the supervisor did not set it, which is PS-11's "no recognised
/// supervisor" and is a degradation the agent already names at start rather than
/// a failure.
#[must_use]
pub fn notify_socket() -> Option<PathBuf> {
    let raw = std::env::var_os("NOTIFY_SOCKET")?;
    let path = PathBuf::from(&raw);
    // `systemd` uses a leading `@` for the abstract namespace. This build does
    // not support that form and says so rather than sending to a path that does
    // not exist: an abstract socket is visible across network namespaces, which
    // is the same objection ADR-0017 §11.2 raises against them for the MI.
    if path.to_string_lossy().starts_with('@') {
        return None;
    }
    Some(path)
}

/// Sends one `sd_notify` datagram.
///
/// Hand-rolled rather than taken from a crate, for the reason `core/Cargo.toml`
/// is the integration lead's: the protocol is a single newline-separated
/// `KEY=VALUE` datagram to an `AF_UNIX` `SOCK_DGRAM` path, and implementing it
/// is four lines against a dependency this workspace does not otherwise need.
///
/// # Errors
///
/// The send's error. Every caller **logs and continues**: `systemd` treats a
/// missed notification as a missed notification, and an agent that stopped
/// because it could not talk to its supervisor would be the outage the
/// supervisor exists to prevent.
pub fn notify(message: &str) -> std::io::Result<()> {
    let Some(path) = notify_socket() else {
        return Ok(());
    };
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    socket.send_to(message.as_bytes(), path)?;
    Ok(())
}

/// `sd_notify(READY=1)` plus EM-45's first line as `STATUS=`.
///
/// # Errors
///
/// The send's error.
pub fn notify_ready(report: &Report) -> std::io::Result<()> {
    notify(&format!(
        "READY=1\nSTATUS={} {}\n",
        report.state, report.worst_reason_code
    ))
}

/// **EM-70's watchdog ping**, which requires a fresh assertion to exist.
///
/// > The ping MUST be emitted only from a health check that includes a **fresh**
/// > `ProtectionAssertion`.
///
/// The assertion is the *argument*, and `false` is a refusal to ping rather than
/// a ping with a caveat. That is the whole mechanism: a timer thread that has
/// not asked the enforcement layer anything has no `true` to pass, so it cannot
/// feed the watchdog, so `WatchdogSec=` fires and `systemd` restarts an agent
/// that has stopped being able to verify its own protection.
///
/// Returns whether a ping was sent, so a caller can log the refusal — a watchdog
/// that silently stops being fed is indistinguishable from a hang, and the point
/// of the refusal is that it should be *diagnosable* before the restart.
///
/// # Errors
///
/// The send's error.
pub fn notify_watchdog(protection_asserted: bool) -> std::io::Result<bool> {
    if !protection_asserted {
        // EM-70's whole point. Not an error — the agent is running — but the
        // watchdog is deliberately not fed, and `systemd` will act on that.
        return Ok(false);
    }
    notify("WATCHDOG=1\n")?;
    Ok(true)
}

/// `sd_notify(STOPPING=1)`, so `systemd` distinguishes a clean stop from a
/// crash.
///
/// EM-71 makes the difference matter: a crash loop is **held** with enforcement
/// installed, and that ladder is only reachable if the supervisor can tell a
/// crash from a shutdown.
///
/// # Errors
///
/// The send's error.
pub fn notify_stopping() -> std::io::Result<()> {
    notify("STOPPING=1\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            state: "PROTECTED",
            worst_reason_code: "NONE",
            as_of_ms: 42,
            protection_asserted: true,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "twinvpn-health-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("creates");
        dir
    }
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[test]
    fn the_health_line_is_one_line_with_four_fields_in_a_fixed_order() {
        // EM-69: "one parse-stable line". A field added in the middle would
        // break every `awk` reading it, silently.
        let line = report().line();
        assert_eq!(line.lines().count(), 1, "one line: {line:?}");
        assert!(line.ends_with('\n'), "newline-terminated for a line reader");
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "{fields:?}");
        assert_eq!(
            fields[0], "PROTECTED",
            "the derived state comes first (EM-45)"
        );
        assert_eq!(fields[1], "NONE", "then the worst active reason_code");
        assert_eq!(fields[2], "42", "then the agent's own reading");
        assert_eq!(fields[3], "asserted");
    }

    #[test]
    fn an_unverifiable_protection_is_unknown_and_never_reads_as_unprotected() {
        // O-18's fail-safe direction. "We could not ask" and "the answer was no"
        // are different facts, and a monitoring system must be able to tell them
        // apart: one is a broken enforcement layer, the other is a broken query.
        let unknown = Report {
            protection_asserted: false,
            ..report()
        };
        assert!(unknown.line().ends_with("unknown\n"));
        assert!(!unknown.line().contains("unprotected"));
    }

    #[test]
    fn the_health_file_is_written_atomically_and_leaves_no_temporary() {
        let dir = temp_dir("atomic");
        write(&dir, &report()).expect("writes");
        assert_eq!(
            std::fs::read_to_string(dir.join(HEALTH_FILE)).expect("reads"),
            report().line()
        );
        assert!(
            !dir.join(".health.tmp").exists(),
            "the temporary was renamed, not copied — a reader must never see a \
             half-written line and raise an alert naming a code that does not exist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retracting_removes_the_line_rather_than_leaving_it_stale() {
        let dir = temp_dir("retract");
        write(&dir, &report()).expect("writes");
        retract(&dir);
        assert!(!dir.join(HEALTH_FILE).exists());
        // Idempotent: shutdown may run twice, and a crash may mean it never ran.
        retract(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn em70_the_watchdog_is_not_fed_without_a_fresh_protection_assertion() {
        // > A watchdog fed by a timer thread proves that the timer thread is
        // > alive, which is not the property anybody wants.
        //
        // With no assertion there is no ping, and the refusal is reported rather
        // than being a silent no-op — because a watchdog that quietly stops
        // being fed is indistinguishable from a hang.
        assert!(
            !notify_watchdog(false).expect("not an error; the agent is running"),
            "EM-70: no fresh ProtectionAssertion, no ping"
        );
    }

    #[test]
    fn an_absent_notify_socket_is_a_no_op_and_never_a_failure() {
        // PS-11: an unsupervised agent does not claim supervised guarantees, and
        // it certainly does not refuse to run because nobody is supervising it.
        if notify_socket().is_none() {
            notify("READY=1\n").expect("a no-op, not an error");
            notify_stopping().expect("a no-op, not an error");
            assert!(notify_watchdog(true).expect("no-op"));
        }
    }

    #[test]
    fn an_abstract_notify_socket_is_refused_rather_than_guessed_at() {
        // `systemd` spells the abstract namespace with a leading `@`. This build
        // does not support that form, and says so rather than sending to a path
        // that does not exist — the same objection ADR-0017 §11.2 raises against
        // abstract sockets for the MI: they are visible across network
        // namespaces.
        let previous = std::env::var_os("NOTIFY_SOCKET");
        // SAFETY-equivalent note: this is a single-threaded test process
        // touching its own environment, and the value is restored below.
        std::env::set_var("NOTIFY_SOCKET", "@/org/freedesktop/systemd1/notify");
        assert_eq!(notify_socket(), None);
        match previous {
            Some(value) => std::env::set_var("NOTIFY_SOCKET", value),
            None => std::env::remove_var("NOTIFY_SOCKET"),
        }
    }

    #[test]
    fn em72_this_module_cannot_reduce_protection() {
        // The structural claim, as a check a reader can run. Nothing here names
        // the enforcement layer, takes a `Principal`, or expresses a timer that
        // could transition out of BLOCKED — and EM-72 prohibits the last of
        // those by name: "No timer may transition out of `BLOCKED`."
        let source = include_str!("health.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        for forbidden in [
            "set_ruleset",
            "NetworkConfig",
            "Principal",
            "disarm",
            "Ruleset::",
        ] {
            for (n, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains(forbidden),
                    "line {} names {forbidden} in code: EM-72 requires the disarm \
                     path to be unreachable from any automatic path, and the way \
                     to keep that is to have no code that could express it",
                    n + 1
                );
            }
        }
    }
}
