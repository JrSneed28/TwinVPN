//! `twinvpn-ksd` — the macOS `LaunchDaemon`, and **only** the KS-19 boot anchor.
//!
//! **Authority:** ADR-0016 §11.2's macOS row and amendment **PS-22**, §11.5's
//! macOS supervisor row, §11.6, PS-7, PS-8, PS-18; ADR-0012 KS-19, KS-20,
//! §11.6's macOS row; ADR-0018 CB-6; `ownership.md` §8 **W-24**, §9.6 **X-7**.
//!
//! # What this binary is
//!
//! ADR-0016 §11.2, "macOS, normatively", verbatim:
//!
//! > The system extension is the authority; the `LaunchDaemon` `ksd` is *not* a
//! > general-purpose privileged helper and MUST NOT accept any request other
//! > than (a) apply the boot anchor and (b) the unblock command's local,
//! > admin-authenticated invocation.
//!
//! It applies `/etc/twinvpn/pf.anchor`, **reads back** what `pfctl` says is
//! loaded, reports, and exits. It is `RunAtLoad`, it is on the boot path, and
//! §11.5's macOS row is why it exists at all as a second privileged component:
//! *"a sysext can be deactivated by the user, and the boot artifact must not be
//! able to be."*
//!
//! # What it does not have, and how you can tell
//!
//! No core. No keys. No sockets. No management interface. The way to check that
//! is `Cargo.toml`: there is no `twinvpn-core`, no `twinvpn-mgmt`, no
//! `twinvpn-mi`, no `twinvpn-env` and no `tokio` in the dependency list, so
//! there is nothing here to reach even by mistake. §11.2's reason for the rule
//! is that the second privileged surface must be "close to nil", and a
//! dependency graph is the only place that claim can be checked.
//!
//! **`stdout` and `stderr`, not `tracing`.** The authority installs a subscriber
//! because it runs for hours and emits structured events; this job emits at most
//! four lines and exits, and its plist routes `StandardErrorPath` to
//! `/var/log/twinvpn/ksd.err.log`. A logging framework here would be more
//! dependency than diagnostic — and every line it prints names a **registered**
//! `reason_code`, which is the property that actually matters.
//!
//! # Graceful shutdown, for a job that exits
//!
//! `ownership.md` §6 rule 7 asks for graceful shutdown. For this process it is
//! one property, and it is **CB-6**: exiting does not remove the anchor.
//! Nothing here unloads, flushes or disables `pf` on any path — not on success,
//! not on refusal, not on a signal — because the OS holding the rule set is the
//! whole reason the boot artifact survives the authority. There is no cleanup
//! handler to review, which is stronger than a correct one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

mod boot;

use std::process::ExitCode;

use twinvpn_platform_macos::netcfg::{PfEngine, PfctlEngine};

/// The exit code a refused apply produces.
///
/// **Not one of ADR-0017 §11.12's**: those are the CLI's, and a daemon that
/// exited 3 would be telling `launchd` something §11.12 never meant. `1` is what
/// a supervisor reads, and `KeepAlive={SuccessfulExit: false}` in the plist is
/// what turns it into a restart.
const EXIT_REFUSED: u8 = 1;

/// The argument the plist passes. Anything else is refused rather than ignored:
/// a job that silently accepted an unknown flag would let a mistyped plist look
/// like a working one.
const APPLY_FLAG: &str = "--apply-boot-anchor";

/// The read-only question, for an operator standing in front of a blocked host.
const STATUS_FLAG: &str = "--status";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}

fn run(args: &[String]) -> u8 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return 0;
    }
    if args.iter().any(|a| a == STATUS_FLAG) {
        return report_status(&Pfctl);
    }
    for arg in args {
        if arg != APPLY_FLAG {
            eprintln!("twinvpn-ksd: unrecognised argument {arg:?}");
            print_help();
            return EXIT_REFUSED;
        }
    }
    apply(&Pfctl)
}

/// Runs the sequence and reports it.
fn apply(probes: &dyn boot::BootProbes) -> u8 {
    let sequence = boot::run(probes);
    if let Some((step, code)) = sequence.refusal() {
        // One line, naming the registered code and the step. A boot-path job
        // that wrote a paragraph on every boot is a log nobody reads.
        eprintln!(
            "twinvpn-ksd: {}: the boot anchor was not applied (step {})",
            code.as_str(),
            step.tag()
        );
    }
    if sequence.is_applied() {
        println!(
            "twinvpn-ksd: the KS-19 boot anchor is loaded into `{}` and the \
             kernel confirms it.",
            twinvpn_platform_macos::pf::ANCHOR
        );
        return 0;
    }
    eprintln!(
        "twinvpn-ksd: steps completed: {} of {}",
        sequence.steps().len(),
        boot::Step::ALL.len()
    );
    EXIT_REFUSED
}

/// `--status`: what the kernel holds, without changing it.
///
/// The first question an operator has is "is TwinVPN what is blocking me", and
/// answering it must not require running the thing that changes state. Same
/// shape as `twinvpn-unblock --status`, deliberately.
fn report_status(probes: &dyn boot::BootProbes) -> u8 {
    if probes.read_back() {
        println!(
            "twinvpn-ksd: the kernel holds the `{}` anchor and the filter is \
             enabled.",
            twinvpn_platform_macos::pf::ANCHOR
        );
    } else {
        println!(
            "twinvpn-ksd: the kernel does not hold a confirmed `{}` anchor.",
            twinvpn_platform_macos::pf::ANCHOR
        );
    }
    0
}

/// The Darwin probes: `pfctl`, and the package's anchor file.
struct Pfctl;

impl boot::BootProbes for Pfctl {
    fn is_root(&self) -> bool {
        effective_uid() == Some(0)
    }

    fn anchor_body(&self) -> Option<String> {
        // **Read only.** PS-7 makes this file the package's; there is no write
        // path in this binary, and `boot`'s own test asserts it over the source.
        std::fs::read_to_string(twinvpn_platform_macos::pf::ANCHOR_FILE).ok()
    }

    fn apply(&self, body: &str) -> bool {
        PfctlEngine
            .load_anchor(twinvpn_platform_macos::pf::ANCHOR, body)
            .is_ok()
    }

    fn read_back(&self) -> bool {
        // **W-24, in the two reads the adapter deliberately keeps separate:**
        // an anchor loaded into a *disabled* filter is not protection, and a
        // single combined answer would let one hide the other.
        let enabled = matches!(
            PfctlEngine.status(),
            Ok(twinvpn_platform_macos::pfread::PfStatus::Enabled)
        );
        let ours = matches!(
            PfctlEngine.tables(twinvpn_platform_macos::pf::ANCHOR),
            Ok(Some(_))
        );
        enabled && ours
    }
}

/// This process's **effective** uid, without `unsafe`.
///
/// This crate carries `#![forbid(unsafe_code)]` and `std` has no `geteuid`, so
/// the question is asked a different way: a file this process creates is owned
/// by its effective uid. The answer has a property the syscall does not — it
/// fails if the process cannot write at all, which is a fact worth having in a
/// job whose next act is to write to the packet filter.
///
/// `None` is treated as "not root", the closed direction.
fn effective_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let path = std::env::temp_dir().join(format!("twinvpn-ksd-probe-{}", std::process::id()));
    let uid = {
        let file = std::fs::File::create(&path).ok()?;
        file.metadata().ok()?.uid()
    };
    let _ = std::fs::remove_file(&path);
    Some(uid)
}

fn print_help() {
    println!(
        "usage: twinvpn-ksd [{APPLY_FLAG} | {STATUS_FLAG}]\n\
         \n\
         Applies TwinVPN's KS-19 boot anchor from /etc/twinvpn/pf.anchor and\n\
         confirms against the kernel that it loaded.\n\
         \n\
         This daemon is NOT the TwinVPN authority. ADR-0016 §11.2 makes the\n\
         NetworkExtension system extension the authority; this job holds the\n\
         boot anchor and nothing else — no core, no keys, no sockets, no\n\
         management interface.\n\
         \n\
         Options:\n\
           {APPLY_FLAG}   apply the anchor and read it back\n\
           {STATUS_FLAG}                report what the kernel holds; change nothing\n\
           -h, --help              this text\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Applied;
    impl boot::BootProbes for Applied {
        fn is_root(&self) -> bool {
            true
        }
        fn anchor_body(&self) -> Option<String> {
            Some("block drop all\n".to_owned())
        }
        fn apply(&self, _body: &str) -> bool {
            true
        }
        fn read_back(&self) -> bool {
            true
        }
    }

    struct Unprivileged;
    impl boot::BootProbes for Unprivileged {
        fn is_root(&self) -> bool {
            false
        }
        fn anchor_body(&self) -> Option<String> {
            None
        }
        fn apply(&self, _body: &str) -> bool {
            false
        }
        fn read_back(&self) -> bool {
            false
        }
    }

    #[test]
    fn a_successful_apply_exits_zero_and_a_refusal_does_not() {
        // `KeepAlive={SuccessfulExit: false}` is what makes the difference
        // operational: 0 means launchd leaves it alone, non-zero means it
        // retries after the 10 s throttle.
        assert_eq!(apply(&Applied), 0);
        assert_eq!(apply(&Unprivileged), EXIT_REFUSED);
    }

    #[test]
    fn an_unrecognised_argument_is_refused_and_never_ignored() {
        // A mistyped plist must not look like a working one.
        assert_eq!(run(&["--apply".to_owned()]), EXIT_REFUSED);
        assert_eq!(run(&["--apply-boot-anchor=yes".to_owned()]), EXIT_REFUSED);
    }

    #[test]
    fn help_is_not_a_failure() {
        assert_eq!(run(&["--help".to_owned()]), 0);
        assert_eq!(run(&["-h".to_owned()]), 0);
    }

    #[test]
    fn the_status_read_never_changes_anything_and_never_fails() {
        // An operator asking "is TwinVPN blocking me" must get an answer whether
        // or not the anchor is there, and asking must not be able to change it.
        assert_eq!(report_status(&Applied), 0);
        assert_eq!(report_status(&Unprivileged), 0);
    }

    #[test]
    fn this_binary_opens_no_socket_and_hosts_no_core() {
        // PS-22's table, as a test a reader can check rather than a paragraph
        // they have to trust. The dependency list is the real mechanism; this is
        // the belt.
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().expect("a first half");
        for (n, line) in production.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for forbidden in [
                "UnixListener",
                "UnixStream",
                "twinvpn_core",
                "twinvpn_mgmt",
                "twinvpn_mi",
                "TcpListener",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "line {} names {forbidden}; ksd holds no core and no \
                     management interface",
                    n + 1
                );
            }
        }
    }

    #[test]
    fn nothing_in_this_binary_removes_enforcement() {
        // **CB-6.** Exiting does not drop protection, and the way that is
        // guaranteed is that there is no unload path to get wrong. A `-d`, a
        // `-F` or a `flush` appearing here is the defect.
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().expect("a first half");
        for (n, line) in production.lines().enumerate() {
            // CODE only: the prose above legitimately explains what a disabled
            // filter means, and a scan that fired on its own documentation is a
            // scan somebody deletes.
            let code = line.split("//").next().unwrap_or("");
            for forbidden in ["flush_anchor", "disable", "\"-F\"", "\"-d\"", "unload"] {
                assert!(
                    !code.contains(forbidden),
                    "line {} names {forbidden}; a boot-path job must not be able \
                     to drop the kill switch",
                    n + 1
                );
            }
        }
    }
}
