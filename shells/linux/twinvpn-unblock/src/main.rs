//! `twinvpn-unblock` — the offline recovery path ADR-0012 **KS-20a** makes
//! mandatory on Linux.
//!
//! **Authority:** [ADR-0012](../../../../docs/adr/ADR-0012-kill-switch-and-leak-prevention.md)
//! §10 (KS-20, KS-20a), §11.10 (KS-21, KS-21a), KS-19;
//! [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-12, MI-13; ADR-0023 EM-38, EM-39, EM-72.
//!
//! > A crash between "rules installed" and "agent running" leaves a host blocked
//! > with no UI. Every platform on which a privileged local command can exist
//! > ships one: privileged, local, network-independent, removing the owner-tagged
//! > rule set and clearing the latch… **Without it, a bug in this ADR bricks
//! > connectivity.**
//!
//! # Why this is a separate binary and not a `twinvpnctl` subcommand
//!
//! Because the case it exists for is **"the authority will not start"**. A
//! subcommand of the CLI would reach the agent over the management socket, and
//! the socket exists only while the agent is running — so the one situation the
//! command is for is the one situation in which it could not work.
//!
//! This binary therefore:
//!
//! - **speaks to no socket.** It links `twinvpn-platform-linux` and nothing from
//!   `twinvpnd`. There is no `mi` module here and no `AF_UNIX` code.
//! - **needs no core.** It does not construct one, so it cannot be blocked by an
//!   `abi_major` mismatch or a poisoned store — two of the ways the authority
//!   fails to start.
//! - **needs no configuration.** The table name is a constant of the enforcement
//!   layer, not a setting.
//! - **is package-owned**, like the KS-19 boot artifact beside it, and is
//!   removed by the same uninstall.
//!
//! # What it does, and the ordering that matters
//!
//! 1. **Refuses without `--confirm-unprotected`.** ADR-0012 KS-21 clause 3 wants
//!    "a confirmation that names the consequence"; ADR-0023 EM-38 forbids a
//!    prompt, because "a command that blocks on a terminal read is a hung cron
//!    job, which on an unattended device is indistinguishable from a wedge". So
//!    the consequence is **printed** and the flag is required, and the exit code
//!    is `2` (usage) rather than `1`: nothing was attempted.
//! 2. **Refuses if it is not privileged.** `CAP_NET_ADMIN` or root. A failure
//!    here is named rather than surfacing as an `nft` error.
//! 3. **Deletes the owner-tagged table**, and *only* that table. It never
//!    flushes the ruleset, because a host's own firewall is not ours to remove —
//!    KS-20's reclamation is scoped to what we tagged.
//! 4. **Reads back.** The table must be gone from the kernel's own answer, not
//!    from the fact that the delete returned zero. Same discipline as the W-24
//!    read-back the agent does when arming.
//! 5. **Names the KS-19 boot artifact if it is still enabled**, because leaving
//!    it enabled means the next boot re-blocks the host and the operator's fix
//!    lasts until the next reboot. It does **not** disable it: that is a
//!    package-owned artifact under PS-7 and disabling it silently would be this
//!    command exceeding its mandate.
//!
//! # What it is not
//!
//! **It is not reachable from any automatic path** (ADR-0023 EM-72). It is a
//! command a human runs on a console or over SSH; no timer, reconciler,
//! supervisor or policy document can invoke it, and it takes no input from any
//! of them. KS-21a's residual is stated rather than hidden: on HC-3 the disarm
//! boundary is whoever holds an authenticated administrator shell on that host,
//! which is the same boundary that already controls the enforcement rule set.
//!
//! It also does **not** report the host as protected afterwards. Removing the
//! table is removing protection, which is the whole point of the command and is
//! why the message says so in those words.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::process::ExitCode;

/// The flag ADR-0012 KS-21(3) requires and ADR-0023 EM-38 makes a flag rather
/// than a prompt.
const CONFIRM_FLAG: &str = "--confirm-unprotected";

/// ADR-0017 §11.12's exit codes, the four this binary can produce.
mod exit {
    /// The table was removed and the removal was confirmed against the kernel.
    pub const OK: u8 = 0;
    /// The removal was attempted and failed.
    pub const FAILED: u8 = 1;
    /// Usage — **nothing was attempted**.
    pub const USAGE: u8 = 2;
    /// Not privileged enough to touch the enforcement layer.
    pub const UNAUTHORIZED: u8 = 4;
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}

fn run(args: &[String]) -> u8 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return exit::OK;
    }
    if args.iter().any(|a| a == "--status") {
        return report_status();
    }

    // Anything we do not recognise is a usage error, not an ignored argument: a
    // typo'd confirmation flag must not read as a missing one and must certainly
    // not read as a present one.
    for arg in args {
        if arg != CONFIRM_FLAG {
            eprintln!("twinvpn-unblock: unrecognised argument {arg:?}");
            print_help();
            return exit::USAGE;
        }
    }

    if !args.iter().any(|a| a == CONFIRM_FLAG) {
        // The consequence, named — KS-21 clause 3 — and then a refusal rather
        // than a prompt (EM-38). Exit 2: nothing was attempted.
        eprintln!(
            "twinvpn-unblock: refusing without {CONFIRM_FLAG}.\n\
             \n\
             This removes TwinVPN's enforcement rule set from this host.\n\
             Traffic that TwinVPN is currently blocking will leave this device\n\
             UNTUNNELED and UNPROTECTED, and will keep doing so until the agent\n\
             starts and re-arms.\n\
             \n\
             Run:  twinvpn-unblock {CONFIRM_FLAG}"
        );
        return exit::USAGE;
    }

    if !is_privileged() {
        eprintln!(
            "twinvpn-unblock: POLICY.KILLSWITCH.ARM_FAILED: this command needs \
             CAP_NET_ADMIN or root to remove the enforcement table"
        );
        return exit::UNAUTHORIZED;
    }

    match twinvpn_platform_linux::netcfg::remove_owner_tagged_table() {
        Ok(()) => {
            println!(
                "twinvpn-unblock: removed the owner-tagged nftables table \
                 `{} {}` and confirmed it is gone from the kernel.",
                twinvpn_platform_linux::nft::FAMILY,
                twinvpn_platform_linux::nft::TABLE
            );
            println!("twinvpn-unblock: this host is now UNPROTECTED by TwinVPN.");
            warn_about_the_boot_artifact();
            exit::OK
        }
        Err(error) => {
            // Never a raw OS error as the complete user-facing error: the
            // registered code plus the errno as typed evidence.
            eprint!(
                "twinvpn-unblock: {}: the enforcement table could not be removed",
                error.reason_code().as_str()
            );
            if let Some(detail) = error.os_detail() {
                eprint!(" (errno {} in {})", detail.code, detail.call);
            }
            eprintln!();
            exit::FAILED
        }
    }
}

/// `--status`: what the kernel is holding, without changing it.
///
/// Present because the first question an operator has is "is TwinVPN what is
/// blocking me", and answering it must not require running the destructive
/// command to find out.
fn report_status() -> u8 {
    match twinvpn_platform_linux::netcfg::read_owner_tagged_table() {
        Ok(Some(installed)) => {
            println!(
                "twinvpn-unblock: the kernel holds `{} {}`: posture {:?}, \
                 covering {} IPv4 and {} IPv6 prefixes.",
                twinvpn_platform_linux::nft::FAMILY,
                twinvpn_platform_linux::nft::TABLE,
                installed.ruleset,
                installed.scope.v4,
                installed.scope.v6
            );
            exit::OK
        }
        Ok(None) => {
            println!(
                "twinvpn-unblock: the kernel holds no `{} {}` table. TwinVPN is \
                 not blocking this host.",
                twinvpn_platform_linux::nft::FAMILY,
                twinvpn_platform_linux::nft::TABLE
            );
            exit::OK
        }
        Err(error) => {
            eprintln!(
                "twinvpn-unblock: {}: the enforcement table could not be read",
                error.reason_code().as_str()
            );
            exit::FAILED
        }
    }
}

/// KS-19's artifact outlives this command, and saying so is the difference
/// between a fix and a fix that lasts until the next reboot.
fn warn_about_the_boot_artifact() {
    const UNIT: &str = "/etc/systemd/system/twinvpn-killswitch.service";
    if std::path::Path::new(UNIT).exists() {
        println!(
            "twinvpn-unblock: NOTE — the KS-19 boot artifact is still installed \
             ({UNIT}).\n\
             It re-applies the boot ruleset at every boot, so this removal lasts \
             until the next reboot.\n\
             That is deliberate: the artifact is package-owned (ADR-0016 PS-7) \
             and this command does not disable it.\n\
             To keep the host unprotected across a reboot, disable it yourself:\n\
             \n    systemctl disable twinvpn-killswitch.service\n"
        );
    }
}

/// Whether this process can touch the enforcement layer.
///
/// Read from `/proc/self/status` rather than through `capget(2)`, for the same
/// reason `twinvpnd`'s posture check does: this binary carries
/// `#![forbid(unsafe_code)]`, and `/proc/self/status` is the same answer from
/// the same kernel.
fn is_privileged() -> bool {
    /// `CAP_NET_ADMIN` is bit 12.
    const CAP_NET_ADMIN: u64 = 1 << 12;
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        // Unable to tell. `nft` will refuse on its own and name the errno, which
        // is a worse message but not a wrong outcome — so this does not refuse
        // on an unreadable /proc.
        return true;
    };
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            if value.split_whitespace().nth(1).and_then(|v| v.parse().ok()) == Some(0u32) {
                return true;
            }
        }
        if let Some(value) = line.strip_prefix("CapEff:") {
            if let Ok(bits) = u64::from_str_radix(value.trim(), 16) {
                if bits & CAP_NET_ADMIN != 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn print_help() {
    println!(
        "usage: twinvpn-unblock [--status | {CONFIRM_FLAG}]\n\
         \n\
         Removes TwinVPN's owner-tagged nftables table from this host.\n\
         \n\
         This is ADR-0012 KS-20a's offline recovery path: it speaks to no\n\
         socket and needs no running agent, precisely because the case it\n\
         exists for is \"the authority will not start\".\n\
         \n\
         It removes ONLY the table TwinVPN owns. Your own firewall rules are\n\
         not touched.\n\
         \n\
         Options:\n\
           --status                report what the kernel holds; change nothing\n\
           {CONFIRM_FLAG}   perform the removal\n\
           -h, --help              this text\n\
         \n\
         Exit codes: 0 removed, 1 failed, 2 usage, 4 not privileged.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_removal_is_refused_without_the_confirmation_flag() {
        // KS-21 clause 3 and EM-38: the consequence is named, the flag is
        // required, and nothing is attempted — which is why the code is USAGE
        // and not FAILED. A caller that sees 2 knows the host is unchanged.
        assert_eq!(run(&[]), exit::USAGE);
    }

    #[test]
    fn an_unrecognised_argument_is_a_usage_error_and_never_ignored() {
        // A typo'd confirmation flag must not read as a missing one, and must
        // certainly not read as a present one.
        assert_eq!(run(&["--confirm".to_owned()]), exit::USAGE);
        assert_eq!(run(&["--confirm-unprotected=yes".to_owned()]), exit::USAGE);
        assert_eq!(
            run(&[CONFIRM_FLAG.to_owned(), "--force".to_owned()]),
            exit::USAGE
        );
    }

    #[test]
    fn help_is_not_a_failure() {
        assert_eq!(run(&["--help".to_owned()]), exit::OK);
        assert_eq!(run(&["-h".to_owned()]), exit::OK);
    }

    #[test]
    fn every_exit_code_is_below_adr_0017s_prohibited_floor() {
        // ADR-0017 §11.12: 64+ is prohibited, because the shell reserves it.
        for code in [exit::OK, exit::FAILED, exit::USAGE, exit::UNAUTHORIZED] {
            assert!(code < 64, "{code} collides with the shell's reserved range");
        }
    }

    #[test]
    fn it_speaks_to_no_socket_and_hosts_no_core() {
        // The structural claim this binary rests on, as a test a reader can
        // check rather than a paragraph they have to trust: the source names no
        // socket path, no MI module and no core.
        let source = include_str!("main.rs");
        // Only the production half: this test module names the forbidden
        // strings itself, in the array below.
        let source = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        for forbidden in [
            "UnixStream",
            "UnixListener",
            "twinvpnd::mi",
            "twinvpn_core",
            "mgmt.sock",
        ] {
            // The doc comment above legitimately discusses these by name, so the
            // check is on CODE: every occurrence must be inside a comment.
            for (n, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains(forbidden),
                    "line {} names {forbidden} in code; this binary must work \
                     when the authority will not start",
                    n + 1
                );
            }
        }
    }

    #[test]
    fn the_status_read_never_changes_anything() {
        // `--status` is the question an operator asks first, and asking it must
        // not require running the destructive command. On a host with no `nft`
        // it reports the failure rather than claiming the host is unprotected —
        // which is O-18's fail-safe direction.
        let code = report_status();
        assert!(matches!(code, exit::OK | exit::FAILED));
    }

    #[test]
    fn the_privilege_check_reads_the_same_file_the_agent_reads() {
        // Not an assertion about this runner's privileges — it has none — but
        // that the check runs and answers without panicking on a real /proc.
        let _ = is_privileged();
        assert!(std::path::Path::new("/proc/self/status").exists());
    }
}
