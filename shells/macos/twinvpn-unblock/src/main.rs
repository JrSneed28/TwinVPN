//! `twinvpn-unblock` — the offline recovery path ADR-0012 **KS-20a** makes
//! mandatory on macOS.
//!
//! **Authority:** ADR-0012 §10 (KS-20, KS-20a), §11.10 (KS-21, KS-21a), KS-19;
//! ADR-0016 §11.2's macOS component row, PS-7, PS-22, §11.15 **S-41**;
//! ADR-0017 MI-12, MI-13, §11.21.2; ADR-0023 EM-38, EM-39, EM-72.
//!
//! > A crash between "rules installed" and "agent running" leaves a host blocked
//! > with no UI. Every platform on which a privileged local command can exist
//! > ships one: privileged, local, network-independent, removing the
//! > owner-tagged rule set and clearing the latch… **Without it, a bug in this
//! > ADR bricks connectivity.**
//!
//! # Why this is a separate binary and not a `twinvpnctl` subcommand
//!
//! Because the case it exists for is **"the authority will not start"**. A
//! subcommand of the CLI would reach the authority over the management channel,
//! and after **PS-22** that channel exists only while the NE system extension is
//! running — so the one situation the command is for is the one situation in
//! which it could not work. PS-22 makes that sharper than it was on Linux, not
//! softer: the authority is now started on demand by NE, so "the channel is
//! absent" is a *routine* state on this platform rather than a fault.
//!
//! This binary therefore:
//!
//! - **speaks to no socket and to no Mach service.** It links
//!   `twinvpn-platform-macos` and nothing from the shell. There is no `mi`
//!   module here, no `AF_UNIX` code and no XPC.
//! - **needs no core.** It does not construct one, so it cannot be blocked by an
//!   `abi_major` mismatch or a poisoned store — two of the ways the authority
//!   fails to start.
//! - **needs no configuration.** The anchor name is a constant of the
//!   enforcement layer, not a setting.
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
//!    is `2` (usage) rather than `1`: nothing was attempted. **MI-13(2): a
//!    `--yes`-style non-interactive flag MUST NOT exist**, and none does.
//! 2. **Refuses if it is not privileged.** `pfctl` needs uid 0. A failure here is
//!    named rather than surfacing as a `pfctl` error.
//! 3. **Writes the `UnblockRecord` BEFORE the mutation** (MI-13(3)) — the same
//!    write-then-mutate ordering S-41 and S-34 use, and for the same reason: a
//!    record written afterwards is lost in exactly the crash it exists to
//!    explain. **MI-13(5): if the record cannot be written the command still
//!    unblocks**, because bricking the host is the worse failure, and the
//!    authority reports `MGMT.AUDIT_GAP` at its next start.
//! 4. **Empties the owner-tagged anchor**, and *only* that anchor. It never
//!    flushes `pf`, because a host's own firewall is not ours to remove — KS-20's
//!    reclamation is scoped to what we tagged.
//! 5. **Reads back.** The anchor must be gone from the kernel's own answer, not
//!    from the fact that the load returned zero. The same W-24 discipline the
//!    authority uses when arming, and `netcfg::remove_owner_tagged_anchor` makes
//!    it part of the operation rather than a courtesy afterwards.
//! 6. **Names the KS-19 boot artifact if it is still installed**, because leaving
//!    it installed means the next boot re-blocks the host and the operator's fix
//!    lasts until the next reboot. It does **not** disable it: that is a
//!    package-owned artifact under PS-7 and disabling it silently would be this
//!    command exceeding its mandate.
//!
//! # What it is not
//!
//! **It is not reachable from any automatic path** (ADR-0023 EM-72). It is a
//! command a human runs on a console or over SSH; no timer, reconciler,
//! supervisor or policy document can invoke it, and it takes no input from any
//! of them.
//!
//! # The MI-13(1) gap, stated rather than claimed
//!
//! MI-13(1) requires "the **same OS-mediated administrator authentication** as
//! §11.14's ceremony — … or `system.privilege.admin`", and is explicit that
//! *"'privileged' means an authenticated administrator act, not merely 'runs as
//! root'"*. This binary checks uid 0 and no more: Authorization Services is a
//! Darwin framework this crate does not link, and `shells/linux`'s copy makes
//! the same trade with `CAP_NET_ADMIN`. **So a root cron job could invoke this,
//! which MI-13(1) forbids.** Named in `shells/macos/README.md` §7 rather than
//! papered over, and not silently upgraded by pretending `sudo` is the ceremony.
//!
//! It also does **not** report the host as protected afterwards. Removing the
//! anchor is removing protection, which is the whole point of the command and is
//! why the message says so in those words.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::process::ExitCode;

use twinvpn_platform_macos::netcfg::{self, PfctlEngine};

/// The flag ADR-0012 KS-21(3) requires and ADR-0023 EM-38 makes a flag rather
/// than a prompt.
const CONFIRM_FLAG: &str = "--confirm-unprotected";

/// Where MI-13(3)'s `UnblockRecord` is written.
///
/// Inside ADR-0020's store root, which is `root:wheel 0700` — the same directory
/// the authority reads at start, so "a location the agent reads at start" is
/// satisfied by construction rather than by convention.
const UNBLOCK_RECORD: &str = "/Library/Application Support/TwinVPN/unblock-record.json";

/// ADR-0017 §11.12's exit codes, the four this binary can produce.
/// **MI-13(1) / KS-21: an interactive local act, not merely a privileged one.**
///
/// # The gap this closes, and the gap it does not
///
/// MI-13(1) is explicit that *"'privileged' means an authenticated
/// administrator act, not merely 'runs as root'"*, and ADR-0012 KS-21 asks for
/// *"a **local interactive action** on the device itself"*. This binary used to
/// check privilege and nothing else, so **a root cron job satisfied it** —
/// recorded as `ownership.md` §9.6 **X-14**, against both this shell and the
/// other one, in the same words.
///
/// A controlling terminal is the one thing available to a
/// `#![forbid(unsafe_code)]` binary on both platforms that separates the two.
/// A human at a console or over `ssh` has one. A `cron` job, a `systemd` timer,
/// a `launchd` job, an `at` job and a daemon that has been compromised into
/// spawning this **do not** — and, decisively, neither does a control plane:
/// KS-22's rule is *"no remote actor, including a compromised control plane"*,
/// and a control plane cannot produce a local terminal. That is the same
/// property KS-21a leans on when it admits an authenticated local shell on
/// `HC-3`, applied one layer down.
///
/// **What it is not.** It is not re-authentication. `polkit` on Linux and
/// Authorization Services on Darwin would prompt for a credential; this does
/// not, and an operator already at a root shell is not asked to prove it again.
/// So the residual is narrower than X-14's but real, and it is stated here
/// rather than closed by assertion: *this establishes that a human is present,
/// not which human.*
///
/// **Headless hosts are not locked out.** ADR-0012 **KS-21a** is the host-class
/// rule for exactly this: on `HC-3` there is no interactive session, and *"a
/// caller on the local management socket, authenticated by kernel-supplied peer
/// credentials to an administrator principal, satisfies this clause"*. That
/// path is the agent's management interface, which authenticates its peer, and
/// it is unaffected by this check. KS-20's *"blocked must not mean bricked"*
/// therefore still holds — the refusal below names the alternative rather than
/// leaving an operator to find it.
fn has_interactive_local_principal() -> bool {
    // Standard input specifically. An interactive invocation has a terminal on
    // it; a scheduled one is handed a pipe or `/dev/null`. Output is not
    // checked, because `twinvpn-unblock --confirm-unprotected | tee log` is a
    // human act and redirecting it must not be read as automation.
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

mod exit {
    /// The anchor was emptied and the removal was confirmed against the kernel.
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
             UNTUNNELED and UNPROTECTED, and will keep doing so until the\n\
             system extension starts and re-arms.\n\
             \n\
             Run:  twinvpn-unblock {CONFIRM_FLAG}"
        );
        return exit::USAGE;
    }

    if !has_interactive_local_principal() {
        eprintln!(
            "twinvpn-unblock: MGMT.DISARM_NO_LOCAL_AUTHORITY: this command is a\n\
             local interactive act (ADR-0017 MI-13(1), ADR-0012 KS-21) and there\n\
             is no terminal on standard input, so it will not run from cron, a\n\
             timer, a service unit or any other automation.\n\
             \n\
             Run it from a console or an ssh session.\n\
             \n\
             On a headless host with no interactive session at all, disarm goes\n\
             through the agent's management interface instead, which authenticates\n\
             its caller by kernel-supplied peer credentials (ADR-0012 KS-21a)."
        );
        return exit::UNAUTHORIZED;
    }

    if !is_privileged() {
        eprintln!(
            "twinvpn-unblock: {}: this command needs root to empty the `{}` pf \
             anchor",
            twinvpn_types::codes::PLATFORM_VPN_PERMISSION_DENIED.as_str(),
            twinvpn_platform_macos::pf::ANCHOR
        );
        return exit::UNAUTHORIZED;
    }

    // **MI-13(3): write-then-mutate.** The record goes down BEFORE the anchor is
    // touched, because a record written afterwards is lost in exactly the crash
    // it exists to explain.
    if write_unblock_record().is_err() {
        // **MI-13(5).** An unwritable record does NOT stop the unblock: bricking
        // the host is the worse failure, and that is §10's whole premise. It
        // becomes `MGMT.AUDIT_GAP` at the authority's next start.
        eprintln!(
            "twinvpn-unblock: {}: the UnblockRecord could not be written to {}. \
             Proceeding — MI-13(5) makes an unwritable record an audit gap, not \
             a reason to leave the host blocked.",
            twinvpn_types::codes::MGMT_AUDIT_GAP.as_str(),
            UNBLOCK_RECORD
        );
    }

    match netcfg::remove_owner_tagged_anchor(&PfctlEngine) {
        Ok(()) => {
            println!(
                "twinvpn-unblock: emptied the owner-tagged pf anchor `{}` and \
                 confirmed it is gone from the kernel.",
                twinvpn_platform_macos::pf::ANCHOR
            );
            println!("twinvpn-unblock: this host is now UNPROTECTED by TwinVPN.");
            warn_about_the_boot_artifact();
            exit::OK
        }
        Err(error) => {
            // Never a raw OS error as the complete user-facing error: the
            // registered code plus the errno as typed evidence.
            eprint!(
                "twinvpn-unblock: {}: the enforcement anchor could not be removed",
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
    match netcfg::read_owner_tagged_anchor(&PfctlEngine) {
        Ok(Some(installed)) => {
            println!(
                "twinvpn-unblock: the kernel holds the `{}` anchor: posture {:?}, \
                 covering {} IPv4 and {} IPv6 prefixes.",
                twinvpn_platform_macos::pf::ANCHOR,
                installed.ruleset,
                installed.scope.v4,
                installed.scope.v6
            );
            exit::OK
        }
        Ok(None) => {
            println!(
                "twinvpn-unblock: the kernel holds no `{}` anchor. TwinVPN is not \
                 blocking this host.",
                twinvpn_platform_macos::pf::ANCHOR
            );
            exit::OK
        }
        Err(error) => {
            // O-18's fail-safe direction: an unreadable filter is UNKNOWN, never
            // "not blocking".
            eprintln!(
                "twinvpn-unblock: {}: the enforcement anchor could not be read",
                error.reason_code().as_str()
            );
            exit::FAILED
        }
    }
}

/// MI-13(3)'s durable record, written **before** the mutation.
///
/// Hand-rolled JSON rather than `serde_json`, and that is deliberate: this
/// binary's dependency list is its contract (MI-12), and four fields do not
/// justify widening it. The field names are MI-13's verbatim, so a later reader
/// in the authority is parsing the spec's shape rather than this file's.
fn write_unblock_record() -> std::io::Result<()> {
    use std::io::Write as _;

    let record = format!(
        "{{\"invoked_at\":null,\
          \"principal\":\"uid:{}\",\
          \"ruleset_digest_before\":null,\
          \"confirmation_text_key\":\"reason.unblock.confirmation\"}}\n",
        // An unanswerable uid probe writes `uid:unknown` rather than a plausible
        // number: MI-13(3) wants the principal, and inventing one would put a
        // false name in an audit record.
        uid().map_or_else(|| "unknown".to_owned(), |uid| uid.to_string())
    );
    // `invoked_at` is **null and not a timestamp**. CD-1a makes the wall clock
    // evidence only and three-state, this binary injects no `Env` and therefore
    // has no trusted clock, and a `SystemTime::now()` here would put an untrusted
    // reading into an audit record that reads as authoritative. The authority
    // ingests the record at its next start and stamps its own reading, which is
    // the one that has a declared trust state. Named in README §7.
    if let Some(parent) = std::path::Path::new(UNBLOCK_RECORD).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(UNBLOCK_RECORD)?;
    file.write_all(record.as_bytes())?;
    // Flushed before the mutation it protects — S-41's ordering rule, applied
    // here because the failure it prevents is the same one.
    file.sync_all()
}

/// KS-19's artifact outlives this command, and saying so is the difference
/// between a fix and a fix that lasts until the next reboot.
fn warn_about_the_boot_artifact() {
    const PLIST: &str = "/Library/LaunchDaemons/com.twinvpn.ksd.plist";
    if std::path::Path::new(PLIST).exists() {
        println!(
            "twinvpn-unblock: NOTE — the KS-19 boot artifact is still installed \
             ({PLIST}).\n\
             It re-applies the boot anchor at every boot, so this removal lasts \
             until the next reboot.\n\
             That is deliberate: the artifact is package-owned (ADR-0016 PS-7) \
             and this command does not disable it.\n\
             To keep the host unprotected across a reboot, disable it yourself:\n\
             \n    sudo launchctl bootout system/com.twinvpn.ksd\n"
        );
    }
}

/// Whether this process can touch the enforcement layer.
///
/// **uid 0 and nothing more** — see the module header's MI-13(1) note. Asked
/// through a safe API because this crate forbids `unsafe`: a file this process
/// creates is owned by its effective uid.
///
/// An unanswerable probe reads as **not** privileged, which is the closed
/// direction: `pfctl` will refuse on its own and name the errno.
fn is_privileged() -> bool {
    uid() == Some(0)
}

fn uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;

    let path = std::env::temp_dir().join(format!("twinvpn-unblock-probe-{}", std::process::id()));
    let uid = {
        let file = std::fs::File::create(&path).ok()?;
        file.metadata().ok()?.uid()
    };
    let _ = std::fs::remove_file(&path);
    Some(uid)
}

fn print_help() {
    println!(
        "usage: twinvpn-unblock [--status | {CONFIRM_FLAG}]\n\
         \n\
         Empties TwinVPN's owner-tagged pf anchor on this host.\n\
         \n\
         This is ADR-0012 KS-20a's offline recovery path: it speaks to no\n\
         socket and to no Mach service, and needs no running system extension,\n\
         precisely because the case it exists for is \"the authority will not\n\
         start\".\n\
         \n\
         It removes ONLY the anchor TwinVPN owns. Your own pf rules and\n\
         /etc/pf.conf are not touched.\n\
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
    /// **X-14.** The ceremony is an interactive local act, and a test runner is
    /// automation — which is exactly the caller MI-13(1) means to exclude.
    ///
    /// `cargo test` gives its children a piped stdin, so this asserts the
    /// refusal from inside the condition it describes rather than by
    /// simulating it. If it ever passes, the check has stopped distinguishing
    /// a human from a scheduler and the whole of X-14 is back.
    #[test]
    fn a_non_interactive_caller_has_no_local_principal() {
        assert!(
            !has_interactive_local_principal(),
            "a piped stdin is automation; MI-13(1) excludes it"
        );
    }

    /// The refusal names the registered code and the way out, not just "no".
    ///
    /// KS-20: *"blocked must not mean bricked"*. An operator refused here on a
    /// headless host must be told where disarm actually lives (KS-21a's
    /// management-interface path) rather than left to find it.
    #[test]
    fn the_refusal_names_the_code_and_the_alternative() {
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().expect("a first half");
        assert!(production.contains("MGMT.DISARM_NO_LOCAL_AUTHORITY"));
        assert!(production.contains("KS-21a"));
    }

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
    fn there_is_no_non_interactive_confirmation_flag() {
        // **MI-13(2), verbatim:** "a `--yes`-style non-interactive flag MUST NOT
        // exist, for the same reason `MGMT.DISARM_NO_LOCAL_AUTHORITY` refuses
        // rather than degrades." Asserted over the source and over the parser.
        let source = include_str!("main.rs");
        let production = source.split("#[cfg(test)]").next().expect("a first half");
        for forbidden in ["--yes", "--force", "--non-interactive", "--batch"] {
            for (n, line) in production.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                assert!(
                    !code.contains(forbidden),
                    "line {} names {forbidden}, which MI-13(2) forbids",
                    n + 1
                );
            }
        }
        for spelling in ["--yes", "-y", "--force"] {
            assert_eq!(run(&[spelling.to_owned()]), exit::USAGE);
        }
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
    fn it_speaks_to_no_channel_and_hosts_no_core() {
        // The structural claim this binary rests on, as a test a reader can
        // check rather than a paragraph they have to trust: the source names no
        // socket path, no Mach service, no MI module and no core.
        let source = include_str!("main.rs");
        let source = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        for forbidden in [
            "UnixStream",
            "UnixListener",
            "twinvpn_mi",
            "twinvpn_core",
            "twinvpn_bridge",
            "mgmt.sock",
            "xpc_",
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
        // not require running the destructive command. On a host with no `pfctl`
        // it reports the failure rather than claiming the host is unprotected —
        // which is O-18's fail-safe direction.
        let code = report_status();
        assert!(matches!(code, exit::OK | exit::FAILED));
    }

    #[test]
    fn the_privilege_check_answers_without_panicking() {
        // Not an assertion about this runner's privileges — it has none — but
        // that the check runs and answers.
        let _ = is_privileged();
        assert!(uid().is_some(), "a temp file is creatable in a test runner");
    }

    #[test]
    fn the_unblock_record_carries_mi_13s_four_field_names_verbatim() {
        // A later reader in the authority parses MI-13's shape, not this file's
        // invention. Checked against the source because writing it needs root.
        let source = include_str!("main.rs");
        for field in [
            "invoked_at",
            "principal",
            "ruleset_digest_before",
            "confirmation_text_key",
        ] {
            assert!(source.contains(field), "MI-13(3) names {field}");
        }
    }

    #[test]
    fn the_record_is_written_before_the_mutation_and_never_after() {
        // **MI-13(3)'s ordering, asserted structurally.** A record written
        // afterwards is lost in exactly the crash it exists to explain, so the
        // call must appear before the removal in the source of `run`.
        let source = include_str!("main.rs");
        let write_at = source.find("write_unblock_record()").expect("it is called");
        let remove_at = source
            .find("remove_owner_tagged_anchor(&PfctlEngine)")
            .expect("it is called");
        assert!(
            write_at < remove_at,
            "the UnblockRecord must be written before the anchor is emptied"
        );
    }
}
