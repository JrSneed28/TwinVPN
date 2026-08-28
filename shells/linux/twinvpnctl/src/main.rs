//! `twinvpnctl` — the unprivileged Linux CLI over the local management
//! interface.
//!
//! **Authority:** [ADR-0017](../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.12 (the command shape, the output modes, **the exit codes**), MI-1,
//! MI-C1, MI-C2, MI-C3, MI-6, MI-15;
//! [ADR-0023](../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! EM-34, EM-36, EM-37, EM-38, EM-42 … EM-45; ADR-0018 CB-2.
//!
//! # NAMING DEVIATION, reported
//!
//! ADR-0016 §11.2 and ADR-0017 §11.12 both name this binary **`twinvpn`**, and
//! EM-42's rendered next actions say `run 'twinvpn peer disconnect nas-attic'`.
//! The path this domain was given is `twinvpnctl`, and renaming a
//! integration-lead-placed directory is not this domain's to do. See
//! `Cargo.toml` and `shells/linux/README.md`.
//!
//! # CB-2: this binary holds no decision
//!
//! Every verb comes from [`twinvpnd::mi`]'s one vocabulary through
//! [`verbs`], every scope comes from the catalogue, every sentence comes from a
//! `reason_code`'s registered attributes, and the exit code is a **mapping** of
//! the code's domain rather than a judgement about it. MI-C1's own words:
//! "the CLI cannot drift ahead of or behind the contract because it has no logic
//! of its own".
//!
//! # EM-38: non-interactive by default
//!
//! > **Every command MUST complete with no TTY and MUST never prompt.**
//!
//! There is no `read_line` in this binary. A destructive operation without its
//! confirmation flag exits **2** (usage) rather than prompting: "A command that
//! blocks on a terminal read is a hung cron job, which on an unattended device
//! is indistinguishable from a wedge."

#![forbid(unsafe_code)]

mod render;
mod verbs;

use std::io::IsTerminal as _;
use std::process::ExitCode;

use twinvpnd::mi::{self, Client, ClientError};

/// ADR-0017 §11.12's exit codes. **Six values, and 64+ is prohibited.**
///
/// > 64+ MUST NOT be used, to avoid collision with `sysexits.h` and shell
/// > conventions (124/125/126/127, 128+n).
mod exit {
    /// The operation succeeded.
    pub const OK: u8 = 0;
    /// Failed for a reason the agent named.
    pub const FAILED: u8 = 1;
    /// Usage error. **Nothing was sent to the agent.**
    pub const USAGE: u8 = 2;
    /// The management channel is unavailable — distinct from `FAILED`.
    pub const UNAVAILABLE: u8 = 3;
    /// Authorization refused — distinct so a script can tell "re-run with
    /// privilege" from "this will never work".
    pub const UNAUTHORIZED: u8 = 4;
    /// Version incompatible.
    pub const VERSION: u8 = 5;
    /// The highest value this CLI may ever use.
    pub const MAX_PERMITTED: u8 = 63;
}

/// How output is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    /// §11.12: the default **when stdout is a TTY**.
    Human,
    /// The default when stdout is **not** a TTY. "**The stable machine
    /// surface.**"
    Json,
    /// One object per line, for streams.
    JsonLines,
}

impl Output {
    /// EM-36: the default follows `isatty`, and `--output human` can be forced
    /// "because on a headless box the human rendering is the incident record and
    /// there is no window to screenshot".
    fn default_for(stdout_is_tty: bool) -> Self {
        if stdout_is_tty {
            Self::Human
        } else {
            Self::Json
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "human" => Some(Self::Human),
            "json" => Some(Self::Json),
            "json-lines" => Some(Self::JsonLines),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout_is_tty = std::io::stdout().is_terminal();

    let code = match run(&args, stdout_is_tty) {
        Ok(code) => code,
        Err(usage) => {
            // Exit 2, and nothing was sent to the agent.
            eprintln!("twinvpnctl: {usage}");
            eprintln!("usage: twinvpnctl [--output human|json|json-lines] <noun> <verb>");
            eprintln!("       twinvpnctl --help");
            exit::USAGE
        }
    };
    debug_assert!(code <= exit::MAX_PERMITTED, "§11.12 forbids 64+");
    ExitCode::from(code)
}

fn run(args: &[String], stdout_is_tty: bool) -> Result<u8, String> {
    let mut output = Output::default_for(stdout_is_tty);
    let mut positional: Vec<&str> = Vec::new();
    let mut confirmed = false;

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(exit::OK);
            }
            "--output" => {
                let value = iter.next().ok_or("--output needs a value")?;
                output =
                    Output::parse(value).ok_or_else(|| format!("unknown output mode: {value}"))?;
            }
            // EM-38 / EM-39(3): a **typed confirmation naming the target**, not
            // a bare `--yes`. ADR-0017 MI-13(2) forbids a `--yes`-style flag on
            // the offline unblock command, and reconciling the two rules is what
            // EM-39(3)'s named flag is for.
            "--confirm-unprotected" => confirmed = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            other => positional.push(other),
        }
    }

    let (noun, verb) = match positional.as_slice() {
        [] => {
            print_help();
            return Ok(exit::OK);
        }
        [single] => (*single, ""),
        [noun, verb, ..] => (*noun, *verb),
    };

    // MI-21's four, and the aliases, before the catalogue lookup — because
    // `mi.catalogue.get` is not a core command and never will be (§11.16 (o)).
    if noun == "mi" && verb == "catalogue.get" {
        return Ok(call(
            mi::wire::Request {
                operation: "mi.catalogue.get".to_owned(),
                params: Vec::new(),
                if_version: None,
            },
            output,
            stdout_is_tty,
        ));
    }

    let op = verbs::resolve(noun, verb)
        .or_else(|| {
            verbs::ALIASES
                .into_iter()
                .find(|(alias, _)| *alias == noun && verb.is_empty())
                .map(|(_, op)| op)
        })
        .ok_or_else(|| {
            format!(
                "unknown operation: {noun}{}{verb}",
                if verb.is_empty() { "" } else { " " }
            )
        })?;

    let entry = twinvpn_mgmt::catalogue::entry(op);
    // EM-38: a destructive operation without its confirmation exits **2**
    // (usage) rather than prompting, defaulting, or hanging.
    if entry.administer && !confirmed {
        return Err(format!(
            "{} is an ADMINISTER operation and needs --confirm-unprotected",
            op.name()
        ));
    }

    Ok(call(
        mi::wire::Request {
            operation: op.name().to_owned(),
            params: Vec::new(),
            if_version: None,
        },
        output,
        stdout_is_tty,
    ))
}

/// Connects, calls, renders, and maps the outcome to an exit code.
fn call(request: mi::wire::Request, output: Output, stdout_is_tty: bool) -> u8 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("twinvpnctl: MGMT.UNAVAILABLE: the local runtime could not start");
            return exit::UNAVAILABLE;
        }
    };

    runtime.block_on(async move {
        let requested: Vec<String> = mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|s| s.name().to_owned())
            .collect();
        let mut client = match Client::connect(
            &mi::socket_path(),
            "cli",
            env!("CARGO_PKG_VERSION"),
            &requested,
        )
        .await
        {
            Ok(client) => client,
            Err(error) => return report(&error, output, stdout_is_tty),
        };

        match client
            .call(&request.operation, request.params, request.if_version, Vec::new())
            .await
        {
            Ok(response) => {
                match output {
                    Output::Human => {
                        // EM-45: `status` prints the derived state first. With no
                        // state in the response yet, the honest line is the
                        // operation and its cursor — never an invented state.
                        println!("[info] {} accepted", request.operation);
                        if let Some(cursor) = response.committed_at_net_seq {
                            // MI-6: the caller must observe an event at or past
                            // this before telling a human it is complete. Saying
                            // so is what keeps this CLI honest until the event
                            // stream is wired.
                            println!(
                                "       committed_at_net_seq={cursor}; not yet confirmed by an event"
                            );
                        }
                    }
                    Output::Json | Output::JsonLines => {
                        // MI-C2: `--output json` is the stable machine surface,
                        // carries `mi_version`, and renders 64-bit integers as
                        // STRINGS (ADR-0003 §11 rule 2) — "a script that treats
                        // them as JSON numbers loses precision silently".
                        let body = serde_json::json!({
                            "mi_version": client.mi_version(),
                            "operation": request.operation,
                            "ok": response.ok,
                            "committed_at_net_seq":
                                response.committed_at_net_seq.map(|c| c.to_string()),
                            "platform_ctx": {
                                // MI-C3: the AGENT's, verbatim.
                                "platform": client.platform_ctx().platform,
                                "os_version": client.platform_ctx().os_version,
                            },
                            "catalogue_digest": client.catalogue_digest(),
                            "agent_version": client.agent_version(),
                        });
                        println!("{body}");
                    }
                }
                exit::OK
            }
            Err(error) => report(&error, output, stdout_is_tty),
        }
    })
}

/// Renders a failure and maps it to §11.12's exit code.
///
/// **The code goes to stderr in every output mode**, "so a `set -e` script that
/// does not parse JSON still gets it".
fn report(error: &ClientError, output: Output, stdout_is_tty: bool) -> u8 {
    let code = error.reason_code().to_owned();
    let exit = exit_for(&code);

    // stderr, always, in every mode.
    eprintln!("{code}");
    if let Some(class) = error.class() {
        // EM-37: automation switches on `class`, not on the exit code. Emitting
        // it on stderr too means a `set -e` script has it without parsing JSON.
        eprintln!("class: {class}");
    }

    let diagnostic = match error {
        ClientError::Rejected(d) | ClientError::Failed(d) => (**d).clone(),
        _ => mi::Diagnostic {
            reason_code: code.clone(),
            class: "TRANSIENT".to_owned(),
            severity: "ERROR".to_owned(),
            user_actionable: true,
            summary_key: None,
            next_action_key: None,
            evidence: Vec::new(),
        },
    };

    match output {
        Output::Human => {
            let rendered = render::Rendered::from_diagnostic("UNKNOWN", &diagnostic);
            // EM-43: colour is applied ONLY when all three conditions hold, and
            // the `[CRIT]`/`[ERR!]` token is present either way — severity is
            // never carried by colour alone.
            let colour = render::use_colour(stdout_is_tty);
            for (index, line) in rendered.to_lines(render::width()).into_iter().enumerate() {
                if colour && index == 0 {
                    eprintln!("\u{1b}[1m{line}\u{1b}[0m");
                } else {
                    eprintln!("{line}");
                }
            }
        }
        Output::Json | Output::JsonLines => {
            let body = serde_json::json!({
                "ok": false,
                "reason_code": diagnostic.reason_code,
                "class": diagnostic.class,
                "severity": diagnostic.severity,
                "user_actionable": diagnostic.user_actionable,
                "summary_key": diagnostic.summary_key,
            });
            println!("{body}");
        }
    }
    exit
}

/// §11.12's exit-code table, as a mapping of the code's **domain**.
///
/// A mapping and not a judgement: the CLI does not decide what went wrong, it
/// translates the agent's answer into the number a script switches on. EM-37
/// makes retryability the `class`'s job, not this one's.
#[must_use]
fn exit_for(reason_code: &str) -> u8 {
    match reason_code {
        "MGMT.UNAVAILABLE" => exit::UNAVAILABLE,
        "PROTO.VERSION_UNSUPPORTED" => exit::VERSION,
        // The authorization family. ADR-0017 spells the first
        // `PLATFORM.PRIV.CLIENT_UNAUTHORIZED`, which is unregistered; the agent
        // emits `POLICY.POLICY_DENIED` in its place (the substitution and its
        // cost are in `twinvpnd::agent::privilege::SUBSTITUTIONS`), so this maps
        // BOTH spellings and keeps working the day the code is registered.
        "PLATFORM.PRIV.CLIENT_UNAUTHORIZED"
        | "PLATFORM.PRIV.ADMIN_AUTH_FAILED"
        | "PLATFORM.PRIV.REMOTE_ADMIN_REFUSED"
        | "POLICY.POLICY_DENIED"
        | "MGMT.DISARM_REQUIRES_LOCAL_AUTH" => exit::UNAUTHORIZED,
        "MGMT.PRINCIPAL_UNVERIFIABLE" => exit::UNAUTHORIZED,
        _ => exit::FAILED,
    }
}

fn print_help() {
    println!("twinvpnctl — the TwinVPN local management CLI");
    println!();
    println!("usage: twinvpnctl [--output human|json|json-lines] <noun> <verb>");
    println!();
    println!("operations (generated from the core's command catalogue — MI-C1):");
    let mut last_noun = "";
    for verb in verbs::verbs() {
        if verb.noun != last_noun {
            println!();
            last_noun = verb.noun;
        }
        println!(
            "  {:<28} {:<18}{}",
            format!("{} {}", verb.noun, verb.verb).trim_end(),
            verb.scope.name(),
            if verb.administer {
                "  [ADMINISTER]"
            } else {
                ""
            }
        );
    }
    println!();
    println!("connection operations (ADR-0017 MI-21's closed set):");
    for (name, _) in verbs::transport_verbs() {
        let (noun, verb) = name.split_once('.').unwrap_or((name, ""));
        let shape = format!("{noun} {verb}");
        println!("  {:<28} mgmt.status", shape.trim_end());
    }
    println!();
    println!("aliases:");
    for (alias, op) in verbs::ALIASES {
        println!("  {alias:<28} -> {}", op.name());
    }
    println!();
    // EM-43: the middle dot is a UTF-8 glyph, so the separator falls back to
    // ASCII wherever LANG/LC_ALL does not say UTF-8. The renderer must be fully
    // legible in US-ASCII on a busybox serial console.
    let sep = if render::use_unicode() { " · " } else { " | " };
    println!(
        "exit codes: {}",
        [
            "0 ok",
            "1 failed",
            "2 usage",
            "3 unavailable",
            "4 unauthorized",
            "5 version"
        ]
        .join(sep)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_exit_code_is_below_the_prohibited_range() {
        // §11.12: "64+ MUST NOT be used, to avoid collision with sysexits.h and
        // shell conventions (124/125/126/127, 128+n)."
        for code in [
            exit::OK,
            exit::FAILED,
            exit::USAGE,
            exit::UNAVAILABLE,
            exit::UNAUTHORIZED,
            exit::VERSION,
        ] {
            assert!(
                code <= exit::MAX_PERMITTED,
                "{code} is in the reserved range"
            );
        }
        assert_eq!(exit::MAX_PERMITTED, 63);
    }

    #[test]
    fn an_unavailable_channel_is_a_different_exit_from_a_refusal() {
        // "distinct from 1", and "distinct so a script can tell re-run with
        // privilege from this will never work".
        assert_eq!(exit_for("MGMT.UNAVAILABLE"), exit::UNAVAILABLE);
        assert_eq!(exit_for("POLICY.POLICY_DENIED"), exit::UNAUTHORIZED);
        assert_eq!(exit_for("PROTO.VERSION_UNSUPPORTED"), exit::VERSION);
        assert_eq!(exit_for("DNS.STUB.BIND_FAILED"), exit::FAILED);
        assert_ne!(
            exit_for("MGMT.UNAVAILABLE"),
            exit_for("POLICY.POLICY_DENIED")
        );
    }

    #[test]
    fn the_authorization_family_maps_both_the_specified_and_the_substituted_spelling() {
        // So the mapping keeps working the day W-18's amendment registers
        // `PLATFORM.PRIV.CLIENT_UNAUTHORIZED`.
        assert_eq!(
            exit_for("PLATFORM.PRIV.CLIENT_UNAUTHORIZED"),
            exit_for("POLICY.POLICY_DENIED")
        );
    }

    #[test]
    fn the_output_default_follows_isatty() {
        // EM-36 / §11.12: json when stdout is not a TTY, human when it is.
        assert_eq!(Output::default_for(true), Output::Human);
        assert_eq!(Output::default_for(false), Output::Json);
        // And it can be forced either way.
        assert_eq!(Output::parse("human"), Some(Output::Human));
        assert_eq!(Output::parse("json-lines"), Some(Output::JsonLines));
        assert_eq!(Output::parse("yaml"), None);
    }

    #[test]
    fn an_unknown_operation_is_a_usage_error_and_nothing_is_sent() {
        // Exit 2's whole meaning: "Nothing was sent to the agent."
        let err =
            run(&["status".to_owned(), "gett".to_owned()], false).expect_err("unknown operation");
        assert!(err.contains("unknown operation"));
    }

    #[test]
    fn an_unknown_flag_is_a_usage_error() {
        let err = run(&["--wat".to_owned()], false).expect_err("unknown flag");
        assert!(err.contains("unknown flag"));
    }

    #[test]
    fn em38_an_administer_operation_without_its_confirmation_exits_usage_not_a_prompt() {
        // "A command that blocks on a terminal read is a hung cron job, which on
        // an unattended device is indistinguishable from a wedge."
        let err = run(&["killswitch".to_owned(), "mode.set".to_owned()], false)
            .expect_err("needs confirmation");
        assert!(err.contains("--confirm-unprotected"), "{err}");
    }

    #[test]
    fn help_exits_zero_and_lists_only_catalogue_operations() {
        assert_eq!(run(&["--help".to_owned()], false).expect("help"), exit::OK);
        // MI-C1: every listed verb is a catalogue operation.
        for verb in verbs::verbs() {
            assert!(twinvpn_mgmt::CoreCommand::ALL.contains(&verb.op));
        }
    }

    #[test]
    fn no_argument_prints_help_rather_than_hanging() {
        assert_eq!(run(&[], false).expect("help"), exit::OK);
    }
}
