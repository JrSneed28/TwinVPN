//! `twinvpnctl` — the unprivileged Windows CLI over the local management
//! interface.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.12 (the command shape, the output modes, **the exit codes**), MI-1,
//! MI-C1, MI-C2, MI-C3, MI-6, MI-15;
//! [ADR-0023](../../../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md)
//! EM-34, EM-36, EM-37, EM-38, EM-42 … EM-45; ADR-0018 CB-2.
//!
//! # NAMING DEVIATION, reported
//!
//! ADR-0016 §11.2's Windows process table names this binary **`twinvpn.exe`**,
//! ADR-0017 §11.12's command shape is `twinvpn <noun> <verb>`, and EM-42's
//! rendered next actions say `run 'twinvpn peer disconnect nas-attic'`. This
//! domain has named it `twinvpnctl` to match the Linux shell that shipped in
//! wave 1, rather than shipping two different names for one CLI across two
//! platforms. Neither name is this domain's to settle — see `Cargo.toml` and
//! `shells/windows/README.md` §7.
//!
//! # CB-2: this binary holds no decision
//!
//! Every verb comes from [`twinvpnsvc::mi`]'s one vocabulary through [`verbs`],
//! every scope comes from the catalogue, every sentence comes from a
//! `reason_code`'s registered attributes through one shared resolver, and the
//! exit code is a **mapping** of the code's domain rather than a judgement about
//! what it means. MI-C1's own words: "the CLI cannot drift ahead of or behind
//! the contract because it has no logic of its own".
//!
//! # EM-38: non-interactive by default
//!
//! > **Every command MUST complete with no TTY and MUST never prompt.**
//!
//! There is no `read_line` in this binary. A destructive operation without its
//! confirmation flag exits **2** (usage) rather than prompting: "A command that
//! blocks on a terminal read is a hung cron job, which on an unattended device
//! is indistinguishable from a wedge."
//!
//! # Where the transport stops and the conversation starts
//!
//! [`converse`] is generic over the stream, so the whole request/response
//! exchange — the rendering, the exit-code mapping, MI-C3's verbatim
//! `platform_ctx` — **runs its tests on a Linux host** over
//! `tokio::io::duplex`. Only [`connect_and_converse`] names a named pipe, and
//! that call has never executed.

#![forbid(unsafe_code)]

mod exit;
mod render;
mod verbs;

use std::io::IsTerminal as _;
use std::process::ExitCode;

use tokio::io::{AsyncRead, AsyncWrite};
use twinvpnsvc::mi::{self, Client, ClientError};

/// The locale renders default to.
///
/// ADR-0019 ships one source locale, and `twinvpn_diag::render`'s fallback chain
/// counts a request for anything else as a lower rung — which is the number
/// §11.5 asks to be *measurable*. `--locale` overrides it.
const DEFAULT_LOCALE: &str = "en";

/// The agent's `platform_ctx`, as the resolver's own type.
///
/// **MI-C3**: the agent supplied it and every client uses it verbatim, so a CLI
/// and a GUI on one host render the same next action for the same diagnostic. An
/// unrecognised platform name resolves to the NEUTRAL variant rather than to
/// this host's own (LT-3b) — which on a Windows CLI is the difference between a
/// correct answer and a lucky one.
fn platform_context(ctx: &mi::PlatformCtx) -> twinvpn_diag::PlatformContext {
    let tag = match ctx.platform.to_ascii_uppercase().as_str() {
        "LINUX" => Some("LINUX"),
        "OPENWRT" => Some("OPENWRT"),
        "ANDROID" => Some("ANDROID"),
        "IOS" => Some("IOS"),
        "IPADOS" => Some("IPADOS"),
        "MACOS" => Some("MACOS"),
        "WINDOWS" => Some("WINDOWS"),
        _ => None,
    };
    twinvpn_diag::PlatformContext {
        platform: tag,
        os_version: if ctx.os_version.is_empty() {
            None
        } else {
            Some(ctx.os_version.clone())
        },
    }
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
    // §11.12's table is closed: six values, 6–63 reserved, 64+ prohibited.
    // Asserting **membership** rather than a bound is what catches a seventh
    // value added without a rule, which a `<= 63` check would let through.
    debug_assert!(
        exit::ALL.contains(&code) && code <= exit::MAX_PERMITTED,
        "{code} is not one of ADR-0017 §11.12's six exit codes"
    );
    ExitCode::from(code)
}

fn run(args: &[String], stdout_is_tty: bool) -> Result<u8, String> {
    let mut output = Output::default_for(stdout_is_tty);
    let mut positional: Vec<&str> = Vec::new();
    let mut confirmed = false;
    // **CD-2 / LT-3b: explicit, never ambient.** `LANG` is deliberately NOT
    // read. A rendering that changes with the operator's environment makes an
    // incident record vary between the person who saw the failure and the person
    // reading the transcript, and ADR-0023's whole surface exists to be a
    // reliable incident record on a machine with no window to screenshot.
    let mut locale = DEFAULT_LOCALE.to_owned();

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
            "--locale" => {
                locale = iter.next().ok_or("--locale needs a value")?.clone();
            }
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
        return Ok(connect_and_converse(
            request_for("mi.catalogue.get"),
            output,
            stdout_is_tty,
            locale,
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

    Ok(connect_and_converse(
        request_for(op.name()),
        output,
        stdout_is_tty,
        locale,
    ))
}

/// A request with no parameters.
///
/// Parameter marshalling is MI-C1's "argument marshalling" and belongs here when
/// there are arguments to marshal; there are none in this wave, and an empty
/// `params` is the honest encoding of that rather than a placeholder.
fn request_for(operation: &str) -> mi::Request {
    mi::Request {
        operation: operation.to_owned(),
        params: Vec::new(),
        if_version: None,
    }
}

/// Builds a runtime, opens the pipe, and hands the connected client to
/// [`converse`].
///
/// **The only function in this binary that names a transport.** Everything it
/// does after `connect` is [`converse`]'s, which is generic and host-tested.
fn connect_and_converse(
    request: mi::Request,
    output: Output,
    stdout_is_tty: bool,
    locale: String,
) -> u8 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("MGMT.UNAVAILABLE");
            eprintln!("twinvpnctl: the local runtime could not start");
            return exit::UNAVAILABLE;
        }
    };

    runtime.block_on(async move {
        let requested: Vec<String> = mi::CLI_REQUESTED_SCOPES
            .iter()
            .map(|s| s.name().to_owned())
            .collect();

        #[cfg(windows)]
        let attached = Client::connect(
            &mi::pipe_name(),
            "cli",
            env!("CARGO_PKG_VERSION"),
            &requested,
        )
        .await;

        // On a host that is not Windows there is no named pipe to open. The
        // binary is not shipped for one — this arm exists so the crate compiles
        // and its host tests run, and it reports the honest condition rather
        // than pretending to have tried.
        #[cfg(not(windows))]
        let attached = {
            let _ = &requested;
            Err::<Client<tokio::io::DuplexStream>, ClientError>(ClientError::Unavailable(
                mi::FrameError::Closed,
            ))
        };

        match attached {
            Ok(client) => converse(client, request, output, stdout_is_tty, &locale).await,
            // No `HelloAck` arrived, so there is no agent-supplied
            // `platform_ctx`. LT-3b: an absent platform resolves to the NEUTRAL
            // variant and MUST NOT fall back to this host's own.
            Err(error) => report(
                &error,
                output,
                stdout_is_tty,
                &locale,
                &twinvpn_diag::PlatformContext::neutral(),
            ),
        }
    })
}

/// Sends one request on an attached client, renders the outcome, and returns
/// §11.12's exit code.
///
/// Generic over the stream, which is what makes this — the part where a mistake
/// is a wrong exit code in somebody's CI — runnable on this host.
async fn converse<S>(
    mut client: Client<S>,
    request: mi::Request,
    output: Output,
    stdout_is_tty: bool,
    locale: &str,
) -> u8
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match client
        .call(
            &request.operation,
            request.params,
            request.if_version,
            Vec::new(),
        )
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
                        // MI-6: the caller must observe an event at or past this
                        // before telling a human it is complete. Saying so is
                        // what keeps this CLI honest until the event stream is
                        // wired.
                        println!(
                            "       committed_at_net_seq={cursor}; not yet confirmed by an event"
                        );
                    }
                }
                Output::Json | Output::JsonLines => {
                    // MI-C2: `--output json` is the stable machine surface,
                    // carries `mi_version`, and renders 64-bit integers as
                    // STRINGS (ADR-0003 §11 rule 2) — "a script that treats them
                    // as JSON numbers loses precision silently".
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
        // **MI-C3.** The agent's `platform_ctx`, used verbatim — never one this
        // client constructed from its own build constants.
        Err(error) => {
            let platform = platform_context(client.platform_ctx());
            report(&error, output, stdout_is_tty, locale, &platform)
        }
    }
}

/// Renders a failure and maps it to §11.12's exit code.
///
/// **The code goes to stderr in every output mode**, "so a `set -e` script that
/// does not parse JSON still gets it".
fn report(
    error: &ClientError,
    output: Output,
    stdout_is_tty: bool,
    locale: &str,
    platform: &twinvpn_diag::PlatformContext,
) -> u8 {
    let code = error.reason_code().to_owned();
    let exit = exit::for_reason_code(&code);

    // stderr, always, in every mode.
    eprintln!("{code}");
    if let Some(class) = error.class() {
        // EM-37: automation switches on `class`, not on the exit code. Emitting
        // it on stderr too means a script has it without parsing JSON.
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
            let rendered =
                render::Rendered::from_diagnostic("UNKNOWN", &diagnostic, locale, platform);
            // EM-43: colour is applied ONLY when every condition holds, and the
            // `[CRIT]`/`[ERR!]` token is present either way — severity is never
            // carried by colour alone.
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
    // ASCII wherever `LANG`/`LC_ALL` does not say UTF-8 — which on a Windows
    // console is normally, and a console whose code page is not UTF-8 renders a
    // multi-byte glyph as mojibake.
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
    use twinvpnsvc::mi::codec::{read_frame, write_frame};
    use twinvpnsvc::mi::wire::{Body, HelloAck, MgmtEnvelope, PlatformCtx, Response};





    #[test]
    fn the_output_default_follows_isatty() {
        // EM-36 / §11.12: json when stdout is not a TTY, human when it is.
        assert_eq!(Output::default_for(true), Output::Human);
        assert_eq!(Output::default_for(false), Output::Json);
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

    /// A `HelloAck` an agent would send.
    fn hello_ack(platform: &str) -> HelloAck {
        HelloAck {
            mi_version: mi::MI_VERSION,
            agent_version: "0.1.0".to_owned(),
            build_profile: "test".to_owned(),
            granted_scopes: vec!["mgmt.status".to_owned()],
            withheld_scopes: Vec::new(),
            catalogue_digest: twinvpn_mgmt::catalogue_digest().to_string(),
            event_cursor: 0,
            protocol_epoch_range: [1, 1],
            platform_ctx: PlatformCtx {
                platform: platform.to_owned(),
                os_version: "10.0.22631".to_owned(),
            },
        }
    }

    fn envelope(body: Body) -> MgmtEnvelope {
        MgmtEnvelope {
            mi_version: mi::MI_VERSION,
            request_id: vec![9; 16],
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 7,
            body,
        }
    }

    /// Spawns an agent side that completes the negotiation and then answers the
    /// one request with `reply`.
    ///
    /// Factored because the two exchanges below differ in exactly one value, and
    /// two copies of the handshake would make the difference the hard thing to
    /// see.
    fn agent_answering(
        mut agent_side: tokio::io::DuplexStream,
        reply: Body,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // The client speaks first: MI-3 gives the agent no way to open.
            let hello = read_frame(&mut agent_side).await.expect("a Hello");
            assert!(
                matches!(hello.body, Body::Hello(_)),
                "the client speaks first"
            );
            write_frame(
                &mut agent_side,
                &envelope(Body::HelloAck(Box::new(hello_ack("WINDOWS")))),
            )
            .await
            .expect("HelloAck");

            let request = read_frame(&mut agent_side).await.expect("a Request");
            assert!(matches!(request.body, Body::Request(_)));
            write_frame(&mut agent_side, &envelope(reply))
                .await
                .expect("the reply");
        })
    }

    fn ok_response() -> Body {
        Body::Response(Response {
            ok: true,
            result: Vec::new(),
            diagnostic: None,
            committed_at_net_seq: None,
        })
    }

    fn denied_response() -> Body {
        Body::Response(Response {
            ok: false,
            result: Vec::new(),
            diagnostic: Some(mi::Diagnostic {
                reason_code: "POLICY.POLICY_DENIED".to_owned(),
                class: "POLICY".to_owned(),
                severity: "ERROR".to_owned(),
                user_actionable: true,
                summary_key: None,
                next_action_key: None,
                evidence: Vec::new(),
            }),
            committed_at_net_seq: None,
        })
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime")
    }

    /// **The end-to-end exchange, on a host with no named pipe.**
    ///
    /// `mi::Client` is generic over the transport precisely so this test can
    /// exist: a hand-written agent on one end of a `tokio::io::duplex`, the real
    /// client and the real [`converse`] on the other. Everything between the
    /// `Hello` and the exit code is the production path.
    #[test]
    fn a_full_attach_and_call_succeeds_over_an_in_memory_transport() {
        runtime().block_on(async {
            let (client_side, agent_side) = tokio::io::duplex(64 * 1024);
            let agent = agent_answering(agent_side, ok_response());

            let client = Client::attach(client_side, "cli", "0.1.0", &["mgmt.status".to_owned()])
                .await
                .expect("attaches");
            // MI-C3: the agent's `platform_ctx`, verbatim.
            assert_eq!(client.platform_ctx().platform, "WINDOWS");
            assert_eq!(
                client.catalogue_digest(),
                twinvpn_mgmt::catalogue_digest().to_string()
            );

            let code = converse(
                client,
                request_for("status.get"),
                Output::Json,
                false,
                DEFAULT_LOCALE,
            )
            .await;
            assert_eq!(code, exit::OK);
            agent.await.expect("the agent side finished");
        });
    }

    /// The same exchange, with the agent naming a failure.
    #[test]
    fn an_agent_named_failure_becomes_its_mapped_exit_code_and_never_a_guess() {
        runtime().block_on(async {
            let (client_side, agent_side) = tokio::io::duplex(64 * 1024);
            let agent = agent_answering(agent_side, denied_response());

            let client = Client::attach(client_side, "cli", "0.1.0", &["mgmt.status".to_owned()])
                .await
                .expect("attaches");
            let code = converse(
                client,
                request_for("net.up"),
                Output::Json,
                false,
                DEFAULT_LOCALE,
            )
            .await;
            assert_eq!(
                code,
                exit::UNAUTHORIZED,
                "the agent named an authorization refusal"
            );
            agent.await.expect("the agent side finished");
        });
    }

    /// §11.7 forbids a silent close, and the client must report the agent's own
    /// reason rather than "the agent is not running" — which is the difference
    /// between exit 4 and exit 3, and between "you are not allowed" and
    /// "reinstall the product".
    #[test]
    fn a_rejected_attach_reports_the_agents_reason_and_not_an_absent_endpoint() {
        runtime().block_on(async {
            let (client_side, mut agent_side) = tokio::io::duplex(64 * 1024);
            let agent = tokio::spawn(async move {
                let _ = read_frame(&mut agent_side).await.expect("a Hello");
                write_frame(
                    &mut agent_side,
                    &envelope(Body::Reject(mi::Diagnostic {
                        reason_code: "MGMT.PRINCIPAL_UNVERIFIABLE".to_owned(),
                        class: "PERSISTENT".to_owned(),
                        severity: "ERROR".to_owned(),
                        user_actionable: true,
                        summary_key: None,
                        next_action_key: None,
                        evidence: Vec::new(),
                    })),
                )
                .await
                .expect("Reject");
            });

            let error = Client::attach(client_side, "cli", "0.1.0", &["mgmt.status".to_owned()])
                .await
                .err()
                .expect("refused");
            assert_eq!(error.reason_code(), "MGMT.PRINCIPAL_UNVERIFIABLE");
            assert_eq!(
                exit::for_reason_code(error.reason_code()),
                exit::UNAUTHORIZED,
                "a refusal is 4, not 3 — the endpoint was there"
            );
            agent.await.expect("the agent side finished");
        });
    }
}
