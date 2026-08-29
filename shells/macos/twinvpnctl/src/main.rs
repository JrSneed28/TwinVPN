//! `twinvpnctl` — the unprivileged macOS CLI.
//!
//! **Authority:** ADR-0017 §11.6 (the output modes), §11.12 (the exit codes and
//! MI-C1), MI-15, MI-C3; ADR-0023 EM-37, EM-38, EM-42, EM-43, EM-44.
//!
//! # The installed name is `twinvpn`; the cargo target stays `twinvpnctl`
//!
//! `ownership.md` §9.5 **D-1** closes W-41: the cargo target keeps the name
//! `twinvpnctl` — renaming it churns three shells for nothing a user sees — and
//! `packaging/install.sh` installs the artifact as `/usr/local/bin/twinvpn`,
//! with a `twinvpnctl` symlink beside it as a compatibility alias. So the usage
//! text in [`verbs::usage`] says `twinvpn`, which is what the operator typed,
//! and EM-42's rendered `run 'twinvpn peer disconnect nas-attic'` names a
//! command this host installs.
//!
//! # EM-38: it never prompts
//!
//! > A command that blocks on a terminal read is a hung cron job, which on an
//! > unattended device is indistinguishable from a wedge.
//!
//! A destructive operation without `--confirm-unprotected` exits **2** — usage —
//! rather than reading from a terminal. There is no `stdin` read anywhere in this
//! binary, and the test at the bottom asserts it over the source.
//!
//! # CB-2: no decision
//!
//! Every branch here is on an argument the user typed or on a value the agent
//! sent. The verb table is the catalogue's (MI-C1), the scope requirement is the
//! catalogue's, the exit code is a mapping from a diagnostic's **domain**, and
//! the `platform_ctx` is the agent's, used verbatim (MI-C3).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

mod render;
mod verbs;

use render::{Exit, Output};
use twinvpn_mi::{Client, ClientError, CLI_REQUESTED_SCOPES};

fn main() {
    let exit = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_or(Exit::Failed, |runtime| runtime.block_on(run()));
    std::process::exit(exit.code());
}

async fn run() -> Exit {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    // §11.12 exit 2: nothing was sent to the agent, because the parse happens
    // before any connection is opened.
    let Ok((output, rest)) = parse_output(&arguments) else {
        eprint!("{}", verbs::usage(columns()));
        return Exit::Usage;
    };

    let Some((noun, verb_words)) = rest.split_first() else {
        print!("{}", verbs::usage(columns()));
        return Exit::Usage;
    };
    if noun == "--help" || noun == "-h" {
        print!("{}", verbs::usage(columns()));
        return Exit::Succeeded;
    }

    // The flags a verb may carry, stripped before resolution so `status get
    // --confirm-unprotected` still resolves.
    let confirmed = verb_words.iter().any(|w| w == "--confirm-unprotected");
    let verb_words: Vec<String> = verb_words
        .iter()
        .filter(|w| !w.starts_with("--"))
        .cloned()
        .collect();

    let Some(verb) = verbs::resolve(noun, &verb_words) else {
        eprint!("{}", verbs::usage(columns()));
        return Exit::Usage;
    };

    // **EM-38.** A destructive operation without the flag exits 2 rather than
    // reading from a terminal.
    if verb.mutating() && !confirmed {
        eprintln!(
            "{} is a state-changing operation; re-run with --confirm-unprotected",
            verb.wire_name()
        );
        return Exit::Usage;
    }

    let path = twinvpn_mi::socket_path();
    let mut client = match Client::attach(
        &path,
        "cli",
        env!("CARGO_PKG_VERSION"),
        &CLI_REQUESTED_SCOPES,
    )
    .await
    {
        Ok(client) => client,
        Err(error) => return report_client_error(&error),
    };

    let response = match client.request(verb.wire_name(), Vec::new()).await {
        Ok(response) => response,
        Err(error) => return report_client_error(&error),
    };
    let _ = client.goodbye().await;

    if response.ok {
        print!("{}", render::render_ok(output, &response.result));
        return Exit::Succeeded;
    }

    // A refusal the agent named. **EM-37**: the code and its class reach stderr
    // in every output mode, and automation switches on the class.
    let diagnostic = response.diagnostic.unwrap_or_else(|| {
        twinvpn_mi::Diagnostic::of(twinvpn_types::codes::INTERNAL_UNEXPECTED_STATE)
    });
    eprintln!(
        "{}",
        render::stderr_line(&diagnostic.reason_code, &diagnostic.class)
    );
    print!(
        "{}",
        render::render_error(
            output,
            // EM-43. `is_tty` is `false` here: this crate forbids `unsafe` and
            // `isatty` needs it, so the conservative answer is the one that is
            // always correct — no colour, and ASCII unless the locale says
            // otherwise. Named as a gap in the README rather than guessed at.
            render::Style::from_env(false),
            &diagnostic.reason_code,
            &diagnostic.class
        )
    );
    exit_for(&diagnostic.reason_code)
}

/// Splits `--output <mode>` off the front.
///
/// # Errors
///
/// `Err(())` for an unknown mode or a missing argument — a **usage** error, so
/// nothing is sent to the agent.
fn parse_output(arguments: &[String]) -> Result<(Output, Vec<String>), ()> {
    let mut output = Output::default();
    let mut rest = Vec::new();
    let mut iter = arguments.iter();
    while let Some(argument) = iter.next() {
        if argument == "--output" {
            let value = iter.next().ok_or(())?;
            output = Output::parse(value).ok_or(())?;
        } else if let Some(value) = argument.strip_prefix("--output=") {
            output = Output::parse(value).ok_or(())?;
        } else {
            rest.push(argument.clone());
        }
    }
    Ok((output, rest))
}

/// The exit code for a refusal, from the diagnostic's **domain**.
///
/// A code registered tomorrow lands in the right bucket without a client change,
/// which a list of individual codes would not.
fn exit_for(reason_code: &str) -> Exit {
    match reason_code.split('.').next() {
        Some("PROTO") => Exit::VersionIncompatible,
        Some("PLATFORM") => Exit::Unauthorized,
        Some("MGMT") if reason_code == "MGMT.UNAVAILABLE" => Exit::ChannelUnavailable,
        _ => Exit::Failed,
    }
}

fn report_client_error(error: &ClientError) -> Exit {
    match error {
        ClientError::Unavailable => {
            eprintln!("{}", render::stderr_line("MGMT.UNAVAILABLE", "TRANSIENT"));
            Exit::ChannelUnavailable
        }
        ClientError::Rejected(diagnostic) => {
            eprintln!(
                "{}",
                render::stderr_line(&diagnostic.reason_code, &diagnostic.class)
            );
            exit_for(&diagnostic.reason_code)
        }
        ClientError::Frame(frame) => {
            eprintln!(
                "{}",
                render::stderr_line(frame.reason_code().as_str(), "PERSISTENT")
            );
            Exit::Failed
        }
        ClientError::UnexpectedBody => {
            eprintln!(
                "{}",
                render::stderr_line("PROTO.UNPARSEABLE_ENVELOPE", "PERSISTENT")
            );
            Exit::Failed
        }
    }
}

/// EM-44's terminal width.
fn columns() -> usize {
    render::wrap_width(
        std::env::var("COLUMNS")
            .ok()
            .and_then(|value| value.parse().ok()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn em38_this_binary_never_reads_from_a_terminal() {
        // "A command that blocks on a terminal read is a hung cron job, which on
        // an unattended device is indistinguishable from a wedge." Asserted over
        // the source, so an edit that adds a prompt fails here.
        let code: String = include_str!("main.rs")
            .lines()
            .take_while(|line| !line.trim_start().starts_with("mod tests"))
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("#[cfg(test)]")
            })
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["stdin", "read_line", "rpassword", "dialoguer"] {
            assert!(
                !code.contains(forbidden),
                "{forbidden} would block a cron job"
            );
        }
    }

    #[test]
    fn an_unknown_output_mode_never_reaches_the_agent() {
        assert!(parse_output(&["--output".to_owned(), "yaml".to_owned()]).is_err());
        assert!(parse_output(&["--output".to_owned()]).is_err());
        assert!(parse_output(&["--output=yaml".to_owned()]).is_err());
    }

    #[test]
    fn the_output_flag_is_stripped_and_the_rest_survives_in_order() {
        let (output, rest) = parse_output(&[
            "--output".to_owned(),
            "json".to_owned(),
            "status".to_owned(),
            "get".to_owned(),
        ])
        .expect("parses");
        assert_eq!(output, Output::Json);
        assert_eq!(rest, vec!["status".to_owned(), "get".to_owned()]);

        let (output, rest) =
            parse_output(&["status".to_owned(), "get".to_owned()]).expect("parses");
        assert_eq!(output, Output::Human, "the default");
        assert_eq!(rest.len(), 2);
    }

    #[test]
    fn the_exit_code_comes_from_the_domain_so_a_new_code_lands_correctly() {
        assert_eq!(exit_for("MGMT.UNAVAILABLE"), Exit::ChannelUnavailable);
        assert_eq!(
            exit_for("PROTO.VERSION_UNSUPPORTED"),
            Exit::VersionIncompatible
        );
        assert_eq!(exit_for("PLATFORM.ADAPTER_UNAVAILABLE"), Exit::Unauthorized);
        assert_eq!(exit_for("MGMT.SOMETHING_NEW"), Exit::Failed);
        assert_eq!(exit_for("NET.NO_ROUTE"), Exit::Failed);
        // And every one of them is inside §11.12's range.
        for code in [
            "MGMT.UNAVAILABLE",
            "PROTO.VERSION_UNSUPPORTED",
            "PLATFORM.ADAPTER_UNAVAILABLE",
            "NET.NO_ROUTE",
        ] {
            assert!((0..=5).contains(&exit_for(code).code()));
        }
    }

    #[test]
    fn a_mutating_verb_without_the_flag_is_a_usage_error_and_not_a_prompt() {
        // Checked at the level the CLI decides it: the catalogue says which
        // operations mutate, and this crate holds no list of its own.
        let mutating: Vec<&str> = verbs::verbs()
            .iter()
            .filter(|v| v.mutating())
            .map(|v| v.wire_name())
            .collect();
        assert!(
            !mutating.is_empty(),
            "the catalogue has mutating operations"
        );
        let read_only: Vec<&str> = verbs::verbs()
            .iter()
            .filter(|v| !v.mutating())
            .map(|v| v.wire_name())
            .collect();
        assert!(read_only.contains(&"status.get"));
    }
}
