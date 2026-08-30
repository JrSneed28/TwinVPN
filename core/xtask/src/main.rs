//! `cargo run -p xtask -- lint` — the T1 architectural lints.
//!
//! See the library crate's documentation for what each check asserts and why it
//! is a build step rather than a review checklist.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    match command.as_deref() {
        Some("lint") => lint(),
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`");
            usage();
            ExitCode::FAILURE
        }
        None => {
            usage();
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!("usage: cargo run -p xtask -- lint");
    eprintln!();
    eprintln!("  lint   run the T1 checks: CD-3, CD-I2, CD-I5, CD-CB3 (ADR-0018), U-22 (ADR-0021)");
}

fn lint() -> ExitCode {
    // `core/xtask` -> `core`. The lints run over the core workspace, which is the
    // exact crate set ADR-0018 §11.12 gives them.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace_root) = manifest_dir.parent() else {
        eprintln!("xtask: cannot locate the core workspace root");
        return ExitCode::FAILURE;
    };
    let manifest = workspace_root.join("Cargo.toml");

    let violations = match xtask::run(&manifest) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("xtask: {e}");
            return ExitCode::FAILURE;
        }
    };

    if violations.is_empty() {
        println!("xtask lint: CD-3, CD-I2, CD-I5, CD-CB3, U-22 — all clean");
        return ExitCode::SUCCESS;
    }

    eprintln!("xtask lint: {} violation(s)", violations.len());
    for v in &violations {
        eprintln!("  {v}");
    }
    eprintln!();
    eprintln!("ADR-0018 CD-3: \"A violation fails the merge.\"");
    ExitCode::FAILURE
}
