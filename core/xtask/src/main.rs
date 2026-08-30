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

/// The `core/Cargo.toml` this run must lint, resolved **at run time**.
///
/// # Why not `env!("CARGO_MANIFEST_DIR")`
///
/// That macro bakes the path at COMPILE time, and this repository shares one
/// `CARGO_TARGET_DIR` across the main checkout, every agent worktree and the
/// mutant rig. Cargo's fingerprint does not include `CARGO_MANIFEST_DIR`, so a
/// binary compiled inside one tree is reused in another — and then lints the
/// tree it was BUILT in rather than the tree it was RUN in.
///
/// That is not a cosmetic defect in a merge gate. It fails both ways: it
/// reported a CD-CB3 violation against a `#[cfg(target_os = "ios")]` that had
/// already been removed from the working tree, and it can equally report
/// `all clean` over a tree that is dirty, which is the direction that ships a
/// violation. The same mechanism has previously turned P15 red on a clean tree.
///
/// `CARGO_MANIFEST_DIR` is also set as an ENVIRONMENT variable by
/// `cargo run`, and that one is correct for the current invocation — so it is
/// preferred, with a walk up from the current directory as the fallback for a
/// binary invoked directly.
fn workspace_manifest() -> Result<PathBuf, String> {
    // `core/xtask` -> `core`. The lints run over the core workspace, which is
    // the exact crate set ADR-0018 §11.12 gives them.
    if let Some(dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        let dir = PathBuf::from(dir);
        if let Some(root) = dir.parent() {
            let manifest = root.join("Cargo.toml");
            if manifest.is_file() {
                return Ok(manifest);
            }
        }
    }

    let mut current =
        std::env::current_dir().map_err(|e| format!("cannot read the current directory: {e}"))?;
    loop {
        let candidate = current.join("Cargo.toml");
        // The core workspace is the one whose `crates/` directory holds the
        // members these lints are defined over. Matching on that rather than on
        // the directory's name keeps a rename from silently selecting a
        // different workspace.
        if candidate.is_file() && current.join("crates").is_dir() {
            return Ok(candidate);
        }
        if !current.pop() {
            return Err(
                "cannot locate the core workspace root: no ancestor of the current \
                 directory has both a Cargo.toml and a crates/ directory"
                    .to_owned(),
            );
        }
    }
}

fn usage() {
    eprintln!("usage: cargo run -p xtask -- lint");
    eprintln!();
    eprintln!("  lint   run the T1 checks: CD-3, CD-I2, CD-I5, CD-CB3 (ADR-0018), U-22 (ADR-0021)");
}

fn lint() -> ExitCode {
    let manifest = match workspace_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("xtask: {e}");
            return ExitCode::FAILURE;
        }
    };

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
