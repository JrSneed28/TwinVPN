//! TwinVPN T1 architectural lints.
//!
//! **Authority:** ADR-0018 §11.7 (CD-I2, CD-I5, CD-CB3) and §11.8 (CD-3),
//! `docs/architecture.md` §5.2 R-DET-1a, `docs/testing-strategy.md` §6.
//!
//! ADR-0018 CD-3 is explicit that the deny-list *is* the mechanism — "a
//! violation fails the merge" — so these belong in the build, not in a review
//! checklist. R-DET-1a says the same thing about determinism: "a requirement of
//! this kind without a mechanical check is an aspiration."
//!
//! | Check | Rule | What it asserts |
//! |---|---|---|
//! | [`checks::cd3`] | CD-3 | no `SystemTime::now`, `Instant::now`, `getrandom`, thread-local RNG, the runtime's time module, `chrono` now-constructors or platform time syscall outside `twinvpn-env/src/binding/` |
//! | [`checks::cd_i2`] | CD-I2 | only `twinvpn-crypto` declares a cryptographic dependency |
//! | [`checks::cd_i5`] | CD-I5 | no data-plane crate reaches `twinvpn-cp-client`, directly or **transitively**; the reverse edge is equally denied; only the composition root names both |
//! | [`checks::cb3`] | CD-CB3 | no `#[cfg(target_os = …)]` outside a `twinvpn-platform-*` crate |
//! | [`checks::u22_updater_unlinked`] | U-22 | no data-plane, state-machine or platform-adapter crate links the updater, directly or **transitively** (ADR-0021 §11.9) |
//!
//! Each check is a pure function over data, so `tests/lints_fire.rs` plants a
//! deliberate violation and asserts it fires. A lint that has never been seen to
//! fail is not a lint.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

pub mod checks;
pub mod manifest;
pub mod source;

use std::path::{Path, PathBuf};

pub use checks::Violation;
use manifest::Workspace;
use source::ScannedFile;

/// Runs every T1 check over the workspace rooted at `manifest_path`.
///
/// # Errors
///
/// A string describing why the workspace could not be read.
pub fn run(manifest_path: &Path) -> Result<Vec<Violation>, String> {
    let workspace = Workspace::load(manifest_path)?;
    let root = PathBuf::from(&workspace.root);

    let mut violations = Vec::new();
    violations.extend(checks::cd_i2(&workspace));
    violations.extend(checks::cd_i5(&workspace));
    violations.extend(checks::cd_i5_composition_root_wired(&workspace));
    violations.extend(checks::u22_updater_unlinked(&workspace));

    for package in &workspace.packages {
        for path in rust_sources(&root.join(&package.dir)) {
            let relative = path.strip_prefix(&root).map_or_else(
                |_| path.to_string_lossy().into_owned(),
                |p| p.to_string_lossy().replace('\\', "/"),
            );
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let file = ScannedFile::new(relative, &contents);
            violations.extend(checks::cd3(&file, &package.name));
            violations.extend(checks::cb3(&file, &package.name));
        }
    }

    violations.sort_by(|a, b| (a.rule, &a.location).cmp(&(b.rule, &b.location)));
    Ok(violations)
}

/// Every `.rs` file under `dir`, excluding build output.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // `target/` is build output, not source; `.git` is not ours.
                if name != "target" && name != ".git" {
                    stack.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}
