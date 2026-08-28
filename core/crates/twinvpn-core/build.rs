//! Stamps the build facts `CoreBuildIdentity` (S-46) carries and the source
//! cannot know.
//!
//! **Authority:** ADR-0018 §11.17 S-46, §11.12 VR-3, §11.10 (the artifact
//! interface handed to ADR-0021).
//!
//! Two values, both **facts about this build**:
//!
//! - `TWINVPN_TARGET_TRIPLE` — cargo's `TARGET`. Read here rather than composed
//!   from `std::env::consts` at runtime, because a cross-compiled artifact must
//!   report the triple it was *built for*.
//! - `TWINVPN_SOURCE_COMMIT` — taken from the environment, **never from git**.
//!   Running `git rev-parse` here would make the value depend on the build
//!   machine's checkout state rather than on the release pipeline's input, and a
//!   dirty worktree would silently produce a commit-labelled artifact that
//!   matches no commit. Absent, it is the empty string, which S-46 renders as
//!   "unstamped" rather than as a plausible-looking wrong answer.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TWINVPN_SOURCE_COMMIT");

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=TWINVPN_TARGET_TRIPLE={target}");

    let commit = std::env::var("TWINVPN_SOURCE_COMMIT").unwrap_or_default();
    println!("cargo:rustc-env=TWINVPN_SOURCE_COMMIT={commit}");
}
