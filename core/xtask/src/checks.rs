//! The four T1 checks, as pure functions over data.
//!
//! Each takes an in-memory representation and returns violations, so
//! `tests/lints_fire.rs` can plant a deliberate violation and assert the lint
//! fires. ADR-0018 CD-3 calls the deny-list "the actual mechanism"; a lint that
//! has never been seen to fail is not a mechanism.

use crate::manifest::Workspace;
use crate::source::ScannedFile;

/// One violation, with enough to fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Which check fired.
    pub rule: &'static str,
    /// Where.
    pub location: String,
    /// What.
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}: {}", self.rule, self.location, self.detail)
    }
}

// ---------------------------------------------------------------------------
// CD-3 — the time and randomness deny-list
// ---------------------------------------------------------------------------

/// The only path in the workspace permitted a deny-listed call.
///
/// ADR-0018 CD-3 excludes "`twinvpn-env`'s implementations". This is that
/// exclusion, made exact: one directory, so the reviewer's question "where does
/// this build read the clock" has a directory as its answer.
pub const CD3_ALLOWED_PREFIX: &str = "crates/twinvpn-env/src/binding/";

/// `(needle, why)`. Matched against source with comments and literals blanked.
pub const CD3_DENIED: &[(&str, &str)] = &[
    (
        "SystemTime::now",
        "read the wall clock through twinvpn_env::WallClock",
    ),
    (
        "Instant::now",
        "read monotonic time through twinvpn_env::MonotonicClock",
    ),
    (
        "std::time::Instant",
        "MonotonicInstant and ElapsedInstant are the injected readings",
    ),
    (
        "getrandom",
        "draw randomness through twinvpn_env::Env::rng_for",
    ),
    ("thread_rng", "a thread-local RNG is not an injected stream"),
    ("ThreadRng", "a thread-local RNG is not an injected stream"),
    (
        "OsRng",
        "platform entropy is supplied through twinvpn_env::Entropy",
    ),
    (
        "rand::random",
        "draw randomness through twinvpn_env::Env::rng_for",
    ),
    (
        "tokio::time",
        "the runtime's own time module; take twinvpn_env::Timer",
    ),
    (
        "::time::sleep",
        "the runtime's own time module; take twinvpn_env::Timer",
    ),
    (
        "::time::interval",
        "the runtime's own time module; take twinvpn_env::Timer",
    ),
    (
        "::time::timeout",
        "compose a deadline from twinvpn_env::Timer",
    ),
    (
        "chrono::",
        "chrono's now-constructors read an ambient clock",
    ),
    (
        "Utc::now",
        "chrono's now-constructors read an ambient clock",
    ),
    (
        "Local::now",
        "chrono's now-constructors read an ambient clock",
    ),
    (
        "clock_gettime",
        "a platform time syscall; the binding owns it",
    ),
    (
        "mach_absolute_time",
        "a platform time syscall; the binding owns it",
    ),
    (
        "mach_continuous_time",
        "a platform time syscall; the binding owns it",
    ),
    (
        "QueryPerformanceCounter",
        "a platform time syscall; the binding owns it",
    ),
    (
        "QueryUnbiasedInterruptTime",
        "a platform time syscall; the binding owns it",
    ),
    (
        "QueryInterruptTime",
        "a platform time syscall; the binding owns it",
    ),
    (
        "GetTickCount64",
        "a platform time syscall; the binding owns it",
    ),
    (
        "GetSystemTimeAsFileTime",
        "a platform time syscall; the binding owns it",
    ),
    (
        "elapsedRealtime",
        "a platform time API; the binding owns it",
    ),
];

/// Runs the CD-3 deny-list over one file.
#[must_use]
pub fn cd3(file: &ScannedFile) -> Vec<Violation> {
    if file.path.starts_with(CD3_ALLOWED_PREFIX) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (needle, why) in CD3_DENIED {
        let mut from = 0usize;
        while let Some(at) = file.blanked[from..].find(needle) {
            let at = from + at;
            out.push(Violation {
                rule: "CD-3",
                location: format!("{}:{}", file.path, file.line_of(at)),
                detail: format!("`{needle}` is denied outside twinvpn-env's binding: {why}"),
            });
            from = at + needle.len();
        }
    }
    out
}

// ---------------------------------------------------------------------------
// CD-CB3 — no OS branch above the adapter
// ---------------------------------------------------------------------------

/// Crates permitted an OS branch: the platform adapter implementations.
#[must_use]
pub fn cb3_crate_is_exempt(crate_name: &str) -> bool {
    crate_name.starts_with("twinvpn-platform-")
}

/// Runs the CD-CB3 check over one file.
///
/// `docs/networking.md` §5.1 requires that nothing above the adapter branch on
/// OS, and ADR-0018 CB-3 makes it concrete: `#[cfg(target_os = …)]` is permitted
/// only in `twinvpn-platform-*` crates and in the shells.
///
/// The subject is the **`cfg` predicate**, not the bare word: a check that fired
/// on any identifier containing `target_os` would fire on
/// `fn does_not_branch_on_target_os()`, and a lint with false positives is a lint
/// somebody adds an `allow` for. So a match counts only inside a `cfg(...)`,
/// `cfg!(...)` or `cfg_attr(...)` predicate, including the nested `any` / `all` /
/// `not` forms.
#[must_use]
pub fn cb3(file: &ScannedFile, crate_name: &str) -> Vec<Violation> {
    if cb3_crate_is_exempt(crate_name) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let needle = "target_os";
    let mut from = 0usize;
    while let Some(at) = file.blanked[from..].find(needle) {
        let at = from + at;
        from = at + needle.len();
        if !in_cfg_predicate(&file.blanked, at) {
            continue;
        }
        out.push(Violation {
            rule: "CD-CB3",
            location: format!("{}:{}", file.path, file.line_of(at)),
            detail: format!(
                "`{needle}` outside a twinvpn-platform-* crate: {}",
                file.line_text(at)
            ),
        });
    }
    out
}

/// Whether the match at `at` sits inside a `cfg` predicate.
///
/// Walks back over the nesting forms `cfg(`, `cfg!(`, `cfg_attr(`, `any(`,
/// `all(` and `not(` — every character between the `cfg` token and the match
/// must belong to one of those — so an identifier that merely contains the word
/// does not count.
fn in_cfg_predicate(blanked: &str, at: usize) -> bool {
    const WINDOW: usize = 80;
    let mut start = at.saturating_sub(WINDOW);
    while start < at && !blanked.is_char_boundary(start) {
        start += 1;
    }
    let window = &blanked[start..at];
    let Some(pos) = window.rfind("cfg") else {
        return false;
    };
    let between = &window[pos + 3..];
    between.contains('(')
        && between.chars().all(|c| {
            c.is_ascii_alphabetic()
                || c == '_'
                || c == '('
                || c == ')'
                || c == '!'
                || c == ','
                || c.is_whitespace()
        })
}

// ---------------------------------------------------------------------------
// CD-I2 — only twinvpn-crypto may declare a cryptographic dependency
// ---------------------------------------------------------------------------

/// The crate permitted a cryptographic dependency.
pub const CD_I2_EXEMPT_CRATE: &str = "twinvpn-crypto";

/// Crate names that count as a cryptographic implementation.
///
/// The first block is exactly the set `core/Cargo.toml` lists under its own
/// "cryptography: CD-I2 restricts these to `twinvpn-crypto`" heading — the
/// integration lead's classification, honoured rather than re-litigated here.
/// The second block covers the common alternatives a crate might reach for
/// instead, so the rule cannot be sidestepped by picking a different library.
pub const CRYPTO_CRATES: &[&str] = &[
    // core/Cargo.toml's declared crypto block
    "snow",
    "x25519-dalek",
    "ed25519-dalek",
    "p256",
    "chacha20poly1305",
    "blake2",
    "sha2",
    "hkdf",
    "zeroize",
    "subtle",
    "rand_core",
    "ciborium",
    "coset",
    // the common alternatives
    "curve25519-dalek",
    "k256",
    "elliptic-curve",
    "signature",
    "ed25519",
    "chacha20",
    "aes",
    "aes-gcm",
    "aes-gcm-siv",
    "blake3",
    "sha1",
    "sha3",
    "hmac",
    "digest",
    "argon2",
    "pbkdf2",
    "scrypt",
    "rand",
    "rand_chacha",
    "getrandom",
    "ring",
    "rustls",
    "openssl",
    "native-tls",
    "boring",
    "aws-lc-rs",
    "orion",
    "dryoc",
    "sodiumoxide",
    "libsodium-sys",
];

/// Runs CD-I2 over the workspace's declared dependencies.
#[must_use]
pub fn cd_i2(workspace: &Workspace) -> Vec<Violation> {
    let mut out = Vec::new();
    for package in &workspace.packages {
        if package.name == CD_I2_EXEMPT_CRATE {
            continue;
        }
        for dep in &package.dependencies {
            if CRYPTO_CRATES.contains(&dep.as_str()) {
                out.push(Violation {
                    rule: "CD-I2",
                    location: package.manifest_path.clone(),
                    detail: format!(
                        "`{}` declares the cryptographic dependency `{}`; only `{}` may",
                        package.name, dep, CD_I2_EXEMPT_CRATE
                    ),
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// CD-I5 — the two planes never reach each other
// ---------------------------------------------------------------------------

/// The data-plane crate set (`ownership.md` §2, ADR-0018 §11.7).
pub const DATA_PLANE: &[&str] = &[
    "twinvpn-tunnel",
    "twinvpn-path",
    "twinvpn-relay-client",
    "twinvpn-route",
    "twinvpn-dns",
    "twinvpn-enforce",
    "twinvpn-gateway",
    "twinvpn-session",
];

/// The control-plane client.
pub const CONTROL_PLANE_CLIENT: &str = "twinvpn-cp-client";

/// The composition root, and everything above it.
///
/// §11.7 places `twinvpn-diag`, `twinvpn-mgmt` and `twinvpn-ffi` above
/// `twinvpn-core` in the arrow diagram, so they reach both planes *through* the
/// composition root. The rule is about crates **below** it: those are the ones
/// for which "reaches the other plane" would mean a direct path that bypasses
/// the store.
pub const COMPOSITION_ROOT_AND_ABOVE: &[&str] = &[
    "twinvpn-core",
    "twinvpn-diag",
    "twinvpn-mgmt",
    "twinvpn-ffi",
    "xtask",
];

/// Runs CD-I5 over the workspace crate graph.
///
/// This is a **graph** check, not a substring one: it computes the transitive
/// closure of each crate's intra-workspace dependencies, because CD-I5 denies
/// the edge "direct **or transitive**", and a manifest grep sees only direct
/// edges. It is the artifact ADR-0002 §11.8 step 3 requires and B-19 blocks a
/// release without.
#[must_use]
pub fn cd_i5(workspace: &Workspace) -> Vec<Violation> {
    let mut out = Vec::new();

    for package in &workspace.packages {
        if COMPOSITION_ROOT_AND_ABOVE.contains(&package.name.as_str()) {
            continue;
        }
        let reach = workspace.transitive_workspace_deps(&package.name);

        // A data-plane crate must not reach the control-plane client.
        if DATA_PLANE.contains(&package.name.as_str()) && reach.contains(CONTROL_PLANE_CLIENT) {
            out.push(Violation {
                rule: "CD-I5",
                location: package.manifest_path.clone(),
                detail: format!(
                    "data-plane crate `{}` reaches `{CONTROL_PLANE_CLIENT}` \
                     (directly or transitively); the only path between the planes is twinvpn-store",
                    package.name
                ),
            });
        }

        // And the reverse edge is equally denied.
        if package.name == CONTROL_PLANE_CLIENT {
            for dp in DATA_PLANE {
                if reach.contains(*dp) {
                    out.push(Violation {
                        rule: "CD-I5",
                        location: package.manifest_path.clone(),
                        detail: format!(
                            "`{CONTROL_PLANE_CLIENT}` reaches data-plane crate `{dp}` \
                             (directly or transitively); the reverse edge is equally denied"
                        ),
                    });
                }
            }
        }

        // No crate below the composition root may name both.
        let touches_control_plane = reach.contains(CONTROL_PLANE_CLIENT);
        let touches_data_plane = DATA_PLANE.iter().any(|d| reach.contains(*d));
        if touches_control_plane && touches_data_plane {
            out.push(Violation {
                rule: "CD-I5",
                location: package.manifest_path.clone(),
                detail: format!(
                    "`{}` reaches both planes; only twinvpn-core, the composition root, may",
                    package.name
                ),
            });
        }
    }

    out
}

/// Asserts the *positive* half of CD-I5: the composition root really does name
/// both planes.
///
/// Without this, CD-I5 would pass trivially on a workspace where the composition
/// root had not been wired up yet — and "the check passes because nothing is
/// connected" is not the artifact ADR-0002 §11.8 step 3 asks for.
#[must_use]
pub fn cd_i5_composition_root_wired(workspace: &Workspace) -> Vec<Violation> {
    let Some(root) = workspace.package("twinvpn-core") else {
        return Vec::new();
    };
    let reach = workspace.transitive_workspace_deps("twinvpn-core");
    let mut out = Vec::new();
    // Only meaningful once the composition root has any intra-workspace deps at
    // all; before core-composition lands it is an empty skeleton, and reporting
    // that as a violation would block wave 1 on work that has not started.
    if reach.is_empty() {
        return out;
    }
    if !reach.contains(CONTROL_PLANE_CLIENT) {
        out.push(Violation {
            rule: "CD-I5",
            location: root.manifest_path.clone(),
            detail: "twinvpn-core does not reach twinvpn-cp-client; the composition root is \
                     the one crate that must wire the control-plane client to the store"
                .to_owned(),
        });
    }
    if !DATA_PLANE.iter().any(|d| reach.contains(*d)) {
        out.push(Violation {
            rule: "CD-I5",
            location: root.manifest_path.clone(),
            detail: "twinvpn-core reaches no data-plane crate; the composition root is the \
                     one crate that must wire the data plane from the store"
                .to_owned(),
        });
    }
    out
}
