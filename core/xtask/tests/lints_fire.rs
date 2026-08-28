//! Every lint, seen to fail.
//!
//! ADR-0018 CD-3 calls the deny-list "the actual mechanism". A mechanism that has
//! never been observed to fire is an assertion about itself, so each check here
//! is given a deliberately planted violation and asserted to catch it — and a
//! clean input, asserted not to.

use xtask::checks::{self, Violation};
use xtask::manifest::{Package, Workspace};
use xtask::source::ScannedFile;

fn dp(name: &str, deps: &[&str]) -> Package {
    Package {
        name: name.to_owned(),
        manifest_path: format!("crates/{name}/Cargo.toml"),
        dir: format!("crates/{name}"),
        dependencies: deps.iter().map(|d| (*d).to_owned()).collect(),
        non_dev_dependencies: deps.iter().map(|d| (*d).to_owned()).collect(),
    }
}

/// A package whose edges to `dev_deps` are **dev**-dependencies.
///
/// They appear in `dependencies` — CD-I2 must still see a cipher a test pulls in
/// — and are absent from `non_dev_dependencies`, which is the list CD-I5 walks.
fn dp_with_dev(name: &str, deps: &[&str], dev_deps: &[&str]) -> Package {
    let mut all: Vec<String> = deps.iter().map(|d| (*d).to_owned()).collect();
    all.extend(dev_deps.iter().map(|d| (*d).to_owned()));
    Package {
        name: name.to_owned(),
        manifest_path: format!("crates/{name}/Cargo.toml"),
        dir: format!("crates/{name}"),
        dependencies: all,
        non_dev_dependencies: deps.iter().map(|d| (*d).to_owned()).collect(),
    }
}

fn ws(packages: Vec<Package>) -> Workspace {
    Workspace {
        packages,
        root: "/core".to_owned(),
    }
}

fn rules(v: &[Violation]) -> Vec<&'static str> {
    v.iter().map(|x| x.rule).collect()
}

// ---------------------------------------------------------------------------
// CD-3
// ---------------------------------------------------------------------------

#[test]
fn cd3_fires_on_a_planted_clock_read() {
    let planted = r"
        pub fn measure() -> u64 {
            let start = std::time::Instant::now();
            start.elapsed().as_micros() as u64
        }
    ";
    let file = ScannedFile::new("crates/twinvpn-path/src/probe.rs", planted);
    let found = checks::cd3(&file, "twinvpn-path");
    assert!(!found.is_empty(), "CD-3 did not fire on `Instant::now`");
    assert_eq!(rules(&found)[0], "CD-3");
    assert!(found[0].location.contains("probe.rs:3"), "{:?}", found[0]);
}

#[test]
fn cd3_fires_on_every_class_in_the_deny_list() {
    // One planted violation per class ADR-0018 CD-3 enumerates.
    let cases = [
        ("let t = SystemTime::now();", "SystemTime::now"),
        ("let t = Instant::now();", "Instant::now"),
        ("getrandom::getrandom(&mut b).unwrap();", "getrandom"),
        ("let mut r = rand::thread_rng();", "thread_rng"),
        ("tokio::time::sleep(d).await;", "tokio::time"),
        ("let now = chrono::Utc::now();", "chrono::"),
        (
            "unsafe { libc::clock_gettime(0, &mut ts) };",
            "clock_gettime",
        ),
    ];
    for (line, expected) in cases {
        let file = ScannedFile::new("crates/twinvpn-session/src/lib.rs", line);
        let found = checks::cd3(&file, "twinvpn-path");
        assert!(
            found.iter().any(|v| v.detail.contains(expected)),
            "CD-3 did not fire on {line:?}"
        );
    }
}

#[test]
fn cd3_permits_the_binding_directory_and_nothing_else() {
    let code = "let now = Instant::now();";
    // The one exclusion ADR-0018 CD-3 states.
    let allowed = ScannedFile::new("crates/twinvpn-env/src/binding/system.rs", code);
    assert!(checks::cd3(&allowed, "twinvpn-env").is_empty());
    // Elsewhere in the same crate, it still fires: the exclusion is
    // "twinvpn-env's implementations", not "twinvpn-env".
    let denied = ScannedFile::new("crates/twinvpn-env/src/clock.rs", code);
    assert!(!checks::cd3(&denied, "twinvpn-env").is_empty());
}

#[test]
fn cd3_does_not_fire_on_its_own_documentation() {
    // The defect that would make this lint get disabled: firing on the prose
    // that explains it. twinvpn-env's clock module names every banned API.
    let documented = r#"
        //! CD-3's deny-list bans `Instant::now` and `SystemTime::now` outright
        //! rather than steering them, because `std::time::Instant` is
        //! suspend-exclusive on Linux and Darwin.
        /// See also `getrandom` and `tokio::time`.
        const WHY: &str = "Instant::now is banned";
        /* A block comment mentioning clock_gettime and Utc::now. */
        pub fn f() {}
    "#;
    let file = ScannedFile::new("crates/twinvpn-env/src/clock.rs", documented);
    assert!(
        checks::cd3(&file, "twinvpn-route").is_empty(),
        "CD-3 fired on documentation: {:?}",
        checks::cd3(&file, "twinvpn-route")
    );
}

#[test]
fn cd3_is_not_fooled_by_a_raw_string_or_a_lifetime() {
    let tricky = r####"
        pub fn f<'a>(s: &'a str) -> &'a str { s }
        const DOC: &str = r#"Instant::now inside a raw string"#;
        const CH: char = '"';
        pub fn g() -> u8 { b'x' }
    "####;
    let file = ScannedFile::new("crates/twinvpn-route/src/lib.rs", tricky);
    assert!(
        checks::cd3(&file, "twinvpn-route").is_empty(),
        "{:?}",
        checks::cd3(&file, "twinvpn-route")
    );
}

/// W-36: a `twinvpn-platform-*` crate may name a platform time or entropy
/// primitive, exactly as `cb3_crate_is_exempt` lets it name `target_os`.
///
/// Before this exemption the two lints contradicted each other and **no
/// location in the tree could legally read a platform clock**.
#[test]
fn cd3_permits_a_platform_crate_to_name_a_platform_primitive() {
    for needle in checks::CD3_PLATFORM_PRIMITIVES {
        let planted = format!("pub fn read() {{ let _ = {needle}; }}");
        let file = ScannedFile::new("crates/twinvpn-platform-linux/src/clock.rs", &planted);
        assert!(
            checks::cd3(&file, "twinvpn-platform-linux").is_empty(),
            "CD-3 denied `{needle}` inside the crate CB-3 designates for it"
        );
    }
    assert!(checks::cd3_crate_may_read_platform_primitives(
        "twinvpn-platform-windows"
    ));
}

/// The exemption must not widen the hole: the same needle outside a platform
/// crate still fires. Same discipline as the CD-I2 exemption.
#[test]
fn cd3_still_fires_on_a_platform_primitive_outside_a_platform_crate() {
    for needle in checks::CD3_PLATFORM_PRIMITIVES {
        let planted = format!("pub fn read() {{ let _ = {needle}; }}");
        for crate_name in [
            "twinvpn-session",
            "twinvpn-path",
            "twinvpn-store",
            // The TRAIT crate is not a platform crate: it is the seam, and CB-3
            // puts the OS below it.
            "twinvpn-platform",
            // Nor is `twinvpn-env` itself, outside its binding directory.
            "twinvpn-env",
        ] {
            let file = ScannedFile::new(format!("crates/{crate_name}/src/lib.rs"), &planted);
            assert!(
                !checks::cd3(&file, crate_name).is_empty(),
                "CD-3 no longer catches `{needle}` in `{crate_name}`"
            );
        }
    }
    assert!(!checks::cd3_crate_may_read_platform_primitives(
        "twinvpn-platform"
    ));
    assert!(!checks::cd3_crate_may_read_platform_primitives(
        "twinvpn-env"
    ));
}

/// A platform crate is exempt from the platform primitives and **nothing else**.
///
/// `std::time::Instant` is the case that matters: it is suspend-*exclusive*, so
/// an adapter reaching for it to implement `ElapsedClock` would produce exactly
/// the defect ADR-0022 LC-8 warns is invisible on Linux CI.
#[test]
fn cd3_still_denies_ambient_rust_clocks_inside_a_platform_crate() {
    for line in [
        "let t = SystemTime::now();",
        "let t = Instant::now();",
        "let t: std::time::Instant = x;",
        "tokio::time::sleep(d).await;",
        "let now = chrono::Utc::now();",
        "let mut r = rand::thread_rng();",
    ] {
        let file = ScannedFile::new("crates/twinvpn-platform-linux/src/lib.rs", line);
        assert!(
            !checks::cd3(&file, "twinvpn-platform-linux").is_empty(),
            "a platform crate must not read an ambient Rust clock or RNG: {line:?}"
        );
    }
}

/// The two exemptions are the only two, and they do not overlap into each other.
#[test]
fn cd3_has_exactly_two_exemptions() {
    // The binding directory may name anything, including an ambient clock.
    let anywhere = ScannedFile::new(
        "crates/twinvpn-env/src/binding/system.rs",
        "let t = Instant::now(); let _ = clock_gettime;",
    );
    assert!(checks::cd3(&anywhere, "twinvpn-env").is_empty());

    // A platform crate may name a primitive but not an ambient clock, so a file
    // with both produces exactly the ambient-clock violation.
    let mixed = ScannedFile::new(
        "crates/twinvpn-platform-linux/src/clock.rs",
        "let a = clock_gettime; let b = Instant::now();",
    );
    let found = checks::cd3(&mixed, "twinvpn-platform-linux");
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].detail.contains("Instant::now"), "{:?}", found[0]);
}

// ---------------------------------------------------------------------------
// CD-CB3
// ---------------------------------------------------------------------------

#[test]
fn cb3_fires_on_a_planted_os_branch() {
    let planted = r#"
        #[cfg(target_os = "linux")]
        fn install() {}
    "#;
    let file = ScannedFile::new("crates/twinvpn-enforce/src/lib.rs", planted);
    let found = checks::cb3(&file, "twinvpn-enforce");
    assert_eq!(rules(&found), vec!["CD-CB3"]);
    assert!(found[0].location.contains(":2"), "{:?}", found[0]);
}

#[test]
fn cb3_fires_on_the_macro_form_too() {
    let planted = r#"if cfg!(target_os = "windows") { 1 } else { 2 }"#;
    let file = ScannedFile::new("crates/twinvpn-dns/src/lib.rs", planted);
    assert!(!checks::cb3(&file, "twinvpn-dns").is_empty());
}

#[test]
fn cb3_exempts_only_the_platform_adapter_crates() {
    let planted = r#"#[cfg(target_os = "linux")] fn f() {}"#;
    let file = ScannedFile::new("crates/twinvpn-platform-linux/src/lib.rs", planted);
    assert!(checks::cb3(&file, "twinvpn-platform-linux").is_empty());
    // The TRAIT crate is not exempt: CB-3 puts the OS branch below the seam,
    // and `twinvpn-platform` is the seam itself.
    let seam = ScannedFile::new("crates/twinvpn-platform/src/lib.rs", planted);
    assert!(!checks::cb3(&seam, "twinvpn-platform").is_empty());
    assert!(checks::cb3_crate_is_exempt("twinvpn-platform-windows"));
    assert!(!checks::cb3_crate_is_exempt("twinvpn-platform"));
}

#[test]
fn cb3_does_not_fire_on_prose_about_target_os() {
    let documented = r#"
        //! CB-3: `#[cfg(target_os = ...)]` is permitted only in twinvpn-platform-*.
        pub fn f() {}
    "#;
    let file = ScannedFile::new("crates/twinvpn-platform/src/lib.rs", documented);
    assert!(checks::cb3(&file, "twinvpn-platform").is_empty());
}

// ---------------------------------------------------------------------------
// CD-I2
// ---------------------------------------------------------------------------

#[test]
fn cd_i2_fires_on_a_planted_crypto_dependency() {
    let workspace = ws(vec![
        dp("twinvpn-crypto", &["snow", "x25519-dalek", "twinvpn-types"]),
        dp("twinvpn-session", &["twinvpn-types", "sha2"]),
    ]);
    let found = checks::cd_i2(&workspace);
    assert_eq!(rules(&found), vec!["CD-I2"]);
    assert!(found[0].detail.contains("twinvpn-session"));
    assert!(found[0].detail.contains("sha2"));
}

#[test]
fn cd_i2_exempts_only_twinvpn_crypto() {
    let clean = ws(vec![
        dp(
            "twinvpn-crypto",
            &["snow", "chacha20poly1305", "zeroize", "subtle"],
        ),
        dp("twinvpn-session", &["twinvpn-types", "twinvpn-env"]),
    ]);
    assert!(checks::cd_i2(&clean).is_empty());
}

/// The integration lead's 2026-08-27 ruling: `zeroize` and `subtle` are memory
/// hygiene and constant-time comparison, not cryptographic implementations, so
/// CD-I2 does not restrict them.
#[test]
fn cd_i2_permits_zeroize_and_subtle_anywhere() {
    for exempt in checks::CD_I2_NOT_CRYPTO_IMPLEMENTATIONS {
        let workspace = ws(vec![
            dp("twinvpn-types", &[exempt]),
            dp("twinvpn-platform", &[exempt]),
            dp("twinvpn-session", &[exempt]),
        ]);
        assert!(
            checks::cd_i2(&workspace).is_empty(),
            "CD-I2 wrongly flagged the exempt crate `{exempt}`"
        );
    }
    // And the exemption is exactly two names, not a category.
    assert_eq!(
        checks::CD_I2_NOT_CRYPTO_IMPLEMENTATIONS,
        ["zeroize", "subtle"]
    );
}

/// The exemption must not widen the hole: a genuine cryptographic
/// implementation is still caught when it sits beside an exempt one, which is
/// the shape a real regression would take.
#[test]
fn cd_i2_still_fires_on_a_real_crypto_crate_beside_an_exempt_one() {
    let workspace = ws(vec![
        dp("twinvpn-crypto", &["snow", "sha2", "zeroize", "subtle"]),
        // A crate that legitimately takes `zeroize` and then quietly adds sha2.
        dp("twinvpn-store", &["zeroize", "subtle", "sha2"]),
    ]);
    let found = checks::cd_i2(&workspace);
    assert_eq!(
        rules(&found),
        vec!["CD-I2"],
        "expected exactly one violation"
    );
    assert!(found[0].detail.contains("twinvpn-store"), "{:?}", found[0]);
    assert!(found[0].detail.contains("sha2"), "{:?}", found[0]);
    assert!(
        !found[0].detail.contains("zeroize") && !found[0].detail.contains("subtle"),
        "the exempt crates must not appear in the violation: {:?}",
        found[0]
    );
}

/// Every other name in `core/Cargo.toml`'s cryptography block stays restricted.
#[test]
fn cd_i2_still_restricts_the_rest_of_the_declared_crypto_block() {
    for restricted in [
        "snow",
        "x25519-dalek",
        "ed25519-dalek",
        "p256",
        "chacha20poly1305",
        "blake2",
        "sha2",
        "hkdf",
        "rand_core",
        "ciborium",
        "coset",
    ] {
        let workspace = ws(vec![dp("twinvpn-session", &[restricted])]);
        assert!(
            !checks::cd_i2(&workspace).is_empty(),
            "CD-I2 no longer restricts `{restricted}`"
        );
    }
}

#[test]
fn cd_i2_covers_the_alternatives_not_only_the_declared_block() {
    for alternative in [
        "ring",
        "rustls",
        "openssl",
        "aes-gcm",
        "blake3",
        "getrandom",
    ] {
        let workspace = ws(vec![dp("twinvpn-trust", &[alternative])]);
        assert!(
            !checks::cd_i2(&workspace).is_empty(),
            "CD-I2 missed `{alternative}`"
        );
    }
}

// ---------------------------------------------------------------------------
// CD-I5
// ---------------------------------------------------------------------------

fn plane_workspace(session_deps: &[&str], cp_deps: &[&str], core_deps: &[&str]) -> Workspace {
    ws(vec![
        dp("twinvpn-types", &[]),
        dp("twinvpn-store", &["twinvpn-types"]),
        dp("twinvpn-session", session_deps),
        dp("twinvpn-path", &["twinvpn-store"]),
        dp("twinvpn-cp-client", cp_deps),
        dp("twinvpn-core", core_deps),
    ])
}

#[test]
fn cd_i5_fires_on_a_direct_data_plane_to_control_plane_edge() {
    let workspace = plane_workspace(
        &["twinvpn-store", "twinvpn-cp-client"],
        &["twinvpn-store"],
        &["twinvpn-session", "twinvpn-cp-client"],
    );
    let found = checks::cd_i5(&workspace);
    assert!(!found.is_empty(), "CD-I5 did not fire on a direct edge");
    assert!(found.iter().all(|v| v.rule == "CD-I5"));
    assert!(found.iter().any(|v| v.detail.contains("twinvpn-session")));
}

/// The case a substring grep over manifests cannot see, and the reason CD-I5
/// says "direct **or transitive**".
#[test]
fn cd_i5_fires_on_a_transitive_edge_no_manifest_grep_would_find() {
    let workspace = ws(vec![
        dp("twinvpn-types", &[]),
        dp("twinvpn-store", &["twinvpn-types"]),
        // An innocuous-looking helper that happens to pull in the CP client.
        dp("twinvpn-helper", &["twinvpn-cp-client"]),
        // The data-plane crate names only the helper. Its own manifest is clean.
        dp("twinvpn-session", &["twinvpn-store", "twinvpn-helper"]),
        dp("twinvpn-cp-client", &["twinvpn-store"]),
        dp("twinvpn-core", &["twinvpn-session", "twinvpn-cp-client"]),
    ]);
    let found = checks::cd_i5(&workspace);
    assert!(
        found
            .iter()
            .any(|v| v.detail.contains("twinvpn-session")
                && v.detail.contains("twinvpn-cp-client")),
        "CD-I5 missed a transitive edge: {found:?}"
    );
}

#[test]
fn cd_i5_denies_the_reverse_edge_equally() {
    let workspace = plane_workspace(
        &["twinvpn-store"],
        &["twinvpn-store", "twinvpn-path"],
        &["twinvpn-session", "twinvpn-cp-client"],
    );
    let found = checks::cd_i5(&workspace);
    assert!(
        found
            .iter()
            .any(|v| v.detail.contains("reverse edge is equally denied")),
        "{found:?}"
    );
}

#[test]
fn cd_i5_permits_the_composition_root_to_name_both() {
    let workspace = plane_workspace(
        &["twinvpn-store"],
        &["twinvpn-store"],
        &["twinvpn-session", "twinvpn-path", "twinvpn-cp-client"],
    );
    assert!(checks::cd_i5(&workspace).is_empty());
    // And the positive half: the composition root really does wire both.
    assert!(checks::cd_i5_composition_root_wired(&workspace).is_empty());
}

#[test]
fn cd_i5_does_not_count_a_dev_dependency_as_a_path_between_the_planes() {
    // `ownership.md` §10.8 M-5, reported by `mobile-android`.
    //
    // A platform adapter that wants to run CB-2's falsification test for real
    // must drive the machine that makes the decision, and the only way to reach
    // it is a DEV-dependency on the composition root. That is not a path between
    // the planes in any shipped artifact -- it exists while a test binary is
    // linked and nowhere else -- so counting it made the rule forbid the
    // evidence for the architecture it exists to protect.
    let workspace = ws(vec![
        dp("twinvpn-store", &[]),
        dp("twinvpn-cp-client", &["twinvpn-store"]),
        dp("twinvpn-session", &["twinvpn-store"]),
        dp("twinvpn-path", &["twinvpn-store"]),
        dp(
            "twinvpn-core",
            &["twinvpn-session", "twinvpn-path", "twinvpn-cp-client"],
        ),
        // The adapter ships against the TRAIT and reaches the composition root
        // only from its tests.
        dp_with_dev("twinvpn-platform-android", &[], &["twinvpn-core"]),
    ]);

    assert!(
        checks::cd_i5(&workspace).is_empty(),
        "a dev-dependency on the composition root is not a plane path: {:?}",
        checks::cd_i5(&workspace)
    );
}

#[test]
fn cd_i5_still_fires_when_the_same_edge_is_a_real_dependency() {
    // The other half of M-5, and the reason the fix is `kind`-aware rather than
    // a relaxation: promote that dev-dependency to a real one and the rule must
    // fire exactly as before. Otherwise the fix would be a hole, not a filter.
    let workspace = ws(vec![
        dp("twinvpn-store", &[]),
        dp("twinvpn-cp-client", &["twinvpn-store"]),
        dp("twinvpn-session", &["twinvpn-store"]),
        dp("twinvpn-path", &["twinvpn-store"]),
        dp(
            "twinvpn-core",
            &["twinvpn-session", "twinvpn-path", "twinvpn-cp-client"],
        ),
        dp("twinvpn-platform-android", &["twinvpn-core"]),
    ]);

    assert_eq!(rules(&checks::cd_i5(&workspace)), vec!["CD-I5"]);
}

#[test]
fn cd_i5_reports_a_composition_root_that_wires_only_one_plane() {
    let workspace = plane_workspace(
        &["twinvpn-store"],
        &["twinvpn-store"],
        // Data plane only: the artifact ADR-0002 §11.8 step 3 requires is absent.
        &["twinvpn-session", "twinvpn-path"],
    );
    let found = checks::cd_i5_composition_root_wired(&workspace);
    assert!(
        found.iter().any(|v| v.detail.contains("twinvpn-cp-client")),
        "{found:?}"
    );
}

#[test]
fn cd_i5_does_not_report_an_unwired_skeleton_composition_root() {
    // Before core-composition lands, twinvpn-core has no intra-workspace deps.
    // Reporting that would block wave 1 on work that has not started.
    let workspace = plane_workspace(&["twinvpn-store"], &["twinvpn-store"], &[]);
    assert!(checks::cd_i5_composition_root_wired(&workspace).is_empty());
}

// ---------------------------------------------------------------------------
// The real workspace
// ---------------------------------------------------------------------------

/// The lint, run over the actual `core/` workspace, must be clean.
///
/// This is the assertion `make lint` and the merge gate rest on; the tests above
/// are what make it meaningful.
#[test]
fn the_real_core_workspace_is_clean() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core/xtask has a parent")
        .join("Cargo.toml");
    let violations = xtask::run(&manifest).expect("the workspace loads");
    assert!(
        violations.is_empty(),
        "the core workspace has T1 violations:\n{}",
        violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
}
