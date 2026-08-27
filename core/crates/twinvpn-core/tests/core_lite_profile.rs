//! **§11.12.** The `core-lite` profile contains **no data-plane crate**, and
//! that is asserted against the manifest rather than against a comment.
//!
//! > **`core-lite`.** A feature profile of the *same* source containing
//! > `twinvpn-schema`, `twinvpn-crypto` (verification only), `twinvpn-store`,
//! > `twinvpn-trust` and `twinvpn-diag`, and **no** data-plane crate.
//!
//! # Why the manifest and not `cargo tree`
//!
//! `cargo tree --no-default-features` would be the direct measurement, but it
//! needs a cargo invocation inside a test, a network-free registry, and a build
//! of the whole graph — slow, and it fails for reasons unrelated to the property.
//!
//! The property has an exact syntactic form: **every data-plane dependency is
//! `optional`, and none is named by the `core-lite` feature.** Cargo's own rules
//! then guarantee the rest: an optional dependency no enabled feature names is
//! not compiled. Reading that off `Cargo.toml` is a complete check of the
//! condition, and it fails the moment someone drops an `optional = true` — which
//! is the exact way this profile would silently grow.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// The data-plane crate set, `ownership.md` §2, plus the control-plane client.
///
/// §11.12 excludes the data plane by name. The control-plane client is excluded
/// for the reason §11.12 spends three paragraphs on: `core-lite` MUST NOT sit on
/// a **fetch path**, and a control-plane client is a fetch path.
const MUST_BE_OPTIONAL: &[&str] = &[
    "twinvpn-tunnel",
    "twinvpn-path",
    "twinvpn-relay-client",
    "twinvpn-route",
    "twinvpn-dns",
    "twinvpn-enforce",
    "twinvpn-gateway",
    "twinvpn-session",
    "twinvpn-cp-client",
];

/// §11.12's list of what `core-lite` **does** contain. Each must be a
/// non-optional dependency.
const MUST_BE_PRESENT: &[&str] = &[
    "twinvpn-schema",
    "twinvpn-crypto",
    "twinvpn-store",
    "twinvpn-trust",
    "twinvpn-diag",
];

fn dependency_line(crate_name: &str) -> &'static str {
    MANIFEST
        .lines()
        .find(|l| l.trim_start().starts_with(crate_name) && l.contains("workspace"))
        .unwrap_or_else(|| panic!("{crate_name} is not a dependency of twinvpn-core"))
}

fn core_lite_feature_body() -> String {
    // The `core-lite` feature's declaration, whatever shape it takes.
    let mut out = String::new();
    let mut in_feature = false;
    for line in MANIFEST.lines() {
        if line.trim_start().starts_with("core-lite") {
            in_feature = true;
        }
        if in_feature {
            out.push_str(line);
            out.push('\n');
            if line.contains(']') {
                break;
            }
        }
    }
    assert!(!out.is_empty(), "no `core-lite` feature is declared");
    out
}

#[test]
fn every_data_plane_dependency_is_optional() {
    for name in MUST_BE_OPTIONAL {
        let line = dependency_line(name);
        assert!(
            line.contains("optional = true"),
            "ADR-0018 §11.12: `{name}` must be `optional = true`, or the `core-lite` \
             profile compiles it. Line was: {line}"
        );
    }
}

#[test]
fn the_core_lite_feature_names_no_data_plane_crate() {
    let body = core_lite_feature_body();
    for name in MUST_BE_OPTIONAL {
        assert!(
            !body.contains(name),
            "ADR-0018 §11.12: the `core-lite` feature must not enable `{name}`"
        );
    }
}

#[test]
fn the_full_feature_enables_every_optional_dependency() {
    // The other direction: an optional dependency no feature enables is dead
    // code that quietly stops being compiled at all.
    let mut in_full = false;
    let mut body = String::new();
    for line in MANIFEST.lines() {
        if line.trim_start().starts_with("full = [") {
            in_full = true;
        }
        if in_full {
            body.push_str(line);
            body.push('\n');
            if line.contains(']') && !line.trim_start().starts_with("full = [") {
                break;
            }
        }
    }
    for name in MUST_BE_OPTIONAL {
        assert!(
            body.contains(name),
            "`{name}` is optional but the `full` feature does not enable it"
        );
    }
}

#[test]
fn the_core_lite_set_is_never_optional() {
    for name in MUST_BE_PRESENT {
        let line = dependency_line(name);
        assert!(
            !line.contains("optional = true"),
            "ADR-0018 §11.12 names `{name}` as part of the core-lite profile, so it must \
             not be optional. Line was: {line}"
        );
    }
}

#[test]
fn the_profile_reports_itself_truthfully() {
    // VR-3's rule applied to the profile field: declared, never inferred.
    assert_eq!(
        twinvpn_core::lite::profile(),
        if cfg!(feature = "full") {
            "full"
        } else {
            "core-lite"
        }
    );
}

#[test]
fn core_lite_can_never_fetch_or_recover() {
    use twinvpn_core::lite::{has, Capability};
    if cfg!(feature = "full") {
        assert!(has(Capability::Fetch));
    } else {
        // §11.12's deadlock shape: under `includeAllNetworks` the app process has
        // no network, so the component that would fetch is the component that
        // cannot.
        assert!(!has(Capability::Fetch));
        assert!(!has(Capability::Recover));
    }
    // In BOTH profiles: parse, verify and render are always available, because
    // rendering the diagnostic that poisoned the core is the one job that must
    // survive everything (F-10).
    assert!(has(Capability::Parse));
    assert!(has(Capability::Verify));
    assert!(has(Capability::Render));
}
