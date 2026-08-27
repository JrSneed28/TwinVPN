//! The attribute vocabulary in this crate must be exactly the collector's.
//!
//! `src/obs/attrs.rs` transcribes `redaction/allowlist.allowed_keys` and
//! `filter/forbidden` from `infra/otel/collector-config.yaml`. A transcription
//! that can drift silently is worse than no transcription: the crate would
//! cheerfully emit a key the collector deletes, and — far worse — would *fail to
//! refuse* a key the collector treats as a security incident.
//!
//! So this test re-reads the collector config from `infra/` (owned by the
//! `infrastructure` domain, read-only from here) and asserts set equality in both
//! directions. When `infrastructure` adds an attribute, this test fails until
//! `attrs.rs` follows — which is the correct direction of dependency, because
//! `infra/README.md` §6.3 makes the collector's allowlist *the* convention:
//!
//! > an attribute not on it does not reach a backend, so there is exactly one
//! > place to look and exactly one place to change.
//!
//! The parsing here is deliberately plain string work. Adding a YAML dependency
//! to a production crate for the sake of one test would be a supply-chain cost
//! paid for a convenience.

use std::collections::BTreeSet;

use twinvpn_service_common::obs::attrs;

fn collector_config() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/otel/collector-config.yaml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The `allowed_keys:` list under `redaction/allowlist`.
fn collector_allowed_keys(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "allowed_keys:" {
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            out.insert(item.trim().to_owned());
        } else if trimmed.is_empty() || trimmed.starts_with('#') {
            // comments and blank lines inside the list
        } else {
            break;
        }
    }
    out
}

/// Every `attributes["…"]` named inside the `filter/forbidden` processor.
fn collector_forbidden_keys(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_processor = false;
    for line in text.lines() {
        if line.trim_start().starts_with("filter/forbidden:") {
            in_processor = true;
            continue;
        }
        if in_processor {
            // A new processor starts at exactly two spaces of indentation.
            let is_new_processor = line.starts_with("  ")
                && !line.starts_with("   ")
                && !line.trim().is_empty()
                && !line.trim_start().starts_with('#');
            if is_new_processor {
                break;
            }
            let mut rest = line;
            while let Some(i) = rest.find("attributes[\"") {
                let after = &rest[i + "attributes[\"".len()..];
                if let Some(j) = after.find('"') {
                    out.insert(after[..j].to_owned());
                    rest = &after[j..];
                } else {
                    break;
                }
            }
        }
    }
    out
}

#[test]
fn the_allowlist_matches_the_collector_exactly() {
    let text = collector_config();
    let theirs = collector_allowed_keys(&text);
    assert!(
        theirs.len() > 40,
        "the parse found only {} keys; the collector config layout changed",
        theirs.len()
    );
    let ours: BTreeSet<String> = attrs::ALLOWED_KEYS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let missing: Vec<_> = theirs.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&theirs).collect();
    assert!(
        missing.is_empty(),
        "infra/otel/collector-config.yaml allowlists keys this crate does not know: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "this crate would emit keys the collector deletes: {extra:?}"
    );
}

#[test]
fn the_forbidden_list_matches_the_collector_exactly() {
    let text = collector_config();
    let theirs = collector_forbidden_keys(&text);
    assert!(
        theirs.len() > 25,
        "the parse found only {} keys; the collector config layout changed",
        theirs.len()
    );
    let ours: BTreeSet<String> = attrs::FORBIDDEN_KEYS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let missing: Vec<_> = theirs.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&theirs).collect();
    assert!(
        missing.is_empty(),
        "the collector drops records for keys this crate does not refuse: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "this crate refuses keys the collector does not treat as forbidden: {extra:?}"
    );
}

#[test]
fn the_deliberate_absences_are_absent_from_the_collector_too() {
    // ADR-0015 §11.2 rule 5 and infra/README.md §6.3: no `summary`, `message` or
    // `title`; no `exception.message` or `exception.stacktrace`.
    let allowed = collector_allowed_keys(&collector_config());
    for absent in [
        "summary",
        "message",
        "title",
        "exception.message",
        "exception.stacktrace",
    ] {
        assert!(
            !allowed.contains(absent),
            "{absent} must never be allowlisted"
        );
        assert_ne!(attrs::verdict(absent), attrs::KeyVerdict::Allowed);
    }
}

#[test]
fn the_negative_control_the_parse_can_actually_fail() {
    // `docs/testing-strategy.md` V4: absence of a signal is not evidence unless
    // the signal was provably possible. A parse that silently returned an empty
    // set would make both tests above vacuous, so prove it detects a difference.
    let ours: BTreeSet<String> = attrs::ALLOWED_KEYS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let mut mutated = ours.clone();
    mutated.insert("twinvpn.a_key_nobody_reviewed".to_owned());
    assert_ne!(ours, mutated);

    let theirs = collector_allowed_keys(&collector_config());
    assert_ne!(theirs, mutated, "set comparison must detect an extra key");
}

#[test]
fn the_tier2_pipeline_strips_what_this_crate_never_emits() {
    // ADR-0018 VR-2 consequence 3. The collector strips abi_* on the Tier-2
    // pipeline; `Tier2Sample` never produces them, so the strip is a backstop.
    let text = collector_config();
    assert!(
        text.contains("attributes/tier2-strip-abi"),
        "the Tier-2 abi strip disappeared from the collector config"
    );
    for k in ["twinvpn.abi_major", "twinvpn.abi_minor"] {
        assert!(!attrs::TIER2_TUPLE.contains(&k));
        // ...but still allowlisted overall, because VR-2 consequence 1 permits
        // them on a Tier-1 bundle and in CoreBuildIdentity.
        assert_eq!(attrs::verdict(k), attrs::KeyVerdict::Allowed);
    }
}

#[test]
fn correlation_and_causation_are_allowlisted_at_every_hop() {
    // infra/README.md §6.3: "The redaction lint asserts they stay allowlisted,
    // with the same force it asserts the forbidden keys stay out, because an
    // allowlist that quietly dropped them would pass every privacy check and
    // destroy the causal chain."
    let allowed = collector_allowed_keys(&collector_config());
    for k in [
        "twinvpn.correlation_id",
        "twinvpn.causation_id",
        "twinvpn.message_id",
        "twinvpn.idempotency_key",
    ] {
        assert!(allowed.contains(k), "{k} must stay allowlisted");
        assert_eq!(attrs::verdict(k), attrs::KeyVerdict::Allowed);
    }
}
