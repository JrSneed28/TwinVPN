//! Compiles the ADR-0019 presentation catalogue into a static Rust table.
//!
//! **Authority:** ADR-0018 CB-4 ("the catalogue ships **embedded in the
//! artifact**"), ADR-0019 §11.5 LT-3a/LT-3b/LT-3c and LT-4.
//!
//! # Two sources, one table
//!
//! 1. **The seed.** `contracts/registry/reason_codes.json` carries a `condition`
//!    sentence for all 201 codes and a `next_action_key` for all 107
//!    `user_actionable` ones. The seed turns those into a `summary` entry for
//!    every code and a **neutral** `next_action` entry for every code that
//!    declares one. That is what makes LT-3c ("every code with a `next_action`
//!    MUST have a neutral variant") true **by construction** rather than by
//!    review, on day one, for every code.
//! 2. **The overlay.** `catalogue/en.json` overrides the seed wherever
//!    user-facing copy has actually been authored, and is the only place a
//!    platform **variant** can come from.
//!
//! The seed is not pretending to be finished copy — `condition` is written for a
//! reviewer, not for a user — and the honest state of that is recorded in this
//! crate's `README.md`. What the seed guarantees is the *structural* property
//! ADR-0019 needs: the resolver never returns an empty string, an i18n key, or a
//! bare code as the primary signal.
//!
//! # LT-4 is checked here, not hoped for
//!
//! Every `{placeholder}` in an entry must be an evidence key the frozen registry
//! **declares for that code**. A placeholder naming an undeclared key fails the
//! build, because at render time it could only ever produce a hole — and a hole
//! is how "Failed: " + code creeps back in.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

const REGISTRY_REL: &str = "../../../contracts/registry/reason_codes.json";
const OVERLAY_REL: &str = "catalogue/en.json";

/// The locale the overlay and the seed are written in (ADR-0019 §11.5's *source
/// locale*, the last localized rung of the fallback chain).
const SOURCE_LOCALE: &str = "en";

/// Every `twinvpn.v1.RemediationClass` value, as the frozen registry spells it.
///
/// The closed set is `twinvpn-types`' `RemediationClass`; it is written out here
/// rather than derived, because a build script that took the set from the same
/// overlay it is validating could not detect a class the overlay forgot — which
/// is precisely the empty part 3 ADR-0019 §11.13 oracle 1 forbids.
const REMEDIATION_CLASSES: &[&str] = &[
    "NONE",
    "WAIT",
    "LOCAL_ACTION",
    "PEER_ACTION",
    "POLICY_CHANGE",
    "UPDATE_REQUIRED",
    "NETWORK_CHANGE",
    "PERMISSION_GRANT",
    "REPORT_DEFECT",
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let registry_path = manifest.join(REGISTRY_REL);
    let overlay_path = manifest.join(OVERLAY_REL);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", registry_path.display());
    println!("cargo:rerun-if-changed={}", overlay_path.display());

    let registry: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&registry_path)
            .unwrap_or_else(|e| panic!("cannot read frozen registry: {e}")),
    )
    .expect("registry is valid JSON");
    let overlay: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&overlay_path)
            .unwrap_or_else(|e| panic!("cannot read catalogue overlay: {e}")),
    )
    .expect("overlay is valid JSON");

    let generated = generate(&registry, &overlay);
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("catalogue.rs");
    std::fs::write(&out, generated).expect("write generated catalogue");
}

struct Authored {
    text: String,
    /// `(platform_tag, text)`. Empty for a summary; LT-3's variants for an action.
    variants: Vec<(String, String)>,
    from_overlay: bool,
}

fn generate(registry: &serde_json::Value, overlay: &serde_json::Value) -> String {
    let codes = registry["reason_codes"]
        .as_array()
        .expect("reason_codes is an array");

    let entries_obj = overlay["entries"]
        .as_object()
        .expect("overlay.entries is an object");

    // key -> (entry, owning code, declared evidence fields)
    let mut table: BTreeMap<String, (Authored, String, Vec<String>)> = BTreeMap::new();

    for c in codes {
        let code = c["reason_code"].as_str().expect("reason_code");
        let condition = c["condition"].as_str().expect("condition");
        let declared: Vec<String> = c["evidence_fields"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| v.as_str().expect("evidence field is a string").to_owned())
                    .collect()
            })
            .unwrap_or_default();

        let summary_key = c["summary_key"].as_str().expect("summary_key");
        let seeded = seed_sentence(condition);
        let authored = authored_for(entries_obj, summary_key, &seeded, false);
        check_placeholders(summary_key, &authored, &declared);
        table.insert(
            summary_key.to_owned(),
            (authored, code.to_owned(), declared.clone()),
        );

        if let Some(next_key) = c.get("next_action_key").and_then(serde_json::Value::as_str) {
            let seeded = default_next_action();
            let authored = authored_for(entries_obj, next_key, seeded, true);
            check_placeholders(next_key, &authored, &declared);
            table.insert(next_key.to_owned(), (authored, code.to_owned(), declared));
        }
    }

    // Overlay keys that name nothing in the registry are a defect: they would be
    // dead text nobody can reach, and the usual way that happens is a typo in a
    // key that silently disables the copy someone wrote.
    for k in entries_obj.keys() {
        assert!(
            table.contains_key(k),
            "catalogue overlay declares `{k}`, which no registered reason code names as its \
             summary_key or next_action_key. Fix the key or delete the entry."
        );
    }

    let domain_summary = overlay["domain_summary"]
        .as_object()
        .expect("overlay.domain_summary");
    let domain_next = overlay["domain_next_action"]
        .as_object()
        .expect("overlay.domain_next_action");
    let closed_domains: Vec<&str> = registry["closed_domain_set"]
        .as_array()
        .expect("closed_domain_set")
        .iter()
        .map(|v| v.as_str().expect("domain"))
        .collect();
    for d in &closed_domains {
        assert!(
            domain_summary.contains_key(*d) && domain_next.contains_key(*d),
            "ADR-0015 §11.2 rule 5 makes DOMAIN-prefix degradation the forward-compatibility \
             mechanism, so every one of the sixteen domains needs a fallback sentence. `{d}` \
             has none."
        );
    }

    // ADR-0019 §11.13 oracle 1: "Where `user_actionable == false`, part 3 is the
    // `remediation_class` sentence — the field is never empty." A class with no
    // sentence would produce exactly the empty part 3 that oracle forbids, so
    // the completeness check belongs here rather than in a review.
    let remediation = overlay["remediation_class"]
        .as_object()
        .expect("overlay.remediation_class");
    for c in REMEDIATION_CLASSES {
        let text = remediation
            .get(*c)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "ADR-0019 §11.13 oracle 1 requires a part-3 sentence for every \
                     RemediationClass, so a code an Owner cannot act on still renders one. \
                     `{c}` has none."
                )
            });
        assert!(
            !text.trim().is_empty(),
            "the `{c}` remediation sentence is empty, which is the exact defect oracle 1 \
             forbids"
        );
    }

    let mut out = String::with_capacity(256 * 1024);
    out.push_str("// @generated by twinvpn-diag/build.rs. DO NOT EDIT.\n");
    out.push_str("// Sources: contracts/registry/reason_codes.json (seed) and\n");
    out.push_str("// catalogue/en.json (authored overlay).\n\n");

    let _ = writeln!(out, "/// The source locale (ADR-0019 §11.5).");
    let _ = writeln!(out, "pub const SOURCE_LOCALE: &str = {SOURCE_LOCALE:?};\n");

    let _ = writeln!(out, "static ENTRIES: &[CatalogueEntry] = &[",);
    for (key, (authored, code, _)) in &table {
        let _ = writeln!(out, "    CatalogueEntry {{");
        let _ = writeln!(out, "        key: {key:?},");
        let _ = writeln!(out, "        code: {code:?},");
        let _ = writeln!(out, "        neutral: {:?},", authored.text);
        let _ = writeln!(out, "        authored: {},", authored.from_overlay);
        let _ = writeln!(out, "        variants: &[");
        for (platform, text) in &authored.variants {
            let _ = writeln!(
                out,
                "            Variant {{ platform: {platform:?}, text: {text:?} }},"
            );
        }
        let _ = writeln!(out, "        ],");
        let _ = writeln!(out, "    }},");
    }
    let _ = writeln!(out, "];\n");

    let _ = writeln!(out, "static DOMAIN_SUMMARY: &[(&str, &str)] = &[");
    for d in &closed_domains {
        let _ = writeln!(
            out,
            "    ({d:?}, {:?}),",
            domain_summary[*d].as_str().expect("domain summary text")
        );
    }
    let _ = writeln!(out, "];\n");

    let _ = writeln!(out, "static DOMAIN_NEXT_ACTION: &[(&str, &str)] = &[");
    for d in &closed_domains {
        let _ = writeln!(
            out,
            "    ({d:?}, {:?}),",
            domain_next[*d].as_str().expect("domain next-action text")
        );
    }
    let _ = writeln!(out, "];\n");

    let _ = writeln!(out, "static REMEDIATION_SENTENCE: &[(&str, &str)] = &[");
    for c in REMEDIATION_CLASSES {
        let _ = writeln!(
            out,
            "    ({c:?}, {:?}),",
            remediation[*c].as_str().expect("remediation sentence")
        );
    }
    let _ = writeln!(out, "];\n");

    let authored_count = table.values().filter(|(a, _, _)| a.from_overlay).count();
    let _ = writeln!(
        out,
        "/// How many catalogue entries carry hand-authored copy rather than the\n\
         /// registry-derived seed. Reported in the connectivity report so the gap is\n\
         /// measurable rather than invisible (ADR-0019 §11.5).\n\
         pub const AUTHORED_ENTRIES: usize = {authored_count};"
    );
    let _ = writeln!(
        out,
        "/// Total catalogue entries. Equals `2 * user_actionable + non_actionable`.\n\
         pub const TOTAL_ENTRIES: usize = {};",
        table.len()
    );

    out
}

/// Turns a registry `condition` into a seed sentence.
///
/// The registry writes conditions for reviewers — clipped, sometimes SHOUTING a
/// normative clause. This normalizes the shape (sentence case is already there;
/// what is missing is terminal punctuation) and does **nothing** else. It does
/// not glue a code, a key or an enum name onto anything, so LT-4 holds.
fn seed_sentence(condition: &str) -> String {
    let trimmed = condition.trim();
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}

/// The seed for a `next_action` the overlay has not authored.
///
/// Deliberately generic and deliberately **true**: producing a diagnostic bundle
/// is always a correct next step, and inventing a specific remedy the registry
/// does not state would be worse than saying something honest and general.
fn default_next_action() -> &'static str {
    "Try again. If the problem continues, create a diagnostic report and share it with support."
}

fn authored_for(
    entries: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    seed: &str,
    allow_variants: bool,
) -> Authored {
    let Some(v) = entries.get(key) else {
        return Authored {
            text: seed.to_owned(),
            variants: Vec::new(),
            from_overlay: false,
        };
    };

    if let Some(obj) = v.as_object() {
        if let Some(text) = obj.get("text").and_then(serde_json::Value::as_str) {
            assert!(
                obj.get("variants").is_none(),
                "`{key}` uses the summary form (`text`) but declares variants; \
                 only a next_action carries LT-3 platform variants"
            );
            return Authored {
                text: text.to_owned(),
                variants: Vec::new(),
                from_overlay: true,
            };
        }
        // LT-3c, enforced: the `neutral` field is mandatory and non-empty. A
        // variant set without one would leave LT-3b resolving to nothing.
        let neutral = obj
            .get("neutral")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "ADR-0019 LT-3c: `{key}` declares platform variants but no `neutral` \
                     variant. Every code with a next_action MUST have a neutral variant."
                )
            });
        assert!(
            !neutral.trim().is_empty(),
            "ADR-0019 LT-3c: `{key}`'s neutral variant is empty."
        );
        assert!(
            allow_variants,
            "`{key}` is a summary and cannot carry a neutral/variants object"
        );
        let mut variants = Vec::new();
        if let Some(list) = obj.get("variants").and_then(serde_json::Value::as_array) {
            for item in list {
                let platform = item["platform"]
                    .as_str()
                    .expect("variant.platform")
                    .to_owned();
                let text = item["text"].as_str().expect("variant.text").to_owned();
                assert!(!text.trim().is_empty(), "`{key}` has an empty variant text");
                variants.push((platform, text));
            }
        }
        return Authored {
            text: neutral.to_owned(),
            variants,
            from_overlay: true,
        };
    }

    panic!("catalogue entry `{key}` must be an object")
}

/// LT-4's half that a build can check: every named placeholder is a
/// registry-declared evidence key for the owning code.
fn check_placeholders(key: &str, authored: &Authored, declared: &[String]) {
    let mut texts = vec![authored.text.as_str()];
    texts.extend(authored.variants.iter().map(|(_, t)| t.as_str()));
    for text in texts {
        for name in placeholders(text) {
            assert!(
                declared.contains(&name),
                "ADR-0019 LT-4: catalogue entry `{key}` names placeholder `{{{name}}}`, which \
                 the frozen registry does not declare among that code's evidence_fields. A \
                 placeholder with no declared source can only ever render as a hole."
            );
        }
    }
}

fn placeholders(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '{' {
            let mut j = i + 1;
            let mut name = String::new();
            while j < bytes.len() && bytes[j] != '}' {
                name.push(bytes[j]);
                j += 1;
            }
            if j < bytes.len() && !name.is_empty() {
                out.push(name);
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}
