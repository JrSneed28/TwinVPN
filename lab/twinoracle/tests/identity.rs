//! Workstream 2: the protected and the unprotected egress paths must be two
//! DISTINGUISHABLE things.
//!
//! If both legs leave from the same address, or both resolve through the same
//! resolver, then "traffic moved into the tunnel" was never observable and a
//! silent armed window says nothing about which path was silent. For DNS the
//! identity is derived from the address the query ARRIVED from, looked up in a
//! configured resolver map — never from the probe's own `path_tag` label, and
//! never from an authoritative server claiming to have seen an original client
//! IP. Both of those are the defendant testifying.
//!
//! Same discipline as `hardening.rs`: one property mutated per test, on a
//! session that otherwise passes.

mod common;

use common::{golden, obs, UNMAPPED_RESOLVER, UNPROTECTED_V4};
use twinoracle::{Family, PathKind, Verdict};

// ===========================================================================
// Workstream 2 — DNS and path identity
// ===========================================================================

/// A DNS query the probe labelled protected that arrived from the ISP resolver
/// went out over the unprotected path. During the armed window that is a leak,
/// and it is named as one rather than being folded into a generic count.
#[test]
fn dns_arriving_via_the_unprotected_resolver_during_silence_fails() {
    let mut s = golden();
    s.record(obs(
        Family::Dns,
        UNPROTECTED_V4,
        350,
        Some(PathKind::Protected),
    ));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Fail, "{r:#?}");
    assert_eq!(r.dns_observed, 1);
    assert!(
        r.failures
            .iter()
            .any(|m| m.contains("did not resolve over the path the probe intended")),
        "the derived resolver identity, not the probe's own label, must be what decides: {r:#?}"
    );
}

/// An arrival from a resolver in no map entry cannot be attributed to a path.
/// Guessing is how a leak through the wrong resolver gets recorded as clean, so
/// the session is inconclusive instead.
#[test]
fn dns_from_an_unmapped_resolver_is_inconclusive_via_the_ambiguity_flag() {
    let mut s = golden();
    // Inside TUNNELLED, so this is deliberately NOT a forbidden arrival — the
    // ambiguity alone has to be enough.
    s.record(obs(
        Family::Dns,
        UNMAPPED_RESOLVER,
        210,
        Some(PathKind::Protected),
    ));

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert!(r.dns_resolver_identity_ambiguous);
    assert_eq!(r.dns_observed, 0, "it did not arrive during SILENCE");
    assert!(r.failures.is_empty());
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("no configured resolver map entry")));
}

/// Both resolvers resolving to the same identity means the protected and
/// unprotected DNS paths are the same thing wearing two addresses. A silent
/// window then says nothing about which of them was silent.
#[test]
fn overlapping_dns_resolver_identities_are_inconclusive() {
    let mut s = golden();
    for entry in s.resolver_map.values_mut() {
        entry.id = "one-and-the-same".into();
    }

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert_eq!(r.dns_identity_distinct, Some(false));
    assert_eq!(r.ipv4_identity_distinct, Some(true), "only DNS was mutated");
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("dns path identities overlap")));
}

/// The same hole on the IP families: if the restored leg is really the
/// unprotected path, the protected and unprotected address sets intersect and
/// no arrival can be attributed to a path.
#[test]
fn overlapping_ipv4_path_identities_are_inconclusive() {
    let mut s = golden();
    let restored = s
        .phases
        .iter_mut()
        .find(|p| p.name == "RESTORED")
        .expect("the golden session has one");
    restored.path = Some(PathKind::Unprotected);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert_eq!(r.ipv4_identity_distinct, Some(false));
    assert_eq!(r.ipv6_identity_distinct, Some(false));
    assert!(r.failures.is_empty());
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("ipv4 path identities overlap")));
}

/// A session that never drove an unprotected leg has one identity, not two.
/// Missing evidence is `false`, and `false` is inconclusive — it must not
/// shortcut to "nothing overlapped, therefore distinct".
#[test]
fn a_missing_unprotected_leg_leaves_the_identity_indistinct_not_distinct() {
    let mut s = golden();
    let baseline = s
        .phases
        .iter_mut()
        .find(|p| p.name == "BASELINE")
        .expect("the golden session has one");
    baseline.path = None;

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Inconclusive, "{r:#?}");
    assert_eq!(r.ipv4_identity_distinct, Some(false));
    assert!(r
        .inconclusive
        .iter()
        .any(|m| m.contains("never established both a protected and an unprotected ipv4")));
}

/// A criterion with no IPv6 leg reports `null`, not `true`. `null` says "this
/// session makes no IPv6 claim"; `true` would say "IPv6 was checked and was
/// fine", and those are not the same sentence.
#[test]
fn a_criterion_with_no_ipv6_leg_reports_null_identity_rather_than_true() {
    let mut s = golden();
    s.required_families = vec![Family::Ipv4, Family::Dns];
    s.observations.retain(|o| o.family != Family::Ipv6);
    if let Some(sentinel) = s.sentinel.as_mut() {
        sentinel.beats.retain(|b| b.family != Family::Ipv6);
    }
    s.attempts.remove(&Family::Ipv6);

    let r = s.report();
    assert_eq!(r.verdict, Verdict::Pass, "{r:#?}");
    assert_eq!(r.ipv6_identity_distinct, None);
    assert!(
        !r.ipv6_sentinel_continuous,
        "no beats is not continuity, even for a family out of play"
    );
    assert_eq!(r.ipv6_attempts, 0);

    let json = serde_json::to_value(r).expect("serialisable");
    assert!(
        json["ipv6_identity_distinct"].is_null(),
        "it must serialize as null, and a reader must not read null as true"
    );
}

/// The control API takes `"p"`/`"u"` for a phase's path so the probe uses ONE
/// vocabulary — the same letter it puts in the DNS query name — rather than
/// two. `"protected"`/`"unprotected"` still work; a phase may also spell the
/// field `path_tag`.
#[test]
fn a_phase_path_accepts_both_the_letter_and_the_word() {
    let cases = [
        (r#"{"path": "p"}"#, Some(PathKind::Protected)),
        (r#"{"path": "u"}"#, Some(PathKind::Unprotected)),
        (r#"{"path": "protected"}"#, Some(PathKind::Protected)),
        (r#"{"path_tag": "u"}"#, Some(PathKind::Unprotected)),
        (r#"{"path": null}"#, None),
        // "n" is the probe stating that this phase makes NO path claim. It has
        // to deserialize, and to null: rejecting it would 400 the whole phase
        // call, and a phase that never opened is a phase whose observations
        // land in the PREVIOUS one — which is how a leak gets attributed to the
        // wrong window.
        (r#"{"path_tag": "n"}"#, None),
        (r#"{"path": "n"}"#, None),
        ("{}", None),
    ];
    for (body, want) in cases {
        let full = format!(
            r#"{{"name":"P","expectation":"SILENCE","started_at_ms":0,"ended_at_ms":null,{}}}"#,
            body.trim_start_matches('{').trim_end_matches('}'),
        );
        let full = full.replace(",}", "}");
        let phase: twinoracle::Phase =
            serde_json::from_str(&full).unwrap_or_else(|e| panic!("{full}: {e}"));
        assert_eq!(phase.path, want, "{full}");
    }
}

/// A path value that is neither a letter, a word, nor `n` is a probe bug, and
/// it must be refused loudly rather than silently becoming "no claim" — a
/// typo'd tag that defaults to null is a phase that quietly stops contributing
/// to path identity.
#[test]
fn an_unrecognised_path_value_is_refused_rather_than_defaulted() {
    let body = r#"{"name":"P","expectation":"SILENCE","started_at_ms":0,
                   "ended_at_ms":null,"path":"protectd"}"#;
    let err = serde_json::from_str::<twinoracle::Phase>(body)
        .expect_err("a misspelled path must not deserialize");
    assert!(err.to_string().contains("is not a path"), "{err}");
}
