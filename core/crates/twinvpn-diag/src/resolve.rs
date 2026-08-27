//! The presentation **resolver** — ADR-0018 CB-4's core-side half, and the pure
//! function behind `tw_render_diagnostic` (F-10).
//!
//! **Authority:** ADR-0018 CB-4 and §11.4 F-4/F-10; ADR-0019 §11.1, §11.5
//! (PC-2's fallback chain, LT-3a/b/c, LT-4, LT-5); ADR-0015 §11.2 rule 4 and
//! rule 5.
//!
//! # The line this module sits on
//!
//! | Job | Side | This module |
//! |---|---|---|
//! | **Resolution** — code + typed evidence + locale + platform context → catalogue lookup, evidence substitution, the F-4 `resolved` attribute set, the LT-3 next-action variant | **Core** | yes |
//! | **Presentation** — typography, layout, truncation, platform idiom, iconography, where it appears | **Shell** | never |
//!
//! # Purity is a property, not an aspiration
//!
//! [`render`] takes no `Env`, no clock, no instance and no global. It reads no
//! ambient locale and no ambient platform: both arrive as parameters, and an
//! **empty** platform context resolves to the neutral variant rather than to the
//! host's own platform (LT-3b). That is what lets ADR-0019's P18 drive every
//! platform's variants exhaustively from one Linux CI runner, and what lets a
//! **poisoned** core instance still render the diagnostic describing the fault
//! that poisoned it (F-7 + F-10).
//!
//! # What it will not do
//!
//! - It will not hardcode a language: the source locale is a generated constant
//!   and every lookup takes a requested locale.
//! - It will not assemble a sentence (LT-4). Placeholders are named and bound to
//!   registry-declared evidence at build time; there is no `format!("{}: {}",
//!   code, msg)` anywhere in the chain.
//! - It will not fail on an unknown code. ADR-0015 §11.2 rule 5: it degrades to
//!   the `DOMAIN` prefix, **with attributes**, and never presents the raw code as
//!   the primary signal.

use twinvpn_types::{
    DiagnosticScope, Domain, ErrorClass, ErrorSeverity, EvidenceValue, ObservedReasonCode,
    ReasonCode, RemediationClass,
};

include!(concat!(env!("OUT_DIR"), "/catalogue.rs"));

/// One catalogue row.
#[derive(Debug)]
struct CatalogueEntry {
    key: &'static str,
    code: &'static str,
    /// LT-3b's mandatory neutral variant. Never empty — the build script
    /// refuses to emit an empty one.
    neutral: &'static str,
    /// Whether this row carries hand-authored copy rather than the
    /// registry-derived seed.
    authored: bool,
    variants: &'static [Variant],
}

/// An LT-3 platform variant.
#[derive(Debug)]
struct Variant {
    /// The `twinvpn.v1.DevicePlatform` enum name, without its prefix:
    /// `IOS`, `IPADOS`, `ANDROID`, `MACOS`, `WINDOWS`, `LINUX`, `OPENWRT`.
    platform: &'static str,
    text: &'static str,
}

/// The platform context `tw_render_diagnostic` carries, decoded.
///
/// ADR-0018 F-10: *"carrying at least `{platform, os_version}` and extensible"*.
/// It is decoded from `twinvpn.v1.DevicePlatformInfo`, which already carries
/// exactly that plus `arch`, so adding a distro identifier later needs no ABI
/// break.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformContext {
    /// The `DevicePlatform` enum name without its prefix, or `None` for the
    /// **neutral** context.
    pub platform: Option<&'static str>,
    /// The OS release, e.g. `"17.4"`. Carried so a future variant table can
    /// select on a version range; the current table selects on platform alone
    /// and this is recorded rather than dropped.
    pub os_version: Option<String>,
}

impl PlatformContext {
    /// The neutral context. LT-3b: this is what an **empty** `platform_ctx`
    /// resolves to, and it MUST NOT fall back to the host's own platform.
    #[must_use]
    pub const fn neutral() -> Self {
        Self {
            platform: None,
            os_version: None,
        }
    }

    /// Decodes `twinvpn.v1.DevicePlatformInfo`.
    ///
    /// An **empty** slice is the neutral context, which is the ABI's way of
    /// saying "render for nobody in particular". A slice that does not decode is
    /// also neutral rather than an error: F-10 must not fail, because the moment
    /// it is called is often the moment nothing else works.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::neutral();
        }
        let Ok(info) = <twinvpn_schema::v1::DevicePlatformInfo as prost::Message>::decode(bytes)
        else {
            return Self::neutral();
        };
        Self {
            platform: platform_tag(info.platform),
            os_version: if info.os_version.is_empty() {
                None
            } else {
                Some(info.os_version)
            },
        }
    }
}

/// The `twinvpn.v1.DevicePlatform` tag, or `None` for `UNSPECIFIED`.
///
/// `UNSPECIFIED` maps to the **neutral** variant, not to a guess.
const fn platform_tag(value: i32) -> Option<&'static str> {
    match value {
        1 => Some("IOS"),
        2 => Some("IPADOS"),
        3 => Some("ANDROID"),
        4 => Some("MACOS"),
        5 => Some("WINDOWS"),
        6 => Some("LINUX"),
        7 => Some("OPENWRT"),
        _ => None,
    }
}

/// One evidence binding, as it arrives at the renderer.
///
/// A `String` key rather than `&'static str` because the renderer must accept a
/// code it has never seen — an unknown code carries keys this build cannot name
/// as constants, and refusing them would defeat rule 5's forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The evidence key.
    pub key: String,
    /// Its typed value.
    pub value: EvidenceValue,
}

/// Which rung of ADR-0019 §11.5's fallback chain produced a sentence.
///
/// Counted and surfaced in the connectivity report so translation and copy gaps
/// are **measurable rather than invisible**, which is what that section asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FallbackRung {
    /// The requested locale had the entry.
    RequestedLocale,
    /// The source locale had it.
    SourceLocale,
    /// The code was not registered; the sentence is its `DOMAIN`'s.
    DomainFallback,
    /// Nothing matched. Reserved: [`render`] never returns this, because the
    /// domain rung is total over the closed sixteen-domain set and the
    /// unparseable case has its own neutral sentence.
    Neutral,
}

/// The F-4 `resolved` attribute set — registry metadata, never text.
///
/// ADR-0018 F-4: *"`resolved` is metadata, not rendered text, and the
/// distinction is normative … Adding a `summary`, `message`, or `title` field
/// here would breach both [CB-4 and MI-15], and MUST NOT be done."* The rendered
/// sentences in [`Resolved`] are a **separate** call's output, produced on the
/// consumer's own side of the boundary; they are not fields of this struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedAttributes {
    /// How the condition behaves over time.
    pub class: ErrorClass,
    /// Its severity.
    pub severity: ErrorSeverity,
    /// Whether it ends the current attempt, read with `scope`.
    pub terminal: bool,
    /// Whether an Owner can act.
    pub user_actionable: bool,
    /// The shape of the remediation.
    pub remediation_class: RemediationClass,
    /// What the condition applies to.
    pub scope: DiagnosticScope,
    /// Stable documentation anchor.
    pub doc_anchor: &'static str,
}

/// The whole result of resolving one diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The code as it arrived, registered or not.
    pub reason_code: String,
    /// The domain it degrades on. Always resolvable: an unparseable code
    /// degrades to [`Domain::Internal`], which is the truthful answer — a code
    /// this build cannot parse is a defect somewhere.
    pub domain: Domain,
    /// Whether the frozen registry carries this code.
    pub registered: bool,
    /// The registry attributes. **Present for every code, including an unknown
    /// one** (F-4): that is the point — an unknown code still arrives with its
    /// severity and actionability intact, so a consumer can behave correctly on
    /// a code shipped after it was built.
    pub attributes: ResolvedAttributes,
    /// The one-line explanation. Never empty, never an i18n key, never the raw
    /// code (PC-3).
    pub summary: String,
    /// What to do, or `None` when the code declares no next action.
    pub next_action: Option<String>,
    /// Which rung produced `summary`.
    pub summary_rung: FallbackRung,
    /// Which rung produced `next_action`.
    pub next_action_rung: Option<FallbackRung>,
    /// Whether the sentences came from hand-authored copy rather than the
    /// registry-derived seed. Reported, not hidden.
    pub authored: bool,
}

/// Resolves one diagnostic. **Pure**: same inputs, same output, on every target.
///
/// This is the function `tw_render_diagnostic` wraps. It takes no instance, no
/// clock, no I/O and no ambient state; `locale` and `platform` are parameters,
/// never read from the environment (CD-2), and an empty `platform` resolves to
/// the neutral variant (LT-3b).
#[must_use]
pub fn render(
    reason_code: &str,
    evidence: &[Binding],
    locale: &str,
    platform: &PlatformContext,
) -> Resolved {
    let observed = ObservedReasonCode::parse(reason_code);
    let registered = observed
        .as_ref()
        .ok()
        .and_then(ObservedReasonCode::registered);
    let domain = observed
        .as_ref()
        .map_or(Domain::Internal, ObservedReasonCode::domain);

    let attributes = registered.map_or(
        // ADR-0015 §11.2 rule 5 says degrade with the *real* attributes. For a
        // code no build carries there are none, so the honest answer is the
        // conservative one: a persistent, error-severity, non-terminal condition
        // an Owner cannot act on. It is not claimed to be the code's own.
        ResolvedAttributes {
            class: ErrorClass::Persistent,
            severity: ErrorSeverity::Error,
            terminal: false,
            user_actionable: false,
            remediation_class: RemediationClass::ReportDefect,
            scope: DiagnosticScope::Session,
            doc_anchor: "adr-0015#reason-code-taxonomy",
        },
        |c| ResolvedAttributes {
            class: c.class(),
            severity: c.severity(),
            terminal: c.terminal(),
            user_actionable: c.user_actionable(),
            remediation_class: c.remediation_class(),
            scope: c.scope(),
            doc_anchor: c.doc_anchor(),
        },
    );

    let (summary, summary_rung, authored) = match registered {
        Some(c) => {
            let entry = lookup(c.summary_key());
            entry.map_or_else(
                || {
                    (
                        domain_summary(domain).to_owned(),
                        FallbackRung::DomainFallback,
                        false,
                    )
                },
                |e| {
                    (
                        substitute(e.neutral, evidence),
                        locale_rung(locale),
                        e.authored,
                    )
                },
            )
        }
        None => (
            domain_summary(domain).to_owned(),
            FallbackRung::DomainFallback,
            false,
        ),
    };

    let (next_action, next_action_rung) = match registered.and_then(ReasonCode::next_action_key) {
        Some(key) => match lookup(key) {
            Some(e) => (
                Some(substitute(select_variant(e, platform), evidence)),
                Some(locale_rung(locale)),
            ),
            None => (
                Some(domain_next_action(domain).to_owned()),
                Some(FallbackRung::DomainFallback),
            ),
        },
        // An unregistered code has no declared next action. Offering the domain
        // fallback anyway is the right call: rule 5 requires a consumer meeting
        // an unknown code to still be able to present something actionable, and
        // "we do not know this code" is not an instruction.
        None if !attributes.user_actionable && registered.is_some() => (None, None),
        None => (
            Some(domain_next_action(domain).to_owned()),
            Some(FallbackRung::DomainFallback),
        ),
    };

    Resolved {
        reason_code: reason_code.to_owned(),
        domain,
        registered: registered.is_some(),
        attributes,
        summary,
        next_action,
        summary_rung,
        next_action_rung,
        authored,
    }
}

/// LT-3a: variant selection is a **decision**, made here, from `platform_ctx`.
///
/// A shell choosing among returned keys is what CB-2 forbids and what would let
/// a GUI and a CLI **on the same host** diverge.
fn select_variant(entry: &'static CatalogueEntry, platform: &PlatformContext) -> &'static str {
    let Some(tag) = platform.platform else {
        // LT-3b, in one line: no platform means the neutral variant, and never
        // the host's own.
        return entry.neutral;
    };
    entry
        .variants
        .iter()
        .find(|v| v.platform == tag)
        .map_or(entry.neutral, |v| v.text)
}

/// Which rung a hit in the shipped catalogue counts as.
///
/// Only the source locale ships today, so a request for it is
/// [`FallbackRung::RequestedLocale`] and anything else is
/// [`FallbackRung::SourceLocale`]. The distinction is kept rather than collapsed
/// because it is exactly the number ADR-0019 §11.5 asks to be *counted*, and a
/// resolver that reported every render as a first-rung hit would make the gap
/// invisible — which is the failure that section names.
fn locale_rung(locale: &str) -> FallbackRung {
    let primary = locale.split(['-', '_']).next().unwrap_or(locale);
    if primary.eq_ignore_ascii_case(SOURCE_LOCALE) {
        FallbackRung::RequestedLocale
    } else {
        FallbackRung::SourceLocale
    }
}

fn lookup(key: &str) -> Option<&'static CatalogueEntry> {
    ENTRIES
        .binary_search_by(|e| e.key.cmp(key))
        .ok()
        .map(|i| &ENTRIES[i])
}

fn domain_summary(domain: Domain) -> &'static str {
    find(DOMAIN_SUMMARY, domain).unwrap_or(
        "TwinVPN reported a condition this version does not recognise. Create a diagnostic \
         report and share it with support.",
    )
}

fn domain_next_action(domain: Domain) -> &'static str {
    find(DOMAIN_NEXT_ACTION, domain)
        .unwrap_or("Create a diagnostic report and share it with support.")
}

fn find(table: &'static [(&'static str, &'static str)], domain: Domain) -> Option<&'static str> {
    let name = domain_name(domain);
    table.iter().find(|(d, _)| *d == name).map(|(_, t)| *t)
}

/// The registry spelling of a domain.
///
/// The wildcard arm and the `INTERNAL` arm share a body deliberately: `Domain`
/// is `#[non_exhaustive]`, and a domain this build cannot name degrades to
/// `INTERNAL` because that is the truthful reading, not because it is the same
/// condition.
#[allow(clippy::match_same_arms)]
const fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Net => "NET",
        Domain::Nat => "NAT",
        Domain::Relay => "RELAY",
        Domain::Auth => "AUTH",
        Domain::Crypto => "CRYPTO",
        Domain::Proto => "PROTO",
        Domain::Policy => "POLICY",
        Domain::Dns => "DNS",
        Domain::Route => "ROUTE",
        Domain::Platform => "PLATFORM",
        Domain::Resource => "RESOURCE",
        Domain::Control => "CONTROL",
        Domain::Internal => "INTERNAL",
        Domain::Mgmt => "MGMT",
        Domain::Store => "STORE",
        Domain::Update => "UPDATE",
        // `Domain` is `#[non_exhaustive]`. ADR-0015 §11.2 closes the set at
        // sixteen and admits a seventeenth only by amendment, so this arm is
        // unreachable today — but it must exist, and it must not guess: an
        // unnamed domain degrades to `INTERNAL`, which is the truthful reading
        // (a build meeting a domain it cannot name has a defect somewhere).
        _ => "INTERNAL",
    }
}

/// LT-4's substitution: named placeholders bound to declared evidence.
///
/// A placeholder with no binding is **removed with its surrounding sentence
/// intact** rather than left as `{key}` or replaced with an empty string in the
/// middle of a clause — a rendered brace is the exact "the code ends up in the
/// headline" failure PC-3 forbids. The build script has already proved every
/// placeholder names a declared key, so a missing binding here means the emitter
/// did not attach the evidence, not that the catalogue is wrong.
fn substitute(pattern: &str, evidence: &[Binding]) -> String {
    if !pattern.contains('{') {
        return pattern.to_owned();
    }
    let mut out = String::with_capacity(pattern.len() + 32);
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let name = &after[..close];
            if let Some(b) = evidence.iter().find(|b| b.key == name) {
                out.push_str(&render_value(&b.value));
            } else {
                out.push_str(MISSING_EVIDENCE);
            }
            rest = &after[close + 1..];
        } else {
            // An unterminated brace: emit it literally and stop scanning.
            out.push('{');
            rest = after;
            break;
        }
    }
    out.push_str(rest);
    out
}

/// What a declared-but-unattached placeholder renders as.
///
/// A whole word, in the source locale, so the sentence stays grammatical. Not an
/// empty string (which produces "TwinVPN found  broken") and not the key.
const MISSING_EVIDENCE: &str = "not recorded";

/// Renders one typed value.
///
/// LT-5's plural and gender rules are a **catalogue** concern — a pattern
/// carries the ICU plural categories — so this renders the value and never the
/// noun beside it.
fn render_value(value: &EvidenceValue) -> String {
    match value {
        EvidenceValue::Text(s) => s.clone(),
        EvidenceValue::Int(n) => n.to_string(),
        EvidenceValue::Uint(n) => n.to_string(),
        EvidenceValue::Bool(b) => (*b).to_string(),
        EvidenceValue::Address(a) => render_address(*a),
        EvidenceValue::Prefix(p) => format!("{}/{}", render_address(p.address()), p.prefix_len()),
        EvidenceValue::Family(f) => match f {
            twinvpn_types::AddressFamily::V4 => "IPv4".to_owned(),
            twinvpn_types::AddressFamily::V6 => "IPv6".to_owned(),
        },
        EvidenceValue::DurationMs(ms) => format!("{ms} ms"),
    }
}

/// Renders an address for a user-facing sentence.
///
/// `V4Addr` and `V6Addr` have a **redacted `Debug`** by design (`core/README.md`
/// §5), so there is no accidental path from a derive to a rendered address. This
/// is the deliberate, greppable one: it is reached only when a catalogue pattern
/// names an address-valued evidence key, and the redaction rules in
/// [`crate::redact`] decide separately whether that value exists at all at the
/// tier being rendered.
fn render_address(addr: twinvpn_types::IpAddr) -> String {
    match addr {
        twinvpn_types::IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        }
        twinvpn_types::IpAddr::V6(a) => {
            let o = a.octets();
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([o[i * 2], o[i * 2 + 1]])))
                .collect();
            groups.join(":")
        }
    }
}

/// Which registered code owns a catalogue key.
///
/// The catalogue's provenance, exposed so a conformance suite can assert that
/// every entry is *derived from* the registry rather than authored beside it —
/// the same "one source" property `twinvpn-mgmt` asserts for the command set.
#[must_use]
pub fn entry_owner(key: &str) -> Option<&'static str> {
    lookup(key).map(|e| e.code)
}

/// How many catalogue entries carry hand-authored copy. Surfaced so the gap
/// between the registry-derived seed and finished copy is measurable.
#[must_use]
pub const fn authored_entries() -> usize {
    AUTHORED_ENTRIES
}

/// Total catalogue entries.
#[must_use]
pub const fn total_entries() -> usize {
    TOTAL_ENTRIES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neutral() -> PlatformContext {
        PlatformContext::neutral()
    }

    #[test]
    fn every_registered_code_resolves_to_a_real_sentence() {
        // ADR-0019 R-33 and the fallback chain's rule: it "never terminates in
        // an empty string, in the i18n key, or in the raw code as the primary
        // signal".
        for code in ReasonCode::all() {
            let r = render(code.as_str(), &[], "en", &neutral());
            assert!(!r.summary.trim().is_empty(), "{code} has no summary");
            assert!(
                !r.summary.contains("reason."),
                "{code} rendered an i18n key: {}",
                r.summary
            );
            assert!(
                !r.summary.starts_with(code.as_str()),
                "{code} rendered the raw code as the headline"
            );
        }
    }

    #[test]
    fn lt_3c_every_user_actionable_code_has_a_neutral_next_action() {
        for code in ReasonCode::all() {
            if !code.user_actionable() {
                continue;
            }
            let r = render(code.as_str(), &[], "en", &neutral());
            let action = r
                .next_action
                .expect("user_actionable implies a next action");
            assert!(!action.trim().is_empty(), "{code} has an empty next action");
        }
    }

    #[test]
    fn lt_3b_an_empty_platform_context_never_falls_back_to_a_host_platform() {
        let neutral = render(
            "PLATFORM.VPN_PERMISSION_DENIED",
            &[],
            "en",
            &PlatformContext::neutral(),
        );
        let linux = render(
            "PLATFORM.VPN_PERMISSION_DENIED",
            &[],
            "en",
            &PlatformContext {
                platform: Some("LINUX"),
                os_version: None,
            },
        );
        assert_ne!(neutral.next_action, linux.next_action);
        assert_eq!(
            neutral.next_action.as_deref(),
            Some("Grant TwinVPN permission to create a VPN connection in this device's system settings.")
        );
    }

    #[test]
    fn lt_3a_variants_differ_per_platform_and_are_selected_core_side() {
        let mut seen = std::collections::BTreeSet::new();
        for p in ["ANDROID", "IOS", "MACOS", "WINDOWS", "LINUX"] {
            let r = render(
                "PLATFORM.VPN_PERMISSION_DENIED",
                &[],
                "en",
                &PlatformContext {
                    platform: Some(p),
                    os_version: None,
                },
            );
            seen.insert(r.next_action.expect("variant"));
        }
        assert_eq!(seen.len(), 5, "each platform selects its own variant");
    }

    #[test]
    fn an_unknown_code_degrades_on_its_domain_with_attributes() {
        let r = render("NET.SOMETHING_SHIPPED_LATER", &[], "en", &neutral());
        assert!(!r.registered);
        assert_eq!(r.domain, Domain::Net);
        assert_eq!(r.summary_rung, FallbackRung::DomainFallback);
        assert!(!r.summary.is_empty());
        // F-4: attributes are present for an unknown code too.
        assert_eq!(r.attributes.severity, ErrorSeverity::Error);
    }

    #[test]
    fn an_unparseable_code_still_renders() {
        let r = render("not a code at all", &[], "en", &neutral());
        assert!(!r.summary.trim().is_empty());
        assert_eq!(r.domain, Domain::Internal);
    }

    #[test]
    fn render_is_pure_for_the_same_inputs() {
        let a = render("NET.NO_ROUTE", &[], "en", &neutral());
        let b = render("NET.NO_ROUTE", &[], "en", &neutral());
        assert_eq!(a, b);
    }

    #[test]
    fn placeholders_bind_declared_evidence() {
        let r = render(
            "INTERNAL.BUFFER_OVERFLOW",
            &[Binding {
                key: "dropped".to_owned(),
                value: EvidenceValue::Uint(12),
            }],
            "en",
            &neutral(),
        );
        assert!(r.summary.contains("12"), "{}", r.summary);
        assert!(!r.summary.contains('{'));
    }

    #[test]
    fn an_unbound_placeholder_leaves_a_grammatical_sentence() {
        let r = render("INTERNAL.BUFFER_OVERFLOW", &[], "en", &neutral());
        assert!(!r.summary.contains('{'), "{}", r.summary);
        assert!(r.summary.contains(MISSING_EVIDENCE), "{}", r.summary);
    }

    #[test]
    fn a_non_source_locale_is_counted_as_a_fallback_rung() {
        let r = render("NET.NO_ROUTE", &[], "fr-CA", &neutral());
        assert_eq!(r.summary_rung, FallbackRung::SourceLocale);
        let r = render("NET.NO_ROUTE", &[], "en-GB", &neutral());
        assert_eq!(r.summary_rung, FallbackRung::RequestedLocale);
    }

    #[test]
    fn an_empty_platform_ctx_blob_decodes_to_neutral() {
        assert_eq!(PlatformContext::decode(&[]), PlatformContext::neutral());
    }

    #[test]
    fn a_malformed_platform_ctx_decodes_to_neutral_not_to_the_host() {
        assert_eq!(
            PlatformContext::decode(&[0xff, 0xff, 0xff]),
            PlatformContext::neutral()
        );
    }

    #[test]
    fn every_catalogue_entry_belongs_to_a_registered_code() {
        // The generated `code` field is the entry's provenance. Asserting it
        // here is what makes the catalogue *derived from the registry* rather
        // than a second table that happens to use the same keys — the R-31
        // divergence this crate exists on the right side of.
        for entry in ENTRIES {
            let code = ReasonCode::lookup(entry.code)
                .unwrap_or_else(|| panic!("{} names an unregistered code", entry.key));
            assert!(
                code.summary_key() == entry.key || code.next_action_key() == Some(entry.key),
                "{} is attributed to {} but that code names neither key",
                entry.key,
                entry.code
            );
        }
    }

    #[test]
    fn the_catalogue_covers_every_key_the_registry_names() {
        let mut expected = 0usize;
        for c in ReasonCode::all() {
            expected += 1;
            if c.next_action_key().is_some() {
                expected += 1;
            }
        }
        assert_eq!(total_entries(), expected);
    }
}
