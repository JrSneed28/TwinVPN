//! Redaction classification — the half of the job ADR-0018 CB-4 puts in the
//! core.
//!
//! **Authority:** [ADR-0015](../../../../docs/adr/ADR-0015-observability-and-diagnostics.md)
//! §11.4 (the classification table and pseudonymization),
//! `docs/implementation/ownership.md` §6 rule 11.
//!
//! # Why this is emitter-side and not a filter
//!
//! §11.4 is explicit: *"Redaction is applied by the emitter based on the schema
//! classification. There is no 'scrub the log with regexes before sending' step,
//! because that approach fails open (O-14)."* [`redact`] is therefore a total
//! function over a typed, already-classified [`Evidence`] — it cannot be handed
//! an unclassified string, so there is nothing for a regex to have missed.
//!
//! # What cannot appear here at all
//!
//! There is no `SECRET` input. `twinvpn_types::FieldClassification` has three
//! variants and none of them is secret, because "never stored, never rendered,
//! **no code path exists**" and giving it an enum value creates the code path.
//! Keys, session keys, pairing secrets and tunnel payloads reach this module
//! through no type it can name.

use std::collections::BTreeMap;

use twinvpn_env::{Env, EnvError};
use twinvpn_types::{Evidence, EvidenceValue, FieldClassification, IpAddr};

use crate::tier::{disposition, Disposition, Tier};

/// The RNG consumer that draws a bundle's pseudonym salt.
///
/// A named `ConsumerId` rather than an ad-hoc draw, so a lab run reproduces a
/// bundle's token assignment exactly and adding a consumer elsewhere does not
/// shift this stream (`twinvpn_env::rng`).
pub const PSEUDONYM_CONSUMER: twinvpn_env::ConsumerId =
    twinvpn_env::ConsumerId::new("diag/bundle-pseudonym");

/// A per-bundle pseudonym mapping.
///
/// §11.4: *"Two occurrences of the same value map to the same token **within one
/// bundle** and to different tokens **across bundles**, so support can follow the
/// topology of one incident and cannot correlate a user across incidents. The
/// mapping is generated per bundle and discarded."*
///
/// The cross-bundle half is why this holds a salt drawn from [`Env`] at
/// construction rather than hashing the value: a pure hash of `203.0.113.7`
/// would be the *same token in every bundle ever produced*, which is precisely
/// the correlation the rule forbids. The within-bundle half is why the map is
/// kept rather than recomputed.
#[derive(Debug)]
pub struct Pseudonymizer {
    salt: [u8; 16],
    /// `(kind, canonical value) -> ordinal`. `BTreeMap` so the token a value
    /// receives depends on **first appearance order**, which is stable for one
    /// input sequence and reveals nothing about the value itself.
    assigned: BTreeMap<(&'static str, String), u32>,
    next: BTreeMap<&'static str, u32>,
}

impl Pseudonymizer {
    /// Draws a fresh mapping for one bundle.
    ///
    /// # Errors
    ///
    /// [`EnvError`] if the entropy source refuses. A pseudonymizer is **not**
    /// constructed with a zero salt on failure: an un-salted mapping is
    /// cross-bundle correlatable, so failing to produce a bundle is the correct
    /// outcome and a silently weaker one is not.
    pub fn new(env: &Env) -> Result<Self, EnvError> {
        let mut rng = env.rng_for(PSEUDONYM_CONSUMER)?;
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        Ok(Self {
            salt,
            assigned: BTreeMap::new(),
            next: BTreeMap::new(),
        })
    }

    /// A mapping with a caller-supplied salt. Test support only.
    #[must_use]
    pub fn with_salt(salt: [u8; 16]) -> Self {
        Self {
            salt,
            assigned: BTreeMap::new(),
            next: BTreeMap::new(),
        }
    }

    /// This bundle's salt, so two mappings can be compared in a test.
    #[must_use]
    pub const fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// The token for one value of one kind.
    ///
    /// Kinds are separate namespaces (`ipv4-A`, `ipv6-B`, `iface-1`, `peer-2`),
    /// which is what makes a pseudonymized bundle still *readable*: the shape of
    /// the incident survives even though no value does.
    pub fn token(&mut self, kind: &'static str, value: &str) -> String {
        let key = (kind, value.to_owned());
        if let Some(n) = self.assigned.get(&key) {
            return format_token(kind, *n);
        }
        let counter = self.next.entry(kind).or_insert(0);
        let n = *counter;
        *counter += 1;
        self.assigned.insert(key, n);
        format_token(kind, n)
    }

    /// How many distinct values this mapping has assigned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.assigned.len()
    }

    /// Whether nothing has been pseudonymized yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.assigned.is_empty()
    }
}

/// `ipv4-A`, `ipv4-B`, … then `ipv4-AA`. Letters for address-like kinds, digits
/// for countable ones, exactly as §11.4's worked example spells them.
fn format_token(kind: &'static str, n: u32) -> String {
    if kind.starts_with("ipv") {
        let mut suffix = String::new();
        let mut v = n;
        loop {
            suffix.insert(0, char::from(b'A' + u8::try_from(v % 26).unwrap_or(0)));
            if v < 26 {
                break;
            }
            v = v / 26 - 1;
        }
        format!("{kind}-{suffix}")
    } else {
        format!("{kind}-{}", n + 1)
    }
}

/// One evidence entry, after the tier's redaction rule has been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEvidence {
    /// The registry-declared key. Never redacted: a key is a registry constant.
    pub key: &'static str,
    /// The classification the value was carried at.
    pub classification: FieldClassification,
    /// What survived. `None` means the field was dropped, which is itself
    /// recorded — a caller can count drops rather than infer them.
    pub value: Option<RedactedValue>,
}

/// A value after redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactedValue {
    /// Carried unchanged.
    Typed(EvidenceValue),
    /// Replaced by a per-bundle pseudonym.
    Pseudonym(String),
    /// Replaced by a coarse bucket tag.
    Bucket(&'static str),
}

/// Applies §11.4's table to one evidence entry.
///
/// The `Pseudonymize` arm needs a mapping; passing `None` at [`Tier::Bundle`]
/// **drops** the field rather than carrying it, because carrying a `SENSITIVE`
/// value into a bundle because no mapping was supplied is the fail-open O-14
/// forbids.
#[must_use]
pub fn redact(
    evidence: &Evidence,
    tier: Tier,
    pseudonyms: Option<&mut Pseudonymizer>,
) -> RedactedEvidence {
    let class = evidence.classification();
    let value = match disposition(class, tier) {
        Disposition::Include => Some(RedactedValue::Typed(evidence.value().clone())),
        Disposition::Drop => None,
        Disposition::Bucket => Some(RedactedValue::Bucket(bucket_tag(evidence.value()))),
        Disposition::Pseudonymize => pseudonyms.map(|p| {
            let (kind, canonical) = pseudonym_kind(evidence.value());
            RedactedValue::Pseudonym(p.token(kind, &canonical))
        }),
    };
    RedactedEvidence {
        key: evidence.key(),
        classification: class,
        value,
    }
}

/// The bucket a Tier-2 aggregate carries in place of a precise value.
///
/// Coarse by construction: ADR-0015 §11.1 restricts Tier 2 to "coarse,
/// identifier-free, k-anonymous counters", so a duration becomes an order of
/// magnitude and a count becomes a magnitude class. Nothing here can carry a
/// value with enough resolution to identify a device.
const fn bucket_tag(value: &EvidenceValue) -> &'static str {
    match value {
        EvidenceValue::Bool(true) => "true",
        EvidenceValue::Bool(false) => "false",
        EvidenceValue::Family(_) => "family",
        EvidenceValue::DurationMs(ms) => match ms {
            0..=99 => "lt_100ms",
            100..=999 => "lt_1s",
            1_000..=9_999 => "lt_10s",
            10_000..=59_999 => "lt_1m",
            _ => "ge_1m",
        },
        EvidenceValue::Uint(n) => match n {
            0 => "zero",
            1 => "one",
            2..=9 => "few",
            10..=99 => "tens",
            _ => "many",
        },
        EvidenceValue::Int(_) => "signed",
        EvidenceValue::Text(_) => "text",
        // Unreachable in practice: both are intrinsically SENSITIVE and are
        // dropped by the table before they reach here. Answering with a
        // non-identifying tag rather than panicking keeps the function total.
        EvidenceValue::Address(_) | EvidenceValue::Prefix(_) => "address",
    }
}

/// The pseudonym namespace and canonical form for a sensitive value.
fn pseudonym_kind(value: &EvidenceValue) -> (&'static str, String) {
    match value {
        EvidenceValue::Address(IpAddr::V4(a)) => ("ipv4", hex(&a.octets())),
        EvidenceValue::Address(IpAddr::V6(a)) => ("ipv6", hex(&a.octets())),
        EvidenceValue::Prefix(p) => (
            "prefix",
            format!("{}/{}", hex(&p.address().octets()), p.prefix_len()),
        ),
        EvidenceValue::Text(t) => ("value", t.clone()),
        EvidenceValue::Int(n) => ("value", n.to_string()),
        EvidenceValue::Uint(n) => ("value", n.to_string()),
        EvidenceValue::Bool(b) => ("value", b.to_string()),
        EvidenceValue::Family(f) => ("value", format!("{f:?}")),
        EvidenceValue::DurationMs(ms) => ("value", ms.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;
    use twinvpn_types::{codes, V4Addr};

    fn addr(last: u8) -> EvidenceValue {
        EvidenceValue::Address(IpAddr::V4(
            V4Addr::from_slice(&[203, 0, 113, last]).expect("v4"),
        ))
    }

    fn sensitive_evidence(last: u8) -> Evidence {
        Evidence::new(codes::ROUTE_ADDRESS_COLLISION, "address", addr(last))
            .expect("address is declared for ROUTE.ADDRESS_COLLISION")
    }

    #[test]
    fn one_value_gets_one_token_within_a_bundle() {
        let mut p = Pseudonymizer::with_salt([7; 16]);
        let a = redact(&sensitive_evidence(7), Tier::Bundle, Some(&mut p));
        let b = redact(&sensitive_evidence(7), Tier::Bundle, Some(&mut p));
        assert_eq!(a.value, b.value);
        assert_eq!(a.value, Some(RedactedValue::Pseudonym("ipv4-A".to_owned())));
    }

    #[test]
    fn two_values_get_two_tokens() {
        let mut p = Pseudonymizer::with_salt([7; 16]);
        let a = redact(&sensitive_evidence(7), Tier::Bundle, Some(&mut p));
        let b = redact(&sensitive_evidence(8), Tier::Bundle, Some(&mut p));
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn a_sensitive_field_is_dropped_at_tier_two() {
        let r = redact(&sensitive_evidence(7), Tier::Aggregate, None);
        assert!(r.value.is_none(), "SENSITIVE must never reach Tier 2");
    }

    #[test]
    fn a_sensitive_field_without_a_mapping_is_dropped_not_carried() {
        // The fail-open case, made a test: no mapping means no bundle entry,
        // never a verbatim address.
        let r = redact(&sensitive_evidence(7), Tier::Bundle, None);
        assert!(r.value.is_none());
    }

    #[test]
    fn tier_zero_carries_the_real_value() {
        let r = redact(&sensitive_evidence(7), Tier::LocalLedger, None);
        assert_eq!(r.value, Some(RedactedValue::Typed(addr(7))));
    }

    #[test]
    fn operational_evidence_is_bucketed_at_tier_two() {
        let e = Evidence::new(
            codes::INTERNAL_BUFFER_OVERFLOW,
            "dropped",
            EvidenceValue::Uint(4_000),
        )
        .expect("dropped is declared");
        let r = redact(&e, Tier::Aggregate, None);
        assert_eq!(r.value, Some(RedactedValue::Bucket("many")));
    }

    #[test]
    fn token_alphabet_wraps_past_z() {
        let mut p = Pseudonymizer::with_salt([0; 16]);
        for i in 0..27u32 {
            let _ = p.token("ipv4", &i.to_string());
        }
        assert_eq!(p.token("ipv4", "0"), "ipv4-A");
        assert_eq!(p.token("ipv4", "26"), "ipv4-AA");
    }
}
