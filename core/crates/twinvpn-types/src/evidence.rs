//! Typed, registry-declared evidence.
//!
//! **Authority:** ADR-0015 §11.3 (evidence is "attached to a code, never in place
//! of one"), ADR-0015 §11.4 (field classification and redaction),
//! `contracts/proto/twinvpn/v1/errors.proto` (`Evidence`),
//! `contracts/registry/limits.json` §`diagnostics` (the caps).
//!
//! # Address family lives here, not in a namespace
//!
//! [`EvidenceValue::Family`] is `Evidence.family_value`, and it is the **only**
//! way an address family is carried on a diagnostic. ADR-0015 §11.2 refuses
//! `TVPN-IPV4`/`TVPN-IPV6` as domains because a per-family namespace "makes 'we
//! have a v4 story and a v6 story' sayable, when the design is that there is one
//! story covering both" (`ownership.md` §4.2). So a v4 failure and a v6 failure
//! are the *same* code with different evidence, and neither family can acquire a
//! diagnostic vocabulary the other lacks.
//!
//! # An undeclared key cannot be constructed
//!
//! ADR-0015 §11.3 requires a receiver to **drop** an evidence entry whose key is
//! not declared for its code, because "an undeclared key is an unclassified key,
//! and an unclassified key cannot be redacted correctly". This crate goes one
//! step earlier: [`Evidence::new`] takes the [`ReasonCode`] and refuses to build
//! an entry the registry does not declare, so an emitter cannot produce the
//! condition in the first place.

use crate::error::TypeError;
use crate::id::FieldClassification;
use crate::net::{AddressFamily, IpAddr, IpPrefix};
use crate::reason::ReasonCode;

/// `limits.json` `diagnostics.max_evidence_entries`.
pub const MAX_EVIDENCE_ENTRIES: usize = 32;
/// `limits.json` `diagnostics.max_evidence_bytes`.
pub const MAX_EVIDENCE_BYTES: usize = 4096;
/// `limits.json` `diagnostics.max_evidence_key_bytes`.
pub const MAX_EVIDENCE_KEY_BYTES: usize = 48;

/// The reserved key an emitter appends when it truncates an evidence set.
///
/// # A registry gap, worked around rather than patched
///
/// `errors.proto` requires a truncating **emitter** to append a final entry
/// `{key: "evidence_truncated"}`, but no code in
/// `contracts/registry/reason_codes.json` declares `evidence_truncated` among
/// its `evidence_fields`. A strict declared-key check would therefore reject the
/// marker the frozen schema mandates. `contracts/` is frozen
/// (`ownership.md` §3), so this key is exempted from the declared-set check here
/// and the gap is reported to the integration lead rather than patched.
pub const EVIDENCE_TRUNCATED_KEY: &str = "evidence_truncated";

/// A typed evidence value. Mirrors `Evidence.value`'s oneof exactly.
///
/// The oneof exists "so that a consumer never has to parse a number back out of
/// a string, which is where unit and precision bugs live". Two variants are
/// named rather than merely typed for the same reason: [`EvidenceValue::DurationMs`]
/// cannot be confused with a timestamp, and [`EvidenceValue::Family`] cannot be
/// confused with an arbitrary enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValue {
    /// A short string. Bounded by the set's byte budget.
    Text(String),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer.
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// A network address. **Always `SENSITIVE`.**
    Address(IpAddr),
    /// A prefix — e.g. the colliding prefix in `POLICY.PREFIX_COLLIDES_LOCAL`,
    /// which `docs/protocol.md` §13.2 requires to be named precisely rather than
    /// described.
    Prefix(IpPrefix),
    /// An address family. This is how family is carried; see the module docs.
    Family(AddressFamily),
    /// A duration in milliseconds, named so it cannot be read as a timestamp.
    DurationMs(u64),
}

impl EvidenceValue {
    /// The classification this value carries **regardless of what a registry
    /// entry claims**.
    ///
    /// An address or a prefix is `SENSITIVE` by its nature, so the floor is
    /// applied here rather than trusted from a peer's claim. A receiver honours
    /// the stricter of the carried classification and its own
    /// ([`FieldClassification::stricter`]); this is the local half of that rule.
    #[must_use]
    pub const fn intrinsic_classification(&self) -> FieldClassification {
        match self {
            EvidenceValue::Address(_) | EvidenceValue::Prefix(_) => FieldClassification::Sensitive,
            // Everything else is OPERATIONAL: "timing, states, counters, coarse
            // categories" (ADR-0015 §11.4). A registry entry may still raise an
            // individual key above this floor via `with_classification_floor`.
            EvidenceValue::Text(_)
            | EvidenceValue::Int(_)
            | EvidenceValue::Uint(_)
            | EvidenceValue::Bool(_)
            | EvidenceValue::Family(_)
            | EvidenceValue::DurationMs(_) => FieldClassification::Operational,
        }
    }

    /// The value's contribution to the set's 4 KiB budget.
    ///
    /// A conservative estimate of the encoded size — key and tag overhead is
    /// counted by [`EvidenceSet`]. Erring high is deliberate: the budget exists
    /// to bound an allocation, and an under-estimate would defeat it.
    #[must_use]
    pub fn budget_bytes(&self) -> usize {
        match self {
            EvidenceValue::Text(s) => s.len(),
            EvidenceValue::Address(_) => 20,
            EvidenceValue::Prefix(_) => 24,
            EvidenceValue::Int(_)
            | EvidenceValue::Uint(_)
            | EvidenceValue::DurationMs(_)
            | EvidenceValue::Family(_) => 10,
            EvidenceValue::Bool(_) => 2,
        }
    }
}

/// One piece of registry-declared evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    key: &'static str,
    classification: FieldClassification,
    value: EvidenceValue,
}

impl Evidence {
    /// Builds an evidence entry for `code`.
    ///
    /// `key` must be `lower_snake_case`, at most 48 bytes, and **declared for
    /// `code`** by the frozen registry. `'static` rather than `&str`: an
    /// evidence key is a registry constant, and accepting a runtime string would
    /// invite one built from attacker input.
    pub fn new(
        code: ReasonCode,
        key: &'static str,
        value: EvidenceValue,
    ) -> Result<Self, TypeError> {
        validate_key(key)?;
        if key != EVIDENCE_TRUNCATED_KEY && !code.declares_evidence(key) {
            return Err(TypeError::EvidenceKeyUndeclared {
                key: key.to_owned(),
                code: code.as_str(),
            });
        }
        Ok(Self {
            classification: value.intrinsic_classification(),
            key,
            value,
        })
    }

    /// The registry-declared key.
    #[must_use]
    pub const fn key(&self) -> &'static str {
        self.key
    }

    /// The emitter's classification of the value.
    #[must_use]
    pub const fn classification(&self) -> FieldClassification {
        self.classification
    }

    /// The typed value.
    #[must_use]
    pub const fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Raises this entry's classification to at least `floor`.
    ///
    /// `errors.proto`: "A receiver MUST honour the STRICTER of this and its own
    /// registry entry." Classification only ever moves in the strict direction —
    /// there is no method that lowers it, because lowering a classification is
    /// how `SENSITIVE` data reaches a Tier-2 export.
    #[must_use]
    pub fn with_classification_floor(mut self, floor: FieldClassification) -> Self {
        self.classification = self.classification.stricter(floor);
        self
    }

    fn budget_bytes(&self) -> usize {
        self.key.len() + 4 + self.value.budget_bytes()
    }
}

/// Validates an evidence key's shape (ADR-0015 §11.3, `limits.json`
/// `diagnostics.max_evidence_key_bytes`).
pub fn validate_key(key: &str) -> Result<(), TypeError> {
    if key.is_empty() || key.len() > MAX_EVIDENCE_KEY_BYTES {
        return Err(TypeError::EvidenceKeyMalformed);
    }
    if !key.as_bytes()[0].is_ascii_lowercase() {
        return Err(TypeError::EvidenceKeyMalformed);
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(TypeError::EvidenceKeyMalformed);
    }
    Ok(())
}

/// A bounded set of evidence entries.
///
/// `errors.proto`: "Bounded: at most 32 entries and 4 KiB total; an envelope
/// exceeding either is truncated **by the emitter (never by the receiver)** with
/// a final entry `{key:"evidence_truncated"}`."
///
/// Both halves of that are implemented: [`EvidenceSet::push`] stops adding and
/// records the truncation, and there is no API by which a *receiver* can
/// truncate — a received set that exceeds the caps is rejected by
/// `twinvpn-schema`, which is the correct answer for a set the emitter should
/// already have bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSet {
    entries: Vec<Evidence>,
    bytes: usize,
    truncated: bool,
}

impl EvidenceSet {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            bytes: 0,
            truncated: false,
        }
    }

    /// Adds an entry if it fits, otherwise records the truncation.
    ///
    /// Returns whether the entry was added. Adding is silent about *which* entry
    /// was dropped by design: the marker says the set is incomplete, and naming
    /// the dropped key would put unbounded attacker-influenced text into a set
    /// that is being truncated precisely because it is too large.
    pub fn push(&mut self, evidence: Evidence) -> bool {
        let cost = evidence.budget_bytes();
        if self.entries.len() >= MAX_EVIDENCE_ENTRIES || self.bytes + cost > MAX_EVIDENCE_BYTES {
            self.truncated = true;
            return false;
        }
        self.bytes += cost;
        self.entries.push(evidence);
        true
    }

    /// The entries, plus the truncation marker when the set was truncated.
    #[must_use]
    pub fn entries(&self) -> &[Evidence] {
        &self.entries
    }

    /// Whether anything was dropped.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The set's counted byte budget.
    #[must_use]
    pub const fn budget_used(&self) -> usize {
        self.bytes
    }

    /// The value to emit for `evidence_truncated`, when the set was truncated.
    ///
    /// Returned separately rather than stored in `entries`, so the marker cannot
    /// be mistaken for evidence and cannot itself be truncated away.
    #[must_use]
    pub fn truncation_marker(&self) -> Option<(&'static str, EvidenceValue)> {
        self.truncated
            .then_some((EVIDENCE_TRUNCATED_KEY, EvidenceValue::Bool(true)))
    }

    /// Looks up an entry by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Evidence> {
        self.entries.iter().find(|e| e.key == key)
    }
}

impl Default for EvidenceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<Evidence> for EvidenceSet {
    /// Collects entries, applying the caps. Anything beyond them sets the
    /// truncation flag rather than growing the set.
    fn from_iter<I: IntoIterator<Item = Evidence>>(iter: I) -> Self {
        let mut set = Self::new();
        for e in iter {
            set.push(e);
        }
        set
    }
}
