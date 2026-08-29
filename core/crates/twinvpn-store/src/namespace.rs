//! ST-14 — the eleven declared namespaces, and the compiled-in table.
//!
//! **Authority:** ADR-0020 ST-14, ST-14a, ST-14b, §11.11 (which rungs may drop
//! which namespace), ADR-0009 (the consistency classes).
//!
//! # ST-14, quoted
//!
//! > "`identity/ peer/ trust/ doc/ session/ net/ policy/ consent/ pref/ cap/
//! > store/`. Each namespace declares its `rec_schema` and its secrecy class in
//! > a compiled-in table. Writing a key outside the declared namespaces is
//! > `INTERNAL.INVARIANT_VIOLATED`."
//!
//! # ST-14a, made structural
//!
//! > "`consent/` and `pref/` are separable by construction … every bulk
//! > operation the management interface exposes is **namespace-scoped**: a
//! > 'reset UI settings' action addresses `pref/` and has no representation
//! > capable of naming `consent/`. **There is no wildcard clear, no 'reset all
//! > local state' verb, and no key pattern that spans both.**"
//!
//! The mechanism: every bulk operation in this crate takes a [`Namespace`] — an
//! enum value, not a pattern — and there is no `clear_all`, no glob, and no
//! prefix match. `Namespace` cannot express "consent and pref", so a cosmetic
//! reset has no representation that reaches an authorization decision.
//!
//! ST-14b adds that `consent/` has no non-local writer: this crate offers no
//! ingress by which a decoded wire message reaches it, because the store has no
//! wire-message API at all — it stores bytes a caller already decided to write.

use crate::error::{Result, StoreError};

/// Whether a namespace's contents are recoverable from elsewhere.
///
/// This is what the recovery ladder's rungs branch on: §11.11 L2 may drop a
/// whole namespace and re-pull it, and explicitly may **not** do that for
/// `peer/` and `trust/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recoverability {
    /// Re-fetchable from the control plane or re-derivable. L2 may drop it.
    Cache,
    /// Holds a monotone floor or an authorization decision. L2 **must not** drop
    /// it; a failure escalates to L3, where floors are seeded from the Tier-1
    /// anchor — never from the quarantined file.
    FloorBearing,
    /// Local-only and irreplaceable: losing it loses an Owner decision that no
    /// remote party may re-supply (ST-14b).
    LocalAuthoritative,
}

/// Whether records in a namespace carry secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secrecy {
    /// Contains material whose disclosure is a compromise — `PairSecret`,
    /// `EpochSeed`.
    SecretBearing,
    /// Sensitive but not secret: identifiers, addresses, labels.
    Sensitive,
    /// Operational.
    Operational,
}

/// One of ST-14's eleven namespaces.
///
/// A closed enum. There is no `Namespace::from_str` that accepts an arbitrary
/// string and no `Other(String)` variant, which is what makes "writing a key
/// outside the declared namespaces" a compile error at most call sites and a
/// typed refusal at the one boundary ([`Namespace::parse`]) where a string
/// arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Namespace {
    /// This device's own identity material and its public record (S-01, S-46).
    Identity,
    /// `TrustedPeer` records (S-05).
    Peer,
    /// Revocation state, epochs, anchors, delegations (S-03, S-32, S-33).
    Trust,
    /// Signed documents and their high-water marks (S-27).
    Doc,
    /// Session-adjacent durable state.
    Session,
    /// Network contract, addresses, routes.
    Net,
    /// The Owner-signed policy bundle (S-06, S-07).
    Policy,
    /// Route consent records (S-50). **Authorization decisions.**
    Consent,
    /// UI presentation preferences (S-51). **Cosmetic.**
    Pref,
    /// Capability advertisements and the S-37 negotiation floor.
    Cap,
    /// The store's own metadata.
    Store,
}

/// Every namespace, in ST-14's declared order.
pub const ALL: &[Namespace] = &[
    Namespace::Identity,
    Namespace::Peer,
    Namespace::Trust,
    Namespace::Doc,
    Namespace::Session,
    Namespace::Net,
    Namespace::Policy,
    Namespace::Consent,
    Namespace::Pref,
    Namespace::Cap,
    Namespace::Store,
];

impl Namespace {
    /// The namespace's on-disk prefix, including the trailing slash.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Namespace::Identity => "identity/",
            Namespace::Peer => "peer/",
            Namespace::Trust => "trust/",
            Namespace::Doc => "doc/",
            Namespace::Session => "session/",
            Namespace::Net => "net/",
            Namespace::Policy => "policy/",
            Namespace::Consent => "consent/",
            Namespace::Pref => "pref/",
            Namespace::Cap => "cap/",
            Namespace::Store => "store/",
        }
    }

    /// The namespace's declared record schema version (ST-14).
    ///
    /// Per-namespace rather than whole-store, so one namespace's record shape
    /// can advance without rewriting every other namespace's records.
    #[must_use]
    pub const fn rec_schema(self) -> u64 {
        // Every namespace starts at 1. A namespace whose record shape changes
        // advances only its own number, and ST-15 rule 4 preserves unknown
        // record fields across a migration.
        1
    }

    /// Whether the recovery ladder may drop this namespace at rung L2.
    #[must_use]
    pub const fn recoverability(self) -> Recoverability {
        match self {
            // §11.11 L2: "`peer/` and `trust/` MUST NOT be dropped at this
            // rung — they escalate to L3." The floors of ST-21 live in Tier 1,
            // but their vault-side mirror and the S-37 negotiation floor live
            // here, so dropping `identity/`, `cap/` or `store/` would silently
            // lower a floor too.
            Namespace::Peer
            | Namespace::Trust
            | Namespace::Identity
            | Namespace::Cap
            | Namespace::Store => Recoverability::FloorBearing,
            // ST-14b: a consent record has no non-local writer, so there is
            // nothing to re-pull it from — dropping it is data loss, not
            // recovery, and the safe state is *absence*, which denies. A
            // preference is merely cosmetic, but is equally irreplaceable from
            // any remote source.
            Namespace::Consent | Namespace::Pref => Recoverability::LocalAuthoritative,
            Namespace::Doc | Namespace::Session | Namespace::Net | Namespace::Policy => {
                Recoverability::Cache
            }
        }
    }

    /// The secrecy class of records in this namespace.
    #[must_use]
    pub const fn secrecy(self) -> Secrecy {
        match self {
            // `PairSecret` and `EpochSeed` (N-19, S-33) live in `peer/` and
            // `trust/`; the sealed `TK` lives in `identity/`.
            //
            // That last clause was one of two production comments placing the
            // same key in two different tiers — ownership.md §11.2 G-17, whose
            // other half was `twinvpn-platform/src/custody.rs` saying TK
            // "reaches the core as a sealed blob through `SecureStore`", i.e.
            // Tier 1. §11.4 D-6 ruled for THIS one, on ADR-0020 ST-1: rule 1
            // admits to Tier 1 only a value never readable by the process, and
            // ADR-0007 N-5 requires TK to be unsealed *into* locked core
            // memory. The record key is `twinvpn_crypto::tk::TK_RECORD_KEY`;
            // its Tier-1 WRAPPING key is `tk::TK_WRAP_ITEM`, which is the item
            // ST-1 names in the words "the `TunnelStaticKey` wrapping key".
            Namespace::Identity | Namespace::Peer | Namespace::Trust => Secrecy::SecretBearing,
            Namespace::Doc | Namespace::Net | Namespace::Policy | Namespace::Consent => {
                Secrecy::Sensitive
            }
            // `session/`, `pref/`, `cap/` and `store/`.
            _ => Secrecy::Operational,
        }
    }

    /// Parses a namespace prefix from a `namespace/key` string.
    ///
    /// # Errors
    ///
    /// [`StoreError::UndeclaredNamespace`] for anything outside ST-14's eleven.
    pub fn parse(prefix: &str) -> Result<Self> {
        ALL.iter()
            .copied()
            .find(|n| n.as_str() == prefix)
            .ok_or(StoreError::UndeclaredNamespace)
    }
}

/// The cap on a record key's length, excluding the namespace prefix.
///
/// A key names a `device_id` hex, a document type, or a preference name. 128
/// bytes is generous for all three and bounds what an untrusted caller can make
/// the store index.
pub const MAX_KEY_BYTES: usize = 128;

/// The cap on one record's plaintext.
///
/// A `PolicyBundle` is the largest record, and
/// [`twinvpn_crypto::cose::MAX_STATEMENT_BYTES`] caps it at 64 KiB. 256 KiB
/// leaves room for a record that wraps one with metadata.
pub const MAX_VALUE_BYTES: usize = 256 * 1024;

/// A validated `namespace/key`.
///
/// The only way to name a record. It cannot be built from a bare string without
/// passing ST-14's table, and it has no wildcard form — which is ST-14a's "no
/// key pattern that spans both" expressed as a type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey {
    namespace: Namespace,
    key: String,
}

impl RecordKey {
    /// Names a record.
    ///
    /// # Errors
    ///
    /// [`StoreError::UndeclaredNamespace`] if `key` is empty, over
    /// [`MAX_KEY_BYTES`], or contains a `/` — a key with an embedded separator
    /// could be read as naming a different namespace by any component that
    /// parses the flat form, which is the ambiguity ST-14's table exists to
    /// remove.
    pub fn new(namespace: Namespace, key: &str) -> Result<Self> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES || key.contains('/') {
            return Err(StoreError::UndeclaredNamespace);
        }
        // A control character in a key would reach a diagnostic and a filename;
        // `common.proto`'s rule is reject, never normalize.
        if key.chars().any(char::is_control) {
            return Err(StoreError::UndeclaredNamespace);
        }
        Ok(Self {
            namespace,
            key: key.to_owned(),
        })
    }

    /// Parses the flat `namespace/key` form, as stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::UndeclaredNamespace`].
    pub fn parse(flat: &str) -> Result<Self> {
        let idx = flat.find('/').ok_or(StoreError::UndeclaredNamespace)?;
        let namespace = Namespace::parse(&flat[..=idx])?;
        Self::new(namespace, &flat[idx + 1..])
    }

    /// The namespace.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// The key within the namespace.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The flat `namespace/key` form.
    #[must_use]
    pub fn flat(&self) -> String {
        format!("{}{}", self.namespace.as_str(), self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_st_14s_eleven_namespaces_in_order() {
        let names: Vec<&str> = ALL.iter().map(|n| n.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "identity/",
                "peer/",
                "trust/",
                "doc/",
                "session/",
                "net/",
                "policy/",
                "consent/",
                "pref/",
                "cap/",
                "store/",
            ]
        );
    }

    #[test]
    fn a_key_outside_the_declared_namespaces_is_refused() {
        assert!(matches!(
            Namespace::parse("secrets/"),
            Err(StoreError::UndeclaredNamespace)
        ));
        assert!(RecordKey::parse("secrets/x").is_err());
        assert!(RecordKey::parse("no-separator").is_err());
    }

    /// **The ST-14a property.** A cosmetic reset addresses `pref/`. There is no
    /// value of `Namespace` that names both `pref/` and `consent/`, and no
    /// wildcard form, so a "reset UI settings" action cannot reach an
    /// authorization decision.
    #[test]
    fn no_namespace_value_spans_consent_and_pref() {
        for n in ALL {
            let s = n.as_str();
            let spans_both = s.contains("consent") && s.contains("pref");
            assert!(!spans_both);
        }
        assert_ne!(Namespace::Consent, Namespace::Pref);
        // And a record key cannot straddle them either.
        let k = RecordKey::new(Namespace::Pref, "theme").expect("key");
        assert_eq!(k.namespace(), Namespace::Pref);
        assert!(RecordKey::new(Namespace::Pref, "../consent/route").is_err());
    }

    /// §11.11 L2 explicitly forbids dropping `peer/` and `trust/`.
    #[test]
    fn peer_and_trust_are_floor_bearing_and_cannot_be_dropped_at_l2() {
        assert_eq!(
            Namespace::Peer.recoverability(),
            Recoverability::FloorBearing
        );
        assert_eq!(
            Namespace::Trust.recoverability(),
            Recoverability::FloorBearing
        );
        assert_eq!(Namespace::Doc.recoverability(), Recoverability::Cache);
    }

    /// N-19: `PairSecret` "MUST NOT be transmitted, backed up, or replicated",
    /// and it lives in `peer/`. The table must say so, because the ladder and
    /// the diagnostics both branch on it.
    #[test]
    fn the_secret_bearing_namespaces_are_declared() {
        assert_eq!(Namespace::Peer.secrecy(), Secrecy::SecretBearing);
        assert_eq!(Namespace::Trust.secrecy(), Secrecy::SecretBearing);
        assert_eq!(Namespace::Identity.secrecy(), Secrecy::SecretBearing);
        assert_eq!(Namespace::Pref.secrecy(), Secrecy::Operational);
    }

    #[test]
    fn a_key_with_a_separator_or_a_control_character_is_refused() {
        assert!(RecordKey::new(Namespace::Peer, "a/b").is_err());
        assert!(RecordKey::new(Namespace::Peer, "a\u{0}b").is_err());
        assert!(RecordKey::new(Namespace::Peer, "").is_err());
        assert!(RecordKey::new(Namespace::Peer, &"x".repeat(MAX_KEY_BYTES + 1)).is_err());
        assert!(RecordKey::new(Namespace::Peer, &"x".repeat(MAX_KEY_BYTES)).is_ok());
    }

    #[test]
    fn the_flat_form_round_trips() {
        let k = RecordKey::new(Namespace::Trust, "epoch").expect("key");
        assert_eq!(k.flat(), "trust/epoch");
        assert_eq!(RecordKey::parse("trust/epoch").expect("parse"), k);
    }
}
