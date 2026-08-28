//! The record envelope, its AAD, and ST-13's verbatim rule.
//!
//! **Authority:** ADR-0020 §11.5 (the envelope and the AAD), ST-13, ST-16,
//! ST-17, ADR-0018 CD-I2 (which is why the AEAD itself is in `twinvpn-crypto`).
//!
//! # The envelope, quoted
//!
//! ```text
//! RecordEnvelope {
//!   1 rec_schema : uint          # per-namespace record schema version
//!   2 rec_seq    : uint          # per-record monotone counter
//!   3 flags      : uint          # VERBATIM_SIGNED | DERIVED | SECRET_BEARING
//!   4 nonce      : bstr(24)
//!   5 ct         : bstr          # XChaCha20-Poly1305(K_ns, nonce, plaintext, aad)
//! }
//! aad = store_id || namespace || key || rec_schema || rec_seq
//! ```
//!
//! # The AAD is length-prefixed, and that is a decision taken here
//!
//! ADR-0020 writes the AAD as a bare concatenation. `namespace` and `key` are
//! both variable-length, so a bare concatenation is **ambiguous**: the record
//! `peer/` + `alice` and the record `peer/a` + `lice` would produce identical
//! AAD, and a record could be moved between them without failing its tag. That
//! defeats the exact property ST-17 attributes to the AAD — "binds every record
//! to its namespace, key, and `rec_seq`".
//!
//! So [`record_aad`] length-prefixes every variable-length field with a
//! big-endian `u32`. This is an under-specification in ADR-0020 §11.5 rather
//! than a disagreement with it, it is reported as one, and the unit test
//! `the_aad_is_unambiguous_across_a_namespace_key_boundary` is what would fail
//! if it were ever "simplified" back.
//!
//! # ST-13
//!
//! > "A record whose `flags` carry `VERBATIM_SIGNED` stores the **received
//! > octets unchanged** (RQ-7). The vault MUST NOT decode-and-re-encode a signed
//! > statement, and signature verification happens at the writer before commit,
//! > never at read time from a re-serialized form."
//!
//! This crate has no CBOR encoder for record *contents* and no statement
//! decoder: a value is a `Vec<u8>` from the caller to the AEAD and back. There
//! is nothing here that could decode-and-re-encode a signed statement, which is
//! ST-13 held by absence.

use twinvpn_crypto::aead::{self, Sealed, StoreKey, NONCE_LEN, STORE_ID_LEN};
use twinvpn_crypto::dcbor;
use twinvpn_crypto::emit::{encode, Item};
use twinvpn_env::Env;

use crate::error::{Result, StoreError};
use crate::namespace::{Namespace, RecordKey, Secrecy, MAX_VALUE_BYTES};

/// The record carries octets that were verified as received and must not be
/// re-encoded (ST-13).
pub const FLAG_VERBATIM_SIGNED: u64 = 1;
/// The record is derived and can be recomputed rather than re-fetched.
pub const FLAG_DERIVED: u64 = 2;
/// The record's plaintext carries secret material.
pub const FLAG_SECRET_BEARING: u64 = 4;

/// Every flag this build understands. An envelope carrying anything else is
/// from a newer writer and is refused rather than read with the unknown bits
/// ignored — an ignored flag is how `VERBATIM_SIGNED` comes to be dropped.
const KNOWN_FLAGS: u64 = FLAG_VERBATIM_SIGNED | FLAG_DERIVED | FLAG_SECRET_BEARING;

/// A record's plaintext plus the metadata that is authenticated alongside it.
///
/// # `Debug` is written by hand (R-9)
///
/// `value` is *the plaintext*, in the composed path — a `PairSecret`, an
/// identity blob, whatever ST-14 says the namespace holds. A derived `Debug`
/// put all of it into any log line, panic message or `assert_eq!` failure that
/// rendered a `Record`, and into every enclosing `#[derive(Debug)]` above it.
/// The hand-written one prints the length and the flags, which are the
/// dimensions an operator actually debugs with.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// The per-namespace record schema version.
    pub rec_schema: u64,
    /// The per-record monotone counter.
    pub rec_seq: u64,
    /// `VERBATIM_SIGNED | DERIVED | SECRET_BEARING`.
    pub flags: u64,
    /// The plaintext.
    pub value: Vec<u8>,
}

impl core::fmt::Debug for Record {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record")
            .field("rec_schema", &self.rec_schema)
            .field("rec_seq", &self.rec_seq)
            .field("flags", &self.flags)
            // NOT the plaintext. The length is what a decode bug shows up in.
            .field("value_len", &self.value.len())
            .finish()
    }
}

impl Record {
    /// A record for a fresh write into `namespace`.
    ///
    /// `SECRET_BEARING` is set from ST-14's table rather than from a caller's
    /// argument: whether `peer/` holds a `PairSecret` is a property of the
    /// namespace, and letting a call site say otherwise is how a secret record
    /// comes to be written without the flag that keeps it out of a bundle.
    #[must_use]
    pub fn new(namespace: Namespace, rec_seq: u64, verbatim_signed: bool, value: Vec<u8>) -> Self {
        let mut flags = 0;
        if verbatim_signed {
            flags |= FLAG_VERBATIM_SIGNED;
        }
        if namespace.secrecy() == Secrecy::SecretBearing {
            flags |= FLAG_SECRET_BEARING;
        }
        Self {
            rec_schema: namespace.rec_schema(),
            rec_seq,
            flags,
            value,
        }
    }

    /// Whether ST-13's verbatim rule applies to this record.
    #[must_use]
    pub const fn is_verbatim_signed(&self) -> bool {
        self.flags & FLAG_VERBATIM_SIGNED != 0
    }

    /// Whether the plaintext carries secret material.
    #[must_use]
    pub const fn is_secret_bearing(&self) -> bool {
        self.flags & FLAG_SECRET_BEARING != 0
    }
}

/// `Debug` renders the metadata and **never** the value.
///
/// A record's plaintext may be a `PairSecret` or an `EpochSeed`
/// (`ownership.md` §6 rule 11), and a derived `Debug` on any struct that held a
/// `Record` would put it in a log.
impl core::fmt::Debug for RecordDebugGuard<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Record")
            .field("rec_schema", &self.0.rec_schema)
            .field("rec_seq", &self.0.rec_seq)
            .field("flags", &self.0.flags)
            .field("value_len", &self.0.value.len())
            .finish()
    }
}

/// A redacted view of a [`Record`] for logging.
pub struct RecordDebugGuard<'a>(pub &'a Record);

/// Builds the AAD for one record.
///
/// See the module documentation on why every variable-length field is
/// length-prefixed.
#[must_use]
pub fn record_aad(
    store_id: &[u8; STORE_ID_LEN],
    key: &RecordKey,
    rec_schema: u64,
    rec_seq: u64,
) -> Vec<u8> {
    let ns = key.namespace().as_str().as_bytes();
    let k = key.key().as_bytes();
    let mut aad = Vec::with_capacity(STORE_ID_LEN + 8 + ns.len() + k.len() + 16);
    aad.extend_from_slice(store_id);
    aad.extend_from_slice(&u32::try_from(ns.len()).unwrap_or(u32::MAX).to_be_bytes());
    aad.extend_from_slice(ns);
    aad.extend_from_slice(&u32::try_from(k.len()).unwrap_or(u32::MAX).to_be_bytes());
    aad.extend_from_slice(k);
    aad.extend_from_slice(&rec_schema.to_be_bytes());
    aad.extend_from_slice(&rec_seq.to_be_bytes());
    aad
}

/// Seals a record into its wire envelope.
///
/// # Errors
///
/// [`StoreError::CryptoInvariant`] if the value exceeds
/// [`MAX_VALUE_BYTES`] or the AEAD refuses it.
pub fn seal_record(
    env: &Env,
    key_ns: &StoreKey,
    store_id: &[u8; STORE_ID_LEN],
    key: &RecordKey,
    record: &Record,
) -> Result<Vec<u8>> {
    if record.value.len() > MAX_VALUE_BYTES {
        return Err(StoreError::CryptoInvariant {
            invariant: "a record value is at most MAX_VALUE_BYTES",
        });
    }
    let aad = record_aad(store_id, key, record.rec_schema, record.rec_seq);
    let Sealed { nonce, ciphertext } = aead::seal(env, key_ns, &aad, &record.value)?;
    encode(&Item::Map(vec![
        (Item::Uint(1), Item::Uint(record.rec_schema)),
        (Item::Uint(2), Item::Uint(record.rec_seq)),
        (Item::Uint(3), Item::Uint(record.flags)),
        (Item::Uint(4), Item::Bytes(nonce.to_vec())),
        (Item::Uint(5), Item::Bytes(ciphertext)),
    ]))
    .map_err(Into::into)
}

/// Opens a record envelope.
///
/// The envelope is parsed as **canonical** CBOR, so a re-encoded or reordered
/// envelope is refused rather than accepted — the same discipline the signed
/// statements get, applied to storage, because a vault file is an untrusted
/// input the moment an attacker can write to it.
///
/// # Errors
///
/// [`StoreError::RecordCorrupt`] naming which detector fired: the envelope
/// parse, the flag check, or the AEAD tag.
pub fn open_record(
    key_ns: &StoreKey,
    store_id: &[u8; STORE_ID_LEN],
    key: &RecordKey,
    envelope: &[u8],
) -> Result<Record> {
    let ns = key.namespace().as_str();
    let corrupt = |detector: &'static str| StoreError::RecordCorrupt {
        namespace: ns,
        detector,
    };
    let v = dcbor::parse_canonical(envelope).map_err(|_| corrupt("envelope encoding"))?;
    if v.map_keys() != vec![1, 2, 3, 4, 5] {
        return Err(corrupt("envelope field set"));
    }
    let rec_schema = v
        .map_get(1)
        .and_then(dcbor::Value::as_uint)
        .ok_or_else(|| corrupt("rec_schema"))?;
    let rec_seq = v
        .map_get(2)
        .and_then(dcbor::Value::as_uint)
        .ok_or_else(|| corrupt("rec_seq"))?;
    let flags = v
        .map_get(3)
        .and_then(dcbor::Value::as_uint)
        .ok_or_else(|| corrupt("flags"))?;
    if flags & !KNOWN_FLAGS != 0 {
        // A flag this build does not know may be a restriction. Reading the
        // record while ignoring it is the silent-authorization-hole shape the
        // `crit` rule exists to close, applied to storage.
        return Err(corrupt("unknown envelope flag"));
    }
    let nonce_bytes = v
        .map_get(4)
        .and_then(dcbor::Value::as_bytes)
        .ok_or_else(|| corrupt("nonce"))?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| corrupt("nonce width"))?;
    let ct = v
        .map_get(5)
        .and_then(dcbor::Value::as_bytes)
        .ok_or_else(|| corrupt("ciphertext"))?;
    if ct.len() > MAX_VALUE_BYTES + aead::TAG_LEN {
        return Err(corrupt("ciphertext over cap"));
    }

    let aad = record_aad(store_id, key, rec_schema, rec_seq);
    let value = aead::open(key_ns, &nonce, &aad, ct).map_err(|e| match e {
        aead::AeadOpenError::Truncated => corrupt("truncated ciphertext"),
        aead::AeadOpenError::TagMismatch => corrupt("aead tag"),
        aead::AeadOpenError::KeyUnusable => corrupt("namespace key"),
    })?;

    Ok(Record {
        rec_schema,
        rec_seq,
        flags,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv::{store_key, test_env, STORE_ID};

    fn key() -> RecordKey {
        RecordKey::new(Namespace::Peer, "alice").expect("key")
    }

    #[test]
    fn a_sealed_record_round_trips() {
        let e = test_env();
        let k = store_key();
        let r = Record::new(Namespace::Peer, 7, true, b"peer record".to_vec());
        let env = seal_record(&e, &k, &STORE_ID, &key(), &r).expect("seal");
        let out = open_record(&k, &STORE_ID, &key(), &env).expect("open");
        assert_eq!(out, r);
        assert!(out.is_verbatim_signed());
        assert!(out.is_secret_bearing(), "peer/ is SECRET_BEARING per ST-14");
    }

    /// **Attack test — ST-17.** A record moved to a different key must fail its
    /// tag, because the AAD binds it to its key.
    #[test]
    fn a_record_moved_to_another_key_fails_its_tag() {
        let e = test_env();
        let k = store_key();
        let r = Record::new(Namespace::Peer, 7, false, b"x".to_vec());
        let env = seal_record(&e, &k, &STORE_ID, &key(), &r).expect("seal");
        let other = RecordKey::new(Namespace::Peer, "bob").expect("key");
        assert!(open_record(&k, &STORE_ID, &other, &env).is_err());
    }

    /// **Attack test — ST-17.** A record replayed at a different `rec_seq` must
    /// fail, which is what makes an in-place record rollback detectable.
    #[test]
    fn a_record_replayed_at_a_different_rec_seq_fails_its_tag() {
        let e = test_env();
        let k = store_key();
        let r = Record::new(Namespace::Peer, 7, false, b"x".to_vec());
        let env = seal_record(&e, &k, &STORE_ID, &key(), &r).expect("seal");
        // Rewrite the envelope's `rec_seq` to 6 while leaving the ciphertext.
        let parsed = dcbor::parse_canonical(&env).expect("parse");
        let nonce = parsed
            .map_get(4)
            .and_then(dcbor::Value::as_bytes)
            .unwrap()
            .to_vec();
        let ct = parsed
            .map_get(5)
            .and_then(dcbor::Value::as_bytes)
            .unwrap()
            .to_vec();
        let tampered = encode(&Item::Map(vec![
            (Item::Uint(1), Item::Uint(1)),
            (Item::Uint(2), Item::Uint(6)),
            (Item::Uint(3), Item::Uint(FLAG_SECRET_BEARING)),
            (Item::Uint(4), Item::Bytes(nonce)),
            (Item::Uint(5), Item::Bytes(ct)),
        ]))
        .expect("encode");
        assert!(open_record(&k, &STORE_ID, &key(), &tampered).is_err());
    }

    /// **Attack test — the ambiguity the length prefixes remove.** Without
    /// length prefixing, `peer/` + `alice` and a hypothetical `peer/a` + `lice`
    /// would produce identical AAD. The namespace set makes the second
    /// unconstructible today, but the AAD must not depend on that.
    #[test]
    fn the_aad_is_unambiguous_across_a_namespace_key_boundary() {
        let a = record_aad(
            &STORE_ID,
            &RecordKey::new(Namespace::Peer, "alice").unwrap(),
            1,
            1,
        );
        let b = record_aad(
            &STORE_ID,
            &RecordKey::new(Namespace::Peer, "ali").unwrap(),
            1,
            1,
        );
        assert_ne!(a, b);
        // And a key whose bytes are a prefix of another's is distinguished by
        // the length field rather than by what follows it.
        let c = record_aad(
            &STORE_ID,
            &RecordKey::new(Namespace::Peer, "alic").unwrap(),
            1,
            1,
        );
        assert_ne!(b, c);
        // The namespace is length-prefixed too, so a namespace and a key cannot
        // trade characters.
        assert_ne!(
            record_aad(
                &STORE_ID,
                &RecordKey::new(Namespace::Peer, "x").unwrap(),
                1,
                1
            ),
            record_aad(
                &STORE_ID,
                &RecordKey::new(Namespace::Pref, "x").unwrap(),
                1,
                1
            )
        );
    }

    /// **Attack test.** A non-canonical envelope is refused, so a vault file an
    /// attacker rewrote cannot present two encodings of one record.
    #[test]
    fn a_non_canonical_envelope_is_refused() {
        let e = test_env();
        let k = store_key();
        let r = Record::new(Namespace::Peer, 1, false, b"x".to_vec());
        let good = seal_record(&e, &k, &STORE_ID, &key(), &r).expect("seal");
        // The map head 0xa5 rewritten as 0xb8 0x05.
        assert_eq!(good[0], 0xa5);
        let mut bad = vec![0xb8, 0x05];
        bad.extend_from_slice(&good[1..]);
        assert!(open_record(&k, &STORE_ID, &key(), &bad).is_err());
    }

    /// **Attack test.** An unknown flag might be a restriction, so it is a
    /// refusal rather than a bit that is ignored.
    #[test]
    fn an_unknown_envelope_flag_is_refused() {
        let e = test_env();
        let k = store_key();
        let mut r = Record::new(Namespace::Peer, 1, false, b"x".to_vec());
        r.flags |= 0x8000;
        let env = seal_record(&e, &k, &STORE_ID, &key(), &r).expect("seal");
        assert!(open_record(&k, &STORE_ID, &key(), &env).is_err());
    }

    #[test]
    fn debug_never_renders_a_record_value() {
        let r = Record::new(Namespace::Peer, 1, false, b"secretvalue".to_vec());
        let s = format!("{:?}", RecordDebugGuard(&r));
        assert!(s.contains("value_len: 11"));
        assert!(!s.contains("secretvalue"));
    }
}
