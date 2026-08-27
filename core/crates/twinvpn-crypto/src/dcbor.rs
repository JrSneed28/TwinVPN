//! Deterministic CBOR (RFC 8949 §4.2.1), parsed strictly and **never
//! normalized**.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/signed_statements.cddl` encoding
//! rules 1 and 3, ADR-0003 §11, `docs/implementation/ownership.md` §6 rules 9
//! and 10.
//!
//! # The rule this module exists to make structural
//!
//! > "Encoded as RFC 8949 §4.2.1 CORE DETERMINISTIC ENCODING. Two conforming
//! > implementations MUST produce byte-identical output for the same logical
//! > value. **Non-canonical input MUST BE REJECTED with
//! > `PROTO.NON_CANONICAL_CBOR`, NEVER NORMALIZED** — normalizing attacker input
//! > before verifying is a signature-bypass pattern."
//!
//! There are two ways to check canonicity. The common one is *decode, re-encode,
//! compare* — which requires an encoder, and an encoder next to a verifier is
//! the exact adjacency the rule warns about. This module takes the other one:
//! **[`parse_canonical`] validates the encoding while it reads it**, directly on
//! the received octets, and there is no encoder in this module at all. A
//! non-canonical input never produces a value, so there is nothing to
//! accidentally verify against.
//!
//! # What "canonical" means here, exactly
//!
//! Every rule below is checked, and each has a negative test:
//!
//! | Rule | RFC 8949 | Rejected as |
//! |---|---|---|
//! | Arguments use the shortest form | §4.2.1 (a) | [`DcborError::NonShortestArgument`] |
//! | No indefinite-length items | §4.2.1 (b) | [`DcborError::IndefiniteLength`] |
//! | Map keys sorted bytewise by their encodings | §4.2.1 (c) | [`DcborError::MapKeysUnsorted`] |
//! | No duplicate map keys | §5.6 | [`DcborError::MapKeysUnsorted`] — a duplicate is not *strictly* increasing |
//! | No floats anywhere | the CDDL: "No float appears anywhere in this schema" | [`DcborError::FloatRejected`] |
//! | Text is valid UTF-8 | §3.1 major type 3 | [`DcborError::InvalidUtf8`] |
//! | Nothing after the top-level item | — | [`DcborError::TrailingBytes`] |
//!
//! # Bounded before allocated
//!
//! Rule 10 of `ownership.md` §6: "Bound every allocation an untrusted input can
//! drive." A CBOR head declaring a 4 GiB byte string is four bytes of input, so
//! [`parse_canonical`] checks every declared length against the **remaining
//! input** before reserving anything, and caps nesting depth and total item
//! count. A hostile 20-byte input cannot make this module allocate.

use crate::error::StatementKind;
use crate::CryptoError;

/// The nesting-depth cap.
///
/// ADR-0003 §11's envelope depth caps govern protobuf; a signed statement is
/// carried *inside* one as opaque bytes, so it needs its own. The deepest
/// statement in the CDDL is `relay-map` → `[relay-entry]` → `[[bstr, uint]]`,
/// which is four levels. Sixteen is generous enough that a legitimate future
/// statement will not hit it and small enough that recursion cannot exhaust a
/// router-class stack.
pub const MAX_DEPTH: usize = 16;

/// The cap on total decoded items, across the whole statement.
///
/// A bound on work, not on shape: a map of a thousand entries is a thousand
/// items even though it is one level deep. `relay-map` is the largest real
/// statement and a fleet of 256 relays with 8 endpoints each is under 8 000
/// items, so 65 536 leaves a wide margin while still refusing a decompression
/// bomb.
pub const MAX_ITEMS: usize = 65_536;

/// Why a byte string was refused as deterministic CBOR.
///
/// Every variant names a *structural* fact about the octets. None of them
/// carries content, so a `Debug` of this type is safe in a log even when the
/// input was a statement carrying sensitive fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DcborError {
    /// The input ended in the middle of an item.
    Truncated,
    /// An argument was encoded in more bytes than necessary (§4.2.1 (a)).
    NonShortestArgument,
    /// An indefinite-length string, array or map (§4.2.1 (b)).
    IndefiniteLength,
    /// Map keys were not in strictly increasing bytewise order (§4.2.1 (c)),
    /// which also catches a duplicate key.
    MapKeysUnsorted,
    /// A float appeared. The CDDL: "No float appears anywhere in this schema."
    FloatRejected,
    /// A simple value other than `false`, `true` or `null`.
    ///
    /// `undefined` is excluded deliberately: it is a second spelling of "no
    /// value" alongside `null`, and two spellings of one thing is how a verifier
    /// and a producer come to disagree about what was signed.
    SimpleValueRejected,
    /// A CBOR tag appeared where the schema permits none.
    TagRejected,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// Nesting deeper than [`MAX_DEPTH`].
    DepthExceeded,
    /// More than [`MAX_ITEMS`] items.
    ItemsExceeded,
    /// A declared length exceeded the bytes actually remaining.
    ///
    /// The check that stops a four-byte head from driving a gigabyte
    /// allocation.
    LengthExceedsInput,
    /// Bytes remained after the top-level item.
    TrailingBytes,
}

impl DcborError {
    /// A stable, bounded name for the failing check, for
    /// [`CryptoError::NonCanonicalCbor`]'s `step`.
    #[must_use]
    pub const fn step(self) -> &'static str {
        match self {
            DcborError::Truncated => "truncated",
            DcborError::NonShortestArgument => "non-shortest argument",
            DcborError::IndefiniteLength => "indefinite length",
            DcborError::MapKeysUnsorted => "map keys unsorted or duplicated",
            DcborError::FloatRejected => "float",
            DcborError::SimpleValueRejected => "simple value",
            DcborError::TagRejected => "tag",
            DcborError::InvalidUtf8 => "invalid utf-8",
            DcborError::DepthExceeded => "depth exceeded",
            DcborError::ItemsExceeded => "item count exceeded",
            DcborError::LengthExceedsInput => "declared length exceeds input",
            DcborError::TrailingBytes => "trailing bytes",
        }
    }

    /// Lifts this into the crate error, naming which statement was being read.
    #[must_use]
    pub const fn into_crypto_error(self, kind: StatementKind) -> CryptoError {
        CryptoError::NonCanonicalCbor {
            kind,
            step: self.step(),
        }
    }
}

/// A deterministic CBOR value.
///
/// Only the shapes `contracts/cddl/twinvpn/v1/` uses. There is no float variant
/// and no `undefined`, so a value that cannot appear in a TwinVPN statement
/// cannot be represented — which is a stronger statement than rejecting it at
/// parse time, because it also means no code path can *construct* one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1. Held as the encoded `n` where the value is `-1 - n`, so the
    /// full 64-bit negative range is representable without an `i128`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5. Held as a `Vec` of pairs **in the canonical order they
    /// arrived**, which [`parse_canonical`] has already proved is sorted. A
    /// `BTreeMap` would re-impose an order and hide a violation.
    Map(Vec<(Value, Value)>),
    /// `false` / `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Value {
    /// The value as a `u64`, if it is one.
    #[must_use]
    pub const fn as_uint(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// The value as bytes, if it is a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The value as text, if it is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    /// The value as an array, if it is one.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The value as a bool, if it is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Whether the value is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Looks up an integer-keyed map entry.
    ///
    /// Every statement in the CDDL is an integer-keyed map, so this is the one
    /// accessor the statement decoders need.
    #[must_use]
    pub fn map_get(&self, key: u64) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Value::Uint(v) if *v == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    /// The integer keys present, in canonical order.
    ///
    /// Used to enforce "no unknown non-`crit` fields" (CDDL encoding rule 5): a
    /// verifier compares the key set against the schema rather than ignoring
    /// what it does not recognise.
    #[must_use]
    pub fn map_keys(&self) -> Vec<u64> {
        match self {
            Value::Map(entries) => entries.iter().filter_map(|(k, _)| k.as_uint()).collect(),
            _ => Vec::new(),
        }
    }
}

/// Parses `input` as deterministic CBOR, rejecting anything non-canonical.
///
/// The whole input must be exactly one item; trailing bytes are a rejection, not
/// an ignored remainder.
///
/// # Errors
///
/// A [`DcborError`] naming the first rule violated. The parse stops there: a
/// non-canonical input never produces a partial value, so there is nothing a
/// caller could be tempted to use.
pub fn parse_canonical(input: &[u8]) -> Result<Value, DcborError> {
    let mut p = Parser {
        input,
        pos: 0,
        items: 0,
    };
    let v = p.value(0)?;
    if p.pos != input.len() {
        return Err(DcborError::TrailingBytes);
    }
    Ok(v)
}

/// Asserts that `input` is deterministic CBOR, discarding the value.
///
/// For a caller that must bind opaque encoded bytes into a hash — ADR-0001
/// §7.3.1's `det_CBOR(Selection)`, for instance — and needs the encoding checked
/// without caring about its contents.
///
/// # Errors
///
/// As [`parse_canonical`].
pub fn require_canonical(input: &[u8]) -> Result<(), DcborError> {
    parse_canonical(input).map(|_| ())
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    items: usize,
}

impl Parser<'_> {
    fn byte(&mut self) -> Result<u8, DcborError> {
        let b = *self.input.get(self.pos).ok_or(DcborError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], DcborError> {
        // The bound check that makes rule 10 hold: a declared length is compared
        // against what is actually left before anything is reserved.
        if n > self.input.len() - self.pos {
            return Err(DcborError::LengthExceedsInput);
        }
        let s = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Reads a head and returns `(major, argument)`, enforcing shortest form.
    fn head(&mut self) -> Result<(u8, u64), DcborError> {
        let b = self.byte()?;
        let major = b >> 5;
        let ai = b & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                // §4.2.1 (a): 0..23 must have used the immediate form.
                if v < 24 {
                    return Err(DcborError::NonShortestArgument);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if u8::try_from(v).is_ok() {
                    return Err(DcborError::NonShortestArgument);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if u16::try_from(v).is_ok() {
                    return Err(DcborError::NonShortestArgument);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                if u32::try_from(v).is_ok() {
                    return Err(DcborError::NonShortestArgument);
                }
                v
            }
            // 28..30 are reserved; 31 is indefinite length. Both are refused,
            // and 31 gets its own error because it is the one an encoder
            // produces by accident.
            31 => return Err(DcborError::IndefiniteLength),
            _ => return Err(DcborError::NonShortestArgument),
        };
        Ok((major, arg))
    }

    fn value(&mut self, depth: usize) -> Result<Value, DcborError> {
        if depth > MAX_DEPTH {
            return Err(DcborError::DepthExceeded);
        }
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(DcborError::ItemsExceeded);
        }

        // Major type 7 carries simple values and floats and has no argument in
        // the ordinary sense, so it is peeked before `head` applies the
        // shortest-form rule to a value that is not a length.
        if let Some(b) = self.input.get(self.pos) {
            if b >> 5 == 7 {
                self.pos += 1;
                return match b & 0x1f {
                    20 => Ok(Value::Bool(false)),
                    21 => Ok(Value::Bool(true)),
                    22 => Ok(Value::Null),
                    // 25/26/27 are half/single/double floats.
                    25..=27 => Err(DcborError::FloatRejected),
                    31 => Err(DcborError::IndefiniteLength),
                    _ => Err(DcborError::SimpleValueRejected),
                };
            }
        }

        let (major, arg) = self.head()?;
        match major {
            0 => Ok(Value::Uint(arg)),
            1 => Ok(Value::Nint(arg)),
            2 => {
                let n = usize::try_from(arg).map_err(|_| DcborError::LengthExceedsInput)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = usize::try_from(arg).map_err(|_| DcborError::LengthExceedsInput)?;
                let s = self.take(n)?;
                let s = core::str::from_utf8(s).map_err(|_| DcborError::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                let n = usize::try_from(arg).map_err(|_| DcborError::LengthExceedsInput)?;
                // An element is at least one byte, so a declared count above the
                // remaining input is refused before the `Vec` is reserved.
                if n > self.input.len() - self.pos {
                    return Err(DcborError::LengthExceedsInput);
                }
                let mut out = Vec::with_capacity(n);
                for _ in 0..n {
                    out.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            5 => {
                let n = usize::try_from(arg).map_err(|_| DcborError::LengthExceedsInput)?;
                // Each pair is at least two bytes.
                if n.saturating_mul(2) > self.input.len() - self.pos {
                    return Err(DcborError::LengthExceedsInput);
                }
                let mut out = Vec::with_capacity(n);
                let mut prev_key: Option<&[u8]> = None;
                for _ in 0..n {
                    let key_start = self.pos;
                    let k = self.value(depth + 1)?;
                    let key_octets = &self.input[key_start..self.pos];
                    // §4.2.1 (c): keys sorted bytewise by their *encodings*, and
                    // strictly — which is also what rejects a duplicate.
                    if let Some(prev) = prev_key {
                        if prev >= key_octets {
                            return Err(DcborError::MapKeysUnsorted);
                        }
                    }
                    prev_key = Some(key_octets);
                    let v = self.value(depth + 1)?;
                    out.push((k, v));
                }
                Ok(Value::Map(out))
            }
            6 => Err(DcborError::TagRejected),
            // Major type 7 was handled above; `head` cannot return it here.
            _ => Err(DcborError::SimpleValueRejected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_integer_keyed_map_parses() {
        // {1: 2, 3: "x"}
        let input = [0xa2, 0x01, 0x02, 0x03, 0x61, 0x78];
        let v = parse_canonical(&input).expect("parse");
        assert_eq!(v.map_get(1).and_then(Value::as_uint), Some(2));
        assert_eq!(v.map_get(3).and_then(Value::as_text), Some("x"));
        assert_eq!(v.map_keys(), vec![1, 3]);
    }

    /// **Attack test.** The canonical-encoding rule exists because two encodings
    /// of one logical value let a producer and a verifier disagree about what
    /// was signed. A one-byte integer written in two bytes must be refused, not
    /// normalized.
    #[test]
    fn a_non_shortest_integer_is_refused_not_normalized() {
        // 1, encoded as 0x18 0x01 rather than 0x01.
        assert_eq!(
            parse_canonical(&[0x18, 0x01]),
            Err(DcborError::NonShortestArgument)
        );
        // 255, correctly in one extra byte, is fine.
        assert_eq!(parse_canonical(&[0x18, 0xff]), Ok(Value::Uint(255)));
        // 255 written as a uint16 is not.
        assert_eq!(
            parse_canonical(&[0x19, 0x00, 0xff]),
            Err(DcborError::NonShortestArgument)
        );
        // and a uint32 that fits a uint16.
        assert_eq!(
            parse_canonical(&[0x1a, 0x00, 0x00, 0xff, 0xff]),
            Err(DcborError::NonShortestArgument)
        );
        // and a uint64 that fits a uint32.
        assert_eq!(
            parse_canonical(&[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]),
            Err(DcborError::NonShortestArgument)
        );
    }

    /// **Attack test.** A non-shortest *length* is the same bug on a string, and
    /// it is the one an attacker reaches for because it changes the octets
    /// without changing the decoded value.
    #[test]
    fn a_non_shortest_string_length_is_refused() {
        // h'61' with a one-byte length that should have been immediate.
        assert_eq!(
            parse_canonical(&[0x58, 0x01, 0x61]),
            Err(DcborError::NonShortestArgument)
        );
    }

    /// **Attack test.** Indefinite-length encoding is a second spelling of every
    /// string, array and map.
    #[test]
    fn an_indefinite_length_item_is_refused() {
        // Indefinite-length array.
        assert_eq!(
            parse_canonical(&[0x9f, 0x01, 0xff]),
            Err(DcborError::IndefiniteLength)
        );
        // Indefinite-length byte string.
        assert_eq!(
            parse_canonical(&[0x5f, 0x41, 0x61, 0xff]),
            Err(DcborError::IndefiniteLength)
        );
        // Indefinite-length map.
        assert_eq!(
            parse_canonical(&[0xbf, 0x01, 0x02, 0xff]),
            Err(DcborError::IndefiniteLength)
        );
    }

    /// **Attack test.** Reordered map keys are the classic way to produce a
    /// second encoding of one map. The verifier must refuse, because normalizing
    /// the order would make two distinct octet strings verify against one
    /// signature.
    #[test]
    fn unsorted_map_keys_are_refused() {
        // {3: 0, 1: 0}
        assert_eq!(
            parse_canonical(&[0xa2, 0x03, 0x00, 0x01, 0x00]),
            Err(DcborError::MapKeysUnsorted)
        );
    }

    /// **Attack test.** A duplicate key lets a producer put two values under one
    /// name and a verifier pick either. RFC 8949 §5.6 and the strictly-increasing
    /// rule together refuse it.
    #[test]
    fn duplicate_map_keys_are_refused() {
        // {1: 0, 1: 1}
        assert_eq!(
            parse_canonical(&[0xa2, 0x01, 0x00, 0x01, 0x01]),
            Err(DcborError::MapKeysUnsorted)
        );
    }

    /// The CDDL: "No float appears anywhere in this schema."
    #[test]
    fn a_float_is_refused() {
        // half-precision 1.0
        assert_eq!(
            parse_canonical(&[0xf9, 0x3c, 0x00]),
            Err(DcborError::FloatRejected)
        );
        // single-precision
        assert_eq!(
            parse_canonical(&[0xfa, 0x3f, 0x80, 0x00, 0x00]),
            Err(DcborError::FloatRejected)
        );
        // double-precision
        assert_eq!(
            parse_canonical(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DcborError::FloatRejected)
        );
    }

    /// `undefined` is a second spelling of "no value". Only `null` is admitted.
    #[test]
    fn undefined_and_other_simple_values_are_refused() {
        assert_eq!(
            parse_canonical(&[0xf7]),
            Err(DcborError::SimpleValueRejected)
        );
        assert_eq!(
            parse_canonical(&[0xe0]),
            Err(DcborError::SimpleValueRejected)
        );
        assert_eq!(parse_canonical(&[0xf4]), Ok(Value::Bool(false)));
        assert_eq!(parse_canonical(&[0xf5]), Ok(Value::Bool(true)));
        assert_eq!(parse_canonical(&[0xf6]), Ok(Value::Null));
    }

    #[test]
    fn a_tag_is_refused_where_the_schema_permits_none() {
        // tag(18) wrapping 0
        assert_eq!(parse_canonical(&[0xd2, 0x00]), Err(DcborError::TagRejected));
    }

    /// **Attack test.** Trailing bytes after a complete item are how a signed
    /// prefix gets a smuggled suffix: the verifier sees a valid statement and
    /// the parser silently ignores the rest.
    #[test]
    fn trailing_bytes_after_the_top_level_item_are_refused() {
        assert_eq!(
            parse_canonical(&[0x01, 0x02]),
            Err(DcborError::TrailingBytes)
        );
    }

    /// **Attack test.** Rule 10: a four-byte head declaring four gigabytes must
    /// not cause a four-gigabyte reservation. The declared length is checked
    /// against the input that actually remains.
    #[test]
    fn a_declared_length_larger_than_the_input_allocates_nothing() {
        // bstr of 0xffff_ffff bytes, with three bytes of input.
        assert_eq!(
            parse_canonical(&[0x5a, 0xff, 0xff, 0xff, 0xff]),
            Err(DcborError::LengthExceedsInput)
        );
        // array of 0xffff_ffff elements.
        assert_eq!(
            parse_canonical(&[0x9a, 0xff, 0xff, 0xff, 0xff]),
            Err(DcborError::LengthExceedsInput)
        );
        // map of 0xffff_ffff pairs.
        assert_eq!(
            parse_canonical(&[0xba, 0xff, 0xff, 0xff, 0xff]),
            Err(DcborError::LengthExceedsInput)
        );
    }

    #[test]
    fn nesting_beyond_the_cap_is_refused_before_the_stack_is() {
        // array(1), MAX_DEPTH + 4 times, then a leaf.
        let mut deep = vec![0x81u8; MAX_DEPTH + 4];
        deep.push(0x00);
        assert_eq!(parse_canonical(&deep), Err(DcborError::DepthExceeded));
    }

    #[test]
    fn invalid_utf8_in_a_text_string_is_refused() {
        assert_eq!(
            parse_canonical(&[0x62, 0xff, 0xfe]),
            Err(DcborError::InvalidUtf8)
        );
    }

    #[test]
    fn a_truncated_item_is_refused() {
        assert_eq!(parse_canonical(&[0x18]), Err(DcborError::Truncated));
        assert_eq!(parse_canonical(&[]), Err(DcborError::Truncated));
    }

    #[test]
    fn a_negative_integer_round_trips_its_encoded_form() {
        // -1 is 0x20 (nint with argument 0).
        assert_eq!(parse_canonical(&[0x20]), Ok(Value::Nint(0)));
        // -500 is 0x39 0x01 0xf3.
        assert_eq!(parse_canonical(&[0x39, 0x01, 0xf3]), Ok(Value::Nint(499)));
        // and a non-shortest negative is refused like any other.
        assert_eq!(
            parse_canonical(&[0x38, 0x01]),
            Err(DcborError::NonShortestArgument)
        );
    }

    #[test]
    fn text_keys_sort_by_their_encodings_not_by_their_characters() {
        // {"a": 0, "aa": 0} — 0x61 0x61 < 0x62 0x61 0x61, so this is sorted.
        assert!(parse_canonical(&[0xa2, 0x61, 0x61, 0x00, 0x62, 0x61, 0x61, 0x00]).is_ok());
        // The reverse is not.
        assert_eq!(
            parse_canonical(&[0xa2, 0x62, 0x61, 0x61, 0x00, 0x61, 0x61, 0x00]),
            Err(DcborError::MapKeysUnsorted)
        );
    }

    #[test]
    fn require_canonical_reports_the_same_verdict_without_the_value() {
        assert!(require_canonical(&[0xa1, 0x01, 0x02]).is_ok());
        assert_eq!(
            require_canonical(&[0x18, 0x01]),
            Err(DcborError::NonShortestArgument)
        );
    }
}
