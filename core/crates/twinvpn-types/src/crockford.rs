//! Crockford base32 — the alphabet a human retypes, and the tolerance that
//! makes retyping survivable.
//!
//! **Authority:** ADR-0023 §11.6 EM-22 **E2** ("renders the same dCBOR bytes as
//! Crockford base32 in groups of eight, for copy-paste into the admin device");
//! `contracts/docs/identifiers.md` §2, whose `device_id` fingerprint uses the
//! same alphabet.
//!
//! # Why an alphabet gets a module
//!
//! Two things in this workspace already render Crockford base32 and a third was
//! about to: [`crate::id::DeviceId::fingerprint`], ADR-0023's E2 text offer, and
//! the `twinvpn-types` byte-form helper next to them that is **not** Crockford at
//! all — it is RFC 4648 lowercase. Three renderings, two alphabets, one file.
//! Duplicate declarations were this wave's recurring defect class (W-20, X-4,
//! R-14, and X-4 again from a non-Rust shell), so the alphabet is declared once,
//! here, and every renderer takes it from [`ALPHABET`].
//!
//! # The decoder is the point, not the encoder
//!
//! E2 exists because a QR does not fit a 40-column serial console. Its bytes are
//! read off one screen and typed into another, so the decoder must survive what
//! a human does to a string: lower case, `I`/`l` typed for `1`, `O` typed for
//! `0`, and the group separators the renderer itself inserted. Crockford's
//! specification says exactly this, and [`decode`] implements it — **and nothing
//! more**. It is not lenient about anything else: an unmapped character is a
//! refusal, not a skip, because a decoder that silently drops what it does not
//! understand turns a mistyped offer into a *different valid-looking* offer.
//!
//! Crockford's check symbol is deliberately **not** implemented. The offer
//! carries its own integrity in a way a five-bit checksum cannot improve on: it
//! is deterministic CBOR whose key set, per-field widths and total length are all
//! bounded, so a corrupted paste fails `twinvpn_crypto::pairing_offer::decode`
//! with a registered code. A second, weaker check would only add a way to
//! disagree.

/// The Crockford base32 alphabet: no `I`, `L`, `O` or `U`.
///
/// `U` is excluded by Crockford to avoid accidental obscenity; the other three
/// are excluded because they are the characters a human confuses with `1` and
/// `0`, which is also why [`decode`] maps them rather than refusing them.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The separator [`encode_groups`] inserts and [`decode`] ignores.
pub const SEPARATOR: char = '-';

/// ADR-0023 EM-22 E2: "groups of eight".
pub const E2_GROUP: usize = 8;

/// Encodes `bytes`, inserting [`SEPARATOR`] every `group` characters.
///
/// `group` of 0 means no grouping. Unpadded: Crockford has no padding character,
/// and the decoder recovers the length from the bit count.
#[must_use]
pub fn encode_groups(bytes: &[u8], group: usize) -> String {
    let chars = bytes.len() * 8 / 5 + usize::from(!(bytes.len() * 8).is_multiple_of(5));
    let separators = if group == 0 { 0 } else { chars / group };
    let mut out = String::with_capacity(chars + separators);

    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut written = 0usize;
    let push = |out: &mut String, idx: usize, written: &mut usize| {
        if group != 0 && *written != 0 && (*written).is_multiple_of(group) {
            out.push(SEPARATOR);
        }
        out.push(char::from(ALPHABET[idx]));
        *written += 1;
    };

    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            push(&mut out, ((acc >> bits) & 0x1f) as usize, &mut written);
        }
    }
    if bits > 0 {
        // The trailing partial group is left-aligned, which is what `decode`
        // reverses: the residual bits are padding and must be zero.
        push(
            &mut out,
            ((acc << (5 - bits)) & 0x1f) as usize,
            &mut written,
        );
    }
    out
}

/// Why a Crockford string was refused.
///
/// Structural only — no variant carries a decoded byte, so this is safe to name
/// in a diagnostic even when the string was an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CrockfordError {
    /// A character that is not in the alphabet, not a recognised confusable, and
    /// not a separator.
    ///
    /// **Refused, not skipped.** Dropping it would turn a mistyped offer into a
    /// different one that still parses.
    #[error("crockford: character is not in the alphabet")]
    UnmappedCharacter,

    /// The bit count left a partial byte whose padding bits were not zero.
    ///
    /// A non-zero residue means the string is not the encoding of any byte
    /// string, so accepting it would admit two spellings of one value — the
    /// canonicity failure `pairing_offer.cddl` rule 1 refuses one layer up.
    #[error("crockford: trailing bits are not zero padding")]
    NonZeroPadding,

    /// The string decoded to more bytes than the caller allows.
    ///
    /// Checked against a caller-supplied bound so the allocation cannot be
    /// driven by the input's length — `ownership.md` §6 rules 9 and 10.
    #[error("crockford: decoded length exceeds the caller's bound")]
    TooLong,
}

/// Decodes a Crockford string, tolerating what a human does to one.
///
/// Accepts: either case; `O`/`o` as `0`; `I`/`i`/`L`/`l` as `1`; [`SEPARATOR`]
/// and ASCII whitespace anywhere. Refuses everything else.
///
/// `max_bytes` bounds the output **before** the buffer grows to meet it, so a
/// long paste cannot drive an allocation proportional to its own length.
///
/// # Errors
///
/// [`CrockfordError`], naming the structural rule that failed.
pub fn decode(s: &str, max_bytes: usize) -> Result<Vec<u8>, CrockfordError> {
    // Five bits per character is the ceiling on what any prefix can produce, so
    // this refuses an over-long input before the first byte is pushed.
    if s.len() / 8 * 5 > max_bytes {
        return Err(CrockfordError::TooLong);
    }

    let mut out = Vec::with_capacity(max_bytes.min(s.len() * 5 / 8 + 1));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for ch in s.chars() {
        if ch == SEPARATOR || ch.is_ascii_whitespace() {
            continue;
        }
        let v = symbol_value(ch).ok_or(CrockfordError::UnmappedCharacter)?;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out.len() == max_bytes {
                return Err(CrockfordError::TooLong);
            }
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }

    // The residue is padding and must be zero. `encode_groups` left-aligns the
    // final partial group, so a conforming encoder always leaves zeros here.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(CrockfordError::NonZeroPadding);
    }
    Ok(out)
}

/// The value of one symbol, with Crockford's confusable mapping applied.
const fn symbol_value(ch: char) -> Option<u8> {
    Some(match ch {
        '0'..='9' => ch as u8 - b'0',
        // The three confusables Crockford maps rather than refuses. They are the
        // whole reason the alphabet omits them in the first place.
        'O' | 'o' => 0,
        'I' | 'i' | 'L' | 'l' => 1,
        'A'..='H' => ch as u8 - b'A' + 10,
        'a'..='h' => ch as u8 - b'a' + 10,
        'J' | 'j' => 18,
        'K' | 'k' => 19,
        'M' | 'm' => 20,
        'N' | 'n' => 21,
        'P'..='T' => ch as u8 - b'P' + 22,
        'p'..='t' => ch as u8 - b'p' + 22,
        'V'..='Z' => ch as u8 - b'V' + 27,
        'v'..='z' => ch as u8 - b'v' + 27,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode_groups, CrockfordError, ALPHABET, E2_GROUP};

    #[test]
    fn every_symbol_round_trips() {
        // One byte string that exercises all 32 symbols, so a transcription
        // error in the alphabet cannot hide in a symbol no test reaches.
        let bytes: Vec<u8> = (0u8..=255).collect();
        let text = encode_groups(&bytes, 0);
        assert_eq!(decode(&text, 512).expect("round trips"), bytes);
        for sym in ALPHABET {
            assert!(text.contains(char::from(*sym)), "symbol {sym} unreached");
        }
    }

    #[test]
    fn the_e2_grouping_is_eight_and_the_separators_are_ignored_on_the_way_back() {
        let bytes = vec![0xAB; 40];
        let text = encode_groups(&bytes, E2_GROUP);
        for group in text.split('-') {
            assert!(group.len() <= E2_GROUP, "group {group} is too long");
        }
        assert_eq!(decode(&text, 64).expect("round trips"), bytes);
    }

    /// The tolerance E2 exists for: read off one screen, typed into another.
    #[test]
    fn a_human_retyping_confusables_still_decodes_to_the_same_bytes() {
        let bytes = vec![0x00, 0x08, 0x42, 0x10];
        let text = encode_groups(&bytes, 0);
        let mangled: String = text
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'l',
                c => c.to_ascii_lowercase(),
            })
            .collect();
        assert_eq!(decode(&mangled, 16).expect("tolerant"), bytes);
    }

    #[test]
    fn an_unmapped_character_is_refused_and_never_skipped() {
        assert_eq!(
            decode("ABC$DEF", 16),
            Err(CrockfordError::UnmappedCharacter),
            "a skipped character would decode a mistyped offer to a different one"
        );
        // `U` is not in the alphabet and is NOT a confusable Crockford maps.
        assert_eq!(decode("ABU", 16), Err(CrockfordError::UnmappedCharacter));
    }

    #[test]
    fn non_zero_padding_is_refused_so_one_value_has_one_spelling() {
        // "10" is two symbols, ten bits, one byte plus two residual bits. The
        // second symbol's low bits are the residue: `1` leaves them zero, `3`
        // does not.
        assert!(decode("10", 8).is_ok());
        assert_eq!(decode("13", 8), Err(CrockfordError::NonZeroPadding));
    }

    #[test]
    fn an_over_long_input_is_refused_before_the_buffer_grows() {
        let long = encode_groups(&vec![0u8; 600], 0);
        assert_eq!(decode(&long, 512), Err(CrockfordError::TooLong));
    }

    #[test]
    fn the_empty_string_decodes_to_no_bytes() {
        assert_eq!(decode("", 16), Ok(Vec::new()));
        assert_eq!(encode_groups(&[], E2_GROUP), "");
    }
}
