//! BLAKE2s — the relay frame MAC and the HRW weight digest.
//!
//! **Authority:** ADR-0005 §9.1 (the frame MAC), ADR-0006 §11.7 and
//! `twinvpn-relay-client`'s `hrw.rs` (the weight digest), RFC 7693, ADR-0018
//! CD-I2.
//!
//! # Two consumers, in two workspaces, computing the same bytes
//!
//! `services/relay` and `core/crates/twinvpn-relay-client` both need BLAKE2s,
//! and both correctly refused to supply it themselves — the relay left its
//! `frame_mac` seam unbound and said so in a startup `ERROR` rather than
//! substituting SHA-256. Its reasoning is the reason this module exists:
//!
//! > "the frame MAC is **on the wire** … the peer's `twinvpn-relay-client`
//! > computes the same value. A relay that MACs with a different primitive
//! > rejects every legitimate frame while looking configured."
//!
//! The same is true of the HRW weight: a client and a directory that disagree
//! rank the fleet differently and never converge on a relay. So both live here,
//! computed once.
//!
//! # The entry points are purpose-named, and there is no general hash
//!
//! There is deliberately **no public `blake2s(input) -> [u8; 32]`**. This is an
//! addition to an audited seam, not a hashing API: each function below is named
//! for the one wire format it serves, so a call site cannot quietly grow a
//! second use with different framing. A future consumer that needs BLAKE2s for
//! something else should ask for an entry point named after *that*, which is how
//! the framing gets reviewed.
//!
//! # Framing: specified, fixed-width-then-variable, and therefore not prefixed
//!
//! Both inputs are unambiguous **as the ADRs write them**, and neither is
//! length-prefixed here:
//!
//! | Input | Fields | Why it is unambiguous |
//! |---|---|---|
//! | [`frame_mac`] | `type(1) ‖ ver\|flags(1) ‖ counter_full(8 BE) ‖ flow_id(4 BE) ‖ payload` | every field fixed-width except `payload`, which is **last** |
//! | [`hrw_weight_digest`] | `relay_id(8) ‖ pair_id(16)` | both fixed-width |
//!
//! This is the opposite call from the ADR-0020 §11.5 record AAD, where two
//! *variable-length* fields were concatenated and the encoding genuinely was
//! ambiguous. Here the formats are specified and unambiguous, and adding a
//! length prefix would be an improvement on a wire format — which is precisely
//! the mistake W-23 recorded. A relay that prefixed would reject every
//! legitimate frame.
//!
//! # The truncation is a truncation, not a short-output BLAKE2s
//!
//! ADR-0005 §9.1: "a keyed BLAKE2s MAC under `K_leg` over `(…)`, **truncated to
//! 64 bits**."
//!
//! BLAKE2 parameterises its output length *inside the initialisation block*, so
//! `BLAKE2s(digest_length = 8)` and `BLAKE2s(digest_length = 32)[0..8]` are
//! **different values**. "Truncated" selects the second reading: compute the
//! full 256-bit keyed MAC, then take the leading eight bytes.
//!
//! Both readings are published as constants in [`vectors`] —
//! [`vectors::FRAME_MAC_TAG`] and
//! [`vectors::FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED`] — so every consumer asserts
//! the *discrimination* and not merely the happy answer. Getting this wrong
//! produces a relay that looks correctly configured and drops every frame,
//! which is the failure mode `services/relay` refused to ship.
//!
//! # The vectors are one artifact (W-33)
//!
//! [`vectors`] is a plain public module, not `#[cfg(test)]`. The §9.1 vector was
//! previously replicated as source in four places, so each side failed
//! separately and regenerating one did not fail the others. This crate's own
//! tests import it like everyone else; there is no private copy here.

pub mod vectors;

use blake2::digest::{FixedOutput, KeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac256};
use subtle::ConstantTimeEq;

/// BLAKE2s-256's output length.
pub const BLAKE2S_LEN: usize = 32;

/// `K_leg`'s length (ADR-0005 §11.1(2): 32 bytes from a Noise_IK transport key
/// or an RFC 8446 exporter).
pub const FRAME_MAC_KEY_LEN: usize = 32;

/// The frame `auth_tag`'s length on the wire: 64 bits (ADR-0005 §9.1).
pub const FRAME_MAC_TAG_LEN: usize = 8;

/// `relay_id`'s width (`contracts/registry/limits.json` `relay_id_bytes`).
pub const HRW_RELAY_ID_LEN: usize = 8;

/// `pair_id`'s width, as `twinvpn-relay-client`'s HRW takes it.
pub const HRW_PAIR_ID_LEN: usize = 16;

/// Unkeyed BLAKE2s-256. **Private on purpose** — see the module documentation.
fn blake2s_256(input: &[u8]) -> [u8; BLAKE2S_LEN] {
    let mut h = Blake2s256::default();
    Update::update(&mut h, input);
    h.finalize_fixed().into()
}

/// Keyed BLAKE2s-256. **Private on purpose.**
///
/// `key` is at most 32 bytes, which BLAKE2s's keyed mode accepts natively
/// (RFC 7693 §2.5) — this is not HMAC, and wrapping it in HMAC would be a
/// different function.
fn blake2s_256_keyed(key: &[u8; FRAME_MAC_KEY_LEN], input: &[u8]) -> [u8; BLAKE2S_LEN] {
    // `new_from_slice` rejects only an over-long key, and the type fixes this
    // one at 32 bytes, so the failure is unreachable. It is still handled rather
    // than unwrapped: an `expect` here would be a panic on a cryptographic path.
    let Ok(mut m) = Blake2sMac256::new_from_slice(key) else {
        // Unreachable given the fixed-width key. Returning a zero tag would be a
        // forgeable constant, so this returns the unkeyed digest of a
        // domain-separated marker instead — a value no legitimate MAC can equal,
        // which fails closed at the comparison rather than opening a hole.
        return blake2s_256(b"twinvpn/blake2s/unreachable-key-length/v1");
    };
    Mac::update(&mut m, input);
    m.finalize_fixed().into()
}

/// The ADR-0005 §9.1 relay frame MAC: keyed BLAKE2s under `K_leg`, truncated to
/// 64 bits.
///
/// `mac_input` is the already-assembled
/// `type ‖ ver|flags ‖ counter_full ‖ flow_id ‖ payload`. The relay owns the
/// frame layout and assembles it; this function owns the MAC and the truncation,
/// and adds nothing to the input.
///
/// The MAC "protects the relay's own session table from off-path injection; it
/// is **not** a confidentiality mechanism, because the payload is already
/// L-DATA-sealed."
#[must_use]
pub fn frame_mac(k_leg: &[u8; FRAME_MAC_KEY_LEN], mac_input: &[u8]) -> [u8; FRAME_MAC_TAG_LEN] {
    let full = blake2s_256_keyed(k_leg, mac_input);
    let mut tag = [0u8; FRAME_MAC_TAG_LEN];
    tag.copy_from_slice(&full[..FRAME_MAC_TAG_LEN]);
    tag
}

/// Verifies a frame MAC in **constant time**.
///
/// The tag arrives on the wire and is attacker-controlled, so a variable-time
/// comparison is a prefix-matching oracle: an attacker recovers the tag one byte
/// at a time and forges a frame into the relay's session table. `subtle`'s
/// comparison is cheap and there is no reason to make the weaker choice.
#[must_use]
pub fn verify_frame_mac(
    k_leg: &[u8; FRAME_MAC_KEY_LEN],
    mac_input: &[u8],
    tag: &[u8; FRAME_MAC_TAG_LEN],
) -> bool {
    frame_mac(k_leg, mac_input).ct_eq(tag).into()
}

/// The HRW weight digest: `BLAKE2s(relay_id ‖ pair_id)`.
///
/// `twinvpn-relay-client`'s `hrw.rs` reads the leading eight bytes as a
/// little-endian `u64` and scales by `capacity_weight`. Both ends of a pair, and
/// any directory that ranks the same fleet, must compute this identically or
/// they select different relays and never meet.
///
/// Both inputs are fixed-width, so the concatenation is unambiguous and is not
/// length-prefixed.
#[must_use]
pub fn hrw_weight_digest(
    relay_id: &[u8; HRW_RELAY_ID_LEN],
    pair_id: &[u8; HRW_PAIR_ID_LEN],
) -> [u8; BLAKE2S_LEN] {
    let mut input = [0u8; HRW_RELAY_ID_LEN + HRW_PAIR_ID_LEN];
    input[..HRW_RELAY_ID_LEN].copy_from_slice(relay_id);
    input[HRW_RELAY_ID_LEN..].copy_from_slice(pair_id);
    blake2s_256(&input)
}

#[cfg(test)]
mod tests {
    use super::vectors as v;
    use super::*;

    /// W-33: this crate holds **no private copy** of the vector. Everything
    /// below reads `vectors`, exactly as `services/relay`,
    /// `twinvpn-relay-client` and the `tests/` workspace do.
    ///
    /// This is the assertion that keeps the published module honest: if a
    /// constant there ever disagreed with `frame_mac` or `hrw_weight_digest`,
    /// every consumer would be pinned to a lie, and this fails first.
    #[test]
    fn the_published_vectors_agree_with_this_implementation() {
        v::self_consistency();
    }

    /// **RFC 7693 Appendix B.** The published unkeyed BLAKE2s-256 vector for
    /// `"abc"`, so the primitive underneath is the one the RFC specifies and not
    /// merely whatever `blake2` happens to compute.
    #[test]
    fn the_unkeyed_primitive_matches_rfc_7693_appendix_b() {
        assert_eq!(v::to_hex(&blake2s_256(b"abc")), v::RFC7693_ABC_HEX);
    }

    /// **RFC 7693 Appendix E**, the keyed known-answer test: key `00 01 … 1f`
    /// over the empty input, and the same key over the single byte `0x00`.
    ///
    /// This is the vector that proves the keyed mode is BLAKE2's own (RFC 7693
    /// §2.5) rather than HMAC-BLAKE2s, which is a different function that would
    /// produce a different wire tag.
    #[test]
    fn the_keyed_primitive_matches_the_rfc_7693_known_answer_test() {
        assert_eq!(
            v::to_hex(&blake2s_256_keyed(&v::RFC7693_KAT_KEY, b"")),
            v::RFC7693_KEYED_EMPTY_HEX
        );
        assert_eq!(
            v::to_hex(&blake2s_256_keyed(&v::RFC7693_KAT_KEY, &[0x00])),
            "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"
        );
    }

    /// The published MAC input is exactly what §9.1's field order produces.
    ///
    /// Built here from the individual field constants rather than copied from
    /// [`v::FRAME_MAC_INPUT`], which is the same discipline a consumer follows
    /// with its own assembler.
    #[test]
    fn the_published_mac_input_is_the_adr_field_order() {
        let mut expected = Vec::new();
        expected.push(v::FRAME_TYPE_DATA);
        expected.push(v::FRAME_VER_FLAGS);
        expected.extend_from_slice(&v::FRAME_COUNTER_FULL.to_be_bytes());
        expected.extend_from_slice(&v::FRAME_FLOW_ID.to_be_bytes());
        expected.extend_from_slice(&v::FRAME_PAYLOAD);
        assert_eq!(expected, v::FRAME_MAC_INPUT);

        // Nothing is length-prefixed: the input is exactly the sum of its
        // fields, with the only variable-length one last.
        assert_eq!(v::FRAME_MAC_INPUT.len(), 1 + 1 + 8 + 4 + 16);
    }

    /// **The frame-MAC golden vector, and the reading it fixes.**
    ///
    /// BLAKE2 parameterises output length inside its init block, so a
    /// short-output BLAKE2s is a *different function* from a truncated
    /// full-length one. ADR-0005 §9.1 says "truncated", and this pins that
    /// reading by asserting the accepted value **and** the rejected one — both
    /// over the published key and input, so neither assertion can pass for free.
    #[test]
    fn the_frame_mac_truncates_and_is_not_a_short_output_blake2s() {
        // The full keyed MAC, of which the tag is the leading eight bytes.
        assert_eq!(
            v::to_hex(&blake2s_256_keyed(&v::FRAME_MAC_KEY, &v::FRAME_MAC_INPUT)),
            "d04f9be2b57fc15b85c861133757746c1ec9788106c2093c2a7b4edc9775ad99"
        );
        let tag = frame_mac(&v::FRAME_MAC_KEY, &v::FRAME_MAC_INPUT);
        assert_eq!(tag, v::FRAME_MAC_TAG);
        assert_ne!(
            tag,
            v::FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED,
            "the tag must be a truncated 256-bit MAC, not a short-output BLAKE2s"
        );
    }

    #[test]
    fn a_frame_mac_verifies_against_itself() {
        assert!(verify_frame_mac(
            &v::FRAME_MAC_KEY,
            &v::FRAME_MAC_INPUT,
            &v::FRAME_MAC_TAG
        ));
    }

    /// **Attack test.** Off-path injection is what the MAC exists to stop, so a
    /// frame under a different `K_leg` must not verify.
    #[test]
    fn a_frame_under_another_leg_key_does_not_verify() {
        let mut other = v::FRAME_MAC_KEY;
        other[0] ^= 0x01;
        assert!(!verify_frame_mac(
            &other,
            &v::FRAME_MAC_INPUT,
            &v::FRAME_MAC_TAG
        ));
    }

    /// **Attack test.** Every byte of the MAC input is covered — the type, the
    /// version and flags, the **full** counter, the flow id, and the payload.
    ///
    /// The counter matters most: `services/relay`'s own comment notes that
    /// "MACing the truncated counter would let a 16-bit wrap be a forgery
    /// oracle", so the eight-byte reconstructed counter is what is covered.
    #[test]
    fn every_byte_of_the_mac_input_is_covered() {
        for i in 0..v::FRAME_MAC_INPUT.len() {
            let mut tampered = v::FRAME_MAC_INPUT;
            tampered[i] ^= 0x01;
            assert!(
                !verify_frame_mac(&v::FRAME_MAC_KEY, &tampered, &v::FRAME_MAC_TAG),
                "a flip at offset {i} was not covered by the MAC"
            );
        }
    }

    /// **Attack test.** A tampered tag must not verify, including one that
    /// shares a prefix with the real tag — which is what a variable-time
    /// comparison would leak.
    #[test]
    fn a_tampered_tag_does_not_verify() {
        for i in 0..FRAME_MAC_TAG_LEN {
            let mut bad = v::FRAME_MAC_TAG;
            bad[i] ^= 0x01;
            assert!(!verify_frame_mac(
                &v::FRAME_MAC_KEY,
                &v::FRAME_MAC_INPUT,
                &bad
            ));
        }
        // A tag matching every byte but the last is still a refusal.
        let mut near = v::FRAME_MAC_TAG;
        near[FRAME_MAC_TAG_LEN - 1] ^= 0xff;
        assert!(!verify_frame_mac(
            &v::FRAME_MAC_KEY,
            &v::FRAME_MAC_INPUT,
            &near
        ));
    }

    /// **Attack test.** Truncating or extending the input changes the MAC, so a
    /// short frame cannot be padded into a long one under one tag.
    #[test]
    fn a_lengthened_or_shortened_input_changes_the_mac() {
        let mut longer = v::FRAME_MAC_INPUT.to_vec();
        longer.push(0x00);
        assert!(!verify_frame_mac(
            &v::FRAME_MAC_KEY,
            &longer,
            &v::FRAME_MAC_TAG
        ));

        let shorter = &v::FRAME_MAC_INPUT[..v::FRAME_MAC_INPUT.len() - 1];
        assert!(!verify_frame_mac(
            &v::FRAME_MAC_KEY,
            shorter,
            &v::FRAME_MAC_TAG
        ));
    }

    /// **The HRW golden vector.** Both ends of a pair and any directory ranking
    /// the same fleet must compute this identically, or they select different
    /// relays and never meet.
    #[test]
    fn the_hrw_weight_digest_is_blake2s_of_relay_id_then_pair_id() {
        assert_eq!(
            hrw_weight_digest(&v::HRW_RELAY_ID, &v::HRW_PAIR_ID),
            v::HRW_DIGEST
        );

        // And it is exactly BLAKE2s over the concatenation, assembled here
        // independently of the function under test.
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&v::HRW_RELAY_ID);
        expected_input.extend_from_slice(&v::HRW_PAIR_ID);
        assert_eq!(v::HRW_DIGEST, blake2s_256(&expected_input));
    }

    /// The order is `relay_id ‖ pair_id`, not the reverse. Both are fixed-width
    /// so a swap is silent at the type level; it is not silent here.
    #[test]
    fn the_hrw_operands_are_ordered() {
        let a = [0x01u8; HRW_RELAY_ID_LEN];
        let pair = [0x02u8; HRW_PAIR_ID_LEN];

        let mut swapped = Vec::new();
        swapped.extend_from_slice(&pair);
        swapped.extend_from_slice(&a);
        assert_ne!(hrw_weight_digest(&a, &pair), blake2s_256(&swapped));
    }

    /// Distinct relays get distinct weights for one pair, and one relay gets
    /// distinct weights for distinct pairs. Without both, HRW would not spread
    /// pairs across the fleet.
    #[test]
    fn distinct_inputs_give_distinct_weights() {
        assert_ne!(
            hrw_weight_digest(&[0x11; 8], &v::HRW_PAIR_ID),
            hrw_weight_digest(&[0x12; 8], &v::HRW_PAIR_ID)
        );
        assert_ne!(
            hrw_weight_digest(&v::HRW_RELAY_ID, &[0x22; 16]),
            hrw_weight_digest(&v::HRW_RELAY_ID, &[0x23; 16])
        );
    }

    /// The declared widths are the contract's, and the published vector's
    /// widths match them.
    #[test]
    fn the_declared_widths_match_the_wire_formats() {
        assert_eq!(BLAKE2S_LEN, 32);
        assert_eq!(FRAME_MAC_KEY_LEN, 32, "K_leg is 32 bytes (ADR-0005 §11.1)");
        assert_eq!(FRAME_MAC_TAG_LEN, 8, "auth_tag is 64 bits (ADR-0005 §9.1)");
        assert_eq!(HRW_RELAY_ID_LEN, 8, "relay_id_bytes");
        assert_eq!(HRW_PAIR_ID_LEN, 16);

        assert_eq!(v::FRAME_MAC_KEY.len(), FRAME_MAC_KEY_LEN);
        assert_eq!(v::FRAME_MAC_TAG.len(), FRAME_MAC_TAG_LEN);
        assert_eq!(v::HRW_RELAY_ID.len(), HRW_RELAY_ID_LEN);
        assert_eq!(v::HRW_PAIR_ID.len(), HRW_PAIR_ID_LEN);
        assert_eq!(v::HRW_DIGEST.len(), BLAKE2S_LEN);
    }
}
