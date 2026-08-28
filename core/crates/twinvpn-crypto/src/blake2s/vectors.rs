//! The published BLAKE2s golden vectors — **one artifact, importable**.
//!
//! **Authority:** ADR-0005 §9.1 (the relay frame MAC), ADR-0006 §11.7 and
//! `twinvpn-relay-client`'s `hrw.rs` (the weight digest), RFC 7693.
//!
//! # Why this is a public module and not `#[cfg(test)]`
//!
//! W-33. The §9.1 vector was replicated as source in four places — this crate's
//! own unit tests, `services/relay`'s provider tests, `twinvpn-relay-client`'s
//! device-frame tests and the `tests/` workspace. Each side then failed
//! *separately*, and regenerating one did not fail the others. Four copies is
//! the shape that lets the two ends of a wire drift silently, which is the exact
//! failure this vector exists to prevent.
//!
//! So it lives here once, in a plain public module. It is published test data,
//! not a secret, and a plain module means the `tests/` workspace and
//! `services/relay` can import it with no feature plumbing.
//!
//! # This module is a reference, not a second implementation
//!
//! `test-engineering` found the same class of defect in its own tripwire: a
//! check that *enumerates* its subject rather than *referencing* it goes blind
//! the moment the subject moves. The rule this module follows, and that a
//! consumer should follow too:
//!
//! - **Import the field values** ([`FRAME_TYPE_DATA`], [`FRAME_COUNTER_FULL`],
//!   [`FRAME_FLOW_ID`], [`FRAME_PAYLOAD`], …) and build the frame **through your
//!   own assembler**, then compare against [`FRAME_MAC_INPUT`]. That is the
//!   assertion that catches a disagreement about §9.1's field order or widths —
//!   copying [`FRAME_MAC_INPUT`] in as a literal instead proves nothing.
//! - **Import [`FRAME_MAC_TAG`]** for the accepted answer and
//!   [`FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED`] for the discrimination, so an
//!   `assert_ne!` against the rejected reading is pinned to *this* key and
//!   *this* input rather than to whatever the consumer happened to have in
//!   scope. A rejected-reading assertion over the wrong inputs passes for free.
//!
//! [`self_consistency`] proves the constants agree with the implementation, so
//! this module cannot drift from `frame_mac` and `hrw_weight_digest` either.

// ---------------------------------------------------------------------------
// ADR-0005 §9.1 — the relay frame MAC
// ---------------------------------------------------------------------------

/// `K_leg` for the shared vector.
pub const FRAME_MAC_KEY: [u8; 32] = [0x4b; 32];

/// `type` — `0x01` = `DATA` (ADR-0005 §9.1).
pub const FRAME_TYPE_DATA: u8 = 0x01;

/// `ver` — the protocol version nibble.
pub const FRAME_VERSION: u8 = 1;

/// `flags` — the flags nibble. Reserved bits are zero on send (§9.1).
pub const FRAME_FLAGS: u8 = 0;

/// The packed `ver | flags` byte, version in the high nibble.
pub const FRAME_VER_FLAGS: u8 = (FRAME_VERSION << 4) | FRAME_FLAGS;

/// `counter_full` — the reconstructed 64-bit per-half-flow counter.
///
/// The **full** counter is what the MAC covers. MACing the truncated
/// `counter_low` would make a 16-bit wrap a forgery oracle.
pub const FRAME_COUNTER_FULL: u64 = 0x0102_0304_0506_0708;

/// `counter_low` — the low 16 bits that travel on the wire, reconstructed by
/// the receiver per RFC 9147 §4.2.2.
pub const FRAME_COUNTER_LOW: u16 = 0x0708;

/// `flow_id`.
pub const FRAME_FLOW_ID: u32 = 0xdead_beef;

/// The opaque L-DATA payload. Variable-length, and **last** in the MAC input,
/// which is what makes the concatenation unambiguous without a length prefix.
pub const FRAME_PAYLOAD: [u8; 16] = [0xab; 16];

/// The assembled MAC input:
/// `type ‖ ver|flags ‖ counter_full(8 BE) ‖ flow_id(4 BE) ‖ payload`.
///
/// **Compare your assembler's output against this; do not copy it in.** The
/// cross-crate risk is a disagreement about field order or widths, and only
/// building it yourself can catch that.
pub const FRAME_MAC_INPUT: [u8; 30] = [
    0x01, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
];

/// The accepted tag: `BLAKE2s-256(K_leg, mac_input)[0..8]`.
///
/// ADR-0005 §9.1 says "**truncated** to 64 bits", which is the leading eight
/// bytes of the full 256-bit keyed MAC.
pub const FRAME_MAC_TAG: [u8; 8] = [0xd0, 0x4f, 0x9b, 0xe2, 0xb5, 0x7f, 0xc1, 0x5b];

/// The reading §9.1 **rejects**: BLAKE2s parameterised to an 8-byte output.
///
/// BLAKE2 fixes its output length inside the initialisation block, so
/// `BLAKE2s(digest_length = 8)` is a *different function* from
/// `BLAKE2s(digest_length = 32)[0..8]` over the same key and input. Published so
/// a consumer can assert the discrimination and not merely the happy answer — a
/// relay computing this value verifies nothing while looking correctly
/// configured.
pub const FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED: [u8; 8] =
    [0x77, 0x42, 0x14, 0xe9, 0x63, 0x46, 0xc3, 0xfa];

/// [`FRAME_MAC_TAG`] as lower-case hex.
///
/// Two of the consumers render the wire tag with `format!("{b:02x}")` and
/// compare strings; publishing both forms keeps them from re-deriving one from
/// the other. `self_consistency` asserts the two agree.
pub const FRAME_MAC_TAG_HEX: &str = "d04f9be2b57fc15b";

/// [`FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED`] as lower-case hex.
pub const FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED_HEX: &str = "774214e96346c3fa";

// ---------------------------------------------------------------------------
// ADR-0006 §11.7 — the HRW weight digest
// ---------------------------------------------------------------------------

/// `relay_id` for the shared vector.
pub const HRW_RELAY_ID: [u8; 8] = [0x11; 8];

/// `pair_id` for the shared vector.
pub const HRW_PAIR_ID: [u8; 16] = [0x22; 16];

/// `BLAKE2s(relay_id ‖ pair_id)`.
///
/// A client and a directory that disagree here rank the fleet differently and
/// never converge on a relay.
pub const HRW_DIGEST: [u8; 32] = [
    0xf0, 0xf1, 0x3f, 0x7c, 0x6d, 0xff, 0x49, 0xdc, 0xa1, 0x04, 0xe8, 0xa8, 0x2a, 0x46, 0xf1, 0xeb,
    0x5f, 0x21, 0xd7, 0xf9, 0x50, 0xee, 0x9b, 0x94, 0xe6, 0xc2, 0xa2, 0x61, 0xc1, 0x36, 0x5a, 0xed,
];

/// [`HRW_DIGEST`] as lower-case hex.
pub const HRW_DIGEST_HEX: &str = "f0f13f7c6dff49dca104e8a82a46f1eb5f21d7f950ee9b94e6c2a261c1365aed";

// ---------------------------------------------------------------------------
// RFC 7693 — the primitive's own published vectors
// ---------------------------------------------------------------------------

/// RFC 7693 Appendix E's keyed known-answer-test key: `00 01 … 1f`.
pub const RFC7693_KAT_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// RFC 7693 Appendix B: unkeyed BLAKE2s-256 of `"abc"`, as lower-case hex.
pub const RFC7693_ABC_HEX: &str =
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";

/// RFC 7693 Appendix E: keyed BLAKE2s-256 under [`RFC7693_KAT_KEY`] over the
/// empty input, as lower-case hex.
///
/// This is the vector that proves the keyed mode is BLAKE2's own (RFC 7693
/// §2.5) rather than HMAC-BLAKE2s, which is a different function and a
/// different wire tag.
pub const RFC7693_KEYED_EMPTY_HEX: &str =
    "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49";

/// Renders bytes as lower-case hex, the form the wire tags are compared in.
///
/// Published so a consumer does not write its own `format!("{b:02x}")` loop —
/// a third rendering of one value is the same duplication W-33 is about, in
/// miniature.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Rebuilds [`FRAME_MAC_INPUT`] from the individual field constants.
///
/// Offered so a consumer can check its own assembler against a construction it
/// can read, without hand-copying the field order. It is **not** a substitute
/// for building the frame through your own code and comparing — that comparison
/// is the one that catches a divergence.
#[must_use]
pub fn assemble_frame_mac_input() -> Vec<u8> {
    let mut v = Vec::with_capacity(FRAME_MAC_INPUT.len());
    v.push(FRAME_TYPE_DATA);
    v.push(FRAME_VER_FLAGS);
    v.extend_from_slice(&FRAME_COUNTER_FULL.to_be_bytes());
    v.extend_from_slice(&FRAME_FLOW_ID.to_be_bytes());
    v.extend_from_slice(&FRAME_PAYLOAD);
    v
}

/// Proves the published constants agree with the implementation.
///
/// Callable from anywhere, so a consumer can assert it too, and run in this
/// crate's own test suite — which is what stops this module from becoming a
/// fifth copy that drifts from `frame_mac`.
///
/// # Panics
///
/// If any published constant disagrees with what this crate computes.
pub fn self_consistency() {
    assert_eq!(
        assemble_frame_mac_input(),
        FRAME_MAC_INPUT,
        "the field constants and the assembled MAC input disagree"
    );
    assert_eq!(
        u64::from(FRAME_COUNTER_LOW),
        FRAME_COUNTER_FULL & 0xffff,
        "counter_low must be the low 16 bits of counter_full"
    );
    assert_eq!(
        super::frame_mac(&FRAME_MAC_KEY, &FRAME_MAC_INPUT),
        FRAME_MAC_TAG,
        "the published tag disagrees with frame_mac"
    );
    assert_ne!(
        FRAME_MAC_TAG, FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED,
        "the accepted and rejected readings must differ, or the pin is vacuous"
    );
    assert!(
        super::verify_frame_mac(&FRAME_MAC_KEY, &FRAME_MAC_INPUT, &FRAME_MAC_TAG),
        "the published tag must verify"
    );
    assert_eq!(
        super::hrw_weight_digest(&HRW_RELAY_ID, &HRW_PAIR_ID),
        HRW_DIGEST,
        "the published HRW digest disagrees with hrw_weight_digest"
    );

    // The hex forms are the byte forms. Two renderings of one value is the
    // duplication this module exists to remove, so they are proved equal here
    // rather than trusted.
    assert_eq!(to_hex(&FRAME_MAC_TAG), FRAME_MAC_TAG_HEX);
    assert_eq!(
        to_hex(&FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED),
        FRAME_MAC_TAG_SHORT_OUTPUT_REJECTED_HEX
    );
    assert_eq!(to_hex(&HRW_DIGEST), HRW_DIGEST_HEX);
}
