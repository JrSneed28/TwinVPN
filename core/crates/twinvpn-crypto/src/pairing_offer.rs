//! `PairingOffer` — the C-B ceremony payload, decoded and emitted.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/pairing_offer.cddl` (Amendment 4);
//! ADR-0007 §7.4; ADR-0023 §11.6 EM-22..EM-26; `contracts/registry/limits.json`
//! `pairing`.
//!
//! **Owner:** `core-security`.
//!
//! # Why this is not in [`crate::statements`]
//!
//! Every module there decodes a [`crate::cose::VerifiedStatement`] — octets whose
//! signature has already verified. **This payload has no verifier.** The joining
//! device is by definition unenrolled: it holds no `OwnerTrustAnchor`, no
//! `TrustedPeer`, and no key any signature over the offer could be checked
//! against. C-B's channel authentication *is* the out-of-band confidentiality,
//! and the CDDL says so in terms. So the decoder below reads raw octets, and
//! everything it can conclude is structural.
//!
//! The one thing inside the offer that *is* verifiable is field 4, the
//! `COSE_Sign1(TunnelKeyBinding)` — and it is verified against field 2's
//! `ik_pub`, which the offer itself supplies. That is not circular in the way it
//! first reads: the offer arrived over a channel a human authenticated, so
//! `ik_pub` is trusted **because of the channel**, and the binding then proves
//! that the same identity vouches for the tunnel key in field 3. Verifying it is
//! [`crate::verify_tunnel_key_binding`]'s job and is deliberately not done here;
//! this module's contract is *the bytes decoded to the shape the CDDL declares*,
//! and nothing beyond it.
//!
//! # The secret, and the rules that are code rather than comments
//!
//! The CDDL classifies the whole payload SECRET and states that there is "NO
//! RENDERING PATH into the diagnostic ledger, syslog, a Tier-1 bundle, or ANY
//! log level, at any severity, in any build profile". Three things hold that:
//!
//! | Rule | The type instead of a comment |
//! |---|---|
//! | `pairing_secret` MUST NOT be logged, "including inside a parse error, a hex dump, a `Debug` rendering, or an `Evidence` attachment" | [`PairingOffer`]'s `Debug` is hand-written and renders `<redacted>`; the field is private and reachable only through [`PairingOffer::pairing_secret`] |
//! | "A decode failure is reported as a bare registered `reason_code` with NO evidence drawn from the input" | [`OfferReject`] carries a [`ReasonCode`] and a `&'static str` naming a *check*. It has no field an input byte, length or field value can reach |
//! | "zeroized on consumption or at expiry, whichever is first" | [`PairingOffer`] implements [`Drop`] and zeroizes the secret and the binding |
//!
//! # Ordering, which is the security property
//!
//! Encoding rule 2: the total length is checked **first**, against
//! `pairing.max_offer_bytes`, before any field is parsed. [`decode`] does that on
//! its first line. The per-field bounds sum to 493 against a 512-byte payload
//! cap, so a receiver enforcing the payload cap first can meet no field it has
//! not already budgeted for — and `twinvpn-schema`'s
//! `the_offer_field_bounds_fit_inside_the_offer_payload_bound` fails the build if
//! a future amendment breaks that relation.

use zeroize::Zeroize;

use twinvpn_schema::limits;
use twinvpn_types::{codes, ReasonCode};

use crate::dcbor::{self, Value};
use crate::emit::{self, Item};
use crate::kdf::{hkdf_sha256, sha256};
use crate::Result;

/// The exact width of `tk_pub`.
///
/// `pairing_offer.cddl` field 3 spells this `bstr .size 32` rather than taking it
/// from `limits.json`, so it is a constant here rather than a generated one. The
/// divergence from `signed_statements.cddl`'s `cose-key` spelling of the same key
/// is finding F-2, recorded under `ownership.md` §11 G-9.
pub const TK_PUB_BYTES: usize = 32;

/// The exact width of `pairing_id`, derived rather than carried.
pub const PAIRING_ID_BYTES: usize = limits::PAIRING_ID_BYTES;

/// The width of `K_pair`.
pub const K_PAIR_BYTES: usize = 32;

/// HKDF `info` for `K_pair`, byte-exact to `pairing_offer.cddl`.
///
/// W-23 is the wave's standing lesson that a specified derivation is not an
/// implementation agent's to improve, so this is a literal and not a builder.
const K_PAIR_INFO: &[u8] = b"TwinVPN/Pair/v1";

/// The seven integer keys the schema declares, in canonical order.
///
/// Encoding rule 3: "UNKNOWN KEYS ARE REJECTED. There is no wildcard entry in the
/// map below and none may be added." So this is compared for *equality* against
/// what arrived, not for containment — a missing key and an extra key are both
/// refusals, and neither needs its own branch.
const OFFER_KEYS: [u64; 7] = [1, 2, 3, 4, 5, 6, 7];

// ---------------------------------------------------------------------------
// The refusal
// ---------------------------------------------------------------------------

/// Why an offer was refused.
///
/// **Carries nothing drawn from the input.** `pairing_offer.cddl`: "A decode
/// failure is reported as a bare registered `reason_code` with NO evidence drawn
/// from the input. *The offer did not parse* is the whole of what may be said
/// about it."
///
/// That is stricter than [`crate::dcbor::DcborError`], which is safe in a log
/// because its variants are structural — and stricter than
/// [`twinvpn_schema::Reject`], whose `SizeExceeded` carries the observed length.
/// A length is not content, but the rule here admits no exception and the type
/// is the cheapest place to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("pairing offer refused: {check}")]
pub struct OfferReject {
    /// The registered code this refusal reports.
    code: ReasonCode,
    /// A bounded, non-localised name for the check that failed. Every value is
    /// a `&'static str` from this module, so no input byte can reach it.
    check: &'static str,
}

impl OfferReject {
    const fn new(code: ReasonCode, check: &'static str) -> Self {
        Self { code, check }
    }

    /// The registered `reason_code` to report.
    #[must_use]
    pub const fn reason_code(&self) -> ReasonCode {
        self.code
    }

    /// The check that failed, as a stable tag.
    #[must_use]
    pub const fn check(&self) -> &'static str {
        self.check
    }
}

// ---------------------------------------------------------------------------
// The offer
// ---------------------------------------------------------------------------

/// A decoded `PairingOffer`.
///
/// Fields are private: `pairing_secret` must not be copied out casually, and
/// making one field private and the rest public would invite a caller to
/// destructure past [`Drop`].
pub struct PairingOffer {
    pairing_secret: [u8; 32],
    ik_pub_cose: Vec<u8>,
    tk_pub: [u8; TK_PUB_BYTES],
    binding: Vec<u8>,
    rendezvous_hint: String,
    not_after_ms: u64,
}

/// `pairing_id = SHA-256(pairing_secret)[0..16]`.
///
/// The **one** derivation of this value in the workspace. `pairing.proto`: it is
/// "COMPUTED BY THE JOINING DEVICE and carried TO the coordination service — it
/// is NOT minted by the server", because it doubles as the HKDF salt for the
/// ceremony channel and a server-chosen handle would let the rendezvous
/// correlate a handle to a secret it must never see.
///
/// `twinvpn_trust::pairing::derive_pairing_id` delegates here rather than
/// deriving again: a value that names a secret must have exactly one definition,
/// or the two copies become a place for a ceremony to disagree with itself.
#[must_use]
pub fn derive_pairing_id(pairing_secret: &[u8]) -> [u8; PAIRING_ID_BYTES] {
    let digest = sha256(pairing_secret);
    let mut id = [0u8; PAIRING_ID_BYTES];
    id.copy_from_slice(&digest[..PAIRING_ID_BYTES]);
    id
}

impl PairingOffer {
    /// The optical secret. **Never log this, never attach it as evidence.**
    #[must_use]
    pub const fn pairing_secret(&self) -> &[u8; 32] {
        &self.pairing_secret
    }

    /// COSE_Key octets for the ES256 identity public key.
    #[must_use]
    pub fn ik_pub_cose(&self) -> &[u8] {
        &self.ik_pub_cose
    }

    /// The raw X25519 tunnel public key.
    #[must_use]
    pub const fn tk_pub(&self) -> &[u8; TK_PUB_BYTES] {
        &self.tk_pub
    }

    /// The `COSE_Sign1(TunnelKeyBinding)` octets, **as received**.
    ///
    /// ADR-0007 N-4: a receiver MUST verify this before writing `tk_pub` into a
    /// `TrustedPeer`, and the check MUST NOT be skippable by configuration. This
    /// accessor hands back the received octets precisely so the verification is
    /// over them and not over a re-serialization.
    #[must_use]
    pub fn binding(&self) -> &[u8] {
        &self.binding
    }

    /// The rendezvous hint.
    #[must_use]
    pub fn rendezvous_hint(&self) -> &str {
        &self.rendezvous_hint
    }

    /// The declared expiry, in UTC milliseconds.
    #[must_use]
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// The public rendezvous handle, `SHA-256(pairing_secret)[0..16]`.
    ///
    /// Derived rather than carried: the CDDL says carrying it "would create a
    /// second place for it to disagree with the secret it names". `pairing_id` is
    /// PUBLIC and MAY be logged; the secret it is derived from may not.
    #[must_use]
    pub fn pairing_id(&self) -> [u8; PAIRING_ID_BYTES] {
        derive_pairing_id(&self.pairing_secret)
    }

    /// Derives `K_pair`, which wraps every subsequent ceremony message.
    ///
    /// `K_pair = HKDF-SHA-256(salt = pairing_id, ikm = pairing_secret,
    /// info = "TwinVPN/Pair/v1")`, byte-exact to the CDDL.
    ///
    /// # Errors
    ///
    /// [`crate::CryptoError::DerivationFailed`], which HKDF raises only for an output
    /// length no caller here can request.
    pub fn derive_k_pair(&self) -> Result<[u8; K_PAIR_BYTES]> {
        let mut out = [0u8; K_PAIR_BYTES];
        hkdf_sha256(
            Some(&self.pairing_id()),
            &self.pairing_secret,
            K_PAIR_INFO,
            &mut out,
        )?;
        Ok(out)
    }
}

impl Drop for PairingOffer {
    fn drop(&mut self) {
        // architecture.md S-67: the in-flight offer is "non-durable BY
        // REQUIREMENT — it MUST NOT survive process restart". Zeroizing on drop
        // is the in-process half of that. `binding` goes too: it is not secret,
        // but it is the one field that names this device to anyone who reads the
        // page afterwards, and clearing it costs nothing.
        self.pairing_secret.zeroize();
        self.binding.zeroize();
    }
}

impl core::fmt::Debug for PairingOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The CDDL forbids a rendering path for the secret at ANY log level in
        // ANY build profile, and R-9's lesson is that a derived `Debug` passes a
        // naive test because `Vec<u8>` renders as digits rather than as
        // something a reviewer recognises. So this is hand-written, the secret
        // is a literal, and `the_debug_rendering_carries_no_secret_byte` asserts
        // the secret's own bytes are absent from the output.
        //
        // `rendezvous_hint` is withheld rather than redacted: it is not secret
        // by classification, but the payload as a whole is, and a hint naming a
        // rendezvous host is exactly the correlating detail a bundle should not
        // carry.
        f.debug_struct("PairingOffer")
            .field("pairing_secret", &"<redacted>")
            .field("ik_pub_cose_len", &self.ik_pub_cose.len())
            .field("tk_pub", &"<withheld>")
            .field("binding_len", &self.binding.len())
            .field("rendezvous_hint", &"<withheld>")
            .field("not_after_ms", &self.not_after_ms)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decodes an offer from the octets an out-of-band channel delivered.
///
/// The order below is the CDDL's and is load-bearing:
///
/// 1. the total length, against `pairing.max_offer_bytes`, **before any field is
///    parsed**;
/// 2. deterministic CBOR, refused rather than normalised;
/// 3. the key set, for equality against the seven the schema declares;
/// 4. each field's type and bound.
///
/// The freshness rule is *not* here: rule 5 evaluates `not_after_ms` against
/// local time, and this crate holds no clock. [`check_window`] is that half, and
/// it is separate so a caller cannot get a decoded offer without having been
/// handed the freshness check as a distinct thing to call.
///
/// # Errors
///
/// An [`OfferReject`] naming the first rule violated, carrying a registered code
/// and nothing drawn from the input.
pub fn decode(input: &[u8]) -> core::result::Result<PairingOffer, OfferReject> {
    // 1. Rule 2. First, before anything looks at a field.
    if input.len() > limits::PAIRING_MAX_OFFER_BYTES {
        return Err(OfferReject::new(
            codes::PROTO_SIZE_EXCEEDED,
            "offer exceeds pairing.max_offer_bytes",
        ));
    }

    // 2. Rule 1, and rule 4's depth and float clauses, which `parse_canonical`
    //    already enforces for every dCBOR payload in the corpus.
    let value = dcbor::parse_canonical(input).map_err(|e| {
        let code = match e {
            dcbor::DcborError::DepthExceeded => codes::PROTO_DEPTH_EXCEEDED,
            dcbor::DcborError::LengthExceedsInput | dcbor::DcborError::ItemsExceeded => {
                codes::PROTO_SIZE_EXCEEDED
            }
            _ => codes::PROTO_NON_CANONICAL_CBOR,
        };
        OfferReject::new(code, e.step())
    })?;

    // 3. Rule 3. Equality, not containment: a missing key and an unknown key are
    //    the same refusal, and neither is "ignored".
    if value.map_keys() != OFFER_KEYS {
        return Err(OfferReject::new(
            codes::PROTO_NON_CANONICAL_CBOR,
            "offer key set is not the seven the schema declares",
        ));
    }

    // 4. The fields.
    let pairing_secret = exact::<32>(&value, 1, "pairing_secret is not 32 bytes")?;

    let ik_pub_cose = bounded(
        &value,
        2,
        1,
        limits::PAIRING_MAX_OFFER_COSE_KEY_BYTES,
        "ik_pub is not a bounded byte string",
    )?;

    let tk_pub = exact::<TK_PUB_BYTES>(&value, 3, "tk_pub is not 32 bytes")?;

    let binding = bounded(
        &value,
        4,
        1,
        limits::PAIRING_MAX_OFFER_BINDING_BYTES,
        "binding is not a bounded byte string",
    )?;

    // Field 5. `pairing.max_offer_attestation_bytes` is 0, so `null` is the only
    // admissible value — and this is the narrowing of ADR-0007 §7.4 that finding
    // F-1 records. Refused by name rather than by a length comparison against
    // zero, so the message a reader sees names the rule and not an arithmetic
    // coincidence.
    if !matches!(value.map_get(5), Some(v) if v.is_null()) {
        return Err(OfferReject::new(
            codes::PROTO_NON_CANONICAL_CBOR,
            "attestation is not null and this channel admits no other value",
        ));
    }

    let rendezvous_hint = match value.map_get(6).and_then(Value::as_text) {
        Some(t) if t.len() <= limits::PAIRING_MAX_OFFER_HINT_BYTES => t.to_owned(),
        _ => {
            return Err(OfferReject::new(
                codes::PROTO_NON_CANONICAL_CBOR,
                "rendezvous_hint is not a bounded text string",
            ))
        }
    };

    let Some(not_after_ms) = value.map_get(7).and_then(Value::as_uint) else {
        return Err(OfferReject::new(
            codes::PROTO_NON_CANONICAL_CBOR,
            "not_after_ms is not a uint",
        ));
    };

    Ok(PairingOffer {
        pairing_secret,
        ik_pub_cose,
        tk_pub,
        binding,
        rendezvous_hint,
        not_after_ms,
    })
}

/// Encoding rule 5 — the receiver owns the window.
///
/// > "A receiver MUST refuse an offer whose window exceeds
/// > `pairing.ceremony_expiry_ms` beyond its own clock … an offer that names its
/// > own longer window is a producer trying to widen a bound the receiver owns."
///
/// So this refuses in **both** directions from one call: an offer already past
/// its own expiry, and an offer reaching further into the future than the
/// ceremony is allowed to last. `now_ms` is the caller's local clock, which is
/// why this is not inside [`decode`] — this crate holds no clock, and the
/// separation keeps the two facts a caller must supply visible.
///
/// # Errors
///
/// [`OfferReject`] carrying `AUTH.PAIRING_EXPIRED` in either direction. The two
/// share a code deliberately: both mean "this offer's window is not one I will
/// honour", and splitting them would tell a producer which side of the bound it
/// missed.
pub const fn check_window(
    offer: &PairingOffer,
    now_ms: u64,
) -> core::result::Result<(), OfferReject> {
    if offer.not_after_ms <= now_ms {
        return Err(OfferReject::new(
            codes::AUTH_PAIRING_EXPIRED,
            "offer window has passed",
        ));
    }
    // `ceremony_expiry_ms` is the whole ceremony's lifetime (120 s), so an offer
    // may not name an expiry further out than that from the receiver's own now.
    if offer.not_after_ms - now_ms > limits::PAIRING_CEREMONY_EXPIRY_MS as u64 {
        return Err(OfferReject::new(
            codes::AUTH_PAIRING_EXPIRED,
            "offer window exceeds pairing.ceremony_expiry_ms",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Emit
// ---------------------------------------------------------------------------

/// Encodes an offer as the deterministic CBOR both out-of-band channels carry.
///
/// Present because encoding rule 1 requires that "two conforming producers MUST
/// emit byte-identical output for the same logical value" — a property nothing
/// can test with a decoder alone. ADR-0023 E1 renders *these bytes* as a QR and
/// E2 renders *these bytes* as Crockford base32, so this is the one function
/// whose output both channels are a view of.
///
/// # Errors
///
/// [`crate::CryptoError::DerivationFailed`] from the emitter, which raises it only for
/// duplicate map keys — impossible here, since the keys are a `const`.
pub fn encode(offer: &PairingOffer) -> Result<Vec<u8>> {
    emit::encode(&Item::Map(vec![
        (Item::Uint(1), Item::Bytes(offer.pairing_secret.to_vec())),
        (Item::Uint(2), Item::Bytes(offer.ik_pub_cose.clone())),
        (Item::Uint(3), Item::Bytes(offer.tk_pub.to_vec())),
        (Item::Uint(4), Item::Bytes(offer.binding.clone())),
        (Item::Uint(5), Item::Null),
        (Item::Uint(6), Item::Text(offer.rendezvous_hint.clone())),
        (Item::Uint(7), Item::Uint(offer.not_after_ms)),
    ]))
}

/// Assembles an offer from its parts, checking every bound the schema declares.
///
/// A producer path, so the bounds are enforced here too rather than only on
/// receipt: an offer this device emits that its peer would refuse is a defect
/// this device should find, not one the peer should report.
///
/// # Errors
///
/// [`OfferReject`], as [`decode`].
pub fn build(
    pairing_secret: [u8; 32],
    ik_pub_cose: Vec<u8>,
    tk_pub: [u8; TK_PUB_BYTES],
    binding: Vec<u8>,
    rendezvous_hint: String,
    not_after_ms: u64,
) -> core::result::Result<PairingOffer, OfferReject> {
    if ik_pub_cose.is_empty() || ik_pub_cose.len() > limits::PAIRING_MAX_OFFER_COSE_KEY_BYTES {
        return Err(OfferReject::new(
            codes::PROTO_SIZE_EXCEEDED,
            "ik_pub exceeds pairing.max_offer_cose_key_bytes",
        ));
    }
    if binding.is_empty() || binding.len() > limits::PAIRING_MAX_OFFER_BINDING_BYTES {
        return Err(OfferReject::new(
            codes::PROTO_SIZE_EXCEEDED,
            "binding exceeds pairing.max_offer_binding_bytes",
        ));
    }
    if rendezvous_hint.len() > limits::PAIRING_MAX_OFFER_HINT_BYTES {
        return Err(OfferReject::new(
            codes::PROTO_SIZE_EXCEEDED,
            "rendezvous_hint exceeds pairing.max_offer_hint_bytes",
        ));
    }
    Ok(PairingOffer {
        pairing_secret,
        ik_pub_cose,
        tk_pub,
        binding,
        rendezvous_hint,
        not_after_ms,
    })
}

// ---------------------------------------------------------------------------
// E2 — the text offer
// ---------------------------------------------------------------------------

/// Renders an offer as ADR-0023 EM-22 **E2**'s text form.
///
/// > "`twinvpn pair begin --text` renders **the same dCBOR bytes** as Crockford
/// > base32 in groups of eight, for copy-paste into the admin device."
///
/// *The same bytes* is the whole of it: this is [`encode`] followed by
/// [`twinvpn_types::crockford::encode_groups`], and nothing in between. E1's QR
/// and E2's text are two views of one encoding, which is why encoding rule 1
/// demands byte-identical output from conforming producers — a QR and a paste of
/// the same offer must reach the same peer state.
///
/// E2 is not a lesser channel. EM-21: C-B "does not require a camera; it requires
/// a confidential channel", and a pasted block over SSH is one. It carries the
/// same 256 bits as the QR.
///
/// # Errors
///
/// As [`encode`].
pub fn render_text(offer: &PairingOffer) -> Result<String> {
    Ok(twinvpn_types::crockford::encode_groups(
        &encode(offer)?,
        twinvpn_types::crockford::E2_GROUP,
    ))
}

/// Parses an E2 text offer back to an offer.
///
/// The bound handed to the base32 decoder is `pairing.max_offer_bytes`, so
/// encoding rule 2's "checked FIRST, BEFORE ANY FIELD IS PARSED" holds on this
/// path too — an over-long paste is refused before a buffer grows to hold it,
/// and before [`decode`] sees a byte.
///
/// # Errors
///
/// [`OfferReject`]. A base32 failure is reported as `PROTO.NON_CANONICAL_CBOR`
/// rather than as its own condition: from the operator's side "the text you
/// pasted is not an offer" is one fact, and the CDDL allows exactly one sentence
/// about a failed decode.
pub fn parse_text(text: &str) -> core::result::Result<PairingOffer, OfferReject> {
    let bytes = twinvpn_types::crockford::decode(text, limits::PAIRING_MAX_OFFER_BYTES).map_err(
        |e| match e {
            twinvpn_types::crockford::CrockfordError::TooLong => OfferReject::new(
                codes::PROTO_SIZE_EXCEEDED,
                "text offer exceeds pairing.max_offer_bytes",
            ),
            _ => OfferReject::new(
                codes::PROTO_NON_CANONICAL_CBOR,
                "text offer is not Crockford base32",
            ),
        },
    )?;
    decode(&bytes)
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

fn exact<const N: usize>(
    value: &Value,
    key: u64,
    check: &'static str,
) -> core::result::Result<[u8; N], OfferReject> {
    let bytes = value
        .map_get(key)
        .and_then(Value::as_bytes)
        .filter(|b| b.len() == N)
        .ok_or_else(|| OfferReject::new(codes::PROTO_NON_CANONICAL_CBOR, check))?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn bounded(
    value: &Value,
    key: u64,
    min: usize,
    max: usize,
    check: &'static str,
) -> core::result::Result<Vec<u8>, OfferReject> {
    value
        .map_get(key)
        .and_then(Value::as_bytes)
        .filter(|b| b.len() >= min && b.len() <= max)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| OfferReject::new(codes::PROTO_NON_CANONICAL_CBOR, check))
}
