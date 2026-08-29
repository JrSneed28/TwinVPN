//! Strongly-typed identifiers, one per row of `contracts/docs/identifiers.md`.
//!
//! **Authority:** `contracts/docs/identifiers.md` (generation authority,
//! uniqueness scope, opacity, reuse, meaning), `contracts/registry/limits.json`
//! §`identifiers` (the exact widths), `contracts/proto/twinvpn/v1/common.proto`.
//!
//! # What the type system carries, and why
//!
//! Four registry facts are encoded as associated constants on [`Identifier`], so
//! they are readable at a call site and assertable in a test rather than living
//! only in a table a reviewer has to remember:
//!
//! | Fact | Type-level form | The defect it prevents |
//! |---|---|---|
//! | Exact width | a distinct newtype over `[u8; N]`; the constructor is the only way in | truncation or padding silently converting one identifier into another (`identifiers.md` §5) |
//! | Uniqueness scope | [`IdScope`] | a process-scoped `TunnelId` used where a globally unique value is required — the two are unrelated bit-bags with no overlap in meaning |
//! | Opacity | [`Opacity`] and the **absence of `Display`** | a UI rendering an opaque bag of bits as if it meant something |
//! | Classification | [`FieldClassification`] driving `Debug` | a `SENSITIVE` identifier reaching a log through a derived `Debug` |
//!
//! # No `Display` on an opaque identifier
//!
//! Nothing here implements `Display`. An opaque identifier has no presentation
//! form, so offering one invites a surface to render it; the two identifiers that
//! *do* have a text form — `device_id` and `identity_id` — expose it as an
//! explicitly named method ([`DeviceId::text_form`], [`DeviceId::fingerprint`])
//! precisely so that rendering is a decision somebody made rather than a
//! formatter that happened to fire. `identifiers.md` §2 makes the text form "a
//! presentation form only" that "appears in no field of this contract set".
//!
//! # `Debug` is classification-driven
//!
//! ADR-0015 §11.4 classifies peer identifiers `SENSITIVE` — "pseudonymized in a
//! Tier-1 bundle; NEVER in Tier 2". A derived `Debug` would put the full value
//! into any `tracing` call that formats the surrounding struct, which is
//! `ownership.md` §6 rule 11's failure mode. So `SENSITIVE` identifiers print
//! `DeviceId(<32 B redacted>)` and expose their bytes only through
//! [`Identifier::as_bytes`] and [`Identifier::to_hex`]. `OPERATIONAL`
//! identifiers — the three envelope-correlation ids that rule 6 requires to be
//! preserved across every component boundary — print their hex, because a trace
//! that cannot show them cannot do its job.

use core::fmt;

use crate::error::TypeError;

/// ADR-0015 §11.4 field classification.
///
/// Mirrors `twinvpn.v1.FieldClassification`, **including the deliberate absence
/// of a `SECRET` value**: ADR-0015 §11.4 says secret material is "never stored,
/// never rendered, no code path exists", and giving it an enum value would
/// create the code path. A field that would have to be classified secret must
/// not be constructed at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldClassification {
    /// Carries no user-identifying information.
    Public = 1,
    /// Timing, states, counters, coarse categories.
    Operational = 2,
    /// Endpoints, addresses, interface names, `DeviceIdentity`, peer
    /// identifiers, hostnames, SSIDs.
    Sensitive = 3,
}

impl FieldClassification {
    /// The stricter of two classifications.
    ///
    /// `errors.proto`: "A receiver MUST honour the STRICTER of this and its own
    /// registry entry." Strictness is the enum's own order.
    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        if (self as u8) >= (other as u8) {
            self
        } else {
            other
        }
    }
}

/// The scope within which an identifier is unique (`identifiers.md` §1).
///
/// Distinct scopes are not comparable and not convertible. A `PathId` is unique
/// within one `Tunnel` in one process; treating it as globally unique is how two
/// unrelated paths come to look like the same path in a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum IdScope {
    /// Collision-resistant globally.
    Global,
    /// Unique within one `TwinNet`.
    TwinNet,
    /// Unique within one operator's relay fleet.
    OperatorFleet,
    /// Unique within one local process; **reused after that process exits**.
    Process,
    /// Unique within one `Tunnel` in one process.
    Tunnel,
    /// Unique within one establishment attempt.
    EstablishmentAttempt,
    /// Unique within one relay and one ten-minute bucket; rotates per bucket.
    RelayBucket,
    /// Unique within one emitter.
    Emitter,
    /// Unique within `(device_id, key)`.
    CallerKeyed,
}

/// Whether an identifier means anything to anybody who holds it
/// (`identifiers.md` §1, "the default is opaque").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opacity {
    /// A bag of bits whose only property is equality.
    Opaque,
    /// Structurally meaningful and self-certifying — `device_id`, `identity_id`,
    /// `pairing_id`. Phase 1 makes exactly these meaningful, deliberately.
    SelfCertifying,
}

/// Whether an identifier's value may ever name a second thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reuse {
    /// Never, under any circumstance, including after expiry or cancellation.
    Never,
    /// Not within the scope named by [`Identifier::SCOPE`]; a new scope may
    /// reuse the value.
    NotWithinScope,
    /// Rotates on a schedule; a later value replaces an earlier one.
    Rotates,
}

/// The registry facts every identifier carries.
///
/// Implemented by every type in this module. `twinvpn-schema` asserts these
/// constants against `contracts/registry/limits.json`, so a width here that
/// disagrees with the frozen registry fails the build rather than a wire
/// exchange.
pub trait Identifier: Sized {
    /// The identifier's key in `limits.json` §`identifiers`.
    const REGISTRY_KEY: &'static str;
    /// Uniqueness scope (`identifiers.md` §1).
    const SCOPE: IdScope;
    /// Whether it means anything to a holder.
    const OPACITY: Opacity;
    /// Whether its value may ever name a second thing.
    const REUSE: Reuse;
    /// ADR-0015 §11.4 classification, which drives `Debug`.
    const CLASSIFICATION: FieldClassification;

    /// The identifier's bytes.
    fn as_bytes(&self) -> &[u8];

    /// Lower-case hex, allocated on demand.
    ///
    /// Deliberately a method and not `Display`: for a `SENSITIVE` identifier this
    /// is the redaction-bypassing path, and it should be visible at the call
    /// site of anything that logs or renders.
    fn to_hex(&self) -> String {
        let bytes = self.as_bytes();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }
}

/// Declares a fixed-width binary identifier.
macro_rules! fixed_id {
    (
        $(#[$meta:meta])*
        $name:ident, $width:expr, $key:literal, $scope:expr, $opacity:expr, $reuse:expr, $class:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $width]);

        impl $name {
            /// The exact width `contracts/registry/limits.json` declares.
            pub const WIDTH: usize = $width;

            /// Builds from an exact-width array. Infallible: the width is the type.
            #[must_use]
            pub const fn from_array(bytes: [u8; $width]) -> Self {
                Self(bytes)
            }

            /// Builds from a wire slice, validating the width.
            ///
            /// A length mismatch is rejected, never truncated and never padded
            /// (`identifiers.md` §5).
            pub fn from_slice(bytes: &[u8]) -> Result<Self, TypeError> {
                if bytes.len() != $width {
                    return Err(TypeError::IdentifierLength {
                        kind: $key,
                        expected: $width,
                        observed: bytes.len(),
                    });
                }
                let mut out = [0u8; $width];
                out.copy_from_slice(bytes);
                Ok(Self(out))
            }

            /// The identifier as a fixed-width array.
            #[must_use]
            pub const fn to_array(self) -> [u8; $width] {
                self.0
            }
        }

        impl Identifier for $name {
            const REGISTRY_KEY: &'static str = $key;
            const SCOPE: IdScope = $scope;
            const OPACITY: Opacity = $opacity;
            const REUSE: Reuse = $reuse;
            const CLASSIFICATION: FieldClassification = $class;

            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                debug_identifier(f, stringify!($name), Self::CLASSIFICATION, &self.0)
            }
        }
    };
}

/// One `Debug` policy for every identifier, driven by its classification.
fn debug_identifier(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    class: FieldClassification,
    bytes: &[u8],
) -> fmt::Result {
    match class {
        FieldClassification::Sensitive => {
            write!(f, "{name}(<{} B redacted>)", bytes.len())
        }
        FieldClassification::Public | FieldClassification::Operational => {
            write!(f, "{name}(")?;
            for b in bytes {
                write!(f, "{b:02x}")?;
            }
            f.write_str(")")
        }
    }
}

fixed_id!(
    /// `device_id` — SHA-256 of the generation-0 identity key.
    ///
    /// **Self-certifying, never reused, stable across rotation.** Verifiable
    /// offline by any peer with no lookup and no authority, which is what lets
    /// two paired devices re-establish a `Session` with the control plane down
    /// (I5, R-11). `RegisterDeviceResp.device_id_echo` is an **echo, never an
    /// assignment**: a device compares it against its own derivation and aborts
    /// with `AUTH.IDENTITY_MISMATCH` on disagreement.
    DeviceId, 32, "device_id_bytes",
    IdScope::Global, Opacity::SelfCertifying, Reuse::Never, FieldClassification::Sensitive
);

fixed_id!(
    /// `identity_id` — SHA-256 of *this generation's* identity key.
    ///
    /// An attribute of the current `DeviceIdentity`, not a separate resource with
    /// its own lifecycle (`identifiers.md` §3). A rotation creates a new
    /// `identity_id` at `generation + 1` and leaves `device_id` unchanged.
    IdentityId, 32, "identity_id_bytes",
    IdScope::Global, Opacity::SelfCertifying, Reuse::Never, FieldClassification::Sensitive
);

fixed_id!(
    /// `pairing_id` — `SHA-256(pairing_secret)[0..15]`, derived by the **joining
    /// device** and carried to the coordination service, never minted by it.
    ///
    /// Single-use and **never reissued, not even after expiry or cancellation**:
    /// reissuing would reset the five-attempt budget ADR-0007 N-17 relies on to
    /// make a nine-digit code safe.
    PairingId, 16, "pairing_id_bytes",
    IdScope::TwinNet, Opacity::SelfCertifying, Reuse::Never, FieldClassification::Sensitive
);

fixed_id!(
    /// `session_id` — a UUIDv7 minted by the initiating device.
    SessionId, 16, "session_id_bytes",
    IdScope::Global, Opacity::Opaque, Reuse::Never, FieldClassification::Sensitive
);

fixed_id!(
    /// `tunnel_id` — local to one process, and **reused across processes**.
    ///
    /// Scope [`IdScope::Process`] is the load-bearing fact: a `TunnelId` from a
    /// previous run of the daemon names nothing in this one.
    TunnelId, 16, "tunnel_id_bytes",
    IdScope::Process, Opacity::Opaque, Reuse::NotWithinScope, FieldClassification::Operational
);

fixed_id!(
    /// `path_id` — unique within one `Tunnel` in one process.
    PathId, 8, "path_id_bytes",
    IdScope::Tunnel, Opacity::Opaque, Reuse::NotWithinScope, FieldClassification::Operational
);

fixed_id!(
    /// `candidate_id` — unique within one establishment attempt.
    CandidateId, 8, "candidate_id_bytes",
    IdScope::EstablishmentAttempt, Opacity::Opaque, Reuse::NotWithinScope,
    FieldClassification::Operational
);

fixed_id!(
    /// `relay_id` — minted by the relay-fleet operator; **never reused after
    /// retirement**.
    RelayId, 8, "relay_id_bytes",
    IdScope::OperatorFleet, Opacity::Opaque, Reuse::Never, FieldClassification::Operational
);

fixed_id!(
    /// `pair_tag` — `HKDF-Expand(RelayPairKey, "tag" || relay_id || bucket, 16)`.
    ///
    /// One-way, scoped to one `relay_id` and one ten-minute bucket, and it
    /// **rotates every bucket**. A tag observed at one relay is useless at
    /// another, which is what a `peer_key_id` field would have destroyed
    /// (`docs/protocol.md` §16 row 21, withdrawn).
    PairTag, 16, "pair_tag_bytes",
    IdScope::RelayBucket, Opacity::Opaque, Reuse::Rotates, FieldClassification::Sensitive
);

fixed_id!(
    /// `message_id` — a UUIDv7, unique **per emission**, including per
    /// retransmission of a logically identical request.
    ///
    /// A retry reuses `idempotency_key` and never this. That separation is what
    /// lets diagnostics distinguish "the client retried once" from "the network
    /// duplicated it".
    MessageId, 16, "message_id_bytes",
    IdScope::Emitter, Opacity::Opaque, Reuse::Never, FieldClassification::Operational
);

fixed_id!(
    /// `correlation_id` — "what is this a reply to?"; a copy of the request's
    /// `message_id`. `ownership.md` §6 rule 6 requires it to be preserved across
    /// every component boundary.
    CorrelationId, 16, "correlation_id_bytes",
    IdScope::Emitter, Opacity::Opaque, Reuse::NotWithinScope, FieldClassification::Operational
);

fixed_id!(
    /// `causation_id` — "what made this happen?"; the `message_id` of the message
    /// whose *processing* produced this one.
    ///
    /// Never invented and **never inherited transitively**: a causation chain is
    /// reconstructed one link at a time, which is what keeps it a chain rather
    /// than a claim.
    CausationId, 16, "causation_id_bytes",
    IdScope::Emitter, Opacity::Opaque, Reuse::NotWithinScope, FieldClassification::Operational
);

fixed_id!(
    /// A SHA-256 digest carried as an identity — `schema_digest` and the like.
    Digest, 32, "digest_bytes",
    IdScope::Global, Opacity::SelfCertifying, Reuse::NotWithinScope,
    FieldClassification::Operational
);

fixed_id!(
    /// `session_nonce` — minted by the initiator, one establishment.
    SessionNonce, 16, "session_nonce_bytes",
    IdScope::EstablishmentAttempt, Opacity::Opaque, Reuse::Never,
    FieldClassification::Operational
);

impl DeviceId {
    /// The presentation text form: `"twd1" || base32-lower-nopad(device_id)`.
    ///
    /// **A presentation form only.** `identifiers.md` §2: it "appears in no field
    /// of this contract set" except `MessageMetadata.sender_id`, which carries
    /// either a device text form or a fixed infrastructure principal name. Never
    /// parse a `DeviceId` back out of a rendered string in a decision path.
    #[must_use]
    pub fn text_form(&self) -> String {
        let mut s = String::with_capacity(4 + 52);
        s.push_str("twd1");
        s.push_str(&base32_lower_nopad(&self.0));
        s
    }

    /// The human fingerprint: the leading 100 bits in Crockford base32, five
    /// groups of four.
    ///
    /// Two rules travel with this value and neither is enforceable here, so both
    /// are stated: a UI **MUST** render all twenty characters and **MUST NOT**
    /// offer a truncated comparison; and the fingerprint **MUST NOT be a trust
    /// decision input** — trust comes from the pairing ceremony, not from a human
    /// comparing strings.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        // The alphabet is `crockford::ALPHABET`'s, not a second copy: ADR-0023
        // E2 renders the pairing offer in the same one, and two spellings of an
        // alphabet is how two renderings of one identifier come to disagree.
        // The *grouping* differs on purpose — four here, eight for E2 — so only
        // the alphabet is shared.
        use crate::crockford::ALPHABET as CROCKFORD;
        let mut out = String::with_capacity(24);
        for i in 0..20 {
            let bit = i * 5;
            let byte = bit / 8;
            let shift = bit % 8;
            let mut v = u16::from(self.0[byte]) << 8;
            if byte + 1 < self.0.len() {
                v |= u16::from(self.0[byte + 1]);
            }
            let idx = ((v >> (11 - shift)) & 0x1f) as usize;
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(char::from(CROCKFORD[idx]));
        }
        out
    }
}

impl IdentityId {
    /// The generation-0 `identity_id` **is** the `device_id` (`identifiers.md`
    /// §2). This is the only sanctioned conversion between the two, and it is
    /// deliberately explicit rather than a `From` impl.
    #[must_use]
    pub const fn as_generation_zero_device_id(self) -> DeviceId {
        DeviceId(self.0)
    }
}

fn base32_lower_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((acc >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize]));
    }
    out
}
