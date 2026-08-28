//! Received octets, kept verbatim.
//!
//! **Authority:** `contracts/proto/twinvpn/v1/identity.proto` (`SignedStatement`:
//! "the signature MUST be verified over the RECEIVED OCTETS; an implementation
//! MUST NOT re-serialize before verifying"), `contracts/docs/trust-boundaries.md`
//! §3, `contracts/docs/phase1-conflicts.md` CF-2, `core/README.md` §8.
//!
//! # Why this type exists at all
//!
//! `prost` 0.13 **drops unknown protobuf fields** — measured by `core-foundation`
//! in `unknown_fields_are_dropped_by_prost_0_13`. ADR-0003 §11 B1 requires a
//! component that *forwards* a message it does not fully understand to preserve
//! and forward unknown fields. `prost` cannot, so the only correct forwarding
//! primitive available to this crate is **forward the bytes you received**.
//!
//! [`ReceivedOctets`] is that primitive. It is produced only from a wire read,
//! it hands out a `&[u8]` and an owned `Vec<u8>` that are *the same bytes*, and
//! it has no constructor that takes a decoded message — so
//! `encode(decode(bytes))` is not a thing a caller can accidentally write where
//! `bytes` were required.
//!
//! # Where this crate forwards
//!
//! Three places, all of them B2 signed statements:
//!
//! | Carrier | Forwarded to | Why verbatim |
//! |---|---|---|
//! | `DeviceRevoked.revocation_entry` / `.trust_epoch_bundle` | the local store, and peer-to-peer carriage (protocol.md §16 rows 37, 45) | a re-encoded COSE_Sign1 stops verifying, and a device that cannot verify a revocation keeps trusting a stolen laptop |
//! | `PolicyBundleUpdated.bundle.signed`, `GetStateDocumentResponse.document` | the local store; enforcement reads the verified payload | `policy.proto`: "the decoded fields above are a VIEW … until `signed` verifies, every field in this message is attacker-controlled" |
//! | `RouteAdvertised` / `ExitNodeAdvertised` inner `SignedStatement` | the local store | device-authored; coordination warehouses what it cannot forge |
//!
//! In every one of them the transported artifact is already an opaque `bytes`
//! field, so `prost`'s unknown-field loss does not touch the signed payload —
//! it would only touch the protobuf *wrapper*, which this crate never forwards.

use core::fmt;

/// Bytes exactly as they arrived, with no decode/encode round trip between.
///
/// `Debug` prints the length and a digest-free marker: a signed statement is not
/// secret, but dumping one into a log turns a support bundle into a replay
/// corpus, and `ownership.md` §6 rule 11 is unambiguous about what must never be
/// logged.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReceivedOctets(Vec<u8>);

impl ReceivedOctets {
    /// Captures the bytes read off a wire.
    ///
    /// The only constructor. There is deliberately no
    /// `from_message(&impl prost::Message)`: that is precisely the
    /// decode-then-re-encode path CF-2 forbids for anything forwarded.
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Captures owned bytes read off a wire.
    #[must_use]
    pub fn from_wire_owned(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The octets, for verification or for forwarding.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// The octets, for forwarding into a store record.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// How many octets. Cheap, and the only thing safe to log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no octets at all — always a malformed statement.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ReceivedOctets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReceivedOctets(<{} B verbatim>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::ReceivedOctets;

    #[test]
    fn octets_survive_a_round_trip_through_the_type() {
        let raw = vec![0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26];
        let held = ReceivedOctets::from_wire(&raw);
        assert_eq!(held.as_slice(), raw.as_slice());
        assert_eq!(held.clone().into_vec(), raw);
        assert_eq!(held.len(), 6);
        assert!(!held.is_empty());
    }

    #[test]
    fn debug_does_not_render_the_payload() {
        let held = ReceivedOctets::from_wire(&[0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{held:?}");
        assert!(rendered.contains("4 B verbatim"));
        assert!(!rendered.contains("de"));
        assert!(!rendered.contains("222"));
    }
}
