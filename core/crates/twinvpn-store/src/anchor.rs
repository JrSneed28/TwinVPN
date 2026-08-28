//! `StoreAntiRollbackAnchor` (S-53) — ST-21, ST-22 and the ST-24 classification.
//!
//! **Authority:** ADR-0020 ST-21, ST-22, ST-23, ST-24, §11.7; ADR-0018 CB-7
//! (the anchor is a Tier-1 item, reached through `SecureStore`).
//!
//! # ST-22, and why it is called load-bearing
//!
//! > "ANCH MUST be stored in the **same Tier-1 backend, under the same custody
//! > class and the same accessibility class, as the `DeviceIdentityKey`.** This
//! > converts 'delete or roll back the anchor' into 'delete or roll back the
//! > identity', whose consequence is already specified and safe:
//! > `AUTH.IDENTITY_MISSING` ⇒ re-enrolment. **Without ST-22, an attacker could
//! > strip the anchor and keep a working identity, which is strictly the best
//! > case for them.**"
//!
//! Co-location is the shell's to provide — the core reaches Tier 1 only through
//! [`twinvpn_platform::SecureStore`], and which backend that is is a shell
//! decision. What this module can do, and does, is make the *consequence*
//! correct: [`AnchorState::classify`] maps "anchor absent, identity present" and
//! "anchor absent, identity absent" onto the two different outcomes ST-24's
//! table requires, so a shell that got the co-location wrong produces a
//! recoverable state rather than a silent one.
//!
//! # The 512-byte cap, and a tension this module resolves explicitly
//!
//! ST-21 says the anchor is "a Tier-1 item of ≤ 512 bytes" and that `floors` is
//! the whole table of §11.7 — which includes **per-peer** `generation` and
//! `tk_generation`. A TwinNet with twenty peers has forty per-peer floors, and
//! forty entries keyed by a 64-character hex name do not fit in 512 bytes.
//!
//! The resolution, taken here and reported as an ADR-0020 §11.7/ST-21
//! under-specification:
//!
//! - `floor_digest` is computed over the **complete** floor set, always. It is
//!   what detects a change to any floor, including a per-peer one.
//! - `floors` carries the **fixed** floors explicitly — the ones ST-25 calls
//!   trust floors and the ones ST-24 must be able to *restore* from Tier 1 alone
//!   after an L3 rebuild — and elides per-peer entries once the cap is reached.
//! - An elided floor is therefore *detected* but not *restorable* from Tier 1.
//!   That is the honest position: after an L3 rebuild the per-peer generation
//!   floors are re-established from the peer's own next `DeviceIdentityRecord`,
//!   whose `generation` is itself monotone at the source, and the fixed trust
//!   floors — the ones that gate authority — do survive.

use twinvpn_crypto::dcbor;
use twinvpn_crypto::emit::{encode, Item};
use twinvpn_crypto::sha256;

use crate::error::{Result, StoreError};
use crate::floors::{FloorId, FloorSet};

/// The Tier-1 item name for the anchor.
pub const ANCHOR_ITEM: &str = "twinvpn.store.anchor";
/// The Tier-1 item name for the store encryption key.
pub const SEK_ITEM: &str = "twinvpn.store.sek";

/// ST-21's size cap on the Tier-1 item.
pub const MAX_ANCHOR_BYTES: usize = 512;

/// `store_id`'s width.
pub const STORE_ID_LEN: usize = 16;

/// The anchor, as ST-21 defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// Identifies this vault; also the HKDF salt of §11.6.
    pub store_id: [u8; STORE_ID_LEN],
    /// The strictly increasing vault commit counter.
    pub store_seq: u64,
    /// Digest of the committed vault at `store_seq`.
    pub vault_digest: [u8; 32],
    /// The floors, as many as the cap admits. See the module documentation.
    pub floors: FloorSet,
    /// Digest over the **complete** floor set.
    pub floor_digest: [u8; 32],
}

impl Anchor {
    /// Builds an anchor for a floor set and a vault digest.
    #[must_use]
    pub fn new(
        store_id: [u8; STORE_ID_LEN],
        store_seq: u64,
        vault_digest: [u8; 32],
        floors: &FloorSet,
    ) -> Self {
        Self {
            store_id,
            store_seq,
            vault_digest,
            floors: floors.clone(),
            floor_digest: floor_digest(floors),
        }
    }

    /// Encodes the anchor as deterministic CBOR, eliding per-peer floors if
    /// necessary to fit [`MAX_ANCHOR_BYTES`].
    ///
    /// `floor_digest` is always over the complete set, so an elision is
    /// detectable rather than silent.
    ///
    /// # Errors
    ///
    /// [`StoreError::CryptoInvariant`] if even the fixed floors do not fit,
    /// which would mean the fixed floor set itself had grown past the Tier-1
    /// item cap — a schema event, not a runtime condition.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Fixed floors first: these are the ones ST-24 restores from.
        let mut entries: Vec<(FloorId, u64)> = self
            .floors
            .pairs()
            .filter(|(id, _)| !is_per_peer(id))
            .map(|(id, v)| (id.clone(), v))
            .collect();
        let per_peer: Vec<(FloorId, u64)> = self
            .floors
            .pairs()
            .filter(|(id, _)| is_per_peer(id))
            .map(|(id, v)| (id.clone(), v))
            .collect();

        let mut bytes = self.encode_with(&entries)?;
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(StoreError::CryptoInvariant {
                invariant: "the fixed floor set exceeds the Tier-1 anchor cap",
            });
        }
        for e in per_peer {
            entries.push(e);
            let candidate = self.encode_with(&entries)?;
            if candidate.len() > MAX_ANCHOR_BYTES {
                entries.pop();
                break;
            }
            bytes = candidate;
        }
        Ok(bytes)
    }

    fn encode_with(&self, entries: &[(FloorId, u64)]) -> Result<Vec<u8>> {
        let floors = Item::Map(
            entries
                .iter()
                .map(|(id, v)| (Item::Text(id.name()), Item::Uint(*v)))
                .collect(),
        );
        encode(&Item::Map(vec![
            (Item::Uint(1), Item::Bytes(self.store_id.to_vec())),
            (Item::Uint(2), Item::Uint(self.store_seq)),
            (Item::Uint(3), Item::Bytes(self.vault_digest.to_vec())),
            (Item::Uint(4), floors),
            (Item::Uint(5), Item::Bytes(self.floor_digest.to_vec())),
        ]))
        .map_err(Into::into)
    }

    /// Decodes an anchor from its Tier-1 item bytes.
    ///
    /// Parsed as **canonical** CBOR: an attacker who can write Tier 1 can also
    /// write a second encoding of one anchor, and accepting both would make
    /// `floor_digest` comparisons meaningless.
    ///
    /// # Errors
    ///
    /// [`StoreError::AnchorMismatch`] with `store_seq` zero if the item is not a
    /// well-formed anchor — a malformed anchor is not "absent", and treating it
    /// as absent would let an attacker downgrade a tamper into a rebuild.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bad = StoreError::AnchorMismatch { store_seq: 0 };
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(bad);
        }
        let v = dcbor::parse_canonical(bytes).map_err(|_| bad.clone())?;
        if v.map_keys() != vec![1, 2, 3, 4, 5] {
            return Err(bad);
        }
        let store_id: [u8; STORE_ID_LEN] = v
            .map_get(1)
            .and_then(dcbor::Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad.clone())?;
        let store_seq = v
            .map_get(2)
            .and_then(dcbor::Value::as_uint)
            .ok_or_else(|| bad.clone())?;
        let vault_digest: [u8; 32] = v
            .map_get(3)
            .and_then(dcbor::Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad.clone())?;
        let floor_digest: [u8; 32] = v
            .map_get(5)
            .and_then(dcbor::Value::as_bytes)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad.clone())?;

        let dcbor::Value::Map(raw) = v.map_get(4).ok_or_else(|| bad.clone())? else {
            return Err(bad);
        };
        let mut floors = Vec::with_capacity(raw.len());
        for (k, val) in raw {
            let name = k.as_text().ok_or_else(|| bad.clone())?;
            let value = val.as_uint().ok_or_else(|| bad.clone())?;
            floors.push((parse_floor_id(name).ok_or_else(|| bad.clone())?, value));
        }
        Ok(Self {
            store_id,
            store_seq,
            vault_digest,
            floors: FloorSet::from_pairs(floors),
            floor_digest,
        })
    }
}

fn is_per_peer(id: &FloorId) -> bool {
    matches!(
        id,
        FloorId::PeerGeneration(_) | FloorId::PeerTkGeneration(_)
    )
}

/// The digest over a complete floor set.
///
/// Deterministic: [`FloorSet`] is a `BTreeMap`, so the iteration order is the
/// floor id's own order, and two devices holding the same floors compute the
/// same digest.
#[must_use]
pub fn floor_digest(floors: &FloorSet) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"TwinVPN/store/floors/v1");
    for (id, v) in floors.pairs() {
        let name = id.name();
        // Length-prefixed for the same reason the record AAD is: a bare
        // concatenation of variable-length names is ambiguous.
        buf.extend_from_slice(&u32::try_from(name.len()).unwrap_or(u32::MAX).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&v.to_be_bytes());
    }
    sha256(&buf)
}

fn parse_floor_id(name: &str) -> Option<FloorId> {
    match name {
        "trust_epoch" => Some(FloorId::TrustEpoch),
        "min_acceptable_epoch" => Some(FloorId::MinAcceptableEpoch),
        "anchor_version" => Some(FloorId::AnchorVersion),
        "contract_seq" => Some(FloorId::ContractSeq),
        "negotiation_floor_digest" => Some(FloorId::NegotiationFloorDigest),
        "store_seq" => Some(FloorId::StoreSeq),
        other => {
            if let Some(hex) = other.strip_prefix("generation:") {
                unhex(hex).map(FloorId::PeerGeneration)
            } else if let Some(hex) = other.strip_prefix("tk_generation:") {
                unhex(hex).map(FloorId::PeerTkGeneration)
            } else {
                // A `doc_version:` floor names a `&'static str` document type,
                // which cannot be reconstructed from an arbitrary string
                // without admitting one this build does not know. Refusing is
                // the conservative direction: an unknown floor name means the
                // anchor was written by a build this one cannot fully read, and
                // reading it partially would drop a floor.
                other.strip_prefix("doc_version:").and_then(doc_type)
            }
        }
    }
}

/// The document types that carry a high-water mark (ADR-0009 R-5, R-7, and
/// `policy.proto`'s `StateDocumentType`).
const DOC_TYPES: &[&str] = &[
    "POLICY_BUNDLE",
    "OWNER_TRUST_ANCHOR",
    "TRUST_EPOCH_BUNDLE",
    "RELAY_MAP",
    "RELAY_EPOCH_FLOOR",
    "NETWORK_CONTRACT",
    "MEMBERSHIP",
    "TRUST_LIST",
];

fn doc_type(name: &str) -> Option<FloorId> {
    DOC_TYPES
        .iter()
        .find(|t| **t == name)
        .map(|t| FloorId::DocVersion(t))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// What ST-24 concluded from the anchor and the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorState {
    /// `anchor.store_seq == vault.store_seq`, digests match.
    Healthy,
    /// `anchor.store_seq > vault.store_seq` — the vault was rolled back or
    /// crash-truncated. Floors come from the anchor.
    VaultRolledBack {
        /// The anchor's sequence.
        anchor_seq: u64,
        /// The vault's sequence.
        vault_seq: u64,
        /// Whether the gap is exactly one, which is what a crash between ST-23
        /// steps 3 and 5 produces.
        crash_recovery: bool,
    },
    /// Equal sequence, differing digests — tamper or fork. **Fatal.**
    Forked {
        /// The sequence both claim.
        store_seq: u64,
    },
    /// `anchor.store_seq < vault.store_seq` — the anchor lost an update. Floors
    /// become `max(anchor, vault)`.
    AnchorBehind {
        /// The anchor's sequence.
        anchor_seq: u64,
        /// The vault's sequence.
        vault_seq: u64,
    },
    /// The anchor is absent while the identity is present, **and a vault
    /// exists**. ST-24 row 5: the anchor was lost independently, which is
    /// possible on a platform that re-provisions secure storage. Floors are
    /// unverified and granted authority is suspended.
    AnchorMissingIdentityPresent,
    /// Neither anchor nor vault exists: this device has never committed.
    ///
    /// **Not** ST-24 row 5, and the distinction matters. Row 5 is about an
    /// anchor that went missing while a vault survived — a state in which the
    /// vault's floors cannot be trusted and authority must be suspended. A first
    /// run has no floors *at all*, so there is nothing unverified and nothing to
    /// suspend; suspending here would make every fresh enrolment start
    /// degraded, which is not what ST-24 says and would be a bad first
    /// experience with no security benefit.
    FirstRun,
    /// Both are absent: a restored image or a re-provisioned device.
    AnchorAndIdentityMissing,
    /// The vault is absent while the anchor is present: a reinstall that
    /// preserved secure storage. **The normal reinstall path**, and not an
    /// error — §11.8.
    VaultAbsent,
}

impl AnchorState {
    /// ST-24's classification.
    ///
    /// `identity_present` comes from `IdentityCustody::public_identity`
    /// succeeding, which the caller performs — this crate never touches identity
    /// material (CB-5).
    #[must_use]
    pub fn classify(
        anchor: Option<&Anchor>,
        vault: Option<(u64, [u8; 32])>,
        identity_present: bool,
    ) -> Self {
        match (anchor, vault) {
            (None, _) if !identity_present => AnchorState::AnchorAndIdentityMissing,
            (None, None) => AnchorState::FirstRun,
            (None, Some(_)) => AnchorState::AnchorMissingIdentityPresent,
            (Some(_), None) => AnchorState::VaultAbsent,
            (Some(a), Some((seq, digest))) => {
                if a.store_seq > seq {
                    AnchorState::VaultRolledBack {
                        anchor_seq: a.store_seq,
                        vault_seq: seq,
                        // ST-23 advances the anchor to `store_seq + 1` before
                        // the vault commits, so a gap of exactly one is what a
                        // crash between steps 3 and 5 leaves. A larger gap is
                        // not explicable as a crash.
                        crash_recovery: a.store_seq == seq + 1,
                    }
                } else if a.store_seq < seq {
                    AnchorState::AnchorBehind {
                        anchor_seq: a.store_seq,
                        vault_seq: seq,
                    }
                } else if a.vault_digest == digest {
                    AnchorState::Healthy
                } else {
                    AnchorState::Forked {
                        store_seq: a.store_seq,
                    }
                }
            }
        }
    }

    /// Whether granted authority must be suspended in this state.
    ///
    /// ST-24 and §11.11 L4/L5: an unverified or rolled-back floor set suspends
    /// **granted** authority — exit use, LAN access, route acceptance, new
    /// pairing — until a fresh signed document at or above the floors verifies.
    /// It never refuses a handshake to a known peer and never tears down a
    /// session (ST-35, I5, R-11).
    #[must_use]
    pub const fn suspends_granted_authority(&self) -> bool {
        matches!(
            self,
            AnchorState::VaultRolledBack { .. }
                | AnchorState::AnchorMissingIdentityPresent
                | AnchorState::Forked { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: [u8; 16] = [0x1d; 16];

    fn floors() -> FloorSet {
        FloorSet::from_pairs([
            (FloorId::TrustEpoch, 7),
            (FloorId::AnchorVersion, 2),
            (FloorId::DocVersion("POLICY_BUNDLE"), 42),
        ])
    }

    #[test]
    fn an_anchor_round_trips_through_its_tier_1_encoding() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        let bytes = a.encode().expect("encode");
        assert!(bytes.len() <= MAX_ANCHOR_BYTES);
        let b = Anchor::decode(&bytes).expect("decode");
        assert_eq!(b.store_seq, 9);
        assert_eq!(b.vault_digest, [0xab; 32]);
        assert_eq!(b.floors.get(&FloorId::TrustEpoch), 7);
        assert_eq!(b.floors.get(&FloorId::DocVersion("POLICY_BUNDLE")), 42);
        assert_eq!(b.floor_digest, a.floor_digest);
    }

    /// ST-24 row 1.
    #[test]
    fn matching_sequence_and_digest_is_healthy() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        assert_eq!(
            AnchorState::classify(Some(&a), Some((9, [0xab; 32])), true),
            AnchorState::Healthy
        );
    }

    /// **Attack test — ST-24 row 2.** Restoring an older vault file leaves the
    /// anchor ahead. The floors from the anchor win.
    #[test]
    fn an_older_vault_is_classified_as_a_rollback() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        let s = AnchorState::classify(Some(&a), Some((4, [0xcd; 32])), true);
        assert_eq!(
            s,
            AnchorState::VaultRolledBack {
                anchor_seq: 9,
                vault_seq: 4,
                crash_recovery: false
            }
        );
        assert!(s.suspends_granted_authority());
    }

    /// A gap of exactly one is what ST-23's ordering leaves after a crash
    /// between steps 3 and 5, and is flagged as such — but is still treated as a
    /// rollback, because "erring toward 'rollback' on an ambiguous crash is the
    /// correct direction".
    #[test]
    fn a_gap_of_one_is_flagged_as_crash_recovery_and_still_treated_as_a_rollback() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        let s = AnchorState::classify(Some(&a), Some((8, [0xcd; 32])), true);
        assert_eq!(
            s,
            AnchorState::VaultRolledBack {
                anchor_seq: 9,
                vault_seq: 8,
                crash_recovery: true
            }
        );
        assert!(s.suspends_granted_authority());
    }

    /// **Attack test — ST-24 row 3.** Equal sequence with a different digest is
    /// a fork or a tamper, and is fatal.
    #[test]
    fn equal_sequence_with_a_different_digest_is_a_fork() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        let s = AnchorState::classify(Some(&a), Some((9, [0xcd; 32])), true);
        assert_eq!(s, AnchorState::Forked { store_seq: 9 });
        assert!(s.suspends_granted_authority());
    }

    /// ST-24 rows 5 and 6 — the ST-22 payoff. Anchor gone with the identity
    /// intact suspends authority; both gone is re-enrolment.
    #[test]
    fn a_missing_anchor_is_classified_by_whether_the_identity_survived() {
        assert_eq!(
            AnchorState::classify(None, Some((3, [0; 32])), true),
            AnchorState::AnchorMissingIdentityPresent
        );
        assert!(AnchorState::AnchorMissingIdentityPresent.suspends_granted_authority());
        assert_eq!(
            AnchorState::classify(None, Some((3, [0; 32])), false),
            AnchorState::AnchorAndIdentityMissing
        );
    }

    /// A first run is not ST-24 row 5. There are no floors to be unverified, so
    /// nothing is suspended — and the distinction is what stops every fresh
    /// enrolment from starting degraded.
    #[test]
    fn a_first_run_is_distinguished_from_a_lost_anchor() {
        let first = AnchorState::classify(None, None, true);
        assert_eq!(first, AnchorState::FirstRun);
        assert!(!first.suspends_granted_authority());
        // But an anchor that vanished while a vault survived is row 5, and does
        // suspend.
        assert!(AnchorState::classify(None, Some((1, [0; 32])), true).suspends_granted_authority());
    }

    /// ST-24 row 7: a reinstall that preserved secure storage is the normal
    /// path and carries no code.
    #[test]
    fn a_missing_vault_with_a_surviving_anchor_is_the_reinstall_path() {
        let a = Anchor::new(SID, 9, [0xab; 32], &floors());
        let s = AnchorState::classify(Some(&a), None, true);
        assert_eq!(s, AnchorState::VaultAbsent);
        assert!(!s.suspends_granted_authority());
    }

    /// **Attack test.** A malformed anchor is *not* "absent": treating it as
    /// absent would let an attacker downgrade a tamper into a rebuild.
    #[test]
    fn a_malformed_anchor_is_a_mismatch_and_not_an_absence() {
        assert!(Anchor::decode(&[0xff, 0xff]).is_err());
        assert!(Anchor::decode(&[]).is_err());
        assert!(Anchor::decode(&vec![0u8; MAX_ANCHOR_BYTES + 1]).is_err());
    }

    /// The digest covers every floor, including a per-peer one that the 512-byte
    /// cap may have elided from the explicit map.
    #[test]
    fn the_floor_digest_covers_floors_the_cap_elided() {
        let mut many = floors();
        let mut pairs: Vec<(FloorId, u64)> = many.pairs().map(|(a, b)| (a.clone(), b)).collect();
        for i in 0u8..40 {
            pairs.push((FloorId::PeerGeneration(vec![i; 32]), u64::from(i) + 1));
        }
        many = FloorSet::from_pairs(pairs);
        let a = Anchor::new(SID, 1, [0; 32], &many);
        let bytes = a.encode().expect("encode");
        assert!(bytes.len() <= MAX_ANCHOR_BYTES, "the cap must be honoured");
        let decoded = Anchor::decode(&bytes).expect("decode");
        assert!(
            decoded.floors.pairs().count() < many.pairs().count(),
            "some per-peer floors must have been elided for this test to mean anything"
        );
        assert_eq!(
            decoded.floor_digest,
            floor_digest(&many),
            "the digest must still cover the complete set"
        );
        // And the fixed trust floors always survive.
        assert_eq!(decoded.floors.get(&FloorId::TrustEpoch), 7);
        assert_eq!(decoded.floors.get(&FloorId::AnchorVersion), 2);
    }

    /// Changing any floor changes the digest, which is what makes the elided
    /// entries detectable.
    #[test]
    fn any_floor_change_changes_the_digest() {
        let base = floor_digest(&floors());
        let mut pairs: Vec<(FloorId, u64)> =
            floors().pairs().map(|(a, b)| (a.clone(), b)).collect();
        pairs.push((FloorId::PeerGeneration(vec![9; 32]), 1));
        assert_ne!(floor_digest(&FloorSet::from_pairs(pairs)), base);
    }
}
