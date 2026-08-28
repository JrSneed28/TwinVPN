//! The `pair_tag` two simulated peers meet under.
//!
//! **Authority:** ADR-0005 §11.1(3): the tag is
//! `HKDF-Expand(RelayPairKey, "tag" ‖ relay_id ‖ bucket, 16)` — one-way, scoped
//! to one relay and one 10-minute bucket, and the **only** thing that
//! identifies the pair to the relay.
//!
//! # The relay does not derive this, and that is why it is here
//!
//! A relay compares tags; it never computes one. `services/relay/` therefore
//! contains no derivation to agree with, and this module's correctness
//! condition is *agreement between the two peers*, not agreement with the
//! server. That is stated rather than implied, because "the relay accepted our
//! BIND" is evidence about the relay's tag handling and **not** evidence that
//! this derivation matches what a shipped device would compute.
//!
//! What it does buy: a tag with the right shape, the right width, the right
//! scoping and the right rotation, so every property the relay *does* enforce —
//! the bucket skew window, the two-halves-one-tag rendezvous, the refusal of a
//! third `BIND` on a bound tag — is exercised by something that rotates and
//! collides exactly as the real thing will.
//!
//! `RelayPairKey` itself is an S-28 secret the two peers already share from
//! their L-DATA session. This simulator has no L-DATA session, so it is given
//! one out of band — which is the one place the simulator stands in for a
//! product mechanism, and it stands in for a *key exchange*, never for a
//! *decision*.

use twinvpn_schema::limits::PAIR_TAG_BYTES;

/// The domain-separation prefix of ADR-0005 §11.1(3).
pub const TAG_INFO_PREFIX: &[u8] = b"tag";

/// A `RelayPairKey`: the S-28 secret two peers share.
///
/// A newtype rather than a `[u8; 32]` so it cannot be passed where a leg key,
/// a static key or a token seed is wanted. Every one of those is 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPairKey([u8; 32]);

impl RelayPairKey {
    /// Wraps raw key material.
    #[must_use]
    pub const fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives a development pair key from a shared secret string.
    ///
    /// For the local environment only: two `twinsim` processes given the same
    /// `--pair-secret` meet, and nothing else can. It is hashed rather than
    /// truncated so a short secret still fills the key, and it is documented as
    /// a stand-in rather than presented as the product's key schedule.
    #[must_use]
    pub fn from_shared_secret(secret: &[u8]) -> Self {
        Self(twinvpn_crypto::sha256(secret))
    }

    /// The tag for one relay and one bucket.
    ///
    /// # Errors
    ///
    /// A derivation failure, which for a 16-byte output cannot happen and is
    /// propagated rather than unwrapped anyway: an `expect` here would be a
    /// panic inside a running simulated gateway.
    pub fn tag(&self, relay_id: &[u8], bucket: u64) -> anyhow::Result<[u8; PAIR_TAG_BYTES]> {
        let mut info = Vec::with_capacity(TAG_INFO_PREFIX.len() + relay_id.len() + 8);
        info.extend_from_slice(TAG_INFO_PREFIX);
        info.extend_from_slice(relay_id);
        info.extend_from_slice(&bucket.to_be_bytes());

        let mut out = [0_u8; PAIR_TAG_BYTES];
        twinvpn_crypto::hkdf_sha256(None, &self.0, &info, &mut out)
            .map_err(|e| anyhow::anyhow!("pair_tag derivation: {e}"))?;
        Ok(out)
    }
}

/// The tag for one pair *slot* under a shared secret.
///
/// A peer that fronts several partners — a gateway (ADR-0013) — needs one tag
/// per partner, and both halves of a given pair must derive the same one. The
/// slot index is folded into the secret rather than into the tag's `info`, so
/// the derivation itself stays exactly ADR-0005 §11.1(3)'s shape and a slot is
/// simply a different `RelayPairKey`.
///
/// **One function, used by every caller.** The first version had `probe` derive
/// from the bare secret and the run loop derive from `secret#0`, so a probe and
/// a running peer could never meet — which presents as two peers that each bind
/// successfully and are each told `PENDING` forever.
///
/// # Errors
///
/// As [`RelayPairKey::tag`].
pub fn pair_tag_for(
    shared_secret: &str,
    slot: u32,
    relay_id: &[u8],
    bucket: u64,
) -> anyhow::Result<[u8; PAIR_TAG_BYTES]> {
    RelayPairKey::from_shared_secret(format!("{shared_secret}#{slot}").as_bytes())
        .tag(relay_id, bucket)
}

/// The bucket the current wall clock falls in.
///
/// # Errors
///
/// A clock before the Unix epoch, which is a host fault rather than a protocol
/// one and must not be silently clamped to bucket zero — every peer on the host
/// would then agree on a tag that no relay's skew window will ever accept.
pub fn current_bucket() -> anyhow::Result<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(crate::wire::bucket_for(secs))
}

/// Milliseconds since the Unix epoch.
///
/// # Errors
///
/// As [`current_bucket`].
pub fn now_ms() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY_A: &[u8] = &[0xAA; 16];
    const RELAY_B: &[u8] = &[0xBB; 16];

    fn key() -> RelayPairKey {
        RelayPairKey::from_shared_secret(b"a-development-pair-secret")
    }

    #[test]
    fn two_peers_with_the_same_secret_agree_and_a_third_does_not() {
        let a = RelayPairKey::from_shared_secret(b"shared");
        let b = RelayPairKey::from_shared_secret(b"shared");
        let c = RelayPairKey::from_shared_secret(b"different");
        assert_eq!(a.tag(RELAY_A, 9).unwrap(), b.tag(RELAY_A, 9).unwrap());
        assert_ne!(a.tag(RELAY_A, 9).unwrap(), c.tag(RELAY_A, 9).unwrap());
    }

    #[test]
    fn a_tag_is_scoped_to_one_relay() {
        // "useless at another relay" — ADR-0005 §11.1(3). If this ever held,
        // a tag observed at one relay would let its holder join a flow at
        // another.
        assert_ne!(
            key().tag(RELAY_A, 9).unwrap(),
            key().tag(RELAY_B, 9).unwrap()
        );
    }

    #[test]
    fn a_tag_rotates_with_its_bucket() {
        assert_ne!(
            key().tag(RELAY_A, 9).unwrap(),
            key().tag(RELAY_A, 10).unwrap()
        );
    }

    #[test]
    fn a_tag_is_exactly_the_frozen_width() {
        // PAIR_TAG_BYTES is generated from contracts/registry/limits.json, so
        // this asserts the derivation follows the contract rather than a
        // literal that happens to match today.
        assert_eq!(key().tag(RELAY_A, 1).unwrap().len(), PAIR_TAG_BYTES);
        assert_eq!(PAIR_TAG_BYTES, 16);
    }

    #[test]
    fn every_caller_derives_a_slot_tag_the_same_way() {
        // The failure this prevents, observed: `probe` derived from the bare
        // secret and the run loop from `secret#0`, so the two never met and
        // both were told PENDING forever — which reads as a broken relay.
        let a = pair_tag_for("shared", 0, RELAY_A, 9).unwrap();
        let b = pair_tag_for("shared", 0, RELAY_A, 9).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, pair_tag_for("shared", 1, RELAY_A, 9).unwrap());
    }

    #[test]
    fn buckets_are_ten_minutes_wide() {
        assert_eq!(crate::wire::bucket_for(0), 0);
        assert_eq!(crate::wire::bucket_for(599), 0);
        assert_eq!(crate::wire::bucket_for(600), 1);
        // Sanity: "now" is far past the epoch, so a clock read that silently
        // returned zero would be caught rather than producing tags nothing accepts.
        assert!(current_bucket().expect("clock") > 2_000_000);
    }
}
