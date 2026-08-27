//! The device leg: `BIND`/`BOUND` keyed by `pair_tag`, **directly with the relay
//! on C6**.
//!
//! **Authority:** ADR-0005 §11.1, §11.3; ADR-0006 §11.9;
//! `contracts/docs/contract-matrix.md` §3.1; `contracts/proto/twinvpn/v1/relay.proto`
//! (frozen); `contracts/docs/identifiers.md` §4; A11, CF-7.
//!
//! # The reservation never travels through the coordination service
//!
//! `relay.proto` on `RelayAssignment`: "the **RESERVATION** is a synchronous
//! resource acquisition made **DIRECTLY WITH THE RELAY**, not through the
//! coordination service: routing reservations through coordination would put the
//! control plane in the data path and **BREAK I5**."
//!
//! So this module models a C6 exchange and nothing else. There is no
//! control-plane type anywhere in this crate, and CD-I5's arrow is what the
//! `xtask` lint asserts.
//!
//! # `peer_key_id` does not exist, and that is the point
//!
//! `identifiers.md` and `protocol.md` §16 row 21 record the field's withdrawal:
//! a `pair_tag` is "one-way, scoped to one `relay_id` and one ten-minute bucket,
//! and it **rotates every bucket**. A tag observed at one relay is useless at
//! another, **which is what a `peer_key_id` field would have destroyed**."
//!
//! [`BindRequest`] therefore carries `pair_tag` and no peer identifier of any
//! kind — not a `device_id`, not a key id, not a fingerprint. A test asserts the
//! struct's whole field set.

use twinvpn_types::{PairTag, RelayId};

use crate::map::Carriage;

/// The ten-minute `pair_tag` bucket, from `limits.json`
/// `relay.pair_tag_bucket_seconds`.
pub const BUCKET_SECONDS: u64 = 600;
/// The accepted bucket skew: both peers accept `bucket`, `bucket−1` and
/// `bucket+1`.
pub const ACCEPTED_BUCKET_SKEW: u64 = 1;

/// The `RelayPairKey`-derived values, supplied by `twinvpn-crypto`.
///
/// CD-I2 forbids this crate a cryptographic dependency, and ADR-0005 §11.1(3)
/// fixes both derivations:
///
/// ```text
/// pair_tag = HKDF-Expand(RelayPairKey, "tag" || relay_id || bucket, 16)
/// pair_id  = HKDF-Expand(RelayPairKey, "twinvpn/relay-pairid/v1", 16)
/// ```
///
/// **Integration item.** `twinvpn-crypto` supplies an implementation over the
/// static-static `PairSecret`.
pub trait RelayPairKeyed: Send + Sync {
    /// The blinded join key for one relay and one bucket.
    fn pair_tag(&self, relay: RelayId, bucket: u64) -> PairTag;

    /// The relay-independent pair identity HRW hashes over (ADR-0006 §11.5).
    fn pair_id(&self) -> [u8; 16];
}

/// Whether a received bucket is inside the accepted skew.
///
/// Expressed as a comparison rather than a subtraction "because the bucket is a
/// `u64` and an underflow would silently accept everything".
#[must_use]
pub fn bucket_accepted(current: u64, received: u64) -> bool {
    received >= current.saturating_sub(ACCEPTED_BUCKET_SKEW)
        && received <= current.saturating_add(ACCEPTED_BUCKET_SKEW)
}

/// The bucket for an elapsed-clock reading.
///
/// The bucket is a *shared* value both peers must compute alike, so it reads the
/// **elapsed** clock rather than the monotonic one — a monotonic origin is
/// process-local and two devices could never agree on it.
#[must_use]
pub const fn bucket_for(seconds_since_epoch: u64) -> u64 {
    seconds_since_epoch / BUCKET_SECONDS
}

/// What the device sends the relay on C6.
///
/// Every field is listed, and the absence of a peer identifier is the security
/// property. The relay "never learns which two devices are talking beyond what
/// forwarding requires".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    /// The blinded join key. **The only thing that identifies the pair**, and it
    /// is useless at another relay and expires with its bucket.
    pub pair_tag: PairTag,
    /// The bucket the tag was derived for.
    pub bucket: u64,
    /// Which carriage the leg uses.
    pub carriage: Carriage,
    /// Which family this half-flow is on. The two halves of one `pair_tag` MAY
    /// differ in family and in carriage — "an IPv6-only peer and an IPv4-only
    /// peer meet at the relay, which is a large part of why the relay exists".
    pub family: twinvpn_types::AddressFamily,
}

/// What the relay returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindResponse {
    /// The relay-assigned handle. Local to that relay instance.
    pub flow_id: Vec<u8>,
    /// Whether the second half of the pair has arrived.
    ///
    /// "The **FIRST** `BIND` creates a pending slot; the **SECOND** on the same
    /// tag binds it."
    pub paired: bool,
}

/// The device-side record of a bound leg (S-29).
///
/// Non-durable by requirement: "loss means flow death, which means `MIGRATING` —
/// a recoverable outcome".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Which relay.
    pub relay: RelayId,
    /// The tag it is keyed by.
    pub pair_tag: PairTag,
    /// The relay-assigned handle.
    pub flow_id: Vec<u8>,
    /// The carriage in use.
    pub carriage: Carriage,
    /// The family this half-flow runs on.
    pub family: twinvpn_types::AddressFamily,
    /// Whether the pair is complete.
    pub paired: bool,
}

/// The relay forwards **opaque ciphertext only** (I1).
///
/// ADR-0005 §7.3: the relay's static Noise public key "is **NOT** an input to
/// the L-DATA `Noise_IKpsk2` handshake — the relay is not a party to it, and
/// holding this key gives it no read access."
///
/// A function rather than a comment so the property is greppable and a change to
/// it fails a test.
#[must_use]
pub const fn relay_can_decrypt_payload() -> bool {
    false
}

/// The pending-slot lifetime: 30 s, after which an unmatched slot expires with
/// `RELAY.PAIR_UNMATCHED` (ADR-0006 §11.5).
pub const PENDING_SLOT_LIFETIME: core::time::Duration = core::time::Duration::from_secs(30);

/// ADR-0006 §11.5's listening posture: re-`BIND` a pending slot at the top
/// `k_rdv` = 2 HRW relays per `TrustedPeer`, at ≤ 30 s intervals.
pub const K_RENDEZVOUS: usize = 2;

/// ADR-0005's default `max_binds_per_min` per `relay_sub`.
pub const DEFAULT_MAX_BINDS_PER_MIN: u32 = 30;

/// How many peers the listening posture scales to on one relay.
///
/// ADR-0006 §11.5: "≈ **15 peers per relay**; beyond that the token's quota must
/// be raised for gateway-class devices."
#[must_use]
pub const fn listening_peer_ceiling(max_binds_per_min: u32) -> u32 {
    max_binds_per_min / K_RENDEZVOUS_U32
}

/// [`K_RENDEZVOUS`] as a `u32`, so the ceiling arithmetic needs no cast.
pub const K_RENDEZVOUS_U32: u32 = 2;
