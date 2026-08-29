//! The material the establishment chain needs and cannot derive for itself.
//!
//! **Authority:** [ADR-0001](../../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.2 (one X25519 static per device, "hardware-wrapped and unsealed into the
//! locked allocator"), §7.3.1 P-1/P-2 (the 83-byte prologue and its two
//! contributed digests), §11 item 1 (the `psk2` slot carries `TwinNetPSK`);
//! [ADR-0007](../../../../../docs/adr/ADR-0007-identity-lifecycle-and-revocation.md)
//! N-4/N-5 (a peer static is trusted only through a verified `TunnelKeyBinding`),
//! N-20 (what the identity binding covers), §7.7 (`TwinNetPSK` is pairwise);
//! [ADR-0014](../../../../../docs/adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
//! N-6 (what the negotiation binding covers), D1 (advertisements are claims);
//! [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CD-I4 (no identity private scalar in any workspace type), CB-5, CD-2;
//! [ADR-0005](../../../../../docs/adr/ADR-0005-relay-architecture.md) §11.1(2)
//! and §11.3, [ADR-0006](../../../../../docs/adr/ADR-0006-relay-discovery-and-failover.md)
//! §11.2 (a device MUST NOT bind a relay absent from a verified map).
//!
//! # Why these are injected rather than sourced
//!
//! Every value below is a fact this crate genuinely does not hold, and each is
//! **named rather than fabricated** — the same rule
//! [`crate::cp_binding::transport`] applies to `ServerPins`, the endpoints and
//! `DeviceIdentity`, applied to L-DATA and to the relay leg.
//!
//! | Value | Why the composition root cannot produce it |
//! |---|---|
//! | the local L-DATA static | it is sealed in the vault's `identity/` namespace and unsealed by `core-security`; nothing in this crate opens that seal |
//! | the peer's [`VerifiedTunnelKey`] | it has **no public constructor**: the only way to obtain one is `twinvpn_crypto::verify_tunnel_key_binding` over a signed statement, and [`crate::planes::PeerRecord`] deliberately carries no key — it carries the *verdict* (`tunnel_key_binding_verified`), which is ADR-0007 N-4's `TrustedPeer` and not a static |
//! | the [`TwinNetPsk`] | it is derived from a `PairSecret` and an `EpochSeed`, which `planes` states outright are "`core-security`'s, and I4 keeps them out of the core's reach entirely" |
//! | the [`NegotiationBinding`] | ADR-0014 owns `Selection` and `twinvpn-crypto` says so at the type: "the bytes arrive already deterministically encoded". Encoding one here would be this crate authoring a canonical form it does not own |
//! | `anchor_version` and `delegation_set_digest` | pinned trust state; `twinvpn-trust`'s `AnchorChain`, which this crate holds no handle to |
//! | every [`RelayAccess`] field | ADR-0006 §11.2's verified `RelayMap`, the device's `RLK` and a `RelayCapabilityToken`. None has a production source anywhere in the workspace — see that type's own documentation |
//!
//! # What the composition root *does* compute, and why that split
//!
//! [`TunnelKeying`] carries no [`IdentityBinding`]. The composition root
//! assembles that itself from the two injected trust facts plus state it already
//! holds — the two `DeviceId`s in their **initiator/responder roles**, the
//! `TwinnetId`, the `trust_epoch` from [`crate::planes::DataPlaneView`] and the
//! `psk_epoch` from the PSK. Injecting the assembled binding instead would move a
//! decision out of the composition root and would let a caller bind one epoch
//! while the session ran at another; ADR-0007 N-20's whole point is that those
//! values are the *session's*, not a caller's claim about the session.
//!
//! # Absence is a refusal, never a weaker handshake
//!
//! There is no constructor here that omits anything, no `Default`, and no
//! `Option` on a field ADR-0001 fixes. A `Session` with no [`TunnelKeying`]
//! installed cannot handshake, and [`crate::execute`] refuses it by name with
//! `AUTH.KEY_UNAVAILABLE` rather than proceeding — ADR-0001 §7.3.1 P-3's
//! direction, and `ownership.md` §6's "never weaken … session-key handling".

use twinvpn_crypto::locked::LockedBytes;
use twinvpn_crypto::prologue::{IdentityBinding, NegotiationBinding, Prologue, TwinnetTag};
use twinvpn_crypto::psk::TwinNetPsk;
use twinvpn_crypto::VerifiedTunnelKey;
use twinvpn_relay_client::map::Carriage;
use twinvpn_types::{DeviceId, Endpoint, Identifier as _, RelayId, TwinnetId};

use crate::relay::TokenPresentation;

/// The L-DATA static key length, restated from `twinvpn-crypto` so a caller can
/// size a buffer without naming the crypto crate.
pub const STATIC_KEY_LEN: usize = 32;

/// Everything one peer's `Noise_IKpsk2` handshake needs beyond what the
/// composition root already holds.
///
/// One per peer. It is **per-peer and not per-device** because `TwinNetPSK` is
/// pairwise (ADR-0007 §7.7) and the peer static is one device's — a single
/// device-wide value would be a PSK shared across peers, which is the sharing
/// §7.7 exists to forbid.
pub struct TunnelKeying {
    local_static: LockedBytes,
    peer_key: VerifiedTunnelKey,
    psk: TwinNetPsk,
    negotiation: NegotiationBinding,
    local_device: DeviceId,
    twinnet: TwinnetId,
    anchor_version: u32,
    delegation_set_digest: [u8; 32],
}

impl TunnelKeying {
    /// Binds one peer's key material to the trust state it was verified under.
    ///
    /// `local_static` is this device's L-DATA static private key, already inside
    /// the locked allocator — ADR-0001 §7.2's custody, and the reason this takes
    /// a [`LockedBytes`] rather than a `Vec<u8>`: `LockedBytes` has no
    /// `from_vec`, so a secret that reached this call *did* pass through the
    /// allocator that locks and erases it.
    ///
    /// `peer_key` is a [`VerifiedTunnelKey`], which cannot be built except by
    /// verifying a `TunnelKeyBinding`. That is ADR-0007 N-4/N-5 held by the type
    /// system: there is no way to hand this constructor a peer static that
    /// nobody checked.
    ///
    /// # Errors
    ///
    /// `None` if `local_static` is not [`STATIC_KEY_LEN`] bytes. Refused here
    /// rather than at `Handshake::new`, because a length failure discovered
    /// inside the handshake is reported as `CryptoUnavailable` — the same
    /// indistinguishable refusal a *hostile* peer provokes — and a local
    /// misconfiguration that reads as an attack is a misconfiguration nobody
    /// fixes.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_static: LockedBytes,
        peer_key: VerifiedTunnelKey,
        psk: TwinNetPsk,
        negotiation: NegotiationBinding,
        local_device: DeviceId,
        twinnet: TwinnetId,
        anchor_version: u32,
        delegation_set_digest: [u8; 32],
    ) -> Option<Self> {
        if local_static.len() != STATIC_KEY_LEN {
            return None;
        }
        Some(Self {
            local_static,
            peer_key,
            psk,
            negotiation,
            local_device,
            twinnet,
            anchor_version,
            delegation_set_digest,
        })
    }

    /// This device's L-DATA static, for `HandshakeConfig::local_static`.
    pub(crate) const fn local_static(&self) -> &LockedBytes {
        &self.local_static
    }

    /// The peer static a completed handshake must have proved.
    pub(crate) const fn peer_key(&self) -> &VerifiedTunnelKey {
        &self.peer_key
    }

    /// The `psk2` slot's contents.
    pub(crate) const fn psk(&self) -> &TwinNetPsk {
        &self.psk
    }

    /// Which `TwinNet` this material belongs to.
    #[must_use]
    pub const fn twinnet(&self) -> &TwinnetId {
        &self.twinnet
    }

    /// Assembles ADR-0001 §7.3.1's 83 bytes for one attempt.
    ///
    /// `initiator` and `responder` are passed in their **roles**, not as "us and
    /// them": the identity binding covers `device_id_init` and `device_id_resp`
    /// as ordered fields, so a peer that computed them in the other order would
    /// derive a different prologue and the handshake would simply fail — P-3's
    /// "observationally indistinguishable from any other handshake failure",
    /// which is exactly what a role confusion should look like from the wire and
    /// exactly what it must never look like from here. The caller states the
    /// roles; this function does not guess them.
    ///
    /// `trust_epoch` is the session's, read from the store-backed view rather
    /// than carried in this type, so a `Session` cannot handshake under an epoch
    /// the data plane has moved past.
    pub(crate) fn prologue(
        &self,
        initiator: DeviceId,
        responder: DeviceId,
        trust_epoch: u64,
    ) -> Prologue {
        Prologue::new(
            &self.identity_binding(initiator, responder, trust_epoch),
            &self.negotiation,
        )
    }

    /// The two 32-byte digests, for the `twinvpn-tunnel` side of the same field.
    ///
    /// `twinvpn_tunnel::crypto::Prologue` and `twinvpn_crypto::prologue::Prologue`
    /// are two Rust types over **one** normative field (P-1). Returning both
    /// halves lets the caller build the tunnel-side value from the same inputs,
    /// which is what makes `twinvpn_tunnel::bind::NoiseBinding`'s byte-for-byte
    /// cross-check a real check of two independent constructions rather than a
    /// comparison of one value with itself.
    pub(crate) fn prologue_digests(
        &self,
        initiator: DeviceId,
        responder: DeviceId,
        trust_epoch: u64,
    ) -> ([u8; 32], [u8; 32]) {
        (
            self.identity_binding(initiator, responder, trust_epoch)
                .hash(),
            self.negotiation.hash(),
        )
    }

    fn identity_binding(
        &self,
        initiator: DeviceId,
        responder: DeviceId,
        trust_epoch: u64,
    ) -> IdentityBinding {
        IdentityBinding {
            twinnet: TwinnetTag::from_twinnet_id(self.twinnet.as_str()),
            device_id_init: fixed32(initiator),
            device_id_resp: fixed32(responder),
            trust_epoch,
            // The PSK's own epoch, not a caller's claim about it. ADR-0007 §7.7
            // forbids accepting a handshake below `min_acceptable_epoch`, and
            // reading the epoch off the key that will actually fill the `psk2`
            // slot is what keeps the bound value and the bound-to value the same
            // one.
            psk_epoch: self.psk.epoch(),
            anchor_version: self.anchor_version,
            delegation_set_digest: self.delegation_set_digest,
        }
    }

    /// This device's own name, as the enrolment record states it.
    pub(crate) const fn local_device(&self) -> DeviceId {
        self.local_device
    }
}

impl core::fmt::Debug for TunnelKeying {
    /// Names the `TwinNet` and nothing else.
    ///
    /// The static, the PSK, the peer key and both prologue halves are all key or
    /// identity material, and `ownership.md` §6 rule 11 is absolute: a derived
    /// `Debug` here would put a `psk2` slot in a diagnostic bundle.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelKeying")
            .field("twinnet", &self.twinnet.as_str())
            .field("psk_epoch", &self.psk.epoch())
            .finish_non_exhaustive()
    }
}

/// A `DeviceId`'s 32 octets.
///
/// `DeviceId` is declared 32 bytes wide, so the copy cannot be short; the
/// `expect` states that rather than silently zero-padding, which would make two
/// different devices bind the same prologue.
fn fixed32(id: DeviceId) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(id.as_bytes());
    out
}

/// Everything one relay leg needs that the composition root cannot produce.
///
/// # None of this has a production source, and that is the finding
///
/// [`crate::relay`] is complete and byte-exact against `services/relay`, and
/// every one of its inputs is unsourced in the composed core:
///
/// | Field | What would have to supply it |
/// |---|---|
/// | `relay`, `endpoint`, `carriage`, `relay_static` | a **verified `RelayMap`** (ADR-0006 §11.2). `twinvpn_relay_client::map::RelayMap` exists; nothing in this crate constructs, caches or verifies one, and `planes::BridgeState` has no field for it |
/// | `rlk_private` | the device's relay-leg static. `twinvpn_crypto::relay_leg` consumes one and nothing in `twinvpn-store` holds one |
/// | `token` | a `RelayCapabilityToken`, issued over C1. There is no issuer, no fetch and no cache |
/// | `pair_tag` | `twinvpn_relay_client::bind::RelayPairKeyed`, whose own documentation calls it an integration item — **there is no implementation of that trait anywhere in the workspace**, and the derivation needs a `PairSecret` I4 keeps out of this crate |
///
/// So this type is the shape those five things must arrive in, and its absence
/// is what makes the relay path refuse by name instead of pretending. It is the
/// same device [`crate::cp_binding::ControlPlaneEnrolment`] uses for the
/// enrolment record, for the same reason: a seam that is declared and empty is
/// auditable, and one that is inferred is not.
pub struct RelayAccess {
    relay: RelayId,
    endpoint: Endpoint,
    carriage: Carriage,
    relay_static: [u8; STATIC_KEY_LEN],
    rlk_private: Vec<u8>,
    token: TokenPresentation,
    pair_tag: twinvpn_types::PairTag,
}

impl RelayAccess {
    /// Binds one relay from a verified map to the credentials this device
    /// presents to it.
    ///
    /// `relay_static_from_verified_map` is named for the obligation this crate
    /// cannot check, exactly as [`crate::relay::LegParams`]' field of the same
    /// name is: ADR-0006 §11.2 forbids binding a relay whose static is absent
    /// from a verified map, and nothing here can tell a verified static from any
    /// other 32 bytes.
    #[must_use]
    pub const fn new(
        relay: RelayId,
        endpoint: Endpoint,
        carriage: Carriage,
        relay_static_from_verified_map: [u8; STATIC_KEY_LEN],
        rlk_private: Vec<u8>,
        token: TokenPresentation,
        pair_tag: twinvpn_types::PairTag,
    ) -> Self {
        Self {
            relay,
            endpoint,
            carriage,
            relay_static: relay_static_from_verified_map,
            rlk_private,
            token,
            pair_tag,
        }
    }

    /// The leg parameters, borrowed for one `open_leg`.
    pub(crate) fn params(&self) -> crate::relay::LegParams<'_> {
        crate::relay::LegParams {
            relay: self.relay,
            endpoint: self.endpoint,
            carriage: self.carriage,
            relay_static_public_from_verified_map: &self.relay_static,
            rlk_private: &self.rlk_private,
            token: &self.token,
        }
    }

    /// The `pair_tag` a `BIND` is keyed by (ADR-0005 §11.1(3)).
    pub(crate) const fn pair_tag(&self) -> twinvpn_types::PairTag {
        self.pair_tag
    }
}

impl core::fmt::Debug for RelayAccess {
    /// The relay and its family. The `RLK` and the token are both credentials
    /// and neither is renderable (`ownership.md` §6 rule 11); the token in
    /// particular is a **bearer** credential, which is the one class a log must
    /// never carry.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayAccess")
            .field("relay", &self.relay)
            .field("family", &self.endpoint.family())
            .field("carriage", &self.carriage)
            .finish_non_exhaustive()
    }
}
