//! The ADR-0001 §7.3.2 resumption secrets, and the direction-bound tag.
//!
//! **Authority:** ADR-0001 §7.3.2 RS-1 (in-memory only, S-13), RS-2 (the MAC is
//! over the whole message); ADR-0018 CD-I2 — every primitive comes from
//! `twinvpn-crypto` and this module names no cryptography crate of its own.

use twinvpn_crypto::noise::Role;
use twinvpn_crypto::{hkdf_expand_label, sha256, EstablishedHandshake, LockedBytes};
use twinvpn_types::codes;

use super::{ResumeRefusal, RESUME_TAG_LEN, RESUMPTION_ID_LEN, RESUMPTION_SECRET_LEN};

/// The ADR-0001 §7.3.2 resumption secrets, held in memory and nowhere else.
///
/// **RS-1 / S-13.** No `Clone`, no `serde`, no accessor for the secret, and no
/// path into `twinvpn-store`: a process restart drops this and the recovery path
/// becomes a full handshake from cached `TrustedPeer` state, which is still
/// control-plane-free. `Debug` is hand-written and shows neither half.
pub struct ResumptionKeys {
    secret: LockedBytes,
    id: [u8; RESUMPTION_ID_LEN],
    /// **This device's** role in the handshake these keys came from, which fixes
    /// which direction label it MACs under and which one it verifies under.
    pub(super) local_role: Role,
}

impl ResumptionKeys {
    /// Derives both secrets from a completed handshake.
    ///
    /// ```text
    /// resumption_secret = HKDF-Expand-Label(handshake_secret, "twinvpn resume", "", 32)
    /// resumption_id     = HKDF-Expand-Label(handshake_secret, "twinvpn resume id", "", 16)
    /// ```
    ///
    /// Verbatim from ADR-0001 §7.3.2, through `twinvpn-crypto`'s
    /// [`hkdf_expand_label`], which keeps RFC 8446's `"tls13 "` prefix — I2
    /// forbids a TwinVPN-designed variant of a standard construction, and the
    /// KDF module already made that call for exactly this consumer.
    ///
    /// # Both inputs come from the handshake, and neither from the caller
    ///
    /// `handshake` is `twinvpn-crypto`'s [`EstablishedHandshake`], which has no
    /// public constructor: the only thing that mints one is
    /// `noise::Handshake::split`, consuming the handshake it describes. So the
    /// secret is the one that handshake produced, and `local_role` is read
    /// **off it** rather than accepted beside it.
    ///
    /// The two parameters this replaced were both silent downgrades. A bare
    /// `&[u8]` accepted the handshake hash — a value ADR-0001 §7.3 D2 puts on
    /// the wire — and a `Role` parameter accepted the *same* role on both
    /// peers, which collapses the two direction labels below into one and
    /// removes the reflection defence entirely. Neither compiles now.
    pub fn derive(handshake: &EstablishedHandshake) -> Result<Self, ResumeRefusal> {
        let handshake_secret = handshake.secret().expose();
        let local_role = handshake.local_role();
        let mut raw = [0u8; RESUMPTION_SECRET_LEN];
        hkdf_expand_label(handshake_secret, "twinvpn resume", b"", &mut raw)
            .map_err(|_| ResumeRefusal::DerivationFailed)?;
        // `adopt` is `twinvpn-crypto`'s named "these bytes have already been in
        // unlocked memory" path, and it is the honest one here: HKDF writes into
        // a caller-supplied buffer, so the secret exists on the stack for the
        // length of this function whatever we do. `adopt` zeroes it on the way
        // out, which is the most that can be done from this side.
        let secret = LockedBytes::adopt(&mut raw).map_err(|_| ResumeRefusal::DerivationFailed)?;

        let mut id = [0u8; RESUMPTION_ID_LEN];
        hkdf_expand_label(handshake_secret, "twinvpn resume id", b"", &mut id)
            .map_err(|_| ResumeRefusal::DerivationFailed)?;

        Ok(Self {
            secret,
            id,
            local_role,
        })
    }

    /// The `resumption_id` this device answers to.
    ///
    /// Not secret: the contract calls it "an opaque handle … NOT the resumption
    /// secret", and it travels in clear in every `ResumeSession`.
    #[must_use]
    pub const fn id(&self) -> &[u8; RESUMPTION_ID_LEN] {
        &self.id
    }

    /// The tag over `encoded`, as seen from `sender`.
    ///
    /// `HKDF-Expand-Label(resumption_secret, "twinvpn resume mac <role>",
    /// SHA-256(encoded), 16)` — HKDF-Expand is HMAC-SHA-256, so this is a PRF
    /// MAC keyed by the resumption secret, domain-separated by a label, over a
    /// fixed-width digest of the whole message (RS-2's "the MAC is over the
    /// whole message"). Hashing first rather than passing the message as the
    /// label's `context` keeps the input fixed-width, so the construction
    /// imposes no length limit of its own on a wire format.
    pub(super) fn tag(
        &self,
        sender: Role,
        encoded: &[u8],
    ) -> Result<[u8; RESUME_TAG_LEN], ResumeRefusal> {
        let digest = sha256(encoded);
        let label = match sender {
            Role::Initiator => "twinvpn resume mac i",
            Role::Responder => "twinvpn resume mac r",
        };
        let mut tag = [0u8; RESUME_TAG_LEN];
        hkdf_expand_label(self.secret.expose(), label, &digest, &mut tag)
            .map_err(|_| ResumeRefusal::DerivationFailed)?;
        Ok(tag)
    }
}

impl core::fmt::Debug for ResumptionKeys {
    /// Neither secret, and not even the `resumption_id`: an id in a support
    /// bundle correlates two captures of the same `Session`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResumptionKeys")
            .field("role", &self.local_role)
            .finish_non_exhaustive()
    }
}
/// The role on the other end of a handshake.
pub(super) const fn peer_role(local: Role) -> Role {
    match local {
        Role::Initiator => Role::Responder,
        Role::Responder => Role::Initiator,
    }
}

/// Splits `encoded ‖ tag`, refusing anything too short to hold a tag.
pub(super) fn split_tag(datagram: &[u8]) -> Result<(&[u8], &[u8; RESUME_TAG_LEN]), ResumeRefusal> {
    if datagram.len() <= RESUME_TAG_LEN {
        return Err(ResumeRefusal::Malformed {
            rule: "resume_datagram_length",
            code: codes::PROTO_MALFORMED_MESSAGE,
        });
    }
    let (body, tail) = datagram.split_at(datagram.len() - RESUME_TAG_LEN);
    let tag: &[u8; RESUME_TAG_LEN] = tail.try_into().map_err(|_| ResumeRefusal::Malformed {
        rule: "resume_datagram_length",
        code: codes::PROTO_MALFORMED_MESSAGE,
    })?;
    Ok((body, tag))
}

/// Constant-time equality.
///
/// The tag and the `resumption_id` both arrive on the wire, so a variable-time
/// comparison is a prefix-matching oracle: an attacker recovers the tag one byte
/// at a time and forges a resume into the session table. `twinvpn-crypto` makes
/// the same call for the relay frame MAC and states the same reason.
pub(super) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
