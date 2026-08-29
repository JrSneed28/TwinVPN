//! Wire-level session resumption: the producer, the consumer, and the refusals.
//!
//! **Authority:** [ADR-0001](../../../../docs/adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)
//! §7.3.2 RS-1…RS-7 (the resumption secrets, the single authenticated datagram,
//! the anti-replay rule, the revocation check, the rekey bound);
//! `docs/protocol.md` §12.1 (the interaction contract, its authorization row and
//! its three visible fallback codes); `docs/reliability.md` §6.2 (the recovery
//! ladder), §6.5 (what survives what), §11.3 (the wake sequence); ADR-0018 CD-1
//! and CD-2 (the injected clock, no ambient time).
//!
//! # What was missing, and what this is
//!
//! The frozen [`v1::ResumeSession`] message existed and nothing produced or
//! consumed it. `core.rs`'s journal hydration restores *state* after a process
//! restart, which ADR-0001 RS-1 explicitly says is **not** resumption: the
//! resumption secrets are in-memory only (S-13), so a restarted agent runs a
//! full handshake. This module is the wire flow the contract describes — one
//! authenticated datagram, no key exchange, no control plane, ~1 RTT.
//!
//! # What is wired, and what is still not — read this before believing the table
//!
//! **Arming is real.** [`crate::execute::establishment`] arms every `Session`
//! that completes a production `Noise_IKpsk2` handshake, from the
//! [`twinvpn_crypto::EstablishedHandshake`] that handshake produced. The keying
//! seam this module used to be blocked on is closed: the secret is
//! `HKDF-Extract(salt, k1 ‖ k2)` over Noise's own split outputs, computed inside
//! `twinvpn-crypto` and reachable no other way. `twinvpn_crypto::established`
//! states the construction and why it is the right one.
//!
//! **Carriage is still not.** Nothing transmits the bytes [`ResumeState::offer`]
//! returns, and no datagram from a socket reaches [`ResumeState::accept`]: the
//! datapath allocates no frame type for a resume. That is ordinary wiring, it is
//! blocked on nothing cryptographic, and until it is done a real `Session` holds
//! usable material and never spends it. A reader who takes "wire-level session
//! resumption is implemented" from this file would still be wrong about the
//! wire, and right about the keys.
//!
//! | Rule | Where it lives here |
//! |---|---|
//! | **RS-1** in-memory only | [`ResumptionKeys`] holds its secret in a `twinvpn_crypto::LockedBytes`, is not `Clone`, is not serialisable, and is reachable only from a live [`ResumeState`] |
//! | **RS-2** one authenticated datagram | [`ResumeState::offer`] / [`ResumeState::accept`], over `encoded ResumeSession ‖ tag` |
//! | **RS-3** re-bind, never reset | there is no constructor here that resets a counter, and the inbound [`ReplayWindow`] is `twinvpn-crypto`'s, which has no `reset` |
//! | **RS-4** strictly increasing `path_epoch` | [`ResumeRefusal::Replayed`], checked before and committed after the MAC |
//! | **RS-5** refuse a revoked peer | [`ResumeRefusal::PeerRevoked`] and [`ResumeRefusal::TrustEpochBehind`] |
//! | **RS-6** bounded by the rekey schedule | [`RESUMPTION_LIFETIME`] and [`ResumeRefusal::Expired`] |
//! | **RS-7** no control-plane call | nothing in this module names `twinvpn-cp-client`, directly or transitively |
//!
//! # Fail-closed, and what that means at each step
//!
//! **Every** refusal in [`ResumeRefusal`] falls back to a full handshake —
//! [`ResumeRefusal::falls_back_to_full_handshake`] is total and returns `true`,
//! written as a function so a future variant has to answer it. There is no
//! partial acceptance: `accept` either returns an [`AcceptedResume`] having
//! committed the `path_epoch` to the window, or returns a refusal having
//! committed nothing at all.
//!
//! The ordering inside `accept` is the security property, and it is
//! `twinvpn-crypto`'s own discipline: shed obvious replays with a cheap check,
//! **verify the MAC**, and only then record anything. Recording an
//! unauthenticated `path_epoch` would let an off-path attacker advance the
//! window with forged datagrams and lock the real peer out — the attack
//! [`ReplayWindow::would_accept`] is documented to prevent.
//!
//! # Why the MAC is direction-bound
//!
//! Both peers derive the *same* `resumption_secret` from the same handshake, so
//! a MAC that did not name a direction would verify on a datagram reflected back
//! at its own sender. The attacker learns nothing, but the reflected offer
//! advances the victim's inbound window and the peer's genuine resume at that
//! `path_epoch` is then dropped as a replay — a denial of service assembled
//! entirely out of the victim's own bytes. The tag is therefore derived under a
//! label naming the **sender's handshake role**, and a receiver verifies under
//! its peer's role.

use core::time::Duration;

use prost::Message as _;
use twinvpn_crypto::noise::REKEY_AFTER_TIME;
use twinvpn_crypto::{EstablishedHandshake, ReplayWindow};
use twinvpn_env::ElapsedInstant;
use twinvpn_schema::{v1, validate, Channel};
use twinvpn_types::{Identifier as _, SessionNonce};

mod driver;
mod keys;
mod refusal;

pub use keys::ResumptionKeys;
pub use refusal::{AcceptedResume, ResumeRefusal};

use keys::{ct_eq, peer_role, split_tag};

/// The `resumption_secret` width. ADR-0001 §7.3.2: 32 bytes.
pub const RESUMPTION_SECRET_LEN: usize = 32;

/// The `resumption_id` width. ADR-0001 §7.3.2: 16 bytes.
pub const RESUMPTION_ID_LEN: usize = 16;

/// The resume tag width, in bytes.
///
/// 128 bits. The tag authenticates a datagram that carries no key material and
/// grants no authority beyond re-binding an existing `Tunnel` to a new `Path`,
/// and a forgery costs an attacker 2^128 work for one accepted resume.
pub const RESUME_TAG_LEN: usize = 16;

/// How long resumption material may be used, on the **elapsed** clock.
///
/// **RS-6:** "Resumption provides no new forward secrecy. It is bounded by the
/// rekey schedule of §7.2: a `Tunnel` that would rekey MUST rekey rather than
/// resume indefinitely."
///
/// The bound is **`REKEY_AFTER_TIME` (120 s), not `REJECT_AFTER_TIME` (180 s)**,
/// and the difference is the whole rule. `REJECT_AFTER_TIME` is when the keys
/// *die*; `REKEY_AFTER_TIME` is when the rekey is *due* — "the initiator begins
/// a new handshake". A `Tunnel` between those two instants is precisely a
/// `Tunnel` that **would rekey**, so RS-6 says it must rekey rather than resume,
/// and keying this to the outer bound admitted a resume across all 60 s of that
/// window. Choosing the earlier constant is also the safe direction on its own
/// terms: it can only turn a resume into a full handshake, never the reverse,
/// and a full handshake is what RS-6 is asking for.
///
/// The **elapsed** clock, not the monotonic one, because `reliability.md` §11.3
/// measures the suspend gap against the rekey window and a device that slept
/// through the window must not resume on the far side of it.
pub const RESUMPTION_LIFETIME: Duration = REKEY_AFTER_TIME;

/// The peer's trust standing, as the resumer's own device sees it right now.
///
/// Facts, supplied by the caller from `twinvpn-trust`, rather than a dependency
/// on it: §12.1's authorization row is a *local* check, and taking it as data
/// keeps this module free of a trust-store handle it would otherwise hold for
/// the life of every `Session`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTrustFacts {
    /// This device's current `trust_epoch` (`RevocationState::trust_epoch`).
    pub revocation_epoch: u64,
    /// Whether this device has a verified revocation for the peer
    /// (`RevocationState::is_revoked`).
    pub peer_revoked: bool,
}

/// One `Session`'s resumption state: the keys, the send epoch, and the window.
///
/// Created only by [`ResumeState::armed`], which the handshake path calls once
/// the tunnel is up. A `Session` with no `ResumeState` refuses to resume
/// ([`ResumeRefusal::NotArmed`]) rather than inventing one, which is RS-1 made
/// structural.
pub struct ResumeState {
    keys: ResumptionKeys,
    session_nonce: SessionNonce,
    /// **RS-4's high-water mark.** `twinvpn-crypto`'s window, reused rather than
    /// duplicated: it already carries the `REJECT_AFTER_MESSAGES` bound and,
    /// more to the point, it has no `reset` — which is RS-3's "MUST NOT reset
    /// the replay window" enforced by the type rather than by review.
    ///
    /// The window's own acceptance rule is *looser* than RS-4: it admits an
    /// unseen counter behind the high-water mark, because reordering on a lossy
    /// data path is normal. A resume is not a data frame and RS-4 is stricter —
    /// "at or below the highest seen MUST be dropped" — so the strict
    /// comparison is applied on top, and the window supplies the mark.
    seen: ReplayWindow,
    next_outbound: u64,
    armed_at: ElapsedInstant,
    lifetime: Duration,
}

impl ResumeState {
    /// Arms resumption for a `Session` whose handshake just completed.
    ///
    /// `handshake` is the authenticated result of that handshake, and it is the
    /// only source of both the secret and this device's role — see
    /// [`ResumptionKeys::derive`] for what accepting either from a caller used
    /// to allow.
    ///
    /// `path_epoch` is the epoch the `Session` was established at; it seeds both
    /// directions, so the first resume in either direction must present a
    /// strictly greater one.
    pub fn armed(
        handshake: &EstablishedHandshake,
        session_nonce: SessionNonce,
        path_epoch: u64,
        now: ElapsedInstant,
    ) -> Result<Self, ResumeRefusal> {
        let keys = ResumptionKeys::derive(handshake)?;
        let mut seen = ReplayWindow::new();
        // Seeding the window is what makes "strictly greater than the epoch we
        // established at" true for the very first inbound resume, rather than
        // only from the second one onwards.
        seen.accept(path_epoch)
            .map_err(|_| ResumeRefusal::DerivationFailed)?;
        Ok(Self {
            keys,
            session_nonce,
            seen,
            next_outbound: path_epoch.saturating_add(1),
            armed_at: now,
            lifetime: RESUMPTION_LIFETIME,
        })
    }

    /// The `resumption_id` this side answers to.
    #[must_use]
    pub const fn resumption_id(&self) -> &[u8; RESUMPTION_ID_LEN] {
        self.keys.id()
    }

    /// The highest inbound `path_epoch` accepted so far.
    #[must_use]
    pub fn highest_accepted_epoch(&self) -> Option<u64> {
        self.seen.highest()
    }

    /// Whether the material is still inside [`RESUMPTION_LIFETIME`] at `now`.
    #[must_use]
    pub fn is_fresh(&self, now: ElapsedInstant) -> bool {
        now.duration_since(self.armed_at) <= self.lifetime
    }

    /// **The producer.** Builds one authenticated `ResumeSession` datagram.
    ///
    /// The freshness check is on the *sending* side as well, so a device that
    /// slept past the rekey window spends no RTT on a resume its peer is
    /// obliged to refuse — and, more importantly, so that the fail-closed rule
    /// does not depend on the peer being correct.
    pub fn offer(
        &mut self,
        new_endpoint_hint: Option<v1::Endpoint>,
        facts: PeerTrustFacts,
        now: ElapsedInstant,
    ) -> Result<Vec<u8>, ResumeRefusal> {
        if !self.is_fresh(now) {
            return Err(ResumeRefusal::Expired);
        }
        // A device that already knows the peer is revoked must not spend a
        // resume on it (RS-5 read from the initiating side).
        if facts.peer_revoked {
            return Err(ResumeRefusal::PeerRevoked);
        }
        let path_epoch = self.next_outbound;
        self.next_outbound = self.next_outbound.saturating_add(1);
        let msg = v1::ResumeSession {
            session_nonce: self.session_nonce.as_bytes().to_vec(),
            resumption_id: self.keys.id().to_vec(),
            new_endpoint_hint,
            path_epoch,
            revocation_epoch: facts.revocation_epoch,
        };
        let mut datagram = msg.encode_to_vec();
        let tag = self.keys.tag(self.keys.local_role, &datagram)?;
        datagram.extend_from_slice(&tag);
        Ok(datagram)
    }

    /// **The consumer.** Authenticates, freshness-checks and authorizes one
    /// datagram, committing its `path_epoch` only on full success.
    pub fn accept(
        &mut self,
        datagram: &[u8],
        facts: PeerTrustFacts,
        now: ElapsedInstant,
    ) -> Result<AcceptedResume, ResumeRefusal> {
        let (body, tag) = split_tag(datagram)?;
        let msg = validate::decode::<v1::ResumeSession>(body, Channel::PeerDatagram).map_err(
            |reject| ResumeRefusal::Malformed {
                rule: "resume_session",
                code: reject.reason_code(),
            },
        )?;

        let nonce = validate::session_nonce(&msg.session_nonce).map_err(|reject| {
            ResumeRefusal::Malformed {
                rule: "session_nonce",
                code: reject.reason_code(),
            }
        })?;
        if nonce != self.session_nonce {
            return Err(ResumeRefusal::WrongSession);
        }
        if !ct_eq(&msg.resumption_id, self.keys.id()) {
            return Err(ResumeRefusal::UnknownResumptionId);
        }

        // The cheap shed, before the MAC: `twinvpn-crypto`'s documented
        // discipline is check-then-AEAD-then-record, and RS-4's comparison costs
        // one integer compare against an obvious flood.
        if !self.epoch_is_strictly_new(msg.path_epoch) {
            return Err(ResumeRefusal::Replayed {
                path_epoch: msg.path_epoch,
            });
        }

        // **Nothing below this line runs on unauthenticated input.**
        let expected = self.keys.tag(peer_role(self.keys.local_role), body)?;
        if !ct_eq(&expected, tag) {
            return Err(ResumeRefusal::Unauthenticated);
        }

        if !self.is_fresh(now) {
            return Err(ResumeRefusal::Expired);
        }
        // §12.1's authorization row, both halves.
        if facts.peer_revoked {
            return Err(ResumeRefusal::PeerRevoked);
        }
        if msg.revocation_epoch < facts.revocation_epoch {
            return Err(ResumeRefusal::TrustEpochBehind {
                offered: msg.revocation_epoch,
                local: facts.revocation_epoch,
            });
        }

        let new_endpoint_hint = match msg.new_endpoint_hint.as_ref() {
            Some(e) => Some(
                validate::endpoint(e).map_err(|reject| ResumeRefusal::Malformed {
                    rule: "new_endpoint_hint",
                    code: reject.reason_code(),
                })?,
            ),
            None => None,
        };

        // Commit last, so a refusal above leaves the window exactly as it was.
        self.seen
            .accept(msg.path_epoch)
            .map_err(|_| ResumeRefusal::Replayed {
                path_epoch: msg.path_epoch,
            })?;
        // RS-3: re-binding an existing Tunnel must not create a second Session
        // and must not reset counters. Nothing here touches either — the send
        // epoch only ever moves forward, past whatever the peer just used, so
        // the two directions cannot collide on one value.
        self.next_outbound = self.next_outbound.max(msg.path_epoch.saturating_add(1));
        Ok(AcceptedResume {
            path_epoch: msg.path_epoch,
            new_endpoint_hint,
            revocation_epoch: msg.revocation_epoch,
        })
    }

    /// **RS-4**, stricter than the sliding window it reads.
    fn epoch_is_strictly_new(&self, path_epoch: u64) -> bool {
        self.seen.would_accept(path_epoch) && self.seen.highest().is_none_or(|h| path_epoch > h)
    }
}

impl core::fmt::Debug for ResumeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResumeState")
            .field("highest_accepted_epoch", &self.seen.highest())
            .field("next_outbound", &self.next_outbound)
            .finish_non_exhaustive()
    }
}
