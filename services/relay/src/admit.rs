//! Leg admission and the control surface: `HANDSHAKE_INIT`, `BIND`, `REBIND`,
//! `CAPS`, and the `DRAIN` the relay originates.
//!
//! **Authority:** ADR-0005 §11.1 (rendezvous), §11.3 (offline admission), §11.5
//! (resource control, "overload is never silent"), §8 and §10 (drain);
//! ADR-0006 §11.4/§11.5 (failover and the listening posture).
//!
//! # Where the boundary between this module and [`crate::pump`] falls
//!
//! `pump` owns the **forwarding path** — the per-datagram work on the highest
//! rate path in the system. This module owns everything that happens **once per
//! leg or once per peer**: an X25519 handshake, a COSE_Sign1 verification, a
//! table insert. Splitting them is not tidiness; it is ADR-0005 §11.5's
//! separation between what an attacker can make the relay do per packet and what
//! it can make it do per round trip, and it is why the rate limits in `resource`
//! can be reasoned about at all.
//!
//! # `BIND` is authenticated by the leg, not by a second token check
//!
//! The token is verified **once**, inside the handshake, and the resulting
//! [`crate::token::VerifiedToken`] is held on the leg. A `BIND` arriving on an
//! established leg is already authenticated — its frame MAC verifies under
//! `K_leg`, and `K_leg` exists only because that token verified and the device
//! proved possession of the `RLK` it was issued for.
//!
//! Re-verifying per `BIND` would put an asymmetric operation on a path a
//! *listening* device uses at ADR-0006 §11.5's cadence — the top `k_rdv` = 2
//! relays per `TrustedPeer`, re-`BIND`ing every ≤ 30 s — which is up to 30
//! binds/min/subject by the frozen limit. That is the shape ADR-0005 §11.3's
//! "no control-plane call, per packet, per bind, or per reconnect" is guarding
//! against, applied to the relay's own CPU.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::condition::Condition;
use crate::control::{
    bucket_accepted, BindBody, BoundBody, BoundState, CapsBody, DrainBody, Family,
};
use crate::crypto::LegKey;
use crate::engine::BindResult;
use crate::flow::{FlowId, PairTag};
use crate::frame::{FrameType, RelayFrame};
use crate::leg::{CookieJar, LegHandshake, COOKIE_BYTES};
use crate::pump::{Action, Drop, Pump};
use crate::status::RelayStatus;
use crate::token::PresentedToken;

/// The `flags` bit a `HANDSHAKE_INIT` sets when it carries a cookie.
pub const FLAG_CARRIES_COOKIE: u8 = 0x01;

/// The handshake-payload envelope version.
pub const PRESENTATION_VERSION: u8 = 1;

/// The fixed prefix of a token presentation.
pub const PRESENTATION_PREFIX_BYTES: usize = 1 + 1 + 2;

/// The largest issuer key id a presentation may name.
///
/// Bounded before the id is copied out. Issuer key ids in
/// `issuer-keys.json` are short labels; 64 octets is generous and finite, which
/// is the property that matters on an unauthenticated path.
pub const MAX_ISSUER_KEY_ID_BYTES: usize = 64;

/// What a device puts in the `Noise_IK` message-1 payload.
///
/// ```text
/// [version:u8][key_id_len:u8][reserved:u16][issuer_key_id][cose_sign1 …]
/// ```
///
/// **Proposed, not frozen**, like every other body in [`crate::control`], and
/// versioned by its own first octet so that changing it is an ADR-0014 event
/// rather than a silent incompatibility.
///
/// The token travels *inside* the handshake rather than in a following frame,
/// which buys two things: leg setup is one round trip, and `IK`'s first message
/// already encrypts its payload to the relay's static — so a bearer credential
/// is never on the wire in the clear, even before a leg exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPresentation {
    /// Which held issuer key the token claims to be signed by. A hint for
    /// lookup only: it selects the key, and the signature decides.
    pub issuer_key_id: String,
    /// The COSE_Sign1 envelope, forwarded to verification **exactly** as it
    /// arrived (`Auth.signed_payload`: verify over the received octets).
    pub cose_sign1: Vec<u8>,
}

impl TokenPresentation {
    /// The payload octets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let id = self.issuer_key_id.as_bytes();
        let id_len = id.len().min(MAX_ISSUER_KEY_ID_BYTES);
        let mut out =
            Vec::with_capacity(PRESENTATION_PREFIX_BYTES + id_len + self.cose_sign1.len());
        out.push(PRESENTATION_VERSION);
        out.push(u8::try_from(id_len).unwrap_or(0));
        out.extend_from_slice(&0_u16.to_be_bytes()); // reserved: zero on send
        out.extend_from_slice(&id[..id_len]);
        out.extend_from_slice(&self.cose_sign1);
        out
    }

    /// Decodes a payload.
    ///
    /// # Errors
    ///
    /// The [`Condition`] that refused it — always one of the token conditions,
    /// because from the device's side a presentation it cannot encode is a
    /// token that does not admit it.
    pub fn decode(payload: &[u8]) -> Result<Self, Condition> {
        if payload.len() < PRESENTATION_PREFIX_BYTES {
            return Err(Condition::TokenMissing);
        }
        if payload[0] != PRESENTATION_VERSION {
            return Err(Condition::VersionUnsupported);
        }
        let id_len = usize::from(payload[1]);
        if id_len > MAX_ISSUER_KEY_ID_BYTES {
            return Err(Condition::TokenInvalid);
        }
        let id_end = PRESENTATION_PREFIX_BYTES + id_len;
        if payload.len() < id_end {
            return Err(Condition::TokenMissing);
        }
        let issuer_key_id = core::str::from_utf8(&payload[PRESENTATION_PREFIX_BYTES..id_end])
            .map_err(|_| Condition::TokenInvalid)?
            .to_owned();
        let cose_sign1 = payload[id_end..].to_vec();
        if cose_sign1.is_empty() {
            return Err(Condition::TokenMissing);
        }
        Ok(Self {
            issuer_key_id,
            cose_sign1,
        })
    }
}

/// Everything leg establishment needs that the pump does not.
///
/// Held once, for the life of the process, and **absent** when the relay has no
/// static key: `Option<LegSetup>` is how "this build cannot establish a leg"
/// stays a visible fact rather than a runtime surprise.
pub struct LegSetup {
    /// The relay's static X25519 private key. ADR-0005 §7.1's first inventory
    /// item — and the reason [`crate::config`] holds only a *path*: this crate
    /// has no use for the key that is not a Noise handshake, and the handshake
    /// lives behind a seam.
    pub static_private: twinvpn_crypto::LockedBytes,
    /// The injected CSPRNG.
    pub entropy: std::sync::Arc<dyn twinvpn_crypto::relay_leg::Entropy>,
    /// The stateless cookie secret.
    pub cookies: CookieJar,
}

impl std::fmt::Debug for LegSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegSetup")
            .field("static_private", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Pump<'_> {
    /// `HANDSHAKE_INIT` — the whole of leg establishment.
    ///
    /// Follows the order in [`crate::leg`]'s table, and every refusal is zero
    /// bytes except the deliberate cookie challenge.
    pub(crate) fn handshake(
        &mut self,
        from: SocketAddr,
        frame: &RelayFrame,
        now_ms: u64,
    ) -> Action {
        let Some(setup) = self.setup else {
            // No static key: this relay cannot answer a handshake. Fail closed
            // and silently — telling an unauthenticated source that the relay is
            // misconfigured is free reconnaissance.
            return Action::Silent { why: Drop::NoLeg };
        };
        let body = frame.payload().as_bytes();

        // Steps 1–3: the cookie gate, BEFORE any asymmetric operation (§11.5).
        let (cookie, noise_message) = if frame.flags() & FLAG_CARRIES_COOKIE == 0 {
            (None, body)
        } else if body.len() > COOKIE_BYTES {
            (Some(&body[..COOKIE_BYTES]), &body[COOKIE_BYTES..])
        } else {
            return Action::Silent {
                why: Drop::Malformed,
            };
        };

        let validated = cookie.is_some_and(|c| setup.cookies.verify(self.crypto, from, c, now_ms));
        if !validated
            && !self
                .engine
                .allows_handshake(from, std::time::Instant::now())
        {
            // Over the per-/24 or per-/48 threshold and no valid cookie: answer
            // with a challenge and do NO public-key work. One datagram out, far
            // smaller than the one that provoked it, so amplification stays < 1.
            let Some(challenge) = setup.cookies.issue(self.crypto, from, now_ms) else {
                return Action::Silent {
                    why: Drop::NoEgressMac,
                };
            };
            return Action::Send {
                to: from,
                datagram: Bytes::from(crate::control::encode_frame(
                    FrameType::CookieChallenge,
                    frame.flow_id(),
                    0,
                    [0; 8],
                    &challenge,
                )),
            };
        }

        // Step 4: the handshake. This is the first asymmetric operation, and it
        // happens only for a source that either was under the threshold or
        // completed a round trip.
        let hs = LegHandshake {
            static_private: setup.static_private.expose(),
            entropy: &setup.entropy,
            cookies: &setup.cookies,
            crypto: self.crypto,
        };
        let Ok((response, completed)) = hs.step(from, noise_message) else {
            return Action::Silent {
                why: Drop::MacInvalid,
            };
        };

        // Steps 5–6: the token, then `cnf` against the static the device just
        // proved possession of. ADR-0005 §11.3's order exactly.
        let Ok(presentation) = TokenPresentation::decode(completed.payload()) else {
            return Action::Silent {
                why: Drop::Unauthorized,
            };
        };
        let presented = PresentedToken::new(presentation.issuer_key_id, presentation.cose_sign1);
        // The `cnf` claim carries `RLK_pub` as a COSE_Key, so the comparison is
        // made in that encoding — built by the ONE encoder both ends share
        // (`twinvpn_crypto::x25519_cose_key`), because two would disagree
        // silently and refuse every legitimate token.
        let presented_leg_key = twinvpn_crypto::x25519_cose_key(completed.remote_static());
        let Ok(token) = self
            .engine
            .admit(&presented, &presented_leg_key, self.crypto, now_ms)
        else {
            return Action::Silent {
                why: Drop::Unauthorized,
            };
        };

        // Step 7: bounded admission.
        let subject = token.subject();
        let k_leg = LegKey::new(*completed.k_leg());
        if !self.legs.establish(from, k_leg, token, now_ms) {
            return Action::Silent {
                why: Drop::LegLimit,
            };
        }
        let _ = subject;

        Action::Send {
            to: from,
            datagram: Bytes::from(crate::control::encode_frame(
                FrameType::HandshakeResp,
                frame.flow_id(),
                0,
                [0; 8],
                &response,
            )),
        }
    }

    /// `BIND` and `REBIND` — the `pair_tag` rendezvous of ADR-0005 §11.1(3)/(4).
    pub(crate) fn bind(
        &mut self,
        from: SocketAddr,
        frame: &RelayFrame,
        ingress_key: &LegKey,
        now_ms: u64,
    ) -> Action {
        let Ok(body) = BindBody::decode(frame.payload().as_bytes()) else {
            return Action::Silent {
                why: Drop::Malformed,
            };
        };
        // The bucket, checked against the relay's own clock with the frozen skew.
        // A tag from a bucket the relay is not in is not an error to argue about:
        // it is a tag that cannot match, because the peer derived a different one.
        let bucket_now = now_ms / 1_000 / self.engine.config().pair_tag_bucket_seconds.max(1);
        if !bucket_accepted(
            bucket_now,
            body.bucket,
            self.engine.config().pair_tag_accepted_skew,
        ) {
            return self.refuse_bind(frame, ingress_key, Condition::PairUnmatched);
        }
        let Ok(tag) = PairTag::from_wire(&body.pair_tag) else {
            return Action::Silent {
                why: Drop::Malformed,
            };
        };

        let Some(leg) = self.legs.get(from) else {
            return Action::Silent { why: Drop::NoLeg };
        };
        let token = leg.token().clone();
        match self
            .engine
            .bind(tag, from, &token, std::time::Instant::now(), now_ms)
        {
            BindResult::Pending(flow_id) => {
                self.bound(frame, ingress_key, flow_id, BoundState::Pending, from)
            }
            BindResult::Bound {
                flow_id,
                peer_flow_id,
            } => {
                // Both peers receive `BOUND{flow_id}` (§11.1(4)). This datagram
                // answers the arriving half; the waiting half is told by
                // `announce_bound`, which the caller drains — one datagram per
                // received datagram is preserved because the second is not a
                // *reply*, it is an announcement onto an already-bound flow, the
                // same class as `DRAIN` and `RELAY_STATUS` (§11.5).
                self.pending_announcements.push((peer_flow_id, flow_id));
                self.bound(frame, ingress_key, flow_id, BoundState::Bound, from)
            }
            BindResult::Refused(condition) => self.refuse_bind(frame, ingress_key, condition),
        }
    }

    /// `CAPS` — version and capability negotiation (ADR-0005 §10).
    pub(crate) fn caps(&mut self, from: SocketAddr, frame: &RelayFrame, key: &LegKey) -> Action {
        // A device's own CAPS body is read only to refuse an incompatible one;
        // the relay's answer is always its own capability set.
        if let Ok(theirs) = CapsBody::decode(frame.payload().as_bytes()) {
            if !theirs.speaks(crate::frame::VERSION) {
                return self.refuse_bind(frame, key, Condition::VersionUnsupported);
            }
        }
        let body = CapsBody::of_this_build().encode();
        self.signed(FrameType::Caps, frame.flow_id(), key, &body, from)
    }

    /// The `BOUND` answer.
    fn bound(
        &mut self,
        frame: &RelayFrame,
        key: &LegKey,
        flow_id: FlowId,
        state: BoundState,
        to: SocketAddr,
    ) -> Action {
        let body = BoundBody {
            state,
            pending_ttl_ms: u32::try_from(self.engine.config().pending_slot_ttl_ms)
                .unwrap_or(u32::MAX),
        }
        .encode();
        let _ = frame;
        self.signed(FrameType::Bound, flow_id.get(), key, &body, to)
    }

    /// A refused `BIND` is a `RELAY_STATUS`, never silence.
    ///
    /// ADR-0005 §11.5: "**Overload is never silent (I6, RQ9).** Whenever the
    /// relay throttles, sheds, or drains, it MUST emit `RELAY_STATUS` … A relay
    /// that drops without a status frame is a defect." A refused bind is the
    /// case a device most needs told about, because the alternative is a
    /// listening posture that retries for ever against a relay that will never
    /// admit it.
    fn refuse_bind(&mut self, frame: &RelayFrame, key: &LegKey, condition: Condition) -> Action {
        let status = RelayStatus::for_condition(condition, retry_after_for(condition));
        let body = status.encode_body();
        let to = self.last_source;
        self.signed(FrameType::RelayStatus, frame.flow_id(), key, &body, to)
    }

    /// Assembles, MACs and addresses one outgoing control frame.
    ///
    /// **If no MAC can be computed, nothing is sent.** An unauthenticated
    /// control frame is worse than none: it is a free injection primitive for
    /// anyone who can spoof a source address, and a device that acted on one
    /// would migrate, unbind or throttle on an attacker's say-so.
    fn signed(
        &mut self,
        kind: FrameType,
        flow_id: u32,
        key: &LegKey,
        body: &[u8],
        to: SocketAddr,
    ) -> Action {
        let mac_input = crate::control::mac_input(kind, flow_id, 0, body);
        let Some(tag) = self.crypto.frame_mac(key, &mac_input) else {
            return Action::Silent {
                why: Drop::NoEgressMac,
            };
        };
        Action::Send {
            to,
            datagram: Bytes::from(crate::control::encode_frame(kind, flow_id, 0, tag, body)),
        }
    }

    /// The `DRAIN` datagram for one bound flow, if its leg can be MACed.
    ///
    /// Announced by the shutdown path rather than in response to a datagram, so
    /// it is one of the two frames ADR-0005 §11.5 permits the relay to originate
    /// — and, like the other, only onto an already-bound, authenticated flow.
    #[must_use]
    pub fn drain_datagram(
        &self,
        flow: FlowId,
        deadline_ms: u64,
        suggestions: &[[u8; twinvpn_schema::limits::RELAY_ID_BYTES]],
    ) -> Option<(SocketAddr, Bytes)> {
        let pair = self.engine.table().bound_for_flow(flow)?;
        let peer = pair.ingress_peer(flow)?;
        let key = self.legs.key_for(peer)?;
        let body = DrainBody {
            drain_deadline_ms: deadline_ms,
            suggested_relay_ids: suggestions.to_vec(),
        }
        .encode();
        let mac_input = crate::control::mac_input(FrameType::Drain, flow.get(), 0, &body);
        let tag = self.crypto.frame_mac(key, &mac_input)?;
        Some((
            peer,
            Bytes::from(crate::control::encode_frame(
                FrameType::Drain,
                flow.get(),
                0,
                tag,
                &body,
            )),
        ))
    }

    /// The `BOUND` datagram for the half-flow that was already waiting.
    #[must_use]
    pub fn announcement_datagram(
        &self,
        waiting: FlowId,
        pending_ttl_ms: u64,
    ) -> Option<(SocketAddr, Bytes)> {
        let pair = self.engine.table().bound_for_flow(waiting)?;
        let peer = pair.ingress_peer(waiting)?;
        let key = self.legs.key_for(peer)?;
        let body = BoundBody {
            state: BoundState::Bound,
            pending_ttl_ms: u32::try_from(pending_ttl_ms).unwrap_or(u32::MAX),
        }
        .encode();
        let mac_input = crate::control::mac_input(FrameType::Bound, waiting.get(), 0, &body);
        let tag = self.crypto.frame_mac(key, &mac_input)?;
        Some((
            peer,
            Bytes::from(crate::control::encode_frame(
                FrameType::Bound,
                waiting.get(),
                0,
                tag,
                &body,
            )),
        ))
    }
}

/// How long a device should wait before retrying, per condition.
///
/// Derived from what the condition *is*, not guessed: a rate limit clears in a
/// second, a bind-rate limit in the minute it is measured over, an hourly quota
/// in an hour, and a drain never — the device is meant to leave, not to retry.
const fn retry_after_for(condition: Condition) -> u32 {
    match condition {
        Condition::RateLimited => 1_000,
        Condition::BindRateLimited => 60_000,
        Condition::QuotaExceeded => 3_600_000,
        Condition::PairUnmatched => 30_000,
        Condition::Draining => 0,
        _ => 5_000,
    }
}

/// The family a half-flow is actually on, for the observability label.
#[must_use]
pub const fn family_of(peer: SocketAddr) -> Family {
    Family::of(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_presentation_round_trips() {
        let p = TokenPresentation {
            issuer_key_id: "k1".into(),
            cose_sign1: b"envelope-octets".to_vec(),
        };
        assert_eq!(TokenPresentation::decode(&p.encode()).expect("decodes"), p);
    }

    #[test]
    fn a_short_presentation_is_refused_before_indexing() {
        for len in 0..PRESENTATION_PREFIX_BYTES {
            assert_eq!(
                TokenPresentation::decode(&vec![PRESENTATION_VERSION; len]),
                Err(Condition::TokenMissing)
            );
        }
        // A declared key-id length not backed by octets.
        let payload = vec![PRESENTATION_VERSION, 40, 0, 0];
        assert_eq!(
            TokenPresentation::decode(&payload),
            Err(Condition::TokenMissing)
        );
    }

    #[test]
    fn an_oversized_issuer_key_id_is_refused_rather_than_truncated() {
        let mut payload = vec![PRESENTATION_VERSION, 255, 0, 0];
        payload.extend_from_slice(&[b'a'; 300]);
        assert_eq!(
            TokenPresentation::decode(&payload),
            Err(Condition::TokenInvalid),
            "a length over the ceiling is a refusal, never a truncation \
             (`ownership.md` §6 rule 9)"
        );
    }

    #[test]
    fn a_presentation_with_no_envelope_is_token_missing_not_an_empty_verify() {
        let payload = vec![PRESENTATION_VERSION, 2, 0, 0, b'k', b'1'];
        assert_eq!(
            TokenPresentation::decode(&payload),
            Err(Condition::TokenMissing)
        );
    }

    #[test]
    fn a_future_presentation_version_is_named_not_guessed() {
        let payload = vec![PRESENTATION_VERSION + 1, 0, 0, 0, 1];
        assert_eq!(
            TokenPresentation::decode(&payload),
            Err(Condition::VersionUnsupported)
        );
    }

    #[test]
    fn a_non_utf8_issuer_key_id_is_refused() {
        let payload = vec![PRESENTATION_VERSION, 2, 0, 0, 0xFF, 0xFE, 1];
        assert_eq!(
            TokenPresentation::decode(&payload),
            Err(Condition::TokenInvalid)
        );
    }

    #[test]
    fn every_refusal_carries_a_retry_hint_that_matches_its_own_timescale() {
        // A device that retried a spent hourly quota every second would be
        // rate-limited for the rest of the hour by its own retries.
        assert!(
            retry_after_for(Condition::QuotaExceeded) > retry_after_for(Condition::RateLimited)
        );
        assert!(
            retry_after_for(Condition::BindRateLimited) > retry_after_for(Condition::RateLimited)
        );
        assert_eq!(retry_after_for(Condition::Draining), 0);
    }
}
