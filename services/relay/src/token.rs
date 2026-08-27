//! `RelayCapabilityToken` verification — a pure function, performed offline.
//!
//! ADR-0005 §11.3:
//!
//! > **Verification is a pure function**, performed entirely offline by the
//! > relay: COSE signature against a held issuer key → `aud` matches this
//! > operator group → `cnf` equals the presented relay-leg static → `nbf`/`exp`
//! > within skew → `epoch ≥ epoch_floor` → `jti` unseen. **No control-plane call,
//! > per packet, per bind, or per reconnect.**
//!
//! [`verify`] is that function, in that order, and it is `fn` — not `async fn`.
//! **That is the structural form of I5**: a synchronous, non-`async` function
//! taking only already-held state cannot make a network call, so no future
//! maintainer can add one without changing the signature and every caller.
//!
//! `contracts/proto/twinvpn/v1/relay.proto` warns about the other half:
//!
//! > A verifier MUST verify the COSE signature and read the claims FROM THE
//! > VERIFIED PAYLOAD. The decoded fields here are attacker-controlled until then.
//!
//! [`PresentedToken`] is therefore the *untrusted* shape, [`VerifiedToken`] the
//! trusted one, and the only way to obtain the latter is [`verify`]. Nothing in
//! this crate constructs a `VerifiedToken` by any other route.

use crate::condition::Condition;
use crate::crypto::RelayCrypto;
use crate::epoch::EpochFloor;
use crate::issuer::IssuerKeySet;
use crate::replay::{Jti, ReplayCache, ReplayVerdict};
use crate::subject::RelaySub;

/// The quota claims a token carries (ADR-0005 §11.3, `relay.proto RelayQuota`).
///
/// Quota values travel **in the token** so a relay enforces the issuer's policy
/// with no lookup (§11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// ADR-0005 §11.5 default 64.
    pub max_concurrent_flows: u32,
    /// Default 20 Mbit/s.
    pub max_bitrate_kbps: u32,
    /// Default 20 GiB.
    pub max_bytes_per_hour: u64,
    /// Default 30. ADR-0006 §11.15(b) requires this to be raisable for
    /// gateway-class devices, or the ≈15-peer rendezvous-listening ceiling stands.
    pub max_binds_per_min: u32,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            max_concurrent_flows: 64,
            max_bitrate_kbps: 20_000,
            max_bytes_per_hour: 20 * 1024 * 1024 * 1024,
            max_binds_per_min: 30,
        }
    }
}

/// A token as it arrived: **attacker-controlled until [`verify`] returns `Ok`.**
///
/// `signed_bytes` are the COSE_Sign1 payload octets exactly as received. They are
/// verified verbatim and never decoded-then-re-encoded (W-4).
#[derive(Debug, Clone)]
pub struct PresentedToken {
    /// `iss`.
    pub issuer_key_id: String,
    /// The signed payload, verbatim.
    pub signed_bytes: Vec<u8>,
    /// The detached signature.
    pub signature: Vec<u8>,
    /// `aud` — the **operator group**, never a single `relay_id`.
    pub audience_operator_group_id: String,
    /// `sub` — the per-operator, per-day pseudonym. Never `device_id`.
    pub subject: [u8; 16],
    /// `cnf` — RFC 7800, carrying `RLK_pub`.
    pub confirmation_key: Vec<u8>,
    /// `nbf`.
    pub not_before_ms: u64,
    /// `exp`.
    pub not_after_ms: u64,
    /// `epoch` — the S-03 trust epoch at issuance.
    pub epoch: u64,
    /// `quota`.
    pub quota: Quota,
    /// `jti` — 16 random bytes for the bounded replay cache.
    pub jti: Jti,
}

/// A token that has passed every check in ADR-0005 §11.3.
///
/// Deliberately carries **no** issuer bytes, no signature and no `cnf`: past
/// verification they are spent, and keeping them alive would invite a second,
/// weaker check somewhere downstream.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    subject: RelaySub,
    epoch: u64,
    not_after_ms: u64,
    quota: Quota,
}

impl VerifiedToken {
    /// The quota key. See [`RelaySub`] for why it cannot be logged.
    #[must_use]
    pub const fn subject(&self) -> RelaySub {
        self.subject
    }

    /// The trust epoch this token was issued at.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// `exp`.
    #[must_use]
    pub const fn not_after_ms(&self) -> u64 {
        self.not_after_ms
    }

    /// The issuer's quota policy, carried in the token.
    #[must_use]
    pub const fn quota(&self) -> Quota {
        self.quota
    }
}

/// Everything [`verify`] needs, all of it already held by the relay.
///
/// There is no client, no pool, no channel and no address in this struct. That
/// absence is I5 (`ownership.md` §6, ADR-0005 RQ2): admission is a pure function
/// of `(token, the relay's own configuration)`.
pub struct VerifyContext<'a> {
    /// This relay's operator group, from `TWINVPN_RELAY_OPERATOR_GROUP_ID`.
    pub operator_group_id: &'a str,
    /// The held issuer public keys. Empty means admit nothing.
    pub issuers: &'a IssuerKeySet,
    /// The current trust-epoch floor.
    pub floor: &'a EpochFloor,
    /// The relay-leg static key the device actually proved possession of, which
    /// `cnf` must equal (ADR-0005 §7.6 — a stolen token without `RLK` is inert).
    pub presented_leg_key: &'a [u8],
    /// The relay's own current time, in milliseconds.
    pub now_ms: u64,
    /// `limits.json relay.token_clock_skew_ms`, 300 000.
    pub clock_skew_ms: u64,
}

/// Verifies a presented token, entirely offline.
///
/// The order is ADR-0005 §11.3's, and it is load-bearing: the cheap, purely local
/// checks that cannot be influenced into an asymmetric operation run first, so a
/// flood of tokens for the wrong operator group costs no signature verification
/// (§11.5's "the relay performs no asymmetric operation for an unvalidated source
/// address" applied one layer up).
///
/// # Errors
///
/// The [`Condition`] that refused it. Every one maps to a registered
/// `reason_code` via [`Condition::reason_code`].
pub fn verify(
    presented: &PresentedToken,
    ctx: &VerifyContext<'_>,
    crypto: &dyn RelayCrypto,
    replay: &mut ReplayCache,
) -> Result<VerifiedToken, Condition> {
    // 0. Structural: a token with no signature or no payload is TOKEN_MISSING,
    //    not TOKEN_INVALID — the device presented nothing to check.
    if presented.signed_bytes.is_empty() || presented.signature.is_empty() {
        return Err(Condition::TokenMissing);
    }

    // 1. `aud` matches this operator group. Purely local, no allocation, and it
    //    rejects a whole TwinNet's traffic aimed at the wrong operator before any
    //    cryptography runs. ADR-0005 §10: `aud` scoping makes cross-TwinNet abuse
    //    structurally impossible.
    if presented.audience_operator_group_id != ctx.operator_group_id {
        return Err(Condition::TokenAudienceMismatch);
    }

    // 2. Validity window with the frozen skew. Also cheap and local, and it is
    //    the single most common legitimate refusal.
    if presented.now_is_before_window(ctx.now_ms, ctx.clock_skew_ms) {
        return Err(Condition::TokenNotYetValid);
    }
    if presented.now_is_after_window(ctx.now_ms, ctx.clock_skew_ms) {
        return Err(Condition::TokenExpired);
    }

    // 3. Proof of possession. `cnf` must equal the leg key the device actually
    //    used, so a stolen token without `RLK` is inert (§7.6). Compared before
    //    the signature so a token harvested from another device costs nothing.
    if presented.confirmation_key.is_empty()
        || presented.confirmation_key.as_slice() != ctx.presented_leg_key
    {
        return Err(Condition::TokenPopFailed);
    }

    // 4. The issuer must be held. An EMPTY key set lands here and refuses —
    //    the fail-closed default (infra/scripts/bootstrap-local.sh).
    let Some(key) = ctx.issuers.find(&presented.issuer_key_id) else {
        return Err(Condition::IssuerUnknown);
    };

    // 5. The signature, over the received octets verbatim.
    if !crypto.verify_signature(key, &presented.signed_bytes, &presented.signature) {
        return Err(Condition::TokenInvalid);
    }

    // 6. `epoch >= epoch_floor`. Defence in depth: revocation is enforced at the
    //    peer (ADR-0005 §11.3), so a lagging floor leaks no confidentiality.
    if !ctx.floor.admits(presented.epoch) {
        return Err(Condition::TokenEpochStale);
    }

    // 7. `jti` unseen, against a bounded cache. Last, because it MUTATES: an
    //    earlier position would let an attacker burn cache entries with tokens
    //    that were going to be refused anyway.
    if replay.admit(presented.jti, ctx.now_ms) == ReplayVerdict::Replayed {
        return Err(Condition::TokenReplayed);
    }

    Ok(VerifiedToken {
        subject: RelaySub::from_verified_claim(presented.subject),
        epoch: presented.epoch,
        not_after_ms: presented.not_after_ms,
        quota: presented.quota,
    })
}

/// Whether a relay may renew this token itself (ADR-0005 §11.3, normative).
///
/// All three conditions, and no others:
///
/// 1. the token verifies and its `epoch` is **equal to** the current floor —
///    epoch equality is the proof that no revocation intervened;
/// 2. it is within `exp + T_RELAY_GRACE`;
/// 3. the device demonstrated possession of the bound `RLK` on the live leg.
///
/// Renewal "is **not** a new grant: a relay can only extend an authority the
/// control plane already issued, at an epoch the control plane already published,
/// and never above its own `epoch_floor`."
#[must_use]
pub fn may_relay_renew(
    presented: &PresentedToken,
    floor: &EpochFloor,
    pop_proven_on_live_leg: bool,
    now_ms: u64,
    grace_ms: u64,
) -> bool {
    pop_proven_on_live_leg
        && floor.permits_relay_renewal(presented.epoch)
        && now_ms <= presented.not_after_ms.saturating_add(grace_ms)
}

impl PresentedToken {
    fn now_is_before_window(&self, now_ms: u64, skew_ms: u64) -> bool {
        now_ms < self.not_before_ms.saturating_sub(skew_ms)
    }

    fn now_is_after_window(&self, now_ms: u64, skew_ms: u64) -> bool {
        now_ms > self.not_after_ms.saturating_add(skew_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{FailClosed, IssuerPublicKey, LegKey};

    struct AlwaysVerifies;
    impl RelayCrypto for AlwaysVerifies {
        fn verify_signature(&self, _: &IssuerPublicKey, _: &[u8], _: &[u8]) -> bool {
            true
        }
        fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
            true
        }
        fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
            Some([0; 8])
        }
        fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
            Some([1; 16])
        }
    }

    const LEG: &[u8] = b"RLK-public-bytes";
    const SKEW: u64 = 300_000;

    fn issuers(populated: bool) -> IssuerKeySet {
        let raw = if populated {
            r#"{"operator_group_id":"local-operator","issuers":[{"key_id":"k1","alg":"Ed25519","public_key_hex":"0102"}]}"#
        } else {
            r#"{"operator_group_id":"local-operator","issuers":[]}"#
        };
        IssuerKeySet::parse(raw, "local-operator", "x").expect("parses")
    }

    fn token() -> PresentedToken {
        PresentedToken {
            issuer_key_id: "k1".into(),
            signed_bytes: b"cose-payload".to_vec(),
            signature: b"sig".to_vec(),
            audience_operator_group_id: "local-operator".into(),
            subject: [9; 16],
            confirmation_key: LEG.to_vec(),
            not_before_ms: 1_000_000,
            not_after_ms: 1_000_000 + 86_400_000,
            epoch: 5,
            quota: Quota::default(),
            jti: [3; 16],
        }
    }

    fn ctx<'a>(issuers: &'a IssuerKeySet, floor: &'a EpochFloor, now_ms: u64) -> VerifyContext<'a> {
        VerifyContext {
            operator_group_id: "local-operator",
            issuers,
            floor,
            presented_leg_key: LEG,
            now_ms,
            clock_skew_ms: SKEW,
        }
    }

    #[test]
    fn a_good_token_verifies() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let v = verify(&token(), &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).expect("ok");
        assert_eq!(v.epoch(), 5);
        assert_eq!(v.quota().max_concurrent_flows, 64);
    }

    #[test]
    fn an_empty_issuer_set_fails_closed() {
        let (i, f) = (issuers(false), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        assert_eq!(
            verify(&token(), &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::IssuerUnknown
        );
    }

    #[test]
    fn the_fail_closed_crypto_provider_admits_nothing_even_with_issuers_held() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        assert_eq!(
            verify(&token(), &ctx(&i, &f, 1_500_000), &FailClosed, &mut r).unwrap_err(),
            Condition::TokenInvalid
        );
    }

    #[test]
    fn a_token_below_the_floor_must_not_be_used() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(9));
        let mut r = ReplayCache::frozen_default();
        assert_eq!(
            verify(&token(), &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::TokenEpochStale
        );
    }

    #[test]
    fn an_expired_token_is_refused_and_the_skew_window_is_honoured() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let t = token();
        // Exactly at exp + skew: still accepted.
        assert!(verify(
            &t,
            &ctx(&i, &f, t.not_after_ms + SKEW),
            &AlwaysVerifies,
            &mut r
        )
        .is_ok());
        // One millisecond past: refused.
        assert_eq!(
            verify(
                &t,
                &ctx(&i, &f, t.not_after_ms + SKEW + 1),
                &AlwaysVerifies,
                &mut r
            )
            .unwrap_err(),
            Condition::TokenExpired
        );
    }

    #[test]
    fn a_not_yet_valid_token_is_distinguished_from_an_expired_one() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let t = token();
        assert_eq!(
            verify(
                &t,
                &ctx(&i, &f, t.not_before_ms - SKEW - 1),
                &AlwaysVerifies,
                &mut r
            )
            .unwrap_err(),
            Condition::TokenNotYetValid
        );
    }

    #[test]
    fn a_stolen_token_without_the_bound_leg_key_is_inert() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let mut c = ctx(&i, &f, 1_500_000);
        c.presented_leg_key = b"some-other-devices-RLK";
        assert_eq!(
            verify(&token(), &c, &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::TokenPopFailed
        );
    }

    #[test]
    fn a_token_for_another_operator_group_is_refused_before_any_cryptography() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let mut t = token();
        t.audience_operator_group_id = "someone-elses-fleet".into();
        assert_eq!(
            verify(&t, &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::TokenAudienceMismatch
        );
        assert!(
            r.is_empty(),
            "a refused token must not consume a replay slot"
        );
    }

    #[test]
    fn a_replayed_jti_is_refused_the_second_time() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        assert!(verify(&token(), &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).is_ok());
        assert_eq!(
            verify(&token(), &ctx(&i, &f, 1_500_001), &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::TokenReplayed
        );
    }

    #[test]
    fn a_token_that_would_fail_anyway_does_not_burn_a_replay_slot() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(9));
        let mut r = ReplayCache::frozen_default();
        let _ = verify(&token(), &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r);
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_token_is_missing_rather_than_invalid() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let mut t = token();
        t.signature.clear();
        assert_eq!(
            verify(&t, &ctx(&i, &f, 1_500_000), &AlwaysVerifies, &mut r).unwrap_err(),
            Condition::TokenMissing
        );
    }

    #[test]
    fn relay_renewal_requires_epoch_equality_grace_and_live_pop() {
        let t = token();
        let floor = EpochFloor::starting_at(5);
        let grace = 21_600_000; // T_RELAY_GRACE = 6 h
        let past_exp = t.not_after_ms + 1;

        assert!(may_relay_renew(&t, &floor, true, past_exp, grace));
        // No proof of possession on the live leg.
        assert!(!may_relay_renew(&t, &floor, false, past_exp, grace));
        // Past the grace window.
        assert!(!may_relay_renew(
            &t,
            &floor,
            true,
            t.not_after_ms + grace + 1,
            grace
        ));
        // The floor moved: epoch equality no longer holds, so a revocation may
        // have intervened and the relay must not extend the authority.
        assert!(!may_relay_renew(
            &t,
            &EpochFloor::starting_at(6),
            true,
            past_exp,
            grace
        ));
    }

    #[test]
    fn verification_is_synchronous_and_takes_only_held_state() {
        // The compile-time property: `verify` is `fn`, not `async fn`, and its
        // context holds no client and no address. A future maintainer cannot add
        // a control-plane call without changing the signature and every caller.
        // This test exists so that change is visibly a test edit (I5).
        let f: fn(
            &PresentedToken,
            &VerifyContext<'_>,
            &dyn RelayCrypto,
            &mut ReplayCache,
        ) -> Result<VerifiedToken, Condition> = verify;
        let _ = f;
    }
}
