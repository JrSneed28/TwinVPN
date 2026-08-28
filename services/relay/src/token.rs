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
//! [`verify`] is that function, **in that order**, and it is `fn` — not
//! `async fn`. That is the structural form of I5: a synchronous, non-`async`
//! function taking only already-held state cannot make a network call, so no
//! future maintainer can add one without changing the signature and every caller.
//!
//! # The signature comes first, and every claim after it is verified
//!
//! `contracts/proto/twinvpn/v1/relay.proto`:
//!
//! > A verifier MUST verify the COSE signature and read the claims **FROM THE
//! > VERIFIED PAYLOAD**. The decoded fields here are attacker-controlled until
//! > then.
//!
//! [`PresentedToken`] therefore carries **only** the issuer key id needed to
//! select a key and the COSE_Sign1 envelope exactly as it arrived. There are no
//! decoded claims on it to be tempted by, and [`VerifiedToken`] — the only type
//! carrying claims — has no constructor but [`verify`].
//!
//! An earlier revision checked `aud`, the validity window and `cnf` *before* the
//! signature, to avoid an asymmetric operation for obviously-wrong input. That
//! concern is real but is solved elsewhere: ADR-0005 §11.5's cookie gate
//! ([`crate::resource::CookieGate`]) already guarantees "no asymmetric operation
//! for an unvalidated source address". Reading unverified claims to re-solve it
//! was the wrong trade, and it is not made here.

use crate::claims::Quota;
use crate::condition::Condition;
use crate::crypto::{RelayCrypto, Statement};
use crate::epoch::EpochFloor;
use crate::issuer::IssuerKeySet;
use crate::replay::{ReplayCache, ReplayVerdict};
use crate::subject::RelaySub;

/// A token as it arrived: **nothing here is trusted until [`verify`] returns**.
///
/// Two fields, and no more. `issuer_key_id` selects a candidate key and is itself
/// attacker-controlled — naming the wrong key can only cause a refusal, never an
/// acceptance, because the signature is then checked under the key that was
/// named. `cose_sign1` is verified verbatim and never decoded-then-re-encoded.
///
/// # `Debug` is written by hand (R-9)
///
/// The derived one rendered `cose_sign1` — **the complete, replayable bearer
/// token** — as a list of digits. The tripwire below asserted only that the
/// rendering omitted the words `"epoch"`, `"quota"`, `"subject"` and
/// `"not_after"`, which a `Vec<u8>` never contains, so it passed while the
/// whole token sat in the output. A guard that reports success.
#[derive(Clone)]
pub struct PresentedToken {
    /// The `iss` the bearer claims. A *hint for key selection only*.
    pub issuer_key_id: String,
    /// The COSE_Sign1 envelope, exactly as received.
    pub cose_sign1: Vec<u8>,
}

impl std::fmt::Debug for PresentedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedToken")
            // Attacker-controlled and non-secret: it selects a candidate key,
            // and naming the wrong one can only cause a refusal.
            .field("issuer_key_id", &self.issuer_key_id)
            .field("cose_sign1_len", &self.cose_sign1.len())
            .finish()
    }
}

impl PresentedToken {
    /// A presented token.
    #[must_use]
    pub const fn new(issuer_key_id: String, cose_sign1: Vec<u8>) -> Self {
        Self {
            issuer_key_id,
            cose_sign1,
        }
    }
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
    renewed_by_relay: bool,
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

    /// Whether a relay, rather than the control plane, last extended it.
    #[must_use]
    pub const fn renewed_by_relay(&self) -> bool {
        self.renewed_by_relay
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
    /// The COSE_Key octets of the relay-leg static the device actually proved
    /// possession of, which `cnf` must equal (ADR-0005 §7.6 — a stolen token
    /// without `RLK` is inert).
    pub presented_leg_key: &'a [u8],
    /// The relay's own current time, in milliseconds.
    pub now_ms: u64,
    /// `limits.json relay.token_clock_skew_ms`, 300 000.
    pub clock_skew_ms: u64,
}

/// Verifies a presented token, entirely offline, in ADR-0005 §11.3's order.
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
    // 0. Structural: nothing was presented to check.
    if presented.cose_sign1.is_empty() {
        return Err(Condition::TokenMissing);
    }

    // 1. The issuer must be held. An EMPTY key set lands here and refuses — the
    //    fail-closed default (infra/scripts/bootstrap-local.sh). This is a map
    //    lookup, not an asymmetric operation, so it costs nothing to do first.
    let Some(key) = ctx.issuers.find(&presented.issuer_key_id) else {
        return Err(Condition::IssuerUnknown);
    };

    // 2. THE SIGNATURE, over the received octets. Everything after this line
    //    reads `claims`, which came out of the verified payload; nothing after it
    //    reads `presented`.
    let Some(verified) =
        crypto.verify_statement(key, Statement::RelayCapabilityToken, &presented.cose_sign1)
    else {
        return Err(Condition::TokenInvalid);
    };
    let Some(claims) = verified.as_token() else {
        // A verified statement of the wrong kind. Cannot happen through
        // `Statement::RelayCapabilityToken`, and is a refusal if it ever does.
        return Err(Condition::TokenInvalid);
    };

    // 3. `aud` matches this operator group. ADR-0005 §10: `aud` scoping is what
    //    makes cross-TwinNet abuse structurally impossible.
    if claims.audience_operator_group_id != ctx.operator_group_id {
        return Err(Condition::TokenAudienceMismatch);
    }

    // 4. `cnf` equals the leg key the device actually used, so a stolen token
    //    without `RLK` is inert (§7.6).
    if claims.confirmation_key.is_empty()
        || claims.confirmation_key.as_slice() != ctx.presented_leg_key
    {
        return Err(Condition::TokenPopFailed);
    }

    // 5. `nbf`/`exp` within the frozen skew.
    if ctx.now_ms < claims.not_before_ms.saturating_sub(ctx.clock_skew_ms) {
        return Err(Condition::TokenNotYetValid);
    }
    if ctx.now_ms > claims.not_after_ms.saturating_add(ctx.clock_skew_ms) {
        return Err(Condition::TokenExpired);
    }

    // 6. `epoch >= epoch_floor`. Defence in depth: revocation is enforced at the
    //    peer (§11.3), so a lagging floor leaks no confidentiality.
    if !ctx.floor.admits(claims.epoch) {
        return Err(Condition::TokenEpochStale);
    }

    // 7. `jti` unseen, against a bounded cache. Last, because it MUTATES: an
    //    earlier position would let an attacker burn cache entries with tokens
    //    that were going to be refused anyway.
    if replay.admit(claims.jti, ctx.now_ms) == ReplayVerdict::Replayed {
        return Err(Condition::TokenReplayed);
    }

    Ok(VerifiedToken {
        subject: RelaySub::from_verified_claim(claims.subject),
        epoch: claims.epoch,
        not_after_ms: claims.not_after_ms,
        quota: claims.quota,
        renewed_by_relay: claims.renewed_by_relay,
    })
}

/// Whether a relay may renew a **verified** token itself (ADR-0005 §11.3).
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
///
/// It takes a [`VerifiedToken`] rather than a [`PresentedToken`], so condition 1's
/// "the token verifies" half is discharged by the type.
#[must_use]
pub fn may_relay_renew(
    token: &VerifiedToken,
    floor: &EpochFloor,
    pop_proven_on_live_leg: bool,
    now_ms: u64,
    grace_ms: u64,
) -> bool {
    pop_proven_on_live_leg
        && floor.permits_relay_renewal(token.epoch())
        && now_ms <= token.not_after_ms().saturating_add(grace_ms)
}

#[cfg(test)]
pub(crate) mod testkit {
    //! A [`RelayCrypto`] double that verifies a token the tests construct.
    //!
    //! It exists because the real provider needs an Ed25519 keypair and a
    //! canonical COSE_Sign1 envelope to produce anything, and the *policy* under
    //! test is the ordering and the checks, not the signature arithmetic.
    //! `provider.rs` tests the real binding separately.

    use crate::claims::{EpochFloorClaims, VerifiedClaims};
    use crate::claims::{Quota, TokenClaims};
    use crate::crypto::{IssuerPublicKey, LegKey, RelayCrypto, Statement};

    /// Verifies any envelope that starts with `b"GOOD"`, yielding fixed claims.
    pub struct Doubles {
        /// The claims a successful verification returns.
        pub claims: TokenClaims,
        /// The epoch floor a successful `RelayEpochFloor` verification returns.
        pub floor_epoch: u64,
        /// Whether the frame MAC verifies.
        pub mac_ok: bool,
    }

    impl Doubles {
        /// A double returning `claims`.
        pub fn new(claims: TokenClaims) -> Self {
            Self {
                claims,
                floor_epoch: 0,
                mac_ok: true,
            }
        }
    }

    /// The envelope prefix this double treats as a valid signature.
    pub const GOOD: &[u8] = b"GOOD";

    /// A well-formed envelope the double accepts.
    pub fn good_envelope() -> Vec<u8> {
        let mut v = GOOD.to_vec();
        v.extend_from_slice(b"-cose-sign1-payload");
        v
    }

    /// An envelope the double rejects, standing in for a bad signature.
    pub fn bad_envelope() -> Vec<u8> {
        b"BAD-cose-sign1-payload".to_vec()
    }

    /// A [`VerifiedToken`] for a subject, without going through verification.
    ///
    /// Only for tests of things *downstream* of admission — the leg registry,
    /// the pump's routing — which need a token-shaped value and are not testing
    /// the token. Everything that tests admission itself goes through
    /// [`super::verify`], because a constructor that skipped it would let the
    /// checks be removed without a test noticing.
    pub fn verified(subject: [u8; 16]) -> super::VerifiedToken {
        super::VerifiedToken {
            subject: crate::subject::RelaySub::from_verified_claim(subject),
            epoch: 5,
            not_after_ms: u64::MAX,
            quota: Quota::default(),
            renewed_by_relay: false,
        }
    }

    /// Claims a test can start from.
    pub fn claims() -> TokenClaims {
        TokenClaims {
            issuer_key_id: "k1".into(),
            audience_operator_group_id: "local-operator".into(),
            subject: [9; 16],
            confirmation_key: b"RLK-cose-key".to_vec(),
            not_before_ms: 1_000_000,
            not_after_ms: 1_000_000 + 86_400_000,
            epoch: 5,
            quota: Quota::default(),
            jti: [3; 16],
            renewed_by_relay: false,
        }
    }

    impl RelayCrypto for Doubles {
        fn verify_statement(
            &self,
            _key: &IssuerPublicKey,
            kind: Statement,
            envelope: &[u8],
        ) -> Option<VerifiedClaims> {
            if !envelope.starts_with(GOOD) {
                return None;
            }
            Some(match kind {
                Statement::RelayCapabilityToken => {
                    VerifiedClaims::Token(Box::new(self.claims.clone()))
                }
                Statement::RelayEpochFloor => VerifiedClaims::EpochFloor(EpochFloorClaims {
                    twinnet_id: "t".into(),
                    operator_group_id: "local-operator".into(),
                    epoch_floor: self.floor_epoch,
                    not_after_ms: u64::MAX,
                }),
            })
        }
        fn verify_frame_mac(&self, _: &LegKey, _: &[u8], _: [u8; 8]) -> bool {
            self.mac_ok
        }
        fn frame_mac(&self, _: &LegKey, _: &[u8]) -> Option<[u8; 8]> {
            self.mac_ok.then_some([0xEE; 8])
        }
        fn digest16(&self, _: &[u8], _: &[u8]) -> Option<[u8; 16]> {
            Some([1; 16])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{bad_envelope, claims, good_envelope, Doubles};
    use super::*;
    use crate::crypto::FailClosed;

    const LEG: &[u8] = b"RLK-cose-key";
    const SKEW: u64 = 300_000;

    fn issuers(populated: bool) -> IssuerKeySet {
        let raw = if populated {
            r#"{"operator_group_id":"local-operator","issuers":[{"key_id":"k1","alg":"Ed25519","cose_key_hex":"0102"}]}"#
        } else {
            r#"{"operator_group_id":"local-operator","issuers":[]}"#
        };
        IssuerKeySet::parse(raw, "local-operator", "x").expect("parses")
    }

    fn token() -> PresentedToken {
        PresentedToken::new("k1".into(), good_envelope())
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
        let v = verify(
            &token(),
            &ctx(&i, &f, 1_500_000),
            &Doubles::new(claims()),
            &mut r,
        )
        .expect("ok");
        assert_eq!(v.epoch(), 5);
        assert_eq!(v.quota().max_concurrent_flows, 64);
        assert!(!v.renewed_by_relay());
    }

    #[test]
    fn an_empty_issuer_set_fails_closed() {
        let (i, f) = (issuers(false), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        assert_eq!(
            verify(
                &token(),
                &ctx(&i, &f, 1_500_000),
                &Doubles::new(claims()),
                &mut r
            )
            .unwrap_err(),
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
    fn a_bad_signature_is_refused_before_any_claim_is_consulted() {
        // The ordering property. The envelope below carries claims that would
        // ALSO fail on `aud`, on `cnf` and on the validity window — and the
        // refusal is TokenInvalid, because the signature is checked first and
        // nothing after it ran.
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let mut hostile = claims();
        hostile.audience_operator_group_id = "someone-else".into();
        hostile.confirmation_key = b"wrong".to_vec();
        hostile.not_after_ms = 0;
        let presented = PresentedToken::new("k1".into(), bad_envelope());
        assert_eq!(
            verify(
                &presented,
                &ctx(&i, &f, 1_500_000),
                &Doubles::new(hostile),
                &mut r
            )
            .unwrap_err(),
            Condition::TokenInvalid
        );
        assert!(
            r.is_empty(),
            "a refused token must not consume a replay slot"
        );
    }

    #[test]
    fn a_token_below_the_floor_must_not_be_used() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(9));
        let mut r = ReplayCache::frozen_default();
        assert_eq!(
            verify(
                &token(),
                &ctx(&i, &f, 1_500_000),
                &Doubles::new(claims()),
                &mut r
            )
            .unwrap_err(),
            Condition::TokenEpochStale
        );
    }

    #[test]
    fn an_expired_token_is_refused_and_the_skew_window_is_honoured() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let c = claims();
        let d = Doubles::new(c.clone());
        // Exactly at exp + skew: still accepted.
        assert!(verify(&token(), &ctx(&i, &f, c.not_after_ms + SKEW), &d, &mut r).is_ok());
        // One millisecond past: refused.
        assert_eq!(
            verify(
                &token(),
                &ctx(&i, &f, c.not_after_ms + SKEW + 1),
                &d,
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
        let c = claims();
        assert_eq!(
            verify(
                &token(),
                &ctx(&i, &f, c.not_before_ms - SKEW - 1),
                &Doubles::new(c.clone()),
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
            verify(&token(), &c, &Doubles::new(claims()), &mut r).unwrap_err(),
            Condition::TokenPopFailed
        );
    }

    #[test]
    fn a_token_for_another_operator_group_is_refused() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let mut hostile = claims();
        hostile.audience_operator_group_id = "someone-elses-fleet".into();
        assert_eq!(
            verify(
                &token(),
                &ctx(&i, &f, 1_500_000),
                &Doubles::new(hostile),
                &mut r
            )
            .unwrap_err(),
            Condition::TokenAudienceMismatch
        );
        assert!(r.is_empty());
    }

    #[test]
    fn a_replayed_jti_is_refused_the_second_time() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let d = Doubles::new(claims());
        assert!(verify(&token(), &ctx(&i, &f, 1_500_000), &d, &mut r).is_ok());
        assert_eq!(
            verify(&token(), &ctx(&i, &f, 1_500_001), &d, &mut r).unwrap_err(),
            Condition::TokenReplayed
        );
    }

    #[test]
    fn a_token_that_would_fail_anyway_does_not_burn_a_replay_slot() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(9));
        let mut r = ReplayCache::frozen_default();
        let _ = verify(
            &token(),
            &ctx(&i, &f, 1_500_000),
            &Doubles::new(claims()),
            &mut r,
        );
        assert!(r.is_empty());
    }

    #[test]
    fn an_empty_envelope_is_missing_rather_than_invalid() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let presented = PresentedToken::new("k1".into(), Vec::new());
        assert_eq!(
            verify(
                &presented,
                &ctx(&i, &f, 1_500_000),
                &Doubles::new(claims()),
                &mut r
            )
            .unwrap_err(),
            Condition::TokenMissing
        );
    }

    #[test]
    fn a_presented_token_carries_no_claim_a_caller_could_read() {
        // relay.proto: "the decoded fields here are attacker-controlled until
        // then". The type has nothing to be tempted by.
        let t = token();
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("epoch"));
        assert!(!rendered.contains("quota"));
        assert!(!rendered.contains("subject"));
        assert!(!rendered.contains("not_after"));

        // R-9. The four assertions above pass against a DERIVED `Debug` too,
        // because a `Vec<u8>` renders as digits and contains none of those
        // words — so they reported success while the complete replayable token
        // sat in the output. This is the assertion that fails if the derive
        // comes back: the token's own bytes must not appear.
        for byte in &t.cose_sign1 {
            let _ = byte;
        }
        let bytes_rendered = t
            .cose_sign1
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            !bytes_rendered.is_empty(),
            "the fixture must carry a token for this to prove anything"
        );
        assert!(
            !rendered.contains(&bytes_rendered),
            "the bearer token itself must never be rendered: {rendered}"
        );
        assert!(
            rendered.contains("cose_sign1_len"),
            "the length is what replaces it"
        );
    }

    #[test]
    fn relay_renewal_requires_epoch_equality_grace_and_live_pop() {
        let (i, f) = (issuers(true), EpochFloor::starting_at(5));
        let mut r = ReplayCache::frozen_default();
        let v = verify(
            &token(),
            &ctx(&i, &f, 1_500_000),
            &Doubles::new(claims()),
            &mut r,
        )
        .expect("verified");
        let grace = 21_600_000; // T_RELAY_GRACE = 6 h
        let past_exp = v.not_after_ms() + 1;

        assert!(may_relay_renew(&v, &f, true, past_exp, grace));
        // No proof of possession on the live leg.
        assert!(!may_relay_renew(&v, &f, false, past_exp, grace));
        // Past the grace window.
        assert!(!may_relay_renew(
            &v,
            &f,
            true,
            v.not_after_ms() + grace + 1,
            grace
        ));
        // The floor moved: epoch equality no longer holds, so a revocation may
        // have intervened and the relay must not extend the authority.
        assert!(!may_relay_renew(
            &v,
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
        type Verify = fn(
            &PresentedToken,
            &VerifyContext<'_>,
            &dyn RelayCrypto,
            &mut ReplayCache,
        ) -> Result<VerifiedToken, Condition>;
        let f: Verify = verify;
        let _ = f;
    }
}
