//! The three `pair.*` operations the composed core performs.
//!
//! **Authority:** ADR-0007 §7.4, N-2, N-4, N-16, N-17, N-25(1); ADR-0008 §11.3
//! and N-4; ADR-0018 CD-1a, CD-3, §11.16 (l); `ownership.md` §11.4 D-6;
//! `contracts/docs/idempotency.md`.
//!
//! Every function here is **fail-closed**: each check refuses with a registered
//! `ReasonCode` before the next runs, and no path reaches a partial success. The
//! order below is the order of ADR-0007 §7.4's own table — authorization first,
//! then identity, then the channel — because an unauthorized device must be
//! refused before its element is asked to sign anything.

use twinvpn_crypto::pairing_offer;
use twinvpn_crypto::statements::OskPower;
use twinvpn_crypto::tk::TunnelStaticKey;
use twinvpn_mgmt::Submission;
use twinvpn_platform::custody::IdentityKeyRef;
use twinvpn_trust::{derive_device_id, derive_identity_id, Operation, TrustError};
use twinvpn_types::{codes, Diagnostic, Identifier as _};

use super::{refusal, Ceremony, FIRST_TK_GENERATION, PAIRING_ID_BYTES};
use crate::core::Core;
use crate::dispatch::Outcome;

/// `pair.begin` — mint a C-B `PairingOffer` and open its ceremony.
///
/// # The order, which is the security property
///
/// 1. **The replay**, before any work. ADR-0008 §11.3: a `CEREMONY` replay
///    returns the **recorded outcome**, and `contract-matrix.md` says what that
///    outcome is — "a duplicate returns the **original** `pairing_id`". Checked
///    first so a retry cannot mint a second secret, burn a second id, or ask the
///    element for a second signature.
/// 2. **C-A is refused by name.** W-22, and the module documentation.
/// 3. **Authorization (C-D).** An OSK bearing `ENROLL`, through
///    `AnchorChain::authorize`. §7.4 marks this "always required".
/// 4. **Identity.** The element is asked who this device is, and the injected
///    `COSE_Key` is checked against that answer under N-2.
/// 5. **Revocation (N-25(1)).** A revoked device does not enrol another.
/// 6. **The clock.** CD-1a: `WallClockReading::Unset` carries no timestamp, and
///    field 7 is a UTC millisecond expiry. Refused rather than guessed.
/// 7. **The ceremony**, then the offer.
///
/// # Errors
///
/// A bare [`Diagnostic`] carrying one of `AUTH.PAIRING_NOT_AUTHORIZED`,
/// `AUTH.IDENTITY_MISSING`, `AUTH.IDENTITY_MISMATCH`, `AUTH.KEY_UNAVAILABLE`,
/// `AUTH.DEVICE_REVOKED`, `AUTH.CLOCK_IMPLAUSIBLE`, `AUTH.PAIRING_EXPIRED`,
/// `PROTO.CAPABILITY_MISSING` or `PROTO.MALFORMED_MESSAGE`. Never evidence.
pub(crate) fn begin(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    // `crate::dispatch::missing_parameter` has already refused a submission
    // without a selector byte and without an idempotency key, so both are
    // present. They are re-read rather than assumed, because a `None` here
    // would otherwise become a silent default and that is the class of defect
    // `dispatch` exists to prevent.
    let Some(ceremony) = Ceremony::from_params(&submission.params) else {
        return Err(refusal(codes::PROTO_MALFORMED_MESSAGE));
    };
    let Some(key) = submission.idempotency_key.as_ref() else {
        return Err(refusal(codes::PROTO_MALFORMED_MESSAGE));
    };

    let mut state = core.pairing();

    // 0. **S-67 / MI-P1 rule 2.** Every offer whose N-17 window has passed is
    //    burned and zeroized before this call adds another. Here rather than on
    //    a timer (CD-2) and rather than in `status` (a read does not burn); see
    //    `PairingCeremonies::expire_stale`. It runs before the replay check so a
    //    retry cannot be answered out of a map still holding expired secrets.
    state.expire_stale(core.env().now_elapsed().as_micros() / 1_000_000);

    // 1. The recorded outcome. One `pairing_id` per key, whatever else changed.
    //    The response is rebuilt from the offer still in flight, so a retry that
    //    lost its answer can render the same ceremony rather than being told an
    //    id it cannot use.
    if let Some(recorded) = state.begun.get(key) {
        let recorded = *recorded;
        let response = response_body(&state, &recorded);
        return Ok(Outcome::new(recorded.to_vec(), 1).responding(response));
    }

    // 2. C-A. `Spake2Exchange` has no implementation and N-15 forbids inventing
    //    one, so the ceremony type that would need it fails closed.
    if ceremony == Ceremony::HumanCode {
        return Err(refusal(codes::PROTO_CAPABILITY_MISSING));
    }

    // No enrolment record at all is a DIFFERENT fact from "the approver lacks
    // ENROLL power", and conflating them misdirects the operator: the
    // authorization spelling reads as "you need an OSK approval" and sends
    // someone hunting for one that would not have helped, when the truth is that
    // this device is not enrolled and no approval exists to find.
    //
    // `AUTH.IDENTITY_MISSING` is the established spelling for exactly this, and
    // the precedent is in-tree: `enforce.rs`'s `arm` refuses with it when the
    // overlay allocation is absent, because "the overlay allocation arrives
    // inside this device's own identity record (S-08), so its absence is exactly
    // 'this device is not enrolled'". The enrolment record here is the same
    // record. The authorization code below is kept for the case it actually
    // names — an approver present and without the power.
    let Some(enrolment) = state.enrolment.as_ref() else {
        return Err(refusal(codes::AUTH_IDENTITY_MISSING));
    };

    // 3. C-D. §7.4: "an OSK device holding `ENROLL` power approves | Yes".
    enrolment
        .chain
        .authorize(
            Operation::Ordinary(OskPower::Enroll),
            enrolment.approvers(),
            &[],
        )
        .map_err(|_| refusal(codes::AUTH_PAIRING_NOT_AUTHORIZED))?;

    // 4. The element. §11.16 (l): a target with no element refuses
    //    `identity_sign` outright, and that refusal is reported rather than
    //    worked around — "the core MUST NOT substitute a file-backed signer
    //    silently".
    let identity = core
        .block_on_adapter(|_, adapter| adapter.identity().public_identity())
        .map_err(|_| refusal(codes::AUTH_KEY_UNAVAILABLE))?;

    // N-2: `identity_id = SHA-256(ik_pub_cose)`. The injected key is checked to
    // BE this device's key rather than trusted to be, which is what keeps the
    // injection in `PairingEnrolment` from being a way to enrol somebody else's
    // identity. At generation 0 `device_id` is the same digest, so both are
    // checkable; after a rotation only `identity_id` is (`identifiers.md` §2).
    let ik_pub_cose = enrolment.ik_pub_cose();
    if derive_identity_id(ik_pub_cose).as_bytes() != identity.identity_id.as_bytes() {
        return Err(refusal(codes::AUTH_IDENTITY_MISMATCH));
    }
    if identity.generation == 0
        && derive_device_id(ik_pub_cose).as_bytes() != identity.device_id.as_bytes()
    {
        return Err(refusal(codes::AUTH_IDENTITY_MISMATCH));
    }

    let (Ok(device_id), Ok(identity_id)) = (
        <[u8; 32]>::try_from(identity.device_id.as_bytes()),
        <[u8; 32]>::try_from(identity.identity_id.as_bytes()),
    ) else {
        return Err(refusal(codes::AUTH_IDENTITY_MISSING));
    };

    // 5. N-25(1): peer refusal is local and immediate. A device the Owner has
    //    revoked does not get to hand out an offer that would enrol a peer into
    //    a TwinNet it is no longer in.
    if enrolment
        .revocation()
        .is_revoked(&device_id, Some(&identity_id))
    {
        return Err(refusal(codes::AUTH_DEVICE_REVOKED));
    }

    // 6. CD-1a. There is no number to misuse in `Unset`, and inventing one would
    //    make field 7 an expiry in 1970.
    let Some(now_ms) = wall_millis(core) else {
        return Err(refusal(codes::AUTH_CLOCK_IMPLAUSIBLE));
    };
    let window_ms = u64::try_from(twinvpn_schema::limits::PAIRING_CEREMONY_EXPIRY_MS)
        .unwrap_or(super::CEREMONY_EXPIRY_MS_FALLBACK);
    let not_after_ms = now_ms.saturating_add(window_ms);
    let hint = enrolment.rendezvous_hint().to_owned();
    let cose_key = ik_pub_cose.to_vec();

    // 7. The secret, from the platform CSPRNG. CD-3 bans `getrandom` inside the
    //    core and D-6 (c) names `os_csprng` as the only permitted source;
    //    `Env::entropy` is that source at this seam. `Env::rng_for` is the
    //    *seeded* stream and is deliberately not used — a reproducible pairing
    //    secret is a total loss of the 2^256 §7.4 relies on.
    //
    //    It lives in exactly one place from here on: `parts`, which is
    //    overwritten below on **both** paths. The durable copy is
    //    `PairingOffer`'s, and that one zeroizes on drop.
    let mut parts = BuildParts {
        secret: [0u8; 32],
        cose_key,
        device_id,
        identity_id,
        generation: identity.generation,
        not_after_ms,
        hint,
    };
    if core.env().entropy().fill(&mut parts.secret).is_err() {
        return Err(refusal(codes::AUTH_KEY_UNAVAILABLE));
    }
    let pairing_id = pairing_offer::derive_pairing_id(&parts.secret);

    // The ledger, which owns single-use and the attempt budget (N-16, N-17).
    // A burned id is refused here rather than reissued: "never reissued, not
    // even after expiry or cancellation".
    let now_secs = core.env().now_elapsed().as_micros() / 1_000_000;
    if state
        .ledger
        .begin(pairing_id, ceremony.recorded(), now_secs)
        .is_err()
    {
        parts.forget_secret();
        return Err(refusal(codes::AUTH_PAIRING_EXPIRED));
    }

    // The offer's three producers, in field order.
    let built = build_offer(core, &mut state, &parts);
    parts.forget_secret();
    let offer = match built {
        Ok(offer) => offer,
        Err(diagnostic) => {
            // The id is burned rather than left pending: a ceremony whose offer
            // was never emitted cannot complete, and leaving it Pending would
            // hold a `pairing_id` that no peer will ever present.
            state.ledger.cancel(pairing_id);
            return Err(diagnostic);
        }
    };

    state.offers.insert(pairing_id, offer);
    state.begun.insert(key.clone(), pairing_id);

    // The **published** body is the `pairing_id` and nothing else: PUBLIC, and
    // the offer it names never reaches the event stream. The **response** body
    // is §11.9's, and reaches only the caller — see `response_body`. Three
    // effects: a ledger entry, an element signature, and an offer minted.
    let response = response_body(&state, &pairing_id);
    Ok(Outcome::new(pairing_id.to_vec(), 3).responding(response))
}

/// The `pair.begin` **response** body — ADR-0017 §11.9 and **MI-P1**.
///
/// > "The `PairingOffer` material to render — QR payload or 9-digit SPAKE2
/// > code. **The one `SECRET` that crosses MI**; see MI-P1."
///
/// `pairing_id ‖ dCBOR(offer)`: the 16-byte PUBLIC handle every subsequent
/// `pair.cancel` / `pair.status` names, followed by the exact octets ADR-0023
/// **E1** renders as a QR and **E2** renders as Crockford base32. One encoding,
/// two views — `pairing_offer.cddl` encoding rule 1 is what makes that true, and
/// it is why nothing here renders: a shell calls
/// `twinvpn_crypto::pairing_offer::decode` and then `::render_text` or its own
/// QR encoder over the same bytes.
///
/// # MI-P1's three rules, and where each is held
///
/// 1. **Only inside a `pair.begin` response, only over the MI channel, never in
///    any other operation.** This is the only function in the workspace that
///    copies an offer out of `PairingCeremonies::offers`, it is called from
///    [`begin`] and nowhere else, and its bytes leave through
///    [`crate::dispatch::Outcome::response`] — which `Core::submit_response`
///    **returns** to the one caller and never publishes. `pair.begin`'s
///    `Outcome::result`, the value that becomes a `CommandCompleted` broadcast
///    to every subscriber, stays the `pairing_id` alone. [`cancel`] and
///    [`status`] answer with state bytes and never call this.
/// 2. **Never logged at any level, never in `diag.log.tail`, never in a Tier-1
///    bundle, dropped by the client at `not_after_ms`.** The first three hold
///    because the value never enters the event stream, the Tier-0 ledger or a
///    `Diagnostic`: there is no path from here to any of them, and
///    `Outcome`'s hand-written `Debug` redacts the field so a future `{:?}`
///    cannot open one. The client's deadline is field 7, which these bytes
///    carry; the agent's own copy is freed by
///    [`super::PairingCeremonies::expire_stale`].
/// 3. **Not persisted by either side.** The offer lives in a `BTreeMap` behind
///    this core's mutex and is written to no store (`architecture.md` S-67:
///    "non-durable BY REQUIREMENT"). Dropping it zeroizes.
///
/// `None` when no ceremony with that `pairing_id` is in flight — a replay after
/// cancellation or expiry, where ADR-0008's recorded outcome is the `pairing_id`
/// alone and there is no longer an offer to render. The response then shrinks to
/// the published body rather than carrying a secret nothing can still use.
fn response_body(
    state: &super::PairingCeremonies,
    pairing_id: &[u8; PAIRING_ID_BYTES],
) -> Option<Vec<u8>> {
    let offer = state.offer(pairing_id)?;
    let mut body = pairing_id.to_vec();
    body.extend_from_slice(&pairing_offer::encode(offer).ok()?);
    Some(body)
}

/// What [`build_offer`] needs, gathered so the signature stays readable.
struct BuildParts {
    secret: [u8; 32],
    cose_key: Vec<u8>,
    device_id: [u8; 32],
    identity_id: [u8; 32],
    /// Which IK generation signs. Explicit because `T_IK_OVERLAP` keeps two
    /// generations live at once, and "the identity key" without one is
    /// ambiguous exactly when it matters (`IdentityKeyRef`'s own words).
    generation: u32,
    not_after_ms: u64,
    hint: String,
}

impl BuildParts {
    /// Overwrites the one copy of the secret this function owns.
    ///
    /// A plain write rather than `Zeroizing`, because `twinvpn-core` carries no
    /// `zeroize` dependency and adding one to the composition root's manifest is
    /// the integration owner's edit, not this module's. The residual is
    /// therefore **stated rather than implied**: an optimiser is free to elide a
    /// dead store, so this narrows the window rather than closing it, and the
    /// copy that has to be right — the offer's — is `PairingOffer`'s, which
    /// zeroizes in `Drop` under `architecture.md` S-67.
    fn forget_secret(&mut self) {
        self.secret.fill(0);
    }
}

/// Fields 2, 3 and 4, then the assembled offer.
///
/// Split out so [`begin`]'s refusal ladder stays one screen: this function
/// performs no authorization and makes no policy decision, it only produces.
fn build_offer(
    core: &Core,
    state: &mut super::PairingCeremonies,
    parts: &BuildParts,
) -> Result<pairing_offer::PairingOffer, Box<Diagnostic>> {
    // Field 3. D-6 (c): generated in `twinvpn-crypto` at enrolment, from the
    // vtable's CSPRNG, and held for the device rather than for the ceremony.
    if state.tk.is_none() {
        state.tk = Some(
            TunnelStaticKey::generate(core.env())
                .map_err(|_| refusal(codes::AUTH_KEY_UNAVAILABLE))?,
        );
    }
    let Some(tk) = state.tk.as_ref() else {
        return Err(refusal(codes::AUTH_KEY_UNAVAILABLE));
    };
    let tk_pub = *tk.public();

    // Field 4. N-4: a receiver MUST verify this before writing `tk_pub` into a
    // `TrustedPeer`, so it is signed over the octets this device emits and
    // assembled around the element's signature rather than re-serialized.
    let unsigned = twinvpn_crypto::binding::emit_tunnel_key_binding(
        &parts.device_id,
        &parts.identity_id,
        &tk_pub,
        FIRST_TK_GENERATION,
        parts.not_after_ms,
    )
    .map_err(|_| refusal(codes::AUTH_BINDING_INVALID))?;

    let signature = core
        .block_on_adapter(|_, adapter| {
            adapter.identity().identity_sign(
                IdentityKeyRef::Identity {
                    generation: parts.generation,
                },
                unsigned.to_be_signed(),
            )
        })
        .map_err(|_| refusal(codes::AUTH_KEY_UNAVAILABLE))?;

    let binding = unsigned
        .assemble(signature.as_bytes())
        .map_err(|_| refusal(codes::AUTH_BINDING_INVALID))?;

    // The bounds are enforced on the producing side too: an offer this device
    // emits that its peer would refuse is a defect this device should find.
    pairing_offer::build(
        parts.secret,
        parts.cose_key.clone(),
        tk_pub,
        binding,
        parts.hint.clone(),
        parts.not_after_ms,
    )
    .map_err(|reject| refusal(reject.reason_code()))
}

/// `pair.cancel` — burn the `pairing_id`.
///
/// `identifiers.md`: the id is "**Single-use and never reissued, not even after
/// expiry or cancellation**". Cancelling is therefore terminal and idempotent,
/// and cancelling a *completed* ceremony does not un-complete it: the ledger
/// returns the original outcome.
///
/// N-17's 120-second window is enforced here as one of its three independent
/// enforcement points. An expired ceremony is burned with
/// `AUTH.PAIRING_EXPIRED` and reported as expired rather than as aborted,
/// because `pairing.proto` requires a timeout to be "surfaced as a distinct,
/// actionable state, never a generic failure".
///
/// # Errors
///
/// `AUTH.PAIRING_NOT_AUTHORIZED` for an id this core never began — an unknown
/// id burns nothing, so a caller cannot consume identifiers it does not own —
/// and `AUTH.PAIRING_EXPIRED` when the window has passed.
pub(crate) fn cancel(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let pairing_id = pairing_id_from(submission)?;
    let mut state = core.pairing();

    // A replay: the recorded outcome, unchanged.
    if let Some(prior) = state.ledger.outcome(&pairing_id) {
        let body = super::state_byte(prior.state);
        return Ok(Outcome::new(vec![body], 1));
    }
    if !state.offers.contains_key(&pairing_id) {
        return Err(refusal(codes::AUTH_PAIRING_NOT_AUTHORIZED));
    }

    let now_secs = core.env().now_elapsed().as_micros() / 1_000_000;
    let expired = matches!(
        state.ledger.check_window(&pairing_id, now_secs),
        Err(TrustError::PairingExpired)
    );
    // The offer goes either way, and dropping it zeroizes.
    state.offers.remove(&pairing_id);
    if expired {
        // `check_window` has already burned the id with the Expired outcome.
        return Err(refusal(codes::AUTH_PAIRING_EXPIRED));
    }

    let outcome = state.ledger.cancel(pairing_id);
    Ok(Outcome::new(vec![super::state_byte(outcome.state)], 2))
}

/// `pair.status` — report one ceremony's state without changing it.
///
/// **Read-only, and it stays read-only.** The catalogue classes this
/// `Idempotency::ReadOnly` and non-mutating, so it does not burn an expired id:
/// burning is an *act*, and N-17's independent enforcement happens at the next
/// operation that acts. What it does report is the truth a caller would meet if
/// it acted now — a ceremony past its offer's `not_after_ms` reads as expired
/// here even though the ledger still holds it Pending.
///
/// The body is two bytes: the state ([`super::state_byte`]) and the remaining
/// attempt budget, which N-17 caps at five so it always fits.
///
/// # Errors
///
/// `AUTH.PAIRING_NOT_AUTHORIZED` for an id this core never began. A ceremony
/// nobody began has no state to report, and answering `0` would invent one.
pub(crate) fn status(core: &Core, submission: &Submission) -> Result<Outcome, Box<Diagnostic>> {
    let pairing_id = pairing_id_from(submission)?;
    let state = core.pairing();

    if let Some(prior) = state.ledger.outcome(&pairing_id) {
        return Ok(Outcome::read(vec![super::state_byte(prior.state), 0]));
    }

    let Some(offer) = state.offers.get(&pairing_id) else {
        return Err(refusal(codes::AUTH_PAIRING_NOT_AUTHORIZED));
    };
    let expired = wall_millis(core).is_none_or(|now_ms| now_ms >= offer.not_after_ms());
    let reported = if expired {
        twinvpn_trust::PairingState::Expired
    } else {
        twinvpn_trust::PairingState::Pending
    };
    // A ceremony still in flight has its full budget: `record_failed_run` is
    // driven by `pair.confirm`, which this build does not perform.
    let remaining = u8::try_from(twinvpn_trust::pairing::MAX_ATTEMPTS).unwrap_or(u8::MAX);
    Ok(Outcome::read(vec![super::state_byte(reported), remaining]))
}

/// The 16-byte `pairing_id` a `pair.cancel` or `pair.status` names.
///
/// `crate::dispatch::missing_parameter` has already refused a submission whose
/// parameters are not exactly this width, so this is the same check stated
/// where the value is used rather than a second, looser one.
fn pairing_id_from(submission: &Submission) -> Result<[u8; PAIRING_ID_BYTES], Box<Diagnostic>> {
    <[u8; PAIRING_ID_BYTES]>::try_from(submission.params.as_slice())
        .map_err(|_| refusal(codes::PROTO_MALFORMED_MESSAGE))
}

/// The wall clock, or `None` when CD-1a says there is no usable reading.
///
/// `timestamps.md` permits exactly three uses of a wall reading, and one of them
/// is "evaluating a signed statement's own validity window against local time".
/// Field 7 and the `TunnelKeyBinding`'s `not_after_ms` are that window's two
/// halves, which is why this is the one clock they may be built from.
fn wall_millis(core: &Core) -> Option<u64> {
    match core.env().now_wall() {
        twinvpn_env::WallClockReading::Unset => None,
        twinvpn_env::WallClockReading::Offset { millis, .. }
        | twinvpn_env::WallClockReading::Trusted { millis } => Some(millis.as_millis()),
    }
}
