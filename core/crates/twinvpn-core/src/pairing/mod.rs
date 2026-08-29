//! The composed pairing ceremony — ADR-0007's **C-B** enrolment, wired.
//!
//! **Authority:** [ADR-0007](../../../../../docs/adr/ADR-0007-device-identity-and-pairing.md)
//! §7.4 (the three separated concerns and the `PairingOffer` field list), N-15,
//! N-16, N-17, N-18, N-19, N-25(1); ADR-0008 §11.3 and N-4 (the `CEREMONY`
//! class, its key and its recorded outcome); ADR-0018 §11.7 CD-I5, §11.16 (l),
//! CD-1a, CD-3; `contracts/cddl/twinvpn/v1/pairing_offer.cddl` (Amendment 4);
//! `docs/implementation/ownership.md` §11.4 **D-6**, §11.2 G-14, G-17, G-21.
//!
//! **Owner:** `core-composition`.
//!
//! # What was missing, and what this module is
//!
//! `twinvpn-trust` has held [`twinvpn_trust::PairingLedger`] — the ceremony
//! state machine, the five-attempt budget, the 120-second window, the
//! single-use `pairing_id` and N-18's mutual-attestation check — since the trust
//! crate was written. `twinvpn-crypto` has held the offer's three producers
//! since G-21 and D-6 closed them: `cose::es256_cose_key` for field 2,
//! `tk::TunnelStaticKey` for field 3, and `binding::emit_tunnel_key_binding` for
//! field 4. Neither crate may name the other's caller, and neither holds an
//! `Env` or a `PlatformAdapter`. **This crate is where they meet**, which is
//! the whole of finding F-2 and the whole of this module.
//!
//! # C-B, and only C-B
//!
//! ADR-0007 §7.4 makes the two channel-authentication ceremonies alternatives —
//! "C-B (QR) where a camera and a screen exist; C-A (SPAKE2/P-256) otherwise |
//! **Yes, exactly one**" — and `ownership.md` G-17 states the consequence
//! plainly: *"W-22 blocks C-A and nothing else; C-B is blocked by G-17's TK
//! ruling alone."* §11.4 **D-6** answered the TK ruling, so C-B is driveable and
//! C-A is not.
//!
//! [`Ceremony::HumanCode`] is therefore **refused by name**, not defaulted away.
//! `twinvpn_trust::pairing::Spake2Exchange` is a trait with no implementation
//! anywhere in the workspace, deliberately: N-17 names RFC 9382 and no audited
//! P-256 implementation is in the dependency table, and N-15 forbids
//! substituting a construction that permits offline testing of a nine-digit
//! code. A ceremony type with no implementation fails closed with a registered
//! reason code; `the_human_code_ceremony_is_refused_by_name` asserts it.
//!
//! # The three concerns §7.4 separates, and where each is discharged here
//!
//! | Concern | §7.4's mechanism | Here |
//! |---|---|---|
//! | **Authorization** — may this device join this `TwinNet`? | C-D: an OSK holding `ENROLL` power approves. *Always required.* | [`PairingEnrolment`] carries the [`twinvpn_trust::AnchorChain`] and the already-verified approvers; [`ops::begin`] calls `AnchorChain::authorize(Operation::Ordinary(OskPower::Enroll), …)` before it touches anything else |
//! | **Channel authentication** | C-B: the offer crosses an out-of-band confidential channel | [`ops::begin`] emits the offer; the channel is the shell's (ADR-0023 E1 renders it as a QR, E2 as Crockford base32) |
//! | **Confirmation** | post-hoc fingerprint display | the shell's, and outside this module |
//!
//! # Why the enrolment record is injected rather than read
//!
//! Three of its five parts have no source the composed core may reach today,
//! and each absence is a seam gap this crate has already recorded rather than a
//! shortcut taken here:
//!
//! - **The Owner chain.** `crate::cp_binding::verifier` states it: *"`Core` has
//!   no `AnchorChain` field … the shell restores one and passes it in."*
//! - **This device's ES256 `COSE_Key`** (field 2). The one production converter
//!   from an element's public key to that map lives in
//!   `services/twinvpn-service-common/src/binding/spki.rs` (`ownership.md`
//!   G-21) — a different workspace — and
//!   `twinvpn_platform::custody::IdentityPublic::public_key` is documented as
//!   carrying "the public key bytes, **in the element's own encoding**", with no
//!   declared encoding to parse. `crate::cp_binding::transport` records the same
//!   gap in the same words: *"the seam owes a declared encoding, or
//!   `IdentityCustody` owes an `spki()`."* Guessing one here would be the
//!   second copy of a specified encoding that G-21 exists to prevent.
//! - **The revocation set**, for the same reason `PeerList` is refused: it
//!   arrives over C2 and the control-plane client has no transport (W-12).
//!
//! The injection is **not** trusted blindly. [`ops::begin`] recomputes
//! `identity_id` from the supplied `COSE_Key` under ADR-0007 N-2 and refuses
//! `AUTH.IDENTITY_MISMATCH` unless it equals what the element reports — and at
//! generation 0 it does the same for `device_id`. A key that is not this
//! device's key cannot be enrolled through this path.
//!
//! # Secrets
//!
//! `pairing_offer.cddl` classifies the whole offer SECRET with "NO RENDERING
//! PATH into the diagnostic ledger, syslog, a Tier-1 bundle, or ANY log level,
//! at any severity, in any build profile". Three things hold that here:
//!
//! 1. **The offer does not reach the diagnostic surfaces.** It is reachable
//!    only through [`crate::Core::with_pairing_offer`], a scoped borrow under
//!    the same mutex, so it never lands in a `CommandCompleted` event, an
//!    `Outcome::result`, or a `Diagnostic`. `pair.begin` answers with the
//!    16-byte `pairing_id`, which `pairing_offer.cddl` classifies PUBLIC.
//!
//!    **This is NOT yet ADR-0017's contract, and the gap is a defect, not a
//!    hardening.** §11.9's `pair.begin` row states the return value as "the
//!    `PairingOffer` material to render — QR payload or 9-digit SPAKE2 code",
//!    and calls it "the one `SECRET` that crosses MI". **MI-P1 does not
//!    tolerate that crossing — it specifies it**, in three numbered rules that
//!    exist precisely to govern it: under H2 the renderer is the unprivileged
//!    UI and the key holder is the agent, so the value has to cross, permitted
//!    "narrowly: 1. Only inside a `pair.begin` response…". §11.17's flow is
//!    explicit that "`pair.begin` returns the QR payload; the CLI renders it as
//!    terminal-drawn QR".
//!
//!    Returning only the `pairing_id` therefore leaves **no shell able to render
//!    an offer**, so C-B — the one ceremony this build supports — cannot be
//!    performed end to end. Closing it means implementing MI-P1's three rules,
//!    not deleting the transfer they govern. Withholding a value the contract
//!    requires is not a stricter reading of the secret-handling rule; it is a
//!    different, non-conforming interface.
//! 2. **`PairingOffer` redacts itself.** Its `Debug` renders `<redacted>` for
//!    the secret and withholds `tk_pub` and the hint, and it zeroizes on drop.
//!    Every `Debug` in this module is hand-written for the same reason.
//! 3. **No refusal carries input.** Every refusal below is a bare registered
//!    `ReasonCode` with no evidence attached, which is `OfferReject`'s own rule
//!    applied to the operations that wrap it.
//!
//! # What is deliberately absent
//!
//! - **`pair.confirm`.** N-18 requires **both** `PairingAttestation`s before a
//!   ceremony is confirmed, and this build can produce neither half: the peer's
//!   crosses the rendezvous, which has no transport (W-12), and this device's
//!   own has no emitter — `twinvpn_crypto::statements` carries
//!   `decode_pairing_attestation` and `check_attestation_pair` and **no**
//!   `emit_pairing_attestation`. It stays refused, with that re-measured reason
//!   stated in `crate::dispatch`.
//! - **A durable TK.** D-6 (a) puts the sealed `TK` in Tier 2 `identity/` and
//!   (b) makes its wrapping key the Tier-1 item; `tk::TK_RECORD_KEY` and
//!   `tk::TK_WRAP_ITEM` name both. Nothing provisions the Tier-1 wrapping key,
//!   so [`PairingCeremonies`] holds the generated `TunnelStaticKey` for the
//!   life of the process and `tk_generation` stays at [`FIRST_TK_GENERATION`].
//!   One key per core rather than one per ceremony is also the *correct* shape —
//!   D-6 (c) generates TK "at enrolment … triggered with the `DeviceIdentity`",
//!   so it is a device-level key, and minting a second one per ceremony would
//!   put two generation-1 bindings for one device in front of a peer.

pub(crate) mod ops;

use std::collections::BTreeMap;

use twinvpn_crypto::pairing_offer::PairingOffer;
use twinvpn_crypto::tk::TunnelStaticKey;
use twinvpn_schema::limits;
use twinvpn_trust::owner::VerifiedSigner;
use twinvpn_trust::{AnchorChain, PairingLedger, RevocationState};
use twinvpn_types::{codes, Component, Diagnostic};

/// The `tk_generation` a first enrolment binds.
///
/// D-6 (c): `tk_generation` "advances on TK rotation independently of IK's
/// `generation`". A first enrolment has performed no rotation, so it is 1 —
/// and it stays 1 because this build has no durable TK record to advance it
/// against. Advancing a counter that does not survive a restart would tell a
/// peer a rotation happened that it cannot verify, which N-22's monotonicity
/// rule makes worse than not advancing at all.
pub const FIRST_TK_GENERATION: u64 = 1;

/// The width of the `pairing_id` every `pair.*` operation names.
pub const PAIRING_ID_BYTES: usize = limits::PAIRING_ID_BYTES;

/// N-17's 120-second window, for the one case the registry's `usize` will not
/// widen to a `u64`.
///
/// Unreachable on every target this workspace builds for, and written out
/// rather than left as an `unwrap_or(0)`: a zero window would emit an offer
/// that has already expired, which is a *silent* refusal at the peer instead of
/// a loud one here.
pub const CEREMONY_EXPIRY_MS_FALLBACK: u64 = 120_000;

/// Which channel-authentication ceremony a `pair.begin` asks for.
///
/// Carried as **one selector byte** in the submission's parameters. The MI has
/// no request schema — `contracts/docs/phase1-conflicts.md` OQ-2 excluded one
/// so the MI could not acquire a second vocabulary — so this follows
/// `crate::dispatch::Lifecycle`'s precedent exactly: a byte, decoded to a typed
/// value, with **no default**. An unrecognised value is `None` and the
/// submission is refused; defaulting to C-B would silently perform a different
/// ceremony from the one asked for, and N-16 makes "which ceremony did this
/// trust come from" an audit question that cannot be answered retroactively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// **C-B.** The offer crosses an out-of-band confidential channel — a QR
    /// under ADR-0023 E1, a pasted Crockford block under E2. ADR-0023 EM-21:
    /// C-B "does not require a camera; it requires a confidential channel".
    ConfidentialChannel,
    /// **C-A.** SPAKE2 over P-256 with a nine-digit code (N-17). Refused: see
    /// the module documentation and W-22.
    HumanCode,
}

impl Ceremony {
    /// Decodes the selector byte a `pair.begin` submission carries.
    #[must_use]
    pub const fn from_params(params: &[u8]) -> Option<Self> {
        match params.first() {
            Some(1) => Some(Ceremony::ConfidentialChannel),
            Some(2) => Some(Ceremony::HumanCode),
            _ => None,
        }
    }

    /// The selector byte, so a caller can build a submission without guessing.
    #[must_use]
    pub const fn to_params(self) -> u8 {
        match self {
            Ceremony::ConfidentialChannel => 1,
            Ceremony::HumanCode => 2,
        }
    }

    /// N-16's recorded method, in the ledger's vocabulary.
    #[must_use]
    pub const fn recorded(self) -> twinvpn_trust::CeremonyType {
        match self {
            Ceremony::ConfidentialChannel => twinvpn_trust::CeremonyType::Qr,
            Ceremony::HumanCode => twinvpn_trust::CeremonyType::Spake2Code,
        }
    }
}

/// The ceremony lifecycle, as `pair.status` reports it.
///
/// A byte rather than a frozen message for the reason `crate::execute`'s banner
/// gives: ADR-0017 §11.9 states `pair.status`'s return and the MI has no
/// response schema, so the body is the narrowest honest encoding rather than an
/// invented message. `1` is deliberately not `0`: a zero byte is what an empty
/// buffer reads as, and "unknown ceremony" is a refusal here, never a state.
#[must_use]
pub const fn state_byte(state: twinvpn_trust::PairingState) -> u8 {
    use twinvpn_trust::PairingState as S;
    match state {
        S::Pending => 1,
        S::Confirmed => 2,
        S::Expired => 3,
        S::Aborted => 4,
        S::Rejected => 5,
    }
}

/// Everything the composed core must be handed before it may begin a pairing.
///
/// **An empty approver set is refused at construction**, for the reason
/// `crate::cp_binding::ControlPlaneEnrolment::new` gives for refusing an empty
/// pin set: it is the verdict every ceremony under it would reach, stated once
/// instead of once per ceremony. There is no `Default`, and no constructor that
/// admits an unverified signature — [`VerifiedSigner`] has none.
pub struct PairingEnrolment {
    chain: AnchorChain,
    approvers: Vec<VerifiedSigner>,
    revocation: RevocationState,
    ik_pub_cose: Vec<u8>,
    rendezvous_hint: String,
}

impl PairingEnrolment {
    /// Binds the Owner chain, the C-D approvers and this device's own
    /// `COSE_Key` into the record `pair.begin` reads.
    ///
    /// `approvers` are signatures **already verified** against the keys they
    /// name; `ik_pub_cose` is this device's ES256 `COSE_Key` as
    /// `twinvpn_crypto::cose::es256_cose_key` encodes it — see the module
    /// documentation on why the core cannot derive it from the element today,
    /// and on the N-2 recomputation that stops a wrong key being enrolled
    /// anyway.
    ///
    /// # Errors
    ///
    /// `AUTH.PAIRING_NOT_AUTHORIZED` for an empty approver set,
    /// `AUTH.IDENTITY_MISSING` for an empty `ik_pub_cose`, and
    /// `PROTO.SIZE_EXCEEDED` for a `rendezvous_hint` past
    /// `pairing.max_offer_hint_bytes` — all three refused here rather than at
    /// the first ceremony.
    pub fn new(
        chain: AnchorChain,
        approvers: Vec<VerifiedSigner>,
        revocation: RevocationState,
        ik_pub_cose: Vec<u8>,
        rendezvous_hint: String,
    ) -> Result<Self, Box<Diagnostic>> {
        if approvers.is_empty() {
            return Err(refusal(codes::AUTH_PAIRING_NOT_AUTHORIZED));
        }
        if ik_pub_cose.is_empty() || ik_pub_cose.len() > limits::PAIRING_MAX_OFFER_COSE_KEY_BYTES {
            return Err(refusal(codes::AUTH_IDENTITY_MISSING));
        }
        if rendezvous_hint.len() > limits::PAIRING_MAX_OFFER_HINT_BYTES {
            return Err(refusal(codes::PROTO_SIZE_EXCEEDED));
        }
        Ok(Self {
            chain,
            approvers,
            revocation,
            ik_pub_cose,
            rendezvous_hint,
        })
    }

    /// The pinned Owner chain.
    #[must_use]
    pub const fn chain(&self) -> &AnchorChain {
        &self.chain
    }

    /// The already-verified C-D approvers.
    #[must_use]
    pub fn approvers(&self) -> &[VerifiedSigner] {
        &self.approvers
    }

    /// The revocation set this device has admitted (N-25(1)).
    #[must_use]
    pub const fn revocation(&self) -> &RevocationState {
        &self.revocation
    }

    /// This device's ES256 `COSE_Key`, the offer's field 2.
    #[must_use]
    pub fn ik_pub_cose(&self) -> &[u8] {
        &self.ik_pub_cose
    }

    /// The offer's field 6.
    #[must_use]
    pub fn rendezvous_hint(&self) -> &str {
        &self.rendezvous_hint
    }
}

impl core::fmt::Debug for PairingEnrolment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `rendezvous_hint` is withheld for the reason `PairingOffer`'s own
        // `Debug` withholds it: it is not secret by classification, but a hint
        // naming a rendezvous host is exactly the correlating detail a Tier-1
        // bundle should not carry.
        f.debug_struct("PairingEnrolment")
            .field("anchor_version", &self.chain.anchor_version())
            .field("approvers", &self.approvers.len())
            .field("revoked_devices", &self.revocation.revoked_count())
            .field("ik_pub_cose_len", &self.ik_pub_cose.len())
            .field("rendezvous_hint", &"<withheld>")
            .finish_non_exhaustive()
    }
}

/// The composed core's pairing state: the ledger, the dedup log, this device's
/// `TK`, and the offers still in flight.
///
/// Held behind **one** mutex on `Core`, which is what makes ADR-0008's
/// `CEREMONY` idempotency hold under concurrency: two `pair.begin` calls
/// carrying one `idempotency_key` serialize here, the second finds the first's
/// recorded `pairing_id`, and exactly one ceremony exists.
/// `two_concurrent_begins_produce_one_ceremony` asserts it.
#[derive(Default)]
pub struct PairingCeremonies {
    enrolment: Option<PairingEnrolment>,
    ledger: PairingLedger,
    /// ADR-0008 §11.3's `CEREMONY` dedup log: `idempotency_key` → the
    /// `pairing_id` the first call recorded.
    ///
    /// > "`BeginPairing` duplicate → the **original** `pairing_id`."
    ///
    /// Keyed on the submission's key rather than on the `pairing_id`, because
    /// the `pairing_id` is derived from a secret the retry does not carry —
    /// the key is the only thing stable across a retry, which is exactly what
    /// ADR-0008 N-4 requires it to be.
    begun: BTreeMap<Vec<u8>, [u8; PAIRING_ID_BYTES]>,
    /// The in-flight offers, by `pairing_id`. **SECRET**, and reachable only
    /// through [`crate::Core::with_pairing_offer`].
    ///
    /// `architecture.md` S-67: the in-flight offer is "non-durable BY
    /// REQUIREMENT — it MUST NOT survive process restart". A `BTreeMap` in a
    /// mutex is that requirement held by construction, and removing an entry
    /// drops a `PairingOffer`, which zeroizes.
    offers: BTreeMap<[u8; PAIRING_ID_BYTES], PairingOffer>,
    /// This device's L-DATA static, generated once (D-6 (c)) and reused.
    tk: Option<TunnelStaticKey>,
}

impl PairingCeremonies {
    /// An empty state: no enrolment, no ceremonies, no key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the enrolment record. A second call **replaces** it, for the
    /// reason `Core::bind_control_transport` accepts a replacement: re-enrolling
    /// is what a device does when its Owner rotates the root, and refusing would
    /// pin it to a chain its Owner has moved away from.
    pub fn install(&mut self, enrolment: PairingEnrolment) {
        self.enrolment = Some(enrolment);
    }

    /// The installed enrolment record, if any.
    #[must_use]
    pub const fn enrolment(&self) -> Option<&PairingEnrolment> {
        self.enrolment.as_ref()
    }

    /// The ceremony ledger.
    #[must_use]
    pub const fn ledger(&self) -> &PairingLedger {
        &self.ledger
    }

    /// The offer for one ceremony, while it is still in flight.
    #[must_use]
    pub fn offer(&self, pairing_id: &[u8; PAIRING_ID_BYTES]) -> Option<&PairingOffer> {
        self.offers.get(pairing_id)
    }

    /// How many ceremonies this core has begun.
    ///
    /// The count a test asserts against to prove that a duplicate `pair.begin`
    /// produced **one** ceremony rather than two.
    #[must_use]
    pub fn begun_count(&self) -> usize {
        self.begun.len()
    }
}

impl core::fmt::Debug for PairingCeremonies {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Counts only. A derived `Debug` would walk into `offers`, and although
        // `PairingOffer` redacts itself, `ownership.md` §6 rule 11 makes a
        // derive that *could* reach a secret the accident to prevent rather
        // than the one to survive.
        f.debug_struct("PairingCeremonies")
            .field("enrolled", &self.enrolment.is_some())
            .field("begun", &self.begun.len())
            .field("offers_in_flight", &self.offers.len())
            .field("tk_present", &self.tk.is_some())
            .finish_non_exhaustive()
    }
}

/// A bare refusal: a registered code, `Component::Pairing`, and **no evidence**.
///
/// `pairing_offer.cddl`: "A decode failure is reported as a bare registered
/// `reason_code` with NO evidence drawn from the input." Every refusal in this
/// module goes through here, so there is no call site at which an input byte, a
/// length, a key or a secret could be attached to one.
// Boxed because every caller's error type is `Box<Diagnostic>` — `Core::submit`
// and `crate::execute` both carry one, so returning it unboxed would put a
// `Box::new` at every refusal site and nowhere else.
#[allow(clippy::unnecessary_box_returns)]
pub(crate) fn refusal(code: twinvpn_types::ReasonCode) -> Box<Diagnostic> {
    Box::new(Diagnostic::builder(code, Component::Pairing).build())
}
