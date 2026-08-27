//! Operation classes, and the stable idempotency key that makes a retry safe.
//!
//! **Authority:** [ADR-0008](../../../../docs/adr/ADR-0008-idempotency.md) §11.3
//! (the classification), N-2/N-4/N-5/N-6, `contracts/docs/idempotency.md`,
//! `contracts/docs/contract-matrix.md` §3, ADR-0002 §11.12.
//!
//! # Exactly-once *effect*, not exactly-once delivery
//!
//! `contract-matrix.md` §5: **no hop claims exactly-once delivery** — it is
//! unachievable over an unreliable network. The client's entire contribution to
//! exactly-once *effect* is two things:
//!
//! - a **stable `idempotency_key` across every retry** of one logical operation, and
//! - an `if_version` / `if_absent` precondition on every declarative mutation.
//!
//! > *"A retry reuses `idempotency_key` and mints a **fresh `message_id`**."*
//!
//! # Why a fresh key on retry is not something this API lets you write
//!
//! A retry that mints a new key is not a slow path; it is a **duplicated
//! ceremony**, and a duplicated `CompletePairing` is how two devices end up
//! disagreeing about whether they trust each other. So the key is minted **once**,
//! by [`Ceremony::begin`], and a retry is [`Ceremony::retry`] — which takes
//! `&mut self`, bumps a counter, and returns *the same key*. There is no
//! `Ceremony::with_new_key`, and the key field is private with no setter.
//!
//! The one legitimate re-mint is a genuinely new operation, and that is spelled
//! by calling `begin` again — which is a different sentence at the call site.

use twinvpn_env::{consumers as env_consumers, ConsumerId, Env};
use twinvpn_types::{IdempotencyKey, Identifier};

use crate::error::{CpError, CpResult};

/// The stream this crate draws idempotency keys from.
///
/// A dedicated `ConsumerId` rather than a shared one: `core/README.md` §5 notes
/// that adding a consumer does not shift an existing consumer's stream, so a
/// seeded scenario recorded a year ago still reproduces.
pub const IDEMPOTENCY_KEY_STREAM: ConsumerId = ConsumerId::new("cp/idempotency-key");

/// The stream this crate draws `message_id`s from.
pub const MESSAGE_ID_STREAM: ConsumerId = ConsumerId::new("cp/message-id");

/// The stream this crate draws reconnect jitter from.
///
/// The **`reliability.md` §6.1 infrastructure regime**, reused verbatim rather
/// than redefined: ADR-0002 R-b sets no timer value that `reliability.md`
/// already owns.
pub const BACKOFF_JITTER_STREAM: ConsumerId = env_consumers::BACKOFF_JITTER;

/// ADR-0008 §11.3's operation classification.
///
/// Carried as a type so a command's obligations are readable at the call site
/// rather than looked up in a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationClass {
    /// An **action with an outcome**. Idempotency key REQUIRED, 24 h dedup
    /// window, and a replay must return the recorded outcome.
    Ceremony,
    /// **Desired state**, not an action. No key; guarded by a
    /// `VersionPrecondition`, which is what closes the dedup-window expiry cliff
    /// (N-6) — the fix is the precondition, never a longer window.
    Declarative,
    /// **Last-writer-wins, loss-tolerant, no dedup log.** A state assertion, not
    /// a command. Permitted to be lost, and never a gate.
    Register,
    /// Trivially idempotent.
    ReadOnly,
    /// The C2 subscription.
    Streaming,
}

impl OperationClass {
    /// Whether an `idempotency_key` is required.
    #[must_use]
    pub const fn requires_idempotency_key(self) -> bool {
        matches!(self, OperationClass::Ceremony)
    }

    /// Whether a `VersionPrecondition` is required.
    ///
    /// `CompletePairing` is the interesting row: it is a `CEREMONY` *and*
    /// carries a precondition, because the key alone stops working once the
    /// 24 h window expires.
    #[must_use]
    pub const fn requires_precondition(self) -> bool {
        matches!(self, OperationClass::Declarative)
    }

    /// Whether the operation keeps a durable dedup record.
    #[must_use]
    pub const fn has_dedup_log(self) -> bool {
        matches!(self, OperationClass::Ceremony)
    }

    /// Whether losing this operation entirely is acceptable.
    ///
    /// True only for `REGISTER`. `PublishPresence` is "permitted to be lost"
    /// (ADR-0008 N-9) and is **never a gate** (S-11) — a client that blocks
    /// establishment on a presence publish has misread the class.
    #[must_use]
    pub const fn permitted_to_be_lost(self) -> bool {
        matches!(self, OperationClass::Register)
    }
}

/// Every C1 command, with its frozen class.
///
/// The table is `contract-matrix.md` §3 transcribed. Nothing here is a judgement
/// call; the classes are contract, and a command whose class disagrees with the
/// matrix is a defect in this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// `CEREMONY`, linearizable on `(twinnet_id, device_pubkey)`.
    RegisterDevice,
    /// `DECLARATIVE`, `MONOTONIC`.
    UpdateDeviceMetadata,
    /// `CEREMONY`. Linearizable admission plus monotonic reads — the strongest
    /// requirement in TwinVPN.
    RevokeDevice,
    /// `CEREMONY`, `MONOTONIC` per counter.
    RotateDeviceCredential,
    /// `CEREMONY`, linearizable. A duplicate returns the **original** `pairing_id`.
    BeginPairing,
    /// `CEREMONY` + `if_version`. A replay returns the **original outcome** —
    /// this is what prevents asymmetric trust.
    CompletePairing,
    /// `CEREMONY`. Burns the `pairing_id`; it is single-use.
    CancelPairing,
    /// `CEREMONY`. Distinct from device revocation: removes one relationship.
    RevokePairing,
    /// Read-only, `MONOTONIC`. Snapshot + delta via `since_net_seq`.
    DiscoverPeers,
    /// `REGISTER`. LWW, no dedup log, permitted to be lost, never a gate.
    PublishPresence,
    /// `DECLARATIVE`, monotone `advertisement_epoch`. Whole desired set.
    PutRouteAdvertisement,
    /// `DECLARATIVE`. A higher epoch with an empty prefix set.
    WithdrawRouteAdvertisement,
    /// `DECLARATIVE`, monotone `offer_epoch`. Whole desired set.
    PutExitNodeOffer,
    /// `DECLARATIVE`. A higher epoch.
    WithdrawExitNodeOffer,
    /// `CEREMONY` + `if_version`, linearizable, quorum-committed. **The only
    /// policy mutation in the contract set.**
    PutPolicy,
    /// Streaming, `MONOTONIC`. Resume, do not reload.
    SubscribeEvents,
    /// Read-only, `MONOTONIC`. **Pull is always sufficient.**
    GetStateDocument,
}

impl Command {
    /// Every command in the C1 surface.
    pub const ALL: [Command; 17] = [
        Command::RegisterDevice,
        Command::UpdateDeviceMetadata,
        Command::RevokeDevice,
        Command::RotateDeviceCredential,
        Command::BeginPairing,
        Command::CompletePairing,
        Command::CancelPairing,
        Command::RevokePairing,
        Command::DiscoverPeers,
        Command::PublishPresence,
        Command::PutRouteAdvertisement,
        Command::WithdrawRouteAdvertisement,
        Command::PutExitNodeOffer,
        Command::WithdrawExitNodeOffer,
        Command::PutPolicy,
        Command::SubscribeEvents,
        Command::GetStateDocument,
    ];

    /// The frozen class.
    #[must_use]
    pub const fn class(self) -> OperationClass {
        match self {
            Command::RegisterDevice
            | Command::RevokeDevice
            | Command::RotateDeviceCredential
            | Command::BeginPairing
            | Command::CompletePairing
            | Command::CancelPairing
            | Command::RevokePairing
            | Command::PutPolicy => OperationClass::Ceremony,
            Command::UpdateDeviceMetadata
            | Command::PutRouteAdvertisement
            | Command::WithdrawRouteAdvertisement
            | Command::PutExitNodeOffer
            | Command::WithdrawExitNodeOffer => OperationClass::Declarative,
            Command::PublishPresence => OperationClass::Register,
            Command::DiscoverPeers | Command::GetStateDocument => OperationClass::ReadOnly,
            Command::SubscribeEvents => OperationClass::Streaming,
        }
    }

    /// Whether this command is E-1 class and therefore quorum-committed before
    /// the response returns (ADR-0002 §11.3).
    ///
    /// If quorum is unreachable the operation is **refused**, never committed
    /// locally with a promise to reconcile — a forked revocation history is
    /// exactly what E-1 forbids.
    #[must_use]
    pub const fn is_e1_class(self) -> bool {
        matches!(
            self,
            Command::RevokeDevice
                | Command::RegisterDevice
                | Command::CompletePairing
                | Command::PutPolicy
        )
    }

    /// Whether the response advances the C2 cursor, so the client must **not**
    /// report the operation complete until the cursor reaches
    /// `committed_at_net_seq`.
    ///
    /// `control_commands.proto` calls that "a PROTOCOL OBLIGATION, NOT A CLIENT
    /// CONVENIENCE": it closes the seam where a device pairs a peer, gets a
    /// success, and immediately fails to connect because its local `TrustedPeer`
    /// cache has not seen the pairing event.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(
            self.class(),
            OperationClass::Ceremony | OperationClass::Declarative
        )
    }

    /// A stable, non-localised name for tracing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Command::RegisterDevice => "RegisterDevice",
            Command::UpdateDeviceMetadata => "UpdateDeviceMetadata",
            Command::RevokeDevice => "RevokeDevice",
            Command::RotateDeviceCredential => "RotateDeviceCredential",
            Command::BeginPairing => "BeginPairing",
            Command::CompletePairing => "CompletePairing",
            Command::CancelPairing => "CancelPairing",
            Command::RevokePairing => "RevokePairing",
            Command::DiscoverPeers => "DiscoverPeers",
            Command::PublishPresence => "PublishPresence",
            Command::PutRouteAdvertisement => "PutRouteAdvertisement",
            Command::WithdrawRouteAdvertisement => "WithdrawRouteAdvertisement",
            Command::PutExitNodeOffer => "PutExitNodeOffer",
            Command::WithdrawExitNodeOffer => "WithdrawExitNodeOffer",
            Command::PutPolicy => "PutPolicy",
            Command::SubscribeEvents => "SubscribeEvents",
            Command::GetStateDocument => "GetStateDocument",
        }
    }
}

/// One `CEREMONY`-class operation, and the key that survives its retries.
///
/// The key is minted once and is private. [`Ceremony::retry`] returns the same
/// key with an incremented attempt count; there is no way to change it.
#[derive(Debug)]
pub struct Ceremony {
    command: Command,
    key: IdempotencyKey,
    attempt: u32,
}

impl Ceremony {
    /// The idempotency key width this crate mints: 32 bytes, comfortably above
    /// ADR-0008 N-4's ≥ 128-bit floor and inside `limits.json`'s 16..=64 range.
    pub const KEY_BYTES: usize = 32;

    /// Begins a ceremony, minting its key **once**.
    ///
    /// # Errors
    ///
    /// [`CpError::Env`] if the injected entropy is unavailable. There is
    /// deliberately no fallback: a weaker key is indistinguishable from working
    /// and is the value every dedup decision depends on.
    ///
    /// # Panics
    ///
    /// Never. `KEY_BYTES` is a compile-time constant inside the validated range.
    pub fn begin(env: &Env, command: Command) -> CpResult<Self> {
        debug_assert!(
            command.class().requires_idempotency_key(),
            "only a CEREMONY-class command takes a key"
        );
        let mut rng = env.rng_for(IDEMPOTENCY_KEY_STREAM)?;
        let mut bytes = [0u8; Self::KEY_BYTES];
        rng.fill_bytes(&mut bytes);
        let key = IdempotencyKey::from_slice(&bytes).map_err(|e| {
            CpError::Rejected(twinvpn_schema::Reject::malformed("idempotency_key", e))
        })?;
        Ok(Self {
            command,
            key,
            attempt: 0,
        })
    }

    /// Rebuilds a ceremony whose key was persisted across a process restart.
    ///
    /// This is the path ADR-0008 §11.3 requires for `RegisterDevice`, whose key
    /// is "derived from a **device-local enrolment nonce**, so a retry after a
    /// lost response returns the *same* `device_id`". A process that crashed
    /// mid-ceremony resumes with its original key rather than enrolling twice.
    #[must_use]
    pub const fn resumed(command: Command, key: IdempotencyKey, attempt: u32) -> Self {
        Self {
            command,
            key,
            attempt,
        }
    }

    /// The stable key. **The same value on every attempt.**
    #[must_use]
    pub const fn key(&self) -> IdempotencyKey {
        self.key
    }

    /// Which command.
    #[must_use]
    pub const fn command(&self) -> Command {
        self.command
    }

    /// How many attempts have been made. `0` before the first send.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Records another attempt and hands back the **same** key.
    ///
    /// Deliberately the only mutating method: there is no `with_new_key`, so a
    /// retry that mints a fresh key is not expressible against this type.
    pub const fn retry(&mut self) -> IdempotencyKey {
        self.attempt = self.attempt.saturating_add(1);
        self.key
    }

    /// The key's bytes, for `MessageMetadata.idempotency_key`.
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{Ceremony, Command, OperationClass};
    use twinvpn_types::Identifier;

    #[test]
    fn the_class_table_matches_the_contract_matrix() {
        // contract-matrix.md §3, transcribed and asserted.
        assert_eq!(Command::RegisterDevice.class(), OperationClass::Ceremony);
        assert_eq!(Command::RevokeDevice.class(), OperationClass::Ceremony);
        assert_eq!(Command::CompletePairing.class(), OperationClass::Ceremony);
        assert_eq!(Command::PutPolicy.class(), OperationClass::Ceremony);
        assert_eq!(
            Command::UpdateDeviceMetadata.class(),
            OperationClass::Declarative
        );
        assert_eq!(
            Command::PutRouteAdvertisement.class(),
            OperationClass::Declarative
        );
        assert_eq!(Command::PublishPresence.class(), OperationClass::Register);
        assert_eq!(Command::DiscoverPeers.class(), OperationClass::ReadOnly);
        assert_eq!(Command::GetStateDocument.class(), OperationClass::ReadOnly);
        assert_eq!(Command::SubscribeEvents.class(), OperationClass::Streaming);
    }

    #[test]
    fn presence_is_permitted_to_be_lost_and_nothing_else_is() {
        for command in Command::ALL {
            let lost_ok = command.class().permitted_to_be_lost();
            assert_eq!(
                lost_ok,
                command == Command::PublishPresence,
                "{} must not be loss-tolerant unless it is REGISTER class",
                command.as_str()
            );
        }
    }

    #[test]
    fn every_ceremony_requires_a_key_and_no_other_class_does() {
        for command in Command::ALL {
            assert_eq!(
                command.class().requires_idempotency_key(),
                command.class() == OperationClass::Ceremony,
                "{}",
                command.as_str()
            );
        }
    }

    #[test]
    fn the_four_e1_class_commands_are_exactly_the_adr_0002_list() {
        // ADR-0002 §11.3: RevokeDeviceReq, RegisterDeviceReq, ConfirmPairingReq,
        // PutPolicyReq commit to a QUORUM before responding.
        let e1: Vec<_> = Command::ALL
            .into_iter()
            .filter(|c| c.is_e1_class())
            .collect();
        assert_eq!(
            e1,
            vec![
                Command::RegisterDevice,
                Command::RevokeDevice,
                Command::CompletePairing,
                Command::PutPolicy,
            ]
        );
    }

    #[test]
    fn a_retry_reuses_the_key() {
        let env = crate::testing::test_env();
        let mut ceremony = Ceremony::begin(&env, Command::CompletePairing).expect("mint");
        let first = ceremony.key();
        assert_eq!(ceremony.attempt(), 0);
        let second = ceremony.retry();
        let third = ceremony.retry();
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.as_bytes(), third.as_bytes());
        assert_eq!(ceremony.attempt(), 2);
    }

    #[test]
    fn two_distinct_ceremonies_get_distinct_keys() {
        let env = crate::testing::test_env();
        let a = Ceremony::begin(&env, Command::BeginPairing).expect("mint");
        let b = Ceremony::begin(&env, Command::BeginPairing).expect("mint");
        assert_ne!(a.key().as_bytes(), b.key().as_bytes());
    }

    #[test]
    fn a_resumed_ceremony_keeps_the_persisted_key() {
        let env = crate::testing::test_env();
        let original = Ceremony::begin(&env, Command::RegisterDevice).expect("mint");
        let persisted = original.key();
        // Simulate a process restart mid-enrolment.
        let resumed = Ceremony::resumed(Command::RegisterDevice, persisted, 1);
        assert_eq!(resumed.key().as_bytes(), original.key().as_bytes());
        assert_eq!(resumed.attempt(), 1);
    }

    #[test]
    fn the_minted_key_is_inside_the_registry_range() {
        let env = crate::testing::test_env();
        let ceremony = Ceremony::begin(&env, Command::PutPolicy).expect("mint");
        let len = ceremony.key_bytes().len();
        assert!(len >= twinvpn_schema::limits::IDEMPOTENCY_KEY_MIN_BYTES);
        assert!(len <= twinvpn_schema::limits::IDEMPOTENCY_KEY_MAX_BYTES);
        assert!(len * 8 >= 128, "ADR-0008 N-4's >= 128-bit floor");
    }
}
