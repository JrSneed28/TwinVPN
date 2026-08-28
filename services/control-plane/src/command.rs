//! The C1 command surface, server side, with the class the frozen contract
//! matrix gives each command.
//!
//! **Authority:** `contracts/docs/contract-matrix.md` §3 and §3.1,
//! `contracts/proto/twinvpn/v1/control_commands.proto`, ADR-0008 §11.3,
//! ADR-0002 §11.3 (the E-1 write path).
//!
//! # This table is the client's table
//!
//! `twinvpn-cp-client`'s `idempotency::Command` carries exactly these seventeen
//! commands with exactly these classes. Nothing here is a judgement call — a
//! command whose class disagrees with the matrix is a defect in this file, and
//! `the_class_table_matches_the_client` asserts the seventeen names and their
//! order against the client's own list.
//!
//! # What is deliberately absent
//!
//! [`FORBIDDEN_ON_C1`] names the eleven requests §3.1 places elsewhere. A server
//! that quietly grew a `ResumeSession` endpoint would put the control plane back
//! in the reconnect path and break **I5** on the *server* side, where no
//! client-side test would see it.

/// ADR-0008 §11.3's classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationClass {
    /// An action with an outcome. `idempotency_key` required, 24 h dedup
    /// window, and a replay returns the **recorded outcome**.
    Ceremony,
    /// Desired state. No key; guarded by a `VersionPrecondition`, which is what
    /// closes the dedup-window expiry cliff (N-6).
    Declarative,
    /// Last-writer-wins, loss-tolerant, **no dedup log**, permitted to be lost.
    Register,
    /// Trivially idempotent.
    ReadOnly,
    /// The C2 subscription.
    Streaming,
}

impl OperationClass {
    /// ADR-0008 N-4: only a `CEREMONY` requires a key.
    #[must_use]
    pub const fn requires_idempotency_key(self) -> bool {
        matches!(self, OperationClass::Ceremony)
    }

    /// ADR-0008 N-9: presence and health writes **MUST NOT** use the dedup log.
    #[must_use]
    pub const fn has_dedup_log(self) -> bool {
        matches!(self, OperationClass::Ceremony)
    }

    /// Whether the response carries a [`MutationResult`](twinvpn_schema::v1::MutationResult).
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(self, OperationClass::Ceremony | OperationClass::Declarative)
    }
}

/// The eleven requests Phase 1 places somewhere other than C1.
///
/// Transcribed from `contract-matrix.md` §3.1 and identical to the client's
/// `FORBIDDEN_ON_C1`, so the two artifacts refuse the same eleven names.
pub const FORBIDDEN_ON_C1: [&str; 11] = [
    "BeginConnection",
    "ExchangeCandidates",
    "RequestRelay",
    "ReleaseRelay",
    "ResumeSession",
    "EndSession",
    "UpdatePeerPermissions",
    "UpdateRoutePolicy",
    "UpdateDNSPolicy",
    "AdvertiseGateway",
    "ReportConnectionHealth",
];

/// One C1 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Command {
    /// `CEREMONY`, **linearizable** on `(twinnet_id, device_pubkey)`.
    RegisterDevice,
    /// `DECLARATIVE`, `MONOTONIC`.
    UpdateDeviceMetadata,
    /// `CEREMONY`. Linearizable admission plus monotonic reads.
    RevokeDevice,
    /// `CEREMONY`, `MONOTONIC` per counter.
    RotateDeviceCredential,
    /// `CEREMONY`, linearizable. A duplicate returns the **original** id.
    BeginPairing,
    /// `CEREMONY` + `if_version`. A replay returns the **original outcome**.
    CompletePairing,
    /// `CEREMONY`. Burns the `pairing_id`; it is single-use.
    CancelPairing,
    /// `CEREMONY`. Removes one relationship; revokes nobody.
    RevokePairing,
    /// Read-only, `MONOTONIC`, snapshot + delta.
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
    /// `CEREMONY` + `if_version`, linearizable, **quorum-committed**.
    PutPolicy,
    /// Streaming, `MONOTONIC`. Resume, do not reload.
    SubscribeEvents,
    /// Read-only, `MONOTONIC`. **Pull is always sufficient.**
    GetStateDocument,
}

impl Command {
    /// Every command in the C1 surface, in the matrix's order.
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

    /// Whether this write commits to a **quorum** before responding.
    ///
    /// ADR-0002 §11.3: the E-1-class set is `RevokeDeviceReq`,
    /// `RegisterDeviceReq`, `ConfirmPairingReq` and `PutPolicyReq`. "If quorum
    /// is unreachable, the operation is refused with
    /// `CONTROL.QUORUM_UNAVAILABLE` — **never** committed locally with a promise
    /// to reconcile, because a forked revocation history is exactly what E-1
    /// forbids."
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

    /// Whether this command may append to the durable log at all.
    ///
    /// `PublishPresence` may not: presence is ephemeral, and a presence write
    /// that reached the log would be the permanent movement history
    /// `protocol.md` §6.1 forbids. `DiscoverPeers`, `GetStateDocument` and
    /// `SubscribeEvents` are reads.
    #[must_use]
    pub const fn may_append_durable(self) -> bool {
        self.class().is_mutating()
    }

    /// A stable, non-localised name for tracing and metrics.
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

#[cfg(test)]
mod tests {
    use super::{Command, OperationClass, FORBIDDEN_ON_C1};

    #[test]
    fn no_forbidden_request_has_a_c1_handler() {
        for forbidden in FORBIDDEN_ON_C1 {
            assert!(
                !Command::ALL.iter().any(|c| c.as_str() == forbidden),
                "{forbidden} is not a C1 command in Phase 1"
            );
        }
    }

    #[test]
    fn only_ceremonies_require_a_key_and_keep_a_dedup_log() {
        for c in Command::ALL {
            assert_eq!(
                c.class().requires_idempotency_key(),
                c.class() == OperationClass::Ceremony,
                "{}",
                c.as_str()
            );
            assert_eq!(
                c.class().has_dedup_log(),
                c.class() == OperationClass::Ceremony,
                "{}",
                c.as_str()
            );
        }
    }

    #[test]
    fn publish_presence_keeps_no_dedup_log_and_appends_nothing_durable() {
        // ADR-0008 N-9 and protocol.md §6.1, in one assertion. A presence write
        // that acquired either would be the durable-presence antipattern.
        let p = Command::PublishPresence;
        assert_eq!(p.class(), OperationClass::Register);
        assert!(!p.class().has_dedup_log());
        assert!(!p.may_append_durable());
    }

    #[test]
    fn the_e1_set_is_exactly_the_four_adr_0002_names() {
        let e1: Vec<&str> = Command::ALL
            .iter()
            .filter(|c| c.is_e1_class())
            .map(|c| c.as_str())
            .collect();
        assert_eq!(
            e1,
            vec![
                "RegisterDevice",
                "RevokeDevice",
                "CompletePairing",
                "PutPolicy"
            ]
        );
    }

    #[test]
    fn put_policy_is_the_only_policy_mutation() {
        let policy_writers: Vec<&str> = Command::ALL
            .iter()
            .map(|c| c.as_str())
            .filter(|n| n.contains("Policy"))
            .collect();
        assert_eq!(policy_writers, vec!["PutPolicy"]);
    }
}
