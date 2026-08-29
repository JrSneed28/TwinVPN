//! The command dispatcher — and the mechanism that stops a command from
//! silently doing nothing.
//!
//! **Authority:** ADR-0018 §11.4 F-5 and F-8, §11.6; ADR-0017 MI-1, MI-20,
//! §11.9; `docs/reliability.md` §4.3 (the event table).
//!
//! # The defect this module exists to prevent
//!
//! An earlier revision of `core.rs` performed the admission checks and returned
//! `Ok(())`. Thirty-three of the forty-seven catalogue operations passed every
//! check and executed **nothing**, and the crate's own README described that as
//! "executing a subset". Nothing failed, so nothing was noticed.
//!
//! [`disposition`] is the fix, and it is structural rather than disciplinary:
//! it is an exhaustive `match` over [`CoreCommand`] with **no wildcard arm**.
//! Adding a variant does not silently acquire an empty implementation — it
//! **fails to compile** until someone states, in this file, either that it
//! executes or why it does not. `execute` is a second exhaustive match over
//! the same enum.
//!
//! A `NotWired` arm carries the **reason**, and `submit` turns it into a named
//! refusal on the event stream. A refusal is worth more than a false success.

use twinvpn_mgmt::{CoreCommand, Submission};
use twinvpn_types::{codes, ReasonCode};

/// Whether this build performs an operation, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The operation is performed by `execute`.
    Executes,
    /// The operation is refused by name. The reason is reported, never hidden.
    NotWired {
        /// The registered code the refusal carries.
        code: ReasonCode,
        /// What is missing, in one line, for the completion report and the
        /// crate `README.md`.
        why: &'static str,
    },
}

impl Disposition {
    /// Whether this build performs the operation.
    #[must_use]
    pub const fn executes(self) -> bool {
        matches!(self, Disposition::Executes)
    }
}

/// What this build does with each catalogue operation.
///
/// **Exhaustive, no wildcard.** This function is the register that the earlier
/// revision lacked; every claim about what the core can do is checked against it
/// by `tests/command_path.rs`.
#[must_use]
// One arm per operation. Merging arms that share a disposition today would hide
// it when one of them is wired tomorrow, which is the whole failure this file
// exists to prevent.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub const fn disposition(op: CoreCommand) -> Disposition {
    use CoreCommand as C;
    match op {
        // -- executed ---------------------------------------------------------
        C::StatusGet
        | C::SessionList
        | C::SessionGet
        | C::PathList
        | C::VersionGet
        | C::MetricsGet
        | C::LifecycleGet
        | C::SessionConnect
        | C::SessionDisconnect
        | C::SessionReconnect
        | C::NetUp
        | C::NetDown
        | C::EventSubscribe
        | C::EventUnsubscribe
        | C::HostNetworkChanged
        | C::HostLifecycle
        // ADR-0023 EM-35's `gateway` noun, reaching `twinvpn-gateway`. The three
        // READS execute: `twinvpn-core` owns the live `GatewayState` and the
        // gateway crate decides everything it reports, so there is nothing
        // absent for them to be refused for.
        | C::GatewayGet
        | C::GatewayPeerList
        | C::GatewayGrantList => Disposition::Executes,

        // -- refused: the control-plane client has no transport (W-12) --------
        C::PeerList | C::PeerGet => Disposition::NotWired {
            code: codes::CONTROL_UNREACHABLE,
            why: "the cached TrustedPeer set is populated by twinvpn-cp-client, which has no \
                  ControlTransport implementation anywhere in the workspace (W-12)",
        },
        C::PolicyGet => Disposition::NotWired {
            code: codes::CONTROL_UNREACHABLE,
            why: "the signed PolicyBundle arrives over C2; see W-12",
        },
        C::CapabilityGet => Disposition::NotWired {
            code: codes::PLATFORM_ADAPTER_UNAVAILABLE,
            why: "the ADR-0018 F-9 vtable carries no capability probe, so the adapter cannot \
                  be asked what it supports",
        },

        // -- refused: a probe needs an authenticated exchange -----------------
        C::PathProbe => Disposition::NotWired {
            code: codes::CRYPTO_PEER_KEY_UNKNOWN,
            why: "protocol.md §10.4's probe is the AUTHENTICATED disco exchange, and \
                  twinvpn-path's DiscoAuth has no binding: twinvpn-crypto exposes \
                  verification only. A keyless probe is sent during establishment and \
                  marks a candidate `Probing`, never `Validated` — offering that as \
                  `path.probe` would imply a validation this build cannot perform",
        },

        // -- refused: the read-back exists; nothing calls it yet ---------------
        //
        // This reason USED to be W-24 — "F-9 offers set_ruleset with no getter".
        // That is no longer true: `twinvpn.h` carries `installed_ruleset` and
        // `current_generation` at ABI minor 2, so every adapter can answer, and
        // `enforce::arm` already queries it. What is missing is narrower and is
        // stated as such rather than left blaming a closed finding — a reason
        // that outlives its cause is `ownership.md` §4.3's residue.
        C::KillswitchGet | C::KillswitchExemptGet => Disposition::NotWired {
            code: codes::PLATFORM_ADAPTER_UNAVAILABLE,
            why: "the enforcement read-back exists on every adapter, and this operation is \
                  not wired to NetworkConfig::installed_ruleset. It is refused rather than \
                  answered from the agent's belief about what it configured, which is what \
                  ADR-0015 §11.6 rule 1 forbids",
        },

        // -- refused: no durable store is open on this path -------------------
        C::SettingsGet | C::SettingsSet => Disposition::NotWired {
            code: codes::STORE_CUSTODY_DEGRADED,
            why: "local preferences (S-24) are vault-backed, and Core::open_store must have \
                  run; the operation is refused rather than answered from memory",
        },

        // -- refused: diagnostics need a populated ledger ----------------------
        C::DiagReport => Disposition::NotWired {
            code: codes::PLATFORM_ADAPTER_UNAVAILABLE,
            why: "ADR-0015 §11.8's eight parts include the enforcement snapshot, which is now \
                  readable but not assembled here, and the candidate ledger, which needs a \
                  completed attempt",
        },
        C::DiagBundleCreate | C::DiagLogTail | C::DiagCaptureSet => Disposition::NotWired {
            code: codes::STORE_CUSTODY_DEGRADED,
            why: "a Tier-1 bundle is written to an agent-owned directory the vault vends \
                  (MI-D3), which needs Core::open_store",
        },

        // -- refused: the ceremonies -------------------------------------------
        //
        // W-21 is CLOSED. `PairingOffer` is contracted (Amendment 4,
        // `cddl/twinvpn/v1/pairing_offer.cddl`) and implemented
        // (`twinvpn_crypto::pairing_offer`, which decodes, emits and bounds it).
        // The four arms below therefore no longer share one cause and are no
        // longer merged: each now names what IT is waiting for, which is the
        // whole reason this function exists rather than a wildcard.
        // `pair.begin`, `pair.cancel` and `pair.status` now EXECUTE. G-14's
        // fourth and smallest gap — "the absent PairingLedger" — is closed:
        // `Core` holds one, `crate::pairing` drives ADR-0007 §7.4's C-B
        // ceremony through it, and the three producers G-21 and §11.4 D-6
        // settled build the offer. A device with no enrolment record still gets
        // `AUTH.PAIRING_NOT_AUTHORIZED`, and one with no element still gets
        // `AUTH.KEY_UNAVAILABLE` under §11.16 (l) — but those are now *this
        // device's* verdicts on a real ceremony rather than a dispatcher
        // declining to have one.
        C::PairBegin | C::PairCancel | C::PairStatus => Disposition::Executes,

        // `pair.confirm` is the one that legitimately remains, and its reason is
        // RE-MEASURED rather than inherited. It is no longer waiting on the
        // ledger, and it never was waiting on SPAKE2 — G-17: "W-22 blocks C-A
        // and nothing else". It is waiting on TWO attestations that this build
        // can produce neither of.
        C::PairConfirm => Disposition::NotWired {
            code: codes::CONTROL_UNREACHABLE,
            why: "N-18 confirms a ceremony on both devices or on neither, so it needs BOTH \
                  PairingAttestations, and this build can produce neither half. The peer's \
                  crosses the rendezvous, which has no transport (W-12). This device's own \
                  has no emitter at all: twinvpn_crypto::statements carries \
                  decode_pairing_attestation and check_attestation_pair and NO \
                  emit_pairing_attestation, so there is nothing to sign — a producer gap in \
                  a crate the pairing wiring may not write to, reported rather than filled",
        },
        C::DeviceRevoke | C::KeyRotate => Disposition::NotWired {
            code: codes::CONTROL_UNREACHABLE,
            why: "an Owner-signed ceremony is committed through C1; see W-12",
        },
        C::KillswitchModeSet => Disposition::NotWired {
            code: codes::PLATFORM_ADAPTER_UNAVAILABLE,
            why: "MI-S3's max(current, requested) needs the current mode read back from the \
                  enforcement layer. The posture read-back exists; the MODE does not — it is \
                  a distinct fact from the BLOCKED/PROTECTED posture and no adapter reports it",
        },
        C::KillswitchDisarmBegin | C::KillswitchDisarmCommit => Disposition::NotWired {
            code: codes::MGMT_DISARM_REQUIRES_LOCAL_AUTH,
            why: "§11.14's ceremony needs ADR-0016's local authentication, which is a shell \
                  capability with no ABI entry. Refusing is the safe direction: a disarm that \
                  silently succeeded would clear the latch",
        },

        // -- refused: policy-gated local decisions ------------------------------
        C::DnsPreferenceSet | C::RouteAcceptSet | C::ExitnodeSelect => Disposition::NotWired {
            code: codes::CONTROL_UNREACHABLE,
            why: "each is a preference WITHIN a signed policy (MI-S4), and the policy arrives \
                  over C2; see W-12",
        },
        C::AutostartSet => Disposition::NotWired {
            code: codes::STORE_CUSTODY_DEGRADED,
            why: "autostart is a durable local preference; see settings.set",
        },

        // -- refused: the gateway's CONFIGURATION is durable ------------------
        //
        // The reads above execute; this one does not, and for a reason that is
        // ADR-0013's own. MG-15 requires a gateway to "refuse a configuration
        // whose worst-case reservation exceeds its measured available memory,
        // AT CONFIGURATION TIME" — which needs both a durable place to put the
        // configuration and a measurement of available memory, and this build
        // has neither. Accepting it into memory would be worse than refusing:
        // the ceiling would be forgotten on restart, and MG-15's refusal would
        // move to "the moment the last peer connects", which is exactly what the
        // rule exists to prevent.
        C::GatewaySet => Disposition::NotWired {
            code: codes::STORE_CUSTODY_DEGRADED,
            why: "ADR-0013 MG-15 refuses an over-committed configuration AT CONFIGURATION \
                  TIME, which needs a durable store for the ceiling and a measurement of \
                  available memory; Core::open_store must have run and no memory probe \
                  exists at the seam. Accepting it in memory would move MG-15's refusal to \
                  the moment the last peer connects",
        },

        // -- refused: ADR-0021 owns delivery ------------------------------------
        C::UpdateStatus | C::UpdateCheck | C::UpdateStage | C::UpdateApply | C::UpdateRollback => {
            Disposition::NotWired {
                code: codes::UPDATE_APPLY_WINDOW_EXCEEDED,
                why: "ADR-0021 owns artifact delivery and this wave built none of it. The \
                      rollback floor (S-23) is the only half the core owns and it has no \
                      store to read it from",
            }
        }

        // `CoreCommand` is `#[non_exhaustive]` to its own crate's consumers, so
        // the compiler wants an arm here even though every declared variant is
        // covered above. It is NOT a silent default: an operation this build
        // does not know about is refused by name, and `tests/command_path.rs`
        // asserts the covered set equals `CoreCommand::ALL`, so a new variant
        // fails a test rather than landing here unnoticed.
        _ => Disposition::NotWired {
            code: codes::PROTO_CAPABILITY_MISSING,
            why: "an operation this build's dispatcher does not know; see \
                  tests/command_path.rs, which asserts this arm is unreachable",
        },
    }
}

/// Every operation this build refuses, with its reason.
///
/// Derived from [`disposition`] rather than maintained beside it, so the list
/// cannot drift from the behaviour.
#[must_use]
pub fn not_wired() -> Vec<(CoreCommand, ReasonCode, &'static str)> {
    CoreCommand::ALL
        .iter()
        .filter_map(|op| match disposition(*op) {
            Disposition::NotWired { code, why } => Some((*op, code, why)),
            Disposition::Executes => None,
        })
        .collect()
}

/// Every operation this build performs.
#[must_use]
pub fn executed() -> Vec<CoreCommand> {
    CoreCommand::ALL
        .iter()
        .copied()
        .filter(|op| disposition(*op).executes())
        .collect()
}

/// What an executed operation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The encoded result (F-8), or empty where the operation has no body.
    pub result: Vec<u8>,
    /// How many observable effects the operation had.
    ///
    /// **Not decoration.** `tests/command_path.rs` asserts that every operation
    /// either refuses by name or reports at least one effect, so an operation
    /// that returns `Ok` having done nothing fails a test rather than passing a
    /// review. An "effect" is a state change, an adapter call, or a published
    /// event — counted by the code that performs it.
    pub effects: u32,
}

impl Outcome {
    /// An outcome with a body and a stated effect count.
    #[must_use]
    pub const fn new(result: Vec<u8>, effects: u32) -> Self {
        Self { result, effects }
    }

    /// A read that produced a body. A read's effect is the read itself.
    #[must_use]
    pub const fn read(result: Vec<u8>) -> Self {
        Self { result, effects: 1 }
    }
}

/// The lifecycle phase a `host.lifecycle` submission carries.
///
/// ADR-0018 §11.16 (e): lifecycle is delivered as **commands**
/// (`SUSPEND`/`RESUME`/`BACKGROUND`/`FOREGROUND`), and the core holds no OS
/// lifecycle assumption of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// `EV_SUSPEND`.
    Suspend,
    /// `EV_RESUME`.
    Resume,
    /// `EV_BACKGROUND`.
    Background,
    /// `EV_FOREGROUND`.
    Foreground,
}

impl Lifecycle {
    /// Decodes the one-byte selector a `host.lifecycle` submission carries.
    ///
    /// An unrecognised value is `None` rather than a default: defaulting to
    /// `FOREGROUND` would wake a device that asked to sleep.
    #[must_use]
    pub const fn from_params(params: &[u8]) -> Option<Self> {
        match params.first() {
            Some(1) => Some(Lifecycle::Suspend),
            Some(2) => Some(Lifecycle::Resume),
            Some(3) => Some(Lifecycle::Background),
            Some(4) => Some(Lifecycle::Foreground),
            _ => None,
        }
    }

    /// The `§4.3` event this phase injects.
    #[must_use]
    pub const fn event(self) -> twinvpn_session::event::Event {
        use twinvpn_session::event::Event as E;
        match self {
            Lifecycle::Suspend => E::Suspend,
            Lifecycle::Resume => E::Resume,
            Lifecycle::Background => E::Background,
            Lifecycle::Foreground => E::Foreground,
        }
    }

    /// The selector byte, so a caller can build a submission without guessing.
    #[must_use]
    pub const fn to_params(self) -> u8 {
        match self {
            Lifecycle::Suspend => 1,
            Lifecycle::Resume => 2,
            Lifecycle::Background => 3,
            Lifecycle::Foreground => 4,
        }
    }
}

/// The peer a session-scoped submission names, if it carries one.
///
/// The MI has no request schema — `contracts/docs/phase1-conflicts.md` OQ-2
/// deliberately excluded one so the MI could not acquire a second vocabulary —
/// so a peer crosses as its raw 32-byte `device_id`. That is the frozen width
/// from `limits.json`, not an invented encoding, and anything else is refused
/// rather than truncated or padded (`ownership.md` §6 rule 9).
#[must_use]
pub fn peer_from_params(params: &[u8]) -> Option<twinvpn_types::DeviceId> {
    twinvpn_types::DeviceId::from_slice(params).ok()
}

/// Whether a submission names a session-scoped operation that needs a peer.
#[must_use]
pub const fn needs_peer(op: CoreCommand) -> bool {
    matches!(
        op,
        CoreCommand::SessionConnect
            | CoreCommand::SessionGet
            | CoreCommand::SessionReconnect
            | CoreCommand::SessionDisconnect
    )
}

/// Whether the submission carries what the operation requires.
///
/// Checked before any work, so a malformed submission is a typed reject and
/// never a partially-applied command.
#[must_use]
pub fn missing_parameter(op: CoreCommand, submission: &Submission) -> Option<ReasonCode> {
    if needs_peer(op) && peer_from_params(&submission.params).is_none() {
        return Some(codes::PROTO_MALFORMED_MESSAGE);
    }
    if matches!(op, CoreCommand::HostLifecycle)
        && Lifecycle::from_params(&submission.params).is_none()
    {
        return Some(codes::PROTO_MALFORMED_MESSAGE);
    }
    // `pair.begin` names WHICH ceremony (ADR-0007 §7.4 — "exactly one"), and
    // N-16 makes that an audit fact rather than a default. An absent or
    // unrecognised selector is refused here, before `crate::pairing` could pick
    // one on the caller's behalf.
    if matches!(op, CoreCommand::PairBegin)
        && crate::pairing::Ceremony::from_params(&submission.params).is_none()
    {
        return Some(codes::PROTO_MALFORMED_MESSAGE);
    }
    // `pair.cancel` and `pair.status` name a `pairing_id`, which is the frozen
    // 16-byte width from `limits.json`. Anything else is refused rather than
    // truncated or padded (`ownership.md` §6 rule 9).
    if matches!(op, CoreCommand::PairCancel | CoreCommand::PairStatus)
        && submission.params.len() != crate::pairing::PAIRING_ID_BYTES
    {
        return Some(codes::PROTO_MALFORMED_MESSAGE);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_operation_has_a_stated_disposition() {
        // The compiler already guarantees it — `disposition` is exhaustive with
        // no wildcard. This asserts the derived lists agree with it.
        assert_eq!(executed().len() + not_wired().len(), CoreCommand::ALL.len());
    }

    #[test]
    fn every_refusal_states_a_reason_and_a_registered_code() {
        for (op, code, why) in not_wired() {
            assert!(
                !why.trim().is_empty(),
                "{op} is refused with no stated reason"
            );
            assert!(
                ReasonCode::lookup(code.as_str()).is_some(),
                "{op} refuses with an unregistered code"
            );
        }
    }

    #[test]
    fn session_connect_is_executed() {
        // The operation a Phase 4 gate opens with. If this ever becomes
        // NotWired, that is a deliberate regression and this test says so.
        assert!(disposition(CoreCommand::SessionConnect).executes());
    }

    #[test]
    fn a_lifecycle_selector_is_never_defaulted() {
        assert_eq!(Lifecycle::from_params(&[]), None);
        assert_eq!(Lifecycle::from_params(&[9]), None);
        for phase in [
            Lifecycle::Suspend,
            Lifecycle::Resume,
            Lifecycle::Background,
            Lifecycle::Foreground,
        ] {
            assert_eq!(Lifecycle::from_params(&[phase.to_params()]), Some(phase));
        }
    }

    #[test]
    fn a_peer_of_the_wrong_width_is_refused_not_padded() {
        assert!(peer_from_params(&[0u8; 31]).is_none());
        assert!(peer_from_params(&[0u8; 33]).is_none());
        assert!(peer_from_params(&[0u8; 32]).is_some());
    }

    #[test]
    fn a_session_operation_without_a_peer_is_a_typed_reject() {
        let bare = Submission::bare(CoreCommand::SessionConnect);
        assert_eq!(
            missing_parameter(CoreCommand::SessionConnect, &bare),
            Some(codes::PROTO_MALFORMED_MESSAGE)
        );
    }
}
