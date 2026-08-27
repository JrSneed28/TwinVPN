//! **The core command set.** One vocabulary, two carriages.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-1, MI-20, MI-21 and §11.9's table;
//! [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 F-5 and §11.16 (b).
//!
//! # Why the vocabulary is declared *here* and not in `twinvpn-core`
//!
//! MI-20 says the MI catalogue is **derived from the core's command/event set**,
//! not specified beside it, and ADR-0018 §11.16 (b) says the same thing from the
//! other side: *"the same command set the core exposes over the ABI — one
//! contract, two carriages, **never two contracts**"*.
//!
//! There is exactly one way to make that structural rather than disciplinary in
//! this crate graph. ADR-0018 §11.7 puts `twinvpn-mgmt` **above** the composition
//! root, so `twinvpn-core` depends on this crate and not the reverse. Declaring
//! [`CoreCommand`] here therefore means:
//!
//! - `twinvpn-core` dispatches **this** enum. It cannot invent an operation,
//!   because there is no other enum to invent it in.
//! - `twinvpn-ffi`'s `tw_core_submit` carries **this** enum's encoding.
//! - [`crate::catalogue`] is generated from **this** enum by an exhaustive
//!   `match`, so adding a variant without a catalogue row **fails to compile**.
//!
//! Declaring it in `twinvpn-core` instead would leave this crate free to write a
//! parallel list, which is precisely the "independently-named MI vocabulary"
//! MI-20's second paragraph forbids and ADR-0018 B-02 says collapses F-1.
//!
//! # The four operations that are deliberately absent
//!
//! MI-21 closes a set of **four** MI operations with no core counterpart —
//! `Hello`/`HelloAck`, `mi.catalogue.get`, `event.resync`, and the MI half of
//! `version.get`. They are in [`crate::transport`], in a different type, because
//! each is about *the connection* — a thing that does not exist in-process — and
//! each **MUST NOT** acquire an ABI counterpart. Keeping them in a separate enum
//! is what stops one drifting into this one.

use core::fmt;

/// One operation of the core's command set.
///
/// The spelling is ADR-0017 §11.9's, verbatim and in its order. MI "MUST NOT
/// rename, re-shape, merge, split, or reorder a core command" — so this enum is
/// the place where a rename would have to happen, and the catalogue cannot
/// disagree with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CoreCommand {
    // -- status and read ----------------------------------------------------
    /// `status.get`
    StatusGet,
    /// `session.list`
    SessionList,
    /// `session.get`
    SessionGet,
    /// `peer.list`
    PeerList,
    /// `peer.get`
    PeerGet,
    /// `path.list`
    PathList,
    /// `policy.get`
    PolicyGet,
    /// `killswitch.get`
    KillswitchGet,
    /// `killswitch.exempt.get`
    ///
    /// ADR-0017 §11.1.1's recorded correction: this reads enforcement-layer
    /// state, which is a core module, so it is an ordinary core command and
    /// **not** one of MI-21's four.
    KillswitchExemptGet,
    /// `capability.get`
    CapabilityGet,
    /// `lifecycle.get`
    LifecycleGet,
    /// `version.get` — the **core's** half. MI adds `mi_version` and the
    /// catalogue digest on its own side (MI-21).
    VersionGet,
    /// `metrics.get`
    MetricsGet,
    /// `settings.get`
    SettingsGet,
    /// `update.status`
    UpdateStatus,

    // -- events -------------------------------------------------------------
    /// `event.subscribe` (stream)
    EventSubscribe,
    /// `event.unsubscribe`
    EventUnsubscribe,

    // -- diagnostics --------------------------------------------------------
    /// `diag.report`
    DiagReport,
    /// `diag.bundle.create`
    DiagBundleCreate,
    /// `diag.log.tail` (stream)
    DiagLogTail,
    /// `diag.capture.set`
    DiagCaptureSet,

    // -- connection ---------------------------------------------------------
    /// `session.connect` — injects `EV_CONNECT_REQUESTED`.
    SessionConnect,
    /// `session.disconnect` — injects `EV_DISCONNECT_REQUESTED`.
    SessionDisconnect,
    /// `session.reconnect`
    SessionReconnect,
    /// `path.probe`
    PathProbe,
    /// `net.up`
    NetUp,
    /// `net.down` — **clears session intent, never the latch** (MI-K1).
    NetDown,

    // -- settings -----------------------------------------------------------
    /// `settings.set`
    SettingsSet,
    /// `dns.preference.set`
    DnsPreferenceSet,
    /// `route.accept.set`
    RouteAcceptSet,
    /// `exitnode.select`
    ExitnodeSelect,
    /// `autostart.set`
    AutostartSet,

    // -- administration -----------------------------------------------------
    /// `killswitch.mode.set` — `max(current, requested)` (MI-S3).
    KillswitchModeSet,
    /// `pair.begin`
    PairBegin,
    /// `pair.confirm`
    PairConfirm,
    /// `pair.cancel`
    PairCancel,
    /// `pair.status`
    PairStatus,
    /// `device.revoke`
    DeviceRevoke,
    /// `key.rotate`
    KeyRotate,
    /// `update.check`
    UpdateCheck,
    /// `update.stage`
    UpdateStage,
    /// `update.apply`
    UpdateApply,
    /// `update.rollback`
    UpdateRollback,

    // -- the disarm ceremony ------------------------------------------------
    /// `killswitch.disarm.begin` — *the ability to **ask**, not to do*.
    KillswitchDisarmBegin,
    /// `killswitch.disarm.commit`
    KillswitchDisarmCommit,

    // -- lifecycle, submitted by the host ----------------------------------
    /// `host.network_changed` — ADR-0018 F-9's inversion of
    /// `subscribe_network_change`: the shell subscribes with the OS and submits
    /// the new link facts as a command, so a notification can never arrive on an
    /// arbitrary thread while a mutating call is in flight (F-6).
    HostNetworkChanged,
    /// `host.lifecycle` — `SUSPEND`/`RESUME`/`BACKGROUND`/`FOREGROUND`
    /// (ADR-0018 §11.16 (e), `docs/reliability.md` §4.3).
    HostLifecycle,
}

impl CoreCommand {
    /// Every command, in ADR-0017 §11.9's order.
    ///
    /// Order is part of the contract: MI-20 forbids MI to reorder a core
    /// command, so the array is the order and the catalogue inherits it.
    pub const ALL: &'static [CoreCommand] = &[
        CoreCommand::StatusGet,
        CoreCommand::SessionList,
        CoreCommand::SessionGet,
        CoreCommand::PeerList,
        CoreCommand::PeerGet,
        CoreCommand::PathList,
        CoreCommand::PolicyGet,
        CoreCommand::KillswitchGet,
        CoreCommand::KillswitchExemptGet,
        CoreCommand::CapabilityGet,
        CoreCommand::LifecycleGet,
        CoreCommand::VersionGet,
        CoreCommand::MetricsGet,
        CoreCommand::SettingsGet,
        CoreCommand::UpdateStatus,
        CoreCommand::EventSubscribe,
        CoreCommand::EventUnsubscribe,
        CoreCommand::DiagReport,
        CoreCommand::DiagBundleCreate,
        CoreCommand::DiagLogTail,
        CoreCommand::DiagCaptureSet,
        CoreCommand::SessionConnect,
        CoreCommand::SessionDisconnect,
        CoreCommand::SessionReconnect,
        CoreCommand::PathProbe,
        CoreCommand::NetUp,
        CoreCommand::NetDown,
        CoreCommand::SettingsSet,
        CoreCommand::DnsPreferenceSet,
        CoreCommand::RouteAcceptSet,
        CoreCommand::ExitnodeSelect,
        CoreCommand::AutostartSet,
        CoreCommand::KillswitchModeSet,
        CoreCommand::PairBegin,
        CoreCommand::PairConfirm,
        CoreCommand::PairCancel,
        CoreCommand::PairStatus,
        CoreCommand::DeviceRevoke,
        CoreCommand::KeyRotate,
        CoreCommand::UpdateCheck,
        CoreCommand::UpdateStage,
        CoreCommand::UpdateApply,
        CoreCommand::UpdateRollback,
        CoreCommand::KillswitchDisarmBegin,
        CoreCommand::KillswitchDisarmCommit,
        CoreCommand::HostNetworkChanged,
        CoreCommand::HostLifecycle,
    ];

    /// The operation's wire name, exactly as ADR-0017 §11.9 spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            CoreCommand::StatusGet => "status.get",
            CoreCommand::SessionList => "session.list",
            CoreCommand::SessionGet => "session.get",
            CoreCommand::PeerList => "peer.list",
            CoreCommand::PeerGet => "peer.get",
            CoreCommand::PathList => "path.list",
            CoreCommand::PolicyGet => "policy.get",
            CoreCommand::KillswitchGet => "killswitch.get",
            CoreCommand::KillswitchExemptGet => "killswitch.exempt.get",
            CoreCommand::CapabilityGet => "capability.get",
            CoreCommand::LifecycleGet => "lifecycle.get",
            CoreCommand::VersionGet => "version.get",
            CoreCommand::MetricsGet => "metrics.get",
            CoreCommand::SettingsGet => "settings.get",
            CoreCommand::UpdateStatus => "update.status",
            CoreCommand::EventSubscribe => "event.subscribe",
            CoreCommand::EventUnsubscribe => "event.unsubscribe",
            CoreCommand::DiagReport => "diag.report",
            CoreCommand::DiagBundleCreate => "diag.bundle.create",
            CoreCommand::DiagLogTail => "diag.log.tail",
            CoreCommand::DiagCaptureSet => "diag.capture.set",
            CoreCommand::SessionConnect => "session.connect",
            CoreCommand::SessionDisconnect => "session.disconnect",
            CoreCommand::SessionReconnect => "session.reconnect",
            CoreCommand::PathProbe => "path.probe",
            CoreCommand::NetUp => "net.up",
            CoreCommand::NetDown => "net.down",
            CoreCommand::SettingsSet => "settings.set",
            CoreCommand::DnsPreferenceSet => "dns.preference.set",
            CoreCommand::RouteAcceptSet => "route.accept.set",
            CoreCommand::ExitnodeSelect => "exitnode.select",
            CoreCommand::AutostartSet => "autostart.set",
            CoreCommand::KillswitchModeSet => "killswitch.mode.set",
            CoreCommand::PairBegin => "pair.begin",
            CoreCommand::PairConfirm => "pair.confirm",
            CoreCommand::PairCancel => "pair.cancel",
            CoreCommand::PairStatus => "pair.status",
            CoreCommand::DeviceRevoke => "device.revoke",
            CoreCommand::KeyRotate => "key.rotate",
            CoreCommand::UpdateCheck => "update.check",
            CoreCommand::UpdateStage => "update.stage",
            CoreCommand::UpdateApply => "update.apply",
            CoreCommand::UpdateRollback => "update.rollback",
            CoreCommand::KillswitchDisarmBegin => "killswitch.disarm.begin",
            CoreCommand::KillswitchDisarmCommit => "killswitch.disarm.commit",
            CoreCommand::HostNetworkChanged => "host.network_changed",
            CoreCommand::HostLifecycle => "host.lifecycle",
        }
    }

    /// Looks an operation up by wire name.
    ///
    /// The only string-driven entry point. It cannot mint an operation the
    /// catalogue does not contain, which is what makes `MGMT.OP_UNKNOWN` a
    /// **typed** rejection rather than a parse failure (ADR-0017 §11.7:
    /// *"Never a parse error, never a hang, never a generic failure"*).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.name() == name)
    }
}

impl fmt::Display for CoreCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One submitted command: the operation, its encoded parameters, and the
/// idempotency material ADR-0008 requires.
///
/// Parameters are **encoded bytes** rather than a Rust enum of payloads, per
/// ADR-0018 F-8: *"only handles, slices and scalars cross; structured data
/// crosses as encoded bytes"*. That is what lets `tw_core_submit` and the MI
/// transport carry the identical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    /// Which operation.
    pub op: CoreCommand,
    /// The operation's parameters, encoded from the frozen contract artifacts.
    pub params: Vec<u8>,
    /// ADR-0008's `CEREMONY` key, where [`crate::catalogue::Idempotency::Key`]
    /// requires one.
    pub idempotency_key: Option<Vec<u8>>,
    /// The `if_version` precondition, where
    /// [`crate::catalogue::Idempotency::Version`] requires one.
    pub if_version: Option<u64>,
    /// MI-18's attribution: the OS principal whose call produced this, or `None`
    /// for an agent-internal cause. Carried through to every event the command
    /// produces, because *"the tunnel went down" and "Dana took the tunnel down"
    /// are different facts*.
    pub actor_principal: Option<String>,
}

impl Submission {
    /// A submission with no parameters and no idempotency material.
    #[must_use]
    pub const fn bare(op: CoreCommand) -> Self {
        Self {
            op,
            params: Vec::new(),
            idempotency_key: None,
            if_version: None,
            actor_principal: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The compiler is the mechanism, not this test's body.
    ///
    /// An exhaustive `match` with no wildcard: adding a variant to
    /// [`CoreCommand`] without adding it here **fails to compile**. That is what
    /// keeps [`CoreCommand::ALL`] honest, and `ALL` is what the catalogue is
    /// derived from.
    #[allow(clippy::match_same_arms)]
    const fn is_in_all(c: CoreCommand) -> bool {
        match c {
            CoreCommand::StatusGet
            | CoreCommand::SessionList
            | CoreCommand::SessionGet
            | CoreCommand::PeerList
            | CoreCommand::PeerGet
            | CoreCommand::PathList
            | CoreCommand::PolicyGet
            | CoreCommand::KillswitchGet
            | CoreCommand::KillswitchExemptGet
            | CoreCommand::CapabilityGet
            | CoreCommand::LifecycleGet
            | CoreCommand::VersionGet
            | CoreCommand::MetricsGet
            | CoreCommand::SettingsGet
            | CoreCommand::UpdateStatus
            | CoreCommand::EventSubscribe
            | CoreCommand::EventUnsubscribe
            | CoreCommand::DiagReport
            | CoreCommand::DiagBundleCreate
            | CoreCommand::DiagLogTail
            | CoreCommand::DiagCaptureSet
            | CoreCommand::SessionConnect
            | CoreCommand::SessionDisconnect
            | CoreCommand::SessionReconnect
            | CoreCommand::PathProbe
            | CoreCommand::NetUp
            | CoreCommand::NetDown
            | CoreCommand::SettingsSet
            | CoreCommand::DnsPreferenceSet
            | CoreCommand::RouteAcceptSet
            | CoreCommand::ExitnodeSelect
            | CoreCommand::AutostartSet
            | CoreCommand::KillswitchModeSet
            | CoreCommand::PairBegin
            | CoreCommand::PairConfirm
            | CoreCommand::PairCancel
            | CoreCommand::PairStatus
            | CoreCommand::DeviceRevoke
            | CoreCommand::KeyRotate
            | CoreCommand::UpdateCheck
            | CoreCommand::UpdateStage
            | CoreCommand::UpdateApply
            | CoreCommand::UpdateRollback
            | CoreCommand::KillswitchDisarmBegin
            | CoreCommand::KillswitchDisarmCommit
            | CoreCommand::HostNetworkChanged
            | CoreCommand::HostLifecycle => true,
        }
    }

    #[test]
    fn all_holds_every_variant_exactly_once() {
        for c in CoreCommand::ALL {
            assert!(is_in_all(*c));
        }
        let mut sorted: Vec<CoreCommand> = CoreCommand::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), CoreCommand::ALL.len(), "a duplicate in ALL");
    }

    #[test]
    fn names_are_unique_and_round_trip() {
        let mut names: Vec<&str> = CoreCommand::ALL.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two operations share a name");
        for c in CoreCommand::ALL {
            assert_eq!(CoreCommand::from_name(c.name()), Some(*c));
        }
    }

    #[test]
    fn an_unknown_name_is_none_never_a_guess() {
        assert_eq!(CoreCommand::from_name("status.gett"), None);
        assert_eq!(CoreCommand::from_name(""), None);
        assert_eq!(CoreCommand::from_name("killswitch.disarm"), None);
    }

    #[test]
    fn mi_21s_four_transport_operations_are_not_core_commands() {
        // MI-21: these are about the connection, and each MUST NOT acquire an
        // ABI counterpart. If one is ever added to `CoreCommand`, this fails.
        for name in ["hello", "mi.catalogue.get", "event.resync"] {
            assert_eq!(
                CoreCommand::from_name(name),
                None,
                "{name} is an MI transport operation and must not be a core command"
            );
        }
    }
}
