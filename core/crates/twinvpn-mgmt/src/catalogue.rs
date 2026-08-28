//! The MI operation catalogue — **derived** from [`CoreCommand`], never
//! authored beside it.
//!
//! **Authority:** [ADR-0017](../../../../docs/adr/ADR-0017-local-management-interface.md)
//! MI-1, MI-20, MI-21, §11.5 (scopes), §11.7 (`catalogue_digest`), §11.9 (the
//! table), §11.12 (MI-C1, the CLI binding);
//! [ADR-0018](../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.16 (b) and (o).
//!
//! # "Derived" is a compiler property here, not a claim
//!
//! [`entry`] is a single exhaustive `match` over [`CoreCommand`] with **no
//! wildcard arm**. Adding a core command without a catalogue row does not produce
//! a missing row — it produces a **compile error**. That is MI-20's *"a core
//! command with no catalogue entry … is a build failure, not a review finding"*,
//! realized.
//!
//! [`catalogue`] then walks [`CoreCommand::ALL`], so the table's contents and its
//! order both come from the command set. There is no list of operations in this
//! file for a reviewer to check against the enum, because there is no second
//! list. `contracts/docs/phase1-conflicts.md` OQ-2 deliberately excluded an MI
//! transport schema from Phase 2 for exactly this reason, and none is created
//! here.

use crate::command::CoreCommand;

/// An authorization scope (ADR-0017 §11.5).
///
/// *"A principal with a scope can use every operation in it. Scope granularity
/// is the whole authorization resolution."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// `mgmt.status` — read connection state, sessions, peers, paths, policy
    /// view, enforcement posture, capabilities, metrics, version, catalogue.
    Status,
    /// `mgmt.events` — the live event stream.
    Events,
    /// `mgmt.diagnostics` — the connectivity report and the Tier-0 tail.
    Diagnostics,
    /// `mgmt.connect` — connect, disconnect, reconnect, probe.
    Connect,
    /// `mgmt.settings` — local preferences and the S-24 surface.
    Settings,
    /// `mgmt.admin` — the ADMINISTER-class ceremonies.
    Admin,
    /// The **ephemeral** `mgmt.disarm` scope. Not held by a principal: it is
    /// granted for one commit by the §11.14 ceremony and expires with it.
    Disarm,
}

impl Scope {
    /// The wire spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Scope::Status => "mgmt.status",
            Scope::Events => "mgmt.events",
            Scope::Diagnostics => "mgmt.diagnostics",
            Scope::Connect => "mgmt.connect",
            Scope::Settings => "mgmt.settings",
            Scope::Admin => "mgmt.admin",
            Scope::Disarm => "mgmt.disarm",
        }
    }
}

/// ADR-0017 §11.9's `Idem` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Idempotency {
    /// `ro` — read-only.
    ReadOnly,
    /// `nat` — naturally idempotent.
    Natural,
    /// `key` — an ADR-0008 `CEREMONY` key is **required**.
    Key,
    /// `ver` — an `if_version` precondition is **required**.
    Version,
}

/// Whether the operation is a request/response or a stream (§11.9's **ST**).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// Request/response.
    Unary,
    /// A stream.
    Stream,
}

/// One catalogue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The core command this row is derived from. Never `None`: a catalogue row
    /// with no core command is what MI-20 forbids, and the type makes it
    /// unrepresentable.
    pub op: CoreCommand,
    /// The scope a principal must hold.
    pub scope: Scope,
    /// Whether the operation mutates state.
    pub mutating: bool,
    /// Its idempotency requirement.
    pub idempotency: Idempotency,
    /// Unary or stream.
    pub delivery: Delivery,
    /// Whether §11.14's ADMINISTER ceremony gates it.
    ///
    /// ADR-0016 §11.7 makes `killswitch.mode.set` ADMINISTER **even for a
    /// raise**, which is why this is a separate flag from the scope: holding
    /// `mgmt.admin` is necessary and not sufficient.
    pub administer: bool,
}

/// The catalogue row for one command.
///
/// **Exhaustive, no wildcard.** This function *is* MI-20's build failure.
#[must_use]
// One arm per operation, and several arms coincide. Neither is a defect: §11.9
// IS the table, so a reviewer must be able to find each operation's row here,
// and merging two operations that happen to share a posture today would hide it
// when one of them changes tomorrow. Splitting the function would hide the same
// thing behind a call.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub const fn entry(op: CoreCommand) -> Entry {
    use CoreCommand as C;
    let (scope, mutating, idempotency, delivery, administer) = match op {
        // -- reads, `mgmt.status` -------------------------------------------
        C::StatusGet
        | C::SessionList
        | C::SessionGet
        | C::PeerList
        | C::PeerGet
        | C::PathList
        | C::PolicyGet
        | C::KillswitchGet
        | C::KillswitchExemptGet
        | C::CapabilityGet
        | C::LifecycleGet
        | C::VersionGet
        | C::MetricsGet
        | C::SettingsGet
        | C::UpdateStatus => (
            Scope::Status,
            false,
            Idempotency::ReadOnly,
            Delivery::Unary,
            false,
        ),

        // -- events ----------------------------------------------------------
        C::EventSubscribe => (
            Scope::Events,
            false,
            Idempotency::Natural,
            Delivery::Stream,
            false,
        ),
        C::EventUnsubscribe => (
            Scope::Events,
            false,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),

        // -- diagnostics ------------------------------------------------------
        C::DiagReport => (
            Scope::Diagnostics,
            false,
            Idempotency::ReadOnly,
            Delivery::Unary,
            false,
        ),
        C::DiagLogTail => (
            Scope::Diagnostics,
            false,
            Idempotency::ReadOnly,
            Delivery::Stream,
            false,
        ),
        // §11.9 puts both of these under `mgmt.settings`, not `mgmt.diagnostics`:
        // they *change* something (an artifact is written; the capture level is
        // raised), and reading diagnostics must not imply the right to produce
        // them.
        C::DiagBundleCreate | C::DiagCaptureSet => (
            Scope::Settings,
            true,
            Idempotency::Key,
            Delivery::Unary,
            false,
        ),

        // -- connection -------------------------------------------------------
        C::SessionConnect
        | C::SessionDisconnect
        | C::SessionReconnect
        | C::PathProbe
        | C::NetUp
        | C::NetDown => (
            Scope::Connect,
            true,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),

        // -- settings ---------------------------------------------------------
        C::SettingsSet
        | C::DnsPreferenceSet
        | C::RouteAcceptSet
        | C::ExitnodeSelect
        | C::AutostartSet => (
            Scope::Settings,
            true,
            Idempotency::Version,
            Delivery::Unary,
            false,
        ),

        // -- administration ---------------------------------------------------
        C::KillswitchModeSet => (
            Scope::Admin,
            true,
            Idempotency::Version,
            Delivery::Unary,
            true,
        ),
        C::PairBegin | C::PairConfirm | C::DeviceRevoke | C::KeyRotate => {
            (Scope::Admin, true, Idempotency::Key, Delivery::Unary, true)
        }
        C::PairCancel => (
            Scope::Admin,
            true,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),
        C::PairStatus => (
            Scope::Admin,
            false,
            Idempotency::ReadOnly,
            Delivery::Unary,
            false,
        ),
        C::UpdateCheck => (
            Scope::Settings,
            true,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),
        C::UpdateStage | C::UpdateApply | C::UpdateRollback => {
            (Scope::Admin, true, Idempotency::Key, Delivery::Unary, true)
        }

        // -- the disarm ceremony ----------------------------------------------
        // `begin` is `mgmt.settings` and NOT mutating: it hands back a challenge.
        // "the ability to ask, not to do".
        C::KillswitchDisarmBegin => (
            Scope::Settings,
            false,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),
        C::KillswitchDisarmCommit => (
            Scope::Disarm,
            true,
            Idempotency::Natural,
            Delivery::Unary,
            true,
        ),

        // -- host-submitted lifecycle -----------------------------------------
        // The shell is the only submitter and it is the process that hosts the
        // core, so these sit at `mgmt.admin`: an unprivileged local client must
        // not be able to tell the core the network changed.
        C::HostNetworkChanged | C::HostLifecycle => (
            Scope::Admin,
            true,
            Idempotency::Natural,
            Delivery::Unary,
            false,
        ),
    };
    Entry {
        op,
        scope,
        mutating,
        idempotency,
        delivery,
        administer,
    }
}

/// The whole catalogue, in the command set's order.
///
/// `mi.catalogue.get` returns this. A client "MUST NOT call an operation absent
/// from the catalogue it fetched on **this** connection", which is why the
/// digest below is per-build and travels in `HelloAck`.
#[must_use]
pub fn catalogue() -> Vec<Entry> {
    CoreCommand::ALL.iter().copied().map(entry).collect()
}

/// The `catalogue_digest` `HelloAck` carries (§11.7).
///
/// *"The catalogue, not the version, is the capability contract."* A router build
/// with a reduced operation set and a desktop build with the full one must be
/// distinguishable by a client that knows neither version, so the digest covers
/// the **rows**, not the build number.
///
/// FNV-1a over the canonical rendering. Not a cryptographic digest, and it is not
/// pretending to be one: nothing trusts it, it only has to change when the table
/// does. Using SHA-256 here would put a cryptographic dependency in a crate CD-I2
/// does not permit one in.
#[must_use]
pub fn catalogue_digest() -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(PRIME);
        }
    };
    for e in catalogue() {
        feed(e.op.name().as_bytes());
        feed(e.scope.name().as_bytes());
        feed(&[
            u8::from(e.mutating),
            e.idempotency as u8,
            e.delivery as u8,
            u8::from(e.administer),
        ]);
        feed(b"\x1f");
    }
    h
}

/// The **one** rendering of [`catalogue_digest`] that crosses a wire.
///
/// **Authority:** ADR-0017 §11.7 (*"The catalogue, not the version, is the
/// capability contract"*), MI-21 (the digest is one of the four transport-layer
/// facts), MI-5's reconnect rule.
///
/// # Why a `u64` needed a pinned spelling
///
/// [`catalogue_digest`] returns a `u64` and `HelloAck.catalogue_digest` is a
/// **string**, so every carriage had to choose an encoding — and they did not
/// all choose the same one. `shells/windows`' `twinvpnctl` rendered it with
/// `to_string()` (decimal) while `shells/windows`' service rendered it as
/// `{:016x}` (hex), so a client and an agent from one build compared two
/// spellings of one number and could conclude the catalogue had changed.
///
/// §11.7 makes the digest *the capability contract*, and MI-5 requires a client
/// to re-fetch the catalogue when it changes. An unpinned rendering is therefore
/// how a client and an agent come to disagree about the contract **silently**,
/// which is the failure MI-20 exists to prevent one level up.
///
/// The encoding is **lowercase hexadecimal, zero-padded to exactly 16 digits**.
/// The fixed width matters on its own: a digest that happened to be small would
/// otherwise render short, and a length-sensitive consumer would see the width
/// move between builds.
///
/// This is the only function that renders it. There is no second one.
#[must_use]
pub fn catalogue_digest_text() -> String {
    format!("{:016x}", catalogue_digest())
}

/// Looks up a row by wire name.
///
/// `None` is the `MGMT.OP_UNKNOWN` case: a **typed** rejection naming the
/// operation, never a parse error and never a hang (§11.7).
#[must_use]
pub fn lookup(name: &str) -> Option<Entry> {
    CoreCommand::from_name(name).map(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_is_the_command_set_and_nothing_else() {
        // MI-20 in both directions: a core command with no catalogue entry, and
        // a catalogue entry with no core command. The second is unrepresentable
        // — `Entry::op` is a `CoreCommand` — and this asserts the first.
        let cat = catalogue();
        assert_eq!(cat.len(), CoreCommand::ALL.len());
        for (row, cmd) in cat.iter().zip(CoreCommand::ALL) {
            assert_eq!(row.op, *cmd, "the catalogue reordered the command set");
        }
    }

    #[test]
    fn a_read_only_row_never_mutates() {
        // One direction only, deliberately. §11.9's table has non-mutating rows
        // that are `nat` rather than `ro` — `event.subscribe`,
        // `event.unsubscribe` and `killswitch.disarm.begin` — because they are
        // *naturally idempotent* without being reads. Asserting the biconditional
        // would force one of those three to be relabelled to satisfy a test,
        // which is the tail wagging the contract.
        for e in catalogue() {
            if e.idempotency == Idempotency::ReadOnly {
                assert!(!e.mutating, "{} is read-only but mutates", e.op);
            }
        }
    }

    #[test]
    fn every_mutating_row_states_how_it_is_made_idempotent() {
        // ADR-0008: a mutating operation is `key`, `ver`, or naturally
        // idempotent. There is no fourth answer, and "we did not think about it"
        // is not one of the three.
        for e in catalogue() {
            if e.mutating {
                assert_ne!(
                    e.idempotency,
                    Idempotency::ReadOnly,
                    "{} mutates but claims to be read-only",
                    e.op
                );
            }
        }
    }

    #[test]
    fn every_administer_row_mutates() {
        for e in catalogue() {
            if e.administer {
                assert!(e.mutating, "{} is ADMINISTER but does not mutate", e.op);
            }
        }
    }

    #[test]
    fn disarm_begin_is_not_mutating_and_commit_is_ephemeral_scoped() {
        // MI's own words: `begin` is "the ability to ask, not to do".
        let begin = entry(CoreCommand::KillswitchDisarmBegin);
        assert!(!begin.mutating);
        assert_eq!(begin.scope, Scope::Settings);

        let commit = entry(CoreCommand::KillswitchDisarmCommit);
        assert!(commit.mutating);
        assert!(commit.administer);
        assert_eq!(
            commit.scope,
            Scope::Disarm,
            "the disarm scope is ephemeral and is not `mgmt.admin`"
        );
    }

    #[test]
    fn killswitch_mode_set_is_administer_even_though_it_can_only_raise() {
        // ADR-0016 §11.7, cited by §11.9: "ADMINISTER even for a raise".
        let e = entry(CoreCommand::KillswitchModeSet);
        assert!(e.administer);
        assert_eq!(e.idempotency, Idempotency::Version);
    }

    #[test]
    fn net_down_is_a_connect_scope_operation_not_an_admin_one() {
        // MI-K1: `net.down` clears session intent and MUST NOT clear the latch.
        // If it were an admin operation it would look like a disarm.
        let e = entry(CoreCommand::NetDown);
        assert_eq!(e.scope, Scope::Connect);
        assert!(!e.administer);
    }

    #[test]
    fn the_digest_changes_when_the_table_does() {
        let d = catalogue_digest();
        assert_ne!(d, 0);
        // Stability within one build: two calls agree.
        assert_eq!(d, catalogue_digest());
    }

    /// **The wire spelling is pinned, because an unpinned one is how two halves
    /// of one build disagree about the capability contract.**
    ///
    /// `shells/windows` rendered it decimal in its CLI and hex in its service.
    /// Both were "correct"; together they were a client that could never match
    /// the digest it was sent.
    #[test]
    fn the_wire_rendering_is_sixteen_lowercase_hex_digits_and_nothing_else() {
        let text = catalogue_digest_text();
        assert_eq!(
            text.len(),
            16,
            "fixed width, so a small digest does not render short"
        );
        assert!(
            text.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "lowercase hex only, got {text}"
        );
        assert_eq!(text, format!("{:016x}", catalogue_digest()));
        // And it is NOT the decimal rendering, which is the spelling that
        // actually shipped in one place.
        assert_ne!(text, catalogue_digest().to_string());
    }

    #[test]
    fn the_rendering_round_trips_back_to_the_digest() {
        // A client that parses it must recover the same number, so the encoding
        // is a bijection and not merely a display form.
        let text = catalogue_digest_text();
        assert_eq!(
            u64::from_str_radix(&text, 16).expect("parses"),
            catalogue_digest()
        );
    }

    #[test]
    fn a_small_digest_still_renders_at_full_width() {
        // A property of the FORMAT, not of today's table, asserted directly so
        // it cannot regress when the table changes.
        assert_eq!(format!("{:016x}", 1u64), "0000000000000001");
        assert_eq!(format!("{:016x}", u64::MAX), "ffffffffffffffff");
    }

    #[test]
    fn lookup_refuses_an_unknown_operation() {
        assert!(lookup("status.get").is_some());
        assert!(lookup("mi.catalogue.get").is_none());
        assert!(lookup("nonsense").is_none());
    }

    #[test]
    fn killswitch_exempt_get_is_read_only_always() {
        // MI-11, and ADR-0017 §11.1.1's correction: it is an ordinary core
        // command, and it is read-only "always".
        let e = entry(CoreCommand::KillswitchExemptGet);
        assert!(!e.mutating);
        assert_eq!(e.idempotency, Idempotency::ReadOnly);
    }
}
