//! The KS-19 boot artifact: the filter set the **installer** writes and the Base
//! Filtering Engine applies before any process of ours runs.
//!
//! **Authority:** ADR-0012 KS-19 ("the rule set that covers the interval between
//! the network stack coming up and the agent starting MUST be installed by an
//! artifact the **OS itself applies**, never by the agent. This is where real
//! products leak."), §11.6's Windows row; ADR-0016 PS-7 (package-owned, and the
//! authority "MUST NOT be a prerequisite for it to apply"), §11.6 step (1);
//! ADR-0022 LC-12.
//!
//! # Who writes this, and who only checks it
//!
//! PS-7 is explicit: the artifact is installed by the package and modified only
//! by an atomic replace under `ADMINISTER` authority. **The service never writes
//! it.** What the service does is *verify its presence* at start, and a missing
//! artifact is `CRITICAL` and **not fatal** — refusing to start would leave the
//! host with neither the boot ruleset nor an agent, which is the worse of the
//! two states.
//!
//! This module therefore renders the set as **data**, for two consumers:
//!
//! | Consumer | Uses |
//! |---|---|
//! | `shells/windows/packaging` | [`boot_set`] — what the MSI installs |
//! | the service, at start | [`verify`] — ADR-0016 §11.6 step (1) |
//!
//! # The one thing a boot-time filter cannot do
//!
//! ADR-0012 §11.6's Windows limitation row, verbatim in effect:
//!
//! > BOOTTIME filters cannot use ALE app-id conditions, so the bootstrap
//! > exception is unavailable during the boot window. The agent cannot connect
//! > until BFE and the service start — an *availability* gap, not a leak.
//! > Deliberate: the boot window fails closed, which is the correct direction.
//!
//! So this set carries **no** [`Condition::AppId`] and no
//! [`Condition::UserSid`], and [`super::FilterSet::validate`] refuses one that
//! does. The consequence is that between BFE applying these filters and the
//! service reaching step 4 of ADR-0022 LC-4, TwinVPN itself cannot reach the
//! control plane. ADR-0022 LC-12 is why the service is `SERVICE_AUTO_START` and
//! not delayed-start: delaying it by two minutes lengthens exactly this window.
//!
//! # Why the boot set is coarser than the runtime set
//!
//! It denies the **product's own address space** — the two constants of
//! [`super::baseline_protected`] — rather than a contract's scope, because at
//! boot there is no contract: the durable store has not been opened and the
//! last-applied generation is not yet known. A boot set that guessed at a scope
//! would be wrong on the first host that changed routing mode. What it
//! guarantees is the narrow, always-true thing: no traffic to the overlay space
//! leaves this host before the authority has asserted a posture.

use twinvpn_types::AddressFamily;

use super::filters::filter_key;
use super::readback::{class_of, EngineState};
use super::{
    baseline_protected, Action, Condition, FilterFlags, FilterSet, FilterSpec, IpProtocol, Layer,
    Ruleset, TrafficClass, FILTER_POSTURE_BLOCKED,
};

/// The flags every boot filter carries.
///
/// Both, and both are load-bearing. `boot_time` is what BFE applies before the
/// network stack is usable; `persistent` is what survives the transition out of
/// the boot phase, so there is no instant between "boot filters expire" and "the
/// service installs its own" in which the host is open.
const fn boot_flags() -> FilterFlags {
    FilterFlags {
        persistent: true,
        boot_time: true,
    }
}

/// The set the installer writes.
///
/// A [`FilterSet`] like any other, and carrying the [`Ruleset::Blocked`] posture
/// marker, so the read-back path is the **same code** as the runtime one: the
/// service's step-(1) check asks the engine the same question it asks every
/// assertion cycle, rather than a special boot-only question that could be
/// wrong in its own way.
///
/// Generation `0`, because a boot set describes no contract. The runtime path
/// treats `0` as "no generation" (see
/// [`super::readback::parse_installed`]), so a host that has booted and not yet
/// converged reports honestly rather than claiming generation 1.
#[must_use]
pub fn boot_set() -> FilterSet {
    let mut filters = Vec::new();

    // Loopback, so the stub's own listeners and every local IPC survive the
    // boot window. Weight above the deny; no ALE condition, so BFE can evaluate
    // it.
    for layer in Layer::BOTH {
        filters.push(FilterSpec {
            key: filter_key(TrafficClass::Loopback, layer, BOOT_ORDINAL),
            name: "twinvpn-boot-loopback",
            layer,
            action: Action::Permit,
            weight: 10_000,
            conditions: vec![Condition::IsLoopback],
            class: TrafficClass::Loopback,
            flags: boot_flags(),
        });
    }

    // DHCP and DHCPv6, so a host can acquire an address during the window. ND
    // and RA on v6 for the same reason. Without these the boot window is not
    // merely offline for TwinVPN, it is offline for the host, and KS-19 asks for
    // a coverage guarantee rather than for a disconnected machine.
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV4,
            BOOT_ORDINAL,
        ),
        name: "twinvpn-boot-dhcp4",
        layer: Layer::AleAuthConnectV4,
        action: Action::Permit,
        weight: 8_000,
        conditions: vec![
            Condition::Protocol(IpProtocol::Udp),
            Condition::RemotePort(67),
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: boot_flags(),
    });
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV6,
            BOOT_ORDINAL,
        ),
        name: "twinvpn-boot-dhcp6",
        layer: Layer::AleAuthConnectV6,
        action: Action::Permit,
        weight: 8_000,
        conditions: vec![
            Condition::Protocol(IpProtocol::Udp),
            Condition::RemotePort(547),
            Condition::LinkLocalScope,
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: boot_flags(),
    });
    filters.push(FilterSpec {
        key: filter_key(
            TrafficClass::UnderlayConfiguration,
            Layer::AleAuthConnectV6,
            BOOT_ORDINAL + 1,
        ),
        name: "twinvpn-boot-nd-ra",
        layer: Layer::AleAuthConnectV6,
        action: Action::Permit,
        weight: 8_000,
        conditions: vec![
            Condition::Protocol(IpProtocol::IcmpV6),
            Condition::LinkLocalScope,
        ],
        class: TrafficClass::UnderlayConfiguration,
        flags: boot_flags(),
    });

    // The coarse deny: the product's own address space, both families. One
    // filter per prefix per family, from the same constant the runtime floor
    // uses, so the two sets cannot disagree about what the overlay space is.
    for (ordinal, prefix) in baseline_protected().into_iter().enumerate() {
        let layer = Layer::for_family(prefix.family());
        filters.push(FilterSpec {
            key: filter_key(
                TrafficClass::ProtectedScopeDeny,
                layer,
                BOOT_ORDINAL + u16::try_from(ordinal).unwrap_or(0),
            ),
            name: "twinvpn-boot-scope-deny",
            layer,
            action: Action::Block,
            weight: 100,
            conditions: vec![Condition::RemotePrefix(prefix)],
            class: TrafficClass::ProtectedScopeDeny,
            flags: boot_flags(),
        });
    }

    filters.push(FilterSpec {
        key: FILTER_POSTURE_BLOCKED,
        name: "twinvpn-boot-posture",
        layer: Layer::AleAuthConnectV4,
        action: Action::Block,
        weight: 0,
        conditions: vec![Condition::LocalInterface(0)],
        class: TrafficClass::Marker,
        flags: boot_flags(),
    });

    FilterSet {
        generation: 0,
        posture: Ruleset::Blocked,
        filters,
    }
}

/// The ordinal band the boot set uses.
///
/// Boot filters and runtime filters live in one sublayer and derive their keys
/// from the same function, so they must not collide. A band rather than a
/// separate class code keeps [`class_of`] able to decode a boot filter — which
/// is what lets the service's step-(1) check reuse the runtime read-back.
pub const BOOT_ORDINAL: u16 = 0xB0_00;

/// What the service's ADR-0016 §11.6 step (1) check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootArtifact {
    /// Whether a boot-time deny exists for IPv4.
    pub v4_deny: bool,
    /// Whether a boot-time deny exists for IPv6.
    pub v6_deny: bool,
}

impl BootArtifact {
    /// Whether the artifact is present in the form KS-19 requires.
    ///
    /// **Both families.** A boot set that covers one is KS-5's non-conforming
    /// case at the moment the host is least defended, and reporting it as
    /// present would hide exactly that.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.v4_deny && self.v6_deny
    }
}

/// Verifies the boot artifact against what the engine holds.
///
/// **Verification, never installation** (PS-7). Nothing in this module writes,
/// and the service that calls it treats a `false` as `CRITICAL`-and-continue
/// rather than as a refusal to start.
#[must_use]
pub fn verify(state: &EngineState) -> BootArtifact {
    let has = |family: AddressFamily| {
        let layer = Layer::for_family(family);
        state.filters.iter().any(|f| {
            f.provider_owned
                && f.layer == layer
                && f.action == Action::Block
                && class_of(f.key) == Some(TrafficClass::ProtectedScopeDeny)
                && is_boot_key(f.key, layer)
        })
    };
    BootArtifact {
        v4_deny: has(AddressFamily::V4),
        v6_deny: has(AddressFamily::V6),
    }
}

/// Whether a key lies in the boot ordinal band.
fn is_boot_key(key: super::Guid, layer: Layer) -> bool {
    (0..8).any(|offset| {
        filter_key(
            TrafficClass::ProtectedScopeDeny,
            layer,
            BOOT_ORDINAL + offset,
        ) == key
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::readback::InstalledFilter;
    use crate::wfp::SetDefect;

    fn engine_holding(set: &FilterSet) -> EngineState {
        EngineState {
            sublayer_present: true,
            provider_data: Some(set.generation.to_be_bytes().to_vec()),
            filters: set
                .filters
                .iter()
                .map(|f| InstalledFilter {
                    key: f.key,
                    layer: f.layer,
                    action: f.action,
                    provider_owned: true,
                })
                .collect(),
        }
    }

    #[test]
    fn the_boot_set_is_installable_and_covers_both_families() {
        let set = boot_set();
        set.validate().expect("installable");
        assert_eq!(set.families_covered(), (true, true));
        assert_eq!(set.posture, Ruleset::Blocked);
        assert_eq!(set.generation, 0, "a boot set describes no contract");
    }

    #[test]
    fn no_boot_filter_names_a_principal_because_bfe_cannot_evaluate_one() {
        // ADR-0012 §11.6's Windows limitation. The whole reason the bootstrap
        // exception is unavailable in the boot window.
        for filter in &boot_set().filters {
            assert!(filter.flags.boot_time, "{}", filter.name);
            assert!(filter.flags.persistent, "{}", filter.name);
            assert!(
                !filter
                    .conditions
                    .iter()
                    .any(|c| matches!(c, Condition::AppId(_) | Condition::UserSid(_))),
                "{} names a principal",
                filter.name
            );
        }
    }

    #[test]
    fn a_boot_filter_that_named_a_principal_is_refused_rather_than_installed() {
        let mut set = boot_set();
        set.filters[0]
            .conditions
            .push(Condition::AppId(r"\device\harddiskvolume3\twinvpnsvc.exe"));
        assert!(matches!(
            set.validate().expect_err("refused"),
            SetDefect::BootTimeFilterNamesAPrincipal(_)
        ));
    }

    #[test]
    fn the_boot_window_fails_closed_for_the_agent_too() {
        // The availability gap, asserted rather than described: there is no
        // permit in the boot set that our own process could use to reach a
        // relay or the control plane.
        let set = boot_set();
        for filter in set.filters.iter().filter(|f| f.action == Action::Permit) {
            assert!(
                matches!(
                    filter.class,
                    TrafficClass::Loopback | TrafficClass::UnderlayConfiguration
                ),
                "{} would let the boot window carry traffic",
                filter.name
            );
        }
    }

    #[test]
    fn a_host_holding_the_boot_set_reports_the_artifact_as_registered() {
        let artifact = verify(&engine_holding(&boot_set()));
        assert!(artifact.is_registered());
        assert!(artifact.v4_deny && artifact.v6_deny);
    }

    #[test]
    fn a_fresh_host_reports_the_artifact_as_absent() {
        let artifact = verify(&EngineState::default());
        assert!(!artifact.is_registered());
    }

    #[test]
    fn a_one_family_boot_set_is_not_registered() {
        // KS-5 at the moment the host is least defended. Reporting it as
        // present would hide exactly the case KS-19 exists to close.
        let mut set = boot_set();
        set.filters.retain(|f| {
            !(f.class == TrafficClass::ProtectedScopeDeny && f.layer == Layer::AleAuthConnectV6)
        });
        let artifact = verify(&engine_holding(&set));
        assert!(artifact.v4_deny);
        assert!(!artifact.v6_deny);
        assert!(!artifact.is_registered());
    }

    #[test]
    fn the_runtime_set_is_never_mistaken_for_the_boot_artifact() {
        // The two sets share a sublayer and a key derivation. If the runtime
        // set satisfied the step-(1) check, a host whose installer never wrote
        // the boot filters would look compliant the moment the service started
        // — which is precisely the leak KS-19 names.
        let runtime = crate::wfp::filters::render(
            &super::super::filters::tests_support::contract(),
            Ruleset::Blocked,
            &super::super::filters::tests_support::config(),
        );
        let artifact = verify(&engine_holding(&runtime));
        assert!(
            !artifact.is_registered(),
            "the runtime set must not satisfy the boot check"
        );
    }

    #[test]
    fn a_third_partys_boot_filter_is_never_counted_as_ours() {
        let mut state = engine_holding(&boot_set());
        for filter in &mut state.filters {
            filter.provider_owned = false;
        }
        assert!(!verify(&state).is_registered());
    }
}
