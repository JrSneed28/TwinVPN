//! The read-back: what the **engine** says is installed, not what we believe we
//! installed.
//!
//! **Authority:** ADR-0012 K12 ("Enforcement state MUST be observable by
//! querying the installed rules, not by trusting the agent's belief about what
//! it installed"), §11.12 (e); ADR-0015 §11.6 rule 1 (O-17) and rule 2 (O-18);
//! ADR-0016 §11.6 step (2); `ownership.md` §8 W-24.
//!
//! # W-24, and why this module exists at all
//!
//! `twinvpn.h`'s F-9 vtable offers `set_ruleset` with **no getter**, so a shell
//! bound only to the C ABI cannot produce a `ProtectionAssertion` at all. This
//! adapter is bound as a Rust crate and does not have that limit: the shell asks
//! the Base Filtering Engine what it holds, hands the rows here, and gets back a
//! posture derived from **which objects exist**.
//!
//! Nothing is cached. The reconciler's whole job is to notice that something
//! else changed the filters, and a cache cannot. A failed query is an error, not
//! a remembered value: `Ok(None)` from this module means "the engine holds no
//! TwinVPN ruleset", which is a very different claim from "we could not ask".
//!
//! # The keys are self-describing, which is what makes this possible
//!
//! [`super::filters::filter_key`] derives every runtime key from
//! `(class, layer, ordinal)`, so an enumerated `FWPM_FILTER0` carries its own
//! class in its key. The read-back therefore needs nothing from the engine
//! beyond what `FwpmFilterEnum0` already returns — no display-name parsing, no
//! description free text, no side table that could disagree with the engine.

use twinvpn_platform::{ContractGeneration, Ruleset};
use twinvpn_types::{AddressFamily, PerFamily};

use super::filters::filter_key;
use super::{Action, Guid, Layer, TrafficClass, FILTER_POSTURE_BLOCKED, FILTER_POSTURE_PROTECTED};

/// One row of `FwpmFilterEnum0`, reduced to the fields that carry meaning.
///
/// Deliberately not a mirror of `FWPM_FILTER0`: the shim in [`crate::sys`]
/// narrows it here so that everything above this line is target-free, and so a
/// reviewer can see exactly which four facts the posture is derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledFilter {
    /// The filter key the engine reported.
    pub key: Guid,
    /// Which layer it sits at.
    pub layer: Layer,
    /// What it does.
    pub action: Action,
    /// Whether the engine reported **our** provider key on it.
    ///
    /// This is the owner tag (KS-20, PS-8). A filter without it is somebody
    /// else's and is never counted, never reclaimed and never deleted.
    pub provider_owned: bool,
}

/// Everything the shim read out of the engine in one query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineState {
    /// Whether the owned sublayer exists.
    pub sublayer_present: bool,
    /// The owned provider's `providerData`, which carries the generation.
    pub provider_data: Option<Vec<u8>>,
    /// Every filter the enumeration returned, ours and not.
    pub filters: Vec<InstalledFilter>,
}

/// What the engine actually holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The posture, from which marker filter is present.
    pub posture: Ruleset,
    /// The generation, from the provider's own blob.
    pub generation: ContractGeneration,
    /// How many Tier-1 scope denies cover each family.
    ///
    /// **`desktop-linux`'s R-6 detector, ported.** The posture marker says which
    /// ruleset was *intended*; this says how much the deny actually covers.
    /// Without it, an engine holding the marker and **zero** deny filters reads
    /// back as `Blocked` and a reconciler is satisfied — which is a fail-closed
    /// posture over nothing. With it, "BLOCKED over nothing" is a value a caller
    /// can refuse.
    pub scope_denies: PerFamily<usize>,
    /// Whether a Tier-2 overlay permit exists, per family.
    pub overlay_permits: PerFamily<bool>,
    /// How many owned filters the engine holds that the **runtime** set owns.
    ///
    /// Excludes the KS-19 boot artifact, which a runtime commit deliberately
    /// does not delete (see [`super::boot::is_boot_filter`]) and therefore must
    /// not be counted against the runtime set's size — a comparison that counted
    /// them would report `FiltersMissing` on every healthy host that had booted.
    pub owned_filters: usize,
    /// How many KS-9 bootstrap-exemption filters the engine holds.
    ///
    /// The fact a start sequence actually needs, and it is **not** implied by
    /// the posture. A host that has just booted holds the KS-19 artifact and
    /// nothing else: fail-closed, `Blocked`, and unable to run, because the
    /// bootstrap exemption is a *runtime* filter and the boot set cannot carry
    /// one — ADR-0012 §11.6's Windows row says why (a BOOTTIME filter cannot
    /// name an ALE principal). Counting it separately is what lets
    /// `WindowsNetworkConfig::reclaim` tell "already running" from "fail-closed
    /// and stuck".
    pub bootstrap_exemptions: usize,
    /// How many of the engine's owned filters are the boot artifact's.
    ///
    /// Reported separately rather than folded away, because "the boot artifact
    /// is still installed" is a fact ADR-0016 §11.6 step (1) asks about and a
    /// support case has no other way to see.
    pub boot_filters: usize,
}

impl Installed {
    /// Whether both families are covered by at least one Tier-1 deny.
    ///
    /// KS-5's question, asked of the engine rather than of the installer's
    /// return code.
    #[must_use]
    pub fn both_families_covered(&self) -> bool {
        *self.scope_denies.get(AddressFamily::V4) > 0
            && *self.scope_denies.get(AddressFamily::V6) > 0
    }
}

/// The generation blob's width. Eight bytes, big-endian, so the value is
/// readable in a hex dump of a support bundle without a decoder.
pub const GENERATION_BLOB_BYTES: usize = 8;

/// Reads the posture, the generation and the coverage out of an engine query.
///
/// Returns `None` when the engine holds **no** TwinVPN ruleset — no owned
/// sublayer, or no posture marker. That is a real state (a fresh host, or one an
/// uninstall has cleaned) and it is deliberately distinct from an error: a query
/// that could not be performed must reach the caller as a
/// [`twinvpn_platform::PlatformError`], never as this `None`.
#[must_use]
pub fn parse_installed(state: &EngineState) -> Option<Installed> {
    if !state.sublayer_present {
        return None;
    }

    let owned = || state.filters.iter().filter(|f| f.provider_owned);

    let blocked = owned().any(|f| f.key == FILTER_POSTURE_BLOCKED);
    let protected = owned().any(|f| f.key == FILTER_POSTURE_PROTECTED);
    // Both present is not a posture: it is a half-finished transaction or a
    // tamper, and answering either way would be a guess. `None` sends the
    // caller down the "re-assert BLOCKED" path of ADR-0022 LC-4 step 4, which
    // is the safe direction.
    let posture = match (blocked, protected) {
        (true, false) => Ruleset::Blocked,
        (false, true) => Ruleset::Protected,
        _ => return None,
    };

    let generation = state
        .provider_data
        .as_ref()
        .and_then(|blob| blob.get(..GENERATION_BLOB_BYTES))
        .and_then(|bytes| <[u8; GENERATION_BLOB_BYTES]>::try_from(bytes).ok())
        .map_or(ContractGeneration(0), |bytes| {
            ContractGeneration(u64::from_be_bytes(bytes))
        });

    let count = |class: TrafficClass, family: AddressFamily| {
        let layer = Layer::for_family(family);
        owned()
            .filter(|f| f.layer == layer && class_of(f.key) == Some(class))
            .count()
    };

    Some(Installed {
        posture,
        generation,
        scope_denies: PerFamily::new(
            count(TrafficClass::ProtectedScopeDeny, AddressFamily::V4),
            count(TrafficClass::ProtectedScopeDeny, AddressFamily::V6),
        ),
        bootstrap_exemptions: owned()
            .filter(|f| class_of(f.key) == Some(TrafficClass::BootstrapExemption))
            .count(),
        overlay_permits: PerFamily::new(
            count(TrafficClass::OverlayEgress, AddressFamily::V4) > 0,
            count(TrafficClass::OverlayEgress, AddressFamily::V6) > 0,
        ),
        owned_filters: owned()
            .filter(|f| !super::boot::is_boot_filter(f.key))
            .count(),
        boot_filters: owned()
            .filter(|f| super::boot::is_boot_filter(f.key))
            .count(),
    })
}

/// The class a derived key encodes, or `None` for a key this crate did not
/// derive.
///
/// The marker keys are deliberately **not** derived keys — they are fixed
/// constants, because their whole job is to be found by a reader who has only
/// the ADR and a filter dump.
#[must_use]
pub fn class_of(key: Guid) -> Option<TrafficClass> {
    if key == FILTER_POSTURE_BLOCKED || key == FILTER_POSTURE_PROTECTED {
        return Some(TrafficClass::Marker);
    }
    let b = key.as_bytes();
    // The derived prefix, and the `F` that separates a filter key from any other
    // derived key this crate might add later.
    if b[..8] != [0x74, 0x77, 0x69, 0x6e, 0x76, 0x70, 0x6e, 0x01] || b[8] != b'F' {
        return None;
    }
    let class = ALL_CLASSES
        .iter()
        .copied()
        .find(|c| super::filters::code_of(*c) == b[9])?;
    let layer = match b[10] {
        4 => Layer::AleAuthConnectV4,
        6 => Layer::AleAuthConnectV6,
        _ => return None,
    };
    // Round-trip the ordinal so a malformed key cannot decode to a real class.
    let ordinal = u16::from_be_bytes([b[11], b[12]]);
    if filter_key(class, layer, ordinal) == key {
        Some(class)
    } else {
        None
    }
}

/// Every class, for the decode. Written out so adding one to the enum without
/// adding it here is caught by [`tests::every_class_round_trips_through_a_key`].
const ALL_CLASSES: [TrafficClass; 13] = [
    TrafficClass::ProtectedScopeDeny,
    TrafficClass::LocalNetwork,
    TrafficClass::UnderlayConfiguration,
    TrafficClass::DnsContainment,
    TrafficClass::BootstrapExemption,
    TrafficClass::ResolverExemption,
    TrafficClass::UpdateExemption,
    TrafficClass::Loopback,
    TrafficClass::LinkLocal,
    TrafficClass::PortalGrant,
    TrafficClass::PortalProbe,
    TrafficClass::OverlayEgress,
    TrafficClass::Marker,
];

/// How the engine's contents compare with what the core asked for.
///
/// ADR-0012 §11.9's `POLICY.KILLSWITCH.ASSERTION_MISMATCH` and
/// `POLICY.KILLSWITCH.RULESET_TAMPERED` are the two conditions this
/// distinguishes; ADR-0015 O-17 is why the comparison exists at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The engine holds exactly what was intended.
    Matches,
    /// The engine holds nothing of ours.
    Absent,
    /// The engine holds a different posture from the one intended.
    PostureDiffers {
        /// What the engine holds.
        installed: Ruleset,
        /// What the core asked for.
        intended: Ruleset,
    },
    /// The engine holds the intended posture at a different generation.
    GenerationDiffers {
        /// What the engine holds.
        installed: ContractGeneration,
        /// What the core asked for.
        intended: ContractGeneration,
    },
    /// Owned filters are missing, so the set is not the one that was installed.
    FiltersMissing {
        /// How many the intended set has.
        intended: usize,
        /// How many the engine holds.
        installed: usize,
    },
    /// The posture is intact but one family has no Tier-1 deny.
    ///
    /// Its own verdict rather than a case of `FiltersMissing`, because KS-5
    /// makes this **non-conforming** rather than degraded and ADR-0010 R6 makes
    /// the v6 half of it a leak: the remediations are different sentences.
    FamilyUncovered {
        /// Whether IPv4 is covered.
        v4: bool,
        /// Whether IPv6 is covered.
        v6: bool,
    },
}

impl Verdict {
    /// Whether the installed state may be reported as protecting the host.
    #[must_use]
    pub const fn is_conforming(&self) -> bool {
        matches!(self, Verdict::Matches)
    }
}

/// Compares what the engine holds against what was intended.
#[must_use]
pub fn compare(state: &EngineState, intended: &super::FilterSet) -> Verdict {
    let Some(installed) = parse_installed(state) else {
        return Verdict::Absent;
    };
    if installed.posture != intended.posture {
        return Verdict::PostureDiffers {
            installed: installed.posture,
            intended: intended.posture,
        };
    }
    if !installed.both_families_covered() {
        return Verdict::FamilyUncovered {
            v4: *installed.scope_denies.get(AddressFamily::V4) > 0,
            v6: *installed.scope_denies.get(AddressFamily::V6) > 0,
        };
    }
    if installed.generation.0 != intended.generation {
        return Verdict::GenerationDiffers {
            installed: installed.generation,
            intended: ContractGeneration(intended.generation),
        };
    }
    if installed.owned_filters != intended.filters.len() {
        return Verdict::FiltersMissing {
            intended: intended.filters.len(),
            installed: installed.owned_filters,
        };
    }
    Verdict::Matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::filters::render;
    use crate::wfp::EnforcementConfig;
    use twinvpn_platform::{DnsConfig, NetworkContract, RouteEntry};
    use twinvpn_types::{IpAddr, IpPrefix, V4Addr};

    fn config() -> EnforcementConfig {
        EnforcementConfig {
            overlay_luid: 6,
            service_app_id: r"\device\harddiskvolume3\twinvpnsvc.exe",
            service_sid: "S-1-5-80-0",
            local_network_access: true,
            on_link_prefixes: Vec::new(),
            updater_app_id: None,
            update_origins: Vec::new(),
            portal_grant: Vec::new(),
            // Empty: this module decodes filter KEYS, and the endpoint half of
            // class 6 shares its class code with the port half, so the decode is
            // the same question either way.
            doh_endpoints: Vec::new(),
        }
    }

    fn contract(generation: u64) -> NetworkContract {
        NetworkContract {
            generation: ContractGeneration(generation),
            addresses: PerFamily::new(Vec::new(), Vec::new()),
            routes: PerFamily::new(
                vec![RouteEntry {
                    destination: IpPrefix::new(IpAddr::V4(V4Addr::from_octets([10, 0, 0, 0])), 8)
                        .expect("prefix"),
                    via: None,
                    interface: twinvpn_platform::InterfaceIndex(6),
                    metric: None,
                }],
                Vec::new(),
            ),
            dns: DnsConfig {
                resolvers: PerFamily::new(Vec::new(), Vec::new()),
                search_domains: Vec::new(),
                split_domains: Vec::new(),
                is_default_resolver: false,
            },
            ruleset: Ruleset::Blocked,
            mtu: 1420,
            tunnel_remote_address: None,
        }
    }

    /// The engine state a faithful install of `set` would produce.
    fn engine_holding(set: &crate::wfp::FilterSet) -> EngineState {
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
    fn a_faithful_install_reads_back_as_exactly_what_was_intended() {
        for posture in [Ruleset::Blocked, Ruleset::Protected] {
            let set = render(&contract(11), posture, &config());
            let state = engine_holding(&set);
            let installed = parse_installed(&state).expect("a ruleset is installed");
            assert_eq!(installed.posture, posture);
            assert_eq!(installed.generation, ContractGeneration(11));
            assert!(installed.both_families_covered());
            assert_eq!(compare(&state, &set), Verdict::Matches);
        }
    }

    #[test]
    fn an_empty_engine_is_absent_and_not_a_posture() {
        assert_eq!(parse_installed(&EngineState::default()), None);
        let set = render(&contract(1), Ruleset::Protected, &config());
        assert_eq!(compare(&EngineState::default(), &set), Verdict::Absent);
    }

    #[test]
    fn a_sublayer_with_no_marker_is_absent_rather_than_blocked() {
        // "We found our sublayer" is not "we found our ruleset". Reporting a
        // posture from a sublayer alone would be the belief K12 forbids.
        let state = EngineState {
            sublayer_present: true,
            provider_data: Some(vec![0; 8]),
            filters: Vec::new(),
        };
        assert_eq!(parse_installed(&state), None);
    }

    #[test]
    fn both_markers_at_once_is_not_a_posture_and_is_never_guessed() {
        // A half-finished transaction or a tamper. Answering either way would
        // be a guess, and `None` routes the caller to re-assert BLOCKED, which
        // is ADR-0022 LC-4 step 4 and the safe direction.
        let mut set = render(&contract(3), Ruleset::Blocked, &config());
        set.filters.push(crate::wfp::FilterSpec {
            key: FILTER_POSTURE_PROTECTED,
            name: "twinvpn-posture",
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            weight: 0,
            conditions: Vec::new(),
            class: TrafficClass::Marker,
            flags: crate::wfp::FilterFlags::default(),
        });
        assert_eq!(parse_installed(&engine_holding(&set)), None);
    }

    #[test]
    fn r6_a_posture_over_nothing_is_visible_rather_than_satisfying() {
        // The marker is present and every deny has been removed. Without
        // `scope_denies` this reads back as a healthy `Blocked`.
        let set = render(&contract(4), Ruleset::Blocked, &config());
        let mut state = engine_holding(&set);
        state
            .filters
            .retain(|f| class_of(f.key) != Some(TrafficClass::ProtectedScopeDeny));
        let installed = parse_installed(&state).expect("the marker is still there");
        assert_eq!(installed.posture, Ruleset::Blocked);
        assert!(
            !installed.both_families_covered(),
            "BLOCKED over nothing must be visible"
        );
        assert_eq!(
            compare(&state, &set),
            Verdict::FamilyUncovered {
                v4: false,
                v6: false
            }
        );
    }

    #[test]
    fn losing_only_the_v6_deny_is_its_own_verdict() {
        // ADR-0010 R6: IPv6 bypassing tunnel policy is a leak, and its
        // remediation is a different sentence from "some filters are missing".
        let set = render(&contract(4), Ruleset::Protected, &config());
        let mut state = engine_holding(&set);
        state.filters.retain(|f| {
            !(class_of(f.key) == Some(TrafficClass::ProtectedScopeDeny)
                && f.layer == Layer::AleAuthConnectV6)
        });
        assert_eq!(
            compare(&state, &set),
            Verdict::FamilyUncovered {
                v4: true,
                v6: false
            }
        );
    }

    #[test]
    fn a_third_partys_filters_are_never_counted_as_ours() {
        // K11 requires coexistence. An endpoint-protection product's block at
        // our layer must not make us believe our ruleset is installed, and its
        // presence must not make the count disagree.
        let set = render(&contract(5), Ruleset::Blocked, &config());
        let mut state = engine_holding(&set);
        state.filters.push(InstalledFilter {
            key: Guid([0xAA; 16]),
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            provider_owned: false,
        });
        assert_eq!(compare(&state, &set), Verdict::Matches);
        // And a filter carrying OUR key but somebody else's provider is still
        // not ours: the owner tag is the provider, not the key.
        state.filters.push(InstalledFilter {
            key: FILTER_POSTURE_PROTECTED,
            layer: Layer::AleAuthConnectV4,
            action: Action::Block,
            provider_owned: false,
        });
        assert_eq!(
            parse_installed(&state).expect("still blocked").posture,
            Ruleset::Blocked
        );
    }

    #[test]
    fn a_posture_that_disagrees_with_the_intent_is_named_as_that() {
        let intended = render(&contract(6), Ruleset::Protected, &config());
        let actual = render(&contract(6), Ruleset::Blocked, &config());
        assert_eq!(
            compare(&engine_holding(&actual), &intended),
            Verdict::PostureDiffers {
                installed: Ruleset::Blocked,
                intended: Ruleset::Protected
            }
        );
    }

    #[test]
    fn a_stale_generation_is_named_rather_than_accepted() {
        let intended = render(&contract(9), Ruleset::Protected, &config());
        let mut state = engine_holding(&intended);
        state.provider_data = Some(8_u64.to_be_bytes().to_vec());
        assert_eq!(
            compare(&state, &intended),
            Verdict::GenerationDiffers {
                installed: ContractGeneration(8),
                intended: ContractGeneration(9)
            }
        );
    }

    #[test]
    fn a_missing_exemption_is_a_mismatch_even_though_the_posture_still_holds() {
        // `POLICY.KILLSWITCH.RULESET_TAMPERED`'s condition: the owner-tagged set
        // was modified externally. The posture is intact and the host is still
        // fail-closed, which is why this is a mismatch and not a leak — but it
        // must still be visible.
        let set = render(&contract(2), Ruleset::Protected, &config());
        let mut state = engine_holding(&set);
        state
            .filters
            .retain(|f| class_of(f.key) != Some(TrafficClass::BootstrapExemption));
        assert!(matches!(
            compare(&state, &set),
            Verdict::FiltersMissing { .. }
        ));
    }

    #[test]
    fn a_missing_provider_blob_reads_as_generation_zero_and_never_as_the_intent() {
        // Generation 0 is a real value the core can compare against; inheriting
        // the intended generation would make a wiped provider look converged.
        let set = render(&contract(12), Ruleset::Blocked, &config());
        let mut state = engine_holding(&set);
        state.provider_data = None;
        let installed = parse_installed(&state).expect("marker present");
        assert_eq!(installed.generation, ContractGeneration(0));
        state.provider_data = Some(vec![0xFF; 3]);
        assert_eq!(
            parse_installed(&state).expect("marker present").generation,
            ContractGeneration(0),
            "a short blob is not a generation"
        );
    }

    #[test]
    fn every_class_round_trips_through_a_key() {
        for class in ALL_CLASSES {
            if class == TrafficClass::Marker {
                // The markers are fixed constants, not derived keys.
                assert_eq!(class_of(FILTER_POSTURE_BLOCKED), Some(TrafficClass::Marker));
                assert_eq!(
                    class_of(FILTER_POSTURE_PROTECTED),
                    Some(TrafficClass::Marker)
                );
                continue;
            }
            for layer in Layer::BOTH {
                for ordinal in [0u16, 1, 7, u16::MAX] {
                    let key = filter_key(class, layer, ordinal);
                    assert_eq!(class_of(key), Some(class), "{class:?} {layer:?} {ordinal}");
                }
            }
        }
    }

    #[test]
    fn a_key_this_crate_did_not_derive_decodes_to_nothing() {
        assert_eq!(class_of(Guid([0; 16])), None);
        assert_eq!(class_of(Guid([0xFF; 16])), None);
        assert_eq!(class_of(crate::wfp::PROVIDER_KEY), None);
        assert_eq!(class_of(crate::wfp::SUBLAYER_KEY), None);
        // A key with our prefix but a class byte nothing uses.
        let mut bytes = *filter_key(TrafficClass::Loopback, Layer::AleAuthConnectV4, 0).as_bytes();
        bytes[9] = 200;
        assert_eq!(class_of(Guid(bytes)), None);
    }
}
