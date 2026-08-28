//! Enforcement on a platform with **no host firewall**: `includeAllNetworks`,
//! `excludeLocalNetworks`, on-demand rules, and the two rulesets that are never
//! zero.
//!
//! **Authority:** ADR-0012 §11.6's iOS mechanism and limitation rows, KS-4,
//! KS-9(1)'s iOS clause, KS-17, KS-19, §11.9's P09, §14 revisit condition 5;
//! ADR-0022 §11.3's iOS on-demand row and §11.10; ADR-0018 CB-2, CB-6;
//! `docs/networking.md` §5.2's iOS row.
//!
//! # What "enforcement" even means here
//!
//! ADR-0012 §11.6's iOS row names the enforcement object as
//! "`NEPacketTunnelProvider` with `includeAllNetworks = true` (+
//! `excludeLocalNetworks` for class 4), on-demand rules with
//! `disconnectOnDemandEnabled = false`" — and the limitation row says plainly:
//! "**No host firewall exists.** Enforcement is the system's". There is no
//! `nft`, no WFP, no `pf` anchor. So the two rulesets KS-17 requires are not two
//! filter programmes; they are two **postures**, and the mechanism splits in
//! two halves that fail differently:
//!
//! | Half | Held by | Survives the provider dying? |
//! |---|---|---|
//! | Capture — `includeAllNetworks`, on-demand rules | **the OS**, in the VPN profile | yes; the system re-arms on the next network attach |
//! | Disposition — whether a captured packet is forwarded or dropped | **the provider process** | **no** |
//!
//! That split is why [`custody`] reports `survives_core_exit: false`, and the
//! reasoning is written out at that function rather than left to be inferred.
//!
//! # KS-9(1) on this platform is *by construction*
//!
//! On Linux the bootstrap exception is a `cgroup` + `fwmark` predicate; on
//! Windows it is an ALE app-id condition. KS-9(1)'s iOS clause is different in
//! kind: "**iOS/Android — implicit, the provider's own sockets are excluded from
//! its own tunnel by construction.**" There is therefore nothing to install, and
//! nothing here installs it. That same clause is what makes
//! `docs/networking.md` §5.4's corrected row true: the **app** process has no way
//! to match the exemption, so it cannot be on a fetch path that the tunnel's own
//! recovery depends on (ADR-0016 PS-24 condition 3).
//!
//! # Everything in this module is target-free
//!
//! It renders plain data from plain data and its tests run on the Linux build
//! host. Swift receives [`EnforcementProgramme::to_json`] and sets the six
//! fields it names on an `NETunnelProviderProtocol` and an
//! `NETunnelProviderManager`; it decides none of them.

use serde_json::{json, Map, Value};
use twinvpn_platform::{ContractGeneration, EnforcementCustody, Ruleset};

/// ADR-0012 §14 revisit condition 5's threshold, in milliseconds.
///
/// > "If P09 measures an iOS attach-to-arm window exceeding 500 ms at p95,
/// > `includeAllNetworks` is not delivering what the limitation table assumes and
/// > iOS must either be reclassified as best-effort in the supported matrix or
/// > restricted to supervised Always-On deployments."
///
/// A constant rather than a comment, so [`AttachToArm::exceeds_revisit_threshold`]
/// is a check a test can run rather than a sentence a reviewer has to remember.
pub const ATTACH_TO_ARM_REVISIT_P95_MS: u64 = 500;

/// Which link types an on-demand rule matches.
///
/// `NEOnDemandRuleInterfaceType`. Cellular and Wi-Fi are separate values because
/// `docs/reliability.md` emits `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR`
/// as distinct codes, and a rule set that could not tell them apart could not
/// re-arm differently for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceTypeMatch {
    /// Any interface type.
    Any,
    /// Wi-Fi only.
    WiFi,
    /// Cellular only.
    Cellular,
}

impl InterfaceTypeMatch {
    /// The stable, non-localised tag Swift maps to the enum case.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            InterfaceTypeMatch::Any => "any",
            InterfaceTypeMatch::WiFi => "wifi",
            InterfaceTypeMatch::Cellular => "cellular",
        }
    }
}

/// One on-demand rule.
///
/// # Why there is no `Disconnect` and no `Ignore` variant
///
/// ADR-0022 **TN-5**: on-demand rules are evaluated by the *system*, and we
/// cannot inject a cryptographic predicate into that evaluation — so `SSIDMatch`
/// "MAY be used **only** in `NEOnDemandRuleConnect` rules (biasing toward
/// connecting — safe under spoofed SSID) and MUST NOT be used in
/// `Disconnect`/`Ignore` rules."
///
/// The rule is made structural rather than documented: this type can only
/// express a *connect* rule, so a spoofed SSID can only ever cause the tunnel to
/// come **up**. There is no value of this type that disconnects on a network the
/// device merely believes it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnDemandConnectRule {
    /// Which link types this rule matches.
    pub interface_type: InterfaceTypeMatch,
    /// SSIDs this rule matches, if any. Connect-only, per TN-5.
    pub ssid_match: Vec<String>,
}

/// The rendered enforcement programme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementProgramme {
    /// The generation this posture belongs to.
    pub generation: ContractGeneration,
    /// Which of the two fail-closed rulesets is in force.
    pub ruleset: Ruleset,
    /// `includeAllNetworks`. ADR-0012 E1 and the iOS mechanism row.
    pub include_all_networks: bool,
    /// `excludeLocalNetworks`.
    ///
    /// KS-4's inverse: `local_network_access = ALLOW` means the LAN is *not*
    /// captured, which iOS spells `excludeLocalNetworks = true`. The two words
    /// point opposite ways and conflating them is how a full-tunnel posture
    /// silently starts letting the LAN out — so the mapping happens once, in
    /// [`EnforcementPosture::programme`], and never in Swift.
    pub exclude_local_networks: bool,
    /// On-demand rules. Connect-only by construction (TN-5).
    pub on_demand_rules: Vec<OnDemandConnectRule>,
    /// `disconnectOnDemandEnabled`.
    ///
    /// **Always `false`**, and there is no constructor that sets it otherwise —
    /// ADR-0012's iOS mechanism row and ADR-0022 §11.10 both fix it, because a
    /// system that may disconnect on demand is a system that may leave the
    /// device unprotected on a network it decided was fine.
    pub disconnect_on_demand_enabled: bool,
}

/// What the core wants enforced, before it is rendered.
///
/// Every field is supplied by the core. This struct exists so the *mapping* —
/// KS-4's inversion, KS-17's two-and-only-two rulesets, TN-5's connect-only
/// rules — is one function with tests rather than a Swift file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPosture {
    /// Whether the LAN is reachable outside the tunnel (`local_network_access`).
    pub local_network_access: bool,
    /// Whether policy demands full protection, which is what
    /// `docs/networking.md` §5.4 conditions `includeAllNetworks` on.
    pub full_protection_required: bool,
    /// Which link types the tunnel should be restarted on.
    pub restart_on: Vec<InterfaceTypeMatch>,
    /// SSIDs biasing toward connecting, per TN-5. Empty in the ordinary case.
    pub connect_ssids: Vec<String>,
}

impl Default for EnforcementPosture {
    /// The fail-closed default: full protection, LAN captured, restart on any
    /// interface type.
    ///
    /// A `Default` that armed nothing would make "we never configured this" and
    /// "policy says protect nothing" the same value.
    fn default() -> Self {
        Self {
            local_network_access: false,
            full_protection_required: true,
            restart_on: vec![InterfaceTypeMatch::Any],
            connect_ssids: Vec::new(),
        }
    }
}

impl EnforcementPosture {
    /// Renders the programme for one generation and one ruleset.
    #[must_use]
    pub fn programme(
        &self,
        generation: ContractGeneration,
        ruleset: Ruleset,
    ) -> EnforcementProgramme {
        let mut on_demand_rules: Vec<OnDemandConnectRule> = self
            .restart_on
            .iter()
            .map(|interface_type| OnDemandConnectRule {
                interface_type: *interface_type,
                ssid_match: self.connect_ssids.clone(),
            })
            .collect();
        // Deterministic order, so the read-back comparison in
        // `matches_installed` is an equality and not a set intersection the
        // reconciler has to re-derive.
        on_demand_rules.sort_by(|a, b| {
            a.interface_type
                .cmp(&b.interface_type)
                .then_with(|| a.ssid_match.cmp(&b.ssid_match))
        });
        on_demand_rules.dedup();

        EnforcementProgramme {
            generation,
            ruleset,
            include_all_networks: self.full_protection_required,
            // KS-4's inversion, in one place.
            exclude_local_networks: self.local_network_access,
            on_demand_rules,
            disconnect_on_demand_enabled: false,
        }
    }
}

impl EnforcementProgramme {
    /// The canonical JSON Swift installs.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut root = Map::new();
        root.insert("generation".to_owned(), json!(self.generation.0));
        root.insert(
            "ruleset".to_owned(),
            Value::String(ruleset_tag(self.ruleset).to_owned()),
        );
        root.insert(
            "include_all_networks".to_owned(),
            Value::Bool(self.include_all_networks),
        );
        root.insert(
            "exclude_local_networks".to_owned(),
            Value::Bool(self.exclude_local_networks),
        );
        root.insert(
            "disconnect_on_demand_enabled".to_owned(),
            Value::Bool(self.disconnect_on_demand_enabled),
        );
        root.insert(
            "on_demand_rules".to_owned(),
            Value::Array(
                self.on_demand_rules
                    .iter()
                    .map(|rule| {
                        json!({
                            // The kind is emitted explicitly even though only one
                            // exists, so a Swift side reading this file learns
                            // that "connect" is the only value it will ever see
                            // rather than inferring it from an absence.
                            "kind": "connect",
                            "interface_type": rule.interface_type.as_str(),
                            "ssid_match": rule.ssid_match,
                        })
                    })
                    .collect(),
            ),
        );
        Value::Object(root).to_string()
    }

    /// Parses a read-back programme.
    ///
    /// Used by [`crate::netcfg`] to answer `installed_ruleset` from the OS's own
    /// configuration rather than from a cached belief — W-24's requirement,
    /// applied to the only enforcement layer this platform has.
    ///
    /// Returns `None` when the bytes are not a programme this build wrote. A
    /// malformed read-back must **not** be reported as "no ruleset installed":
    /// `Ok(None)` there would read as the opposite of the truth, which is the
    /// dangerous direction O-18 forbids.
    #[must_use]
    pub fn parse(json: &str) -> Option<Self> {
        let value: Value = serde_json::from_str(json).ok()?;
        let object = value.as_object()?;
        let ruleset = match object.get("ruleset")?.as_str()? {
            "BLOCKED" => Ruleset::Blocked,
            "PROTECTED" => Ruleset::Protected,
            _ => return None,
        };
        let mut on_demand_rules = Vec::new();
        for entry in object.get("on_demand_rules")?.as_array()? {
            let rule = entry.as_object()?;
            if rule.get("kind")?.as_str()? != "connect" {
                // TN-5 forbids a disconnect or ignore rule. Reading one back
                // means something other than this build wrote the profile, and
                // the reconciler must see that as a mismatch, not as noise.
                return None;
            }
            let interface_type = match rule.get("interface_type")?.as_str()? {
                "any" => InterfaceTypeMatch::Any,
                "wifi" => InterfaceTypeMatch::WiFi,
                "cellular" => InterfaceTypeMatch::Cellular,
                _ => return None,
            };
            let ssid_match = rule
                .get("ssid_match")?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()?;
            on_demand_rules.push(OnDemandConnectRule {
                interface_type,
                ssid_match,
            });
        }
        Some(Self {
            generation: ContractGeneration(object.get("generation")?.as_u64()?),
            ruleset,
            include_all_networks: object.get("include_all_networks")?.as_bool()?,
            exclude_local_networks: object.get("exclude_local_networks")?.as_bool()?,
            on_demand_rules,
            disconnect_on_demand_enabled: object.get("disconnect_on_demand_enabled")?.as_bool()?,
        })
    }
}

/// The stable, non-localised tag for a ruleset.
#[must_use]
pub const fn ruleset_tag(ruleset: Ruleset) -> &'static str {
    match ruleset {
        Ruleset::Blocked => "BLOCKED",
        Ruleset::Protected => "PROTECTED",
    }
}

/// Who holds the rules on iOS — declared, with the reasoning at the value.
///
/// # `survives_core_exit: false`, and why that is the honest answer
///
/// ADR-0012 §11.6's durability table gives iOS **`◐`** — not `✔` — for both
/// "agent crash" and "`SIGKILL`", annotated "system restarts the provider
/// on-demand". [`EnforcementCustody::survives_core_exit`] is a `bool`, and a
/// partial guarantee has no `bool`:
///
/// - `true` asserts CB-6's guarantee — "a core crash therefore cannot drop
///   protection" — which iOS does not give. The interval between the provider
///   dying and on-demand re-arming is real; ADR-0012's limitation row names it
///   as a residual and P09 **measures** it rather than assuming it is zero.
/// - `false` says the rules die with the process, which understates what the OS
///   does re-arm.
///
/// `false` is chosen because ADR-0015 O-18 fixes the direction: an assertion that
/// cannot be made must fail toward `UNKNOWN`, never toward `PROTECTED`. The core
/// then records "this device's enforcement does not survive a core exit" in the
/// diagnostic bundle, which is a true statement about the *disposition* half of
/// the mechanism (see this module's header table) and pessimistic about the
/// capture half. **That the seam cannot express `◐` at all is reported as a
/// finding**, not smoothed over here.
///
/// # `swap_is_atomic: true`
///
/// KS-17 requires the transition between the two rulesets to be a single atomic
/// swap with no moment in which rules are absent. On this platform the swap is a
/// single store of the posture the packet pump reads on its next batch: there is
/// no window in which the pump has no posture, because the field is never
/// vacated. The OS-held capture half is not touched by a swap at all.
#[must_use]
pub const fn custody() -> EnforcementCustody {
    EnforcementCustody {
        survives_core_exit: false,
        swap_is_atomic: true,
    }
}

/// One measurement of ADR-0012 §11.9's P09 window.
///
/// > "the iOS attach-to-arm window is measured rather than assumed"
///
/// KS-19 requires the boot ruleset to be installed "by an artifact the **OS
/// itself applies**", and records that "where a platform cannot do this (iOS),
/// `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` is emitted at first run, the
/// residual window is named, and P09 measures it."
///
/// The *taking* of the two readings is device-bound and lives in the XCTest
/// suite under `shells/ios`. The **model, the arithmetic and the threshold
/// check** are here, target-free, so the part that decides whether a measurement
/// trips §14's revisit condition is executed on this host rather than written and
/// hoped for.
///
/// Both readings are on ADR-0022 LC-8's suspend-**inclusive** clock
/// ([`crate::clock::ContinuousElapsedClock`]): a network attach can straddle a
/// suspend, and a suspend-exclusive reading would under-measure exactly the
/// window this exists to size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachToArm {
    /// When the OS reported the network attach, in microseconds.
    pub attached_us: u64,
    /// When the provider had `includeAllNetworks` in force, in microseconds.
    pub armed_us: u64,
}

impl AttachToArm {
    /// The window, in milliseconds.
    ///
    /// A reading that runs backwards is reported as `None` rather than saturated
    /// to zero: zero is precisely the value ADR-0012 says must not be *assumed*,
    /// so a broken clock must not be able to produce it.
    #[must_use]
    pub const fn window_ms(self) -> Option<u64> {
        if self.armed_us < self.attached_us {
            return None;
        }
        Some((self.armed_us - self.attached_us) / 1_000)
    }

    /// Whether this reading trips ADR-0012 §14's revisit condition 5.
    #[must_use]
    pub const fn exceeds_revisit_threshold(self) -> bool {
        match self.window_ms() {
            Some(ms) => ms > ATTACH_TO_ARM_REVISIT_P95_MS,
            // An unusable reading is not evidence that the threshold was met.
            None => false,
        }
    }
}

/// The p95 of a set of measurements, in milliseconds, by nearest-rank.
///
/// `None` when no reading is usable. Nearest-rank rather than interpolation
/// because §14's condition is stated on p95 of *measurements*, and an
/// interpolated value is not one of them.
#[must_use]
pub fn p95_window_ms(samples: &[AttachToArm]) -> Option<u64> {
    let mut windows: Vec<u64> = samples.iter().filter_map(|s| s.window_ms()).collect();
    if windows.is_empty() {
        return None;
    }
    windows.sort_unstable();
    let rank = windows.len().saturating_mul(95).div_ceil(100).max(1);
    windows.get(rank - 1).copied()
}

/// What this platform structurally cannot enforce, declared at startup.
///
/// ADR-0012's iOS limitation row, expressed as data so a shell reports it rather
/// than a user discovering it. None of these is a decision: each is a fact about
/// the platform that the core turns into a posture and a diagnostic.
// Four booleans, and each is a distinct fact a shell reports on its own line.
// `boot_enforcement_available` and `host_firewall_available` in particular must
// stay separate: "there is no boot ruleset" and "there is no filter to carry a
// bootstrap exemption" have different consequences — the first is KS-19's
// residual window, the second is what forces networking.md §5.4's corrected
// fetch split. A bitflags type would make exactly that distinction invisible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcementLimits {
    /// Whether a boot-time, pre-network ruleset can be installed at all.
    ///
    /// **Always `false`.** ADR-0012 §11.6's boot column for iOS is
    /// "None available", and KS-19 names the consequence.
    pub boot_enforcement_available: bool,
    /// Whether a host packet filter exists to carry a bootstrap exemption.
    ///
    /// **Always `false`.** This is what makes KS-9(1)'s iOS clause "implicit …
    /// by construction" and what forces `docs/networking.md` §5.4's corrected
    /// fetch split.
    pub host_firewall_available: bool,
    /// Whether the per-app enforcement tier is available.
    ///
    /// **Always `false`** — ADR-0012 §11.1's scope table marks per-app
    /// unavailable on iOS.
    pub per_app_tier_available: bool,
    /// Whether some system services are documented as not tunnelled even under
    /// `includeAllNetworks`.
    ///
    /// **Always `true`**: the limitation row's first residual.
    pub os_exempted_system_traffic: bool,
}

impl EnforcementLimits {
    /// The iOS/iPadOS limits, as ADR-0012 §11.6 states them.
    #[must_use]
    pub const fn ios() -> Self {
        Self {
            boot_enforcement_available: false,
            host_firewall_available: false,
            per_app_tier_available: false,
            os_exempted_system_traffic: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(n: u64) -> ContractGeneration {
        ContractGeneration(n)
    }

    #[test]
    fn the_default_posture_is_fail_closed_and_not_a_blank() {
        let programme = EnforcementPosture::default().programme(generation(1), Ruleset::Blocked);
        assert!(programme.include_all_networks);
        assert!(!programme.exclude_local_networks);
        assert!(!programme.disconnect_on_demand_enabled);
        assert_eq!(programme.ruleset, Ruleset::Blocked);
    }

    #[test]
    fn disconnect_on_demand_is_false_in_every_reachable_value() {
        // ADR-0012's iOS mechanism row and ADR-0022 §11.10 both fix it. There is
        // no constructor that sets it otherwise; this asserts the closure.
        for local in [false, true] {
            for full in [false, true] {
                let posture = EnforcementPosture {
                    local_network_access: local,
                    full_protection_required: full,
                    restart_on: vec![InterfaceTypeMatch::Any],
                    connect_ssids: Vec::new(),
                };
                for ruleset in [Ruleset::Blocked, Ruleset::Protected] {
                    assert!(
                        !posture
                            .programme(generation(1), ruleset)
                            .disconnect_on_demand_enabled
                    );
                }
            }
        }
    }

    #[test]
    fn local_network_access_inverts_into_exclude_local_networks_exactly_once() {
        // KS-4: `local_network_access = ALLOW` means the LAN is NOT captured,
        // which iOS spells `excludeLocalNetworks = true`. The two words point
        // opposite ways; getting this backwards silently lets the LAN out of a
        // full tunnel.
        let allow = EnforcementPosture {
            local_network_access: true,
            ..EnforcementPosture::default()
        };
        assert!(
            allow
                .programme(generation(1), Ruleset::Protected)
                .exclude_local_networks
        );
        let deny = EnforcementPosture {
            local_network_access: false,
            ..EnforcementPosture::default()
        };
        assert!(
            !deny
                .programme(generation(1), Ruleset::Protected)
                .exclude_local_networks
        );
    }

    #[test]
    fn an_ssid_can_only_ever_cause_the_tunnel_to_come_up() {
        // TN-5, made structural: this type expresses no disconnect or ignore
        // rule, so a spoofed SSID cannot disconnect a protected device.
        let posture = EnforcementPosture {
            connect_ssids: vec!["CoffeeShop".to_owned()],
            restart_on: vec![InterfaceTypeMatch::WiFi],
            ..EnforcementPosture::default()
        };
        let json = posture
            .programme(generation(1), Ruleset::Protected)
            .to_json();
        assert!(json.contains("\"kind\":\"connect\""));
        assert!(!json.contains("disconnect\""), "{json}");
        assert!(json.contains("CoffeeShop"));
    }

    #[test]
    fn a_read_back_round_trips_so_the_reconciler_compares_equal_values() {
        let posture = EnforcementPosture {
            local_network_access: true,
            full_protection_required: true,
            restart_on: vec![InterfaceTypeMatch::WiFi, InterfaceTypeMatch::Cellular],
            connect_ssids: vec!["Home".to_owned()],
        };
        let programme = posture.programme(generation(7), Ruleset::Protected);
        let parsed = EnforcementProgramme::parse(&programme.to_json()).expect("parses");
        assert_eq!(parsed, programme);
    }

    #[test]
    fn the_rule_order_is_deterministic_so_two_renders_compare_equal() {
        let a = EnforcementPosture {
            restart_on: vec![InterfaceTypeMatch::Cellular, InterfaceTypeMatch::WiFi],
            ..EnforcementPosture::default()
        }
        .programme(generation(1), Ruleset::Protected);
        let b = EnforcementPosture {
            restart_on: vec![InterfaceTypeMatch::WiFi, InterfaceTypeMatch::Cellular],
            ..EnforcementPosture::default()
        }
        .programme(generation(1), Ruleset::Protected);
        assert_eq!(a, b);
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn a_duplicate_restart_rule_is_installed_once() {
        let programme = EnforcementPosture {
            restart_on: vec![InterfaceTypeMatch::Any, InterfaceTypeMatch::Any],
            ..EnforcementPosture::default()
        }
        .programme(generation(1), Ruleset::Protected);
        assert_eq!(programme.on_demand_rules.len(), 1);
    }

    #[test]
    fn a_malformed_read_back_is_not_reported_as_no_ruleset_installed() {
        // O-18's direction: `None` here means "we could not tell", and the
        // caller must render UNKNOWN. It must never be produced by garbage that
        // could equally mean "somebody else owns this profile".
        assert!(EnforcementProgramme::parse("not json").is_none());
        assert!(EnforcementProgramme::parse("{}").is_none());
        assert!(EnforcementProgramme::parse(r#"{"ruleset":"OFF"}"#).is_none());
    }

    #[test]
    fn a_disconnect_rule_read_back_is_a_mismatch_and_not_noise() {
        // TN-5 forbids one. Reading one back means the profile is not ours.
        let json = r#"{"generation":1,"ruleset":"PROTECTED","include_all_networks":true,
            "exclude_local_networks":false,"disconnect_on_demand_enabled":false,
            "on_demand_rules":[{"kind":"disconnect","interface_type":"any","ssid_match":[]}]}"#;
        assert!(EnforcementProgramme::parse(json).is_none());
    }

    #[test]
    fn there_are_exactly_two_rulesets_and_no_way_to_spell_a_third() {
        assert_eq!(ruleset_tag(Ruleset::Blocked), "BLOCKED");
        assert_eq!(ruleset_tag(Ruleset::Protected), "PROTECTED");
        // KS-17: "a moment with no ruleset is the leak window the whole
        // mechanism exists to close." The seam offers no third value and this
        // module adds none.
        assert!(EnforcementProgramme::parse(r#"{"ruleset":"NONE"}"#).is_none());
    }

    #[test]
    fn the_custody_declaration_is_pessimistic_in_o18s_direction() {
        let custody = custody();
        assert!(
            !custody.survives_core_exit,
            "ADR-0012 gives iOS ◐ for agent crash and SIGKILL, not ✔; a bool \
             cannot say ◐ and O-18 fixes which way it must round"
        );
        assert!(custody.swap_is_atomic);
    }

    #[test]
    fn the_platform_limits_are_declared_and_not_discovered_by_a_user() {
        let limits = EnforcementLimits::ios();
        assert!(
            !limits.boot_enforcement_available,
            "ADR-0012 §11.6 iOS boot column: none available"
        );
        assert!(
            !limits.host_firewall_available,
            "which is why KS-9(1) is implicit here"
        );
        assert!(!limits.per_app_tier_available, "ADR-0012 §11.1 scope table");
        assert!(limits.os_exempted_system_traffic);
    }

    #[test]
    fn the_attach_to_arm_window_is_measured_and_never_assumed_to_be_zero() {
        let sample = AttachToArm {
            attached_us: 1_000_000,
            armed_us: 1_120_000,
        };
        assert_eq!(sample.window_ms(), Some(120));
        assert!(!sample.exceeds_revisit_threshold());

        let slow = AttachToArm {
            attached_us: 1_000_000,
            armed_us: 1_501_000,
        };
        assert_eq!(slow.window_ms(), Some(501));
        assert!(
            slow.exceeds_revisit_threshold(),
            "ADR-0012 §14 condition 5: >500 ms at p95 reclassifies iOS"
        );

        // A backwards reading is unusable, not zero. Zero is exactly the value
        // ADR-0012 forbids assuming, so a broken clock must not manufacture it.
        let backwards = AttachToArm {
            attached_us: 2_000_000,
            armed_us: 1_000_000,
        };
        assert_eq!(backwards.window_ms(), None);
        assert!(!backwards.exceeds_revisit_threshold());
    }

    #[test]
    fn the_p95_is_a_measurement_and_not_an_interpolation() {
        let samples: Vec<AttachToArm> = (1..=100)
            .map(|i| AttachToArm {
                attached_us: 0,
                armed_us: i * 1_000,
            })
            .collect();
        assert_eq!(p95_window_ms(&samples), Some(95));
        assert_eq!(p95_window_ms(&[]), None);
        // A set of unusable readings yields no percentile rather than a zero
        // that would read as "the window is closed".
        assert_eq!(
            p95_window_ms(&[AttachToArm {
                attached_us: 10,
                armed_us: 0
            }]),
            None
        );
    }
}
