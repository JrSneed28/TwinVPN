//  EnforcementFixtures.swift — the programmes both acceptance suites drive.
//
//  Authority: `core/crates/twinvpn-platform-ios/src/enforce.rs`'s
//  `EnforcementProgramme::to_json`, which is what these mirror byte for byte.
//
//  ===========================================================================
//  WHY THESE ARE LITERALS AND NOT BUILT WITH A HELPER
//  ===========================================================================
//
//  The bytes are the contract. `EnforcementProgramme` decodes JSON that Rust
//  rendered, and the failure this whole lane exists to catch is a Swift side
//  that reads a field the Rust side does not write, or spells one differently.
//  A Swift helper that constructed the JSON would be written from the same
//  belief the decoder holds, so the two would agree while both were wrong. A
//  literal transcribed from `to_json` disagrees loudly.
//
//  Field names and value spellings come from `enforce.rs`: `generation`,
//  `ruleset` (`"BLOCKED"` or `"PROTECTED"`), `include_all_networks`,
//  `exclude_local_networks`, `disconnect_on_demand_enabled`, and
//  `on_demand_rules` with `kind` / `interface_type` (`"any"`, `"wifi"`,
//  `"cellular"`) / `ssid_match`.
//
//  STATUS: written, not compiled on the build host.

import Foundation
import NetworkExtension

enum EnforcementFixtures {

    /// A full-protection posture: what `RULESET_PROTECTED` renders.
    ///
    /// `include_all_networks` is true because `enforce.rs` ties it to
    /// `full_protection_required`; `exclude_local_networks` is false because
    /// KS-4's inversion makes that field carry `local_network_access`.
    static let fullProtection = """
    {"generation":7,"ruleset":"PROTECTED","include_all_networks":true,\
    "exclude_local_networks":false,"disconnect_on_demand_enabled":false,\
    "on_demand_rules":[\
    {"kind":"connect","interface_type":"any","ssid_match":[]},\
    {"kind":"connect","interface_type":"wifi","ssid_match":["twin-lab","twin-lab-5g"]},\
    {"kind":"connect","interface_type":"cellular","ssid_match":[]}]}
    """

    /// The same posture with a rule Rust's type cannot express.
    ///
    /// ADR-0022 TN-5 permits `SSIDMatch` only in `NEOnDemandRuleConnect` rules,
    /// because the system evaluates on-demand rules and no cryptographic
    /// predicate can be injected into that evaluation. A `kind` other than
    /// `"connect"` means the bytes did not come from this build, and
    /// `makeOnDemandRules()` skips it rather than translating it into whatever
    /// it names.
    static let carryingANonConnectRule = """
    {"generation":8,"ruleset":"PROTECTED","include_all_networks":true,\
    "exclude_local_networks":false,"disconnect_on_demand_enabled":false,\
    "on_demand_rules":[\
    {"kind":"connect","interface_type":"any","ssid_match":[]},\
    {"kind":"disconnect","interface_type":"wifi","ssid_match":["hostile"]},\
    {"kind":"ignore","interface_type":"cellular","ssid_match":[]}]}
    """

    /// A stale App Group status record still claiming the tunnel is protected.
    ///
    /// The dangerous input, on purpose. It is what the provider legitimately
    /// wrote while it was alive, and it is still on disk after the user removes
    /// the configuration that authorised it.
    static let staleProtectedStatusRecord = """
    {"protection":{"state":"protected","as_of_ms":1712000000000,\
    "family_v4_protected":true,"family_v6_protected":true},"peers":[]}
    """

    /// The same record claiming `blocked`.
    ///
    /// `blocked` is as wrong as `protected` after removal and for the same
    /// reason: both assert that TwinVPN is still deciding what leaves the
    /// device, when the authority to decide is exactly what the user removed.
    static let staleBlockedStatusRecord = """
    {"protection":{"state":"blocked","as_of_ms":1712000000000,\
    "family_v4_protected":false,"family_v6_protected":false},"peers":[]}
    """

    static func bytes(_ json: String) -> Data { Data(json.utf8) }
}

/// What the loader reports, held by reference so a test can change it between
/// two `reload()` calls.
///
/// A reference rather than a captured `var`: the loader is `@escaping`, and a
/// mutable local captured by an escaping async closure is the shape strict
/// concurrency checking rejects. This says the same thing without depending on
/// which language mode the project is built in.
final class ObservedConfigurations {
    var managers: [NETunnelProviderManager]

    init(_ managers: [NETunnelProviderManager]) {
        self.managers = managers
    }
}
