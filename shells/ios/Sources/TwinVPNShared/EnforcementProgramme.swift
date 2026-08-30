//  EnforcementProgramme.swift — the one decoded programme BOTH processes hold.
//
//  Authority: ADR-0012 §11.6's iOS row and TN-5; ADR-0022 §11.3's iOS on-demand
//  row; ADR-0019 §11.10 (a); ADR-0018 CB-2.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHY THIS FILE IS IN `TwinVPNShared` AND NOT IN EITHER TARGET'S OWN DIRECTORY
//  ===========================================================================
//
//  The app and the extension each hold one half of this type's job, and neither
//  half is optional:
//
//    * the APP installs the profile — `NETunnelProviderManager.saveToPreferences`
//      is the call that presents the system consent sheet, and an app extension
//      cannot present it (ADR-0019 §11.10 (a)). So `VPNPermission.install` reads
//      `includeAllNetworks`, `excludeLocalNetworks` and `makeOnDemandRules()`
//      out of a decoded programme;
//    * the EXTENSION decodes the bytes Rust rendered and writes them into
//      `providerConfiguration` under `configurationKey`, then reads the SAME
//      bytes back for W-24's `installed_enforcement` query.
//
//  It lived in `Sources/TwinVPNProvider/Programmes.swift`, which the app target
//  does not compile — `project.yml`'s `TwinVPN` target lists `Sources/TwinVPNApp`
//  and `Sources/TwinVPNBridge` and nothing else — so the app referenced a type
//  that compiled for a different target. A file on disk outside a target's
//  `sources` compiles for nothing.
//
//  A SECOND COPY IN THE APP WOULD BE THE WRONG FIX. `configurationKey` and the
//  `CodingKeys` below are the exact spelling the extension writes and reads back;
//  two declarations of them is two things that can drift, and the drift would
//  show up as an enforcement posture the app installed and the extension cannot
//  find. One declaration, compiled into both targets, is the property that makes
//  W-24's read-back a query rather than a belief.
//
//  `Sources/TwinVPNBridge` is already listed by both targets for the same
//  reason; this directory is that arrangement applied to a Swift type instead of
//  a module map.

import Foundation
import NetworkExtension

/// One rendered enforcement posture.
///
/// Mirrors `twinvpn_platform_ios::enforce::EnforcementProgramme`. Every field is
/// a `Decodable` mirror of a Rust field and every method is a field-by-field copy
/// into an Apple object: no arithmetic, no defaulting, and no branch on a TwinVPN
/// fact. If a field is absent the decode FAILS rather than substituting a value.
struct EnforcementProgramme: Decodable {
    /// The `providerConfiguration` key the programme travels under, verbatim.
    ///
    /// Verbatim so that `installed_enforcement` reads back the **same bytes**
    /// Rust rendered: re-serialising would let the read-back differ from the
    /// write, and W-24's whole point is that the assertion is a query rather
    /// than a belief.
    static let configurationKey = "net.twinvpn.enforcement.v0"

    struct OnDemandRule: Decodable {
        let kind: String
        let interfaceType: String
        let ssidMatch: [String]

        enum CodingKeys: String, CodingKey {
            case kind
            case interfaceType = "interface_type"
            case ssidMatch = "ssid_match"
        }
    }

    let generation: UInt64
    let ruleset: String
    let includeAllNetworks: Bool
    let excludeLocalNetworks: Bool
    let disconnectOnDemandEnabled: Bool
    let onDemandRules: [OnDemandRule]

    enum CodingKeys: String, CodingKey {
        case generation, ruleset
        case includeAllNetworks = "include_all_networks"
        case excludeLocalNetworks = "exclude_local_networks"
        case disconnectOnDemandEnabled = "disconnect_on_demand_enabled"
        case onDemandRules = "on_demand_rules"
    }

    static func decode(_ bytes: Data) -> EnforcementProgramme? {
        try? JSONDecoder().decode(EnforcementProgramme.self, from: bytes)
    }

    /// Builds the on-demand rules.
    ///
    /// **Connect rules only.** ADR-0022 TN-5: `SSIDMatch` "MAY be used only in
    /// `NEOnDemandRuleConnect` rules (biasing toward connecting — safe under
    /// spoofed SSID) and MUST NOT be used in `Disconnect`/`Ignore` rules",
    /// because the system evaluates these and we cannot inject a cryptographic
    /// predicate into that evaluation.
    ///
    /// Rust's type can express no other kind, so a `kind` other than `"connect"`
    /// here means the bytes did not come from this build — and it is **skipped**
    /// rather than translated into whatever it names.
    func makeOnDemandRules() -> [NEOnDemandRule] {
        onDemandRules.compactMap { rule in
            guard rule.kind == "connect" else { return nil }
            let connect = NEOnDemandRuleConnect()
            switch rule.interfaceType {
            case "wifi": connect.interfaceTypeMatch = .wiFi
            case "cellular": connect.interfaceTypeMatch = .cellular
            default: connect.interfaceTypeMatch = .any
            }
            if !rule.ssidMatch.isEmpty {
                connect.ssidMatch = rule.ssidMatch
            }
            return connect
        }
    }
}
