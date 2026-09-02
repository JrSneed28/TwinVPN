//  EnforcementInstaller.swift — the extension's half of the enforcement write,
//  as a function of its arguments.
//
//  Authority: ADR-0012 §11.6's iOS row, KS-17, TN-5; ADR-0022 §11.3's iOS
//  on-demand row and §11.10; W-24's read-back; ownership.md §10.4.
//
//  ===========================================================================
//  WHY THIS IS NOT STILL INSIDE `BridgeHost`
//  ===========================================================================
//
//  `BridgeHost.applyEnforcement` and `installedEnforcement` each do two things:
//  they cross into the Network Extension daemons (`loadAllFromPreferences`,
//  `saveToPreferences`) and they copy fields between a decoded programme and an
//  Apple object. The first half needs a device; the second half needs nothing
//  at all — the objects are plain Objective-C objects whose properties can be
//  set and read with no daemon involved.
//
//  Splitting them is what lets the second half be asserted. That matters here
//  more than in most places, because the APP writes the same posture
//  independently in `VPNPermission`, and a drift between the two reads as an
//  enforcement posture the app installed and the extension cannot find. The
//  two implementations stay separate — they genuinely do different work, and
//  merging them would make "the two halves agree" a tautology rather than a
//  test — but both are now reachable from one, so the agreement is checked
//  rather than assumed.
//
//  CB-2 still holds: there is no branch here whose condition is a TwinVPN
//  domain fact. Every value copied arrived in a programme Rust rendered.
//
//  STATUS: written, not compiled on the build host.

import Foundation
import NetworkExtension

/// The field-by-field copy the extension performs on the installed profile.
enum EnforcementInstaller {

    /// Writes one decoded programme into one manager.
    ///
    /// `verbatim` is the programme's ORIGINAL bytes, and they are stored rather
    /// than re-serialised so `installed_enforcement` reads back exactly what
    /// Rust rendered. Re-serialising would let the read-back differ from the
    /// write for a reason nobody could see, and W-24's whole point is that the
    /// assertion is a query rather than a belief.
    ///
    /// Saving is the CALLER's, because a save crosses into the NE daemons and
    /// this does not. KS-17's atomicity is that save: one call replaces the
    /// whole configuration, so there is no moment at which the profile carries
    /// neither ruleset.
    static func apply(_ decoded: EnforcementProgramme,
                      verbatim bytes: Data,
                      to manager: NETunnelProviderManager) {
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            proto.includeAllNetworks = decoded.includeAllNetworks
            proto.excludeLocalNetworks = decoded.excludeLocalNetworks
            var config = proto.providerConfiguration ?? [:]
            config[EnforcementProgramme.configurationKey] = bytes
            proto.providerConfiguration = config
        }
        manager.onDemandRules = decoded.makeOnDemandRules()
        manager.isOnDemandEnabled = true
    }

    /// The programme bytes currently installed, or nil when none are.
    ///
    /// Nil means "no configuration installed", which Rust reads as `Ok(None)`.
    /// A configuration that exists but cannot be parsed is Rust's to name, and
    /// it names it as a suspected third-party profile rather than as an
    /// absence — so nothing here decodes, validates or substitutes.
    static func installedProgrammeBytes(in manager: NETunnelProviderManager) -> Data? {
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            return nil
        }
        return proto.providerConfiguration?[EnforcementProgramme.configurationKey] as? Data
    }
}
