//  VPNPermission.swift — the profile lifecycle: install, consent, denial,
//  revocation, deletion.
//
//  Authority: ADR-0019 §11.10 (a)'s iOS row and LT-3's variant table; ADR-0012
//  §11.6's iOS durability row and §11.10; ADR-0022 §11.3's iOS on-demand row and
//  §11.10; ADR-0018 CB-4; ownership.md §10.1.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  DENIAL IS A STATE, NOT A DEAD END
//  ===========================================================================
//
//  ADR-0019 §11.10 (a)'s iOS row, verbatim on refusal: "No tunnel is possible;
//  **the rest of the app remains usable**", surfacing
//  `PLATFORM.VPN_PERMISSION_DENIED`. `ownership.md` §10.1 says the same:
//  "pairing, device list, settings and diagnostics stay usable without a tunnel".
//
//  So nothing in this file gates the app. It reports a condition, and the views
//  that need a tunnel disable themselves; the ones that do not, do not.
//
//  ===========================================================================
//  WHAT THIS FILE DOES NOT CONTAIN
//  ===========================================================================
//
//  A user-facing string. CB-4 splits resolution from presentation: the core
//  resolves `(reason_code, evidence, locale, platform_ctx)` into a rendered
//  three-part diagnostic through `tw_render_diagnostic`, and LT-3a is explicit
//  that variant selection "is a decision; by CB-2 a shell may not hold it… made
//  in core from `platform_ctx`, never a shell choosing among returned keys."
//
//  The deep link `App-prefs:General&path=VPN` that LT-3's iOS row names is
//  therefore NOT hard-coded here: it arrives inside the rendered next action.

import Foundation
import NetworkExtension

/// What the OS currently says about our VPN profile.
///
/// Every case is a fact about the profile. None is a `ConnectionState`: the two
/// are different questions, and ADR-0022 §11.1 keeps `HostLifecycleState` and
/// `ConnectionState` apart for the same reason.
enum ProfileState: Equatable {
    /// No profile has been installed yet.
    case absent
    /// A profile exists and is enabled.
    case installed
    /// A profile exists and the user switched it off in Settings.
    ///
    /// ADR-0012's durability table gives iOS `✘` for "uninstall/update — profile
    /// removal removes enforcement", and this is the softer sibling of that: the
    /// profile is there and doing nothing.
    case disabled
    /// The user declined the consent sheet, or Settings refused.
    case denied
}

@MainActor
final class VPNPermission: ObservableObject {
    @Published private(set) var state: ProfileState = .absent
    /// The registered `reason_code` for the current state, if it is a refusal.
    ///
    /// A code, never a sentence. The app renders it through
    /// `tw_render_diagnostic` with an explicit `platform_ctx`.
    @Published private(set) var reasonCode: String?

    private var manager: NETunnelProviderManager?

    /// Loads whatever profile exists.
    ///
    /// Called at launch and after every return from Settings, because
    /// **revocation happens outside the app**: ADR-0012 §11.10 records that "on
    /// iOS/iPadOS the **only** unblock mechanism is removing the VPN profile in
    /// Settings — this is not 'ours', not a command". The app finds out by
    /// looking, so it looks every time it can.
    func reload() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let manager = managers.first else {
                self.manager = nil
                state = .absent
                reasonCode = nil
                return
            }
            self.manager = manager
            state = manager.isEnabled ? .installed : .disabled
            reasonCode = manager.isEnabled ? nil : ReasonCode.vpnPermissionDenied
        } catch {
            state = .denied
            reasonCode = ReasonCode.vpnPermissionDenied
        }
    }

    /// Installs the profile, which presents the system consent sheet.
    ///
    /// ADR-0019 §11.10 (a): `NEVPNManager.saveToPreferences` → system prompt plus
    /// passcode or biometric.
    ///
    /// On refusal this sets `.denied` and a registered code, and **returns**. It
    /// does not retry, does not escalate, and does not disable anything else in
    /// the app.
    func install(enforcement: EnforcementProgramme) async {
        let manager = self.manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "net.twinvpn.client.provider"
        // The settings object carries the real remote address once the tunnel is
        // up; this is the placeholder NE requires at install time and is never a
        // routing decision.
        proto.serverAddress = "TwinVPN"
        proto.includeAllNetworks = enforcement.includeAllNetworks
        proto.excludeLocalNetworks = enforcement.excludeLocalNetworks
        manager.protocolConfiguration = proto
        manager.localizedDescription = "TwinVPN"
        manager.onDemandRules = enforcement.makeOnDemandRules()
        manager.isOnDemandEnabled = true
        manager.isEnabled = true

        do {
            try await manager.saveToPreferences()
            // `NEVPNErrorConfigurationStale` is the one condition worth retrying
            // ONCE: the profile in preferences moved under us between the load
            // and the save. Rust classes it Transient; the retry is mechanical
            // and is not a policy.
            try await manager.loadFromPreferences()
            self.manager = manager
            state = .installed
            reasonCode = nil
        } catch let error as NSError where error.domain == NEVPNErrorDomain {
            // Declining the sheet arrives as `configurationReadWriteFailed`, and
            // switching the profile off later arrives as `configurationDisabled`.
            // Both are the GRANT, which is why
            // `twinvpn_platform_ios::oserr::from_ne_vpn_error` maps both to
            // `PLATFORM.VPN_PERMISSION_DENIED` rather than to an adapter fault.
            state = .denied
            reasonCode = ReasonCode.vpnPermissionDenied
        } catch {
            state = .denied
            reasonCode = ReasonCode.vpnPermissionDenied
        }
    }

    /// Starts the tunnel, if a profile exists and is enabled.
    ///
    /// ADR-0022 §11.3's iOS row: "app launch MAY call `startVPNTunnel()`;
    /// **user-session trigger, not boot start**." There is no boot start on an
    /// unsupervised device, which is KS-19's residual and which
    /// `EnforcementLimits::boot_enforcement_available == false` declares.
    func startTunnel() throws {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            throw ManagementChannelError.notConnected
        }
        try session.startVPNTunnel()
    }
}

/// The registered codes this file may name.
///
/// A closed set, quoted from `contracts/registry/reason_codes.json`. Nothing in
/// this shell invents a code: `ownership.md` §6 rule 12 requires registered ones
/// only, and a code that is not in the registry "fails the contract tests".
enum ReasonCode {
    static let vpnPermissionDenied = "PLATFORM.VPN_PERMISSION_DENIED"
    static let adapterUnavailable = "PLATFORM.ADAPTER_UNAVAILABLE"
    static let processRestarted = "PLATFORM.PROCESS_RESTARTED"
    static let suspended = "PLATFORM.SUSPENDED"
    /// What `dispatch::disposition` answers for `diag.bundle.create` today —
    /// "which needs `Core::open_store`". `CoreLite.assembleBundle` reports the
    /// core's own code rather than inventing a shell-side one.
    static let storeCustodyDegraded = "STORE.CUSTODY_DEGRADED"
    /// What `twinvpn.h` says a name off ADR-0017 §11.9's catalogue produces:
    /// "a name the catalogue does not contain is MGMT.OP_UNKNOWN". It is the
    /// honest code for the contract-courier operations §11.14 (a) still owes.
    static let operationUnknown = "MGMT.OP_UNKNOWN"
}
