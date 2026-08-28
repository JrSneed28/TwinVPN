//
//  SystemExtensionInstaller.swift
//  TwinVPN.app  —  THE CONTAINING APP, not the extension.
//
//  This file lives on the APP side (`shells/macos/TwinVPNApp/`) and is the only
//  Swift file in this shell that does. The reason is an entitlement, not taste:
//  `OSSystemExtensionRequest` requires `com.apple.developer.system-extension.
//  install`, which ADR-0016 §11.9's macOS row grants to the App and not to the
//  sysext — an extension cannot install itself.
//
//  Authority: ADR-0016 §11.2's macOS component row, §12.6 / MX-1 (Developer ID
//  + notarized system extension; MX-2 rejected), §11.9's macOS row, P-06;
//  ADR-0018 CB-2, CB-4; ADR-0015 (the diagnostic envelope).
//
//  ============================================================================
//  WHAT THE APP IS AND IS NOT
//
//  The app is a client. It activates the extension, installs the VPN profile,
//  and renders what the core resolved (ADR-0019: the presentation resolver is
//  IN-CORE; the UI renders and decides nothing).
//
//  It is NOT on any recovery path. `docs/application-architecture.md` §6 FC-1
//  instance 5 puts the signed-contract fetch in the EXTENSION so that a device
//  can recover with no GUI running and no GUI installed. Nothing in this file
//  fetches a contract, and adding such a path here would break FC-1.
//
//  ============================================================================
//  CB-2 IN A DELEGATE
//
//  `OSSystemExtensionRequestDelegate` is where a shell is most tempted to hold a
//  decision, because Apple's API asks it two questions:
//
//    - `actionForReplacingExtension(_:withExtension:)` — replace or not?
//    - `requestNeedsUserApproval(_:)` — what now?
//
//  Neither is a TwinVPN domain fact. The first is a VERSION COMPARISON between
//  two bundles of ours, which CB-2 names explicitly as a forbidden branch
//  condition — so this file answers `.replace` unconditionally and lets the
//  packaging system be the thing that decides which version is installed
//  (ADR-0021). The second is a UI state, reported upward and rendered by
//  whatever the core resolved, never interpreted here.
//

import Foundation
import SystemExtensions
import os

/// The outcome of an activation request, as a FACT for the core and the UI.
///
/// Not a decision, and deliberately not an enum with a `shouldRetry` case:
/// whether to retry is the core's, and an enum that answered it would be this
/// file holding a policy.
enum SystemExtensionOutcome: Sendable {
    /// The extension is active.
    case completed
    /// The extension is staged and will activate on reboot.
    case completedWillCompleteAfterReboot
    /// macOS is waiting for an administrator to approve it in System Settings.
    ///
    /// ADR-0016's code table registers this condition as
    /// `PLATFORM.SERVICE.SYSEXT_NOT_APPROVED`, "distinct from
    /// `PLATFORM.VPN_PERMISSION_DENIED`, which is the VPN profile". The two
    /// have different remediations and must not be collapsed.
    case needsUserApproval
    /// The request failed. `description` is the `OSSystemExtensionError`'s own
    /// text, carried for a log line and **not parsed**.
    case failed(description: String)
}

/// Activates and deactivates `com.twinvpn.app.sysext`.
///
/// UNVERIFIED, and worth stating at the top: `OSSystemExtensionManager` requires
/// the app to be running from `/Applications` (or another Gatekeeper-approved
/// location) and signed with a Developer ID that carries the system-extension
/// entitlement. A request from a debug build in a build directory fails with an
/// opaque error. This domain has run none of it.
final class SystemExtensionInstaller: NSObject, @unchecked Sendable {
    /// Must match `TwinVPNTunnel.Info.plist`'s `CFBundleIdentifier`.
    ///
    /// A system extension's identifier MUST be prefixed by the containing app's,
    /// which is why this is `com.twinvpn.app.sysext` and not ADR-0016 §11.2's
    /// literal `com.twinvpn.sysext`. The divergence is reported, not resolved
    /// here — see the note in `TwinVPNTunnel.Info.plist`.
    static let extensionIdentifier = "com.twinvpn.app.sysext"

    private let log = Logger(subsystem: "com.twinvpn.app", category: "sysext")
    private var completion: ((SystemExtensionOutcome) -> Void)?

    /// Requests activation. The delegate below reports the outcome exactly once.
    func activate(_ completion: @escaping (SystemExtensionOutcome) -> Void) {
        self.completion = completion
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        log.info("sysext.activation.submitted")
    }

    /// Requests deactivation.
    ///
    /// **Deactivating the extension does NOT disarm the kill switch**, and that
    /// is the point of the macOS component split. ADR-0016 §11.5's macOS row: "a
    /// sysext can be deactivated by the user, and the boot artifact must not be
    /// able to be." The pf anchor is owned by `com.twinvpn.ksd` and by
    /// `/etc/pf.conf`, neither of which this request touches.
    ///
    /// ADR-0016 PS-20 is the related rule for the OTHER direction: no packaging
    /// path may remove the enforcement rule set without the ADMINISTER
    /// authority. That ceremony is not in this wave.
    func deactivate(_ completion: @escaping (SystemExtensionOutcome) -> Void) {
        self.completion = completion
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        log.info("sysext.deactivation.submitted")
    }

    private func finish(_ outcome: SystemExtensionOutcome) {
        let handler = completion
        completion = nil
        handler?(outcome)
    }
}

extension SystemExtensionInstaller: OSSystemExtensionRequestDelegate {

    /// An older build of our own extension is installed.
    ///
    /// **Answered unconditionally `.replace`.** CB-2 names a version comparison
    /// as a forbidden branch condition for a shell, and comparing
    /// `existing.bundleShortVersion` against `ext.bundleShortVersion` here would
    /// be exactly that — a downgrade policy, expressed in Swift, in the one
    /// place nobody looks for one. Which version is installed is decided by the
    /// packaging system (ADR-0021), and by the time this delegate runs that
    /// decision has already been made.
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log.info("sysext.replacing")
        return .replace
    }

    /// macOS is waiting for administrator approval in System Settings.
    ///
    /// Reported upward as a fact. The UI text is not written here: CB-4 keeps
    /// every rendered string out of the core AND out of ad-hoc shell literals —
    /// what the user reads is what ADR-0019's in-core presentation resolver
    /// produced for `PLATFORM.SERVICE.SYSEXT_NOT_APPROVED`.
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log.notice("sysext.needs_user_approval")
        finish(.needsUserApproval)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            log.info("sysext.completed")
            finish(.completed)
        case .willCompleteAfterReboot:
            log.notice("sysext.will_complete_after_reboot")
            finish(.completedWillCompleteAfterReboot)
        @unknown default:
            // A result this build does not know. Reported as a FAILURE rather
            // than assumed to be success: `docs/architecture.md` §2.16 resolves
            // ambiguity closed, and treating an unknown result as "active" would
            // report a tunnel that may not exist.
            log.error("sysext.unknown_result")
            finish(.failed(description: "unknown OSSystemExtensionRequest.Result"))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        // The error's text is carried for a support case and NOT parsed. There
        // is no branch here on an `OSSystemExtensionError.Code`: which codes
        // warrant a retry is the core's judgement, driven by
        // `Diagnostic.class`, not by a shell reading an Apple enum.
        log.error("sysext.failed: \(String(describing: error), privacy: .private)")
        finish(.failed(description: String(describing: error)))
    }
}
