//
//  main.swift — `TwinVPN.app`'s entry point.
//
//  Authority: ADR-0016 §11.2's macOS component row ("`TwinVPN.app` (per-user,
//  sandboxed) | UI, the VPN profile, the sysext activation | no authority, no
//  key, no recovery path"), §11.5, PS-22; ADR-0018 CB-1, CB-2, CB-4, C-7.
//
//  ===========================================================================
//  WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
//  ===========================================================================
//  It is the **activation host** and nothing else. `OSSystemExtensionRequest`
//  can only be submitted by an application, and a `.systemextension` bundle can
//  only be delivered inside an application bundle — so there MUST be an app
//  target for the system extension to exist at all, and this file is the
//  smallest one that is real.
//
//  **There is no UI here.** ADR-0016 §11.2 gives this component "UI, the VPN
//  profile, the sysext activation", and only the third of those is written.
//  Writing a window now would mean writing user-facing English, and CB-4 puts
//  every rendered string in the core's catalogue with LT-3a's variant selection
//  in the core too — which this shell has no plumbing for yet. An empty window
//  with placeholder copy would be a CB-4 violation dressed as progress, so the
//  UI is recorded as a gap in `README.md` §7 instead of stubbed here.
//
//  What it prints is not user copy either: they are the same stable,
//  non-localised outcome TAGS `SystemExtensionInstaller` already reports to
//  `os.Logger`, echoed to stdout so a CI run and an operator at a terminal see
//  the same word. A tag is not a sentence, and CB-4 governs sentences.
//
//  ===========================================================================
//  THE APP LINKS NO CORE, ON PURPOSE
//  ===========================================================================
//  ADR-0018 §11.9 row 5 puts the core `staticlib` inside the **system
//  extension**, and ADR-0016 §11.2 gives this process "no authority, no key, no
//  recovery path". So `project.yml` links `libtwinvpn_bridge.a` into
//  `TwinVPNTunnel` and NOT into this target. If a future change makes this
//  target link it, that is a topology change and needs the ADR amended first —
//  it is not a build-settings tidy-up.
//
//  STATUS: this file has never been compiled. There is no Darwin SDK on the
//  development host; `build/ci/ci-macos.sh` is what compiles it.
//

import AppKit
import Foundation
import os

private let log = Logger(subsystem: "com.twinvpn.app", category: "app")

/// The application delegate. Submits one activation request at launch and
/// reports its outcome.
///
/// **CB-2**: there is no branch here whose condition is a TwinVPN domain fact.
/// The `switch` below is over `SystemExtensionOutcome`, which is a statement
/// about the OS's own request machinery — approved, staged, awaiting an
/// administrator, failed — and never about a session, a policy verdict or a
/// `ConnectionState`.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let installer = SystemExtensionInstaller()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // `TWINVPN_NO_ACTIVATION` exists for one reason: a CI job that builds
        // and launches this bundle to prove it links must not submit a real
        // system-extension request to the runner it happens to be on.
        // ADR-0016 §11.5 makes activation an administrator ceremony, and a
        // build gate has no business performing one.
        if ProcessInfo.processInfo.environment["TWINVPN_NO_ACTIVATION"] != nil {
            log.info("sysext.activation.skipped")
            print("sysext.activation.skipped")
            NSApplication.shared.terminate(nil)
            return
        }

        installer.activate { outcome in
            let tag: String
            switch outcome {
            case .completed:
                tag = "sysext.activation.completed"
            case .completedWillCompleteAfterReboot:
                tag = "sysext.activation.completed_after_reboot"
            case .needsUserApproval:
                // ADR-0016's code table registers this as
                // `PLATFORM.SERVICE.SYSEXT_NOT_APPROVED`, distinct from
                // `PLATFORM.VPN_PERMISSION_DENIED`. The two have different
                // remediations, and collapsing them is the defect that table
                // exists to prevent.
                tag = "sysext.activation.needs_user_approval"
            case .failed(let description):
                // The OS's own text, carried and NOT parsed (F-4's discipline
                // applied to an Apple error rather than one of ours).
                log.error("sysext.activation.failed: \(description, privacy: .public)")
                tag = "sysext.activation.failed"
            }
            log.info("\(tag, privacy: .public)")
            print(tag)
        }
    }

    /// The app is a launcher for the extension, not a resident agent.
    ///
    /// PS-3 and ADR-0016 §11.13 procedure A: the AUTHORITY outlives every
    /// unprivileged process, and this is an unprivileged process. It must be
    /// disposable, and a delegate that kept the app alive "to watch the tunnel"
    /// would be the M-P16-1 mutant written by hand.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

let delegate = AppDelegate()
let application = NSApplication.shared
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
