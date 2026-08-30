//  TwinVPNApp.swift — the SwiftUI app. UI lives in the app process ONLY.
//
//  Authority: ADR-0019 §11.7's iOS/iPadOS rows (iOS 15+, SwiftUI, "the
//  `NEPacketTunnelProvider` extension holds no UI (C-7)"), §11.8 (iPadOS),
//  §11.10 (onboarding); ADR-0018 CB-1 (c), CB-4, F-10; ADR-0017 §11.2.1;
//  ownership.md §10.1.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  CB-4: THE CORE RESOLVES, THE SHELL PRESENTS
//  ===========================================================================
//
//  | Job          | Side  | Content                                          |
//  |--------------|-------|--------------------------------------------------|
//  | Resolution   | core  | reason_code + evidence + locale + platform_ctx -> |
//  |              |       | catalogue lookup, next-action variant (LT-3)      |
//  | Presentation | shell | typography, layout, truncation, platform idiom,   |
//  |              |       | accessibility, iconography, WHERE it appears      |
//
//  There is therefore **no user-facing English in this file**, and none in any
//  view below it. Every string a user reads arrives from `tw_render_diagnostic`,
//  which F-10 makes pure and instance-free "because the moment a diagnostic most
//  needs rendering is exactly when no such instance exists — after
//  `INTERNAL.CORE_PANIC` poisoned it, before `tw_core_create` has run, or inside
//  a crash reporter."
//
//  `platform_ctx` is passed EXPLICITLY. LT-3b: an empty one "MUST resolve to the
//  platform-neutral variant and MUST NOT fall back to the host's own platform",
//  and reading the OS version ambiently would be CD-2's forbidden ambient input.

import SwiftUI

@main
struct TwinVPNApp: App {
    @StateObject private var permission = VPNPermission()
    @StateObject private var management = ManagementClient.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(permission)
                .environmentObject(management)
                .task {
                    await permission.reload()
                }
        }
        // `onChange(of:perform:)` — ONE closure parameter, the new value. The
        // two-parameter `onChange(of:initial:_:)` is iOS 17.0+, and ADR-0018
        // §11.9 row 1 fixes this product's floor at iOS 15.0, so the newer
        // spelling names nothing at the version this app is built for. Only the
        // NEW phase is read either way; the old one was already discarded.
        .onChange(of: scenePhase) { phase in
            // ADR-0022 LC-14: background is an APP-level fact, not a scene-level
            // one — "`EV_BACKGROUND` derived from ALL surfaces being background".
            // On iPadOS a single scene going background while another is visible
            // is explicitly NOT background, and mapping it as one is named as the
            // hazard.
            //
            // This is also LC-23b's OPTIMIZATION-bearing signal, never a
            // correctness-bearing one: it renews the foreground lease and does
            // nothing else. If it never arrives, the provider runs the background
            // profile, which LC-23b calls "the battery-optimal default, not
            // degraded".
            switch phase {
            case .active:
                management.beginPolling()
                Task { await permission.reload() }
            case .background, .inactive:
                management.endPolling()
            @unknown default:
                management.endPolling()
            }
        }
    }
}

/// The root.
///
/// **Everything except the tunnel works without a VPN profile.** ADR-0019
/// §11.10 (a)'s iOS row: on refusal "no tunnel is possible; the rest of the app
/// remains usable", and `ownership.md` §10.1 lists what that means concretely —
/// "pairing, device list, settings and diagnostics stay usable without a tunnel".
///
/// So `permission.state` gates exactly one tab, and no other.
struct RootView: View {
    @EnvironmentObject private var permission: VPNPermission

    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label(Catalogue.tabStatus, systemImage: "shield") }
            PairingView()
                .tabItem { Label(Catalogue.tabPairing, systemImage: "qrcode") }
            DiagnosticsView()
                .tabItem { Label(Catalogue.tabDiagnostics, systemImage: "stethoscope") }
        }
    }
}

/// The one place a string may be looked up, and it is a LOOKUP.
///
/// Even the tab labels come from the core's catalogue rather than from literals
/// here: CB-4 puts the catalogue "embedded in the artifact, so it is covered by
/// S-46 and by DP-5's SBOM", and a literal in a Swift file is outside both.
///
/// These are keys, resolved through `tw_render_diagnostic`'s sibling entry
/// point. They are named here so a reviewer can see there are exactly three.
enum Catalogue {
    static var tabStatus: String { CoreLite.shared.string("ui.tab.status") }
    static var tabPairing: String { CoreLite.shared.string("ui.tab.pairing") }
    static var tabDiagnostics: String { CoreLite.shared.string("ui.tab.diagnostics") }
}
