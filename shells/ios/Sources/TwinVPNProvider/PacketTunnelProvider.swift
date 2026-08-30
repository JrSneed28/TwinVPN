//  PacketTunnelProvider.swift — the OS-started process (CB-1 (b)).
//
//  Authority: ADR-0018 CB-1, CB-2, §11.2 row 2.19, §11.5's iOS rows, PB-1, PB-5;
//  ADR-0022 LC-4, LC-7, LC-17, LC-23a, LC-23b, LC-24, LC-31; ADR-0012 §11.6's
//  iOS row; docs/networking.md §5.4's iOS rows; ownership.md §10.2.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHAT THIS CLASS IS ALLOWED TO DO
//  ===========================================================================
//
//  It is the process the OS starts (CB-1 (b)) and the process that holds the
//  datapath (ADR-0022 LC-17's division table). It hosts the FULL core — not
//  `core-lite` — and every decision it appears to make is a `tw_core_submit` of
//  a fact, followed by draining `tw_core_next_event`.
//
//  There is no ConnectionState in this file. There is no timer profile, no
//  retry ladder, no policy. LC-18 is exact: "OS termination produces no
//  ConnectionState transition — it produces a journal fact -> reason_code on next
//  start", and that is the shape of every handler below.
//
//  ===========================================================================
//  THE TWO PROHIBITIONS (ownership.md §10.2)
//  ===========================================================================
//
//  1. NO DEPENDENCE ON KEEPING THE SCREEN AWAKE. There is no
//     `isIdleTimerDisabled` in this file — the extension has no UIApplication to
//     set it on, and the app must not set it either. The sanctioned mechanism is
//     "the extension's own lifecycle plus on-demand rules", which is what
//     `applyEnforcement` installs.
//
//  2. NO UNDOCUMENTED BACKGROUND-EXECUTION TRICKS. There is no background task
//     assertion, no silent-audio session, no repeating timer chosen to keep the
//     process resident. Keepalives ride the tunnel socket's own timer, which is
//     the core's, on the injected monotonic clock. "An iOS provider that survives
//     only because of an undocumented behaviour is written, not verified by
//     definition."

import Foundation
import NetworkExtension
import os
import TwinVPNBridge

final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// The app-group and keychain identities, injected from the signed
    /// entitlements rather than discovered (CD-2, ADR-0020 ST-12e).
    private enum Identity {
        static let appGroup = "group.net.twinvpn.client"
        /// The SAME string as `appGroup`, and that is not a copy-paste slip.
        ///
        /// Apple, "Sharing access to keychain items among a collection of apps":
        /// the system already treats every app-group identifier as a keychain
        /// access group, and — unlike a keychain group — does NOT team-prefix it.
        /// So `group.net.twinvpn.client` is the literal value
        /// `kSecAttrAccessGroup` must carry.
        ///
        /// **This used to read `"$(AppIdentifierPrefix)group.net.twinvpn.client"`,
        /// and that was a defect.** `$(AppIdentifierPrefix)` is an Xcode BUILD
        /// SETTING, expanded when a `.entitlements` plist is processed and never
        /// inside a Swift string literal — so every keychain call would have
        /// carried those seventeen characters verbatim, matched no access group,
        /// and returned `errSecMissingEntitlement`. It fails only on a signed
        /// device: the simulator ignores keychain access groups entirely, so no
        /// simulator run could have caught it.
        ///
        /// The two names are kept separate rather than folded into one constant
        /// because they are two different facts that happen to share a value —
        /// the container identifier and the keychain access group — and ST-22's
        /// co-location is a claim about the second, not the first.
        static let keychainAccessGroup = "group.net.twinvpn.client"
        static let keychainService = "net.twinvpn.client"
    }

    private var host: BridgeHost?
    private var core: CoreInstance?
    private let log = Logger(subsystem: "net.twinvpn.provider", category: "lifecycle")

    /// ADR-0022 LC-31's trigger. Held so `stopTunnel` can cancel it: a live
    /// dispatch source keeps firing into a provider whose core has been
    /// destroyed, and `submitMemoryPressure` on a torn-down handle is exactly
    /// the use-after-free F-6 forbids.
    private var memoryPressureSource: DispatchSourceMemoryPressure?
    private let memoryPressureQueue = DispatchQueue(label: "net.twinvpn.provider.memory")

    // MARK: - start

    override func startTunnel(options: [String: NSObject]?) async throws {
        // PB-5 budgets `tw_core_create` at <= 50 ms p95 here, "the tightest,
        // because the OS starts the extension on demand while the user waits".
        let host = try BridgeHost(provider: self,
                                  appGroupIdentifier: Identity.appGroup,
                                  keychainAccessGroup: Identity.keychainAccessGroup,
                                  keychainService: Identity.keychainService)
        let registration = host.register()
        guard registration.kind == TW_IOS_KIND_OK else {
            // A `size` mismatch means the Swift side and the linked staticlib
            // came from different commits. That is a build error, and starting
            // anyway would run a provider whose bridge half is a different
            // shape from the one the core expects.
            log.fault("bridge registration refused: kind=\(registration.kind) code=\(registration.code)")
            throw NEVPNError(.configurationInvalid)
        }
        self.host = host

        // Event-driven, never polled (networking.md §5.1). Swift serialises the
        // NWPath and hands it over; what a change MEANS is decided in Rust and,
        // above it, in the core.
        host.startObservingPath { [weak self] snapshot, acrossWake in
            self?.core?.submitPathSnapshot(snapshot, acrossWake: acrossWake)
        }

        let core = try CoreInstance.create()
        self.core = core

        // ADR-0022 LC-4's eleven ordered steps are the CORE's, not this file's.
        // What the extension does is hand it the start trigger and then drain.
        core.submitStart(options: options)
        PacketPump.shared.attach(flow: packetFlow, core: core)
        core.startDraining { [weak self] event in
            self?.handle(event)
        }
        armMemoryPressureMonitor()
    }

    // MARK: - stop

    override func stopTunnel(with reason: NEProviderStopReason) async {
        // LC-18: this produces no ConnectionState transition. It produces a
        // FACT, submitted to the core, which decides what it means for
        // `absence_cause` and whether `clean_shutdown` may be set.
        //
        // The raw value crosses; Swift does not classify it. A `switch` here
        // that decided "this one is clean" would be CB-2's forbidden branch on a
        // domain fact — and `twinvpn_platform_ios::lifecycle::ProviderStopReason`
        // is where that translation lives, in Rust, with tests.
        core?.submitStopReason(reason.rawValue)

        // ADR-0022 §11.4's iOS row gives roughly five seconds and requires the
        // flush inside one. LC-25: pre-sleep is FLUSH, never teardown.
        core?.flush(withinMilliseconds: 1_000)

        // Before the core is destroyed — see `memoryPressureSource`.
        memoryPressureSource?.cancel()
        memoryPressureSource = nil

        PacketPump.shared.detach()
        host?.stopObservingPath()
        // Deliberately NOT removing the on-demand rules or includeAllNetworks.
        // CB-6 puts them in the OS's custody so the provider going away does not
        // drop protection, and ADR-0012 already gives iOS only `◐` here.
        host?.unregister()
        core?.destroy()
        core = nil
        host = nil
    }

    // MARK: - sleep and wake

    override func sleep() async {
        // LC-25: a flush, not a teardown. The settings and the enforcement stay
        // exactly where they are; `includeAllNetworks` is system-maintained
        // across sleep (ADR-0022 §11.6's iOS row).
        core?.submitSleep()
        core?.flush(withinMilliseconds: 500)
    }

    override func wake() {
        // networking.md §5.4's iOS row: "on `wake`, immediately re-validate every
        // path rather than assuming continuity; treat every wake as a
        // network-change event."
        //
        // The re-validation is the core's. What this does is make sure the core
        // learns that the monitor was NOT running: the snapshot is pushed with
        // `acrossWake: true`, which Rust turns into a leading `EventsLost` even
        // when the path looks identical.
        core?.submitWake()
        host?.startObservingPath { [weak self] snapshot, _ in
            self?.core?.submitPathSnapshot(snapshot, acrossWake: true)
        }
    }

    // MARK: - the app channel (ADR-0017's iOS subset)

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        // ADR-0017 §11.2.1: `sendProviderMessage` is "the only Apple-sanctioned
        // app<->provider message path", and the contract it carries is NOT a
        // subset — "same operations, same scopes, same schema, same reason
        // codes". Only the CHANNEL is a subset: request/response, app-initiated,
        // and only while the session is connected.
        //
        // The envelope is opaque here. Parsing it would put the management
        // interface's vocabulary in a shell.
        core?.handleManagementRequest(messageData)
    }

    // MARK: - memory and thermal posture

    /// Arms the OS memory-pressure notification for ADR-0022 LC-31's ladder.
    ///
    /// ADR-0022 §11.4's iOS row: jetsam gives **no notice** — a bare `SIGKILL`.
    /// So the response is pre-emptive, and LC-7's write-ahead journal is what
    /// makes the next start a resume rather than a mystery.
    ///
    /// # Why a `DispatchSource` and NOT `didReceiveMemoryWarning()`
    ///
    /// `didReceiveMemoryWarning()` is `UIViewController`'s — UIKit's responder
    /// chain — and `NEPacketTunnelProvider` does not inherit it. Its chain is
    /// `NSObject` -> `NEProvider` -> `NETunnelProvider` ->
    /// `NEPacketTunnelProvider`, none of which declares that method, so an
    /// `override` of it does not compile and a plain definition of it would
    /// never be called by anything. A NetworkExtension provider has no UIKit
    /// responder chain at all; `DISPATCH_SOURCE_TYPE_MEMORYPRESSURE` is the
    /// mechanism that does deliver this to a non-UIKit process, and it works
    /// inside an app extension.
    ///
    /// `.warning` and `.critical` only. `.normal` is the pressure LIFTING, and
    /// submitting the resident size on that edge would tell the core to shed at
    /// the moment it no longer needs to.
    private func armMemoryPressureMonitor() {
        let source = DispatchSource.makeMemoryPressureSource(
            eventMask: [.warning, .critical], queue: memoryPressureQueue)
        source.setEventHandler { [weak self] in
            // The THRESHOLDS are Rust's (`twinvpn_platform_ios::lifecycle`).
            // This reports the number; it does not decide what it means — CB-2
            // keeps that branch out of the shell.
            self?.core?.submitMemoryPressure(residentBytes: MemoryReporter.residentBytes())
        }
        source.resume()
        memoryPressureSource = source
    }

    // MARK: - draining

    private func handle(_ event: CoreEvent) {
        // Every event is rendered or forwarded; none is interpreted. The one
        // thing this method may do with a `reason_code` is put it in a log line,
        // and even then the RENDERED text comes from `tw_render_diagnostic`
        // (F-10) rather than from a string in this file — CB-4 keeps every
        // rendered string out of the shell's judgement and in the core's
        // catalogue.
        switch event.kind {
        case .settingsRequested, .enforcementRequested:
            // Already handled synchronously through the bridge.
            break
        case .diagnostic:
            log.notice("\(event.reasonCode, privacy: .public)")
        case .cancelTunnel:
            cancelTunnelWithError(nil)
        }
    }
}
