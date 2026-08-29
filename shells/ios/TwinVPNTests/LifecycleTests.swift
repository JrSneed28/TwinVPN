//  LifecycleTests.swift — the rows that genuinely need a device.
//
//  Authority: docs/implementation/ownership.md §10.3's fourth row and §10.5
//  rule 2; ADR-0022 §11.4's iOS rows, LC-7, LC-17, LC-20, LC-23, LC-24;
//  ADR-0012 §11.6's durability table and §11.10.
//
//  ===========================================================================
//  STATUS: WRITTEN, NOT EXECUTED. AND NOT COMPILED EITHER.
//  ===========================================================================
//
//  `ownership.md` §10.3's wave-3 table puts these in TWO of its four categories
//  at once: they are Swift, so they are *written, not compiled* (there is no
//  Xcode and no Darwin SDK on the build host); and they are real-device
//  lifecycle tests, so they are *written, not executed*.
//
//  **Nothing in this file has ever run.** It must not be reported as passing,
//  and a green `make cross-check` says nothing whatever about it — that target
//  reaches no Swift at all, and says so at the target.
//
//  §10.5 rule 2 is why they are written anyway: "the genuinely device-bound rows
//  are written as real-device lifecycle tests and reported as unrun… Process
//  termination by the OS, Doze, extension memory-limit kill, and the iOS
//  attach-to-arm window ADR-0012 §11.9's P09 *measures* rather than assumes, are
//  in this set." Writing them is what a device farm executes on the day it
//  exists; not writing them is what makes the debt invisible.
//
//  ===========================================================================
//  WHAT A DEVICE FARM NEEDS TO RUN THEM
//  ===========================================================================
//
//  * A physical iPhone and a physical iPad (ADR-0018 §11.9 lists iPadOS as a
//    DISTINCT farm entry, not a variant). The simulator has no Secure Enclave,
//    no jetsam, and no real `includeAllNetworks`, so every assertion here is
//    vacuous on it.
//  * A provisioning profile carrying `packet-tunnel-provider`, `allow-vpn`, the
//    shared keychain access group and the App Group (ADR-0016 §11.2's
//    entitlement table).
//  * A supervised device for the always-on rows: ADR-0022 §11.10's iOS row makes
//    true boot start an MDM payload, and an unsupervised device cannot reach it.
//  * A second peer, to have a tunnel worth terminating.

import NetworkExtension
import XCTest

@testable import TwinVPNApp

final class LifecycleTests: XCTestCase {
    private var permission: VPNPermission!
    private var management: ManagementClient!

    override func setUp() async throws {
        try await super.setUp()
        try XCTSkipUnless(DeviceCapabilities.isPhysicalDevice,
                          "every assertion in this suite is vacuous on the simulator")
        permission = await VPNPermission()
        management = await ManagementClient.shared
        await permission.reload()
    }

    // MARK: - OS termination of the extension

    /// ADR-0022 §11.4's iOS row: jetsam kills the extension with **no notice** —
    /// a bare `SIGKILL`. LC-7's write-ahead journal is what makes the next start
    /// a resume rather than a mystery.
    ///
    /// The point of the test is NOT that the tunnel survives the kill; it does
    /// not. It is that the state afterwards is the one LC-2 maps to, that the
    /// generation the OS holds is the one that was in force, and that the app
    /// reports `UNKNOWN` in the interval rather than the last green it saw.
    func testExtensionTerminationResumesFromTheJournalAndNotFromMemory() async throws {
        try await startTunnelAndWaitForProtection()
        let generationBefore = try await currentGeneration()

        // Force the OS to reclaim the provider. On a device farm this is the
        // `NEProviderStopReason` path plus a memory-pressure injection; there is
        // no supported way to ask jetsam directly, which is itself worth
        // recording: this test approximates the condition it is named for.
        try await ProviderHarness.forceTerminateExtension()

        // ADR-0017 LC-21/LC-22 and ADR-0015 O-18: a re-attaching UI renders
        // UNKNOWN until a snapshot or a fresh ProtectionAssertion, NEVER the
        // last value it happened to hold.
        await management.beginPolling()
        XCTAssertFalse(management.isLive,
                       "a dead provider must not leave the app rendering a stale live value")

        // The on-demand rules re-arm on the next network event, and the
        // generation the OS holds is the one that was in force — which is what
        // makes LC-4 step 3's read-back work with no in-process memory at all.
        try await ProviderHarness.waitForOnDemandRearm(timeout: 60)
        let generationAfter = try await currentGeneration()
        XCTAssertEqual(generationAfter, generationBefore,
                       "W-24: the generation is READ from the OS, never remembered")
    }

    /// ADR-0022 §11.4's iOS row and LC-31: the provider sheds bounded caches at
    /// **10 MB** and raises the condition *before* the OS acts, because the OS
    /// gives no warning when it does.
    ///
    /// ADR-0018 PB-6 fixes the figures: 15 MB observed ceiling, 12 MB
    /// provider-wide budget, 10 MB shed threshold, **9 MB core share**. The
    /// corresponding constants are asserted on the build host in
    /// `twinvpn_platform_ios::lifecycle`; what needs a device is whether the
    /// real provider stays under them.
    func testTheProviderStaysInsideItsMemoryBudgetUnderLoad() async throws {
        try await startTunnelAndWaitForProtection()
        var peak: UInt64 = 0
        try await TrafficGenerator.saturate(forSeconds: 120) {
            peak = max(peak, try ProviderHarness.residentBytes())
        }
        XCTAssertLessThan(peak, 12 * 1024 * 1024,
                          "ADR-0022 LC-17's provider-wide engineering budget")
        // ADR-0018 §14 condition 2's revisit trigger is on the CORE's share at
        // p95, which this harness cannot separate from the provider's total.
        // Recorded as a measurement rather than asserted, so the number reaches
        // a human instead of a green tick.
        XCTContext.runActivity(named: "peak provider RSS") { activity in
            activity.add(XCTAttachment(string: "\(peak)"))
        }
    }

    /// ADR-0012's durability table gives iOS `✘` for uninstall/update: "profile
    /// removal removes enforcement". ADR-0012 §11.10 adds that on iOS "the ONLY
    /// unblock mechanism is removing the VPN profile in Settings — this is not
    /// 'ours', not a command".
    ///
    /// So this test asserts the honest thing: that the app NOTICES, names the
    /// condition, and keeps working without a tunnel.
    func testProfileRevocationFromSettingsIsNoticedAndNamed() async throws {
        try await startTunnelAndWaitForProtection()

        // Requires a human, or a supervised device with an MDM command. There is
        // no API by which an app removes its own profile and observes the
        // revocation path, which is the point.
        try await ProviderHarness.awaitManualProfileRemoval(timeout: 300)

        await permission.reload()
        XCTAssertEqual(permission.state, .absent)
        XCTAssertEqual(permission.reasonCode, "PLATFORM.VPN_PERMISSION_DENIED")

        // ADR-0019 §11.10 (a): "no tunnel is possible; the rest of the app
        // remains usable". Pairing, the device list, settings and diagnostics
        // must still work.
        XCTAssertNoThrow(try DiagnosticsHarness.assembleBundle())
    }

    /// ADR-0022 LC-23: "the app may not be a required participant in any runtime
    /// path" — a variant of P21, testable here by force-quitting the app.
    ///
    /// Keepalive, liveness, rekey, path migration, relay failover and enforcement
    /// reconciliation must all continue. LC-23b's foreground lease simply expires
    /// and the provider falls back to the background profile, which LC-23b calls
    /// "the battery-optimal default, not degraded".
    func testTheTunnelSurvivesTheAppBeingForceQuit() async throws {
        try await startTunnelAndWaitForProtection()
        try await ProviderHarness.forceQuitContainingApp()
        try await Task.sleep(for: .seconds(120))

        // Observed from the OS, not from our own IPC — LC-20: "the app detects
        // provider status from the OS's own `NEVPNStatus`/`NETunnelProviderSession`
        // state, which is authoritative and survives the app's death; it does not
        // infer status from whether its own IPC replied."
        let status = try await ProviderHarness.osReportedStatus()
        XCTAssertEqual(status, .connected)
        XCTAssertGreaterThan(try await TrafficGenerator.roundTripCount(), 0)
    }

    /// ADR-0022 LC-24 and §11.6: `NEProvider.sleep`/`wake`, and
    /// `docs/networking.md` §5.4's "treat every wake as a network-change event".
    ///
    /// The host-side half — that a wake always leads with `EventsLost` even when
    /// the path is byte-identical — is executed in
    /// `core/crates/twinvpn-platform-ios/tests/matrix.rs`. What needs a device is
    /// that the OS actually delivers `wake()` and that the measured gap comes
    /// from the SUSPEND-INCLUSIVE clock: LC-8 warns that Darwin's
    /// `CLOCK_MONOTONIC` is suspend-inclusive, the reverse of Linux's, and a
    /// build that got it backwards measures every suspension as zero — which no
    /// CI runner can catch, because no CI runner sleeps.
    func testASuspensionIsMeasuredOnTheSuspendInclusiveClock() async throws {
        try await startTunnelAndWaitForProtection()
        try await ProviderHarness.suspendDevice(forSeconds: 300)
        let gap = try await ProviderHarness.lastReportedResumeGapMilliseconds()
        XCTAssertGreaterThan(gap, 250_000,
                             "a gap near zero means mach_absolute_time was read "
                             + "where mach_continuous_time was meant — LC-8's "
                             + "invisible-on-CI failure")
    }

    // MARK: - helpers

    private func startTunnelAndWaitForProtection() async throws {
        try XCTSkipUnless(permission.state == .installed,
                          "install the VPN profile before running this suite")
        try permission.startTunnel()
        try await ProviderHarness.waitForProtection(timeout: 30)
    }

    private func currentGeneration() async throws -> UInt64 {
        try await ProviderHarness.installedEnforcementGeneration()
    }
}
