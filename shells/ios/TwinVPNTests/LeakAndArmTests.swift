//  LeakAndArmTests.swift — measured leak coverage, and P09's attach-to-arm window.
//
//  Authority: ADR-0012 §11.6's iOS limitation row, KS-18, KS-19, §11.9's **P09**,
//  §14 revisit condition 5; ADR-0010 R1; ADR-0011 §11.9's iOS row;
//  ownership.md §10.5 rule 2 and its leak-coverage rule.
//
//  ===========================================================================
//  STATUS: WRITTEN, NOT EXECUTED. AND NOT COMPILED.
//  ===========================================================================
//
//  Nothing here has run. See `LifecycleTests.swift`'s header for what a device
//  farm needs; this suite needs one thing more: **a capture point on the far side
//  of the device's uplink**, because a leak is by definition a packet the device
//  emitted that we did not see it emit. A test that asks the device whether it
//  leaked is asking the wrong process.
//
//  ===========================================================================
//  BOTH FAMILIES AND DNS, ON EVERY ROW
//  ===========================================================================
//
//  `ownership.md` §10.5: "Leak coverage is **both families and DNS on every
//  platform**, per ADR-0010 R1: an IPv4 story with a weaker IPv6 story is the
//  asymmetry that ADR forbids, and §4.2 already refuses to let address family
//  become a namespace."
//
//  So every leak test below is written once and parameterised over
//  `[.v4, .v6]` — not written for v4 and then extended. The structural half is
//  executed on the build host in `tests/matrix.rs`
//  (`no_enforcement_programme_can_capture_one_family_and_not_the_other`); this is
//  the measured half, and the two are complementary rather than duplicates.

import XCTest

@testable import TwinVPNApp

/// Which family a leak assertion covers. Never defaulted, never optional.
enum Family: CaseIterable {
    case v4
    case v6
}

final class LeakTests: XCTestCase {
    override func setUp() async throws {
        try await super.setUp()
        try XCTSkipUnless(DeviceCapabilities.isPhysicalDevice)
        try XCTSkipUnless(CaptureHarness.isReachable,
                          "a leak is a packet we did not see the device emit; asking "
                          + "the device whether it leaked is asking the wrong process")
    }

    /// With the latch up and no tunnel, **nothing** protected egresses on either
    /// family.
    ///
    /// ADR-0012 KS-18: both `EV_PATH_VALIDATED` and a `ProtectionAssertion`
    /// confirming intent **for both families** are required before entering
    /// `RULESET_PROTECTED`; either failing keeps `RULESET_BLOCKED`.
    func testNothingEgressesWhileBlocked() async throws {
        for family in Family.allCases {
            try await ProviderHarness.forceRuleset(.blocked)
            let capture = try await CaptureHarness.record(seconds: 30) {
                try await TrafficGenerator.attemptEgress(family: family)
            }
            XCTAssertTrue(capture.protectedPackets(family: family).isEmpty,
                          "\(family): a packet escaped while RULESET_BLOCKED was live")
        }
    }

    /// A **DNS** query never leaves in the clear.
    ///
    /// ADR-0011 §11.9's iOS row is the starkest in that ADR: "Same
    /// `mDNSResponder` behaviour, **and no host firewall exists at all** …
    /// `includeAllNetworks = true` on the provider is the ONLY containment
    /// available; there is no packet filter to fall back on. **The largest
    /// residual in this ADR.** Disclosed per ADR-0012's iOS limitation row;
    /// measured, not assumed."
    ///
    /// This is the measurement. It is expected to find `.local` going to
    /// multicast (N2 says mDNSResponder does that regardless of what we
    /// configure) and that is asserted as a KNOWN residual rather than a pass.
    func testNoDnsQueryLeavesInTheClear() async throws {
        try await ProviderHarness.forceRuleset(.protected)
        let capture = try await CaptureHarness.record(seconds: 60) {
            try await TrafficGenerator.resolve(["example.invalid", "peer.twin.example"])
        }
        for family in Family.allCases {
            XCTAssertTrue(capture.plaintextDnsPackets(family: family).isEmpty,
                          "\(family): a DNS query left outside the tunnel")
        }
        // The disclosed residual, asserted as such so that its DISAPPEARANCE is
        // also a signal — if this ever comes back empty, either the OS changed
        // or the test stopped exercising mDNS.
        XCTAssertFalse(capture.multicastDnsPackets().isEmpty,
                       "ADR-0011 N2: mDNSResponder sends .local to multicast "
                       + "regardless of configuration. This is DISCLOSED, not fixed.")
    }

    /// IPv6 arriving **after** the tunnel is up does not acquire a way out.
    ///
    /// ADR-0010 R6 names exactly this case, and it is the one an IPv4-first test
    /// suite never reaches: a network that was v4-only when the tunnel came up
    /// and gains a v6 default route afterwards.
    func testIPv6ArrivingAfterTheTunnelIsUpDoesNotBypassPolicy() async throws {
        try await NetworkHarness.attach(.wifiV4Only)
        try await ProviderHarness.waitForProtection(timeout: 30)
        try await NetworkHarness.enableRouterAdvertisements()

        let capture = try await CaptureHarness.record(seconds: 30) {
            try await TrafficGenerator.attemptEgress(family: .v6)
        }
        XCTAssertTrue(capture.protectedPackets(family: .v6).isEmpty,
                      "R6: IPv6 must not bypass tunnel policy, INCLUDING when it "
                      + "appears after the tunnel is up")
    }

    /// A Wi-Fi to cellular roam does not leak during the migration.
    ///
    /// `docs/networking.md` §5.4: "make-before-break migration… `MIGRATING`, not
    /// `RECONNECTING`". The host-side half — that the overlay contract is
    /// untouched by the roam — is executed in `tests/matrix.rs`. What needs a
    /// device is that no packet takes the old path in the clear while the new one
    /// is being validated.
    func testARoamDoesNotLeakDuringMigration() async throws {
        try await NetworkHarness.attach(.wifiDualStack)
        try await ProviderHarness.waitForProtection(timeout: 30)
        let capture = try await CaptureHarness.record(seconds: 45) {
            try await TrafficGenerator.saturate(forSeconds: 45) {}
            try await NetworkHarness.detach(.wifiDualStack)
        }
        for family in Family.allCases {
            XCTAssertTrue(capture.protectedPackets(family: family).isEmpty,
                          "\(family): a packet took the old path in the clear")
        }
    }
}

/// ADR-0012 §11.9's **P09**, and the one number §14 condition 5 turns on.
final class AttachToArmTests: XCTestCase {
    override func setUp() async throws {
        try await super.setUp()
        try XCTSkipUnless(DeviceCapabilities.isPhysicalDevice)
    }

    /// **The window is measured, never assumed to be zero.**
    ///
    /// ADR-0012 §11.6's iOS limitation row names the residual: "the interval
    /// between network attachment and provider start on an unsupervised device",
    /// and it ends "P09 **measures** the attach-to-arm window rather than assuming
    /// it is zero." KS-19 explains why there is a window at all: the boot ruleset
    /// "MUST be installed by an artifact the **OS itself applies**… Where a
    /// platform cannot do this (iOS), `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE`
    /// is emitted at first run, the residual window is named, and P09 measures it."
    ///
    /// §14 condition 5 is what the number decides: "If P09 measures an iOS
    /// attach-to-arm window exceeding **500 ms at p95**, `includeAllNetworks` is
    /// not delivering what the limitation table assumes and iOS must either be
    /// reclassified as best-effort in the supported matrix or restricted to
    /// supervised Always-On deployments."
    ///
    /// The arithmetic and the threshold check are EXECUTED on the build host in
    /// `twinvpn_platform_ios::enforce::{AttachToArm, p95_window_ms}`. This test
    /// supplies the readings, and it supplies enough of them for a p95 to mean
    /// something.
    func testTheAttachToArmWindowIsMeasuredAcrossManyAttaches() async throws {
        var samples: [(attachedMicros: UInt64, armedMicros: UInt64)] = []

        // Twenty is the smallest count at which a nearest-rank p95 is not simply
        // the maximum. Fewer would report a number that looks like a percentile
        // and is not one.
        for _ in 0..<20 {
            try await NetworkHarness.detachAll()
            let attached = try await NetworkHarness.attachAndStampArrival(.wifiDualStack)
            let armed = try await ProviderHarness.awaitIncludeAllNetworksInForce(timeout: 10)
            samples.append((attached, armed))
        }

        let windows = samples
            .filter { $0.armedMicros >= $0.attachedMicros }
            .map { ($0.armedMicros - $0.attachedMicros) / 1_000 }
            .sorted()
        XCTAssertEqual(windows.count, samples.count,
                       "a backwards reading means the wrong clock was read; it is "
                       + "NOT a zero-length window, which is precisely the value "
                       + "ADR-0012 forbids assuming")

        let rank = max(1, Int((Double(windows.count) * 0.95).rounded(.up)))
        let p95 = windows[rank - 1]

        // The number reaches a human whether or not it passes, because §14's
        // condition is a decision about the SUPPORTED MATRIX and not a bug.
        XCTContext.runActivity(named: "P09 attach-to-arm") { activity in
            activity.add(XCTAttachment(string: "p95=\(p95)ms samples=\(windows)"))
        }
        XCTAssertLessThanOrEqual(
            p95, 500,
            "ADR-0012 §14 condition 5: above 500 ms at p95, iOS must be "
            + "reclassified as best-effort or restricted to supervised Always-On")
    }

    /// The boot window has no artifact to close it, and the build says so.
    ///
    /// This is the assertion that keeps the residual honest: if a future build
    /// ever *did* acquire boot-time enforcement, `EnforcementLimits::ios()` would
    /// change and this test would fail, prompting the ADR to be revisited rather
    /// than the claim quietly widening.
    func testTheBuildDeclaresThatBootEnforcementIsUnavailable() async throws {
        let posture = try await ProviderHarness.declaredEnforcementLimits()
        XCTAssertFalse(posture.bootEnforcementAvailable,
                       "ADR-0012 §11.6's iOS boot column is 'None available'")
        XCTAssertFalse(posture.hostFirewallAvailable,
                       "which is why KS-9(1)'s iOS clause is implicit, and why "
                       + "networking.md §5.4's fetch split had to be corrected")
    }
}
