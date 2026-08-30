//  ProfileRemovalAcceptanceTests.swift — `IOS-PROFILE-REMOVAL-HONESTY`.
//
//  Authority: ADR-0012's durability table (iOS: "profile removal removes
//  enforcement") and §11.10 ("the ONLY unblock mechanism is removing the VPN
//  profile in Settings — this is not 'ours', not a command"); ADR-0015 §11.6
//  O-18 (an absent assertion is UNKNOWN, never PROTECTED); ADR-0019 §11.10 (a);
//  ADR-0022 LC-20.
//
//  ==========================================================================
//  THE ACCEPTANCE CRITERION THIS FILE CORRECTS
//  ==========================================================================
//  The wave's iOS row used to require that TwinVPN keep blocking after the user
//  removed the VPN configuration. **That criterion was wrong, and no
//  implementation could have satisfied it honestly.**
//
//  On ordinary consumer iOS, the VPN configuration IS TwinVPN's authority to
//  intercept network traffic. Removing it revokes that authority: the
//  NetworkExtension is torn down by the system, `NEVPNManager` no longer holds
//  a configuration, and there is no API — none, at any entitlement level
//  available outside MDM — by which an app continues to filter traffic
//  afterwards. A product that claimed to block after removal would be claiming
//  a capability the OS does not grant, and the only way to make a test of that
//  claim pass would be to make the test lie.
//
//  So the criterion is replaced by the strongest TRUE one, which is about
//  HONESTY rather than enforcement. After the user removes the configuration:
//
//    1. TwinVPN reports NOT PROTECTED,
//    2. a green shield is IMPOSSIBLE,
//    3. the connected state is CLEARED,
//    4. the user gets an ACTIONABLE protection-lost state,
//    5. TwinVPN makes NO CONTINUED KILL-SWITCH CLAIM.
//
//  Each of the five is a separate test below, because each fails separately and
//  a reader of a red run should be told which one.
//
//  ==========================================================================
//  WHAT THIS FILE DOES NOT ASSERT, AND MUST NOT
//  ==========================================================================
//  It makes NO egress claim. There is no leak-oracle phase here and there must
//  not be: after removal, traffic leaving the device is EXPECTED and correct,
//  and a SILENCE phase over that window would be a test asserting a promise the
//  product does not make.
//
//  The egress claims live in `IOS-NE-FAIL-CLOSED`, over the windows where
//  TwinVPN's authority is intact and the provider disappeared unexpectedly —
//  which is a completely different situation and the one the security invariant
//  is about.
//
//  ==========================================================================
//  SUPERVISED / MANAGED iOS IS A DIFFERENT AND STRONGER CRITERION
//  ==========================================================================
//  A supervised device under MDM can carry an Always-On VPN payload the user
//  cannot remove, and there the stronger criterion — no egress at all, ever,
//  outside the tunnel — is both true and testable. It is
//  `IOS-SUPERVISED-ALWAYS-ON`, it is NOT this, and
//  `theSupervisedCriterionIsNotSilentlySatisfiedByTheConsumerOne` below exists
//  to stop a consumer-mode pass from ever being read as that one.
//
//  STATUS: written, not compiled. Like every file in this directory it needs a
//  Darwin host with the provisioning profile; the first run should expect to
//  correct it.

import XCTest

@testable import TwinVPNApp

final class ProfileRemovalAcceptanceTests: XCTestCase {

    private var permission: VPNPermission!

    override func setUp() async throws {
        try await super.setUp()
        // A simulator has no NEVPNManager worth the name and no profile to
        // remove, so a pass there would be a pass about nothing.
        try XCTSkipUnless(DeviceCapabilities.isPhysicalDevice,
                          "profile removal is a device-only condition")
        permission = VPNPermission()
        try await startTunnelAndWaitForProtection()
        // The removal itself. No API removes our own profile — that is the
        // point of the criterion — so this is a human on a hand-held device or
        // an MDM command on a supervised one. `ProviderHarness` is what the
        // Corellium lane drives.
        try await ProviderHarness.awaitManualProfileRemoval(timeout: 300)
        await permission.reload()
    }

    /// 1. TwinVPN reports NOT PROTECTED.
    ///
    /// Read from the OS's own view of the configuration, not from our IPC:
    /// LC-20 requires the app to detect provider status from `NEVPNStatus`, and
    /// a status our own extension reported would be a status from a process the
    /// system has already torn down.
    func testTheAppReportsNotProtected() async throws {
        XCTAssertEqual(permission.state, .absent,
                       "the configuration is gone; any other ProfileState is the app believing a stale fact")
        XCTAssertEqual(permission.reasonCode, ReasonCode.vpnPermissionDenied,
                       "the condition must be NAMED with a registered reason code, not merely rendered")
    }

    /// 2. A GREEN SHIELD IS IMPOSSIBLE.
    ///
    /// Not "is not currently shown" — impossible. The indicator is green for
    /// exactly one input, and O-18 fixes which way an absence rounds. This
    /// asserts the input cannot occur, so that a future refactor that made the
    /// view default to `.protected` fails here rather than shipping.
    func testAGreenShieldIsImpossibleAfterRemoval() async throws {
        let snapshot = StatusRecord.read()
        // The only value that renders green.
        XCTAssertNotEqual(snapshot?.protection?.state, .protected,
                          "a protected assertion survived the removal of the authority that produced it")
        // And the stronger half: with no configuration there is no live
        // assertion at all, which O-18 renders UNKNOWN rather than green.
        let assertion = await currentProtectionAssertion()
        XCTAssertNil(assertion,
                     "an assertion produced after the profile was removed cannot have been produced by querying the enforcement point, because there is no longer one")
    }

    /// 3. The connected state is CLEARED.
    ///
    /// A UI that still says "connected" over a torn-down tunnel is the same
    /// defect as a green shield wearing different clothes.
    func testTheConnectedStateIsCleared() async throws {
        let status = await ProviderHarness.currentVPNStatus()
        XCTAssertEqual(status, .invalid,
                       "NEVPNStatus must be .invalid once the configuration is gone; .disconnected would mean a configuration still exists")
        XCTAssertFalse(permission.state == .installed || permission.state == .disabled,
                       "a removed profile is neither installed nor disabled")
    }

    /// 4. The user receives an ACTIONABLE protection-lost state.
    ///
    /// Actionable means two things and this asserts both: the app says WHAT
    /// happened with a registered code, and it offers the ONE recovery iOS
    /// permits — reinstalling the configuration. A dead end with a red shield
    /// is a report, not an actionable state.
    func testTheUserGetsAnActionableProtectionLostState() async throws {
        XCTAssertEqual(permission.reasonCode, ReasonCode.vpnPermissionDenied)
        // The rest of the app keeps working — ADR-0019 §11.10 (a): "no tunnel
        // is possible; the rest of the app remains usable".
        XCTAssertNoThrow(try DiagnosticsHarness.assembleBundle())
        // And the recovery is OFFERED rather than merely possible. The
        // distinction is the whole of "actionable": `VPNPermission.install` has
        // always existed, and a user who is never shown a way to reach it is in
        // the same position as one for whom it did not.
        XCTAssertTrue(await ProviderHarness.recoveryAffordanceOffered(),
                      "the only recovery iOS permits is reinstalling the configuration; an app that does not OFFER it has left the user with a red shield and nothing to do")
    }

    /// 5. TwinVPN makes NO CONTINUED KILL-SWITCH CLAIM.
    ///
    /// The failure this guards against is a sentence, not a state: a UI that
    /// keeps a "kill switch: on" row, or an assertion whose `blocked` state
    /// implies TwinVPN is still blocking, tells the user they are covered when
    /// the OS has revoked the authority to cover them. `blocked` is as wrong as
    /// `protected` here, and for the same reason — both assert that TwinVPN is
    /// still deciding what leaves the device.
    func testNoContinuedKillSwitchClaimIsMade() async throws {
        let snapshot = StatusRecord.read()
        if let state = snapshot?.protection?.state {
            XCTAssertEqual(state, .unprotected,
                           "after removal the only truthful assertion is `unprotected`. `blocked` would claim TwinVPN is still enforcing, which it cannot be — the authority to enforce is what the user removed.")
        }
        let claims = await ProviderHarness.activeEnforcementClaims()
        XCTAssertTrue(claims.isEmpty,
                      "TwinVPN still advertises enforcement it cannot perform: \(claims)")
    }

    /// The guard that keeps the consumer criterion from being read as the
    /// supervised one.
    ///
    /// If this device IS supervised with an Always-On payload, the five tests
    /// above are the WRONG acceptance for it: on such a device the profile
    /// cannot be removed by the user at all, and the stronger criterion —
    /// `IOS-SUPERVISED-ALWAYS-ON` — applies instead. Failing here is correct:
    /// it says "you ran the consumer criterion on a managed device", which is a
    /// configuration error and not a product defect.
    func testTheSupervisedCriterionIsNotSilentlySatisfiedByTheConsumerOne() async throws {
        let supervised = await ProviderHarness.isSupervisedWithAlwaysOn()
        XCTAssertFalse(supervised,
                       "this device is supervised with an Always-On VPN payload. IOS-PROFILE-REMOVAL-HONESTY is the CONSUMER criterion and must not be recorded as evidence for IOS-SUPERVISED-ALWAYS-ON, which requires zero egress rather than an honest report.")
    }

    // MARK: - helpers

    private func startTunnelAndWaitForProtection() async throws {
        try await ProviderHarness.startTunnel()
        try await ProviderHarness.awaitProtection(timeout: 60)
    }

    private func currentProtectionAssertion() async -> ProtectionAssertion? {
        await ProviderHarness.protectionAssertion()
    }
}
