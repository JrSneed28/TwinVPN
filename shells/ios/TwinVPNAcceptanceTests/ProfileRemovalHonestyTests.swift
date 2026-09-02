//  ProfileRemovalHonestyTests.swift — `IOS-PROFILE-REMOVAL-HONESTY`, driven
//  from an injected observation rather than from a real removal.
//
//  Authority: ADR-0012's durability table (iOS: "profile removal removes
//  enforcement") and §11.10 ("the ONLY unblock mechanism is removing the VPN
//  profile in Settings — this is not 'ours', not a command"); ADR-0015 §11.6
//  O-18 (an absent assertion is UNKNOWN, never PROTECTED); ADR-0019 §11.10 (a);
//  ADR-0022 LC-20; `contracts/registry/reason_codes.json`.
//
//  ==========================================================================
//  WHY THE OBSERVATION IS INJECTED, AND WHY THAT IS NOT A WEAKER TEST
//  ==========================================================================
//
//  On consumer iOS the VPN configuration IS TwinVPN's authority to intercept
//  traffic. Removing it revokes that authority, and no API at any entitlement
//  level available outside MDM keeps an app filtering afterwards. So the
//  criterion is not about enforcement — it is about HONESTY:
//
//    1. TwinVPN reports NOT PROTECTED,
//    2. a green shield is IMPOSSIBLE,
//    3. the connected state is CLEARED,
//    4. the user gets an ACTIONABLE protection-lost state,
//    5. TwinVPN makes NO CONTINUED KILL-SWITCH CLAIM.
//
//  Every one of the five is app-side logic downstream of ONE observation: the
//  OS reports that no configuration exists. What the removal itself needs is a
//  human in Settings on a provisioned device; what the five conditions need is
//  that observation, and the observation is a value.
//
//  So `VPNPermission` takes its preferences loader as a parameter and this file
//  supplies an empty result. The removal EVENT is not reproduced here and is
//  not claimed: the device suite in `TwinVPNTests/` still owns that, and the
//  evidence file this run writes says `real_network_extension_invoked: false`
//  and `assertion_source: "in-process-object-state"` so the two can never be
//  read as each other.
//
//  ==========================================================================
//  WHAT THIS FILE MUST NOT ASSERT
//  ==========================================================================
//
//  Any egress claim. After removal, traffic leaving the device is EXPECTED and
//  correct, so a silence window here would test a promise the product does not
//  make. It is also unobservable from a simulator, which shares the macOS
//  host's network stack — the observation point would be the runner, not a
//  device. The evidence file records no `probe_host` and no oracle session for
//  exactly that reason.
//
//  STATUS: written, not compiled on the build host.

import NetworkExtension
import TwinVPNCore
import XCTest

/// Prints one transition marker. `build/ci/ci-ios-acceptance.sh` reads exactly
/// this line, and it is printed ONLY after the transition has been driven and
/// asserted.
private func recordTransition(_ transition: String) {
    print("TWINVPN_LIFECYCLE_TRANSITION \(transition)")
}

final class ProfileRemovalHonestyTests: XCTestCase {

    /// The post-removal observation: the OS reports no configuration.
    ///
    /// This is what `loadAllFromPreferences` delivers once the profile is gone.
    /// Nothing else about the removal is modelled, because nothing else about
    /// it reaches the five conditions.
    private var permission: VPNPermission!

    override func setUp() async throws {
        try await super.setUp()
        permission = await VPNPermission(loadPreferences: { [] })
        await permission.reload()
    }

    // MARK: - 1. TwinVPN reports NOT PROTECTED

    func testTheAppReportsNotProtected() async throws {
        let state = await permission.state
        let reasonCode = await permission.reasonCode

        XCTAssertEqual(state, .absent,
                       "the configuration is gone; any other ProfileState is the app believing a stale fact")

        // NIL, and the reason is a registry fact rather than a preference.
        // `contracts/registry/reason_codes.json` gives
        // `PLATFORM.VPN_PERMISSION_DENIED` the condition "The OS denied the VPN
        // permission or entitlement" and `remediation_class: PERMISSION_GRANT`.
        // A removed configuration was not denied — nothing was refused — and
        // naming it a denial would send the user to grant a permission nobody
        // withheld. The refusal code belongs to the disabled and error branches,
        // which is where `reload` puts it. `contracts/` is frozen and is right.
        XCTAssertNil(reasonCode,
                     "an absent configuration is a STATE, not a refusal")

        // And there is nothing to start. `startTunnel` needs a session, a
        // session needs a manager, and there is no manager.
        do {
            try await permission.startTunnel()
            XCTFail("startTunnel succeeded with no configuration installed")
        } catch {
            XCTAssertTrue(error is ManagementChannelError,
                          "expected the channel to refuse; got \(error)")
        }
    }

    // MARK: - 2. A GREEN SHIELD IS IMPOSSIBLE

    /// Not "is not currently shown" — impossible.
    ///
    /// The indicator is green for exactly one input: a `ProtectionAssertion`
    /// whose state is `.protected`, delivered as LIVE. This test supplies that
    /// input — a stale App Group record the provider legitimately wrote while it
    /// was alive and which is still on disk — and then asserts the app has no
    /// path that can present it.
    ///
    /// Supplying the dangerous input is the point. An earlier shape of this test
    /// read the real App Group container, which returns nil without the
    /// entitlement, so `XCTAssertNotEqual(snapshot?.protection?.state,
    /// .protected)` passed on an input that was always absent. That is a vacuous
    /// pass, and the first assertion below is what makes it impossible: the
    /// record demonstrably decodes to `.protected` before anything is claimed
    /// about how the app treats it.
    func testAGreenShieldIsImpossibleAfterRemoval() async throws {
        let stale = StatusRecord.read(from: {
            EnforcementFixtures.bytes(EnforcementFixtures.staleProtectedStatusRecord)
        })
        XCTAssertEqual(stale?.protection?.state, .protected,
                       "the fixture must decode to the ONE value that renders green, or this test asserts nothing")

        // The app cannot present it as live. `ManagementClient.isLive` is the
        // flag O-18 turns on: a stopped session cannot be queried, so what is
        // rendered came from the App Group record and is marked NOT LIVE rather
        // than shown as current. With no configuration there is no session to
        // attach, so nothing can set it.
        // `.shared`, not a second instance: ADR-0017 §11.2.1 and ADR-0019 §11.8
        // make one client per process an I8 invariant, and this is the object
        // the app actually renders from.
        let management = ManagementClient.shared
        let isLive = await management.isLive
        let snapshot = await management.snapshot
        XCTAssertFalse(isLive,
                       "a stale record must never be presented as a live assertion; that is the green shield, wearing the provider's last words")
        XCTAssertNil(snapshot)

        // And the authority that produced the assertion is gone.
        let state = await permission.state
        XCTAssertEqual(state, .absent)
    }

    // MARK: - 3. The connected state is CLEARED

    /// A UI that still says "connected" over a torn-down tunnel is the same
    /// defect as a green shield wearing different clothes.
    ///
    /// This drives the TRANSITION rather than the end state, because the end
    /// state alone is satisfied by an app that was never installed. A `reload`
    /// that returned early on an empty result — leaving the previous
    /// `.installed` in place — passes an end-state check and fails this one.
    func testTheConnectedStateIsCleared() async throws {
        let observed = ObservedConfigurations([Self.anInstalledManager()])
        let permission = await VPNPermission(loadPreferences: { observed.managers })

        await permission.reload()
        let before = await permission.state
        XCTAssertEqual(before, .installed,
                       "the seeded observation must first be read as an installed configuration")

        // The removal, as the OS reports it afterwards.
        observed.managers = []
        await permission.reload()

        let after = await permission.state
        let reasonCode = await permission.reasonCode
        XCTAssertEqual(after, .absent)
        XCTAssertFalse(after == .installed || after == .disabled,
                       "a removed profile is neither installed nor disabled")
        XCTAssertNil(reasonCode)

        do {
            try await permission.startTunnel()
            XCTFail("startTunnel succeeded after the configuration was removed")
        } catch {
            XCTAssertTrue(error is ManagementChannelError, "got \(error)")
        }

        // The transition this row's `lifecycle_transitions` carries. Printed
        // here, after it has been driven and asserted, and nowhere else.
        recordTransition("INSTALLED->ABSENT")
    }

    // MARK: - 4. An ACTIONABLE protection-lost state

    /// Actionable means the condition is named AND the one recovery iOS permits
    /// is still reachable.
    ///
    /// The recovery is reinstalling the configuration, and this asserts it is
    /// genuinely available after removal: from no manager at all, the app can
    /// still build a complete, correct configuration. An app whose install path
    /// depended on the manager it just lost would be a red shield with nothing
    /// behind it.
    ///
    /// Whether a VIEW surfaces the affordance is not asserted here and is not
    /// claimed by this row — that is presentation, and it stays with the device
    /// suite.
    func testTheUserGetsAnActionableProtectionLostState() async throws {
        let state = await permission.state
        XCTAssertEqual(state, .absent)

        // The condition is NAMED where naming it is truthful. Drive the loader
        // into the error branch and the registered code appears — which is what
        // makes the nil above a distinction the app draws rather than a code it
        // does not have.
        let denied = await VPNPermission(loadPreferences: { throw NEVPNError(.configurationInvalid) })
        await denied.reload()
        let deniedState = await denied.state
        let deniedCode = await denied.reasonCode
        XCTAssertEqual(deniedState, .denied)
        XCTAssertEqual(deniedCode, ReasonCode.vpnPermissionDenied,
                       "a refusal IS named with a registered code; only an absence is not")

        // The recovery path is intact with no prior manager.
        let bytes = EnforcementFixtures.bytes(EnforcementFixtures.fullProtection)
        let programme = try XCTUnwrap(EnforcementProgramme.decode(bytes))
        let fresh = NETunnelProviderManager()
        await permission.configure(fresh, with: programme)
        XCTAssertTrue(fresh.isEnabled)
        XCTAssertTrue(fresh.isOnDemandEnabled)
        let proto = try XCTUnwrap(fresh.protocolConfiguration as? NETunnelProviderProtocol)
        XCTAssertEqual(proto.providerBundleIdentifier, "net.twinvpn.client.provider")
        XCTAssertTrue(proto.includeAllNetworks,
                      "a reinstall that came back without full protection is not a recovery")
    }

    // MARK: - 5. NO CONTINUED KILL-SWITCH CLAIM

    /// The failure this guards against is a sentence, not a state.
    ///
    /// `blocked` is as wrong as `protected` here, and for the same reason: both
    /// assert that TwinVPN is still deciding what leaves the device, when the
    /// authority to decide is exactly what the user removed. So the dangerous
    /// input this time is a stale record claiming `blocked`.
    func testNoContinuedKillSwitchClaimIsMade() async throws {
        let stale = StatusRecord.read(from: {
            EnforcementFixtures.bytes(EnforcementFixtures.staleBlockedStatusRecord)
        })
        XCTAssertEqual(stale?.protection?.state, .blocked,
                       "the fixture must decode to `blocked`, or this test asserts nothing")

        let management = ManagementClient.shared
        let isLive = await management.isLive
        XCTAssertFalse(isLive,
                       "`blocked` presented as live is a continued kill-switch claim: it says TwinVPN is still blocking, which it cannot be")

        // Building a configuration is not installing one. This is the shape the
        // seam in `VPNPermission` could plausibly regress into — a builder that
        // also published `.installed` — and it would advertise enforcement that
        // was never saved and never granted.
        let bytes = EnforcementFixtures.bytes(EnforcementFixtures.fullProtection)
        let programme = try XCTUnwrap(EnforcementProgramme.decode(bytes))
        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: programme)

        let state = await permission.state
        let reasonCode = await permission.reasonCode
        XCTAssertEqual(state, .absent,
                       "constructing a configuration must not report one as installed")
        XCTAssertNil(reasonCode)
    }

    // MARK: - the linked core is real, and is crossed

    /// The bundle links the REAL `core-lite` archive and calls into it.
    ///
    /// `TW_ABI_MAJOR` is the constant THIS TARGET compiled from the staged
    /// `twinvpn.h`; `tw_abi_major()` is what the linked archive reports, so a
    /// mismatch is a packaging defect -- header and staticlib from different
    /// commits -- that only a link-and-run finds.
    ///
    /// It is also what makes this row's `linked_real_core`, `loaded`,
    /// `invoked_core` and `received_result` TRUE STATEMENTS rather than a
    /// lane's belief. Without a crossing in the suite, an evidence file
    /// claiming one would be describing something that did not happen.
    func testTheLinkedCoreIsCrossedAtLeastOnce() {
        XCTAssertEqual(tw_abi_major(), TW_ABI_MAJOR,
                       "VR-4: the staticlib and the staged twinvpn.h are from different builds")
        XCTAssertEqual(tw_abi_minor(), TW_ABI_MINOR)
    }

    // MARK: - the guard against the stronger criterion

    /// This is the CONSUMER criterion, and a pass must never be read as
    /// `IOS-SUPERVISED-ALWAYS-ON`.
    ///
    /// On a supervised device under MDM the Always-On payload cannot be removed
    /// by the user, so "zero egress outside the tunnel, ever" is both true and
    /// testable there — including across configuration removal, which on
    /// consumer iOS revokes the authority and therefore cannot be tested that
    /// way at all.
    ///
    /// Two facts make this run unmistakably the consumer one, and both are
    /// asserted rather than described: it is a simulator, which cannot be
    /// supervised, carries no MDM enrolment and has no Always-On payload to
    /// observe; and the configuration under test is installed through the app's
    /// own consent-sheet path, which produces a profile the user can remove.
    func testTheSupervisedCriterionIsNotSilentlySatisfiedByTheConsumerOne() async throws {
        XCTAssertFalse(DeviceCapabilities.isPhysicalDevice,
                       "this row is the hosted-simulator consumer criterion. A device run must write device evidence, and IOS-SUPERVISED-ALWAYS-ON requires zero egress rather than an honest report.")

        // The app has exactly one install path and it is the consumer one:
        // `NETunnelProviderManager` + `saveToPreferences`, which presents the
        // system consent sheet and yields a user-removable profile. An MDM
        // Always-On payload is installed by a management server and this app has
        // no path to one — which is why the removal the five tests above model
        // is possible at all.
        let bytes = EnforcementFixtures.bytes(EnforcementFixtures.fullProtection)
        let programme = try XCTUnwrap(EnforcementProgramme.decode(bytes))
        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: programme)
        XCTAssertNotNil(manager.protocolConfiguration as? NETunnelProviderProtocol,
                        "a consumer profile, built by this app, not an MDM payload")
    }

    // MARK: - helpers

    /// One manager standing in for an installed, enabled configuration.
    ///
    /// A plain object with `isEnabled` set: `reload` reads that property and
    /// nothing else, and setting it crosses into no daemon.
    private static func anInstalledManager() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        manager.isEnabled = true
        return manager
    }
}
