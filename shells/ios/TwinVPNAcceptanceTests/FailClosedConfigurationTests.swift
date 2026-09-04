//  FailClosedConfigurationTests.swift — `IOS-FAILCLOSED-CONFIGURATION`.
//
//  Authority: ADR-0012 §11.6's iOS row, KS-4, KS-17, TN-5, W-24; ADR-0019
//  §11.10 (a); ADR-0022 §11.3's iOS on-demand row.
//
//  ==========================================================================
//  WHAT THIS CRITERION CLAIMS, AND WHAT IT DELIBERATELY DOES NOT
//  ==========================================================================
//
//  TwinVPN installs exactly the configuration that earns iOS's documented
//  fail-closed enforcement. That is the whole claim, and it is the whole part
//  of the guarantee TwinVPN controls.
//
//  The enforcement itself is Apple's obligation, stated in "Route additional
//  traffic through a personal VPN or packet tunnel provider": "When the VPN
//  transitions away from the connected state, the system drops network
//  traffic." Nothing here tests that. It cannot: the promise is scoped to a
//  configuration that EXISTS and IS ENABLED, and it is discharged inside the
//  Network Extension daemons, which do not run in the simulator at all — the
//  simulator is a group of processes running natively on macOS, using the
//  macOS kernel for its networking.
//
//  What IS testable, everywhere, is whether TwinVPN hands the OS the
//  configuration the promise is scoped to. Every `NEVPNProtocol`,
//  `NETunnelProviderProtocol`, `NETunnelProviderManager` and
//  `NEOnDemandRuleConnect` below is a plain Objective-C object whose properties
//  are set and read with no daemon involved. Only `saveToPreferences`,
//  `loadAllFromPreferences`, `removeFromPreferences` and `connection` cross,
//  and this file calls none of them.
//
//  **This is not `IOS-NE-FAIL-CLOSED`.** That row asserts no unauthorized
//  egress over a window in which the provider disappeared unexpectedly, it
//  needs a real device and an external observation point, and it stays open.
//  A pass here is evidence about a configuration, and the evidence file says
//  so: `execution: "simulator"`, `real_network_extension_invoked: false`,
//  `os_enforcement_exercised: false`, `assertion_source:
//  "in-process-object-state"`.
//
//  ==========================================================================
//  BOTH HALVES, BECAUSE A DRIFT BETWEEN THEM IS THE DEFECT
//  ==========================================================================
//
//  The app installs the profile (`VPNPermission`) because only an app can
//  present the system consent sheet. The extension maintains it afterwards
//  (`EnforcementInstaller`, driven by `BridgeHost.applyEnforcement`) because
//  only the extension holds the bytes Rust rendered. They are two
//  implementations of an overlapping write, and a drift between them reads as
//  an enforcement posture the app installed and the extension cannot find.
//  So both are driven from ONE decoded programme and compared field by field.
//
//  STATUS: written, not compiled on the build host. `make swift-parse` is a
//  syntax check; the first real run is on a `macos-26` simulator in CI.

import NetworkExtension
import TwinVPNCore
import XCTest

/// Prints one transition marker. `build/ci/ci-ios-acceptance.sh` reads exactly
/// this line out of the run's own output, and it is printed ONLY after the
/// transition has been driven and asserted — never unconditionally, which would
/// be the compile-only-job-dressed-as-a-lifecycle-job the gate rejects.
private func recordTransition(_ transition: String) {
    print("TWINVPN_LIFECYCLE_TRANSITION \(transition)")
}

final class FailClosedConfigurationTests: XCTestCase {

    private var permission: VPNPermission!
    private var programme: EnforcementProgramme!
    private var programmeBytes: Data!

    override func setUp() async throws {
        try await super.setUp()
        // No loader is ever called: nothing in this file reloads. The injected
        // one is here so that a future edit which does reload cannot silently
        // reach the OS.
        permission = await VPNPermission(loadPreferences: { [] })
        programmeBytes = EnforcementFixtures.bytes(EnforcementFixtures.fullProtection)
        programme = try XCTUnwrap(
            EnforcementProgramme.decode(programmeBytes),
            "the fixture must decode; if it does not, Swift and `enforce.rs` "
            + "disagree about the wire shape and that is the defect")
    }

    // MARK: - the protocol object the app builds

    /// The provider bundle identifier, verbatim.
    ///
    /// It is what tells the OS which extension to start, and a wrong value is a
    /// configuration that installs cleanly and never brings a tunnel up.
    func testTheProtocolNamesThePacketTunnelProvider() async throws {
        let proto = await permission.makeProtocolConfiguration(enforcement: programme)
        XCTAssertEqual(proto.providerBundleIdentifier, "net.twinvpn.client.provider",
                       "this must equal TwinVPNProvider's PRODUCT_BUNDLE_IDENTIFIER in project.yml")
    }

    /// `serverAddress` is the documented placeholder and not a routing decision.
    ///
    /// The settings object carries the real remote address once the tunnel is
    /// up. NE requires something non-empty at install time; a reader who found
    /// a hostname here would reasonably conclude this app routes by name.
    func testTheServerAddressIsThePlaceholderAndNotARoute() async throws {
        let proto = await permission.makeProtocolConfiguration(enforcement: programme)
        XCTAssertEqual(proto.serverAddress, "TwinVPN")
    }

    /// `includeAllNetworks` and `excludeLocalNetworks` are COPIED, not decided.
    ///
    /// `includeAllNetworks` is the field Apple's guarantee is written against:
    /// "the system routes network traffic through the tunnel except traffic for
    /// designated system services necessary for maintaining expected device
    /// functionality". CB-2 forbids this shell from deciding it, so the
    /// assertion is equality with the programme rather than with `true` — a
    /// build that hard-coded `true` would pass a `true` check and would be
    /// making the decision.
    func testTheFlagsAreCopiedFromTheProgramme() async throws {
        let proto = await permission.makeProtocolConfiguration(enforcement: programme)
        XCTAssertEqual(proto.includeAllNetworks, programme.includeAllNetworks)
        XCTAssertEqual(proto.excludeLocalNetworks, programme.excludeLocalNetworks)
        // And the fixture is a full-protection posture, so the values it carries
        // are the ones that matter. Without this the equality above holds just
        // as well for a programme that protects nothing.
        XCTAssertTrue(proto.includeAllNetworks,
                      "the full-protection fixture must produce includeAllNetworks = true")
    }

    /// `enforceRoutes` is NOT set, and that is a decision rather than an
    /// omission.
    ///
    /// Apple scopes `enforceRoutes` to the case where `includeAllNetworks` is
    /// false. `twinvpn_platform_ios::enforce` ties `include_all_networks` to
    /// `full_protection_required` for both rulesets, so a full-tunnel posture
    /// never reaches the case it governs. This assertion is what stops it being
    /// added "for completeness" by someone who reads the name and not the
    /// scope.
    func testEnforceRoutesIsNotAddedForCompleteness() async throws {
        let proto = await permission.makeProtocolConfiguration(enforcement: programme)
        XCTAssertFalse(proto.enforceRoutes,
                       "enforceRoutes applies when includeAllNetworks is false, which this product's postures never are")
    }

    // MARK: - the manager the app configures

    /// On-demand, enabled, and enabled at all.
    ///
    /// `isEnabled` is half of the precondition Apple's guarantee is scoped to —
    /// a configuration that exists but is switched off reads `.invalid` and
    /// enforces nothing.
    func testTheManagerIsEnabledAndOnDemandIsOn() async throws {
        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: programme)
        XCTAssertTrue(manager.isEnabled,
                      "a disabled configuration is not an enforcement point; NEVPNStatus reads .invalid for it")
        XCTAssertTrue(manager.isOnDemandEnabled)
        XCTAssertEqual(manager.localizedDescription, "TwinVPN")
        XCTAssertNotNil(manager.protocolConfiguration as? NETunnelProviderProtocol,
                        "an NEVPNProtocol that is not a NETunnelProviderProtocol names no provider")
    }

    /// EVERY on-demand rule is a Connect rule.
    ///
    /// ADR-0022 TN-5: `SSIDMatch` "MAY be used only in `NEOnDemandRuleConnect`
    /// rules (biasing toward connecting — safe under spoofed SSID) and MUST NOT
    /// be used in `Disconnect`/`Ignore` rules". Apple's own semantics are that
    /// each rule is evaluated in order and the first match applies, and that a
    /// Connect rule "starts the VPN connection whenever an application running
    /// on the system opens a network connection" — a trigger, never a barrier.
    func testEveryOnDemandRuleIsAConnectRule() async throws {
        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: programme)
        let rules = try XCTUnwrap(manager.onDemandRules)
        XCTAssertEqual(rules.count, 3, "the fixture carries three connect rules")
        for rule in rules {
            XCTAssertTrue(rule is NEOnDemandRuleConnect,
                          "a Disconnect or Ignore rule can leave the device unprotected on a network the system decided was fine: \(type(of: rule))")
        }
        // The interface matches and the SSID lists are copied through, in order.
        // Compared as whole arrays rather than by index, so a short list is one
        // failed assertion instead of a trap.
        let connects = rules.compactMap { $0 as? NEOnDemandRuleConnect }
        XCTAssertEqual(connects.count, rules.count)
        XCTAssertEqual(connects.map(\.interfaceTypeMatch), [.any, .wiFi, .cellular])
        XCTAssertEqual(connects.map { $0.ssidMatch ?? [] },
                       [[], ["twin-lab", "twin-lab-5g"], []])
        // An EMPTY `ssid_match` must leave the property nil rather than set an
        // empty-array match, which is a rule that matches no SSID at all.
        XCTAssertNil(connects.first?.ssidMatch)
    }

    /// A rule this build cannot express is SKIPPED, never translated.
    ///
    /// Rust's type can render nothing but `"connect"`, so any other `kind` means
    /// the bytes did not come from this build. Translating it into whatever it
    /// names would install a rule on the strength of an untrusted string.
    func testANonConnectRuleIsSkippedRatherThanTranslated() async throws {
        let bytes = EnforcementFixtures.bytes(EnforcementFixtures.carryingANonConnectRule)
        let hostile = try XCTUnwrap(EnforcementProgramme.decode(bytes))
        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: hostile)
        let rules = try XCTUnwrap(manager.onDemandRules)
        XCTAssertEqual(rules.count, 1,
                       "the disconnect and ignore rules must be dropped, leaving only the connect rule")
        XCTAssertTrue(rules.allSatisfy { $0 is NEOnDemandRuleConnect })
    }

    // MARK: - the two halves agree

    /// The app half and the extension half write the same posture.
    ///
    /// `VPNPermission.configure` is the app's; `EnforcementInstaller.apply` is
    /// the extension's, and it is what `BridgeHost.applyEnforcement` calls
    /// between its load and its save. They are separate implementations of an
    /// overlapping write — which is the point, because a single shared
    /// implementation would make this test a tautology — so the fields they
    /// both write are compared directly.
    func testTheExtensionHalfAgreesWithTheAppHalf() async throws {
        let appManager = NETunnelProviderManager()
        await permission.configure(appManager, with: programme)

        // The extension writes onto a profile the app already installed, so the
        // manager it is handed already carries a protocol object.
        let extensionManager = NETunnelProviderManager()
        extensionManager.protocolConfiguration = NETunnelProviderProtocol()
        EnforcementInstaller.apply(programme, verbatim: programmeBytes, to: extensionManager)

        let appProto = try XCTUnwrap(appManager.protocolConfiguration as? NETunnelProviderProtocol)
        let extProto = try XCTUnwrap(
            extensionManager.protocolConfiguration as? NETunnelProviderProtocol)

        XCTAssertEqual(appProto.includeAllNetworks, extProto.includeAllNetworks,
                       "the app and the extension disagree about includeAllNetworks, which is the posture the OS enforces")
        XCTAssertEqual(appProto.excludeLocalNetworks, extProto.excludeLocalNetworks)
        XCTAssertEqual(appManager.isOnDemandEnabled, extensionManager.isOnDemandEnabled)

        let appRules = try XCTUnwrap(appManager.onDemandRules).compactMap { $0 as? NEOnDemandRuleConnect }
        let extRules = try XCTUnwrap(extensionManager.onDemandRules).compactMap { $0 as? NEOnDemandRuleConnect }
        XCTAssertEqual(appRules.count, extRules.count)
        XCTAssertEqual(appRules.map(\.interfaceTypeMatch), extRules.map(\.interfaceTypeMatch))
        XCTAssertEqual(appRules.map { $0.ssidMatch ?? [] }, extRules.map { $0.ssidMatch ?? [] })
    }

    /// W-24: the read-back returns the bytes Rust rendered, verbatim.
    ///
    /// Not a re-serialisation of a decoded object. `installed_enforcement` is a
    /// QUERY of what is actually installed, and it survives a provider restart —
    /// which is what makes ADR-0022 LC-4 step 3 work after a jetsam kill, when
    /// the provider's own memory is gone. A round trip that re-encoded would let
    /// the read-back differ from the write for a reason nobody could see.
    func testTheProgrammeReadsBackVerbatim() throws {
        let manager = NETunnelProviderManager()
        manager.protocolConfiguration = NETunnelProviderProtocol()
        EnforcementInstaller.apply(programme, verbatim: programmeBytes, to: manager)
        XCTAssertEqual(EnforcementInstaller.installedProgrammeBytes(in: manager), programmeBytes,
                       "the read-back must be the ORIGINAL bytes; anything else makes W-24 a belief rather than a query")
    }

    /// No programme installed reads back as an absence, not as an empty one.
    ///
    /// Rust reads nil as `Ok(None)`. A zero-length `Data` would decode-fail and
    /// be reported as a suspected third-party profile, which is a different and
    /// much louder claim.
    func testAnUnwrittenConfigurationReadsBackAsNil() throws {
        let untouched = NETunnelProviderManager()
        untouched.protocolConfiguration = NETunnelProviderProtocol()
        XCTAssertNil(EnforcementInstaller.installedProgrammeBytes(in: untouched))
    }

    // MARK: - the app recognises the configuration it installed

    /// The other half of the precondition Apple's guarantee is scoped to.
    ///
    /// "When the VPN transitions away from the connected state, the system drops
    /// network traffic" holds for a configuration that EXISTS AND IS ENABLED.
    /// The tests above assert this app builds one; this asserts it then reads
    /// one back correctly — including the case that looks like protection and is
    /// not, a configuration that is present and switched off, which
    /// `NEVPNStatus` reports as `.invalid` exactly as a missing one does.
    ///
    /// Driven through the injected loader, so the two transitions are observed
    /// rather than assumed. The markers are printed after the assertion, and
    /// they are what `lifecycle_transitions` in this row's evidence carries.
    func testTheAppRecognisesAnEnabledConfigurationAsInstalled() async throws {
        let observed = ObservedConfigurations([])
        let permission = await VPNPermission(loadPreferences: { observed.managers })

        await permission.reload()
        let absent = await permission.state
        XCTAssertEqual(absent, .absent)

        let manager = NETunnelProviderManager()
        await permission.configure(manager, with: programme)
        observed.managers = [manager]
        await permission.reload()
        let installed = await permission.state
        XCTAssertEqual(installed, .installed,
                       "a present, enabled configuration is the enforcement point Apple's guarantee is scoped to")
        recordTransition("ABSENT->INSTALLED")

        // Switched off in Settings. The profile is still there and enforcing
        // nothing, which ADR-0012's durability table calls the softer sibling of
        // removal — and it must NOT read as installed.
        manager.isEnabled = false
        await permission.reload()
        let disabled = await permission.state
        let reasonCode = await permission.reasonCode
        XCTAssertEqual(disabled, .disabled)
        XCTAssertEqual(reasonCode, ReasonCode.vpnPermissionDenied,
                       "a configuration the user switched off IS a withheld grant, and the registry code is the right name for it")
        recordTransition("INSTALLED->DISABLED")
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

    // MARK: - what this run is NOT

    /// The row this file produces is a SIMULATOR row.
    ///
    /// Asserted in-process as well as attested in the evidence file, so that a
    /// build which somehow ran this on a device fails here rather than writing
    /// `execution: "simulator"` about a device.
    func testThisRunIsASimulatorRunAndSaysSo() throws {
        XCTAssertFalse(DeviceCapabilities.isPhysicalDevice,
                       "IOS-FAILCLOSED-CONFIGURATION is the hosted-simulator row. On a device the evidence this run writes would be false about the machine that produced it, and IOS-NE-FAIL-CLOSED is the row that wants a device.")
    }
}
