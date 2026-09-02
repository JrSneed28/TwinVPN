//  DeviceHarness.swift — the five harnesses the device-bound suite drives.
//
//  Authority: docs/implementation/ownership.md §10.3's wave-3 table and §10.5
//  rule 2; ADR-0012 §11.9's P09; ADR-0022 §11.4.
//
//  ===========================================================================
//  WHY THIS FILE EXISTS AT ALL
//  ===========================================================================
//
//  `LifecycleTests`, `LeakAndArmTests` and `ProfileRemovalAcceptanceTests` were
//  written against `ProviderHarness`, `DiagnosticsHarness`, `CaptureHarness`,
//  `NetworkHarness` and `TrafficGenerator`, and NONE of the five was declared
//  anywhere in the tree. "Written, not compiled" was hiding a stronger fact than
//  it stated: those suites did not merely lack a Darwin host, they lacked source
//  to compile. A test bundle that cannot be built is not a debt a reader can
//  see, because it looks exactly like one that builds and skips.
//
//  So each is a protocol with a default implementation that REFUSES, and two
//  conformers — one selected on a simulator, one on a device. The device suite
//  now compiles everywhere and skips only where its own `XCTSkipUnless` says it
//  must.
//
//  ===========================================================================
//  A REFUSAL, NEVER A PLACEHOLDER ANSWER
//  ===========================================================================
//
//  Every member below either throws or records an XCTest failure and returns a
//  value chosen to FAIL the assertion that asked for it. That is deliberate and
//  it is the point of the file: a harness that answered plausibly would turn
//  every device row green on a machine that exercised nothing, which is the
//  vacuous pass this repository has already shipped once.
//
//  The real implementations are a device farm's to supply — a provisioned
//  iPhone and iPad, a supervised device, a second peer, and a capture point on
//  the far side of the uplink (see `LifecycleTests.swift`'s header). Until one
//  exists, "unimplemented" is the honest answer and it is spelled loudly.
//
//  STATUS: written, not compiled on the build host.

import NetworkExtension
import XCTest

@testable import TwinVPNApp

/// What a harness reports when it cannot answer.
struct HarnessUnavailable: Error, CustomStringConvertible {
    let capability: String
    let why: String

    var description: String { "\(capability) is unavailable: \(why)" }
}

/// The half every harness shares: WHY it cannot answer, and how it says so.
protocol DeviceBoundHarness {
    /// One sentence naming what this lane is missing. Read by a human off a red
    /// run, so it names the missing INFRASTRUCTURE and not the missing code.
    static var unavailability: String { get }
}

extension DeviceBoundHarness {
    /// For a member that can throw.
    static func refuse(_ capability: String) -> HarnessUnavailable {
        HarnessUnavailable(capability: capability, why: unavailability)
    }

    /// For a member that cannot.
    ///
    /// Records a failure and hands back a value chosen so the caller's own
    /// assertion fails too. Both halves matter: the failure names the harness,
    /// and the returned value stops a caller that ignores it from passing.
    static func report<T>(_ capability: String,
                          _ failingValue: T,
                          file: StaticString = #filePath,
                          line: UInt = #line) -> T {
        XCTFail("\(capability) is unavailable: \(unavailability)", file: file, line: line)
        return failingValue
    }
}

// MARK: - the provider

/// Which ruleset the provider is forced into for a leak measurement.
enum HarnessRuleset {
    case blocked
    case protected
}

/// What `EnforcementLimits::ios()` declares, as the device suite reads it back.
struct DeclaredEnforcementLimits {
    let bootEnforcementAvailable: Bool
    let hostFirewallAvailable: Bool
}

/// Everything the suites ask of a running provider on a provisioned device.
protocol ProviderHarnessing: DeviceBoundHarness {
    static func startTunnel() async throws
    static func awaitProtection(timeout: TimeInterval) async throws
    static func waitForProtection(timeout: TimeInterval) async throws
    static func awaitManualProfileRemoval(timeout: TimeInterval) async throws
    static func currentVPNStatus() async -> NEVPNStatus
    static func osReportedStatus() async throws -> NEVPNStatus
    static func protectionAssertion() async -> ProtectionAssertion?
    static func recoveryAffordanceOffered() async -> Bool
    static func activeEnforcementClaims() async -> [String]
    static func isSupervisedWithAlwaysOn() async -> Bool
    static func forceTerminateExtension() async throws
    static func forceQuitContainingApp() async throws
    static func waitForOnDemandRearm(timeout: TimeInterval) async throws
    static func installedEnforcementGeneration() async throws -> UInt64
    static func residentBytes() throws -> UInt64
    static func suspendDevice(forSeconds: TimeInterval) async throws
    static func lastReportedResumeGapMilliseconds() async throws -> UInt64
    static func forceRuleset(_ ruleset: HarnessRuleset) async throws
    static func awaitIncludeAllNetworksInForce(timeout: TimeInterval) async throws -> UInt64
    static func declaredEnforcementLimits() async throws -> DeclaredEnforcementLimits
}

extension ProviderHarnessing {
    static func startTunnel() async throws { throw refuse("ProviderHarness.startTunnel") }

    static func awaitProtection(timeout: TimeInterval) async throws {
        throw refuse("ProviderHarness.awaitProtection")
    }

    static func waitForProtection(timeout: TimeInterval) async throws {
        throw refuse("ProviderHarness.waitForProtection")
    }

    static func awaitManualProfileRemoval(timeout: TimeInterval) async throws {
        throw refuse("ProviderHarness.awaitManualProfileRemoval")
    }

    /// `.disconnected` rather than `.invalid`, on purpose: the one caller
    /// asserts `.invalid`, so an unimplemented harness fails it.
    static func currentVPNStatus() async -> NEVPNStatus {
        report("ProviderHarness.currentVPNStatus", NEVPNStatus.disconnected)
    }

    static func osReportedStatus() async throws -> NEVPNStatus {
        throw refuse("ProviderHarness.osReportedStatus")
    }

    static func protectionAssertion() async -> ProtectionAssertion? {
        report("ProviderHarness.protectionAssertion", nil as ProtectionAssertion?)
    }

    static func recoveryAffordanceOffered() async -> Bool {
        report("ProviderHarness.recoveryAffordanceOffered", false)
    }

    /// A non-empty list, so the caller's `isEmpty` assertion fails as well.
    static func activeEnforcementClaims() async -> [String] {
        report("ProviderHarness.activeEnforcementClaims", ["<harness unimplemented>"])
    }

    static func isSupervisedWithAlwaysOn() async -> Bool {
        report("ProviderHarness.isSupervisedWithAlwaysOn", true)
    }

    static func forceTerminateExtension() async throws {
        throw refuse("ProviderHarness.forceTerminateExtension")
    }

    static func forceQuitContainingApp() async throws {
        throw refuse("ProviderHarness.forceQuitContainingApp")
    }

    static func waitForOnDemandRearm(timeout: TimeInterval) async throws {
        throw refuse("ProviderHarness.waitForOnDemandRearm")
    }

    static func installedEnforcementGeneration() async throws -> UInt64 {
        throw refuse("ProviderHarness.installedEnforcementGeneration")
    }

    static func residentBytes() throws -> UInt64 {
        throw refuse("ProviderHarness.residentBytes")
    }

    static func suspendDevice(forSeconds: TimeInterval) async throws {
        throw refuse("ProviderHarness.suspendDevice")
    }

    static func lastReportedResumeGapMilliseconds() async throws -> UInt64 {
        throw refuse("ProviderHarness.lastReportedResumeGapMilliseconds")
    }

    static func forceRuleset(_ ruleset: HarnessRuleset) async throws {
        throw refuse("ProviderHarness.forceRuleset")
    }

    static func awaitIncludeAllNetworksInForce(timeout: TimeInterval) async throws -> UInt64 {
        throw refuse("ProviderHarness.awaitIncludeAllNetworksInForce")
    }

    static func declaredEnforcementLimits() async throws -> DeclaredEnforcementLimits {
        throw refuse("ProviderHarness.declaredEnforcementLimits")
    }
}

enum SimulatorProviderHarness: ProviderHarnessing {
    static let unavailability =
        "the iOS Simulator uses the macOS kernel for networking, so no iOS "
        + "NetworkExtension provider runs in it and there is nothing to drive. "
        + "Every case that reaches this should have skipped on "
        + "DeviceCapabilities.isPhysicalDevice."
}

enum PhysicalDeviceProviderHarness: ProviderHarnessing {
    static let unavailability =
        "no device farm is wired up. This needs a provisioned iPhone and iPad "
        + "carrying packet-tunnel-provider, allow-vpn, the shared keychain "
        + "access group and the App Group, plus a supervised device for the "
        + "always-on rows and a second peer."
}

// MARK: - diagnostics

/// ADR-0019 §11.10 (a)'s "the rest of the app remains usable" half.
protocol DiagnosticsHarnessing: DeviceBoundHarness {
    static func assembleBundle() throws -> DiagnosticBundle
}

extension DiagnosticsHarnessing {
    static func assembleBundle() throws -> DiagnosticBundle {
        throw refuse("DiagnosticsHarness.assembleBundle")
    }
}

enum SimulatorDiagnosticsHarness: DiagnosticsHarnessing {
    static let unavailability =
        "a Tier-1 bundle is assembled, redacted and signed by core-lite against "
        + "the device's own store and DeviceKey, neither of which exists here."
}

enum PhysicalDeviceDiagnosticsHarness: DiagnosticsHarnessing {
    static let unavailability = PhysicalDeviceProviderHarness.unavailability
}

// MARK: - the capture point

/// What one capture window saw. Packets, as raw bytes, per family.
///
/// The suites only ever ask whether a set is empty, so nothing here parses a
/// packet: the classification is the CAPTURE POINT's, which is off-device, and
/// re-deriving it here would move the judgement back onto the machine under
/// test.
protocol PacketCaptureReport {
    func protectedPackets(family: Family) -> [Data]
    func plaintextDnsPackets(family: Family) -> [Data]
    func multicastDnsPackets() -> [Data]
}

/// A capture point on the far side of the device's uplink.
///
/// A leak is by definition a packet the device emitted that we did not see it
/// emit, so asking the device is asking the wrong process. `isReachable` is what
/// `LeakTests.setUp` skips on, and it is false here rather than true, because a
/// suite that believed it had an observer and did not would report silence as
/// safety.
protocol CaptureHarnessing: DeviceBoundHarness {
    static var isReachable: Bool { get }
    static func record(seconds: TimeInterval,
                       during body: () async throws -> Void) async throws -> PacketCaptureReport
}

extension CaptureHarnessing {
    static var isReachable: Bool { false }

    static func record(seconds: TimeInterval,
                       during body: () async throws -> Void) async throws -> PacketCaptureReport {
        throw refuse("CaptureHarness.record")
    }
}

enum SimulatorCaptureHarness: CaptureHarnessing {
    static let unavailability =
        "the simulator shares the host's network stack, so the only observation "
        + "point available is the runner itself — which measures the runner's "
        + "egress and not a device's."
}

enum PhysicalDeviceCaptureHarness: CaptureHarnessing {
    static let unavailability =
        "no capture point exists on the far side of the device uplink."
}

// MARK: - the network under the device

/// Which network the device is attached to for a measurement.
enum HarnessNetworkProfile {
    case wifiV4Only
    case wifiDualStack
}

/// Attaching, detaching and mutating the network the device sees.
///
/// ADR-0010 R6's case — a network that was v4-only when the tunnel came up and
/// gains a v6 default route afterwards — needs router advertisements turned on
/// under a live device, which is a property of the test network and not of the
/// device.
protocol NetworkHarnessing: DeviceBoundHarness {
    static func attach(_ profile: HarnessNetworkProfile) async throws
    static func detach(_ profile: HarnessNetworkProfile) async throws
    static func detachAll() async throws
    static func enableRouterAdvertisements() async throws
    /// The arrival instant, on the suspend-inclusive clock, in MICROseconds.
    static func attachAndStampArrival(_ profile: HarnessNetworkProfile) async throws -> UInt64
}

extension NetworkHarnessing {
    static func attach(_ profile: HarnessNetworkProfile) async throws {
        throw refuse("NetworkHarness.attach")
    }

    static func detach(_ profile: HarnessNetworkProfile) async throws {
        throw refuse("NetworkHarness.detach")
    }

    static func detachAll() async throws { throw refuse("NetworkHarness.detachAll") }

    static func enableRouterAdvertisements() async throws {
        throw refuse("NetworkHarness.enableRouterAdvertisements")
    }

    static func attachAndStampArrival(_ profile: HarnessNetworkProfile) async throws -> UInt64 {
        throw refuse("NetworkHarness.attachAndStampArrival")
    }
}

enum SimulatorNetworkHarness: NetworkHarnessing {
    static let unavailability =
        "a simulator has no network interface of its own to attach or detach; "
        + "it uses the host's."
}

enum PhysicalDeviceNetworkHarness: NetworkHarnessing {
    static let unavailability =
        "no controllable test network is wired up. P09 needs twenty real "
        + "attach cycles for a p95 to mean anything."
}

// MARK: - traffic

/// Traffic the device is made to attempt.
protocol TrafficGenerating: DeviceBoundHarness {
    static func attemptEgress(family: Family) async throws
    static func resolve(_ names: [String]) async throws
    static func saturate(forSeconds seconds: TimeInterval,
                         sampling sample: () throws -> Void) async throws
    static func roundTripCount() async throws -> Int
}

extension TrafficGenerating {
    static func attemptEgress(family: Family) async throws {
        throw refuse("TrafficGenerator.attemptEgress")
    }

    static func resolve(_ names: [String]) async throws {
        throw refuse("TrafficGenerator.resolve")
    }

    static func saturate(forSeconds seconds: TimeInterval,
                         sampling sample: () throws -> Void) async throws {
        throw refuse("TrafficGenerator.saturate")
    }

    static func roundTripCount() async throws -> Int {
        throw refuse("TrafficGenerator.roundTripCount")
    }
}

enum SimulatorTrafficGenerator: TrafficGenerating {
    static let unavailability =
        "traffic generated here leaves the macOS host, not a device, so nothing "
        + "it produces is evidence about this product's enforcement."
}

enum PhysicalDeviceTrafficGenerator: TrafficGenerating {
    static let unavailability = PhysicalDeviceProviderHarness.unavailability
}

// MARK: - which conformer this build uses

// A compile-time selection rather than a runtime one, and it agrees with
// `DeviceCapabilities.isPhysicalDevice` because both read the same condition.
// A runtime switch would let a simulator build carry the device implementation's
// symbols, which is how a lane starts "working" on the wrong machine.
#if targetEnvironment(simulator)
typealias ProviderHarness = SimulatorProviderHarness
typealias DiagnosticsHarness = SimulatorDiagnosticsHarness
typealias CaptureHarness = SimulatorCaptureHarness
typealias NetworkHarness = SimulatorNetworkHarness
typealias TrafficGenerator = SimulatorTrafficGenerator
#else
typealias ProviderHarness = PhysicalDeviceProviderHarness
typealias DiagnosticsHarness = PhysicalDeviceDiagnosticsHarness
typealias CaptureHarness = PhysicalDeviceCaptureHarness
typealias NetworkHarness = PhysicalDeviceNetworkHarness
typealias TrafficGenerator = PhysicalDeviceTrafficGenerator
#endif
