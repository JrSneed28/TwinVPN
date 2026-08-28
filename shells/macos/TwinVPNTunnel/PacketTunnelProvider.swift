//
//  PacketTunnelProvider.swift
//  com.twinvpn.app.sysext
//
//  Authority: ADR-0016 §11.2's macOS component row (`com.twinvpn.sysext`, NE
//  system extension, root) and §12.6 / MX-1; ADR-0018 CB-1, CB-2, CB-4, PB-1,
//  F-7; ADR-0022 (lifecycle, background execution, sleep/wake, LC-17a);
//  ADR-0012 §11.6's macOS row; `docs/application-architecture.md` §6 FC-1.
//
//  ============================================================================
//  CB-2: THERE IS NO DECISION IN THIS FILE.
//
//  Every method below is one of: marshal a value across the bridge, hand a
//  document NE gave us to the core, hand a document the core computed to NE, or
//  start/stop a task. There is no branch anywhere in this file whose condition
//  is a `ConnectionState`, a `reason_code` class, a policy verdict, a candidate
//  priority, a timer expiry, or a version comparison.
//
//  The branches that DO exist are on:
//    - whether an OS call succeeded (`TVB_OK` vs `TVB_ERR`) — a shape, not a
//      meaning;
//    - whether a task has already been started — the shell's own bookkeeping;
//    - whether a settings document arrived within a poll interval — a
//      liveness fact about a C call, not about the product.
//
//  ============================================================================
//  ADR-0022: WHAT `wake()` MUST NOT DO
//
//  "A resume must not render a confident, stale green." So `wake()` reports the
//  fact and returns. It does not:
//
//    - re-apply the last settings it saw,
//    - probe the path,
//    - assert that the tunnel is still up,
//    - update any indicator.
//
//  The core decides what a resume means, using the suspend-INCLUSIVE clock the
//  platform adapter supplies (ADR-0022 LC-8). A provider that re-asserted here
//  would be answering a question the core is the only thing equipped to answer,
//  and it would answer it with information that is by definition stale.
//
//  ============================================================================
//  F-7: PANIC CONTAINMENT IS THE OTHER SIDE'S
//
//  `catch_unwind` at the FFI boundary is the Rust side's obligation, which is
//  why `panic = "unwind"` is in every shipped profile. This file must not assume
//  a Rust call can trap safely: it handles a `TVB_ERR` from EVERY call, and
//  there is no `try!` and no `try?` that discards an error in this file.
//
//  ============================================================================
//  X-7 / PS-22: THIS PROCESS IS THE AUTHORITY
//
//  Until wave 3 the core, the keys and the management interface lived in a
//  `LaunchDaemon` called `twinvpnd` and this provider was a packet pump.
//  ADR-0016 §11.2's amendment PS-22 moves all three here, and the argument is
//  physical rather than editorial: `packetFlow` — the property four lines of
//  this file use — exists only inside this process, the core owns the datapath,
//  and §11.16 (a) / S-47 permit exactly ONE process to hold a mutating core
//  handle.
//
//  What that changes in this file is small and deliberate, which is the point:
//
//    - `tvb_ext_start` now runs ADR-0016 §11.6's whole start sequence behind
//      the ABI, so a refusal here means "the authority could not arm" rather
//      than "an object could not be allocated". PS-18 makes that a refused
//      `startTunnel`, which is what it already was.
//    - a `ManagementListener` is started after the handle exists and stopped
//      before it goes away.
//
//  There is still no decision in this file. The listener marshals; the sequence
//  is the core's.
//
//  ============================================================================
//  FC-1 §6 instance 5
//
//  The EXTENSION fetches the signed contract; core-lite parses and verifies it.
//  That happens entirely behind `tvb_ext_start` — inside the Rust core hosted in
//  this process. No Swift code here fetches anything, and the containing app has
//  no code path that could: putting the app on the recovery path would make a
//  GUI a rung of the fail-closed ladder.
//

import Foundation
import NetworkExtension

/// The packet-tunnel provider.
///
/// `@objc(TwinVPNPacketTunnelProvider)` is not decoration: `Info.plist`'s
/// `NEProviderClasses` names the class as an Objective-C runtime string, and
/// Swift's default mangled name is not resolvable by NetworkExtension. Without
/// the explicit name the provider never starts, and the failure is silent.
@objc(TwinVPNPacketTunnelProvider)
final class TwinVPNPacketTunnelProvider: NEPacketTunnelProvider {

    private var bridge: CoreBridge?
    private var packets: PacketLoop?
    private var settingsTask: Task<Void, Never>?

    /// The MI's XPC carriage (PS-22, ADR-0017 §11.2's macOS row).
    ///
    /// Started only once `tvb_ext_start` has returned a handle: a Mach service
    /// that exists but can only refuse is the shape MI-A3 rejects socket
    /// activation for. The `AF_UNIX` carriage is bound inside `tvb_ext_start`
    /// itself, on the Rust side, and is not this file's to manage.
    private var management: ManagementListener?

    /// The correlation chain for this provider's lifetime. `startTunnel` is an
    /// ORIGIN — the OS initiated it and there is no parent id to carry — so a
    /// fresh chain is minted here and every later call is a child of it.
    private var lifetime = Correlation.origin()

    /// How long the settings task blocks before checking for cancellation.
    /// A poll granularity, not a deadline. See `PacketLoop.outboundPollMillis`.
    private static let settingsPollMillis: UInt32 = 500

    // MARK: - startTunnel

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        lifetime = Correlation.origin()
        let correlation = lifetime
        TunnelLog.provider.info("provider.start.begin", correlation)

        do {
            // VR-4: checked before any capability is touched.
            try CoreBridge.assertABI()

            // The configuration document. OPAQUE to this file: it is produced by
            // the containing app, stored in the NETunnelProviderProtocol, and
            // passed through byte for byte. This file does not read a key of it,
            // does not validate it, and supplies no default for anything missing
            // — every one of those would be a decision, and the core is where
            // `limits.json` validation lives.
            let configBytes = try Self.configurationBytes(
                protocolConfiguration: protocolConfiguration,
                options: options)

            // Behind this call: §11.6's start sequence — the boot artifact, the
            // privilege posture, the three clocks, the runtime's I/O driver, the
            // capability probe, the enforcement READ-BACK (W-24), the vault, the
            // core (ABI-checked, VR-4) and the MI socket endpoint. A refusal
            // arrives here as a `BridgeError` carrying the step's registered
            // code, and this file does not read it — CB-2.
            let bridge = try CoreBridge(configJSON: configBytes, correlation: correlation)
            self.bridge = bridge

            // The management interface's second carriage. After the handle
            // exists, and never before.
            let management = ManagementListener(bridge: bridge)
            management.start(correlation: correlation)
            self.management = management

            let packets = PacketLoop(bridge: bridge, flow: packetFlow)
            self.packets = packets

            // The settings task owns the first apply, so `startTunnel`'s
            // completion handler fires only once the core has produced a
            // settings document AND NE has accepted it. Completing earlier
            // would report a running tunnel with no addresses and no routes —
            // `docs/networking.md` §2.3's partial-application leak window, in
            // the one place NE lets a provider create it.
            settingsTask = Task { [weak self] in
                await self?.runSettings(
                    bridge: bridge,
                    packets: packets,
                    firstApply: completionHandler,
                    correlation: correlation)
            }
        } catch let error as BridgeError {
            TunnelLog.provider.error("provider.start.failed",
                                     envelope: error.envelopeText, correlation)
            completionHandler(error)
        } catch {
            TunnelLog.provider.error("provider.start.failed", correlation)
            completionHandler(error)
        }
    }

    /// Pulls the opaque configuration document out of the NE profile.
    ///
    /// `options` takes precedence when present, because that is how a manual
    /// `startVPNTunnel(options:)` supplies a one-shot configuration; otherwise
    /// the stored `providerConfiguration` is used, which is what an on-demand
    /// start has.
    ///
    /// **This is not a decision.** Both paths yield the same opaque bytes to the
    /// same core; the precedence is about WHERE the document was found, not
    /// about what it says.
    private static func configurationBytes(
        protocolConfiguration: NEVPNProtocol,
        options: [String: NSObject]?
    ) throws -> [UInt8] {
        let key = "twinvpn.config"
        if let data = options?[key] as? NSData {
            return [UInt8](Data(referencing: data))
        }
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let raw = tunnelProtocol.providerConfiguration?[key],
              let data = raw as? Data
        else {
            throw BridgeUnavailable(call: "providerConfiguration")
        }
        return [UInt8](data)
    }

    // MARK: - The settings task

    /// Applies every settings document the core produces, in order, for the life
    /// of the tunnel.
    ///
    /// A LOOP rather than a one-shot apply, because the core re-computes
    /// settings on a network change, a contract change and a resume, and NE's
    /// model is that a provider re-applies the whole object each time.
    /// `setTunnelNetworkSettings` replaces rather than merges, which is the
    /// all-or-nothing shape `NetworkConfig::apply` already has on the Rust side.
    private func runSettings(
        bridge: CoreBridge,
        packets: PacketLoop,
        firstApply: @escaping (Error?) -> Void,
        correlation: Correlation
    ) async {
        var firstApplyPending = true

        while !Task.isCancelled {
            let document: [UInt8]?
            do {
                document = try bridge.nextSettings(
                    timeoutMillis: Self.settingsPollMillis, correlation: correlation)
            } catch let error as BridgeError {
                TunnelLog.settings.error("settings.fetch.failed",
                                         envelope: error.envelopeText, correlation)
                if firstApplyPending { firstApplyPending = false; firstApply(error) }
                break
            } catch {
                TunnelLog.settings.error("settings.fetch.unavailable", correlation)
                if firstApplyPending { firstApplyPending = false; firstApply(error) }
                break
            }

            guard let document else { continue }   // timeout: nothing new

            let step = correlation.child()
            do {
                let parsed = try TunnelSettingsBuilder.decode(document)
                let settings = TunnelSettingsBuilder.build(parsed)
                try await setTunnelNetworkSettingsAsync(settings)
                TunnelLog.settings.info("settings.applied", step)

                if firstApplyPending {
                    firstApplyPending = false
                    // The datapath starts only after the first settings object
                    // is in force. An interface that carries packets before its
                    // addresses and routes are installed is the same leak window
                    // `create_interface` is "created DOWN" to avoid.
                    await packets.start(correlation: correlation)
                    firstApply(nil)
                }
            } catch let error as SettingsDecodeFailure {
                // A document that does not decode is NOT partially applied. The
                // previous settings stay in force, which is the fail-closed
                // direction: the tunnel keeps the routes and resolver it had
                // rather than losing them because a later document was malformed.
                TunnelLog.settings.error("settings.decode.failed",
                                         envelope: error.detail, step)
                if firstApplyPending { firstApplyPending = false; firstApply(error) }
                break
            } catch {
                TunnelLog.settings.error("settings.apply.failed", step)
                if firstApplyPending { firstApplyPending = false; firstApply(error) }
                break
            }
        }
        TunnelLog.settings.info("settings.task.exited", correlation)
    }

    private func setTunnelNetworkSettingsAsync(
        _ settings: NEPacketTunnelNetworkSettings
    ) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            self.setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }
    }

    // MARK: - stopTunnel

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        let correlation = lifetime.child()
        TunnelLog.provider.info("provider.stop.begin", correlation)

        settingsTask?.cancel()
        settingsTask = nil

        // The MI goes first. A client that reaches the service after the
        // datapath has stopped would be answered by an authority in the middle
        // of tearing itself down, and §11.7's "never a silent close" is easier
        // to keep by not accepting than by racing.
        management?.stop(correlation: correlation)
        management = nil

        let packets = self.packets
        let bridge = self.bridge
        self.packets = nil

        Task {
            await packets?.stop(correlation: correlation)

            // The stop reason is an OS fact, marshalled across unchanged. This
            // file does not interpret it — it does not decide that a
            // `.userInitiated` stop means something different from an
            // `.providerFailed` one, because that is the core's judgement.
            do {
                try bridge?.stop(reason: Int32(reason.rawValue), correlation: correlation)
            } catch let error as BridgeError {
                TunnelLog.provider.error("provider.stop.reported.failed",
                                         envelope: error.envelopeText, correlation)
            } catch {
                TunnelLog.provider.error("provider.stop.reported.failed", correlation)
            }

            // Releasing the last reference runs `deinit`, which is the only
            // `tvb_ext_free` in the shell. Deliberately AFTER the loops have
            // stopped: freeing while a blocked `next_outbound` is in flight
            // would be a use-after-free on the other side of the ABI.
            self.bridge = nil

            // CB-6, restated for macOS: the pf anchor is NOT torn down here.
            // "The OS holds it precisely so that the core going away does not
            // drop protection." Nothing on this path touches pf, and the anchor
            // outlives the provider by design — which is also why
            // `com.twinvpn.ksd` exists as a separate component.
            TunnelLog.provider.info("provider.stop.done", correlation)
            completionHandler()
        }
    }

    // MARK: - handleAppMessage

    /// ADR-0017: an opaque MI envelope in, an opaque MI envelope out.
    ///
    /// MI-20 — "one contract, two carriages, never two contracts" — is why this
    /// method decodes neither side. The envelope's schema lives in
    /// `twinvpn-mgmt`, shared by the authority and the CLI; a Swift copy of it
    /// would be the second contract.
    ///
    /// **The Rust side refuses this hop**, and after X-7 the reason is not that
    /// the MI is absent — it is served on the Mach service and on the socket.
    /// `sendProviderMessage` carries no peer credential, MI-A1 requires one from
    /// the kernel on the connected channel, and MI-A5 makes an unverifiable
    /// identity a refusal. The envelope that comes back says
    /// `MGMT.PRINCIPAL_UNVERIFIABLE`, and this method hands it on unread.
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        let correlation = lifetime.child()
        guard let bridge else {
            // No bridge: the tunnel is not running. A nil response is NE's own
            // "no answer"; this file does not synthesise an error envelope,
            // because an envelope is an ADR-0015 §11.2 document and only the
            // core produces one.
            TunnelLog.provider.error("provider.app_message.no_bridge", correlation)
            completionHandler?(nil)
            return
        }
        Task {
            do {
                let response = try bridge.appMessage([UInt8](messageData), correlation: correlation)
                completionHandler?(Data(response))
            } catch let error as BridgeError {
                // The core's own envelope is handed back verbatim. This is the
                // one place a failure has a body the caller can read, and it is
                // the core's body, not one this file wrote.
                completionHandler?(Data(error.envelope))
            } catch {
                completionHandler?(nil)
            }
        }
    }

    // MARK: - sleep / wake  (ADR-0022)

    /// The system is about to sleep.
    ///
    /// NE gives a provider a short, unspecified window here. This method reports
    /// the fact and calls the completion handler as soon as the report is made:
    /// holding the handler to "prepare" for sleep would be the shell scheduling
    /// work whose deadline it does not own.
    override func sleep(completionHandler: @escaping () -> Void) {
        let correlation = lifetime.child()
        TunnelLog.provider.info("provider.sleep", correlation)
        do {
            try bridge?.reportSleep(correlation: correlation)
        } catch let error as BridgeError {
            TunnelLog.provider.error("provider.sleep.report.failed",
                                     envelope: error.envelopeText, correlation)
        } catch {
            TunnelLog.provider.error("provider.sleep.report.failed", correlation)
        }
        completionHandler()
    }

    /// The system has woken.
    ///
    /// **Reports, and nothing else.** See the file header: ADR-0022's rule is
    /// that a resume must not render a confident, stale green. There is
    /// deliberately no re-apply, no probe, no assertion and no indicator update
    /// in this method. The core decides what the gap means, on the
    /// suspend-inclusive clock; the settings loop is still running and will
    /// apply whatever the core computes next, through the same path every other
    /// settings change takes.
    override func wake() {
        let correlation = lifetime.child()
        TunnelLog.provider.info("provider.wake", correlation)
        do {
            try bridge?.reportWake(correlation: correlation)
        } catch let error as BridgeError {
            TunnelLog.provider.error("provider.wake.report.failed",
                                     envelope: error.envelopeText, correlation)
        } catch {
            TunnelLog.provider.error("provider.wake.report.failed", correlation)
        }
    }

    // MARK: - Network change

    /// NE signals a path change by re-invoking the provider's
    /// `reasserting`/path observation. UNVERIFIED: on macOS the documented hook
    /// for a packet-tunnel provider is KVO on `NWPathMonitor` or on
    /// `NEProvider.defaultPath`, the latter deprecated. This domain has not
    /// confirmed which is current.
    ///
    /// Whichever it is, the handling is this: REPORT the fact. ADR-0018 F-9 is
    /// explicit that the subscription is realised as "an inbound command
    /// submission rather than a literal outbound function pointer", and this is
    /// the Swift side of that — `tvb_ext_network_changed` is the submission.
    /// The shell does not decide that a path change means a reconnect.
    func reportNetworkChanged() {
        let correlation = lifetime.child()
        do {
            try bridge?.reportNetworkChanged(correlation: correlation)
            TunnelLog.provider.info("provider.network_changed", correlation)
        } catch let error as BridgeError {
            TunnelLog.provider.error("provider.network_changed.failed",
                                     envelope: error.envelopeText, correlation)
        } catch {
            TunnelLog.provider.error("provider.network_changed.failed", correlation)
        }
    }
}
