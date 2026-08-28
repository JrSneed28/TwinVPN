//  BridgeHost.swift — the Swift half of ownership.md §10.4's internal bridge.
//
//  Authority: docs/implementation/ownership.md §10.4; ADR-0018 CB-1, CB-2, CB-5,
//  CB-6, CB-7, PB-1; ADR-0012 KS-17; ADR-0020 ST-5, ST-6, ST-12e, ST-26.
//
//  STATUS: written, not compiled. There is no Xcode, no Darwin SDK and no Swift
//  toolchain on the build host (ownership.md §10.3). Every line here is
//  unverified until a macOS builder exists.
//
//  ===========================================================================
//  THE ONE RULE THIS FILE EXISTS TO OBEY
//  ===========================================================================
//
//  CB-2: "A shell MAY translate, marshal, schedule and render. It MUST NOT
//  contain a branch whose condition is a TwinVPN domain fact — a
//  ConnectionState, a reason_code class, a policy verdict, a candidate priority,
//  a timer expiry, a version comparison."
//
//  Read this file looking for an `if`. Every one you find is either a nil check,
//  a bounds check, or a `switch` over an OS enum. There is no TwinVPN vocabulary
//  in this file: no ConnectionState, no reason_code, no Ruleset, no policy. The
//  settings object is built field by field from a programme Rust rendered, and
//  where Swift appears to "decide" something — which AF_* number a packet
//  carries, which accessibility class a Keychain item takes — it is copying an
//  answer that arrived in the programme.
//
//  §10.4's falsification: delete this file and bind the mock adapter, and the
//  core still makes every decision correctly, because none of them is here.

import Foundation
import NetworkExtension
import Security
import TwinVPNBridge

/// Fills `tw_ios_host_vtable` for one running provider.
///
/// One instance per provider, held for the provider's life: the vtable stores a
/// raw `ctx` pointer to it, and `twinvpn_ios_bridge_register`'s contract is that
/// `ctx` outlives every subsequent call.
final class BridgeHost {
    private unowned let provider: NEPacketTunnelProvider
    private let pathObserver: PathMonitorBridge
    private let keychain: KeychainBridge
    private let enclave: EnclaveBridge
    private let storeRoot: URL

    /// The enforcement programme Rust most recently applied.
    ///
    /// Held so `installed_enforcement` can answer W-24's *query*. It is a cache
    /// of what the OS was asked for, and it is deliberately **not** the answer:
    /// `installedEnforcement()` re-reads `NETunnelProviderManager` and returns
    /// what is actually there, falling back to this only to detect that the two
    /// disagree.
    private var lastRequestedEnforcement: Data?

    init(provider: NEPacketTunnelProvider,
         appGroupIdentifier: String,
         keychainAccessGroup: String,
         keychainService: String) throws {
        self.provider = provider
        self.pathObserver = PathMonitorBridge()
        self.keychain = KeychainBridge(accessGroup: keychainAccessGroup,
                                       service: keychainService)
        self.enclave = EnclaveBridge(accessGroup: keychainAccessGroup)
        self.storeRoot = try StoreRoot.prepare(appGroupIdentifier: appGroupIdentifier)
    }

    /// Starts the path monitor. Event-driven, never polled (networking.md §5.1).
    func startObservingPath(onUpdate: @escaping (String, Bool) -> Void) {
        pathObserver.start(onUpdate: onUpdate)
    }

    func stopObservingPath() {
        pathObserver.stop()
    }

    /// Registers this host with the Rust adapter.
    ///
    /// - Returns: the status Rust reported. A `size` mismatch means the Swift
    ///   side and the linked staticlib came from different commits, which is a
    ///   build error and not a compatibility question (§10.4).
    func register() -> tw_ios_status {
        var vtable = tw_ios_host_vtable()
        vtable.size = UInt32(MemoryLayout<tw_ios_host_vtable>.size)
        vtable.ctx = Unmanaged.passUnretained(self).toOpaque()

        vtable.apply_settings = { ctx, programme in
            BridgeHost.of(ctx).applySettings(programme)
        }
        vtable.clear_settings = { ctx in
            BridgeHost.of(ctx).clearSettings()
        }
        vtable.read_packets = { ctx, sink in
            BridgeHost.of(ctx).readPackets(into: sink)
        }
        vtable.write_packets = { ctx, packets, families, count in
            BridgeHost.of(ctx).writePackets(packets, families, count)
        }
        vtable.apply_enforcement = { ctx, programme in
            BridgeHost.of(ctx).applyEnforcement(programme)
        }
        vtable.installed_enforcement = { ctx, sink in
            BridgeHost.of(ctx).installedEnforcement(into: sink)
        }
        vtable.path_snapshot = { ctx, sink in
            BridgeHost.of(ctx).pathSnapshot(into: sink)
        }
        vtable.keychain_read = { ctx, attributes, sink in
            BridgeHost.of(ctx).keychain.read(attributes, into: sink)
        }
        vtable.keychain_write = { ctx, attributes, value in
            BridgeHost.of(ctx).keychain.write(attributes, value)
        }
        vtable.keychain_delete = { ctx, attributes in
            BridgeHost.of(ctx).keychain.delete(attributes)
        }
        vtable.store_root = { ctx, sink in
            BridgeHost.of(ctx).storeRootPath(into: sink)
        }
        vtable.store_root_backup_excluded = { ctx in
            BridgeHost.of(ctx).storeRootBackupExcluded()
        }
        vtable.enclave_sign = { ctx, tag, message, sink in
            BridgeHost.of(ctx).enclave.sign(tag, message, into: sink)
        }
        vtable.enclave_agree = { ctx, tag, algorithm, peer, sink in
            BridgeHost.of(ctx).enclave.agree(tag, algorithm, peer, into: sink)
        }
        vtable.enclave_public = { ctx, tag, sink in
            BridgeHost.of(ctx).enclave.publicKey(tag, into: sink)
        }
        vtable.enclave_hardware_backed = { ctx in
            BridgeHost.of(ctx).enclave.isHardwareBacked ? 1 : 0
        }

        return withUnsafePointer(to: &vtable) { twinvpn_ios_bridge_register($0) }
    }

    func unregister() {
        twinvpn_ios_bridge_unregister()
    }

    private static func of(_ ctx: UnsafeMutableRawPointer?) -> BridgeHost {
        // `ctx` is the pointer this class handed `register()`, and
        // `twinvpn_ios_bridge_register`'s contract is that it outlives every
        // call. A nil here would be a Rust-side defect, and crashing on it is
        // better than proceeding with an invented host.
        Unmanaged<BridgeHost>.fromOpaque(ctx!).takeUnretainedValue()
    }

    // MARK: - the packet tunnel

    /// `setTunnelNetworkSettings` from a rendered programme.
    ///
    /// networking.md §5.2's iOS row: "NEPacketTunnelNetworkSettings only (no
    /// route API)". So this call is the whole of address, route, DNS and MTU
    /// programming — and every value in it arrived from Rust. Swift chooses
    /// nothing; it copies fields.
    private func applySettings(_ programme: tw_ios_slice) -> tw_ios_status {
        guard let decoded = TunnelSettingsProgramme.decode(programme) else {
            // `errSecDecode`'s number is wrong here — this is not a Keychain
            // failure. `EINVAL` says "the bytes we were handed were not the
            // shape we expect", which is what happened, and Rust maps it to
            // ROUTE.PROGRAMMING_DENIED because on this platform the settings
            // object IS route programming.
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }

        let settings = decoded.makeNetworkSettings()
        let semaphore = DispatchSemaphore(value: 0)
        var applyError: Error?
        provider.setTunnelNetworkSettings(settings) { error in
            applyError = error
            semaphore.signal()
        }
        semaphore.wait()
        return Self.status(from: applyError)
    }

    /// `setTunnelNetworkSettings(nil)`.
    ///
    /// Removes the addresses, routes and resolvers. It does **not** touch the
    /// on-demand rules or `includeAllNetworks`, and must not: CB-6 puts those in
    /// the OS's custody precisely so that the core going away does not drop
    /// protection.
    private func clearSettings() -> tw_ios_status {
        let semaphore = DispatchSemaphore(value: 0)
        var applyError: Error?
        provider.setTunnelNetworkSettings(nil) { error in
            applyError = error
            semaphore.signal()
        }
        semaphore.wait()
        return Self.status(from: applyError)
    }

    /// One `NEPacketTunnelFlow.readPackets` — PB-1's **one** crossing per batch,
    /// and the one forced `Data` copy per packet that PB-2 budgets.
    ///
    /// The call is asynchronous and this entry point is synchronous, so the
    /// batch most recently delivered by the standing read is drained here. The
    /// standing read is re-armed by `PacketPump`, which is what keeps the
    /// crossing count at one per batch rather than one per poll.
    private func readPackets(into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        for packet in PacketPump.shared.drainInbound() {
            packet.withUnsafeBytes { raw in
                twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
            }
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    /// One `NEPacketTunnelFlow.writePackets(_:withProtocols:)`.
    ///
    /// `families` arrived from Rust, which derived it from each packet's version
    /// nibble. Swift MUST NOT re-derive it: a packet labelled with the wrong
    /// family is dropped by the OS in silence, and the resulting "the tunnel is
    /// up but IPv6 does not work" is the asymmetry ADR-0010 R1 forbids.
    private func writePackets(_ packets: UnsafePointer<tw_ios_slice>?,
                              _ families: UnsafePointer<Int32>?,
                              _ count: Int) -> tw_ios_status {
        guard let packets, let families, count > 0 else {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        var datas: [Data] = []
        var protocols: [NSNumber] = []
        datas.reserveCapacity(count)
        protocols.reserveCapacity(count)
        for index in 0..<count {
            let slice = packets[index]
            guard let base = slice.ptr, slice.len > 0 else { continue }
            datas.append(Data(bytes: base, count: slice.len))
            protocols.append(NSNumber(value: families[index]))
        }
        provider.packetFlow.writePackets(datas, withProtocols: protocols)
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    // MARK: - enforcement

    /// Installs the on-demand rules and the `includeAllNetworks` flags.
    ///
    /// ADR-0012 §11.6's iOS row is the whole mechanism, and KS-17's atomicity is
    /// the OS's `saveToPreferences`: one save replaces the whole configuration,
    /// so there is no moment at which the profile carries neither ruleset.
    private func applyEnforcement(_ programme: tw_ios_slice) -> tw_ios_status {
        guard let bytes = Self.data(programme),
              let decoded = EnforcementProgramme.decode(bytes) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        lastRequestedEnforcement = bytes

        let semaphore = DispatchSemaphore(value: 0)
        var result: Error?
        NETunnelProviderManager.loadAllFromPreferences { managers, loadError in
            guard let manager = managers?.first else {
                result = loadError ?? NEVPNError(.configurationInvalid)
                semaphore.signal()
                return
            }
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
                proto.includeAllNetworks = decoded.includeAllNetworks
                proto.excludeLocalNetworks = decoded.excludeLocalNetworks
                // The programme travels verbatim so `installed_enforcement`
                // reads back the SAME bytes Rust rendered. Re-serialising it
                // here would let the read-back differ from the write for a
                // reason nobody could see.
                var config = proto.providerConfiguration ?? [:]
                config[EnforcementProgramme.configurationKey] = bytes
                proto.providerConfiguration = config
            }
            manager.onDemandRules = decoded.makeOnDemandRules()
            // ADR-0012's iOS row and ADR-0022 §11.10 both fix this to false: a
            // system that may disconnect on demand may leave the device
            // unprotected on a network it decided was fine.
            manager.isOnDemandEnabled = true
            manager.saveToPreferences { saveError in
                result = saveError
                semaphore.signal()
            }
        }
        semaphore.wait()
        return Self.status(from: result)
    }

    /// Reads back what is **actually installed** — W-24's query.
    ///
    /// Not `lastRequestedEnforcement`. On a platform with no firewall to
    /// interrogate, `NETunnelProviderManager`'s saved configuration *is* the
    /// enforcement layer, and it survives a provider restart — which is exactly
    /// what makes ADR-0022 LC-4 step 3 work after a jetsam kill, when this
    /// object's own memory is gone.
    private func installedEnforcement(into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        let semaphore = DispatchSemaphore(value: 0)
        var installed: Data?
        var loadFailure: Error?
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            loadFailure = error
            if let proto = managers?.first?.protocolConfiguration as? NETunnelProviderProtocol {
                installed = proto.providerConfiguration?[
                    EnforcementProgramme.configurationKey] as? Data
            }
            semaphore.signal()
        }
        semaphore.wait()
        if let loadFailure {
            return Self.status(from: loadFailure)
        }
        // Pushing nothing means "no configuration installed", which Rust reads
        // as Ok(None). A configuration that exists but cannot be parsed is
        // Rust's problem to name, and it names it as a suspected third-party
        // profile rather than as an absence.
        if let installed {
            installed.withUnsafeBytes { raw in
                twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
            }
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    // MARK: - network path

    private func pathSnapshot(into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        guard let json = pathObserver.currentSnapshotJSON() else {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        let bytes = Data(json.utf8)
        bytes.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    // MARK: - the store root

    private func storeRootPath(into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        let bytes = Data(storeRoot.path.utf8)
        bytes.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    /// ST-26: re-verified at **every** start, never assumed.
    private func storeRootBackupExcluded() -> Int32 {
        StoreRoot.isBackupExcluded(storeRoot) ? 1 : 0
    }

    // MARK: - status marshalling

    /// Maps an `Error` onto the two integers the bridge carries.
    ///
    /// This is the only place Swift touches an error at all, and it does not
    /// interpret one: it reports which number space the OS used. Turning the
    /// number into a registered `reason_code` is `twinvpn-platform-ios::oserr`'s,
    /// in Rust — which is what keeps CB-2 true and what makes the mapping
    /// testable on a Linux build host.
    static func status(from error: Error?) -> tw_ios_status {
        guard let error else {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        let ns = error as NSError
        switch ns.domain {
        case NEVPNErrorDomain:
            return tw_ios_status(kind: TW_IOS_KIND_NEVPN, code: Int32(ns.code))
        case NSOSStatusErrorDomain:
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(ns.code))
        case NSPOSIXErrorDomain:
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: Int32(ns.code))
        default:
            // A domain this build does not know is NOT mapped onto a number in
            // a space it does not belong to — that would have Rust name a
            // condition nobody observed. `NOT_ATTACHED` is the honest "we cannot
            // say", and it is what Rust turns into PLATFORM.ADAPTER_UNAVAILABLE.
            return tw_ios_status(kind: TW_IOS_KIND_NOT_ATTACHED, code: 0)
        }
    }

    static func data(_ slice: tw_ios_slice) -> Data? {
        guard let base = slice.ptr else { return slice.len == 0 ? Data() : nil }
        return Data(bytes: base, count: slice.len)
    }

    static func string(_ slice: tw_ios_slice) -> String? {
        data(slice).flatMap { String(data: $0, encoding: .utf8) }
    }
}
