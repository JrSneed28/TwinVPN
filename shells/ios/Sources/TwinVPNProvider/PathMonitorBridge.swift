//  PathMonitorBridge.swift — NWPathMonitor, serialised and handed over.
//
//  Authority: docs/networking.md §5.1 ("event-driven, never polled"), §5.2's
//  iOS change-events column, §5.4's shared roaming row; ADR-0010 §11.7;
//  ADR-0018 CB-2, §11.16 (h).
//
//  STATUS: written, not compiled.
//
//  This file SERIALISES an `NWPath`. It does not interpret one. There is no
//  "did we roam", no "is this a migration", no comparison against a previous
//  path — all of that is `twinvpn_platform_ios::pathmon`, in Rust, where it is
//  tested on a Linux build host with synthetic snapshots.
//
//  §5.4's shared row is the sentence this division protects: "Underlay change
//  does not touch overlay addressing (N2); path re-validation + make-before-break
//  migration. `MIGRATING`, not `RECONNECTING`." That verdict is the core's, and
//  it stays the core's because the only thing that crosses from here is a
//  description of what the OS said.

import Foundation
import Network

final class PathMonitorBridge {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "net.twinvpn.pathmonitor")
    private var latest: String?
    private let lock = NSLock()

    /// Starts the monitor.
    ///
    /// `onUpdate` receives the serialised snapshot and whether it is the first
    /// one after a wake. **Never polled**: `docs/networking.md` §5.1 is explicit,
    /// and the reason is not efficiency — "a poll interval is a window in which
    /// the host has moved networks and the core still believes it has not", and
    /// it "is added directly to `T_FAILOVER_TARGET`."
    func start(onUpdate: @escaping (String, Bool) -> Void) {
        var isFirstAfterStart = true
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let json = Self.serialise(path)
            self.lock.lock()
            self.latest = json
            self.lock.unlock()
            onUpdate(json, isFirstAfterStart)
            isFirstAfterStart = false
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
    }

    func currentSnapshotJSON() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return latest
    }

    /// Serialises one `NWPath` into the shape `twinvpn_platform_ios::pathmon`
    /// parses.
    ///
    /// Addresses cross as **octets**, not text: the shell already has the bytes
    /// from the `sockaddr`, and a text round-trip is a parser the adapter would
    /// have to get exactly as right as the OS's own.
    private static func serialise(_ path: NWPath) -> String {
        var interfaces: [[String: Any]] = []
        for interface in path.availableInterfaces {
            interfaces.append([
                "index": interface.index,
                "name": interface.name,
                // The raw `NWInterface.InterfaceType` tag. Rust maps it to a
                // `LinkClass`, and an unknown tag maps to `Unknown` there rather
                // than being guessed here — guessing WiFi would make a cellular
                // roam emit `NET.LINK.DOWN_WIFI`.
                "interface_type": tag(for: interface.type),
                "is_up": true,
                "mtu": mtu(forInterfaceNamed: interface.name),
                "addresses": addresses(forInterfaceNamed: interface.name),
            ])
        }

        var snapshot: [String: Any] = [
            "interfaces": interfaces,
            // Two flags, never one. ADR-0010 R1 exists to forbid a design in
            // which "we have a v4 story and a v6 story" is sayable, and a single
            // "is satisfied" flag is exactly how that sentence becomes true.
            "supports_v4": path.supportsIPv4,
            "supports_v6": path.supportsIPv6,
            "supports_dns": path.supportsDNS,
            // Two DIFFERENT OS signals with two different responses under
            // ADR-0022 LC-31, kept apart: `isExpensive` is metering,
            // `isConstrained` is Low Data Mode.
            "metered": path.isExpensive,
            "constrained": path.isConstrained,
            // `is_overlay` is answered by OUR prefix, not by a link kind: every
            // NEPacketTunnelProvider on Darwin — including another vendor's —
            // presents as a `utun` of type `other`.
            "overlay_name_prefix": "utun",
        ]

        if let resolvers = SystemResolvers.current() {
            snapshot["resolvers_v4"] = resolvers.v4
            snapshot["resolvers_v6"] = resolvers.v6
        }
        // ADR-0010 §11.7: PREF64 from the RFC 8781 RA option. Absent is a
        // DIFFERENT fact from present-with-a-prefix — IPv6-only-with-NAT64 and
        // IPv6-only-without are "three distinct situations with three distinct
        // behaviours" — so the key is omitted rather than nulled.
        if let nat64 = NAT64Discovery.currentPrefix() {
            snapshot["nat64_prefix"] = nat64
        }

        guard let data = try? JSONSerialization.data(withJSONObject: snapshot),
              let json = String(data: data, encoding: .utf8) else {
            // A snapshot that will not serialise must not become an EMPTY one:
            // an empty interface list reads as "this device has no network",
            // which is a far stronger claim than "we could not describe it".
            // Rust refuses this string with a named condition.
            return "{}"
        }
        return json
    }

    private static func tag(for type: NWInterface.InterfaceType) -> String {
        switch type {
        case .wifi: return "wifi"
        case .cellular: return "cellular"
        case .wiredEthernet: return "wiredEthernet"
        case .loopback: return "loopback"
        case .other: return "other"
        @unknown default:
            // A future case is reported AS unknown rather than mapped onto the
            // nearest one this build knows. Rust's `LinkClass::Unknown` exists
            // for exactly this.
            return "unknown"
        }
    }

    private static func mtu(forInterfaceNamed name: String) -> Int {
        InterfaceFacts.mtu(named: name) ?? 0
    }

    private static func addresses(forInterfaceNamed name: String) -> [[String: Any]] {
        InterfaceFacts.addresses(named: name).map { address in
            var entry: [String: Any] = [
                "address": ["octets": address.octets],
                "prefix_length": address.prefixLength,
            ]
            if address.zone != 0 {
                var value = entry["address"] as? [String: Any] ?? [:]
                value["zone"] = address.zone
                entry["address"] = value
            }
            return entry
        }
    }
}
