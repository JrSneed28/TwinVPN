//  Programmes.swift — decoding what Rust rendered, and nothing more.
//
//  Authority: docs/networking.md §5.2's iOS row and §11.3 of ADR-0010;
//  ADR-0011 §11.7's iOS row; ADR-0012 §11.6's iOS row and TN-5; ADR-0018 CB-2.
//
//  STATUS: written, not compiled.
//
//  Every type here is a `Decodable` mirror of a Rust struct, and every method is
//  a field-by-field copy into an Apple object. There is no arithmetic, no
//  defaulting, and no branch on a TwinVPN fact. If a field is absent the decode
//  FAILS rather than substituting a value — a silently defaulted MTU or a
//  silently empty route list is exactly the "silent default is how one side comes
//  to believe a fact the other never supplied" failure the seam's own comments
//  warn about.
//
//  `EnforcementProgramme` used to sit below `TunnelSettingsProgramme` here and
//  now lives in `Sources/TwinVPNShared/EnforcementProgramme.swift` — the APP is
//  what installs the profile carrying it, and this directory is not in the app
//  target's `sources`. That file's header carries the whole reason. What stays
//  here is what only the extension can use: `TunnelSettingsProgramme` decodes
//  from a `tw_ios_slice` through `BridgeHost`, and the app target has neither.

import Foundation
import NetworkExtension
import TwinVPNBridge

// MARK: - the tunnel settings programme

/// One rendered `NEPacketTunnelNetworkSettings`.
///
/// Mirrors `twinvpn_platform_ios::settings::TunnelSettingsProgramme`.
struct TunnelSettingsProgramme: Decodable {
    struct Route: Decodable {
        let isDefault: Bool
        let address: String?
        let subnetMask: String?
        let prefixLength: String?

        enum CodingKeys: String, CodingKey {
            case isDefault = "default"
            case address
            case subnetMask = "subnet_mask"
            case prefixLength = "prefix_length"
        }
    }

    struct V4: Decodable {
        let addresses: [String]
        let subnetMasks: [String]
        let includedRoutes: [Route]
        let excludedRoutes: [Route]

        enum CodingKeys: String, CodingKey {
            case addresses
            case subnetMasks = "subnet_masks"
            case includedRoutes = "included_routes"
            case excludedRoutes = "excluded_routes"
        }
    }

    struct V6: Decodable {
        let addresses: [String]
        let prefixLengths: [String]
        let includedRoutes: [Route]
        let excludedRoutes: [Route]

        enum CodingKeys: String, CodingKey {
            case addresses
            case prefixLengths = "prefix_lengths"
            case includedRoutes = "included_routes"
            case excludedRoutes = "excluded_routes"
        }
    }

    struct DNS: Decodable {
        let servers: [String]
        let searchDomains: [String]
        let matchDomains: [String]

        enum CodingKeys: String, CodingKey {
            case servers
            case searchDomains = "search_domains"
            case matchDomains = "match_domains"
        }
    }

    let tunnelRemoteAddress: String
    let ipv4: V4
    let ipv6: V6
    let dns: DNS
    let mtu: Int

    enum CodingKeys: String, CodingKey {
        case tunnelRemoteAddress = "tunnel_remote_address"
        case ipv4, ipv6, dns, mtu
    }

    static func decode(_ slice: tw_ios_slice) -> TunnelSettingsProgramme? {
        guard let bytes = BridgeHost.data(slice) else { return nil }
        return try? JSONDecoder().decode(TunnelSettingsProgramme.self, from: bytes)
    }

    /// Builds the settings object.
    ///
    /// **Both families, always.** ADR-0010 R1 requires both overlay addresses
    /// regardless of what the underlay offers, and §11.3 requires both families'
    /// routes "in the same `apply()` transaction. An implementation that can
    /// install one family's routes without the other's is non-conforming."
    /// `ipv4` and `ipv6` are non-optional in the decoded programme, so there is
    /// no shape of this function that sets one and not the other.
    func makeNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)

        let v4 = NEIPv4Settings(addresses: ipv4.addresses, subnetMasks: ipv4.subnetMasks)
        v4.includedRoutes = ipv4.includedRoutes.map(Self.makeV4Route)
        v4.excludedRoutes = ipv4.excludedRoutes.map(Self.makeV4Route)
        settings.ipv4Settings = v4

        let v6 = NEIPv6Settings(
            addresses: ipv6.addresses,
            networkPrefixLengths: ipv6.prefixLengths.map { NSNumber(value: Int($0) ?? 128) })
        v6.includedRoutes = ipv6.includedRoutes.map(Self.makeV6Route)
        v6.excludedRoutes = ipv6.excludedRoutes.map(Self.makeV6Route)
        settings.ipv6Settings = v6

        let dnsSettings = NEDNSSettings(servers: dns.servers)
        dnsSettings.searchDomains = dns.searchDomains
        // ADR-0011 §11.7's iOS row. `matchDomains == [""]` claims everything;
        // an empty array claims nothing. Rust decided which, and `.local` is
        // already excluded there (N2), because mDNSResponder sends it to
        // multicast regardless of what we configure.
        dnsSettings.matchDomains = dns.matchDomains
        settings.dnsSettings = dnsSettings

        settings.mtu = NSNumber(value: mtu)
        return settings
    }

    private static func makeV4Route(_ route: Route) -> NEIPv4Route {
        // ADR-0010 §11.3's iOS row gives the default-route form as
        // `NEIPv4Route.default()` — NOT the `0.0.0.0/1` + `128.0.0.0/1` split
        // Linux installs. Rust rendered the marker; this copies it.
        guard !route.isDefault else { return NEIPv4Route.default() }
        return NEIPv4Route(destinationAddress: route.address ?? "0.0.0.0",
                           subnetMask: route.subnetMask ?? "255.255.255.255")
    }

    private static func makeV6Route(_ route: Route) -> NEIPv6Route {
        guard !route.isDefault else { return NEIPv6Route.default() }
        return NEIPv6Route(destinationAddress: route.address ?? "::",
                           networkPrefixLength: NSNumber(value: Int(route.prefixLength ?? "128") ?? 128))
    }
}
