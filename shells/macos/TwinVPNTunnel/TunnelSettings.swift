//
//  TunnelSettings.swift
//  com.twinvpn.app.sysext
//
//  Authority: ADR-0012 §11.6's macOS row ("`pf` anchor `twinvpn` (both
//  families) + `NEPacketTunnelNetworkSettings` carrying `IPv4Settings` and
//  `IPv6Settings`"); ADR-0010 R1 (there is no v4 story and a v6 story);
//  ADR-0011 (DNS handling, and the macOS `matchDomains` row); ADR-0018 CB-2.
//
//  ============================================================================
//  EVERY VALUE IN THIS FILE ORIGINATES IN THE CORE.
//
//  This file decodes a JSON document the Rust core computed and copies it,
//  field for field, into NetworkExtension's objects. It contains:
//
//    - no default for an absent field,
//    - no clamp on any value (not on the MTU, not on a prefix length),
//    - no family selection,
//    - no fallback route,
//    - no normalisation of an address,
//    - no validation that would substitute a "safe" value for a rejected one.
//
//  Those are all decisions, and CB-2 puts every decision in the core. The
//  falsification test is the design target: with this file deleted and a mock
//  adapter bound, the core must still compute exactly the same settings.
//
//  The one thing this file does that is not a copy is REFUSE. A document that
//  does not decode throws, and the provider reports the failure; it does not
//  proceed with a partially applied settings object, because a partial apply is
//  the leak window `docs/networking.md` §2.3 names.
//
//  ============================================================================
//  WHY `included_routes: []` IS NOT `NEIPv4Route.default()`
//
//  It is tempting to read an empty included-routes array as "no routes, so
//  presumably everything" and substitute `NEIPv4Route.default()`. That is a
//  decision, it is the most consequential one in the file, and it is wrong: the
//  core emits the default route EXPLICITLY when it wants one — as
//  `docs/networking.md` §7.2's four `/1` routes, or as `0.0.0.0/0` — and an
//  empty array means the core wants no routes in that family for this
//  generation. Substituting a default route here would put a full tunnel on a
//  device whose contract asked for a split one.
//
//  ============================================================================
//  WHY `.local` NEVER APPEARS IN `matchDomains`
//
//  ADR-0011's macOS row specifies `matchDomains` with `.local` EXCLUDED, "so
//  mDNS keeps working". That exclusion is performed by the CORE, which is where
//  the resolver programme is computed. This file neither adds `.local` nor
//  filters it: it copies the list. The rule is recorded here only so that the
//  next reader, noticing `.local` is absent, does not "fix" it.
//

import Foundation
import NetworkExtension

/// The settings document, exactly as `tvb_ext_next_settings` yields it.
///
/// `Codable` with explicit `CodingKeys`, so the wire names are the snake_case
/// ones the core writes and a Swift rename cannot silently change the contract.
///
/// `ipv4` and `ipv6` are **non-optional**. ADR-0010 R1 forbids a v4 story and a
/// v6 story, and this is that rule as a type: a document missing either family
/// fails to decode, rather than producing a tunnel that carries one family and
/// silently leaks the other.
struct TunnelSettingsDocument: Decodable, Sendable {
    let tunnelRemoteAddress: String
    let mtu: Int
    let ipv4: IPv4Section
    let ipv6: IPv6Section
    /// Optional: a generation may legitimately install no resolver at all.
    /// `nil` means "leave `dnsSettings` unset", not "use the system's".
    let dns: DNSSection?

    enum CodingKeys: String, CodingKey {
        case tunnelRemoteAddress = "tunnel_remote_address"
        case mtu
        case ipv4
        case ipv6
        case dns
    }

    struct IPv4Section: Decodable, Sendable {
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

        struct Route: Decodable, Sendable {
            let address: String
            let subnetMask: String

            enum CodingKeys: String, CodingKey {
                case address
                case subnetMask = "subnet_mask"
            }
        }
    }

    struct IPv6Section: Decodable, Sendable {
        let addresses: [String]
        let networkPrefixLengths: [Int]
        let includedRoutes: [Route]
        let excludedRoutes: [Route]

        enum CodingKeys: String, CodingKey {
            case addresses
            case networkPrefixLengths = "network_prefix_lengths"
            case includedRoutes = "included_routes"
            case excludedRoutes = "excluded_routes"
        }

        struct Route: Decodable, Sendable {
            let address: String
            let networkPrefixLength: Int

            enum CodingKeys: String, CodingKey {
                case address
                case networkPrefixLength = "network_prefix_length"
            }
        }
    }

    struct DNSSection: Decodable, Sendable {
        let servers: [String]
        let searchDomains: [String]?
        /// **Three-valued, and the three values are different.**
        ///
        ///   - absent (`nil`)  -> leave `NEDNSSettings.matchDomains` nil
        ///   - `[]` (present, empty) -> NE's "this resolver is the default for
        ///     everything"
        ///   - a list -> split DNS over exactly those domains
        ///
        /// Collapsing absent and empty — which a non-optional `[String]` would
        /// do — turns "do not touch the system resolver" into "become the
        /// system resolver". They are opposite outcomes, so the optionality is
        /// load-bearing rather than defensive.
        let matchDomains: [String]?
        let matchDomainsNoSearch: Bool?

        enum CodingKeys: String, CodingKey {
            case servers
            case searchDomains = "search_domains"
            case matchDomains = "match_domains"
            case matchDomainsNoSearch = "match_domains_no_search"
        }
    }
}

/// A settings document that could not be decoded.
///
/// Carries the `DecodingError`'s description for a log line and nothing else.
/// The provider does not act on the reason; it reports the failure and stops.
struct SettingsDecodeFailure: Error, Sendable {
    let detail: String
}

enum TunnelSettingsBuilder {
    /// Decodes one document.
    ///
    /// `JSONDecoder` with no `keyDecodingStrategy`: the `CodingKeys` above name
    /// every wire key explicitly. A `.convertFromSnakeCase` strategy would make
    /// the contract implicit and would silently change if a field were renamed
    /// in Swift.
    static func decode(_ bytes: [UInt8]) throws -> TunnelSettingsDocument {
        do {
            return try JSONDecoder().decode(TunnelSettingsDocument.self, from: Data(bytes))
        } catch {
            throw SettingsDecodeFailure(detail: String(describing: error))
        }
    }

    /// Builds the NE object. A copy, field for field.
    ///
    /// UNVERIFIED: `NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` does not
    /// validate its argument at construction — an unparseable address surfaces
    /// later, when `setTunnelNetworkSettings` fails. This file does not
    /// pre-validate it, because a shell-side address parse would be a second
    /// opinion about a value the core already put in canonical form
    /// (`common.proto`: canonical forms are enforced, never normalized).
    static func build(_ doc: TunnelSettingsDocument) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: doc.tunnelRemoteAddress)

        // The MTU. Copied, not clamped. `docs/networking.md` §6.2 puts the 1280
        // floor and DPLPMTUD in the CORE; a `max(1280, …)` here would be the
        // shell holding a second opinion about the path MTU, and the two would
        // disagree exactly when the path is broken.
        settings.mtu = NSNumber(value: doc.mtu)

        // ---- IPv4 and IPv6, side by side ---------------------------------
        //
        // ADR-0010 R1. Both are ALWAYS constructed — there is no `if
        // !addresses.isEmpty` guard, because a guard would make an empty v6
        // section produce a settings object with no `IPv6Settings` at all, and
        // "we forgot IPv6" and "the core asked for no IPv6 addresses" would
        // become the same tunnel. KS-5's sibling rule: one family present and
        // the other absent is non-conforming, not degraded.

        let v4 = NEIPv4Settings(
            addresses: doc.ipv4.addresses,
            subnetMasks: doc.ipv4.subnetMasks)
        v4.includedRoutes = doc.ipv4.includedRoutes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnetMask)
        }
        v4.excludedRoutes = doc.ipv4.excludedRoutes.map {
            NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnetMask)
        }
        settings.ipv4Settings = v4

        let v6 = NEIPv6Settings(
            addresses: doc.ipv6.addresses,
            networkPrefixLengths: doc.ipv6.networkPrefixLengths.map { NSNumber(value: $0) })
        v6.includedRoutes = doc.ipv6.includedRoutes.map {
            NEIPv6Route(destinationAddress: $0.address,
                        networkPrefixLength: NSNumber(value: $0.networkPrefixLength))
        }
        v6.excludedRoutes = doc.ipv6.excludedRoutes.map {
            NEIPv6Route(destinationAddress: $0.address,
                        networkPrefixLength: NSNumber(value: $0.networkPrefixLength))
        }
        settings.ipv6Settings = v6

        // ---- DNS ----------------------------------------------------------
        //
        // `nil` leaves `dnsSettings` unset, which is NE's "do not touch the
        // resolver". That is a different outcome from an empty
        // `NEDNSSettings(servers: [])`, and the core distinguishes them.
        if let dns = doc.dns {
            let dnsSettings = NEDNSSettings(servers: dns.servers)
            // Each of these is assigned only when the core supplied it, so an
            // absent field leaves NE's own default in place rather than being
            // overwritten with an empty value this file invented.
            if let search = dns.searchDomains {
                dnsSettings.searchDomains = search
            }
            if let match = dns.matchDomains {
                // Copied verbatim. `.local` is already absent (ADR-0011's macOS
                // row) because the CORE excluded it; this file neither adds nor
                // removes a domain.
                dnsSettings.matchDomains = match
            }
            if let noSearch = dns.matchDomainsNoSearch {
                dnsSettings.matchDomainsNoSearch = noSearch
            }
            settings.dnsSettings = dnsSettings
        }

        // DELIBERATELY NOT SET:
        //
        //  - `proxySettings`: the core computes no proxy programme, and an
        //    empty NEProxySettings is not the same as none.
        //  - `tunnelOverheadBytes`: NE uses it to derive an MTU, which would
        //    be a second MTU decision competing with `settings.mtu` above.
        //  - `includeAllNetworks` / `excludeLocalNetworks`: those live on
        //    NEVPNProtocol, not here, and ADR-0012 §11.6 assigns
        //    `includeAllNetworks` to iOS. On macOS the equivalent enforcement
        //    is the pf anchor, which is the daemon's.
        return settings
    }
}
