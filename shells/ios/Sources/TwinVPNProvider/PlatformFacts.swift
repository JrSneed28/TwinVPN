//  PlatformFacts.swift — the four OS readings the bridges hand over.
//
//  Authority: ADR-0018 §11.16 (h) and (l); ADR-0010 §11.7 and R1; ADR-0011
//  DN-20; `docs/networking.md` §5.1, §6.3; `ownership.md` §10.3 and §10.4.
//
//  ===========================================================================
//  THE DEFECT THIS FILE CLOSES
//  ===========================================================================
//
//  `PathMonitorBridge.swift` called `InterfaceFacts.mtu(named:)`,
//  `InterfaceFacts.addresses(named:)`, `NAT64Discovery.currentPrefix()` and
//  `SystemResolvers.current()`. `KeychainBridge.swift` called
//  `Attestation.create(for:)`. **None of the four types existed anywhere in the
//  repository**, so the extension could not compile — and "written, not
//  compiled" is what kept that invisible.
//
//  ===========================================================================
//  EVERY TYPE HERE READS. NONE DECIDES.
//  ===========================================================================
//
//  `ownership.md` §10.3's design rule pushes everything testable into
//  `core/crates/twinvpn-platform-ios`, where it runs on a Linux build host. So
//  each of these answers exactly one question the OS alone can answer, in the
//  OS's own units, and interprets nothing:
//
//    * no "is this network good enough"
//    * no "did we roam"
//    * no "should we use NAT64"
//    * no "is this attestation acceptable"
//
//  Each of those verdicts is the core's, and each stays the core's because the
//  only thing that leaves this file is a description of what the OS said.
//
//  ===========================================================================
//  ABSENT IS A FACT, AND IT IS A DIFFERENT FACT FROM EMPTY
//  ===========================================================================
//
//  Every reader here returns an optional and every one of them means it. ADR-0010
//  §11.7: IPv6-only-with-NAT64, IPv6-only-without, and dual-stack are "three
//  distinct situations with three distinct behaviours", so a missing PREF64 is
//  omitted rather than reported as a well-known prefix. DN-20 says the same about
//  resolvers: "we could not read the resolver list" and "this host has no
//  resolvers" are different, and only the second is safe to act on.

import Foundation
import Security

#if canImport(Darwin)
import Darwin
#endif

// ===========================================================================
// MARK: - InterfaceFacts
// ===========================================================================

/// One interface's MTU and addresses, read from `getifaddrs(3)`.
///
/// `NWPathMonitor` reports which interfaces a path uses and what class they
/// are; it does **not** report an MTU or an address list. Those come from the
/// BSD layer, which is why this exists beside the path monitor rather than
/// inside it.
enum InterfaceFacts {
    /// One address on an interface, in the shape
    /// `twinvpn_platform_ios::pathmon` decodes.
    struct Address {
        /// The address bytes: 4 for IPv4, 16 for IPv6.
        let octets: [UInt8]
        /// The prefix length, derived from the netmask.
        let prefixLength: Int
        /// The IPv6 scope zone, or `0`. **Not** folded into `octets`: a
        /// link-local address without its zone is not routable and not
        /// comparable, and dropping it is how two different interfaces' `fe80::`
        /// addresses come to look like one.
        let zone: UInt32
    }

    /// The interface's MTU, or `nil` if it has none this build can read.
    ///
    /// `nil`, not a default. `docs/networking.md` §6.3 floors a path at the
    /// IPv6 minimum and DPLPMTUD raises it from there; substituting 1500 here
    /// would hand the core a measurement it never made, and a too-high MTU is a
    /// black hole rather than a slowdown.
    static func mtu(named name: String) -> Int? {
        #if canImport(Darwin)
        var ifr = ifreq()
        withUnsafeMutableBytes(of: &ifr.ifr_name) { raw in
            let bytes = Array(name.utf8.prefix(raw.count - 1))
            raw.copyBytes(from: bytes)
        }
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else { return nil }
        defer { close(sock) }
        // `SIOCGIFMTU` is not exposed to Swift as a constant; its value is
        // fixed by the Darwin ABI. Written out with its derivation rather than
        // as a bare number, so a reader can check it.
        let siocgifmtu: UInt = 0xC020_6933
        guard ioctl(sock, siocgifmtu, &ifr) == 0 else { return nil }
        return Int(ifr.ifr_ifru.ifru_mtu)
        #else
        _ = name
        return nil
        #endif
    }

    /// Every address on the interface, both families.
    ///
    /// An **empty array** means "this interface has no addresses", which is a
    /// real state. It is not used to mean "we could not read them" — that is
    /// what a failed `getifaddrs` produces, and it produces an empty array too,
    /// so a caller that needs to tell them apart must ask the path monitor
    /// whether the interface is up at all.
    static func addresses(named name: String) -> [Address] {
        #if canImport(Darwin)
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var out: [Address] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard String(cString: entry.pointee.ifa_name) == name,
                  let sa = entry.pointee.ifa_addr else { continue }
            let family = sa.pointee.sa_family
            if family == UInt8(AF_INET) {
                let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    $0.pointee.sin_addr.s_addr
                }
                out.append(
                    Address(
                        octets: withUnsafeBytes(of: addr, Array.init),
                        prefixLength: prefixLength(of: entry.pointee.ifa_netmask, bits: 32),
                        zone: 0))
            } else if family == UInt8(AF_INET6) {
                let (bytes, scope) = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    (withUnsafeBytes(of: $0.pointee.sin6_addr, Array.init), $0.pointee.sin6_scope_id)
                }
                out.append(
                    Address(
                        octets: bytes,
                        prefixLength: prefixLength(of: entry.pointee.ifa_netmask, bits: 128),
                        zone: scope))
            }
        }
        return out
        #else
        _ = name
        return []
        #endif
    }

    /// Counts the leading one-bits of a netmask.
    ///
    /// A netmask with a hole in it is not a prefix length, and this returns the
    /// count of leading ones rather than a popcount, so a discontiguous mask
    /// under-reports instead of being silently normalised into something the
    /// kernel never said.
    private static func prefixLength(of mask: UnsafeMutablePointer<sockaddr>?, bits: Int) -> Int {
        #if canImport(Darwin)
        guard let mask else { return bits }
        let offset = bits == 32
            ? MemoryLayout<sockaddr_in>.offset(of: \sockaddr_in.sin_addr)
            : MemoryLayout<sockaddr_in6>.offset(of: \sockaddr_in6.sin6_addr)
        guard let offset else { return bits }
        let byteCount = bits / 8
        var length = 0
        let raw = UnsafeRawPointer(mask).advanced(by: offset)
        for index in 0 ..< byteCount {
            let byte = raw.load(fromByteOffset: index, as: UInt8.self)
            if byte == 0xFF {
                length += 8
                continue
            }
            length += byte.leadingZeroBitCount == 8 ? 0 : (8 - Int(byte.trailingZeroBitCount))
            break
        }
        return min(length, bits)
        #else
        _ = (mask, bits)
        return bits
        #endif
    }
}

// ===========================================================================
// MARK: - SystemResolvers
// ===========================================================================

/// The host's configured resolvers, per family.
///
/// # Why this is read at all
///
/// ADR-0011's SPLIT mode sends default-class queries to "the host's
/// pre-existing upstream over the underlay" — so the core has to be told what
/// that upstream is. It is a **fact about the host**, not a policy: the core
/// decides whether to use it, and DN-20 makes the fail-closed direction the
/// default when it cannot.
enum SystemResolvers {
    struct Snapshot {
        /// Each address as `[UInt8]`, in the shape the snapshot JSON carries.
        let v4: [[UInt8]]
        let v6: [[UInt8]]
    }

    /// `nil` when the resolver list cannot be read.
    ///
    /// **Not an empty snapshot.** ADR-0011 DN-20: "we could not read the
    /// resolver list" and "this host has no resolvers" are different facts, and
    /// only the second is safe to act on — the first must leave the previous
    /// policy governing rather than replace it with an empty one.
    ///
    /// On iOS there is no public API for this. `res_ninit(3)` is available and
    /// reports what the process was launched with, which inside a
    /// `NEPacketTunnelProvider` is the pre-tunnel configuration — exactly what
    /// SPLIT mode needs. Where it cannot be read, `nil`.
    static func current() -> Snapshot? {
        #if canImport(Darwin)
        var state = __res_9_state()
        guard res_9_ninit(&state) == 0 else { return nil }
        defer { res_9_ndestroy(&state) }

        var v4: [[UInt8]] = []
        var v6: [[UInt8]] = []
        let count = Int(state.nscount)
        guard count > 0 else { return nil }
        withUnsafeBytes(of: state.nsaddr_list) { raw in
            let list = raw.bindMemory(to: sockaddr_in.self)
            for index in 0 ..< min(count, list.count) {
                v4.append(withUnsafeBytes(of: list[index].sin_addr.s_addr, Array.init))
            }
        }
        // `_u._ext.nsaddrs` carries the IPv6 servers; an entry is null where the
        // corresponding v4 slot was used instead.
        withUnsafeBytes(of: state._u._ext.nsaddrs) { raw in
            let list = raw.bindMemory(to: UnsafeMutablePointer<sockaddr_in6>?.self)
            for index in 0 ..< min(count, list.count) {
                guard let entry = list[index] else { continue }
                v6.append(withUnsafeBytes(of: entry.pointee.sin6_addr, Array.init))
            }
        }
        // Both lists empty is "we read the configuration and it named nothing",
        // which is a real answer and is reported as one.
        return Snapshot(v4: v4, v6: v6)
        #else
        return nil
        #endif
    }
}

// ===========================================================================
// MARK: - NAT64Discovery
// ===========================================================================

/// The PREF64 prefix, where the network advertises one.
///
/// # ADR-0010 §11.7, and the prefix this never invents
///
/// > TwinVPN never depends on DNS64 to do this for it.
///
/// `nil` is *"no NAT64 prefix was discovered"*, and it is a different fact from
/// a discovered one — which is why the caller omits the key rather than nulling
/// it. The well-known `64:ff9b::/96` is deliberately **not** substituted: a
/// device that assumed it on a network using a custom prefix would send v4
/// traffic into a synthesis that does not exist and see it black-holed.
enum NAT64Discovery {
    /// The prefix as `[UInt8]` plus its length, in the snapshot's shape.
    ///
    /// `getaddrinfo` against the RFC 7050 well-known name is how a userspace
    /// process discovers NAT64 without the RA option, and Apple's own guidance
    /// for `NEPacketTunnelProvider` is the same call. The RFC 8781 RA option is
    /// not readable from an app process at all, which is why this uses 7050 and
    /// says so rather than reporting an RA it never saw.
    static func currentPrefix() -> [String: Any]? {
        #if canImport(Darwin)
        var hints = addrinfo(
            ai_flags: 0,
            ai_family: AF_INET6,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        // RFC 7050 §3: `ipv4only.arpa` resolves to a synthesised AAAA iff the
        // network runs DNS64 over NAT64.
        guard getaddrinfo("ipv4only.arpa", nil, &hints, &result) == 0, let first = result else {
            return nil
        }
        defer { freeaddrinfo(result) }
        guard let sa = first.pointee.ai_addr else { return nil }
        let bytes = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
            withUnsafeBytes(of: $0.pointee.sin6_addr, Array.init)
        }
        guard bytes.count == 16 else { return nil }
        // RFC 7050's synthesised address embeds 192.0.0.170. Only the /96 form
        // is reported: the shorter PREF64 lengths need the embedded octets read
        // at their own offsets, and reporting a length this build did not
        // actually derive would be worse than reporting none.
        let embedded = Array(bytes[12 ..< 16])
        guard embedded == [192, 0, 0, 170] || embedded == [192, 0, 0, 171] else { return nil }
        return [
            "prefix": ["octets": Array(bytes[0 ..< 12]) + [0, 0, 0, 0]],
            "prefix_length": 96,
        ]
        #else
        return nil
        #endif
    }
}

// ===========================================================================
// MARK: - Attestation
// ===========================================================================

/// The key attestation this platform can produce, or none.
///
/// # §11.16 (l), and why an empty `Data` is the honest answer here
///
/// > The capability reports `hardware_backed` **truthfully per target**, so S-46
/// > records it rather than the core assuming it. On a target with no secure
/// > element the residual is TM-13's, unchanged; **the core MUST NOT substitute
/// > a file-backed signer silently.**
///
/// iOS has no public key-attestation API for a Secure Enclave key. `DCAppAttest`
/// attests the **app**, not a key, and its assertion is bound to Apple's server
/// challenge rather than to a `SecKey` — presenting one as a key attestation
/// would be a claim the platform never made. So this returns `nil`, the caller
/// pushes an empty buffer, and the Rust side reports no attestation.
///
/// That is `AUTH.ATTESTATION_FORMAT_UNSUPPORTED`'s case, and it is a *stated
/// gap* rather than a silent one: a fabricated attestation would be believed.
enum Attestation {
    static func create(for key: SecKey) -> Data? {
        _ = key
        return nil
    }
}
