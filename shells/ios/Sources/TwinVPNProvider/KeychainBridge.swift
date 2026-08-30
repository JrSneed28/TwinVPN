//  KeychainBridge.swift — SecItem calls, from a query Rust computed.
//  EnclaveBridge (below) — SecKey operations, inside the element.
//  StoreRoot (below)    — the App Group container, with its attributes applied.
//
//  Authority: ADR-0018 CB-5, CB-7, §11.16 (c) and (l); ADR-0020 §11.3's iOS row,
//  ST-5, ST-6, ST-8, ST-12e, ST-22, ST-26, §11.8's iOS row; ADR-0007 §7.3's iOS
//  row and N-5.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHAT SWIFT DOES NOT CHOOSE HERE
//  ===========================================================================
//
//  Not the accessibility class. Not the access group. Not the service. Not the
//  key tag. Not the synchronizable flag. Every one of those arrives inside
//  `attributes`, computed by `twinvpn_platform_ios::keychain` where ST-5 and
//  ST-22 are enforced by construction and tested on a Linux build host.
//
//  Why it matters that they are not chosen here: ST-5's failure is SILENT on a
//  device that is never locked and TOTAL on one that is —
//  `kSecAttrAccessibleWhenUnlocked` "makes every rekey after a screen lock fail
//  … exact defect class R-05". A constant in a Swift file is a constant nobody
//  runs a test over.

// `SecureEnclave` is CryptoKit's, not Security's: `SecureEnclave.isAvailable`
// is `static var isAvailable: Bool` in Apple CryptoKit, iOS 13.0+ (against this
// project's iOS 15.0 floor, so no `@available` guard is owed).
// <https://developer.apple.com/documentation/cryptokit/secureenclave/isavailable>
// Missing it is what made `EnclaveBridge.isHardwareBacked` fail to compile with
// "cannot find 'SecureEnclave' in scope"; `Security` vends `SecKey`, not this.
import CryptoKit
import Foundation
import Security
import TwinVPNBridge

// MARK: - Tier-1 items

struct KeychainBridge {
    let accessGroup: String
    let service: String

    /// One decoded query. Mirrors `twinvpn_platform_ios::keychain::ItemQuery`.
    private struct ItemQuery: Decodable {
        let itemClass: String
        let service: String
        let account: String
        let accessGroup: String
        let accessible: String
        let synchronizable: Bool

        enum CodingKeys: String, CodingKey {
            case itemClass = "class"
            case service, account
            case accessGroup = "access_group"
            case accessible
            case synchronizable
        }

        /// Builds the `CFDictionary`.
        ///
        /// Field for field. There is no default here and no fallback: a query
        /// that does not decode is refused, because a Keychain query assembled
        /// from partial information matches the wrong item or no item, and both
        /// are worse than a named failure.
        func makeQuery() -> [String: Any] {
            [
                kSecClass as String: Self.secClass(itemClass),
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccessible as String: Self.accessibility(accessible),
                // ADR-0020 §11.8's iOS row: `kSecAttrSynchronizable = false`
                // plus `…ThisDeviceOnly` is what keeps Tier 1 out of iCloud
                // Keychain and out of any backup restorable to different
                // hardware. I4 is enforced HERE, on Apple platforms.
                kSecAttrSynchronizable as String: synchronizable,
            ]
        }

        private static func secClass(_ tag: String) -> CFString {
            tag == "kSecClassKey" ? kSecClassKey : kSecClassGenericPassword
        }

        private static func accessibility(_ tag: String) -> CFString {
            // The mapping is a lookup, not a policy. Rust already refused every
            // class but one (ST-5); an unrecognised tag here would be a bridge
            // mismatch, and mapping it to the SAFEST value rather than the most
            // permissive is the direction O-18 fixes for every such choice.
            switch tag {
            case "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly":
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case "kSecAttrAccessibleAfterFirstUnlock":
                return kSecAttrAccessibleAfterFirstUnlock
            case "kSecAttrAccessibleWhenUnlockedThisDeviceOnly":
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case "kSecAttrAccessibleWhenUnlocked":
                return kSecAttrAccessibleWhenUnlocked
            default:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }

    private func decode(_ attributes: tw_ios_slice) -> ItemQuery? {
        guard let bytes = BridgeHost.data(attributes) else { return nil }
        return try? JSONDecoder().decode(ItemQuery.self, from: bytes)
    }

    /// `SecItemCopyMatching`.
    ///
    /// Pushing nothing means **absent**, which Rust reads as `Ok(None)` — a
    /// normal first-run state. `errSecItemNotFound` crosses as a status only if
    /// the call reported something other than success, and Rust distinguishes
    /// "absent" from "unavailable" there. The distinction is load-bearing:
    /// absent enrols and unavailable must not, and conflating them re-enrols the
    /// device on every reboot before first unlock.
    func read(_ attributes: tw_ios_slice, into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        guard let decoded = decode(attributes) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        var query = decoded.makeQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        guard status == errSecSuccess, let data = result as? Data else {
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(status))
        }
        data.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    /// Whole-blob atomic replacement (CB-7).
    ///
    /// Add-or-update, never read-modify-write: "a torn write of the SEK would
    /// make the whole vault unreadable, and ADR-0020's recovery ladder cannot
    /// recover a key it never received."
    func write(_ attributes: tw_ios_slice, _ value: tw_ios_slice) -> tw_ios_status {
        guard let decoded = decode(attributes), let bytes = BridgeHost.data(value) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        let query = decoded.makeQuery()
        var add = query
        add[kSecValueData as String] = bytes

        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        guard addStatus == errSecDuplicateItem else {
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(addStatus))
        }
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: bytes] as CFDictionary)
        return updateStatus == errSecSuccess
            ? tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
            : tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(updateStatus))
    }

    /// `SecItemDelete`. Idempotent — deleting what is not there is success.
    func delete(_ attributes: tw_ios_slice) -> tw_ios_status {
        guard let decoded = decode(attributes) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        let status = SecItemDelete(decoded.makeQuery() as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(status))
    }
}

// MARK: - the Secure Enclave

struct EnclaveBridge {
    let accessGroup: String

    /// §11.16 (l): reported **truthfully**. A simulator has no SEP, and `false`
    /// is the honest answer the core records — never a reason to substitute a
    /// file-backed signer.
    var isHardwareBacked: Bool {
        SecureEnclave.isAvailable
    }

    /// `SecKeyCreateSignature`, ES256, inside the element.
    ///
    /// The private half is never exported (CB-5 row 1, ADR-0007 N-5), and there
    /// is no code path in this file that could export it: `SecKey` references
    /// obtained with `kSecAttrTokenIDSecureEnclave` cannot yield their scalar.
    func sign(_ keyTag: tw_ios_slice,
              _ message: tw_ios_slice,
              into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        guard let tag = BridgeHost.string(keyTag),
              let bytes = BridgeHost.data(message) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        guard let key = privateKey(tag: tag) else {
            // The key is absent, or the device is locked before first unlock and
            // its accessibility class makes it unreadable right now. Both are
            // OSStatus conditions, and Rust names them —
            // `errSecInteractionNotAllowed` becomes `AUTH.KEY_UNAVAILABLE`, a
            // DESIGNED state rather than a surprise.
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(errSecItemNotFound))
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            bytes as CFData,
            &error) as Data? else {
            return BridgeHost.status(from: error?.takeRetainedValue())
        }
        signature.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    /// `SecKeyCopyKeyExchangeResult`.
    ///
    /// The Secure Enclave does **P-256 ECDH and nothing else**. That is exactly
    /// ADR-0007 N-5's reason for TK being hardware-*wrapped* rather than
    /// element-resident: "platform key APIs largely do not offer X25519 ECDH".
    ///
    /// An algorithm the element cannot perform returns `errSecUnimplemented`,
    /// which Rust names `PLATFORM.OS_UNSUPPORTED`. `ownership.md` §10.1: "that
    /// is a fact the core records, never a licence to substitute a software
    /// key." There is no `else` branch in this function that reaches for one,
    /// and there is no key here to reach for.
    func agree(_ keyTag: tw_ios_slice,
               _ algorithm: tw_ios_slice,
               _ peerPublic: tw_ios_slice,
               into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        guard let tag = BridgeHost.string(keyTag),
              let algorithmTag = BridgeHost.string(algorithm),
              let peer = BridgeHost.data(peerPublic) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        guard algorithmTag == "ecdh-p256" else {
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(errSecUnimplemented))
        }
        guard let key = privateKey(tag: tag) else {
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(errSecItemNotFound))
        }
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 32,
        ]
        guard let peerKey = SecKeyCreateWithData(
            peer as CFData,
            [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            ] as CFDictionary,
            &error) else {
            return BridgeHost.status(from: error?.takeRetainedValue())
        }
        guard let shared = SecKeyCopyKeyExchangeResult(
            key,
            .ecdhKeyExchangeStandard,
            peerKey,
            attributes as CFDictionary,
            &error) as Data? else {
            return BridgeHost.status(from: error?.takeRetainedValue())
        }
        shared.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    /// Two pushes: the public key, then the attestation blob.
    ///
    /// ST-8: the attestation "is a Tier-1 OUTPUT, not a Tier-2 record" — it is
    /// produced at enrolment and consumed by the approving OSK device, and "a
    /// stored blob is not evidence of anything at a later date and MUST NOT be
    /// re-presented as though it were." So it is produced fresh here rather than
    /// read from anywhere.
    ///
    /// An element with no attestation pushes an **empty** second item, which
    /// Rust distinguishes from "no attestation was produced".
    func publicKey(_ keyTag: tw_ios_slice, into sink: UnsafeMutableRawPointer?) -> tw_ios_status {
        guard let tag = BridgeHost.string(keyTag) else {
            return tw_ios_status(kind: TW_IOS_KIND_ERRNO, code: EINVAL)
        }
        guard let key = privateKey(tag: tag),
              let publicKey = SecKeyCopyPublicKey(key) else {
            return tw_ios_status(kind: TW_IOS_KIND_OSSTATUS, code: Int32(errSecItemNotFound))
        }
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return BridgeHost.status(from: error?.takeRetainedValue())
        }
        external.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }

        let attestation = Attestation.create(for: key) ?? Data()
        attestation.withUnsafeBytes { raw in
            twinvpn_ios_sink_push(sink, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        return tw_ios_status(kind: TW_IOS_KIND_OK, code: 0)
    }

    private func privateKey(tag: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else {
            return nil
        }
        // A force cast would be a crash on a malformed keychain. The `as?` is
        // the only reason this returns an Optional.
        return result as! SecKey?
    }
}

// MARK: - the vault directory

enum StoreRoot {
    /// Vends the App Group container with its attributes **already applied**.
    ///
    /// CB-7 puts exactly this on the shell's side because "on iOS the app-group
    /// container URL, the file protection class, and the backup-exclusion flag
    /// are Objective-C APIs". ST-12e adds that the path is vended at
    /// construction and the core "MUST NOT derive, probe, or fall back to a path
    /// of its own".
    static func prepare(appGroupIdentifier: String) throws -> URL {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ENOENT))
        }
        let root = container.appendingPathComponent("store", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true,
            attributes: [
                // ST-6: exactly this class. `NSFileProtectionComplete` "makes the
                // vault unreadable while the device is locked, which breaks the
                // extension for the same reason ST-5 does" — the provider must
                // rekey with the screen locked.
                .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
            ])
        var mutable = root
        var values = URLResourceValues()
        // ST-26: exclusion is a MUST on every platform that has a mechanism.
        values.isExcludedFromBackup = true
        try mutable.setResourceValues(values)
        return root
    }

    /// ST-26: "re-verified at **every** start; a failure is
    /// `STORE.BACKUP_EXCLUSION_FAILED`, not a silent success."
    ///
    /// That code is absent from the frozen registry (see the crate README), so
    /// the fact travels to the core as `StoreRootAttributes::backup_excluded`
    /// and is recorded there rather than invented here.
    static func isBackupExcluded(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]))?
            .isExcludedFromBackup ?? false
    }
}
