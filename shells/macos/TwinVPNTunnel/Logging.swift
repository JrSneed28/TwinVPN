//
//  Logging.swift
//  com.twinvpn.app.sysext
//
//  Authority: ADR-0015 (observability and diagnostics) §11.2 (the diagnostic
//  envelope), §11.4 (the sensitivity classes and what may never be recorded),
//  §11.5 (levels); ADR-0018 CB-4 (no rendered string in the core, and no
//  interpretation of one in the shell).
//
//  ============================================================================
//  THE RULE THIS FILE EXISTS TO MAKE STRUCTURAL
//
//  Nothing that could carry a key, a session key, a tunnel payload, a pairing
//  secret or a token is logged AT ALL — not redacted, not truncated, not hashed,
//  not at `.private`. Redaction is a property of the API's SHAPE here, not of
//  the caller's care:
//
//    - no function in this file accepts `Data`, `[UInt8]`, `UnsafeRawPointer`
//      or `NEPacket`. There is no overload a packet could be passed to.
//    - the only free-form parameter is `String`, and every call site that has
//      one passes a compile-time literal or an identifier.
//    - the ONE place bytes reach a log is `BridgeError`'s envelope, which is
//      an ADR-0015 §11.2 diagnostic envelope produced by the core — a document
//      whose redaction the core already performed — and it is emitted at
//      `.private` and never parsed.
//
//  A reviewer's check is therefore mechanical: grep this file for `Data`. If
//  there is a hit, the guarantee is gone.
//
//  ============================================================================
//  CORRELATION
//
//  ADR-0015 requires `correlation_id` and `causation_id` to be preserved across
//  EVERY boundary, including the FFI hop. They are therefore not optional
//  parameters with defaults — every entry point below takes a `Correlation`,
//  so a call that has not got one does not compile.
//
//  CB-2: nothing here decides anything. A log level is not a domain fact, and
//  no function in this file branches on a `reason_code`, a state, or a class.
//

import Foundation
import os

/// The identifiers that travel with a unit of work, unchanged, across the FFI
/// hop and back.
///
/// ADR-0015: `correlation_id` identifies the whole causal chain;
/// `causation_id` identifies the immediate parent step. The shell **generates**
/// them where it is the origin of the chain (a `startTunnel` the OS initiated
/// is such an origin) and otherwise **carries** the ones it was given. It never
/// interprets them, and it never derives a decision from one.
struct Correlation: Sendable, Hashable {
    let correlationID: String
    let causationID: String?

    /// A fresh chain, for a boundary the OS initiated and no caller supplied an
    /// id for — `startTunnel`, `sleep`, `wake`.
    ///
    /// A UUID rather than a counter: a counter would need state that survives a
    /// provider restart, and a provider restart is precisely when two chains
    /// must not collide.
    static func origin() -> Correlation {
        Correlation(correlationID: UUID().uuidString, causationID: nil)
    }

    /// A child step of this chain.
    func child() -> Correlation {
        Correlation(correlationID: correlationID, causationID: UUID().uuidString)
    }

    /// The bytes handed across the FFI hop. UTF-8, length-delimited by the
    /// caller — `twinvpn_bridge.h`'s `tvb_slice` is never NUL-reliant (F-3).
    var wireBytes: [UInt8] { Array(correlationID.utf8) }
}

/// The shell's log surface.
///
/// One type, so that "where does this shell write to the log" has one answer.
/// `os.Logger` rather than `print` or `NSLog`: a system extension has no stdout
/// anybody reads, and `os_log`'s privacy annotations are enforced by the
/// logging system rather than by the format string's author.
struct TunnelLog: Sendable {
    /// The subsystem is the bundle identifier, so `log stream --predicate
    /// 'subsystem == "com.twinvpn.app.sysext"'` is the one command an operator
    /// needs.
    private static let subsystem = "com.twinvpn.app.sysext"

    private let logger: Logger

    init(category: String) {
        self.logger = Logger(subsystem: Self.subsystem, category: category)
    }

    static let provider = TunnelLog(category: "provider")
    static let bridge = TunnelLog(category: "bridge")
    static let settings = TunnelLog(category: "settings")
    static let packets = TunnelLog(category: "packets")

    // MARK: - Entry points
    //
    // Every one takes a `Correlation`. Every one takes `event` as a stable,
    // non-localised tag — the same discipline as `OsDetail.call` on the Rust
    // side: "a name a support case greps for, never a sentence". CB-4 keeps
    // rendered, user-facing strings out of anything that is not a UI, and a log
    // line is not a UI.

    func info(_ event: StaticString, _ correlation: Correlation) {
        logger.info("\(event, privacy: .public) cid=\(correlation.correlationID, privacy: .public) caus=\(correlation.causationID ?? "-", privacy: .public)")
    }

    func notice(_ event: StaticString, _ correlation: Correlation) {
        logger.notice("\(event, privacy: .public) cid=\(correlation.correlationID, privacy: .public) caus=\(correlation.causationID ?? "-", privacy: .public)")
    }

    func error(_ event: StaticString, _ correlation: Correlation) {
        logger.error("\(event, privacy: .public) cid=\(correlation.correlationID, privacy: .public) caus=\(correlation.causationID ?? "-", privacy: .public)")
    }

    /// A count. Safe at `.public` because a cardinality is not a payload:
    /// "how many routes did the core send" identifies nothing about a user.
    func info(_ event: StaticString, count: Int, _ correlation: Correlation) {
        logger.info("\(event, privacy: .public) n=\(count, privacy: .public) cid=\(correlation.correlationID, privacy: .public)")
    }

    /// An identifier a user's network could be inferred from — an interface
    /// name, a domain, a host. ADR-0015 §11.4 classes these `SENSITIVE`, so
    /// they are `.private`: present in the log for a support case with the
    /// device in hand, absent from anything sent anywhere.
    func info(_ event: StaticString, sensitive value: String, _ correlation: Correlation) {
        logger.info("\(event, privacy: .public) v=\(value, privacy: .private) cid=\(correlation.correlationID, privacy: .public)")
    }

    /// The one place bytes reach a log.
    ///
    /// `envelope` is an ADR-0015 §11.2 diagnostic envelope the CORE produced —
    /// a document the core has already redacted, carrying a registered
    /// `reason_code`. The shell logs it verbatim and **never parses it**: CB-2
    /// forbids a branch whose condition is a `reason_code` class, and a shell
    /// that read the envelope to decide anything would be exactly that branch.
    ///
    /// `.private` even so. The envelope is not secret, but it is a support
    /// artifact, and the default for anything the shell did not itself author
    /// is that it does not leave the device.
    func error(_ event: StaticString, envelope: String, _ correlation: Correlation) {
        logger.error("\(event, privacy: .public) env=\(envelope, privacy: .private) cid=\(correlation.correlationID, privacy: .public)")
    }
}
