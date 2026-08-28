//
//  ManagementListener.swift
//  com.twinvpn.app.sysext
//
//  The XPC half of the management interface, which after `ownership.md` §9.6
//  **X-7** lives inside the authority — this extension.
//
//  Authority: ADR-0016 §11.2's macOS row and amendment **PS-22** ("the
//  management interface over XPC with `audit_token_t` (§11.14 (a))"), §11.14 (a),
//  PS-3, PS-4; ADR-0017 §11.2's macOS row (the Mach service
//  `com.twinvpn.agent.mgmt` and its audit-token attestation), §11.7, MI-A1,
//  MI-A2, MI-A5, MI-20, MI-21.
//
//  ============================================================================
//  CB-2: THERE IS NO DECISION IN THIS FILE.
//
//  Every line below does one of four things: accept a connection, copy the
//  sending process's `audit_token_t` out of it, hand a byte string to Rust, or
//  hand Rust's byte string back. It does not decode the envelope, does not know
//  what a scope is, does not decide whether a principal may run an operation,
//  does not construct a reply, and does not classify a refusal.
//
//  The branches that DO exist are on:
//    - whether an XPC object is a connection or a data message — a shape, not a
//      meaning;
//    - whether a Rust call succeeded — `TVB_OK` versus an envelope;
//    - whether a session has been opened on this connection — the shell's own
//      bookkeeping.
//
//  ============================================================================
//  WHY SWIFT OWNS THE LISTENER AND RUST OWNS EVERYTHING ELSE
//
//  XPC's listener is a block-based Objective-C API. There is no way to register
//  an event handler from Rust without hand-building an `_NSConcreteStackBlock`
//  literal, which is a large piece of unverifiable `unsafe` for a boundary that
//  is three function calls wide. So Swift accepts and marshals, and every
//  decision stays in `twinvpn-bridge`'s `mgmt` module, where `cargo test` runs
//  it on the Linux CI host.
//
//  That split is `ownership.md` §10.4's ruling applied literally: "the missing
//  capabilities stay in Rust, in-process, reached through a per-platform
//  `extern "C"` bridge … Swift and Kotlin marshal; they do not decide."
//
//  ============================================================================
//  THE SECOND CARRIAGE, AND WHY IT IS NOT IN THIS FILE
//
//  ADR-0017 §11.2's macOS row gives this platform TWO channels for one contract:
//  this Mach service, and `AF_UNIX` at `/var/run/twinvpn/mgmt.sock` "for non-XPC
//  clients such as the CLI". The socket one is bound and served entirely in
//  Rust (`twinvpn-bridge`'s `host::Host::accept_management`) because nothing
//  about it needs a block. One contract, two carriages, one set of decisions.
//
//  ============================================================================
//  PS-3: A CLIENT GOING AWAY CHANGES NOTHING
//
//  An invalidated connection drops a `ManagementSession` and nothing else. It
//  does not change `session_intent`, the enforcement mode, the installed rule
//  set or the `ConnectionState` — and it cannot, because this file holds none of
//  them and the ABI has no entry that would let it.
//
//  ============================================================================
//  NOTHING HERE HAS BEEN COMPILED.
//
//  There is no Darwin SDK on the host this was written on: `XPC` and
//  `NetworkExtension` do not exist there. Every API shape below is a
//  read-the-documentation claim, and `shells/macos/README.md` §7 says so.
//

import Foundation
import XPC

/// The Mach service the extension vends for the management interface.
///
/// **One spelling, in three places, and they are checked against each other by
/// review rather than by a test:** here, `twinvpn_mi::XPC_SERVICE_NAME` in Rust,
/// and `NEMachServiceName` in `packaging/TwinVPNTunnel.Info.plist`. ADR-0017
/// §11.2's macOS row is where the name comes from.
///
/// It is deliberately **not** the bundle identifier (`com.twinvpn.app.sysext`,
/// PS-19): the bundle is what the extension is called, the service is what it
/// answers on, and a reader who conflated them would look for the MI on the
/// wrong name.
private let managementServiceName = "com.twinvpn.agent.mgmt"

/// Accepts management connections and marshals their messages into Rust.
///
/// `@unchecked Sendable` records the judgement explicitly: XPC delivers events
/// on the queue this object hands it, and the mutable state below (`sessions`)
/// is confined to that queue.
final class ManagementListener: @unchecked Sendable {

    /// The XPC key the request bytes travel under.
    ///
    /// **Opaque to this file.** MI-20 puts the envelope's schema in
    /// `twinvpn-mgmt`; this is the name of the dictionary slot the bytes sit in,
    /// which is transport plumbing and not contract.
    private static let requestKey = "twinvpn.mi.request"

    /// The key the reply travels under.
    private static let replyKey = "twinvpn.mi.response"

    private let bridge: CoreBridge
    private let queue: DispatchQueue
    private var listener: xpc_connection_t?

    /// One session per connection, keyed by the connection's identity.
    ///
    /// A session, not a scope set: MI-S2 makes the granted set attach-time and
    /// immutable, and it lives on the Rust side of the boundary where it was
    /// computed. This map holds handles and nothing else.
    private var sessions: [ObjectIdentifier: ManagementSession] = [:]

    init(bridge: CoreBridge) {
        self.bridge = bridge
        // A serial queue, deliberately. Two messages on one connection are one
        // conversation and their order is part of the contract — `Hello` first
        // (§11.7), then requests. A concurrent queue would let a request
        // overtake the attach that authorized it.
        self.queue = DispatchQueue(label: "com.twinvpn.agent.mgmt.listener")
    }

    // MARK: - Lifecycle

    /// Starts accepting.
    ///
    /// Called from `startTunnel` **after** `tvb_ext_start` has returned a
    /// handle, and never before: the Rust side answers `MGMT.UNAVAILABLE` for a
    /// session opened against an extension whose start refused, and advertising
    /// a service that can only refuse is the shape MI-A3 rejects socket
    /// activation for.
    func start(correlation: Correlation) {
        guard listener == nil else { return }
        let listener = xpc_connection_create_mach_service(
            managementServiceName,
            queue,
            UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(listener) { [weak self] event in
            self?.accept(event, correlation: correlation)
        }
        xpc_connection_resume(listener)
        self.listener = listener
        TunnelLog.provider.info("mgmt.listener.started", correlation)
    }

    /// Stops accepting and drops every open session.
    ///
    /// **CB-6 and PS-3, both.** Cancelling the listener removes a channel; it
    /// removes no rule, no route and no resolver entry, and it changes no
    /// product state. The pf anchor is the OS's and outlives this object by
    /// design.
    func stop(correlation: Correlation) {
        if let listener {
            xpc_connection_cancel(listener)
        }
        listener = nil
        queue.sync { sessions.removeAll() }
        TunnelLog.provider.info("mgmt.listener.stopped", correlation)
    }

    // MARK: - Accepting

    private func accept(_ event: xpc_object_t, correlation: Correlation) {
        // `XPC_TYPE_CONNECTION` on the listener means a new peer; anything else
        // on the listener is an error object (`XPC_ERROR_CONNECTION_INVALID` and
        // friends), which is a shape and not a diagnosis.
        guard xpc_get_type(event) == XPC_TYPE_CONNECTION else {
            TunnelLog.provider.error("mgmt.listener.event.not_a_connection", correlation)
            return
        }
        let connection = event as xpc_connection_t
        let identity = ObjectIdentifier(connection as AnyObject)

        // **MI-A1, and the order is the security property.** The principal is
        // established from the kernel's snapshot BEFORE the first byte is
        // parsed. A listener that read the message first would have to decide
        // what to do with a client whose identity it then could not establish,
        // and every answer to that is worse than not having asked.
        let session: ManagementSession
        do {
            session = try bridge.openManagementSession(
                auditToken: Self.auditTokenBytes(for: connection),
                correlation: correlation)
        } catch {
            // **MI-A5**: an unverifiable identity is a closed connection, never
            // a default principal. There is no envelope to send, because there
            // is no session that could have produced one.
            TunnelLog.provider.error("mgmt.listener.principal_unverifiable", correlation)
            xpc_connection_cancel(connection)
            return
        }
        sessions[identity] = session

        xpc_connection_set_event_handler(connection) { [weak self] message in
            self?.handle(message, from: connection, identity: identity, correlation: correlation)
        }
        xpc_connection_resume(connection)
    }

    // MARK: - One message

    private func handle(
        _ message: xpc_object_t,
        from connection: xpc_connection_t,
        identity: ObjectIdentifier,
        correlation: Correlation
    ) {
        let type = xpc_get_type(message)
        guard type == XPC_TYPE_DICTIONARY else {
            // Every error XPC delivers on a peer connection means the same
            // thing to this file: the peer is gone. PS-3 — dropping the session
            // is the whole of the response.
            sessions.removeValue(forKey: identity)
            return
        }
        guard let session = sessions[identity] else {
            xpc_connection_cancel(connection)
            return
        }

        var length = 0
        guard let raw = xpc_dictionary_get_data(message, Self.requestKey, &length) else {
            // A dictionary with no request slot is not an MI message. Nothing is
            // decoded here to find that out — the slot is either present or it
            // is not.
            xpc_connection_cancel(connection)
            sessions.removeValue(forKey: identity)
            return
        }
        let request = Array(UnsafeRawBufferPointer(start: raw, count: length))

        let step = correlation.child()
        do {
            let response = try session.exchange(request, correlation: step)
            let reply = xpc_dictionary_create_reply(message) ?? xpc_dictionary_create(nil, nil, 0)
            response.withUnsafeBufferPointer { buffer in
                xpc_dictionary_set_data(
                    reply, Self.replyKey, buffer.baseAddress, buffer.count)
            }
            xpc_connection_send_message(connection, reply)
        } catch {
            // The Rust side produces an envelope for every refusal it can name;
            // reaching here means it could not produce one at all, which is the
            // session being gone. Closing is the honest answer and the client
            // reads it as `MGMT.UNAVAILABLE`, which is the code ADR-0017 §11.12
            // has a client mint for exactly this.
            TunnelLog.provider.error("mgmt.exchange.no_session", step)
            xpc_connection_cancel(connection)
            sessions.removeValue(forKey: identity)
        }
    }

    // MARK: - The audit token

    /// The sending process's credentials, as the kernel snapshotted them.
    ///
    /// **The one function to change if the SPI in `TwinVPNXPCShim.h` ever has to
    /// go.** `NSXPCConnection` publishes `effectiveUserIdentifier`,
    /// `effectiveGroupIdentifier`, `processIdentifier` and
    /// `auditSessionIdentifier`, which between them cover the two fields the
    /// authorization decision uses — ADR-0016 PS-12a's class map needs a uid and
    /// a gid. What the public four cannot give is `pidversion`, and a build that
    /// used them would have to fabricate the remaining words of a struct that
    /// claims to be a kernel snapshot. That is why this build takes the SPI, and
    /// why the swap is confined to this function rather than to the protocol.
    ///
    /// See `TwinVPNXPCShim.h` for the full statement of the trade.
    private static func auditTokenBytes(for connection: xpc_connection_t) -> [UInt8] {
        var token = audit_token_t()
        xpc_connection_get_audit_token(connection, &token)
        return withUnsafeBytes(of: &token) { Array($0) }
    }
}
