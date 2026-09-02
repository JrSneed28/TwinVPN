//  SupportTypes.swift — the model types the views render, and the App Group
//  status record the app reads when the channel cannot answer.
//
//  Authority: ADR-0017 §11.2.1 (the three emulations), MI-14, MI-16; ADR-0015
//  §11.4 (classification), §11.6 (O-18); ADR-0016 PS-24 condition 2 (one writer
//  per fact); ADR-0022 LC-20.
//
//  STATUS: written, not compiled.

import Foundation

// MARK: - what the status snapshot carries

/// The `ProtectionAssertion` ADR-0015 §11.6 defines, as the app receives it.
///
/// `state` has exactly three values and **`unknown` is not among them** — an
/// absent assertion is modelled as an absent `ProtectionAssertion`, not as a
/// fourth state, so that O-18's "an unrenewed assertion → the indicator becomes
/// UNKNOWN, never PROTECTED" is a property of the OPTIONAL rather than a case a
/// view might forget to handle.
struct ProtectionAssertion: Decodable {
    enum State: String, Decodable {
        case protected
        case blocked
        case unprotected
    }

    let state: State
    /// When the assertion was made, on the suspend-inclusive clock.
    ///
    /// MI-16: every response, event and snapshot row carries `as_of_ms`, "the
    /// time at which the carried value WAS TRUE, stamped by the AGENT, on a
    /// boot-time monotonic clock". On Apple platforms that is
    /// `mach_continuous_time()` — ADR-0022's `ElapsedClock`, never
    /// `MonotonicClock` and never `WallClock` — and §11.2.1 notes that the app
    /// and the provider "share `mach_continuous_time()`, so the property holds
    /// across the subset channel too."
    let asOfMillis: UInt64
    /// Both families, always. ADR-0015 §11.6 requires the assertion to be
    /// produced "for BOTH address families", and a single boolean here would make
    /// "v4 is protected and v6 is not" unsayable — which is ADR-0010 R1's
    /// forbidden asymmetry expressed as a data-model bug.
    let familyV4Protected: Bool
    let familyV6Protected: Bool

    enum CodingKeys: String, CodingKey {
        case state
        case asOfMillis = "as_of_ms"
        case familyV4Protected = "family_v4_protected"
        case familyV6Protected = "family_v6_protected"
    }
}

/// One peer row.
///
/// Every field here is already CLASSIFIED and, where the tier requires it,
/// pseudonymised by the emitter (ADR-0015 §11.4). This app applies no filter of
/// its own: "there is no 'scrub the log with regexes before sending' step."
struct PeerSummary: Decodable, Identifiable {
    let id: String
    /// A `reason_code`, never a sentence. MI-15 forbids rendered text on the
    /// channel; the view renders this through `tw_render_diagnostic`.
    let reasonCode: String?
    let asOfMillis: UInt64

    enum CodingKeys: String, CodingKey {
        case id
        case reasonCode = "reason_code"
        case asOfMillis = "as_of_ms"
    }
}

struct StatusSnapshot: Decodable {
    let protection: ProtectionAssertion?
    let peers: [PeerSummary]
}

// MARK: - the App Group status record

/// The record the app reads when `sendProviderMessage` cannot be used.
///
/// ADR-0017 §11.2.1's third emulation: "stopped-session rendering marked
/// **not-live** (from the last App Group status record and
/// `NEVPNManager.connection.status`)", per ADR-0015 O-18.
///
/// PS-24 condition 2 assigns the writer: this record describes facts "learned,
/// measured or negotiated by the datapath", so the **extension** writes it and
/// the app **reads** it. A cross-write is `INTERNAL.INVARIANT_VIOLATED`, and this
/// type has no write method for exactly that reason.
enum StatusRecord {
    /// The Darwin notification the provider posts after each write.
    ///
    /// §11.2.1's second emulation, and its constraint: the notification carries
    /// **no payload** and is best-effort — "a hint that triggers a declarative
    /// re-read, never a state delta". A delta would make the app a second holder
    /// of state the provider owns (I8).
    static let changeNotification = "net.twinvpn.status.changed"

    private static let filename = "status.json"

    /// Reads the record. **There is deliberately no `write`.**
    ///
    /// ===================================================================
    /// WHY THE BYTE SOURCE IS A PARAMETER
    /// ===================================================================
    ///
    /// `appGroupBytes` resolves an App Group container, and a container URL is
    /// nil without the App Group entitlement — which is applied at the
    /// CODE-SIGN step. So on any build where signing is off, this returns nil
    /// unconditionally, and every `XCTAssertNotEqual(snapshot?.protection?.state,
    /// .protected)` in the acceptance suite passes without ever seeing a
    /// snapshot. That is a vacuous pass: an assertion that cannot fail because
    /// its input is always absent, which is a shape this repository has already
    /// shipped once.
    ///
    /// Passing the source in removes the dependency rather than hoping around
    /// it: a test supplies the exact bytes it wants judged — including the
    /// dangerous ones, a stale record still claiming `protected` — and the
    /// assertion is then about the app's handling and not about whether a
    /// container happened to resolve.
    ///
    /// The default is the real container, so no production path changes.
    static func read(from source: () -> Data? = StatusRecord.appGroupBytes) -> StatusSnapshot? {
        guard let data = source() else { return nil }
        return try? JSONDecoder().decode(StatusSnapshot.self, from: data)
    }

    /// The App Group file the provider writes, as bytes.
    static func appGroupBytes() -> Data? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.net.twinvpn.client") else {
            return nil
        }
        return try? Data(contentsOf: container.appendingPathComponent(filename))
    }
}

/// Observes a payload-free Darwin notification.
final class DarwinNotificationObserver {
    private let name: CFNotificationName
    private let handler: () -> Void

    init(name: String, handler: @escaping () -> Void) {
        self.name = CFNotificationName(name as CFString)
        self.handler = handler
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                Unmanaged<DarwinNotificationObserver>
                    .fromOpaque(observer)
                    .takeUnretainedValue()
                    .handler()
            },
            name as CFString,
            nil,
            .deliverImmediately)
    }

    deinit {
        CFNotificationCenterRemoveEveryObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque())
    }
}

// MARK: - the diagnostic bundle

/// A Tier-1 bundle, already assembled, redacted and signed by `core-lite`.
///
/// The app moves it; it does not build it, filter it, or sign it.
struct DiagnosticBundle {
    /// The bytes, signed with `DeviceKey` (ADR-0015 §11.8).
    let signedBytes: Data
    /// What the user is shown before export (ADR-0019 §11.10 (g)).
    let preview: String
    let suggestedFilename: String
}
