//  ManagementClient.swift — the app as a management client of the extension.
//
//  Authority: ADR-0017 §11.2's iOS row, §11.2.1 (the honest subset), §11.3's
//  `MgmtEnvelope`, MI-14, MI-15, MI-16; ADR-0019's iOS row ("the app is a
//  management client of the extension over ADR-0017's platform binding");
//  ADR-0015 O-18; ADR-0016 PS-24; ownership.md §6 rule 6.
//
//  STATUS: written, not compiled.
//
//  ===========================================================================
//  WHAT THE CHANNEL CARRIES, AND WHAT IT DOES NOT
//  ===========================================================================
//
//  ADR-0017 §11.2.1: `NETunnelProviderSession.sendProviderMessage` is "the only
//  Apple-sanctioned app<->provider message path". The CONTRACT is not a subset —
//  "same operations, same scopes, same schema, same reason codes". The CHANNEL
//  is:
//
//  | Property                                            | Status        |
//  |-----------------------------------------------------|---------------|
//  | Full request/response, byte-identical framing         | carried       |
//  | Full operation catalogue, scopes, schema, MGMT.* codes| carried       |
//  | Agent-initiated push (the event stream)               | NOT carried   |
//  | Any message while the session is not connected        | NOT carried   |
//  | A caller other than the containing app                | not applicable|
//
//  The three emulations §11.2.1 sanctions for the missing push are implemented
//  below: scene-bound polling, an App Group change hint, and a stopped session
//  rendered as NOT LIVE.
//
//  ===========================================================================
//  MI-15: NO RENDERED TEXT CROSSES THIS CHANNEL
//  ===========================================================================
//
//  "MI payloads carry codes and typed evidence, never rendered human text. There
//  is no `summary`, `message`, `title`, `description`, or per-code 'user message'
//  field in any MI message, in any version." Rendering happens at the surface
//  that has a locale and a viewport — from `tw_render_diagnostic` (F-10), which
//  this app calls on its own side of the boundary. There is no user-facing string
//  in this file.

import Foundation
import NetworkExtension
import os

/// The app's one client. **One per process, not per scene.**
///
/// ADR-0019 §11.8 and ADR-0017 §11.2.1: under Stage Manager several
/// `UIWindowScene`s may be live, and "opening per-scene clients multiplies poll
/// cost N×". A second replica per scene "would be an **I8** break inside the app
/// and is prohibited".
@MainActor
final class ManagementClient: ObservableObject {
    static let shared = ManagementClient()

    /// The last snapshot, and whether it is live.
    ///
    /// `isLive == false` is ADR-0015 O-18's direction made explicit: a stopped
    /// session cannot be queried, so what is rendered came from the App Group
    /// status record and is marked as not-live rather than shown as current.
    @Published private(set) var snapshot: StatusSnapshot?
    @Published private(set) var isLive = false

    private var session: NETunnelProviderSession?
    private var pollTimer: Timer?
    private var darwinObserver: DarwinNotificationObserver?
    private let log = Logger(subsystem: "net.twinvpn.app", category: "mi")

    /// How often a **visible scene** polls.
    ///
    /// §11.2.1's first emulation: "scene-bound polling — `status.get` at 1 s while
    /// the relevant scene is visible, 0 otherwise". Bound to SCENE VISIBILITY and
    /// not to app foreground, because on iPadOS an app is foreground while a
    /// scene showing nothing relevant is on screen.
    private static let visiblePollInterval: TimeInterval = 1.0

    // MARK: - lifecycle

    /// Binds this client to whatever profile the OS currently has — **or to the
    /// absence of one**.
    ///
    /// # The parameter is optional, and that is the whole point
    ///
    /// ADR-0012 §11.10: "on iOS/iPadOS the **only** unblock mechanism is removing
    /// the VPN profile in Settings — this is not 'ours', not a command". So the
    /// profile can vanish while this object holds a session for it, and the
    /// session object outlives the configuration it came from. Passing `nil`
    /// drops it, which is what makes `refresh` fall to the not-live branch
    /// instead of renewing an assertion about a tunnel whose profile is gone
    /// (O-18).
    ///
    /// Call it after every `VPNPermission.reload()`, which is every launch and
    /// every return from Settings.
    func attach(to manager: NETunnelProviderManager?) {
        session = manager?.connection as? NETunnelProviderSession
        // §11.2.1's second emulation: a Darwin notification carrying NO payload,
        // which triggers a declarative re-read. "A hint that triggers a
        // declarative re-read, never a state delta" — a delta would make the app
        // a second holder of state the provider owns (I8).
        //
        // Armed ONCE. The notification is about the App Group record, not about
        // a particular session, so re-arming it on every attach would churn a
        // process-wide CFNotificationCenter registration for no change in what it
        // observes.
        guard darwinObserver == nil else { return }
        darwinObserver = DarwinNotificationObserver(name: StatusRecord.changeNotification) {
            [weak self] in
            Task { @MainActor in await self?.refresh() }
        }
    }

    /// Starts polling. Call when a scene becomes visible.
    func beginPolling() {
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(
            withTimeInterval: Self.visiblePollInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        Task { await refresh() }
    }

    /// Stops polling. Call when the last relevant scene stops being visible.
    ///
    /// The battery cost of polling is §11.2.1's stated residual, and stopping it
    /// the moment nothing is watching is the only mitigation the platform allows.
    func endPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    // MARK: - the request/response half

    /// Sends one `MgmtEnvelope` and awaits the response.
    ///
    /// The envelope is built and parsed by `core-lite` in this process. This
    /// function moves bytes.
    func send(_ envelope: Data) async throws -> Data {
        guard let session, session.status == .connected else {
            // §11.2.1: "`sendProviderMessage` fails when stopped; status of a
            // stopped tunnel is NOT obtainable from the provider." The channel
            // says so with `MGMT.CHANNEL_UNSUPPORTED`, which `core-lite`
            // resolves — this layer only reports that the channel refused.
            throw ManagementChannelError.notConnected
        }
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(envelope) { response in
                    guard let response else {
                        continuation.resume(throwing: ManagementChannelError.noResponse)
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func refresh() async {
        // NO SESSION AND A DISCONNECTED SESSION ARE THE SAME ANSWER, and merging
        // them is a fix, not a tidy-up. These used to be two guards, and the
        // first one was `guard let session else { return }` — a bare return that
        // left `snapshot` and `isLive` exactly as the last successful poll had
        // set them. So the sequence "tunnel connects, poll succeeds, user removes
        // the profile in Settings" ended with `isLive == true` and a snapshot
        // still claiming `protected`, renewed by nothing. That is precisely the
        // reading O-18 forbids: "an unrenewed assertion → the indicator becomes
        // UNKNOWN, never PROTECTED."
        guard let session, session.status == .connected else {
            // §11.2.1's third emulation: render from the App Group status record
            // and mark it NOT LIVE. O-18: an assertion that cannot be renewed
            // becomes `UNKNOWN`, never `PROTECTED`.
            snapshot = StatusRecord.read()
            isLive = false
            return
        }
        do {
            let request = CoreLite.shared.makeStatusRequest()
            let response = try await send(request)
            // Parsed and verified by `core-lite`, in this process, per ADR-0018
            // §11.12. MI-14: the resolved attribute set travels WITH the code,
            // so an unrecognised code still renders correctly.
            snapshot = CoreLite.shared.decodeStatus(response)
            isLive = true
        } catch {
            log.notice("management poll failed")
            isLive = false
        }
    }
}

enum ManagementChannelError: Error {
    /// The session is not connected, so the channel cannot carry anything.
    case notConnected
    /// The provider replied with nothing.
    case noResponse
}
