//  ConnectWiringTests.swift — the focal disc's action, and the error table it
//  reports through.
//
//  Authority: `shells/ios/DESIGN.md` D4, §10; ADR-0012 §11.10; ADR-0018 §11.12;
//  ADR-0019 §11.10 (a); `twinvpn_platform_ios::oserr::from_ne_vpn_error`.
//
//  ==========================================================================
//  WHY THIS FILE EXISTS NOW AND NOT BEFORE
//  ==========================================================================
//
//  `VPNPermission.install(enforcement:)` and `startTunnel()` had no caller
//  outside the test suites, which is what DESIGN.md §10 recorded. A method with
//  no caller cannot report the wrong reason code to anyone, so `install`'s
//  blanket `catch let error as NSError where error.domain == NEVPNErrorDomain
//  -> PLATFORM.VPN_PERMISSION_DENIED` was inert.
//
//  The disc is now that caller. The blanket catch stopped being inert the moment
//  it was wired, because `NEVPNErrorConnectionFailed` — which
//  `from_ne_vpn_error` classes `AdapterUnavailable` — would have been rendered
//  as the grant being refused, sending a user to Settings to re-approve a
//  profile they had already approved.
//
//  These assertions are in-process and touch no daemon: `reasonCode(forNEVPNError:)`
//  is a `switch` over an `Int`, which is the same shape `oserr.rs` chose so its
//  own tests could run on a Linux host, and `connect()`'s two non-OS branches are
//  reached with an injected `loadPreferences`.

import Foundation
import NetworkExtension
import XCTest

@MainActor
final class ConnectWiringTests: XCTestCase {

    // MARK: - the NEVPNError table agrees with Rust's

    /// `from_ne_vpn_error`, case for case.
    ///
    /// The six constants are `oserr.rs`'s `NE_VPN_*`, transcribed from
    /// `NEVPNConnection.h`. Rust maps `configurationDisabled` and
    /// `configurationReadWriteFailed` to `VpnPermissionDenied`, and
    /// `connectionFailed`, `configurationInvalid`, `configurationUnknown` and its
    /// `_` arm to `AdapterUnavailable`.
    func testTheErrorTableMatchesTheRustMapping() {
        let grant = [
            2,  // NE_VPN_CONFIGURATION_DISABLED
            5,  // NE_VPN_CONFIGURATION_READ_WRITE_FAILED
        ]
        let adapter = [
            1,  // NE_VPN_CONFIGURATION_INVALID
            3,  // NE_VPN_CONNECTION_FAILED
            6,  // NE_VPN_CONFIGURATION_UNKNOWN
            99, // Rust's `_` arm
        ]

        for code in grant {
            XCTAssertEqual(
                VPNPermission.reasonCode(forNEVPNError: code),
                "PLATFORM.VPN_PERMISSION_DENIED",
                "NEVPNError \(code) is the GRANT in from_ne_vpn_error")
        }
        for code in adapter {
            XCTAssertEqual(
                VPNPermission.reasonCode(forNEVPNError: code),
                "PLATFORM.ADAPTER_UNAVAILABLE",
                "NEVPNError \(code) is AdapterUnavailable in from_ne_vpn_error")
        }
        XCTAssertEqual(grant.count + adapter.count, 6)
    }

    /// The regression the wiring created, named on its own.
    ///
    /// `connectionFailed` must NOT be reported as the user refusing consent.
    func testAConnectionFailureIsNotReportedAsARefusedGrant() {
        XCTAssertNotEqual(
            VPNPermission.reasonCode(forNEVPNError: 3),
            "PLATFORM.VPN_PERMISSION_DENIED")
    }

    // MARK: - `connect()`

    /// With no profile, the disc's action asks the core for a posture, is
    /// refused, and installs NOTHING.
    ///
    /// ADR-0018 §11.12: `core-lite` "performs NO command" —
    /// `Core::submit_response` refuses under `#[cfg(not(feature = "full"))]` with
    /// `PLATFORM.ADAPTER_UNAVAILABLE` — so `CoreLite.makeEnforcementProgramme`
    /// has nothing to return. What matters is the DIRECTION of that failure: no
    /// profile is written, and the state does not advance.
    ///
    /// If this test ever fails because a profile WAS installed, the thing to
    /// check is not this file — it is whether something started inventing an
    /// `EnforcementProgramme` in Swift, which
    /// `Sources/TwinVPNShared/EnforcementProgramme.swift`'s header forbids.
    func testConnectWithNoProfileRefusesAndInstallsNothing() async {
        let permission = VPNPermission(loadPreferences: { [] })
        await permission.reload()
        XCTAssertEqual(permission.state, .absent)

        await permission.connect()

        XCTAssertEqual(
            permission.state, .absent,
            "no posture is obtainable in this process, so nothing may be installed")
        XCTAssertEqual(permission.reasonCode, "PLATFORM.ADAPTER_UNAVAILABLE")
        XCTAssertNil(permission.manager, "a refused install leaves no manager behind")
    }

    /// A denied profile is not actionable from the app, and `connect()` says so
    /// by doing nothing.
    ///
    /// ADR-0012 §11.10: "on iOS/iPadOS the **only** unblock mechanism is removing
    /// the VPN profile in Settings — this is not 'ours', not a command." So the
    /// invariant is that `connect()` neither clears the standing reason code nor
    /// moves the state: the diagnostic panel is carrying the user's next action,
    /// and a disc that wiped it would remove the only instruction on screen.
    func testConnectOnADeniedProfileChangesNothing() async {
        let permission = VPNPermission(
            loadPreferences: { throw NEVPNError(.configurationInvalid) })
        await permission.reload()
        XCTAssertEqual(permission.state, .denied)
        let standing = permission.reasonCode
        XCTAssertNotNil(standing)

        await permission.connect()

        XCTAssertEqual(permission.state, .denied)
        XCTAssertEqual(
            permission.reasonCode, standing,
            "the standing diagnostic is the user's next action; connect() must not clear it")
    }
}
