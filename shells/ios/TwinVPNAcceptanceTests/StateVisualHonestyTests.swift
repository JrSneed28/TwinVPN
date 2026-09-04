//  StateVisualHonestyTests.swift — DESIGN.md D2 and O-18, as assertions.
//
//  Authority: `shells/ios/DESIGN.md` D2 ("Three hues, and *in progress* has
//  none"), §2.4 (the state mapping table); ADR-0015 §11.6 O-18.
//
//  ==========================================================================
//  WHY A VISUAL RULE IS TESTED HERE AND NOT LOOKED AT
//  ==========================================================================
//
//  DESIGN.md D2 is not a taste rule. It is a product-honesty rule expressed as
//  a palette: "O-18 already says an unrenewed assertion rounds to `UNKNOWN`,
//  never `PROTECTED`; a design that gave *Connecting* a hopeful blue would be
//  re-asserting in pixels what the state model refuses to assert in data."
//
//  So the failure this file guards against is a security-shaped one — a user
//  reading "protected" off a screen at a moment the product cannot assert it —
//  and it lives in exactly one place: `StateVisual.resolve`, a pure function of
//  three values. A pure function is testable without a device, without a
//  simulator display, and without rendering anything.
//
//  This is why `Sources/TwinVPNApp/Views/DesignSystem.swift` is named as an
//  explicit source of this target while the rest of `Views/` stays excluded.
//  The exclusion's stated reason is "SwiftUI presentation, which no assertion
//  here reaches"; the mapping table is not presentation, it is the rule the
//  presentation obeys, and this file is the assertion that reaches it.
//
//  It asserts NOTHING about colour values, layout, materials or motion. Those
//  are looked at, or diffed by P18 oracle-5, not unit-tested.

// No `import TwinVPNApp`: this target COMPILES the app sources it needs
// into its own module rather than hosting the app, so `StateVisual`,
// `ProfileState` and `ProtectionAssertion` are already visible here. That is
// the same arrangement `FailClosedConfigurationTests` relies on.
import Foundation
import XCTest

final class StateVisualHonestyTests: XCTestCase {

    // MARK: - the rule: nothing rounds toward `secure`

    /// D2: everything the product does not yet know renders achromatic.
    ///
    /// The enumeration is exhaustive over the inputs `StateVisual.resolve`
    /// reads, so a later row added to §2.4's table cannot quietly introduce a
    /// hopeful tone for a state that carries no assertion.
    func testNoAbsentAssertionEverResolvesToSecure() {
        var checked = 0
        for profile in Self.allProfileStates {
            for isLive in [true, false] {
                let visual = StateVisual.resolve(
                    profile: profile, isLive: isLive, protection: nil)
                XCTAssertNotEqual(
                    visual.tone, .secure,
                    "profile=\(profile) isLive=\(isLive) with NO assertion resolved to "
                        + "`secure`. O-18: an unrenewed assertion rounds to UNKNOWN, "
                        + "never PROTECTED.")
                XCTAssertNotEqual(
                    visual.symbol, "checkmark.shield.fill",
                    "profile=\(profile) isLive=\(isLive) with NO assertion drew the "
                        + "protected glyph. A11Y-1 makes the glyph a state carrier, so "
                        + "this asserts in pixels what the data refuses to assert.")
                checked += 1
            }
        }
        // A filter that matches nothing exits 0. Assert the loop ran.
        XCTAssertEqual(checked, Self.allProfileStates.count * 2)
    }

    /// A live `protected` assertion is the ONLY way to reach `secure`.
    func testSecureRequiresAProtectedAssertionOnALiveChannel() {
        XCTAssertEqual(
            StateVisual.resolve(
                profile: .installed, isLive: true,
                protection: Self.assertion(.protected)).tone,
            .secure)

        // The same assertion, with the channel not live: O-18's "an unrenewed
        // assertion → the indicator becomes UNKNOWN".
        XCTAssertEqual(
            StateVisual.resolve(
                profile: .installed, isLive: false,
                protection: Self.assertion(.protected)).tone,
            .neutral)
    }

    // MARK: - §2.4's table, row by row

    func testProtectedRow() {
        let visual = StateVisual.resolve(
            profile: .installed, isLive: true, protection: Self.assertion(.protected))
        XCTAssertEqual(visual.tone, .secure)
        XCTAssertEqual(visual.geometry, .tightBright)
        XCTAssertFalse(visual.isBreathing)
        XCTAssertEqual(visual.symbol, "checkmark.shield.fill")
    }

    func testBlockedRow() {
        let visual = StateVisual.resolve(
            profile: .installed, isLive: true, protection: Self.assertion(.blocked))
        XCTAssertEqual(visual.tone, .held)
        XCTAssertEqual(visual.geometry, .tightBright)
        XCTAssertFalse(visual.isBreathing)
        XCTAssertEqual(visual.symbol, "shield.slash.fill")
    }

    func testUnprotectedRow() {
        let visual = StateVisual.resolve(
            profile: .installed, isLive: true, protection: Self.assertion(.unprotected))
        XCTAssertEqual(visual.tone, .attention)
        XCTAssertEqual(visual.geometry, .wideDim)
        XCTAssertFalse(visual.isBreathing)
        XCTAssertEqual(visual.symbol, "exclamationmark.shield.fill")
    }

    /// The three ways to reach the unknown row, each of which §2.4 lists.
    func testUnknownRow() {
        let cases: [(ProfileState, Bool, ProtectionAssertion?)] = [
            (.installed, true, nil),                            // protection == nil
            (.installed, false, Self.assertion(.protected)),    // !isLive
            (.absent, true, Self.assertion(.protected)),        // profile .absent
        ]
        for (profile, isLive, protection) in cases {
            let visual = StateVisual.resolve(
                profile: profile, isLive: isLive, protection: protection)
            XCTAssertEqual(visual.tone, .neutral, "profile=\(profile) isLive=\(isLive)")
            XCTAssertEqual(visual.geometry, .wideDim)
            // §2.4: the unknown row is the only one that breathes.
            XCTAssertTrue(visual.isBreathing)
            XCTAssertEqual(visual.symbol, "questionmark.circle")
        }
    }

    /// §2.4's last row. The profile is read FIRST, so a denied or disabled
    /// configuration wins over whatever a stale snapshot still claims.
    func testDeniedAndDisabledRowsOutrankAStaleProtectedSnapshot() {
        for profile in [ProfileState.denied, .disabled] {
            let visual = StateVisual.resolve(
                profile: profile, isLive: true, protection: Self.assertion(.protected))
            XCTAssertEqual(visual.tone, .attention, "profile=\(profile)")
            XCTAssertEqual(visual.geometry, .wideDim)
            XCTAssertFalse(visual.isBreathing)
            XCTAssertEqual(visual.symbol, "exclamationmark.shield.fill")
        }
    }

    /// D2: "*in progress* has none" — only the unknown row breathes, and only
    /// the two asserted rows are tight and bright.
    func testOnlyTheUnknownToneBreathes() {
        for profile in Self.allProfileStates {
            for isLive in [true, false] {
                for state in Self.allAssertionStates + [nil] {
                    let visual = StateVisual.resolve(
                        profile: profile,
                        isLive: isLive,
                        protection: state.map(Self.assertion))
                    if visual.isBreathing {
                        XCTAssertEqual(
                            visual.tone, .neutral,
                            "a breathing field must be achromatic (D2): "
                                + "profile=\(profile) isLive=\(isLive) state=\(String(describing: state))")
                    }
                    if visual.geometry == .tightBright {
                        XCTAssertTrue(
                            visual.tone == .secure || visual.tone == .held,
                            "only an asserted posture is tight and bright: "
                                + "profile=\(profile) isLive=\(isLive) state=\(String(describing: state))")
                    }
                }
            }
        }
    }

    // MARK: - fixtures

    private static let allProfileStates: [ProfileState] =
        [.absent, .installed, .disabled, .denied]

    private static let allAssertionStates: [ProtectionAssertion.State?] =
        [.protected, .blocked, .unprotected]

    /// `ProtectionAssertion` is `Decodable` and has no memberwise initializer,
    /// so a fixture is built the way the app receives one: from bytes.
    ///
    /// Both families are set to match `state` because §2.4 does not read them —
    /// asserting on a value the function never touches would be a test about
    /// this fixture rather than about the mapping.
    private static func assertion(_ state: ProtectionAssertion.State) -> ProtectionAssertion {
        let isProtected = state == .protected
        let json = """
            {
              "state": "\(state.rawValue)",
              "as_of_ms": 1,
              "family_v4_protected": \(isProtected),
              "family_v6_protected": \(isProtected)
            }
            """
        // A fixture that will not decode is a broken test, not a failing one.
        // swiftlint:disable:next force_try
        return try! JSONDecoder().decode(
            ProtectionAssertion.self, from: Data(json.utf8))
    }
}
