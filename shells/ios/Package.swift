// swift-tools-version:5.9
//
//  Package.swift — SwiftPM, for editor tooling and for `swift build` of the
//  parts that do not need an app bundle.
//
//  Authority: ADR-0018 §11.12 ("/shells/ios/  Swift package + Xcode project
//  (app + NE extension)").
//
//  STATUS: written, not compiled. There is no Swift toolchain on the build host,
//  Darwin or otherwise (ownership.md §10.3).
//
//  This package does NOT build the app or the extension: an `app-extension`
//  target is an Xcode product type with entitlements and an Info.plist, and
//  SwiftPM has no equivalent. `project.yml` is what builds those. What this gives
//  is a module graph an editor can resolve and a place for logic that is worth
//  unit-testing without a device — of which there is deliberately very little,
//  because ownership.md §10.3's design rule pushes everything testable into
//  `core/crates/twinvpn-platform-ios` where it runs on Linux.

import PackageDescription

let package = Package(
    name: "TwinVPN",
    platforms: [
        // ADR-0018 §11.9 row 1, docs/networking.md §5.2's iOS row and ADR-0019's
        // iOS row all fix the minimum at iOS 15.
        .iOS(.v15)
    ],
    products: [
        .library(name: "TwinVPNProviderCore", targets: ["TwinVPNProvider"]),
        .library(name: "TwinVPNAppCore", targets: ["TwinVPNApp"]),
    ],
    targets: [
        // The C bridge, as a system library target. TWO modules — the ABI of
        // record and the internal bridge — because they have entirely different
        // compatibility status; see `include/module.modulemap`.
        .systemLibrary(name: "TwinVPNBridge", path: "Sources/TwinVPNBridge"),

        // `Sources/TwinVPNShared` IS DELIBERATELY NOT A TARGET HERE.
        //
        // `project.yml` lists that directory under BOTH production targets, so
        // in the Xcode build of record `EnforcementProgramme` is compiled into
        // the app's module and into the extension's module, and neither needs an
        // `import`. SwiftPM cannot express that: two targets whose source sets
        // intersect is an overlapping-sources error, and making it a third
        // module instead would need an `import TwinVPNShared` in the consuming
        // files — a line the Xcode build would reject, because there is no such
        // module there. So the sharing is stated in `project.yml`, which is what
        // `build/ci/ci-ios.sh` builds, and this package carries the app and the
        // extension only. Do not "complete" this list without changing the
        // consuming files at the same time.

        .target(
            name: "TwinVPNProvider",
            dependencies: ["TwinVPNBridge"],
            path: "Sources/TwinVPNProvider",
            linkerSettings: [
                // The FULL core, as a staticlib. ADR-0018 §11.9 row 1: <= 12 MB
                // stripped, core RSS <= 9 MB inside ADR-0022's 12 MB provider
                // budget. Built by `Scripts/build-core.sh`, which does not exist
                // yet — see README §3.
                .unsafeFlags(["-L", "Frameworks"]),
                .linkedLibrary("twinvpn_core"),
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
                .linkedFramework("Network"),
            ]),

        .target(
            name: "TwinVPNApp",
            dependencies: ["TwinVPNBridge"],
            path: "Sources/TwinVPNApp",
            // The chrome string catalogue. Declared because an undeclared
            // non-source file under a target path is not bundled — SwiftPM warns
            // ("found 1 file(s) which are unhandled") and carries on, so the
            // failure would be a missing string rather than a red build.
            // `.process`, not `.copy`: the catalogue has to be COMPILED to
            // `.lproj/Localizable.strings`, which is what `.copy` would skip.
            //
            // NOTE THE BUNDLE DIFFERENCE. SwiftPM puts resources in
            // `Bundle.module`; the XcodeGen app target puts them in
            // `Bundle.main`. The view files say `String(localized:)` with no
            // `bundle:` — that is `Bundle.main` — because `project.yml` is the
            // build of record and `Bundle.module` does not exist in it. This
            // package builds a module graph for an editor and produces no
            // running app, so nothing here reads a string at runtime.
            resources: [.process("Resources/Localizable.xcstrings")],
            linkerSettings: [
                // `core-lite`: ADR-0018 §11.12's feature profile of the SAME
                // source — twinvpn-schema, twinvpn-crypto (verification only),
                // twinvpn-store, twinvpn-trust, twinvpn-diag — and NO data-plane
                // crate. "One source, two artifacts; the profile is recorded in
                // S-46 so a support case is answerable."
                .unsafeFlags(["-L", "Frameworks"]),
                .linkedLibrary("twinvpn_core_lite"),
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
            ]),

        // Device-bound. WRITTEN, NOT EXECUTED — see the headers in the suite. A
        // green `swift build` of this target would prove nothing about them, and
        // on this host there is no `swift` to run anyway.
        .testTarget(
            name: "TwinVPNTests",
            dependencies: ["TwinVPNApp"],
            path: "TwinVPNTests"),
    ]
)
