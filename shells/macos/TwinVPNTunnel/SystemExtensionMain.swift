//  SystemExtensionMain.swift — the system extension's entry point.
//
//  Authority: ADR-0016 §11.2's macOS component row and §12.6 / MX-1 (a system
//  extension, NOT an app extension); ADR-0018 §11.9 row 5.
//
//  ===========================================================================
//  WHY THIS FILE EXISTS
//  ===========================================================================
//  Run 33287265563 failed here, and the diagnostic was NOT about the core:
//
//      Undefined symbols for architecture arm64:
//        "_main", referenced from:
//            <initial-undefines>
//      ld: symbol(s) not found for architecture arm64
//
//  `libtwinvpn_bridge.a` was found and read on that run — the linker emitted
//  per-object-file warnings naming its arm64 members, which it can only do
//  after opening the archive — so `LIBRARY_SEARCH_PATHS`, `-ltwinvpn_bridge`
//  and `build-bridge.sh`'s `lipo` step were all already correct. What was
//  missing was an entry point.
//
//  A system extension is an EXECUTABLE, and that is the whole difference from
//  the iOS shell. `shells/ios`'s `TwinVPNProvider` is an app extension: a
//  bundle the OS loads, entered at `NSExtensionMain`, whose principal class
//  comes from `Info.plist` and which therefore has no `main` of its own. A
//  macOS system extension is a Mach-O executable that `systemextensionsd`
//  launches as its own process, so it needs `main` exactly like any other
//  program. `TwinVPNApp/main.swift` supplies one for the containing app; this
//  is the same obligation for the extension, and nothing was meeting it.
//
//  ===========================================================================
//  WHAT IT MAY AND MAY NOT DO
//  ===========================================================================
//  `NEProvider.startSystemExtensionMode()` hands the process to the
//  NetworkExtension machinery, which reads `Info.plist`'s
//  `NetworkExtension` -> `NEProviderClasses` ->
//  `com.apple.networkextension.packet-tunnel` key, finds
//  `TwinVPNPacketTunnelProvider` by the Objective-C name
//  `PacketTunnelProvider.swift` pins with `@objc(TwinVPNPacketTunnelProvider)`,
//  and instantiates it when a tunnel is started. So the class is reached
//  through the plist, never by being named here — and this file must NOT
//  construct a provider, open the bridge, or touch `tvb_*`. ADR-0016 §11.6
//  gives `tvb_ext_start` the privilege posture check, and a process that had
//  already done work before the OS asked it to would be doing that work outside
//  the check.
//
//  `dispatchMain()` then parks the main thread on the dispatch queue and never
//  returns. It is not a busy-wait and it is not a run loop of this file's
//  making: the NetworkExtension callbacks arrive on GCD, and returning from
//  `main` instead would exit the process the instant it finished launching.
//
//  ===========================================================================
//  `@main`, AND NOT A FILE CALLED `main.swift`
//  ===========================================================================
//  Apple's system-extension samples put this in a `main.swift` as top-level
//  code, because top-level executable code is only legal in a file with that
//  exact name. `@main` on a type with a `static func main()` is the other
//  documented spelling of the same entry point, it produces the same `_main`
//  symbol, and it is the one this shell can use.
//
//  The reason is `make swift-parse`, which passes EVERY `.swift` under
//  `shells/macos` to a single `swiftc -parse`. `TwinVPNApp/main.swift` already
//  claims that filename, and a second one is rejected outright:
//
//      error: filename "main.swift" used twice:
//      'shells/macos/TwinVPNApp/main.swift' and
//      'shells/macos/TwinVPNTunnel/main.swift'
//      note: filenames are used to distinguish private declarations with the
//      same name
//
//  That collision is an artefact of the syntax check, not of the real build —
//  Xcode compiles the app and the extension as separate modules, where two
//  `main.swift` files would be fine. But the check is a gate, so the entry
//  point is spelled the way that satisfies both. `@main` requires Swift 5.3;
//  `project.yml` pins language mode 5.9.
//
//  STATUS: written against Apple's documented system-extension provider entry
//  point. `startSystemExtensionMode()` is macOS 10.15+, and `project.yml` sets
//  this target's floor at macOS 11.0, so no availability guard is needed.

import Foundation
import NetworkExtension

@main
enum SystemExtensionMain {
    static func main() {
        // The `autoreleasepool` is Apple's own shape for this entry point: the
        // call creates Objective-C objects that would otherwise have no pool to
        // drain into on a thread that is about to stop returning.
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }

        dispatchMain()
    }
}
