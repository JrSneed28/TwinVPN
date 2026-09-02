//  DeviceCapabilities.swift — the one predicate that separates the two lanes.
//
//  Authority: docs/implementation/ownership.md §10.3 and §10.5 rule 2;
//  ADR-0018 §11.9 row 1.
//
//  ===========================================================================
//  WHY THIS IS ITS OWN FILE
//  ===========================================================================
//
//  It is compiled into BOTH test targets — `TwinVPNTests`, whose every case
//  skips itself unless this is true, and `TwinVPNAcceptanceTests`, whose
//  simulator rows assert that it is false so that a hosted run can never be
//  read as device evidence. One declaration, because a second copy of the
//  predicate that decides which acceptance criterion a run discharges is a
//  second thing that can drift, and the drift would be a simulator file
//  claiming a device row.
//
//  STATUS: written, not compiled on the build host. `make swift-parse` is a
//  SYNTAX check and nothing more (ownership.md §10.3).

import Foundation

/// What the machine running this bundle can actually do.
enum DeviceCapabilities {
    /// True on a provisioned iPhone or iPad, false in the simulator.
    ///
    /// The simulator is not an emulator: it is a group of processes running
    /// natively on macOS and using the macOS kernel for networking, which is why
    /// an iOS NetworkExtension provider cannot run in it at all. So there is no
    /// Secure Enclave, no jetsam, no real `includeAllNetworks` and no
    /// enforcement point — and every device-bound assertion is vacuous here
    /// rather than merely unsupported.
    static var isPhysicalDevice: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
}
