/*
 * TwinVPNBridgeTests-Bridging-Header.h — what the XCTest bundle compiles Swift
 * against.
 *
 * `twinvpn_bridge.h` and NOTHING ELSE. The suite tests the ABI of this shell; it
 * has no business seeing `TwinVPNXPCShim.h`'s Apple SPI, and importing it here
 * would let a test reach a surface the extension deliberately keeps private to
 * one file (`ManagementListener.swift`'s `auditTokenBytes(for:)`).
 */

#ifndef TWINVPN_BRIDGE_TESTS_BRIDGING_HEADER_H
#define TWINVPN_BRIDGE_TESTS_BRIDGING_HEADER_H

#include "twinvpn_bridge.h"

#endif /* TWINVPN_BRIDGE_TESTS_BRIDGING_HEADER_H */
