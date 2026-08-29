/*
 * TwinVPNTunnel-Bridging-Header.h — the Objective-C bridging header the system
 * extension target compiles Swift against.
 *
 * Authority: ADR-0018 §11.4 (a hand-written header is the ABI of record),
 * §11.6 (the seam in both directions); ADR-0016 §11.14 (a) (`audit_token_t`
 * over XPC).
 *
 * ===========================================================================
 * WHY IT EXISTS
 * ===========================================================================
 * `shells/macos/README.md` §7 gap 45 recorded it as missing: "There is also **no
 * bridging header**, which `TwinVPNXPCShim.h` needs to be in." Without one,
 * `CoreBridge.swift` cannot see a single `tvb_*` symbol and
 * `ManagementListener.swift` cannot see `xpc_connection_get_audit_token`, so
 * neither file could ever have compiled. Nothing noticed, because nothing on the
 * development host could compile Swift against a Darwin SDK — which is the
 * defect class `build/ci/ci-macos.sh` exists to close.
 *
 * `project.yml` points `SWIFT_OBJC_BRIDGING_HEADER` at this file for the
 * `TwinVPNTunnel` target. It carries exactly two includes and must not grow a
 * third without a reason written here.
 *
 * ===========================================================================
 * A BRIDGING HEADER AND NOT A MODULE MAP, AND WHY THAT DIFFERS FROM shells/ios
 * ===========================================================================
 * `shells/ios` uses a module map (`Sources/TwinVPNBridge/include/
 * module.modulemap`) because it needs TWO modules with different compatibility
 * status: `TwinVPNCore` over the ABI of record and `TwinVPNBridge` over an
 * internal, versionless surface.
 *
 * This shell has one surface — `twinvpn_bridge.h` — and it needs
 * `TwinVPNXPCShim.h` alongside it, which declares Apple SPI and therefore must
 * NOT be exported as a module anyone could import by name. A bridging header is
 * target-private and cannot be imported from elsewhere, which is the property
 * wanted here. The asymmetry between the two shells is deliberate.
 */

#ifndef TWINVPN_TUNNEL_BRIDGING_HEADER_H
#define TWINVPN_TUNNEL_BRIDGING_HEADER_H

/* The Swift <-> Rust ABI of this shell. `Scripts/build-bridge.sh` builds the
 * archive that implements it; `project.yml` links it into this target only. */
#include "twinvpn_bridge.h"

/* `xpc_connection_get_audit_token`, which is Apple SPI. The header explains at
 * length why the SPI is taken and what the public alternative would cost. */
#include "TwinVPNXPCShim.h"

#endif /* TWINVPN_TUNNEL_BRIDGING_HEADER_H */
