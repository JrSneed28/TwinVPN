/*
 * TwinVPNXPCShim.h - the one Apple symbol this shell declares for itself.
 *
 * Authority: ADR-0016 §11.14 (a) ("`audit_token_t` over XPC"), §11.2's macOS
 * amendment PS-22; ADR-0017 §11.2's macOS row ("XPC audit token"), MI-A1,
 * MI-A2, MI-A5.
 *
 * This header belongs in the extension target's Objective-C bridging header. It
 * exists because of one gap between what the corpus requires and what Apple
 * publishes.
 *
 * ===========================================================================
 * WHY THIS FILE EXISTS, AND WHAT IS WRONG WITH IT
 *
 * ADR-0016 §11.14 (a) requires the transport to "expose the calling process's
 * OS credentials to the authority without the client asserting them", and names
 * `audit_token_t` over XPC as the macOS spelling. ADR-0017 §11.2's macOS row
 * gives the reason: "audit-token attestation is not pid-based and therefore not
 * TOCTOU-able", and MI-A2 names the macOS audit token as the ONE exception to
 * "pid lookups are advisory".
 *
 * `xpc_connection_get_audit_token` is the only API that returns it, and it is
 * **Apple SPI**: it is declared in `<xpc/private.h>`, not in the public SDK.
 * Declaring it here does not make it public; it makes it VISIBLE, which is the
 * honest form of the dependency.
 *
 * THE PUBLIC ALTERNATIVE, AND WHY IT IS WEAKER. `NSXPCConnection` publishes
 * `effectiveUserIdentifier`, `effectiveGroupIdentifier`, `processIdentifier` and
 * `auditSessionIdentifier`. Those cover the two fields the authorization
 * decision actually uses — ADR-0016 PS-12a's class map needs a uid and a gid —
 * so a build that refused to use SPI would still authorize correctly. What it
 * would lose is `pidversion`, which is the field that makes a pid unambiguous
 * in an audit line after the pid has been reused, and it would have to
 * FABRICATE the other four words of a struct that claims to be a kernel
 * snapshot. Fabricating them is worse than not having them.
 *
 * So this build takes the SPI, and `ManagementListener.swift` is written so that
 * switching to the public four is a change to ONE function
 * (`auditTokenBytes(for:)`) rather than to the protocol. Recorded in
 * `shells/macos/README.md` §7.
 *
 * NOTHING HERE HAS BEEN COMPILED. There is no Darwin SDK on the host this was
 * written on; `xpc/xpc.h` does not exist here and neither does `bsm/audit.h`.
 */

#ifndef TWINVPN_XPC_SHIM_H
#define TWINVPN_XPC_SHIM_H

#include <bsm/audit.h>
#include <xpc/xpc.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Apple SPI. Fills `*token` with the sending process's credentials as the
 * kernel snapshotted them at send time.
 *
 * The eight words are, in order: auid, euid, egid, ruid, rgid, pid, asid,
 * pidversion. `twinvpn-bridge`'s `mgmt::audit` decodes them at those offsets
 * and asserts the layout in its own tests, which run on Linux — so a drift in
 * this struct is caught by a test rather than by a wrong uid. */
void xpc_connection_get_audit_token(xpc_connection_t connection,
                                    audit_token_t *token);

#ifdef __cplusplus
}
#endif

#endif /* TWINVPN_XPC_SHIM_H */
