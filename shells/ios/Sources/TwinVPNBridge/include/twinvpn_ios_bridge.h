/*
 * twinvpn_ios_bridge.h — the internal Swift↔Rust bridge for iOS/iPadOS.
 *
 * Authority: docs/implementation/ownership.md §10.4; ADR-0018 VR-2, F-2, F-7.
 *
 * ============================================================================
 * THIS IS NOT `twinvpn.h`. IT IS NOT AN ABI OF RECORD.
 * ============================================================================
 *
 * `ownership.md` §10.4, on why this file exists at all:
 *
 *   "The missing capabilities stay IN RUST, IN-PROCESS, inside
 *    twinvpn-platform-{ios,android}, and the Swift/Kotlin side reaches them
 *    through a per-platform `extern "C"` bridge exported by that same adapter
 *    crate. That bridge is NOT an ABI of record, is NOT twinvpn.h, and acquires
 *    NO compatibility obligation: both sides are compiled from one commit into
 *    one artifact, which is precisely the same-process scope VR-2 already carves
 *    out. It is internal linkage, and it is versionless because there is nothing
 *    for it to be compatible with."
 *
 * So: there is deliberately NO abi_major and NO abi_minor here, and adding one
 * would assert a promise the ruling withholds. `size` on the vtable is a SAFETY
 * check against a Swift side built from a different commit, not a version.
 *
 * This header is hand-written to mirror `core/crates/twinvpn-platform-ios/
 * src/bridge.rs`. The struct's field count and order are load-bearing; the Rust
 * side asserts `size_of` in `bridge::tests::the_bridge_surface_carries_no_domain_fact`,
 * which fails if either side drifts.
 *
 * ---------------------------------------------------------------------------
 * THE ONE RULE THIS SURFACE MUST NOT BREAK
 * ---------------------------------------------------------------------------
 *
 * §10.4: "The bridge surface is NOT permitted to grow a TwinVPN domain fact. An
 * entry that takes or returns a ConnectionState, a reason_code class, a policy
 * verdict or a candidate priority is a CB-2 violation on the wrong side of the
 * line, and is a finding."
 *
 * Every entry below carries BYTES, COUNTS and OS NUMBERS. Swift reports what the
 * OS reported; Rust turns the number into a registered reason_code. There is no
 * TwinVPN vocabulary in this file, and there must not be.
 */

#ifndef TWINVPN_IOS_BRIDGE_H
#define TWINVPN_IOS_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Which number space `code` is in. */
#define TW_IOS_KIND_OK           0
#define TW_IOS_KIND_ERRNO        1
#define TW_IOS_KIND_OSSTATUS     2
#define TW_IOS_KIND_NEVPN        3
#define TW_IOS_KIND_NOT_ATTACHED 4
#define TW_IOS_KIND_PANIC        5

/* A borrowed byte range. F-2's ownership rule: the borrow is valid for exactly
 * one call, and neither side frees the other's allocation. */
typedef struct {
    const uint8_t *ptr;
    size_t len;
} tw_ios_slice;

/* What a host call returned. Two integers and nothing else — the shape that
 * keeps the NAMING of conditions in Rust (CB-2). */
typedef struct {
    int32_t kind;
    int32_t code;
} tw_ios_status;

/* Pushes one item into a sink Rust supplied.
 *
 * Rust owns the storage. Swift never allocates for Rust and never frees a Rust
 * allocation — F-2, applied here even though this is not F-2's ABI.
 *
 * Call it once per item, synchronously, inside the callback that was handed the
 * sink. The sink is invalid the moment the callback returns. */
void twinvpn_ios_sink_push(void *sink, const uint8_t *ptr, size_t len);

/* The Swift side of the bridge.
 *
 * Every function pointer may be NULL; Rust reads a NULL entry as
 * TW_IOS_KIND_NOT_ATTACHED, never as a silent success — a `clear_settings` that
 * quietly did nothing would leave a tunnel installed that the core believes is
 * gone. */
typedef struct {
    /* sizeof(tw_ios_host_vtable). Checked at registration. */
    uint32_t size;
    /* The NEPacketTunnelProvider, opaque to Rust. Rust never dereferences it. */
    void *ctx;

    /* --- the packet tunnel (PB-1's one conceded crossing) ----------------- */

    /* setTunnelNetworkSettings, from a rendered programme (JSON bytes). This is
     * the WHOLE of address, route, DNS and MTU programming on this platform:
     * networking.md §5.2's iOS row is "no route API". */
    tw_ios_status (*apply_settings)(void *ctx, tw_ios_slice programme);

    /* setTunnelNetworkSettings(nil). MUST NOT remove on-demand rules or
     * includeAllNetworks: CB-6 puts those in the OS's custody so that the core
     * going away cannot drop protection. */
    tw_ios_status (*clear_settings)(void *ctx);

    /* NEPacketTunnelFlow.readPackets — ONE crossing per batch, one copy per
     * packet, which is exactly PB-1's budgeted cost. Push each packet. */
    tw_ios_status (*read_packets)(void *ctx, void *sink);

    /* NEPacketTunnelFlow.writePackets(_:withProtocols:).
     * `families` runs parallel to `packets` and carries AF_INET (2) or
     * AF_INET6 (30) per packet. Rust derived it from the version nibble; Swift
     * MUST NOT re-derive or override it. */
    tw_ios_status (*write_packets)(void *ctx,
                                   const tw_ios_slice *packets,
                                   const int32_t *families,
                                   size_t count);

    /* --- enforcement (there is no host firewall on this platform) --------- */

    /* On-demand rules plus includeAllNetworks/excludeLocalNetworks, from a
     * rendered programme. ADR-0012's iOS row has no packet filter to install;
     * this is the entire mechanism. */
    tw_ios_status (*apply_enforcement)(void *ctx, tw_ios_slice programme);

    /* Read back what is ACTUALLY installed, from NETunnelProviderManager.
     * W-24: the ProtectionAssertion is "a pure function of the most recent
     * assertion, never of the agent's belief". Push the programme, or push
     * nothing when no configuration exists. */
    tw_ios_status (*installed_enforcement)(void *ctx, void *sink);

    /* --- network path ----------------------------------------------------- */

    /* The most recent NWPathMonitor snapshot, as JSON bytes. Push it, or push
     * nothing if the monitor has not fired. */
    tw_ios_status (*path_snapshot)(void *ctx, void *sink);

    /* --- Tier-1 custody (CB-7) -------------------------------------------- */

    /* SecItemCopyMatching. `attributes` is the query Rust computed — the
     * service, account, access group and accessibility class. Swift builds the
     * CFDictionary from it and CHOOSES NONE OF THOSE VALUES. */
    tw_ios_status (*keychain_read)(void *ctx, tw_ios_slice attributes, void *sink);

    /* Whole-blob atomic replacement (CB-7). */
    tw_ios_status (*keychain_write)(void *ctx, tw_ios_slice attributes, tw_ios_slice value);

    /* SecItemDelete. Idempotent. */
    tw_ios_status (*keychain_delete)(void *ctx, tw_ios_slice attributes);

    /* The App Group container path, UTF-8, with its file-protection class
     * (ST-6) and backup-exclusion flag (ST-26) ALREADY APPLIED. */
    tw_ios_status (*store_root)(void *ctx, void *sink);

    /* Whether backup exclusion was re-verified at THIS start (ST-26). */
    int32_t (*store_root_backup_excluded)(void *ctx);

    /* --- the Secure Enclave (CB-5) ---------------------------------------- */

    /* SecKeyCreateSignature, ES256, inside the element. The private half is
     * never exported (CB-5 row 1, ADR-0007 N-5). */
    tw_ios_status (*enclave_sign)(void *ctx,
                                  tw_ios_slice key_tag,
                                  tw_ios_slice message,
                                  void *sink);

    /* SecKeyCopyKeyExchangeResult. `algorithm` is "ecdh-p256" or another tag.
     * An algorithm the enclave does not offer MUST return
     * TW_IOS_KIND_OSSTATUS with errSecUnimplemented (-4) — a FACT the core
     * records, never a licence to substitute a software key. */
    tw_ios_status (*enclave_agree)(void *ctx,
                                   tw_ios_slice key_tag,
                                   tw_ios_slice algorithm,
                                   tw_ios_slice peer_public,
                                   void *sink);

    /* Two pushes: the public key first, then the SecKeyCreateAttestation blob
     * (push an empty item when the element produced none). */
    tw_ios_status (*enclave_public)(void *ctx, tw_ios_slice key_tag, void *sink);

    /* Whether the private halves genuinely live in the SEP. Report TRUTHFULLY
     * (§11.16 (l)): a simulator has no SEP and 0 is the honest answer. */
    int32_t (*enclave_hardware_backed)(void *ctx);
} tw_ios_host_vtable;

/* Registers the Swift provider. `ctx` must outlive every subsequent call.
 * Returns TW_IOS_KIND_NOT_ATTACHED with `code` set to the received `size` when
 * the vtable does not match the linked Rust build. */
tw_ios_status twinvpn_ios_bridge_register(const tw_ios_host_vtable *vtable);

/* Forgets the registered provider. Call at provider teardown. */
void twinvpn_ios_bridge_unregister(void);

#ifdef __cplusplus
}
#endif

#endif /* TWINVPN_IOS_BRIDGE_H */
