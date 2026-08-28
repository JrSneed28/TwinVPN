/*
 * twinvpn_bridge.h - the Swift <-> Rust ABI of the macOS system extension.
 *
 * Authority: ADR-0018 §11.4 (a hand-written header is the ABI of record), §11.6
 * (the seam in both directions), F-1 (every exported function is a
 * compatibility obligation forever), F-2 (no malloc/free pairing crosses the
 * boundary), F-3 (length-delimited, never NUL-reliant), F-4 (errors carry a
 * name, never an errno), F-7 (`catch_unwind` containment at the boundary),
 * CB-2 (the shell holds no decision), DP-4 (`unsafe` is permitted here);
 * ADR-0015 §11.2 (the diagnostic envelope), §6 rule 6 (correlation is preserved
 * across every component boundary, INCLUDING this one).
 *
 * ===========================================================================
 * WHY THIS ABI EXISTS AT ALL, BESIDE twinvpn.h
 *
 * `core/ffi/include/twinvpn.h` is the ABI of record between a shell and the
 * core, and `ownership.md` §8 records two findings against it:
 *
 *   W-25  the F-9 vtable has NO socket capability and NO interface
 *         enumeration, so a shell bound only to it cannot do NAT traversal;
 *   W-24  it offers `set_ruleset` with NO getter and no `current_generation`,
 *         so a shell bound only to it cannot produce a `ProtectionAssertion`
 *         at all.
 *
 * A Swift-only extension speaking `twinvpn.h` would therefore be unable to do
 * the two things a VPN datapath most needs. This ABI is the answer: the vtable,
 * the marshalling and the object lifetimes live in Rust over
 * `twinvpn-platform-macos`, and Swift speaks the much smaller surface below.
 *
 * The consequence that matters for review: every line of that marshalling is
 * covered by `make cross-check` for aarch64-apple-darwin with `-D warnings`,
 * and by `cargo test` on the Linux host. It is not unverified Swift.
 *
 * ===========================================================================
 * WHAT IS DELIBERATELY ABSENT
 *
 *   - Anything Swift could BRANCH on. CB-2 forbids a branch in the shell whose
 *     condition is a TwinVPN domain fact, so no entry here returns a
 *     ConnectionState, a reason_code class, a policy verdict, a candidate
 *     priority or a version comparison. The three result codes below say which
 *     SHAPE an outcome took and never what it means.
 *   - A callback into Swift. Every entry is called BY Swift and returns to it.
 *     F-9's reasoning applies unchanged: handing the OS a pointer into Rust
 *     would let a notification arrive on an arbitrary thread while a mutating
 *     call is in flight. The two blocking readers below are how Swift learns
 *     about work instead.
 *   - A `causation_id` field. ADR-0015 §6 rule 6 asks for correlation AND
 *     causation across every boundary and this ABI carries only the first.
 *     Reported as a gap rather than invented.
 */

#ifndef TWINVPN_BRIDGE_H
#define TWINVPN_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ABI version.
 *
 * VR-4: a mismatch is a PACKAGING DEFECT, not an operating state - but it is
 * still checked, because the alternative is undefined behaviour. VR-2 forbids
 * `abi_*` being used as a compatibility input anywhere except between a shell
 * and a core IN THE SAME PROCESS, which is exactly and only what this is.
 * -------------------------------------------------------------------------- */
#define TVB_ABI_MAJOR 1u
#define TVB_ABI_MINOR 0u

/* Opaque handles. F-8: no struct with product fields crosses. */
typedef struct tvb_ext tvb_ext; /* one running extension instance */
typedef struct tvb_buf tvb_buf; /* a bridge-owned buffer; free with tvb_buf_free */

/* A borrowed, length-delimited byte range. F-3: never NUL-reliant.
 *
 * Valid ONLY for the duration of the call it is passed to.
 *
 * `ptr` MAY BE NULL WHEN `len` IS ZERO. Swift's `withUnsafeBufferPointer`
 * yields a nil base address for an empty array, so `(NULL, 0)` is a well-formed
 * empty slice and the Rust side accepts it. It is written down here because
 * `slice::from_raw_parts` on a null base is undefined behaviour, and that is
 * the one shape a naive implementation gets wrong. */
typedef struct {
  const uint8_t *ptr;
  size_t         len;
} tvb_slice;

/* --------------------------------------------------------------------------
 * Result codes.
 *
 * These are NOT F-4 error names. F-4 forbids a bare int AS THE FAILURE SIGNAL,
 * and the failure signal is the `tvb_buf *err` a call writes. These three
 * values only say WHICH SHAPE the outcome took, so a caller knows whether to
 * look at `err` at all. The name of what went wrong is always in the buffer.
 * -------------------------------------------------------------------------- */
#define TVB_OK      0 /* success; *err untouched                             */
#define TVB_ERR     1 /* failure; *err holds an ADR-0015 §11.2 envelope       */
#define TVB_TIMEOUT 2 /* the two blocking readers only: nothing arrived
                       * within the timeout. NOT a failure, and NOT a deadline
                       * guarantee - a reader may return this early. The caller
                       * loops.                                               */

/* Address family, as a PRODUCT-NEUTRAL number.
 *
 * Deliberately 4 and 6 rather than AF_INET/AF_INET6: those are 2 and 30 on
 * Darwin and 2 and 10 on Linux, and a constant whose value depends on which
 * host compiled the header is a constant that is wrong in exactly the tests
 * meant to check it. The Rust side maps these to Darwin's numbers in one
 * place, and the Swift side maps them to `AF_INET`/`AF_INET6` in one other. */
#define TVB_FAMILY_V4 4
#define TVB_FAMILY_V6 6

/* --------------------------------------------------------------------------
 * Instance-free entry points.
 * -------------------------------------------------------------------------- */

/* This bridge's ABI major. Compare against TVB_ABI_MAJOR as the caller
 * compiled it. */
uint32_t tvb_abi_major(void);

/* This bridge's ABI minor. Additions bump this and never break a caller. */
uint32_t tvb_abi_minor(void);

/* --------------------------------------------------------------------------
 * Lifecycle.
 * -------------------------------------------------------------------------- */

/* Creates one extension instance.
 *
 * `config_json` is the provider configuration, opaque to Swift and passed
 * through byte for byte. `correlation_id` is the caller's chain identifier and
 * reaches every log line this call emits (ADR-0015 §6 rule 6).
 *
 * On TVB_OK, `*out` owns a handle the caller releases with `tvb_ext_free` and
 * `*err` IS NOT WRITTEN. On TVB_ERR, `*err` holds an envelope and `*out` is not
 * written. */
int32_t tvb_ext_start(tvb_slice config_json, tvb_slice correlation_id,
                      tvb_ext **out, tvb_buf **err);

/* Reports a stop. DOES NOT free the handle, and DOES NOT tear down
 * enforcement.
 *
 * CB-6 puts the installed rule set in the OS's custody precisely so that the
 * core going away does not drop protection; a stop that removed the pf anchor
 * would defeat it. `reason` is the OS's own stop reason, marshalled across
 * unchanged - the CORE decides what a stop reason means. */
int32_t tvb_ext_stop(tvb_ext *ext, int32_t reason, tvb_slice correlation_id,
                     tvb_buf **err);

/* Releases the handle. Tolerates NULL.
 *
 * F-2: the bridge allocated it, the bridge frees it. Calling this twice on the
 * same non-null pointer is undefined behaviour - which is why the Swift side
 * calls it from `deinit` and nowhere else, and why `tvb_ext_stop` does not
 * free: a stopped instance is still a valid handle, and freeing on stop would
 * make a double `stopTunnel` a use-after-free. */
void tvb_ext_free(tvb_ext *ext);

/* --------------------------------------------------------------------------
 * Settings.
 * -------------------------------------------------------------------------- */

/* Blocks up to `timeout_ms` for the next settings document THE CORE COMPUTED.
 *
 * The document is UTF-8 JSON and is applied VERBATIM: every field of the
 * `NEPacketTunnelNetworkSettings` object is computed on the Rust side by
 * `twinvpn_platform_macos::nesettings`, so the Swift side decides no family, no
 * netmask, no match-domain set and no default. That is CB-2's falsification
 * test made concrete.
 *
 * TVB_TIMEOUT means none arrived. It is not a failure and not a deadline
 * guarantee; a spurious wakeup may return it early. */
int32_t tvb_ext_next_settings(tvb_ext *ext, uint32_t timeout_ms,
                              tvb_buf **doc, tvb_buf **err);

/* --------------------------------------------------------------------------
 * The packet path.
 *
 * PB-1 permits exactly one FFI crossing per packet, through
 * `NEPacketTunnelFlow`. These two entries are that crossing, and there is no
 * other packet-bearing call in this ABI.
 * -------------------------------------------------------------------------- */

/* Hands the core one packet read from `packetFlow`.
 *
 * `pkt` MAY BE NULL WHEN `len` IS ZERO, for the same reason `tvb_slice` may be.
 * `family` is TVB_FAMILY_V4 or TVB_FAMILY_V6; any other value is a typed
 * error, never a guess. */
int32_t tvb_ext_inject_inbound(tvb_ext *ext, const uint8_t *pkt, size_t len,
                               int32_t family, tvb_buf **err);

/* One packet the core wants written to `packetFlow`, or TVB_TIMEOUT.
 *
 * On TVB_OK, `*pkt` owns a buffer and `*family` is set. On TVB_TIMEOUT neither
 * is written. */
int32_t tvb_ext_next_outbound(tvb_ext *ext, uint32_t timeout_ms,
                              tvb_buf **pkt, int32_t *family, tvb_buf **err);

/* --------------------------------------------------------------------------
 * Lifecycle facts (ADR-0022).
 *
 * Each of these REPORTS a fact the OS handed the provider. None of them
 * asserts, renders or decides anything: ADR-0022's rule is that a resume must
 * not render a confident, stale green, so `wake` is a notification and never a
 * "we are still connected". The core decides what each means.
 * -------------------------------------------------------------------------- */
int32_t tvb_ext_sleep(tvb_ext *ext, tvb_slice correlation_id, tvb_buf **err);
int32_t tvb_ext_wake(tvb_ext *ext, tvb_slice correlation_id, tvb_buf **err);
int32_t tvb_ext_network_changed(tvb_ext *ext, tvb_slice correlation_id,
                                tvb_buf **err);

/* --------------------------------------------------------------------------
 * The management hop.
 * -------------------------------------------------------------------------- */

/* `handleAppMessage`: an opaque MI envelope in, an opaque MI envelope out.
 *
 * ADR-0017 MI-20 - "one contract, two carriages, never two contracts" - is why
 * neither side of this call decodes the envelope in Swift. Its schema lives in
 * the Rust `mi` module that `twinvpnd` and `twinvpnctl` share. */
int32_t tvb_ext_app_message(tvb_ext *ext, tvb_slice req, tvb_buf **resp,
                            tvb_buf **err);

/* --------------------------------------------------------------------------
 * Buffers.
 * -------------------------------------------------------------------------- */

/* Borrows a buffer's bytes. The slice is valid until `tvb_buf_free`.
 *
 * Returns `(NULL, 0)` for a NULL buffer, so a caller that forgot to check does
 * not dereference. */
tvb_slice tvb_buf_bytes(const tvb_buf *buf);

/* Releases a buffer the bridge produced. Tolerates NULL.
 *
 * F-2: the ONLY way to free one. Calling it twice on the same non-null pointer
 * is undefined behaviour. */
void tvb_buf_free(tvb_buf *buf);

#ifdef __cplusplus
}
#endif

#endif /* TWINVPN_BRIDGE_H */
