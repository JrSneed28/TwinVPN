/* ==========================================================================
 * twinvpn.h — the TwinVPN C ABI. ABI major 1.
 *
 * HAND-WRITTEN. THIS FILE IS THE ABI OF RECORD.
 * (ADR-0018 §11.12: "/core/ffi/include/twinvpn.h  hand-written; the ABI of
 *  record"; §11.4 adopts alternative H — "hand-written `twinvpn.h` as the ABI
 *  of record, generated idiomatic wrappers above it".)
 *
 * Nothing generates this file and this file generates nothing. The Rust side
 * is `core/crates/twinvpn-ffi`, and
 * `core/crates/twinvpn-ffi/tests/header_matches_rust.rs` parses THIS FILE and
 * fails if the two drift. A comment saying "keep in sync" is not a mechanism;
 * that test is.
 *
 * Owner: core-composition.
 * ==========================================================================
 *
 * DESIGN RULES THIS FILE OBEYS (ADR-0018 §11.4). Read them before adding
 * anything: every exported function is a compatibility obligation forever.
 *
 *   F-1  The surface is SMALL AND COARSE — roughly a dozen functions. One
 *        deliberate exception is granted, in F-10.
 *   F-2  OWNERSHIP. A buffer crossing the boundary is either borrowed for the
 *        duration of one call (`tw_slice`) or owned by the allocator that
 *        created it and released by that side's own free function. The core
 *        never frees a shell allocation; the shell never frees a core
 *        allocation. NO malloc/free PAIRING CROSSES THE BOUNDARY.
 *   F-3  STRINGS AND BUFFERS. UTF-8, length-delimited, never relying on NUL
 *        termination, never assumed valid on input: invalid UTF-8 is a typed
 *        error, never a panic.
 *   F-4  ERRORS CARRY A NAME, NEVER AN ERRNO. No function returns a bare int,
 *        a negative errno, or a bool as its FAILURE SIGNAL. Every fallible
 *        call yields, on failure, an opaque `tw_buf` whose bytes decode to
 *        `{reason_code, evidence, resolved}` in ADR-0015 §11.2 form, with
 *        evidence restricted to that code's declared `evidence_fields` and
 *        ALREADY REDACTED. The shell MUST NOT synthesize error text; it
 *        renders what it is given.
 *   F-5  SUBMIT + ONE ORDERED EVENT STREAM. No blocking call crosses the
 *        boundary except `tw_core_next_event`, which takes an explicit timeout
 *        and is cancellable via `tw_core_wake`. `tw_core_submit` is
 *        non-blocking. All state changes, INCLUDING THE COMPLETION OF A
 *        SUBMITTED COMMAND, arrive as events on EXACTLY ONE totally ordered
 *        stream per instance.
 *   F-6  THREADS AND REENTRANCY. A `tw_core*` is Send but NOT Sync for
 *        mutating calls: exactly one thread may hold it for mutation at a time
 *        (S-47). Read-only snapshot calls are safe from any thread. Host
 *        vtable callbacks MAY be invoked on a core-owned thread; A CALLBACK
 *        MUST NOT RE-ENTER ANY MUTATING CORE FUNCTION.
 *   F-7  PANIC CONTAINMENT. Every extern "C" body is wrapped in catch_unwind.
 *        A caught panic emits INTERNAL.CORE_PANIC, marks the instance
 *        POISONED, makes every subsequent call return that code, and obliges
 *        the shell to tw_core_destroy and re-create. IT MUST NOT TEAR DOWN THE
 *        INSTALLED RULE SET.
 *   F-8  ONLY HANDLES, SLICES AND SCALARS CROSS; structured data crosses as
 *        ENCODED BYTES. No struct with product fields is defined here except
 *        `tw_slice` (a slice) and `tw_host_vtable` (function pointers).
 *   F-10 `tw_render_diagnostic` is PURE and INSTANCE-FREE, and is F-1's one
 *        exception.
 *
 * WHAT IS DELIBERATELY ABSENT
 *
 *   - THE DATAPATH. PB-1: zero FFI crossings per packet, with one exception
 *     (`NEPacketTunnelFlow`, which is a Swift API and not this ABI). No
 *     function here takes or returns a packet.
 *   - `subscribe_network_change(cb)`. F-9: handing the OS a pointer into the
 *     core would let a notification arrive on an arbitrary thread while a
 *     mutating call is in flight, breaking F-6. The shell subscribes with the
 *     OS and submits a `host.network_changed` command instead.
 *   - The four ADR-0017 MI-21 transport operations (Hello/HelloAck,
 *     mi.catalogue.get, event.resync, the MI half of version.get). Each is
 *     about THE CONNECTION, which does not exist in-process, and each MUST NOT
 *     acquire an ABI counterpart (ADR-0018 §11.16 (o)).
 */

#ifndef TWINVPN_H
#define TWINVPN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ABI version. V-B in ADR-0018 §11.12's three-number table.
 *
 * VR-2: `abi_*` MUST NOT be used as a COMPATIBILITY INPUT anywhere except
 * between a shell and a core IN THE SAME PROCESS. It may be recorded as build
 * provenance (CoreBuildIdentity, a Tier-1 bundle); it MUST NOT appear in any
 * C1/C2/C4/C5/C6 message, MUST be omitted from Tier-2 telemetry, and NO
 * RECEIVER MAY BRANCH ON A RECEIVED VALUE.
 * -------------------------------------------------------------------------- */
#define TW_ABI_MAJOR 1u
#define TW_ABI_MINOR 0u

/* Opaque handles. F-8: no struct with product fields crosses. */
typedef struct tw_core tw_core; /* one core instance (S-47)               */
typedef struct tw_buf  tw_buf;  /* a core-owned buffer; free with tw_buf_free */

/* A borrowed, length-delimited byte range. F-3: never NUL-reliant.
 * Valid ONLY for the duration of the call it is passed to. */
typedef struct {
  const uint8_t *ptr;
  size_t         len;
} tw_slice;

/* --------------------------------------------------------------------------
 * Result codes.
 *
 * These are NOT F-4 error names. F-4 forbids a bare int AS THE FAILURE SIGNAL,
 * and the failure signal is the `tw_buf *err_out` a call writes. These three
 * values only say WHICH SHAPE the outcome took, so a caller knows whether to
 * look at `err_out` at all. The name of what went wrong is always in the
 * buffer, never in this integer.
 * -------------------------------------------------------------------------- */
#define TW_OK       0  /* success; *err_out untouched                        */
#define TW_ERR      1  /* failure; *err_out holds an ADR-0015 §11.2 envelope */
#define TW_TIMEOUT  2  /* tw_core_next_event only: no event within timeout,
                        * or tw_core_wake was called. NOT a failure.         */

/* --------------------------------------------------------------------------
 * Ruleset selector for `set_ruleset`. ADR-0012's two postures.
 * -------------------------------------------------------------------------- */
#define TW_RULESET_BLOCKED   0
#define TW_RULESET_PROTECTED 1

/* --------------------------------------------------------------------------
 * Link state for `set_link`. docs/networking.md §5.1: an interface is CREATED
 * DOWN, because one that comes up before its addresses, routes and rules are
 * installed is the partial-application leak window.
 * -------------------------------------------------------------------------- */
#define TW_LINK_DOWN 0
#define TW_LINK_UP   1

/* --------------------------------------------------------------------------
 * F-9 — the host vtable.
 *
 * Carries docs/networking.md §5.1 plus the CB-5 capabilities. Its FIRST FIELD
 * IS `size`, so entries may be added WITHOUT an abi_major bump: the core reads
 * only the entries the declared size covers.
 *
 * Every entry returns TW_OK or TW_ERR and writes an F-4 envelope into `err` on
 * failure. Every `tw_buf **` out-parameter transfers ownership TO THE CORE,
 * which releases it with the shell's... no: F-2 forbids that. A `tw_buf` the
 * SHELL produces is released by the shell's own free function, which the core
 * calls through `buf_free` below. That entry exists precisely so no
 * malloc/free pairing crosses the boundary.
 * -------------------------------------------------------------------------- */
typedef struct tw_host_vtable {
  /* The size of this struct as the SHELL compiled it. Set to
   * sizeof(tw_host_vtable). The core refuses a size smaller than the entries
   * it requires, naming PLATFORM.ADAPTER_UNAVAILABLE. */
  uint32_t size;
  /* Opaque shell context, passed back to every entry. */
  void *ctx;

  /* Borrows the bytes of a tw_buf the SHELL allocated.
   *
   * F-2 makes the shell's allocation the shell's to free, which means the core
   * cannot look inside a shell `tw_buf` without asking. These two entries are
   * the shell's half of `tw_buf_bytes`/`tw_buf_free`, and their existence is
   * what keeps "no malloc/free pairing crosses the boundary" exact rather than
   * aspirational. */
  tw_slice (*buf_bytes)(void *ctx, const tw_buf *buf);

  /* Releases a tw_buf the SHELL allocated (F-2). */
  void (*buf_free)(void *ctx, tw_buf *buf);

  /* ---- docs/networking.md §5.1 ------------------------------------------ */

  /* Creates the overlay interface. CREATED DOWN. */
  int32_t (*create_interface)(void *ctx, tw_slice name, uint32_t mtu,
                              uint64_t *h, tw_buf **err);

  /* Installs a whole generation, ATOMICALLY. All-or-nothing; IDEMPOTENT ON
   * THE GENERATION ID, so a retry after a crash converges rather than
   * duplicating routes (ADR-0008). `plan` is an encoded network contract. */
  int32_t (*apply)(void *ctx, uint64_t h, uint64_t contract_generation,
                   tw_slice plan, tw_buf **err);

  /* Restores the generation before `contract_generation`, exactly. */
  int32_t (*rollback)(void *ctx, uint64_t h, uint64_t contract_generation,
                      tw_buf **err);

  /* Brings the interface up or down. TW_LINK_DOWN / TW_LINK_UP. */
  int32_t (*set_link)(void *ctx, uint64_t h, int32_t up, tw_buf **err);

  /* Swaps the enforcement ruleset. AN ATOMIC SWAP: rules are never absent
   * while the latch is up (KS-17). TW_RULESET_BLOCKED / TW_RULESET_PROTECTED.
   * The core computes which ruleset is desired; this installs it; THE OS
   * HOLDS IT (CB-6), which is why a core crash cannot drop protection. */
  int32_t (*set_ruleset)(void *ctx, uint64_t h, int32_t ruleset, tw_buf **err);

  /* The underlay's current facts, as an encoded blob. */
  int32_t (*query_link_facts)(void *ctx, tw_buf **facts, tw_buf **err);

  /* Destroys the interface. IDEMPOTENT; safe after a crash. */
  int32_t (*destroy_interface)(void *ctx, uint64_t h, tw_buf **err);

  /* subscribe_network_change: see the file header. Realized INBOUND as a
   * `host.network_changed` command submission, and DELIBERATELY ABSENT here. */

  /* ---- CB-5 capabilities ------------------------------------------------
   * The identity private half NEVER crosses into the core (I4). These are
   * OPERATIONS performed INSIDE THE ELEMENT; no entry returns key material and
   * no parameter accepts it. */

  /* The public identity, encoded. */
  int32_t (*identity_public)(void *ctx, tw_buf **spki, tw_buf **err);

  /* Signs `msg` with an element-resident key. ADR-0018 §11.16 (c): IK, ES256,
   * NEVER EXPORTED. Failure is the AUTH.KEY_UNAVAILABLE class. */
  int32_t (*identity_sign)(void *ctx, tw_slice msg, tw_buf **sig,
                           tw_buf **err);

  /* Element-resident key agreement.
   *
   * NOT REQUIRED ON EVERY TARGET. ADR-0018 §11.16 (c) is explicit that
   * in-element AGREE is not required — TK is hardware-WRAPPED rather than
   * element-resident precisely because platform key APIs largely do not offer
   * X25519 ECDH. An adapter that cannot do this returns TW_ERR with
   * PLATFORM.OS_UNSUPPORTED, which is A FACT THE CORE RECORDS; it is NOT a
   * licence for the core to fall back to a private key it does not have.
   *
   * Present here because ADR-0018 §11.6 lists "core -> shell: identity
   * sign/agree/attest" as a seam direction while §11.4's struct listing omits
   * it. The `size` field makes adding it a minor-version addition, not a
   * break. Reported to the integration lead as an ADR-0018 inconsistency. */
  int32_t (*identity_agree)(void *ctx, tw_slice peer_public,
                            tw_buf **shared, tw_buf **err);

  /* The attestation record. Reports `hardware_backed` TRUTHFULLY PER TARGET
   * (§11.16 (l)); on a target with no secure element the honest answer is
   * false, and THE CORE MUST NOT SUBSTITUTE A FILE-BACKED SIGNER SILENTLY. */
  int32_t (*identity_attestation)(void *ctx, tw_buf **att, tw_buf **err);

  /* ---- Tier 1 ONLY — secure-storage-shaped items (CB-7) -----------------
   * SEK, K_bind, the S-53 anchor. WHOLE-BLOB ATOMIC REPLACEMENT, which is the
   * shape Keychain / Keystore / DPAPI / libsecret actually have. NOT a general
   * store: the record envelope, AEAD, namespaces, schema, migration, monotone
   * rejection, the recovery ladder and multi-key commit are ALL CORE-SIDE. */
  int32_t (*secure_item_read)(void *ctx, tw_slice key, tw_buf **val,
                              tw_buf **err);
  int32_t (*secure_item_write_atomic)(void *ctx, tw_slice key, tw_slice val,
                                      tw_buf **err);
  int32_t (*secure_item_delete)(void *ctx, tw_slice key, tw_buf **err);

  /* ---- Tier 2 — the shell vends the directory --------------------------
   * The shell stamps the platform attributes (file-protection class, backup
   * exclusion) and the core does the POSIX I/O beneath it. THE PATH IS
   * INJECTED AT CONSTRUCTION, NEVER DISCOVERED (CD-2, CB-7). */
  int32_t (*store_root)(void *ctx, tw_buf **path_utf8, tw_buf **err);

  /* Whether the platform key API performs the record AEAD itself (CB-6a).
   * 0 = the key is core-held (the common case, 8 of 10 targets);
   * 1 = the platform performs it. DECLARED, never inferred. */
  int32_t (*record_aead_custody)(void *ctx);

  /* Fills `out` with `len` bytes from the platform CSPRNG.
   * CD-3 bans `getrandom` inside the core, so this is the only entropy source.
   * MUST NOT fall back to a weaker source: a silent downgrade here is
   * indistinguishable from working. */
  int32_t (*os_csprng)(void *ctx, uint8_t *out, size_t len);

  /* Suspend-inclusive elapsed milliseconds since an arbitrary fixed origin.
   *
   * ADR-0018 CD-1 requires THREE non-interchangeable clocks and `std` has no
   * suspend-inclusive one, so the shell must supply it. Recorded as gap W-7 in
   * docs/implementation/ownership.md §8 — "precisely the invisible-on-Linux-CI
   * failure LC-8 warns about" — and present here so a shell cannot forget it. */
  int32_t (*elapsed_millis)(void *ctx, uint64_t *out);

  /* A stable identifier for this boot, or TW_ERR where the platform has none.
   * W-7's third required shell interface. */
  int32_t (*boot_id)(void *ctx, uint8_t out[16]);
} tw_host_vtable;

/* --------------------------------------------------------------------------
 * The instance-free entry points.
 * -------------------------------------------------------------------------- */

/* This core's ABI major. Compare against TW_ABI_MAJOR as the shell compiled
 * it. VR-4: a mismatch is a PACKAGING DEFECT, not an operating state — but it
 * is still checked, because the alternative is undefined behaviour. */
uint32_t tw_abi_major(void);

/* This core's ABI minor. Additions bump this and never break a caller. */
uint32_t tw_abi_minor(void);

/* S-46 CoreBuildIdentity, encoded (twinvpn.v1.CoreBuildIdentity).
 *
 * STATIC STORAGE, NEVER FREED. The value is a property of the loaded binary
 * and is IMMUTABLE WITHIN AN ARTIFACT, so there is nothing to own and nothing
 * to release. Do not pass the returned pointer to tw_buf_free. */
tw_slice tw_build_identity(void);

/* The reason-code registry version this build was compiled against.
 * Mirrored in CoreBuildIdentity, so a diagnostic bundle can answer "which
 * registry" WITHOUT A LIVE INSTANCE. */
uint32_t tw_reason_registry_version(void);

/* F-10 — F-1's one exception.
 *
 * PURE: no I/O, no clock, no ambient locale, no ambient platform, no instance,
 * no global state. Same inputs -> same bytes, on every target. CALLABLE WHILE
 * AN INSTANCE IS POISONED, which is the point: the moment a diagnostic most
 * needs rendering is exactly when no instance exists — after
 * INTERNAL.CORE_PANIC poisoned it, before tw_core_create has run, or inside a
 * crash reporter.
 *
 *   reason_code    UTF-8, e.g. "PLATFORM.VPN_PERMISSION_DENIED". An UNKNOWN
 *                  code degrades on its DOMAIN prefix rather than failing, and
 *                  still arrives with its severity and actionability intact.
 *   evidence       an encoded twinvpn.v1.DiagnosticContext; its `evidence`
 *                  field binds the catalogue pattern's named placeholders.
 *   locale_bcp47   e.g. "en-GB". AN EXPLICIT PARAMETER, NEVER AMBIENT (CD-2).
 *   platform_ctx   an encoded twinvpn.v1.DevicePlatformInfo carrying at least
 *                  {platform, os_version}. AN EMPTY platform_ctx MUST resolve
 *                  to the PLATFORM-NEUTRAL variant and MUST NOT fall back to
 *                  the host's own platform (ADR-0019 LT-3b) — an implicit host
 *                  fallback readmits ambient state through the back door.
 *
 * Returns a core-owned buffer holding an encoded twinvpn.v1.ErrorEnvelope with
 * the resolved attributes and the rendered sentences. Release it with
 * tw_buf_free. NEVER returns NULL: an unparseable code still renders. */
tw_buf *tw_render_diagnostic(tw_slice reason_code, tw_slice evidence,
                             tw_slice locale_bcp47, tw_slice platform_ctx);

/* --------------------------------------------------------------------------
 * The instance.
 * -------------------------------------------------------------------------- */

/* Creates an instance.
 *
 * `abi_major_expected` is TW_ABI_MAJOR as the SHELL compiled it. A mismatch
 * returns NULL and writes INTERNAL.ABI_VERSION_MISMATCH into *err_out; the
 * core NEVER proceeds on a "close enough" match (S-46).
 *
 * `host` must outlive the instance. `config` is an encoded configuration blob
 * (F-8) and is BORROWED for the duration of this call only.
 *
 * On failure returns NULL and writes an F-4 envelope into *err_out. */
tw_core *tw_core_create(uint32_t abi_major_expected,
                        const tw_host_vtable *host,
                        tw_slice config, tw_buf **err_out);

/* Destroys an instance. IDEMPOTENT ON NULL.
 *
 * Does NOT tear down the installed rule set: CB-6 puts it in the OS's custody
 * precisely so that the core going away cannot drop protection. Clearing it is
 * a separate, deliberate act (ADR-0012's disarm ceremony). */
void tw_core_destroy(tw_core *core);

/* Submits one command. NON-BLOCKING (F-5).
 *
 * `command` is an encoded command from the SAME command set the local
 * management interface carries — one contract, two carriages, NEVER TWO
 * CONTRACTS (ADR-0017 MI-20, ADR-0018 §11.16 (b)).
 *
 * A rejected command still produces an EVENT; it is never a silent drop. */
int32_t tw_core_submit(tw_core *core, tw_slice command, tw_buf **err_out);

/* Waits up to `timeout_ms` for the next event on the ONE ordered stream.
 *
 * Returns TW_OK with *event_out set, TW_TIMEOUT (no event, or tw_core_wake was
 * called), or TW_ERR with *err_out set. Release *event_out with tw_buf_free.
 *
 * THE ONLY BLOCKING CALL IN THIS ABI. */
int32_t tw_core_next_event(tw_core *core, uint32_t timeout_ms,
                           tw_buf **event_out, tw_buf **err_out);

/* Cancels an in-flight tw_core_next_event. CALLABLE FROM ANY THREAD. */
void tw_core_wake(tw_core *core);

/* --------------------------------------------------------------------------
 * Core-allocated buffers. F-2: the core allocates, the core frees.
 * -------------------------------------------------------------------------- */

/* Borrows the bytes. Valid until tw_buf_free. NULL-safe: a NULL buf yields an
 * empty slice rather than a crash. */
tw_slice tw_buf_bytes(const tw_buf *buf);

/* Releases a core-allocated buffer. IDEMPOTENT ON NULL. */
void tw_buf_free(tw_buf *buf);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TWINVPN_H */
