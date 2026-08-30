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
 *        and is cancellable via `tw_core_wake`. `tw_core_submit` and
 *        `tw_core_submit_response` are both non-blocking. All state changes,
 *        INCLUDING THE COMPLETION OF A SUBMITTED COMMAND, arrive as events on
 *        EXACTLY ONE totally ordered stream per instance.
 *   F-5a THE ONE VALUE THAT STREAM MUST NOT CARRY. `tw_core_submit_response`'s
 *        `*response_out` is NOT a state change and NOT the completion. The
 *        completion still arrives on the stream, in order, exactly as F-5
 *        says; `*response_out` is the answer to THIS call, delivered to THIS
 *        caller, and to nothing else.
 *
 *        It exists because F-5 and ADR-0017 MI-P1 rule 1 are otherwise
 *        jointly unsatisfiable. MI-P1 permits `pair.begin`'s offer -- the one
 *        SECRET that crosses the management interface -- "only inside a
 *        `pair.begin` response", and the event stream is a BROADCAST: every
 *        subscriber reads it and MI-9 retains the last body per topic. A value
 *        one connection may see therefore cannot leave through it. A RETURN
 *        VALUE IS THE ONLY UNICAST EXIT, and F-6 guarantees a submission has
 *        exactly one caller to return it to.
 *
 *        So the direction is normative and not stylistic: COPYING
 *        `*response_out` ONTO THE EVENT STREAM, INTO A LOG, INTO A DIAGNOSTIC
 *        BUNDLE OR INTO ANY STORE VIOLATES MI-P1 RULES 2 AND 3 AND DEFEATS THE
 *        ONLY REASON THIS ENTRY EXISTS.
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
 *   - SOCKETS. ownership.md §8 W-25 / §11.2 G-11. A UDP socket is on the
 *     datapath, so the first bullet governs it: at PB-3's desktop userspace
 *     gate (>= 60% of >= 90% of 1 GbE, so ~540 Mbit/s) a 1420-byte payload is
 *     ~47,500 datagrams per second PER DIRECTION, and PB-4 prices the split at
 *     0 ns/packet on Linux, Windows, Android and OpenWrt. No per-datagram
 *     crossing costs 0 ns, so a `udp_send`/`udp_recv` pair here would falsify
 *     PB-1 and PB-4 BY CONSTRUCTION rather than on a measurement. F-6 compounds
 *     it: a vtable callee MUST NOT re-enter a mutating core function, so every
 *     received datagram would additionally owe a hop to the one mutating thread
 *     S-47 allows -- scheduler latency, per packet. THIS ENTRY MUST NOT BE
 *     ADDED. Sockets belong in Rust in the shell's own process, over
 *     `twinvpn-platform-*`, which is what all five shells already do
 *     (ownership.md §10.4, generalised by X-7).
 *   - INTERFACE ENUMERATION. Same finding, DIFFERENT reason, and the difference
 *     matters because this one is closeable. It is control-rate -- a gather and
 *     a network change, never a packet -- so PB-1 and PB-4 say nothing about
 *     it. What blocks it is F-8: structured data crosses as blobs generated
 *     from ADR-0003's contract artifacts, and `contracts/` holds no message
 *     that can carry `InterfaceFacts`. `twinvpn.v1.NetworkInterface` is lossy
 *     three ways -- no interface INDEX, no `link_class`, and `addresses` as
 *     `repeated IPPrefix`, the shape that masks 10.0.0.7/24 to its network
 *     address and drops fe80::/10 outright (W-39). Encoding over it would
 *     reinstate a defect the corpus has already fixed once. Closing this needs
 *     a `contracts/` amendment under ownership.md §3; it is an ask, not a patch,
 *     and `contracts/` is FROZEN.
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
/* 0 -> 1: `tw_core_submit` gained the MI-frame form, which can carry an
 * operation's PARAMETERS. VR-1 makes an ADDITION a MINOR bump: the bare-name
 * form it joins is unchanged and still accepted, so no shell breaks.
 *
 * 1 -> 2: F-9 gained `installed_ruleset` and `current_generation` (W-24). Both
 * are APPENDED vtable entries, so a shell compiled against minor 1 declares a
 * shorter struct, the core reads only the prefix that struct's `size` covers,
 * and every entry past it stays absent — which is the same state a shell that
 * declared them and left them null already produces. Nothing is removed, no
 * signature changes, and no existing entry moves; VR-1 therefore makes this a
 * MINOR bump and NOT an `abi_major` break.
 *
 * 2 -> 3: `tw_core_submit_response` was ADDED, and the MI frame's
 * `idempotency_key` is now honoured where the catalogue requires one. VR-1's
 * V-B row reads "major on removal or semantic change; minor on addition", and
 * neither half removes or changes anything a shell compiled against minor 2
 * can observe:
 *
 *   - The new entry is a NEW SYMBOL. `tw_core_submit` keeps its name, its
 *     three parameters and its behaviour to the byte, so a shell that never
 *     names the new symbol cannot tell it exists. Carrying the response on
 *     `tw_core_submit` instead -- as a fourth parameter -- WOULD have been an
 *     `abi_major` break, because every shipped shell holds a three-argument
 *     prototype for a symbol whose argument count would have moved, and that
 *     is a mismatch which links cleanly and corrupts at run time.
 *   - `idempotency_key` was documented as ignored AND as something a caller
 *     SHOULD leave empty, so the only submissions whose handling changes are
 *     the ones this header told shells not to send; an empty key still yields
 *     exactly the old behaviour. It has to be honoured now because the
 *     catalogue requires one on `pair.begin` -- the very operation F-5a's
 *     unicast return exists for -- and refusing it as MGMT.PRECONDITION_FAILED
 *     would leave the new entry a channel with nothing to carry. */
#define TW_ABI_MINOR 3u

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

  /* ---- The enforcement read-back (W-24) ---------------------------------
   *
   * These two belong beside `set_ruleset` and `rollback` and are NOT there,
   * because F-9's `size` field only makes an APPEND compatible: moving an
   * entry changes the prefix every older shell already compiled, which is an
   * abi_major break that compiles cleanly on both sides and corrupts at run
   * time. Position here is an ABI constraint, not a statement about what they
   * are for. Read them with `set_ruleset` and `rollback`.
   *
   * WHY THEY EXIST. ADR-0015 §11.6 rule 1: "A `ProtectionAssertion` is
   * produced by QUERYING THE ENFORCEMENT LAYER … The user-visible protection
   * indicator is a pure function of the most recent assertion, NEVER of the
   * agent's belief about what it configured." ADR-0018 §11.4's printed F-9
   * struct offers `set_ruleset` and no getter, so across this ABI the
   * assertion could not be produced AT ALL, and `twinvpn-ffi` returned a typed
   * refusal that rendered the indicator UNKNOWN. That is O-18's fail-safe
   * direction and it is not the required one: a Swift or Kotlin shell bound
   * only to this vtable could never report protection truthfully. Recorded as
   * W-24 in `docs/implementation/ownership.md` §8, and added here on the same
   * ground and by the same mechanism as W-26's four additions.
   *
   * Both are QUERIES OF THE OS, never of a value the shell remembers. The
   * reconciler's whole job is to notice that something else changed the rules,
   * and a cached answer cannot. A shell that can only report what it last set
   * MUST return TW_ERR with PLATFORM.OS_UNSUPPORTED rather than echo its own
   * belief back: an unreadable posture is not an asserted one, and the core
   * renders that UNKNOWN instead of claiming protection nobody confirmed. */

  /* The ruleset the OS is ACTUALLY holding.
   *
   * On TW_OK the shell MUST write BOTH out-parameters. `*present_out` is 0 when
   * no ruleset of this product's is installed and non-zero otherwise;
   * `*ruleset_out` is meaningful only when `*present_out` is non-zero and MUST
   * then be TW_RULESET_BLOCKED or TW_RULESET_PROTECTED. The core initializes
   * both before the call and REFUSES any other posture value rather than
   * guessing one — an unrecognized posture is a shell defect, and treating it
   * as PROTECTED would assert protection nobody stated.
   *
   * There is deliberately no third Ruleset value: KS-17 makes the two postures
   * an atomic swap and "a moment with no ruleset is the leak window the whole
   * mechanism exists to close". `present_out` reports the ABSENCE of this
   * product's rules, which is a different fact from a third posture. */
  int32_t (*installed_ruleset)(void *ctx, uint64_t h, int32_t *ruleset_out,
                               int32_t *present_out, tw_buf **err);

  /* The contract generation currently in force, if any.
   *
   * THE RECOVERY ENTRY POINT: after a crash the core reads this and decides
   * whether to converge or roll back (ADR-0022 LC-4). Read from the OS, not
   * from this process's history — a value remembered in memory is exactly what
   * a crash destroys.
   *
   * On TW_OK the shell MUST write both out-parameters. `*present_out` is 0
   * when no generation is in force, and `*generation_out` is meaningful only
   * when it is non-zero. A generation id is a monotone `uint64` allocated by
   * the core, so no reserved value could carry "none" without stealing one. */
  int32_t (*current_generation)(void *ctx, uint64_t h, uint64_t *generation_out,
                                int32_t *present_out, tw_buf **err);
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
 * ---------------------------------------------------------------------------
 * THE BYTES IN `command`. This paragraph is normative.
 * ---------------------------------------------------------------------------
 * TWO forms are accepted, told apart by their SHAPE and not by a flag.
 *
 *  1. PREFERRED — one MANAGEMENT-INTERFACE FRAME, exactly as *event_out below
 *     carries one and exactly as the Unix socket, the named pipe and XPC carry
 *     one: a 4-byte BIG-ENDIAN length prefix followed by that many bytes of
 *     UTF-8 JSON. `body.kind` MUST be "request", and the body carries:
 *
 *       operation   string  the wire name, e.g. "session.connect"
 *       params      []uint8 the operation's encoded parameters (F-8)
 *       if_version  uint?   the precondition, where the catalogue needs one
 *
 *     This is the form that can carry PARAMETERS, and several operations mean
 *     nothing without them: `session.connect` names a 32-byte peer device_id,
 *     `host.lifecycle` names a phase, `host.network_changed` names a snapshot.
 *
 *  2. LEGACY — a bare UTF-8 operation name, no framing. Means exactly what it
 *     always did: that operation, with NO parameters. Kept because F-1 makes
 *     every exported function a compatibility obligation forever.
 *
 * Anything else is PROTO.MALFORMED_MESSAGE; a name the catalogue does not
 * contain is MGMT.OP_UNKNOWN. Both are TYPED rejections — never a parse error,
 * never a hang, never a generic failure (ADR-0017 11.7).
 *
 * `request_id` and `correlation_id` are ignored on this carriage and SHOULD be
 * empty: there is no connection here, and nothing to correlate an answer
 * against. THIS ENTRY RETURNS NO BODY -- a caller that wants one calls
 * `tw_core_submit_response` below, which answers the call itself and so still
 * needs no id.
 *
 * `idempotency_key` IS read, from the FRAME (form 1 only; a bare name carries
 * none). An empty key means absent, which is what this entry has always seen
 * and is still what a shell SHOULD send unless the catalogue requires one:
 * ADR-0008 makes it the CEREMONY key for `pair.begin`, `pair.confirm`,
 * `device.revoke`, `key.rotate` and the three update operations, and those are
 * refused as MGMT.PRECONDITION_FAILED without it. It is NOT a retry token
 * here; it is the precondition, checked in the core so both carriages check it
 * once. Added at minor 3 -- see TW_ABI_MINOR.
 *
 * A rejected command still produces an EVENT; it is never a silent drop. */
int32_t tw_core_submit(tw_core *core, tw_slice command, tw_buf **err_out);

/* Submits one command AND HANDS BACK ITS UNICAST RESPONSE BODY. NON-BLOCKING.
 *
 * ADDED AT MINOR 3. `tw_core_submit` above is UNCHANGED and stays correct for
 * every caller that wants no body. This is the same submission, decoded by the
 * same code from the same two `command` forms -- MI-20's "one contract, two
 * carriages" would be broken by a second parse -- with the one value F-5a
 * describes returned to the caller that submitted it.
 *
 * ---------------------------------------------------------------------------
 * *response_out. This paragraph is normative.
 * ---------------------------------------------------------------------------
 * On TW_OK, `*response_out` is EITHER
 *
 *   - NULL, which is what every operation but `pair.begin` produces today. It
 *     does NOT mean "no answer". It means THE ANSWER IS THE ONE THE STREAM
 *     ALREADY CARRIED: the `command.completed` event's `payload`. Read it
 *     there, off `tw_core_next_event`, exactly as before.
 *   - a core-owned `tw_buf` holding the operation's WHOLE response body, the
 *     same bytes a Unix-socket, named-pipe or XPC client receives in its
 *     `Response`. It is a SUPERSET of what the completion event carried, never
 *     a substitute for reading the stream.
 *
 * OWNERSHIP IS `tw_render_diagnostic`'S, EXACTLY, and F-2 admits no second
 * rule: the core allocated it, the caller releases it with `tw_buf_free`, and
 * no other free is valid. The one difference is that this pointer MAY be NULL
 * where `tw_render_diagnostic`'s never is -- and `tw_buf_free` is NULL-safe,
 * so an unconditional free is still correct.
 *
 * Passing NULL for `response_out` DECLINES the body: the core drops it instead
 * of allocating one that nothing will free. That is exactly what
 * `tw_core_submit` does, and it is why the older entry CANNOT leak this value
 * even by accident -- it is not a convention, it is the absence of a
 * destination.
 *
 * ---------------------------------------------------------------------------
 * MI-P1 RULES 2 AND 3 BECOME THE CALLER'S HERE
 * ---------------------------------------------------------------------------
 * Up to this pointer the core has held them structurally: the value never
 * entered the event stream, a log line, the Tier-0 ledger, a `Diagnostic` or
 * any store, and the core's own retained copy is zeroized when it is dropped.
 * Past `tw_buf_free` the shell owns that obligation. THE BYTES MUST NOT BE
 * LOGGED AT ANY LEVEL, MUST NOT BE PUT BACK ON THE EVENT STREAM, MUST NOT
 * REACH A TIER-1 DIAGNOSTIC BUNDLE, AND MUST NOT BE PERSISTED BY EITHER SIDE.
 * A `pair.begin` body additionally EXPIRES: drop it at the offer's
 * `not_after_ms` (120 s), whether or not the user has finished with it.
 *
 * Errors are `tw_core_submit`'s, identically. On TW_ERR `*response_out` is set
 * to NULL and *err_out holds the F-4 envelope. */
int32_t tw_core_submit_response(tw_core *core, tw_slice command,
                                tw_buf **response_out, tw_buf **err_out);

/* Waits up to `timeout_ms` for the next event on the ONE ordered stream.
 *
 * Returns TW_OK with *event_out set, TW_TIMEOUT (no event, or tw_core_wake was
 * called), or TW_ERR with *err_out set. Release *event_out with tw_buf_free.
 *
 * THE ONLY BLOCKING CALL IN THIS ABI.
 *
 * ---------------------------------------------------------------------------
 * THE BYTES IN *event_out. This paragraph is normative.
 * ---------------------------------------------------------------------------
 * One MANAGEMENT-INTERFACE FRAME, exactly as the Unix socket, the named pipe
 * and XPC carry it: a 4-byte BIG-ENDIAN length prefix followed by that many
 * bytes of UTF-8 JSON. MI-20 -- "one contract, two carriages, NEVER two
 * contracts" -- and this ABI is one of the carriages, not an exception to it.
 * The Rust declaration is `twinvpn_mgmt::envelope::MgmtEnvelope`; a shell in
 * another language decodes the JSON and links NOTHING.
 *
 * The object has these members. `body.kind` is the DISCRIMINATOR: read it
 * first, and treat an unknown value as a forward-compatible event to ignore,
 * never as a parse failure.
 *
 *   mi_version      uint    the MI version this core speaks
 *   request_id      []      ALWAYS EMPTY here -- see below
 *   correlation_id  []      ALWAYS EMPTY: this is a PUSHED event (ADR-0017
 *                           11.3), not an answer to a request
 *   seq             uint    the core's own sequence number. STRICTLY
 *                           INCREASING, and contiguous EXCEPT across a
 *                           `compacted` body, which announces the gap it
 *                           spans. A receiver that sees no `compacted` has
 *                           missed nothing (MI-9a, MI-19).
 *   idempotency_key []      ALWAYS EMPTY here
 *   as_of_ms        uint    MI-16. The AGENT's stamp on the boot-time
 *                           monotonic clock. A contiguous `seq` proves no
 *                           event was LOST; this proves one was RECENT.
 *   body            object  one of the two below
 *
 *   body.kind == "event"
 *     topic            string   one of exactly five: "transition", "session",
 *                               "diagnostic", "command.completed",
 *                               "command.rejected" (ADR-0017 11.10)
 *     payload          bytes    the frozen contract message for that topic:
 *                               TransitionEvent, SessionEvent, or ErrorEnvelope
 *                               for "diagnostic" and "command.rejected"; for
 *                               "command.completed", the operation's own result
 *                               bytes, which may be empty
 *     actor_principal  string?  MI-18. The OS principal whose call caused this,
 *                               or absent for an agent-internal or
 *                               peer-initiated cause. "The tunnel went down"
 *                               and "DANA took the tunnel down" are different
 *                               facts, and this is the field that keeps them
 *                               different.
 *     op               string?  WHICH operation, on the two `command.*` topics;
 *                               absent on the other three. It is on the wire
 *                               BECAUSE OF THIS ABI: tw_core_submit is
 *                               fire-and-forget and returns no request id, so a
 *                               shell here has nothing else to correlate a
 *                               completion against. A socket carriage holds
 *                               that registration in memory and does not need
 *                               it -- but carries it now too, because one
 *                               vocabulary is the point.
 *
 *   body.kind == "compacted"                                         (MI-19)
 *     up_to_seq        uint     bodies were dropped up to and including this
 *     dropped_by_topic array    [topic, count] pairs
 *
 *   A DROP IS NEVER A SILENCE. The marker arrives IN ORDER, before any further
 *   event, so "I missed something" and "I missed nothing" stay
 *   distinguishable -- which is the whole of MI-9a. */
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
