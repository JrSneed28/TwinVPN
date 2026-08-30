//! `twinvpn-ffi` — the `twinvpn.h` C ABI.
//!
//! **Authority:** [ADR-0018](../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! §11.4 (F-1…F-10), §11.5 (per-shell binding), §11.6 (the seam), §11.12 (VR-2,
//! VR-4), §11.13 (PB-1); DP-4 (the `unsafe` allowlist).
//!
//! **Owner:** `core-composition`. `core/ffi/include/twinvpn.h` is the **ABI of
//! record**; this crate implements it, and
//! `tests/header_matches_rust.rs` fails if the two drift.
//!
//! # The surface, function by function
//!
//! Twelve exported functions. F-1: *"the surface is small and coarse … Every
//! exported function is a compatibility obligation forever; convenience added
//! here is permanent."*
//!
//! | Symbol | Purpose |
//! |---|---|
//! | [`tw_abi_major`] / [`tw_abi_minor`] | V-B, checked in-process only (VR-2) |
//! | [`tw_build_identity`] | S-46, static storage, never freed |
//! | [`tw_reason_registry_version`] | the registry this build compiled against |
//! | [`tw_render_diagnostic`] | **F-10** — pure, instance-free |
//! | [`tw_core_create`] / [`tw_core_destroy`] | the instance (S-47) |
//! | [`tw_core_submit`] | non-blocking command submission (F-5) |
//! | [`tw_core_next_event`] | the **one** blocking call (F-5) |
//! | [`tw_core_wake`] | cancels it, from any thread |
//! | [`tw_buf_bytes`] / [`tw_buf_free`] | core-allocated buffers (F-2) |
//!
//! # F-7 containment
//!
//! **Every `extern "C"` body in this crate is wrapped in
//! [`std::panic::catch_unwind`].** ADR-0018 §11.3 requires `panic = "unwind"` in
//! every shipped profile precisely for this, and the entry points are declared
//! `extern "C"` (not `"C-unwind"`), so an unwind that somehow escaped a wrapper
//! aborts deterministically rather than becoming undefined behaviour. A caught
//! panic marks the instance poisoned, emits `INTERNAL.CORE_PANIC`, and **does
//! not touch the installed rule set** (§7.5, CB-6).
//!
//! # PB-1
//!
//! **No function here takes or returns a packet.** Zero FFI crossings per
//! packet, with the one exception §11.13 names — `NEPacketTunnelFlow`, which is
//! a Swift API and not this ABI.
//!
//! # DP-4
//!
//! `unsafe` is permitted here and nowhere else outside `twinvpn-crypto`. Every
//! block carries a `// SAFETY:` comment naming its invariant, and the pointer
//! work is concentrated in [`abi`] so the count stays small and reviewable.

// DP-4 unsafe allowlist member: `unsafe` is permitted here and NOWHERE else.
// Every `unsafe` block MUST carry a `// SAFETY:` comment stating the invariant.
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::module_name_repetitions)]

// The iOS adapter is LINKED, not called. `ownership.md` §10.4 puts the Swift
// bridge in `twinvpn-platform-ios` and `shells/ios` links exactly one archive —
// this crate's `staticlib`. Nothing in this crate references that one, so
// `extern crate` is what pulls its objects in; without it every `twinvpn_ios_*`
// symbol the Swift side calls is undefined at the shell's link step, which is a
// link failure and not a runtime one.
//
// This adds NO surface to `twinvpn.h`: the entries it carries are the three
// `tw_host_vtable` slots (`os_csprng`, `elapsed_millis`, `boot_id`) that have
// existed since minor 0, implemented over the INTERNAL, versionless bridge
// §10.4 carves out. `TW_ABI_MINOR` does not move.
#[cfg(target_os = "ios")]
extern crate twinvpn_platform_ios;

pub mod abi;
pub mod env;
pub mod vtable;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use std::time::Duration;

use twinvpn_core::{Core, CoreParts};
use twinvpn_diag::{Binding, PlatformContext, Tier};
use twinvpn_platform::PlatformAdapter as _;
use twinvpn_types::{codes, Component, Diagnostic, ReasonCode};

use crate::abi::{as_ref_opt, write_out, TwBuf, TwSlice};
use crate::vtable::{HostAdapter, HostFns, TwHostVtable, TW_ERR, TW_OK, TW_TIMEOUT};

/// The ABI major this build implements. Mirrors `TW_ABI_MAJOR` in `twinvpn.h`.
pub const TW_ABI_MAJOR: u32 = twinvpn_core::ABI_MAJOR;
/// The ABI minor. Mirrors `TW_ABI_MINOR`.
pub const TW_ABI_MINOR: u32 = twinvpn_core::ABI_MINOR;

/// The instance a `tw_core *` points at.
///
/// A newtype rather than `Core` directly, so the pointer C holds names a type
/// that exists only at this boundary and cannot be confused with anything else.
pub struct TwCore {
    core: Core,
}

// ---------------------------------------------------------------------------
// Panic containment (F-7)
// ---------------------------------------------------------------------------

/// Runs `body`, containing any panic.
///
/// `AssertUnwindSafe` is used deliberately and is sound here for the reason F-7
/// gives: a caught panic **poisons the instance**, so no caller ever observes
/// state that a partially-completed operation left behind. The poison is the
/// unwind-safety argument, not an assumption that nothing was half-done.
fn contained<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Runs `body` on a live instance, containing any panic and poisoning on one.
///
/// # R-16: the fallback is a THUNK, not a value
///
/// Every caller's fallback is `(TW_ERR, envelope_for(..))`, and `envelope_for`
/// allocates a `Box<TwBuf>` holding an encoded envelope. Taken **by value**,
/// that allocation happened on every call — including the success path, where
/// the value is dropped without ever reaching `write_out`, so the `Box` was
/// never reclaimed by anything. On the shell's blocking `tw_core_next_event`
/// loop in a long-lived privileged daemon that is an unbounded heap leak.
///
/// Taking it as `FnOnce() -> T` means the envelope is built **only on the two
/// paths that hand it to the caller** — a null instance, or a contained panic.
fn contained_on<T>(
    core: Option<&TwCore>,
    fallback: impl FnOnce() -> T,
    body: impl FnOnce(&TwCore) -> T,
) -> T {
    let Some(core) = core else {
        return fallback();
    };
    catch_unwind(AssertUnwindSafe(|| body(core))).unwrap_or_else(|_| {
        // F-7: emit INTERNAL.CORE_PANIC, mark the instance poisoned, make
        // every subsequent call return that code — and DO NOT tear down the
        // installed rule set. `Core::poison` touches no adapter capability,
        // which is what makes the last clause true.
        core.core.poison();
        fallback()
    })
}

/// Encodes a diagnostic into an F-4 envelope buffer.
fn envelope(diagnostic: &Diagnostic) -> *mut TwBuf {
    let emitter = twinvpn_diag::Emitter::new(Component::Diagnostics, Tier::LocalLedger);
    let msg = emitter.error_envelope(diagnostic, None);
    let mut buf = Vec::with_capacity(prost::Message::encoded_len(&msg));
    // `Vec` never fails to grow, and a failure here would be the one path that
    // cannot report a failure. Encoding into a `Vec` is infallible by contract.
    let _ = prost::Message::encode(&msg, &mut buf);
    TwBuf::into_raw(buf)
}

/// The F-4 envelope for a bare code.
fn envelope_for(code: ReasonCode) -> *mut TwBuf {
    envelope(&Diagnostic::builder(code, Component::Diagnostics).build())
}

/// **MI-16's agent stamp**, on the boot-time monotonic clock ADR-0022 LC-8
/// names — the same reading `shells/linux` puts on every envelope it emits.
///
/// > A contiguous `seq` proves **no event was lost**; it does not prove **any
/// > event was recent**.
fn as_of_ms(tw: &TwCore) -> u64 {
    tw.core.env().now_elapsed().as_micros() / 1_000
}

// ---------------------------------------------------------------------------
// Instance-free entry points
// ---------------------------------------------------------------------------

/// `uint32_t tw_abi_major(void);`
#[no_mangle]
pub extern "C" fn tw_abi_major() -> u32 {
    contained(0, || TW_ABI_MAJOR)
}

/// `uint32_t tw_abi_minor(void);`
#[no_mangle]
pub extern "C" fn tw_abi_minor() -> u32 {
    contained(0, || TW_ABI_MINOR)
}

/// `uint32_t tw_reason_registry_version(void);`
///
/// Discharges ADR-0019's "expose the registry version built against", and is
/// mirrored in S-46 so it also reaches a diagnostic bundle **without a live
/// instance**.
#[no_mangle]
pub extern "C" fn tw_reason_registry_version() -> u32 {
    contained(0, twinvpn_diag::reason_registry_version)
}

/// The process-wide S-46 blob.
///
/// S-46 is *"immutable within an artifact"* and *"impossible to conflict — the
/// value is a property of the loaded binary"*, so one static allocation is the
/// honest representation and `tw_build_identity` documents that it is never
/// freed.
///
/// The ABI pair **is** carried here: VR-2's 2026-08-27 clarification permits
/// `abi_*` in `CoreBuildIdentity` and in a Tier-1 bundle, and forbids it only as
/// a decision input outside one process and in Tier-2 telemetry.
static BUILD_IDENTITY: OnceLock<Vec<u8>> = OnceLock::new();

/// `tw_slice tw_build_identity(void);`
#[no_mangle]
pub extern "C" fn tw_build_identity() -> TwSlice {
    contained(TwSlice::empty(), || {
        let bytes = BUILD_IDENTITY.get_or_init(|| {
            twinvpn_core::CoreBuildIdentity::assemble(
                TW_ABI_MAJOR,
                TW_ABI_MINOR,
                Vec::new(),
                "twinvpn-crypto".to_owned(),
                false,
                "unbound".to_owned(),
                "twinvpn-ffi/host-vtable",
            )
            .map_or_else(|_| Vec::new(), |id| id.encode(Tier::LocalLedger))
        });
        TwSlice::from_slice(bytes)
    })
}

/// `tw_buf *tw_render_diagnostic(tw_slice, tw_slice, tw_slice, tw_slice);`
///
/// **F-10**, F-1's one exception. Pure: no I/O, no clock, no ambient locale, no
/// ambient platform, no instance, no global state. Callable while an instance is
/// poisoned, which is the point.
///
/// # Safety
///
/// Each `tw_slice` is either empty or points to a valid, initialised byte range
/// that stays valid for this call, per `twinvpn.h`.
#[no_mangle]
pub unsafe extern "C" fn tw_render_diagnostic(
    reason_code: TwSlice,
    evidence: TwSlice,
    locale_bcp47: TwSlice,
    platform_ctx: TwSlice,
) -> *mut TwBuf {
    // SAFETY: the caller's contract, stated above and in `twinvpn.h`: each slice
    // is empty or points to an initialised range valid for this call. The bytes
    // are read and copied before this function returns.
    let code_bytes = unsafe { reason_code.as_bytes() };
    // SAFETY: as above.
    let evidence_bytes = unsafe { evidence.as_bytes() };
    // SAFETY: as above.
    let locale_bytes = unsafe { locale_bcp47.as_bytes() };
    // SAFETY: as above.
    let platform_bytes = unsafe { platform_ctx.as_bytes() };

    contained(core::ptr::null_mut(), || {
        // F-3: UTF-8, never assumed valid on input. Invalid UTF-8 is a typed
        // condition, never a panic — and here it is not even an error, because
        // F-10 must not fail: an unparseable code degrades like an unknown one.
        let code = core::str::from_utf8(code_bytes).unwrap_or("INTERNAL.UNEXPECTED_STATE");
        let locale = core::str::from_utf8(locale_bytes).unwrap_or("en");
        let platform = PlatformContext::decode(platform_bytes);
        let bindings = decode_bindings(evidence_bytes);

        let resolved = twinvpn_diag::render(code, &bindings, locale, &platform);
        TwBuf::into_raw(encode_resolved(&resolved))
    })
}

/// Decodes `twinvpn.v1.DiagnosticContext`'s evidence into render bindings.
///
/// A malformed blob yields **no** bindings rather than an error: a catalogue
/// pattern with an unbound placeholder still renders a grammatical sentence, and
/// failing the render because the evidence was corrupt would lose the code as
/// well as the detail.
fn decode_bindings(bytes: &[u8]) -> Vec<Binding> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let Ok(ctx) = <twinvpn_schema::v1::DiagnosticContext as prost::Message>::decode(bytes) else {
        return Vec::new();
    };
    ctx.evidence
        .into_iter()
        .filter_map(|e| {
            let value = match e.value? {
                twinvpn_schema::v1::evidence::Value::StringValue(s) => {
                    twinvpn_types::EvidenceValue::Text(s)
                }
                twinvpn_schema::v1::evidence::Value::IntValue(n) => {
                    twinvpn_types::EvidenceValue::Int(n)
                }
                twinvpn_schema::v1::evidence::Value::UintValue(n) => {
                    twinvpn_types::EvidenceValue::Uint(n)
                }
                twinvpn_schema::v1::evidence::Value::BoolValue(b) => {
                    twinvpn_types::EvidenceValue::Bool(b)
                }
                twinvpn_schema::v1::evidence::Value::DurationMsValue(ms) => {
                    twinvpn_types::EvidenceValue::DurationMs(ms)
                }
                // An address or a prefix is intrinsically SENSITIVE. Rendering
                // one is legitimate at Tier 0 — but the *caller* decides the
                // tier, and F-10 has no tier parameter, so this refuses to bind
                // them rather than deciding on the caller's behalf.
                _ => return None,
            };
            Some(Binding { key: e.key, value })
        })
        .collect()
}

/// Encodes a [`twinvpn_diag::Resolved`] as an `ErrorEnvelope`.
///
/// The envelope carries the code and the F-4 `resolved` attribute set. The
/// rendered sentences ride in the evidence set under two reserved keys, because
/// `errors.proto` **prohibits** adding a `summary`, `message` or `title` field —
/// doing so would place a second text authority outside the registry (CB-4,
/// MI-15). A consumer that does not know the keys ignores them and still gets
/// the code and the attributes, which is rule 5's degradation working.
fn encode_resolved(resolved: &twinvpn_diag::Resolved) -> Vec<u8> {
    use twinvpn_schema::v1;
    let mut evidence = vec![v1::Evidence {
        key: "resolved_summary".to_owned(),
        classification: twinvpn_types::FieldClassification::Public as i32,
        value: Some(v1::evidence::Value::StringValue(resolved.summary.clone())),
    }];
    if let Some(action) = &resolved.next_action {
        evidence.push(v1::Evidence {
            key: "resolved_next_action".to_owned(),
            classification: twinvpn_types::FieldClassification::Public as i32,
            value: Some(v1::evidence::Value::StringValue(action.clone())),
        });
    }
    let msg = v1::ErrorEnvelope {
        reason_code: resolved.reason_code.clone(),
        evidence,
        resolved: Some(v1::ResolvedAttributes {
            class: resolved.attributes.class as i32,
            severity: resolved.attributes.severity as i32,
            terminal: resolved.attributes.terminal,
            user_actionable: resolved.attributes.user_actionable,
            remediation_class: resolved.attributes.remediation_class as i32,
            scope: resolved.attributes.scope as i32,
            doc_anchor: resolved.attributes.doc_anchor.to_owned(),
            // Registry LOOKUP KEYS, never text. `errors.proto` prohibits a
            // `summary`, `message` or `title` field here for exactly the reason
            // CB-4 and MI-15 give; carrying the keys keeps the registry the one
            // text authority.
            summary_key: String::new(),
            next_action_key: String::new(),
        }),
        ..Default::default()
    };
    let mut buf = Vec::with_capacity(prost::Message::encoded_len(&msg));
    let _ = prost::Message::encode(&msg, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// The instance
// ---------------------------------------------------------------------------

/// `tw_core *tw_core_create(uint32_t, const tw_host_vtable *, tw_slice, tw_buf **);`
///
/// # Safety
///
/// `host` is either null or a valid `tw_host_vtable` whose `size` truthfully
/// reports what the shell compiled; `config` follows `tw_slice`'s contract;
/// `err_out` is either null or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn tw_core_create(
    abi_major_expected: u32,
    host: *const TwHostVtable,
    config: TwSlice,
    err_out: *mut *mut TwBuf,
) -> *mut TwCore {
    // SAFETY: the caller's contract, above. `copy_from` checks for null and for
    // an implausible `size` before reading anything else.
    let fns = unsafe { HostFns::copy_from(host) };
    // SAFETY: the caller's `tw_slice` contract.
    let _config = unsafe { config.as_bytes() };

    let (result, err) = contained((core::ptr::null_mut(), core::ptr::null_mut()), || {
        // VR-4, first, before any capability is touched.
        if abi_major_expected != TW_ABI_MAJOR {
            return (
                core::ptr::null_mut(),
                envelope_for(codes::INTERNAL_ABI_VERSION_MISMATCH),
            );
        }
        let Some(fns) = fns else {
            return (
                core::ptr::null_mut(),
                envelope_for(codes::PLATFORM_ADAPTER_UNAVAILABLE),
            );
        };
        let Ok(env) = env::assemble(fns, env::Scheduler::WorkStealing) else {
            return (
                core::ptr::null_mut(),
                envelope_for(codes::PLATFORM_ADAPTER_UNAVAILABLE),
            );
        };
        let adapter = std::sync::Arc::new(HostAdapter::new(fns));
        let custody = adapter.store().record_aead_custody();
        let parts = CoreParts {
            env,
            adapter: adapter.clone(),
            abi_major_expected,
            abi_major: TW_ABI_MAJOR,
            abi_minor: TW_ABI_MINOR,
            schema_digest: Vec::new(),
            crypto_provider: "twinvpn-crypto".to_owned(),
            sek_custody: match custody {
                twinvpn_platform::custody::RecordAeadCustody::PlatformPerformed => {
                    "platform-aead".to_owned()
                }
                twinvpn_platform::custody::RecordAeadCustody::CoreHeld => {
                    "core-held:unreported".to_owned()
                }
            },
            // §11.16 (l): the attestation is the adapter's to report truthfully.
            // Until it has been queried, `false` is the honest answer, and the
            // core MUST NOT assume otherwise.
            hardware_backed: false,
            ledger_capacity: twinvpn_diag::ring::DEFAULT_CAPACITY,
            event_capacity: twinvpn_core::events::DEFAULT_CAPACITY,
        };
        match Core::create(parts) {
            Ok(core) => (
                Box::into_raw(Box::new(TwCore { core })),
                core::ptr::null_mut(),
            ),
            Err(diagnostic) => (core::ptr::null_mut(), envelope(&diagnostic)),
        }
    });

    // SAFETY: the caller's `err_out` contract, above.
    unsafe { write_out(err_out, err) };
    result
}

/// `void tw_core_destroy(tw_core *);`
///
/// # Safety
///
/// `core` is either null or a pointer from [`tw_core_create`] not yet destroyed.
#[no_mangle]
pub unsafe extern "C" fn tw_core_destroy(core: *mut TwCore) {
    if core.is_null() {
        return;
    }
    // SAFETY: non-null, and by the caller's contract it came from
    // `Box::into_raw` in `tw_core_create` and has not been destroyed.
    let boxed = unsafe { Box::from_raw(core) };
    // Graceful shutdown, contained: a panic in a component's teardown must not
    // escape into C. It also does not remove the installed ruleset (CB-6).
    let _ = catch_unwind(AssertUnwindSafe(|| boxed.core.begin_shutdown()));
    drop(boxed);
}

/// `int32_t tw_core_submit(tw_core *, tw_slice, tw_buf **);`
///
/// # Safety
///
/// `core` and `command` follow their `twinvpn.h` contracts.
#[no_mangle]
pub unsafe extern "C" fn tw_core_submit(
    core: *mut TwCore,
    command: TwSlice,
    err_out: *mut *mut TwBuf,
) -> i32 {
    // SAFETY: the caller's instance-pointer contract.
    let instance = unsafe { as_ref_opt(core.cast_const()) };
    // SAFETY: the caller's `tw_slice` contract.
    let bytes = unsafe { command.as_bytes() };

    let (rc, err) = contained_on(
        instance,
        || (TW_ERR, envelope_for(codes::INTERNAL_UNEXPECTED_STATE)),
        |tw| {
            // F-8: the command crosses as an encoded blob, and the name inside
            // it is looked up in the SAME catalogue the MI transport uses — one
            // contract, two carriages.
            let submission = match decode_submission(bytes) {
                Ok(submission) => submission,
                Err(reason) => return (TW_ERR, envelope_for(reason)),
            };
            match tw.core.submit(&submission) {
                Ok(()) => (TW_OK, core::ptr::null_mut()),
                Err(d) => (TW_ERR, envelope(&d)),
            }
        },
    );

    // SAFETY: the caller's `err_out` contract.
    unsafe { write_out(err_out, err) };
    rc
}

/// `int32_t tw_core_next_event(tw_core *, uint32_t, tw_buf **, tw_buf **);`
///
/// The **only** blocking call in this ABI.
///
/// # Safety
///
/// `core`, `event_out` and `err_out` follow their `twinvpn.h` contracts.
#[no_mangle]
pub unsafe extern "C" fn tw_core_next_event(
    core: *mut TwCore,
    timeout_ms: u32,
    event_out: *mut *mut TwBuf,
    err_out: *mut *mut TwBuf,
) -> i32 {
    // SAFETY: the caller's instance-pointer contract.
    let instance = unsafe { as_ref_opt(core.cast_const()) };

    let (rc, event, err) = contained_on(
        instance,
        || {
            (
                TW_ERR,
                core::ptr::null_mut(),
                envelope_for(codes::INTERNAL_UNEXPECTED_STATE),
            )
        },
        |tw| {
            match tw
                .core
                .next_event(Duration::from_millis(u64::from(timeout_ms)))
            {
                Some(event) => (
                    TW_OK,
                    TwBuf::into_raw(encode_event(&event, as_of_ms(tw))),
                    core::ptr::null_mut(),
                ),
                // Not a failure: a timeout and a wake are both normal, and F-4
                // reserves the envelope for things that have a NAME.
                None => (TW_TIMEOUT, core::ptr::null_mut(), core::ptr::null_mut()),
            }
        },
    );

    // SAFETY: the caller's out-parameter contracts.
    unsafe { write_out(event_out, event) };
    // SAFETY: as above.
    unsafe { write_out(err_out, err) };
    rc
}

/// Decodes a submitted command, in **either** of the two forms this ABI accepts.
///
/// # M-1's other direction
///
/// M-1 made the *event* side self-describing: every event now crosses as a
/// length-prefixed [`twinvpn_mgmt::envelope::MgmtEnvelope`], the same vocabulary
/// the Unix socket, the named pipe and XPC speak (MI-20 — *"one contract, two
/// carriages, never two contracts"*). The **command** side was left as a bare
/// UTF-8 operation name, and that is a real ceiling rather than a stylistic
/// one: `Submission` carries `params`, `idempotency_key`, `if_version` and
/// `actor_principal`, and a bare name can express none of them.
///
/// The consequence was visible in the mobile shells. `shells/ios`'
/// `CoreCommand.pathSnapshot(json, acrossWake:)` and
/// `CoreCommand.memoryPressure(residentBytes:)` had no way to carry the JSON or
/// the byte count across, and `session.connect` — which requires a 32-byte peer
/// `device_id` — could not be submitted **at all**, because its parameter is the
/// whole of what it means.
///
/// So this accepts both:
///
/// 1. **A length-prefixed `MgmtEnvelope` whose body is a `Request`.** The full
///    submission: operation, `params`, `if_version`. This is the form a shell
///    should use, and it is byte-identical to what it would put on a socket.
/// 2. **A bare UTF-8 operation name.** Kept, unchanged, because F-1 makes every
///    exported function a compatibility obligation forever — a shell already
///    submitting a bare name must keep working. It means exactly what it
///    always did: `Submission::bare`.
///
/// The two are told apart by the framing, not by a flag: a frame begins with a
/// four-byte big-endian length that equals the remaining byte count, and no
/// operation name in the catalogue has that shape.
///
/// # Errors
///
/// `PROTO.MALFORMED_MESSAGE` for bytes that are neither, and the substituted
/// `MGMT.OP_UNKNOWN` for a name the catalogue does not contain — a **typed**
/// rejection, never a parse failure (ADR-0017 §11.7).
fn decode_submission(bytes: &[u8]) -> Result<twinvpn_mgmt::Submission, ReasonCode> {
    use twinvpn_mgmt::envelope::{Body, MgmtEnvelope};

    // Form 1: the MI frame. Tried first and told apart by SHAPE — a frame whose
    // declared length matches its own body cannot be mistaken for an operation
    // name, and no catalogue name begins with a four-byte length that happens
    // to equal the rest of it.
    //
    // A frame that decodes and is NOT a `Request` does not fall through to form
    // 2. It is malformed *as a submission*, and saying so beats letting its
    // JSON be read as an operation name and answered `MGMT.OP_UNKNOWN` — which
    // would tell a shell "that operation does not exist" about bytes that named
    // no operation at all. MI-3's direction rule: a client may send `Hello`,
    // `Request` or `Goodbye`, and only the middle one is a command.
    if let Ok(MgmtEnvelope { body, .. }) = twinvpn_mgmt::envelope::decode_frame(bytes) {
        let Body::Request(request) = body else {
            return Err(codes::PROTO_MALFORMED_MESSAGE);
        };
        let Some(op) = twinvpn_mgmt::CoreCommand::from_name(request.operation.trim()) else {
            return Err(twinvpn_mgmt::codes::op_unknown());
        };
        return Ok(twinvpn_mgmt::Submission {
            op,
            params: request.params,
            // The ABI is in-process and fire-and-forget, so there is no retry to
            // deduplicate and no key to carry one. Left absent rather than
            // fabricated; `dispatch::disposition` refuses an operation whose
            // catalogue row requires one, by name.
            idempotency_key: None,
            if_version: request.if_version,
            // MI-18: the OS principal. There is no peer on this carriage to
            // attribute to, and inventing one would make "the tunnel went down"
            // and "someone took the tunnel down" the same fact.
            actor_principal: None,
        });
    }

    // Form 2: the bare name.
    let Ok(name) = core::str::from_utf8(bytes) else {
        return Err(codes::PROTO_MALFORMED_MESSAGE);
    };
    twinvpn_mgmt::CoreCommand::from_name(name.trim())
        .map(twinvpn_mgmt::Submission::bare)
        .ok_or_else(twinvpn_mgmt::codes::op_unknown)
}

/// Encodes one event for the wire, **in the MI envelope every other carriage
/// uses**.
///
/// **Authority:** ADR-0018 F-5 and F-8; ADR-0017 §11.3, MI-18, MI-19, MI-20
/// (*"one contract, two carriages, never two contracts"*); `ownership.md`
/// §10.8 **M-1** and **M-2**.
///
/// # What this used to do, and why it was the largest defect of wave 3
///
/// It wrote the bare [`twinvpn_core::CoreEventKind::encoded_payload`] bytes and
/// nothing else — **six different message types into one `tw_buf` with no
/// discriminator**. A receiver could not tell which it held.
/// `Diagnostic` and `CommandRejected` are both an `ErrorEnvelope` and were
/// therefore byte-identical, so *"your command failed"* and *"here is an
/// unsolicited diagnostic"* were the same bytes. `CommandCompleted` dropped
/// `op`, so a shell could not tell **which** command completed. And because
/// `seq` and `actor_principal` live on [`twinvpn_core::CoreEvent`] rather than
/// on its `kind`, encoding only the kind dropped both: F-5's *"exactly one
/// totally ordered stream"* crossed the ABI with its ordering removed, MI-19's
/// `Compacted` marker lost the `up_to_seq` that makes a gap resyncable, and
/// MI-18's *"'the tunnel went down' and 'Dana took the tunnel down' are
/// different facts"* became unsayable.
///
/// # Why the envelope, and not a new contract message
///
/// M-2 dispositioned the wire half as needing a **generated contract message**,
/// which would mean reopening the freeze. It does not, because
/// [`twinvpn_mgmt::envelope::MgmtEnvelope`] already carries every field M-1
/// names as lost — `seq`, the topic, `actor_principal`, and
/// `Compacted { up_to_seq, dropped_by_topic }` — and it is length-prefixed
/// JSON, which a Swift or Kotlin shell decodes **without linking a Rust type**.
/// That was M-2's whole objection to the `twinvpn-mgmt` half, and it is
/// answered by the encoding rather than by a second declaration. Using it here
/// is MI-20 applied to the ABI: the C ABI is a *carriage*, and it now speaks the
/// same vocabulary as the Unix socket, the named pipe and XPC.
///
/// # The four connection-scoped fields, stated rather than fabricated
///
/// `MgmtEnvelope` frames a **connection**, and the ABI is in-process and has
/// none. Each of those fields takes its documented not-applicable value and no
/// invented one:
///
/// - `request_id` is empty. MI-2 makes it unique per emission on a carriage that
///   has requests; this one does not — `tw_core_submit` is fire-and-forget and
///   returns no id, which is precisely why `op` has to travel on the event.
/// - `correlation_id` is empty, which §11.3 already specifies for a **pushed**
///   event on every carriage.
/// - `mi_version` is [`twinvpn_mgmt::envelope::MI_VERSION`], the version this
///   core speaks. It is not negotiated here because ADR-0018 §11.16 (o) keeps
///   `Hello`/`HelloAck` off the ABI: there is no peer to negotiate with.
/// - `as_of_ms` is stamped from the caller's [`twinvpn_env::Env`] elapsed clock
///   exactly as `shells/linux` stamps it, because MI-16 makes it the **agent's**
///   assertion and a contiguous `seq` proves nothing was lost without proving
///   anything was recent.
///
/// # Why a `Compacted` body rather than a diagnostic
///
/// The previous code synthesized an `INTERNAL.BUFFER_OVERFLOW` envelope for a
/// gap, which made MI-19's **ordered marker** indistinguishable from an
/// ordinary diagnostic and threw `up_to_seq` away. `Body::Compacted` is the
/// marker MI-19 asks for, and it carries both numbers.
fn encode_event(event: &twinvpn_core::CoreEvent, as_of_ms: u64) -> Vec<u8> {
    use twinvpn_core::CoreEventKind as K;
    use twinvpn_mgmt::envelope::{self, Body, Compacted, Event, MgmtEnvelope};

    let body = match &event.kind {
        K::Compacted { up_to_seq, dropped } => Body::Compacted(Compacted {
            up_to_seq: *up_to_seq,
            // The core counts a gap as one total rather than per topic, so the
            // one bucket it can honestly fill is filled and no other is
            // invented. A per-topic breakdown a carriage made up would be worse
            // than a total that is true.
            dropped_by_topic: vec![(event.kind.topic().to_owned(), *dropped)],
        }),
        kind => Body::Event(Event {
            topic: kind.topic().to_owned(),
            payload: kind.encoded_payload(),
            actor_principal: event.actor_principal.clone(),
            op: kind.op().map(str::to_owned),
        }),
    };

    let framed = MgmtEnvelope {
        mi_version: envelope::MI_VERSION,
        request_id: Vec::new(),
        correlation_id: Vec::new(),
        seq: event.seq,
        idempotency_key: Vec::new(),
        as_of_ms,
        body,
    };

    // `encode_frame`'s only failure is the size cap, which is checked on the
    // SEND side so this agent cannot emit a frame it would itself refuse. A
    // payload over the cap is a defect in whatever produced it, and it crosses
    // as a NAMED refusal rather than as a truncation or a silent drop —
    // `ownership.md` §6 rule 9.
    envelope::encode_frame(&framed).unwrap_or_else(|_| {
        let d = Diagnostic::builder(codes::PROTO_SIZE_EXCEEDED, Component::Diagnostics).build();
        let emitter = twinvpn_diag::Emitter::new(Component::Diagnostics, Tier::LocalLedger);
        let refusal = MgmtEnvelope {
            mi_version: envelope::MI_VERSION,
            request_id: Vec::new(),
            correlation_id: Vec::new(),
            seq: event.seq,
            idempotency_key: Vec::new(),
            as_of_ms,
            body: Body::Event(Event {
                topic: twinvpn_core::events::topics::DIAGNOSTIC.to_owned(),
                payload: {
                    let mut buf = Vec::new();
                    let _ = prost::Message::encode(&emitter.error_envelope(&d, None), &mut buf);
                    buf
                },
                actor_principal: None,
                op: None,
            }),
        };
        // The refusal carries no payload of the caller's, so it cannot itself
        // exceed the cap; if it somehow did, an empty frame is a decode error
        // at the reader rather than a panic here (F-3).
        envelope::encode_frame(&refusal).unwrap_or_default()
    })
}

/// `void tw_core_wake(tw_core *);` — callable from **any** thread.
///
/// # Safety
///
/// `core` is either null or a live instance pointer.
#[no_mangle]
pub unsafe extern "C" fn tw_core_wake(core: *mut TwCore) {
    // SAFETY: the caller's instance-pointer contract; null is handled.
    let instance = unsafe { as_ref_opt(core.cast_const()) };
    contained_on(instance, || (), |tw| tw.core.wake());
}

// ---------------------------------------------------------------------------
// Buffers (F-2)
// ---------------------------------------------------------------------------

/// `tw_slice tw_buf_bytes(const tw_buf *);`
///
/// # Safety
///
/// `buf` is either null or a live pointer from this crate.
#[no_mangle]
pub unsafe extern "C" fn tw_buf_bytes(buf: *const TwBuf) -> TwSlice {
    // SAFETY: the caller's contract; null yields the empty slice rather than a
    // dereference.
    let borrowed = unsafe { as_ref_opt(buf) };
    contained(TwSlice::empty(), || {
        borrowed.map_or_else(TwSlice::empty, |b| TwSlice::from_slice(b.bytes()))
    })
}

/// `void tw_buf_free(tw_buf *);` — idempotent on null.
///
/// # Safety
///
/// `buf` is either null or a pointer from this crate, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn tw_buf_free(buf: *mut TwBuf) {
    // SAFETY: the caller's contract, above; `release` handles null.
    unsafe { TwBuf::release(buf) };
}

#[cfg(test)]
mod event_encoding {
    //! **M-1.** The six shapes on the ABI's event stream, each asserted to be
    //! distinguishable from the other five.
    //!
    //! Every one of these failed before `encode_event` framed through the MI
    //! envelope, and each fails again the day it stops.

    use twinvpn_core::{CoreEvent, CoreEventKind};
    use twinvpn_mgmt::envelope::{decode_frame, Body, MgmtEnvelope};
    use twinvpn_schema::v1;

    use super::encode_event;

    const AS_OF: u64 = 4_242;

    fn event(seq: u64, kind: CoreEventKind, actor: Option<&str>) -> CoreEvent {
        CoreEvent {
            seq,
            kind,
            actor_principal: actor.map(str::to_owned),
        }
    }

    fn roundtrip(e: &CoreEvent) -> MgmtEnvelope {
        decode_frame(&encode_event(e, AS_OF)).expect("the ABI emits a decodable MI frame")
    }

    fn envelope() -> Box<v1::ErrorEnvelope> {
        Box::new(v1::ErrorEnvelope {
            reason_code: "INTERNAL.INVARIANT_VIOLATED".to_owned(),
            ..Default::default()
        })
    }

    #[test]
    fn a_diagnostic_and_a_command_rejection_are_no_longer_the_same_bytes() {
        // THE defect. Both carry an `ErrorEnvelope`, so before the envelope
        // they were byte-identical and "your command failed" and "here is an
        // unsolicited diagnostic" could not be told apart.
        let diagnostic = roundtrip(&event(1, CoreEventKind::Diagnostic(envelope()), None));
        let rejected = roundtrip(&event(
            2,
            CoreEventKind::CommandRejected {
                op: "tunnel.up",
                diagnostic: envelope(),
            },
            None,
        ));

        let (Body::Event(d), Body::Event(r)) = (&diagnostic.body, &rejected.body) else {
            panic!("both are events");
        };
        assert_eq!(d.topic, "diagnostic");
        assert_eq!(r.topic, "command.rejected");
        assert_ne!(d.topic, r.topic, "the two are distinguishable");
        // The payloads still agree, which is correct: the DISCRIMINATOR is the
        // topic, not a difference in the contract message.
        assert_eq!(d.payload, r.payload);
    }

    #[test]
    fn a_completion_says_which_command_completed() {
        let framed = roundtrip(&event(
            7,
            CoreEventKind::CommandCompleted {
                op: "peer.disconnect",
                result: vec![9, 9, 9],
            },
            None,
        ));
        let Body::Event(e) = &framed.body else {
            panic!("an event")
        };
        assert_eq!(e.topic, "command.completed");
        assert_eq!(e.op.as_deref(), Some("peer.disconnect"));
        assert_eq!(e.payload, vec![9, 9, 9], "the result is forwarded whole");
    }

    #[test]
    fn ordering_survives_the_crossing() {
        // F-5: "exactly one totally ordered stream". `seq` lives on CoreEvent
        // and encoding only the KIND dropped it, so the stream crossed with its
        // ordering removed.
        for seq in [0, 1, 2, u64::MAX] {
            let framed = roundtrip(&event(seq, CoreEventKind::Diagnostic(envelope()), None));
            assert_eq!(framed.seq, seq);
        }
    }

    #[test]
    fn mi_18_survives_the_crossing_and_absence_stays_absence() {
        // "The tunnel went down" and "Dana took the tunnel down" are different
        // facts. Both directions asserted: a named actor arrives named, and an
        // agent-internal cause arrives with no actor rather than an empty one.
        let by_dana = roundtrip(&event(
            1,
            CoreEventKind::Transition(Box::default()),
            Some("dana"),
        ));
        let Body::Event(e) = &by_dana.body else {
            panic!("an event")
        };
        assert_eq!(e.actor_principal.as_deref(), Some("dana"));

        let internal = roundtrip(&event(2, CoreEventKind::Transition(Box::default()), None));
        let Body::Event(e) = &internal.body else {
            panic!("an event")
        };
        assert_eq!(e.actor_principal, None);
    }

    #[test]
    fn a_gap_is_an_ordered_marker_that_keeps_its_up_to_seq() {
        // MI-19. Before, a gap was synthesized into an INTERNAL.BUFFER_OVERFLOW
        // diagnostic -- indistinguishable from an ordinary one, with `up_to_seq`
        // thrown away, so a receiver could not resync from it.
        let framed = roundtrip(&event(
            12,
            CoreEventKind::Compacted {
                up_to_seq: 11,
                dropped: 5,
            },
            None,
        ));
        let Body::Compacted(c) = &framed.body else {
            panic!("MI-19's marker is its own body, not a diagnostic");
        };
        assert_eq!(c.up_to_seq, 11);
        assert_eq!(c.dropped_by_topic, vec![("diagnostic".to_owned(), 5)]);
    }

    #[test]
    fn every_kind_lands_on_its_own_topic_and_the_five_are_the_registered_five() {
        let kinds = [
            CoreEventKind::Transition(Box::default()),
            CoreEventKind::SessionEvent(Box::default()),
            CoreEventKind::Diagnostic(envelope()),
            CoreEventKind::CommandCompleted {
                op: "x",
                result: Vec::new(),
            },
            CoreEventKind::CommandRejected {
                op: "x",
                diagnostic: envelope(),
            },
        ];
        let mut seen = Vec::new();
        for (i, kind) in kinds.into_iter().enumerate() {
            let framed = roundtrip(&event(i as u64, kind, None));
            let Body::Event(e) = &framed.body else {
                panic!("an event")
            };
            assert!(
                twinvpn_core::events::topics::ALL.contains(&e.topic.as_str()),
                "{} is not a registered topic",
                e.topic
            );
            seen.push(e.topic.clone());
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 5, "five kinds, five distinct topics");
    }

    #[test]
    fn the_connection_scoped_fields_are_empty_rather_than_invented() {
        // The ABI is in-process and has no connection. Each of these takes its
        // documented not-applicable value, and `twinvpn.h` says so normatively.
        let framed = roundtrip(&event(3, CoreEventKind::Diagnostic(envelope()), None));
        assert!(framed.request_id.is_empty(), "no requests on this carriage");
        assert!(
            framed.correlation_id.is_empty(),
            "a pushed event answers nothing"
        );
        assert!(framed.idempotency_key.is_empty());
        assert_eq!(framed.mi_version, twinvpn_mgmt::envelope::MI_VERSION);
        assert_eq!(framed.as_of_ms, AS_OF, "MI-16 is the AGENT's stamp");
    }

    #[test]
    fn the_frame_is_length_prefixed_so_a_foreign_shell_can_read_it_without_rust() {
        // M-2's objection: a Swift or Kotlin shell cannot link a Rust type. It
        // does not have to -- the frame is a big-endian length and then JSON.
        let bytes = encode_event(
            &event(1, CoreEventKind::Diagnostic(envelope()), None),
            AS_OF,
        );
        let declared = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, bytes.len() - 4, "the prefix describes the body");
        let json: serde_json::Value =
            serde_json::from_slice(&bytes[4..]).expect("the body is plain JSON");
        assert_eq!(json["body"]["kind"], "event");
        assert_eq!(json["body"]["topic"], "diagnostic");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_abi_version_matches_the_core() {
        assert_eq!(tw_abi_major(), twinvpn_core::ABI_MAJOR);
        assert_eq!(tw_abi_minor(), twinvpn_core::ABI_MINOR);
    }

    #[test]
    fn the_registry_version_is_the_one_the_build_compiled_against() {
        assert_eq!(
            tw_reason_registry_version(),
            twinvpn_types::REASON_REGISTRY_VERSION
        );
    }

    #[test]
    fn build_identity_is_static_and_stable_across_calls() {
        let a = tw_build_identity();
        let b = tw_build_identity();
        assert_eq!(a.ptr, b.ptr, "S-46 is immutable within an artifact");
        assert!(a.len > 0);
    }

    #[test]
    fn f10_renders_with_no_instance_and_no_ambient_state() {
        let code = b"PLATFORM.VPN_PERMISSION_DENIED";
        // SAFETY: every slice below borrows a live local for the call.
        let buf = unsafe {
            tw_render_diagnostic(
                TwSlice::from_slice(code),
                TwSlice::empty(),
                TwSlice::from_slice(b"en"),
                TwSlice::empty(),
            )
        };
        assert!(!buf.is_null());
        // SAFETY: `buf` was just produced by this crate and is live.
        let bytes = unsafe { tw_buf_bytes(buf.cast_const()) };
        // SAFETY: the slice borrows `buf`, which is still live.
        let decoded = <twinvpn_schema::v1::ErrorEnvelope as prost::Message>::decode(unsafe {
            bytes.as_bytes()
        })
        .expect("decodes");
        assert_eq!(decoded.reason_code, "PLATFORM.VPN_PERMISSION_DENIED");
        let resolved = decoded.resolved.expect("F-4 attributes are always present");
        assert!(resolved.user_actionable);
        assert!(!resolved.doc_anchor.is_empty());
        // SAFETY: `buf` came from this crate and has not been freed.
        unsafe { tw_buf_free(buf) };
    }

    #[test]
    fn f10_an_empty_platform_ctx_gives_the_neutral_variant() {
        // ADR-0019 LT-3b, at the ABI boundary.
        let code = b"PLATFORM.VPN_PERMISSION_DENIED";
        let android = twinvpn_schema::v1::DevicePlatformInfo {
            platform: 3,
            ..Default::default()
        };
        let mut android_bytes = Vec::new();
        prost::Message::encode(&android, &mut android_bytes).expect("encodes");

        // SAFETY: both slices borrow live locals.
        let neutral = unsafe {
            tw_render_diagnostic(
                TwSlice::from_slice(code),
                TwSlice::empty(),
                TwSlice::from_slice(b"en"),
                TwSlice::empty(),
            )
        };
        // SAFETY: as above.
        let specific = unsafe {
            tw_render_diagnostic(
                TwSlice::from_slice(code),
                TwSlice::empty(),
                TwSlice::from_slice(b"en"),
                TwSlice::from_slice(&android_bytes),
            )
        };
        // SAFETY: both buffers are live.
        let a = unsafe { tw_buf_bytes(neutral.cast_const()).as_bytes() }.to_vec();
        // SAFETY: as above.
        let b = unsafe { tw_buf_bytes(specific.cast_const()).as_bytes() }.to_vec();
        assert_ne!(a, b, "an empty platform_ctx must not resolve to a platform");
        // SAFETY: both came from this crate and have not been freed.
        unsafe {
            tw_buf_free(neutral);
            tw_buf_free(specific);
        }
    }

    #[test]
    fn f10_never_returns_null_even_for_nonsense() {
        // SAFETY: the slices borrow live locals; the empty slice is valid input.
        let buf = unsafe {
            tw_render_diagnostic(
                TwSlice::from_slice(&[0xff, 0xfe]),
                TwSlice::from_slice(&[0xff]),
                TwSlice::empty(),
                TwSlice::from_slice(&[0xff]),
            )
        };
        assert!(!buf.is_null(), "F-10 must render something, always");
        // SAFETY: live, unfreed.
        unsafe { tw_buf_free(buf) };
    }

    #[test]
    fn create_refuses_an_abi_mismatch_by_name() {
        let mut err: *mut TwBuf = core::ptr::null_mut();
        // SAFETY: a null vtable and a null config slice are both handled; the
        // ABI check runs before either is read.
        let core = unsafe { tw_core_create(99, core::ptr::null(), TwSlice::empty(), &raw mut err) };
        assert!(core.is_null());
        assert!(!err.is_null(), "F-4: a failure carries a NAME");
        // SAFETY: `err` is live.
        let bytes = unsafe { tw_buf_bytes(err.cast_const()) };
        // SAFETY: the slice borrows `err`, still live.
        let decoded = <twinvpn_schema::v1::ErrorEnvelope as prost::Message>::decode(unsafe {
            bytes.as_bytes()
        })
        .expect("decodes");
        assert_eq!(decoded.reason_code, "INTERNAL.ABI_VERSION_MISMATCH");
        // SAFETY: live, unfreed.
        unsafe { tw_buf_free(err) };
    }

    #[test]
    fn create_refuses_a_null_vtable_by_name() {
        let mut err: *mut TwBuf = core::ptr::null_mut();
        // SAFETY: null is checked before any read.
        let core = unsafe {
            tw_core_create(
                TW_ABI_MAJOR,
                core::ptr::null(),
                TwSlice::empty(),
                &raw mut err,
            )
        };
        assert!(core.is_null());
        assert!(!err.is_null());
        // SAFETY: live, unfreed.
        unsafe { tw_buf_free(err) };
    }

    #[test]
    fn every_entry_point_tolerates_a_null_instance() {
        // F-7's neighbour: a null handle must be a typed refusal, never a
        // segfault. A shell that has already destroyed its instance and calls
        // once more is a bug, and it must be a *reported* one.
        let mut err: *mut TwBuf = core::ptr::null_mut();
        // SAFETY: null is handled by `as_ref_opt`.
        assert_eq!(
            unsafe { tw_core_submit(core::ptr::null_mut(), TwSlice::empty(), &raw mut err) },
            TW_ERR
        );
        // SAFETY: live if non-null.
        unsafe { tw_buf_free(err) };

        let mut event: *mut TwBuf = core::ptr::null_mut();
        let mut err2: *mut TwBuf = core::ptr::null_mut();
        // SAFETY: null is handled.
        assert_eq!(
            unsafe { tw_core_next_event(core::ptr::null_mut(), 0, &raw mut event, &raw mut err2) },
            TW_ERR
        );
        // SAFETY: live if non-null.
        unsafe {
            tw_buf_free(event);
            tw_buf_free(err2);
        }

        // SAFETY: null is handled.
        unsafe { tw_core_wake(core::ptr::null_mut()) };
        // SAFETY: null is handled.
        unsafe { tw_core_destroy(core::ptr::null_mut()) };
    }

    /// The MI-frame form carries an operation's PARAMETERS.
    ///
    /// `tw_core_submit` used to parse its whole slice as a bare operation name,
    /// so `session.connect` — whose parameter is a 32-byte peer `device_id` and
    /// which means nothing without it — could not be submitted across this ABI
    /// at all. `shells/ios`' `CoreCommand.pathSnapshot(_:acrossWake:)` and
    /// `.memoryPressure(residentBytes:)` had the same problem, and
    /// `shells/android` had no submission path at all.
    #[test]
    fn a_submission_may_carry_parameters_in_an_mi_frame() {
        use twinvpn_mgmt::envelope::{self, Body, MgmtEnvelope, Request};

        let framed = envelope::encode_frame(&MgmtEnvelope {
            mi_version: envelope::MI_VERSION,
            request_id: Vec::new(),
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Request(Request {
                operation: "session.connect".to_owned(),
                params: vec![0x5a; 32],
                if_version: None,
            }),
        })
        .expect("within the cap");

        let submission = decode_submission(&framed).expect("decodes");
        assert_eq!(submission.op, twinvpn_mgmt::CoreCommand::SessionConnect);
        assert_eq!(
            submission.params,
            vec![0x5a; 32],
            "the parameter is the whole of what the operation means"
        );
    }

    /// The bare-name form still means exactly what it always did.
    ///
    /// F-1 makes every exported function a compatibility obligation forever, so
    /// the new form is an ADDITION beside this one rather than a replacement —
    /// which is what makes the version bump minor.
    #[test]
    fn a_bare_operation_name_is_still_accepted_with_no_parameters() {
        let submission = decode_submission(b"net.up").expect("decodes");
        assert_eq!(submission.op, twinvpn_mgmt::CoreCommand::NetUp);
        assert!(submission.params.is_empty());
        assert!(submission.if_version.is_none());

        // Whitespace is trimmed, as it always was.
        assert_eq!(
            decode_submission(
                b"  status.get 
"
            )
            .expect("decodes")
            .op,
            twinvpn_mgmt::CoreCommand::StatusGet
        );
    }

    #[test]
    fn both_forms_refuse_an_unknown_operation_by_name_rather_than_parsing_it() {
        use twinvpn_mgmt::envelope::{self, Body, MgmtEnvelope, Request};

        // ADR-0017 §11.7: "Never a parse error, never a hang, never a generic
        // failure."
        assert_eq!(
            decode_submission(b"tunnel.explode").unwrap_err(),
            twinvpn_mgmt::codes::op_unknown()
        );
        let framed = envelope::encode_frame(&MgmtEnvelope {
            mi_version: envelope::MI_VERSION,
            request_id: Vec::new(),
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Request(Request {
                operation: "tunnel.explode".to_owned(),
                params: Vec::new(),
                if_version: None,
            }),
        })
        .expect("within the cap");
        assert_eq!(
            decode_submission(&framed).unwrap_err(),
            twinvpn_mgmt::codes::op_unknown()
        );

        // And bytes that are neither form are malformed, not an unknown op:
        // the two are different facts and the shell acts differently on them.
        assert_eq!(
            decode_submission(&[0xff, 0xfe, 0xfd]).unwrap_err(),
            codes::PROTO_MALFORMED_MESSAGE
        );
    }

    #[test]
    fn an_agent_originated_body_is_not_a_submission() {
        use twinvpn_mgmt::envelope::{self, Body, MgmtEnvelope};

        // MI-3's direction rule. A `Goodbye` is client-originated but means
        // nothing on an in-process carriage with no connection, and a
        // `HelloAck` is the agent's own — neither is a command, and neither may
        // fall through to being read as an operation NAME.
        let framed = envelope::encode_frame(&MgmtEnvelope {
            mi_version: envelope::MI_VERSION,
            request_id: Vec::new(),
            correlation_id: Vec::new(),
            seq: 0,
            idempotency_key: Vec::new(),
            as_of_ms: 0,
            body: Body::Goodbye,
        })
        .expect("within the cap");
        assert_eq!(
            decode_submission(&framed).unwrap_err(),
            codes::PROTO_MALFORMED_MESSAGE
        );
    }

    #[test]
    fn buf_bytes_on_null_is_the_empty_slice() {
        // SAFETY: null is handled.
        let slice = unsafe { tw_buf_bytes(core::ptr::null()) };
        assert_eq!(slice.len, 0);
    }
}
