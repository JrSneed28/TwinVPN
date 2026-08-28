//! **The Android shell's JNI carriage for `twinvpn.h`.**
//!
//! **Authority:** ADR-0018 §11.4 F-1…F-8, §11.5's Android rows, §11.12, CB-2,
//! CD-I5, PB-1; ADR-0017 §11.3 and MI-20; `ownership.md` §8 item 10 and §10.4
//! (*"Swift and Kotlin marshal; they do not decide"*).
//!
//! # The defect this crate closes
//!
//! > **Android never instantiates a core.** `nativeCreate` returns an
//! > `AndroidBridge` wrapping only the platform adapter; there is no
//! > `tw_core_create`/`submit`/`next_event` JNI entry. `CoreClient.start()`
//! > sleeps in a loop, `requestConnect()` logs and returns — and
//! > `TwinVpnService.onStartCommand` calls it.
//!
//! So the Android app ran a platform adapter with **no core behind it**. The
//! service started, the notification appeared, the tile said what the tile
//! always says, and no command ever reached anything.
//!
//! # W-38 was stale, and this crate is why
//!
//! `CoreClient` recorded the blocker as *"`contracts/` defines no command or
//! event message"* — OQ-2 having deliberately excluded a `mgmt.proto` so the
//! management interface could not acquire a second vocabulary. That reasoning
//! was right when it was written and is no longer true of the code:
//!
//! * **Events** cross as a `twinvpn_mgmt::envelope::MgmtEnvelope` — the same
//!   length-prefixed JSON the Unix socket, the named pipe and XPC carry (M-1,
//!   MI-20). A Kotlin shell decodes JSON and links nothing.
//! * **Commands** cross the same way: `tw_core_submit` accepts an MI frame
//!   whose body is a `Request`, carrying the operation name and its encoded
//!   parameters, and still accepts a bare operation name.
//!
//! Neither needed a new contract message, which was OQ-2's whole objection.
//! Inventing an encoding here *would* have created the second vocabulary — so
//! this crate invents none: every byte it moves is produced or consumed by
//! `twinvpn-mgmt`.
//!
//! # Why this is a separate crate from `twinvpn-platform-android`
//!
//! CD-I5 forbids a `twinvpn-platform-*` crate to name `twinvpn-core`, and the
//! reason is the direction of the arrow: a platform implementation that could
//! reach the composition root would let a decision migrate downward into it.
//! `twinvpn-platform-android`'s own manifest records that its dev-dependency on
//! `twinvpn-core` was refused for exactly this. So the core's JNI entries live
//! here, in the shell, where naming both is what a shell is for.
//!
//! # CB-2, as a property of this file
//!
//! There is no branch here on a `ConnectionState`, a `reason_code` class, a
//! policy verdict or a candidate priority. A `ByteArray` becomes a `tw_slice`,
//! a `tw_buf` becomes a `ByteArray`, and a null handle becomes `null`. The one
//! judgement made anywhere below is *"the JVM asked for a buffer we could not
//! produce"*, and its answer is to return nothing rather than something.
//!
//! # PB-1
//!
//! **No packet crosses here.** `twinvpn.h` declares no per-packet entry point
//! and neither does this crate: the tunnel descriptor is detached once at
//! `establish()` and read directly by Rust thereafter — "one JNI call at setup,
//! then direct reads", zero crossings per packet.

#![forbid(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;

use twinvpn_ffi::abi::{TwBuf, TwSlice};
use twinvpn_ffi::vtable::TW_OK;
use twinvpn_ffi::{
    tw_abi_major, tw_buf_bytes, tw_buf_free, tw_core_create, tw_core_destroy, tw_core_next_event,
    tw_core_submit, tw_core_wake, TwCore,
};

/// Turns a core handle back into a pointer.
///
/// Zero is the "no instance" value the Kotlin side holds before `create` and
/// after `destroy`, and every entry below tolerates it — F-7's neighbour: a
/// stale handle must be a typed no-op, never a crash in someone's VPN app.
const fn as_core(handle: jlong) -> *mut TwCore {
    handle as *mut TwCore
}

/// Copies a `tw_buf`'s bytes into a fresh Java array and frees the buffer.
///
/// F-2: the buffer was allocated by the core, so the core's own `tw_buf_free`
/// releases it — no malloc/free pairing crosses the boundary, and none crosses
/// the JVM heap either. The bytes are copied first, because after the free the
/// core's memory is gone.
fn take_buf(env: &mut JNIEnv<'_>, buf: *mut TwBuf) -> jbyteArray {
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `buf` is non-null and was produced by this ABI, so it is a live
    // core-owned buffer that has not been freed. `tw_buf_bytes` borrows its
    // bytes for the duration of the call and they are copied out immediately,
    // before the free below.
    let slice = unsafe { tw_buf_bytes(buf.cast_const()) };
    // SAFETY: as above — the slice's pointer and length come from the core and
    // are valid until `tw_buf_free`.
    let bytes = unsafe { slice.as_bytes() }.to_vec();
    // SAFETY: live and not yet freed; freed exactly once, here.
    unsafe { tw_buf_free(buf) };

    env.byte_array_from_slice(&bytes)
        .map_or(std::ptr::null_mut(), jni::objects::JByteArray::into_raw)
}

/// `NativeBridge.nativeCoreCreate(config: ByteArray): Long`
///
/// Returns `0` on refusal, which the Kotlin side treats as a startup failure
/// rather than as a usable handle.
///
/// # A stated gap
///
/// The F-4 envelope naming *why* is freed here rather than returned, because a
/// `long` cannot carry it and this entry has no second out-parameter. The two
/// refusals `tw_core_create` can produce are `INTERNAL.ABI_VERSION_MISMATCH` (a
/// packaging defect — the `.so` and the app were built from different sources)
/// and `PLATFORM.ADAPTER_UNAVAILABLE`; both are fatal to the service either
/// way. Carrying the code would still be better than not, and it needs a
/// second entry point rather than a reinterpretation of this one's return.
///
/// # The host vtable is null, deliberately
///
/// On Android the adapter is linked in-process as a Rust crate
/// (`twinvpn-platform-android`), so the core reaches the platform directly
/// rather than back out through F-9. That is `ownership.md` §10.4's ruling, and
/// it is the same shape `shells/ios` uses.
///
/// # Safety
///
/// Called by the JVM with a valid environment. The returned handle must be
/// passed to `nativeCoreDestroy` exactly once and to no other entry after that.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCoreCreate(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    config: JByteArray<'_>,
) -> jlong {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = env.convert_byte_array(&config).unwrap_or_default();
        let mut error: *mut TwBuf = std::ptr::null_mut();
        let slice = TwSlice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        };
        // SAFETY: `slice` borrows `bytes`, which outlives the call; the vtable
        // is null, which `tw_core_create` checks before any read; `&raw mut
        // error` is a live writable slot.
        let core =
            unsafe { tw_core_create(tw_abi_major(), std::ptr::null(), slice, &raw mut error) };
        if !error.is_null() {
            // SAFETY: non-null and unfreed. The envelope is discarded on this
            // entry point by contract — see the doc comment.
            unsafe { tw_buf_free(error) };
        }
        core as jlong
    }))
    .unwrap_or(0)
}

/// `NativeBridge.nativeCoreDestroy(handle: Long)`. Idempotent on `0`.
///
/// **Does not tear down enforcement.** CB-6 puts the installed claim in the OS's
/// custody precisely so the core going away cannot drop protection; on Android
/// the `VpnService` claim dies with the process, which is the OS holding it, not
/// this call releasing it.
///
/// # Safety
///
/// `handle` is `0` or a value returned by `nativeCoreCreate` and not yet
/// destroyed.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCoreDestroy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    // SAFETY: the caller's contract. `tw_core_destroy` is itself idempotent on
    // null, so a `0` handle is a no-op rather than a check this file repeats.
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        tw_core_destroy(as_core(handle));
    }));
}

/// `NativeBridge.nativeCoreSubmit(handle: Long, command: ByteArray): ByteArray?`
///
/// Returns `null` on success and the **F-4 envelope** on refusal — bytes, never
/// a sentence. MI-15 and CB-4: the rendered text comes from the core's
/// catalogue through `tw_render_diagnostic`, never from a string in the shell.
///
/// `command` is one MI frame whose body is a `Request` (see `twinvpn.h`), so it
/// carries the operation **and its parameters**. `session.connect` needs a
/// 32-byte peer `device_id` and means nothing without it, which is why the
/// bare-name form this shell used to be limited to could not express it.
///
/// # Safety
///
/// Called by the JVM. `handle` is `0` or a live core.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCoreSubmit(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    command: JByteArray<'_>,
) -> jbyteArray {
    let mut env = env;
    catch_unwind(AssertUnwindSafe(|| {
        let bytes = env.convert_byte_array(&command).unwrap_or_default();
        let mut error: *mut TwBuf = std::ptr::null_mut();
        let slice = TwSlice {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
        };
        // SAFETY: `slice` borrows `bytes`, live for the call; a null or stale
        // handle is a typed refusal inside the ABI, not a dereference here.
        let rc = unsafe { tw_core_submit(as_core(handle), slice, &raw mut error) };
        if rc == TW_OK {
            if !error.is_null() {
                // SAFETY: non-null and unfreed.
                unsafe { tw_buf_free(error) };
            }
            return std::ptr::null_mut();
        }
        take_buf(&mut env, error)
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// `NativeBridge.nativeCoreNextEvent(handle: Long, timeoutMs: Int): ByteArray?`
///
/// **The only blocking call in this ABI.** Returns one MI frame, or `null` on a
/// timeout, a wake, or a refusal — the three are not distinguished here on
/// purpose: the core's own documentation says a caller tells them apart "by
/// asking again", and a Kotlin drain loop does exactly that.
///
/// F-6/S-47: exactly one thread may hold the instance for mutation at a time,
/// and the Kotlin side gives this its own thread.
///
/// # Safety
///
/// Called by the JVM. `handle` is `0` or a live core.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCoreNextEvent(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    timeout_ms: jint,
) -> jbyteArray {
    let mut env = env;
    catch_unwind(AssertUnwindSafe(|| {
        let mut event: *mut TwBuf = std::ptr::null_mut();
        let mut error: *mut TwBuf = std::ptr::null_mut();
        // A negative timeout from the JVM would become an enormous `u32`. It is
        // clamped to zero rather than wrapped: "poll once" is the honest
        // reading of a nonsensical deadline, and a 49-day block is not.
        let timeout = u32::try_from(timeout_ms).unwrap_or(0);
        // SAFETY: both out-parameters are live writable slots; a null or stale
        // handle is a typed refusal inside the ABI.
        let rc =
            unsafe { tw_core_next_event(as_core(handle), timeout, &raw mut event, &raw mut error) };
        if !error.is_null() {
            // SAFETY: non-null and unfreed. A failure on the drain path is
            // reported by the ABSENCE of an event; the envelope arrives on the
            // stream like everything else (F-5).
            unsafe { tw_buf_free(error) };
        }
        if rc != TW_OK {
            if !event.is_null() {
                // SAFETY: non-null and unfreed.
                unsafe { tw_buf_free(event) };
            }
            return std::ptr::null_mut();
        }
        take_buf(&mut env, event)
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// `NativeBridge.nativeCoreWake(handle: Long)`
///
/// Cancels an in-flight `nativeCoreNextEvent`. Callable from **any** thread,
/// which is what lets shutdown stop the drain loop rather than wait out its
/// timeout — and is why the drain thread is never killed.
///
/// # Safety
///
/// Called by the JVM. `handle` is `0` or a live core.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCoreWake(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    // SAFETY: the caller's contract; `tw_core_wake` tolerates null.
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        tw_core_wake(as_core(handle));
    }));
}

/// `NativeBridge.nativeRenderDiagnostic(reasonCode, evidence, locale, platformCtx): ByteArray?`
///
/// **F-10**, the one deliberate exception to F-1's small surface: the core owns
/// every rendered string, and a shell that composed one would be making exactly
/// the judgement CB-4 removes from it. The four slices are `twinvpn.h`'s, in its
/// order, and this crate reorders nothing.
///
/// # Safety
///
/// Called by the JVM with a valid environment.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeRenderDiagnostic(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    reason_code: JString<'_>,
    evidence: JByteArray<'_>,
    locale: JString<'_>,
    platform_ctx: JByteArray<'_>,
) -> jbyteArray {
    let mut env = env;
    catch_unwind(AssertUnwindSafe(|| {
        let code = env
            .get_string(&reason_code)
            .map_or_else(|_| Vec::new(), |s| String::from(s).into_bytes());
        let evidence_bytes = env.convert_byte_array(&evidence).unwrap_or_default();
        let tag = env
            .get_string(&locale)
            .map_or_else(|_| Vec::new(), |s| String::from(s).into_bytes());
        let platform_bytes = env.convert_byte_array(&platform_ctx).unwrap_or_default();

        let of = |v: &[u8]| TwSlice {
            ptr: v.as_ptr(),
            len: v.len(),
        };
        // SAFETY: every slice borrows a local that outlives the call, which is
        // `twinvpn.h`'s stated contract for these arguments.
        let rendered = unsafe {
            twinvpn_ffi::tw_render_diagnostic(
                of(&code),
                of(&evidence_bytes),
                of(&tag),
                of(&platform_bytes),
            )
        };
        // F-10 never returns null, but a buffer is a buffer: it is taken and
        // freed through the same path as every other core allocation (F-2).
        take_buf(&mut env, rendered)
    }))
    .unwrap_or(std::ptr::null_mut())
}
