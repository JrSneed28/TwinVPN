//! The `Java_net_twinvpn_android_NativeBridge_*` symbols.
//!
//! **Authority:** `docs/implementation/ownership.md` §10.4; ADR-0018 F-7 (panic
//! containment, applied here by analogy rather than by obligation — this is not
//! `twinvpn.h`, but a panic unwinding into the JVM is undefined behaviour and
//! the same `catch_unwind` closes it), CB-2.
//!
//! **`#[cfg(target_os = "android")]`. `cargo check`ed against the real `jni`
//! crate by `make cross-check`; never linked, never run.**
//!
//! # Five entry points, and their whole contract
//!
//! Each takes an opaque handle plus Android facts and returns `void`. There is
//! no entry that takes a `ConnectionState`, a `reason_code`, a policy verdict or
//! a candidate priority, and
//! [`super::tests::the_bridge_speaks_android_and_never_twinvpn`] asserts it over
//! the surface's own source.
//!
//! # Nothing here throws, and that is a correctness requirement
//!
//! **All five are platform callbacks**, and on four of them a Java exception is
//! process death. `Throw`/`ThrowNew` does not unwind the native frame — it sets
//! a pending exception on the current thread, which materialises in managed code
//! the instant the native method returns. What it returns *into* is:
//!
//! | Entry | Called from | Thread | A throw is |
//! |---|---|---|---|
//! | `Java_…_nativeOnNetwork` | `NetworkCallback.onAvailable` / `onCapabilitiesChanged` / `onLinkPropertiesChanged` | `ConnectivityThread` | **fatal** |
//! | `Java_…_nativeOnNetworkLost` | `NetworkCallback.onLost` | `ConnectivityThread` | **fatal** |
//! | `Java_…_nativeOnPower` | a `BroadcastReceiver` | main `Looper` | **fatal** |
//! | `Java_…_nativeOnLockdownReport` | `VpnService` startup | main `Looper` | **fatal** |
//! | `Java_…_nativeOnRevoked` | `VpnService.onRevoke()` | binder | survivable, and **silently discarded** |
//!
//! `ConnectivityManager.CallbackHandler.handleMessage` has no `try`/`catch`,
//! `Looper.loop` rethrows after notifying its observer, and `RuntimeInit`'s
//! process-wide `KillApplicationHandler` ends in `Process.killProcess` +
//! `System.exit(10)`. There is no thread on which throwing from here is
//! reportable: it either kills the process — taking the rest of a synchronous
//! callback fan-out with it — or is eaten by `Binder.execTransactInternal`.
//!
//! So a refusal is **logged with its `reason_code` and the entry returns**,
//! which is what every comparable Rust+JNI VPN core does. **CB-4 is unchanged**:
//! the code is still the whole of what this boundary says about a failure, and
//! it is still never a sentence this side composed. What changed is where it is
//! recorded — see `refused` below.
//!
//! # Why every body is still wrapped in `catch_unwind`
//!
//! A Rust panic unwinding across an `extern "system"` frame into the JVM is
//! undefined behaviour, and ADR-0018 §11.3 requires `panic = "unwind"` in every
//! shipped profile so `abort` is not the answer either. Each body therefore
//! catches, and a caught panic is recorded as `INTERNAL.CORE_PANIC` — the code
//! ADR-0018 F-7 uses for the same condition across `twinvpn.h`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

use twinvpn_platform::PlatformError;

use super::AndroidBridge;

/// Turns a bridge handle back into a reference.
///
/// # Safety
///
/// `handle` must be a value returned by the Rust-side composition root's
/// `Box::into_raw(Box::new(AndroidBridge))` and not yet freed. The Kotlin side
/// holds it as an opaque `long` and never constructs one.
unsafe fn bridge<'a>(handle: jlong) -> Option<&'a AndroidBridge> {
    if handle == 0 {
        return None;
    }
    // SAFETY: the caller's contract above. The pointer was produced by
    // `Box::into_raw` on an `AndroidBridge` that outlives every call, and the
    // reference does not escape the entry point that takes it.
    Some(unsafe { &*(handle as *const AndroidBridge) })
}

/// Records a refusal the JVM will never see.
///
/// The `reason_code`'s **spelling**, not a sentence: CB-4 keeps every rendered
/// string out of the core, and a support case greps for the code. It is the same
/// value that used to be the exception's message, recorded on the one path that
/// does not kill the process — the module documentation above is why.
///
/// The observation itself is dropped, and the log line says so. Android
/// re-delivers whole current state on the next callback, so a dropped
/// observation is a gap rather than a divergence: the next
/// `onLinkPropertiesChanged` carries the same picture again.
fn refused(entry: &'static str, reason_code: &str) {
    tracing::warn!(
        target: "twinvpn.platform.android.bridge",
        entry,
        reason_code,
        "an Android fact was refused at the bridge and the observation was dropped"
    );
    logcat_refusal(entry, reason_code);
}

/// The logcat tag for this bridge. **An interface, not a detail.**
///
/// `build/ci/ci-android.sh` greps `logcat.txt` for the marker below and fails
/// the run on it, so this string and the marker's shape are as load-bearing as
/// `TWINVPN_LIFECYCLE_TRANSITION` and must not drift. `TwinVPN.*` is the family
/// the instrumented suite already uses (`TwinVPN.CI`).
#[cfg(target_os = "android")]
const LOG_TAG: &[u8] = b"TwinVPN.Bridge\0";

/// What CI greps for, if the marker itself could not be built.
///
/// `CString::new` fails only on an interior NUL, which neither an entry name
/// (a literal in this file) nor a registered code can contain. The fallback
/// exists so this path is total rather than reaching for `unwrap`, and it is
/// shaped to match CI's pattern so the failure is still *seen* rather than
/// silently dropped — which is the whole point of the marker.
#[cfg(target_os = "android")]
const LOG_FALLBACK: &[u8] = b"TWINVPN_BRIDGE_REFUSED unknown INTERNAL.CORE_PANIC\0";

#[cfg(target_os = "android")]
#[link(name = "log")]
extern "C" {
    /// bionic's `liblog`. **Not in the `libc` crate** — `libc` 0.2.189 declares
    /// no `__android_log_*` symbol on any Android target — so it is declared
    /// here and `#[link(name = "log")]` supplies the `-llog` that resolves it.
    /// `liblog` is an NDK stable-ABI library present on every device.
    fn __android_log_write(
        prio: core::ffi::c_int,
        tag: *const core::ffi::c_char,
        text: *const core::ffi::c_char,
    ) -> core::ffi::c_int;
}

/// Writes one refusal to logcat, where CI and a support case can both see it.
///
/// `tracing` alone was not enough: no `tracing_subscriber` is installed anywhere
/// in `shells/android`, so the event had no sink and the `reason_code` went
/// nowhere. Losing it mattered more here than elsewhere — a *contained* refusal
/// is invisible to `NativeLinkRunTest`, which asserts lifecycle transitions and
/// nothing about network facts, so a run in which no observation ever reached
/// the core would still be green. `ci-android.sh` closes that by failing on this
/// line; this function is what there is to fail on.
///
/// The line is `TWINVPN_BRIDGE_REFUSED <entry> <REASON.CODE>` — a location and a
/// registered code, and nothing else. CB-4 is intact: no sentence, and nothing
/// this side composed.
#[cfg(target_os = "android")]
fn logcat_refusal(entry: &'static str, reason_code: &str) {
    /// `ANDROID_LOG_WARN`, from `<android/log.h>`'s `android_LogPriority`.
    const ANDROID_LOG_WARN: core::ffi::c_int = 5;

    // One bounded allocation: an entry name is a literal from this file and a
    // code is a registry row, so the line is tens of bytes and cannot be driven
    // by anything a caller supplies.
    let line = std::ffi::CString::new(format!("TWINVPN_BRIDGE_REFUSED {entry} {reason_code}"));
    let text = match &line {
        Ok(line) => line.as_ptr(),
        Err(_) => LOG_FALLBACK.as_ptr().cast(),
    };
    // SAFETY: both pointers are NUL-terminated C strings that outlive the call —
    // `LOG_TAG` and `LOG_FALLBACK` are `'static`, and `line` is held in this
    // frame until after it returns. `__android_log_write` copies what it reads,
    // takes no ownership, stores no pointer, and is safe on any thread.
    unsafe {
        __android_log_write(ANDROID_LOG_WARN, LOG_TAG.as_ptr().cast(), text);
    }
}

/// No logcat off-device. The host build keeps the `tracing` event and this
/// no-op, so `bridge::tests` still compiles and runs.
#[cfg(not(target_os = "android"))]
fn logcat_refusal(_entry: &'static str, _reason_code: &str) {}

/// Wraps one entry body: catches a panic, and records either failure.
fn guard<F>(entry: &'static str, body: F)
where
    F: FnOnce() -> Result<(), PlatformError>,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => refused(entry, error.reason_code().as_str()),
        // A panic here is a defect. It is named as one rather than absorbed:
        // `INTERNAL.CORE_PANIC` is the code ADR-0018 F-7 uses for the same
        // condition across `twinvpn.h`.
        Err(_) => refused(entry, twinvpn_types::codes::INTERNAL_CORE_PANIC.as_str()),
    }
}

/// `onAvailable` / `onCapabilitiesChanged` / `onLinkPropertiesChanged`.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnNetwork(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    payload: JByteArray<'_>,
) {
    let Ok(bytes) = env.convert_byte_array(&payload) else {
        // `GetArrayLength` leaves a PENDING exception, and a pending exception
        // is a real Java exception the instant this frame returns — which on
        // `ConnectivityThread` is the process death this module exists to
        // prevent. Clearing it is a no-op when none is pending.
        //
        // This used to be `unwrap_or_default()`, which decoded an empty payload
        // AND left the exception pending.
        let _ = env.exception_clear();
        refused(
            "nativeOnNetwork",
            PlatformError::AdapterUnavailable(None)
                .reason_code()
                .as_str(),
        );
        return;
    };
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard("nativeOnNetwork", || {
        held.ok_or(PlatformError::AdapterUnavailable(None))?
            .on_network(&bytes)
    });
}

/// `onLost(Network)`.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnNetworkLost(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network: jlong,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard("nativeOnNetworkLost", || {
        held.ok_or(PlatformError::AdapterUnavailable(None))?
            // Bit-preserving, not numeric: `networkHandle` is an opaque token
            // whose identity is all that matters, and it crossed as a signed
            // Java `long`.
            .on_network_lost(u64::from_ne_bytes(network.to_ne_bytes()))
    });
}

/// `PowerManager.isDeviceIdleMode()` / `isPowerSaveMode()` plus metering.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnPower(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    metered: jboolean,
    low_power: jboolean,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard("nativeOnPower", || {
        held.ok_or(PlatformError::AdapterUnavailable(None))?
            .on_power(metered != 0, low_power != 0)
    });
}

/// `VpnService.onRevoke()`.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnRevoked(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard("nativeOnRevoked", || {
        held.ok_or(PlatformError::AdapterUnavailable(None))?
            .on_revoked()
    });
}

/// What a DPC or managed configuration reported about lockdown.
///
/// `reported` is **three-valued** and is passed as an `int`: `-1` unknown, `0`
/// absent, `1` confirmed. A boolean would collapse LC-40's three values into
/// two and make "nobody told us" indistinguishable from "we were told it is
/// off" — which is the whole of the rule.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnLockdownReport(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    reported: jint,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard("nativeOnLockdownReport", || {
        let reported = match reported {
            0 => Some(false),
            1 => Some(true),
            // Anything else -- including a value this build does not know -- is
            // UNVERIFIED, which presents as unprotected. The fail-closed
            // direction, and the one an unexpected value must take.
            _ => None,
        };
        held.ok_or(PlatformError::AdapterUnavailable(None))?
            .on_lockdown_report(reported);
        Ok(())
    });
}

/// Registers the `NativeHost` instance and returns the bridge handle.
///
/// The returned `long` is opaque to Kotlin and is the only thing it holds. The
/// `JavaVM` and a global reference to `host` are captured here, so no JNI local
/// reference outlives the frame that made it.
///
/// Returns `0` if the environment could not be captured, which the Kotlin side
/// treats as a startup failure rather than as a usable handle.
///
/// # Safety
///
/// The returned handle must be passed to
/// `Java_net_twinvpn_android_NativeBridge_nativeDestroy` exactly once, and to no
/// other function after that.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeCreate(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    host: JObject<'_>,
    store_root: jni::objects::JString<'_>,
) -> jlong {
    let mut env = env;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let vm = Arc::new(env.get_java_vm().ok()?);
        let host = env.new_global_ref(host).ok()?;
        let root: String = env.get_string(&store_root).ok()?.into();
        let jvm = Arc::new(super::jvm::JvmHost::new(vm, host));
        let adapter = crate::AndroidPlatformAdapter::new(crate::AndroidAdapterParts {
            controller: jvm.clone(),
            element: jvm,
            store_root: std::path::PathBuf::from(root),
            vpn_config: crate::builder::VpnConfig::default(),
        });
        Some(Box::into_raw(Box::new(AndroidBridge::new(adapter))) as jlong)
    }));
    match outcome {
        Ok(Some(handle)) => handle,
        _ => 0,
    }
}

/// Releases the bridge.
///
/// # Safety
///
/// `handle` must be a value returned by `nativeCreate` and not yet destroyed.
/// After this call it must not be passed to any other function.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeDestroy(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: the caller's contract above. The pointer came from
    // `Box::into_raw` in `nativeCreate` and is reclaimed exactly once here.
    //
    // Dropping the bridge does NOT tear down enforcement: CB-6 puts the claim in
    // the OS's custody, and on Android the claim dies with the process anyway.
    // Nothing on this path touches the descriptor or the disposition.
    drop(unsafe { Box::from_raw(handle as *mut AndroidBridge) });
}
