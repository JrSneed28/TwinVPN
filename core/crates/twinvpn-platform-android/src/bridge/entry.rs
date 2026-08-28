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
//! Each takes an opaque handle plus Android facts, and returns `void` or
//! throws. There is no entry that takes a `ConnectionState`, a `reason_code`, a
//! policy verdict or a candidate priority, and
//! [`super::tests::the_bridge_speaks_android_and_never_twinvpn`] asserts it over
//! the surface's own source.
//!
//! # Why every body is wrapped in `catch_unwind`
//!
//! A Rust panic unwinding across an `extern "system"` frame into the JVM is
//! undefined behaviour, and ADR-0018 §11.3 requires `panic = "unwind"` in every
//! shipped profile so `abort` is not the answer either. Each body therefore
//! catches, and a caught panic becomes a thrown `IllegalStateException` — which
//! the Kotlin side surfaces as a `PLATFORM.*` diagnostic through the core,
//! never as a message it composed itself (CB-4).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use jni::objects::{JByteArray, JClass, JObject};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;

use twinvpn_platform::PlatformError;

use super::AndroidBridge;

/// The Java exception thrown for any refusal.
///
/// One class, because the *name* of what went wrong is the `reason_code` the
/// core emits, not the Java type. The Kotlin side never branches on this — it
/// reports the failure to the core and renders what the core resolves (CB-4).
const THROWABLE: &str = "java/lang/IllegalStateException";

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

/// Reports a refusal to the JVM.
///
/// The thrown message is the registered `reason_code`'s **spelling**, not a
/// sentence: CB-4 keeps every rendered string out of the core, and a support
/// case greps for the code.
fn throw(env: &mut JNIEnv<'_>, error: &PlatformError) {
    let _ = env.throw_new(THROWABLE, error.reason_code().as_str());
}

/// Wraps one entry body: catches a panic, and throws on either failure.
fn guard<F>(env: &mut JNIEnv<'_>, body: F)
where
    F: FnOnce() -> Result<(), PlatformError>,
{
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => throw(env, &error),
        Err(_) => {
            // A panic here is a defect. It is named as one rather than absorbed:
            // `INTERNAL.CORE_PANIC` is the code ADR-0018 F-7 uses for the same
            // condition across `twinvpn.h`.
            let _ = env.throw_new(
                THROWABLE,
                twinvpn_types::codes::INTERNAL_CORE_PANIC.as_str(),
            );
        }
    }
}

/// `onAvailable` / `onCapabilitiesChanged` / `onLinkPropertiesChanged`.
///
/// # Safety
///
/// `handle` must satisfy [`bridge`]'s contract.
#[no_mangle]
pub unsafe extern "system" fn Java_net_twinvpn_android_NativeBridge_nativeOnNetwork(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    payload: JByteArray<'_>,
) {
    let bytes = env.convert_byte_array(&payload).unwrap_or_default();
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard(&mut env, || {
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
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    network: jlong,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard(&mut env, || {
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
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    metered: jboolean,
    low_power: jboolean,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard(&mut env, || {
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
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard(&mut env, || {
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
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    reported: jint,
) {
    // SAFETY: the caller's contract, documented above.
    let held = unsafe { bridge(handle) };
    guard(&mut env, || {
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
