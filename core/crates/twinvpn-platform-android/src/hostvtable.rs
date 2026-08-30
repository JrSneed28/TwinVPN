//! The `tw_host_vtable` entries this adapter can honestly back — **three**, and
//! the reason there are only three is the whole substance of this module.
//!
//! **Authority:** ADR-0018 §11.4 **F-9** (the host vtable), **F-8**, CB-2, CB-3,
//! CD-3, DP-4, PB-1; `docs/implementation/ownership.md` §8 **W-7** and **W-36**,
//! §10.4, §11.2 **G-11**; ADR-0022 LC-8, LC-24; `core/ffi/include/twinvpn.h`.
//!
//! # The defect this module closes
//!
//! `tw_core_create` refuses a null `tw_host_vtable` with
//! `PLATFORM.ADAPTER_UNAVAILABLE` — `twinvpn-ffi`'s own
//! `create_refuses_a_null_vtable_by_name` pins it, and
//! `twinvpn_ffi::env::assemble` refuses again if `os_csprng` or `elapsed_millis`
//! is absent. `shells/android/jni`'s `nativeCoreCreate` passed **null**, so the
//! shipping `TwinVpnService` **could never create a core**: every start returned
//! a refusal envelope, which that entry point then freed, before a single
//! command was submitted.
//!
//! The comment that justified the null was right about the *internal* bridge
//! ([`crate::bridge`]) and wrong about `tw_core_create`, which has no in-process
//! path: the vtable is how the core is handed W-7's three capabilities, and
//! there is no target on which it may be absent. This is the identical defect
//! `shells/ios` carried, reported by that owner, and it is closed the same way.
//!
//! # Why exactly three entries, and why every other one stays NULL
//!
//! F-9 reads a NULL entry as **not attached**, never as a silent success, so a
//! partly-filled vtable is a declared posture rather than a hole. What this
//! crate may fill is decided by two rulings and one dependency fact, and all
//! three bind `twinvpn-platform-android` exactly as they bind
//! `twinvpn-platform-ios`:
//!
//! | Entry group | Filled here? | Why |
//! |---|---|---|
//! | `os_csprng`, `elapsed_millis`, `boot_id` | **yes** | W-7's three shell-supplied capabilities. Each carries a **byte buffer, a count and a `u64`** — no structured data, so F-8 has nothing to say about them, and [`crate::clock`] already implements all three against the Android primitives ADR-0022 LC-8's table names. |
//! | sockets, interface enumeration | **never** | Not on this ABI at all. §11.2 **G-11**: a datagram is the datapath, PB-1 budgets **zero** FFI crossings per packet, and interface enumeration is blocked on F-8 because `contracts/` holds no message that can carry `InterfaceFacts`. Both stay in Rust, in-process — [`crate::sock`] and [`crate::iface`], which is what `ownership.md` §10.4 rules for a mobile shell. |
//! | `create_interface`, `apply`, `set_ruleset`, `identity_*`, `secure_item_*`, `store_root`, … | **not from here** | Every one carries **F-8 structured data** — a blob generated from an ADR-0003 contract artifact. This crate's manifest carries **no `twinvpn-schema` and no `prost`**, and must not grow either: CD-I5 keeps the arrow pointing away from the core, and a platform adapter that could encode contract messages could hold a decision. |
//!
//! The dependency fact was **checked, not assumed**: this crate's `[dependencies]`
//! are `twinvpn-types`, `twinvpn-env`, `twinvpn-platform`, `thiserror`, `libc`,
//! `socket2`, `tokio`, `tracing`, `futures-core`, `serde_json` and `zeroize` —
//! the same shape as `twinvpn-platform-ios`, with no schema crate among them. So
//! the iOS owner's reasoning binds here unchanged, and the same three entries are
//! the honest maximum.
//!
//! # These are not new ABI
//!
//! **No F-9 entry is added, moved or removed by this module**, and `TW_ABI_MINOR`
//! does not move: `os_csprng`, `elapsed_millis` and `boot_id` have been in
//! `tw_host_vtable` since minor 0. What is new is an *implementation* of three
//! existing entries. `contracts/` and `twinvpn.h` are untouched.
//!
//! # Why these are NOT `#[no_mangle]`, where the iOS pair are
//!
//! The one place this module deliberately differs from
//! `twinvpn_platform_ios::hostvtable`, and the reason is the shell's language.
//!
//! On iOS the installer is **Swift**, so the entries must be reachable as C
//! symbols out of the one archive `shells/ios` links. On Android the installer
//! is **Rust** — `shells/android/jni` is itself a Rust crate — so it names these
//! functions directly and the compiler checks each one against the
//! `tw_host_vtable` field it is assigned to. An exported symbol would buy
//! nothing and cost something: `libtwinvpn_platform_android.so` and
//! `libtwinvpn_android_jni.so` are **two shared objects in one process**
//! (`build/ci/ci-android.sh` §1, CD-I5), and a `#[no_mangle]` here would be a
//! third name resolved by load order rather than by the type system.
//!
//! `extern "C"` is kept because F-9's fields are C function pointers; only the
//! symbol export is dropped.
//!
//!
//! # Why these are `pub` SAFE functions that take raw pointers
//!
//! `tw_host_vtable`'s three fields are `Option<extern "C" fn(…)>` — **safe** fn
//! pointers — so an `unsafe fn` does not coerce into one and could not be
//! installed at all. (`twinvpn_platform_ios::hostvtable` declares its pair
//! `unsafe`; that compiles only because Swift installs them through an untyped C
//! function pointer, and a Rust installer would not accept them. Reported.)
//!
//! `clippy::not_unsafe_ptr_arg_deref` is right in general and is suppressed per
//! function rather than per crate: a public safe function taking a raw pointer
//! IS a trap for a Rust caller, and the only thing that makes it acceptable here
//! is that the sole legitimate caller is the core across `twinvpn.h`, under a
//! contract each function restates and then **guards** — every entry checks its
//! out-parameter for null before any write, so the worst a broken caller gets is
//! `TW_ERR`.
//!
//! # Why Rust and not Kotlin
//!
//! Kotlin *could* not fill these at all — F-9 wants function pointers — but the
//! deeper reason is the same one ADR-0022 LC-8 gives for iOS, mirrored: the
//! suspend-inclusive clock is the one every platform gets backwards. On Android
//! it is **`CLOCK_BOOTTIME`**, not `CLOCK_MONOTONIC`, and
//! [`crate::clock::BootTimeElapsedClock`] carries that choice with a test that
//! reads both and asserts they are different clocks. This module adds a C
//! calling convention to that decision and **re-decides nothing**.

use core::ffi::c_void;

use twinvpn_env::{BootIdSource, Entropy};

use crate::clock::{BootTimeElapsedClock, DerivedBootId, SystemEntropy};

/// `TW_OK` — success. Mirrors `twinvpn.h`.
///
/// A second copy of the value, because CD-I5 forbids this crate to name
/// `twinvpn-ffi` (which names `twinvpn-core`). The drift that invites is
/// **closed rather than merely named**: `shells/android/jni` sees both this
/// constant and `twinvpn_ffi::vtable::TW_OK`, and pins them equal in a
/// `const _: () = assert!(…)` that fails the build rather than a test.
pub const TW_OK: i32 = 0;

/// `TW_ERR` — failure. Mirrors `twinvpn.h`. See [`TW_OK`] on the drift.
pub const TW_ERR: i32 = 1;

/// How many bytes [`boot_id`] writes. `twinvpn.h`: `uint8_t out[16]`.
pub const BOOT_ID_LEN: usize = 16;

/// F-7's guard, on this side of the boundary.
///
/// An unwind out of an `extern "C"` function aborts the process, and an abort
/// inside a `VpnService` is a VPN that dropped. Nothing below can panic today;
/// the guard is here so that stays true of whatever is edited into them later.
fn guarded(body: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(TW_ERR)
}

/// `tw_host_vtable::os_csprng`, backed by `/dev/urandom`.
///
/// CD-3 bans `getrandom` inside the core, so this is the only entropy source the
/// core has. It **never** falls back to a weaker one:
/// [`crate::clock::SystemEntropy`] propagates the refusal, because "a silent
/// downgrade here is indistinguishable from working, and its output is what
/// every nonce and key depends on". That module also records why the source is
/// `/dev/urandom` rather than `getrandom(2)`: bionic did not expose the syscall
/// until API 28 and `docs/networking.md` §5.2 sets the floor at API 26.
///
/// `ctx` is ignored. The capability is the platform's, not one service
/// instance's, which is why this entry answers before `NativeBridge`'s
/// `nativeCreate` has registered anything.
///
/// # The caller's contract
///
/// `out` must be writable for `len` bytes, or `len` must be zero. `twinvpn.h`
/// states it; Rust cannot mark it, because `tw_host_vtable::os_csprng` is a
/// **safe** `extern "C" fn` pointer and an `unsafe fn` does not coerce into one.
/// The null check below is what makes the unmarked contract survive a shell that
/// breaks it.
// F-9 declares this slot as a SAFE fn pointer, so this cannot be an
// `unsafe fn`. See the module note; the null guard below is the substitute.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn os_csprng(_ctx: *mut c_void, out: *mut u8, len: usize) -> i32 {
    if len == 0 {
        return TW_OK;
    }
    if out.is_null() {
        return TW_ERR;
    }
    guarded(|| {
        // SAFETY: the caller's contract, restated above — `out` is writable for
        // `len` bytes for the duration of this call, and the borrow ends with it.
        let dst = unsafe { core::slice::from_raw_parts_mut(out, len) };
        if SystemEntropy::new().fill(dst).is_ok() {
            TW_OK
        } else {
            TW_ERR
        }
    })
}

/// `tw_host_vtable::elapsed_millis`, backed by `clock_gettime(CLOCK_BOOTTIME)`.
///
/// **Suspend-INCLUSIVE**, which is the whole point of the entry: `std` has no
/// such clock (W-7). ADR-0022 LC-8's Android row names
/// `SystemClock.elapsedRealtime` / `CLOCK_BOOTTIME`, and
/// [`crate::clock::BootTimeElapsedClock`] is the same reading through the
/// [`twinvpn_env::ElapsedClock`] trait — so the JNI shell and the in-process
/// adapter cannot disagree about what time it is.
///
/// # The caller's contract
///
/// `out` must be a live, writable `uint64_t` slot. See [`os_csprng`] on why this
/// is prose rather than an `unsafe fn`.
// F-9 declares this slot as a SAFE fn pointer, so this cannot be an
// `unsafe fn`. See the module note; the null guard below is the substitute.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn elapsed_millis(_ctx: *mut c_void, out: *mut u64) -> i32 {
    if out.is_null() {
        return TW_ERR;
    }
    guarded(|| match BootTimeElapsedClock::read_micros() {
        Some(micros) => {
            // SAFETY: the caller's contract, restated above.
            unsafe { out.write(micros / 1_000) };
            TW_OK
        }
        // TW_ERR, never a fabricated reading: `twinvpn-ffi`'s `env::assemble`
        // REFUSES to build an `Env` without this entry rather than substituting
        // the monotonic clock, and a zero here would defeat that refusal.
        None => TW_ERR,
    })
}

/// `tw_host_vtable::boot_id`, backed by `/proc/sys/kernel/random/boot_id` and,
/// where SELinux hides it, by the wall time at which this boot began.
///
/// W-7's third capability and LC-24 step 1's input: *"`boot_id` changed ⇒ **NOT**
/// a resume"*. [`crate::clock::DerivedBootId`] holds both sources and reports
/// which one answered, so a device that denies `/proc` still produces an
/// identity that is stable within a boot and different across boots — the whole
/// contract — rather than a constant that would make "we rebooted" and "we did
/// not" the same fact.
///
/// Returns `TW_ERR` where neither source is reachable. A fabricated sixteen
/// bytes would be worse than the refusal.
///
/// # The caller's contract
///
/// `out` must be writable for [`BOOT_ID_LEN`] bytes. See [`os_csprng`] on why
/// this is prose rather than an `unsafe fn`.
// F-9 declares this slot as a SAFE fn pointer, so this cannot be an
// `unsafe fn`. See the module note; the null guard below is the substitute.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn boot_id(_ctx: *mut c_void, out: *mut u8) -> i32 {
    if out.is_null() {
        return TW_ERR;
    }
    guarded(|| match DerivedBootId::read() {
        Ok(source) => {
            let raw = *source.boot_id().as_bytes();
            // SAFETY: the caller's contract, restated above. `raw` is a local
            // `[u8; BOOT_ID_LEN]` and cannot overlap the caller's buffer.
            unsafe { core::ptr::copy_nonoverlapping(raw.as_ptr(), out, BOOT_ID_LEN) };
            TW_OK
        }
        Err(_) => TW_ERR,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants this module mirrors out of `twinvpn.h`.
    ///
    /// The *other* half of the drift check — that these agree with
    /// `twinvpn_ffi::vtable`'s copies — is in `shells/android/jni`, which is the
    /// only place that may name both crates.
    #[test]
    fn the_result_codes_mirror_twinvpn_h() {
        assert_eq!(TW_OK, 0, "twinvpn.h: #define TW_OK 0");
        assert_eq!(TW_ERR, 1, "twinvpn.h: #define TW_ERR 1");
        assert_eq!(
            BOOT_ID_LEN, 16,
            "twinvpn.h: int32_t (*boot_id)(void *, uint8_t[16])"
        );
    }

    /// F-9 gives these entries no error channel but the return value, so a null
    /// out-parameter must be a refusal rather than a store through null.
    #[test]
    fn every_entry_refuses_a_null_out_parameter() {
        // No `unsafe` block, and that is the point rather than an omission: the
        // entries are SAFE `extern "C" fn`s because `tw_host_vtable`'s fields
        // are, so the null handling below is the only thing standing between a
        // shell's mistake and a store through null.
        assert_eq!(
            os_csprng(core::ptr::null_mut(), core::ptr::null_mut(), 8),
            TW_ERR
        );
        assert_eq!(
            elapsed_millis(core::ptr::null_mut(), core::ptr::null_mut()),
            TW_ERR
        );
        assert_eq!(boot_id(core::ptr::null_mut(), core::ptr::null_mut()), TW_ERR);
    }

    /// A zero-length draw asks for nothing and gets it. Refusing would make the
    /// core's own "fill this empty buffer" path an entropy failure.
    #[test]
    fn a_zero_length_draw_succeeds_without_touching_the_pointer() {
        // `len` is zero, so the pointer is never read or written.
        let rc = os_csprng(core::ptr::null_mut(), core::ptr::null_mut(), 0);
        assert_eq!(rc, TW_OK);
    }

    /// The entries answer for real on this host, because every primitive behind
    /// them is a Linux one — which is the half `twinvpn-platform-ios` could only
    /// assert the *refusal* of.
    ///
    /// `ownership.md` §10.3's **executed** row: the bionic build and the host
    /// build read the same `CLOCK_BOOTTIME` and the same `/dev/urandom`, so a
    /// pass here is evidence about the shipped path rather than about a stub.
    #[test]
    fn the_entries_answer_on_a_linux_host_because_the_primitives_are_shared() {
        let mut millis = 0u64;
        let mut id = [0u8; BOOT_ID_LEN];
        let mut draw = [0u8; 32];
        // Every out-parameter is a live local of the size the entry documents,
        // which is exactly the contract the doc comments state.
        assert_eq!(
            os_csprng(core::ptr::null_mut(), draw.as_mut_ptr(), draw.len()),
            TW_OK
        );
        assert_eq!(
            elapsed_millis(core::ptr::null_mut(), std::ptr::addr_of_mut!(millis)),
            TW_OK
        );
        assert_eq!(boot_id(core::ptr::null_mut(), id.as_mut_ptr()), TW_OK);
        assert_ne!(draw, [0u8; 32], "the CSPRNG must not hand back zeroes");
        assert_ne!(id, [0u8; BOOT_ID_LEN], "a boot identity is never all-zero");
        // A machine that has been up for zero milliseconds cannot be running
        // this test, so a zero here would mean the reading was fabricated.
        assert!(millis > 0, "CLOCK_BOOTTIME must have advanced");
    }
}
