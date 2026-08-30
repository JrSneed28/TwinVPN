//! The `tw_host_vtable` entries this adapter can honestly back — **three**, and
//! the reason there are only three is the whole substance of this module.
//!
//! **Authority:** ADR-0018 §11.4 **F-9** (the host vtable), **F-8**, CB-2, CB-3,
//! DP-4, PB-1; `docs/implementation/ownership.md` §8 **W-7**, §10.4, §11.2
//! **G-11**; ADR-0022 LC-8, LC-24; `core/ffi/include/twinvpn.h`.
//!
//! # The defect this module closes
//!
//! `tw_core_create` refuses a null `tw_host_vtable` with
//! `PLATFORM.ADAPTER_UNAVAILABLE` — `twinvpn-ffi`'s own
//! `create_refuses_a_null_vtable_by_name` pins it. `shells/ios`'s
//! `CoreInstance.create()` passed `nil`, so the production
//! `NEPacketTunnelProvider` **could never create a core**: every start returned
//! a refusal envelope before a single command was submitted.
//!
//! The comment that justified the `nil` was right about the *internal* bridge
//! ([`crate::bridge`]) and wrong about `tw_core_create`, which has no in-process
//! path: the vtable is how the core is handed W-7's three capabilities, and
//! there is no target on which it may be absent.
//!
//! # Why exactly three entries, and why every other one stays NULL
//!
//! F-9 reads a NULL entry as **not attached**, never as a silent success, so a
//! partly-filled vtable is a declared posture rather than a hole. What this
//! crate may fill is decided by two rulings and one dependency fact:
//!
//! | Entry group | Filled here? | Why |
//! |---|---|---|
//! | `os_csprng`, `elapsed_millis`, `boot_id` | **yes** | W-7's three shell-supplied capabilities. Each carries a **byte buffer, a count and a `u64`** — no structured data, so F-8 has nothing to say about them, and [`crate::sys`] already implements all three against the Darwin primitives LC-8's table names. |
//! | sockets, interface enumeration | **never** | Not on this ABI at all. §11.2 **G-11**: a datagram is the datapath, PB-1 budgets **zero** FFI crossings per packet, and interface enumeration is blocked on F-8 because `contracts/` holds no message that can carry `InterfaceFacts`. Both stay in Rust, in-process, which is what this crate is. |
//! | `create_interface`, `apply`, `set_ruleset`, `identity_*`, `secure_item_*`, `store_root`, … | **not from here** | Every one carries **F-8 structured data** — a blob generated from an ADR-0003 contract artifact. This crate has no `twinvpn-schema` and no `prost` dependency and must not grow one: CD-I5 keeps the arrow pointing away from the core, and a platform adapter that could encode contract messages could hold a decision. The core reaches these through [`crate::IosPlatformAdapter`] in-process instead, over [`crate::bridge`]. |
//!
//! So the vtable `shells/ios` hands `tw_core_create` is **real** and **backed by
//! this crate**, and its remaining entries are absent for a ruled reason rather
//! than by omission. That is the same posture `ownership.md` §10.4 describes for
//! every mobile shell, stated at the one seam that previously had no statement
//! at all.
//!
//! # These are not new ABI
//!
//! **No F-9 entry is added, moved or removed by this module**, and `TW_ABI_MINOR`
//! does not move: `os_csprng`, `elapsed_millis` and `boot_id` have been in
//! `tw_host_vtable` since minor 0. What is new is an *implementation* of three
//! existing entries, exported over the **internal, versionless** bridge
//! §10.4 carves out (`shells/ios/Sources/TwinVPNBridge/include/twinvpn_ios_bridge.h`)
//! so Swift can install them without writing them.
//!
//! # Why Rust and not Swift
//!
//! Swift *could* fill these three — they carry no TwinVPN domain fact, so CB-2
//! permits it — and `TwinVPNIntegrationTests` did exactly that. It should not,
//! because LC-8 records the trap: **"Darwin's `CLOCK_MONOTONIC` is
//! suspend-inclusive, reverse of Linux's."** A wrong primitive here "compiles,
//! passes every test that does not suspend, and fails only on a device that
//! actually sleeps". Every Swift line in `shells/ios` is *written, not compiled*
//! on this host; every line below is checked for `aarch64-apple-ios` and
//! `aarch64-apple-ios-sim` and its refusal path is executed on Linux. Choosing
//! the tested half is `ownership.md` §10.3's design rule, not a preference.

use core::ffi::c_void;

use crate::sys;

/// `TW_OK` — success. Mirrors `twinvpn.h`.
///
/// A third copy of the value, and the drift it invites is named rather than
/// hidden: `twinvpn-ffi`'s `tests/header_matches_rust.rs` pins the header
/// against `twinvpn_ffi::vtable::TW_OK`, this crate cannot name that crate
/// (CD-I5), and the check that closes the loop is
/// `TwinVPNIntegrationTests` — a disagreement makes `tw_core_create` refuse and
/// the simulator suite goes red.
pub const TW_OK: i32 = 0;

/// `TW_ERR` — failure. Mirrors `twinvpn.h`. See [`TW_OK`] on the drift.
pub const TW_ERR: i32 = 1;

/// How many bytes [`twinvpn_ios_boot_id`] writes. `twinvpn.h`: `uint8_t out[16]`.
pub const BOOT_ID_LEN: usize = 16;

/// F-7's guard, on this side of the boundary.
///
/// An unwind out of an `extern "C"` function aborts the process, and an abort
/// inside a `NEPacketTunnelProvider` is a VPN that dropped. Nothing below can
/// panic today; the guard is here so that stays true of whatever is edited into
/// them later.
fn guarded(body: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(TW_ERR)
}

/// `tw_host_vtable::os_csprng`, backed by Darwin `getentropy(2)`.
///
/// CD-3 bans `getrandom` inside the core, so this is the only entropy source the
/// core has. It **never** falls back to a weaker one: [`crate::sys::fill_entropy`]
/// propagates the refusal, because "a silent downgrade here is indistinguishable
/// from working, and the value it produces is the one every nonce and key depends
/// on".
///
/// `ctx` is ignored. The capability is the platform's, not one provider
/// instance's, which is why this entry needs no registration and works before
/// `twinvpn_ios_bridge_register` has been called.
///
/// # Safety
///
/// `out` must be writable for `len` bytes, or `len` must be zero.
#[no_mangle]
pub unsafe extern "C" fn twinvpn_ios_os_csprng(_ctx: *mut c_void, out: *mut u8, len: usize) -> i32 {
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
        if sys::fill_entropy(dst).is_ok() {
            TW_OK
        } else {
            TW_ERR
        }
    })
}

/// `tw_host_vtable::elapsed_millis`, backed by Darwin `mach_continuous_time()`.
///
/// **Suspend-INCLUSIVE**, which is the whole point of the entry: `std` has no
/// such clock (W-7), and ADR-0022 LC-8 records that Darwin's `CLOCK_MONOTONIC`
/// is suspend-inclusive where Linux's is not — so a developer carrying the Linux
/// reasoning across picks the wrong primitive and the failure is invisible on a
/// host that never sleeps. [`crate::clock::ContinuousElapsedClock`] is the same
/// reading through the [`twinvpn_env::ElapsedClock`] trait.
///
/// # Safety
///
/// `out` must be a live, writable `uint64_t` slot.
#[no_mangle]
pub unsafe extern "C" fn twinvpn_ios_elapsed_millis(_ctx: *mut c_void, out: *mut u64) -> i32 {
    if out.is_null() {
        return TW_ERR;
    }
    guarded(|| match sys::continuous_micros() {
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

/// `tw_host_vtable::boot_id`, backed by `sysctl kern.boottime`.
///
/// W-7's third capability and LC-24 step 1's input: *"`boot_id` changed ⇒ **NOT**
/// a resume"*. The kernel's boot `timeval` pair is stable for the life of a boot
/// and differs across boots, which is exactly the contract; see
/// [`crate::clock::KernBootTimeId`] for why the raw bytes are the identity and
/// why hashing them is not available here.
///
/// Returns `TW_ERR` where the sysctl is unreachable, which `twinvpn.h` names as
/// the answer for a platform that has no boot identity. A fabricated sixteen
/// bytes would make "we rebooted" and "we did not" the same fact.
///
/// # Safety
///
/// `out` must be writable for [`BOOT_ID_LEN`] bytes.
#[no_mangle]
pub unsafe extern "C" fn twinvpn_ios_boot_id(_ctx: *mut c_void, out: *mut u8) -> i32 {
    if out.is_null() {
        return TW_ERR;
    }
    guarded(|| match sys::boot_time_raw() {
        Some(raw) => {
            // SAFETY: the caller's contract, restated above. `raw` is a local
            // `[u8; BOOT_ID_LEN]` and cannot overlap the caller's buffer.
            unsafe { core::ptr::copy_nonoverlapping(raw.as_ptr(), out, BOOT_ID_LEN) };
            TW_OK
        }
        None => TW_ERR,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing a Linux host can check about the constants.
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
        // SAFETY: null is checked before any write, which is what this asserts.
        unsafe {
            assert_eq!(
                twinvpn_ios_os_csprng(core::ptr::null_mut(), core::ptr::null_mut(), 8),
                TW_ERR
            );
            assert_eq!(
                twinvpn_ios_elapsed_millis(core::ptr::null_mut(), core::ptr::null_mut()),
                TW_ERR
            );
            assert_eq!(
                twinvpn_ios_boot_id(core::ptr::null_mut(), core::ptr::null_mut()),
                TW_ERR
            );
        }
    }

    /// A zero-length draw asks for nothing and gets it. Refusing would make the
    /// core's own "fill this empty buffer" path an entropy failure.
    #[test]
    fn a_zero_length_draw_succeeds_without_touching_the_pointer() {
        // SAFETY: `len` is zero, so the pointer is never read or written.
        let rc = unsafe { twinvpn_ios_os_csprng(core::ptr::null_mut(), core::ptr::null_mut(), 0) };
        assert_eq!(rc, TW_OK);
    }

    /// The build host has no Darwin primitives, and these entries say so rather
    /// than returning a stub. [`crate::clock`]'s tests assert the same absence
    /// for the same reason: a zero would make this file look tested and the
    /// product wrong on a device.
    #[cfg(not(target_os = "ios"))]
    #[test]
    fn the_entries_refuse_on_a_host_without_the_darwin_primitives() {
        let mut byte = 0u8;
        let mut millis = 0u64;
        let mut id = [0u8; BOOT_ID_LEN];
        // SAFETY: every out-parameter is a live local of the size the entry
        // documents.
        unsafe {
            assert_eq!(
                twinvpn_ios_os_csprng(core::ptr::null_mut(), core::ptr::addr_of_mut!(byte), 1),
                TW_ERR
            );
            assert_eq!(
                twinvpn_ios_elapsed_millis(core::ptr::null_mut(), core::ptr::addr_of_mut!(millis)),
                TW_ERR
            );
            assert_eq!(
                twinvpn_ios_boot_id(core::ptr::null_mut(), id.as_mut_ptr()),
                TW_ERR
            );
        }
        assert_eq!(millis, 0, "a refused reading must not be written");
        assert_eq!(
            id, [0u8; BOOT_ID_LEN],
            "a refused boot id must not be written"
        );
    }
}
