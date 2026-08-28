//! [`crate::oserr`]'s literals, checked against `windows-sys`.
//!
//! **Authority:** [`crate::oserr`]'s own module doc — "The literals are asserted
//! against `windows-sys`'s own constants in [`crate::sys::win`] under
//! `#[cfg(windows)]`, so a drifted value fails `make cross-check` rather than
//! silently mapping the wrong condition."
//!
//! # Why this file is nothing but assertions
//!
//! `oserr.rs` is target-free on purpose: it declares `ERROR_ACCESS_DENIED` as
//! `5` rather than importing it, so the whole `WIN32_ERROR` → `reason_code`
//! mapping compiles and its tests run on a Linux host. The cost of that choice
//! is a hand-copied number, and a hand-copied number is wrong eventually.
//!
//! These are `const` assertions. They are evaluated at **compile** time, so a
//! wrong literal is a build failure under `make cross-check` with nothing
//! running and nobody having to remember to check. That is the only kind of
//! verification available to a crate that cannot be executed on the host that
//! wrote it, and it is worth more here than anywhere else in the tree.
//!
//! # The sign trap, which is the whole reason for the `HRESULT` half
//!
//! `windows-sys` declares a `WIN32_ERROR` as `u32` and an `HRESULT` as `i32`.
//! `FWP_E_ALREADY_EXISTS` is `0x80320009`, which as an `i32` is
//! `-2144206839` — and [`crate::oserr::Win32Error`] exists precisely so that
//! number never reaches a support bundle in that form. The `HRESULT`
//! assertions below therefore go through
//! [`crate::oserr::Win32Error::from_i32`], which is the same conversion the
//! production path uses. An assertion that cast the other way would pass while
//! the mapping was broken.

#![allow(clippy::assertions_on_constants)]

use crate::oserr::{self, Win32Error};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ADAP_HDW_ERR, ERROR_ALREADY_EXISTS, ERROR_BAD_EXE_FORMAT,
    ERROR_BUSY, ERROR_CANCELLED, ERROR_DEV_NOT_EXIST, ERROR_ELEVATION_REQUIRED,
    ERROR_FILE_NOT_FOUND, ERROR_HOST_UNREACHABLE, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_FUNCTION, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING,
    ERROR_MOD_NOT_FOUND, ERROR_NETWORK_ACCESS_DENIED, ERROR_NETWORK_UNREACHABLE,
    ERROR_NOT_ALL_ASSIGNED, ERROR_NOT_ENOUGH_MEMORY, ERROR_NOT_FOUND, ERROR_NOT_READY,
    ERROR_NOT_SUPPORTED, ERROR_NO_NETWORK, ERROR_NO_SYSTEM_RESOURCES, ERROR_OBJECT_ALREADY_EXISTS,
    ERROR_OPERATION_ABORTED, ERROR_OUTOFMEMORY, ERROR_PATH_NOT_FOUND, ERROR_PRIVILEGE_NOT_HELD,
    ERROR_PROC_NOT_FOUND, ERROR_SEM_TIMEOUT, ERROR_SHARING_VIOLATION, ERROR_TIMEOUT,
};
use windows_sys::Win32::Networking::WinSock::{
    WSAEACCES, WSAEADDRINUSE, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAECONNRESET, WSAEHOSTUNREACH,
    WSAEINTR, WSAEINVAL, WSAEMFILE, WSAEMSGSIZE, WSAENETDOWN, WSAENETUNREACH, WSAENOBUFS,
    WSAENOPROTOOPT, WSAEOPNOTSUPP, WSAEPROTONOSUPPORT, WSAEWOULDBLOCK, WSASYSNOTREADY,
};

/// The plain `WIN32_ERROR` half. `windows-sys` types these `u32`, which is the
/// same type `oserr` declares, so the comparison is direct.
mod win32 {
    use super::{oserr, *};

    const _: () = assert!(oserr::ERROR_INVALID_FUNCTION == ERROR_INVALID_FUNCTION);
    const _: () = assert!(oserr::ERROR_FILE_NOT_FOUND == ERROR_FILE_NOT_FOUND);
    const _: () = assert!(oserr::ERROR_PATH_NOT_FOUND == ERROR_PATH_NOT_FOUND);
    const _: () = assert!(oserr::ERROR_ACCESS_DENIED == ERROR_ACCESS_DENIED);
    const _: () = assert!(oserr::ERROR_INVALID_HANDLE == ERROR_INVALID_HANDLE);
    const _: () = assert!(oserr::ERROR_NOT_ENOUGH_MEMORY == ERROR_NOT_ENOUGH_MEMORY);
    const _: () = assert!(oserr::ERROR_OUTOFMEMORY == ERROR_OUTOFMEMORY);
    const _: () = assert!(oserr::ERROR_NOT_READY == ERROR_NOT_READY);
    const _: () = assert!(oserr::ERROR_SHARING_VIOLATION == ERROR_SHARING_VIOLATION);
    const _: () = assert!(oserr::ERROR_NOT_SUPPORTED == ERROR_NOT_SUPPORTED);
    const _: () = assert!(oserr::ERROR_DEV_NOT_EXIST == ERROR_DEV_NOT_EXIST);
    const _: () = assert!(oserr::ERROR_ADAP_HDW_ERR == ERROR_ADAP_HDW_ERR);
    const _: () = assert!(oserr::ERROR_NETWORK_ACCESS_DENIED == ERROR_NETWORK_ACCESS_DENIED);
    const _: () = assert!(oserr::ERROR_INVALID_PARAMETER == ERROR_INVALID_PARAMETER);
    const _: () = assert!(oserr::ERROR_SEM_TIMEOUT == ERROR_SEM_TIMEOUT);
    const _: () = assert!(oserr::ERROR_INSUFFICIENT_BUFFER == ERROR_INSUFFICIENT_BUFFER);
    const _: () = assert!(oserr::ERROR_MOD_NOT_FOUND == ERROR_MOD_NOT_FOUND);
    const _: () = assert!(oserr::ERROR_PROC_NOT_FOUND == ERROR_PROC_NOT_FOUND);
    const _: () = assert!(oserr::ERROR_BUSY == ERROR_BUSY);
    const _: () = assert!(oserr::ERROR_ALREADY_EXISTS == ERROR_ALREADY_EXISTS);
    const _: () = assert!(oserr::ERROR_BAD_EXE_FORMAT == ERROR_BAD_EXE_FORMAT);
    const _: () = assert!(oserr::ERROR_ELEVATION_REQUIRED == ERROR_ELEVATION_REQUIRED);
    const _: () = assert!(oserr::ERROR_OPERATION_ABORTED == ERROR_OPERATION_ABORTED);
    const _: () = assert!(oserr::ERROR_IO_PENDING == ERROR_IO_PENDING);
    const _: () = assert!(oserr::ERROR_NOT_FOUND == ERROR_NOT_FOUND);
    const _: () = assert!(oserr::ERROR_NO_NETWORK == ERROR_NO_NETWORK);
    const _: () = assert!(oserr::ERROR_CANCELLED == ERROR_CANCELLED);
    const _: () = assert!(oserr::ERROR_NETWORK_UNREACHABLE == ERROR_NETWORK_UNREACHABLE);
    const _: () = assert!(oserr::ERROR_HOST_UNREACHABLE == ERROR_HOST_UNREACHABLE);
    const _: () = assert!(oserr::ERROR_NOT_ALL_ASSIGNED == ERROR_NOT_ALL_ASSIGNED);
    const _: () = assert!(oserr::ERROR_PRIVILEGE_NOT_HELD == ERROR_PRIVILEGE_NOT_HELD);
    const _: () = assert!(oserr::ERROR_NO_SYSTEM_RESOURCES == ERROR_NO_SYSTEM_RESOURCES);
    const _: () = assert!(oserr::ERROR_TIMEOUT == ERROR_TIMEOUT);
    const _: () = assert!(oserr::ERROR_OBJECT_ALREADY_EXISTS == ERROR_OBJECT_ALREADY_EXISTS);
}

/// The Winsock half.
///
/// `windows-sys` declares these as `i32` (`WSA_ERROR`), and every one of them is
/// a small positive number, so the widening is exact — but it is written out
/// rather than assumed, because "these happen to be positive" is the kind of
/// fact that stops being true when somebody adds a constant.
mod winsock {
    use super::{oserr, *};

    /// `WSA_ERROR` as `oserr` holds it. `as u32` on a value asserted positive.
    const fn as_u32(value: i32) -> u32 {
        assert!(value > 0, "a Winsock code this crate maps is not positive");
        #[allow(clippy::cast_sign_loss)]
        {
            value as u32
        }
    }

    const _: () = assert!(oserr::WSAEINTR == as_u32(WSAEINTR));
    const _: () = assert!(oserr::WSAEACCES == as_u32(WSAEACCES));
    const _: () = assert!(oserr::WSAEINVAL == as_u32(WSAEINVAL));
    const _: () = assert!(oserr::WSAEMFILE == as_u32(WSAEMFILE));
    const _: () = assert!(oserr::WSAEWOULDBLOCK == as_u32(WSAEWOULDBLOCK));
    const _: () = assert!(oserr::WSAEMSGSIZE == as_u32(WSAEMSGSIZE));
    const _: () = assert!(oserr::WSAENOPROTOOPT == as_u32(WSAENOPROTOOPT));
    const _: () = assert!(oserr::WSAEPROTONOSUPPORT == as_u32(WSAEPROTONOSUPPORT));
    const _: () = assert!(oserr::WSAEOPNOTSUPP == as_u32(WSAEOPNOTSUPP));
    const _: () = assert!(oserr::WSAEAFNOSUPPORT == as_u32(WSAEAFNOSUPPORT));
    const _: () = assert!(oserr::WSAEADDRINUSE == as_u32(WSAEADDRINUSE));
    const _: () = assert!(oserr::WSAEADDRNOTAVAIL == as_u32(WSAEADDRNOTAVAIL));
    const _: () = assert!(oserr::WSAENETDOWN == as_u32(WSAENETDOWN));
    const _: () = assert!(oserr::WSAENETUNREACH == as_u32(WSAENETUNREACH));
    const _: () = assert!(oserr::WSAECONNRESET == as_u32(WSAECONNRESET));
    const _: () = assert!(oserr::WSAENOBUFS == as_u32(WSAENOBUFS));
    const _: () = assert!(oserr::WSAEHOSTUNREACH == as_u32(WSAEHOSTUNREACH));
    const _: () = assert!(oserr::WSASYSNOTREADY == as_u32(WSASYSNOTREADY));
}

/// The `HRESULT` half: the WFP and CNG codes.
///
/// These are the ones the sign trap is about. Each goes through
/// [`Win32Error::from_i32`] — the **same** conversion the production path uses —
/// so an assertion cannot pass while the mapping is broken.
///
/// `windows-sys` 0.61 does not expose the `FWP_E_*` or `NTE_*` values as
/// constants at this feature set; they live in the Win32 metadata as HRESULTs
/// without a binding. So the assertions here check the two things that are
/// checkable without one: that the literal round-trips through the crate's own
/// signed conversion, and that its facility bits are the ones the mapping keys
/// on. **That is weaker than the `WIN32_ERROR` half, and it is stated rather
/// than left to be discovered** — see this domain's report.
mod hresult {
    use super::{oserr, Win32Error};

    /// The signed form of a `0x8xxxxxxx` literal.
    const fn signed(value: u32) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        {
            value as i32
        }
    }

    /// Every `FWP_E_*` and `NTE_*` literal survives the signed round trip.
    macro_rules! round_trips {
        ($($name:ident),* $(,)?) => {
            $(const _: () = assert!(
                Win32Error::from_i32(signed(oserr::$name)).get() == oserr::$name
            );)*
        };
    }

    round_trips!(
        FWP_E_FILTER_NOT_FOUND,
        FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND,
        FWP_E_NOT_FOUND,
        FWP_E_ALREADY_EXISTS,
        FWP_E_IN_USE,
        FWP_E_TXN_IN_PROGRESS,
        FWP_E_TXN_ABORTED,
        FWP_E_SESSION_ABORTED,
        FWP_E_TIMEOUT,
        NTE_NO_KEY,
        NTE_PERM,
        NTE_BAD_KEYSET,
        NTE_NOT_FOUND,
        NTE_DEVICE_NOT_READY,
    );

    /// Every `FWP_E_*` is in the filtering platform's facility, and every
    /// `NTE_*` is not.
    ///
    /// `Win32Error::is_fwp` is what `oserr` uses to tell them apart, and a
    /// literal typed into the wrong family would make a CNG failure map to a
    /// coexistence diagnosis.
    macro_rules! is_fwp {
        ($($name:ident),* $(,)?) => {
            $(const _: () = assert!(Win32Error(oserr::$name).is_fwp());)*
        };
    }
    macro_rules! is_not_fwp {
        ($($name:ident),* $(,)?) => {
            $(const _: () = assert!(!Win32Error(oserr::$name).is_fwp());)*
        };
    }

    is_fwp!(
        FWP_E_FILTER_NOT_FOUND,
        FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND,
        FWP_E_NOT_FOUND,
        FWP_E_ALREADY_EXISTS,
        FWP_E_IN_USE,
        FWP_E_TXN_IN_PROGRESS,
        FWP_E_TXN_ABORTED,
        FWP_E_SESSION_ABORTED,
        FWP_E_TIMEOUT,
    );
    is_not_fwp!(
        NTE_NO_KEY,
        NTE_PERM,
        NTE_BAD_KEYSET,
        NTE_NOT_FOUND,
        NTE_DEVICE_NOT_READY,
    );

    /// And every one of them is an `HRESULT` rather than a `WIN32_ERROR`, which
    /// is the distinction `oserr`'s three-number-space table turns on.
    const _: () = assert!(Win32Error(oserr::FWP_E_ALREADY_EXISTS).is_hresult());
    const _: () = assert!(Win32Error(oserr::NTE_BAD_KEYSET).is_hresult());
    const _: () = assert!(!Win32Error(oserr::ERROR_ACCESS_DENIED).is_hresult());
}

/// The WFP layer GUIDs `windows-sys` does expose, checked against the two this
/// crate installs into.
///
/// [`crate::wfp::Layer`] names them in prose; this is the check that the prose
/// and the metadata agree. A wrong layer GUID would install a perfectly valid
/// filter set at a layer that classifies something else entirely — which
/// compiles, installs, and protects nothing.
mod layers {
    use windows_sys::core::GUID;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };

    /// A `GUID` as the 128-bit value the metadata publishes.
    ///
    /// `windows_sys::core::GUID` derives neither `PartialEq` nor a `to_u128`, so
    /// the comparison is written out. Reconstructing the integer rather than
    /// comparing fields one at a time is deliberate: it is the form the ADR and
    /// the Microsoft documentation both print, so a reviewer can check the
    /// literal against either without transposing four fields by eye.
    const fn as_u128(g: GUID) -> u128 {
        ((g.data1 as u128) << 96)
            | ((g.data2 as u128) << 80)
            | ((g.data3 as u128) << 64)
            | (u64::from_be_bytes(g.data4) as u128)
    }

    const _: () = assert!(
        as_u128(FWPM_LAYER_ALE_AUTH_CONNECT_V4) == 0xc38d_57d1_05a7_4c33_904f_7fbc_eee6_0e82
    );
    const _: () = assert!(
        as_u128(FWPM_LAYER_ALE_AUTH_CONNECT_V6) == 0x4a72_393b_319f_44bc_84c3_ba54_dcb3_b6b4
    );
    const _: () =
        assert!(as_u128(FWPM_LAYER_ALE_AUTH_CONNECT_V4) != as_u128(FWPM_LAYER_ALE_AUTH_CONNECT_V6));
}
