//! `twinvpn-bridge` — the Swift ↔ Rust ABI of the macOS packet-tunnel system
//! extension.
//!
//! **Authority:** `shells/macos/twinvpn-bridge/include/twinvpn_bridge.h` (the
//! ABI of record for this boundary); ADR-0018 §11.4, §11.6, F-1, F-2, F-3, F-4,
//! F-6, F-7, CB-2, DP-4; ADR-0015 §11.2 and §6 rule 6;
//! `docs/implementation/ownership.md` §8 **W-24** and **W-25**.
//!
//! **Owner:** `desktop-macos`.
//!
//! # Why this crate exists beside `twinvpn.h`
//!
//! `core/ffi/include/twinvpn.h` is the shell↔core ABI, and `ownership.md` §8
//! records two findings against it: the F-9 vtable has **no socket capability
//! and no interface enumeration** (W-25), and it offers `set_ruleset` with **no
//! getter and no `current_generation`** (W-24). A Swift-only extension bound to
//! it could therefore do neither NAT traversal nor a `ProtectionAssertion` —
//! the two things a VPN datapath most needs.
//!
//! So the vtable, the marshalling and the object lifetimes live here, in Rust,
//! over `twinvpn-platform-macos`. The consequence that matters for review:
//! every line of it is type-checked by `make cross-check` for
//! `aarch64-apple-darwin` with `-D warnings`, and **executed** by `cargo test`
//! on the Linux host. It is not unverified Swift.
//!
//! # The shape of every entry point
//!
//! Each `extern "C"` function below is the same five steps and nothing else:
//!
//! 1. wrap the whole body in [`abi::contained`] — **F-7**, without exception;
//! 2. resolve the handle and the slices, turning a null into a typed error
//!    rather than a dereference;
//! 3. validate the correlation id **before** anything proportional to its
//!    length is allocated (§6 rule 9);
//! 4. call one method on [`ext::TvbExt`];
//! 5. write the out-parameters and return `TVB_OK` / `TVB_ERR` / `TVB_TIMEOUT`.
//!
//! There is no branch in this file whose condition is a TwinVPN domain fact
//! (CB-2). The three result codes say which *shape* an outcome took and never
//! what it means.
//!
//! # `unsafe`
//!
//! This is the one crate under `shells/` that cannot carry
//! `#![forbid(unsafe_code)]`: it **is** the FFI boundary. DP-4 permits `unsafe`
//! here, `#![deny(unsafe_op_in_unsafe_fn)]` is on, and every block carries a
//! `// SAFETY:` comment naming its invariant.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod abi;
pub mod config;
pub mod correlation;
pub mod envelope;
pub mod ext;
pub mod host;
pub mod log;
pub mod logging;
pub mod mgmt;
pub mod port;
pub mod probes;
pub mod report;
pub mod start;

use std::sync::Arc;
use std::time::Duration;

use twinvpn_types::codes;

use abi::{contained, ext_of, slice_of, slice_of_raw, write_out, TvbBuf, TvbSlice};
use correlation::CorrelationId;
use ext::{CoreHandle, TvbExt};
use mgmt::audit::AuditToken;
use mgmt::session::SessionHandle;
use report::{fail, fail_code, fail_panic, resolve};

/// `TVB_ABI_MAJOR`.
pub const TVB_ABI_MAJOR: u32 = 1;

/// `TVB_ABI_MINOR`.
pub const TVB_ABI_MINOR: u32 = 0;

/// `TVB_OK` — success; `*err` untouched.
pub const TVB_OK: i32 = 0;

/// `TVB_ERR` — failure; `*err` holds an ADR-0015 §11.2 envelope.
pub const TVB_ERR: i32 = 1;

/// `TVB_TIMEOUT` — nothing arrived. **Not a failure.**
pub const TVB_TIMEOUT: i32 = 2;

// ---------------------------------------------------------------------------
// Instance-free entry points
// ---------------------------------------------------------------------------

/// `uint32_t tvb_abi_major(void);`
#[no_mangle]
pub extern "C" fn tvb_abi_major() -> u32 {
    contained(|| TVB_ABI_MAJOR).unwrap_or(0)
}

/// `uint32_t tvb_abi_minor(void);`
#[no_mangle]
pub extern "C" fn tvb_abi_minor() -> u32 {
    contained(|| TVB_ABI_MINOR).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// `int32_t tvb_ext_start(tvb_slice, tvb_slice, tvb_ext **, tvb_buf **);`
///
/// # Safety
///
/// `config_json` and `correlation_id` are valid for the duration of the call;
/// `out` and `err` are null or writable.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_start(
    config_json: TvbSlice,
    correlation_id: TvbSlice,
    out: *mut *mut TvbExt,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_start";
    let result = contained(|| {
        // SAFETY: both slices obey the ABI contract by this function's own.
        let Some(config) = (unsafe { slice_of(config_json) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::PROTO_MALFORMED_MESSAGE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // SAFETY: as above.
        let Some(cid) = (unsafe { slice_of(correlation_id) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::PROTO_MALFORMED_MESSAGE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        let correlation = match CorrelationId::validated(cid) {
            Ok(correlation) => correlation,
            // SAFETY: `err`'s contract is unchanged.
            Err(diagnostic) => {
                return unsafe { fail(CALL, &diagnostic, &CorrelationId::absent(), err) }
            }
        };
        if out.is_null() {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe { fail_code(CALL, codes::INTERNAL_UNEXPECTED_STATE, &correlation, err) };
        }
        // The configuration document is OPAQUE here and is validated by the core
        // against `limits.json`, which is where those limits live. Its LENGTH is
        // logged; its bytes are not.
        log::counted(CALL, "config_bytes", config.len() as u64, &correlation);
        // The subscriber is installed here because THIS is the authority's
        // process entry point now: there is no `main` to do it in. Idempotent,
        // so a second `startTunnel` after a stop does not fight the first.
        logging::install_once();
        // **PS-22: the authority starts here.** `Host::start` runs §11.6's
        // sequence — boot artifact, privilege posture, clocks, the runtime's
        // I/O driver, the capability probe, the enforcement READ-BACK, the
        // vault, the core, the MI endpoint — and refuses by naming the step
        // that failed. PS-18: an extension that started without arming
        // enforcement would report itself as running while protecting nothing.
        let host = match host::Host::start(&config::ExtensionConfig::from_env()) {
            Ok(host) => Arc::new(host),
            Err(sequence) => {
                let code = sequence
                    .refusal()
                    .map_or(codes::INTERNAL_UNEXPECTED_STATE, |(_, code)| code);
                // SAFETY: `err`'s contract is unchanged.
                return unsafe { fail_code(CALL, code, &correlation, err) };
            }
        };
        for (step, code) in host.sequence().degradations() {
            // PS-17: a directive that cannot be applied is REPORTED, never
            // skipped. Silently running wider than declared is the defect that
            // rule retires.
            tracing::warn!(
                target: "twinvpn.agent",
                step = step.tag(),
                reason_code = code.as_str(),
                "a start-sequence step reported a degradation"
            );
        }
        let instance = Box::into_raw(Box::new(TvbExt::new(CoreHandle::Hosted(host))));
        // SAFETY: `out` is non-null by the branch above and writable by this
        // function's contract. Ownership of the instance passes to the caller,
        // who releases it with `tvb_ext_free`.
        unsafe { write_out(out, instance) };
        log::entered(CALL, &correlation);
        TVB_OK
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

/// `int32_t tvb_ext_stop(tvb_ext *, int32_t, tvb_slice, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_stop(
    ext: *mut TvbExt,
    reason: i32,
    correlation_id: TvbSlice,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_stop";
    let result = contained(|| {
        // SAFETY: the ABI contract, delegated.
        match unsafe { resolve(CALL, ext.cast_const(), correlation_id, err) } {
            Ok((instance, correlation)) => {
                instance.stop(reason, &correlation);
                TVB_OK
            }
            Err(code) => code,
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

/// `void tvb_ext_free(tvb_ext *);`
///
/// # Safety
///
/// `ext` is null, or a pointer from `tvb_ext_start` that has **not** been freed.
/// Freeing twice is undefined behaviour — which is why `CoreBridge.swift` calls
/// this from `deinit` and nowhere else.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_free(ext: *mut TvbExt) {
    let _ = contained(|| {
        if ext.is_null() {
            return;
        }
        // SAFETY: non-null by the branch above, and by this function's contract
        // it came from `Box::into_raw` in `tvb_ext_start` and has not been
        // released. Reboxing reclaims exactly that allocation.
        drop(unsafe { Box::from_raw(ext) });
    });
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// `int32_t tvb_ext_next_settings(tvb_ext *, uint32_t, tvb_buf **, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_next_settings(
    ext: *mut TvbExt,
    timeout_ms: u32,
    doc: *mut *mut TvbBuf,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_next_settings";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        match instance.next_settings(Duration::from_millis(u64::from(timeout_ms))) {
            Ok(Some(document)) => {
                // SAFETY: `doc` is null or writable by the ABI contract, and
                // ownership of the buffer passes to the caller.
                unsafe { write_out(doc, TvbBuf::into_raw(document)) };
                TVB_OK
            }
            Ok(None) => TVB_TIMEOUT,
            // SAFETY: `err`'s contract is unchanged.
            Err(diagnostic) => unsafe { fail(CALL, &diagnostic, &CorrelationId::absent(), err) },
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

// ---------------------------------------------------------------------------
// The packet path
// ---------------------------------------------------------------------------

/// `int32_t tvb_ext_inject_inbound(tvb_ext *, const uint8_t *, size_t, int32_t, tvb_buf **);`
///
/// # Safety
///
/// `pkt` is null with `len == 0`, or points to `len` valid bytes for the
/// duration of the call.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_inject_inbound(
    ext: *mut TvbExt,
    pkt: *const u8,
    len: usize,
    family: i32,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_inject_inbound";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // SAFETY: the `(ptr, len)` pair obeys the ABI contract by this
        // function's own, and `slice_of_raw` handles the `(NULL, 0)` shape.
        let Some(packet) = (unsafe { slice_of_raw(pkt, len) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::PROTO_MALFORMED_MESSAGE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        match instance.inject_inbound(packet, family) {
            Ok(()) => TVB_OK,
            // SAFETY: `err`'s contract is unchanged.
            Err(diagnostic) => unsafe { fail(CALL, &diagnostic, &CorrelationId::absent(), err) },
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

/// `int32_t tvb_ext_next_outbound(tvb_ext *, uint32_t, tvb_buf **, int32_t *, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_next_outbound(
    ext: *mut TvbExt,
    timeout_ms: u32,
    pkt: *mut *mut TvbBuf,
    family: *mut i32,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_next_outbound";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        match instance.next_outbound(Duration::from_millis(u64::from(timeout_ms))) {
            Ok(Some((packet, wire))) => {
                // The family is written FIRST, so a caller that reads it after a
                // successful return never sees a stale value beside a fresh
                // buffer.
                // SAFETY: `family` is null or writable by the ABI contract.
                unsafe { write_out(family, wire) };
                // SAFETY: `pkt` is null or writable; ownership passes out.
                unsafe { write_out(pkt, TvbBuf::into_raw(packet)) };
                TVB_OK
            }
            Ok(None) => TVB_TIMEOUT,
            // SAFETY: `err`'s contract is unchanged.
            Err(diagnostic) => unsafe { fail(CALL, &diagnostic, &CorrelationId::absent(), err) },
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

// ---------------------------------------------------------------------------
// Lifecycle facts
// ---------------------------------------------------------------------------

/// `int32_t tvb_ext_sleep(tvb_ext *, tvb_slice, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_sleep(
    ext: *mut TvbExt,
    correlation_id: TvbSlice,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_sleep";
    // SAFETY: delegated to `report`, whose contract is this one.
    unsafe { report(CALL, ext, correlation_id, err, TvbExt::report_sleep) }
}

/// `int32_t tvb_ext_wake(tvb_ext *, tvb_slice, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_wake(
    ext: *mut TvbExt,
    correlation_id: TvbSlice,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_wake";
    // SAFETY: delegated to `report`.
    unsafe { report(CALL, ext, correlation_id, err, TvbExt::report_wake) }
}

/// `int32_t tvb_ext_network_changed(tvb_ext *, tvb_slice, tvb_buf **);`
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_network_changed(
    ext: *mut TvbExt,
    correlation_id: TvbSlice,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_network_changed";
    // SAFETY: delegated to `report`.
    unsafe {
        report(
            CALL,
            ext,
            correlation_id,
            err,
            TvbExt::report_network_changed,
        )
    }
}

/// The shared shape of the three lifecycle-fact entries.
///
/// Each of them **reports** and returns; none asserts, renders or decides.
///
/// # Safety
///
/// As the ABI's own contract.
unsafe fn report(
    call: &'static str,
    ext: *mut TvbExt,
    correlation_id: TvbSlice,
    err: *mut *mut TvbBuf,
    body: fn(&TvbExt, &CorrelationId),
) -> i32 {
    let result = contained(|| {
        // SAFETY: the ABI contract, delegated.
        match unsafe { resolve(call, ext.cast_const(), correlation_id, err) } {
            Ok((instance, correlation)) => {
                body(instance, &correlation);
                TVB_OK
            }
            Err(code) => code,
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(call, err) })
}

// ---------------------------------------------------------------------------
// The management hop
// ---------------------------------------------------------------------------

/// `int32_t tvb_ext_app_message(tvb_ext *, tvb_slice, tvb_buf **, tvb_buf **);`
///
/// **Refuses, and the reason changed with X-7.** The MI now lives in this
/// process — served on the XPC Mach service by `tvb_mgmt_*` below and on the
/// `AF_UNIX` socket by the accept loop in [`host`]. What
/// `NETunnelProviderSession.sendProviderMessage` cannot supply is a **peer
/// credential**: there is no `audit_token_t` on this hop and no `xucred`, and
/// MI-A1 requires the calling principal to be obtained from the kernel on the
/// connected channel. MI-A5 makes an unverifiable identity a refusal rather than
/// a default principal, so the honest code is now
/// `MGMT.PRINCIPAL_UNVERIFIABLE` and not `MGMT.UNAVAILABLE` — the channel is
/// there; the caller cannot be named on it.
///
/// ADR-0017 §11.2 agrees by omission: the provider-message row is the *future-
/// compatible* App Store variant (C-13), not a Phase 1 macOS channel. The two
/// Phase 1 channels are the ones this file serves.
///
/// # Safety
///
/// As the ABI's own contract.
#[no_mangle]
pub unsafe extern "C" fn tvb_ext_app_message(
    ext: *mut TvbExt,
    req: TvbSlice,
    resp: *mut *mut TvbBuf,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_ext_app_message";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // SAFETY: the slice obeys the ABI contract by this function's own.
        let Some(request) = (unsafe { slice_of(req) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::PROTO_MALFORMED_MESSAGE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        let _ = (instance, resp);
        // The request's LENGTH, never its bytes: an MI envelope can carry a
        // `pairing_secret` (MI-P1), and §6 rule 11 forbids logging one.
        log::counted(
            CALL,
            "request_bytes",
            request.len() as u64,
            &CorrelationId::absent(),
        );
        // SAFETY: `err`'s contract is unchanged.
        unsafe {
            fail_code(
                CALL,
                codes::MGMT_PRINCIPAL_UNVERIFIABLE,
                &CorrelationId::absent(),
                err,
            )
        }
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

// ---------------------------------------------------------------------------
// The management interface - the XPC carriage (11.14 (a), PS-22)
// ---------------------------------------------------------------------------

/// `int32_t tvb_mgmt_open(tvb_ext *, tvb_slice, tvb_session **, tvb_buf **);`
///
/// Opens one management session for the process an `audit_token_t` names.
///
/// **Swift marshals; it decides nothing.** It accepts the `xpc_connection_t`,
/// copies the 32-byte token out of it with `xpc_connection_get_audit_token`, and
/// hands the bytes here. Everything that follows — decoding the token, deriving
/// the principal, deriving the scope set, checking the catalogue, reaching the
/// core — is Rust, and is tested on the Linux host.
///
/// **MI-A5**: a token that does not decode is a refusal, and there is no
/// constructor anywhere below that produces an anonymous principal.
///
/// # Safety
///
/// `audit_token` is valid for the duration of the call; `out` and `err` are null
/// or writable.
#[no_mangle]
pub unsafe extern "C" fn tvb_mgmt_open(
    ext: *mut TvbExt,
    audit_token: TvbSlice,
    out: *mut *mut SessionHandle,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_mgmt_open";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // The MI exists only while the authority does. An extension whose start
        // refused has no context, and `MGMT.UNAVAILABLE` is exactly the code
        // ADR-0017 11.12 has a client mint for "the channel is not there".
        if instance.mgmt_context().is_none() {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(CALL, codes::MGMT_UNAVAILABLE, &CorrelationId::absent(), err)
            };
        }
        // SAFETY: the slice obeys the ABI contract by this function's own.
        let Some(bytes) = (unsafe { slice_of(audit_token) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::MGMT_PRINCIPAL_UNVERIFIABLE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // Bounds before anything proportional to a declared length: the token is
        // a fixed 32 bytes and a buffer of any other size is refused rather than
        // read short.
        let Some(token) = AuditToken::from_bytes(bytes) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::MGMT_PRINCIPAL_UNVERIFIABLE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        if out.is_null() {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        }
        // **X-13.** ADR-0017 §11.2's macOS row gives this carriage "XPC audit
        // token -> `SecCodeCheckValidity` against a Team-ID-pinned code
        // requirement", and it was not done: the token was decoded, the
        // principal derived from it, and the client's *code signature* never
        // checked — so any local process whose euid/egid landed in a TwinVPN
        // group could attach, not only a Team-signed one.
        //
        // It is checked here, at attach, before a `SessionHandle` exists. MI-A5
        // is the rule for what happens when it fails: close, and never
        // substitute a default principal. `Unavailable` refuses with the rest,
        // because O-18 makes an assertion that cannot be made fail toward
        // UNKNOWN rather than toward trusted.
        let verdict = crate::mgmt::codesign::check(token, configured_team_id_pin().as_ref());
        if !verdict.admits() {
            log::counted(CALL, "codesign_refused", 1, &CorrelationId::absent());
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::MGMT_PRINCIPAL_UNVERIFIABLE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        }
        if verdict == crate::mgmt::codesign::Verdict::Unpinned {
            // Not a refusal: a development build has no Team ID and must stay
            // usable. But a SHIPPED build that reaches this has lost its pin,
            // which is a packaging defect, so it is reported every time rather
            // than being the quiet default.
            log::counted(CALL, "codesign_unpinned", 1, &CorrelationId::absent());
        }
        let session = Box::into_raw(Box::new(SessionHandle::new(token.principal())));
        // SAFETY: `out` is non-null by the branch above and writable by this
        // function's contract. Ownership passes to the caller, who releases it
        // with `tvb_mgmt_close`.
        unsafe { write_out(out, session) };
        log::counted(
            CALL,
            "peer_pid",
            u64::from(token.pid()),
            &CorrelationId::absent(),
        );
        TVB_OK
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

/// `int32_t tvb_mgmt_exchange(tvb_ext *, tvb_session *, tvb_slice, tvb_buf **, tvb_buf **);`
///
/// One framed `MgmtEnvelope` in, one framed `MgmtEnvelope` out.
///
/// **Always writes a response on `TVB_OK`**, including for a refusal: ADR-0017
/// 11.7 forbids a silent close, "because a silent close is indistinguishable
/// from the agent not running and sends the user to reinstall rather than to
/// update". `TVB_ERR` is reserved for the cases where there is no session and
/// therefore nothing that could have produced an envelope.
///
/// The bytes are **opaque to Swift** (MI-20): their schema lives in
/// `twinvpn-mgmt`, and a Swift copy of it would be the second contract.
///
/// # Safety
///
/// `session` came from `tvb_mgmt_open` and has not been closed; `req` is valid
/// for the duration of the call; `resp` and `err` are null or writable.
#[no_mangle]
pub unsafe extern "C" fn tvb_mgmt_exchange(
    ext: *mut TvbExt,
    session: *mut SessionHandle,
    req: TvbSlice,
    resp: *mut *mut TvbBuf,
    err: *mut *mut TvbBuf,
) -> i32 {
    const CALL: &str = "tvb_mgmt_exchange";
    let result = contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        let Some(instance) = (unsafe { ext_of(ext.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // SAFETY: as above.
        let Some(session) = (unsafe { ext_of(session.cast_const()) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::INTERNAL_UNEXPECTED_STATE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        let Some(context) = instance.mgmt_context() else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(CALL, codes::MGMT_UNAVAILABLE, &CorrelationId::absent(), err)
            };
        };
        // SAFETY: the slice obeys the ABI contract by this function's own.
        let Some(request) = (unsafe { slice_of(req) }) else {
            // SAFETY: `err`'s contract is unchanged.
            return unsafe {
                fail_code(
                    CALL,
                    codes::PROTO_MALFORMED_MESSAGE,
                    &CorrelationId::absent(),
                    err,
                )
            };
        };
        // The request's LENGTH, never its bytes: an MI envelope can carry a
        // `pairing_secret` (MI-P1), and 6 rule 11 forbids logging one.
        log::counted(
            CALL,
            "request_bytes",
            request.len() as u64,
            &CorrelationId::absent(),
        );
        let exchange = session.exchange(request, context);
        // SAFETY: `resp` is null or writable by the ABI contract, and ownership
        // of the buffer passes to the caller.
        unsafe { write_out(resp, TvbBuf::into_raw(exchange.reply)) };
        TVB_OK
    });
    // SAFETY: `err`'s contract is unchanged.
    result.unwrap_or_else(|| unsafe { fail_panic(CALL, err) })
}

/// `void tvb_mgmt_close(tvb_session *);`
///
/// Releases a session. Tolerates NULL.
///
/// **PS-3**: a client going away changes nothing. Closing a session drops a
/// scope set and a lock and touches no product state — not `session_intent`, not
/// the enforcement mode, not the installed rule set, not the `ConnectionState`.
///
/// # Safety
///
/// `session` is null, or a pointer from `tvb_mgmt_open` that has **not** been
/// closed. Closing twice is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn tvb_mgmt_close(session: *mut SessionHandle) {
    let _ = contained(|| {
        if session.is_null() {
            return;
        }
        // SAFETY: non-null by the branch above, and by this function's contract
        // it came from `Box::into_raw` in `tvb_mgmt_open` and has not been
        // released. Reboxing reclaims exactly that allocation.
        drop(unsafe { Box::from_raw(session) });
    });
}

// ---------------------------------------------------------------------------
// Buffers
// ---------------------------------------------------------------------------

/// `tvb_slice tvb_buf_bytes(const tvb_buf *);`
///
/// # Safety
///
/// `buf` is null, or a live buffer from this crate that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn tvb_buf_bytes(buf: *const TvbBuf) -> TvbSlice {
    contained(|| {
        // SAFETY: null is checked rather than dereferenced.
        match unsafe { ext_of(buf) } {
            Some(buffer) => TvbSlice::borrowing(buffer.bytes()),
            None => TvbSlice::empty(),
        }
    })
    .unwrap_or_else(TvbSlice::empty)
}

/// `void tvb_buf_free(tvb_buf *);`
///
/// # Safety
///
/// `buf` is null, or a buffer from this crate that has **not** been freed.
#[no_mangle]
pub unsafe extern "C" fn tvb_buf_free(buf: *mut TvbBuf) {
    let _ = contained(|| {
        // SAFETY: `TvbBuf::release` tolerates null and reclaims exactly the
        // allocation `into_raw` produced.
        unsafe { TvbBuf::release(buf) };
    });
}

#[cfg(test)]
mod tests;

/// The Team ID this build pins clients to, from `TWINVPN_MACOS_TEAM_ID` at
/// **compile** time.
///
/// # Why `option_env!` and not configuration
///
/// A code requirement is the thing that decides whether a stranger may attach,
/// so it must not be settable by anything the attacker could also set. A
/// runtime environment variable is readable and writable by whoever launched
/// the process; a build-time constant is fixed by whoever signed it, which is
/// the same authority the requirement is about. `packaging/SIGNING.md` is where
/// the value comes from.
///
/// `None` — an unsigned development build — produces
/// [`crate::mgmt::codesign::Verdict::Unpinned`], which admits and is reported
/// on every attach. That is deliberate: a build with no signing identity must
/// stay usable, and a SHIPPED build that reaches it has a packaging defect the
/// operator needs told about rather than a connection to drop silently.
fn configured_team_id_pin() -> Option<crate::mgmt::codesign::TeamIdPin> {
    option_env!("TWINVPN_MACOS_TEAM_ID").and_then(crate::mgmt::codesign::TeamIdPin::new)
}
