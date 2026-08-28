//! The C surface, exercised as C calls it.
//!
//! **Authority:** `docs/implementation/ownership.md` §6 rule 3 and rule 9;
//! ADR-0018 F-2, F-3, F-7.
//!
//! # Why these are unit tests and not integration tests
//!
//! Half of what is worth checking here needs a `*mut TvbExt` **and** the Rust
//! side of the same instance: the outbound packet path has no C producer, so a
//! test has to publish through [`crate::port::BridgePort`] and then read through
//! `tvb_ext_next_outbound`. An integration test sees only the public API and
//! could not hold both ends.
//!
//! Every test below calls the real `extern "C"` function through a raw pointer,
//! with the same null and empty shapes Swift produces.

use super::*;
use crate::ext::{FAMILY_V4, FAMILY_V6};
use crate::port::BridgePort;
use std::sync::Arc;
use twinvpn_platform_macos::utun::encode_frame;
use twinvpn_types::AddressFamily;

/// Reads an envelope out of an out-parameter and frees it, exactly once.
fn take_envelope(err: *mut TvbBuf) -> serde_json::Value {
    assert!(!err.is_null(), "a TVB_ERR must write an envelope");
    // SAFETY: `err` is non-null and came from `TvbBuf::into_raw` inside `fail`.
    let slice = unsafe { tvb_buf_bytes(err.cast_const()) };
    // SAFETY: the slice borrows the buffer, which is still live.
    let bytes = unsafe { slice_of(slice) }.expect("well formed").to_vec();
    // SAFETY: the only release of this buffer.
    unsafe { tvb_buf_free(err) };
    serde_json::from_slice(&bytes).expect("the envelope is JSON")
}

/// A live instance and the port the core would write to.
fn instance() -> (*mut TvbExt, Arc<BridgePort>) {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let port = ext.port();
    (Box::into_raw(Box::new(ext)), port)
}

/// Releases an instance built by [`instance`].
fn release(ext: *mut TvbExt) {
    // SAFETY: `ext` came from `Box::into_raw` and this is its only release.
    unsafe { tvb_ext_free(ext) };
}

fn packet(version: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 40];
    packet[0] = version << 4;
    packet[39] = 0xAB;
    packet
}

// ---------------------------------------------------------------------------
// The instance-free entries
// ---------------------------------------------------------------------------

#[test]
fn the_abi_version_is_what_the_header_declares() {
    // VR-4: a mismatch is a packaging defect, and `CoreBridge.assertABI()`
    // compares these against the header's `#define`s.
    assert_eq!(tvb_abi_major(), TVB_ABI_MAJOR);
    assert_eq!(tvb_abi_minor(), TVB_ABI_MINOR);
    assert_eq!(tvb_abi_major(), 1);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn a_start_yields_a_handle_the_caller_frees() {
    let config = br#"{"twinvpn":"config"}"#;
    let cid = b"A1B2C3D4-0000-0000-0000-0000000000FF";
    let mut handle: *mut TvbExt = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: both slices borrow live arrays; both out-parameters are live.
    let rc = unsafe {
        tvb_ext_start(
            TvbSlice::borrowing(config),
            TvbSlice::borrowing(cid),
            &raw mut handle,
            &raw mut err,
        )
    };
    assert_eq!(rc, TVB_OK);
    assert!(!handle.is_null());
    assert!(err.is_null(), "TVB_OK leaves *err untouched");
    release(handle);
}

#[test]
fn an_empty_config_is_accepted_because_swift_sends_a_null_base_for_one() {
    // `withUnsafeBufferPointer` on `[]` yields `(nil, 0)`. Dereferencing it is
    // UB, and refusing it would refuse a legitimate empty document.
    let mut handle: *mut TvbExt = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: both slices are the well-formed empty shape.
    let rc = unsafe {
        tvb_ext_start(
            TvbSlice::empty(),
            TvbSlice::empty(),
            &raw mut handle,
            &raw mut err,
        )
    };
    assert_eq!(rc, TVB_OK);
    release(handle);
}

#[test]
fn a_null_base_with_a_non_zero_length_is_refused_and_never_dereferenced() {
    let malformed = TvbSlice {
        ptr: core::ptr::null(),
        len: 32,
    };
    let mut handle: *mut TvbExt = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: the slice is malformed and the function checks it before any
    // dereference; that is precisely what is being tested.
    let rc = unsafe { tvb_ext_start(malformed, TvbSlice::empty(), &raw mut handle, &raw mut err) };
    assert_eq!(rc, TVB_ERR);
    assert!(handle.is_null(), "no handle is written on failure");
    assert_eq!(take_envelope(err)["reason_code"], "PROTO.MALFORMED_MESSAGE");
}

#[test]
fn an_over_long_correlation_id_is_refused_before_anything_is_allocated() {
    // §6 rule 9. The bound is checked against the borrowed slice, before the
    // copy — and the envelope names what was seen and what was allowed.
    let long = vec![b'x'; crate::correlation::MAX_CORRELATION_BYTES + 1];
    let mut handle: *mut TvbExt = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: both slices borrow live arrays.
    let rc = unsafe {
        tvb_ext_start(
            TvbSlice::empty(),
            TvbSlice::borrowing(&long),
            &raw mut handle,
            &raw mut err,
        )
    };
    assert_eq!(rc, TVB_ERR);
    assert!(handle.is_null());
    let envelope = take_envelope(err);
    assert_eq!(envelope["reason_code"], "PROTO.SIZE_EXCEEDED");
    assert_eq!(envelope["evidence"]["observed"], serde_json::json!(65));
    assert_eq!(envelope["evidence"]["limit"], serde_json::json!(64));
}

#[test]
fn a_start_with_a_null_out_parameter_is_a_typed_error() {
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `out` is null, which the function checks rather than writing
    // through.
    let rc = unsafe {
        tvb_ext_start(
            TvbSlice::empty(),
            TvbSlice::empty(),
            core::ptr::null_mut(),
            &raw mut err,
        )
    };
    assert_eq!(rc, TVB_ERR);
    assert_eq!(
        take_envelope(err)["reason_code"],
        "INTERNAL.UNEXPECTED_STATE"
    );
}

#[test]
fn a_null_handle_is_a_typed_error_on_every_entry_that_takes_one() {
    for rc in [
        // SAFETY: every call passes a null handle, which each function checks
        // rather than dereferencing. That is what is being tested.
        unsafe {
            tvb_ext_stop(
                core::ptr::null_mut(),
                0,
                TvbSlice::empty(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_sleep(
                core::ptr::null_mut(),
                TvbSlice::empty(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_wake(
                core::ptr::null_mut(),
                TvbSlice::empty(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_network_changed(
                core::ptr::null_mut(),
                TvbSlice::empty(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_next_settings(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_inject_inbound(
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                FAMILY_V4,
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_next_outbound(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
        unsafe {
            tvb_ext_app_message(
                core::ptr::null_mut(),
                TvbSlice::empty(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        },
    ] {
        assert_eq!(rc, TVB_ERR, "a null handle must be a typed error");
    }
}

#[test]
fn freeing_a_null_handle_is_a_no_op() {
    // SAFETY: null is explicitly tolerated.
    unsafe { tvb_ext_free(core::ptr::null_mut()) };
    // SAFETY: as above.
    unsafe { tvb_buf_free(core::ptr::null_mut()) };
}

#[test]
fn a_stop_reports_and_does_not_free() {
    // Rule 3 on the Swift side depends on this: `stop()` does not free, so a
    // double `stopTunnel` is not a use-after-free.
    let (ext, port) = instance();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `ext` is live; the slice is the empty shape.
    let rc = unsafe { tvb_ext_stop(ext, 3, TvbSlice::empty(), &raw mut err) };
    assert_eq!(rc, TVB_OK);
    assert!(err.is_null());
    assert!(port.is_closed());
    // A second stop is still safe — the handle is still valid.
    // SAFETY: `ext` is still live; `stop` did not free it.
    assert_eq!(
        unsafe { tvb_ext_stop(ext, 3, TvbSlice::empty(), &raw mut err) },
        TVB_OK
    );
    release(ext);
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[test]
fn settings_refuse_by_name_while_no_core_is_wired() {
    // The gap, as the tested path. `PacketTunnelProvider.startTunnel` completes
    // only once a settings document has arrived, so this refusal refuses the
    // start from the OS's point of view.
    let (ext, _port) = instance();
    let mut doc: *mut TvbBuf = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `ext` is live; both out-parameters are live.
    let rc = unsafe { tvb_ext_next_settings(ext, 5, &raw mut doc, &raw mut err) };
    assert_eq!(rc, TVB_ERR);
    assert!(doc.is_null(), "no document is written on failure");
    assert_eq!(
        take_envelope(err)["reason_code"],
        "PLATFORM.ADAPTER_UNAVAILABLE"
    );
    release(ext);
}

#[test]
fn a_published_settings_document_reaches_the_c_surface() {
    // The shape the wiring plugs into: the document is rendered by the adapter,
    // so Swift decides no family, no netmask and no match-domain set.
    let ext = TvbExt::new(CoreHandle::Unwired);
    ext.publish_settings(&twinvpn_platform_macos::testkit::contract(1), "203.0.113.7")
        .expect("renders");
    let raw = Box::into_raw(Box::new(ext));
    let mut doc: *mut TvbBuf = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `raw` is live; both out-parameters are live.
    let rc = unsafe { tvb_ext_next_settings(raw, 5, &raw mut doc, &raw mut err) };
    assert_eq!(rc, TVB_OK);
    assert!(err.is_null());
    let document = take_envelope(doc);
    assert_eq!(document["tunnel_remote_address"], "203.0.113.7");
    assert!(document["ipv6"].is_object(), "ADR-0010 R1: both, always");
    release(raw);
}

// ---------------------------------------------------------------------------
// The packet path
// ---------------------------------------------------------------------------

#[test]
fn a_packet_crosses_in_both_directions_and_in_both_families() {
    let (ext, port) = instance();
    for (family, version) in [(AddressFamily::V4, 4u8), (AddressFamily::V6, 6)] {
        let bytes = packet(version);
        let wire = crate::ext::wire_of_family(family);

        // Inbound: Swift -> core.
        let mut err: *mut TvbBuf = core::ptr::null_mut();
        // SAFETY: `ext` is live and `bytes` outlives the call.
        let rc =
            unsafe { tvb_ext_inject_inbound(ext, bytes.as_ptr(), bytes.len(), wire, &raw mut err) };
        assert_eq!(rc, TVB_OK);
        assert!(err.is_null());

        // Outbound: core -> Swift, published through the port the core writes to.
        let mut frame = Vec::new();
        encode_frame(family, &bytes, &mut frame);
        port.publish_outbound(frame);

        let mut pkt: *mut TvbBuf = core::ptr::null_mut();
        let mut got_family: i32 = 0;
        // SAFETY: `ext` is live; all three out-parameters are live.
        let rc = unsafe {
            tvb_ext_next_outbound(ext, 100, &raw mut pkt, &raw mut got_family, &raw mut err)
        };
        assert_eq!(rc, TVB_OK);
        assert_eq!(got_family, wire);
        assert!(!pkt.is_null());
        // SAFETY: `pkt` is a live buffer this call produced.
        let slice = unsafe { tvb_buf_bytes(pkt.cast_const()) };
        // SAFETY: the slice borrows a live buffer.
        let seen = unsafe { slice_of(slice) }.expect("well formed").to_vec();
        assert_eq!(seen, bytes);
        // SAFETY: the only release of this buffer.
        unsafe { tvb_buf_free(pkt) };
    }
    release(ext);
}

#[test]
fn an_empty_outbound_queue_is_a_timeout_and_not_a_failure() {
    // `PacketLoop.swift` calls this with a sub-second timeout in a loop, so
    // TVB_TIMEOUT is the ordinary case and reporting it as an error would make
    // an idle tunnel look like a failing one.
    let (ext, _port) = instance();
    let mut pkt: *mut TvbBuf = core::ptr::null_mut();
    let mut family: i32 = 0;
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `ext` is live; all out-parameters are live.
    let rc = unsafe { tvb_ext_next_outbound(ext, 5, &raw mut pkt, &raw mut family, &raw mut err) };
    assert_eq!(rc, TVB_TIMEOUT);
    assert!(
        pkt.is_null() && err.is_null(),
        "neither is written on a timeout"
    );
    release(ext);
}

#[test]
fn an_unknown_family_is_refused_rather_than_guessed() {
    // The family decides which 4-byte header the frame carries; a wrong one is a
    // frame the kernel drops with no diagnostic at all.
    let (ext, _port) = instance();
    let bytes = packet(4);
    for family in [0, 2, 10, 30, -1, FAMILY_V6 + 1] {
        let mut err: *mut TvbBuf = core::ptr::null_mut();
        // SAFETY: `ext` is live and `bytes` outlives the call.
        let rc = unsafe {
            tvb_ext_inject_inbound(ext, bytes.as_ptr(), bytes.len(), family, &raw mut err)
        };
        assert_eq!(rc, TVB_ERR, "family {family} must be refused");
        assert_eq!(take_envelope(err)["reason_code"], "PROTO.MALFORMED_MESSAGE");
    }
    release(ext);
}

#[test]
fn an_empty_packet_is_refused_at_this_hop_rather_than_one_hop_later() {
    let (ext, _port) = instance();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: the `(NULL, 0)` shape, which is well formed and not dereferenced.
    let rc = unsafe { tvb_ext_inject_inbound(ext, core::ptr::null(), 0, FAMILY_V4, &raw mut err) };
    assert_eq!(rc, TVB_ERR);
    let envelope = take_envelope(err);
    assert_eq!(envelope["reason_code"], "PROTO.MALFORMED_MESSAGE");
    assert_eq!(envelope["evidence"]["cap_violated"], "packet_len");
    release(ext);
}

// ---------------------------------------------------------------------------
// Lifecycle facts
// ---------------------------------------------------------------------------

#[test]
fn the_three_lifecycle_facts_report_and_return_ok() {
    let (ext, _port) = instance();
    let cid = b"A1B2C3D4-0000-0000-0000-0000000000FF";
    for rc in [
        // SAFETY: `ext` is live and `cid` outlives each call.
        unsafe { tvb_ext_sleep(ext, TvbSlice::borrowing(cid), core::ptr::null_mut()) },
        unsafe { tvb_ext_wake(ext, TvbSlice::borrowing(cid), core::ptr::null_mut()) },
        unsafe { tvb_ext_network_changed(ext, TvbSlice::borrowing(cid), core::ptr::null_mut()) },
    ] {
        assert_eq!(rc, TVB_OK);
    }
    release(ext);
}

// ---------------------------------------------------------------------------
// The management hop
// ---------------------------------------------------------------------------

#[test]
fn an_app_message_refuses_by_name_while_no_mi_is_wired() {
    // `MGMT.UNAVAILABLE`, whose registered condition is "the local management
    // interface is not reachable" — the truthful answer rather than an empty
    // success a client would read as a working but silent agent.
    let (ext, _port) = instance();
    let request = br#"{"kind":"hello"}"#;
    let mut resp: *mut TvbBuf = core::ptr::null_mut();
    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `ext` is live and `request` outlives the call.
    let rc = unsafe {
        tvb_ext_app_message(
            ext,
            TvbSlice::borrowing(request),
            &raw mut resp,
            &raw mut err,
        )
    };
    assert_eq!(rc, TVB_ERR);
    assert!(resp.is_null());
    assert_eq!(take_envelope(err)["reason_code"], "MGMT.UNAVAILABLE");
    release(ext);
}

// ---------------------------------------------------------------------------
// Buffers and containment
// ---------------------------------------------------------------------------

#[test]
fn buf_bytes_on_a_null_buffer_is_the_empty_slice_and_not_a_crash() {
    // A caller that forgot to check does not get undefined behaviour.
    // SAFETY: null is explicitly tolerated.
    let slice = unsafe { tvb_buf_bytes(core::ptr::null()) };
    assert!(slice.ptr.is_null());
    assert_eq!(slice.len, 0);
}

#[test]
fn a_caught_panic_becomes_tvb_err_with_the_registered_code() {
    // **F-7, end to end.** This is the exact composition every entry point uses
    // — `contained(...)` producing `None`, then `fail_panic` — with a closure
    // that panics for real. A panic unwinding past here would be undefined
    // behaviour in Swift; `INTERNAL.CORE_PANIC` is what the caller sees instead.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = contained(|| -> i32 { panic!("a deliberate defect at the boundary") });
    std::panic::set_hook(previous);

    let mut err: *mut TvbBuf = core::ptr::null_mut();
    // SAFETY: `err` is a live out-parameter.
    let rc = result.unwrap_or_else(|| unsafe { fail_panic("tvb_ext_stop", &raw mut err) });
    assert_eq!(rc, TVB_ERR);
    let envelope = take_envelope(err);
    assert_eq!(envelope["reason_code"], "INTERNAL.CORE_PANIC");
    // ADR-0015's own condition text: terminal for the core INSTANCE, and
    // enforcement stays installed.
    assert_eq!(envelope["class"], "FATAL");
    assert_eq!(envelope["terminal"], serde_json::json!(true));
}

#[test]
fn every_result_code_is_distinct_and_matches_the_header() {
    assert_eq!((TVB_OK, TVB_ERR, TVB_TIMEOUT), (0, 1, 2));
    assert_eq!((FAMILY_V4, FAMILY_V6), (4, 6));
}
