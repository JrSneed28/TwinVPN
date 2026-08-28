//! `TvbExt`'s tests.
//!
//! Split out of `ext.rs` to keep both files under the 500-line rule in
//! `CLAUDE.md`. `#[path]` rather than a submodule directory, so the tests stay
//! `mod tests` inside `ext` and reach its private fields exactly as an inline
//! `#[cfg(test)]` block would.

use super::*;
use twinvpn_platform::InterfaceProvider;

#[test]
fn the_family_mapping_is_product_neutral_in_both_directions() {
    // 4 and 6, not 2 and 30. A constant whose value depends on which host
    // compiled it is a constant that is wrong in exactly the tests meant to
    // check it.
    assert_eq!(family_of_wire(4), Some(AddressFamily::V4));
    assert_eq!(family_of_wire(6), Some(AddressFamily::V6));
    assert_eq!(family_of_wire(2), None, "2 is AF_INET, not our v4 tag");
    assert_eq!(family_of_wire(30), None, "30 is Darwin's AF_INET6");
    assert_eq!(family_of_wire(10), None, "10 is Linux's AF_INET6");
    assert_eq!(wire_of_family(AddressFamily::V6), 6);
    assert_eq!(family_tag(AddressFamily::V4), "v4");
}

#[test]
fn an_unknown_family_is_refused_and_never_guessed() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let error = ext
        .inject_inbound(&[0x45, 0, 0, 0], 99)
        .expect_err("refused");
    assert_eq!(error.code().as_str(), "PROTO.MALFORMED_MESSAGE");
}

#[test]
fn a_packet_round_trips_through_the_port_in_both_families() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    for (family, version) in [(AddressFamily::V4, 0x45u8), (AddressFamily::V6, 0x60)] {
        let mut packet = vec![0u8; 40];
        packet[0] = version;
        packet[39] = 0xAB;
        // Inbound: Swift -> core.
        ext.inject_inbound(&packet, wire_of_family(family))
            .expect("accepted");
        // Outbound: core -> Swift. Published through the port the core would
        // write to.
        let mut frame = Vec::new();
        encode_frame(family, &packet, &mut frame);
        ext.port().publish_outbound(frame);
        let (out, wire) = ext
            .next_outbound(Duration::from_millis(50))
            .expect("no error")
            .expect("a packet");
        assert_eq!(wire, wire_of_family(family));
        assert_eq!(out, packet);
    }
}

#[test]
fn an_empty_outbound_queue_is_a_timeout_and_not_an_error() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    assert!(ext
        .next_outbound(Duration::from_millis(5))
        .expect("not an error")
        .is_none());
}

#[test]
fn a_frame_that_does_not_decode_is_reported_rather_than_handed_over() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    // Four bytes of header naming Linux's AF_INET6, which this decoder must
    // not accept as v6.
    ext.port().publish_outbound(vec![0, 0, 0, 10, 0x45]);
    let error = ext
        .next_outbound(Duration::from_millis(50))
        .expect_err("refused");
    assert_eq!(error.code().as_str(), "PROTO.MALFORMED_MESSAGE");
}

#[test]
fn settings_refuse_by_name_while_no_core_is_wired() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let error = ext
        .next_settings(Duration::from_millis(5))
        .expect_err("refused");
    assert_eq!(error.code().as_str(), "PLATFORM.ADAPTER_UNAVAILABLE");
}

#[test]
fn the_settings_channel_carries_a_document_the_core_computed() {
    // The shape the wiring plugs into. The document is the adapter's, so
    // both families are present and Swift decides nothing.
    let ext = TvbExt::new(CoreHandle::Unwired);
    let contract = twinvpn_platform_macos::testkit::contract(1);
    ext.publish_settings(&contract)
        .expect("renders");
    let bytes = ext
        .await_settings(Duration::from_millis(100))
        .expect("a document");
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    // M-15: the contract's own remote, not one this test handed the shell.
    assert_eq!(doc["tunnel_remote_address"], "198.51.100.7");
    assert!(doc["ipv4"].is_object());
    assert!(doc["ipv6"].is_object(), "ADR-0010 R1: both, always");
}

#[test]
fn a_resume_reports_the_gap_before_the_posture() {
    // ADR-0022: a resume must not render a confident, stale green.
    let ext = TvbExt::new(CoreHandle::Unwired);
    let mut stream = ext.interfaces().subscribe().expect("subscribes");
    let correlation = CorrelationId::validated(b"wake-1").expect("bounded");
    ext.report_sleep(&correlation);
    ext.report_wake(&correlation);
    let seen = drain(&mut stream, 4);
    assert_eq!(
        seen[0],
        NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: true,
        }
    );
    assert_eq!(seen[1], NetworkChange::EventsLost { count: None });
    // The seam gained `SystemResumed`, and the adapter emits it between the gap
    // and the posture. This bridge supplies no `ElapsedClock` reading, so
    // `suspended_for` is `None` — "we do not know how long", which the core
    // treats as exceeding the rekey window. That is the safe direction and it is
    // a REPORTED gap, not a design: measuring it needs `ContinuousElapsedClock`
    // wired into `TvbExt`, which is a Darwin-only reading this host cannot take.
    match seen[2] {
        NetworkChange::SystemResumed(facts) => {
            assert!(facts.announced_by_os, "IOKit told the provider");
            assert_eq!(facts.suspended_for, None);
        }
        ref other => panic!("expected a resume, got {other:?}"),
    }
    assert_eq!(
        seen[3],
        NetworkChange::LinkPostureChanged {
            metered: false,
            low_power: false,
        }
    );
}

#[test]
fn a_network_change_forces_a_re_enumeration() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    let mut stream = ext.interfaces().subscribe().expect("subscribes");
    ext.report_network_changed(&CorrelationId::absent());
    assert_eq!(
        drain(&mut stream, 1),
        vec![NetworkChange::EventsLost { count: None }]
    );
}

#[test]
fn a_stop_closes_the_datapath_and_holds_no_enforcement_to_release() {
    let ext = TvbExt::new(CoreHandle::Unwired);
    assert!(!ext.is_stopped());
    ext.stop(3, &CorrelationId::absent());
    assert!(ext.is_stopped());
    assert!(ext.port().is_closed());
    // CB-6, structurally: this type has no `NetworkConfig` field, so there is
    // no path from a stop to a pf anchor. The assertion is the type's shape,
    // and this line records that a reviewer checked it.
    let debug = format!("{ext:?}");
    assert!(!debug.contains("NetworkConfig"));
    assert!(!debug.contains("pf"));
}

/// Pulls `n` items off a change stream without an async runtime.
fn drain(
    stream: &mut std::pin::Pin<Box<dyn futures_core::Stream<Item = NetworkChange> + Send>>,
    n: usize,
) -> Vec<NetworkChange> {
    use futures_core::Stream;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    // SAFETY: every vtable entry is a no-op that ignores its data pointer, so
    // the null data pointer is never dereferenced.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut context = Context::from_waker(&waker);
    let mut out = Vec::new();
    for _ in 0..n {
        match Stream::poll_next(stream.as_mut(), &mut context) {
            Poll::Ready(Some(change)) => out.push(change),
            other => panic!("the change was already published: {other:?}"),
        }
    }
    out
}
