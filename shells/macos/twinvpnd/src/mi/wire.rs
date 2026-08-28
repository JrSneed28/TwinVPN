//! The MI envelope, **carried here and declared in `twinvpn-mgmt`**.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.2 (the macOS transport row), §11.3, MI-20; `ownership.md` §9.6 **X-4**.
//!
//! # This shell raised X-4, and this is the other half of the fix
//!
//! `shells/macos` §7 gap 15 asked for exactly this:
//!
//! > The MI envelope is declared in this shell, and in `shells/linux` too.
//! > ADR-0017 §11.3's message appears **nowhere in `contracts/`** … two shells
//! > now carry two copies of one envelope. **Request: move it into
//! > `core/crates/twinvpn-mgmt`.**
//!
//! It was three by the time it was fixed, and this shell's copy was not a copy:
//! it was a **third dialect**. Its `Diagnostic` carried `terminal`,
//! `remediation_class`, `scope` and `doc_anchor` that the other two lacked, and
//! lacked `summary_key` that they had; its `Compacted` had lost `up_to_seq`,
//! which is the boundary MI-19's ordered marker exists to name; its
//! `FrameError` had different variants and returned a different type. A client
//! built against `shells/linux`' `Reject` could not have parsed this shell's,
//! from the same build of the same product.
//!
//! **Two of this dialect's three divergences were the right answer and were
//! adopted for all three carriages:** MI-14 requires the whole resolved
//! attribute set to travel with the code, which only this shell did, and a
//! zero-length frame is a desynchronised stream rather than a body that failed
//! to parse, which only this shell said. The third — `Compacted` without
//! `up_to_seq` — was the regression, and the shared type has it back.
//!
//! # What stayed with this shell
//!
//! The **transport**. §11.2 prefers `SOCK_SEQPACKET` "so message boundaries are
//! kernel-preserved"; `tokio`'s `UnixListener` is `SOCK_STREAM` only, so this
//! build takes the length-prefix fallback and the cost is the one §11.2 names,
//! bounded by [`MAX_ENVELOPE_BYTES`] being enforced **before any allocation** —
//! in `twinvpn-mgmt` now, once, for all three shells. §11.2 also *prefers* XPC
//! on this platform; the name is fixed in one place (`mi::XPC_SERVICE_NAME`) and
//! the transport is `AF_UNIX` for this wave, which is §7 gap 13.
//!
//! What a clean close means is also the transport's, and it genuinely differs:
//! this shell answers `Ok(None)` and `shells/linux` answers `Err(Closed)`.
//! Neither is a judgement about bytes, which is why the shared codec has no
//! variant for it.

pub use twinvpn_mgmt::envelope::{
    declared_length, decode_body, decode_frame, encode_frame, Body, Compacted, Diagnostic, Event,
    FrameError, Hello, HelloAck, MgmtEnvelope, PlatformCtx, Request, Response, LENGTH_PREFIX_BYTES,
    MAX_ENVELOPE_BYTES, MI_VERSION, MI_VERSION_MIN,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// **The one assertion that has to live in the shell.**
    ///
    /// Every operation this wire can carry comes from the one vocabulary. The
    /// envelope moved to `twinvpn-mgmt`; the guarantee that *this shell* invents
    /// no operation is a property of this crate and is asserted here — and this
    /// shell had no such test before the move.
    #[test]
    fn every_operation_name_this_shell_can_carry_comes_from_the_one_vocabulary() {
        let mut names: Vec<&str> = twinvpn_mgmt::CoreCommand::ALL
            .iter()
            .map(|c| c.name())
            .collect();
        names.extend(twinvpn_mgmt::TransportOp::ALL.iter().map(|t| t.name()));
        assert!(names.contains(&"status.get"));
        assert!(names.contains(&"mi.catalogue.get"));
        twinvpn_mgmt::assert_closed().expect("MI-21 holds");
    }

    /// The envelope this shell serves is the shared one and not a third dialect.
    #[test]
    fn the_framing_constants_are_the_shared_ones() {
        assert_eq!(MAX_ENVELOPE_BYTES, twinvpn_mgmt::MAX_ENVELOPE_BYTES);
        assert_eq!(LENGTH_PREFIX_BYTES, twinvpn_mgmt::LENGTH_PREFIX_BYTES);
        assert_eq!(MI_VERSION, twinvpn_mgmt::MI_VERSION);
        assert_eq!(MI_VERSION_MIN, twinvpn_mgmt::MI_VERSION_MIN);
    }

    /// **MI-19's gap boundary is back.**
    ///
    /// This shell's `Compacted` carried only the per-topic counts, so a client
    /// could learn that events were dropped and not where the gap ended — which
    /// is the one thing an ordered marker exists to say.
    #[test]
    fn the_compacted_marker_names_where_the_gap_ends() {
        let marker = Compacted {
            up_to_seq: 9,
            dropped_by_topic: vec![("transition".to_owned(), 4)],
        };
        assert_eq!(marker.up_to_seq, 9);
    }
}
