//! The MI envelope, **carried here and declared in `twinvpn-mgmt`**.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.2 (the Linux transport row), §11.3, MI-20; `ownership.md` §9.6 **X-4**.
//!
//! # This file used to be 562 lines, and that was the defect
//!
//! It carried the whole envelope — the types, the framing, the codec — and so
//! did `shells/windows`, byte for byte, and so did `shells/macos` in a **third
//! dialect** with a different `Diagnostic`, a `Compacted` that had lost
//! MI-19's `up_to_seq`, and a different `FrameError`. X-4:
//!
//! > The MI envelope is declared three times. It is in no contract, so each
//! > shell declares its own — MI-20's *"one contract, two carriages, never two
//! > contracts"* failing one level up, with three carriages.
//!
//! It now lives in [`twinvpn_mgmt::envelope`], which is where MI-20 puts a
//! vocabulary: above the composition root, shared by every carriage. This module
//! re-exports it so the transport code below reads unchanged, and holds
//! **nothing of its own**.
//!
//! # What stayed with this shell, and why
//!
//! The **transport**. §11.2 prefers `SOCK_SEQPACKET` "so message boundaries are
//! kernel-preserved: a length-prefix bug cannot desynchronize the stream", and
//! names "`SOCK_STREAM` + length prefix" as the fallback. This build takes the
//! fallback, for a stated reason: `tokio`'s `UnixListener` is `SOCK_STREAM`
//! only, and hand-rolling a `SOCK_SEQPACKET` listener would put an
//! `AsyncFd`-driven accept loop and a second `unsafe` surface in a crate that
//! carries `#![forbid(unsafe_code)]`. The cost is exactly the one §11.2 names,
//! and it is bounded by [`MAX_ENVELOPE_BYTES`] being enforced **before any
//! allocation** — in `twinvpn-mgmt` now, once, for all three shells.
//!
//! What a clean close means is also the transport's, and it genuinely differs:
//! this shell answers `Err(TransportError::Closed)` and `shells/macos` answers
//! `Ok(None)`. Both are defensible and neither is a judgement about bytes, which
//! is why the shared codec has no variant for it.

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
    /// no operation is a property of this crate and is asserted here.
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

    /// The envelope this shell serves is the shared one and not a copy.
    ///
    /// A `use` cannot drift, which is the whole point of the move — but the
    /// constants are what a reviewer checks first, so they are pinned to
    /// `twinvpn-mgmt`'s here rather than restated.
    #[test]
    fn the_framing_constants_are_the_shared_ones() {
        assert_eq!(MAX_ENVELOPE_BYTES, twinvpn_mgmt::MAX_ENVELOPE_BYTES);
        assert_eq!(LENGTH_PREFIX_BYTES, twinvpn_mgmt::LENGTH_PREFIX_BYTES);
        assert_eq!(MI_VERSION, twinvpn_mgmt::MI_VERSION);
        assert_eq!(MI_VERSION_MIN, twinvpn_mgmt::MI_VERSION_MIN);
    }
}
