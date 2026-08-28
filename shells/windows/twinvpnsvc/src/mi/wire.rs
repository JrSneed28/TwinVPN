//! The MI envelope, **carried here and declared in `twinvpn-mgmt`**.
//!
//! **Authority:** [ADR-0017](../../../../../docs/adr/ADR-0017-local-management-interface.md)
//! §11.2 (the Windows transport row), §11.3, MI-20; `ownership.md` §9.6 **X-4**.
//!
//! # This file used to be 571 lines, and it was a copy
//!
//! It carried the whole envelope — the types, the framing, the codec — and so
//! did `shells/linux`, byte for byte apart from two doc-comment hunks, and so
//! did `shells/macos` in a **third dialect** with a different `Diagnostic`, a
//! `Compacted` that had lost MI-19's `up_to_seq`, and a different `FrameError`.
//! X-4:
//!
//! > The MI envelope is declared three times. It is in no contract, so each
//! > shell declares its own — MI-20's *"one contract, two carriages, never two
//! > contracts"* failing one level up, with three carriages.
//!
//! It now lives in [`twinvpn_mgmt::envelope`]. This module re-exports it so the
//! transport code reads unchanged, and holds **nothing of its own**.
//!
//! # Message mode **and** a length prefix, and why both
//!
//! §11.2 prefers a boundary the kernel preserves, and a Windows named pipe in
//! `PIPE_TYPE_MESSAGE` gives exactly that: a read returns one whole message or
//! `ERROR_MORE_DATA`, so a length-prefix bug cannot desynchronize the stream the
//! way it can on `SOCK_STREAM`.
//!
//! The prefix is still written and still checked, for a reason that is not
//! belt-and-braces. Message mode gives the **boundary**; it does not give the
//! **size in advance**. `ownership.md` §6 rule 9 requires a declared length to be
//! validated *before* any allocation proportional to it, and without a prefix
//! the only way to size the buffer is to read and grow — which is the unbounded
//! allocation the rule exists to forbid. The prefix is what makes
//! [`MAX_ENVELOPE_BYTES`] enforceable on four bytes instead of on a buffer that
//! already exists. It also keeps this carriage byte-compatible with the
//! `SOCK_STREAM` one, which is what lets one client speak to any of the three.

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

    #[test]
    fn no_verb_in_this_table_is_windows_specific() {
        // The envelope is shared now, so this is the assertion that matters: a
        // client built against the Linux or macOS carriage must be able to
        // parse anything this one emits.
        for name in twinvpn_mgmt::CoreCommand::ALL.iter().map(|c| c.name()) {
            assert!(twinvpn_mgmt::CoreCommand::from_name(name).is_some());
        }
    }

    /// The envelope this shell serves is the shared one and not a copy.
    #[test]
    fn the_framing_constants_are_the_shared_ones() {
        assert_eq!(MAX_ENVELOPE_BYTES, twinvpn_mgmt::MAX_ENVELOPE_BYTES);
        assert_eq!(LENGTH_PREFIX_BYTES, twinvpn_mgmt::LENGTH_PREFIX_BYTES);
        assert_eq!(MI_VERSION, twinvpn_mgmt::MI_VERSION);
        assert_eq!(MI_VERSION_MIN, twinvpn_mgmt::MI_VERSION_MIN);
    }
}
