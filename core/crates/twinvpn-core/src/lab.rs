//! **A lab surface.** The establishment chain's entry points, re-exported for
//! `lab/twinpeer` under the `lab-peer` feature.
//!
//! **Authority:** ADR-0018 §11.12 ("`/lab/` TwinLab; never shipped");
//! `docs/testing-strategy.md` §3.1's REALIZATION PRINCIPLE — "every condition
//! TwinLab reproduces MUST be produced by a real mechanism, and a test MUST NOT
//! be able to detect that it is running in TwinLab by inspecting the system
//! under test".
//!
//! # Why this module exists
//!
//! The Windows kill-switch lane needs a *real* `Noise_IKpsk2` peer on the other
//! end of the tunnel: an oracle that observed traffic from a simulated overlay
//! would be measuring the simulation. The peer therefore has to run the same
//! handshake and the same pump the product runs, which means it has to be able
//! to call them.
//!
//! [`crate::datapath`] and [`crate::session_table`] are already public;
//! `crate::execute` is `pub(crate)` and stays that way. So this module is the
//! **one** place the lab surface is named, and the `lab-peer` feature is the one
//! switch that opens it. A reviewer asking "what can a lab binary reach inside
//! the composition root" reads this file and nothing else.
//!
//! # What is deliberately NOT here
//!
//! - **No parser for a datagram a peer sent.** A peer classifies an incoming
//!   datagram by its first octet against [`TYPE_HANDSHAKE_INITIATION`] and
//!   [`TYPE_TRANSPORT_DATA`]; the message bodies are parsed inside [`drive`] and
//!   the [`Pump`], where the bounds and the refusals already live.
//! - **No key material and no constructor for any.** [`TunnelKeying::new`] is
//!   already public and already takes a `VerifiedTunnelKey`, which has no public
//!   constructor — a lab peer builds one through `twinvpn-crypto`'s own
//!   `test-support` fixture, exactly as a test does, and nothing here weakens
//!   ADR-0007 N-4's gate.
//! - **No `Core`, no session table and no ports.** A lab peer drives one
//!   handshake and one pump. Giving it the composition root's state machine
//!   would make it a second client rather than a peer.

pub use crate::datapath::{
    race, Budget, Buffers, Cancel, Cancelled, Counters, DataHeader, Fault, Pump, PumpParts, Race,
    Raced, ReceiverIndex, Refused, Reject, Report, Step, Stop, DATAGRAM_CEILING, HEADER_BYTES,
    OVERHEAD_BYTES, OVERLAY_MTU_FLOOR, TAG_BYTES, TYPE_TRANSPORT_DATA,
};
pub use crate::enforce::MTU as OVERLAY_MTU;
pub use crate::establish::PROBE;
pub use crate::execute::handshake::{
    deadline_from, drive, encode_initiation, encode_response, ordered, role_for, Attempt,
    Handshaken, Refusal, INITIATION_PREFIX_BYTES, MAX_HANDSHAKE_DATAGRAM_BYTES,
    RESPONSE_PREFIX_BYTES, TYPE_HANDSHAKE_INITIATION, TYPE_HANDSHAKE_RESPONSE,
};
pub use crate::session_table::{session_id_for, TunnelKeying, STATIC_KEY_LEN};
pub use twinvpn_crypto::noise::Role;
