//! `twinvpn-relay-client` — the **device leg** of the relay, and nothing else.
//!
//! **Authority:** ADR-0005 (the relay architecture), ADR-0006 (discovery and
//! failover), `docs/reliability.md` §8, ADR-0018 CB-2, CB-3, CD-I2, CD-I5, CD-4;
//! `contracts/docs/contract-matrix.md` §3.1;
//! `contracts/proto/twinvpn/v1/relay.proto` (frozen).
//!
//! **Owner:** `core-dataplane`.
//!
//! # The reservation is made with the relay, not through the control plane
//!
//! Contract matrix §3.1 and `relay.proto` both say it: "routing reservations
//! through coordination would put the control plane in the data path and **break
//! I5**." So [`bind::BindRequest`] is a C6 message and this crate names no
//! control-plane type at all — CD-I5's arrow, which `xtask lint` asserts.
//!
//! # The relay never learns which two devices are talking
//!
//! [`bind::BindRequest`] carries a `pair_tag` and **no peer identifier of any
//! kind**. `peer_key_id` was removed from the contract for exactly that reason
//! (A11, CF-7), and a test asserts the struct's whole field set so the field
//! cannot creep back.
//!
//! # Selection is a total ordering, never a filter
//!
//! ADR-0006 §11.3 rule 1: an `UNHEALTHY` `HealthState`, a "peer offline"
//! presence record, and any age of relay set are **score deltas only**.
//! [`select::Selection::order`] returns the whole admissible set, and the only
//! four permitted reductions — [`map::Excluded`] — are "local or structural facts
//! rather than `EVENTUAL` state".
//!
//! # Two random draws, both from named streams
//!
//! CD-4 puts the HRW hash on `relay/hrw` and the region-spread draw on
//! `relay/region-spread`. [`failover::region_move_timing`] and
//! [`failover::drain_offset`] take an `Env` and draw from
//! `twinvpn_env::consumers::RELAY_REGION_SPREAD`, "which is what makes a
//! herd-control decision testable at all".
//!
//! # No cryptography here (CD-I2)
//!
//! Two traits carry it: [`bind::RelayPairKeyed`] for the `pair_tag` and
//! `pair_id` derivations, and [`hrw::HrwHash`] for `BLAKE2s(relay_id ‖
//! pair_id)`. Both are `twinvpn-crypto`'s to implement.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]

pub mod bind;
pub mod codes;
pub mod failover;
pub mod frame;
pub mod hrw;
pub mod map;
pub mod select;
pub mod standby;

pub use bind::{BindRequest, BindResponse, Binding, RelayPairKeyed};
pub use failover::{Attribution, FleetExhausted, Observation, RegionMoveTiming};
pub use frame::{
    CounterWindow, FrameError, FrameType, InboundFrame, LegKey, LegSendCounter, OutboundFrame,
    Payload, VerifiedFrame,
};
pub use hrw::{HrwHash, Weight};
pub use map::{AdminState, Carriage, DeviceCapability, Excluded, HealthState, Relay, RelayMap};
pub use select::{Observations, Scored, Selection};
pub use standby::{Conditions, Posture, PowerPosture, Role};
