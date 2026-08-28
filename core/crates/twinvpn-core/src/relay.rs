//! The relay leg: `twinvpn-relay-client`'s decisions, given a socket to speak on.
//!
//! **Owner:** `core-composition`. Scaffolded by the integration lead; the
//! implementation is this module's own.
//!
//! **Authority:** ADR-0005 (relay architecture), ADR-0006 (discovery and
//! failover), `docs/reliability.md` §8.3; ADR-0018 CB-1 and CB-2;
//! `twinvpn_relay_client::{bind, frame, failover, select, standby}`.
//!
//! # The defect this module exists to close
//!
//! `twinvpn-relay-client` is complete and was **all decision and no I/O**.
//! `bind.rs` builds a `BindRequest`, `frame.rs` is the wire codec,
//! `failover.rs` attributes a failure and draws a drain offset, `select.rs` and
//! `hrw.rs` choose a relay, `standby.rs` decides whether to hold a warm
//! alternate. Every one of those was reachable from its own tests and from
//! nothing else: before this module,
//! `grep -rn "twinvpn_relay_client::" core/crates/twinvpn-core/src shells/ lab/`
//! matched nothing at all.
//!
//! So relay fallback — a named wave-1 requirement, and the whole answer to *the
//! direct path failed* — did not happen. The crate could rank every relay in a
//! verified map and could not put one byte on the wire to any of them. This
//! module is the byte.
//!
//! # What CB-1 assigns here rather than to either neighbour
//!
//! `twinvpn-relay-client` takes facts as parameters and decides; `twinvpn-platform`
//! is a seam with no decisions in it. Neither one can open a leg, because
//! opening a leg is *asking the platform a question and deciding what the
//! answer means* — the join CB-1 gives the core and CB-2 forbids a shell to
//! hold. `establish` is the same shape for the direct path; this is the shape
//! for the relayed one.
//!
//! # The map from this module to the frozen wire
//!
//! | Module | What it is |
//! |---|---|
//! | [`sealed`] | [`Sealed`], the payload this module **cannot open** — ADR-0001 I1 |
//! | [`codec`] | The control-frame bodies, matching `services/relay/src/{control,status}.rs` octet for octet |
//! | [`legsetup`] | The three leg-setup frames, which carry **no MAC** and are kept apart for that reason |
//! | [`leg`] | The `Noise_IK` leg handshake, `BIND`, and every frame the leg carries |
//! | [`outcome`] | Four refusals, four typed outcomes, four registered codes |
//! | [`drain`] | §8.3's herd-safe draw, and the bucket both peers compute alike |
//! | [`failover`] | §11.4 attribution, and promotion of the warm standby |
//! | [`transport`] | The only place that awaits a socket, and it decides nothing |
//!
//! # Both families, one code path (ADR-0010 R1)
//!
//! There is no v4 branch and no v6 branch anywhere below. A leg's family is
//! **derived from its endpoint** rather than chosen beside it, and reaches the
//! wire as one octet of one `BIND` body. `ownership.md` §4.2 records why the
//! objective's own `TVPN-IPV4-*` / `TVPN-IPV6-*` families were refused: a
//! per-family namespace makes "we have a v4 story and a v6 story" sayable, and
//! that is the exact asymmetry R1 exists to forbid.
//!
//! # Nothing here reads an ambient clock, an ambient RNG, or an environment
//!
//! CD-1, CD-2, CD-3. Every instant is [`twinvpn_env::MonotonicInstant`] from
//! the injected clock, the one random draw is
//! `twinvpn_relay_client::failover::drain_offset` on CD-4's
//! `relay/region-spread` stream, and the leg handshake's randomness is
//! `Env::entropy()` rather than `snow`'s `DefaultResolver`. There is no
//! `SystemTime::now`, no `Instant::now`, no `tokio::time`, no `getrandom` and
//! no thread-local RNG; `cargo run -p xtask -- lint` is what holds that.
//!
//! # Nothing here logs a token, a key, or a payload
//!
//! `ownership.md` §6 rule 11. [`Sealed`] and `LegKey` both print a length or a
//! redaction and never octets, [`leg::RelayLeg`]'s `Debug` names no key at all,
//! and the `TokenPresentation` this module builds is never rendered — it is
//! encoded into a `Noise_IK` payload and dropped.
//!
//! # Wiring is the integration lead's
//!
//! Every entry point takes its inputs as parameters: the socket, the `Env`, the
//! relay's endpoint and static key from a verified map, the device's `RLK`, the
//! token, the `pair_tag`. Nothing reaches into a `SessionEntry` and nothing
//! here is registered anywhere, so binding it to a session stays one
//! integration-owned edit.

pub mod codec;
pub mod drain;
pub mod failover;
pub mod leg;
pub mod legsetup;
pub mod outcome;
pub mod sealed;
pub mod transport;

pub use codec::{BindBody, BoundBody, BoundState, CapsBody, DrainBody, StatusBody};
pub use drain::{bucket_accepted, pair_tag_bucket, DrainNotice, MigrationSchedule};
pub use failover::{Failover, RelayPair};
pub use leg::{LegParams, LegStep, PendingLeg, RelayLeg};
pub use legsetup::{LegSetupType, TokenPresentation};
pub use outcome::{admissible, BindOutcome, Inbound, Refusal, RelayReject};
pub use sealed::Sealed;
pub use transport::{bind, open_leg, receive, send_sealed, LegError, MAX_RELAY_DATAGRAM_BYTES};
