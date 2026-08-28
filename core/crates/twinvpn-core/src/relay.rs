//! The relay leg: `twinvpn-relay-client`'s decisions, given a socket to speak on.
//!
//! **Owner:** `core-composition`. Scaffolded by the integration lead; the
//! implementation is this module's own.
//!
//! **Authority:** ADR-0005 (relay architecture), ADR-0006 (discovery and
//! failover), `docs/reliability.md` §8.3; ADR-0018 CB-1 and CB-2;
//! `twinvpn_relay_client::{bind, frame, failover, select, standby}`.
