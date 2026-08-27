//! `twinvpn-service-common` — shared server-side plumbing: config, health/readiness, OTel wiring, graceful shutdown, ErrorEnvelope mapping.
//!
//! **Owner:** `control-plane`.
//!
//! This crate exists so that the four server-side domains do not each invent
//! their own health endpoint, shutdown sequence, log format, OTel wiring and
//! error mapping — six divergent implementations of one decision is exactly the
//! R-31 defect class ADR-0018 CB-2 exists to prevent.
//!
//! Nothing is implemented yet. `control-plane` owns this crate; the other three
//! server domains consume it and file an issue rather than forking it.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
