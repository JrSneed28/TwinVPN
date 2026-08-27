//! `twinlab` — namespace/veth topology, NAT classes, netem impairment and the seeded scenario runtime.
//!
//! **Owner:** `test-engineering`. Never shipped (ADR-0018 §11.12).
//!
//! docs/testing-strategy.md §3.1's realization principle is the constraint that
//! makes this crate hard: a condition must be produced by a real mechanism, and
//! the system under test must not be able to detect the lab.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
