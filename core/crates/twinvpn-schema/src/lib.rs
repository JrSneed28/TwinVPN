//! `twinvpn-schema` — the frozen contract bindings, plus validation of untrusted
//! input.
//!
//! **Authority:** ADR-0018 §11.12 (`/contracts` is the single source and
//! `/contracts/gen/**` is committed and CI-verified), ADR-0003 §11 (the envelope
//! caps and depth limits), `contracts/registry/limits.json`,
//! `docs/implementation/ownership.md` §6 rules 9 and 10.
//!
//! **Owner:** `core-foundation`.
//!
//! # The bindings are included, never copied
//!
//! [`v1`] `include!`s `contracts/gen/rust/src/twinvpn.v1.rs` **from the frozen
//! source tree**. Copying it into this crate would create a second copy that CI's
//! regenerate-and-diff check does not cover, and §11.12's whole point is that "a
//! schema change that a language binding cannot express fails at merge rather
//! than at integration". A build script `rerun-if-changed` on the generated file
//! makes a change to it rebuild this crate.
//!
//! `contracts/gen/rust/mod.rs` is deliberately **not** used: its `include!` path
//! assumes it sits in `src/`, so it only resolves inside a crate laid out the way
//! the `prost-crate` plugin expects. Including the generated file directly is
//! both simpler and one fewer thing to keep in step.
//!
//! # Validation
//!
//! Everything arriving on a wire goes through [`validate::decode`], which applies
//! the byte cap and the depth cap **to the raw bytes** before `prost` allocates or
//! recurses, and then through the per-field validators in [`validate`]. Every
//! violation is a typed [`reject::Reject`] carrying a `PROTO.*` code — never a
//! truncation, never a pad, never a silent accept.
//!
//! # Unknown fields are NOT preserved
//!
//! **A finding, not a design choice.** `prost` 0.13 discards unknown fields on
//! decode and cannot re-emit them, and
//! `contracts/docs/phase1-conflicts.md` CF-2 records the measured constraint:
//!
//! > "ADR-0003 §11 B1 requires unknown fields to be **preserved and forwarded**
//! > … Any language chosen for a component that *forwards* a message it does not
//! > fully understand — the coordination service, the rendezvous, a relay
//! > carrying an opaque `CALL` — must use a runtime with preserve-and-forward."
//!
//! `unknown_fields_are_dropped_by_prost_0_13` measures it here rather than
//! leaving it to be discovered. **The consequence for the services:** a
//! forwarding component must not decode-then-re-encode a message it does not
//! fully understand; it must forward the **received octets verbatim**. That is
//! already the required behaviour for `Auth.signed_payload`, which "MUST verify
//! over the exact received octets … and MUST NOT re-serialize", so the pattern
//! exists — it now has to cover forwarding generally. Reported to the integration
//! lead.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod depth;
pub mod envelope;
pub mod limits;
pub mod reject;
pub mod validate;

/// The generated `twinvpn.v1` bindings, included from the frozen source.
///
/// The lint allowances are for generated code and apply to nothing hand-written.
#[allow(
    clippy::all,
    clippy::pedantic,
    missing_docs,
    non_camel_case_types,
    clippy::doc_lazy_continuation
)]
pub mod v1 {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/gen/rust/src/twinvpn.v1.rs"
    ));
}

pub use limits::Channel;
pub use reject::Reject;
