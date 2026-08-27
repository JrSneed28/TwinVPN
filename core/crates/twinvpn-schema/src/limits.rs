//! The frozen validation limits, compiled in.
//!
//! **Authority:** `contracts/registry/limits.json`, whose own comment states the
//! rule these constants exist to serve:
//!
//! > "Every field here is enforced BEFORE any allocation proportional to a
//! > declared length. A violation is a typed reject with a `PROTO.*` code, never
//! > a truncation, never a pad, and never a silent accept."
//!
//! Two independent paths lead from the one frozen file to this module: the
//! generated constants (build script) and [`LIMITS_JSON`] (`include_str!`). A
//! test re-parses the second and asserts every constant from the first, so the
//! compiled copy cannot drift from the registry without failing `cargo test`.

include!(concat!(env!("OUT_DIR"), "/limits_generated.rs"));

/// The frozen registry, embedded verbatim.
///
/// Present so the compiled constants can be checked against their source at test
/// time, and so a diagnostic bundle can state which limits this build enforces
/// without needing the file on disk.
pub const LIMITS_JSON: &str = include_str!("../../../../contracts/registry/limits.json");

/// The frozen capability registry, embedded verbatim.
pub const CAPABILITIES_JSON: &str =
    include_str!("../../../../contracts/registry/capabilities.json");

/// The capability-name cap this build enforces: **32, not the registry's 24**.
///
/// # An open contract defect, worked around rather than patched
///
/// `docs/implementation/ownership.md` §4.3 records it in full. In short:
/// `limits.json` says `capability.max_name_bytes = 24`, while
/// `capabilities.json` says `capability_name_max_length = 32`,
/// `capabilities.cddl` says `[a-z][a-z0-9_]{0,31}`, and the capability registry
/// itself contains `dns_config_dies_with_tunnel` — **27 bytes**. CF-6 amended
/// ADR-0014 N-11 from 24 to 32 and deliberately did *not* rename the token,
/// because it is `security_relevant` and a rename is an S-37 compatibility event.
///
/// A validator built on `limits.json` alone would therefore **reject a
/// Phase-1-mandated token**. `contracts/` is frozen (`ownership.md` §3), so this
/// build validates against 32 and cites the section. `capability_name_cap_is_32_per_ownership_md_4_3`
/// pins the exception, and
/// `the_registry_still_disagrees_with_itself` fails the moment the defect is
/// dispositioned — which is what makes this removable rather than permanent.
pub const CAPABILITY_MAX_NAME_BYTES: usize = 32;

/// Which channel's envelope caps apply.
///
/// ADR-0003 §11 gives C4 a different cap and a different depth from the control
/// channels, so the channel is a parameter of validation rather than a global.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// C1 (control request/response), C2 (control events) and C7 (telemetry).
    ControlAndTelemetry,
    /// C4, the peer-to-peer datagram channel. Never fragmented.
    PeerDatagram,
}

impl Channel {
    /// The envelope byte cap for this channel.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Channel::ControlAndTelemetry => C1_C2_C7_MAX_BYTES,
            Channel::PeerDatagram => C4_MAX_BYTES,
        }
    }

    /// The nesting-depth cap for this channel.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        match self {
            Channel::ControlAndTelemetry => C1_C2_C7_MAX_DEPTH,
            Channel::PeerDatagram => C4_MAX_DEPTH,
        }
    }

    /// A stable name for the `parser_id` evidence field.
    #[must_use]
    pub const fn parser_id(self) -> &'static str {
        match self {
            Channel::ControlAndTelemetry => "c1_c2_c7",
            Channel::PeerDatagram => "c4",
        }
    }
}
