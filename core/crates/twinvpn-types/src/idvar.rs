//! Variable-width and text identifiers, plus the one security value among them.
//!
//! **Authority:** `contracts/docs/identifiers.md`,
//! `contracts/registry/limits.json` §`identifiers`,
//! `contracts/proto/twinvpn/v1/common.proto`.
//!
//! Everything here is bounded at construction, because every one of these
//! arrives on a wire and every one of them would otherwise drive an allocation
//! proportional to an attacker-declared length (`ownership.md` §6 rules 9, 10).

use core::fmt;

use crate::error::TypeError;
use crate::id::{FieldClassification, IdScope, Identifier, Opacity, Reuse};

/// `idempotency_key` — client-generated, ≥ 128 bits of randomness, scoped by the
/// server to the authenticated `DeviceIdentity`.
///
/// **An idempotency key is not a capability** (ADR-0008 §7.3): it confers no
/// authorization, and dedup lookup is scoped to the caller, so one device cannot
/// probe or replay another device's outcomes by guessing keys.
///
/// Stored inline at its 64-byte maximum, so decoding one allocates nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey {
    bytes: [u8; Self::MAX_WIDTH],
    len: u8,
}

impl IdempotencyKey {
    /// `limits.json` `idempotency_key_min_bytes`. The ≥ 128-bit floor.
    pub const MIN_WIDTH: usize = 16;
    /// `limits.json` `idempotency_key_max_bytes`.
    pub const MAX_WIDTH: usize = 64;

    /// Builds from a wire slice, validating the range.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TypeError> {
        if !(Self::MIN_WIDTH..=Self::MAX_WIDTH).contains(&bytes.len()) {
            return Err(TypeError::IdentifierRange {
                kind: "idempotency_key",
                min: Self::MIN_WIDTH,
                max: Self::MAX_WIDTH,
                observed: bytes.len(),
            });
        }
        let mut out = [0u8; Self::MAX_WIDTH];
        out[..bytes.len()].copy_from_slice(bytes);
        #[allow(clippy::cast_possible_truncation)]
        Ok(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }
}

impl Identifier for IdempotencyKey {
    const REGISTRY_KEY: &'static str = "idempotency_key";
    const SCOPE: IdScope = IdScope::CallerKeyed;
    const OPACITY: Opacity = Opacity::Opaque;
    const REUSE: Reuse = Reuse::Never;
    const CLASSIFICATION: FieldClassification = FieldClassification::Sensitive;

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdempotencyKey(<{} B redacted>)", self.len)
    }
}

/// `Auth.channel_binding` — the RFC 9266 `tls-exporter` value of the current
/// control connection: 32 bytes, label `"EXPORTER-Channel-Binding"`, empty
/// context, from the TLS 1.3 handshake underlying QUIC.
///
/// This is a **security value, not an identifier**: ADR-0002 N-2 requires a
/// receiver to verify it against its own exporter and to reject a mismatch with
/// `CONTROL.CHANNEL_BINDING_MISMATCH`, "treated as a security event and never as
/// a parse error".
///
/// # Comparison
///
/// [`ChannelBinding::verify_against`] compares in constant time with respect to
/// the *position* of the first differing byte. It is written by hand rather than
/// with `subtle`, because `core/Cargo.toml` classifies `subtle` among the
/// cryptographic dependencies that CD-I2 restricts to `twinvpn-crypto`. The
/// residual is stated rather than hidden: without `subtle::ConstantTimeEq` there
/// is no compiler barrier preventing LLVM from introducing an early exit, and
/// the mitigation is the loop's data dependence on every byte. A caller with a
/// stronger requirement should perform the comparison in `twinvpn-crypto`.
///
/// `PartialEq` is deliberately **not** implemented: `==` on this type would be a
/// variable-time comparison somebody wrote without meaning to. Neither is
/// `Clone`: a security value that copies itself silently is one more place the
/// scrub in `Drop` does not reach.
pub struct ChannelBinding([u8; 32]);

impl ChannelBinding {
    /// The exact width `limits.json` declares.
    pub const WIDTH: usize = 32;

    /// Builds from an exact-width array.
    #[must_use]
    pub const fn from_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Builds from a wire slice, validating the width.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TypeError> {
        if bytes.len() != Self::WIDTH {
            return Err(TypeError::IdentifierLength {
                kind: "channel_binding_bytes",
                expected: Self::WIDTH,
                observed: bytes.len(),
            });
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    /// Compares against the locally computed exporter value.
    ///
    /// Returns `true` only on an exact match. See the type's docs for the
    /// timing-side-channel residual.
    #[must_use]
    pub fn verify_against(&self, local: &ChannelBinding) -> bool {
        let mut diff = 0u8;
        for i in 0..Self::WIDTH {
            diff |= self.0[i] ^ local.0[i];
        }
        diff == 0
    }
}

impl Identifier for ChannelBinding {
    const REGISTRY_KEY: &'static str = "channel_binding_bytes";
    const SCOPE: IdScope = IdScope::Process;
    const OPACITY: Opacity = Opacity::Opaque;
    const REUSE: Reuse = Reuse::NotWithinScope;
    const CLASSIFICATION: FieldClassification = FieldClassification::Sensitive;

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChannelBinding(<32 B redacted>)")
    }
}

impl Drop for ChannelBinding {
    /// Best-effort scrub.
    ///
    /// **Stated honestly:** this is not a guaranteed erase. A true scrub needs a
    /// volatile write, which `zeroize` provides and which `#![forbid(unsafe_code)]`
    /// forbids us to write by hand — and `zeroize` is classified among the
    /// cryptographic dependencies CD-I2 restricts to `twinvpn-crypto`. The
    /// compiler is free to elide this store. It is kept because it costs nothing
    /// and removes the value in every build where it is not elided.
    fn drop(&mut self) {
        self.0 = [0u8; 32];
    }
}

/// `causality_token` — opaque, minted by the control plane, **echoed by devices
/// and never parsed by them**.
///
/// Devices store the newest per `twinnet_id` and send it back on every C1
/// request. `identifiers.md` §4: "any client-side interpretation of causality
/// metadata becomes a compatibility landmine across version boundaries". This
/// type therefore exposes its bytes only for re-emission — there is no accessor
/// that invites a device to look inside.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CausalityToken(Vec<u8>);

impl CausalityToken {
    /// `limits.json` `causality_token_max_bytes`.
    pub const MAX_WIDTH: usize = 512;

    /// Builds from a wire slice, validating the cap **before** allocating.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, TypeError> {
        if bytes.len() > Self::MAX_WIDTH {
            return Err(TypeError::TextIdentifierTooLong {
                kind: "causality_token_max_bytes",
                limit: Self::MAX_WIDTH,
                observed: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The exact bytes to echo back. The only accessor, by design.
    #[must_use]
    pub fn octets_to_echo(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CausalityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CausalityToken(<{} B opaque>)", self.0.len())
    }
}

/// Declares a bounded text identifier.
macro_rules! text_id {
    (
        $(#[$meta:meta])*
        $name:ident, $limit:expr, $key:literal, $scope:expr, $reuse:expr, $class:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The cap `contracts/registry/limits.json` declares, in bytes.
            pub const MAX_BYTES: usize = $limit;

            /// Builds from wire text, validating the cap **before** allocating and
            /// rejecting any control character.
            ///
            /// A control character in an identifier that reaches a log or a
            /// terminal is a formatting-injection vector, and this boundary is the
            /// only place that can refuse it.
            pub fn new(s: &str) -> Result<Self, TypeError> {
                if s.len() > $limit {
                    return Err(TypeError::TextIdentifierTooLong {
                        kind: $key,
                        limit: $limit,
                        observed: s.len(),
                    });
                }
                if s.is_empty() || s.chars().any(char::is_control) {
                    return Err(TypeError::TextIdentifierTooLong {
                        kind: $key,
                        limit: $limit,
                        observed: s.len(),
                    });
                }
                Ok(Self(s.to_owned()))
            }

            /// The identifier's text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Identifier for $name {
            const REGISTRY_KEY: &'static str = $key;
            const SCOPE: IdScope = $scope;
            const OPACITY: Opacity = Opacity::Opaque;
            const REUSE: Reuse = $reuse;
            const CLASSIFICATION: FieldClassification = $class;

            fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match Self::CLASSIFICATION {
                    FieldClassification::Sensitive => {
                        write!(f, "{}(<{} B redacted>)", stringify!($name), self.0.len())
                    }
                    _ => write!(f, "{}({:?})", stringify!($name), self.0),
                }
            }
        }
    };
}

text_id!(
    /// `twinnet_id` — minted by the control plane, globally unique, **opaque to a
    /// device** and meaningful only to the operator.
    TwinnetId, 64, "twinnet_id_max_bytes",
    IdScope::Global, Reuse::Never, FieldClassification::Sensitive
);

text_id!(
    /// `region_id` — minted by the relay-fleet operator.
    ///
    /// **A device MUST NOT parse it** (`identifiers.md` §1). It is a label the
    /// operator understands; treating its text as structure is how a client comes
    /// to depend on a naming scheme the operator is free to change.
    RegionId, 64, "region_id_max_bytes",
    IdScope::OperatorFleet, Reuse::NotWithinScope, FieldClassification::Operational
);

text_id!(
    /// `policy_id` / `dnspolicy_id` — minted by the Owner authority, unique within
    /// one `TwinNet`, never reused.
    PolicyId, 64, "policy_id_max_bytes",
    IdScope::TwinNet, Reuse::Never, FieldClassification::Operational
);

text_id!(
    /// `signer_key_id` — the `DeviceKey` fingerprint of a signer (ADR-0007),
    /// carried in `Auth.signer_key_id` under the Rule B forwarding mode.
    SignerKeyId, 64, "signer_key_id_max_bytes",
    IdScope::Global, Reuse::Never, FieldClassification::Sensitive
);
