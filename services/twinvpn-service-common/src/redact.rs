//! Secret- and sensitive-bearing wrappers whose `Debug` cannot leak.
//!
//! **Authority:** ADR-0015 §11.4 (field classification), O-12 (`SECRET` "MUST
//! NEVER be written to any log, metric, trace, crash artifact, or diagnostic
//! bundle at any log level, in any build, INCLUDING debug builds"),
//! `docs/implementation/ownership.md` §6 rule 11.
//!
//! # Why a wrapper and not a convention
//!
//! `#[derive(Debug)]` on a struct holding a `String` password renders the
//! password. The derive is the leak; a rule that says "do not log secrets" does
//! not survive one derive on an enclosing type six months later. [`Secret`]
//! makes the derive safe: an enclosing `#[derive(Debug)]` renders
//! `Secret(<redacted>)` because that is the only `Debug` this type has.
//!
//! `twinvpn-types` does the same for `DeviceId`, `ChannelBinding`,
//! `SharedSecret`, `V4Addr`, `V6Addr` and `InterfaceName`; this module covers
//! the server-side values that have no core type — a database URL, a token, a
//! private key path's *contents*.
//!
//! # What is deliberately absent
//!
//! - No `Display`. A `Display` impl is what a format string reaches for.
//! - No `Serialize`. Serialisation is how a secret reaches a JSON log.
//! - No `AsRef<str>`, no `Deref`. Both are implicit conversions, and an implicit
//!   conversion is exactly what a reviewer does not see.
//!
//! The one way out is [`Secret::expose`], which is long, explicit and greppable.

use std::fmt;

/// A value classified `SECRET` by ADR-0015 §11.4.
///
/// Key material, pairing secrets, packet payloads, tunnel plaintext,
/// authentication tokens, and anything embedding one (a database URL embeds a
/// password).
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Yields the wrapped value.
    ///
    /// Named so that every use site is greppable and reads as a deliberate act.
    /// The result MUST NOT be logged, put on a span, placed in `Evidence`, or
    /// rendered into an `ErrorEnvelope`.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper, yielding the value. Same obligations as
    /// [`Secret::expose`].
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_exposed(self) -> T {
        self.0
    }

    /// Maps the inner value, keeping it wrapped throughout.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Secret<U> {
        Secret(f(self.0))
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// A `SECRET` string — a password, a token, a connection URL.
pub type SecretString = Secret<String>;

/// A value classified `SENSITIVE` by ADR-0015 §11.4.
///
/// Endpoints, addresses, interface names, `DeviceIdentity`, peer identifiers,
/// hostnames, SSIDs. Unlike [`Secret`] these may be *stored* locally and may be
/// pseudonymised into a Tier-1 bundle — but they are never Tier-2 and they never
/// reach an infrastructure span attribute, because the collector's forbidden-key
/// filter drops the whole record when one arrives.
#[derive(Clone, PartialEq, Eq)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wraps `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Yields the wrapped value for a use that is *not* telemetry — opening a
    /// socket, comparing a name, writing a row.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper.
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_exposed(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sensitive(<redacted>)")
    }
}

/// Lowercase hex, for the correlation identifiers that ARE allowlisted.
///
/// Deliberately here rather than in a general utility module: the only bytes
/// this crate ever renders as text are `message_id`, `correlation_id`,
/// `causation_id` and `idempotency_key`, all of which the collector allowlists
/// (`infra/otel/collector-config.yaml`). Everything else is a
/// [`Secret`] or a [`Sensitive`] and has no rendering path.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Parses lowercase or uppercase hex into at most `max` bytes.
///
/// Returns `None` on odd length, a non-hex character, or more than `max` bytes.
/// The cap is checked **before** the output vector is allocated, so an attacker
/// controlling a header cannot drive an allocation (`ownership.md` §6 rule 10).
#[must_use]
pub fn hex_decode_bounded(s: &str, max: usize) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) || bytes.len() / 2 > max {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        #[allow(clippy::cast_possible_truncation)]
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct Enclosing {
        name: &'static str,
        password: SecretString,
    }

    #[test]
    fn a_derived_debug_on_an_enclosing_struct_cannot_render_the_secret() {
        let e = Enclosing {
            name: "postgres",
            password: Secret::new("hunter2-correct-horse".to_owned()),
        };
        let rendered = format!("{e:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn sensitive_debug_is_redacted_too() {
        let s = Sensitive::new("203.0.113.7:51820".to_owned());
        assert_eq!(format!("{s:?}"), "Sensitive(<redacted>)");
    }

    #[test]
    fn expose_is_the_only_way_out() {
        let s = Secret::new(7u32);
        assert_eq!(*s.expose(), 7);
        assert_eq!(s.map(|v| v + 1).into_exposed(), 8);
    }

    #[test]
    fn hex_round_trips() {
        let b = [0x00u8, 0x0f, 0xa1, 0xff];
        let h = hex_lower(&b);
        assert_eq!(h, "000fa1ff");
        assert_eq!(hex_decode_bounded(&h, 4).unwrap(), b);
    }

    #[test]
    fn hex_decode_refuses_over_long_input_before_allocating() {
        let long = "ab".repeat(1024);
        assert!(hex_decode_bounded(&long, 16).is_none());
        assert!(hex_decode_bounded("abc", 16).is_none());
        assert!(hex_decode_bounded("zz", 16).is_none());
    }
}
