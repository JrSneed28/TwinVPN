//! [`Sealed`] — the payload a relay carries, which this module cannot open.
//!
//! **Authority:** ADR-0001 I1 and ADR-0005 RQ1 / §7.1 / §7.3 (*"the relay MUST
//! NEVER be able to decrypt or interpret what it forwards"*); `ownership.md` §6
//! rules 9, 10 and 11; `services/relay/tests/cannot_decrypt.rs`, which is the
//! server-side half of exactly this property.
//!
//! # Why a newtype and not a comment
//!
//! ADR-0005 §7.3 states the trust position from the relay's side: the relay's
//! static Noise public key *"is **NOT** an input to the L-DATA `Noise_IKpsk2`
//! handshake — the relay is not a party to it, and holding this key gives it no
//! read access."* The device side owes the same guarantee in the other
//! direction. A relay leg is a **carriage**, so the module that drives one must
//! not be able to read what it carries either; a module that could would make
//! the leg a second place where an L-DATA plaintext exists, and the smallest
//! such place is the one an attacker looks for first.
//!
//! Three things make that structural rather than aspirational:
//!
//! 1. **This module names no opening primitive.** It does not depend on
//!    `twinvpn-tunnel`, and it names no AEAD, no `open`, no `decrypt` and no
//!    tunnel key type. `the_relay_leg_holds_no_key_that_could_open_a_payload`
//!    in `tests/relay.rs` asserts that against the source, the way
//!    `cannot_decrypt.rs` asserts it against the relay's.
//! 2. **The type has no reader that yields a decoded value.** [`Sealed`] offers
//!    a length, a hand-back to the crate that sealed it, and a module-private
//!    borrow used only to fill a frame body. There is no `Deref`, no
//!    `AsRef<[u8]>`, no `Display`, and no parser.
//! 3. **`Debug` prints a length.** `ownership.md` §6 rule 11 forbids
//!    observability capturing a tunnel payload, and a derived `Debug` on any
//!    enclosing struct would do precisely that.
//!
//! # The bound is applied before the octets are retained
//!
//! [`Sealed::from_tunnel`] refuses anything past
//! `twinvpn_relay_client::frame::MAX_DATA_PAYLOAD_BYTES` **before** it takes
//! ownership, which is §6 rule 9 applied to the one value in this module whose
//! size a peer can influence.

use twinvpn_relay_client::frame::MAX_DATA_PAYLOAD_BYTES;

use super::outcome::RelayReject;

/// One sealed L-DATA datagram, on its way to or from a relay.
///
/// Built from `twinvpn-tunnel`'s output by the composition root and handed back
/// to `twinvpn-tunnel` on the way in. Between those two points it is opaque:
/// nothing in this module can tell one sealed datagram from another except by
/// its length.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed(Vec<u8>);

impl Sealed {
    /// Wraps a datagram `twinvpn-tunnel` has already sealed.
    ///
    /// The name says where the octets must come from, because that is the one
    /// thing this module cannot check: it holds no key, so it cannot tell a
    /// sealed datagram from an unsealed one. Naming the obligation in the
    /// constructor is the same device `LegInitiator::new`'s
    /// `relay_static_public_from_verified_map` parameter uses for the
    /// obligation *it* cannot check.
    ///
    /// # Errors
    ///
    /// [`RelayReject::PayloadTooLarge`] past ADR-0005 §9.2's derived ceiling,
    /// **before** the vector is retained.
    pub fn from_tunnel(datagram: Vec<u8>) -> Result<Self, RelayReject> {
        if datagram.len() > MAX_DATA_PAYLOAD_BYTES {
            return Err(RelayReject::PayloadTooLarge {
                observed: datagram.len(),
                limit: MAX_DATA_PAYLOAD_BYTES,
            });
        }
        Ok(Self(datagram))
    }

    /// How many octets. The **only** thing this module learns about a payload.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Hands the octets back to the crate that can open them.
    ///
    /// Consuming rather than borrowing, so a caller cannot hold the `Sealed`
    /// and the octets at once and then have to decide which of the two is
    /// authoritative.
    #[must_use]
    pub fn into_tunnel(self) -> Vec<u8> {
        self.0
    }

    /// The octets, for filling a `DATA` frame body and nothing else.
    ///
    /// Module-private on purpose: this is the single place inside the module
    /// where the payload is touched at all, and it copies it onto the wire
    /// unexamined.
    pub(super) fn as_wire(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Sealed {
    /// A length and nothing else (`ownership.md` §6 rule 11), matching
    /// `twinvpn_relay_client::frame::Payload`'s own `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sealed(<{} B opaque>)", self.0.len())
    }
}
