//! What the device presents, and what it will accept in return.
//!
//! **Authority:** ADR-0001 §11 item 3 (mutual RFC 7250 raw-public-key
//! authentication to `DeviceIdentityKey`, server auth against a **pinned** key
//! set), ADR-0001 §7.2 (a device pins from its enrolment record), ADR-0018
//! CB-5 / invariant **I4** (identity private keys stay inside the platform
//! element), `ownership.md` §8 **W-12**.
//!
//! # There is no learn-on-first-use, and there is no variant for it
//!
//! `lab/twinsim/src/lcontrol.rs` — the working client this module is promoted
//! from — has a `ServerKey::LearnOnFirstUse`, and is careful to name it so it
//! cannot be mistaken for pinning: a lab client bootstrapping against a freshly
//! generated development key has nothing to pin from, and pretending otherwise
//! would make the local environment's authentication story a fiction.
//!
//! A **product** device is never in that position: it pins from its enrolment
//! record. So the mode is not merely off here, it is unrepresentable —
//! [`ServerPins`] is a non-empty set of exact SPKI octets, with no `Any`
//! variant, no `Default`, and no constructor that yields an empty set. The
//! same technique [`crate::transport::EarlyData`] uses for 0-RTT: a posture you
//! cannot spell is stronger than a posture you have to remember not to select.
//!
//! An empty pin set would trust nothing, so [`ServerPins::new`] refuses one
//! with `CONTROL.HANDSHAKE_REJECTED` — the same verdict every handshake under
//! it would reach, stated at construction instead of once per connection.

use std::sync::Arc;

use quinn::rustls;

use crate::error::CpError;

/// The server raw public keys this device will accept, as exact
/// `SubjectPublicKeyInfo` octets.
///
/// Byte equality, and deliberately nothing more. Anything beyond
/// byte-equality pinning — parsing the key, checking a signature over it,
/// chaining it to an issuer — is cryptography, and CD-I2 puts that in
/// `twinvpn-crypto`. Comparing two public blobs for equality is not, and it is
/// the whole of what ADR-0001 asks for here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPins(Vec<Vec<u8>>);

impl ServerPins {
    /// Pins a non-empty set of server keys.
    ///
    /// A **set**, not one key: ADR-0007 rotation means the front-end fleet can
    /// legitimately present either the outgoing or the incoming key during a
    /// rollover, and a single-key pin would make every rotation an outage. The
    /// enrolment record is what fills it.
    ///
    /// # Errors
    ///
    /// [`CpError::HandshakeRejected`] on an empty set or an empty pin. An empty
    /// set accepts no server at all, so refusing here is the same answer the
    /// verifier would give, reached before a socket is bound.
    pub fn new(pins: Vec<Vec<u8>>) -> Result<Self, CpError> {
        if pins.is_empty() || pins.iter().any(Vec::is_empty) {
            return Err(CpError::HandshakeRejected);
        }
        Ok(Self(pins))
    }

    /// Whether `presented` is one of the pinned keys.
    ///
    /// Not constant-time, and that is deliberate rather than an omission: both
    /// operands are **public** keys, and the comparison leaks nothing an
    /// observer of the handshake does not already hold. `subtle` is reserved
    /// for values where the timing would say something — the channel binding,
    /// which is why [`twinvpn_types::ChannelBinding::verify_against`] uses it.
    #[must_use]
    pub fn accepts(&self, presented: &[u8]) -> bool {
        self.0.iter().any(|pin| pin.as_slice() == presented)
    }

    /// How many keys are pinned. Never zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false` — [`ServerPins::new`] refuses an empty set.
    ///
    /// Present because `clippy::len_without_is_empty` asks for it, and it is
    /// worth having a function whose body is the invariant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// The device's own RFC 7250 raw public key and the signer behind it.
///
/// # Why the private half is a trait object and not bytes
///
/// CB-5 / I4 keep the identity private key inside the platform element, and
/// `twinvpn_platform::custody::IdentityCustody` is how the rest of this crate
/// reaches it — `signing.rs`'s module docs put it plainly: *no private scalar
/// exists in this crate*.
///
/// That trait cannot serve TLS directly: `identity_sign` is `async` and
/// rustls' `Signer::sign` is synchronous, so bridging one to the other inside
/// a handshake means blocking a runtime thread from inside the runtime —
/// which deadlocks outright on the single-threaded iOS binding
/// (`Runtime::block_on`'s own documentation says so, and it is the same trap
/// `ownership.md` §8 W-28 records).
///
/// So the seam is rustls' own key handle. [`rustls::sign::SigningKey`] has no
/// method that yields key octets, so holding one is holding a *capability to
/// sign*, not a key — exactly the shape `IdentityCustody` has, expressed in the
/// vocabulary the TLS stack accepts. A platform element that can back one
/// implements it; a target with no element uses
/// [`DeviceIdentity::software_key`], which is named for what it costs.
#[derive(Clone)]
pub struct DeviceIdentity {
    spki: Vec<u8>,
    signer: Arc<dyn rustls::sign::SigningKey>,
}

impl core::fmt::Debug for DeviceIdentity {
    /// The public half's length and nothing else.
    ///
    /// The signer is a capability, not bytes, so there is no key here to
    /// render — but a `Debug` that printed the handle's inner state would be a
    /// path to one, and `ownership.md` §6 rule 11 is absolute about what must
    /// never reach a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "DeviceIdentity({} B SPKI, <signer not rendered>)",
            self.spki.len()
        )
    }
}

impl DeviceIdentity {
    /// Binds an element-resident identity: the public SPKI, and a signer that
    /// never exports the private half.
    ///
    /// The constructor a product target uses.
    ///
    /// # Errors
    ///
    /// [`CpError::HandshakeRejected`] on an empty SPKI — a key we cannot
    /// present is a handshake we cannot complete, said at construction.
    pub fn element_resident(
        spki: Vec<u8>,
        signer: Arc<dyn rustls::sign::SigningKey>,
    ) -> Result<Self, CpError> {
        if spki.is_empty() {
            return Err(CpError::HandshakeRejected);
        }
        Ok(Self { spki, signer })
    }

    /// Binds a **software-held** identity from PKCS#8 octets.
    ///
    /// Named for its cost. CB-5 wants the private half inside the platform
    /// element; this constructor is for a target that has none, and for tests.
    /// The octets are handed straight to the provider's key loader and are not
    /// retained by this type — what is retained is the resulting signer, the
    /// same handle [`DeviceIdentity::element_resident`] takes.
    ///
    /// The public half is **derived from the loaded key** rather than supplied
    /// alongside it. A separately-passed SPKI is a second source for a fact the
    /// key already carries, and the failure mode of the two disagreeing is a
    /// handshake in which the device presents one key and signs with another —
    /// which fails with no diagnosis on either side.
    ///
    /// # Errors
    ///
    /// [`CpError::HandshakeRejected`] when the octets are not a PKCS#8 key the
    /// provider will load, or the loaded key will not yield its public half.
    /// The parse detail deliberately does not survive into the error: a caller
    /// cannot act on it differently, and `contracts/docs/phase1-conflicts.md`
    /// CF-4 keeps that detail off the wire.
    pub fn software_key(pkcs8: Vec<u8>) -> Result<Self, CpError> {
        let key = rustls::pki_types::PrivateKeyDer::try_from(pkcs8)
            .map_err(|_| CpError::HandshakeRejected)?;
        let signer = super::provider()
            .key_provider
            .load_private_key(key)
            .map_err(|_| CpError::HandshakeRejected)?;
        let spki = signer
            .public_key()
            .map(|spki| spki.as_ref().to_vec())
            .ok_or(CpError::HandshakeRejected)?;
        Self::element_resident(spki, signer)
    }

    /// The public half, as it goes on the wire under RFC 7250.
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }

    /// The rustls certified-key shape a raw-public-key client resolver needs.
    ///
    /// Under RFC 7250 the "certificate" slot carries the `SubjectPublicKeyInfo`
    /// itself; there is no chain, because ADR-0001 §6 rejected the naming
    /// system a certificate implies.
    pub(super) fn certified_key(&self) -> Arc<rustls::sign::CertifiedKey> {
        Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(self.spki.clone())],
            Arc::clone(&self.signer),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::ServerPins;

    #[test]
    fn an_empty_pin_set_is_refused_at_construction() {
        let err = ServerPins::new(Vec::new()).expect_err("nothing is pinned");
        assert_eq!(err.reason_code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
        let err = ServerPins::new(vec![Vec::new()]).expect_err("an empty pin");
        assert_eq!(err.reason_code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
    }

    #[test]
    fn a_pin_set_accepts_exactly_what_was_pinned() {
        let pins = ServerPins::new(vec![vec![1, 2, 3], vec![4, 5, 6]]).expect("two pins");
        assert_eq!(pins.len(), 2);
        assert!(!pins.is_empty());
        assert!(pins.accepts(&[1, 2, 3]));
        assert!(pins.accepts(&[4, 5, 6]));
        assert!(!pins.accepts(&[1, 2, 3, 4]));
        assert!(!pins.accepts(&[1, 2]));
        assert!(!pins.accepts(&[]));
    }

    #[test]
    fn there_is_no_way_to_spell_learn_on_first_use() {
        // A documentation assertion, and it is here for the reason the lab's
        // sibling test gives: the failure it guards against is somebody adding
        // the variant back because a bootstrap was inconvenient. `ServerPins`
        // is a struct with one private field, so the only way to widen it is to
        // change this file — and this test is in it.
        let rendered = format!("{:?}", ServerPins::new(vec![vec![9]]).expect("one pin"));
        assert!(!rendered.contains("Learn"));
        assert!(!rendered.contains("Any"));
    }
}
