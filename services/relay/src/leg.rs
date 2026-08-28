//! Leg establishment: the `Noise_IK` responder, the stateless cookie, and the
//! bounded registry of established legs.
//!
//! **Authority:** ADR-0005 §11.1(1) ("at most one authenticated leg per
//! (`Device`, `Relay`), multiplexing N half-flows by `flow_id`"), §11.1(2) (the
//! leg is `Noise_IK` for `R-UDP`), §11.3 (offline token verification, `cnf`
//! against the presented relay-leg static), §11.5 (amplification ≤ 1, no
//! asymmetric operation for an unvalidated source address).
//!
//! # This module is what closed the one gap the rest of the crate was waiting on
//!
//! Until it existed, [`LegRegistry`] was empty in production and every received
//! datagram was dropped with zero bytes — fail-closed, correct, and useless. The
//! forwarding path, the admission policy, the limits and the drain were all
//! written and tested against a registry only a test could populate.
//!
//! # The order of operations is the anti-amplification argument
//!
//! ADR-0005 §11.5 is specific about what may happen before a source address is
//! validated, and [`LegHandshake::step`] follows it in this order:
//!
//! | # | Step | Cost to the relay | Cost to an attacker |
//! |---|---|---|---|
//! | 1 | length bounds | one comparison | — |
//! | 2 | per-prefix handshake rate ([`crate::resource::CookieGate`]) | one counter | — |
//! | 3 | **cookie challenge** if over the threshold | one 16-byte digest, ≤ 1 datagram out | a round trip it can only complete from a real address |
//! | 4 | the X25519 handshake | **the first asymmetric operation** | a completed round trip |
//! | 5 | token verification (COSE_Sign1) | the second | a valid Owner-signed token |
//! | 6 | `cnf` against the proved `RLK` | one comparison | possession of the bound key |
//! | 7 | registry admission, bounded | one insert | — |
//!
//! Step 3 before step 4 is the whole of "**no asymmetric operation for an
//! unvalidated source address**". Steps 5 and 6 are ADR-0005 §11.3's order, and
//! step 6 is what stops a *stolen* token from admitting anyone: `IK` proves the
//! initiator holds the `RLK`, and `cnf` proves the token was issued for it.
//!
//! # Amplification, measured at the type
//!
//! Every outcome of [`LegHandshake::step`] is a [`LegOutcome`], and the only two
//! variants that emit bytes emit **one** datagram: message 2 (≤ message 1 plus
//! the `CAPS` body, so ≤ 1) or a cookie challenge (a 32-octet body, far smaller
//! than the message that provoked it). Every refusal is `Silent`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use twinvpn_crypto::relay_leg::{
    CompletedLeg, Entropy, LegResponder, MAX_MSG1_BYTES, MSG1_OVERHEAD,
};

use crate::condition::Condition;
use crate::control::CapsBody;
use crate::crypto::{LegKey, RelayCrypto};
use crate::resource::CookieGate;
use crate::subject::RelaySub;
use crate::token::VerifiedToken;

/// The cookie's width. 16 octets of a one-way digest, as
/// [`RelayCrypto::digest16`] produces.
pub const COOKIE_BYTES: usize = 16;

/// How long one cookie stays valid, in milliseconds.
///
/// WireGuard's cookie secret rotates every 120 s and the same number is used
/// here: long enough that a device on a slow path completes the round trip,
/// short enough that a cookie captured from one address is worthless before it
/// could be replayed at scale from another.
pub const COOKIE_VALIDITY_MS: u64 = 120_000;

/// The domain separator for the cookie digest. Distinct from every other
/// `digest16` use, so a cookie can never be mistaken for a log subject.
const COOKIE_DOMAIN: &[u8] = b"twinvpn/relay/cookie/v1";

/// One established leg.
///
/// # What is stored, and what is deliberately not
///
/// `K_leg` and the subject are stored because forwarding and metering need them.
/// The device's `RLK_pub` is **not**: it is checked against `cnf` at admission
/// and then dropped, because after admission the relay has no use for it and
/// keeping it would be a second, *stable, cross-day* identifier sitting next to
/// a subject that ADR-0005 §10 goes to some trouble to rotate daily.
pub struct Leg {
    key: LegKey,
    token: VerifiedToken,
    last_activity_ms: u64,
}

impl Leg {
    /// The frame-MAC key.
    #[must_use]
    pub const fn key(&self) -> &LegKey {
        &self.key
    }

    /// The verified token this leg was admitted on.
    ///
    /// Held so a `BIND` on an established leg needs **no** second verification:
    /// the leg is already authenticated, and re-running COSE_Sign1 per bind
    /// would put an asymmetric operation on a path a device uses once per peer.
    /// ADR-0005 §11.3's "no control-plane call, per packet, per bind, or per
    /// reconnect" is about the control plane; this is the same economy applied
    /// to the relay's own CPU.
    #[must_use]
    pub const fn token(&self) -> &VerifiedToken {
        &self.token
    }

    /// The quota subject this leg's traffic is charged to.
    #[must_use]
    pub const fn subject(&self) -> RelaySub {
        self.token.subject()
    }

    /// When this leg was last heard from.
    #[must_use]
    pub const fn last_activity_ms(&self) -> u64 {
        self.last_activity_ms
    }
}

impl std::fmt::Debug for Leg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is a secret and the subject is a per-device pseudonym; neither
        // reaches a log line from here (`ownership.md` §6 rule 11, ADR-0015 O-13).
        f.debug_struct("Leg")
            .field("key", &"<redacted>")
            .field("token", &"<redacted>")
            .field("last_activity_ms", &self.last_activity_ms)
            .finish()
    }
}

/// The per-`(peer, leg)` registry, bounded three ways.
///
/// A leg is created by a source that was unauthenticated one round trip ago, so
/// an unbounded map keyed by source address is a remote memory-exhaustion
/// primitive (`ownership.md` §6 rule 10). Three ceilings, because one is not
/// enough:
///
/// | Ceiling | Bounds | Without it |
/// |---|---|---|
/// | `max_legs` | total memory | one attacker fills the table |
/// | `max_per_prefix` | legs from one source /24 or /48 | **one attacker still fills the table**, from one subnet, since a /64 is 2^64 addresses |
/// | `idle_timeout_ms` | how long an abandoned leg holds a slot | a table that only ever grows |
///
/// The second is the one that matters and the one a single global cap misses:
/// ADR-0005 §11.5 already groups handshake rate by /24 and /48 for exactly this
/// reason, and the *occupancy* limit has to use the same grouping or the rate
/// limit merely slows the fill down.
pub struct LegRegistry {
    legs: HashMap<SocketAddr, Leg>,
    per_prefix: HashMap<[u8; 16], usize>,
    max_legs: usize,
    max_per_prefix: usize,
    idle_timeout_ms: u64,
}

impl std::fmt::Debug for LegRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Peers and keys are both withheld: the count is the only safe dimension.
        f.debug_struct("LegRegistry")
            .field("legs", &self.legs.len())
            .field("max_legs", &self.max_legs)
            .finish()
    }
}

impl LegRegistry {
    /// A registry holding at most `max_legs`, at most `max_per_prefix` from one
    /// source /24 or /48, each expiring after `idle_timeout_ms` of silence.
    #[must_use]
    pub fn new(max_legs: usize, max_per_prefix: usize, idle_timeout_ms: u64) -> Self {
        Self {
            legs: HashMap::new(),
            per_prefix: HashMap::new(),
            max_legs: max_legs.max(1),
            max_per_prefix: max_per_prefix.max(1),
            idle_timeout_ms,
        }
    }

    /// Records an established leg. `false` when a ceiling refuses it.
    ///
    /// **Only a completed handshake may call this** — [`LegHandshake::step`] is
    /// the only production caller, and it calls it after step 7 of the table in
    /// the module docs and not before.
    pub fn establish(
        &mut self,
        peer: SocketAddr,
        key: LegKey,
        token: VerifiedToken,
        now_ms: u64,
    ) -> bool {
        let prefix = CookieGate::prefix_key(peer.ip());
        let replacing = self.legs.contains_key(&peer);
        if !replacing {
            if self.legs.len() >= self.max_legs {
                return false;
            }
            if self.per_prefix.get(&prefix).copied().unwrap_or(0) >= self.max_per_prefix {
                return false;
            }
            *self.per_prefix.entry(prefix).or_insert(0) += 1;
        }
        // A device re-handshaking from the same 5-tuple REPLACES its leg rather
        // than adding one: §11.1(1) is "at most one authenticated leg per
        // (Device, Relay)", and a device whose K_leg was lost across its own
        // restart must be able to establish a new one without waiting out the
        // idle timeout. It re-proves possession of the RLK to get here.
        self.legs.insert(
            peer,
            Leg {
                key,
                token,
                last_activity_ms: now_ms,
            },
        );
        true
    }

    /// The leg for a peer, if one is established.
    #[must_use]
    pub fn get(&self, peer: SocketAddr) -> Option<&Leg> {
        self.legs.get(&peer)
    }

    /// The frame-MAC key for a peer's leg.
    #[must_use]
    pub fn key_for(&self, peer: SocketAddr) -> Option<&LegKey> {
        self.legs.get(&peer).map(Leg::key)
    }

    /// Records that a peer was heard from, so its leg does not expire under it.
    pub fn touch(&mut self, peer: SocketAddr, now_ms: u64) {
        if let Some(leg) = self.legs.get_mut(&peer) {
            leg.last_activity_ms = now_ms;
        }
    }

    /// Drops one leg.
    pub fn remove(&mut self, peer: SocketAddr) -> bool {
        if self.legs.remove(&peer).is_some() {
            self.release_prefix(peer.ip());
            return true;
        }
        false
    }

    /// Expires legs idle beyond the timeout. Returns how many were reclaimed.
    ///
    /// Called from the same collector that expires pending slots and idle flows,
    /// so there is one place in the process where time reclaims memory.
    pub fn collect(&mut self, now_ms: u64) -> usize {
        let timeout = self.idle_timeout_ms;
        let expired: Vec<SocketAddr> = self
            .legs
            .iter()
            .filter(|(_, leg)| now_ms.saturating_sub(leg.last_activity_ms) >= timeout)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &expired {
            self.legs.remove(peer);
            self.release_prefix(peer.ip());
        }
        expired.len()
    }

    /// How many legs are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.legs.len()
    }

    /// Whether no leg is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// Drops every leg, as a restart does. Nothing was ever written anywhere.
    pub fn drop_everything(&mut self) -> usize {
        let n = self.legs.len();
        self.legs.clear();
        self.per_prefix.clear();
        n
    }

    fn release_prefix(&mut self, ip: IpAddr) {
        let prefix = CookieGate::prefix_key(ip);
        if let Some(count) = self.per_prefix.get_mut(&prefix) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_prefix.remove(&prefix);
            }
        }
    }
}

/// The stateless cookie of ADR-0005 §11.5.
///
/// # Why this is not a fourth key
///
/// ADR-0005 §7.1 closes the relay's key inventory at three, and this holds a
/// 32-octet secret. It is not a fourth entry in that inventory and the
/// distinction is not a word game: the secret **authenticates nothing and
/// decrypts nothing**. It is a per-process, per-two-minute value whose only use
/// is to let the relay recognise a token it minted for one source address, so
/// that it can be stateless about address validation. Disclosing it costs
/// exactly the anti-DoS property and no confidentiality, integrity or admission
/// property anywhere in the system — which is precisely why it may live in
/// ordinary memory and be regenerated at will.
///
/// It is derived through [`RelayCrypto::digest16`], the seam's one-way digest, so
/// this module implements no primitive of its own (`ownership.md` §6, "do not
/// invent cryptographic primitives").
pub struct CookieJar {
    secret: [u8; 32],
}

impl std::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieJar")
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CookieJar {
    /// A jar with a fresh secret.
    ///
    /// # Errors
    ///
    /// Propagates an entropy failure. A relay that cannot draw a cookie secret
    /// cannot defend its handshake path and must not pretend otherwise.
    pub fn new(
        entropy: &Arc<dyn Entropy>,
    ) -> Result<Self, twinvpn_crypto::relay_leg::EntropyError> {
        let mut secret = [0_u8; 32];
        entropy.fill(&mut secret)?;
        Ok(Self { secret })
    }

    /// The cookie for one source address in one validity window.
    ///
    /// The **port is included**. A NAT can put many devices behind one address,
    /// and a cookie bound only to the address would let one of them mint
    /// challenges the others could spend.
    #[must_use]
    pub fn issue(
        &self,
        crypto: &dyn RelayCrypto,
        peer: SocketAddr,
        now_ms: u64,
    ) -> Option<[u8; COOKIE_BYTES]> {
        self.at_window(crypto, peer, now_ms / COOKIE_VALIDITY_MS)
    }

    /// Whether `presented` is a cookie this relay issued to `peer` recently.
    ///
    /// The previous window is accepted as well as the current one, so a device
    /// that receives a challenge at the end of a window is not refused for
    /// answering it a moment later — without that, one request in every
    /// `COOKIE_VALIDITY_MS` fails for reasons the device cannot diagnose.
    #[must_use]
    pub fn verify(
        &self,
        crypto: &dyn RelayCrypto,
        peer: SocketAddr,
        presented: &[u8],
        now_ms: u64,
    ) -> bool {
        if presented.len() != COOKIE_BYTES {
            return false;
        }
        let window = now_ms / COOKIE_VALIDITY_MS;
        [window, window.saturating_sub(1)]
            .iter()
            .filter_map(|w| self.at_window(crypto, peer, *w))
            .any(|expected| constant_time_eq(&expected, presented))
    }

    fn at_window(
        &self,
        crypto: &dyn RelayCrypto,
        peer: SocketAddr,
        window: u64,
    ) -> Option<[u8; COOKIE_BYTES]> {
        let mut input = Vec::with_capacity(32 + 18 + 8 + 2);
        input.extend_from_slice(&self.secret);
        match peer.ip() {
            IpAddr::V4(v4) => {
                input.push(4);
                input.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                input.push(6);
                input.extend_from_slice(&v6.octets());
            }
        }
        input.extend_from_slice(&peer.port().to_be_bytes());
        input.extend_from_slice(&window.to_be_bytes());
        crypto.digest16(COOKIE_DOMAIN, &input)
    }
}

/// A comparison that does not return early.
///
/// A cookie is attacker-supplied and compared against a value the relay
/// computed; a `==` on byte slices is permitted to short-circuit, which turns
/// the comparison into a prefix-matching oracle. Sixteen bytes is small enough
/// that the oracle is cheap to exploit and the fix is four lines.
fn constant_time_eq(a: &[u8; COOKIE_BYTES], b: &[u8]) -> bool {
    if b.len() != COOKIE_BYTES {
        return false;
    }
    let mut diff = 0_u8;
    for i in 0..COOKIE_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// What one handshake datagram produced.
///
/// Three variants, and **at most one datagram in any of them** — which is
/// ADR-0005 §11.5's amplification factor expressed in the return type rather
/// than in a comment, exactly as [`crate::pump::Action`] does for the forwarding
/// path.
#[derive(Debug)]
pub enum LegOutcome {
    /// **Zero bytes.** Malformed, refused, or over a ceiling.
    Silent {
        /// Why, for a counter. Never sent to the peer.
        why: Condition,
    },
    /// A stateless cookie challenge: answer it from this address and try again.
    Challenge {
        /// The complete datagram.
        datagram: Vec<u8>,
    },
    /// The leg is established and message 2 is ready to send.
    Established {
        /// The complete datagram.
        datagram: Vec<u8>,
        /// The subject this leg's traffic is charged to.
        subject: RelaySub,
    },
}

impl LegOutcome {
    /// How many bytes leave the socket. Zero for [`LegOutcome::Silent`].
    #[must_use]
    pub fn emitted_len(&self) -> usize {
        match self {
            LegOutcome::Silent { .. } => 0,
            LegOutcome::Challenge { datagram } | LegOutcome::Established { datagram, .. } => {
                datagram.len()
            }
        }
    }
}

/// The bound handshake payload a device may present.
pub const MAX_INIT_PAYLOAD_BYTES: usize = MAX_MSG1_BYTES;

/// The minimum a `HANDSHAKE_INIT` body can be.
pub const MIN_INIT_PAYLOAD_BYTES: usize = MSG1_OVERHEAD;

/// The `CAPS` body carried inside message 2.
///
/// ADR-0005 §10 puts capability negotiation "at leg setup", and carrying it in
/// the encrypted handshake payload rather than in a following `CAPS` frame means
/// a relay's version window and capability set are not observable to anyone on
/// path — and that leg setup is one round trip, not two.
#[must_use]
pub fn leg_setup_caps() -> Vec<u8> {
    CapsBody::of_this_build().encode()
}

/// Runs one `Noise_IK` responder handshake to completion or refusal.
///
/// It is a free function rather than a type with state because a `R-UDP` leg
/// handshake is **one datagram in, one datagram out**: there is no half-finished
/// responder to keep, and keeping one would be per-source state an
/// unauthenticated address could allocate — the thing the stateless cookie
/// exists to avoid.
pub struct LegHandshake<'a> {
    /// The relay's static Noise private key, held only for the life of the call.
    pub static_private: &'a [u8],
    /// The injected CSPRNG.
    pub entropy: &'a Arc<dyn Entropy>,
    /// The cookie secret.
    pub cookies: &'a CookieJar,
    /// The cryptographic seam.
    pub crypto: &'a dyn RelayCrypto,
}

impl LegHandshake<'_> {
    /// Handles one `HANDSHAKE_INIT` body.
    ///
    /// `body` is `[cookie:16]` when `carries_cookie`, then the `Noise_IK`
    /// message. Returns the completed leg for the caller to admit, or the reason
    /// it did not.
    ///
    /// The caller does token verification and registry admission: this function
    /// deliberately stops at "the peer proved possession of an `RLK` and said
    /// this", because the admission policy needs the engine's tables and this
    /// needs the relay's private key — and keeping the two apart is what lets
    /// every admission rule be tested with no key and no handshake at all.
    pub fn step(
        &self,
        _peer: SocketAddr,
        noise_message: &[u8],
    ) -> Result<(Vec<u8>, CompletedLeg), Condition> {
        if noise_message.len() < MIN_INIT_PAYLOAD_BYTES
            || noise_message.len() > MAX_INIT_PAYLOAD_BYTES
        {
            return Err(Condition::TokenMissing);
        }
        let responder = LegResponder::new(self.entropy, self.static_private)
            .map_err(|_| Condition::TransportUnavailable)?;
        responder
            .respond(noise_message, &leg_setup_caps())
            // Every handshake failure is one condition: a responder that
            // distinguished "wrong prologue" from "bad ephemeral" for an
            // unauthenticated source would be an oracle (ADR-0001 §7.3.1 P-3).
            .map_err(|_| Condition::TokenInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::FailClosed;
    use crate::provider::CryptoProvider;

    struct FixedEntropy(u8);
    impl Entropy for FixedEntropy {
        fn fill(&self, dst: &mut [u8]) -> Result<(), twinvpn_crypto::relay_leg::EntropyError> {
            dst.fill(self.0);
            Ok(())
        }
    }

    fn entropy(v: u8) -> Arc<dyn Entropy> {
        Arc::new(FixedEntropy(v))
    }

    fn sub(n: u8) -> VerifiedToken {
        crate::token::testkit::verified([n; 16])
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("address")
    }

    #[test]
    fn the_registry_bounds_total_legs() {
        let mut r = LegRegistry::new(2, 100, 900_000);
        assert!(r.establish(addr("192.0.2.1:1"), LegKey::new([1; 32]), sub(1), 0));
        assert!(r.establish(addr("198.51.100.1:1"), LegKey::new([2; 32]), sub(2), 0));
        assert!(!r.establish(addr("203.0.113.1:1"), LegKey::new([3; 32]), sub(3), 0));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn the_registry_bounds_legs_from_one_source_prefix() {
        // The ceiling that a single global cap misses: one /64 is 2^64 addresses,
        // so without this one subnet fills the whole table by itself.
        let mut r = LegRegistry::new(1_000, 2, 900_000);
        assert!(r.establish(addr("[2001:db8::1]:1"), LegKey::new([1; 32]), sub(1), 0));
        assert!(r.establish(addr("[2001:db8::2]:1"), LegKey::new([2; 32]), sub(2), 0));
        assert!(
            !r.establish(addr("[2001:db8::3]:1"), LegKey::new([3; 32]), sub(3), 0),
            "a third leg from the same /48 must be refused while the table is \
             nowhere near its global ceiling"
        );
        // A different prefix is unaffected — one abusive source must not deny
        // service to everyone else (I7).
        assert!(r.establish(addr("[2001:db9::1]:1"), LegKey::new([4; 32]), sub(4), 0));
    }

    #[test]
    fn a_re_handshake_from_one_peer_replaces_rather_than_accumulates() {
        // §11.1(1): at most one leg per (Device, Relay).
        let mut r = LegRegistry::new(1_000, 1, 900_000);
        let peer = addr("192.0.2.1:5");
        assert!(r.establish(peer, LegKey::new([1; 32]), sub(1), 0));
        assert!(
            r.establish(peer, LegKey::new([2; 32]), sub(1), 10),
            "a device re-handshaking from the same 5-tuple must not be refused by \
             its own prior leg"
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r.key_for(peer).expect("leg").expose(), &[2_u8; 32]);
    }

    #[test]
    fn an_idle_leg_is_reclaimed_and_its_prefix_slot_with_it() {
        let mut r = LegRegistry::new(10, 1, 1_000);
        let peer = addr("192.0.2.1:1");
        assert!(r.establish(peer, LegKey::new([1; 32]), sub(1), 0));
        assert_eq!(r.collect(500), 0, "not yet idle");
        assert_eq!(r.collect(1_000), 1);
        assert!(r.is_empty());
        // The prefix counter was released, not leaked: a table that reclaims the
        // leg but not its slot refuses that subnet for ever.
        assert!(r.establish(addr("192.0.2.9:1"), LegKey::new([2; 32]), sub(2), 1_000));
    }

    #[test]
    fn touching_a_leg_keeps_it_alive() {
        let mut r = LegRegistry::new(10, 10, 1_000);
        let peer = addr("192.0.2.1:1");
        r.establish(peer, LegKey::new([1; 32]), sub(1), 0);
        r.touch(peer, 900);
        assert_eq!(r.collect(1_000), 0);
        assert_eq!(r.collect(1_900), 1);
    }

    #[test]
    fn a_restart_drops_every_leg() {
        let mut r = LegRegistry::new(10, 10, 1_000);
        r.establish(addr("192.0.2.1:1"), LegKey::new([1; 32]), sub(1), 0);
        r.establish(addr("192.0.2.2:1"), LegKey::new([2; 32]), sub(2), 0);
        assert_eq!(r.drop_everything(), 2);
        assert!(r.is_empty());
        assert!(r.establish(addr("192.0.2.3:1"), LegKey::new([3; 32]), sub(3), 0));
    }

    #[test]
    fn a_leg_renders_neither_its_key_nor_its_subject() {
        let mut r = LegRegistry::new(10, 10, 1_000);
        let peer = addr("192.0.2.1:1");
        r.establish(peer, LegKey::new([0xAB; 32]), sub(0xCD), 0);
        let rendered = format!("{:?}", r.get(peer).expect("leg"));
        assert!(!rendered.contains("ab") && !rendered.contains("171"));
        assert!(!rendered.contains("cd") && !rendered.contains("205"));
        // And the registry itself renders a count, never a peer address.
        let registry = format!("{r:?}");
        assert!(!registry.contains("192.0.2.1"));
    }

    #[test]
    fn a_cookie_verifies_only_for_the_address_it_was_issued_to() {
        let crypto = CryptoProvider::new();
        let jar = CookieJar::new(&entropy(0x11)).expect("jar");
        let a = addr("192.0.2.1:1000");
        let b = addr("192.0.2.1:1001");
        let cookie = jar.issue(&crypto, a, 0).expect("cookie");
        assert!(jar.verify(&crypto, a, &cookie, 0));
        // A different PORT behind the same NAT must not spend it: one device
        // behind a CGNAT could otherwise mint challenges for its neighbours.
        assert!(!jar.verify(&crypto, b, &cookie, 0));
        assert!(!jar.verify(&crypto, addr("198.51.100.1:1000"), &cookie, 0));
    }

    #[test]
    fn a_cookie_expires_but_tolerates_the_window_edge() {
        let crypto = CryptoProvider::new();
        let jar = CookieJar::new(&entropy(0x22)).expect("jar");
        let peer = addr("192.0.2.1:1");
        let cookie = jar.issue(&crypto, peer, 0).expect("cookie");
        assert!(jar.verify(&crypto, peer, &cookie, 0));
        // Issued in window 0, answered in window 1: still accepted, or one
        // request in every validity period fails undiagnosably.
        assert!(jar.verify(&crypto, peer, &cookie, COOKIE_VALIDITY_MS));
        // Two windows later it is gone.
        assert!(!jar.verify(&crypto, peer, &cookie, COOKIE_VALIDITY_MS * 2));
    }

    #[test]
    fn a_wrong_length_cookie_is_refused_without_indexing() {
        let crypto = CryptoProvider::new();
        let jar = CookieJar::new(&entropy(0x33)).expect("jar");
        let peer = addr("192.0.2.1:1");
        for len in [0_usize, 1, COOKIE_BYTES - 1, COOKIE_BYTES + 1, 4096] {
            assert!(!jar.verify(&crypto, peer, &vec![0_u8; len], 0));
        }
    }

    #[test]
    fn without_a_provider_no_cookie_can_be_minted_and_none_verifies() {
        // The fail-closed direction: `FailClosed::digest16` returns None, so the
        // relay cannot issue a challenge and never accepts one either.
        let jar = CookieJar::new(&entropy(0x44)).expect("jar");
        let peer = addr("192.0.2.1:1");
        assert!(jar.issue(&FailClosed, peer, 0).is_none());
        assert!(!jar.verify(&FailClosed, peer, &[0_u8; COOKIE_BYTES], 0));
    }

    #[test]
    fn a_cookie_jar_renders_no_secret() {
        let jar = CookieJar::new(&entropy(0x55)).expect("jar");
        assert_eq!(format!("{jar:?}"), "CookieJar { secret: \"<redacted>\" }");
    }

    #[test]
    fn a_short_or_oversized_handshake_message_never_reaches_the_key() {
        let jar = CookieJar::new(&entropy(0x66)).expect("jar");
        let e = entropy(0x77);
        let crypto = CryptoProvider::new();
        let hs = LegHandshake {
            static_private: &[7_u8; 32],
            entropy: &e,
            cookies: &jar,
            crypto: &crypto,
        };
        let peer = addr("192.0.2.1:1");
        assert!(hs.step(peer, &[0_u8; MIN_INIT_PAYLOAD_BYTES - 1]).is_err());
        assert!(hs
            .step(peer, &vec![0_u8; MAX_INIT_PAYLOAD_BYTES + 1])
            .is_err());
    }

    #[test]
    fn a_garbage_handshake_message_is_one_indistinguishable_refusal() {
        let jar = CookieJar::new(&entropy(0x88)).expect("jar");
        let e = entropy(0x99);
        let crypto = CryptoProvider::new();
        let hs = LegHandshake {
            static_private: &[7_u8; 32],
            entropy: &e,
            cookies: &jar,
            crypto: &crypto,
        };
        let peer = addr("192.0.2.1:1");
        let a = hs.step(peer, &[0_u8; MIN_INIT_PAYLOAD_BYTES]).unwrap_err();
        let b = hs.step(peer, &[0xFF_u8; 300]).unwrap_err();
        assert_eq!(a, b, "a prober must not learn WHICH check refused it");
    }

    #[test]
    fn the_caps_body_offered_at_leg_setup_decodes_and_names_this_version() {
        let caps = CapsBody::decode(&leg_setup_caps()).expect("decodes");
        assert!(caps.speaks(crate::frame::VERSION));
        assert_eq!(
            usize::from(caps.max_data_payload_bytes),
            crate::frame::MAX_DATA_PAYLOAD_BYTES
        );
    }
}
