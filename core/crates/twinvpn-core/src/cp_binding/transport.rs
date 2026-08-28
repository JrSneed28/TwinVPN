//! `ControlTransport` → `twinvpn_cp_client::quic::QuicControlTransport`. **The
//! composed core's L-CONTROL binding.**
//!
//! **Authority:** [ADR-0001](../../../../../docs/adr/ADR-0001-cryptographic-architecture.md)
//! §11 item 3 (L-CONTROL is "QUIC + TLS 1.3 with mutual raw-public-key auth and
//! per-message `DeviceIdentityKey` signatures, **0-RTT prohibited**"), **R8**,
//! §7.2 (a device pins its server key set from its enrolment record);
//! [ADR-0002](../../../../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md)
//! §11.2 (the ladder and its budgets), **N-1**, §11.7, §11.10 (the mobile rule);
//! [ADR-0010](../../../../../docs/adr/ADR-0010-ipv4-ipv6-routing.md) **R1**;
//! [ADR-0018](../../../../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
//! CB-1 (resolution is a platform call), CB-3 (branch on capability, not on OS),
//! CB-5 / **I4** (identity private keys stay inside the element), CD-2 (`Env` at
//! construction), CD-I2 and finding **W-12**.
//!
//! # What the composition root must supply, and who can supply it
//!
//! `QuicControlTransport::new` takes five arguments. They divide sharply, and
//! the division is the point of this module:
//!
//! | Argument | Supplied by | Why |
//! |---|---|---|
//! | `Env` | **the core** | CD-2. [`ControlTransportBinding::bind`] takes it and clones it in |
//! | `Option<Nat64Prefix>` | **the core** | `PlatformAdapter::network_config().query_link_facts()` already reports ADR-0010 §11.7's discovered PREF64. Derived here, never guessed |
//! | `AttachFamilies` (via `TransportConfig`) | **the core** | the same `LinkFacts`. ADR-0010 R1: family is *data*, so this is one derivation and not four branches |
//! | `ServerPins` | **the shell**, from the enrolment record | see below |
//! | `Vec<ControlEndpoint>` | **the shell**, resolved | see below |
//! | `DeviceIdentity` | **the shell** | see below |
//!
//! ## Why the last three are injected rather than sourced here
//!
//! Each is a value the core genuinely does not hold today, and each is named
//! rather than fabricated.
//!
//! **`ServerPins` and the endpoints.** ADR-0001 §7.2 puts the pinned server key
//! set in the **enrolment record**, and `twinvpn-store` has no enrolment record:
//! its `Namespace` table has `Identity` and `Trust`, but no frozen key under
//! either holds a coordination front-end's SPKI or its names. Inventing one
//! would be this crate declaring a durable schema that belongs to
//! `core-security` and to the enrolment ceremony, and a pin set read from a key
//! nobody writes is an empty pin set with extra steps. So
//! [`ControlPlaneEnrolment`] is the shape the enrolment record must produce, the
//! shell hands one over, and **an empty pin set is refused at construction** —
//! see [`ControlPlaneEnrolment::new`].
//!
//! **The endpoints.** ADR-0011 DN-0 resolves coordination names in the bootstrap
//! DNS scope, and CB-1 puts name resolution at the platform seam.
//! `twinvpn_platform` exposes no resolver — `NetworkConfig` *programs* resolvers
//! and never queries one — so the core cannot resolve a name at all. That is a
//! real seam gap and it is reported as one; until it closes, the shell resolves
//! and passes `ControlEndpoint`s in, exactly as
//! `twinvpn_cp_client::quic::candidates`' own docs describe.
//!
//! **`DeviceIdentity`.** This is the CB-5 one and it is the important one.
//! `twinvpn_platform::custody::IdentityCustody` is the core's only reach to the
//! identity key, and `identity_sign` is **`async`** while rustls' `Signer::sign`
//! is synchronous. Bridging one to the other inside a handshake blocks a runtime
//! thread from inside the runtime, which deadlocks outright on the
//! single-threaded iOS binding (W-28). So the element-backed
//! `rustls::sign::SigningKey` is the shell's to construct and hand across, and
//! this crate never names a rustls type.
//!
//! **This crate will not build a software identity.** `DeviceIdentity::software_key`
//! exists and takes PKCS#8 octets; calling it here would mean a
//! `twinvpn-core`-held identity private scalar, which CD-I4 forbids outright —
//! "no type in the workspace may carry an identity private scalar" — and would
//! be precisely ADR-0018 §11.16 (l)'s prohibition: *"the core MUST NOT
//! substitute a file-backed signer silently."* There is no code path below that
//! calls it. That the constructor exists at all is a live CB-5 / I4 hole on
//! targets with no platform element, and it is reported, not closed here.
//!
//! # What [`ControlTransportBinding::bind`] does check
//!
//! It asks the element for [`twinvpn_platform::custody::IdentityCustody::public_identity`]
//! **before** it builds anything. A device with no usable identity fails with
//! `AUTH.KEY_UNAVAILABLE` at binding time rather than presenting a key at a
//! handshake and being refused — the same reasoning `ServerPins::new` gives for
//! refusing an empty set at construction: it is the verdict every attach under
//! it would reach, stated once instead of once per connection.
//!
//! **What it deliberately does not check** is that the injected `DeviceIdentity`'s
//! SPKI *is* the enrolled key. `IdentityPublic::public_key` is documented as
//! carrying "the public key bytes, **in the element's own encoding**", and RFC
//! 7250 puts a DER `SubjectPublicKeyInfo` on the wire; a byte comparison between
//! the two would refuse a correct adapter whose element hands back a raw SEC1
//! point. Asserting an equality the seam does not promise is worse than not
//! asserting it, so the check is absent and the gap is reported: the seam owes a
//! declared encoding, or `IdentityCustody` owes an `spki()`.
//!
//! # 0-RTT
//!
//! Nothing here can enable it. `TransportConfig` carries an `EarlyData` whose
//! only inhabitant is `Prohibited` and has no setter, so this module could not
//! ask for early data even by mistake — which is ADR-0001 R8 held by the type
//! system rather than by this comment.

use std::sync::Arc;

use twinvpn_cp_client::quic::QuicControlTransport;
use twinvpn_cp_client::transport::{
    AttachFamilies, ControlConnection, ControlTransport, Rung, TransportConfig,
};
use twinvpn_cp_client::CpError;
use twinvpn_env::Env;
use twinvpn_platform::PlatformAdapter;
use twinvpn_types::{AddressFamily, Component, Diagnostic, V4Addr};

pub use twinvpn_cp_client::quic::{ControlEndpoint, DeviceIdentity, Nat64Prefix, ServerPins};

/// The component every diagnostic this module emits is **observed by**.
///
/// ADR-0015 §11.3: the field names the observer, not the blamed party. A
/// platform refusal seen while composing the control-plane client is observed
/// here, at the control-plane client, even though the `reason_code` blames the
/// element.
const COMPONENT: Component = Component::ControlPlaneClient;

/// The part of ADR-0001 §7.2's enrolment record the L-CONTROL transport needs.
///
/// A **shape**, declared here so the shell has something exact to fill and so
/// the emptiness checks live in one place. It is deliberately not a durable
/// record type: `twinvpn-store` owns the vault's schema and this crate does not
/// get to add a namespace key to it. See the module docs.
#[derive(Debug, Clone)]
pub struct ControlPlaneEnrolment {
    pins: ServerPins,
    endpoints: Vec<ControlEndpoint>,
}

impl ControlPlaneEnrolment {
    /// Binds the enrolled server pin set to the resolved coordination endpoints.
    ///
    /// # Errors
    ///
    /// `CONTROL.HANDSHAKE_REJECTED` when `server_pins` is empty or contains an
    /// empty pin — an empty set accepts **no** server, so this is the verdict
    /// every handshake under it would reach, refused before a socket is bound.
    /// There is no learn-on-first-use here and no variant that could express
    /// one: `ServerPins` has no `Any` and no `Default`.
    ///
    /// `CONTROL.UNREACHABLE` when `endpoints` is empty. A transport with nothing
    /// to attach to reports a budget expiry three seconds later and reads as a
    /// network outage; saying so at construction keeps a misconfiguration
    /// distinguishable from one.
    pub fn new(
        server_pins: Vec<Vec<u8>>,
        endpoints: Vec<ControlEndpoint>,
    ) -> Result<Self, Box<Diagnostic>> {
        let pins = ServerPins::new(server_pins).map_err(|e| refusal(&e))?;
        if endpoints.is_empty() {
            return Err(refusal(&CpError::Unreachable));
        }
        Ok(Self { pins, endpoints })
    }

    /// The coordination names, in the order they were resolved.
    ///
    /// These are what go in `TransportConfig::coordination_endpoints` and in
    /// SNI. Derived from the endpoints rather than carried a second time: a
    /// name list that can disagree with the endpoint list is a name that
    /// resolves to nothing and is logged as an outage.
    #[must_use]
    pub fn coordination_names(&self) -> Vec<String> {
        self.endpoints
            .iter()
            .map(|e| e.server_name().to_owned())
            .collect()
    }

    /// How many server keys are pinned. **Never zero.**
    #[must_use]
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }
}

/// The composed core's L-CONTROL transport, and the placement facts it attaches
/// with.
///
/// Holds an `Arc<dyn ControlTransport>` rather than the concrete type so a lab
/// harness can substitute `twinvpn_cp_client::testing`'s scripted transport at
/// the same seam — which is what lets an eight-hour outage run on a virtual
/// clock, and what no real transport can do.
pub struct ControlTransportBinding {
    transport: Arc<dyn ControlTransport>,
    names: Vec<String>,
    families: AttachFamilies,
}

impl core::fmt::Debug for ControlTransportBinding {
    /// Placement facts only.
    ///
    /// The transport holds the client certificate resolver, which holds the
    /// signer. There is nothing in there that is safe to render, and
    /// `ownership.md` §6 rule 11 is absolute about what must never reach a log.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlTransportBinding")
            .field("rung", &Rung::Quic)
            .field("endpoints", &self.names.len())
            .field("families", &self.families)
            .finish_non_exhaustive()
    }
}

impl ControlTransportBinding {
    /// Builds the transport from core-held state plus the three values the shell
    /// must inject.
    ///
    /// The order of operations is load-bearing and the tests assert it:
    ///
    /// 1. **the identity, first.** A device with no usable identity key cannot
    ///    complete a mutual handshake, and finding that out from a timed-out
    ///    attach would report `CONTROL.UNREACHABLE` for a locked keychain.
    /// 2. the host's families and NAT64 prefix, from the platform;
    /// 3. whether any attach is possible at all;
    /// 4. only then, the TLS configuration and the transport.
    ///
    /// # Errors
    ///
    /// `AUTH.KEY_UNAVAILABLE` when the element cannot report a public identity —
    /// the code `PlatformError::IdentityKeyUnavailable` already maps to, carried
    /// through rather than re-decided here.
    ///
    /// `CONTROL.UNREACHABLE` when the platform cannot report link facts, when
    /// the host has no usable address family at all (ADR-0010 R1: a v6-only host
    /// **with** a NAT64 prefix still counts as usable), or when the endpoint list
    /// is empty.
    ///
    /// `CONTROL.HANDSHAKE_REJECTED` when the identity and pin set cannot produce
    /// a usable TLS configuration.
    pub async fn bind(
        env: &Env,
        adapter: &dyn PlatformAdapter,
        identity: &DeviceIdentity,
        enrolment: ControlPlaneEnrolment,
    ) -> Result<Self, Box<Diagnostic>> {
        // (1) CB-5. The element is asked before anything is built, and its
        // refusal is reported as its own code rather than as a network one.
        adapter
            .identity()
            .public_identity()
            .await
            .map_err(|e| Box::new(Diagnostic::builder(e.reason_code(), COMPONENT).build()))?;

        // (2) CB-3: a capability fact, not an OS branch.
        let facts = adapter
            .network_config()
            .query_link_facts()
            .await
            .map_err(|_| refusal(&CpError::Unreachable))?;
        let nat64 = nat64_of(facts.families.nat64());
        let families = AttachFamilies {
            v4: facts.families.carries(AddressFamily::V4),
            v6: facts.families.carries(AddressFamily::V6),
            // The flag tracks the prefix this binding can actually *use*, not
            // the one the host discovered. A prefix at a length rung 1 cannot
            // synthesize with is no prefix here — see `nat64_of`.
            nat64: nat64.is_some(),
        };

        // (3) ADR-0010 R1, as one question over both families rather than two
        // questions asked separately.
        //
        // **Uninhabitable through the seam today, and deliberately kept.**
        // `UnderlayFamilies` has no variant carrying neither family, so no
        // adapter can currently reach this refusal. It is here for the reason
        // the `EarlyData` match inside `QuicControlTransport::attach` is:
        // widening the seam should fail at this line rather than silently
        // produce a transport with nothing to race. It is not merely
        // decorative — dropping an unusable PREF64 above already moves
        // `families.nat64` to false, and this is where a v6-only host that has
        // lost its only route to a v4-only front-end would be caught.
        if !families.can_attach() {
            return Err(refusal(&CpError::Unreachable));
        }

        let names = enrolment.coordination_names();
        let transport = QuicControlTransport::new(
            env.clone(),
            identity,
            enrolment.pins,
            enrolment.endpoints,
            nat64,
        )
        .map_err(|e| refusal(&e))?;

        Ok(Self {
            transport: Arc::new(transport),
            names,
            families,
        })
    }

    /// Builds a binding over an already-constructed transport.
    ///
    /// The seam a lab harness enters at. It takes the placement facts
    /// explicitly rather than re-deriving them, because a scripted transport has
    /// no host to derive them from.
    #[must_use]
    pub fn over(
        transport: Arc<dyn ControlTransport>,
        coordination_names: Vec<String>,
        families: AttachFamilies,
    ) -> Self {
        Self {
            transport,
            names: coordination_names,
            families,
        }
    }

    /// The bound transport, for a `ControlPlaneClient`'s `ClientParts`.
    #[must_use]
    pub fn transport(&self) -> Arc<dyn ControlTransport> {
        Arc::clone(&self.transport)
    }

    /// Which families this host has, as the ladder will race them.
    #[must_use]
    pub const fn families(&self) -> AttachFamilies {
        self.families
    }

    /// The config one rung-1 attach runs under.
    ///
    /// `Rung::Quic` is a literal here and that is the honest spelling: rungs 2
    /// to 4 have no implementation anywhere in the workspace, so a binding that
    /// walked `Rung::LADDER` would fall through three rungs that refuse
    /// immediately and report a ladder exhaustion that never happened.
    #[must_use]
    pub fn attach_config(&self, mobile_background: bool) -> TransportConfig {
        TransportConfig::new(
            self.names.clone(),
            self.families,
            Rung::Quic,
            mobile_background,
        )
    }

    /// Attaches one control connection carrying both C1 and C2 (ADR-0002 N-1).
    ///
    /// # Errors
    ///
    /// `CONTROL.UNREACHABLE` when rung 1 did not come up inside its 3 s budget,
    /// and `CONTROL.HANDSHAKE_REJECTED` when a candidate completed a handshake
    /// attempt and it was refused — an unknown device key on the server's side,
    /// or a **pin mismatch** on ours. The two are kept apart because an operator
    /// does different things about them, and neither is ever a fallback to an
    /// unauthenticated channel.
    pub async fn attach(
        &self,
        mobile_background: bool,
    ) -> Result<Box<dyn ControlConnection>, Box<Diagnostic>> {
        let config = self.attach_config(mobile_background);
        self.transport
            .attach(&config)
            .await
            .map_err(|e| refusal(&CpError::from(e)))
    }
}

/// One `CpError` → the boxed, registered diagnostic this module refuses with.
///
/// `CpError::diagnostic` is reused rather than rebuilt so that the code and its
/// declared evidence stay one decision. `ownership.md` §6 rule 12 asks that
/// every exposed error be a registered code; a second builder here would be a
/// second place for that mapping to drift.
///
/// Boxed because `Diagnostic` carries an `EvidenceSet` and the crate's error
/// type is `Box<Diagnostic>` throughout — `Core::create` and `Core::submit`
/// return the same shape, so a caller matches on one type.
#[allow(clippy::unnecessary_box_returns)]
fn refusal(err: &CpError) -> Box<Diagnostic> {
    Box::new(err.diagnostic())
}

/// The host's discovered PREF64, in the shape rung 1 can synthesize with.
///
/// **Only `/96`.** RFC 6052 §2.2 defines six prefix lengths;
/// `twinvpn_cp_client::quic::Nat64Prefix` accepts only `/96` and says why — it
/// is what RFC 8781 advertises in practice, and the only length where the
/// embedded IPv4 address is a contiguous suffix. A host that reports one of the
/// other five is **not** silently coerced: the prefix is dropped, `nat64` goes
/// false, and the finding is logged. Guessing the bit-shuffling around the
/// u-octet on a path that has never had a prefix to test it with would be a code
/// path that cannot be exercised, which is not a capability.
///
/// The `/96` base address is recovered by synthesizing `0.0.0.0` into the
/// prefix: `Nat64Prefix::new` already refuses any prefix with a set host bit, so
/// at `/96` that writes four zero octets into a suffix that is already zero and
/// yields the prefix itself.
fn nat64_of(prefix: Option<twinvpn_types::Nat64Prefix>) -> Option<Nat64Prefix> {
    let prefix = prefix?;
    if prefix.prefix_len() != 96 {
        tracing::warn!(
            prefix_len = prefix.prefix_len(),
            "PREF64 at a length rung 1 cannot synthesize with; attaching without NAT64"
        );
        return None;
    }
    let zero = V4Addr::from_slice(&[0, 0, 0, 0]).ok()?;
    let base = std::net::Ipv6Addr::from(prefix.synthesize(zero).octets());
    Nat64Prefix::from_ipv6(base).ok()
}

#[cfg(test)]
mod tests {
    use super::{nat64_of, ControlEndpoint, ControlPlaneEnrolment};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn endpoint() -> ControlEndpoint {
        ControlEndpoint::new(
            "cp.test.invalid".to_owned(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)],
        )
        .expect("one address")
    }

    #[test]
    fn an_empty_pin_set_is_refused_before_a_socket_is_bound() {
        let err = ControlPlaneEnrolment::new(Vec::new(), vec![endpoint()])
            .expect_err("nothing is pinned");
        assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
        let err = ControlPlaneEnrolment::new(vec![Vec::new()], vec![endpoint()])
            .expect_err("an empty pin");
        assert_eq!(err.code().as_str(), "CONTROL.HANDSHAKE_REJECTED");
    }

    #[test]
    fn no_endpoint_is_unreachable_rather_than_a_rejected_handshake() {
        // The two refusals are different facts: nothing to attach to, versus a
        // configuration that could never authenticate. Collapsing them would
        // send an operator to the wrong half of the problem.
        let err = ControlPlaneEnrolment::new(vec![vec![1, 2, 3]], Vec::new())
            .expect_err("nowhere to attach");
        assert_eq!(err.code().as_str(), "CONTROL.UNREACHABLE");
    }

    #[test]
    fn the_names_come_from_the_endpoints_and_cannot_disagree_with_them() {
        let enrolment =
            ControlPlaneEnrolment::new(vec![vec![9]], vec![endpoint()]).expect("one pin");
        assert_eq!(enrolment.coordination_names(), vec!["cp.test.invalid"]);
        assert_eq!(enrolment.pin_count(), 1);
    }

    #[test]
    fn a_well_known_pref64_survives_and_a_shorter_prefix_is_dropped() {
        let well_known = twinvpn_types::Nat64Prefix::well_known();
        assert_eq!(well_known.prefix_len(), 96);
        assert_eq!(
            nat64_of(Some(well_known)),
            Some(super::Nat64Prefix::WELL_KNOWN),
            "64:ff9b::/96 round-trips through the two representations"
        );
        assert_eq!(nat64_of(None), None);

        // RFC 6052 permits /64; rung 1's synthesizer does not. Dropped, never
        // coerced — a guessed u-octet shuffle would attach to an address the
        // operator did not configure.
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        let sixty_four = twinvpn_types::Nat64Prefix::new(octets, 64).expect("canonical /64");
        assert_eq!(nat64_of(Some(sixty_four)), None);
    }
}
