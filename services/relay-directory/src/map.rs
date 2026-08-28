//! The published `RelayMap`, and the floor that decides whether it may be published.
//!
//! ADR-0006 §11.1 and §10. The publication invariant is the one that matters:
//!
//! > The relay-selection service MUST refuse to publish a map in which any
//! > `RelayRegion` with live sessions falls below **2 `ACTIVE` relays in ≥2
//! > distinct `failure_domain`s**.
//!
//! architecture §2.12 states the consequence for the device side: **"a cached set
//! of size 1 is a design error."** [`PublicationFloor::check`] is where that stops
//! being a sentence.
//!
//! # The map is stale-but-usable without limit
//!
//! §11.1 rule 4, and `infra/README.md` §4.7 marks
//! `TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED` "must stay false":
//!
//! > Past `not_after_ms` the device continues to use it unchanged and emits
//! > ADR-0009's `CONTROL.STALENESS.RELAY_SET_EXPIRED`. **No expiry, at any age,
//! > may reduce the candidate set or block an attempt.**
//!
//! So `not_after_ms` is carried as **soft freshness only** and nothing in this
//! crate compares it to a clock. [`RelayMap`] has no `is_expired` method, because
//! a method like that is how an expiry check appears three refactors later.

use crate::fleet::{AdminState, RelayRecord};
use crate::sign::{MapSigner, SignError};

/// One region and its ordered fallbacks (`relay.proto RelayRegion`).
#[derive(Debug, Clone)]
pub struct Region {
    /// Opaque to a device: `relay.proto` says a device "MUST NOT parse it for
    /// geography and MUST NOT rank by string comparison".
    pub region_id: String,
    /// A continent-scale display hint. Never a coordinate, never a city.
    pub geo_hint: String,
    /// `(region_id, added_rtt_ms_p50, order)`.
    pub adjacent_regions: Vec<(String, u32, u32)>,
}

/// A publishable relay map.
#[derive(Debug, Clone)]
pub struct RelayMap {
    /// Strictly monotone. A lower version MUST be refused by a receiver.
    pub map_version: u64,
    /// When it was built.
    pub issued_at_ms: u64,
    /// **Soft freshness only.** Expiry has no enforcement effect (ADR-0009 §11.4).
    pub not_after_ms: u64,
    /// Matches the `aud` of a `RelayCapabilityToken`.
    pub operator_group_id: String,
    /// The regions.
    pub regions: Vec<Region>,
    /// The relays. Retired entries are included so a device learns an id is gone
    /// rather than merely missing.
    pub relays: Vec<RelayRecord>,
    /// The issuer key id that signed it.
    pub signer_key_id: String,
    /// The complete COSE_Sign1 envelope: protected header, payload and signature,
    /// assembled by `twinvpn_crypto::emit` so it is the document a device's
    /// `verify_cose_sign1` will accept — not a signature beside some bytes.
    pub cose_sign1: Vec<u8>,
}

/// Why a map could not be published.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// A region with live sessions has fewer than 2 `ACTIVE` relays.
    #[error("region {region}: {found} ACTIVE relays, floor is {floor}")]
    TooFewAlternates {
        /// Which region.
        region: String,
        /// How many were found.
        found: usize,
        /// The configured floor.
        floor: usize,
    },
    /// A region with live sessions spans fewer than 2 `failure_domain`s.
    #[error("region {region}: {found} failure domains, floor is {floor}")]
    TooFewFailureDomains {
        /// Which region.
        region: String,
        /// How many were found.
        found: usize,
        /// The configured floor.
        floor: usize,
    },
    /// A region does not publish relays reachable over **both** families.
    #[error("region {region}: not reachable over both address families")]
    NotDualStack {
        /// Which region.
        region: String,
    },
    /// The map version did not strictly increase.
    #[error("map_version must strictly increase: {proposed} is not above {current}")]
    VersionNotMonotone {
        /// What was proposed.
        proposed: u64,
        /// What is already published.
        current: u64,
    },
    /// It could not be signed. An unsigned map is never published.
    #[error(transparent)]
    Unsigned(#[from] SignError),
}

/// ADR-0006 §11.1 rule 3's floor, from `TWINVPN_RELAYDIR_MIN_*`.
#[derive(Debug, Clone, Copy)]
pub struct PublicationFloor {
    /// `TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION`, frozen at 2.
    pub min_alternates_per_region: usize,
    /// `TWINVPN_RELAYDIR_MIN_FAILURE_DOMAINS_PER_REGION`, frozen at 2.
    pub min_failure_domains_per_region: usize,
    /// `TWINVPN_RELAYDIR_REQUIRE_BOTH_FAMILIES`, frozen true except in the
    /// v4-only and v6-only compose overrides, "where the relaxation is visible in
    /// configuration".
    pub require_both_families: bool,
}

impl Default for PublicationFloor {
    fn default() -> Self {
        Self {
            min_alternates_per_region: 2,
            min_failure_domains_per_region: 2,
            require_both_families: true,
        }
    }
}

impl PublicationFloor {
    /// Checks every region in `records` against the floor.
    ///
    /// # Errors
    ///
    /// [`PublishError`] naming the first region that fails and by how much, so an
    /// operator learns *which* region is short rather than that "publication
    /// failed".
    pub fn check(&self, records: &[RelayRecord]) -> Result<(), PublishError> {
        let mut regions: Vec<&str> = records.iter().map(|r| r.region_id.as_str()).collect();
        regions.sort_unstable();
        regions.dedup();

        for region in regions {
            let active: Vec<&RelayRecord> = records
                .iter()
                .filter(|r| r.region_id == region && r.admin_state == AdminState::Active)
                .collect();

            if active.len() < self.min_alternates_per_region {
                return Err(PublishError::TooFewAlternates {
                    region: region.to_owned(),
                    found: active.len(),
                    floor: self.min_alternates_per_region,
                });
            }

            let mut domains: Vec<&str> = active.iter().map(|r| r.failure_domain.as_str()).collect();
            domains.sort_unstable();
            domains.dedup();
            if domains.len() < self.min_failure_domains_per_region {
                return Err(PublishError::TooFewFailureDomains {
                    region: region.to_owned(),
                    found: domains.len(),
                    floor: self.min_failure_domains_per_region,
                });
            }

            if self.require_both_families {
                let has_v4 = active.iter().any(|r| !r.endpoints_v4.is_empty());
                let has_v6 = active.iter().any(|r| !r.endpoints_v6.is_empty());
                if !has_v4 || !has_v6 {
                    return Err(PublishError::NotDualStack {
                        region: region.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Builds and signs a map, refusing to publish one that breaches the floor.
#[derive(Debug)]
pub struct MapBuilder {
    operator_group_id: String,
    floor: PublicationFloor,
    ttl_ms: u64,
    current_version: u64,
}

impl MapBuilder {
    /// A builder for `operator_group_id`.
    #[must_use]
    pub fn new(operator_group_id: String, floor: PublicationFloor, ttl_ms: u64) -> Self {
        Self {
            operator_group_id,
            floor,
            ttl_ms,
            current_version: 0,
        }
    }

    /// The version currently published.
    #[must_use]
    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// Builds, checks and signs the next map.
    ///
    /// The order is deliberate: **floor first, signature last**. Signing a map
    /// that then fails the floor would leave a signed document nobody may publish
    /// lying around, and a signature is the expensive step.
    ///
    /// # Errors
    ///
    /// [`PublishError`] for a floor breach, a non-monotone version, or an absent
    /// signer.
    pub fn publish(
        &mut self,
        records: Vec<RelayRecord>,
        regions: Vec<Region>,
        version: u64,
        now_ms: u64,
        signer: &dyn MapSigner,
    ) -> Result<RelayMap, PublishError> {
        if version <= self.current_version {
            return Err(PublishError::VersionNotMonotone {
                proposed: version,
                current: self.current_version,
            });
        }
        self.floor.check(&records)?;

        let not_after_ms = now_ms.saturating_add(self.ttl_ms);
        // The frozen `relay-map` CDDL as ADR-0003 deterministic CBOR, wrapped in
        // an RFC 9052 Sig_structure with `alg` in the PROTECTED header.
        let unsigned = crate::map_cbor::to_be_signed(
            &self.operator_group_id,
            version,
            not_after_ms,
            &records,
            &regions,
            signer.key_id(),
        )
        .map_err(|_| PublishError::Unsigned(SignError::Encoding))?;
        let signature = signer.sign(unsigned.to_be_signed())?;
        let cose_sign1 = unsigned
            .assemble(&signature)
            .map_err(|_| PublishError::Unsigned(SignError::Encoding))?;

        self.current_version = version;
        Ok(RelayMap {
            map_version: version,
            issued_at_ms: now_ms,
            not_after_ms,
            operator_group_id: self.operator_group_id.clone(),
            regions,
            relays: records,
            signer_key_id: signer.key_id().to_owned(),
            cose_sign1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::sample;
    use crate::sign::Unsigned;

    struct FixedSigner;
    impl MapSigner for FixedSigner {
        fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, SignError> {
            Ok(canonical_bytes.len().to_be_bytes().to_vec())
        }
        fn key_id(&self) -> &str {
            "map-k1"
        }
    }

    fn healthy_region() -> Vec<RelayRecord> {
        vec![sample(1, "eu-west", "fd-a"), sample(2, "eu-west", "fd-b")]
    }

    fn regions() -> Vec<Region> {
        vec![Region {
            region_id: "eu-west".into(),
            geo_hint: "eu-west".into(),
            adjacent_regions: vec![("eu-central".into(), 25, 1)],
        }]
    }

    #[test]
    fn a_region_with_two_relays_in_two_domains_publishes() {
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        let m = b
            .publish(healthy_region(), regions(), 1, 1_000, &FixedSigner)
            .expect("publishes");
        assert_eq!(m.map_version, 1);
        assert_eq!(m.signer_key_id, "map-k1");
        // A real four-element COSE_Sign1 array, not a signature beside some bytes.
        let parsed = twinvpn_crypto::dcbor::parse_canonical(&m.cose_sign1).expect("canonical");
        assert_eq!(parsed.as_array().expect("array").len(), 4);
    }

    #[test]
    fn a_cached_set_of_size_one_is_refused_at_publication() {
        // architecture §2.12: "a cached set of size 1 is a design error". This is
        // where that stops being a sentence.
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        let e = b
            .publish(
                vec![sample(1, "eu-west", "fd-a")],
                regions(),
                1,
                0,
                &FixedSigner,
            )
            .unwrap_err();
        assert_eq!(
            e,
            PublishError::TooFewAlternates {
                region: "eu-west".into(),
                found: 1,
                floor: 2
            }
        );
    }

    #[test]
    fn two_relays_in_one_failure_domain_are_not_two_alternates() {
        // A standby that fails with its primary is not a standby (ADR-0006 §11.6).
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        let e = b
            .publish(
                vec![sample(1, "eu-west", "fd-a"), sample(2, "eu-west", "fd-a")],
                regions(),
                1,
                0,
                &FixedSigner,
            )
            .unwrap_err();
        assert_eq!(
            e,
            PublishError::TooFewFailureDomains {
                region: "eu-west".into(),
                found: 1,
                floor: 2
            }
        );
    }

    #[test]
    fn draining_relays_do_not_count_toward_the_floor() {
        // §10: retiring is a TWO-STEP operation — publish DRAINING, wait, then
        // publish RETIRED "in a map that still satisfies the floor". A DRAINING
        // relay is still usable but is not an alternate for floor purposes.
        let mut records = healthy_region();
        records[1].admin_state = AdminState::Draining;
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        assert!(matches!(
            b.publish(records, regions(), 1, 0, &FixedSigner)
                .unwrap_err(),
            PublishError::TooFewAlternates { .. }
        ));
    }

    #[test]
    fn a_region_reachable_over_only_one_family_is_refused() {
        // §11.1 rule 2 / C8 / P9: every region publishes relays reachable over
        // BOTH families.
        let mut records = healthy_region();
        for r in &mut records {
            r.endpoints_v6.clear();
        }
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        assert_eq!(
            b.publish(records, regions(), 1, 0, &FixedSigner)
                .unwrap_err(),
            PublishError::NotDualStack {
                region: "eu-west".into()
            }
        );
    }

    #[test]
    fn the_single_family_relaxation_is_visible_in_configuration() {
        // infra/README.md §4.7: relaxed "only in the v4-only and v6-only
        // overrides, where the relaxation is visible in configuration".
        let mut records = healthy_region();
        for r in &mut records {
            r.endpoints_v4.clear();
        }
        let floor = PublicationFloor {
            require_both_families: false,
            ..PublicationFloor::default()
        };
        let mut b = MapBuilder::new("local-operator".into(), floor, 3_600_000);
        assert!(b.publish(records, regions(), 1, 0, &FixedSigner).is_ok());
    }

    #[test]
    fn an_unsigned_map_is_never_published() {
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        let e = b
            .publish(healthy_region(), regions(), 1, 0, &Unsigned)
            .unwrap_err();
        assert_eq!(e, PublishError::Unsigned(SignError::NoSigner));
        assert_eq!(
            b.current_version(),
            0,
            "a failed publish must not burn a map_version — a device refuses a \
             non-increasing version, so a burnt one is a permanently skipped slot"
        );
    }

    #[test]
    fn map_version_must_strictly_increase() {
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        b.publish(healthy_region(), regions(), 5, 0, &FixedSigner)
            .expect("publishes");
        for v in [0, 4, 5] {
            assert!(matches!(
                b.publish(healthy_region(), regions(), v, 0, &FixedSigner)
                    .unwrap_err(),
                PublishError::VersionNotMonotone { .. }
            ));
        }
        assert!(b
            .publish(healthy_region(), regions(), 6, 0, &FixedSigner)
            .is_ok());
    }

    #[test]
    fn expiry_has_no_enforcement_effect_anywhere_in_this_type() {
        // §11.1 rule 4: "No expiry, at any age, may reduce the candidate set or
        // block an attempt." So there is no method to call.
        let mut b = MapBuilder::new("local-operator".into(), PublicationFloor::default(), 1);
        let m = b
            .publish(healthy_region(), regions(), 1, 0, &FixedSigner)
            .expect("publishes");
        assert_eq!(m.not_after_ms, 1);
        // The map still carries every relay, and there is no `is_expired`,
        // no `valid_at`, and no clock read in this module.
        assert_eq!(m.relays.len(), 2);
        let src = include_str!("map.rs");
        let production = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        for forbidden in [
            "fn is_expired",
            "fn valid_at",
            "SystemTime::now",
            "Instant::now",
        ] {
            assert!(
                !production.contains(forbidden),
                "map.rs provides `{forbidden}`"
            );
        }
    }

    #[test]
    fn the_published_document_is_the_one_the_contract_defines() {
        // An earlier revision signed a bespoke big-endian layout. It was
        // deterministic, which a signature needs — but no device could have
        // verified it, because it was not a `relay-map`. Now the payload inside
        // the envelope parses as the frozen CDDL with its own key numbers.
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        let m = b
            .publish(healthy_region(), regions(), 4, 1_000, &FixedSigner)
            .expect("publishes");

        let envelope =
            twinvpn_crypto::dcbor::parse_canonical(&m.cose_sign1).expect("canonical envelope");
        let parts = envelope.as_array().expect("COSE_Sign1 array");
        let payload =
            twinvpn_crypto::dcbor::parse_canonical(parts[2].as_bytes().expect("payload bstr"))
                .expect("canonical payload");

        assert_eq!(
            payload
                .map_get(1)
                .and_then(twinvpn_crypto::dcbor::Value::as_text),
            Some("local-operator")
        );
        assert_eq!(
            payload
                .map_get(2)
                .and_then(twinvpn_crypto::dcbor::Value::as_uint),
            Some(4),
            "map_version is INSIDE the signed payload"
        );
        assert_eq!(
            payload
                .map_get(3)
                .expect("relays")
                .as_array()
                .expect("array")
                .len(),
            2
        );
    }

    #[test]
    fn the_signed_bytes_are_a_pure_function_of_the_fleet() {
        // A signature over a non-deterministic encoding is a signature over
        // whatever iteration order the process happened to produce.
        let mut reversed = healthy_region();
        reversed.reverse();
        let a = crate::map_cbor::canonical_payload("g", 1, 7, &healthy_region(), &regions())
            .expect("encodes");
        let b =
            crate::map_cbor::canonical_payload("g", 1, 7, &reversed, &regions()).expect("encodes");
        assert_eq!(a, b);
        assert_ne!(
            a,
            crate::map_cbor::canonical_payload("g", 2, 7, &healthy_region(), &regions())
                .expect("encodes"),
            "the version must be covered by the signature"
        );
    }
}
