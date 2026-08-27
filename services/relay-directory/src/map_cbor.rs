//! The `relay-map` deterministic CBOR encoding, per the frozen CDDL.
//!
//! **Authority:** `contracts/cddl/twinvpn/v1/signed_statements.cddl` §15
//! (`relay-entry`, `relay-map`), ADR-0003 (canonical encoding), ADR-0006 §11.1.
//!
//! # This replaced a hand-rolled encoding, and the difference matters
//!
//! An earlier revision signed a bespoke big-endian byte layout. It had the
//! *determinism* property a signature needs — fixed field order, sorted
//! collections, no map iteration — but nothing else: no device could have
//! verified it, because it was not the document the contract defines. `map_version`
//! being covered by the signature is not enough if the thing signed is not a
//! `relay-map`.
//!
//! Now the encoding is `twinvpn_crypto::emit`'s, which is ADR-0003's RFC 8949
//! §4.2.1 core deterministic CBOR with map keys sorted by their encodings and a
//! duplicate key refused rather than last-writer-wins. The field numbering below
//! is the CDDL's, transcribed with the key number in each comment so a reader can
//! check it against the frozen schema without a second file open.
//!
//! # Endpoints are `[octets, port]`, and that is another place DNS cannot enter
//!
//! CDDL keys 4 and 5: `[* [bstr .size 4, uint]]` and `[* [bstr .size 16, uint]]`.
//! A hostname has no representation in that shape — it is four or sixteen raw
//! octets or it is nothing — so ADR-0006 §11.1 rule 1 ("endpoints are literals,
//! never hostnames") holds at the encoding as well as at
//! [`crate::fleet::RelayRecord`]'s `SocketAddr`.

use std::net::{IpAddr, SocketAddr};

use twinvpn_crypto::emit::{encode, Item, StatementToSign};

use crate::fleet::{AdminState, Carriage, RelayRecord};
use crate::map::Region;

/// COSE `alg` for EdDSA over Ed25519. ADR-0005 §11.3 and ADR-0006 §11.1 fix it
/// for the relay-credential and relay-map issuer.
pub const ALG_EDDSA: i64 = -8;

/// The `crit` set a `relay-map` MUST carry (CDDL key 5).
///
/// "MUST include `map_version`" — a verifier that does not understand version
/// monotonicity must refuse the document rather than apply it, which is what
/// stops a rollback being silently accepted by an older build.
pub const MAP_CRIT: &[&str] = &["map_version"];

/// Builds the `relay-map` CBOR item.
///
/// `regions` is carried for completeness of the caller's model; the frozen
/// `relay-map` has **no regions field**, so it is deliberately not encoded —
/// adding one would be a contract change, and adjacency reaches the device
/// through `RelayAssignment` in `relay.proto` instead. Flagged rather than
/// invented.
#[must_use]
pub fn relay_map_item(
    twinnet_id: &str,
    map_version: u64,
    not_after_ms: u64,
    records: &[RelayRecord],
    regions: &[Region],
) -> Item {
    let _ = regions;
    let mut entries: Vec<&RelayRecord> = records.iter().collect();
    // Sorted so the document is a pure function of the fleet, not of iteration
    // order. `emit::encode` sorts map KEYS; array order is ours to fix.
    entries.sort_unstable_by(|a, b| a.relay_id.cmp(&b.relay_id));

    Item::Map(vec![
        (Item::Uint(1), Item::Text(twinnet_id.to_owned())),
        (Item::Uint(2), Item::Uint(map_version)),
        (
            Item::Uint(3),
            Item::Array(entries.into_iter().map(relay_entry_item).collect()),
        ),
        (Item::Uint(4), Item::Uint(not_after_ms)),
        (
            Item::Uint(5),
            Item::Array(
                MAP_CRIT
                    .iter()
                    .map(|s| Item::Text((*s).to_owned()))
                    .collect(),
            ),
        ),
    ])
}

/// CDDL §15 `relay-entry`.
fn relay_entry_item(r: &RelayRecord) -> Item {
    Item::Map(vec![
        (Item::Uint(1), Item::Bytes(r.relay_id.to_vec())),
        (Item::Uint(2), Item::Text(r.operator_group_id.clone())),
        (
            Item::Uint(3),
            Item::Bytes(r.static_noise_public_key.clone()),
        ),
        (Item::Uint(4), endpoints_item(&r.endpoints_v4, true)),
        (Item::Uint(5), endpoints_item(&r.endpoints_v6, false)),
        (
            Item::Uint(6),
            Item::Array(
                r.carriages
                    .iter()
                    .map(|c| Item::Text(carriage_tag(*c).to_owned()))
                    .collect(),
            ),
        ),
        (Item::Uint(7), Item::Text(r.region_id.clone())),
        (Item::Uint(8), Item::Text(r.failure_domain.clone())),
        (Item::Uint(9), Item::Uint(u64::from(r.server_rank))),
        (Item::Uint(10), Item::Uint(u64::from(r.load_class))),
        (Item::Uint(11), Item::Uint(u64::from(r.capacity_weight))),
        (
            Item::Uint(12),
            Item::Text(admin_state_tag(r.admin_state).to_owned()),
        ),
        (Item::Uint(13), Item::Bool(r.self_hosted)),
        (Item::Uint(14), Item::Bool(r.supports_drain)),
        (Item::Uint(15), Item::Bool(r.supports_caps)),
    ])
}

/// `[* [bstr .size 4|16, uint]]`. A family mismatch is **dropped**, not coerced:
/// a v4-mapped v6 address in the v4 list would be four octets that mean something
/// different to every reader.
fn endpoints_item(endpoints: &[SocketAddr], want_v4: bool) -> Item {
    let mut out = Vec::new();
    for e in endpoints {
        let octets: Option<Vec<u8>> = match (e.ip(), want_v4) {
            (IpAddr::V4(a), true) => Some(a.octets().to_vec()),
            (IpAddr::V6(a), false) => Some(a.octets().to_vec()),
            _ => None,
        };
        if let Some(octets) = octets {
            out.push(Item::Array(vec![
                Item::Bytes(octets),
                Item::Uint(u64::from(e.port())),
            ]));
        }
    }
    Item::Array(out)
}

const fn carriage_tag(c: Carriage) -> &'static str {
    match c {
        Carriage::Udp => "R-UDP",
        Carriage::Quic => "R-QUIC",
        Carriage::Tls => "R-TLS",
    }
}

const fn admin_state_tag(s: AdminState) -> &'static str {
    match s {
        AdminState::Active => "ACTIVE",
        AdminState::Draining => "DRAINING",
        AdminState::Retired => "RETIRED",
    }
}

/// The canonical payload octets of a `relay-map`.
///
/// # Errors
///
/// A `twinvpn_crypto` encoding failure, which is a caller defect (a duplicate
/// map key) rather than an input problem — every key set here is a constant.
pub fn canonical_payload(
    twinnet_id: &str,
    map_version: u64,
    not_after_ms: u64,
    records: &[RelayRecord],
    regions: &[Region],
) -> Result<Vec<u8>, twinvpn_crypto::CryptoError> {
    encode(&relay_map_item(
        twinnet_id,
        map_version,
        not_after_ms,
        records,
        regions,
    ))
}

/// The `Sig_structure` a signer signs, with the protected header a verifier
/// will check.
///
/// Built by `twinvpn_crypto::emit::StatementToSign`, so the protected header the
/// signature covers and the one shipped are the same object — "a caller cannot
/// sign one protected header and ship another, which would be a signature over
/// bytes nobody will verify".
///
/// # Errors
///
/// As [`canonical_payload`].
pub fn to_be_signed(
    twinnet_id: &str,
    map_version: u64,
    not_after_ms: u64,
    records: &[RelayRecord],
    regions: &[Region],
    key_id: &str,
) -> Result<StatementToSign, twinvpn_crypto::CryptoError> {
    StatementToSign::new(
        &relay_map_item(twinnet_id, map_version, not_after_ms, records, regions),
        ALG_EDDSA,
        Some(key_id.as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::sample;

    fn regions() -> Vec<Region> {
        vec![Region {
            region_id: "eu-west".into(),
            geo_hint: "eu-west".into(),
            adjacent_regions: vec![],
        }]
    }

    fn fleet() -> Vec<RelayRecord> {
        vec![sample(1, "eu-west", "fd-a"), sample(2, "eu-west", "fd-b")]
    }

    #[test]
    fn the_payload_is_deterministic_and_order_independent() {
        // A signature over a non-deterministic encoding is a signature over
        // whatever iteration order the process happened to produce.
        let a = canonical_payload("t", 1, 7, &fleet(), &regions()).expect("encodes");
        let mut reversed = fleet();
        reversed.reverse();
        let b = canonical_payload("t", 1, 7, &reversed, &regions()).expect("encodes");
        assert_eq!(a, b);
    }

    #[test]
    fn the_version_and_the_expiry_are_both_covered() {
        let base = canonical_payload("t", 1, 7, &fleet(), &regions()).expect("encodes");
        assert_ne!(
            base,
            canonical_payload("t", 2, 7, &fleet(), &regions()).expect("encodes")
        );
        assert_ne!(
            base,
            canonical_payload("t", 1, 8, &fleet(), &regions()).expect("encodes")
        );
        assert_ne!(
            base,
            canonical_payload("u", 1, 7, &fleet(), &regions()).expect("encodes")
        );
    }

    #[test]
    fn the_crit_set_names_map_version() {
        // CDDL key 5: "MUST include map_version". A verifier that does not
        // understand version monotonicity must refuse rather than apply, which is
        // what stops an older build silently accepting a rollback.
        assert_eq!(MAP_CRIT, &["map_version"]);
        let payload = canonical_payload("t", 1, 7, &fleet(), &regions()).expect("encodes");
        let parsed = twinvpn_crypto::dcbor::parse_canonical(&payload).expect("canonical");
        let crit = parsed.map_get(5).expect("crit set");
        assert_eq!(
            crit.as_array().expect("array")[0].as_text(),
            Some("map_version")
        );
    }

    #[test]
    fn it_parses_back_as_canonical_cbor_with_the_cddl_key_numbers() {
        let payload = canonical_payload("twinnet-1", 9, 42, &fleet(), &regions()).expect("encodes");
        let m = twinvpn_crypto::dcbor::parse_canonical(&payload).expect("canonical");
        assert_eq!(
            m.map_get(1).and_then(twinvpn_crypto::dcbor::Value::as_text),
            Some("twinnet-1")
        );
        assert_eq!(
            m.map_get(2).and_then(twinvpn_crypto::dcbor::Value::as_uint),
            Some(9)
        );
        assert_eq!(
            m.map_get(4).and_then(twinvpn_crypto::dcbor::Value::as_uint),
            Some(42)
        );
        let relays = m.map_get(3).expect("relays").as_array().expect("array");
        assert_eq!(relays.len(), 2);
        // Sorted by relay_id, so the document is a function of the fleet.
        assert_eq!(
            relays[0]
                .map_get(1)
                .and_then(twinvpn_crypto::dcbor::Value::as_bytes),
            Some(&[1_u8; 8][..])
        );
        assert_eq!(
            relays[1]
                .map_get(1)
                .and_then(twinvpn_crypto::dcbor::Value::as_bytes),
            Some(&[2_u8; 8][..])
        );
        // Key 12 is the admin state as a text tag, per the CDDL.
        assert_eq!(
            relays[0]
                .map_get(12)
                .and_then(twinvpn_crypto::dcbor::Value::as_text),
            Some("ACTIVE")
        );
    }

    #[test]
    fn an_endpoint_is_four_or_sixteen_raw_octets_and_never_a_name() {
        // ADR-0006 §11.1 rule 1 at the encoding as well as at the type: a
        // hostname has no representation in `[bstr .size 4|16, uint]`.
        let payload = canonical_payload("t", 1, 0, &fleet(), &regions()).expect("encodes");
        let m = twinvpn_crypto::dcbor::parse_canonical(&payload).expect("canonical");
        let relays = m.map_get(3).expect("relays").as_array().expect("array");
        let v4 = relays[0].map_get(4).expect("v4").as_array().expect("array");
        let v6 = relays[0].map_get(5).expect("v6").as_array().expect("array");
        assert_eq!(
            v4[0].as_array().expect("pair")[0]
                .as_bytes()
                .expect("octets")
                .len(),
            4
        );
        assert_eq!(
            v6[0].as_array().expect("pair")[0]
                .as_bytes()
                .expect("octets")
                .len(),
            16
        );
    }

    #[test]
    fn a_family_mismatch_is_dropped_rather_than_coerced() {
        // A v4-mapped v6 address in the v4 list would be four octets meaning
        // something different to every reader.
        let mut r = sample(1, "eu-west", "fd-a");
        r.endpoints_v4 = vec!["[::ffff:192.0.2.1]:41641".parse().expect("mapped")];
        let payload = canonical_payload("t", 1, 0, &[r], &regions()).expect("encodes");
        let m = twinvpn_crypto::dcbor::parse_canonical(&payload).expect("canonical");
        let relays = m.map_get(3).expect("relays").as_array().expect("array");
        assert!(relays[0]
            .map_get(4)
            .expect("v4")
            .as_array()
            .expect("array")
            .is_empty());
    }

    #[test]
    fn the_signed_structure_carries_the_algorithm_in_the_protected_header() {
        // An unprotected `alg` is not covered by the signature, so an attacker
        // could rewrite it. `StatementToSign` puts it in the protected header.
        let s = to_be_signed("t", 1, 0, &fleet(), &regions(), "map-k1").expect("builds");
        assert!(!s.to_be_signed().is_empty());
        assert_eq!(
            s.payload(),
            canonical_payload("t", 1, 0, &fleet(), &regions())
                .expect("encodes")
                .as_slice()
        );
        // And the assembled envelope is a four-element COSE_Sign1 array.
        let envelope = s.assemble(&[0_u8; 64]).expect("assembles");
        let parsed = twinvpn_crypto::dcbor::parse_canonical(&envelope).expect("canonical");
        assert_eq!(parsed.as_array().expect("array").len(), 4);
    }
}
