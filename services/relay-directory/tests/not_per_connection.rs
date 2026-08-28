//! **A per-connection dependency on this service must not be expressible.**
//!
//! ADR-0006 C1 and §11.3 rule 4; architecture §2.12; and `relay.proto`'s CF-7
//! entry, which is the sharpest statement of it:
//!
//! > The RESERVATION is a synchronous resource acquisition made DIRECTLY WITH THE
//! > RELAY, not through the coordination service: routing reservations through
//! > coordination would put the control plane in the data path and **BREAK I5**.
//!
//! The ranked set is *cached state*. A device that must call this service to open
//! a connection cannot fail over during a control-plane outage, which is exactly
//! what ADR-0006 §11.9 exists to guarantee it can do.
//!
//! So the checks below are about **what cannot be written**, not about what the
//! current handler happens to do:
//!
//! - one route, and it serves one whole document;
//! - its only input is an operator group, which every device in a fleet shares;
//! - no request body, no query string, no per-connection identifier anywhere in
//!   the surface;
//! - the served bytes are identical for every caller, so an edge cache or a CDN
//!   can answer instead — which is `infra/README.md` §4.7's availability argument
//!   and is only true because there is nothing per-caller to vary on.

use std::path::Path;
use std::sync::{Arc, RwLock};

use twinvpn_relay_directory::api::{render, router, MapCache, MAP_ROUTE};
use twinvpn_relay_directory::fleet::{AdminState, Carriage, RelayRecord};
use twinvpn_relay_directory::map::{MapBuilder, PublicationFloor, Region, RelayMap};
use twinvpn_relay_directory::sign::{MapSigner, SignError};

fn api_source() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api.rs");
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let end = s.find("#[cfg(test)]").unwrap_or(s.len());
    s[..end]
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_device_facing_surface_is_exactly_one_route() {
    let src = api_source();
    assert_eq!(
        src.matches(".route(").count(),
        1,
        "a second device-facing route is how a per-connection call arrives"
    );
    assert!(src.contains(MAP_ROUTE));
}

#[test]
fn the_route_takes_no_per_connection_input_of_any_kind() {
    let src = api_source();

    // No extractor that can carry a body, a query or a header value.
    for forbidden in [
        "Query<",
        "Json<",
        "Form<",
        "Bytes>",
        "TypedHeader",
        "Request<",
    ] {
        assert!(
            !src.contains(forbidden),
            "api.rs uses `{forbidden}`: the handler must take no request input \
             beyond the operator group, so no future field can name a session, a \
             peer, a pair_tag or a relay"
        );
    }

    // Exactly one path parameter, and it is the operator group.
    assert_eq!(MAP_ROUTE.matches('{').count(), 1);
    assert!(MAP_ROUTE.contains("{operator_group_id}"));

    // Nothing per-connection is even nameable in the module.
    for forbidden in [
        "session_id",
        "device_id",
        "peer_id",
        "peer_key_id",
        "pair_tag",
        "flow_id",
        "candidate",
        "reserve",
        "Reserve",
    ] {
        assert!(
            !src.contains(forbidden),
            "api.rs names `{forbidden}`. A surface that can accept a connection's \
             identifiers is a surface that will eventually be called per \
             connection, and CF-7 says that breaks I5."
        );
    }
}

#[test]
fn the_router_builds_and_holds_only_the_cache() {
    // Construction is the behavioural half: the router's state is a map cache and
    // nothing else — no database handle, no control-plane client, no relay client.
    let cache: Arc<RwLock<MapCache>> = Arc::new(RwLock::new(MapCache::new()));
    cache.write().expect("lock").put(published(1));
    let _app = router(Arc::clone(&cache));
    assert_eq!(cache.read().expect("lock").len(), 1);
}

#[test]
fn every_caller_in_a_group_receives_identical_bytes() {
    // The cacheability property, and the reason the map "does not share a failure
    // domain with the control-plane database" (ADR-0006 §10). It holds only
    // because there is nothing per-caller to vary on.
    let map = published(7);
    let a = render(&map);
    let b = render(&map);
    assert_eq!(a, b);
    assert!(!a.is_empty());
}

#[test]
fn the_whole_ranked_set_is_served_at_once_so_it_can_be_cached() {
    // A device receives every candidate in one document. That is what makes the
    // set CACHED STATE — the precondition for relay failover with the control
    // plane down (ADR-0006 §11.9).
    let map = published(1);
    assert!(
        map.relays.len() >= 2,
        "a cached set of size 1 is a design error (architecture §2.12)"
    );
    // Including relays that are not currently the best choice: selection is a
    // reordering, never a filter (§11.3 rule 1).
    assert!(map
        .relays
        .iter()
        .any(|r| r.admin_state == AdminState::Active));
}

#[test]
fn the_service_publishes_no_computed_score() {
    // §12: the server's global view is a BIAS, not a decision. Publishing a
    // computed ranking would make it authoritative in practice however labelled,
    // and S-31 says the client's own measurement wins.
    let src = api_source();
    for forbidden in ["score", "rank::", "ServerAdvice", "Measured"] {
        assert!(
            !src.contains(forbidden),
            "api.rs serves `{forbidden}`: only server_rank, load_class, \
             capacity_weight and admin_state are published"
        );
    }
    let map = published(1);
    let bytes = render(&map);
    // The rendered document carries the raw advisory inputs, not a verdict.
    assert!(!bytes.is_empty());
}

// --- helpers ---------------------------------------------------------------

struct FixedSigner;
impl MapSigner for FixedSigner {
    fn sign(&self, b: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(b.len().to_be_bytes().to_vec())
    }
    fn key_id(&self) -> &str {
        "map-k1"
    }
}

fn record(id: u8, domain: &str) -> RelayRecord {
    RelayRecord {
        relay_id: [id; twinvpn_schema::limits::RELAY_ID_BYTES],
        operator_group_id: "local-operator".into(),
        region_id: "eu-west".into(),
        static_noise_public_key: vec![id; 32],
        endpoints_v4: vec!["192.0.2.1:41641".parse().expect("v4")],
        endpoints_v6: vec!["[2001:db8::1]:41641".parse().expect("v6")],
        carriages: vec![Carriage::Udp, Carriage::Quic, Carriage::Tls],
        failure_domain: domain.into(),
        server_rank: 50,
        load_class: 0,
        capacity_weight: 100,
        admin_state: AdminState::Active,
        self_hosted: false,
        supports_drain: true,
        supports_caps: true,
    }
}

fn published(version: u64) -> RelayMap {
    let mut b = MapBuilder::new(
        "local-operator".into(),
        PublicationFloor::default(),
        3_600_000,
    );
    b.publish(
        vec![record(1, "fd-a"), record(2, "fd-b")],
        vec![Region {
            region_id: "eu-west".into(),
            geo_hint: "eu-west".into(),
            adjacent_regions: vec![("eu-central".into(), 25, 1)],
        }],
        version,
        1_000,
        &FixedSigner,
    )
    .expect("publishes")
}
