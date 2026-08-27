//! The device-facing surface — **one document, no per-connection input**.
//!
//! # The property this module exists to make unexpressible
//!
//! ADR-0006 C1 and §11.3 rule 4: selection is a pure local function that "never
//! runs on the packet path", and `relay.proto` says the reservation is made
//! "DIRECTLY WITH THE RELAY, not through the coordination service: routing
//! reservations through coordination would put the control plane in the data path
//! and BREAK I5". architecture §2.12 adds that the ranked set is *cached state*,
//! so relay failover works during a control-plane outage.
//!
//! A per-connection call is therefore not merely discouraged — it must be
//! **impossible to write**. Three things make that so:
//!
//! 1. **One route.** `GET /v1/relay-map/{operator_group_id}` returns the whole
//!    signed document. There is no second route.
//! 2. **The only path parameter is an operator group** — the unit of admission,
//!    shared by every device in the fleet. There is no path, query, header or body
//!    input naming a session, a device, a peer, a `pair_tag` or a relay.
//! 3. **The handler takes no request body at all**, so no future field can smuggle
//!    one in.
//!
//! `tests/not_per_connection.rs` asserts (1)–(3) against the router and the
//! source, so adding a per-connection route fails the build rather than a review.
//!
//! # What is deliberately not served
//!
//! No computed score, no "which relay should I use", no ordering beyond the map's
//! own field order. Publishing a computed ranking would make it authoritative in
//! practice however it were labelled, and S-31 says the client's measurement wins.
//! What the device gets is the same bytes every other device gets — which is also
//! why `infra/README.md` §4.7 can call the map "cacheable at the edge, and
//! servable from a CDN".

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::map::RelayMap;

/// The one route's path template.
pub const MAP_ROUTE: &str = "/v1/relay-map/{operator_group_id}";

/// What the API serves: the most recently published map per operator group.
#[derive(Debug, Default)]
pub struct MapCache {
    published: std::collections::BTreeMap<String, Arc<RelayMap>>,
}

impl MapCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the map for an operator group.
    pub fn put(&mut self, map: RelayMap) {
        self.published
            .insert(map.operator_group_id.clone(), Arc::new(map));
    }

    /// The current map for an operator group.
    #[must_use]
    pub fn get(&self, operator_group_id: &str) -> Option<Arc<RelayMap>> {
        self.published.get(operator_group_id).cloned()
    }

    /// How many groups have a published map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.published.len()
    }

    /// Whether nothing has been published.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.published.is_empty()
    }
}

/// The shared state the one handler reads.
pub type SharedCache = Arc<std::sync::RwLock<MapCache>>;

/// The device-facing router. **One route, and it takes no per-connection input.**
pub fn router(cache: SharedCache) -> Router {
    Router::new()
        .route(MAP_ROUTE, get(serve_map))
        .with_state(cache)
}

/// Serves the signed map for an operator group.
///
/// The signature covers the document, so this handler does no authorisation of
/// its own: the map "contains no device data, only fleet inventory" (ADR-0006
/// §10) and is identical for every device in the group. A handler that
/// authenticated the caller would be a handler that knows which device is asking,
/// which is the per-connection coupling this file exists to prevent.
async fn serve_map(
    State(cache): State<SharedCache>,
    Path(operator_group_id): Path<String>,
) -> Response {
    // Bounded before use: `operator_group_id` is attacker-controlled and is used
    // as a map key (ownership.md §6 rule 9).
    if operator_group_id.is_empty()
        || operator_group_id.len() > twinvpn_schema::limits::TWINNET_ID_MAX_BYTES
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let found = cache.read().ok().and_then(|c| c.get(&operator_group_id));

    match found {
        // Nothing published yet. A device that has a cached map keeps using it —
        // §11.1 rule 4 — so this is not an outage for anyone already running.
        None => StatusCode::NOT_FOUND.into_response(),
        Some(map) => {
            let body = render(&map);
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
                    (header::ETAG, format!("\"{}\"", map.map_version)),
                    // Cacheable at the edge: the document is identical for every
                    // device in the group, which is itself an availability
                    // property (§10 — map distribution does not share a failure
                    // domain with the control-plane database).
                    (header::CACHE_CONTROL, "public, max-age=60".to_owned()),
                ],
                body,
            )
                .into_response()
        }
    }
}

/// The bytes served: the canonical encoding followed by the detached signature.
#[must_use]
pub fn render(map: &RelayMap) -> Vec<u8> {
    let mut out = crate::map::canonical_encoding(
        map.map_version,
        map.issued_at_ms,
        &map.operator_group_id,
        &map.regions,
        &map.relays,
    );
    out.extend_from_slice(map.signer_key_id.as_bytes());
    out.extend_from_slice(&map.signature);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::sample;
    use crate::map::{MapBuilder, PublicationFloor, Region};
    use crate::sign::{MapSigner, SignError};

    struct FixedSigner;
    impl MapSigner for FixedSigner {
        fn sign(&self, b: &[u8]) -> Result<Vec<u8>, SignError> {
            Ok(b.len().to_be_bytes().to_vec())
        }
        fn key_id(&self) -> &str {
            "map-k1"
        }
    }

    fn published() -> RelayMap {
        let mut b = MapBuilder::new(
            "local-operator".into(),
            PublicationFloor::default(),
            3_600_000,
        );
        b.publish(
            vec![sample(1, "eu-west", "fd-a"), sample(2, "eu-west", "fd-b")],
            vec![Region {
                region_id: "eu-west".into(),
                geo_hint: "eu-west".into(),
                adjacent_regions: vec![],
            }],
            1,
            0,
            &FixedSigner,
        )
        .expect("publishes")
    }

    #[test]
    fn the_router_has_exactly_one_route() {
        let src = include_str!("api.rs");
        let end = src.find("#[cfg(test)]").unwrap_or(src.len());
        let production = &src[..end];
        assert_eq!(
            production.matches(".route(").count(),
            1,
            "the device-facing surface is one document; a second route is how a \
             per-connection call arrives"
        );
    }

    #[test]
    fn the_only_input_is_an_operator_group() {
        let src = include_str!("api.rs");
        let end = src.find("#[cfg(test)]").unwrap_or(src.len());
        let production = &src[..end];
        // No extractor that could carry per-connection input.
        for forbidden in ["Query<", "Json<", "Form<", "TypedHeader", "Body>"] {
            assert!(
                !production.contains(forbidden),
                "api.rs uses `{forbidden}`: the handler must take no request body \
                 and no query, so no future field can name a session or a peer"
            );
        }
        // And the route template names exactly one parameter.
        assert_eq!(MAP_ROUTE.matches('{').count(), 1);
        assert!(MAP_ROUTE.contains("{operator_group_id}"));
    }

    #[test]
    fn no_per_connection_identifier_appears_in_the_surface_at_all() {
        let src = include_str!("api.rs");
        let end = src.find("#[cfg(test)]").unwrap_or(src.len());
        let code: String = src[..end]
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "session_id",
            "device_id",
            "peer_id",
            "pair_tag",
            "relay_id",
            "candidate",
        ] {
            assert!(
                !code.contains(forbidden),
                "api.rs names `{forbidden}`: selection is cached state, and a \
                 surface that accepts a connection's identifiers is a surface that \
                 will eventually be called per connection"
            );
        }
    }

    #[test]
    fn the_cache_serves_the_whole_document_per_group() {
        let mut c = MapCache::new();
        assert!(c.is_empty());
        c.put(published());
        assert_eq!(c.len(), 1);
        let m = c.get("local-operator").expect("published");
        assert_eq!(m.map_version, 1);
        assert_eq!(m.relays.len(), 2);
        assert!(c.get("someone-else").is_none());
    }

    #[test]
    fn the_rendered_document_covers_the_version_and_the_signature() {
        let m = published();
        let bytes = render(&m);
        assert!(bytes.ends_with(&m.signature));
        assert!(bytes.starts_with(&1_u64.to_be_bytes()));
    }
}
