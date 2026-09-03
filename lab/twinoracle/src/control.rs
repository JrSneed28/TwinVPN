//! The control plane. Everything here needs the bearer token, and nothing on
//! the data plane can reach it — so a device that leaks cannot also rewrite the
//! record of its leak.
//!
//! It is a separate module from `main.rs` for one reason: the data plane must
//! stay small enough to read in one sitting, because it is the half a reader
//! has to believe.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use twinoracle::{Expectation, Family, Phase, ResolverEntry, SentinelEvidence, Session};

use crate::{http, now_ms, random_id, Serve, Shared};

#[derive(Deserialize)]
struct OpenRequest {
    commit: String,
    run_id: String,
    /// `GITHUB_RUN_ATTEMPT`. Defaulted rather than required only because a
    /// local run has no such thing; the acceptance report is what refuses an
    /// empty one against a real workflow run.
    #[serde(default)]
    run_attempt: String,
    platform: String,
    criterion: String,
    /// Per-session override of the oracle's `--sentinel-max-gap-ms`. The
    /// cadence is a property of the SENTINEL DEPLOYMENT, not of the probe, so
    /// the flag is where it belongs and is required at process start; a probe
    /// that omits this inherits it rather than inventing one.
    #[serde(default)]
    sentinel_max_gap_ms: Option<u64>,
    /// Families this criterion makes a claim about. Empty means all three.
    #[serde(default)]
    required_families: Vec<Family>,
    #[serde(default)]
    attempt_minimums: BTreeMap<Family, u64>,
    /// Per-session override of the oracle's `--resolver` flags. Empty inherits
    /// them. Like the cadence, the map is a property of the deployment's
    /// topology, which the device under test is the last party that should be
    /// describing.
    #[serde(default)]
    resolver_map: BTreeMap<IpAddr, ResolverEntry>,
}

/// What the PROBE is told. It deliberately carries no sentinel token: the
/// device under test must never hold the credential whose beats are read as
/// proof the oracle was listening. `POST /v1/sessions/{id}/sentinel` is where
/// that token lives, and only the sentinel operator calls it.
#[derive(Serialize)]
struct OpenResponse {
    session_id: String,
    probe_token: String,
    beacon_v4: Option<String>,
    beacon_v6: Option<String>,
    /// `<probe_token>.<zone>`. Kept for callers that already build on it; a
    /// caller assembling the tagged DNS name wants `zone` instead, because
    /// splitting the token back out of this string is guesswork.
    dns_suffix: String,
    zone: String,
    /// The per-family attempt floor this session will be judged against, so the
    /// probe can log the number it has to beat instead of the operator holding
    /// it in their head.
    min_attempts: BTreeMap<Family, u64>,
}

/// What the SENTINEL operator is told.
#[derive(Serialize)]
struct SentinelResponse {
    /// Distinct from `probe_token` by construction. Beats carrying it are
    /// recorded as continuity evidence, never as observations — a sentinel beat
    /// during a SILENCE phase is what proves the ears were open.
    sentinel_token: String,
    sentinel_beacon_v4: Option<String>,
    sentinel_beacon_v6: Option<String>,
    sentinel_zone: String,
}

#[derive(Deserialize)]
struct SentinelRequest {
    /// Free-text id of the machine running the sentinel. Echoed into the
    /// report: WHERE the sentinel ran is the whole independence claim.
    #[serde(default)]
    host: Option<String>,
}

#[derive(Deserialize)]
struct PhaseRequest {
    phase: String,
    expectation: Expectation,
    #[serde(default)]
    require_families: Vec<Family>,
    #[serde(default)]
    sources_disjoint_from: Option<String>,
    #[serde(default)]
    sources_subset_of: Option<String>,
    // The SAME field rules as `twinoracle::Phase`: `path_tag` is the name the
    // probe sends, and `"n"` is its "no claim". A plain `Option<PathKind>`
    // here silently ignored `path_tag`, so no phase ever carried a path and no
    // session could establish an IPv4 or IPv6 path identity.
    #[serde(
        default,
        alias = "path_tag",
        deserialize_with = "twinoracle::model::deserialize_path"
    )]
    path: Option<twinoracle::PathKind>,
}

pub(crate) async fn control(mut sock: TcpStream, state: Shared, cfg: Arc<Serve>, token: String) {
    let Some(req) = http::read_request(&mut sock).await else {
        return;
    };
    if req.bearer() != Some(token.as_str()) {
        http::respond(&mut sock, 401, "text/plain", b"unauthorized\n").await;
        return;
    }
    let seg = req.segments();
    let (status, body) = match (req.method.as_str(), seg.as_slice()) {
        ("POST", ["v1", "sessions"]) => open_session(&req, &state, &cfg).await,
        ("POST", ["v1", "sessions", id, "phase"]) => mark_phase(&req, id, &state).await,
        ("POST", ["v1", "sessions", id, "attempts"]) => report_attempts(&req, id, &state).await,
        ("POST", ["v1", "sessions", id, "sentinel"]) => {
            claim_sentinel(&req, id, &state, &cfg).await
        }
        ("POST", ["v1", "sessions", id, "close"]) => close_session(id, &state).await,
        ("GET", ["v1", "sessions", id, "report"]) => fetch_report(id, &state).await,
        _ => (404, json_error("no such control endpoint")),
    };
    http::respond(&mut sock, status, "application/json", body.as_bytes()).await;
}

fn json_error(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

async fn open_session(req: &http::Request, state: &Shared, cfg: &Serve) -> (u16, String) {
    let Ok(body) = serde_json::from_slice::<OpenRequest>(&req.body) else {
        return (
            400,
            json_error(
                "body must be {commit, run_id, platform, criterion, sentinel_max_gap_ms, ...}",
            ),
        );
    };
    let id = random_id();
    let probe_token = random_id();
    let sentinel_token = random_id();
    let mut session = Session::new(
        id.clone(),
        probe_token.clone(),
        body.commit,
        body.run_id,
        body.platform,
        body.criterion,
        now_ms(),
    );
    session.run_attempt = body.run_attempt;
    session.required_families = body.required_families;
    session.attempt_minimums = body.attempt_minimums;
    session.resolver_map = if body.resolver_map.is_empty() {
        cfg.resolver_map()
    } else {
        body.resolver_map
    };
    session.sentinel = Some(SentinelEvidence {
        token: sentinel_token.clone(),
        max_gap_ms: body.sentinel_max_gap_ms.unwrap_or(cfg.sentinel_max_gap_ms),
        host: None,
        beats: Vec::new(),
    });
    let min_attempts = session.attempt_minimums.clone();
    {
        let mut st = state.lock().await;
        st.by_token.insert(probe_token.clone(), id.clone());
        st.by_sentinel_token.insert(sentinel_token, id.clone());
        st.sessions.insert(id.clone(), session);
    }
    let out = OpenResponse {
        session_id: id,
        beacon_v4: cfg
            .advertise_v4
            .map(|a| beacon_url(&a.to_string(), cfg.advertise_port, &probe_token)),
        beacon_v6: cfg
            .advertise_v6
            .map(|a| beacon_url(&format!("[{a}]"), cfg.advertise_port, &probe_token)),
        dns_suffix: format!("{}.{}", probe_token, cfg.zone),
        zone: cfg.zone.clone(),
        min_attempts,
        probe_token,
    };
    (201, serde_json::to_string(&out).expect("serialisable"))
}

async fn mark_phase(req: &http::Request, id: &str, state: &Shared) -> (u16, String) {
    let Ok(body) = serde_json::from_slice::<PhaseRequest>(&req.body) else {
        return (400, json_error("body must be {phase, expectation, ...}"));
    };
    let mut st = state.lock().await;
    let Some(s) = st.sessions.get_mut(id) else {
        return (404, json_error("no such session"));
    };
    if s.closed_at_ms.is_some() {
        // A closed session is a finished record. Reopening one would let a
        // failing run re-cut its phase boundaries around the leak.
        return (409, json_error("the session is closed"));
    }
    s.begin_phase(Phase {
        name: body.phase,
        expectation: body.expectation,
        started_at_ms: now_ms(),
        ended_at_ms: None,
        require_families: body.require_families,
        sources_disjoint_from: body.sources_disjoint_from,
        sources_subset_of: body.sources_subset_of,
        path: body.path,
    });
    (200, serde_json::json!({ "ok": true }).to_string())
}

/// `{"ipv4": 15, "ipv6": 15, "dns": 15}` — an INCREMENT, added to the running
/// whole-session total. Not an absolute value.
///
/// Incremental because the probe posts at the end of each beacon burst and does
/// not carry a running total between invocations; a post that fails is dropped,
/// which makes the recorded total too LOW. That direction is the safe one: a
/// low count makes the session INCONCLUSIVE, and inconclusive is the verdict a
/// half-run probe has earned.
///
/// Only the device can count what it TRIED to send, so this number is
/// self-reported and is used in exactly one direction: too few attempts makes
/// the session INCONCLUSIVE. It can never make one PASS — which is also why a
/// retried post double-counting is not a hole, since a device that wanted a
/// large number could simply send one. A closed session refuses the update, so
/// a run cannot top up its count after the record was sealed.
async fn report_attempts(req: &http::Request, id: &str, state: &Shared) -> (u16, String) {
    let Ok(counts) = serde_json::from_slice::<BTreeMap<Family, u64>>(&req.body) else {
        return (
            400,
            json_error("body must be {\"ipv4\": n, \"ipv6\": n, \"dns\": n}"),
        );
    };
    let mut st = state.lock().await;
    let Some(s) = st.sessions.get_mut(id) else {
        return (404, json_error("no such session"));
    };
    if s.closed_at_ms.is_some() {
        return (409, json_error("the session is closed"));
    }
    for (family, n) in counts {
        let total = s.attempts.entry(family).or_insert(0);
        *total = total.saturating_add(n);
    }
    (200, serde_json::json!({ "ok": true }).to_string())
}

/// Hand the sentinel operator the session's sentinel token, and record where
/// they say it is running.
///
/// A SEPARATE endpoint from `open_session` on purpose. If the token came back
/// in the open response, the device under test would hold it — and a device
/// that beat the sentinel token from its own address during the armed window
/// would be emitting exactly the packet the kill switch was supposed to stop,
/// filed as proof the oracle was alive. `evidence::is_dut_sourced` is the check
/// that catches that anyway; this is the door it should never get through.
async fn claim_sentinel(
    req: &http::Request,
    id: &str,
    state: &Shared,
    cfg: &Serve,
) -> (u16, String) {
    // An absent body is fine; only a malformed one is refused.
    let host = if req.body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<SentinelRequest>(&req.body) {
            Ok(b) => b.host,
            Err(_) => return (400, json_error("body must be {host} or empty")),
        }
    };
    let mut st = state.lock().await;
    let Some(s) = st.sessions.get_mut(id) else {
        return (404, json_error("no such session"));
    };
    if s.closed_at_ms.is_some() {
        return (409, json_error("the session is closed"));
    }
    let Some(sentinel) = s.sentinel.as_mut() else {
        return (409, json_error("this session has no sentinel"));
    };
    if host.is_some() {
        sentinel.host = host;
    }
    let sentinel_token = sentinel.token.clone();
    let out = SentinelResponse {
        sentinel_beacon_v4: cfg
            .advertise_v4
            .map(|a| beacon_url(&a.to_string(), cfg.advertise_port, &sentinel_token)),
        sentinel_beacon_v6: cfg
            .advertise_v6
            .map(|a| beacon_url(&format!("[{a}]"), cfg.advertise_port, &sentinel_token)),
        sentinel_zone: cfg.zone.clone(),
        sentinel_token,
    };
    (200, serde_json::to_string(&out).expect("serialisable"))
}

async fn close_session(id: &str, state: &Shared) -> (u16, String) {
    let mut st = state.lock().await;
    let Some(s) = st.sessions.get_mut(id) else {
        return (404, json_error("no such session"));
    };
    s.close(now_ms());
    let token = s.probe_token.clone();
    let sentinel_token = s.sentinel.as_ref().map(|x| x.token.clone());
    // Both tokens stop resolving, so neither a probe nor the sentinel can keep
    // appending to a finished record.
    st.by_token.remove(&token);
    if let Some(t) = sentinel_token {
        st.by_sentinel_token.remove(&t);
    }
    (200, serde_json::json!({ "ok": true }).to_string())
}

async fn fetch_report(id: &str, state: &Shared) -> (u16, String) {
    let st = state.lock().await;
    let Some(s) = st.sessions.get(id) else {
        return (404, json_error("no such session"));
    };
    (
        200,
        serde_json::to_string(&s.report()).expect("serialisable"),
    )
}

/// `http://<host>/b/<token>`, carrying the port only when it is not the
/// scheme default so a public deployment's URLs read exactly as before.
fn beacon_url(host: &str, port: u16, token: &str) -> String {
    if port == 80 {
        format!("http://{host}/b/{token}")
    } else {
        format!("http://{host}:{port}/b/{token}")
    }
}

#[cfg(test)]
mod tests {
    use super::PhaseRequest;
    use twinoracle::PathKind;

    /// `leak-probe.sh phase --path u` posts `"path_tag":"u"`, and `"n"` for a
    /// phase with no claim. Both must land on the phase the oracle records.
    #[test]
    fn the_probes_path_tag_reaches_the_phase() {
        let cases = [
            (r#""path_tag":"u""#, Some(PathKind::Unprotected)),
            (r#""path_tag":"p""#, Some(PathKind::Protected)),
            (r#""path":"u""#, Some(PathKind::Unprotected)),
            (r#""path_tag":"n""#, None),
        ];
        for (field, want) in cases {
            let body = format!(r#"{{"phase":"BASELINE","expectation":"OBSERVE",{field}}}"#);
            let req: PhaseRequest = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{body}: {e}"));
            assert_eq!(req.path, want, "{body}");
        }
    }
}
