//! `twinoracle serve` — the external leak oracle process.
//!
//! # Deployment shape, and why it is not negotiable
//!
//! This process MUST run somewhere the device under test can reach only by
//! emitting a packet that leaves the device: a small cloud instance with a
//! public IPv4 address, a public IPv6 address, and the beacon zone delegated to
//! it. On the same host as the test it observes nothing — loopback egress is
//! not egress, and a kill switch that permits it would still pass.
//!
//! Three listeners, and the split is the evidence:
//!
//! * `--http4` binds IPv4 only, `--http6` binds IPv6 only (`V6ONLY`), so the
//!   family of an observation is a property of the socket that accepted it and
//!   not of anything the client asserted.
//! * `--dns4`/`--dns6` answer the beacon zone.
//!
//! The control plane is a FOURTH listener on its own address and port, behind a
//! bearer token. It is what opens sessions, marks phases and hands out reports;
//! nothing on the data plane can reach it, so a device that leaks cannot also
//! rewrite the record of its leak.
//!
//! # Usage
//!
//! ```text
//! twinoracle serve \
//!   --control 0.0.0.0:8443 --control-token-file /etc/twinoracle/token \
//!   --http4 0.0.0.0:80 --http6 '[::]:80' \
//!   --dns4 0.0.0.0:53  --dns6 '[::]:53' \
//!   --zone leak.oracle.twinvpn.example \
//!   --advertise-v4 198.51.100.7 --advertise-v6 2001:db8::7
//! ```

mod control;
mod dns;
mod http;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use twinoracle::{Family, Observation, PathKind, ResolverEntry, SentinelBeat, Session};

#[derive(Parser, Debug)]
#[command(name = "twinoracle", about = "the external TwinVPN leak oracle")]
enum Cli {
    Serve(Serve),
}

#[derive(Parser, Debug)]
struct Serve {
    /// Control-plane listener. Bind this to a management address, never to the
    /// same public surface as the beacons.
    #[arg(long, default_value = "127.0.0.1:8443")]
    control: SocketAddr,
    /// File holding the control bearer token. A FILE rather than a flag: an
    /// argument is visible in `ps` on the oracle host.
    #[arg(long)]
    control_token_file: std::path::PathBuf,
    #[arg(long)]
    http4: Option<SocketAddr>,
    #[arg(long)]
    http6: Option<SocketAddr>,
    #[arg(long)]
    dns4: Option<SocketAddr>,
    #[arg(long)]
    dns6: Option<SocketAddr>,
    /// The delegated beacon zone, e.g. `leak.oracle.twinvpn.example`.
    #[arg(long)]
    zone: String,
    /// The addresses a probe should beacon at. Reported to the probe when a
    /// session opens, so the probe script carries no hard-coded address.
    #[arg(long)]
    advertise_v4: Option<std::net::Ipv4Addr>,
    #[arg(long)]
    advertise_v6: Option<std::net::Ipv6Addr>,
    /// The TCP port the advertised beacon URLs carry. Defaults to 80, which is
    /// what a public deployment binds; an in-box deployment on a host whose
    /// port 80 is held by another service (Windows HTTP.sys is the known case)
    /// binds `--http4`/`--http6` elsewhere and advertises that port here.
    #[arg(long, default_value_t = 80)]
    advertise_port: u16,
    /// The widest gap between sentinel beats that still counts as the oracle
    /// having been continuously listening. REQUIRED: this is a property of the
    /// sentinel's cadence, which is a property of THIS DEPLOYMENT — not of the
    /// probe, which should not be inventing the resolution at which liveness is
    /// claimed. A session may override it, but there is no way to start an
    /// oracle that has not declared one.
    #[arg(long)]
    sentinel_max_gap_ms: u64,
    /// Repeatable: `--resolver 198.51.100.53=isp-recursive:u`, mapping an
    /// arriving resolver address to the identity and path the oracle derives
    /// for it. Configured by the operator who knows the topology; the device
    /// under test is the last party that should be describing it.
    ///
    /// Leave it empty and every DNS arrival is unattributable, which sets
    /// `dns_resolver_identity_ambiguous` and makes sessions INCONCLUSIVE. That
    /// is the fail-closed direction: an unconfigured map must not read as a
    /// clean one.
    #[arg(long = "resolver", value_parser = parse_resolver)]
    resolvers: Vec<(IpAddr, ResolverEntry)>,
    /// File holding a STANDING sentinel token, for a sentinel process that runs
    /// continuously rather than being started per session.
    ///
    /// It exists for the criteria where no host in the CI job is independent of
    /// the device — an EC2 Mac testing its own system extension IS the device,
    /// so nothing in that job can be a sentinel. Beats carrying this token are
    /// recorded in EVERY open session, because "the listeners were alive" is a
    /// fact about the oracle rather than about any one run.
    #[arg(long)]
    sentinel_token_file: Option<std::path::PathBuf>,
}

/// `<ip>=<id>:<p|u>`.
fn parse_resolver(spec: &str) -> Result<(IpAddr, ResolverEntry), String> {
    let (addr, rest) = spec
        .split_once('=')
        .ok_or("expected <ip>=<id>:<p|u>, e.g. 198.51.100.53=isp-recursive:u")?;
    let (id, tag) = rest
        .rsplit_once(':')
        .ok_or("expected <ip>=<id>:<p|u>; the path letter is missing")?;
    let addr: IpAddr = addr.parse().map_err(|e| format!("{addr:?}: {e}"))?;
    let path = PathKind::from_tag(tag).ok_or_else(|| format!("{tag:?} is not `p` or `u`"))?;
    if id.is_empty() {
        return Err("the resolver id must not be empty".into());
    }
    Ok((
        addr,
        ResolverEntry {
            id: id.to_string(),
            path,
        },
    ))
}

impl Serve {
    fn resolver_map(&self) -> std::collections::BTreeMap<IpAddr, ResolverEntry> {
        self.resolvers.iter().cloned().collect()
    }
}

/// Sessions, plus the token index the data plane needs. One lock: this observes
/// a handful of CI runs, not a fleet, and a single mutex is the shape whose
/// correctness a reader can check at a glance.
//
// ponytail: one global mutex; shard by session id if this ever observes more
// than a few concurrent runs.
#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    by_token: HashMap<String, String>,
    /// A SEPARATE index. The sentinel beats at the same three listeners during
    /// the armed window; if it shared `by_token` with the probe, every
    /// heartbeat that proved the oracle was still listening would be recorded
    /// as an unauthorized arrival and the liveness check would manufacture the
    /// leak it exists to rule out.
    by_sentinel_token: HashMap<String, String>,
    /// A token that is not tied to any one session. See `--sentinel-token-file`.
    standing_sentinel: Option<String>,
}

type Shared = Arc<Mutex<State>>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the oracle host's clock is before the epoch")
        .as_millis() as u64
}

/// 128 bits from the platform CSPRNG, hex.
///
/// This used to open `/dev/urandom` directly, on the stated assumption that the
/// oracle host is Linux. It is not any more: the Windows kill-switch lane runs
/// the oracle in-box on the CI runner that hosts the device under test, where
/// that path does not exist and the process would panic on its first session.
/// `getrandom` was already in `lab/Cargo.lock` as a transitive dependency, so
/// naming it directly costs one edge and no new code in the tree.
///
/// These bytes are session ids, probe tokens and sentinel tokens: a probe token
/// an observer could guess would let anything on the network write arrivals
/// into somebody's session, so the CSPRNG is not decoration.
fn random_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("the oracle host must have a working CSPRNG");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let Cli::Serve(cfg) = Cli::parse();

    let token = std::fs::read_to_string(&cfg.control_token_file)?
        .trim()
        .to_string();
    if token.len() < 32 {
        eprintln!(
            "::error::the control token is {} characters; use at least 32. This token is the \
             only thing between the public internet and the ability to rewrite a session's \
             phase boundaries.",
            token.len()
        );
        std::process::exit(2);
    }

    let standing_sentinel = match &cfg.sentinel_token_file {
        Some(path) => {
            let t = std::fs::read_to_string(path)?.trim().to_string();
            if t.len() < 32 {
                eprintln!(
                    "::error::the standing sentinel token is {} characters; use at least 32. \
                     Anyone holding it can write continuity evidence into every open session.",
                    t.len()
                );
                std::process::exit(2);
            }
            Some(t)
        }
        None => None,
    };
    let state: Shared = Arc::new(Mutex::new(State {
        standing_sentinel,
        ..State::default()
    }));
    let cfg = Arc::new(cfg);
    let mut tasks = Vec::new();

    {
        let (state, cfg, token) = (state.clone(), cfg.clone(), token.clone());
        let listener = TcpListener::bind(cfg.control)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("bind {}: {e}", cfg.control)))?;
        tracing::info!(addr = %cfg.control, "control plane listening");
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((sock, _peer)) = listener.accept().await else {
                    continue;
                };
                let (state, cfg, token) = (state.clone(), cfg.clone(), token.clone());
                tokio::spawn(async move { control::control(sock, state, cfg, token).await });
            }
        }));
    }

    for (addr, family) in [(cfg.http4, Family::Ipv4), (cfg.http6, Family::Ipv6)] {
        let Some(addr) = addr else { continue };
        let state = state.clone();
        // BOUND SEPARATELY, and the v6 socket is v6-only by construction: a
        // dual-stack socket would accept an IPv4 connection and report it as
        // `::ffff:a.b.c.d`, and the family of the observation would then be a
        // guess. `TcpListener::bind` on a `[::]` address under tokio inherits
        // the OS default, so the deployment MUST set `net.ipv6.bindv6only=1`;
        // the mapped-address check below is the belt to that braces.
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("bind {}: {e}", addr)))?;
        tracing::info!(%addr, family = family.as_str(), "beacon listening");
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((sock, peer)) = listener.accept().await else {
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move { beacon(sock, peer, family, state).await });
            }
        }));
    }

    for addr in [cfg.dns4, cfg.dns6] {
        let Some(addr) = addr else { continue };
        let state = state.clone();
        let cfg = cfg.clone();
        let sock = UdpSocket::bind(addr)
            .await
            .map_err(|e| std::io::Error::new(e.kind(), format!("bind {}: {e}", addr)))?;
        tracing::info!(%addr, "dns listening");
        tasks.push(tokio::spawn(
            async move { dns_loop(sock, state, cfg).await },
        ));
    }

    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

/// The data plane. Anything that reaches here left the device.
async fn beacon(mut sock: TcpStream, peer: SocketAddr, family: Family, state: Shared) {
    let Some(req) = http::read_request(&mut sock).await else {
        return;
    };
    // `/b/<token>/<seq>`.
    let seg = req.segments();
    if seg.len() < 2 || seg[0] != "b" {
        http::respond(&mut sock, 404, "text/plain", b"no\n").await;
        return;
    }
    let (token, seq) = (seg[1].to_string(), seg.get(2).unwrap_or(&"").to_string());

    // A v4-mapped peer on the v6 listener means the socket was dual-stack after
    // all. Recording it as IPv6 would be a lie in the evidence, so it is
    // recorded as what it is.
    let source = normalise(peer.ip());
    let family = match (family, source) {
        (Family::Ipv6, IpAddr::V4(_)) => Family::Ipv4,
        (f, _) => f,
    };

    match record_arrival(&state, &token, family, source, seq.clone(), None).await {
        Arrival::Probe => {
            tracing::info!(%source, family = family.as_str(), %seq, "observed egress")
        }
        Arrival::Sentinel => {
            tracing::debug!(%source, family = family.as_str(), "sentinel beat")
        }
        Arrival::Unknown => {}
    }
    // The SAME answer either way. A probe must not be able to tell from the
    // response whether its session is live, because a probe that could would be
    // a probe that could be written to stop beaconing once it mattered.
    http::respond(&mut sock, 200, "text/plain", b"ok\n").await;
}

/// Who a beacon belonged to. The token decides, and nothing else does.
enum Arrival {
    Probe,
    Sentinel,
    /// Internet scan noise, or a token from a session that has since closed.
    /// Recorded nowhere: appending to a sealed record is exactly what closing
    /// the session was for.
    Unknown,
}

/// The single place an arrival becomes evidence, shared by the HTTP and DNS
/// listeners so the probe/sentinel split cannot be implemented twice and drift.
///
/// The order matters: the PROBE token is checked first. If the two indexes ever
/// held the same string, the arrival would count as a leak rather than silently
/// becoming a heartbeat that excuses one.
async fn record_arrival(
    state: &Shared,
    token: &str,
    family: Family,
    source: IpAddr,
    seq: String,
    path_tag: Option<PathKind>,
) -> Arrival {
    let mut st = state.lock().await;
    if let Some(id) = st.by_token.get(token).cloned() {
        if let Some(s) = st.sessions.get_mut(&id) {
            s.record(Observation {
                family,
                source,
                at_ms: now_ms(),
                seq,
                path_tag,
            });
            return Arrival::Probe;
        }
    }
    if let Some(id) = st.by_sentinel_token.get(token).cloned() {
        if let Some(s) = st.sessions.get_mut(&id) {
            if let Some(sentinel) = s.sentinel.as_mut() {
                sentinel.beats.push(SentinelBeat {
                    family,
                    source,
                    at_ms: now_ms(),
                });
                return Arrival::Sentinel;
            }
        }
    }
    // The standing sentinel fans out: one beat is evidence about the ORACLE,
    // so every session that is currently open gets it. A closed session does
    // not, for the same reason a closed session stops resolving its probe
    // token — a sealed record must not keep growing.
    if st.standing_sentinel.as_deref() == Some(token) {
        let at_ms = now_ms();
        let mut recorded = false;
        for s in st.sessions.values_mut() {
            if s.closed_at_ms.is_some() {
                continue;
            }
            if let Some(sentinel) = s.sentinel.as_mut() {
                sentinel.beats.push(SentinelBeat {
                    family,
                    source,
                    at_ms,
                });
                recorded = true;
            }
        }
        if recorded {
            return Arrival::Sentinel;
        }
    }
    Arrival::Unknown
}

fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

async fn dns_loop(sock: UdpSocket, state: Shared, cfg: Arc<Serve>) {
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let packet = &buf[..n];
        let Some(q) = dns::parse_query(packet) else {
            continue;
        };
        let Some((token, seq, path_tag)) = dns::beacon_labels(&q.name, &cfg.zone) else {
            // REFUSED, at once, and nothing recorded. A dropped query is not
            // free: the querier waits out its timeout and retries, and the
            // lab's relay waits on the unanswered upstream. See `build_refusal`.
            let _ = sock.send_to(&dns::build_refusal(packet, &q), peer).await;
            continue;
        };
        let source = normalise(peer.ip());
        match record_arrival(&state, &token, Family::Dns, source, seq.clone(), path_tag).await {
            Arrival::Probe => tracing::info!(%source, %seq, "observed dns egress"),
            Arrival::Sentinel => tracing::debug!(%source, "sentinel dns beat"),
            Arrival::Unknown => {}
        }
        let answer = match q.qtype {
            dns::TYPE_A => cfg.advertise_v4.map(IpAddr::V4),
            dns::TYPE_AAAA => cfg.advertise_v6.map(IpAddr::V6),
            _ => None,
        };
        let reply = dns::build_reply(packet, &q, answer);
        let _ = sock.send_to(&reply, peer).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tokens this hands out are the only thing between an observer on the
    /// network and the ability to write arrivals into somebody else's session,
    /// so a `random_id` that returned a constant, a short value or the same
    /// value twice would be a hole rather than a cosmetic defect. It is also
    /// the function that has to work on every host the oracle now runs on --
    /// including the Windows CI runner where the old `/dev/urandom` open would
    /// have panicked on the first session.
    #[test]
    fn random_ids_are_full_width_and_do_not_repeat() {
        let a = random_id();
        let b = random_id();
        assert_eq!(a.len(), 32, "128 bits as hex is 32 characters: {a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "two draws from the CSPRNG must not be equal");
    }

    /// A mistyped `--resolver` must fail at startup, loudly. The alternative is
    /// an oracle that starts with a half-built map, silently cannot attribute
    /// half its DNS arrivals, and reports INCONCLUSIVE for a reason nobody
    /// traces back to a typo in a systemd unit.
    #[test]
    fn resolver_specs_parse_or_are_refused() {
        let (addr, entry) = parse_resolver("198.51.100.53=isp-recursive:u").expect("valid");
        assert_eq!(addr, "198.51.100.53".parse::<IpAddr>().unwrap());
        assert_eq!(entry.id, "isp-recursive");
        assert_eq!(entry.path, PathKind::Unprotected);

        // An IPv6 resolver: the id/path split is the LAST colon, so the
        // address's own colons cannot be mistaken for it.
        let (addr, entry) = parse_resolver("2001:db8::53=twinvpn-dns:p").expect("valid");
        assert_eq!(addr, "2001:db8::53".parse::<IpAddr>().unwrap());
        assert_eq!(entry.path, PathKind::Protected);

        for bad in [
            "198.51.100.53",       // no id or path
            "198.51.100.53=isp",   // no path letter
            "198.51.100.53=isp:x", // not p or u
            "198.51.100.53=:u",    // empty id
            "not-an-address=isp:u",
        ] {
            assert!(parse_resolver(bad).is_err(), "{bad} must be refused");
        }
    }
}
