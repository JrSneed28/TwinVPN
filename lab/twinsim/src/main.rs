//! `twinsim` — the CLI over the simulated devices and the development credentials.
//!
//! **Owner:** `test-engineering`. Never shipped (ADR-0018 §11.12).
//!
//! ```text
//! twinsim issuer init      generate the DEVELOPMENT issuer and write every relay's key set
//! twinsim map init         derive each relay's static PUBLIC key into a development map
//! twinsim peer             run a simulated device or gateway until stopped
//! twinsim probe            one-shot: establish, bind, send, report, exit
//! twinsim ceremony         attach to the CONTROL PLANE and run one C1 command
//! ```
//!
//! `issuer init` and `map init` are **separate, explicit acts**, never a side
//! effect of `peer`. `infra/scripts/bootstrap-local.sh` writes a fail-closed
//! empty issuer set on purpose — "a relay that admitted flows because it had no
//! issuer keys would be an open relay" — and a simulator that quietly populated
//! it at startup would turn that decision into a comment.
//!
//! `probe` exits non-zero when it could not do what it was asked. That is what
//! makes it usable as a CI smoke test: a green stack whose relays refuse every
//! bind must fail a lane, not print a summary.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use twinsim::admin::SimState;
use twinsim::device::{BindOutcome, SimDevice};
use twinsim::issuer::{DevIssuer, TokenSpec, DEV_ISSUER_KEY_ID, DEV_OPERATOR_GROUP};
// `Identifier` carries `as_bytes`/`to_hex`; `to_hex` is deliberately a method
// rather than `Display` because for a SENSITIVE identifier it is the
// redaction-bypassing path and must be visible at the call site. A channel
// binding is public per-connection material, so rendering it here is safe and
// is what lets an operator compare it against the control plane's own log.
use twinvpn_types::Identifier as _;

use twinsim::lcontrol::{QuicControlTransport, ServerKey};
use twinsim::map::{DevRelayMap, RelayEntry};
use twinsim::pairing::{current_bucket, now_ms, pair_tag_for};
use twinsim::run::{run_peer, PeerConfig, DEV_EPOCH};
use twinvpn_cp_client::transport::ControlConnection;

#[derive(Parser)]
#[command(
    name = "twinsim",
    about = "simulated TwinVPN devices and gateways for the local multi-node environment"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The DEVELOPMENT relay-credential issuer.
    Issuer {
        #[command(subcommand)]
        action: IssuerAction,
    },
    /// The DEVELOPMENT relay map.
    Map {
        #[command(subcommand)]
        action: MapAction,
    },
    /// Run a simulated device or gateway until stopped.
    Peer(PeerArgs),
    /// One-shot reachability probe. Non-zero exit on anything but success.
    Probe(ProbeArgs),
    /// Attach to the control plane over rung 1 and run one C1 command.
    ///
    /// This is the L-CONTROL half of the local environment. It completes a real
    /// mutually-authenticated QUIC handshake with RFC 7250 raw public keys
    /// against the real `twinvpn-control-plane` binary, reads the RFC 9266
    /// channel binding off the live connection, and exchanges one C1 frame.
    Ceremony(CeremonyArgs),
}

#[derive(Parser)]
struct CeremonyArgs {
    /// The control plane's QUIC listener. A LITERAL address:port — ADR-0011
    /// DN-0 forbids a hostname on this path, and resolving one here would hide
    /// the violation until it reached a device.
    #[arg(long, env = "TWINSIM_CP_ADDR", default_value = "127.0.0.1:14430")]
    cp: SocketAddr,
    /// The local socket. `[::]:0` attaches over IPv6, `0.0.0.0:0` over IPv4.
    #[arg(long, env = "TWINSIM_LOCAL_ADDR", default_value = "0.0.0.0:0")]
    local: SocketAddr,
    /// The seed for this device's identity key. The RFC 7250 raw public key
    /// derived from it IS the `DeviceIdentityKey` the control plane sees
    /// (ADR-0007 N-32) — it derives `device_id` from the key rather than
    /// looking it up, so a new seed is a new device.
    #[arg(long, env = "TWINSIM_DEVICE_SEED", default_value = "twinsim-device-1")]
    device_seed: String,
    /// The server's pinned raw public key, lowercase hex. Omit to LEARN it and
    /// print it — which is not pinning, and the output says so.
    #[arg(long, env = "TWINSIM_CP_SERVER_KEY")]
    server_key: Option<String>,
    /// Which C1 command to send. `services/control-plane/src/wire.rs` assigns
    /// the codes; 30 is `DiscoverPeers`, which the control plane serves without
    /// an Owner trust anchor bound.
    #[arg(long, default_value_t = 30)]
    code: u16,
}

#[derive(Subcommand)]
enum IssuerAction {
    /// Generate the seed if absent and write each relay's `issuer-keys.json`.
    ///
    /// Idempotent and non-rotating: an existing seed is reused, because
    /// rotating it would invalidate every token the running stack holds and
    /// present as relays refusing binds for no visible reason.
    Init {
        /// Where the signing seed lives. NEVER mounted into a relay.
        #[arg(long, default_value = "infra/secrets/dev-issuer/seed.bin")]
        seed: PathBuf,
        /// Each relay's secret directory, one `--relay-secrets` per relay.
        #[arg(long, default_values = ["infra/secrets/relay-a", "infra/secrets/relay-b"])]
        relay_secrets: Vec<PathBuf>,
        /// The operator group. Must equal every relay's
        /// `TWINVPN_RELAY_OPERATOR_GROUP_ID`, or the key set is refused at load.
        #[arg(long, default_value = DEV_OPERATOR_GROUP)]
        operator_group: String,
    },
}

#[derive(Subcommand)]
enum MapAction {
    /// Derive each relay's static PUBLIC key and write the development map.
    Init {
        /// Where to write it.
        #[arg(long, default_value = "infra/secrets/dev-issuer/relay-map.json")]
        out: PathBuf,
        /// `id=endpoint=region=failure_domain=path/to/static-noise.key`, repeated.
        #[arg(long = "relay", required = true)]
        relays: Vec<String>,
        /// The operator group.
        #[arg(long, default_value = DEV_OPERATOR_GROUP)]
        operator_group: String,
    },
}

#[derive(Parser)]
struct PeerArgs {
    /// Which relay in the map to bind.
    #[arg(long, env = "TWINSIM_RELAY_ID")]
    relay_id: String,
    /// The development relay map.
    #[arg(
        long,
        env = "TWINSIM_RELAY_MAP",
        default_value = "/run/secrets/twinsim/relay-map.json"
    )]
    map: PathBuf,
    /// The development issuer seed.
    #[arg(
        long,
        env = "TWINSIM_ISSUER_SEED",
        default_value = "/run/secrets/twinsim/seed.bin"
    )]
    seed: PathBuf,
    /// The local socket. `[::]:0` runs the leg on v6, `0.0.0.0:0` on v4 —
    /// which is what makes the v4-only and v6-only compose profiles differ.
    #[arg(long, env = "TWINSIM_LOCAL_ADDR", default_value = "[::]:0")]
    local: SocketAddr,
    /// This peer's identity seed. Two peers sharing one is a subject collision
    /// and a shared per-subject quota.
    #[arg(long, env = "TWINSIM_PEER_SEED")]
    peer_seed: String,
    /// The secret both halves of a pair derive their `pair_tag` from.
    #[arg(long, env = "TWINSIM_PAIR_SECRET")]
    pair_secret: String,
    /// How many pairs this peer drives. 1 for a client; one per fronted peer
    /// for a gateway (ADR-0013).
    #[arg(long, env = "TWINSIM_PAIRS", default_value_t = 1)]
    pairs: u32,
    /// `max_binds_per_min` in the minted token. ADR-0006 §11.15(b) requires
    /// this to be raisable for a gateway, or a ~15-peer ceiling stands.
    #[arg(long, env = "TWINSIM_MAX_BINDS_PER_MIN", default_value_t = 30)]
    max_binds_per_min: u32,
    /// The admin listener. Operator-facing; NOT a device-facing surface.
    #[arg(long, env = "TWINSIM_ADMIN_ADDR", default_value = "[::]:9090")]
    admin: SocketAddr,
}

#[derive(Parser)]
struct ProbeArgs {
    #[command(flatten)]
    peer: PeerArgs,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match dispatch() {
        Ok(code) => code,
        Err(e) => {
            // `{e:#}` so the anyhow chain prints its cause. A one-line "error"
            // over a misconfigured mount is how an hour goes missing.
            eprintln!("twinsim: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Issuer { action } => issuer_init(action).map(|()| ExitCode::SUCCESS),
        Command::Map { action } => map_init(action).map(|()| ExitCode::SUCCESS),
        Command::Peer(args) => runtime()?.block_on(peer(args)).map(|()| ExitCode::SUCCESS),
        Command::Probe(args) => runtime()?.block_on(probe(args.peer)),
        Command::Ceremony(args) => runtime()?.block_on(ceremony(args)),
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn issuer_init(action: IssuerAction) -> anyhow::Result<()> {
    let IssuerAction::Init {
        seed,
        relay_secrets,
        operator_group,
    } = action;
    let issuer = DevIssuer::load_or_create(&seed, DEV_ISSUER_KEY_ID, &operator_group)?;
    println!("==> development issuer");
    println!(
        "    seed:           {} (0600, NEVER mounted into a relay)",
        seed.display()
    );
    println!("    key_id:         {DEV_ISSUER_KEY_ID}");
    println!("    operator group: {operator_group}");

    let json = issuer.key_set_json();
    for dir in &relay_secrets {
        let path = dir.join("issuer-keys.json");
        std::fs::create_dir_all(dir)?;
        std::fs::write(&path, &json)?;
        println!("    wrote {}", path.display());
    }
    println!();
    println!("    Every relay must run with TWINVPN_RELAY_OPERATOR_GROUP_ID={operator_group}");
    println!("    and TWINVPN_RELAY_EPOCH_FLOOR <= {DEV_EPOCH}, or nothing binds.");
    Ok(())
}

fn map_init(action: MapAction) -> anyhow::Result<()> {
    let MapAction::Init {
        out,
        relays,
        operator_group,
    } = action;
    let mut entries = Vec::with_capacity(relays.len());
    for spec in &relays {
        let parts: Vec<&str> = spec.split('=').collect();
        anyhow::ensure!(
            parts.len() == 5,
            "--relay wants id=endpoint=region=failure_domain=static_key_path, got `{spec}`"
        );
        entries.push(RelayEntry::from_static_key_file(
            parts[0],
            parts[1],
            parts[2],
            parts[3],
            std::path::Path::new(parts[4]),
        )?);
    }
    let map = DevRelayMap::new(&operator_group, entries);
    map.write(&out)?;
    println!("==> development relay map (UNSIGNED — key distribution, not verification)");
    for r in &map.relays {
        println!(
            "    {} {} {}/{} {}",
            r.relay_id, r.endpoint, r.region, r.failure_domain, r.static_noise_public_key_hex
        );
    }
    println!("    wrote {}", out.display());
    Ok(())
}

/// Builds the shared pieces both `peer` and `probe` need.
fn prepare(args: &PeerArgs) -> anyhow::Result<(Arc<DevIssuer>, RelayEntry)> {
    let map = DevRelayMap::load(&args.map)?;
    let relay = map
        .find(&args.relay_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "relay `{}` is not in {}. The map has: {}",
                args.relay_id,
                args.map.display(),
                map.relays
                    .iter()
                    .map(|r| r.relay_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?
        .clone();
    let issuer = DevIssuer::load_or_create(&args.seed, DEV_ISSUER_KEY_ID, &map.operator_group_id)?;
    Ok((Arc::new(issuer), relay))
}

async fn peer(args: PeerArgs) -> anyhow::Result<()> {
    let (issuer, relay) = prepare(&args)?;
    let state = SimState::new();
    let family = if args.local.is_ipv6() { "v6" } else { "v4" };

    tokio::spawn(twinsim::admin::serve(
        args.admin,
        Arc::clone(&state),
        family.to_owned(),
    ));

    run_peer(
        PeerConfig {
            relay,
            local: args.local,
            seed: args.peer_seed,
            pair_secret: args.pair_secret,
            pairs: args.pairs,
            max_binds_per_min: args.max_binds_per_min,
        },
        issuer,
        state,
    )
    .await
}

/// Attaches to the control plane and runs one C1 command.
///
/// Exits non-zero when the handshake or the exchange fails, so it is usable as
/// a CI smoke test: a control plane that is READY but refuses every device is
/// exactly the state a `/readyz` probe cannot see.
async fn ceremony(args: CeremonyArgs) -> anyhow::Result<ExitCode> {
    // The identity. `FixtureIdentity` is `twinvpn-crypto`'s, behind the
    // never-shipped `test-support` feature, and it owns the DER encodings —
    // CD-I2 puts every key encoding in that crate, and a lab crate assembling
    // its own SPKI around a P-256 point would be the second key-handling path
    // CD-I2 exists to forbid.
    let identity = twinvpn_crypto::testkit::FixtureIdentity::from_seed(args.device_seed.as_bytes());
    let spki = identity.spki_der();

    let server_key = match &args.server_key {
        Some(hex) => ServerKey::Trusted(
            unhex(hex).ok_or_else(|| anyhow::anyhow!("--server-key must be lowercase base16"))?,
        ),
        None => ServerKey::LearnOnFirstUse,
    };

    let transport = QuicControlTransport::new(
        args.local,
        args.cp,
        // The SNI name. The server authenticates by KEY, not by name (ADR-0001
        // §6 rejected the naming system a certificate implies), so this is a
        // required TLS field carrying no authority. Saying that here beats
        // someone later assuming it is checked.
        "control-plane.twinvpn.invalid",
        identity.pkcs8_der(),
        spki.clone(),
        server_key,
    )?;

    println!(
        "device raw public key (SPKI): {}",
        twinsim::issuer::hex(&spki)
    );

    let attached = transport
        .attach_quic()
        .await
        .map_err(|e| anyhow::anyhow!("rung 1 attach failed: {e}"))?;

    println!("attach: rung 1 (QUIC + TLS 1.3, mutual RFC 7250 raw public keys)");
    if let Some(key) = attached.server_key() {
        println!("server raw public key: {}", twinsim::issuer::hex(&key));
        if args.server_key.is_none() {
            println!(
                "  NOTE: this was LEARNED, not pinned. Pass it as --server-key on the \
                 next run to make the attach authenticated (ADR-0001 §7.2)."
            );
        }
    }

    // The channel binding, read off the LIVE connection (ADR-0002 N-2).
    let binding = attached.channel_binding();
    anyhow::ensure!(
        binding.as_bytes() != [0_u8; 32],
        "the tls-exporter read back as all zeros: the connection completed but N-2's channel \
         binding is unavailable, and every Auth.channel_binding check would fail"
    );
    println!("channel binding: {}", binding.to_hex());

    // One C1 round trip. An empty body is deliberate: this asserts the
    // FRAMING and the ATTACH, not a command's semantics. The control plane
    // answers a well-framed request it cannot satisfy with a typed refusal,
    // and a refusal that arrives is a completed ceremony — an unparseable
    // frame closes the connection instead, which is what this distinguishes.
    match attached.command(args.code, &[]).await {
        Ok((code, body)) => {
            println!(
                "C1 exchange: sent code {} -> answered code {code}, {} body octets",
                args.code,
                body.len()
            );
            println!("the control plane completed a real C1 round trip");
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!(
                "twinsim ceremony: the C1 exchange failed: {e}. A closed stream here means the \
                 control plane refused the FRAME, not the command."
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

/// Decodes lowercase base16.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// The first 16 octets of SHA-256 over `s`.
fn digest16(s: &str) -> [u8; 16] {
    let d = twinvpn_crypto::sha256(s.as_bytes());
    let mut out = [0_u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// One-shot: establish a leg, bind once, report, exit.
///
/// Exits non-zero for anything but a `BOUND` or a `PENDING`. A pending slot is
/// a success here because a probe run alone has no partner — the relay
/// answering `PENDING` means admission, token verification and the `pair_tag`
/// rendezvous all worked, and only the second half is missing.
async fn probe(args: PeerArgs) -> anyhow::Result<ExitCode> {
    let (issuer, relay) = prepare(&args)?;
    let relay_addr = relay.socket_addr()?;
    let relay_static = relay.static_public()?;
    let relay_id = relay.relay_id_bytes()?;

    let socket = tokio::net::UdpSocket::bind(args.local).await?;
    socket.connect(relay_addr).await?;

    let mut device = SimDevice::new(args.peer_seed.as_bytes())?;
    // The `jti` is FRESH PER RUN, and it has to be.
    //
    // ADR-0005 §11.3 ends token verification with "`jti` unseen", against a
    // bounded replay cache the relay holds for the token's lifetime. A probe
    // that minted a constant `jti` succeeded exactly once against a given
    // relay process and was then refused as a replay for the next 24 hours —
    // silently, because §11.5 makes an unauthorised handshake a zero-byte
    // drop. That is what the first version of this command did, and the
    // symptom was indistinguishable from a misconfigured issuer key set.
    let now = now_ms()?;
    let subject = digest16(&format!("{}|sub", args.peer_seed));
    let jti = digest16(&format!("{}|jti|{now}", args.peer_seed));
    let spec = TokenSpec::admitting(*device.rlk_public(), subject, jti, now, DEV_EPOCH);

    let leg = device
        .establish(&socket, relay_addr, &relay_static, &issuer, &spec)
        .await?;
    println!("leg:  {}", leg.name());
    if !leg.is_established() {
        eprintln!(
            "twinsim probe: no leg. Check that the relay runs with \
             TWINVPN_RELAY_OPERATOR_GROUP_ID={} and that its issuer-keys.json is the one \
             `twinsim issuer init` wrote.",
            issuer.operator_group()
        );
        return Ok(ExitCode::FAILURE);
    }

    let bucket = current_bucket()?;
    // Slot 0: the same derivation a running peer uses for its first pair, so a
    // probe and a `twinsim peer` can genuinely meet on one tag.
    let tag = pair_tag_for(&args.pair_secret, 0, &relay_id, bucket)?;
    let outcome = device.bind(&socket, relay_addr, tag, bucket).await?;
    match outcome {
        BindOutcome::Bound => {
            println!("bind: bound (flow {:?})", device.flow_id());
            Ok(ExitCode::SUCCESS)
        }
        BindOutcome::Pending { ttl_ms } => {
            println!("bind: pending, the relay gives the partner {ttl_ms} ms");
            Ok(ExitCode::SUCCESS)
        }
        BindOutcome::Status => {
            eprintln!("bind: RELAY_STATUS — the relay is shedding, draining or overloaded");
            Ok(ExitCode::FAILURE)
        }
        BindOutcome::Unauthenticated => {
            eprintln!(
                "bind: the reply did NOT verify under K_leg. This is a security event, \
                       not packet loss."
            );
            Ok(ExitCode::FAILURE)
        }
        BindOutcome::Silent => {
            eprintln!(
                "bind: silent. ADR-0005 §11.5 makes an unauthorised BIND a silent drop, \
                       so this is a refusal the relay declined to explain."
            );
            Ok(ExitCode::FAILURE)
        }
    }
}
