//! `twinpeer serve` — the far end of the lane's tunnel.
//!
//! One Wintun adapter, one UDP socket, and a loop of
//! *listen → handshake as responder → pump → a new initiation stops the pump*.
//! The handshake is [`twinvpn_core::lab::drive`] and the packet path is
//! [`twinvpn_core::lab::Pump`]: the product's own, so a guest cannot tell this
//! peer from a device (`docs/testing-strategy.md` §3.1).
//!
//! # What this binary deliberately does NOT do
//!
//! It never touches `NetworkConfig`. `WindowsPlatformAdapter::new` opens the WFP
//! engine handle because the adapter is one object, but nothing here calls
//! `apply`, `set_ruleset`, `reclaim` or `commit`, so **no filter is ever
//! installed on the lab host**. It holds no vault, presents
//! [`twinvpn_platform_windows::custody::AbsentElement`] and reports
//! `Tier1Backend::Absent`, because a peer that signed nothing needs no identity
//! element and inventing one would be a claim about custody that is not true.
//!
//! # Re-handshake, and why it needs a wrapper
//!
//! The lane restarts the service twice, and each restart is a fresh handshake
//! from the same guest. Once a pump owns the socket the new initiation would
//! arrive as a frame the pump rejects, and the peer would go on pumping into a
//! tunnel whose keys the guest no longer holds. [`crate::sockets::Guard`] is
//! what turns that into a stop-and-re-handshake.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context as _, Result};
use twinvpn_core::lab::{
    deadline_from, drive, session_id_for, Attempt, Cancel, Pump, PumpParts, Refusal,
    MAX_HANDSHAKE_DATAGRAM_BYTES, OVERLAY_MTU,
};
use twinvpn_env::binding::tokio_rt::TokioRuntime;
use twinvpn_env::{ElapsedClock, Entropy, Env, EnvParts, MonotonicClock, Runtime, SystemRngSource};
use twinvpn_platform::socket::{SocketFamily, SocketOptions, UdpBindSpec, UdpSocket};
use twinvpn_platform::{InterfaceName, LinkState, PlatformAdapter, TunnelHandle};
use twinvpn_platform_windows::clock::{
    WallClockTrust, WindowsElapsedClock, WindowsEntropy, WindowsMonotonicClock, WindowsWallClock,
};
use twinvpn_platform_windows::wintun;
use twinvpn_types::Endpoint;

use crate::seedfile::{ResolvedSeed, SeedFile};
use crate::sockets::{classify, Captured, Guard, Kind, Replay};

/// What `serve` was asked for.
pub struct ServeArgs {
    /// `peer.json`, as `twinpeer seed --peer-out` wrote it.
    pub peer_file: PathBuf,
    /// The Wintun adapter's name.
    pub adapter_name: String,
    /// A directory holding `wintun.dll`, copied beside this binary if it is not
    /// already there.
    ///
    /// `WintunDriver::load` searches the **application directory and nowhere
    /// else** — `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, which is ADR-0016 §11.9's
    /// intention at the call site. That property is not weakened for a lab tool,
    /// so the DLL is brought to the loader rather than the loader sent after it.
    pub wintun_dll: Option<PathBuf>,
    /// Where scratch state would go, if there were any. Never written to.
    pub state_dir: PathBuf,
}

/// The line the lane waits for before it assigns the overlay addresses.
pub const ADAPTER_READY: &str = "TWINPEER_ADAPTER_READY";

/// Runs until the process is killed.
///
/// # Errors
///
/// A malformed seed, a driver that will not load, an adapter that will not be
/// created, or a socket that will not bind. Every one of them is fatal: a peer
/// that cannot answer is a lane that should fail loudly rather than one that
/// reports a silent ARMED phase for the wrong reason.
pub fn run(args: &ServeArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.peer_file)
        .with_context(|| format!("could not read {}", args.peer_file.display()))?;
    let file: SeedFile =
        serde_json::from_str(&text).context("the peer seed is not well-formed JSON")?;
    let seed = file.resolve().context("the peer seed is malformed")?;
    let Some(bind) = seed.bind else {
        bail!("the peer seed carries no `local.bind`; that is the guest half, not the peer half");
    };
    tracing::warn!(
        twinnet = %file.twinnet_id,
        "LAB PEER ACTIVE: this binary is not a release artifact"
    );

    stage_wintun(args.wintun_dll.as_deref())?;

    let (env, runtime) = build_env()?;
    let adapter = build_adapter(&args.state_dir)?;

    let mut outcome = Ok(());
    runtime.block_on(Box::pin(async {
        outcome = serve(&env, &adapter, &seed, bind, &args.adapter_name).await;
    }));
    outcome
}

/// Brings `wintun.dll` into the loader's one search directory.
fn stage_wintun(from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        return Ok(());
    };
    let exe = std::env::current_exe().context("could not locate this binary")?;
    let target = exe
        .parent()
        .context("this binary has no directory")?
        .join(wintun::WINTUN_DLL);
    if target.exists() {
        return Ok(());
    }
    let source = from.join(wintun::WINTUN_DLL);
    std::fs::copy(&source, &target).with_context(|| {
        format!(
            "could not place {} beside this binary from {}",
            wintun::WINTUN_DLL,
            source.display()
        )
    })?;
    tracing::info!(path = %target.display(), "staged wintun.dll for the application-directory loader");
    Ok(())
}

/// The capability set, from the same bindings the Windows service uses.
///
/// The entropy source is **probed here**: a CSPRNG that refuses is a peer that
/// cannot draw a receiver index, and finding that out at start is strictly
/// better than finding it out inside a handshake. On a host that is not Windows
/// this refuses, which is the honest answer — `clock::fill_random`'s
/// non-Windows sibling fails closed rather than producing synthetic bytes.
fn build_env() -> Result<(Env, Arc<TokioRuntime>)> {
    let windows_entropy = WindowsEntropy::new();
    windows_entropy
        .probe()
        .map_err(|e| anyhow::anyhow!("the platform CSPRNG is unavailable: {e}"))?;
    let entropy: Arc<dyn Entropy> = Arc::new(windows_entropy);

    let monotonic: Arc<dyn MonotonicClock> = WindowsMonotonicClock::shared();
    let elapsed: Arc<dyn ElapsedClock> = WindowsElapsedClock::shared();
    let runtime = Arc::new(
        TokioRuntime::work_stealing()
            .map_err(|e| anyhow::anyhow!("the async runtime could not be built: {e}"))?,
    );
    let timer = runtime.timer(Arc::clone(&monotonic));
    let env = Env::new(EnvParts {
        monotonic,
        elapsed,
        // The same claim the service makes: this build does not query the
        // Windows Time service, so it claims nothing.
        wall: WindowsWallClock::shared(WallClockTrust::Unsynchronised),
        timer,
        runtime: Arc::clone(&runtime) as Arc<dyn Runtime>,
        entropy: Arc::clone(&entropy),
        rng: Arc::new(SystemRngSource::new(entropy)),
    });
    Ok((env, runtime))
}

#[cfg(windows)]
fn build_adapter(
    state_dir: &Path,
) -> Result<Arc<twinvpn_platform_windows::WindowsPlatformAdapter>> {
    let driver = Arc::new(
        wintun::WintunDriver::load()
            .map_err(|e| anyhow::anyhow!("wintun.dll could not be loaded: {e}"))?,
    );
    use twinvpn_platform_windows::custody;
    let adapter = twinvpn_platform_windows::WindowsPlatformAdapter::new(
        twinvpn_platform_windows::WindowsAdapterParts {
            // Every field is the pre-arming value, and NOTHING here renders or
            // commits a filter: the peer holds no `NetworkContract` and never
            // calls `apply`. The overlay LUID stays `0` in this struct and is
            // published by the tunnel device when the adapter is created, which
            // is the only reason it is not a lie.
            enforcement: twinvpn_platform_windows::wfp::EnforcementConfig {
                overlay_luid: 0,
                service_app_id: "",
                service_sid: "",
                local_network_access: true,
                on_link_prefixes: Vec::new(),
                updater_app_id: None,
                update_origins: Vec::new(),
                portal_grant: Vec::new(),
                doh_endpoints: Vec::new(),
            },
            stub: stub_addresses()?,
            store_root: state_dir.to_path_buf(),
            restore_point_path: state_dir.join("resolver.restore"),
            // §11.16 (l): reported truthfully. The peer signs nothing, so an
            // absent element is the fact rather than a degradation.
            identity_element: Arc::new(custody::AbsentElement),
            tier1_backend: custody::Tier1Backend::Absent,
            tunnel_driver: driver,
        },
    )
    .map_err(|e| anyhow::anyhow!("the Windows adapter could not be opened: {e}"))?;
    Ok(Arc::new(adapter))
}

#[cfg(not(windows))]
fn build_adapter(
    _state_dir: &Path,
) -> Result<Arc<twinvpn_platform_windows::WindowsPlatformAdapter>> {
    // Named rather than stubbed. A peer that pretended to hold an adapter on a
    // host with no Wintun would make a green lane mean nothing.
    bail!("`twinpeer serve` needs a Windows host: there is no Wintun adapter here")
}

/// ADR-0011 §11.2's four stub addresses. Injected because the adapter takes
/// them; never used, because the peer programs no resolver.
#[cfg(windows)]
fn stub_addresses() -> Result<twinvpn_platform_windows::dns::StubAddresses> {
    use twinvpn_types::{IpAddr, V4Addr, V6Addr};
    let mut anycast6 = [0u8; 16];
    anycast6[..6].copy_from_slice(&[0xfd, 0x7c, 0x9e, 0x5d, 0x2a, 0x10]);
    anycast6[6] = 0xff;
    anycast6[7] = 0xff;
    anycast6[15] = 0x53;
    let mut loopback6 = [0u8; 16];
    loopback6[15] = 1;
    Ok(twinvpn_platform_windows::dns::StubAddresses {
        loopback_v4: IpAddr::V4(V4Addr::from_octets([127, 0, 0, 53])),
        loopback_v6: IpAddr::V6(V6Addr::new(loopback6, None).context("::1")?),
        anycast_v4: IpAddr::V4(V4Addr::from_octets([100, 127, 255, 53])),
        anycast_v6: IpAddr::V6(V6Addr::new(anycast6, None).context("the service anycast")?),
    })
}

async fn serve(
    env: &Env,
    adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
    seed: &ResolvedSeed,
    bind: Endpoint,
    adapter_name: &str,
) -> Result<()> {
    // The adapter first, then the socket, then the ready line. The lane blocks
    // on that line and only then runs `New-NetIPAddress`, so everything the peer
    // needs in order to answer has to exist before it is printed — a READY the
    // socket had not yet reached would let the lane bring the guest up against a
    // peer that cannot receive.
    let name = InterfaceName::new(adapter_name)
        .map_err(|e| anyhow::anyhow!("`{adapter_name}` is not a usable interface name: {e}"))?;
    let handle = adapter
        .tunnel()
        .create_interface(&name, OVERLAY_MTU)
        .await
        .map_err(|e| anyhow::anyhow!("the Wintun adapter could not be created: {e}"))?;
    // The peer's adapter carries traffic immediately: unlike a client's, there is
    // no contract to apply first and nothing to leak into.
    let outcome = bring_up(env, adapter, seed, bind, handle).await;

    // Always, on every exit: an adapter left behind holds the overlay addresses
    // the next run assigns.
    let _ = adapter.tunnel().set_link(handle, LinkState::Down).await;
    let _ = adapter.tunnel().destroy_interface(handle).await;
    outcome
}

/// Everything between a created adapter and the supervisor, so `serve` can tear
/// the adapter down on every path out of it.
async fn bring_up(
    env: &Env,
    adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
    seed: &ResolvedSeed,
    bind: Endpoint,
    handle: TunnelHandle,
) -> Result<()> {
    adapter
        .tunnel()
        .set_link(handle, LinkState::Up)
        .await
        .map_err(|e| anyhow::anyhow!("the Wintun link would not come up: {e}"))?;
    let luid = adapter
        .tunnel_device()
        .luid_of(handle)
        .context("the created adapter reported no LUID")?;

    let socket: Arc<dyn UdpSocket> = Arc::from(
        adapter
            .sockets()
            .bind_udp(&UdpBindSpec {
                family: SocketFamily::V4,
                local: Some(bind),
                options: SocketOptions::default(),
            })
            .await
            .map_err(|e| anyhow::anyhow!("could not bind the underlay socket: {e}"))?,
    );
    tracing::info!(
        bound = ?socket.local_endpoint().ok(),
        overlay_v4 = ?seed.local_overlay.0,
        overlay_v6 = ?seed.local_overlay.1,
        "the underlay socket is bound; the lane assigns the overlay addresses"
    );

    // The lane blocks on this line, on STDOUT, before it runs New-NetIPAddress.
    println!("{ADAPTER_READY} {}", luid.0);
    let _ = std::io::Write::flush(&mut std::io::stdout());

    supervise(env, adapter, seed, &socket, handle).await
}

/// listen → handshake → pump → a new initiation stops the pump → listen.
async fn supervise(
    env: &Env,
    adapter: &Arc<twinvpn_platform_windows::WindowsPlatformAdapter>,
    seed: &ResolvedSeed,
    socket: &Arc<dyn UdpSocket>,
    handle: TunnelHandle,
) -> Result<()> {
    // Built once and borrowed by every attempt: `Attempt` takes the keying by
    // reference precisely so a refusal leaves it where the next attempt looks.
    let keying = seed.keying()?;
    let session = session_id_for(seed.peer_device);
    let mut pending: Option<Captured> = None;

    loop {
        let (datagram, source) = match pending.take() {
            Some(captured) => captured,
            None => listen(socket.as_ref()).await?,
        };
        tracing::info!(?source, "an initiation arrived; answering as responder");

        let replay = Replay::new(Arc::clone(socket), (datagram, source));
        let attempt = Attempt {
            session,
            local_device: seed.local_device,
            peer: seed.peer_device,
            // The initiation's source, never the seed's: that is the only
            // address that is right through a NAT, and the guest's port is
            // ephemeral.
            peer_endpoint: Some(source),
            keying: Some(&keying),
            trust_epoch: seed.trust_epoch,
        };
        let handshaken =
            match drive(env, &replay, attempt, deadline_from(env.now_monotonic())).await {
                Ok(handshaken) => handshaken,
                Err(refusal) => {
                    // §7.3.1 P-3 keeps the causes indistinguishable on the wire; the
                    // registered code is what a lane operator reads.
                    tracing::warn!(
                        code = %code_of(&refusal),
                        "the handshake was refused; returning to listen"
                    );
                    continue;
                }
            };
        tracing::info!("the handshake completed; the tunnel is carrying");

        let cancel = Cancel::new();
        let guard = Arc::new(Guard::new(Arc::clone(socket), cancel.clone()));
        let pump = Pump::new(PumpParts {
            env: env.clone(),
            adapter: Arc::clone(adapter) as Arc<dyn PlatformAdapter>,
            handle,
            socket: Arc::clone(&guard) as Arc<dyn UdpSocket>,
            tunnel: handshaken.tunnel,
            local_receiver: handshaken.local_receiver,
            peer_receiver: handshaken.peer_receiver,
            // The guest's own, from `twinvpn_core::enforce::MTU`. A peer that
            // chose its own would size its buffers below the guest's records.
            overlay_mtu: OVERLAY_MTU,
            cancel,
        })
        .map_err(|refused| anyhow::anyhow!("the pump was refused: {refused}"))?;

        // ponytail: both directions on one task. `WindowsTunnelDevice::read_packet`
        // polls the Wintun ring with `yield_now`, so a separate task would burn
        // the same core for the same reason; a readiness integration over
        // `WintunGetReadWaitEvent` is what would actually fix it, and that is
        // the adapter's work rather than this binary's.
        let (outbound, inbound) = tokio::join!(pump.run_outbound(), pump.run_inbound());
        tracing::info!(
            outbound = ?outbound.stop,
            inbound = ?inbound.stop,
            packets_out = outbound.counters.packets,
            packets_in = inbound.counters.packets,
            "the pump stopped"
        );
        pending = guard.take_initiation();
    }
}

/// Reads until an initiation arrives, discarding everything else.
///
/// The buffer is sized from [`MAX_HANDSHAKE_DATAGRAM_BYTES`] — a constant, never
/// a length a sender declared. A larger datagram is truncated and then refused by
/// `drive`, which is where a malformed initiation belongs.
async fn listen(socket: &dyn UdpSocket) -> Result<Captured> {
    let mut buf = vec![0u8; MAX_HANDSHAKE_DATAGRAM_BYTES];
    loop {
        let arrival = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("the underlay socket failed: {e}"))?;
        match classify(&buf[..arrival.len]) {
            Kind::Initiation => return Ok((buf[..arrival.len].to_vec(), arrival.source)),
            Kind::Probe => {
                tracing::debug!(source = ?arrival.source, "discarded a reachability probe");
            }
            Kind::Carry => {
                tracing::debug!(
                    source = ?arrival.source,
                    len = arrival.len,
                    "discarded a datagram that is not an initiation"
                );
            }
        }
    }
}

/// The registered code a refusal reports as, for the log line.
fn code_of(refusal: &Refusal) -> &'static str {
    refusal.reason_code().as_str()
}
