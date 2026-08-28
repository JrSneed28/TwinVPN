//! `twinvpn-relay` — process entry point.
//!
//! The wiring order is `twinvpn-service-common`'s README §2: configuration
//! before observability, health before shutdown, the admin listener last.
//!
//! Two things differ from the other five services, and both are load-bearing:
//!
//! 1. **`ReadinessPolicy::NoControlPlaneCalls`.** Structural I5: the registry
//!    *refuses* a probe declaring `ProbeKind::ControlPlane`, so a relay cannot
//!    acquire a control-plane readiness dependency by accident. ADR-0005 §11.3
//!    and architecture A-12: admission is offline, so a relay must come up and
//!    stay up with the whole control plane down.
//! 2. **The issuer key set is loaded at startup and a failure is fatal**, but an
//!    *empty* set is not. `infra/scripts/bootstrap-local.sh` ships `issuers: []`
//!    on purpose; a relay with no issuers is correctly configured and correctly
//!    admits nothing. A relay whose key file is missing or corrupt is genuinely
//!    broken and refuses to start.
#![forbid(unsafe_code)]

use std::sync::Arc;

use twinvpn_relay::admit::LegSetup;
use twinvpn_relay::config::RelayConfig;
use twinvpn_relay::drr::TwoTierDrr;
use twinvpn_relay::entropy::SystemEntropy;
use twinvpn_relay::issuer::IssuerKeySet;
use twinvpn_relay::leg::{CookieJar, LegRegistry};
use twinvpn_relay::loop_udp::{serve_udp, RelayRuntime};
use twinvpn_relay::net::CarriageSet;
use twinvpn_relay::provider::CryptoProvider;
use twinvpn_relay::register::{dual_stack, RelayDescriptor};
use twinvpn_relay::RelayEngine;
use twinvpn_service_common as svc;

/// The leg-registry ceiling.
///
/// A leg is created by an unauthenticated source completing a handshake, so an
/// unbounded map keyed by source address is a remote memory-exhaustion primitive
/// (`ownership.md` §6 rule 10). 65 536 legs is the same order as the relay-wide
/// half-flow ceiling and is stated as an addition, like that one.
const MAX_LEGS: usize = 65_536;

/// The most legs one source /24 (v4) or /48 (v6) may hold.
///
/// **Also an addition, stated as one.** ADR-0005 §11.5 rate-limits *handshakes*
/// per /24 and /48 but bounds no occupancy, and a global ceiling alone does not
/// close the hole: a /64 is 2^64 addresses, so one subnet can fill the whole
/// table at the permitted 20 handshakes/s given time. 1 024 is 1/64th of
/// [`MAX_LEGS`] — enough for a large NAT or a campus behind one prefix, small
/// enough that sixty-four such prefixes are needed to exhaust the relay.
const MAX_LEGS_PER_PREFIX: usize = 1_024;

/// How long an established leg survives with no frame on it.
///
/// The same 15 minutes ADR-0005 §11.5 gives an idle *half-flow*, because a leg
/// with no live half-flow is exactly as reclaimable and the two would otherwise
/// expire in an order that depends on which limit was configured lower.
const LEG_IDLE_TIMEOUT_MS: u64 = 900_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration. A missing file, an altered frozen limit, or
    //    TWINVPN_RELAY_RETAIN_PEER_PAIR=true fails HERE.
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        "relay",
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_RELAY_SERVER",
        svc::config::RegistryCheck::Required,
    )?;
    let relay_cfg = RelayConfig::load(&svc::config::SystemEnv)?;

    // 2. Metrics, then observability.
    //
    // `observability()` uses the RESOLVED `TWINVPN_INSTANCE_ID`, which compose
    // supplies from the container hostname. Passing `relay_id_hex` here instead
    // looked stable — it is per-instance and comes from configuration — but it
    // ignores the id the operator actually chose, so a fleet query keyed on
    // `service.instance.id` would not match anything an operator set.
    let metrics = svc::metrics::Metrics::new();
    let obs = svc::obs::init(&cfg.observability(), metrics.clone())?;
    // Logged AFTER the subscriber is installed, so the WARN on the per-process
    // fallback actually reaches a log.
    cfg.log_instance_id_resolution();

    // 3. The issuer key set. Empty is legal and means "admit nothing".
    let issuers = IssuerKeySet::load(&relay_cfg.issuer_keys_path, &relay_cfg.operator_group_id)?;
    if issuers.is_empty() {
        tracing::warn!(
            outcome = "closed",
            "issuer key set is empty: no RelayCapabilityToken can verify, so this \
             relay will admit no flow. That is the fail-closed default."
        );
    }

    // 4. The cryptographic provider. `twinvpn-crypto` (ADR-0018 CD-I2, DP-8):
    //    COSE_Sign1 verification over the received octets, the keyed BLAKE2s
    //    frame MAC, and the daily relay_sub digest. All three are bound.
    let crypto = CryptoProvider::new();
    if !crypto.frame_mac_available() {
        // Kept rather than deleted: a build that again could not MAC must say so
        // once, rather than present as a flood of dropped frames.
        tracing::error!(
            outcome = "partial_provider",
            "the keyed BLAKE2s frame MAC (ADR-0005 §9.1) is unavailable in this \
             build: admission and the epoch floor are live, but NO DATA FRAME \
             WILL BE FORWARDED. See services/relay/README.md §8."
        );
    }

    // 5. Carriages. A carriage this build cannot serve is recorded, not faked.
    let mut carriages = CarriageSet::bind(&relay_cfg).await?;
    let all_bound = carriages.all_configured_carriages_bound();
    for (carriage, why) in &carriages.unavailable {
        tracing::error!(
            outcome = "unavailable",
            carriage = carriage.as_str(),
            detail = why.as_str(),
            "configured carriage is not served; readiness will stay RED"
        );
    }
    // Each bound socket is shared between its receive loop and the drain, which
    // has to be able to send a `DRAIN` frame after the loops have been told to
    // stop reading. Wrapped once here rather than per consumer, so the two
    // cannot end up holding different sockets.
    let bound_sockets: Vec<(
        Arc<tokio::net::UdpSocket>,
        std::net::SocketAddr,
        &'static str,
    )> = core::mem::take(&mut carriages.bound)
        .into_iter()
        .map(|b| (Arc::new(b.socket), b.local_addr, b.families.as_label()))
        .collect();
    let listening = bound_sockets.len();
    let drain_sockets: Arc<Vec<Arc<tokio::net::UdpSocket>>> = Arc::new(
        bound_sockets
            .iter()
            .map(|(s, _, _)| Arc::clone(s))
            .collect(),
    );

    // 6. Leg establishment: the static Noise key, the CSPRNG and the cookie
    //    secret. A relay that cannot assemble all three establishes NO LEG and
    //    forwards nothing — the same fail-closed direction as an empty issuer key
    //    set — and says so once here rather than one dropped handshake at a time.
    let setup = match assemble_leg_setup(&relay_cfg) {
        Ok(setup) => {
            match RelayDescriptor::build(&relay_cfg, setup.static_private.expose()) {
                Ok(descriptor) => {
                    if !dual_stack(&descriptor) {
                        // Reported, not refused: `infra/`'s IPv6-only profile is
                        // deliberate. But a relay reachable by half the fleet is
                        // worth one line at startup (docs/protocol.md §11.1).
                        tracing::warn!(
                            outcome = "single_family",
                            "this relay publishes only one address family; a device \
                             on the other cannot use it at all"
                        );
                    }
                    // The enrolment record, emitted so an operator's relay-map
                    // entry names the key this process actually holds. A map
                    // entry with the wrong static key fails every Noise_IK
                    // initiation at the responder, and a failed handshake is
                    // deliberately indistinguishable from noise.
                    match descriptor.to_json() {
                        Ok(json) => tracing::info!(
                            outcome = "registration_record",
                            "enrol this instance in the relay map as: {json}"
                        ),
                        Err(e) => tracing::error!(
                            outcome = "registration_unavailable",
                            "the enrolment record could not be rendered: {e}"
                        ),
                    }
                }
                Err(e) => tracing::error!(
                    outcome = "registration_unavailable",
                    "no enrolment record could be built: {e}. The relay still \
                     serves; the operator must supply a routable endpoint and a \
                     32-byte static key before enrolling it."
                ),
            }
            Some(Arc::new(setup))
        }
        Err(e) => {
            tracing::error!(
                outcome = "no_legs",
                "leg establishment is unavailable: {e}. NO DEVICE CAN ESTABLISH \
                 K_leg and every received frame is dropped with zero bytes in \
                 reply. This is the fail-closed direction; see \
                 services/relay/README.md §11."
            );
            None
        }
    };

    // 7. The runtime the receive loop drives.
    let runtime = Arc::new(std::sync::Mutex::new(RelayRuntime {
        engine: RelayEngine::new(relay_cfg.clone(), issuers, 0),
        legs: LegRegistry::new(MAX_LEGS, MAX_LEGS_PER_PREFIX, LEG_IDLE_TIMEOUT_MS),
        scheduler: TwoTierDrr::with_default_quantum(),
        setup,
    }));

    // 7. Health. NoControlPlaneCalls REFUSES a ProbeKind::ControlPlane probe,
    //    which is what makes I5 structural rather than remembered.
    let issuer_probe = {
        let runtime = Arc::clone(&runtime);
        svc::health::FnProbe::new("issuer_keys", svc::health::ProbeKind::Local, move || {
            // Loaded and parsable — NOT non-empty. infra/README.md §5.
            let ok = runtime.lock().is_ok();
            async move {
                if ok {
                    svc::health::ProbeOutcome::Ready
                } else {
                    svc::health::ProbeOutcome::NotReady(
                        twinvpn_types::codes::INTERNAL_INVARIANT_VIOLATED,
                    )
                }
            }
        })
    };
    let carriage_probe = svc::health::FnProbe::new(
        "carriages_bound",
        svc::health::ProbeKind::Local,
        move || async move {
            if all_bound {
                svc::health::ProbeOutcome::Ready
            } else {
                svc::health::ProbeOutcome::NotReady(twinvpn_types::codes::RELAY_NONE_REACHABLE)
            }
        },
    );

    let health =
        svc::health::HealthRegistry::builder(svc::health::ReadinessPolicy::NoControlPlaneCalls)
            .readiness(issuer_probe)?
            .readiness(carriage_probe)?
            .liveness(svc::health::FnLiveness::new("forwarder", || true))
            .build();

    // 8. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );

    // The relay's drain is ADR-0005 §8's, not a generic one: it announces one
    // deadline to every bound flow and then keeps carrying until that deadline.
    //
    // The announcement is a real `DRAIN` frame on each flow's own leg, MACed
    // under that leg's `K_leg`. ADR-0005 §11.5 permits the relay to originate
    // exactly two frames — `DRAIN` and `RELAY_STATUS` — and only "onto
    // already-bound, authenticated flows", which is what makes this the one
    // place in the process that sends without having received.
    {
        let runtime = Arc::clone(&runtime);
        let deadline = shutdown.drain_deadline_ms();
        let sockets = Arc::clone(&drain_sockets);
        shutdown.register_teardown(20, "relay_drain", move || {
            let runtime = Arc::clone(&runtime);
            let sockets = Arc::clone(&sockets);
            svc::shutdown::futures_step::boxed(async move {
                let announcements = {
                    let Ok(mut rt) = runtime.lock() else {
                        return;
                    };
                    let (plan, flows) = rt.engine.begin_drain(0, deadline);
                    let setup = rt.setup.clone();
                    let RelayRuntime {
                        engine,
                        legs,
                        scheduler,
                        ..
                    } = &mut *rt;
                    let pump = twinvpn_relay::pump::Pump {
                        engine,
                        legs,
                        scheduler,
                        crypto: &CryptoProvider::new(),
                        setup: setup.as_deref(),
                        last_source: "[::]:0".parse().expect("wildcard"),
                        pending_announcements: Vec::new(),
                    };
                    let out: Vec<_> = flows
                        .iter()
                        .filter_map(|f| {
                            // No suggested alternates: ADR-0006 §11.2 requires a
                            // device to re-rank against its own VERIFIED map, and
                            // this instance has no verified view of the fleet to
                            // suggest from. An empty list is honest; a guessed one
                            // would be a compromised relay's steering primitive
                            // wearing a shutdown's clothes.
                            pump.drain_datagram(*f, plan.deadline_ms(), &[])
                        })
                        .collect();
                    tracing::info!(
                        outcome = "draining",
                        "announced a {} ms drain deadline to {} of {} flows",
                        plan.deadline_ms(),
                        out.len(),
                        flows.len()
                    );
                    out
                };
                // Sent outside the lock, so it is still never held across an
                // `.await`. Best effort: a device that misses its `DRAIN` still
                // migrates on the deadline, which is why the deadline is in the
                // frame rather than implied by it.
                for (to, datagram) in announcements {
                    for socket in sockets.iter() {
                        if socket.send_to(&datagram, to).await.is_ok() {
                            break;
                        }
                    }
                }
            })
        });
    }
    shutdown.register_teardown(90, "otel", || svc::shutdown::futures_step::boxed(async {}));

    let handle = shutdown.handle();
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    // 9. The receive loops, one per bound socket. Each reads a datagram, calls
    //    the synchronous pump, and writes AT MOST ONE datagram — the shape of
    //    ADR-0005 §11.5's amplification factor of exactly 1.0.
    let provider: Arc<dyn twinvpn_relay::RelayCrypto> = Arc::new(crypto);
    let mut pumps = Vec::new();
    for (socket, addr, family) in bound_sockets {
        let runtime = Arc::clone(&runtime);
        let provider = Arc::clone(&provider);
        let h = handle.clone();
        pumps.push(tokio::spawn(async move {
            tracing::info!(
                outcome = "listening",
                address_family = family,
                "R-UDP receive loop on {addr}"
            );
            serve_udp(
                socket,
                runtime,
                provider,
                // =====================================================
                // The packet path's clock: WALL, and it has to be.
                // =====================================================
                // An earlier revision passed `Instant::now().elapsed()` — a
                // monotonic offset from process start — citing ADR-0018 CD-1's
                // "`WallClock` is evidence only". That reading is half of CD-1.
                // The other half of the same row is the exception that governs
                // here: `WallClock` takes "diagnostics, **and validity windows
                // subject to CD-1a**".
                //
                // `Pump::step`'s `now_ms` is a validity window input. It is
                // compared against a `RelayCapabilityToken`'s `nbf` and `exp`
                // (ADR-0005 §11.3) and used to derive the accepted `pair_tag`
                // bucket (§11.1(3)). Both are ABSOLUTE times an Owner signed;
                // neither has any meaning relative to when this process
                // started.
                //
                // THE OBSERVED CONSEQUENCE, which is why this is a fix and not
                // a preference: a few seconds after start, `now_ms` was ~3000
                // while a legitimately minted token carried `nbf` ≈ 1.79e12.
                // Every token was therefore refused as NOT YET VALID, and
                // §11.5 makes that refusal a zero-byte drop — so a correctly
                // configured relay admitted nothing at all, silently, and
                // presented as a network fault. It was found by running a real
                // device against this binary (`lab/twinsim`); the in-crate
                // integration tests could not find it, because
                // `tests/common/mod.rs` passes `|| NOW_MS`, a wall-clock
                // constant, and so exercises a clock this binary never used.
                // CD-1a names this exact failure class and this exact
                // direction: a wall clock misread as a small number "would
                // make every `nbf` check pass and every `exp` check fail" — the
                // mirror of what happened here.
                //
                // Every OTHER use of `now_ms` inside the pump is a DIFFERENCE
                // of two of its readings — leg idle timeout, pending-slot TTL,
                // quota windows, the cookie's own lifetime — and a difference
                // is correct under either clock. So there is exactly one
                // reading that is right for all of them, and it is this one.
                //
                // `SystemTime::now` is named directly because this is a server
                // artifact, not `/core`: CD-3's deny-list scopes to the core
                // workspace, where the injected `twinvpn-env` clocks live and
                // where CD-1a's `Unset` state is a real operating condition on
                // RTC-less hardware. A relay is a datacentre process with an
                // RTC and NTP; its clock being unset is a host fault, and
                // `UNIX_EPOCH` is used as the floor so that a host clock
                // before 1970 yields 0 — which refuses every token rather than
                // admitting every token, the fail-closed direction.
                || {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                },
                async move { h.draining().await },
            )
            .await;
        }));
    }

    health.set_state(svc::health::ServiceState::Serving);
    tracing::info!(
        outcome = "serving",
        "relay {} in region {} failure domain {} on {} carriage socket(s)",
        relay_cfg.relay_id_hex,
        relay_cfg.region_id,
        relay_cfg.failure_domain,
        listening
    );

    svc::shutdown::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = admin.await;
    for p in pumps {
        let _ = p.await;
    }
    obs.shutdown();
    if !report.drained {
        tracing::warn!(
            outcome = "grace_expired",
            "shutdown grace expired mid-drain"
        );
    }
    Ok(())
}

/// Assembles everything leg establishment needs, or says why it cannot.
///
/// Three things, and all three are required: the relay's static X25519 private
/// key, a CSPRNG, and a cookie secret drawn from it. There is no partial mode —
/// a relay that could handshake but not issue a cookie challenge would lose
/// ADR-0005 §11.5's only anti-amplification control at exactly the moment it is
/// needed.
///
/// # The key is read HERE and not in `config`
///
/// [`RelayConfig`] holds a **path**, never bytes. ADR-0005 §7.1 enumerates the
/// relay's key inventory as a closed set of three, and
/// `tests/cannot_decrypt.rs` asserts from the source that the configuration
/// module does not load this one — because a relay has no use for its static key
/// that is not a Noise handshake, and the handshake lives behind a seam.
///
/// It is read into [`twinvpn_crypto::LockedBytes`], the locked allocator, so the
/// key is not paged to disk and is zeroed on drop.
fn assemble_leg_setup(cfg: &RelayConfig) -> Result<LegSetup, Box<dyn std::error::Error>> {
    let mut raw = std::fs::read(&cfg.static_key_path)?;
    let bytes = decode_static_key(&raw)?;
    // The file's own buffer is wiped before it is dropped: it held the key in
    // ordinary heap memory for as long as it took to decode.
    raw.iter_mut().for_each(|b| *b = 0);
    let mut owned = bytes;
    let static_private = twinvpn_crypto::LockedBytes::adopt(&mut owned)?;

    let entropy: Arc<dyn twinvpn_crypto::relay_leg::Entropy> = Arc::new(SystemEntropy::open()?);
    let cookies = CookieJar::new(&entropy)
        .map_err(|_| "the cookie secret could not be drawn from the platform CSPRNG")?;
    Ok(LegSetup {
        static_private,
        entropy,
        cookies,
    })
}

/// Reads a 32-byte X25519 private key from the key file.
///
/// Accepts the raw 32 octets or 64 hex characters, because both are what an
/// operator's tooling produces and refusing one of them would be a deployment
/// trap rather than a security control. Anything else is a refusal — never a
/// truncation and never a pad, which for a private key would silently weaken it.
fn decode_static_key(raw: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    const LEN: usize = 32;
    if raw.len() == LEN {
        let mut out = [0_u8; LEN];
        out.copy_from_slice(raw);
        return Ok(out);
    }
    let text =
        core::str::from_utf8(raw).map_err(|_| "the static key is neither 32 bytes nor hex")?;
    let trimmed = text.trim();
    if trimmed.len() != LEN * 2 {
        return Err("the static key must be 32 bytes or 64 hex characters".into());
    }
    let mut out = [0_u8; LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|_| "the static key is not valid hex")?;
    }
    Ok(out)
}
