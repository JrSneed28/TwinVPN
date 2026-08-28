//! `twinvpn-control-plane` — the process.
//!
//! **Authority:** `services/twinvpn-service-common/README.md` §2 (the wiring
//! order, and why it is that order), `infra/README.md` §4.3 and §5, ADR-0002
//! §11.7 (the drain).
//!
//! The order in [`run`] is the order `service-common`'s README fixes, and each
//! step is there for a stated reason:
//!
//! 1. **Configuration first.** A missing secret or a mismatched registry fails
//!    *here*, before a socket exists to accept a request it cannot answer.
//! 2. **Metrics, then observability.** The subscriber is process-global and is
//!    installed once, from `main`.
//! 3. **Health before shutdown**, so the drain can turn `/readyz` red.
//! 4. **Shutdown before the listener**, so a `SIGTERM` during startup drains
//!    rather than races.
//! 5. **The admin listener last**, so it never reports ready before the service
//!    can serve.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use twinvpn_control_plane as cp;
use twinvpn_service_common as svc;

fn main() -> std::process::ExitCode {
    // One argument, and it is not a flag: `migrate` is a different PROGRAM that
    // happens to ship in the same binary, not a mode the serving path can fall
    // into. See `migrate`.
    let migrate_only = std::env::args().nth(1).as_deref() == Some("migrate");
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(async move {
            if migrate_only {
                migrate().await
            } else {
                run().await
            }
        }),
        Err(e) => {
            eprintln!("control-plane: could not build the runtime: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `twinvpn-control-plane migrate` — applies `migrations/`, then exits.
///
/// **Separate from serving on purpose.** A service that migrated on startup
/// would mutate a production schema on every deployment, from every replica at
/// once, before any review, and with no operator present to read the failure.
/// The migrations are ordered, forward-only and idempotent to re-run, and
/// `sqlx::migrate!` records what it applied and refuses a file whose checksum
/// changed — which is what makes "the schema in the database is the schema in
/// the repository" a fact rather than a hope.
///
/// This path **connects eagerly**: an operator running a migration is present,
/// is waiting, and needs to be told that the database is unreachable rather than
/// left with a process that reports healthy and has done nothing.
async fn migrate() -> std::process::ExitCode {
    let cfg = match cp::ControlPlaneConfig::load(&svc::config::SystemEnv) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("control-plane: configuration refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // One connection: a migration is a single serialised act, and a pool would
    // invite two of them.
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(cfg.database_url.expose())
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("control-plane: could not reach the database: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match cp::store::pg::PgStore::migrate(&pool).await {
        Ok(()) => {
            println!("control-plane: migrations applied");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("control-plane: migration failed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> std::process::ExitCode {
    // 1. Configuration. `RegistryCheck::Required`: a service validating against
    //    different bounds from the ones it was built with would pass its own
    //    tests and reject real traffic.
    let cfg = match svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        cp::SERVICE_NAME,
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_COORDINATION_SERVICE",
        svc::config::RegistryCheck::Required,
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            // The error names the key and the expectation and never the value:
            // a variant holding the value would put the database password in
            // the first line of the container log.
            eprintln!("control-plane: configuration refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let cp_cfg = match cp::ControlPlaneConfig::load(&svc::config::SystemEnv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("control-plane: configuration refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // 2. Metrics, then observability.
    //
    //    `observability()` uses the instance id `ServiceConfig` resolved from
    //    TWINVPN_INSTANCE_ID (which compose supplies per service), not one
    //    derived here. A `{name}-{pid}` id changes on every restart, so every
    //    fleet aggregate grouped by `service.instance.id` silently counts
    //    restarts instead of instances.
    let metrics = svc::Metrics::new();
    let obs = match svc::obs::init(&cfg.observability(), metrics.clone()) {
        Ok(obs) => Arc::new(obs),
        Err(e) => {
            eprintln!("control-plane: observability refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    // Which of the three sources was used, visible rather than inferred.
    cfg.log_instance_id_resolution();

    // 2b. The signature verifier. Real: COSE_Sign1 through `twinvpn-crypto`,
    //     the same audited provider the client verifies with.
    let anchors = match cp_cfg.load_owner_anchors() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("control-plane: owner anchor set refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let delegations = match cp_cfg.load_owner_delegations() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("control-plane: owner delegation set refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let verifier = match cp::verify::CryptoVerifier::with_delegations(
        &anchors,
        &delegations,
        cp_cfg.owner_anchor_version,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "control-plane: owner authority set refused: {}",
                e.code().as_str()
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    if verifier.has_owner_anchor() {
        // The POSTURE, not just the count. An operator reading "anchor pinned"
        // and nothing else cannot tell whether an admin key's powers are scoped
        // or whether every key that can sign can do everything the Owner can —
        // and that is the difference between an enrol-only phone and one that
        // can revoke the fleet.
        let held = verifier.delegations();
        if held.is_empty() {
            tracing::warn!(
                anchors = anchors.len(),
                "Owner trust anchor pinned and NO delegations are loaded: only a statement                  signed by the ROOT key itself will be admitted. ADR-0007 O5 expects routine                  enrol/revoke/policy to be OSK-signed, so this posture either requires the                  offline recovery phrase for every operation or means OSK keys have been put                  in the anchor file, where their powers are NOT scoped. Set                  TWINVPN_CP_OWNER_DELEGATIONS_PATH."
            );
        } else {
            for d in &held {
                tracing::info!(
                    osk_id = %d.osk_id,
                    powers = %d.powers_str(),
                    anchor_version = d.anchor_version,
                    "Owner delegation admitted"
                );
            }
            tracing::info!(
                anchors = anchors.len(),
                delegations = held.len(),
                anchor_version_enforced = cp_cfg.owner_anchor_version,
                "Owner authority pinned and SCOPED: each signing key may do only what its                  delegation grants"
            );
        }
    } else {
        // Said out loud at startup so an operator does not discover it from a
        // refusal. See README.md §7.
        tracing::warn!(
            reason_code = twinvpn_types::codes::AUTH_KEY_UNAVAILABLE.as_str(),
            "no Owner trust anchor is bound: RevokeDevice, PutPolicy, RevokePairing \
             and the enrolment proof on RegisterDevice will be refused. \
             Device-signed statements, discovery, presence and the C2 stream are \
             unaffected."
        );
    }

    // 2c. The peer-identity verifier. Also real: the RFC 7250 raw public key a
    //     peer presents IS its `DeviceIdentityKey` (ADR-0007 N-32), so the
    //     `device_id` it speaks for is DERIVED from that key rather than looked
    //     up in a table this service could be persuaded to write.
    let identity: Arc<dyn cp::quic::PeerIdentityVerifier> =
        Arc::new(cp::identity::ChannelDerivedIdentity);

    // 3. The store, then health. Readiness genuinely reaches Postgres and the
    //    write lease; `infra/README.md` §5 names both halves for this service.
    //
    //    ==============================================================
    //    LAZY, AND DELIBERATELY NOT MIGRATING.
    //    ==============================================================
    //    `connect_lazy` builds the pool without requiring the database to be up
    //    at this instant. That is not laziness about correctness — it is what
    //    lets /healthz answer 200 and /readyz answer 503 while Postgres is
    //    restarting, instead of a crash loop that takes the process out during
    //    exactly the window an operator is trying to observe. The probe in step
    //    3b is what makes the difference visible.
    //
    //    Nothing here runs a migration. A service that migrated on startup would
    //    mutate a production schema on every deployment, from every replica, at
    //    once — and would do it before any review. Migrations are run by
    //    `twinvpn-control-plane migrate`, as a separate, deliberate act.
    let pool = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(cp_cfg.database_max_connections)
        .connect_lazy(cp_cfg.database_url.expose())
    {
        Ok(pool) => pool,
        Err(e) => {
            // The URL itself is unusable — malformed, or naming a driver this
            // build does not have. The error names neither the URL nor its
            // password: `SecretString` is never rendered.
            eprintln!(
                "control-plane: TWINVPN_CP_DATABASE_URL is not a usable connection string: {e}"
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let store: Arc<dyn cp::store::ControlStore> = Arc::new(cp::store::pg::PgStore::new(
        pool,
        cp_cfg.shard_epoch,
        cfg.instance_id.clone(),
    ));
    tracing::info!(
        shard_epoch = cp_cfg.shard_epoch,
        max_connections = cp_cfg.database_max_connections,
        holder = %cfg.instance_id,
        "PostgreSQL store bound; the schema is NOT migrated from here"
    );

    let probe_store = Arc::clone(&store);
    let health = match svc::HealthRegistry::builder(svc::ReadinessPolicy::AnyDependency).readiness(
        svc::health::FnProbe::new(
            "datastore_and_write_lease",
            svc::ProbeKind::Datastore,
            move || {
                let store = Arc::clone(&probe_store);
                async move {
                    match store.probe().await {
                        Ok(h) if h.is_ready() => svc::ProbeOutcome::Ready,
                        Ok(_) | Err(_) => svc::ProbeOutcome::NotReady(
                            twinvpn_types::codes::CONTROL_WRITE_LEADER_UNAVAILABLE,
                        ),
                    }
                }
            },
        ),
    ) {
        Ok(b) => b
            .liveness(svc::health::FnLiveness::new("accept_loop", || true))
            .build(),
        Err(e) => {
            eprintln!("control-plane: health registry refused a probe: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // 4. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = Arc::new(
        svc::Shutdown::new(cfg.shutdown_config(), metrics.clone()).with_health(health.clone()),
    );
    // Order 90: the OTLP exporter is shut down LAST, so it still carries the
    // records describing the drain itself.
    let obs_for_teardown = Arc::clone(&obs);
    shutdown.register_teardown(90, "otel", move || {
        let obs = Arc::clone(&obs_for_teardown);
        svc::shutdown::futures_step::boxed(async move {
            obs.shutdown();
        })
    });

    // 5. The admin listener on :9090.
    let handle = shutdown.handle();
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        {
            let h = handle.clone();
            async move { h.draining().await }
        },
    ));

    // 6. The listener. TLS 1.3, mutual RFC 7250 raw public keys, client
    //    authentication mandatory, no early data — built by `service-common`,
    //    which is the one home for that termination in this workspace so the
    //    four server artifacts cannot drift four copies of it. This crate adds
    //    what is QUIC's and its own: ALPN and the transport policy.
    let tls = match svc::tls::ServerTlsBuilder::from_pem_file(&cp_cfg.tls_key_path)
        .with_alpn([cp::quic::ALPN])
        .build()
    {
        Ok(tls) => tls,
        Err(e) => {
            // A key that cannot be read is a STARTUP FAILURE, never a fallback
            // to an unauthenticated listener. There is no code path here that
            // produces a client-auth-optional configuration.
            eprintln!("control-plane: TLS material refused: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(
        server_public_key_bytes = tls.public_key().len(),
        "server raw public key loaded; clients pin this value (ADR-0001 §7.2)"
    );

    let server_config = match cp::quic::from_rustls(tls.config()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!(
                "control-plane: QUIC configuration refused: {}",
                e.code().as_str()
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let endpoint = match cp::quic::bind(cp_cfg.listen_quic, server_config) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            eprintln!(
                "control-plane: could not bind {}: {}",
                cp_cfg.listen_quic,
                e.code().as_str()
            );
            return std::process::ExitCode::FAILURE;
        }
    };

    let plane = Arc::new(cp::serve::ControlPlane::new(
        Arc::clone(&store),
        Arc::new(verifier),
        identity,
        metrics.clone(),
        &cp_cfg,
        cp_cfg.coordination_endpoints.clone(),
    ));
    let listener = tokio::spawn(Arc::clone(&plane).serve(endpoint, shutdown.handle()));

    tracing::info!(
        listen_quic = %cp_cfg.listen_quic,
        drain_deadline_ms = cp_cfg.drain_deadline_ms(),
        attach_rate_sustained = cp_cfg.attach_rate_sustained,
        "control-plane serving"
    );
    // Ready only now: step 5's admin listener answered /readyz before this
    // point, and it answered from the health registry, which is not `Serving`
    // until the thing that serves is actually accepting.
    health.set_state(svc::ServiceState::Serving);

    svc::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = listener.await;
    let _ = admin.await;
    obs.shutdown();

    if report.drained {
        std::process::ExitCode::SUCCESS
    } else {
        // The honest answer. `twinvpn_shutdown_grace_expired_total` carries the
        // metric; there is no registered reason_code for it
        // (`service-common` README §11 item 6, raised to the integration lead).
        tracing::warn!(
            outstanding = report.outstanding,
            "the grace period expired with work in flight"
        );
        std::process::ExitCode::FAILURE
    }
}
