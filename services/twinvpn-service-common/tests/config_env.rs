//! Configuration tests.
//!
//! The properties that matter are the ones a deployment gets wrong quietly:
//! a secret with a default, a placeholder copied from `infra/env.example`, a
//! misspelled boolean read as `false`, and a mounted registry that disagrees
//! with the one the binary compiled in.

use std::time::Duration;

use twinvpn_service_common::config::{
    keys, AddressFamilies, ConfigError, EnvSource, InstanceIdSource, Loader, MapEnv, RegistryCheck,
    ServiceConfig, SystemEnv,
};

fn empty() -> MapEnv {
    MapEnv::new()
}

fn load(env: &MapEnv) -> Result<ServiceConfig, ConfigError> {
    ServiceConfig::load(
        env,
        "control-plane",
        "0.1.0",
        "COMPONENT_COORDINATION_SERVICE",
        RegistryCheck::Skip,
    )
}

#[test]
fn the_defaults_are_the_ones_infra_readme_documents() {
    let cfg = load(&empty()).expect("defaults load");
    assert_eq!(cfg.service_name, "control-plane");
    assert_eq!(cfg.environment, "local");
    assert_eq!(cfg.log_level, tracing::level_filters::LevelFilter::INFO);
    assert_eq!(cfg.admin_addr.to_string(), "[::]:9090");
    assert_eq!(cfg.shutdown_grace, Duration::from_millis(120_000));
    assert_eq!(cfg.shutdown_drain_deadline, Duration::from_millis(120_000));
    assert_eq!(cfg.log_level_expiry, Duration::from_millis(3_600_000));
    assert_eq!(cfg.address_families, AddressFamilies::Dual);
    assert_eq!(cfg.happy_eyeballs_v6_bias, Duration::from_millis(250));
    assert!(cfg.otel_enabled);
    assert_eq!(cfg.otel_endpoint, "http://otel-collector:4317");
    assert!((cfg.otel_sampler_ratio - 1.0).abs() < f64::EPSILON);
}

#[test]
fn a_secret_has_no_default_and_the_signature_says_so() {
    // `Loader::secret` takes only a key. There is no `secret_or_default`, so a
    // caller cannot supply a fallback even by accident (infra/README.md §4.1
    // rule 1).
    let env = empty();
    let l = Loader::new(&env);
    assert_eq!(
        l.secret("TWINVPN_CP_DATABASE_URL"),
        Err(ConfigError::Missing {
            key: "TWINVPN_CP_DATABASE_URL"
        })
    );
}

#[test]
fn the_env_example_placeholder_is_refused() {
    let env = empty().with(
        "TWINVPN_CP_DATABASE_URL",
        "postgres://twinvpn:CHANGE-ME-choose-a-real-value@postgres:5432/twinvpn_control",
    );
    let l = Loader::new(&env);
    assert_eq!(
        l.secret("TWINVPN_CP_DATABASE_URL"),
        Err(ConfigError::PlaceholderSecret {
            key: "TWINVPN_CP_DATABASE_URL"
        })
    );
}

#[test]
fn a_real_secret_loads_and_its_debug_is_redacted() {
    let env = empty().with("TWINVPN_PG_PASSWORD", "an-actual-value-1234");
    let l = Loader::new(&env);
    let s = l.secret("TWINVPN_PG_PASSWORD").expect("loads");
    assert_eq!(s.expose(), "an-actual-value-1234");
    assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
}

#[test]
fn a_config_error_never_carries_the_value() {
    // The error is printed at startup into the container log. A variant holding
    // the value would put a password in the first line of it.
    for e in [
        ConfigError::Missing { key: "K" },
        ConfigError::Invalid {
            key: "K",
            expected: "boolean",
        },
        ConfigError::PlaceholderSecret { key: "K" },
        ConfigError::FileUnreadable { key: "K" },
        ConfigError::RegistryMismatch { key: "K" },
    ] {
        let rendered = format!("{e} {e:?}");
        assert!(rendered.contains('K'));
        assert!(!rendered.contains("CHANGE-ME"));
    }
}

#[test]
fn a_misspelled_boolean_is_refused_rather_than_read_as_false() {
    // TWINVPN_CP_QUIC_ZERO_RTT=flase silently meaning "off" is luck, not safety.
    let env = empty().with("TWINVPN_CP_QUIC_ZERO_RTT", "flase");
    let l = Loader::new(&env);
    assert_eq!(
        l.bool("TWINVPN_CP_QUIC_ZERO_RTT", false),
        Err(ConfigError::Invalid {
            key: "TWINVPN_CP_QUIC_ZERO_RTT",
            expected: "boolean"
        })
    );
    // ...while the spellings the compose file uses all work.
    for (raw, want) in [
        ("true", true),
        ("1", true),
        ("yes", true),
        ("false", false),
        ("0", false),
        ("no", false),
    ] {
        let env = empty().with("K", raw);
        assert_eq!(Loader::new(&env).bool("K", !want), Ok(want), "{raw}");
    }
}

#[test]
fn an_unparseable_value_names_its_variable_and_stops_the_load() {
    let env = empty().with(keys::SHUTDOWN_GRACE_MS, "two minutes");
    assert_eq!(
        load(&env),
        Err(ConfigError::Invalid {
            key: keys::SHUTDOWN_GRACE_MS,
            expected: "duration in milliseconds"
        })
    );

    let env = empty().with(keys::ADMIN_ADDR, "9090");
    assert_eq!(
        load(&env),
        Err(ConfigError::Invalid {
            key: keys::ADMIN_ADDR,
            expected: "socket address, e.g. [::]:9090"
        })
    );

    let env = empty().with(keys::LOG_FORMAT, "xml");
    assert!(matches!(
        load(&env),
        Err(ConfigError::Invalid {
            key: keys::LOG_FORMAT,
            ..
        })
    ));
}

#[test]
fn both_address_families_are_expressible_and_neither_is_implied() {
    for (raw, want, v4, v6) in [
        ("dual", AddressFamilies::Dual, true, true),
        ("ipv4", AddressFamilies::V4Only, true, false),
        ("ipv6", AddressFamilies::V6Only, false, true),
    ] {
        let cfg = load(&empty().with(keys::ADDRESS_FAMILIES, raw)).expect("loads");
        assert_eq!(cfg.address_families, want, "{raw}");
        assert_eq!(cfg.address_families.v4(), v4);
        assert_eq!(cfg.address_families.v6(), v6);
    }
    assert!(matches!(
        load(&empty().with(keys::ADDRESS_FAMILIES, "v4-only")),
        Err(ConfigError::Invalid { .. })
    ));
}

#[test]
fn the_adr_0015_level_names_configure_the_service() {
    // §11.5 names the top level CRITICAL; a value copied from the ADR must work.
    for (raw, want) in [
        ("critical", tracing::level_filters::LevelFilter::ERROR),
        ("error", tracing::level_filters::LevelFilter::ERROR),
        ("warn", tracing::level_filters::LevelFilter::WARN),
        ("info", tracing::level_filters::LevelFilter::INFO),
        ("debug", tracing::level_filters::LevelFilter::DEBUG),
        ("trace", tracing::level_filters::LevelFilter::TRACE),
    ] {
        let cfg = load(&empty().with(keys::LOG_LEVEL, raw)).expect("loads");
        assert_eq!(cfg.log_level, want, "{raw}");
    }
    assert!(matches!(
        load(&empty().with(keys::LOG_LEVEL, "verbose")),
        Err(ConfigError::Invalid { .. })
    ));
}

#[test]
fn an_empty_variable_is_treated_as_unset() {
    // `FOO=` in a compose file is an easy way to think you set something.
    let env = empty().with(keys::ENVIRONMENT, "   ");
    assert_eq!(load(&env).expect("loads").environment, "local");
    assert!(SystemEnv
        .get("TWINVPN_A_VARIABLE_THAT_IS_NOT_SET")
        .is_none());
}

#[test]
fn a_missing_registry_file_refuses_to_start() {
    // infra/README.md §4.2: "the service must refuse to start … a service with
    // no bounds file has no bounds."
    let env = empty().with(keys::LIMITS_PATH, "/nonexistent/limits.json");
    assert_eq!(
        ServiceConfig::load(
            &env,
            "control-plane",
            "0.1.0",
            "COMPONENT_COORDINATION_SERVICE",
            RegistryCheck::Required,
        ),
        Err(ConfigError::FileUnreadable {
            key: keys::LIMITS_PATH
        })
    );
}

#[test]
fn the_real_frozen_registries_satisfy_the_required_check() {
    // The compose file bind-mounts contracts/registry read-only into every
    // service; this is that mount, from the repository.
    let registry =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/registry");
    let env = empty()
        .with(
            keys::LIMITS_PATH,
            registry.join("limits.json").to_str().expect("utf-8"),
        )
        .with(
            keys::REASON_CODES_PATH,
            registry.join("reason_codes.json").to_str().expect("utf-8"),
        );
    let cfg = ServiceConfig::load(
        &env,
        "control-plane",
        "0.1.0",
        "COMPONENT_COORDINATION_SERVICE",
        RegistryCheck::Required,
    )
    .expect("the frozen registries must satisfy their own check");
    assert!(cfg.limits_path.ends_with("limits.json"));
}

#[test]
fn a_registry_that_disagrees_with_the_build_is_refused() {
    // The negative control for the test above: a service validating against
    // bounds different from the ones it was built with would pass its own tests
    // and reject real traffic.
    let dir = std::env::temp_dir().join("twinvpn-service-common-registry-mismatch");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let limits = dir.join("limits.json");
    std::fs::write(&limits, "{\"envelope\":{\"c4_max_bytes\":9999}}").expect("write");
    let codes = dir.join("reason_codes.json");
    std::fs::write(&codes, "{\"registry_version\":1}").expect("write");

    let env = empty()
        .with(keys::LIMITS_PATH, limits.to_str().expect("utf-8"))
        .with(keys::REASON_CODES_PATH, codes.to_str().expect("utf-8"));
    assert_eq!(
        ServiceConfig::load(
            &env,
            "control-plane",
            "0.1.0",
            "COMPONENT_COORDINATION_SERVICE",
            RegistryCheck::Required,
        ),
        Err(ConfigError::RegistryMismatch {
            key: keys::LIMITS_PATH
        })
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_derived_sub_configs_carry_the_loaded_values() {
    let cfg = load(
        &empty()
            .with(keys::SHUTDOWN_GRACE_MS, "5000")
            .with(keys::OTEL_ENABLED, "false")
            .with(keys::LOG_LEVEL_EXPIRY_MS, "60000"),
    )
    .expect("loads");

    let sd = cfg.shutdown_config();
    assert_eq!(sd.grace, Duration::from_millis(5000));
    assert_eq!(sd.drain_deadline, Duration::from_millis(120_000));

    let obs = cfg.observability_config("instance-7");
    assert_eq!(obs.instance_id, "instance-7");
    assert!(!obs.otel.enabled);
    assert_eq!(obs.log_level_expiry, Duration::from_millis(60_000));
    assert_eq!(obs.component, "COMPONENT_COORDINATION_SERVICE");
}

// ---------------------------------------------------------------------------
// service.instance.id
// ---------------------------------------------------------------------------

#[test]
fn the_configured_instance_id_wins_over_every_fallback() {
    // `docker-compose.yml` sets TWINVPN_INSTANCE_ID per service. A service that
    // derived its own would ignore it, and `service.instance.id` would change on
    // every restart — which makes "how many instances served this" silently mean
    // "how many times did anything restart".
    let cfg = load(
        &empty()
            .with(keys::INSTANCE_ID, "control-plane")
            .with("HOSTNAME", "some-container-abc123"),
    )
    .expect("loads");
    assert_eq!(cfg.instance_id, "control-plane");
    assert_eq!(cfg.instance_id_source, InstanceIdSource::Configured);
    assert!(cfg.instance_id_source.is_stable_across_restarts());
}

#[test]
fn the_hostname_is_the_documented_fallback() {
    let cfg = load(&empty().with("HOSTNAME", "some-container-abc123")).expect("loads");
    assert_eq!(cfg.instance_id, "some-container-abc123");
    assert_eq!(cfg.instance_id_source, InstanceIdSource::Hostname);
    // Still stable across a restart, which is the property that matters.
    assert!(cfg.instance_id_source.is_stable_across_restarts());
}

#[test]
fn an_empty_instance_id_falls_through_rather_than_naming_an_instance_empty() {
    // `TWINVPN_INSTANCE_ID=` in a compose file is an easy way to think you set
    // one. An empty `service.instance.id` would collapse the whole fleet into a
    // single series.
    let cfg = load(
        &empty()
            .with(keys::INSTANCE_ID, "   ")
            .with("HOSTNAME", "h1"),
    )
    .expect("loads");
    assert_eq!(cfg.instance_id, "h1");
    assert_eq!(cfg.instance_id_source, InstanceIdSource::Hostname);
}

#[test]
fn the_process_fallback_is_marked_as_the_degraded_mode_it_is() {
    // No variable, no HOSTNAME. `MapEnv` supplies neither, so the resolver falls
    // to the pid form — unless this host has an /etc/hostname, which a container
    // does. Assert the property rather than the value.
    let cfg = load(&empty()).expect("loads");
    match cfg.instance_id_source {
        InstanceIdSource::ProcessFallback => {
            assert!(cfg.instance_id.starts_with("control-plane-"));
            assert!(
                !cfg.instance_id_source.is_stable_across_restarts(),
                "the pid form must not claim to survive a restart"
            );
        }
        InstanceIdSource::Hostname => {
            assert!(cfg.instance_id_source.is_stable_across_restarts());
        }
        InstanceIdSource::Configured => panic!("nothing configured it"),
    }
    assert!(!cfg.instance_id.is_empty(), "an id is always produced");
}

#[test]
fn each_source_has_a_distinct_allowlisted_outcome_token() {
    use twinvpn_service_common::obs::attrs;
    let mut seen = std::collections::BTreeSet::new();
    for src in [
        InstanceIdSource::Configured,
        InstanceIdSource::Hostname,
        InstanceIdSource::ProcessFallback,
    ] {
        assert!(seen.insert(src.as_outcome()), "duplicate outcome token");
    }
    // The token rides `twinvpn.outcome`, which IS on the collector allowlist.
    // There is no allowlisted key meaning "where an id came from", and inventing
    // one would be a field the collector silently deletes.
    assert_eq!(
        attrs::verdict("twinvpn.outcome"),
        attrs::KeyVerdict::Allowed
    );
}

#[test]
fn the_resolved_id_is_what_reaches_observability() {
    let cfg = load(&empty().with(keys::INSTANCE_ID, "relay-a")).expect("loads");
    assert_eq!(cfg.observability().instance_id, "relay-a");
    // ...and the explicit override still overrides, for a caller that mints one.
    assert_eq!(
        cfg.observability_config("minted-elsewhere").instance_id,
        "minted-elsewhere"
    );
}
