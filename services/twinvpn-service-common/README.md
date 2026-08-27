# `twinvpn-service-common`

Shared server-side plumbing for the six TwinVPN service artifacts: configuration,
health and readiness, observability, correlation, graceful shutdown, error
mapping, bounded transport helpers, and the forward-verbatim primitive.

**Owner:** `control-plane` ([`docs/implementation/ownership.md`](../../docs/implementation/ownership.md) §2).
**Consumers:** `control-plane`, `rendezvous`, `presence`, `relay`,
`relay-directory`, `relay-health`.

Six divergent implementations of health, shutdown, logging, tracing and error
mapping is the R-31 defect class ADR-0018 CB-2 exists to prevent. This crate is
how that is avoided — so it is designed for **four consumers with different
needs**, not for one. Anything awkward here gets worked around four different
ways, and that is the divergence arriving through the back door. File an issue
rather than forking it.

---

## 1. Build and test

```bash
source build/toolchain/env.sh          # the pinned toolchain
cd services
cargo build -p twinvpn-service-common
cargo test  -p twinvpn-service-common
```

The gate, exactly as it is run before reporting:

```bash
cd services
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd .. && make test-contracts           # must remain 35801 checks, 0 failures
```

`make test-contracts` needs `node_modules/.bin/buf`, which `npm ci` installs at
the repository root. In a `git worktree` that directory is absent (it is
git-ignored, so it lives only in the primary checkout); symlink it or run
`npm ci` inside the worktree.

---

## 2. Wiring a service

The order matters: configuration before observability (the log level comes from
it), health before shutdown (the drain turns `/readyz` red), and the admin
listener last so it never reports ready before the service can serve.

```rust
use twinvpn_service_common as svc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration. A missing secret or a mismatched registry fails HERE.
    let cfg = svc::config::ServiceConfig::load(
        &svc::config::SystemEnv,
        "control-plane",                       // TWINVPN_SERVICE_NAME default
        env!("CARGO_PKG_VERSION"),
        "COMPONENT_COORDINATION_SERVICE",      // errors.proto Component
        svc::config::RegistryCheck::Required,
    )?;

    // 2. Metrics, then observability. `obs::init` installs the process-global
    //    subscriber; call it once, from main.
    let metrics = svc::metrics::Metrics::new();
    let obs = svc::obs::init(&cfg.observability_config(&instance_id), metrics.clone())?;

    // 3. Health. Every probe declares what it reaches for.
    let pool = connect_to_postgres(&cfg).await?;
    let health = svc::health::HealthRegistry::builder(
        svc::health::ReadinessPolicy::AnyDependency,   // NoControlPlaneCalls on a relay
    )
    .readiness(svc::health::FnProbe::new(
        "postgres",
        svc::health::ProbeKind::Datastore,
        move || { let p = pool.clone(); async move { probe_db(&p).await } },
    ))?
    .liveness(svc::health::FnLiveness::new("event_loop", || true))
    .build();

    // 4. Shutdown, wired to health so the drain turns /readyz red immediately.
    let shutdown = std::sync::Arc::new(
        svc::shutdown::Shutdown::new(cfg.shutdown_config(), metrics.clone())
            .with_health(health.clone()),
    );
    shutdown.register_teardown(10, "db_pool", { /* close the pool */ });
    shutdown.register_teardown(90, "otel", { /* obs.shutdown() */ });

    // 5. The admin listener on :9090.
    let handle = shutdown.handle();
    let admin = tokio::spawn(svc::admin::serve(
        cfg.admin_addr,
        svc::admin::router(health.clone(), metrics.clone()),
        { let h = handle.clone(); async move { h.draining().await } },
    ));

    // 6. Serve.
    health.set_state(svc::health::ServiceState::Serving);
    svc::shutdown::Shutdown::wait_for_signal().await;
    let report = shutdown.shutdown().await;
    let _ = admin.await;
    obs.shutdown();
    if !report.drained { /* the grace period expired; see §6 */ }
    Ok(())
}
```

Every request handler wraps its work in a guard, so the drain has something to
wait for:

```rust
let Some(_guard) = handle.try_acquire() else {
    // Draining. ADR-0002 §11.7 rule 3 (S-6): answer, never reset, never drop.
    return Err(svc::ServiceError::new(
        svc::codes::CONTROL_ADMISSION_DEFERRED,
        svc::Component::CoordinationService,
    )
    .evidence("retry_after_ms", EvidenceValue::DurationMs(retry_after_ms))
    .build());
};
```

---

## 3. Environment configuration

Every variable, its type, its default, whether it is required, and — the column
that matters — **what happens when it is absent**. These names are
[`infra/env.example`](../../infra/env.example)'s and `docker-compose.yml`'s; this
crate invents none of them.

### 3.1 The rule that shapes the loader

**No secret has a default.** [`config::Loader::secret`] takes no default
parameter, so there is no signature in which a secret acquires one. It also
refuses a value still containing `CHANGE-ME`, so a `.env` copied from
`infra/env.example` unedited fails at startup with a readable message rather than
running with a known password. `infra/README.md` §4.1 rule 1 and the compose
`${VAR:?}` guards are the same rule enforced one layer out.

### 3.2 Common to all six services (loaded by `ServiceConfig::load`)

| Variable | Type | Default | Required | If absent |
|---|---|---|---|---|
| `TWINVPN_SERVICE_NAME` | string | the caller's `default_service_name` | no | the per-service default baked into the image |
| `TWINVPN_ENVIRONMENT` | string | `local` | no | `local` |
| `TWINVPN_LOG_LEVEL` | `off\|critical\|error\|warn\|info\|debug\|trace` | `info` | no | `info`. A value the loader does not recognise is a **startup failure**, not a fallback |
| `TWINVPN_LOG_FORMAT` | `json\|text` | `json` | no | `json` |
| `TWINVPN_LOG_LEVEL_EXPIRY_MS` | u64 ms | `3600000` | no | 1 h. The bound on how long `DEBUG`/`TRACE` may stay on (ADR-0015 §11.5). Raising it is a real privacy decision |
| `TWINVPN_ADMIN_ADDR` | socket addr | `[::]:9090` | no | `[::]:9090`. Serves `/healthz`, `/readyz`, `/metrics` |
| `TWINVPN_SHUTDOWN_GRACE_MS` | u64 ms | `120000` | no | 120 s |
| `TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS` | u64 ms | `120000` | no | 120 s — ADR-0002 §11.7 rule 1 |
| `TWINVPN_ADDRESS_FAMILIES` | `dual\|ipv4\|ipv6` | `dual` | no | `dual` |
| `TWINVPN_HAPPY_EYEBALLS_V6_BIAS_MS` | u64 ms | `250` | no | 250 ms — RFC 8305 |
| `TWINVPN_OTEL_ENABLED` | bool | `true` | no | telemetry is emitted. `false` builds **no exporter at all**, so the cost is zero rather than small |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | URL | `http://otel-collector:4317` | no | exports fail; **this must never affect a `Session`** (ADR-0015 §8), so an exporter that cannot be built is logged and skipped, never fatal |
| `OTEL_TRACES_SAMPLER_ARG` | f64 `[0,1]` | `1.0` | no | sample everything locally |
| `TWINVPN_LIMITS_PATH` | path | `/contracts/registry/limits.json` | **effectively yes** | with `RegistryCheck::Required` the service **refuses to start**: a service with no bounds file has no bounds (`ownership.md` §6 rule 9) |
| `TWINVPN_REASON_CODES_PATH` | path | `/contracts/registry/reason_codes.json` | **effectively yes** | as above (`ownership.md` §6 rule 12) |

`TWINVPN_HEALTHCHECK_URL` is read by the container `HEALTHCHECK`, not by the
process; it is documented in `infra/README.md` §4.2 and needs no loader here.

**A boolean is validated, not coerced.** `TWINVPN_CP_QUIC_ZERO_RTT=flase` is a
startup failure, not `false`. `true|1|yes|on` and `false|0|no|off` are accepted;
anything else is refused. 0-RTT is prohibited by ADR-0001 L-CONTROL, and a
misspelling silently meaning "off" would be luck rather than safety.

**An empty value is an unset value.** `FOO=` in a compose file is an easy way to
believe you set something.

### 3.3 The registry check

With `RegistryCheck::Required`, the loader verifies that the **mounted**
`limits.json` parses to the same JSON as the one this build compiled in (through
`twinvpn_schema::limits::LIMITS_JSON`), and that the mounted
`reason_codes.json`'s `registry_version` matches
`twinvpn_types::REASON_REGISTRY_VERSION`. A mismatch is
`ConfigError::RegistryMismatch` and startup fails.

That check exists because the *enforced* bounds are the compiled-in ones — a
service validating against different bounds from the ones it was built with would
pass its own tests and reject real traffic. Pass `RegistryCheck::Skip` in a unit
test or on a host with no `contracts/registry` mount.

### 3.4 Per-service variables

`TWINVPN_CP_*`, `TWINVPN_RZ_*`, `TWINVPN_PRESENCE_*`, `TWINVPN_RELAY_*`,
`TWINVPN_RELAYDIR_*` and `TWINVPN_RELAYHEALTH_*` belong to their own domains and
are listed in `infra/README.md` §4.3–§4.8. Load them with the same
[`config::Loader`] so the "no secret has a default" rule and the typed-error
behaviour are the same everywhere:

```rust
let l = svc::config::Loader::new(&svc::config::SystemEnv);
let db  = l.secret("TWINVPN_CP_DATABASE_URL")?;              // no default, ever
let ttl = l.duration_ms("TWINVPN_RZ_MAILBOX_TTL_MS", Duration::from_millis(30_000))?;
let key = l.readable_file("TWINVPN_RELAY_ISSUER_KEYS_PATH", "/run/secrets/relay/issuer-keys.json")?;
```

A `ConfigError` never carries the **value**, only the key and the expectation:
the error is printed into the container log at startup, and a variant holding the
value would put a password in its first line.

---

## 4. Health and readiness

Two different checks, both required
([`ownership.md`](../../docs/implementation/ownership.md) §6 rule 4,
`infra/README.md` §5).

| Path | Question | 503 when |
|---|---|---|
| `/healthz` | is this process running and are its own invariants holding? | the process is wedged; a restart would help |
| `/readyz` | can this process serve — **including its dependencies**? | starting, draining, a dependency is down, or **no probe is registered** |

A control plane whose database is unreachable is **live** and **not ready**.

**A registry with no readiness probe is not ready.** `ReadinessStatus::NoProbes`
answers 503. An unconfigured `/readyz` that answered 200 would convert an outage
into a silent one, which is worse than having no endpoint.

**A probe that does not answer within `probe_timeout` is not ready.** Treating a
timeout as ready is the same failure with extra steps.

**Readiness is cached** for `cache_ttl` (default 500 ms) so the Prometheus scrape
and the container `HEALTHCHECK` do not each open a database connection. A state
change invalidates the cache immediately, so a drain is red on the very next
probe rather than up to one TTL later.

### I5 — the relay's readiness may never call the control plane

ADR-0005 §11.3 and architecture.md A-12: relay admission verifies an Owner-rooted
`RelayCapabilityToken` **offline**, so a relay must come up and stay up with the
whole control plane down. `infra/README.md` §2.3 records that the compose
topology has no `depends_on` edge from a relay onto the control plane and that
"that absence is load-bearing".

The same absence holds inside the process. Build the relay's registry with
`ReadinessPolicy::NoControlPlaneCalls` and `readiness()` **refuses** any probe
declaring `ProbeKind::ControlPlane`:

```rust
HealthRegistry::builder(ReadinessPolicy::NoControlPlaneCalls)
    .readiness(FnProbe::new("issuer_keys",     ProbeKind::Local, …))?   // ok
    .readiness(FnProbe::new("carriages_bound", ProbeKind::Local, …))?   // ok
    .readiness(FnProbe::new("cp_authz", ProbeKind::ControlPlane, …))?   // Err
```

The four services' readiness sets, from `infra/README.md` §5, are:

| Service | policy | `/readyz` checks |
|---|---|---|
| `control-plane` | `AnyDependency` | Postgres reachable; the per-`TwinNet` write lease obtainable or knowingly held elsewhere |
| `rendezvous` | `AnyDependency` | the control-plane authorization endpoint reachable |
| `presence` | `AnyDependency` | Postgres reachable |
| `relay-a`/`relay-b` | **`NoControlPlaneCalls`** | issuer key set loaded and parsable; all configured carriages bound |
| `relay-directory` | `AnyDependency` | Postgres; signing key loaded; the map satisfies ≥2 alternates / ≥2 failure domains |
| `relay-health` | `AnyDependency` | Postgres reachable |

---

## 5. Observability

### What reaches a backend

The collector's allowlist **is** the attribute convention (`infra/README.md`
§6.3). This crate transcribes it into `obs::attrs`, and
`tests/collector_contract.rs` re-reads `infra/otel/collector-config.yaml` on
every test run and fails on any divergence, in both directions.

Four controls, in the order they run:

1. **Typed keys.** `AttrKey` has no `From<&str>`. The ordinary way to name an
   attribute is a constant; the only runtime constructor, `AttrKey::checked`,
   refuses a forbidden key with a *distinct* error from an unknown one.
2. **Emit-time filtering.** `obs::layer::RedactingLayer` inspects every event's
   fields **before rendering**. A `filter/forbidden` key drops the **whole
   record** and increments
   `twinvpn_observability_forbidden_attribute_dropped_total`; a non-allowlisted
   field is deleted and counted separately.
3. **Export-time filtering.** `obs::otel::RedactingSpanProcessor` applies the same
   contract to span attributes before the batch processor sees them — so the
   property holds even if the collector is misconfigured or absent.
4. **The collector**, and the Prometheus `metric_relabel_configs` for the direct
   `:9090/metrics` scrape.

None of those is the primary control on `SECRET` material. That one is
structural: `redact::Secret`, `redact::Sensitive` and the redacted `Debug` on the
`twinvpn-types` identifiers mean the code that would render key material, a
tunnel payload or a pairing secret **does not exist**, which is what ADR-0015
§11.4 requires and no filter can achieve.

`obs::layer::looks_like_credential` is a fifth, deliberately weakest backstop —
the non-regex twin of the collector's `blocked_values`.

### How payload and secret capture is prevented

- **No `Display` and no `Serialize`** on `Secret`/`Sensitive`; the one way out is
  `expose()`, which is greppable.
- **`Verbatim`'s `Debug` prints a length and a channel**, never the octets: a
  forwarded body is by construction content this process is not entitled to
  interpret (a relay leg is ciphertext, I1).
- **`ServiceError` has no message field** and its `Display` is the reason code.
  An internal source error is retained in-process for a log line and is **never**
  encoded; `tests/errors_mapping.rs::no_text_beyond_the_registry` asserts that a
  canary string in the source does not appear in the encoded envelope bytes.
- **The `error` field is not allowlisted**, so a `tracing` `error = &e` is dropped
  by the layer. Attach `error.type` and the registered `reason_code` instead.
- **`exception.message` and `exception.stacktrace` are absent from the
  allowlist**, deliberately: a VPN process's exception text can contain packet
  buffers and key material.
- **String values are bounded** to 512 bytes before rendering.

### Log levels

`TWINVPN_LOG_LEVEL` sets the baseline. `DEBUG` and `TRACE` **auto-revert** to the
baseline after `TWINVPN_LOG_LEVEL_EXPIRY_MS` (ADR-0015 §11.5), including when they
are the *configured* start-up value — a start-up value is no more permanent than a
runtime one. Requesting a verbose level with no tokio runtime available is
**refused**, because leaving `DEBUG` on with no way to turn it off is exactly the
accumulation §11.5 forbids.

```rust
obs.level().set(LevelFilter::DEBUG)?;   // arms the auto-revert
obs.level().revert();                   // immediately
```

### Correlation

`correlation_id` answers *"what is this a reply to"*; `causation_id` answers
*"what made this happen"*. They are different methods with different results:

```rust
let reply       = request.reply_to(new_id);          // both fields = the request
let consequence = request.derive_consequence(new_id); // causation only, no correlation
```

`derive_consequence` is `common.proto`'s worked example: a route withdrawal
triggered by processing a `DeviceRevoked` carries the revocation's id in
`causation_id` and **no** `correlation_id` at all. Causation is never inherited
transitively — one link at a time is what keeps a chain a chain.

Three mechanisms keep them alive across a hop:

- `Correlation::from_metadata` / `apply_to_metadata` for the protobuf envelope,
  with every width validated before the value is retained.
- `admin::correlation_middleware` for HTTP: it extracts the headers, binds the
  ambient correlation, records the span fields, and echoes them on the response.
  A handler cannot drop the ids by forgetting to pass them, because it never
  holds them.
- `correlation::scope` / `correlation::current` for everything in between.

`RedactingLayer` walks the span scope, so every event inside a
`correlation::request_span` inherits the three fields without the emitting code
naming them.

### Tier 2

`obs::tier2::Tier2Sample` has exactly the seven fields of ADR-0015 §11.1 and no
`extra`, no map, no `with_attribute`. Adding a dimension is an edit to that struct
that a reviewer sees. `abi_*` and every other build-provenance key is absent, per
ADR-0018 VR-2 consequence 3; the collector's Tier-2 strip is a backstop rather
than the only control.

---

## 6. Graceful shutdown

```
SIGTERM ──▶ 1. state := Draining, /readyz goes RED immediately
            2. announce drain_deadline_ms (GOAWAY / close frame)
            3. wait for in-flight guards to drop — bounded by TWINVPN_SHUTDOWN_GRACE_MS
            4. ordered teardown, each step bounded
            5. report
```

The wait in step 3 ends on the **in-flight count**, not on a timer; the timer is
the bound. `ShutdownReport::drained` is the honest answer, and an expiry
increments `twinvpn_shutdown_grace_expired_total` and sets
`twinvpn_shutdown_inflight_at_deadline`.

Teardown steps run in ascending `order`, so a database pool closed at order 10 is
still open while in-flight requests finish, and the OTLP exporter shut down at
order 90 still carries the records describing the drain. A step that exceeds
`teardown_step_timeout` is reported and does not block the steps after it.

`infra/README.md` §4.2: the container `stop_grace_period` is 130 s so Docker does
not `SIGKILL` a service mid-drain. **Raising `TWINVPN_SHUTDOWN_GRACE_MS` without
raising that is a mistake.**

---

## 7. Forward-verbatim

`prost` 0.13 **drops unknown protobuf fields on decode and cannot re-emit them**
— measured by `core-foundation`'s `unknown_fields_are_dropped_by_prost_0_13` and
recorded in `contracts/docs/phase1-conflicts.md` CF-2. ADR-0003 §11 B1 requires a
forwarder to **preserve and forward** them.

Rust with `prost` is not a preserve-and-forward runtime, so the rule for the
services is **do not decode-then-re-encode**:

```rust
let f = svc::Forwarded::<v1::CallEnvelope>::decode(bytes, Channel::ControlAndTelemetry)?;
route_using(f.view());     // inspect: route, authorise, count
next_hop.send(f.forward()); // send: the ORIGINAL octets, byte for byte
```

There is no `view_mut()` and no `encode()`. The one way to produce different
bytes is `rewrite_dropping_unknown_fields`, whose name is the documentation.

Three of the four server domains forward: the control plane relays events it did
not author, the rendezvous carries an opaque `CALL` body, and a relay carries a
leg it must never interpret.

Evidence, in `src/forward.rs`, asserts **both halves**:

- `the_failing_control_decode_then_re_encode_drops_the_unknown_field` — the
  control: `M::decode(bytes).encode_to_vec() != bytes`, and shorter.
- `forward_verbatim_preserves_the_unknown_field` — `Forwarded::forward() == bytes`.
- `the_two_halves_disagree_which_is_the_whole_finding` — both, side by side.

If the control ever starts passing, `prost` gained preserve-and-forward and CF-2's
constraint on this crate can be revisited.

### 7.1 Which mode belongs on which channel

`Verbatim` carries a `Framing`, and **choosing the wrong one is a real defect in
both directions**, so pick from this table rather than from the shorter name.

| Constructor | `Framing` | Checks | Use on | Boundary |
|---|---|---|---|---|
| `Verbatim::from_received` | `ProtobufRecords` | size cap **and** depth cap | control-plane C1/C2/C7 bodies; rendezvous C4 envelopes; anything `Forwarded<M>` will decode | **B1**, **B3** |
| `Verbatim::from_opaque` | `Opaque` | size cap **only** | a relay `DATA` payload (WireGuard L-DATA); a COSE_Sign1 `signed_payload` being *carried* rather than verified; any ciphertext leg | **B4** |

`Forwarded<M>` is always `ProtobufRecords` — it holds a decoded view, so an
opaque framing could not mean anything on it. A component carrying octets it must
not interpret holds a bare `Verbatim` and **no view at all**, which is the
stronger position rather than a lesser one.

**Why the opaque mode exists.** The first version of this crate ran
`twinvpn_schema::depth::check` on every `Verbatim`. That is a **protobuf record
scan**, and a relay `DATA` payload is an unmodified WireGuard L-DATA datagram —
AEAD ciphertext with a fixed binary header — so `Verbatim` rejected essentially
all real relay traffic. `relay-plane` measured it and worked around it with a
local `frame::Opaque`.

The API mismatch was the smaller half. The larger half is that requiring the bytes
to parse as protobuf had put a protobuf parser on the **B4 packet path**, which
ADR-0003 R7 forbids outright — *"B4 MUST have zero serialization framework in the
packet path"* — and §11's table restates as a property: *"A serialization library
MUST NOT appear in the packet path. Relay framing is a length + opaque-bytes
header only."* `contracts/README.md` records why that is worth a rule: B4's schema
artifact is **absent by design**, so *"the highest-rate path is immune to
serialization bugs by construction"*. A primitive that quietly reintroduced the
parser removed that immunity while looking like the safe choice.

**Why a named constructor and not a flag or a `Channel` variant.**
`from_received(bytes, channel, false)` at a call site tells a reviewer nothing;
`from_opaque(bytes, channel)` tells them everything. A `Channel` variant was the
other reasonable shape and is not available: `Channel` lives in `twinvpn-schema`,
is owned by `core-foundation`, and enumerates the two envelope **cap families** of
`limits.json` — it is a bounds selector, not a framing selector, and B4 has no
`limits.json` entry to add. `from_received` keeps its name, signature and
behaviour so the control plane and the rendezvous cannot lose the depth guard by
anyone's inaction.

Evidence, again in both halves:

- `the_failing_control_the_protobuf_mode_still_refuses_l_data` — the control.
- `the_opaque_mode_carries_l_data_byte_for_byte` — the fix.
- `the_two_modes_differ_in_exactly_one_respect` — on protobuf-shaped bytes both
  accept and both carry the identical octets; only the check differs.
- `the_opaque_mode_carries_every_byte_value` — `0x00..=0xFF`, reversed, plus NUL
  and `0xFF` runs, byte for byte.
- `the_opaque_mode_runs_no_structural_scan_at_all` — a tag claiming a 4 GiB field
  is refused by the protobuf mode and carried unexamined by the opaque one.
- `the_protobuf_mode_still_enforces_the_depth_cap` — the guard B1/B3 must not lose.
- `both_modes_enforce_the_same_size_cap` — the bound is not what differs.
- `an_opaque_debug_still_renders_no_octets` — length, channel and framing only.

---

## 8. Errors

One place internal errors become registered reason codes with typed evidence.

```rust
ServiceError::from_reject(&reject, Component::CoordinationService)     // a validator
ServiceError::from_os_error(codes::CONTROL_UNREACHABLE, comp, io_err)  // an OS failure
ServiceError::new(codes::CONTROL_EVENT_RATE_EXCEEDED, comp).build()    // a decision
```

- `envelope()` produces `v1::ErrorEnvelope` through
  `twinvpn_schema::envelope::encode`, which fills `resolved` from **this build's**
  registry — so the attribute block cannot disagree with the code, and ADR-0015
  §11.2 rule 5's attribute degradation works for a code the receiver has never
  seen.
- `http_status()` is a pure function of the registry attributes: the same code
  always produces the same status.
- `emit(&metrics, outcome)` logs at the level §11.5 assigns to the code's severity
  with the registry attributes attached, and counts
  `twinvpn_errors_total{reason_code, outcome}`.

**There is no message string on the wire.** `errors.proto` has no such field,
`contracts/` is frozen, and this crate defines no local envelope type one could be
added to. The OS detail stays in `source_detail()` for a log line.

**`from_os_error` requires the caller to name the code.** A table mapping `errno`
to `reason_code` would be a second taxonomy, and only the caller knows whether
`ECONNREFUSED` on this socket means `CONTROL.UNREACHABLE` or
`RELAY.NONE_REACHABLE`.

---

## 9. Transport helpers

- `check_declared_length(declared, channel)` — the cap check that must precede any
  allocation proportional to a declared length. `read_frame` uses it; so should
  anything hand-rolling a reader.
- `EventQueue` + `BacklogWatermark` — ADR-0002 §11.6's C2 backlog. `for_rung(2)`
  halves the watermark because TCP head-of-line blocking makes a backlog costlier.
  On breach, bodies are discarded and `PushOutcome::Compacted{up_to_net_seq}`
  tells the caller what to put in `StreamCompacted` and
  `CONTROL.STREAM_COMPACTED`.
- `TokenBucket` / `Admission` — §11.7 rule 3's accept limiter. `try_admit` returns
  `Deferred{retry_after_ms}` rather than a bare `false`, so **S-6**'s prohibition
  on a TCP reset or a silent drop is discharged by using the return value.
- `WriteBudget` — the per-`TwinNet` durable write budget (1/s sustained, burst 20,
  both frozen in `limits.json`). Refuses with `CONTROL.EVENT_RATE_EXCEEDED`; a
  queued over-budget write is the flood, delayed.

All of these take `now: Instant` as a parameter rather than reading a clock, so a
decision is reproducible from its inputs (`architecture.md` §5.2 R-DET-1) and the
boundary cases are testable without sleeping.

---

## 10. Debugging

```bash
docker compose logs -f control-plane                 # structured JSON on stdout
curl -s http://127.0.0.1:19001/readyz  | jq          # control-plane admin
curl -s http://127.0.0.1:19001/healthz | jq
curl -s http://127.0.0.1:19001/metrics | grep twinvpn_
```

The runtime image has **no shell**, so `docker compose exec control-plane sh` will
not work. Probe from a container that has one (`prometheus`, `postgres`) or from
the host via the published admin port (`infra/README.md` §2.1's table).

| Symptom | First thing to check |
|---|---|
| startup fails naming a variable | a required value is unset, or a secret still says `CHANGE-ME` |
| `ConfigError::RegistryMismatch` | the mounted `contracts/registry` is not the one this binary was built against |
| `/readyz` 503, `/healthz` 200 | a **dependency** is down. The JSON body names the probe and its registered code. A restart will not help |
| `/readyz` says `no_probes` | the service registered none. That is a wiring defect, reported red rather than green |
| `/readyz` says `starting` forever | `health.set_state(ServiceState::Serving)` was never called |
| a field you expected is missing from a log line | it is not on the collector allowlist (§5). That is the design |
| `twinvpn_observability_forbidden_attribute_dropped_total > 0` | **a security defect in this service.** ADR-0015 O-12 says that field cannot exist in any build. Find the emitter |
| `twinvpn_shutdown_grace_expired_total > 0` | in-flight work outlived `TWINVPN_SHUTDOWN_GRACE_MS`, or a guard was never dropped |
| a forwarded message lost a field | something called `rewrite_dropping_unknown_fields`, or decoded and re-encoded by hand (§7) |
| traces missing, metrics present | `otelcol_exporter_send_failed_spans_total`. A stalled export must never affect a `Session` (ADR-0015 §8) |

Verbose logging, with the mandatory expiry:

```bash
RUST_LOG=twinvpn_service_common=debug cargo test -p twinvpn-service-common -- --nocapture
```

---

## 11. Known limitations

Stated here rather than discovered later.

1. **No container has been built or run.** `infra/README.md` §9 records that
   Docker is absent from this host. Everything in §2 and §10 that involves
   `docker compose` is unexercised; the crate's own tests run a **real** HTTP
   server on loopback and make real requests to it, which is the part that could
   be exercised.
2. **No OTLP collector was contacted.** `RedactingSpanProcessor` is tested against
   a recording processor, and `build_pipeline` is tested only in its disabled
   form. The exporter's wire behaviour against a live collector is untested here.
3. **`obs::init` is process-global and therefore untested end to end.** Installing
   a subscriber can happen once per process; the layer is tested with a scoped
   subscriber instead, and `init` itself is exercised only through the doc
   example's compile check.
4. **Metrics are counters and gauges only.** No histogram. A service needing
   latency quantiles uses an OTel meter and the collector's Prometheus exporter.
   The §9 label allowlist is enforced on this crate's registry, not on OTel
   metrics a service creates itself.
5. **The Tier-2 emitter defines the shape but ships no exporter.** Tier 2 is a
   client channel, off by default and opt-in; nothing in the compose topology
   feeds it. The type exists so the aggregation service and the services share one
   definition of the tuple.
6. **No registered `reason_code` covers "the shutdown grace period expired."**
   `INTERNAL.INVARIANT_VIOLATED` would overclaim. Expiry is reported as a metric
   plus a `WARN` carrying `twinvpn.outcome="grace_expired"`. Raised to the
   integration lead.
7. **`ProbeKind` is a declaration, not a proof.** A probe declaring `Local` that
   opens a control-plane socket is not caught by anything here. The declaration
   makes the intent reviewable and machine-checkable at wiring time; it is not a
   sandbox.
8. **Capability names, if a service validates one, must be checked against 32 and
   not `limits.json`'s 24** — `ownership.md` §4.3's open contract defect.
   `twinvpn_schema::limits::CAPABILITY_MAX_NAME_BYTES` is the value to use.
