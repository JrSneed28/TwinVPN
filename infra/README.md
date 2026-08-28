# TwinVPN local infrastructure

Owner: `infrastructure` (`docs/implementation/ownership.md` §2).
Scope: `infra/`, `docker-compose.yml`, `build/`, `.github/workflows/`.

This directory is the environment the six server-side artifacts in `services/`
run in: the compose topology, the images, the observability stack, and the
configuration contract between them.

---

## 0. What works today and what does not

Read this first; everything below assumes it.

| Component | State |
|---|---|
| `postgres`, `otel-collector`, `prometheus`, `tempo`, `loki`, `grafana` | Configured and structurally validated. |
| `control-plane`, `rendezvous`, `presence`, `relay-a`, `relay-b`, `relay-directory`, `relay-health` | **All six are implemented.** An earlier revision of this section said they were skeletons that print a line and exit 1; that stopped being true when the four service domains landed. |

```bash
docker compose up -d
```

**But nothing in this directory has ever been started.** Docker is not
installed on the host this was authored on, so no image has been built, no
container has run, and the healthcheck, the busybox shim and the distroless
runtime are all unexercised. §9 says precisely what was and was not verified,
and the CI lanes in `.github/workflows/` exist to close that gap on a runner
that has Docker.

Read every claim below as "this is what the configuration says", not "this was
observed".

---

## 1. Quick start

```bash
# 1. Create the per-service secret directories and development key material.
#    Idempotent; never overwrites an existing file.
bash infra/scripts/bootstrap-local.sh

# 2. Configure. NOTHING in the example is a usable credential — the file is
#    written so that copying it unedited FAILS AT STARTUP with a readable
#    message rather than silently using a known password.
cp infra/env.example .env
$EDITOR .env

# 3. Validate before starting anything.
python3 build/verify/check-compose.py     # invariants; needs only PyYAML
docker compose config --quiet             # schema

# 4. Bring up what currently works.
docker compose up -d postgres otel-collector prometheus tempo loki grafana
docker compose ps
```

Grafana: <http://127.0.0.1:13000> — anonymous Viewer, login form disabled.
Prometheus: <http://127.0.0.1:19090>.

> **Why `infra/env.example` and not `infra/.env.example`.** The tooling in this
> workspace refuses to write any path matching `.env*`. The name is the only
> difference; the workflow (`cp … .env`) is unchanged, and the guard is doing
> exactly what it exists to do.

---

## 2. Topology

```
                        ┌──────────── MANAGEMENT PLANE ────────────┐
                        │  otel-collector → tempo / loki / promet. │
                        │  grafana · relay-health                  │
                        └──────────────────┬───────────────────────┘
                                           │ observes; never in the datapath
   ┌──────────────── CONTROL PLANE ───────────────────────────────────────┐
   │  control-plane :443   rendezvous :443   presence :443                │
   │  relay-directory :443                    ── postgres :5432 ──        │
   └──────────────────────────────────────────────────────────────────────┘

   ┌──────────────── DATA PLANE, OUTSIDE THE TRUST BOUNDARY ──────────────┐
   │  relay-a  (region local-1, failure domain fd-a)   :41641 :443        │
   │  relay-b  (region local-1, failure domain fd-b)   :41641 :443        │
   │  NO depends_on EDGE ONTO THE CONTROL PLANE — see §2.3                │
   └──────────────────────────────────────────────────────────────────────┘
```

### 2.1 Ports — where each number comes from

The **wire-facing** ports are the ADRs', not choices made here. Each service
has its own network namespace, so each binds the ADR port on its own address
and no number is invented.

| Service | In-container | Authority |
|---|---|---|
| `control-plane` | UDP/443 (QUIC+H3, rung 1), TCP/443 (rungs 2–4) | ADR-0002 §11.2 transport ladder |
| `rendezvous` | UDP/443, TCP/443 | ADR-0002 §11.5 — `CALL` delivery rides the same C1/C2 channel |
| `presence` | UDP/443, TCP/443 | ADR-0002; architecture.md §2.13 |
| `relay-a`, `relay-b` | UDP/41641 and UDP/443 (`R-UDP`), UDP/443 (`R-QUIC`), TCP/443 (`R-TLS`) | ADR-0005 §11.4 carriage ladder |
| `relay-directory` | TCP/443, UDP/443 | ADR-0002 |
| `relay-health` | admin listener only | no device-facing surface |

**`contracts/registry/limits.json` has a `ports` section, and it is `{min: 1,
max: 65535}`.** It is a *validation bound for untrusted input*, not a service
port assignment — it says which port values a parser may accept, not which
ports TwinVPN listens on. The ADRs above are the assignment authority.

The **admin listener is an infrastructure-lead choice**, recorded as one in the
same way `docs/implementation/ownership.md` §1 records `services/`:

> One listener per service on **:9090**, serving three paths — `/healthz`
> (liveness), `/readyz` (readiness), `/metrics` (Prometheus). One port to open,
> one port to firewall, one port to forget to publish. It is operator-facing
> and MUST NOT be exposed to an untrusted network.

**Host publication** is development-only and bound to loopback in *both*
families (`127.0.0.1` and `[::1]`), so nothing here is reachable from the LAN:

| Host | Service | Host | Service |
|---|---|---|---|
| `8443` | control-plane (tcp+udp) | `19001` | control-plane admin |
| `8444` | rendezvous | `19002` | rendezvous admin |
| `8445` | presence | `19003` | presence admin |
| `41641`, `8446` | relay-a | `19004` | relay-a admin |
| `41642`, `8447` | relay-b | `19005` | relay-b admin |
| `8448` | relay-directory | `19006` | relay-directory admin |
| — | — | `19007` | relay-health admin |
| `15432` | postgres | `19090` | prometheus |
| `14317`/`14318` | otel-collector OTLP | `18888` | otel-collector self-telemetry |
| `13000` | grafana | `13200`/`13100` | tempo / loki |

### 2.2 The backing store, and why there is no broker

ADR-0002 selected **B-3: "the log is a table"** — a per-`TwinNet` append-only
`event` relation in the *same transactional store* as control-plane state, with
`net_seq` allocated **inside the mutating transaction** (N-3). That co-location
is a correctness property, so there is one Postgres and the control-plane state
and its event log share `twinvpn_control`.

The internal fan-out bus (N-6) carries **only** `{twinnet_id, net_seq,
revocation_epoch}` watermarks — never payloads. Here it is Postgres
`LISTEN/NOTIFY` (`TWINVPN_CP_EVENT_BUS=postgres-notify`): it is the smallest
thing that satisfies N-6, adds no component to operate or breach, and N-7
forbids exposing a broker protocol to a device even if one existed. Adding
Kafka or NATS would be inventing topology the ADR explicitly rejected (B-1,
B-2, B-5).

Three databases, split along architecture.md §5's state-ownership rows rather
than along service names:

| Database | Holds | §5 row |
|---|---|---|
| `twinvpn_control` | membership, revocation, policy, the durable event log, and the `RelayCapabilityToken` **issuance record** | S-30 among others |
| `twinvpn_relay_directory` | the `Relay` fleet **registry *and* ranking**, plus aggregated `HealthState` | **S-09** |

**There is no presence database, and adding one would be a privacy defect.**
An earlier revision created `twinvpn_presence`, required
`TWINVPN_PRESENCE_DATABASE_URL`, gave presence a Postgres readiness probe and a
`depends_on` edge. All four are gone. `docs/protocol.md` §6.1 and
`contracts/docs/contract-matrix.md` §1 category 4 make a **durable** presence
record *"a permanent movement and IP history of the Owner"* — the privacy
defect itself, arriving as an infrastructure convenience — and
`presence.proto` classifies presence as ephemeral for that reason among
others.

Presence state is a bounded in-memory table with a TTL. **Losing it on restart
is correct**, not a gap: architecture.md §2.13 makes presence a *hint service,
never an authority*, whose unavailability degrades reconnect *latency* and not
reconnect *capability*, and S-11 marks the state explicitly eventually
consistent and TTL'd.

The service still *reads* `TWINVPN_DATABASE_URL` if one is present — it
validates it, so a `.env` copied unedited still fails on `CHANGE-ME` rather
than running with it, and then drops the value. Compose no longer supplies
one.

**On the relay-fleet row.** §2.8 and §2.12 contradict each other about who owns
the fleet registry, and both cannot be the single writer of one fact under I8.
§5 is architecture.md's own named authority for that question, and **S-09
assigns registry *and* ranking together to the Relay-Selection Service (2.12)**
— so §2.8's sentence is a prose error. The control plane keeps S-30, the
issuance record, which §5 *does* assign to it and which the relay never reads:
it verifies an Owner-rooted token offline against a signed issuer key set
(ADR-0005 §11.3, architecture.md A-12). `infra/postgres/initdb/10-databases.sh`
carries the full reasoning.

### 2.3 Two relays, and no control-plane edge

Two relays, in **two failure domains**, in one region. ADR-0006 §11.1 rule 3
refuses a `RelayMap` that drops a region with live sessions below 2 `ACTIVE`
relays in ≥2 `failure_domain`s; architecture.md §2.12 calls a cached set of
size 1 **a design error**. A one-relay local topology would make every failover
path — the thing R-10 is about — untestable.

**Neither relay has a `depends_on` edge onto the control plane, and that
absence is load-bearing.** ADR-0005 §11.3 and architecture.md A-12: relay
admission verifies an Owner-rooted `RelayCapabilityToken` **offline** against a
signed issuer key set, so a relay must come up and stay up with the whole
control plane down. Adding a startup edge would make **I5 quietly untrue in the
local topology** — and I5 is the invariant a convenience-shaped local setup is
most likely to erode. `build/verify/check-compose.py` asserts the absence.

---

## 3. Address families — IPv4 **and** IPv6

`docs/implementation/ownership.md`: *"IPv4 and IPv6 are equally required —
there is no 'v6 later'."* ADR-0010 R1 is **one story covering both**, and
ADR-0015 §11.2 refused `TVPN-IPV4-*` / `TVPN-IPV6-*` as reason-code domains
precisely because a per-family namespace makes "we have a v4 story and a v6
story" *sayable*.

A v4-only compose file reintroduces that asymmetry in practice while leaving
the claim standing. So there are three topologies, and the v6-only one is part
of the deliverable rather than a wave-2 item:

```bash
# dual stack — the DEFAULT
docker compose up -d …

# IPv6-only — the one that finds v6 defects
docker compose -f docker-compose.yml -f infra/compose/ipv6-only.yml up -d …

# IPv4-only — THE CONTROL RUN, not a supported mode
docker compose -f docker-compose.yml -f infra/compose/ipv4-only.yml up -d …
```

The v4-only override exists for `docs/testing-strategy.md` **V4**: *"absence of
a signal is not evidence unless the signal was provably possible."* When a v6
run fails, the question is always "would the same procedure have failed on v4?"
and answering it needs a same-rig, same-command v4 run. **It is not a
deployment mode and a service that only works there is broken.** If you reach
for it to make something *work* rather than to explain why something *did not*,
that is the finding.

### Network prefixes, and one thing they must not be

| Topology | IPv4 | IPv6 |
|---|---|---|
| dual stack | `172.31.240.0/24` | `fd00:7717:1::/64` |
| IPv6-only | — | `fd00:7717:6::/64` |
| IPv4-only | `172.31.241.0/24` | — |

All infrastructure-lead choices, all deliberately outside the ranges the
product owns. ADR-0010 §11 fixes the TwinNet **overlay** plan at
`100.64.0.0/10` and the product ULA `fd7c:9e5d:2a10::/48` (AP-1, a pinned
constant); the compose network is **underlay** and must not collide with
either, or a local run would silently exercise an address plan the product
forbids. `check-compose.py` asserts the product ULA never appears as an
underlay prefix.

### Docker daemon requirements

`enable_ipv6: true` on a compose network is **not sufficient on every daemon**.
IPv6 and `ip6tables` must be on in the daemon itself, or the v6 topology comes
up "successfully" with unreachable addresses — which is worse than failing,
because it is a green IPv6 lane that never carried a v6 packet.

```json
/* /etc/docker/daemon.json */
{ "ipv6": true, "ip6tables": true, "experimental": true,
  "fixed-cidr-v6": "fd00:7717:d0c::/64" }
```

`.github/workflows/t2-post-merge.yml` does this and then **asserts the
result**: every container must hold a v6 address in the dual-stack run, and
must hold *no* v4 address in the v6-only run. A v6-only lane whose containers
still have v4 addresses proves nothing at all.

---

## 4. Environment configuration

Every variable, its default, whether it is required, and — the column that
matters — **what happens when it is absent**.

### 4.1 Rules that hold for the whole table

1. **No secret has a default.** Every secret uses `${VAR:?message}`, so an
   unset value is a readable startup error and never a fallback to a known
   value. `check-compose.py` asserts this mechanically, and the infra CI lane
   asserts that the guard actually bites by running `docker compose config`
   with everything unset and requiring it to *fail*.
2. **A default is stated where one exists.** "It uses a sensible default" and
   "it fails to start" are very different facts and only one of them is safe.
3. **Values transcribed from `contracts/registry/limits.json` or from an ADR
   are marked `frozen`.** A deployment may narrow them; widening one is a
   contract change, not a configuration change.

### 4.2 Common to all six services

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_SERVICE_NAME` | per-service, baked into the image | no | image default is used |
| `TWINVPN_INSTANCE_ID` | the container `hostname` | no | **the OTel `service.instance.id` attribute has no supplier.** The collector allowlists it, so it would simply be absent from every span, metric and log. `twinvpn-service-common` takes it as an explicit caller argument rather than reading a hostname or generating entropy — correct, because an id invented per process makes fleet queries *lie*: "how many instances served this" silently becomes "how many times did anything restart". Compose supplies the container hostname, which is stable across restarts. **See §11 — the services currently derive `name-pid` and do not yet read this variable.** |
| `TWINVPN_ENVIRONMENT` | `local` | no | `local` |
| `TWINVPN_LOG_LEVEL` | `info` | no | `info`. ADR-0015 §11.5: `CRITICAL`/`ERROR`/`WARN`/`INFO` on by default; `DEBUG`/`TRACE` off and auto-expiring. **No level, in any build, may emit `SECRET`.** |
| `TWINVPN_LOG_FORMAT` | `json` | no | `json` |
| `TWINVPN_LOG_LEVEL_EXPIRY_MS` | `3600000` | no | 1 h. The bound on how long `DEBUG`/`TRACE` may stay on. Raising it is a real privacy decision — a verbose `SENSITIVE`-bearing ledger must not accumulate indefinitely. |
| `TWINVPN_ADMIN_ADDR` | `[::]:9090` | no | `[::]:9090`. Serves `/healthz`, `/readyz`, `/metrics`. |
| `TWINVPN_HEALTHCHECK_URL` | `http://127.0.0.1:9090/readyz` | no | the container `HEALTHCHECK` has nothing to probe and reports unhealthy |
| `TWINVPN_SHUTDOWN_GRACE_MS` | `120000` | no | 120 s |
| `TWINVPN_SHUTDOWN_DRAIN_DEADLINE_MS` | `120000` | no | 120 s — ADR-0002 §11.7 rule 1 |
| `TWINVPN_ADDRESS_FAMILIES` | `dual` | no | `dual`. `dual` \| `ipv4` \| `ipv6`. |
| `TWINVPN_HAPPY_EYEBALLS_V6_BIAS_MS` | `250` | no | 250 ms — ADR-0002 §11.2, ADR-0005 §11.4, RFC 8305 |
| `TWINVPN_OTEL_ENABLED` | `true` | no | telemetry is emitted |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4317` | no | exports fail; **this must never affect a `Session`** (ADR-0015 §8) |
| `OTEL_TRACES_SAMPLER_ARG` | `1.0` | no | sample everything locally |
| `TWINVPN_LIMITS_PATH` | `/contracts/registry/limits.json` | no | **the service must refuse to start.** ownership.md rule 9 requires every untrusted input validated against `limits.json` *before* any allocation proportional to a declared length; a service with no bounds file has no bounds. |
| `TWINVPN_REASON_CODES_PATH` | `/contracts/registry/reason_codes.json` | no | **the service must refuse to start.** ownership.md rule 12: expose registered `reason_code`s, never raw internal errors. A code with no registry entry fails the contract tests. |

### 4.3 `control-plane`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_CP_LISTEN_QUIC` | `[::]:443` | no | ADR-0002 §11.2 rung 1 |
| `TWINVPN_CP_LISTEN_TCP` | `[::]:443` | no | rungs 2–4 |
| `TWINVPN_CP_QUIC_ZERO_RTT` | `false` | no | **must stay false.** 0-RTT is prohibited by ADR-0001 L-CONTROL and ownership.md §6. It is named as configuration so that enabling it is a visible, reviewable act rather than a silent default. |
| `TWINVPN_CP_TLS_CERT_PATH` | `/run/secrets/control-plane/tls.crt` | yes (file) | startup fails |
| `TWINVPN_CP_TLS_KEY_PATH` | `/run/secrets/control-plane/tls.key` | yes (file) | startup fails |
| `TWINVPN_CP_DATABASE_URL` | **none** | **YES** | **compose refuses to start** with a message naming the variable. The key name is the *service's*: an earlier revision of `docker-compose.yml` set `TWINVPN_DATABASE_URL`, which the control plane does not read, so a fully configured stack would still have failed at startup. `check-compose.py` now fails the build on any `TWINVPN_*` variable no service reads. |
| `TWINVPN_CP_DATABASE_MAX_CONNECTIONS` | `16` | no | 16 |
| `TWINVPN_CP_QUORUM_REPLICAS` | `0` | no | 0 — single-writer, correct for one Postgres. ADR-0009 §11.2 makes this a **deployment** choice. Above 0, an E-1-class write with no reachable quorum is **refused** with `CONTROL.QUORUM_UNAVAILABLE`, never committed locally with a promise to reconcile — a forked revocation history is exactly what E-1 forbids. |
| `TWINVPN_CP_OWNER_ANCHOR_PATH` | `/run/secrets/control-plane/owner-anchors.hex` | no | **a capability lost, not a startup failure.** The pinned `OwnerTrustAnchor` set (S-32), one base16 COSE_Key per line. With no file the control plane still enrols, discovers and streams, and refuses every Owner-authority statement with `AUTH.KEY_UNAVAILABLE` — announced at startup, not discovered from a refusal. A **malformed** line *is* a startup failure: a half-parsed trust anchor set is worse than none. `bootstrap-local.sh` writes an empty stub and compose mounts the directory, so Owner-authority commands are reachable outside a unit test; the stub is empty because an Owner root of trust is the Owner's to create (ADR-0007, architecture.md A-04) and a key this repository invented would be a root of trust nobody chose. |
| `TWINVPN_CP_EVENT_BUS` | `postgres-notify` | no | §2.2 |
| `TWINVPN_CP_WRITE_LEASE_TTL_MS` | `15000` | no | ADR-0002 N-4: exactly one writer per `TwinNet` log, held by a lease. Without the lease a write is refused with `CONTROL.WRITE_LEADER_UNAVAILABLE`, never written optimistically. |
| `TWINVPN_CP_RETENTION_FLOOR_DAYS` | `30` | frozen | `limits.json control_plane.retention_floor_days` |
| `TWINVPN_CP_RETENTION_FLOOR_EVENTS` | `1000000` | frozen | `limits.json` |
| `TWINVPN_CP_EVENT_RATE_SUSTAINED` | `1` | frozen | `limits.json`; over budget ⇒ `CONTROL.EVENT_RATE_EXCEEDED`, write refused |
| `TWINVPN_CP_EVENT_RATE_BURST` | `20` | frozen | `limits.json` |
| `TWINVPN_CP_C2_WATERMARK_BYTES` | `262144` | frozen | ADR-0002 §11.6; **halved on rung 2**, because TCP head-of-line blocking makes a backlog costlier |
| `TWINVPN_CP_C2_WATERMARK_EVENTS` | `512` | frozen | as above |
| `TWINVPN_CP_IDEMPOTENCY_WINDOW_MS` | `86400000` | frozen | `limits.json`; ADR-0008 |
| `TWINVPN_CP_ATTACH_RATE_SUSTAINED` | `200` | no | ADR-0002 §11.7 rule 3. Over-limit attaches get `CONTROL.ADMISSION_DEFERRED{retry_after_ms}`; **a TCP reset or a silent drop is prohibited here.** |
| `TWINVPN_CP_ATTACH_RATE_BURST` | `1000` | no | as above |
| `TWINVPN_CP_DRAIN_DEADLINE_MS` | `120000` | no | ADR-0002 §11.7 rule 1 |
| `TWINVPN_CP_READ_STALENESS_WAIT_MS` | `250` | frozen | ADR-0002 §11.3: a replica that cannot satisfy `causality_token` waits ≤250 ms then refuses with `CONTROL.READ_TOO_STALE`. **It MUST NOT serve a read it cannot satisfy** — this is what makes replica failover safe for revocation. |

### 4.4 `rendezvous`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_RZ_LISTEN_QUIC` / `_TCP` | `[::]:443` | no | — |
| `TWINVPN_RZ_TLS_CERT_PATH` / `_KEY_PATH` | `/run/secrets/rendezvous/tls.*` | yes (file) | startup fails |
| `TWINVPN_RZ_CONTROL_PLANE_URL` | `https://control-plane:443` | no | architecture.md §2.9 — for **authorization only**; rendezvous holds nothing durable |
| `TWINVPN_RZ_MAILBOX_TTL_MS` | `30000` | frozen | ADR-0002 §11.5. **The mailbox is a jitter buffer, not durability** (N-9). |
| `TWINVPN_RZ_MAILBOX_CAPACITY_PER_TARGET` | `8` | frozen | ADR-0002 §11.5 |
| `TWINVPN_RZ_MAILBOX_OVERFLOW_POLICY` | `drop-oldest` | frozen | overflow ⇒ `CONTROL.MAILBOX_OVERFLOW` |
| `TWINVPN_RZ_CALL_DELIVERY_P50_BUDGET_MS` | `150` | no | ADR-0002 §11.5 path [1] |
| `TWINVPN_RZ_C4_MAX_BYTES` | `1200` | frozen | `limits.json envelope.c4_max_bytes`. **B3 is the hostile boundary** — reachable by anyone with a UDP socket, pre-authentication. 1200 B is the worst-case IPv6 path MTU minus headers, *not* the IPv4 576 B floor. |
| `TWINVPN_RZ_C4_MAX_DEPTH` | `4` | frozen | half the C1 limit; the hostile boundary gets the tighter bound |
| `TWINVPN_RZ_MAX_CANDIDATES_PER_SET` | `32` | frozen | `limits.json candidates.max_candidates_per_set` |
| `TWINVPN_RZ_CANDIDATE_EXPIRY_MS` | `30000` | frozen | `limits.json candidates.default_expiry_ms` |
| `TWINVPN_RZ_FRAME_READ_TIMEOUT_MS` | `5000` | no | **closes a slowloris hold its own tests found.** Without a deadline on a *partially received* frame, an attacker sends one length prefix and one byte and holds a connection and its buffer open indefinitely — having authenticated nothing. |
| `TWINVPN_RZ_MAX_CONNECTIONS` | `16384` | no | **closes descriptor exhaustion its own tests found.** Past the ceiling `accept` is refused; without it the process runs out of file descriptors and fails at everything at once. |
| `TWINVPN_RZ_MAX_ATTACHMENTS` | `8192` | no | unbounded attachment table |
| `TWINVPN_RZ_MAX_MAILBOX_TARGETS` | `8192` | no | unbounded distinct-target growth |
| `TWINVPN_RZ_MAX_MAILBOX_BYTES` | `33554432` (32 MiB) | no | unbounded retained mailbox bytes |
| `TWINVPN_RZ_MAX_BINDINGS` | `16384` | no | unbounded `device_id`↔channel binding table |
| `TWINVPN_RZ_BINDING_TTL_MS` | `600000` | no | a binding outlives its connection forever |
| `TWINVPN_RZ_SOURCE_RATE_PER_SEC` | `20` | no | no per-source `CALL` rate limit. A device sends an offer, an answer and a few trickle candidate sets — single-digit frames per second per peer — so 20/s with a burst of 40 leaves a CGNAT full of real devices ample room while making a flood cost the attacker a bucket entry rather than a mailbox. |
| `TWINVPN_RZ_SOURCE_BURST` | `40` | no | as above |

> **These nine are additions, not transcriptions, and `rendezvous-connectivity`
> was right to make them.** `limits.json` bounds **one message** — 1200 B, depth
> 4, 32 candidates. Nothing in the frozen contracts bounds **how many** messages,
> connections or table entries exist at once, and `ownership.md` rule 10 requires
> every allocation an untrusted input can drive to be bounded. This is
> `contracts/docs/trust-boundaries.md` B3: *"reachable by anyone with a UDP
> socket"*, *"where a parser bug is a remote memory-safety bug"*. Two of them
> close real bugs the service's own tests found.

### 4.5 `presence`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_PRESENCE_LISTEN_QUIC` / `_TCP` | `[::]:443` | no | — |
| `TWINVPN_PRESENCE_TLS_CERT_PATH` / `_KEY_PATH` | `/run/secrets/presence/tls.*` | yes (file) | startup fails |
| `TWINVPN_PRESENCE_CONTROL_PLANE_URL` | `https://control-plane:443` | no | authorization only — **not** a readiness input, see §5 |
| `TWINVPN_PRESENCE_HEARTBEAT_INTERVAL_MS` | `30000` | no | 30 s |
| `TWINVPN_PRESENCE_RECORD_TTL_MS` | `180000` | no | 3 min. Records are explicitly eventually consistent and TTL'd (ADR-0009). **Presence never gates a connection attempt** — "presence says offline" MUST NOT prevent an attempt (architecture.md §2.13, S-11). |
| `TWINVPN_PRESENCE_MAX_DEVICES` | `65536` | no | unbounded device-record table |
| `TWINVPN_PRESENCE_FRAME_READ_TIMEOUT_MS` | `5000` | no | a slowloris hold, exactly as for rendezvous |
| `TWINVPN_PRESENCE_MAX_CONNECTIONS` | `16384` | no | descriptor exhaustion, exactly as for rendezvous |
| `TWINVPN_PRESENCE_MAX_BINDINGS` | `16384` | no | unbounded binding table |
| `TWINVPN_PRESENCE_BINDING_TTL_MS` | `600000` | no | a binding outlives its connection forever |

> **There is no `TWINVPN_PRESENCE_DATABASE_URL` row because presence has no
> database.** See §2.2. The service still validates a `TWINVPN_DATABASE_URL` if
> one reaches it — so an unedited `CHANGE-ME` still fails startup — and then
> drops the value; `SecretString` has no `Display` and no `Serialize`, so it has
> no rendering path even by accident.

### 4.6 `relay-a` / `relay-b`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_RELAY_ID` | per-instance, 16 hex chars | **YES** | no identity in the `RelayMap`. 8 bytes = `limits.json identifiers.relay_id_bytes`. |
| `TWINVPN_RELAY_REGION` | `local-1` | **YES** | ADR-0006 §11.1 `regions[]` |
| `TWINVPN_RELAY_FAILURE_DOMAIN` | `fd-a` / `fd-b` | **YES** | ADR-0006 §11.1; the warm standby (ADR-0005 §11.6 `RELAY_STANDBY_READY`) requires a *different* domain |
| `TWINVPN_RELAY_OPERATOR_GROUP_ID` | `local-operator` | **YES** | must match the `aud` of the `RelayCapabilityToken` |
| `TWINVPN_RELAY_ADMIN_STATE` | `ACTIVE` | no | `ACTIVE` \| `DRAINING` \| `RETIRED` |
| `TWINVPN_RELAY_CARRIAGES` | `R-UDP,R-QUIC,R-TLS` | no | ADR-0005 §11.4; **raced with a staggered start, never sequential after a timeout** |
| `TWINVPN_RELAY_LISTEN_UDP` | `[::]:41641` | no | `R-UDP` primary |
| `TWINVPN_RELAY_LISTEN_UDP_443` | `[::]:443` | no | `R-UDP` on 443 |
| `TWINVPN_RELAY_LISTEN_QUIC` | `[::]:443` | no | `R-QUIC`, QUIC DATAGRAM (RFC 9221) |
| `TWINVPN_RELAY_LISTEN_TLS` | `[::]:443` | no | `R-TLS`, TLS 1.3, 2-byte length-prefixed frames |
| `TWINVPN_RELAY_ISSUER_KEYS_PATH` | `/run/secrets/relay/issuer-keys.json` | **YES** (file) | **fail closed.** The bootstrap stub is an EMPTY key set on purpose: no token verifies. A relay that admitted flows because it had no issuer keys would be an open relay. |
| `TWINVPN_RELAY_STATIC_KEY_PATH` | `/run/secrets/relay/static-noise.key` | **YES** (file) | no leg can be established |
| `TWINVPN_RELAY_TOKEN_LIFETIME_MS` | `86400000` | frozen | `limits.json relay.token_lifetime_ms` |
| `TWINVPN_RELAY_TOKEN_CLOCK_SKEW_MS` | `300000` | frozen | `limits.json relay.token_clock_skew_ms` |
| `TWINVPN_RELAY_TOKEN_GRACE_MS` | `21600000` | no | 6 h `T_RELAY_GRACE` (ADR-0005 §11.3, testing-strategy A-13). Relay-issued renewal — **no control-plane involvement.** |
| `TWINVPN_RELAY_PAIR_TAG_BUCKET_SECONDS` | `600` | frozen | `limits.json relay.pair_tag_bucket_seconds`. Rotates every 10 min so a tag cannot be used for long-term linkage. |
| `TWINVPN_RELAY_PAIR_TAG_ACCEPTED_SKEW` | `1` | frozen | accept `bucket`, `bucket−1`, `bucket+1` |
| `TWINVPN_RELAY_MAX_FLOWS_PER_SUBJECT` | `64` | no | ADR-0005 §11.5; exceeded ⇒ `RELAY.FLOW_LIMIT_REACHED` |
| `TWINVPN_RELAY_MAX_TOTAL_FLOWS` | `65536` | no | **the ceiling ADR-0005 §11.5 does not provide, and `relay-plane` was right to add it.** Every limit in §11.5's table is *per `relay_sub`*. That bounds one attacker; it says nothing about how many subjects exist, so the flow table had **no memory bound at all** — against `ownership.md` rule 10. 65536 is 1024 subjects at their full per-subject allowance. The **subject table** and the **cookie gate** are sized *from* this value rather than configured separately, so one number moves all three and they cannot drift apart. |
| `TWINVPN_RELAY_RATE_PER_SUBJECT_MBPS` | `20` | no | token bucket, **throttle not drop** ⇒ `RELAY.RATE_LIMITED` |
| `TWINVPN_RELAY_RATE_PER_FLOW_MBPS` | `10` | no | as above |
| `TWINVPN_RELAY_QUOTA_BYTES_PER_HOUR` | `21474836480` (20 GiB) | no | ⇒ `RELAY.QUOTA_EXCEEDED` |
| `TWINVPN_RELAY_BIND_PER_MINUTE_PER_SUBJECT` | `30` | no | ⇒ `RELAY.BIND_RATE_LIMITED` |
| `TWINVPN_RELAY_COOKIE_THRESHOLD_HANDSHAKES_PER_S` | `20` | no | per source /24 (v4) or /48 (v6); above it a **stateless cookie challenge** comes first, so the relay performs no asymmetric operation for an unvalidated source address |
| `TWINVPN_RELAY_PENDING_SLOT_TTL_MS` | `30000` | no | ⇒ `RELAY.PAIR_UNMATCHED` |
| `TWINVPN_RELAY_IDLE_FLOW_TIMEOUT_MS` | `900000` | no | ⇒ `RELAY.FLOW_IDLE_TIMEOUT` |
| `TWINVPN_RELAY_FLOW_QUEUE_MAX_BYTES` | `65536` | no | `min(64 KiB, 250 ms × flow rate)`, tail-drop |
| `TWINVPN_RELAY_RETAIN_PEER_PAIR` | `false` | **must stay false** | **O-13.** A relay sees both ends of a `RELAYED` session by necessity; retaining that correlation would hold the peer graph and defeat I1 *in metadata* even though the relay never sees plaintext. Per-session relay debugging is deliberately impossible (ADR-0015 §13 records this as accepted cost). |
| `TWINVPN_RELAY_METRICS_LABEL_ALLOWLIST` | the five §9 labels | frozen | `relay_region, protocol_version, reason_code, outcome, address_family` — ADR-0015 §9 |

### 4.7 `relay-directory`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_RELAYDIR_LISTEN_TCP` / `_QUIC` | `[::]:443` | no | — |
| `TWINVPN_RELAYDIR_TLS_CERT_PATH` / `_KEY_PATH` | `/run/secrets/relay-directory/tls.*` | yes (file) | startup fails |
| `TWINVPN_DATABASE_URL` ← `TWINVPN_RELAYDIR_DATABASE_URL` | **none** | **YES** | **compose refuses to start** |
| `TWINVPN_RELAYDIR_MAP_SIGNING_KEY_PATH` | `/run/secrets/relay-directory/map-signing.key` | **YES** (file) | no `RelayMap` can be signed. ADR-0006 §11.1: one COSE_Sign1/CBOR document per operator group, issuer Ed25519 over the canonical encoding. |
| `TWINVPN_RELAYDIR_OPERATOR_GROUP_ID` | `local-operator` | **YES** | — |
| `TWINVPN_RELAYDIR_MIN_ALTERNATES_PER_REGION` | `2` | frozen | ADR-0006 §11.1 rule 3; below it the device keeps the prior map and emits `RELAY.SELECT.ALTERNATES_INSUFFICIENT` |
| `TWINVPN_RELAYDIR_MIN_FAILURE_DOMAINS_PER_REGION` | `2` | frozen | as above |
| `TWINVPN_RELAYDIR_REQUIRE_LITERAL_ENDPOINTS` | `true` | frozen | ADR-0006 §11.1 rule 1: **endpoints are literals, never hostnames. Relay reachability MUST NOT depend on DNS.** |
| `TWINVPN_RELAYDIR_REQUIRE_BOTH_FAMILIES` | `true` | frozen | rule 2: every region publishes relays reachable over **both** families. Relaxed only in the v4-only and v6-only overrides, where the relaxation is visible in configuration. |
| `TWINVPN_RELAYDIR_MAP_TTL_MS` | `3600000` | no | soft freshness only |
| `TWINVPN_RELAYDIR_MAP_EXPIRY_ENFORCED` | `false` | **must stay false** | rule 4: **the map is stale-but-usable without limit.** Past `not_after_ms` the device keeps using it and emits `CONTROL.STALENESS.RELAY_SET_EXPIRED`. No expiry, at any age, may reduce the candidate set or block an attempt. |
| `TWINVPN_RELAYDIR_REGION_SPREAD_MS` | `20000` | no | ADR-0006 §11.7 `T_REGION_SPREAD` |

### 4.8 `relay-health`

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_DATABASE_URL` ← `TWINVPN_RELAYDIR_DATABASE_URL` | **none** | **YES** | **compose refuses to start** |
| `TWINVPN_RELAYHEALTH_TARGETS` | `relay-a:9090,relay-b:9090` | no | nothing is probed. Targets are the relays' **admin** listeners, not their data ports: a prober that opened a relay flow would be indistinguishable from a peer and would consume the fleet's own quota. |
| `TWINVPN_RELAYHEALTH_PROBE_INTERVAL_MS` | `10000` | no | 10 s |
| `TWINVPN_RELAYHEALTH_PROBE_TIMEOUT_MS` | `3000` | no | 3 s |
| `TWINVPN_RELAYHEALTH_STATES` | `HEALTHY,DEGRADED,UNHEALTHY,UNKNOWN` | frozen | testing-strategy A-03 |
| `TWINVPN_RELAYHEALTH_DEGRADED_RTT_MS` | `250` | no | reliability.md §5.4's relay threshold |

### 4.9 Compose-level

| Variable | Default | Required | If absent |
|---|---|---|---|
| `TWINVPN_PG_PASSWORD` | **none** | **YES** | `docker compose up` fails immediately, naming the variable |
| `TWINVPN_PG_USER` / `TWINVPN_PG_DATABASE` | `twinvpn` / `twinvpn_control` | no | — |
| `TWINVPN_CP_DATABASE_URL` | **none** | **YES** | as above. Two database URLs are required, not three — presence has none (§2.2). |
| `TWINVPN_RELAYDIR_DATABASE_URL` | **none** | **YES** | as above |
| `SOURCE_DATE_EPOCH` | `1756252800` | no | a fixed date, **not `now`** — ADR-0018 BM-6, so an unparameterised image build is still deterministic |
| `TWINVPN_SOURCE_COMMIT` | `unknown` | no | image label only |
| `TWINVPN_*_IMAGE` | the tags in `infra/docker/base-images.lock` | no | tags are used; see §7 |

---

## 5. Health and readiness

**They are different checks, both are required, and only one of them is a
dependency signal.** `docs/implementation/ownership.md` rule 4.

| Path | Question | Fails when |
|---|---|---|
| `/healthz` | *Is this process running and are its own invariants holding?* | the process is wedged; a restart would help |
| `/readyz` | *Can this process serve — **including its dependencies**?* | a dependency is unreachable; a restart would **not** help |

A control plane whose database is unreachable is **live** and **not ready**. A
readiness probe that returns 200 unconditionally is not a readiness probe, and
`build/verify/check-compose.py` fails the build if the Dockerfile's healthcheck
stops targeting `/readyz` or the liveness path disappears.

Readiness must reflect real dependency availability:

| Service | Policy | `/readyz` checks |
|---|---|---|
| `control-plane` | `AnyDependency` | Postgres reachable; the per-`TwinNet` write lease obtainable or knowingly held elsewhere (ADR-0002 N-4) |
| `rendezvous` | **`NoControlPlaneCalls`** | routing tables reachable and the ceilings hold. **Asks nothing of any other process** — see below |
| `presence` | **`NoControlPlaneCalls`** | the in-memory record table is reachable and within its ceilings. **No database** — §2.2 |
| `relay-a`, `relay-b` | `NoControlPlaneCalls` | issuer key set loaded and parsable; all configured carriages bound |
| `relay-directory` | `AnyDependency` | Postgres reachable; signing key loaded; the current map satisfies the ≥2 alternates / ≥2 failure domains floor |
| `relay-health` | `AnyDependency` | Postgres reachable |

### Why `rendezvous` and `presence` refuse a control-plane readiness probe

**This table used to say `AnyDependency` for both, with rendezvous probing "the
control-plane authorization endpoint reachable". That was wrong, both services
refused it, and their reasoning is worth stating rather than just correcting.**

A rendezvous that reports **NOT READY** when the control plane blips is removed
from the load balancer. Removing it stops peers exchanging candidates. Peers
that cannot exchange candidates fall back on the control plane to reconnect.
So a health check intended to express a dependency **puts the control plane
back in the critical path of every reconnect** — **I5 violated by way of a
health check**, with no line of code anywhere that calls the control plane.

The same argument covers presence with an extra step: architecture.md §2.13
makes presence a **hint service, never an authority**, whose unavailability
degrades reconnect *latency* and not reconnect *capability*. A readiness probe
that fails on a control-plane blip converts a latency degradation into an
availability one.

`twinvpn-service-common` makes the mistake **unrepresentable** rather than
merely discouraged: every probe declares a `ProbeKind`, and a registry built
with `ReadinessPolicy::NoControlPlaneCalls` **refuses to register** a
`ControlPlane` probe. The refusal happens at wiring time, not when the control
plane is next down.

The `depends_on` edges in `docker-compose.yml` were weakened from
`service_healthy` to `service_started` for the same reason: a startup gate is
the same mistake one step earlier — it makes rendezvous unstartable while the
control plane is unhealthy. **Ordering is useful; gating is not.** These two
services still read `TWINVPN_{RZ,PRESENCE}_CONTROL_PLANE_URL` for
*authorization*, which is a per-request concern and not a liveness
precondition.

The container `HEALTHCHECK` targets `/readyz`, because that is what
`depends_on: condition: service_healthy` needs. It is an **HTTP request to the
service's own endpoint, not a TCP probe** — a listening socket proves a bind,
not health. The runtime image is distroless and has no HTTP client, so a single
static `busybox` (~1 MB) is copied in for `sh` and `wget` and nothing else in
the image can fetch, resolve or execute anything.

**The `otel-collector` has no container `HEALTHCHECK`, and that is stated
rather than faked.** Its image contains no HTTP client, so any check
expressible there would be a process-liveness or TCP probe. Its readiness is
observed the honest way instead: the `health_check` extension on `:13133` and
the `otelcol_*` self-telemetry on `:8888` are both scraped by Prometheus.
Dependents therefore use `service_started`, not `service_healthy`.

---

## 6. Observability

### 6.1 What ADR-0015 permits here

§11.1: *"OpenTelemetry as an **internal, infrastructure-side** instrumentation
library is permitted; OpenTelemetry as an **end-to-end client-to-backend**
pipeline is **rejected**."*

Alternative A was rejected as **fatal on privacy**: a cross-component trace
correlating client, rendezvous and relay *is* a peer graph and a movement
record, and it exists on infrastructure by construction. So:

- This collector receives telemetry from the six server-side artifacts and
  **from nothing else**. There is no client-facing ingress anywhere in the
  stack.
- **Tier 0** never leaves a device, because there is no transport for it.
- **Tier 1** leaves only by an explicit user act, as a signed bundle — not over
  OTLP.
- **Tier 2** is off by default, opt-in, identifier-free. Its pipeline is
  configured here so that the aggregation service and this collector share one
  config rather than two that drift.

### 6.2 How payload capture is prevented — structurally

Four mechanisms, in order:

1. **Emit-time classification (the real control, and not ours).** O-14 requires
   redaction at emit time by schema-level field classification, *not* at export
   time by pattern matching over rendered text. `SECRET`-classified fields have
   **no rendering path at all — the code that would print them does not exist,
   in any build.** That is the services' and the schema's obligation and
   nothing here relieves them of it.

2. **A positive attribute allowlist** (`redaction/allowlist`,
   `allow_all_keys: false`). Anything not named is deleted, so a field added
   tomorrow with no classification and nobody's review is dropped **by
   default**. A denylist only catches what someone thought of, and O-12's
   "never, in any build, including debug builds" is not a property a denylist
   can have.

3. **A forbidden-key filter *in front of* the allowlist** (`filter/forbidden`).
   This is not redundant. The allowlist would **silently delete** a leaked key;
   the filter **drops the whole record and increments a counter**. A silently
   sanitised leak is a leak nobody fixes. Order is asserted by
   `build/verify/check-otel-redaction.py`, and a non-zero drop rate raises the
   `TwinVPNObservabilityForbiddenAttributeObserved` alert as **critical** — a
   security defect in the emitting service, not a collector tuning problem.

4. **Prometheus `metric_relabel_configs`** as a second, independent enforcement
   point for the §9 label discipline, for anything scraped directly rather than
   routed through the collector.

Plus two negative controls on the backends: Tempo's `metrics_generator` and
Grafana's Tempo `nodeGraph` are both **off**, in two files, because a service
graph derived from spans across control-plane, rendezvous, presence and relay
reconstructs — from individually permitted per-component traces — exactly the
cross-component correlation §6 called fatal.

**Relay-specific (O-13).** `transform/relay-severs-context` clears the parent
span ID and deletes the correlation/causation/message ids on any span whose
`service.name` is `twinvpn-relay`. §11.1 forbids propagating trace context
across a relay; §7 calls relay-side observability *"the sharpest risk"*. This
makes it impossible for a mis-instrumented relay to stitch two peers into one
trace even if it tries.

**ADR-0018 VR-2 consequence 3.** `abi_major`/`abi_minor` are **stripped on the
Tier-2 pipeline only** — an ABI pair is build-identifying and has no aggregate
meaning. Consequence 1 *permits* them in a Tier-1 bundle and in
`CoreBuildIdentity`, so the strip is scoped rather than global, and
`check-otel-redaction.py` fails the build if it is applied outside Tier 2.

### 6.3 Attribute conventions — the R-31 divergence closed by naming things once

`twinvpn-service-common` exists so the four server domains do not each invent a
health endpoint, a log format and an OTel wiring. The same argument applies to
attribute names, and it is why the collector's allowlist *is* the convention:
an attribute not on it does not reach a backend, so there is exactly one place
to look and exactly one place to change.

| Group | Attributes |
|---|---|
| Provenance (`CoreBuildIdentity`, S-46) | `service.name`, `service.version`, `service.instance.id`, `deployment.environment`, `twinvpn.component`, `twinvpn.core_version`, `twinvpn.protocol_epoch`, `twinvpn.schema_digest`, `twinvpn.reason_registry_version`, `twinvpn.crypto_provider`, `twinvpn.profile`, `twinvpn.target_triple`, `twinvpn.source_commit`, `twinvpn.abi_major`, `twinvpn.abi_minor` |
| **Correlation** | `twinvpn.correlation_id`, `twinvpn.causation_id`, `twinvpn.message_id`, `twinvpn.idempotency_key` |
| Reason code + registry attributes | `twinvpn.reason_code`, `twinvpn.reason_domain`, `twinvpn.reason_class`, `twinvpn.severity`, `twinvpn.terminal`, `twinvpn.user_actionable`, `twinvpn.remediation_class`, `twinvpn.scope`, `twinvpn.doc_anchor`, `twinvpn.evidence_key` |
| The §9 metric label allowlist | `twinvpn.relay_region`, `twinvpn.protocol_version`, `twinvpn.outcome`, `twinvpn.address_family` |
| Tier-2 only | `twinvpn.nat_class`, `twinvpn.nat_class_local`, `twinvpn.nat_class_remote`, `twinvpn.platform_class`, `twinvpn.day_bucket` |
| State machine (O-05) | `twinvpn.state_from`, `twinvpn.state_to`, `twinvpn.trigger`, `twinvpn.connection_state` |
| Transport / relay shape | `twinvpn.transport_rung`, `twinvpn.carriage`, `twinvpn.failure_domain`, `twinvpn.admin_state`, `twinvpn.load_class`, `twinvpn.health_state` |
| Observability self-report (§8) | `twinvpn.dropped_events`, `twinvpn.ring` |
| Narrow semconv | `http.request.method`, `http.response.status_code`, `rpc.system`, `rpc.method`, `rpc.grpc.status_code`, `error.type`, `exception.type`, `otel.status_code` |

Two absences are deliberate and are asserted by the redaction lint:

- **No `summary` / `message` / `title`.** ADR-0015 §11.2 rule 5 forbids a
  carrier of a `Diagnostic` from adding a localized text field — that would
  place a second text authority outside the registry and defeat rule 4, *"the
  code is the contract; the human text is not."*
- **No `exception.message` / `exception.stacktrace`.** A VPN process's
  exception text can contain packet buffers and key material, which is why §7
  makes crash reporting opt-in, stacks-and-registers only, with those regions
  dump-excluded.

#### Correlation and causation, across every hop

`correlation_id` answers *"what is this a reply to"*; `causation_id` answers
*"what made this happen"*. They differ whenever an event is a second-order
consequence — `contracts/proto/twinvpn/v1/common.proto` gives the worked
example. `causation_id` is set from the message currently being processed,
**never invented and never inherited transitively**, which is what keeps a
causal chain a chain rather than a claim.

These are the **protocol** correlation from `MessageMetadata`, already on the
wire. `contracts/proto/twinvpn/v1/errors.proto` records the deliberate
difference from ADR-0015 §11.3's *local ledger* `correlation_id`, which is
classified `SENSITIVE` and never leaves the device. The two are different
facts; only the wire one is allowlisted here.

They are preserved at **every hop** — control-plane → rendezvous → presence →
relay-directory — and the **relay is the one exception**, severed under O-13
above. The redaction lint asserts they stay allowlisted, with the same force it
asserts the forbidden keys stay out, because an allowlist that quietly dropped
them would pass every privacy check and destroy the causal chain.

### 6.4 Dashboards

Provisioned read-only from `infra/grafana/dashboards/`. `allowUiUpdates: false`
— a dashboard that answers *"did the NAT-traversal success rate regress in
release N?"* is only evidence if the query that produced it is under review
like any other artifact.

| Dashboard | Answers |
|---|---|
| `TwinVPN — Connection outcomes` | outcome by NAT class pair; relay incidence; time-to-first-byte p50/p90/p99 by family; control-plane transport rung |
| `TwinVPN — Reason codes by domain` | reason-code frequency by domain; `INTERNAL`-domain share against §14 condition 5's 5% trigger; emissions carrying **no** `reason_code` (must be zero) |
| `TwinVPN — Infrastructure health` | forbidden-attribute drops; Tier-0 event drops; export failures; liveness vs readiness; relay fleet floors; control-plane event budget |

**Read the Tier-2 panels with §13 in hand.** The opt-in channel has low and
*biased* take-up — privacy-motivated users decline — so its aggregates *"must
never be treated as a representative sample"*. Use them for regression
**detection**, never for absolute rates, and never gate a decision on them
alone.

---

## 7. Images and supply chain

One `Dockerfile.service` for all six services, parameterised by `SERVICE`. Six
near-identical Dockerfiles is the same R-31 divergence class
`twinvpn-service-common` exists to prevent.

- **Multi-stage**: dependency fetch → build → distroless runtime.
- **Non-root**: `gcr.io/distroless/cc-debian12:nonroot` runs as uid 65532.
  There is no root user to downgrade from and no shell to exec into.
- **Read-only root filesystem**, all capabilities dropped except
  `NET_BIND_SERVICE` (needed for the ADR-mandated ports 443 and 41641), a
  16 MB `noexec,nosuid,nodev` tmpfs, `no-new-privileges`.
- **PID 1 is the service**, so `SIGTERM` reaches it directly and the graceful
  shutdown sequence is actually exercised. No shell, no init wrapper, no signal
  to swallow.
- **Reproducibility (ADR-0018 BM-6)**: `--remap-path-prefix` for every source
  root, `SOURCE_DATE_EPOCH` as a build arg defaulting to a fixed date,
  `cargo build --locked --offline`.

### The TLS key is the identity; the certificate is not

`bootstrap-local.sh` mints an Ed25519 key **and** a self-signed certificate for
each wire-facing service. **Only the key matters.**

`rendezvous` and `presence` terminate TLS 1.3 with **mutual RFC 7250 raw-public-key
authentication** — client auth mandatory and non-configurable, 0-RTT
structurally prohibited. In that mode the server's whole identity is `tls.key`
and the peer is authenticated by its public key, not by a name in a
certificate; ADR-0001 §6 rejected the naming system a certificate implies.

`tls.crt` is generated anyway, and each service's config requires it to
**exist**, because tooling in this space expects a certificate file to be
there. Nothing reads its contents and nothing trusts its subject, its SAN or
its expiry. Two consequences an operator will otherwise get wrong:

- Rotating `tls.key` **rotates the server's identity**, and every pinning peer
  must learn the new key.
- Rotating `tls.crt` accomplishes **nothing**. Its 90-day expiry is not a
  deadline.

Do not reason about the two files as a pair.

### Base image pinning — an honest gap

ADR-0018 DP-2 pins dependencies **by digest**, because a mutable pointer
*"makes a dependency bump invisible in the diff, which is exactly the review a
supply-chain policy exists to force."* A container tag has the same defect.

`infra/docker/base-images.lock` has **empty digest fields**. They were not
invented: *a fabricated digest is strictly worse than an honest tag, because it
reads as a pin, passes review as a pin, and pins nothing.* Resolve them on a
host with registry access:

```bash
bash build/verify/pin-base-images.sh          # needs crane, skopeo or docker
python3 build/verify/check-budgets.py --check-image-pins
TWINVPN_REQUIRE_IMAGE_DIGESTS=1 python3 build/verify/check-budgets.py --check-image-pins
```

Until then the CI supply-chain lane reports the gap as a **warning**, and the
last command above turns it into a gate.

---

## 8. Debugging each service

```bash
docker compose ps                        # what is up, and healthy vs unhealthy
docker compose logs -f control-plane     # structured JSON on stdout
docker compose exec -T prometheus wget -q -O - http://control-plane:9090/readyz
```

The runtime image has **no shell**, so `docker compose exec control-plane sh`
will not work. Probe from a container that does have one (`prometheus`,
`postgres`) or from the host via the published admin port.

| Symptom | First thing to check |
|---|---|
| `docker compose up` fails instantly naming a variable | a required secret is unset. That is the `${VAR:?}` guard working — set it in `.env`. |
| A service exits naming a missing `TWINVPN_*` variable | compose and the service disagree on the key name. Run `python3 build/verify/check-compose.py`, which fails on any `TWINVPN_*` variable no service reads — that check exists because this exact mismatch shipped once (`TWINVPN_DATABASE_URL` vs `TWINVPN_CP_DATABASE_URL`). |
| An Owner-authority command is refused with `AUTH.KEY_UNAVAILABLE` | the `OwnerTrustAnchor` set is empty. `bootstrap-local.sh` writes an empty stub on purpose; add your development Owner public key to `infra/secrets/control-plane/owner-anchors.hex`. This is a capability lost, not a fault. |
| The control plane refuses to **start**, citing the anchor path | a **malformed** line in that file. Empty is fine; unparseable base16 is not. |
| `rendezvous` or `presence` is up while the control plane is down | **correct.** §5 explains why their readiness must not depend on it. |
| A service is `unhealthy` | `curl http://127.0.0.1:1900N/readyz`. Readiness reflects **dependencies**; check those before the service. |
| A service never starts | it has a `service_healthy` edge onto something that is not healthy. `docker compose ps` shows which. |
| Ports "already allocated" | something else holds `8443`/`41641`/`15432`/`13000`. `check-compose.py` catches collisions *within* the topology, not against the rest of your machine. |
| Nothing in Grafana | `http://127.0.0.1:18888/metrics` on the collector — `otelcol_receiver_accepted_*` at zero means nothing is being sent. |
| Traces missing but metrics present | `otelcol_exporter_send_failed_spans_total`. A stalled export **must never affect a `Session`** (ADR-0015 §8); if it correlates with a degradation, the causation is the other way round. |
| An attribute you expected is absent | it is not on the allowlist (§6.3). That is the design. Add it to `redaction/allowlist` **and** justify its classification. |
| `TwinVPNObservabilityForbiddenAttributeObserved` firing | **a security defect in the emitting service.** O-12 says that field cannot exist in any build. Find the emitter; do not tune the collector. |
| IPv6-only topology comes up but nothing is reachable | the Docker daemon needs `ipv6` and `ip6tables`. See §3. |

Per-service notes:

- **`control-plane`** — the whole ladder is on 443. `CONTROL.TRANSPORT_DEGRADED_TCP`
  means rung 1 (QUIC/UDP:443) failed; check UDP reachability first.
- **`rendezvous`** — depends on control-plane for *authorization only*. It holds
  nothing durable; a restart loses only the 30 s mailbox, and N-9 says that is
  correct.
- **`presence`** — never gates anything. If a connection failure correlates with
  presence being down, presence is not the cause.
- **`relay-a` / `relay-b`** — if a relay will not admit a flow, check
  `issuer-keys.json` first: the bootstrap stub is an **empty** key set, so no
  token verifies. That is fail-closed, and it is correct.
- **`relay-directory`** — refuses to publish a map that drops a region below 2
  alternates in 2 failure domains. If it publishes nothing, check whether both
  relays are registered.
- **`relay-health`** — probes admin listeners, not data ports.

---

## 9. What was verified on this host, and what was not

Stated plainly, because a claim of "it works" that was never run is the failure
mode the wave-1 objective names in its last line.

**Verified here:**

| Check | Result |
|---|---|
| All 18 YAML files parse; no duplicate keys, tabs or trailing whitespace | pass |
| `build/verify/check-compose.py --strict` — secrets, bind sources, port collisions, wildcard binds, relay independence, relay floors, v6 override coverage, product-ULA-as-underlay, **env-key coverage, presence-has-no-database, the Owner anchor mount, and the readiness edges** | pass, **0 warnings on a freshly bootstrapped tree** |
| …its env-key coverage check, **negative-controlled**: reinstating the old `TWINVPN_DATABASE_URL` on `control-plane` | FAIL, naming the variable and the service |
| …its secret check, **negative-controlled three ways**: a key force-added to the index, a key excluded from the ignore rule, and git made unavailable | FAIL / FAIL / degraded-with-reason, as designed |
| `build/verify/check-otel-redaction.py` — allowlist, filter-order, Tier-2 `abi_*` strip, correlation preserved, no service graph | pass, **and negative-controlled**: flipping `allow_all_keys` to `true` and removing `correlation_id` makes it fail with both diagnoses |
| `build/budgets.toml` parses; `check-budgets.py --list` and `--check-image-pins` | pass |
| All three Grafana dashboards are valid JSON with `uid`, `title`, panels | pass |
| `bash -n` on every shell script | pass |
| `make lint`, `make test-contracts` | pass — 35801 contract checks, 0 failures |
| `make arch-lint` (ADR-0018 CD-3 / CD-I2 / CD-I5 / CB-3) | pass — core-foundation has landed `core/xtask`, so the named CI job is green |

**NOT verified here — Docker is not installed on this host:**

- `docker compose config` was **not run**. The compose file was validated by
  YAML parse, by merge-key resolution, and by `check-compose.py`'s structural
  checks, but the Compose schema itself was not checked by Compose.
- **No container was built and none was started.** The Dockerfile, the
  healthcheck command, the busybox shim, and the distroless runtime are
  **unexercised**.
- **The IPv6 and IPv6-only topologies were not brought up.** The configuration
  is complete and the CI lane asserts the outcome, but no v6 packet has been
  carried on this host.
- `yamllint`, `hadolint` and `shellcheck` are **not installed and could not be
  run**; there is also no `pip`. YAML was checked with PyYAML (parse,
  duplicate keys, tabs, trailing whitespace, final newline) and shell with
  `bash -n`. `infra/yamllint.yml` is configured and the CI lane runs all three.
- The collector config was **not loaded by a collector**. Processor names,
  OTTL syntax and the `redaction` processor's metrics support are asserted
  against the documented contract, not against a running binary. The
  `topology-up` job in `t2-post-merge.yml` exists to close exactly this gap:
  it scrapes `otelcol_processor_*`, which only exists once the pipelines are
  live.

---

## 10. Open requests to other domains

Recorded here rather than in a commit message, because they outlive the commit.

| # | Request | Owner | Why it matters |
|---|---|---|---|
| 1 | Read **`TWINVPN_INSTANCE_ID`** in `twinvpn-service-common` and pass it as the `instance_id` argument. | `control-plane` (owns `twinvpn-service-common`) | Compose now supplies a stable per-container value (§4.2). The services currently derive `format!("{service_name}-{pid}")`, so `service.instance.id` changes on every restart and every fleet query that groups by it is wrong — "how many instances served this" silently becomes "how many times did anything restart". The collector already allowlists the attribute; only the supplier is missing. |
| 2 | Widen the doc comment on `ReadinessPolicy::NoControlPlaneCalls`. | `control-plane` | It reads *"**The relays.**"*, but `rendezvous` and `presence` now use it too, for a different and equally load-bearing reason (§5). A reader checking whether the policy applies to them will conclude it does not. |
| 3 | Confirm the `depends_on` weakening from `service_healthy` to `service_started` on `rendezvous` and `presence`. | integration lead | It follows from the readiness ruling — a startup gate is the same I5 mistake one step earlier — but it is an inference from that ruling rather than something explicitly asked for, and it is one line per service to reverse. |

---

## 11. Related

- `docs/adr/ADR-0002` — control-plane messaging and event bus
- `docs/adr/ADR-0005`, `ADR-0006` — relay architecture, discovery and failover
- `docs/adr/ADR-0010` — IPv4/IPv6 routing
- `docs/adr/ADR-0015` — observability and diagnostics (**the authority for §6**)
- `docs/adr/ADR-0018` §11.9–§11.12 — build matrix, reproducibility, supply chain, layout
- `docs/testing-strategy.md` §6 — the T1/T2/T3/T4 tiers
- `contracts/registry/limits.json` — every bound marked `frozen` above
- `contracts/docs/trust-boundaries.md` — B1–B5
