# `twinvpn-relay-health`

Aggregates relay **self-reports** into a `RelayHealth` (S-10). `EVENTUAL`,
non-durable, recomputed — and **never a gate**.

**Owner:** `relay-plane`.
**Authority:** `docs/architecture.md` §5 row **S-10**,
[`contracts/proto/twinvpn/v1/relay.proto`](../../contracts/proto/twinvpn/v1/relay.proto)'s
`RelayHealth`, [ADR-0006](../../docs/adr/ADR-0006-relay-discovery-and-failover.md)
§11.2 and §11.3 rule 1, `docs/reliability.md` §4.1.

---

## 1. The one rule that shapes every type here

`relay.proto`:

> CONSISTENCY: EVENTUAL. Freshest observation wins, and **A CLIENT'S OWN PROBE
> FAILURE ALWAYS OUTRANKS A "HEALTHY" REPORT.** Per `docs/reliability.md` §4.1
> this MUST NOT gate a connection attempt — it contributes a score delta to
> selection and nothing more.

ADR-0006 §11.3 rule 1 says the same from the selection side: an `UNHEALTHY` state
"MUST NOT suppress a connection attempt".

So this crate has **no API that returns a usability verdict**:

- no `is_healthy`, no `is_usable`, no `admits`, no `candidates()`, no `filter()`;
- no `impl From<HealthState> for bool`;
- the only thing a `HealthState` produces is `score_delta() -> i32`;
- no `-> bool` keyed by a `relay_id` exists anywhere in the module.

[`tests/never_a_gate.rs`](tests/never_a_gate.rs) asserts those **absences** in the
source, because a gate that does not exist cannot be added by accident, and a
behavioural test can only show that today's callers do not gate.

---

## 2. A health-service outage costs a ranking exactly zero

The deltas are ADR-0006 §11.2's: `HEALTHY 0 · DEGRADED −40 · UNHEALTHY −150 ·
**UNKNOWN 0**`.

`UNKNOWN` contributing **0**, identically to `HEALTHY`, is the availability
property. A relay this service has never heard from — or has not heard from
recently — is `UNKNOWN`, so an outage does not push any relay down the ranking; it
merely removes a *negative* signal from relays that deserve one. The fleet then
ranks by measurement alone, which is what S-31 says should dominate anyway.

Making the unobserved state cost −40 or −150 would turn one service's failure into
a fleet-wide ranking distortion — the exact shape of failure §11.3 rule 1 forbids.
`the_health_service_being_down_costs_a_ranking_exactly_zero` and
`a_previously_healthy_fleet_going_unobserved_loses_no_ground` pin it from both
directions.

For the same reason, **a stale observation is `UNKNOWN`, never `UNHEALTHY`**: "we
have not looked recently" and "it is broken" are different facts.

---

## 3. Probing the admin listener, not the data port

`infra/README.md` §4.8: "Targets are the relays' **admin** listeners, not their
data ports: a prober that opened a relay flow would be indistinguishable from a
peer and would consume the fleet's own quota."

A `SelfReport` is therefore what a relay says about itself on `:9090`.

---

## 4. No per-session or peer-pair label, ever

`relay.proto`: "ADR-0015 O-13 forbids any per-session or peer-pair label on relay
telemetry, so this message carries no `session_id`, no `pair_tag`, and no device
identifier."

`SelfReport` carries a `relay_id`, a `load_class`, reachability, a probe RTT and an
observation timestamp — and there is no constructor that takes anything else. A
test asserts the absence of every forbidden name.

---

## 5. Build, test, and environment

```bash
source build/toolchain/env.sh
cd services
cargo build -p twinvpn-relay-health
cargo test  -p twinvpn-relay-health
```

`infra/README.md` §4.8's variables, plus every `twinvpn-service-common` one.

| Variable | Default | Required | If absent / if wrong |
|---|---|---|---|
| `TWINVPN_DATABASE_URL` ← `TWINVPN_RELAYDIR_DATABASE_URL` | **none** | **yes** | startup fails; a secret has no default |
| `TWINVPN_RELAYHEALTH_TARGETS` | *(empty)* | no | **nothing is probed, and that is legitimate**: every relay is `UNKNOWN`, which costs nothing. A malformed entry *is* a startup failure |
| `TWINVPN_RELAYHEALTH_PROBE_INTERVAL_MS` | `10000` | no | also sets the staleness window (6× the interval) |
| `TWINVPN_RELAYHEALTH_PROBE_TIMEOUT_MS` | `3000` | no | — |
| `TWINVPN_RELAYHEALTH_STATES` | `HEALTHY,DEGRADED,UNHEALTHY,UNKNOWN` | frozen | any change is a **startup failure**. Dropping `UNKNOWN` would be the worst possible edit — §2 |
| `TWINVPN_RELAYHEALTH_DEGRADED_RTT_MS` | `250` | no | `reliability.md` §5.4's relay threshold |

`TWINVPN_RELAYHEALTH_TARGETS` accepts IPv6 literals (`[::1]:9090`) as well as
names.

---

## 6. Health and readiness

`infra/README.md` §5: *Postgres reachable*.

Readiness is deliberately **not** "targets reachable". A relay-health service whose
probe targets are all down is working perfectly — it is reporting that they are
down. Tying its readiness to the fleet's would make one relay's outage look like
this service's, and would take the aggregate offline at exactly the moment it is
most useful. An **empty** aggregate is also ready, for the same reason as §2.

---

## 7. Known limitations

1. **The aggregate is in memory and no prober loop runs.** S-10 is `EVENTUAL`,
   non-durable and recomputed, so in-memory is the correct shape — but the periodic
   HTTP probe of each target's `/healthz` is not written. `Aggregate::observe` is
   the seam, and it is fully tested.
2. **No Postgres binding.** `sqlx` is declared in `services/Cargo.toml`'s workspace
   set but no member has ever built it, so it is absent from `services/Cargo.lock`
   and cannot be resolved on this host. `infra/README.md` §5 names Postgres in this
   service's readiness set; that probe is not implemented.
3. **No container has been built or run.** Docker is absent from this host.
4. **Nothing publishes the aggregate to `relay-directory`.** ADR-0006 §11.2 feeds
   `HealthState` into the score; `relay-directory`'s `rank::Health` is the matching
   type, and the transport between the two services is not wired. Because
   `UNKNOWN` costs zero, the unwired state is exactly the degraded-but-correct one.
