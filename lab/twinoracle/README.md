# twinoracle — the external leak oracle

**Owner:** `test-engineering`. **Never shipped** ([ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12).

---

## 1. The problem it exists to solve

A kill-switch criterion used to be discharged by asking the platform under test
whether it was blocking. That is the defendant grading its own exam, and all
three of these produce a confident "protected" while packets leave:

| What actually happened | What the platform's own API says |
|---|---|
| the WFP filter set was never installed (the caller was not really elevated) | `protected` |
| the pf anchor was flushed by something else on the Mac | `protected` |
| the NetworkExtension provider died and the configuration remains | `protected` |

So the observation moves **off the device**. `twinoracle` runs somewhere the
device under test can reach only by emitting a packet that actually left it, and
it records what arrived, from which address, on which family, and when.
"External" here means external to the device under test, which is the whole of
the claim — it need not be a different machine (§3.1).

> **"Zero unauthorized egress" is a statement made by a third party, or it is not
> a statement at all.**

---

## 2. The one failure this design is shaped around

**Zero observations because the kill switch worked, and zero observations
because the oracle was unreachable, are the same bytes.**

Every other decision follows from that. A session must prove the oracle could
hear the device *before* its silence means anything, so:

* every sequence begins with an `OBSERVE` phase on all three families — the
  **positive control**;
* a family never observed in any `OBSERVE` phase makes the session
  `INCONCLUSIVE`, whatever the `SILENCE` phases show;
* `INCONCLUSIVE` is **not a pass**, and `build/acceptance/report.py` counts it
  against Phase 5 eligibility exactly as a failure;
* `build/ci/leak-probe.sh` refuses a beacon target on loopback or link-local, on
  **both** families, and refuses any address the probe host itself owns, because
  egress to the machine you are testing is not egress. A non-global target is
  accepted only under `TWINVPN_ORACLE_TOPOLOGY=in-box` (§3.1).

`tests/verdict.rs` is where each of those is a runnable check.

---

## 3. Deployment

Two shapes. **In-box (§3.1) is what the acceptance gate uses as of 2026-09-02**;
the public deployment (§3.2) is the alternative and is what the flag reference
below describes.

The binary builds on Windows as well as Linux: `random_id` uses `getrandom`
rather than opening `/dev/urandom`, so an oracle can run on the same Windows
runner that drives a nested guest. Windows also defaults `IPV6_V6ONLY` to on, so
the listener split §3.3 depends on is satisfied there without a sysctl.

### 3.1 In-box deployment on one runner

The oracle, the sentinel and the DNS forwarders run on the runner that drives
the device under test, on address space that runner creates for the run. There
is no cloud instance, no public address and no delegated zone. **Independence is
then structural rather than asserted:** `is_dut_sourced` compares source
addresses for exact membership, so a fabric with **no NAT anywhere between the
device and the observer** satisfies it by construction.

Four rules, and each of them is load-bearing:

* **Listeners go on a second, ROUTED segment** that the device reaches only
  through its default route. **Never on-link with the device.** A correct kill
  switch permits the device's own link by design — the local-network class is
  ALLOW in every routing mode — so an on-link oracle is permitted *correctly*
  and the SILENCE phase then fails for a reason that is not a leak.
* **The sentinel beats from a second host identity on that segment**, disjoint
  from every address the device presents. It no longer needs a separate machine.
* **A stateless per-leg DNS forwarder replaces the delegated zone** — one for
  the unprotected leg and one for the protected leg, each named in
  `--resolver <ip>=<id>:<p|u>`, with the device's `nameserver` rewritten when
  the tunnel comes up. **No forwarder may retry, cache or health-check:** one
  that retransmits on its own manufactures a DNS arrival during a SILENCE phase,
  which this process records as a leak and the acceptance report turns into a
  FAIL against the product.
* **The control plane is driven by the controller, never by the device.** A
  correct kill switch blocks the device's control POSTs during the armed window,
  and dropped attempt increments push the session under `attempt_minimums` —
  INCONCLUSIVE for the opposite of the real reason. Exempt only the control
  address from the kill switch; never a beacon address.

Four address ranges the listeners and the sentinel must avoid, because a correct
product permits or denies them for reasons that have nothing to do with the
criterion: **link-local** (`169.254.0.0/16`, `fe80::/10`), **anything on-link
with the device**, **`100.64.0.0/10`** and **`fd7c:9e5d:2a10::/48`** — the last
two being the Tier-1 baseline deny floor, blocked in both postures, so a beacon
there could never arrive even through a working tunnel.

The session's evidence records which shape produced it. `oracle_topology` is
`in-box` or `external`, and `sentinel_egress_identity` is the measured identity
the sentinel presented, which the acceptance adjudicator requires to differ from
both path identities. `sentinel_host` stays what it has always been: free text,
echoed for a human, gated by nothing (§4.2).

### 3.2 Public deployment — the alternative

One small instance with **a public IPv4 address, a public IPv6 address**, and
the beacon zone delegated to it.

```bash
cd lab && cargo build --release -p twinoracle

sudo install -m 0700 -d /etc/twinoracle
head -c 32 /dev/urandom | base64 | sudo tee /etc/twinoracle/token   # >= 32 chars

sudo twinoracle serve \
  --control 10.0.0.5:8443 \
  --control-token-file /etc/twinoracle/token \
  --http4 0.0.0.0:80 --http6 '[::]:80' \
  --dns4  0.0.0.0:53 --dns6  '[::]:53' \
  --zone leak.oracle.twinvpn.example \
  --advertise-v4 198.51.100.7 --advertise-v6 2001:db8::7 \
  --sentinel-max-gap-ms 15000 \
  --resolver 198.51.100.53=isp-recursive:u \
  --resolver 2001:db8::53=twinvpn-dns:p \
  --sentinel-token-file /etc/twinoracle/sentinel-token   # optional, see 4.2
```

`--sentinel-max-gap-ms` and `--resolver` are **deployment** configuration, not
probe configuration. The sentinel's cadence and the resolver topology are facts
about this installation; the device under test is the last party that should be
describing either, and the probe should not be inventing the resolution at which
liveness is claimed. A session may override both, and neither has to be sent.

`--sentinel-max-gap-ms` is required: there is no way to start an oracle that has
not declared one. `--resolver` is not, and an empty map is the fail-closed
default — every DNS arrival is then unattributable, which sets
`dns_resolver_identity_ambiguous` and makes sessions `INCONCLUSIVE`. An
unconfigured map must never read as a clean one.

Four listeners, and the split is not cosmetic:

| Listener | Why it is its own socket |
|---|---|
| `--http4` / `--http6` | the family of an observation is a property of the socket that accepted it, never of anything the client claimed |
| `--dns4` / `--dns6` | the beacon zone, answered authoritatively with TTL 0 so a cached answer cannot stop the next beacon leaving |
| `--control` | bind it to a **management address**. Nothing on the data plane can reach it, so a device that leaks cannot also rewrite the record of its leak |

### 3.3 Two things the host must be configured for

* **`net.ipv6.bindv6only=1`**, on Linux. A dual-stack socket accepts IPv4
  connections and reports them as `::ffff:a.b.c.d`, which would make the family
  of the observation a guess. The process also normalises v4-mapped peers and
  records them as IPv4 — belt to that braces — but the socket option is the fix.
  Windows defaults `IPV6_V6ONLY` to on, so there it needs nothing.
* **The zone must be delegated**, in the §3.2 deployment only.
  `leak.oracle.twinvpn.example. NS <this host>` in the parent zone. Without
  delegation the DNS beacons never arrive, every session is `INCONCLUSIVE` for
  `dns`, and no criterion that makes a DNS claim can pass — which is the correct
  outcome, loudly. In-box, the per-leg forwarders take this role: the device
  resolves through them, and they are what the `--resolver` map names.

### 3.4 What the source address means, per family

IPv4 and IPv6 beacons arrive **from the device**, so their source addresses
carry the `sources_disjoint_from` / `sources_subset_of` constraints — the ones
that prove traffic really entered the tunnel and really resumed inside it.

A DNS beacon goes through the device's own resolver, which is the egress path
users actually leak through — so it arrives **from the recursive resolver**, not
from the device. Its address says nothing about whether the device was inside
the tunnel, so `lib.rs` keeps DNS out of the source sets and uses it only for
presence and absence, which is what the criterion is about.

---

## 4. The session protocol

```text
POST /v1/sessions                    {commit, run_id, run_attempt, platform,
                                      criterion}
     -> {session_id, probe_token, beacon_v4, beacon_v6, dns_suffix, zone,
         min_attempts}
     optional overrides: sentinel_max_gap_ms, required_families,
                         attempt_minimums, resolver_map
POST /v1/sessions/{id}/phase         {phase, expectation, require_families,
                                      sources_disjoint_from, sources_subset_of,
                                      path}
POST /v1/sessions/{id}/attempts      {ipv4, ipv6, dns}   -- an INCREMENT
POST /v1/sessions/{id}/sentinel      {host}              -- sentinel operator only
     -> {sentinel_token, sentinel_beacon_v4, sentinel_beacon_v6, sentinel_zone}
POST /v1/sessions/{id}/close
GET  /v1/sessions/{id}/report
```

All six need `Authorization: Bearer <control token>`. The data plane needs
nothing — arriving **is** the observation.

`path` on a phase takes `"p"`/`"u"` as well as `"protected"`/`"unprotected"`,
plus `"n"` for NO CLAIM, and may be spelled `path_tag` — so a probe uses ONE
vocabulary, the same letters it puts in DNS query names. `"n"` and `null` mean
the same thing and are both distinguishable from `"p"` and `"u"`. Anything else
is refused with a 400 rather than defaulting to no-claim: a typo'd tag that
silently became null is a phase that quietly stops contributing to path
identity.

Beacon names carry four tag letters: `p`, `u`, `n`, and `s` for a sentinel
beacon (`<seq>.<sentinel_token>.s.<zone>`). `n` and `s` name no path but are
still consumed — leave one in place and it becomes the token, the beacon matches
no session, and the family reports zero arrivals, which is what a working kill
switch also reports.

`/attempts` is an **increment**, added to a running whole-session total, because
the probe posts at the end of each beacon burst and carries no state between
invocations. A post that fails is dropped, which makes the total too LOW, and
that is the safe direction: a low count is `INCONCLUSIVE`, and inconclusive is
what a half-run probe has earned. A retried post double-counting is not a hole
either — the count can only ever *gate*, never establish silence, so a device
that wanted a large number could simply send one.

**The open response deliberately carries no sentinel token.** The device under
test must never hold the credential whose beats are read as proof the oracle was
listening; `/sentinel` is where that token lives, and only the sentinel operator
calls it.

A new phase closes the previous one, so there is no gap between the tunnel dying
and the armed window opening for a packet to fall into and be excused. A closed
session stops resolving its probe token, so a probe still beaconing after the
run cannot append to a finished record.

### 4.1 The ten-step kill-switch sequence, as phases

| Step | Phase | Expectation | Constraint |
|---|---|---|---|
| 1 baseline unprotected egress | `BASELINE` | `OBSERVE` | all three families |
| 2–3 connect, confirm tunnel egress | `TUNNELLED` | `OBSERVE` | `sources_disjoint_from: BASELINE` |
| 4–7 arm, terminate, attempt egress | `ARMED` | `SILENCE` | zero, on every family |
| 8–9 restore, verify | `RESTORED` | `OBSERVE` | `sources_subset_of: TUNNELLED` |

`build/ci/leak-probe.sh` is the device-side driver; step 10 (destroying the
disposable guest) belongs to the controller, not to the oracle.

### 4.2 The sentinel — proving the oracle was still listening

A positive control in `BASELINE` establishes the oracle was reachable at **one
moment**, before the armed window opens. It says nothing about the window
itself. The concrete failure it misses: the IPv6 accept loop dies ten seconds
into `ARMED` — the task panicked, the host ran out of file descriptors, an
operator restarted the process, a security group changed under it. The session
then records zero IPv6 arrivals during the armed window, which is byte-for-byte
what a perfect kill switch records.

So a **sentinel** runs alongside: an independent heartbeat source that is *not*
the DUT and does *not* traverse the DUT's network, beating at the same three
data-plane listeners on a cadence.

* It carries `sentinel_token`, **distinct from `probe_token` by construction**.
  If one token served both, every heartbeat proving the oracle was alive during
  the armed window would also be recorded as a leak — the liveness check would
  manufacture the failure it exists to rule out.
* **Independence is checked, not assumed.** A beat whose source address is one
  the *device* was observed egressing from is not independent evidence: either
  the device emitted it, or the sentinel shares the device's egress path. Such a
  beat is excluded from the continuity arithmetic and named in `inconclusive` —
  `INCONCLUSIVE`, not `FAIL`, because a sentinel behind the same NAT as the
  device presents the device's public address too, and the product must not be
  accused of a defect on the strength of a network layout. `INCONCLUSIVE` blocks
  the gate exactly as a failure does, so nothing ships on the back of it either.
  Only IPv4 and IPv6 are checked this way — a DNS beat arrives from a resolver
  whether the sentinel or the device sent it, so its address cannot separate the
  two.
* Where it runs is the whole claim, and the oracle cannot verify it. Pass
  `{"host": "..."}` to `/sentinel` and it is echoed into the report as
  `sentinel_host`, to be read by a human rather than trusted by a check. The
  checkable form of that claim lives outside this process: the lane measures the
  identity its sentinel presented into `sentinel_egress_identity`, and the
  acceptance adjudicator refuses one equal to either path identity.
* **Per-session or standing.** By default each session mints its own token. A
  standing sentinel run against `--sentinel-token-file` has its beats recorded
  in every **open** session, because "the listeners were alive" is a fact about
  the oracle rather than about any one run. That mode was introduced for
  criteria where no host in the CI job looked independent of the device; under
  the §3.1 topology the lane's own runner *is* independent by address, so the
  per-session token is the ordinary choice again.
* Continuity for family `F` over a SILENCE phase `[t0, t1]` holds iff every
  consecutive gap in `{t0} ∪ beats(F) ∪ {t1}` is `<= sentinel_max_gap_ms`.
  Anchoring at **both** ends is what catches an oracle that died at the start of
  the window (beats begin late) and one that died and never came back (beats
  stop early); checking only the gaps *between* beats would miss both.
* **Zero beats is not continuity**, and a session with no sentinel section at
  all reports `false`, never `true`. Missing evidence is not absence of gaps.
* A discontinuous sentinel for a family the criterion claims makes the session
  `INCONCLUSIVE` — never `PASS`, and never `FAIL`. A broken rig is not a
  product defect.

`*_attempts` is the mirror of this on the device's side: whole-session probe
counts the DUT reports over `/attempts`. It is self-reported, and it is used in
exactly one direction — below `attempt_minimums` makes the session
`INCONCLUSIVE`. It can never make one pass, which is why a device inflating it
gains nothing. A window nothing was sent into is silent for the wrong reason.

### 4.3 Path identity — the two paths must be distinguishable

If the protected and the unprotected leg both egress from the same address, or
both resolve through the same resolver, then "traffic moved into the tunnel" was
never observable and a silent window does not say *which* path was silent.

* IPv4/IPv6: a phase declares `path: "protected" | "unprotected"`, and the
  oracle collects the source addresses that actually **arrived** during each.
  Overlap between the two sets, or an empty set on either side, is
  `*_identity_distinct: false` and `INCONCLUSIVE`.
* DNS: the probe encodes its intent in the query name as
  `<seq>.<probe_token>.<path_tag>.<zone>`, `path_tag` being `p` or `u`. That is
  evidence of **intent only**. The oracle derives the real `resolver_id` from
  the address the query **arrived from**, via the operator-configured
  `resolver_map` — never from the tag, and never from an authoritative server
  claiming to have seen an original client IP. Both of those are the defendant
  testifying.
* Tag and derived identity disagreeing during `SILENCE` is a leak through the
  wrong resolver: `FAIL`. An arrival from a resolver in no map entry sets
  `dns_resolver_identity_ambiguous` and is `INCONCLUSIVE` — guessing is how a
  leak through the wrong path gets recorded as clean.

### 4.4 Verdict precedence

```text
any forbidden arrival during SILENCE                      -> FAIL
else any of { sentinel discontinuous for a claimed family,
              attempts below the minimum,
              dns_resolver_identity_ambiguous,
              *_identity_distinct == false,
              a failed positive control }                 -> INCONCLUSIVE
else                                                      -> PASS
```

`FAIL` outranks `INCONCLUSIVE` deliberately. A run that both leaked *and* lost
its sentinel is a `FAIL`: "the measurement was flawed" must never launder an
observed packet into a softer verdict, because the packet arrived either way.

`*_identity_distinct` is `null` for a family the criterion makes no claim about.
**`null` is not `true`** — it says "this session makes no IPv6 claim", not "IPv6
was checked and was fine". `build/acceptance/report.py` must not read one as the
other.

---

## 5. Why there is no signature on the report

A signature would be produced with a key the reporting side also holds, which
proves nothing about a CI job that lies.

The integrity property comes from somewhere else and is stronger: the acceptance
job fetches the report **from this process**, over the control API, keyed by a
session id that the platform evidence recorded — rather than believing a file
the platform job uploaded. `report.py` then re-checks that the session was
opened for the same commit, the same criterion, and returned `PASS`, and it
names any disagreement between the oracle and the job's own claim.

See `build/acceptance/report.py`'s `check_oracle`, and
`build/acceptance/test_report_prerequisites.py` for the cases that prove a
lying job cannot get a green row.

---

## 6. Why there is no HTTP framework and no DNS library

The data plane answers exactly two shapes — one HTTP request line and one DNS
question — and needs the **peer address** and the **listener's family** more
than it needs routing, middleware or a resolver. A framework here would be more
code to trust inside the one process whose entire value is that a reader
believes what it recorded.

The parsers are deliberately hostile-input-shaped: the DNS parser refuses a
compression pointer in a QNAME rather than following it, drops anything
malformed, and is tested against truncated packets. In the §3.2 deployment this
socket is reachable from the internet and will be scanned; in the §3.1 one it is
reachable by a device whose whole purpose in the run is to try to reach it.
