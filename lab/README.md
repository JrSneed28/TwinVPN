# TwinLab — the reproducible network laboratory

**Owner:** `test-engineering`. **Never shipped** ([ADR-0018](../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12).

TwinLab is the rig on which every claim in [`docs/networking.md`](../docs/networking.md),
[`docs/reliability.md`](../docs/reliability.md), ADR-0004, ADR-0005, ADR-0006 and
ADR-0012 is made falsifiable. [`docs/testing-strategy.md`](../docs/testing-strategy.md)
§3 is its specification.

---

## 1. The one rule

> **§3.1 (normative).** Every condition TwinLab reproduces MUST be produced by a
> *mechanism with the same observable semantics as the real thing*, never by a
> flag inside TwinVPN. A test MUST NOT be able to detect that it is running in
> TwinLab by inspecting the product's own configuration.

The consequence that shapes every type in `twinlab`: **a facility this host does
not provide yields `Verdict::Unavailable`, never a pass.** `Verdict` has four
values — `Pass`, `Fail`, `Unavailable`, `Void` — and only `Pass` answers `true`
to `is_evidence_of_success()`. Collapsing `Unavailable` into `Pass` would turn
"we have no nftables" into "symmetric NAT traversal works", which is the single
way a network laboratory can be worse than none.

There is no simulated backend, no `lab_mode`, and no switch inside TwinVPN that
TwinLab sets. The absence is the point.

---

## 2. What this host can actually produce

Run the probe. It executes real commands; it does not read a table.

```bash
cd lab && cargo run -q -p twinlab-scenarios -- capabilities
```

On the WSL2 host this domain was built on:

| Facility | Status | Evidence |
|---|---|---|
| `network-namespaces` | **available** | `unshare --user --net --map-root-user` succeeds |
| `veth` | **available** | probed inside an unprivileged user+net namespace |
| `bridge` | **available** | probed inside an unprivileged user+net namespace |
| `netem` | **available** | `tc qdisc add … netem delay` succeeds |
| `shaping` | **available** | `tc qdisc add … tbf` succeeds |
| `ipv6` | **available** | v6 addressing and `net.ipv6.conf.all.forwarding` inside a namespace |
| `nftables` | unavailable | `nft` is not installed |
| `conntrack` | unavailable | `conntrack` is not installed |
| `ebpf-tc-classifier` | unavailable | `bpftool` is not installed |
| `containers` | unavailable | neither `docker` nor `podman` on `PATH` |

**What that means, plainly.** Real namespaces, real `veth`, real bridges, real
`netem`, real IPv4 **and** IPv6 forwarding all work here — verified by actually
creating a two-namespace topology and passing ICMP and ICMPv6 across it. What
does **not** work is every §3.3 NAT personality except `N-ROUTED`, because each
one is realized by an `nftables` `nat` chain and `conntrack` state, and neither
userspace exists on this host. `LinuxNamespaceBackend::realization()` reports a
third fact: `ip netns add` needs `CAP_NET_ADMIN` in the initial user namespace,
so the **named** namespace table is unavailable here even though namespaces
themselves are not.

No NAT-class result in this repository was produced by a NAT. The
`twinlab-scenarios plan` verdict for every such scenario is `Unavailable`, and
that is the honest state.

---

## 3. Layout

| Crate | What it is |
|---|---|
| `twinlab` | the laboratory: capability probe, topology, NAT personalities, impairment, determinism, seeding, conformance, verdicts, run record |
| `twinlab-scenarios` | the named scenario family and the NAT class-pair matrix, plus the CLI |

### `twinlab` modules

| Module | § | What it holds |
|---|---|---|
| `capability` | §3.1, §3.2 | what this host can realize, **probed** |
| `exec` | §3.1 | the only place a real `ip`/`tc`/`nft` process is spawned |
| `addressing` | §3.2 | the address plan, and the contradiction inside §3.2's realism rule (§6) |
| `topology` | §3.2 | namespaces, `veth`, bridges, lifecycle |
| `nat` | §3.3 | the personalities, their real `nft` rulesets, and the class-pair matrix **parsed from `docs/networking.md` §3.2** |
| `impair` | §3.4, §3.5 | the impairment matrix and the seeded drop schedule |
| `determinism` | §3.5 | the three classes and rule **L-2** made mechanical |
| `seed` | §3.5, CD-4 | the HKDF binding TwinLab owns (finding **W-1**) |
| `conformance` | §3.4.2 | control **V10**, and why nothing here is conformant yet |
| `outcome` | §2.10 | the expected classes, and a verdict with four values |
| `record` | §3.6 | the run record, and what it honestly does not carry |

---

## 4. Running it

```bash
source build/toolchain/env.sh
cd lab

cargo test --workspace                      # 106 tests, ~4 s

cargo run -q -p twinlab-scenarios -- capabilities   # probe this host
cargo run -q -p twinlab-scenarios -- matrix         # the class-pair matrix
cargo run -q -p twinlab-scenarios -- list           # 171 scenarios
cargo run -q -p twinlab-scenarios -- list --family KS
cargo run -q -p twinlab-scenarios -- show S-KS-FAIL-CLOSED-V6-02   # §3.6's document
cargo run -q -p twinlab-scenarios -- plan S-KS-FAIL-CLOSED-V6-02   # what it needs, and whether this host has it
```

There is **no `run` subcommand**. On a host that cannot create a named network
namespace there is nothing to run, and a `run` that printed a green line would
be exactly the lie §3.1 exists to prevent. `plan` is the honest half: it names
every facility a scenario needs and says which of them this host lacks.

### Cost per tier

`Tier` refers to `docs/testing-strategy.md` §6.1. These are the costs of the
parts that exist today, measured on this host — not the budgets §6.1 sets.

| Tier | What of TwinLab runs | Measured cost here |
|---|---|---|
| **T1** | `cargo test --workspace` in `lab/` — the laboratory's own logic, the CD-4 end-to-end vectors, the scenario catalogue's invariants | **≈ 4 s** wall clock, no privilege, no network |
| **T2** | the `DIRECT_EXPECTED` and `RELAY_EXPECTED` scenario classes at 5 runs each | **not runnable on this host** — every one needs `nftables` |
| **T3** | the full class-pair matrix at §3.6's run counts (20–50 runs per pair × 147 v4 pairs) | not runnable here; the arithmetic alone is ≈ 4 400 scenario runs |
| **T4** | the soak and performance families | not implemented — no `S-SOAK-*` or `S-PERF-*` scenario exists yet |

---

## 5. Determinism, per scenario family (CD-6's residual)

ADR-0018 **CD-6** and §3.5 both say the same thing and it is stated here rather
than hidden: injected clocks give the **core's event sequence** `BIT`
determinism, and give nothing at all to a duration, because `conntrack` timers,
`netem` and the kernel scheduler are outside every injected provider.

| Family | Class | Why |
|---|---|---|
| `S-NAT-*` | `STATISTICAL` | `conntrack` allocation and mapping lifetime are kernel timers |
| `S-NET-*` | `STATISTICAL` | `netem` and PMTU discovery are kernel-timed |
| `S-RELAY-*` | `STATISTICAL` | the failover budget is a wall-clock measurement against a real socket |
| `S-KS-*` | `BIT` | the enforcement decision is entirely in the core against injected clocks and a mock adapter (CD-5); the observation is a deny-counter comparison, not a duration |
| `S-COLL-*` | `BIT` | pre-flight detection compares two captured host states |
| `S-CP-*` | `BIT` | §9's three-way split is a `Guards` input; the response is an event sequence |

`BIT` here means exactly what §3.5 says it means above level 2: the **ordered
event sequence and the `reason_code` sequence**, never the timing. No scenario in
the catalogue asserts a duration, and `Class::permits` refuses one — for every
class, including `BIT`.

`ImpairmentSet::check_class` enforces the other half: a scenario that declares
`BIT` while carrying `netem jitter` is refused at construction, because §3.5's
"review failure" should not be discoverable only as flake three months later.

---

## 6. Findings this laboratory raised

**§3.2's address-realism rule is unsatisfiable as literally written.** It
requires RFC 6598 `100.64.0.0/10` for the carrier-NAT tier *and* forbids reusing
the `TwinNet` overlay prefixes for underlay addressing — and
`docs/networking.md` §2.1 makes the TwinNet IPv4 overlay prefix `100.64.0.0/10`.
Every CGNAT scenario therefore violates one sentence or the other.

`addressing.rs` implements the rule as its **purpose** rather than its letter,
and says so at the definition: the overlay is allocated in control-plane `/22`
blocks, not the whole `/10`, so the lab carves `100.64.0.0/12` for the overlay
and `100.80.0.0/12` for the carrier tier and enforces *disjointness against the
allocation in force*. `S-COLL-*` opts out explicitly, because reproducing that
exact collision is its entire purpose. **This needs the integration lead's
ruling**; it is not a decision this domain is entitled to make alone.

**Nothing has passed §3.4.2's conformance suite.** Rule **L-1** says no
traversal, leak or relay test may run against a personality that has not passed
its conformance suite in the same lab instantiation. §3.4.2 requires an
independent RFC 5780-style prober that is **not TwinVPN code**; none is bound,
`ConformanceSuite::nat_personality` returns `Unavailable` for every personality,
and L-1 therefore forbids running a traversal test against any of them. That is
the correct state, not a gap to work around.
