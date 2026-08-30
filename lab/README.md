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

It prints **two** reports, and the difference between them is the whole of §2.

| Facility | From this process | Inside the `twinnet` sandbox |
|---|---|---|
| `network-namespaces` | available | **available**, and *named* ones too |
| `veth`, `bridge`, `netem`, `shaping`, `ipv6` | available | available |
| `af-packet` | not probed | **available** |
| `userspace-nat` | not probed | **available** |
| `tun` (a real tunnel device) | not probed | **available** |
| `nftables` | unavailable — `nft` is not installed | unavailable |
| `conntrack` | unavailable — `conntrack` is not installed | unavailable |
| `ebpf-tc-classifier` | unavailable — `bpftool` is not installed | unavailable |
| `containers` | unavailable — neither `docker` nor `podman` | unavailable |

**What changed, and what did not.** This document used to end §2 with a sentence
that was true when it was written:

> No NAT-class result in this repository was produced by a NAT. The
> `twinlab-scenarios plan` verdict for every such scenario is `Unavailable`, and
> that is the honest state.

It is no longer the state, and the reason is not that the rule was relaxed. Two
obstacles were removed and one was not:

1. **`ip netns add` needs `CAP_NET_ADMIN` in the initial user namespace.** It
   does not need it in a namespace you own. `twinnet`'s agent unshares
   `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET` at `main`, holds the full
   capability set inside, and mounts a private `tmpfs` over `/run` so `ip netns`
   has somewhere to bind. Named namespaces exist here now, unprivileged.
2. **Every §3.3 personality was realized by `nftables` and `conntrack`.** That is
   *a* realization. §3.1 constrains the **observable semantics**, not the kernel
   subsystem: `twinnet::nat` is a real middlebox process on the path, holding a
   real RFC 4787 mapping table with real filtering behaviour and real timers,
   forwarding real frames between two real `veth`s. `twinlab::nat::Realization`
   names which one produced a result, and a run record carries it.
3. **`N-NAT64` needed a third realization, and now has one.** §3.3 realizes it
   with a `jool`-class stateful NAT64 and there is none here.
   `twinnet::nat::xlat` is RFC 6052 addressing and RFC 7915 header translation
   inside the middlebox that is already in the path, and §3.4.2's NAT64 row —
   a v4-literal reachable from a v6-only client through the synthesized prefix,
   and `PREF64`-off forcing the RFC 7050 path — now passes. What is **not**
   realized is named rather than left out: RFC 8781 PREF64 in Router
   Advertisements, which needs an RA daemon.
4. **A facility this host does not have is still `Unavailable`.**
   `nftables`-specific scenarios still need `nft`; a `BIT`-deterministic loss
   schedule still needs an eBPF classifier; this kernel's `netem reorder` is
   near-inert. Those report `UNAVAILABLE` with the evidence, and never a pass.
   The set of producible conditions grew. The rule about the rest did not move.

**And the personalities are checked, not asserted.** §3.4.2 requires an
independent RFC 5780-style prober that is *not TwinVPN code* before rule **L-1**
lets a traversal test run at all. There is one — `twinnet::prober`, which imports
nothing from `core/` or `services/` and does not know what a `Candidate` is:

```
$ cargo run -q -p twinlab-scenarios -- conformance
  N-ROUTED           PASS         mapping None, filtering EndpointIndependent
  N-EIM-EIF          PASS         mapping EndpointIndependent, filtering EndpointIndependent
  N-EIM-ADF          PASS         mapping EndpointIndependent, filtering AddressDependent
  N-EIM-APDF         PASS         mapping EndpointIndependent, filtering AddressPortDependent
  N-APDM-APDF-RAND   PASS         mapping AddressPortDependent, filtering AddressPortDependent
  N-APDM-APDF-SEQ    PASS         mapping AddressPortDependent, filtering AddressPortDependent
  N-CGNAT            PASS         mapping AddressPortDependent, filtering AddressPortDependent
  N-NAT64            PASS         synthesized AAAA reachable; PREF64-off correctly fails;
                                  RFC 7050 fallback reachable; negative control unreachable;
                                  NOT COVERED: RFC 8781 PREF64 in Router Advertisements

  8 of 8 personalities passed §3.4.2's conformance suite.
  Rule L-1 permits a traversal, leak or relay test against any of them.
```

## 3. Layout

| Crate | What it is |
|---|---|
| `twinlab` | the laboratory: capability probe, topology, NAT personalities, impairment, determinism, seeding, conformance, verdicts, run record |
| `twinlab-scenarios` | the named scenario family and the NAT class-pair matrix, plus the CLI |
| `twinnet` | **the fabric**: the sandbox, real topologies, the userspace middleboxes, impairment, the packet observer, the §3.4.2 prober, and the traffic that makes any of it do work |
| `twinsim` | the **peers**: simulated devices and gateways, and the L-CONTROL binding |
| `twinoracle` | **the external leak oracle**: the off-device observer that decides whether a platform kill-switch criterion holds. It is the only member deployed OUTSIDE this repository's runners, and that is the point — see below |

### `twinnet`, and why it is a separate crate

`twinlab` decides what a scenario *means* and what a verdict *is*, and it is
`#![forbid(unsafe_code)]` — a crate that decides verdicts should be readable in
one sitting. `twinnet` is the half that moves packets, and it owns the only
`unsafe` in `/lab/`: two files, `afpacket.rs` (raw sockets) and `agent::enter`
(`unshare` and `mount`), each a short list of libc calls with stack-allocated
arguments and no pointer arithmetic.

| Module | What it is |
|---|---|
| `agent`, `sandbox`, `proto` | the privileged half: one single-threaded process that unshares at `main` and then takes orders on a pipe. Namespaces outlive individual commands, which is what makes a scenario a sequence of steps |
| `fabric` | namespaces, `veth`, bridges, dual-stack addressing, **static neighbours** (so no scenario's first packet waits on ARP), `netem`/`tbf` impairment, MTU, link up/down |
| `nat` | §3.3's personalities as a real middlebox: an RFC 4787 mapping table with the mapping and filtering axes configured **independently**, seeded port allocation, real lifetimes, hairpinning, an egress policy, and a per-subscriber port budget that makes CGNAT exhaustion reachable |
| `ip`, `rewrite` | the packet parser and the in-place translator, including every checksum a rewrite invalidates |
| `observer` | rule **PT-2**'s wire oracle: `AF_PACKET` capture, and a `LeakPolicy` that names each escape and why |
| `prober`, `traffic` | §3.4.2's RFC 5780-style behaviour prober and the two-address, two-port reflector it measures against — neither of which imports anything from `core/` or `services/` |
| `relay` | a forwarder two peers behind symmetric NATs can both reach, and a peer that fails over between forwarders |
| `tun` | a real TUN device and the smallest real tunnel that can carry protected traffic off an interface |
| `rigs` | the three prebuilt topologies, in the library rather than in a test helper so that `run` builds the same experiment a test does |

**What `twinnet` is not.** It is not `twinvpn-relay`, `twinvpn-rendezvous` or
`twinvpn-tunnel`. Its relay carries no `RelayCapabilityToken`; its tunnel is a
real encapsulation and not a real cryptographic one, so nothing built on it may
claim a payload was unreadable. Those claims belong to `twinsim`, which drives
the real binaries, and to `tests/`, which links the real crates.

### `twinoracle`, and why it does not run beside the test

Every other member here runs on the same host as the thing it measures.
`twinoracle` must not, and the §3.1 realization principle is the reason: a
kill-switch criterion cannot be produced by a mechanism the system under test
can see, and it cannot be *graded* by one either.

A platform's own status API says `protected` when the filter set was never
installed, when the firewall anchor was flushed by something else, and when the
NetworkExtension provider died — three separate ways for a device to be leaking
while reporting that it is not. So the observation moves off the device
entirely: `twinoracle` runs on a public instance the device can reach only by
emitting a packet that actually left it, and it records what arrived, from
which address, on which family, and when.

The verdict logic's whole shape comes from one fact: **zero observations because
the kill switch worked and zero observations because the oracle was unreachable
are the same bytes.** So a session that never proved the oracle could hear it is
`Inconclusive`, never `Pass` — which is `Verdict::Unavailable`'s discipline from
§1, arriving in a different crate for the same reason.

`lab/twinoracle/README.md` has the deployment and the session protocol;
`build/ci/leak-probe.sh` is the device-side driver;
`build/acceptance/report.py` fetches the verdict from the oracle rather than
from the job under test.

### `twinsim`, and the one thing it proves that `twinlab` cannot

`twinlab` reproduces network *conditions*. It has no traffic of its own — a
namespace with a NAT in it and nothing crossing it is a laboratory with no
experiment. `twinsim` is the experiment: a real relay peer, driving the real
`twinvpn-relay` binary over a real socket.

| Piece | What runs |
|---|---|
| the token | a real COSE_Sign1, signed by a per-machine development issuer |
| the leg | a real `Noise_IK` handshake against the relay's real static key |
| `K_leg` | derived at both ends independently; nothing is copied across |
| every frame MAC | real keyed BLAKE2s under the derived `K_leg` |
| the transport | a real `tokio::net::UdpSocket`, IPv4 **and** IPv6 |

**`twinsim::wire` is a second implementation of the C6 encodings, deliberately.**
`services/relay/tests/common/mod.rs` says what its own harness costs: it
re-derives the wire from the relay's public constants, "which means these tests
assert *self-consistency*, not interoperability", and records interoperability
as a separate unmet obligation. `twinsim` reads ADR-0005 §9.1 and the frozen
contract instead, so when the two agree that is evidence. Importing
`twinvpn_relay::control` would delete the evidence and leave the code looking
identical. The one exception is cryptography: CD-I2 forbids a second
implementation, so `Noise_IK`, the frame MAC, HKDF and COSE all come from
`twinvpn-crypto`.

**It found a defect the relay's own tests could not.** The running relay passed
its packet path a monotonic offset from process start where a token's
`nbf`/`exp` needed a wall clock, so it refused every legitimate token —
silently, because §11.5 makes that a zero-byte drop. The in-crate harness
injects `|| NOW_MS`, a wall-clock constant, and therefore never exercised the
clock the binary runs with. See `services/relay/src/main.rs`.

### The L-CONTROL binding

`twinsim` also carries `lcontrol.rs`, the rung-1 client ADR-0002 §11.2 describes
and nothing in `core/` implements — `twinvpn-cp-client`'s `ControlTransport` is
a trait because CB-1 puts the socket at the platform seam, so a *binding* has to
come from somewhere and for the lab it comes from here.

With it, a simulated device completes a real attach against the real
`twinvpn-control-plane` binary: QUIC + TLS 1.3, mutual RFC 7250 raw public keys,
the RFC 9266 `tls-exporter` channel binding read off the live connection, and a
real C1 round trip. Verified on both address families, with the server key
learned and pinned, and with a wrong pin refused.

It is **not** the product's composition root: that belongs on the platform seam,
per target, under CB-1. `infra/README.md` §9a says what else it deliberately is
not.

Run it with `make plane-up` / `make plane-probe` / `make plane-ceremony`;
`infra/README.md` §9a has the whole picture, including why the development
issuer exists and why the relay map it writes is unsigned.

### `twinlab` modules

| Module | § | What it holds |
|---|---|---|
| `capability` | §3.1, §3.2 | what this host can realize, **probed** |
| `exec` | §3.1 | the only place a real `ip`/`tc`/`nft` process is spawned |
| `addressing` | §3.2 | the address plan, and the contradiction inside §3.2's realism rule (§6) |
| `topology` | §3.2 | namespaces, `veth`, bridges, lifecycle |
| `nat` | §3.3 | the personalities, their real `nft` rulesets, the `Realization` axis, and the class-pair matrix **parsed from `docs/networking.md` §3.2** |
| `impair` | §3.4, §3.5 | the impairment matrix and the seeded drop schedule |
| `determinism` | §3.5 | the three classes and rule **L-2** made mechanical |
| `seed` | §3.5, CD-4 | the HKDF binding TwinLab owns (finding **W-1**) |
| `conformance` | §3.4.2 | control **V10**; the suite itself now runs, in `twinlab-scenarios::runner` |
| `outcome` | §2.10 | the expected classes, and a verdict with four values |
| `record` | §3.6 | the run record, and what it honestly does not carry |

---
## 4. Running it

```bash
source build/toolchain/env.sh
cd lab

cargo test --workspace                      # the laboratory's own logic and the fabric

cargo run -q -p twinlab-scenarios -- capabilities   # probe this host, twice
cargo run -q -p twinlab-scenarios -- conformance    # §3.4.2, and the L-1 gate
cargo run -q -p twinlab-scenarios -- matrix         # the class-pair matrix
cargo run -q -p twinlab-scenarios -- list           # 171 scenarios
cargo run -q -p twinlab-scenarios -- show S-KS-FAIL-CLOSED-V6-02   # §3.6's document
cargo run -q -p twinlab-scenarios -- plan S-KS-FAIL-CLOSED-V6-02   # what it needs
cargo run -q -p twinlab-scenarios -- run  S-NAT-ROUTED-ROUTED-V4-01
```

### `run`, and the five answers it can give

There **is** a `run` subcommand now. The sentence it replaces — *"a `run` that
printed a green line would be exactly the lie §3.1 exists to prevent"* — is still
the design constraint, so `run` has five outcomes and prints five different
words. Only one of them is evidence that the product did something right.

| Word | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | the scenario ran and its oracle held |
| `FAIL` | 1 | the scenario ran and its oracle did not hold |
| `UNAVAILABLE` | 3 | this host cannot produce the condition. **Not a pass** |
| `NOT-EXECUTABLE` | 3 | this runner has no procedure for that family yet |
| `VOID` | 4 | a middlebox failed §3.4.2, so the result is evidence of nothing |

`UNAVAILABLE` and `NOT-EXECUTABLE` are deliberately separate. "This host lacks
`nft`" and "nobody has written the DNS family's procedure yet" are different
problems with different owners, and collapsing them would hide the second behind
the first for ever.

**`run` enforces rule L-1 itself.** Before it punches anything, it runs §3.4.2's
conformance suite against both of the scenario's personalities *in the rig it is
about to use*, and a personality that disagrees with its configuration makes the
run `VOID` rather than `FAIL` — a result taken from a middlebox that is not what
it claims is evidence of nothing.

| Family | `run` | Why |
|---|---|---|
| `S-NAT-*` | **executes** | the class-pair matrix, against two real middleboxes |
| `S-RELAY-*` | **executes** | the primary relay is asserted in use, then terminated; the standby must carry the pair with no user action |
| `S-CP-*` | **executes** | **I5**: a path is established, held, and the rendezvous destroyed *while it is held*; the oracle is a count of datagrams that arrived afterwards |
| `S-KS-*` | **executes** | on the topology the documents declare — a site behind `N-EIM-APDF` — with ADR-0012's kill switch as an OS-level blackhole, **B-7**'s positive control, and a **V2** mutant that disarms the switch and watches the same traffic escape |
| `S-NET-*` | **executes** | the PMTU black hole (with a control proving the middlebox *could* have reported the MTU) and the roam between two access networks behind a router, with the tunnel process asserted not to have restarted |
| `S-COLL-*` | `NOT-EXECUTABLE` | it compares two captured host states before a tunnel exists — in-process work against the real pre-flight detector, not a network scenario, and it belongs in `tests/` |

`D*` cells within `S-NAT-*` are `NOT-EXECUTABLE` too, and the reason is stated
rather than skipped: §3.2 defines `D*` as direct **with port prediction or port
mapping**, `twinnet`'s hole-puncher implements neither, and a success rate
measured against it would be a number about the laboratory.

### Cost per tier

`Tier` refers to `docs/testing-strategy.md` §6.1. Measured on this host.

| Tier | What of TwinLab runs | Measured cost here |
|---|---|---|
| **T1** | `cargo test -p twinlab -p twinlab-scenarios -p twinsim` — the laboratory's own logic, the CD-4 vectors, the catalogue's invariants | **≈ 4 s**, no privilege, no network |
| **T2** | `cargo test -p twinnet` — the fabric: 50 tests over real namespaces, real middleboxes, real captures | **≈ 5 min** |
| **T2** | `twinlab-scenarios conformance` — §3.4.2 over all eight personalities | **≈ 90 s** |
| **T3** | the full class-pair matrix at §3.6's run counts | the arithmetic alone is ≈ 4 400 scenario runs; `TWINNET_MATRIX_RUNS` raises the per-cell count |
| **T4** | the soak and performance families | not implemented — no `S-SOAK-*` or `S-PERF-*` scenario exists yet |

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

**§3.4.2's conformance suite passes for all eight personalities**, and rule
**L-1** is enforced by the runner rather than described in a document. `N-NAT64`
was the last holdout and is now realized by `twinnet::nat::xlat`; the one part of
its row that is still not covered — RFC 8781 PREF64 in Router Advertisements —
is printed in its own conformance line rather than omitted, because a report that
listed only what it checked would read as coverage of what it did not.

**This kernel's `netem reorder` is close to inert, and jitter is not.** §3.4's
reordering row specifies `netem delay <d> reorder <p> <corr>`. Measured over 300
datagrams on this host, `reorder 50%` delivered nothing out of order while
`delay 20ms 15ms` delivered 23 — until the measurement's own send loop was fixed
(below), after which `reorder` began to fire. The conformance test keeps both
paths: it measures the specified mechanism, and if that delivers nothing it runs
the jitter control to prove the measurement channel can *see* reordering before
reporting the option `UNAVAILABLE`. Without the control, "netem's option is
inert here" and "this measurement is blind" would produce the same silence.

**Three defects were found in this laboratory's own instruments, and each one
would have reported a false result about the product.** They are recorded because
each is a class, not an incident:

| Defect | What it would have reported |
|---|---|
| `AF_PACKET` skipped `PACKET_OUTGOING` unconditionally | a capture on a device's own interface would have been blind to everything that device **transmitted** — that is, to every leak a fail-closed oracle exists to catch, while printing a clean run |
| the pass-through paths re-injected a `CHECKSUM_PARTIAL` transport checksum | **every NAT personality traversed and the plain router did not.** A packet a host generates for a `veth` may carry an incomplete checksum the receiving stack is told to ignore; re-injected from userspace it has no such promise and the receiver drops it. The translating paths recompute the checksum as part of the rewrite and never hit it |
| the impairment measurement drained with a 20 ms timeout after every send | a nominally back-to-back population went out at ~50 datagrams a second — **slower than the 64 kbit/s shaper it was measuring**. The shaper was in the path, was working, and the measurement reported "no shaper in the path" |

The common shape is worth naming: **an instrument that is slower, blinder or
more forgiving than the thing it measures reports the absence of a phenomenon
that is present.** Every one of these was caught by a positive control — an
assertion that the thing *would* have been visible — and none of them by the
assertion it was paired with.

**A fourth, in the suite's own structure, and it is the worst kind.** Every test
opened with `let Ok(mut rig) = build(...) else { return };`, which returns
silently for *any* error and not only for a facility the host lacks. A change
made the two-site rig fail to install a route, and the class-pair matrix went
from asserting 24 cells to asserting **none** — in 5 seconds instead of 48 — and
reported `ok`. The suite had a hole in it and said nothing. `or_skip` now
separates the two cases and only one of them is quiet: a host that cannot is
printed and skipped, and a rig that is broken **panics**.

**A fifth: the middlebox snapshot is written on a timer, and a test that read it
the instant its traffic finished read the one from before.** It reported "the
destination answered but the translator translated nothing, so something else
carried the traffic" about a translator that had carried it correctly.
`rigs::await_snapshot` waits for an observation that has already happened,
bounded, and returns the last snapshot anyway when the deadline passes — so it
cannot make a failing assertion pass.

**The kill-switch blackhole severed the tunnel it was protecting.** ADR-0012's
switch is realized as a blackhole route for each overlay prefix, and the first
version installed it at the *same metric* as the tunnel's own route for the same
prefix — so `ip route replace` overwrote the tunnel. Arming the kill switch broke
the tunnel, and the symptom was a rig that carried nothing at all. Two routes for
one prefix need two metrics; the comment claiming longest-prefix wins was simply
wrong.

**One of this laboratory's own tests was named for a claim it did not make.**
`when_the_tunnel_dies_protected_traffic_stops_rather_than_finding_another_way_out`
passed on a rig whose device has **no default route**: with `tun0` gone there was
no route to the overlay at all, so the traffic stopped for a *topological* reason
and nothing was enforcing anything. The behind-NAT rig has a default route by
construction, and the same scenario leaks in the clear without a kill switch —
which is how the overclaim was found. The test is renamed to say what it shows,
and `kill_switch_behind_nat.rs` makes the claim ADR-0012 actually makes.

**A roaming client that binds an address instead of a port never comes back.**
The tunnel bound its underlay socket to the device's Wi-Fi address; the moment
the roam took that address away, every send failed with `EADDRNOTAVAIL`, for
ever. A real client binds the port and lets the routing table choose the source.
That one line is the difference between a session that survives an interface
change and one that cannot.

**A black hole needs something to swallow.** §3.4 specifies the PMTU condition as
a reduced MTU *plus* a drop of ICMPv4 type 3 code 4 and ICMPv6 type 2. A
middlebox that forwards in userspace generates no ICMP at all, so the drop flag
alone changed nothing: the sender learned nothing either way, and the assertion
"no fragmentation-needed arrived" would have passed against a middlebox that had
never been capable of sending one. The middlebox now *generates* the report, and
the black hole is the switch that suppresses it — so the two are distinguishable,
which is the only thing that makes the absence a condition.

**The NAT64 forwarded what it could not translate, and the wire oracle is what
found it.** An IPv6 destination outside the translation prefix fell through to
the general "a family this middlebox does not translate is routed" branch, which
is right for a dual-stack middlebox and wrong for a NAT64 whose outside is
IPv4-only. The observable symptom was one frame: the client's own router
solicitation, on the v4-only segment, with the translator's MAC as its source.
It is now a refusal, and so are link-local and multicast in every personality —
a router does not forward those, and a middlebox that did would carry one
segment's housekeeping onto another where it is indistinguishable from a leak.

**The prober compared the mapped address against `0.0.0.0`.** A STUN client
decides "no NAT" by comparing the mapped address to its own source address, and
a socket bound to `0.0.0.0` reports `0.0.0.0`. The prober therefore reported a
translation on a router that performs none — which matters more than it looks:
`N-ROUTED` is the personality every `DIRECT_EXPECTED` v6 cell in §3.2's matrix is
evaluated as, so a prober that cannot recognise "no NAT" cannot certify the case
the matrix leans on hardest.
