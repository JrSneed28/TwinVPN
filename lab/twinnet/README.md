# `twinnet` — the fabric TwinLab scenarios actually run on

**Owner:** `test-engineering`. **Never shipped** ([ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12).

`twinlab` describes network conditions and decides verdicts. `twinnet` produces
them: real namespaces, real `veth`, real middleboxes, real impairment, real
packets, and an independent oracle that reads the wire.

---

## 1. What it removed

Before this crate, `lab/README.md` §2 ended with a sentence that was true:

> No NAT-class result in this repository was produced by a NAT. The
> `twinlab-scenarios plan` verdict for every such scenario is `Unavailable`, and
> that is the honest state.

Three obstacles produced that state. Two are gone and the third is not:

| Obstacle | Status |
|---|---|
| `ip netns add` needs `CAP_NET_ADMIN` in the initial user namespace | **gone.** [`agent::enter`] unshares `CLONE_NEWUSER \| CLONE_NEWNS \| CLONE_NEWNET` at `main` and holds the full capability set inside, then mounts a private `tmpfs` over `/run` so `ip netns` has somewhere to bind |
| every §3.3 personality was realized by `nftables` + `conntrack` | **gone.** [`nat`] is a second realization — a real middlebox process with a real RFC 4787 table. §3.1 constrains observable semantics, not the kernel subsystem |
| `N-NAT64` needed a `jool`-class translator | **gone.** [`nat::xlat`] is RFC 6052 addressing and RFC 7915 header translation inside the middlebox already in the path |
| a facility this host does not have | **unchanged.** `nft`-specific rulesets, a `BIT`-deterministic loss schedule, this kernel's `netem reorder`, and RFC 8781 PREF64 in Router Advertisements still report `Unavailable`, with evidence, and never a pass |

---

## 2. The one rule, restated where it bites

> **§3.1 (normative).** Every condition TwinLab reproduces MUST be produced by a
> mechanism with the same observable semantics as the real thing, never by a flag
> inside TwinVPN. A test MUST NOT be able to detect that it is running in TwinLab
> by inspecting the product's own configuration.

There is no flag in TwinVPN for a scenario to detect, because there is none to
set. The middlebox is a process on the path holding per-flow state; the impairment
is a `tc` qdisc; the outage is a killed process or a downed link; the leak oracle
is a raw socket on the interface. The only way to tell this middlebox from an
`nftables` one is to **probe its behaviour** — which is exactly what §3.4.2's
conformance suite does, with a prober that is not TwinVPN code.

---

## 3. Running it

```bash
source build/toolchain/env.sh
cd lab

cargo test -p twinnet            # 50 tests, ~5 min, no privilege required
cargo run -q -p twinnet -- capabilities

TWINNET_MATRIX_RUNS=20  cargo test -p twinnet --test traversal_matrix   # §3.6's run budget
TWINNET_IMPAIR_PACKETS=100000 cargo test -p twinnet --test impairment_conformance
```

`twinnet` is one binary that is every role — `agent`, `natbox`, `observe`,
`reflect`, `probe`, `relay`, `relayed`, `tunnel`, `p2p`, `measure`, `udp-send`,
`udp-echo`, `dns-query` — because every role has to be spawnable *inside* a
namespace by the agent, and the agent knows exactly one path: its own.

**Exit 3 means "this host cannot produce the condition."** Not 1. A caller can
tell a missing facility from a failed oracle without parsing a message.

---

## 4. What the suite covers

### 4.1 Behaviour

| Behaviour | Where | How it is decided |
|---|---|---|
| connection negotiation, direct P2P | `traversal_matrix.rs` | a simultaneous open across two real middleboxes; the expectation is **read from** `docs/networking.md` §3.2, never restated |
| local direct P2P | `address_families_and_cgnat.rs` | two hosts on one bridged LAN; asserted by the middlebox having allocated **no** mapping |
| relay fallback | `chaos_and_failover.rs` | a `RELAY_EXPECTED` pair binds a forwarder and exchanges traffic |
| relay failover | `chaos_and_failover.rs` | the primary is `SIGKILL`ed *after* being asserted in use; the standby takes over with no user action |
| session recovery, client restart | `kill_switch_and_tunnel_chaos.rs` | the tunnel is killed, the gap is asserted to be a gap, and the restart is asserted to resume |
| network migration / path disappearance | `kill_switch_and_tunnel_chaos.rs` | the underlay link goes down mid-session |
| full tunnel | `fail_closed_packets.rs` | no protected address and no plaintext name on the underlay, judged by a capture |
| split tunnel | `fail_closed_packets.rs` | protected traffic absent **and** unprotected traffic present |
| LAN access | `fail_closed_packets.rs` | the LAN is reached and the overlay is not exposed to it |
| IPv4, IPv6, dual stack | `address_families_and_cgnat.rs` | §3.2's last row asserted through the *same* middleboxes as the v4 matrix |
| DNS | `fail_closed_packets.rs` | the QNAME is parsed out of the wire; an off-tunnel query is named in the failure |
| kill switch | `kill_switch_and_tunnel_chaos.rs` | traffic stops rather than finding another way out — **plus** a mutant that gives it one |

### 4.2 Network scenarios

| Scenario | Realization |
|---|---|
| direct public addressing | `N-ROUTED`, conformance-checked |
| NAT, restricted, port-restricted, symmetric | `N-EIM-EIF`, `N-EIM-ADF`, `N-EIM-APDF`, `N-APDM-APDF-{RAND,SEQ}`, each conformance-checked |
| CGNAT approximation | one shared public address, disjoint per-subscriber port ranges, **reachable exhaustion** |
| IPv4-only / IPv6-only / dual stack | the rigs carry both families from the start (rule **L-5**) |
| NAT64 | RFC 6052 `/96` addressing and RFC 7915 translation. A v6-only client with **no IPv4 address at all** reaches a v4-only destination. All three prefix advertisements are realized and **independently switchable**: synthesized AAAA, RFC 7050 `ipv4only.arpa`, and RFC 8781 PREF64 in a real Router Advertisement. With none of them, the client correctly cannot get there |
| blocked UDP, "all but 443" | the middlebox's egress policy; the permitted-port variant asserts 443 still passes, so a total block cannot masquerade as a partial one |
| high latency, jitter, loss, duplication, reordering, bandwidth, MTU | `netem` / `tbf`, each **measured** against §3.4.2's tolerance rather than assumed applied |
| PMTU black hole | a reduced egress MTU **plus** suppression of the ICMP report — with a control proving the middlebox *would* have reported it, because an absence is only a condition if the thing could have been present |
| interface change (roam) | the device's leg moves between two access networks behind a router and re-addresses; the tunnel process is asserted **not** to have restarted, so what resumes is the same session |

### 4.3 Chaos

| Scenario | Mechanism |
|---|---|
| relay termination | `SIGKILL`, after asserting the primary was in use |
| relay-region outage | the region's link goes **down** — healthy and unreachable, which is the harder case: a killed service refuses, a blackholed one is silent |
| rendezvous termination | killed *during* an established path's hold phase |
| control-plane outage | blackholed during an established tunnel's traffic |
| client restart | kill the device's tunnel, assert the gap, restart, assert resumption, assert nothing leaked across it |
| gateway restart | kill the **far** end while the client is untouched — a gateway is restarted on a schedule its clients know nothing about, and a client that needed its own restart to recover would turn every deploy into an outage for everyone behind it |
| path disappearance | the underlay goes down; the LAN is watched for rerouted protected traffic |
| database outage | **not here.** It needs the real control plane and its store; it belongs to `tests/`, which links them |

### 4.4 Phase 1 — the control plane going away

`an_established_tunnel_keeps_carrying_traffic_while_the_control_plane_is_blackholed`
asserts invariant **I5** the way no in-process test can: two real sockets, a real
tunnel, a real blackhole, and a count of packets that arrived afterwards. Its
preconditions are asserted, not assumed — the control plane is shown reachable
before the outage and unreachable after, or the outage proves nothing.

`tests/chaos/outage_and_failover.rs` asserts the same invariant structurally, by
showing no control-plane event exists in the data plane's alphabet. That argument
is the stronger one. This is the other half.

---

## 5. Fail-closed, and why every assertion here is paired

> A test MUST fail if protected IPv4, IPv6 or DNS traffic escapes through an
> unauthorized path.

Rule **PT-2** requires an independent wire oracle for every security property,
"because a system reporting on itself is not sufficient evidence". A deny counter
read out of `twinvpn-enforce` is that insufficient evidence: a packet that never
reached the enforcement hook is invisible to it *by construction*, and that packet
is the leak.

So the oracle is a capture. Which creates the failure mode this section exists for:
**a capture that recorded nothing is indistinguishable from a perfectly sealed
tunnel, and prints the same green line.** Every sealed-tunnel assertion in this
suite is therefore preceded — in the same test, on the same capture — by a
deliberate leak the same oracle must catch:

- a plaintext DNS query to an unauthorized resolver, whose **QNAME** must appear
  in the finding;
- a mutant route that survives the tunnel's death, which must be caught;
- an unprotected flow that must still be *visible* in the split-tunnel case.

`Capture::is_silent` exists for exactly this question, and the kill-switch test
runs its positive control **after** the kill, so "nothing leaked" is a statement
about the device rather than about a dead observer.

**What this suite does not claim.** [`tun`] is a real encapsulation, not a real
cryptographic tunnel. The oracle answers "did protected addressing appear as an
outer source or destination"; it does not answer "was the payload unreadable".
That claim belongs to the product's own tunnel and to
`tests/integration/tunnel_wire_agreement.rs`.

---

## 6. Three defects in this laboratory's own instruments

Each would have reported a false result *about the product*, and each was caught
by a positive control rather than by the assertion it was paired with.

| Defect | What it would have reported |
|---|---|
| `AF_PACKET` skipped `PACKET_OUTGOING` unconditionally | a capture on a device's own interface, blind to everything that device **transmitted** — that is, to every leak this suite exists to catch — while printing a clean run |
| the pass-through paths re-injected a `CHECKSUM_PARTIAL` transport checksum | **every NAT personality traversed and the plain router did not.** Packets a host generates for a `veth` can carry an incomplete checksum the receiving stack is told to ignore; re-injected from userspace they carry no such promise and are dropped. The translating paths recompute as part of the rewrite and never hit it |
| the impairment measurement drained with a 20 ms timeout after every send | a nominally back-to-back population left at ~50 datagrams a second, **slower than the 64 kbit/s shaper it was measuring**. The shaper was working; the measurement reported "no shaper in the path" |

The shape is one thing: **an instrument slower, blinder or more forgiving than
what it measures reports the absence of a phenomenon that is present.**

A fourth, in the reflector rather than an oracle: it polled four sockets
round-robin with 100 ms blocking timeouts, so it could take 400 ms to answer —
longer than the prober's own read timeout. It answered one peer and looked
unreachable to another, which the laboratory would have reported as a NAT class.
It now runs one thread per socket. **A reflector must never be the slowest thing
in a measurement of something else.**

A fifth, in the suite's own structure, and it is the worst of them. Every test
opened with `let Ok(mut rig) = build(...) else { return };`, which returns
silently for *any* error rather than only for a facility the host lacks. A change
made the two-site rig fail to install a route, and `traversal_matrix` went from
asserting 24 cells to asserting **none** — in 5 seconds instead of 48 — and
reported `ok`. `common::or_skip` now separates the two cases and only one is
quiet: a host that cannot is printed and skipped; a rig that is broken **panics**.

---

## 7. What the wire oracle found in the translator

The NAT64 was written, its three functional tests passed, and the fourth — a
capture on the IPv4-only segment asserting that no IPv6 addressing ever crosses
onto it — failed on **one frame**:

```
[02:00:35:4e:af:fa] fe80::8cff:fe28:9cd9 -> ff02::2  proto 58
```

Two MACs tell the whole story. The Ethernet source is the *translator's* wan
port. The IPv6 source is the link-local address derived from the *client's* MAC.
It is the client's router solicitation, forwarded untranslated onto a network
that has no IPv6 — by the general "a family this middlebox does not translate is
routed" branch, which is correct for a dual-stack middlebox and wrong for a NAT64
whose outside is IPv4-only.

Nothing else would have caught it. The three functional tests passed: the client
reached the destination, the fallback worked, the negative control held. A
counter read out of the translator would have agreed. **The only thing that
disagreed was the wire**, which is the argument rule PT-2 makes, arriving from
the direction PT-2 predicts.

Two refusals came out of it, and both are now unconditional:

- a NAT64 **drops** an IPv6 destination outside the translation prefix, because
  there is no IPv6 next hop to give it;
- **every** personality drops link-local and multicast, because a router does not
  forward those and a middlebox that did would carry one segment's housekeeping
  onto another, where it is indistinguishable from a leak.
