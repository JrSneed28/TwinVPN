# Timestamp and clock rules

Two clocks exist. They are never interchangeable, and the type system enforces
the distinction: `WallClockMillis` and `MonotonicMicros` are different messages
in [`common.proto`](../proto/twinvpn/v1/common.proto).

---

## 1. The rule that decides everything else

> [docs/protocol.md](../../docs/protocol.md) §2: `sender_time_ms` is **ADVISORY
> ONLY. No protocol decision may depend on a peer's clock.** Freshness is
> enforced by nonces and monotonic counters, never by timestamps.

> [ADR-0009](../../docs/adr/ADR-0009-state-consistency.md) K-1 / RQ-9: **no
> security decision may depend on the device's clock being correct.**

The reasoning is concrete, not theoretical: mobile devices sleep, resume with
skewed clocks, and cross timezones. **A clock-guarded protocol fails exactly
when the user is roaming** — which is the scenario the product exists to fix.

And at the other end of the hardware range, much OpenWrt-class hardware has **no
RTC and boots to epoch 0 on every power cycle**. A protocol that gates on wall
time does not merely inconvenience such a device; it bricks it, because there is
nobody present to perform the remediation. That is why
`AUTH.CLOCK_IMPLAUSIBLE` is registered **non-terminal and non-gating**: a bad
clock is a condition to *report*, never a gate.

---

## 2. `WallClockMillis`

**Representation.** `uint64`, **milliseconds since the Unix epoch, UTC**.

- **UTC always.** No timezone field exists, and none may be added: a timezone is
  a presentation concern, and carrying one invites arithmetic that is correct in
  one zone and wrong in another.
- **Milliseconds.** Finer precision would imply an accuracy the source does not
  have; coarser would be unable to express the 120 s pairing window or a 30 s
  candidate TTL usefully.
- **`uint64`, explicitly sized.** [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md)
  §11 rule 2. It also has to survive JSON at boundary B5, where rule 2 requires
  64-bit integers to be **rendered as strings**, because several target
  ecosystems cannot represent them as JSON numbers and silent precision loss on
  a sequence or an epoch would be a critical, near-invisible bug.
- **Field naming.** Every wall-clock field ends in `_ms`. A bare `*_at` integer
  is rejected by [`tests/test_schema_structure.py`](../tests/test_schema_structure.py),
  because a name that does not state its clock is how a wall clock ends up on a
  timeout.

**Creation authority.** The emitting host, from its own system clock. Nobody
corrects it, and no receiver may.

**Permitted uses — exactly three:**

1. Rendering to a human.
2. Evaluating a signed statement's `not_before_ms` / `not_after_ms` **against
   local time with an explicit skew allowance**. Failure surfaces as
   `AUTH.STATEMENT_EXPIRED`, never a silent drop. This is the one exception the
   corpus grants, and it is safe because bounded-lifetime statements are
   evaluated against the *verifier's* clock, not the *signer's*.
3. TTL expiry of an ephemeral hint, where being wrong costs a wasted probe.

**Prohibited uses:** ordering, freshness proofs, retry and backoff scheduling,
any protocol timeout, and any authorization decision.

**Skew assumptions.** None, in general. Where a skew allowance is unavoidable it
is stated at the site:

| Site | Allowance | Authority |
|---|---|---|
| Relay token `nbf`/`exp` | ±300 s | [ADR-0005](../../docs/adr/ADR-0005-relay-architecture.md) §11.3 |
| `pair_tag` bucket | ±1 bucket (±10 min) | [ADR-0005](../../docs/adr/ADR-0005-relay-architecture.md) §11.1 |
| Signed statement windows | per-statement, explicit | [ADR-0003](../../docs/adr/ADR-0003-network-contract-schema-format.md) §11 |

**Clock recovery without egress.** On `RELAY.TOKEN_EXPIRED` the relay returns
its own current time; the device computes an **offset**, retries **once**, and on
a second failure emits `RELAY.CLOCK_SKEW_EXCESSIVE`. **A device MUST NOT set its
system clock from a relay** — the offset is held for token-validity evaluation
only. This is the recovery path for an RTC-less router, and it deliberately needs
no egress, because a device that cannot get a token cannot reach anything else
either.

---

## 3. `MonotonicMicros`

**Representation.** `uint64`, **microseconds from an unspecified, host-local,
strictly non-decreasing origin**, unaffected by NTP steps, timezone changes, and
user clock edits.

**The only clock permitted for:** protocol timeouts, backoff and retry
scheduling, RTT and quality measurement, liveness and dead-path detection,
path-validation budgets, and freshness windows on locally held assertions.

**Prohibited:** transmitting between devices, comparing across a process
restart, or persisting and reloading as if still valid. The origin is
process-local and meaningless off-device.

**Suspend.** [ADR-0022](../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md),
via [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.16 (e), requires the injected `Clock` to **report** the wall-clock
discontinuity across suspend rather than hide it. So a monotonic reading that
spans a suspend is still correctly *ordered*, while the wall clock beside it may
jump — and the code that cares can see that it did.

**Why microseconds.** RTT on a LAN path is routinely under a millisecond; a
millisecond-resolution RTT would quantize `LOCAL_DIRECT` measurements into two or
three buckets and make the quality objectives in
[docs/reliability.md](../../docs/reliability.md) §5.4 unmeasurable.

---

## 4. Ordering is never derived from a clock

| Ordering need | Mechanism | Never |
|---|---|---|
| Durable events within a TwinNet | `net_seq`, from the single writer | a timestamp |
| Policy versions | monotone `policy_version` | `issued_at_ms` |
| Trust epochs | monotone `trust_epoch` | `effective_from_ms` |
| Identity rotation | `generation` / `tk_generation` | `not_after_ms` |
| Route advertisements | `advertisement_epoch` per advertiser | TTL |
| Path migration | `path_epoch` | arrival time |
| Candidate trickle | `generation` | `expires_at_ms` |
| Presence | **no ordering at all** — an absolute `expires_at_ms` with last-writer-wins | any ordering assumption |

[ADR-0002](../../docs/adr/ADR-0002-control-plane-messaging-and-event-bus.md) C-8
states it flatly: *"Clocks are advisory. Ordering may not be derived from wall
clocks anywhere in this design."*

The presence row is the instructive one. Presence has **no ordering guarantee**
and consumers **MUST tolerate reordering**, which is exactly why it carries an
**absolute** `expires_at_ms` rather than a relative TTL: a relative TTL applied
to a reordered pair of updates yields the wrong expiry, while an absolute instant
cannot be reordered into the wrong answer.

---

## 5. Timestamps and the `sample_epoch`

`HealthSample.sample_epoch` is an **absolute** instant; the collector reorders.
Samples are unordered on the wire and idempotent by `(device_id, sample_epoch)`,
so a duplicate does not double-count a metric and a gap is recorded as a gap
rather than guessed at.
