# TwinVPN shared contracts

The frozen boundaries the first TwinVPN parallel implementation wave builds
against. **This package contains no production implementation** — no tunnel
engine, no session cryptography, no NAT traversal, no rendezvous, no relay
server, no control-plane service, no daemon, no application, no routing or DNS
engine, no kill switch, no UI, no database. It exists so those components can be
built in parallel without negotiating their interfaces with each other.

Everything here implements a Phase 1 decision. Where a Phase 2 requirement
conflicted with a Phase 1 ADR, the ADR won and the conflict is recorded in
[docs/phase1-conflicts.md](docs/phase1-conflicts.md).

---

## Layout

```
contracts/
  proto/twinvpn/v1/       protobuf schemas   (boundaries B1 and B3)
  cddl/twinvpn/v1/        CDDL schemas       (boundary B2, signed statements)
  registry/               machine-readable registries, diffed append-only in CI
  gen/{rust,swift,kotlin,csharp}/   generated bindings — COMMITTED, CI-verified
  tests/                  the contract test suite
  docs/                   ownership, identifiers, time, idempotency, versioning,
                          trust boundaries, and the Phase 1 conflict register
  buf.yaml  buf.gen.yaml  schema lint, breaking-change, and codegen configuration
```

The path is `/contracts`, not `packages/contracts`, because
[ADR-0018](../docs/adr/ADR-0018-shared-core-and-build-architecture.md) §11.12
fixes the repository layout. See
[docs/phase1-conflicts.md](docs/phase1-conflicts.md) CF-1.

---

## The four encoding boundaries

[ADR-0003](../docs/adr/ADR-0003-network-contract-schema-format.md) §11 selects a
different format at each boundary, because the boundaries have genuinely opposed
requirements and no single format is best at more than two of them.

| Boundary | Format | Here | Why |
|---|---|---|---|
| **B1** control plane (C1/C2/C7) | **Protocol Buffers**, length-delimited | `proto/` | Best-in-class schema evolution, preserve-and-forward unknown fields, codegen for every target |
| **B2** signed statements | **Deterministic CBOR** (RFC 8949 §4.2.1) in **COSE_Sign1** (RFC 9052) | `cddl/` | **Protobuf explicitly does not guarantee deterministic serialization.** A normative canonical form is required for anything signed, and adopting an audited one satisfies "no novel cryptography" |
| **B3** ephemeral signaling (C4) | Protobuf envelope wrapping deterministic CBOR | `proto/signaling.proto`, `candidate.proto` | Smallest safe parser on a pre-authentication, attacker-reachable path |
| **B4** data plane (C5/C6) | **No serialization framework** | **absent by design** | "A serialization library MUST NOT appear in the packet path." The highest-rate path is immune to serialization bugs by construction |

Signed statements are carried as **opaque `bytes`** inside protobuf, precisely so
no protobuf re-encoding can sit between receipt and verification. Verification is
over the **received octets**.

---

## Contract families

| File | Contents |
|---|---|
| [`common.proto`](proto/twinvpn/v1/common.proto) | envelope metadata, `Auth`, versions, the two clocks, canonical IPv4/IPv6 types, `VersionPrecondition` |
| [`errors.proto`](proto/twinvpn/v1/errors.proto) | `ErrorEnvelope`, `ResolvedAttributes`, `Evidence`, classification |
| [`identity.proto`](proto/twinvpn/v1/identity.proto) | `DeviceIdentity`, `SignedStatement`, the B2 statement inventory |
| [`device.proto`](proto/twinvpn/v1/device.proto) | `Device`, `DevicePlatform`, `DeviceRole` |
| [`capability.proto`](proto/twinvpn/v1/capability.proto) | `Capability`, `CapabilitySet`, `NegotiationResult` |
| [`peer.proto`](proto/twinvpn/v1/peer.proto) | `TrustedPeer`, `PeerTrust`, `PeerPermission`, `NegotiationFloor` |
| [`pairing.proto`](proto/twinvpn/v1/pairing.proto) | the full pairing lifecycle |
| [`presence.proto`](proto/twinvpn/v1/presence.proto) | `Presence`, `Heartbeat` — ephemeral by the four-part test |
| [`candidate.proto`](proto/twinvpn/v1/candidate.proto) | `ConnectionCandidate`, `CandidateSet`, `NetworkInterface`, punching |
| [`connection.proto`](proto/twinvpn/v1/connection.proto) | **the canonical `ConnectionState`**, `ConnectionSession`, `NetworkPath`, `ConnectionHealth` |
| [`tunnel.proto`](proto/twinvpn/v1/tunnel.proto) | `TunnelDescriptor`, `TunnelState` |
| [`routing.proto`](proto/twinvpn/v1/routing.proto) | `RoutePrefix`, `RouteAdvertisement`, `RoutePolicy`, `Route` |
| [`dns.proto`](proto/twinvpn/v1/dns.proto) | `DNSPolicy`, `DNSProtectionAssertion` |
| [`gateway.proto`](proto/twinvpn/v1/gateway.proto) | `LanGateway`, `ExitNode`, grants, `LanAccessPolicy` |
| [`relay.proto`](proto/twinvpn/v1/relay.proto) | `Relay`, `RelayRegion`, `RelayAssignment`, `RelayHealth`, `RelayBinding` |
| [`policy.proto`](proto/twinvpn/v1/policy.proto) | `PolicyBundle`, `StateDocumentRef` |
| [`control_commands.proto`](proto/twinvpn/v1/control_commands.proto) | C1 request/response |
| [`control_events.proto`](proto/twinvpn/v1/control_events.proto) | C2, durable and ephemeral, with the classification on the wire |
| [`signaling.proto`](proto/twinvpn/v1/signaling.proto) | C4 offer/answer, C5 path and session lifecycle |
| [`diagnostics.proto`](proto/twinvpn/v1/diagnostics.proto) | **local, device-authoritative** session events; `DiagnosticContext`; `HealthSample` |

**Not everything that looks like a control-plane command is one.** Connection
negotiation, candidate exchange, relay reservation, session resumption and health
reporting all live elsewhere, because Phase 1 puts them elsewhere for stated
reasons. The full placement table is
[docs/contract-matrix.md](docs/contract-matrix.md) §3.1.

---

## Registries

| File | Contents | CI rule |
|---|---|---|
| [`registry/reason_codes.json`](registry/reason_codes.json) | 201 codes across the sixteen `ADR-0015` domains, each with class, severity, terminality, actionability, remediation class, scope, doc anchor and declared evidence fields | **append-only** |
| [`registry/capabilities.json`](registry/capabilities.json) | 28 capabilities with probe evidence, absence consequence, `security_relevant` and `session_critical` flags | **append-only**; the whole registry is asserted to fit the 512 B advertisement reservation |
| [`registry/limits.json`](registry/limits.json) | Every size, count and depth limit enforced on untrusted input | one source for schemas, validators and tests |

---

## Using these contracts

**Regenerate bindings**

```bash
make bootstrap        # install/verify pinned buf
make toolchains       # install pinned Rust / Swift / JVM / .NET (user-local, no sudo)
make contracts        # validate, lint, generate, fail if stale
```

**Verify**

```bash
make verify-bindings  # every binding COMPILES against its pinned runtime
make test-contracts   # breaking-change check + the full behavioural suite
make gate             # the complete Phase 2 contract freeze gate (31 conditions)
```

`make verify-bindings` is not redundant with the staleness diff. A diff proves
the committed bindings are **current**; only a compile proves they are
**usable**. ADR-0018 §11.12 wants a schema change that a language binding
*cannot express* to fail at merge — and "cannot express" is a compile error, not
a diff.

Protobuf **runtime** versions are pinned to match the **generator** versions in
`build/toolchain/env.sh`, and the pairing is asserted before anything compiles.
They are one decision recorded twice: protoc 33.x emits
`@com.google.protobuf.Generated`, which protobuf-java 4.28 does not have, so a
mismatched pair fails with a wall of "cannot find symbol" rather than a clear
message.

`contracts/gen/**` is **committed**. CI regenerates and diffs it, so a schema
change a language binding cannot express **fails at merge rather than at
integration**. Do not hand-edit generated files.

**Add a field**

1. Use a fresh field number. Never reuse a removed one.
2. `make contracts` — regenerate and commit the bindings.
3. `make test-contracts` — the breaking check must pass.
4. **Do not bump `ProtocolEpoch`** unless a receiver's required behaviour
   changes. An additive change must not bump it.

**Remove a field**

1. `reserved` **both the number and the name**.
2. Everything above.
3. The number and name are never reclaimed.

**Add a reason code**

1. Append to `registry/reason_codes.json` with all required attributes.
2. A `user_actionable` code needs a `next_action_key`.
3. Use an existing domain. A new top-level domain requires an ADR-0015 amendment.

---

## Reading order

1. [docs/contract-matrix.md](docs/contract-matrix.md) — who owns what, who
   produces it, who consumes it, and how it is delivered
2. [docs/trust-boundaries.md](docs/trust-boundaries.md) — what an attacker can
   reach and what is structurally prevented
3. [docs/identifiers.md](docs/identifiers.md) — every identifier's authority,
   scope, opacity and reuse rule
4. [docs/timestamps.md](docs/timestamps.md) — the two clocks and why ordering is
   never derived from either
5. [docs/idempotency.md](docs/idempotency.md) — the three mechanisms and the
   anti-rollback control
6. [docs/versioning.md](docs/versioning.md) — six version numbers, one negotiated
7. [docs/phase1-conflicts.md](docs/phase1-conflicts.md) — the conflicts found
   during implementation and **the Phase 1 amendments that resolved them**
