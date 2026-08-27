# Implementation wave 1 — ownership, layout, and the rules every agent works under

**Status:** authoritative for the first production implementation wave.
**Owner:** the integration lead. An implementation domain does not edit this file.

Phase 1 wins wherever it and the wave-1 objective disagree. Three places they do,
and the resolution in each, are recorded in §4 — read them before writing code,
because two of them will otherwise look like this document is wrong.

---

## 1. Repository layout

[ADR-0018](../adr/ADR-0018-shared-core-and-build-architecture.md) §11.12 fixes
the layout. It is reproduced here with the one integration-lead addition marked.

| Path | Contents | Owning domain |
|---|---|---|
| `contracts/` | **FROZEN.** proto, CDDL, registries, committed bindings, contract tests | nobody — see §3 |
| `core/` | one cargo workspace, all `twinvpn-*` crates | `shared-core` (four sub-domains, §2) |
| `core/ffi/include/twinvpn.h` | hand-written; **the ABI of record** | `core-composition` |
| `services/` | server-side artifacts — **integration-lead placement, not an ADR one** | `control-plane`, `rendezvous-connectivity`, `relay-plane` |
| `shells/linux/` | `twinvpnd` + `twinvpnctl` (Rust) | `desktop-linux` |
| `shells/{windows,macos,ios,android,openwrt}/` | per-platform shells | wave 2 (§5) |
| `build/` | toolchain pins, target definitions, budgets | `infrastructure` |
| `infra/` | compose, deployment, observability, local orchestration | `infrastructure` |
| `lab/` | TwinLab; **never shipped** | `test-engineering` |
| `tests/` | integration, chaos, compatibility, end-to-end | `test-engineering` |

**Why `services/` is not in ADR-0018.** §11.12 lists no server path. §11.2 says
only that the control plane's "server-side is a different artifact" (row 2.8) and
that "the relay server is a separate artifact sharing `twinvpn-schema` and the
framing crate" (row 2.11). `services/` is therefore chosen by the integration
lead — consistent with the wave-1 ownership map and with
`scripts/check_freeze_scope.py`, which already names `services` among the
production paths it guards. It is a decision, recorded as one, not an ADR.

**Four cargo workspaces, not one.** `core/`, `services/`, `shells/linux/` and
`lab/` are separate workspaces. §11.12 makes `/core` "one cargo workspace"; the
others are separate *artifacts*, and separating the workspaces means no domain
silently acquires another's dependency graph, each domain owns its own manifests,
and the ADR-0018 T1 lints have an exact crate set to run over.

**The workspace manifests — `core/Cargo.toml`, `services/Cargo.toml`,
`shells/linux/Cargo.toml`, `lab/Cargo.toml`, `rust-toolchain.toml` and the
`Makefile` — are owned by the integration lead.** A crate's own `Cargo.toml` is
owned by the crate's domain. This is the shared-manifest rule from `CLAUDE.md`.

---

## 2. Domain ownership

No domain writes into another's paths. A change that needs to cross a boundary is
a request to the integration lead, not an edit.

| Domain | Owns | Notes |
|---|---|---|
| `core-foundation` | `core/crates/twinvpn-{types,env,schema,platform}`, `core/xtask` | everything else depends on it; lands first |
| `core-security` | `core/crates/twinvpn-{crypto,store,trust}` | `twinvpn-crypto` is the **only** crate permitted a cryptographic dependency (CD-I2) |
| `core-dataplane` | `core/crates/twinvpn-{tunnel,path,relay-client,route,dns,enforce,gateway,session}` | **MUST NOT** depend on `twinvpn-cp-client` (CD-I5) |
| `core-controlplane` | `core/crates/twinvpn-cp-client` | **MUST NOT** depend on any data-plane crate (CD-I5) |
| `core-composition` | `core/crates/twinvpn-{core,ffi,diag,mgmt}`, `core/ffi/include/twinvpn.h` | the composition root is the only crate that may name both planes |
| `control-plane` | `services/control-plane`, `services/twinvpn-service-common`, control-plane migrations | also owns the shared service crate the other three consume |
| `rendezvous-connectivity` | `services/{rendezvous,presence}` | **not** the portable NAT traversal — that is `core-dataplane`'s `twinvpn-path` |
| `relay-plane` | `services/{relay,relay-directory,relay-health}` | |
| `desktop-linux` | `shells/linux/`, `core/crates/twinvpn-platform-linux` | the platform adapter *implementation* is a shell-side concern under CB-3 |
| `infrastructure` | `infra/`, `docker-compose.yml`, `build/`, `.github/workflows/` | CI files only as assigned |
| `test-engineering` | `lab/`, `tests/` | may **read** everything; writes nowhere else |
| `security-review` | reviews; **files findings, does not silently rewrite** another domain's component |
| `final-review` | cross-component review after integration |

---

## 3. The contract freeze

`contracts/` is frozen. `contracts/FROZEN` records the digest and the evidence.

**No implementation agent may modify `contracts/`** — not the schemas, not the
registries, not the generated bindings, not the tests — unless every one of these
happens, in order:

1. the implementation exposes a **genuine contract defect**,
2. the agent documents the incompatibility precisely,
3. the integration lead reviews it,
4. Phase 1 architectural implications are checked,
5. compatibility implications are analyzed,
6. the change is **explicitly approved**,
7. contract tests are updated,
8. `contracts/FROZEN` is re-declared and this decision amended.

**Implementation inconvenience is not a defect.** Adapt the implementation to the
contract. If the contract genuinely cannot express what Phase 1 requires, that is
a finding to report, not a patch to land.

One defect is already open and is recorded in §4.

---

## 4. Where the wave-1 objective and Phase 1 disagree

### 4.1 `packages/contracts` → `contracts/`

The objective says `packages/contracts`. ADR-0018 §11.12 fixes `/contracts`.
**Phase 1 wins**; this is CF-1 in
[`contracts/docs/phase1-conflicts.md`](../../contracts/docs/phase1-conflicts.md),
already closed.

### 4.2 `TVPN-AUTH-*` error families → the ADR-0015 `DOMAIN.CONDITION` taxonomy

The objective asks for stable families spelled `TVPN-AUTH-*`, `TVPN-NAT-*`,
`TVPN-IPV4-*` and so on. **Phase 1 explicitly rejected that scheme**, and the
rejection is now recorded in [ADR-0015](../adr/ADR-0015-observability-and-diagnostics.md)
§11.2 as a considered alternative — see CF-3. Use the frozen taxonomy:

- Format `DOMAIN.CONDITION` or `DOMAIN.SUBDOMAIN.CONDITION`; uppercase; ASCII;
  ≤ 64 bytes; two or three segments.
- A **closed set of sixteen domains**: `NET NAT RELAY AUTH CRYPTO PROTO POLICY
  DNS ROUTE PLATFORM RESOURCE CONTROL INTERNAL MGMT STORE UPDATE`.
- Every code must already exist in
  [`contracts/registry/reason_codes.json`](../../contracts/registry/reason_codes.json)
  (201 codes). A code with no registry entry **fails the contract tests**.
- A `user_actionable` code needs a `next_action_key`.
- The requested families map as: `TVPN-AUTH`→`AUTH`, `TVPN-PAIR`→`AUTH.PAIRING_*`,
  `TVPN-NAT`→`NAT`, `TVPN-RELAY`→`RELAY`, `TVPN-TUNNEL`→`CRYPTO` +
  `NET.SESSION.*`/`NET.PATH.*`, `TVPN-ROUTE`→`ROUTE`, `TVPN-DNS`→`DNS`,
  `TVPN-POLICY`→`POLICY`, `TVPN-PLATFORM`→`PLATFORM`, `TVPN-PROTOCOL`→`PROTO`,
  `TVPN-CONTROL`→`CONTROL`, `TVPN-INTERNAL`→`INTERNAL`.
- **`TVPN-IPV4-*` / `TVPN-IPV6-*` are refused as domains.** Address family is an
  *evidence field* (`Evidence.family_value`), not a namespace, because a
  per-family namespace makes "we have a v4 story and a v6 story" sayable — the
  exact asymmetry [ADR-0010](../adr/ADR-0010-ipv4-ipv6-routing.md) R1 exists to
  forbid. The objective's own rule that IPv4 and IPv6 are equally required is
  what makes the split wrong.

The objective's underlying requirement — *never expose a raw unexplained OS error
as the complete user-facing error* — is satisfied structurally and is still
binding: map every internal error into a registered `reason_code`, carry the
platform detail as typed `Evidence`, and never let an `errno` be the whole story.

### 4.3 OPEN DEFECT — `limits.json` capability name bound is stale

`contracts/registry/limits.json` has `capability.max_name_bytes = 24`.
`contracts/registry/capabilities.json` has `capability_name_max_length = 32`,
`contracts/cddl/twinvpn/v1/capabilities.cddl` has `[a-z][a-z0-9_]{0,31}`, and the
registry itself contains `dns_config_dies_with_tunnel` — **27 bytes**. CF-6
amended [ADR-0014](../adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
N-11 from 24 to 32 and deliberately did **not** rename the token, because it is
`security_relevant` and a rename is an S-37 compatibility event.

`limits.json` exists to be *the* source for validators on untrusted input. An
implementation that validates a capability advertisement against it would reject
a Phase-1-mandated token. That is a genuine contract defect, not an
inconvenience.

**Until it is dispositioned:** validate capability names against **32** and cite
this section. Do **not** edit `contracts/`. The integration lead has raised it.

---

## 5. Wave-1 scope, stated honestly

**In wave 1:** `core/` (all crates), `services/` (all six), `shells/linux/`,
`infra/`, `lab/`, `tests/`, and the security and final reviews.

**Deferred to wave 2, with the reason:** the Windows, macOS, iOS, iPadOS and
Android shells. Their platform surfaces — `NEPacketTunnelProvider`,
`VpnService`, the Windows service + WinUI host, the macOS system extension —
cannot be compiled, let alone exercised, on the Linux host this wave runs on.
Producing shell code that has never been built would be the failure mode the
wave-1 objective names in its last line: declaring completion because something
looked done. Wave 2 needs a macOS builder and a Windows builder.

The generated Swift, Kotlin and C# bindings those shells consume **are** built
and verified here every gate run (`make verify-bindings`), so the contract half
of the mobile and desktop surface is already proven.

---

## 6. Rules every implementation agent works under

1. Implement only your assigned component.
2. **Consume the frozen contracts.** Never redeclare an equivalent struct, enum,
   message or API that `contracts/` already defines.
3. Unit tests, and component tests where the component has a seam worth testing.
4. Health and readiness checks on every long-running service.
5. Structured logging; OpenTelemetry per
   [ADR-0015](../adr/ADR-0015-observability-and-diagnostics.md).
6. Preserve `correlation_id` and `causation_id` across every component boundary.
7. Graceful shutdown.
8. Document environment configuration, local startup and debugging in the
   component's own `README.md`.
9. **Validate every untrusted input** against
   [`contracts/registry/limits.json`](../../contracts/registry/limits.json)
   *before* any allocation proportional to a declared length. A violation is a
   typed reject with a `PROTO.*` code — never a truncation, never a pad, never a
   silent accept.
10. Bound every allocation an untrusted input can drive.
11. **Never log** private keys, session keys, raw tunnel payloads, pairing
    secrets, or authentication tokens. Observability must never capture tunnel
    payloads.
12. Expose registered `reason_code`s, never raw internal errors (§4.2).
13. Run `make lint`, your tests, and `make test-contracts` before reporting.
14. Report unresolved architecture conflicts rather than resolving them locally.
15. Return the completion report the objective specifies.

### Security rules that are not negotiable

Do not invent cryptographic primitives. Use
[ADR-0001](../adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §11
exactly: L-DATA is unmodified WireGuard `Noise_IKpsk2` (X25519,
ChaCha20-Poly1305, BLAKE2s) end-to-end between devices and terminated by no
infrastructure component; L-TRANSPORT is pluggable and security-neutral;
L-CONTROL is QUIC + TLS 1.3 with mutual raw-public-key auth and per-message
`DeviceIdentityKey` signatures, **0-RTT prohibited**; L-STORE is platform-native.

Do not weaken mutual device authentication, replay protection, downgrade
protection, credential validation, device revocation, session-key handling,
control-plane authentication or relay authentication. Identity private keys stay
inside the platform element (CB-5 / I4). Relays must never need plaintext access
to tunnel payloads (I1).

### Networking rules

IPv4 and IPv6 are equally required — there is no "v6 later". Every networking
component considers IPv4, IPv6, dual stack, IPv6-only, NAT64 where
[ADR-0010](../adr/ADR-0010-ipv4-ipv6-routing.md) requires it, interface changes,
path changes, MTU, timeouts, cancellation, shutdown and transient failure.
Never route around TwinVPN while fail-closed is active.

### Time, randomness, and the lint that enforces it

[ADR-0018](../adr/ADR-0018-shared-core-and-build-architecture.md) CD-1 defines
**three non-interchangeable clock types** — `MonotonicClock` (does *not* advance
across suspend; every timer takes this), `ElapsedClock` (does), and `WallClock`
(evidence only, never a timer input, and a three-state value: `Unset` /
`Offset{source}` / `Trusted`). CD-2: every component takes its `Env` at
construction — no global, no `OnceCell` clock, no ambient default. CD-3 bans
`SystemTime::now`, `Instant::now`, `getrandom`, thread-local RNG constructors,
the runtime's time module and `chrono` now-constructors everywhere outside
`twinvpn-env`. `make arch-lint` is the mechanism.

---

## 7. Integration order

Domains develop in parallel in isolated worktrees. They **integrate one at a
time**, in this order, and after each one the full gate must be green before the
next lands:

```
make contracts && make test-contracts && make build && make lint && make test
```

1. `core-foundation`
2. `core-security`
3. `core-controlplane` and `core-dataplane`
4. `core-composition`
5. `control-plane`
6. `rendezvous-connectivity`
7. `relay-plane`
8. `desktop-linux`
9. `infrastructure`
10. `test-engineering`
11. `security-review` corrections
12. `final-review`

**Do not continue integrating onto a broken `main`.**
