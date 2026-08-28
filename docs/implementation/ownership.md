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

---

## 8. Wave-1 findings register

Findings surfaced by implementation, with the integration lead's disposition.
A **ruling** is an interpretation of Phase 1 applied now; a **defect** needs the
contract or an ADR amended and is not patched under the freeze; a **gap** is
something Phase 1 does not say and someone must decide.

| # | Kind | Finding | Disposition |
|---|---|---|---|
| **W-1** | ruling | **CD-4 vs CD-I2.** ADR-0018 CD-4 puts an HKDF-SHA-256 derivation in `twinvpn-env`, but CD-I2 permits a cryptographic dependency only in `twinvpn-crypto`, and §11.7's arrow has crypto depending on env — so the literal reading is a cycle. | **Confirmed split.** `twinvpn-env` declares `rng_for`/`StreamDerivation` and no crypto dependency; the *binding* supplies the derivation. CD-4's substance divides cleanly: the structural half (`info == "twinlab/v1/" ‖ consumer_id`, stream independence) is what `docs/testing-strategy.md` §3.5 actually relies on and holds for any injective derivation — `twinvpn-env` owns and tests that. The cryptographic half is `twinvpn-crypto`'s, with a named known-vector test, and `lab/` asserts it end to end. **Needs ADR-0018 §11.7 confirmation.** |
| **W-2** | ruling | **Are `zeroize` and `subtle` "cryptographic implementations" under CD-I2?** Reading them as such forbade them outside `twinvpn-crypto`, leaving an elidable `fill(0)` on secret types and a data-dependent comparison on `ChannelBinding`. | **No — exempt.** CD-I2's text says cryptographic *implementation* and its stated purpose (§11.7, "P2's static half") is that a reviewer asking *what cryptography do we use* reads one crate. Neither crate answers that question: one is memory hygiene, the other constant-time comparison. Reading the rule to forbid them makes security **worse**, which cannot be the intent of a rule that exists to make crypto auditable. The alternative — moving `ChannelBinding`/`SharedSecret` into `twinvpn-crypto` — was rejected because it destroys `twinvpn-types`' dependency-free property. The `xtask` CD-I2 check carries the exemption **and a test that it still fires on a real crypto dependency**, so the hole did not widen. |
| **W-3** | ruling | **`architecture.md` §2.8 vs §5 row S-09** — §2.8's prose makes the Control Plane "single authoritative writer for … relay-fleet registry"; S-09 assigns registry **and ranking** to the Relay-Selection Service (2.12). Both cannot hold under I8. | **§5 wins; §2.8's sentence is a prose error.** `architecture.md` names §5 as its own authority for exactly this question. Registry and ranking both belong to `relay-directory`; the control plane keeps **S-30** (`RelayCapabilityToken` issuance), which §5 does assign to it. |
| **W-4** | gap → **binding constraint** | **`prost` 0.13 drops unknown fields.** Measured, not assumed. `contracts/docs/phase1-conflicts.md` CF-2 recorded preserve-and-forward as a constraint on a hypothetical JS runtime; it binds **the Rust services too**. | Every forwarder — coordination, rendezvous, and any relay carrying an opaque `CALL` — **MUST forward the received octets verbatim** and never decode-then-re-encode. `twinvpn-service-common` provides a forward-verbatim primitive so the four service domains inherit it rather than each rediscovering the trap. The most consequential cross-domain finding of the wave. |
| **W-5** | **defect** | **`evidence_truncated` is declared by no reason code.** `errors.proto` normatively requires a truncating emitter to append `{key:"evidence_truncated"}`, but no registry entry lists it, so a declared-set check rejects a message the schema requires. | Not patched. One key exempted from the declared-set check, documented at the constant. **Needs the amendment procedure.** |
| **W-6** | **defect** | **No reason code declares an evidence key for an OS error number.** §6 rule 12 requires platform detail be carried as typed `Evidence`; `PLATFORM.ADAPTER_UNAVAILABLE` declares none and `PLATFORM.OS_UNSUPPORTED` declares only `os_version`, so `errno`/`syscall` evidence is dropped for exactly those codes. | Not patched. The rule's substance still holds (registered code; detail reachable for a Tier-1 bundle) but its typed-evidence half cannot be satisfied. **Needs the amendment procedure.** |
| **W-7** | gap | **`ElapsedClock`, `Entropy` and `BootIdSource` are required shell interfaces that ADR-0018 §11.16 does not list.** `std` has no suspend-inclusive clock, and the platform calls need `unsafe` (DP-4) or `cfg(target_os)` (CB-3), so the shell must supply them. | Accepted as a real gap — and it is precisely the invisible-on-Linux-CI failure LC-8 warns about. Every shell brief names all three as required. **Should be recorded in ADR-0018 §11.16.** |
| **W-8** | gap | **`limits.json`'s `ports` section is a validation bound (`{min:1,max:65535}`), not a port assignment.** | Correct reading. Ports come from ADR-0002 §11.2 and ADR-0005 §11.4. The `:9090` admin listener is an infrastructure-domain decision, recorded as one. |
| **W-9** | gap | **Tier-2 `nat_class` is singular; "outcome by NAT class pair" needs two.** ADR-0015 §11.1's tuple names one; `docs/testing-strategy.md` §3.6 and the wave objective both speak of pairs — and a pair carries k-anonymity consequences. | A decision, not an oversight. Dashboards query `nat_class_local`/`nat_class_remote` with the divergence flagged in the panel. **Referred to ADR-0015's owner.** |
| **W-10** | gap | **ADR-0015 §9's router-class observability budget (< 512 KB) cites no `GC-*` class**, which under ADR-0018 BM-1 makes it an unqualified budget. | Transcribed as written in `build/budgets.toml` and flagged, rather than attributed to `GC-0` or `GC-0U` on a guess. **Referred to ADR-0015's owner.** |

| **W-11** | **defect** | **Eight `CONTROL.*` reason codes that ADR-0009 §11 names are absent from the frozen registry.** Present: `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR`, `CONTROL.STALENESS.DOCUMENT_STALE`, `CONTROL.STALENESS.TRUST_LIST_EXPIRED`. **Missing:** `CONTROL.CONSISTENCY.{VERSION_ROLLBACK_REJECTED, FORKED_HISTORY_DETECTED, CURSOR_INVALIDATED, CLOCK_SKEW_EXCESSIVE, SIGNATURE_UNVERIFIABLE}` and `CONTROL.STALENESS.{POLICY_GRANT_SUSPENDED, RELAY_SET_EXPIRED, TRUST_EPOCH_BEHIND_PEER}` — 8 of the 11 names ADR-0009 uses. Verified directly against the registry rather than taken on report: `core-controlplane` reported five; `CLOCK_SKEW_EXCESSIVE` and `TRUST_EPOCH_BEHIND_PEER` were also missing and unreported. | Not patched. The interim mapping onto the nearest registered codes (`AUTH.TRUST_EPOCH_ROLLBACK`, `AUTH.TRUST_HISTORY_FORKED`, `POLICY.EXPIRY.BUNDLE_EXPIRED`) is **defensible and accepted for now**, but it has a real cost: it loses the `CONTROL.CONSISTENCY.*` namespace ADR-0009 asked for, and ADR-0015 §11.2's whole forward-compatibility story is **prefix degradation** — an older client meeting `AUTH.*` where a consistency failure occurred degrades to the wrong diagnosis, which is the failure mode the closed-domain rule exists to prevent. The registry is **append-only**, so adding these breaks nothing and is the sanctioned evolution path — but it is still a `contracts/` change. **Needs approval.** |
| **W-12** | ruling | **Where does the L-CONTROL QUIC/TLS stack live?** ADR-0001 §11 item 3 requires QUIC + TLS 1.3 with mutual raw-public-key auth in the core, but CD-I2 permits a cryptographic dependency only in `twinvpn-crypto`, and `rustls` is one. `core-controlplane` was blocked on this and shipped the ladder policy without a production binding. | **Split by what is actually cryptographic.** `rustls` — the TLS implementation, the raw-public-key verifier, the cipher-suite policy, the `CryptoProvider` — belongs to **`twinvpn-crypto`**: those are exactly the decisions a reviewer auditing *what cryptography do we use* must read, which is CD-I2's stated purpose. `quinn` is a **transport protocol** implementation — framing, loss recovery, congestion control — that takes its cryptography from rustls and implements none itself, so **`twinvpn-cp-client` may declare it**, constructing its endpoint from configuration `twinvpn-crypto` vends. `twinvpn-core` wires the two. **Not the shell:** CB-1 puts code in a shell only when it must call a platform API with no stable C-callable form; QUIC is not one, and CB-1 says ambiguity resolves to the core. |

| **W-13** | **defect** | **No registered reason code covers "shutdown grace period expired with work still in flight."** `INTERNAL.INVARIANT_VIOLATED` would overclaim — grace expiry under load is not necessarily a defect. | Not patched, and **no code was invented**. Reported as the metric `twinvpn_shutdown_grace_expired_total` plus a WARN carrying the allowlisted attribute `twinvpn.outcome="grace_expired"`. Correct handling under the freeze. **Registry addition needs approval.** |
| **W-14** | gap | **`/metrics` is scraped by Prometheus directly, so the collector's *positive* allowlist is not in that path** — only a `labeldrop` denylist is. | The positive control therefore had to move to **emit time**, which is where it belongs anyway. Consequence to be aware of: ADR-0015 §9's five labels are the *entire* metric-label vocabulary, so per-dependency readiness detail lives in the `/readyz` JSON body rather than as a metric label. Widening that is a §9 conversation, not a code change. |
| **W-15** | gap | **`service.instance.id` is allowlisted by the collector but nothing in `docker-compose.yml` supplies it.** | `twinvpn-service-common` takes it as an explicit caller argument rather than silently reading a hostname or generating entropy — the right call, since an instance id invented per process makes fleet queries lie. **`infrastructure` to supply it in compose.** |
| **W-16** | gap | **ADR-0015 §11.5 names a `CRITICAL` log level; `tracing` has none.** | `TWINVPN_LOG_LEVEL=critical` is accepted and mapped to `ERROR`, so a value copied verbatim from the ADR configures the service rather than failing it. Documented at the mapping. Flag if a genuinely distinct level is wanted. |
| **W-17** | ruling | **`infra/README.md` §4.2 marks `TWINVPN_LIMITS_PATH`/`TWINVPN_REASON_CODES_PATH` "Required: no" but "if absent the service must refuse to start"** — apparently contradictory. | **Read as: the variable has a default; the resulting *file* must exist.** `service-common`'s `RegistryCheck::Required` goes further and asserts the mounted `limits.json` equals the compiled-in one and that `reason_codes.json`'s `registry_version` matches the build. **That stronger check is endorsed:** the bounds actually enforced are the compiled-in ones, so a service validating against a *different* mounted registry would pass its own tests and reject real traffic — a divergence that is invisible until production. |

| **W-18** | **DEFECT — the dominant finding of the wave** | **316 of the 514 reason codes named normatively across the Phase 1 corpus are absent from the frozen 201-code registry.** Measured by the integration lead over all of `docs/`, not extrapolated from one domain: three domains hit it independently (`core-controlplane` 8 `CONTROL.*`, `core-security` 14 `STORE.*`, `core-dataplane` ~50 across `POLICY`/`RELAY`/`NET`/`NAT`/`ROUTE`) and each saw only its own slice. By domain: `PLATFORM` 73, `RELAY` 47, `MGMT` 38, `NET` 35, `POLICY` 34, `DNS` 20, `UPDATE` 17, `RESOURCE` 16, `STORE` 14, `CONTROL` 10, `NAT` 5, `CRYPTO` 3, `AUTH` 2, `ROUTE` 1, `PROTO` 1. By source: `reliability.md` 52, ADR-0023 45, ADR-0022 36, ADR-0017 36, ADR-0006 33. Only **3** registered codes are never cited, so this is a one-directional shortfall, not a mismatch. | **Systemic, and Phase 1 predicted it.** `reliability.md` §3.5 says plainly that "a contribution is a request for registration, not an act of registration" — the requests were made across the corpus and the registry never granted them. The consequences are not cosmetic: `POLICY.LEAK.EGRESS_OBSERVED` is the **leak canary's own verdict**, `NET.PATH.DEAD_NO_ALTERNATE` is the most-taken transition on mobile, `RELAY.FLEET.UNREACHABLE` drives §6.3's global brake, and `NAT.CLASS_OBSERVED` is declared a *guaranteed observable*. Not patched — the registry is append-only so adding is the sanctioned path and breaks nothing, but it is a `contracts/` change of real size. **Every domain documents its substitution in a `SUBSTITUTIONS`/`UNREGISTERED` table with a tripwire test asserting the spelling is still absent, so registering a code fails the build and points at the line to delete.** That pattern, from `core-dataplane`, is now the standard. **Needs approval; W-5, W-6, W-11 and W-13 are instances of this.** |
| **W-19** | ruling | **Four transition rows name a reason code whose registered class contradicts the ADR's.** T29 sends `ROUTE.DRIFT_DETECTED`/`ROUTE.IFACE_MISSING` to `BLOCKED` though both are registered `PERSISTENT`, not `POLICY`; T11/T28 send `AUTH.DEVICE_REVOKED` (registered `POLICY`) to `FAILED`; T27's fallback names `NET.NO_USABLE_CANDIDATES` (`TRANSIENT`) for `FAILED`; §5.4's effective-MTU row names **no code at all**. ADR-0012 §11.9 and ADR-0010 §11.8 also class three codes differently from the registry. | **The registry wins for emission.** ADR-0015 §11.2 rule 4 is "the code is the contract"; a class the registry does not carry cannot be asserted by a receiver. `docs/reliability.md` §10.2's class rule is restated as the transition table already implies, rather than the four rows being bent to fit it. The divergences are recorded as part of W-18 and go with it to the amendment. |
| **W-20** | ruling | **`HealthState` is exported from `connection.proto` but not re-exported by `twinvpn-types`**, unlike `ConnectionState`, `PathClass` and `TrafficDisposition`, so `core-dataplane` modelled a second copy. | Two models of one frozen enum is the R-31 divergence in miniature. **`HealthState` moves to `twinvpn-types`** beside the other three and the duplicate is deleted. |

| **W-21** | **defect** | **`PairingOffer` — the deterministic-CBOR payload the C-B ceremony actually carries (ADR-0007 §7.4) — appears NOWHERE in `contracts/`.** It is named normatively in `architecture.md`, ADR-0007, ADR-0017 and ADR-0023 (which builds `S-67 HeadlessEnrolmentOffer` on it), and the contract set defines no message for it. | Not patched. Consequence, stated plainly: the ceremony-agnostic half of pairing is implemented and tested, but **C-B is not end-to-end either** until this payload has an owner and a contract. With W-22 below, that means *neither* channel authenticator is complete. **Needs approval.** |
| **W-22** | ruling (**correcting an earlier integration-lead ruling**) | **SPAKE2 (C-A) is unimplementable — no audited RFC 9382 P-256 Rust implementation exists** — but the integration lead's first scoping of the blast radius was **wrong**. It read ADR-0007 §7.4's table ("C-B where a camera and a screen exist; C-A otherwise") and concluded headless, CLI and cameraless pairing were blocked. | **`core-security` corrected it, with a citation, and the correction is verified.** ADR-0023 **EM-21** supersedes that reading: "the C-B ceremony **does not require a camera; it requires a confidential channel**… Headless targets therefore use C-B, unchanged, and do not fall back to C-A's ~2^29.9." ADR-0023 §11.16 records ADR-0007's confirmation, and **EM-22** gives four enrolment channels — terminal QR, text offer, reverse ceremony, first-boot provisioning — all C-B at 256 bits. **Corrected scope: headless, CLI and embedded pairing are NOT blocked.** What is blocked is the residue — a device with *no confidential out-of-band channel of any kind*, where the nine-digit code is the only remaining channel authenticator. The no-PAKE ruling itself stands: ADR-0018 DP-3 requires a published audit or a ledgered assurance argument, ADR-0007 N-17 requires RFC 9382 **P-256** parameters, the well-known `spake2` crate is Ed25519-group, and the crates claiming RFC 9382 are obscure and unaudited. Adding one would breach I2 and DP-3 worse than the gap. |
| **W-23** | **defect, corrected in-wave** | **`twinvpn-crypto` initially derived `TwinNetPSK` with invented HKDF parameters** — `salt` absent, `info = "TWINVPN-TWINNETPSK-v1" ‖ be64(epoch) ‖ sorted(device_ids)` — and documented the corpus as silent on them. ADR-0001 §7.5 does write an ellipsis, but carries a forward pointer to ADR-0007 §7.7, which specifies the derivation completely, and ADR-0007 §10 records the overrule in terms. | **Caught at integration review and corrected.** The shipped derivation is now exactly ADR-0007 §7.7: `salt = twinnet_id ‖ e (u64 BE)`, `info = "TwinVPN/psk2/v1"`, peer identities removed (`PairSecret(A,B)` already carries the pairwise binding by N-19). Pinned by a golden vector **independently recomputed by the integration lead from the ADR text**, plus a regression test naming the old wrong value. `EpochSeed` is now length-checked at exactly 32 bytes. Recorded because it is the wave's clearest instance of the rule it broke — **a specified derivation is not ours to improve** — and because it would have been fleet-wide irreversible: every peer pair's `psk2` at every epoch depends on it. |

| **W-24** | **DEFECT — the most consequential ABI finding** | **ADR-0018 §11.4's F-9 vtable has no `installed_ruleset` read-back.** ADR-0015 §11.6 rule 1 requires the `ProtectionAssertion` to be produced by **querying the enforcement layer**, and states the indicator is "a pure function of the most recent assertion, **never of the agent's belief**". §11.4 offers `set_ruleset` and no getter, so **across this ABI the assertion cannot be produced at all**. `current_generation` — named as "the recovery entry point" — is missing for the same reason. | Not patched. `twinvpn-ffi` returns a **typed refusal** so the indicator renders `UNKNOWN`, which is O-18's fail-safe direction; `Ok(None)` would read as "no ruleset installed" — the opposite of the truth, and the dangerous direction. **Needs ADR-0018 §11.4 amended, or an explicit acceptance that a vtable-only shell cannot assert protection.** |
| **W-25** | **defect** | **F-9 has no socket provider and no interface enumerator**, yet ADR-0018 §11.2 row 2.10 places *all* NAT traversal in the core "with sockets via the adapter", and `twinvpn-platform`'s trait requires both. | A Swift or Kotlin shell binding only this ABI **cannot do NAT traversal**. Not patched. Same amendment as W-24. |
| **W-26** | ruling | **ADR-0018 is internally inconsistent on `identity_agree`:** §11.6 lists "identity sign/**agree**/attest" as a seam direction; §11.4's F-9 struct omits it. Also W-7's three shell interfaces (`ElapsedClock`, `Entropy`, `BootIdSource`) have no vtable entries, and F-2's ownership rule means the core cannot read a shell buffer without asking. | **Four vtable additions approved**, all as `size`-field **minor** additions — none is an `abi_major` break, and each is justified in the header at its definition: `identity_agree` (following §11.6 over §11.4), `elapsed_millis` and `boot_id` (W-7), and `buf_bytes` (F-2). |
| **W-27** | ruling | **The launch `ProtocolEpoch` is stated by no Phase 1 document**, and VR-3 forbids inferring it from `core_version`. | **Confirmed as 1.** `twinvpn-core`'s `EPOCH_TABLE` declares `0.1.0 → 1..=1` and says so — which is VR-3's required form: **a table, not an inference**. |
| **W-28** | ruling (**accepted with a stated cost**) | **`SessionJournal` is sync; `Store::commit` is async over a multi-key transaction.** A `block_on` adapter deadlocks on the single-threaded iOS runtime by `Runtime::block_on`'s own documentation, and a per-record commit is the split ADR-0020 ST-12b names as a defect. | **Write-behind queue accepted for wave 1.** `CoreSessionJournal` queues; `StoreBridge::flush` drains into one transaction. **The cost is real and stated rather than hidden: a successful `persist` now means *queued*, not *durable*, and the most recent transition can be lost to a crash inside the flush window.** `docs/reliability.md` §6.5's resumption guarantee survives. **The proper fix is to make `SessionJournal` async in `twinvpn-session` — a wave-2 item, not a workaround to keep.** |
| **W-29** | **defect** | **`ControlPlaneStore::document_version` cannot be implemented.** `StoredDocumentMark` carries `issued_at_ms`/`refresh_after_ms`/`not_after_ms`, which live **inside the signed payload**; the store bridge holds octets verbatim and never decodes them (ST-13, W-4). | Returns `Ok(None)` rather than fabricating band boundaries that the client's staleness ladder would then run on. Correct: a fabricated freshness band is worse than an absent one. |
| **W-30** | gap | **`docs/testing-strategy.md` §3.2's address-realism rule is unsatisfiable as written.** It mandates RFC 6598 `100.64.0.0/10` for the carrier tier *and* forbids reusing TwinNet overlay prefixes for underlay — while `docs/networking.md` §2.1 makes the TwinNet IPv4 overlay `100.64.0.0/10`. Every CGNAT scenario violates one sentence. | **Implemented as the rule's *purpose* — disjointness against the allocation in force** (overlay `100.64/12`, carrier `100.80/12`), documented at the definition. The purpose is that a traversal test must not succeed by underlay/overlay collision, and that purpose is servable; the literal text is not. **Referred to `testing-strategy.md`'s owner.** |
| **W-31** | **DEFECT — P1, found in-wave** | **The first data packet of every tunnel was rejected as a replay.** `SendCounter::take_next()` yielded `0`; `ReplayWindow::new()` set `highest = 0` and treated bit 0 as seen, so `would_accept(0)` was `false` and `Tunnel::open(0, …)` returned `TunnelError::Replay`, class **FATAL**. Found by `test-engineering`'s cross-domain rig; **independently reproduced by the integration lead** against the public API. | **No tunnel could ever have carried its first packet.** Neither crate's own suite caught it because **every existing test starts at counter 1** — the replay window was thoroughly tested for the attack it defends against and untested at its own origin. The strongest argument in the wave for cross-domain testing: found within hours of a rig existing. Routed to `core-dataplane` with D-2 … D-5. |

Plus the capability-name-bound defect already recorded in §4.3, which remains the
only one with a live workaround in production code.
