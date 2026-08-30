# Implementation — ownership, layout, and the rules every agent works under

**Status:** authoritative for the production implementation waves. §§1–8 are
wave 1; **§9 is wave 2, the desktop platform runtimes**, and everything in §§1–7
still binds there.
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
| `shells/windows/` | `twinvpnsvc` + `twinvpnctl` (Rust) | `desktop-windows` (**wave 2**, §9) |
| `shells/macos/` | `twinvpnd` (Rust) + the NE packet-tunnel provider (Swift) | `desktop-macos` (**wave 2**, §9) |
| `shells/{ios,android,openwrt}/` | per-platform shells | wave 3 |
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

**Separate cargo workspaces, not one.** `core/`, `services/`, `shells/linux/`,
`lab/` and `tests/` are separate workspaces, and wave 2 adds `shells/windows/`
and `shells/macos/`. §11.12 makes `/core` "one cargo workspace"; the others are
separate *artifacts*, and separating the workspaces means no domain silently
acquires another's dependency graph, each domain owns its own manifests, and the
ADR-0018 T1 lints have an exact crate set to run over.

**The two wave-2 shell workspaces are deliberately NOT in the `Makefile`'s
`WORKSPACES`.** That variable drives the host build, the host test run and the
host clippy pass, and neither shell compiles for `x86_64-unknown-linux-gnu` — a
Windows service and a launchd daemon are not host artifacts. They are reached
instead by `make cross-check`, which is a **compile** proof for their targets and
says so at the target. Putting them in `WORKSPACES` would turn a true statement
about the host gate into a false one.

**The workspace manifests — `core/Cargo.toml`, `services/Cargo.toml`,
`shells/linux/Cargo.toml`, `lab/Cargo.toml`, `tests/Cargo.toml`,
`rust-toolchain.toml` and the `Makefile` — are owned by the integration lead.**
A crate's own `Cargo.toml` is owned by the crate's domain. This is the
shared-manifest rule from `CLAUDE.md`. Wave 2's two new shell workspace manifests
are created by their domains and pass to the integration lead on integration.

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
| `desktop-windows` | `shells/windows/`, `core/crates/twinvpn-platform-windows` | **wave 2.** Same CB-3 split as `desktop-linux` |
| `desktop-macos` | `shells/macos/`, `core/crates/twinvpn-platform-macos` | **wave 2.** Same CB-3 split. The Swift extension is inside `shells/macos/`, not a sibling domain — CB-2 is what keeps it thin |
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

One defect was raised under this procedure and is recorded in §4.3; Amendment 1
closed it. **Six amendments have now been taken**, the latest being **Amendment 6**
(2026-08-29), which closed §11.2 **G-20** — `pairing_offer.cddl`'s comments
asserted a point form that would rename every device in the fleet. No contract
defect is open.

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

### 4.3 CLOSED — `limits.json` capability name bound was stale

**The defect, as it stood.** `contracts/registry/limits.json` had
`capability.max_name_bytes = 24`, while
`contracts/registry/capabilities.json` had `capability_name_max_length = 32`,
`contracts/cddl/twinvpn/v1/capabilities.cddl` had `[a-z][a-z0-9_]{0,31}`, and the
registry itself contained `dns_config_dies_with_tunnel` — **27 bytes**. CF-6
amended [ADR-0014](../adr/ADR-0014-protocol-versioning-and-capability-negotiation.md)
N-11 from 24 to 32 and deliberately did **not** rename the token, because it is
`security_relevant` and a rename is an S-37 compatibility event.

`limits.json` exists to be *the* source for validators on untrusted input, so an
implementation that validated a capability advertisement against it would have
rejected a Phase-1-mandated token. That was a genuine contract defect, not an
inconvenience, and it is why every validator in the tree carried a hand-written
exception reading "32, not `limits.json`'s 24" with a pointer back to this
section.

**The close.** Amendment 1 to the freeze moved `capability.max_name_bytes` to
**32** under the §3 eight-step procedure — `contracts/FROZEN` lists it, and
`limits.json` carries the reasoning at the field itself. The registry, the
capability registry, the CDDL and ADR-0014 N-11 now all say 32.

**The residue, which is the part worth recording.** Closing the registry did not
close the workarounds: a defect that instructs every domain to hardcode a value
leaves that value hardcoded after the defect is gone, and nothing fails when it
does. Two kinds were found and both are fixed:

- **Stale prose** in `twinvpn-schema`, `twinvpn-tunnel`, `core/README.md` and
  `services/twinvpn-service-common/README.md`, still describing an open defect —
  including a doc-comment string in `twinvpn-schema/build.rs` that was
  *generated into* `limits_generated.rs`, so the wrong claim was reproduced into
  every build output.
- **One surviving code workaround**, a magic `32` in
  `twinvpn-crypto/src/statements/peerdocs.rs`, which would not have moved if the
  registry moved again.

`CAPABILITY_MAX_NAME_BYTES` is now **derived** from the registry rather than
pinned beside it, and `twinvpn-schema`'s `the_registry_agrees_with_itself`
asserts the constant and `limits.json` are the same number — so the next registry
change fails a test instead of silently disagreeing with a validator. That test
was written during the defect to fail *the moment* `contracts/` was amended,
which is what made this exception removable rather than permanent; it fired on
`registry_version` 2, exactly as intended.

**One clause in `contracts/` is now out of date, and stays that way.**
`contracts/registry/limits.json`'s `_max_name_bytes_note` still reads "Recorded
as an open contract defect in `ownership.md` §4.3 with a live workaround in
production code". There is no live workaround any more — `peerdocs.rs` was the
last one and it now derives the bound. The note is a frozen file and the clause
is history rather than an instruction, so it is **not** worth an amendment on its
own; fold the correction into the next one that opens `contracts/` for a real
reason.

**One asymmetry, ruled on rather than fixed.** `contracts/tests/` asserts
`capabilities.json`'s 32 and the CDDL's pattern, but never compares
`limits.json`'s `capability.max_name_bytes` to a literal — the bound is read
dynamically there, so that suite would pass at any value. The line is therefore
held Rust-side only. **It stays that way for now:** §3 names the contract tests
as frozen, and adding an assertion to them mid-gate is a contract change for a
property already asserted elsewhere. Recorded here so the asymmetry is a decision
someone can revisit at the next amendment, not an oversight.

**The rule this leaves.** Take the bound from
`twinvpn_schema::limits::CAPABILITY_MAX_NAME_BYTES`, never from a literal, and
cite ADR-0014 N-11 / CF-6 rather than this section. Nothing here is an open
instruction any more.

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

> **Amended by §9.2.** Half of that reasoning no longer holds. `cargo check` and
> `clippy` need no linker, so the `x86_64-pc-windows-msvc` and
> `aarch64-apple-darwin` rust-std install on this host and wave-2 Rust **is**
> built here, against the real platform crates, with `-D warnings`. What still
> holds exactly as written: nothing links, nothing runs, and no Swift compiles at
> all. §9.2 replaces the built/not-built binary with the four categories a wave-2
> report must keep apart, and a macOS builder and a Windows builder are still
> owed for the rows `cross-check` cannot reach.

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
| **W-5** | **defect** | **`evidence_truncated` is declared by no reason code.** `errors.proto` normatively requires a truncating emitter to append `{key:"evidence_truncated"}`, but no registry entry lists it, so a declared-set check rejects a message the schema requires. | **CLOSED.** `reason_codes.json` now declares `universal_evidence_fields`, so a declared-set check has a superset to consult and the hard-coded exemption at the constant is gone. `registry_version` 2. |
| **W-6** | **defect** | **No reason code declares an evidence key for an OS error number.** §6 rule 12 requires platform detail be carried as typed `Evidence`; `PLATFORM.ADAPTER_UNAVAILABLE` declares none and `PLATFORM.OS_UNSUPPORTED` declares only `os_version`, so `errno`/`syscall` evidence is dropped for exactly those codes. | **CLOSED.** `PLATFORM.ADAPTER_UNAVAILABLE` and `PLATFORM.OS_UNSUPPORTED` declare `errno`, `syscall`, `os_error_code` and `platform`, and every new `PLATFORM.*` code carries them. `registry_version` 2. |
| **W-7** | gap | **`ElapsedClock`, `Entropy` and `BootIdSource` are required shell interfaces that ADR-0018 §11.16 does not list.** `std` has no suspend-inclusive clock, and the platform calls need `unsafe` (DP-4) or `cfg(target_os)` (CB-3), so the shell must supply them. | Accepted as a real gap — and it is precisely the invisible-on-Linux-CI failure LC-8 warns about. Every shell brief names all three as required. **Should be recorded in ADR-0018 §11.16.** — **CLOSED: recorded as §11.16 (p)**, with the reason each is the shell's (CD-1's suspend-inclusive clock has no `std` equivalent; the calls behind the other two need `unsafe` or `cfg(target_os)`, which CB-3 puts outside the portable core) and with LC-8's failure mode named — all three have `std`-only stand-ins that work on Linux, so an omission is invisible on a Linux CI host and wrong on every target that suspends. Their F-9 entries already existed: `elapsed_millis` and `boot_id` were two of W-26's four approved additions, `os_csprng` was in the struct from the start. The gap was the *list*, not the mechanism. |
| **W-8** | gap | **`limits.json`'s `ports` section is a validation bound (`{min:1,max:65535}`), not a port assignment.** | Correct reading. Ports come from ADR-0002 §11.2 and ADR-0005 §11.4. The `:9090` admin listener is an infrastructure-domain decision, recorded as one. |
| **W-9** | gap | **Tier-2 `nat_class` is singular; "outcome by NAT class pair" needs two.** ADR-0015 §11.1's tuple names one; `docs/testing-strategy.md` §3.6 and the wave objective both speak of pairs — and a pair carries k-anonymity consequences. | A decision, not an oversight. Dashboards query `nat_class_local`/`nat_class_remote` with the divergence flagged in the panel. **Referred to ADR-0015's owner.** |
| **W-10** | gap | **ADR-0015 §9's router-class observability budget (< 512 KB) cites no `GC-*` class**, which under ADR-0018 BM-1 makes it an unqualified budget. | Transcribed as written in `build/budgets.toml` and flagged, rather than attributed to `GC-0` or `GC-0U` on a guess. **Referred to ADR-0015's owner.** |

| **W-11** | **defect** | **Eight `CONTROL.*` reason codes that ADR-0009 §11 names are absent from the frozen registry.** Present: `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR`, `CONTROL.STALENESS.DOCUMENT_STALE`, `CONTROL.STALENESS.TRUST_LIST_EXPIRED`. **Missing:** `CONTROL.CONSISTENCY.{VERSION_ROLLBACK_REJECTED, FORKED_HISTORY_DETECTED, CURSOR_INVALIDATED, CLOCK_SKEW_EXCESSIVE, SIGNATURE_UNVERIFIABLE}` and `CONTROL.STALENESS.{POLICY_GRANT_SUSPENDED, RELAY_SET_EXPIRED, TRUST_EPOCH_BEHIND_PEER}` — 8 of the 11 names ADR-0009 uses. Verified directly against the registry rather than taken on report: `core-controlplane` reported five; `CLOCK_SKEW_EXCESSIVE` and `TRUST_EPOCH_BEHIND_PEER` were also missing and unreported. | Not patched. The interim mapping onto the nearest registered codes (`AUTH.TRUST_EPOCH_ROLLBACK`, `AUTH.TRUST_HISTORY_FORKED`, `POLICY.EXPIRY.BUNDLE_EXPIRED`) is **defensible and accepted for now**, but it has a real cost: it loses the `CONTROL.CONSISTENCY.*` namespace ADR-0009 asked for, and ADR-0015 §11.2's whole forward-compatibility story is **prefix degradation** — an older client meeting `AUTH.*` where a consistency failure occurred degrades to the wrong diagnosis, which is the failure mode the closed-domain rule exists to prevent. The registry is **append-only**, so adding these breaks nothing and is the sanctioned evolution path — but it is still a `contracts/` change. **Needs approval.** — **CLOSED by Amendment 1**, which registered all eight, and this row's "Not patched" outlived that by three amendments. Verified in the registry rather than assumed: `CONTROL.CONSISTENCY.{VERSION_ROLLBACK_REJECTED, FORKED_HISTORY_DETECTED, CURSOR_INVALIDATED, CLOCK_SKEW_EXCESSIVE, SIGNATURE_UNVERIFIABLE}` and `CONTROL.STALENESS.{POLICY_GRANT_SUSPENDED, RELAY_SET_EXPIRED, TRUST_EPOCH_BEHIND_PEER}` are all present. **The interim `AUTH.*` mapping is still live in `twinvpn-cp-client` and `twinvpn-store`, and that half is NOT closed** — the prefix degradation this row describes is still what an older client sees. Carried forward as its own item; §11 G-2 is the precedent for how a stale substitution gets found and removed. |
| **W-12** | ruling | **Where does the L-CONTROL QUIC/TLS stack live?** ADR-0001 §11 item 3 requires QUIC + TLS 1.3 with mutual raw-public-key auth in the core, but CD-I2 permits a cryptographic dependency only in `twinvpn-crypto`, and `rustls` is one. `core-controlplane` was blocked on this and shipped the ladder policy without a production binding. | **Split by what is actually cryptographic.** `rustls` — the TLS implementation, the raw-public-key verifier, the cipher-suite policy, the `CryptoProvider` — belongs to **`twinvpn-crypto`**: those are exactly the decisions a reviewer auditing *what cryptography do we use* must read, which is CD-I2's stated purpose. `quinn` is a **transport protocol** implementation — framing, loss recovery, congestion control — that takes its cryptography from rustls and implements none itself, so **`twinvpn-cp-client` may declare it**, constructing its endpoint from configuration `twinvpn-crypto` vends. `twinvpn-core` wires the two. **Not the shell:** CB-1 puts code in a shell only when it must call a platform API with no stable C-callable form; QUIC is not one, and CB-1 says ambiguity resolves to the core. |

| **W-13** | **defect** | **No registered reason code covers "shutdown grace period expired with work still in flight."** `INTERNAL.INVARIANT_VIOLATED` would overclaim — grace expiry under load is not necessarily a defect. | **CLOSED — and the answer is that the condition should not have a code.** The search for an owning ADR found there was none: ADR-0002 §11.7 rule 1 fixed what a server *announces* at drain start and said nothing about the deadline arriving; ADR-0015 C-5 points the other way, ADR-0016 is client-side, ADR-0022 is mobile lifecycle, and ADR-0005 §8 / `reliability.md` §8.3 govern the *relay's* drain, a different condition. **ADR-0002 §11.7 rule 5 (amended 2026-08-28) now owns it**, because that ADR already owns the drain and the 120 s default. The rule refuses a `reason_code` on the merits rather than for want of one: a `reason_code` is a fact reported to a peer about that peer's request, and by grace expiry the affected requests are being abandoned on a connection that is closing — there is nobody left to tell, so a registered code would be one no receiver could ever act on. It also **explicitly forbids `INTERNAL.INVARIANT_VIOLATED`**, whose registry entry reads "EVERY OCCURRENCE IS A DEFECT": expiry under genuine load is the bound working, and reporting it that way would page an engineer for a correct outcome and devalue the one code that depends on never being cried wolf. Required reporting is the metric pair `twinvpn_shutdown_grace_expired_total` / `twinvpn_shutdown_inflight_at_deadline` plus one WARN carrying `twinvpn.outcome = "grace_expired"` and the count — which is what `services/twinvpn-service-common/src/shutdown.rs` already emitted. **No contracts amendment was needed**; the registry is untouched. |
| **W-14** | gap | **`/metrics` is scraped by Prometheus directly, so the collector's *positive* allowlist is not in that path** — only a `labeldrop` denylist is. | The positive control therefore had to move to **emit time**, which is where it belongs anyway. Consequence to be aware of: ADR-0015 §9's five labels are the *entire* metric-label vocabulary, so per-dependency readiness detail lives in the `/readyz` JSON body rather than as a metric label. Widening that is a §9 conversation, not a code change. |
| **W-15** | gap | **`service.instance.id` is allowlisted by the collector but nothing in `docker-compose.yml` supplies it.** | `twinvpn-service-common` takes it as an explicit caller argument rather than silently reading a hostname or generating entropy — the right call, since an instance id invented per process makes fleet queries lie. **`infrastructure` to supply it in compose.** |
| **W-16** | gap | **ADR-0015 §11.5 names a `CRITICAL` log level; `tracing` has none.** | `TWINVPN_LOG_LEVEL=critical` is accepted and mapped to `ERROR`, so a value copied verbatim from the ADR configures the service rather than failing it. Documented at the mapping. Flag if a genuinely distinct level is wanted. |
| **W-17** | ruling | **`infra/README.md` §4.2 marks `TWINVPN_LIMITS_PATH`/`TWINVPN_REASON_CODES_PATH` "Required: no" but "if absent the service must refuse to start"** — apparently contradictory. | **Read as: the variable has a default; the resulting *file* must exist.** `service-common`'s `RegistryCheck::Required` goes further and asserts the mounted `limits.json` equals the compiled-in one and that `reason_codes.json`'s `registry_version` matches the build. **That stronger check is endorsed:** the bounds actually enforced are the compiled-in ones, so a service validating against a *different* mounted registry would pass its own tests and reject real traffic — a divergence that is invisible until production. |

| **W-18** | **DEFECT — the dominant finding of the wave** | **316 of the 514 reason codes named normatively across the Phase 1 corpus are absent from the frozen 201-code registry.** Measured by the integration lead over all of `docs/`, not extrapolated from one domain: three domains hit it independently (`core-controlplane` 8 `CONTROL.*`, `core-security` 14 `STORE.*`, `core-dataplane` ~50 across `POLICY`/`RELAY`/`NET`/`NAT`/`ROUTE`) and each saw only its own slice. By domain: `PLATFORM` 73, `RELAY` 47, `MGMT` 38, `NET` 35, `POLICY` 34, `DNS` 20, `UPDATE` 17, `RESOURCE` 16, `STORE` 14, `CONTROL` 10, `NAT` 5, `CRYPTO` 3, `AUTH` 2, `ROUTE` 1, `PROTO` 1. By source: `reliability.md` 52, ADR-0023 45, ADR-0022 36, ADR-0017 36, ADR-0006 33. Only **3** registered codes are never cited, so this is a one-directional shortfall, not a mismatch. | **Systemic, and Phase 1 predicted it.** `reliability.md` §3.5 says plainly that "a contribution is a request for registration, not an act of registration" — the requests were made across the corpus and the registry never granted them. The consequences are not cosmetic: `POLICY.LEAK.EGRESS_OBSERVED` is the **leak canary's own verdict**, `NET.PATH.DEAD_NO_ALTERNATE` is the most-taken transition on mobile, `RELAY.FLEET.UNREACHABLE` drives §6.3's global brake, and `NAT.CLASS_OBSERVED` is declared a *guaranteed observable*. Not patched — the registry is append-only so adding is the sanctioned path and breaks nothing, but it is a `contracts/` change of real size. **Every domain documents its substitution in a `SUBSTITUTIONS`/`UNREGISTERED` table with a tripwire test asserting the spelling is still absent, so registering a code fails the build and points at the line to delete.** That pattern, from `core-dataplane`, is now the standard. **CLOSED by `registry_version` 2** (§9.6 X-1, 2026-08-28): 201 → 454 codes, every substitution table emptied and every tripwire inverted rather than deleted. W-5, W-6 and W-11 closed with it; W-13 partly, because no ADR names its condition. |
| **W-19** | ruling | **Four transition rows name a reason code whose registered class contradicts the ADR's.** T29 sends `ROUTE.DRIFT_DETECTED`/`ROUTE.IFACE_MISSING` to `BLOCKED` though both are registered `PERSISTENT`, not `POLICY`; T11/T28 send `AUTH.DEVICE_REVOKED` (registered `POLICY`) to `FAILED`; T27's fallback names `NET.NO_USABLE_CANDIDATES` (`TRANSIENT`) for `FAILED`; §5.4's effective-MTU row names **no code at all**. ADR-0012 §11.9 and ADR-0010 §11.8 also class three codes differently from the registry. | **The registry wins for emission.** ADR-0015 §11.2 rule 4 is "the code is the contract"; a class the registry does not carry cannot be asserted by a receiver. `docs/reliability.md` §10.2's class rule is restated as the transition table already implies, rather than the four rows being bent to fit it. The divergences are recorded as part of W-18 and go with it to the amendment. |
| **W-20** | ruling | **`HealthState` is exported from `connection.proto` but not re-exported by `twinvpn-types`**, unlike `ConnectionState`, `PathClass` and `TrafficDisposition`, so `core-dataplane` modelled a second copy. | Two models of one frozen enum is the R-31 divergence in miniature. **`HealthState` moves to `twinvpn-types`** beside the other three and the duplicate is deleted. |

| **W-21** | **defect** | **`PairingOffer` — the deterministic-CBOR payload the C-B ceremony actually carries (ADR-0007 §7.4) — appears NOWHERE in `contracts/`.** It is named normatively in `architecture.md`, ADR-0007, ADR-0017 and ADR-0023 (which builds `S-67 HeadlessEnrolmentOffer` on it), and the contract set defines no message for it. | Not patched. Consequence, stated plainly: the ceremony-agnostic half of pairing is implemented and tested, but **C-B is not end-to-end either** until this payload has an owner and a contract. With W-22 below, that means *neither* channel authenticator is complete. **Needs approval.** — **APPROVED and CLOSED as Amendment 4** (2026-08-29): `contracts/cddl/twinvpn/v1/pairing_offer.cddl`, six `pairing` bounds at limits `registry_version` 3, and the contract tests. §11 **G-9** carries the disposition and the proposal is at `docs/implementation/w21-pairing-offer-amendment.md`. **What is closed is the contract, not the ceremony:** the payload is nameable and bounded, and every consumer of it — the `twinvpn-schema` bounds, `twinvpn-crypto`'s decoder, the four `pair.*` refusals that are still refusals, the E1/E2 renderers — is owed. **Finding F-1 is open and is an ADR owner's:** the offer measures 377 bytes and ADR-0023 EM-22 E1's declared 71-column terminal admits 321 at EC level L, so the product's default enrolment channel does not fit its own payload. |
| **W-22** | ruling (**correcting an earlier integration-lead ruling**) | **SPAKE2 (C-A) is unimplementable — no audited RFC 9382 P-256 Rust implementation exists** — but the integration lead's first scoping of the blast radius was **wrong**. It read ADR-0007 §7.4's table ("C-B where a camera and a screen exist; C-A otherwise") and concluded headless, CLI and cameraless pairing were blocked. | **`core-security` corrected it, with a citation, and the correction is verified.** ADR-0023 **EM-21** supersedes that reading: "the C-B ceremony **does not require a camera; it requires a confidential channel**… Headless targets therefore use C-B, unchanged, and do not fall back to C-A's ~2^29.9." ADR-0023 §11.16 records ADR-0007's confirmation, and **EM-22** gives four enrolment channels — terminal QR, text offer, reverse ceremony, first-boot provisioning — all C-B at 256 bits. **Corrected scope: headless, CLI and embedded pairing are NOT blocked.** What is blocked is the residue — a device with *no confidential out-of-band channel of any kind*, where the nine-digit code is the only remaining channel authenticator. The no-PAKE ruling itself stands: ADR-0018 DP-3 requires a published audit or a ledgered assurance argument, ADR-0007 N-17 requires RFC 9382 **P-256** parameters, the well-known `spake2` crate is Ed25519-group, and the crates claiming RFC 9382 are obscure and unaudited. Adding one would breach I2 and DP-3 worse than the gap. |
| **W-23** | **defect, corrected in-wave** | **`twinvpn-crypto` initially derived `TwinNetPSK` with invented HKDF parameters** — `salt` absent, `info = "TWINVPN-TWINNETPSK-v1" ‖ be64(epoch) ‖ sorted(device_ids)` — and documented the corpus as silent on them. ADR-0001 §7.5 does write an ellipsis, but carries a forward pointer to ADR-0007 §7.7, which specifies the derivation completely, and ADR-0007 §10 records the overrule in terms. | **Caught at integration review and corrected.** The shipped derivation is now exactly ADR-0007 §7.7: `salt = twinnet_id ‖ e (u64 BE)`, `info = "TwinVPN/psk2/v1"`, peer identities removed (`PairSecret(A,B)` already carries the pairwise binding by N-19). Pinned by a golden vector **independently recomputed by the integration lead from the ADR text**, plus a regression test naming the old wrong value. `EpochSeed` is now length-checked at exactly 32 bytes. Recorded because it is the wave's clearest instance of the rule it broke — **a specified derivation is not ours to improve** — and because it would have been fleet-wide irreversible: every peer pair's `psk2` at every epoch depends on it. |

| **W-24** | **DEFECT — the most consequential ABI finding** | **ADR-0018 §11.4's F-9 vtable has no `installed_ruleset` read-back.** ADR-0015 §11.6 rule 1 requires the `ProtectionAssertion` to be produced by **querying the enforcement layer**, and states the indicator is "a pure function of the most recent assertion, **never of the agent's belief**". §11.4 offers `set_ruleset` and no getter, so **across this ABI the assertion cannot be produced at all**. `current_generation` — named as "the recovery entry point" — is missing for the same reason. | Not patched. `twinvpn-ffi` returns a **typed refusal** so the indicator renders `UNKNOWN`, which is O-18's fail-safe direction; `Ok(None)` would read as "no ruleset installed" — the opposite of the truth, and the dangerous direction. **Needs ADR-0018 §11.4 amended, or an explicit acceptance that a vtable-only shell cannot assert protection.** — **CLOSED, and it needed neither.** F-9's first field is `uint32_t size` precisely so entries may be APPENDED without an `abi_major` bump, and W-26 had already approved four additions on those terms, so `installed_ruleset` and `current_generation` join the same way: `TW_ABI_MINOR` 1 → 2, nothing removed, no signature changed, no existing entry moved. A shell built against minor 1 declares a shorter struct and the core reads only the prefix its `size` covers. The `ProtectionAssertion` is now producible across this ABI, which is what ADR-0015 §11.6 rule 1 requires and what the typed refusal could not deliver. §11 **G-8** carries the disposition. |
| **W-25** | **defect → ruled, see §11.2 G-11** | **F-9 has no socket provider and no interface enumerator**, yet ADR-0018 §11.2 row 2.10 places *all* NAT traversal in the core "with sockets via the adapter", and `twinvpn-platform`'s trait requires both. | Originally: *"A Swift or Kotlin shell binding only this ABI **cannot do NAT traversal**. Not patched. Same amendment as W-24."* **That road was taken and does not lead here — see [G-11](#112-gate-findings-register).** The socket half **must not** become F-9 entries: a datagram is the datapath, PB-1 budgets zero FFI crossings per packet and PB-4 prices the split at **0 ns/packet** on four targets, against ≈ 47 500 datagrams/s per direction at PB-3's desktop userspace gate. The interface half **would** be admissible at control rate and is blocked instead on F-8 — `contracts/` holds no message that can carry `InterfaceFacts` without reinstating the `repeated IPPrefix` defect W-39 records, so it stops at a §3 ask. **And the premise is too wide:** no shell in the tree binds only this vtable — all five host the Rust adapter through a per-platform bridge (§10.4, generalised by X-7). What ADR-0018 owes is row 2.10's *wording*, not F-9 entries. |
| **W-26** | ruling | **ADR-0018 is internally inconsistent on `identity_agree`:** §11.6 lists "identity sign/**agree**/attest" as a seam direction; §11.4's F-9 struct omits it. Also W-7's three shell interfaces (`ElapsedClock`, `Entropy`, `BootIdSource`) have no vtable entries, and F-2's ownership rule means the core cannot read a shell buffer without asking. | **Four vtable additions approved**, all as `size`-field **minor** additions — none is an `abi_major` break, and each is justified in the header at its definition: `identity_agree` (following §11.6 over §11.4), `elapsed_millis` and `boot_id` (W-7), and `buf_bytes` (F-2). |
| **W-27** | ruling | **The launch `ProtocolEpoch` is stated by no Phase 1 document**, and VR-3 forbids inferring it from `core_version`. | **Confirmed as 1.** `twinvpn-core`'s `EPOCH_TABLE` declares `0.1.0 → 1..=1` and says so — which is VR-3's required form: **a table, not an inference**. |
| **W-28** | ruling (**accepted with a stated cost**) | **`SessionJournal` is sync; `Store::commit` is async over a multi-key transaction.** A `block_on` adapter deadlocks on the single-threaded iOS runtime by `Runtime::block_on`'s own documentation, and a per-record commit is the split ADR-0020 ST-12b names as a defect. | **Write-behind queue accepted for wave 1.** `CoreSessionJournal` queues; `StoreBridge::flush` drains into one transaction. **The cost is real and stated rather than hidden: a successful `persist` now means *queued*, not *durable*, and the most recent transition can be lost to a crash inside the flush window.** `docs/reliability.md` §6.5's resumption guarantee survives. **The proper fix is to make `SessionJournal` async in `twinvpn-session` — a wave-2 item, not a workaround to keep.** |
| **W-29** | **defect** | **`ControlPlaneStore::document_version` cannot be implemented.** `StoredDocumentMark` carries `issued_at_ms`/`refresh_after_ms`/`not_after_ms`, which live **inside the signed payload**; the store bridge holds octets verbatim and never decodes them (ST-13, W-4). | Returns `Ok(None)` rather than fabricating band boundaries that the client's staleness ladder would then run on. Correct: a fabricated freshness band is worse than an absent one. |
| **W-30** | gap | **`docs/testing-strategy.md` §3.2's address-realism rule is unsatisfiable as written.** It mandates RFC 6598 `100.64.0.0/10` for the carrier tier *and* forbids reusing TwinNet overlay prefixes for underlay — while `docs/networking.md` §2.1 makes the TwinNet IPv4 overlay `100.64.0.0/10`. Every CGNAT scenario violates one sentence. | **Implemented as the rule's *purpose* — disjointness against the allocation in force** (overlay `100.64/12`, carrier `100.80/12`), documented at the definition. The purpose is that a traversal test must not succeed by underlay/overlay collision, and that purpose is servable; the literal text is not. **Referred to `testing-strategy.md`'s owner.** |
| **W-31** | **DEFECT — P1, found in-wave** | **The first data packet of every tunnel was rejected as a replay.** `SendCounter::take_next()` yielded `0`; `ReplayWindow::new()` set `highest = 0` and treated bit 0 as seen, so `would_accept(0)` was `false` and `Tunnel::open(0, …)` returned `TunnelError::Replay`, class **FATAL**. Found by `test-engineering`'s cross-domain rig; **independently reproduced by the integration lead** against the public API. | **No tunnel could ever have carried its first packet.** Neither crate's own suite caught it because **every existing test starts at counter 1** — the replay window was thoroughly tested for the attack it defends against and untested at its own origin. The strongest argument in the wave for cross-domain testing: found within hours of a rig existing. Routed to `core-dataplane` with D-2 … D-5. |

| **W-32** | **defect** | **A device authenticates an inbound relay frame it should never have been sent.** `device_may_send` refuses `BOUND`/`DRAIN`/`RELAY_STATUS` on the *send* path, but `InboundFrame::verify` never checks direction — so a device accepts and **authenticates** a `BIND` or `CAPS` arriving *from* the relay. Not a MAC forgery; a **confused-deputy surface** on a compromised or misbehaving relay. | Routed to `core-dataplane`. Direction belongs on the receive side too. |
| **W-33** | gap | **The ADR-0005 §9.1 golden vector is replicated as source in four places and shared as a constant in none.** `twinvpn-crypto`'s copy is `#[cfg(test)]` and therefore unimportable, so each side fails separately and a regeneration in one place does not fail the others. | The vector is the only thing making the two ends of the relay wire provably agree; four independent copies is the shape that lets them drift. Routed to `core-security` to expose it importably. |
| **W-34** | gap | **`SessionRuntime` re-arms only on a state *change*.** A timer that fires and matches no transition row leaves the state with that deadline consumed and nothing re-arming it. | Not reachable from a driver that delivers `EV_CANDIDATES_READY`, so recorded rather than tripwired — but it is the shape of an unbounded state, which `docs/reliability.md` §4.4 bounds deliberately for every transient state. Routed to `core-composition`. |
| **W-35** | amendment to **W-28** | **The write-behind journal delays *deletions* too.** An unflushed `forget` returns `Ok` and leaves the record durable, so a restarted client **resumes a peer the caller believed it had dropped**. | Measured by `test-engineering`'s chaos suite, which also confirmed W-28's acceptance holds in the direction it was granted (loss bounded to the most recent transition; the `Session` survives; `resume_state()` is still `RECONNECTING`). This is the opposite direction with a different consequence, and it strengthens the case that making `SessionJournal` async is a wave-2 requirement rather than an improvement. |

| **W-36** | **defect — the lints contradict each other** | **No location in the tree may legally read a platform clock.** CB-3 and DP-4 put platform syscalls in `twinvpn-platform-*`; **CD-3's deny-list denies `clock_gettime` and `getrandom` there too**. Verified: `checks.rs` has `cb3_crate_is_exempt` for `target_os` and **no equivalent for the CD-3 needles**. The shells are outside the lint but carry `#![forbid(unsafe_code)]`. | `desktop-linux` reached `CLOCK_BOOTTIME` via `/proc/uptime` and entropy via `/dev/urandom` — correct, and 10 ms quantised where a syscall is not. **Fix: one exemption in `checks.rs` for `twinvpn-platform-*`, exactly as `cb3_crate_is_exempt` already does.** Routed to `core-foundation`. |
| **W-37** | **defect** | **The seam cannot express Linux kernel offload.** ADR-0018 §11.2 row 2.3 says the core *programs the kernel WireGuard module* on Linux, and `Datapath::KernelOffload` exists to declare it — but `TunnelDevice` has **no method carrying a WireGuard peer, private key, endpoint, allowed-IP set or keepalive**. | A Linux adapter can **declare** offload and cannot **achieve** it. `desktop-linux` reports `Datapath::Userspace` honestly; declaring the other "would produce a tunnel that carries nothing and calls itself offloaded". **Needs ADR-0018 §11.4/§11.6 amended.** |
| **W-38** | **defect** | **`MgmtEnvelope` is in no contract.** ADR-0017 §11.3 specifies it as protobuf and prints the `.proto`; `contracts/` has no `mgmt.proto`. OQ-2 excluded one so the MI could not acquire an independent vocabulary — which worked — but leaves the **carriage** unspecified. Same class as **W-21** (`PairingOffer`). | §11.3's field list carried verbatim over B5 JSON, so a later `mgmt.proto` is a re-encoding rather than a redesign. |
| **W-39** | **defect** | **`fe80::/10` is unrepresentable as an `IpPrefix`.** `V6Addr::new` requires a zone on link-local; `IpPrefix::new` rejects any zone. **Both rules are individually right**; their conjunction silently drops link-local prefixes from `InterfaceFacts.addresses`. | Enforcement is unaffected (`nft` emits the literal). Pinned as a test. |
| **W-40** | **defect** (W-18 instance) | **No `PlatformError` is retryable under the frozen registry.** `Transient` → `PLATFORM.ADAPTER_UNAVAILABLE` → class `PERSISTENT`, so `is_retryable()` is `false` for `EAGAIN`. There is no `TRANSIENT`-class `PLATFORM.*` code to name. | Pinned as a test. Goes with W-18 to the amendment. |
| **W-41** | gap — **decided in wave 2, implemented 2026-08-29** | **The CLI binary is `twinvpnctl`; ADR-0016 §11.2 and ADR-0017 §11.12 both name it `twinvpn`**, and ADR-0023 EM-42's rendered next actions instruct the user to `run 'twinvpn peer disconnect …'` — **naming a command not installed under that name**. | A user-facing next action that names a nonexistent binary is the R-31 defect class in its most literal form. **Settled by §9.5 D-1, not by this row**: the cargo target stays `twinvpnctl`, the package installs it as `twinvpn`, `twinvpnctl` stays a compatibility alias. This row read "needs a decision" long after one was taken — corrected as §11.4 **D-8**. **CLOSED**: the packaging installs the alias, `clap`'s `bin_name` renders `twinvpn`, and EM-42's next action now names a command the package installs. |
| **W-42** | gap | **Two numbers the corpus never pins:** the routing `fwmark` (table 52 is fixed; the mark is not) and the LAN-discovery multicast group/port. | `0x7677` chosen and **recorded as a decision**; the multicast values are literal placeholders and marked as such rather than presented as derived. |


### Review findings (`security-review` and `final-review`, post-integration)

Ranked by consequence. **S-1/D1 is the root of most of the rest.**

| # | Severity | Finding | Owner |
|---|---|---|---|
| **R-1** | **CRITICAL** | **`Core::submit` executes nothing.** It checks poison, catalogue, ADR-0008 precondition and `is_implemented`, bumps `generation`, publishes `CommandCompleted { result: Vec::new() }`, returns `Ok`. **Verified: it references zero component crates.** 47 `CoreCommand` variants, 14 in `UNIMPLEMENTED`, **33 — `session.connect` among them — report success having called nothing.** `core/README.md` §6's "executes a subset" is false and was relayed upward on that authority. | `core-composition` |
| **R-2** | **CRITICAL** | **Nine core crates are compiled but never composed.** `twinvpn-core/src` names neither `twinvpn_trust` nor `twinvpn_crypto` outside doc prose. Never entered: `trust`, `tunnel`, `path`, `relay-client`, `route`, `dns`, `enforce`, `gateway`, and `crypto`'s `cose`/`noise`/`psk`/`prologue`/`transcript`/`binding`/`statements`. **54 public functions in `crypto`+`trust` have zero references outside their own crate**, including the whole Noise driver, `confirm_transcript` (ADR-0001 §7.3 D2), the S-37 monotone floor, and `verify_succession_pair` (ADR-0007 N-21). Consequence: `crypto` and `tunnel` each hold a complete independent prologue/replay/floor implementation with **two incompatible `Prologue` types**, and nothing would ever have forced them to meet. | `core-composition` |
| **R-3** | **CRITICAL** | **FFI: the vtable `size` field is honoured *after* the struct is dereferenced.** `vtable.rs:207` does `let v = unsafe { *ptr }` — reading all 24 fn-pointer fields — then checks `size` at `:208`. `twinvpn.h:139` promises "the core reads only the entries the declared size covers"; it is not implemented. A wave-2 shell built against an older header passes a smaller struct, the core reads past it, and any non-zero word becomes `Some(fn)` **and is called**. The existing test builds a full-size Rust struct with `size: 1`, so it passes regardless. | `core-composition` |
| **R-4** | **HIGH** | **The control plane verifies eight signatures and never reads what it verified.** No signed statement payload is decoded anywhere in `domain/` (verified: the only `decode_` hits are `decode_device` on its own stored record). `revoke` takes `target` from `req.target_device_id` — the **unsigned wire field** — so replaying any Owner-signed revocation with a different wire target **revokes an arbitrary device**. `put_policy` advances the floor from the wire `policy_version`, so an old signed bundle claiming a higher version is a **signed policy rollback**, and `u64::MAX` permanently bricks future policy. Blocked today only by `RefuseUnidentified`. | `control-plane`, `core-controlplane` |
| **R-5** | **HIGH** | **The relay authenticates by source address and authorizes by nothing.** `pump.rs:225` `forward_data` never receives `from`; the pair is resolved from `frame.flow_id()` alone and `HalfFlow.peer` is compared nowhere. `FlowId` is a sequential enumerable `u32`. One valid token lets an attacker advance a victim's replay window (killing the flow with one packet), reflect bytes to any bound peer, and charge the victim's quota. Blocked today only by the absent leg handshake. | `relay-plane` |
| **R-6** | **HIGH** | **`set_ruleset(Blocked)` installs a table that drops nothing** and atomically replaces one that did. The synthetic contract's `routes` is unconditionally empty, and the drop rules are loops over those sets. Both chains are `policy accept`. The read-back parses the counter *object*, not the rules, so the assertion still reports `Protected`. | `desktop-linux` |
| **R-7** | **HIGH** | **The boot artifact is the only enforcement that exists, and it governs only the overlay prefixes.** Because `apply` has no caller (R-2), the boot table is never replaced. On a full-tunnel host all Internet traffic egresses untunneled from boot, indefinitely. **I3 does not hold for the composed Linux product.** | `desktop-linux`; scope question for ADR-0012's owner |
| **R-8** | **HIGH** | **An Owner anchor advance does not remove the old root's delegations.** `offer_anchor` replaces the anchor and touches nothing else; `remove_delegation` has no caller. A compromised OSK delegated under the old anchor still authorizes after the Owner rotates the root — ADR-0007 §7.5's phrase-compromise recovery failing. | `core-security` |
| **R-9** | **HIGH** | **Nine secret-bearing types leak through derived `Debug`** — `Record.value` ("the plaintext", in the composed path), `RelayTokenRecord.octets`, `KeySource::Pkcs8Der`, `Action::Send { to, datagram }` (peer address *and* relayed payload in one value), `PresentedToken.cose_sign1`. The last has a tripwire asserting its rendering omits `"epoch"/"quota"/…` — which **passes because `Vec<u8>` renders as digits**, while the complete replayable token sits in the output. A guard that reports success. | multiple; one source-scanning lint recommended |
| **R-10** | **DEFECT** | **Nothing in production opens the vault.** `StoreBridge::new` is constructed only in `tests/chaos/`; `twinvpnd` has no `twinvpn-store` dependency. S-12/S-15/S-27/S-30/S-37 are memory-only, so W-28's crash window is **the entire process lifetime**. Two domains each documented that the *other* end was wired. | `core-composition` + `desktop-linux` |
| **R-11** | **DEFECT** | **A relay tells a device to fail over when the device's own table says not to.** `PairUnmatched` ("the peer has not arrived") collapses onto `RELAY.CAPACITY_REJECTED` → `Attribution::Capacity` → fail over, short-circuiting the `PeerLoss` arm documented "Do not fail over". Fires at 30 s pending-slot expiry, so two peers arriving >30 s apart each fail the other over — a rendezvous livelock that worsens with fleet size. | `relay-plane` + `core-dataplane` |
| **R-12** | **DEFECT** | **The shipped verifier hardcodes `not_before_ms: 0`** while the adjacent line decodes `not_after_ms` from the payload. The nbf tests exercise `ScriptedVerifier`, which is `#[cfg(test)]` — **tested thoroughly, against the wrong object.** | `control-plane` |
| **R-13** | **DEFECT** | **No test could link a client crate and a server crate.** `tests/Cargo.toml` declared only `core/`. This is the shared cause of every cross-artifact defect the wave paid for. **Fixed by the integration lead**: `tests/` now links `services/*` and `shells/linux`; no production crate gained another domain's graph. | integration lead — **done** |
| **R-14** | **DEFECT** | **W-20's disposition was never executed and the duplication grew.** Three hand-written `HealthState` models in two workspaces, each re-encoding ADR-0006 §11.2's deltas as literals, each with **four** variants where the frozen enum has five (omitting the proto3 zero value an unset field decodes to). | `core-foundation`, `relay-plane` |
| **R-15** | **DEFECT** | **The CLI renders catalogue *keys* to the user.** `twinvpnctl` links `twinvpn-diag` and never calls its resolver, so a diagnostic reads `reason.proto_unparseable_envelope.summary` / `Next: reason.…next_action`. The tell that it is a defect: **an unknown code renders better than a known one**, because the unknown-code fallback emits a real sentence. `twinvpnd` also hardcodes `next_action_key: None` on the MI wire, so any other MI client gets `null`. | `desktop-linux` |
| **R-16** | **DEFECT** | `contained_on` takes `fallback` by value, so `tw_core_next_event` and `tw_core_submit` each **leak a `Box<TwBuf>` per call** on the success path — an unbounded heap leak on the shell's blocking event loop, in a long-lived privileged daemon. | `core-composition` |

### Dispositions

Applied in one pass, with the finding text above left unedited so the record of
what was found stays readable beside what was done.

| # | Disposition |
|---|---|
| **R-1** | **Superseded.** `Core::submit` executes: `execute::connect` gathers on the platform, drives T01→T03/T04 through the real §4.5 table, admits into the candidate ledger, schedules a race, probes and persists. The register row describes a revision `core/crates/twinvpn-core/tests/command_path.rs` already falsifies. What remained of it is item 2 below. |
| **R-2 / R-7** | **Fixed** — `core/crates/twinvpn-core/src/enforce.rs`, CB-6's second clause and the only place in the tree that holds a `RoutePlan`, a `Dnspolicy`, a `Latch` and a `PlatformAdapter` at once. `net.up` computes one contract through `twinvpn-route` → `twinvpn-dns` → `twinvpn-enforce` and installs it in `ArmStep` order; `net.down` runs `TeardownStep`'s. **`PlatformAdapter::apply` and `set_ruleset` now have production callers.** Every failure path calls `enforce::block`, so an arm that fails leaves the host `RULESET_BLOCKED` rather than open — the fail condition the register named. KS-18 is honoured: with no path validation the latch stays `Blocked` and says so, rather than reporting protection over an unvalidated tunnel. Asserted against the adapter in `tests/data_plane_composed.rs`. |
| **R-3** | **Fixed** — `vtable.rs`. `size` is read on its own through `addr_of!((*ptr).size)`, checked, clamped to this core's struct, rounded **down to a whole entry** so a truncation cannot land mid-pointer, and only then copied over `TwHostVtable::EMPTY`. Entries past the declared size are `None`, not a poisoned word read as `Some(fn)`. The old test built a full-size Rust struct with `size: 1` and passed either way; the new one allocates a buffer that genuinely ends, fills the rest with `0xAA`, and checks neither the poison nor a half-copied pointer survives. |
| **R-4** | **Fixed** — `verify.rs` gained `revocation_of` and `policy_of` beside `succession_of`, both exhaustive with no wildcard arm. `device::revoke` compares the wire `target_device_id` against the one the **Owner signed**; `policy::put` takes the monotone version from inside the signature and refuses a wire disagreement. Both refuse a payload that did not decode rather than falling back to the wire's word — the fallback *is* the vulnerability. Regression tests at both the unit and the integration level. |
| **R-6** | **Already fixed** by `desktop-linux` before this pass: `set_ruleset` re-renders the same generation's contract with the other posture, and `nft::render`'s baseline drops the product's own address space in both families rather than nothing. Verified rather than assumed. |
| **R-8** | **Fixed** — `AnchorChain::offer_anchor` retires every delegation bound below the new anchor when the root advances, through `remove_delegation`. ADR-0007 §7.5's phrase-compromise recovery now removes the stolen OSK's authority, which was the ceremony's whole purpose. A no-op re-delivery, a refused rollback and a detected fork all leave the set untouched. |
| **R-9** | **Fixed** for the live cases: hand-written `Debug` on `twinvpn_store::Record`, `RelayTokenRecord`, `KeySource` (which was rendering the server's **private key**) and `PresentedToken`. `Action::Send` already had one. The `PresentedToken` tripwire that "passed because `Vec<u8>` renders as digits" now asserts the token's own bytes are absent, so the derive cannot come back unnoticed. |
| **R-10** | **Fixed** — `twinvpnd` §11.6 step (5b) calls `Core::open_store` before the endpoint accepts connections, and a failure is a **startup refusal**, not a warning. `Core::open_store` had only test callers; the composed daemon ran memory-only for its whole life. |
| **R-12** | **Fixed** — `not_before_of` mirrors `not_after_of` with an exhaustive per-kind match. Of the ten kinds this service admits, `signed_statements.cddl` declares `not_before_ms` on none, so zero is the honest answer *per kind* rather than one blanket literal, and a kind that later gains one fails to compile. Tested against the **shipped** `CryptoVerifier`, not `ScriptedVerifier`. |
| **R-14** | **Fixed** — W-20's disposition executed. The canonical five-variant `HealthState` lives in `twinvpn-types`; `twinvpn-relay-client` and `twinvpn-relay-health` re-export it and their copies are gone. `relay-health`'s never-a-gate tripwire follows the enum to its new home rather than passing vacuously. `tests/` asserts the device's and the service's vocabularies are the same object. |
| **R-16** | **Fixed** — `contained_on` takes its fallback as `FnOnce() -> T`, so the envelope is built only on the two paths that hand it to the caller. The `Box<TwBuf>` per `tw_core_next_event` and per `tw_core_submit` is gone. |
| **item 2** (`session.connect` reaches CONNECTED with no authentication) | **Fixed** — `execute::trust_guards`. `credentials_valid` is the adapter's `identity_public` (§11.16 (l)'s specified behaviour on a host with none), `peer_authorized` is ADR-0007 N-4's `TrustedPeer`. Both **fail closed** and refuse by name — `AUTH.KEY_UNAVAILABLE` and `AUTH.PEER_UNTRUSTED`, which are different facts. **Still open:** there is no handshake and no key exchange; what is closed is that an unauthorized peer no longer reaches CONNECTED, and that no test could previously tell the two apart. |
| **item 9** (iOS cannot compile) | **Fixed** — the seven undefined types now exist: `CoreCommand`, `CoreConfiguration` and `CoreEvent` in `CoreProtocol.swift`; `InterfaceFacts`, `SystemResolvers`, `NAT64Discovery` and `Attestation` in `PlatformFacts.swift`. **Not compiled**: there is no Swift toolchain on this host, so this closes "referenced and undefined", not "builds". |
| **item 10** (Android never instantiates a core) | **Fixed** — `shells/android/jni`, a new crate and a second `.so` (CD-I5 forbids `twinvpn-platform-android` naming `twinvpn-core`). `NativeBridge` declares the five core entries plus F-10; `TwinVpnService` creates a core and `CoreClient` drains its stream on a thread of its own. **W-38 was stale and is recorded as such**: both directions carry the MI frame, so no `mgmt.proto` was needed. The Rust half is clippy-clean for `aarch64-linux-android` under `make cross-check`; the Kotlin half is not compiled, for §10.3's reason. |

**Related ABI change.** `tw_core_submit` gained the MI-frame form, which carries
an operation's **parameters** — `TW_ABI_MINOR` 0 → 1, an addition under VR-1,
with the bare-name form unchanged and still accepted. Without it
`session.connect` could not be submitted across the ABI at all, because its
parameter is the whole of what it means; `shells/ios`' `pathSnapshot` and
`memoryPressure` had the same problem.

**Verified clean and worth trusting** (`security-review` traced each rather than reading its comments): `dcbor.rs`'s six determinism clauses; COSE `Sig_structure` built from **received** protected-header octets, alg-confusion and alg=none closed, ES256 refused unless exactly 64 bytes; the `TwinNetPSK` derivation byte-exact to ADR-0007 §7.7; **both** replay windows RFC 6479-correct at 8192 bits including counter 0; **I4 structurally enforced** — a COSE_Key carrying `d` is *refused*, not discarded; **I1** traced ingress→egress with no decrypt operation on the trait to call; DP-4 — **no `transmute`, no `assume_init`, no `set_len` anywhere in the tree**; `SO_PEERCRED` handling; MI framing bounds-before-allocate; relay token verification order exactly ADR-0005 §11.3.

**R-5 and R-11 have no row above, and that is a bookkeeping gap rather than an
open defect — verified in the tree, not assumed** (§11.2 G-19). Both are fixed:
`services/relay/src/pump.rs:250` now takes `from: SocketAddr` and refuses a
datagram whose `flow_id` names a half-flow the source address does not own
(`Drop::WrongSource`, with an `R-5:` comment at `:262`); and `PairUnmatched` has
its own registered code `RELAY.PAIR_UNMATCHED`
(`services/relay/src/condition.rs:185`) with a 30 s pending-slot lifetime
(`admit.rs:487`) instead of collapsing onto `RELAY.CAPACITY_REJECTED`, so the
device advances HRW rank bands rather than failing over.

Plus the capability-name-bound defect already recorded in §4.3, which remains the
only one with a live workaround in production code.

---

## 9. Wave 2 — the desktop platform runtimes

**Status:** authoritative for the second implementation wave. Everything in §§1–7
still binds; this section says only what is different.

### 9.1 Scope

The three desktop runtimes of `docs/application-architecture.md` §7, built
against the Phase 1 application architecture, the shared core and the frozen
contracts:

| Domain | Deliverable |
|---|---|
| `desktop-windows` | the `TwinVPNService` privileged service, the virtual adapter, route management on both families, DNS, the WFP kill switch, the named-pipe MI, protected credential storage, service startup/recovery, network-change handling, diagnostics |
| `desktop-macos` | the NetworkExtension system extension and packet-tunnel provider, the shared-core bridge, Keychain custody, routing and DNS, lifecycle, network-change handling, sleep/wake recovery, diagnostics |
| `desktop-linux` | completing the wave-1 shell: the event stream, the PS-1 lock, `twinvpn-unblock`, the `systemd-resolved` scoped path, headless gateway operation, and the test matrix |

**The protocol is not reimplemented per platform.** Each domain implements the
`twinvpn-platform` trait and binds the same core; CB-1 puts everything else above
the seam, and CB-2's falsification test is the check. A second copy of a TwinVPN
decision in a shell is a defect in wave 2 exactly as it was in wave 1.

### 9.2 What "done" can mean on this host, and what it cannot

`ownership.md` §5 deferred Windows and macOS because their platform surfaces
"cannot be compiled, let alone exercised, on the Linux host this wave runs on",
and named the failure mode to avoid: *shell code that has never been built*.
Wave 2 splits that sentence, because half of it is now false and half is still
exactly true. **Four categories, and a report that blurs them is the defect:**

| Category | What it means | How it is obtained |
|---|---|---|
| **executed** | the code ran and its assertions held | `make test` on this host; `unshare`-based netns runs for the privileged Linux paths |
| **compiled** | type-checked against the real platform crates for the real target, `-D warnings` — **never linked, never run** | `make cross-check` (`x86_64-pc-windows-msvc`, `aarch64-apple-darwin`) |
| **written, not compiled** | Swift. The installed toolchain is Linux-only: no Darwin SDK, no `NetworkExtension`, no `Security`, no `SystemConfiguration` | — |
| **written, not executed** | target-gated integration tests that compile for their target and have no host to run on | — |

The **compiled** row is what wave 1 could not have, and it is the reason wave 2
is attemptable at all: `cargo check` and `clippy` need no linker, so the two
rust-std targets install on this host and every line of Rust in both wave-2
adapters and both wave-2 shells is checked against the real `windows-sys` and
Darwin sys crates. It is a real gate and it is **not** a behaviour proof.

The **executed** row is bought by a design rule, not by luck, and it is the one
instruction that decides whether wave 2 is verifiable: **every layer that can be
target-free is target-free.** `#[cfg]` is confined to the thinnest syscall shim;
filter and anchor construction, the route and DNS programmes rendered from a
`RouteEntry`/`DnsConfig`, the platform-event decoding and the OS-error →
`reason_code` mapping are pure Rust over plain data, and they run their tests
here. This is `twinvpn-platform-linux`'s own discipline — its nftables ruleset
text and `nft --json` parser are tested exhaustively on a host with no `nft`
installed — generalised into the rule for the wave.

### 9.3 Concurrency

Each domain works in an isolated worktree with a non-overlapping file scope, per
`CLAUDE.md`. `core/Cargo.toml`, `contracts/`, the `Makefile` and `docs/` stay
with the integration lead. One exception is granted and recorded here:
`desktop-linux` holds `shells/linux/Cargo.toml`'s member list for this wave,
because `twinvpn-unblock` is a package-owned binary that cannot be added without
it and no sibling domain touches that file.

### 9.4 Integration order

```
1. desktop-linux     — it is the only one whose gate can execute end to end
2. desktop-windows
3. desktop-macos
```

After each, the full wave-1 gate must be green **plus** `make cross-check`:

```
make contracts && make test-contracts && make build && make lint && make test && make cross-check
```

**Do not continue integrating onto a broken `master`.**

---

## 10. Wave 3 — the mobile platform runtimes

**Status:** authoritative for the third implementation wave. Everything in
§§1–7 still binds, and §9.2's four categories bind unchanged; this section says
only what is different.

**Ordering note, stated rather than glossed.** §1 places `shells/{ios,android}`
in wave 3 and §5 defers them behind wave 2, whose two desktop runtimes were
*scaffolded* (commit `5fae6ea`) and not implemented when this section was
written. Wave 3 was run **ahead of wave 2's completion, by explicit
instruction**. Nothing in wave 3 depended on `shells/windows` or `shells/macos`
existing — both mobile domains bind the same `twinvpn-platform` trait and the
same core that wave 1 shipped — so the waves were independent in fact, not
merely by assertion. What was *lost* by reordering is the macOS runtime as a
worked precedent for the Apple half; the `desktop-linux` shell is the precedent
wave 3 used instead.

**What the reordering actually cost, now that both waves are integrated.** Both
mobile crates were written against the seam as it stood at `35ccd94`/`7c2f88d`,
and wave 2's integration then moved it twice — **X-10** replaced
`InterfaceFacts.addresses`' `IpPrefix` with `InterfaceAddress`, and **M-6**
replaced `EnforcementCustody.survives_core_exit`'s `bool` with
`RulesetCustody`. Neither crate compiled against the result, which is **M-14**.
That is the bill for running the waves in parallel and it was a small one,
because both changes were *requested by these domains*: each had written the
defect down at the line and deferred it to "a coordinated commit across those
domains rather than a red build from this one", and the integration was that
commit. Five tripwires fired on the way through and every one was inverted
rather than deleted.

### 10.1 Scope

| Domain | Owns | Deliverable |
|---|---|---|
| `mobile-ios` | `shells/ios/`, `core/crates/twinvpn-platform-ios` | the SwiftUI app, the `NEPacketTunnelProvider` NetworkExtension, the shared-core bridge, Keychain + Secure Enclave custody, the VPN-permission lifecycle, network-change and Wi-Fi↔cellular roaming, lock/unlock, background-supported operation, diagnostics, the pairing foundation |
| `mobile-android` | `shells/android/`, `core/crates/twinvpn-platform-android` | the Kotlin app, the Jetpack Compose UI, `VpnService`, the foreground-service lifecycle, the shared-core bridge, Android Keystore custody, connectivity changes and Wi-Fi↔cellular roaming, Doze handling, always-on/lockdown integration, diagnostics, the pairing foundation |

Same CB-3 split as every other platform domain: the trait is
`core-foundation`'s, the implementation is the shell domain's.

**The protocol is not reimplemented per platform.** §9.1's sentence binds here
verbatim. A second copy of a TwinVPN decision in a mobile shell is a defect in
wave 3 exactly as it was in waves 1 and 2, and CB-2's falsification test is the
check: with both mobile shells deleted and the mock adapter bound, the core must
still make every decision correctly.

### 10.2 The two prohibitions the objective states, and where they bite

1. **No dependency on keeping the screen awake.** No wake lock, no
   `isIdleTimerDisabled`, no "keep-alive by staying foreground". On Android the
   sanctioned mechanism is the foreground service with its persistent
   notification plus `setUnderlyingNetworks`; on iOS it is the extension's own
   lifecycle plus on-demand rules. `docs/networking.md` §5.4 names both.
2. **No undocumented background-execution tricks.** Keepalives ride the tunnel
   socket's own kernel-side timer where the platform offers one, never an
   app-side alarm cadence chosen to defeat Doze. An iOS provider that survives
   only because of an undocumented behaviour is *written, not verified* by
   definition, and would be reported as working on a device farm long before it
   was reported as broken by a user.

### 10.3 What "done" can mean on this host — wave 3's row of §9.2's table

Wave 3 sits **worse** than wave 2 on this host, and the report must say so:

| Category | Wave-3 content | How it is obtained |
|---|---|---|
| **executed** | every target-free layer of both adapters — OS-error → `reason_code` mapping, `NEPacketTunnelNetworkSettings` / `VpnService.Builder` programme rendering from a `RouteEntry`/`DnsConfig`, event decoding, posture computation | `make test` on this host |
| **compiled** | every line of Rust in both adapters, type-checked against the real Darwin and bionic sys crates, `-D warnings`, **never linked, never run** | `make cross-check` (`aarch64-apple-ios`, `aarch64-linux-android`) |
| **written, not compiled** | **all Swift and all Kotlin.** There is no Xcode, no Darwin SDK, no `NetworkExtension`, no JDK, no Gradle, no Android SDK and no NDK on this host | — |
| **written, not executed** | the XCTest and instrumented-test suites, and every real-device lifecycle test | — |

§9.2's design rule is therefore **more** binding here, not less: **every layer
that can be target-free is target-free**, `#[cfg]` is confined to the thinnest
syscall shim, and everything a reviewer would want to see exercised runs its
tests on this Linux host. A mobile domain that pushes logic up into Swift or
Kotlin has moved it from *executed* to *written, not compiled* — and, under
CB-2, has probably moved a decision into a shell as well. The two failures have
the same shape and the same fix.

**A device farm is owed.** The rows `cross-check` cannot reach need a macOS
builder with Xcode and an Android builder with the SDK and NDK, plus real
devices for the lifecycle matrix. Wave 3 does not close that debt; it writes the
tests that will discharge it and says plainly that they have not run.

### 10.4 W-24 / W-25 on a Swift or Kotlin shell — integration-lead ruling

§8's W-24 and W-25 record that `twinvpn.h`'s F-9 vtable carries **no**
`installed_ruleset` read-back, **no** `current_generation`, **no** socket
provider and **no** interface enumerator, so *a shell bound only to that vtable
cannot do NAT traversal and cannot produce a `ProtectionAssertion` at all*.
`shells/linux` escapes this by linking `twinvpn-platform-linux` as a Rust crate.
A Swift or Kotlin shell cannot do that, which is exactly the case W-24 and W-25
say "needs ADR-0018 §11.4 amended, or an explicit acceptance".

**Ruling, for wave 3, recorded as a decision and not as an amendment:** neither.
The missing capabilities stay **in Rust, in-process**, inside
`twinvpn-platform-{ios,android}`, and the Swift/Kotlin side reaches them through
a per-platform `extern "C"` bridge exported by that same adapter crate. That
bridge is **not** an ABI of record, is **not** `twinvpn.h`, and acquires **no**
compatibility obligation: both sides are compiled from one commit into one
artifact, which is precisely the same-process scope VR-2 already carves out. It
is internal linkage, and it is versionless because there is nothing for it to be
compatible *with*.

Consequences, stated so they are not discovered later:

- Sockets, the NAT ladder, interface enumeration and change events, ruleset
  read-back and `current_generation` are Rust on both mobile targets. Swift and
  Kotlin marshal; they do not decide (CB-2).
- The bridge surface is **not** permitted to grow a TwinVPN domain fact. An
  entry that takes or returns a `ConnectionState`, a `reason_code` class, a
  policy verdict or a candidate priority is a CB-2 violation on the wrong side
  of the line, and is a finding.
- **This does not discharge W-24 or W-25.** ADR-0018 §11.4 still needs the
  amendment they ask for, because the *general* claim "a vtable-only shell can
  assert protection" remains false. Wave 3 removes the blocker for two shells;
  it does not close the defect. Both mobile domains report it again, in their
  own words, if their implementation contradicts this ruling.

### 10.5 The mobile test matrix

Both domains cover, and report per §9.2 category:

foreground/background · lock/unlock · network changes · cellular↔Wi-Fi
migration · tunnel restart · process termination · restored connection ·
revoked peers · kill-switch behaviour · IPv4 leaks · IPv6 leaks · DNS leaks.

Two rules on how they are covered:

1. **Every row that can be a host-runnable test over the mock adapter MUST be
   one.** A roaming migration is `MIGRATING` rather than `RECONNECTING`
   (`docs/networking.md` §5.4) — that is a core decision, testable here with no
   device. A revoked peer, a restored connection and a kill-switch posture are
   the same. Writing these only as device tests would put them in the
   *written, not executed* row for no reason.
2. **The genuinely device-bound rows are written as real-device lifecycle tests
   and reported as unrun.** Process termination by the OS, Doze, extension
   memory-limit kill, and the iOS attach-to-arm window ADR-0012 §11.9's P09
   *measures* rather than assumes, are in this set.

Leak coverage is **both families and DNS on every platform**, per ADR-0010 R1:
an IPv4 story with a weaker IPv6 story is the asymmetry that ADR forbids, and
§4.2 already refuses to let address family become a namespace.

### 10.8 Wave-3 findings register

Wave 2's X-register form, continued. `M-` for the mobile wave.

| ID | Kind | Finding | Disposition |
|---|---|---|---|
| **M-1** | **defect — the largest of the wave** | **The ABI's event stream is type-erased and undecodable.** `twinvpn-ffi::encode_event` writes **six** different message types into one `tw_buf` with **no discriminator**: a bare `TransitionEvent`, a `SessionEvent`, an `ErrorEnvelope` for `Diagnostic`, a byte-identical `ErrorEnvelope` for `CommandRejected`, the raw `result` bytes of `CommandCompleted`, and a synthesized envelope for `Compacted`. A receiver cannot tell which it holds. `Diagnostic` and `CommandRejected` are indistinguishable on the wire, so *"your command failed"* and *"here is an unsolicited diagnostic"* are the same bytes. `CommandCompleted` drops `op`, so a shell cannot tell **which** command completed. And `seq` and `actor_principal` live on `CoreEvent` rather than on its `kind`, so `encode_event` — which encodes only the kind — **drops both**: F-5's *"exactly one totally ordered stream"* crosses the ABI with its ordering removed, MI-19's `Compacted` marker loses the `up_to_seq` that makes a gap resyncable, and MI-18's *"'the tunnel went down' and 'Dana took the tunnel down' are different facts"* becomes unsayable. `twinvpn.h` states nothing about the bytes, and no test decodes them. **This, not the command direction, is why both mobile UIs are stubs.** | **CLOSED, and the disposition it was given was wrong in a useful direction.** M-2 assigned the wire half to a **generated contract message**, which would have meant reopening the freeze. It did not need one: `twinvpn_mgmt::envelope::MgmtEnvelope` already carries every field M-1 names as lost — `seq`, the topic, `actor_principal`, and `Compacted { up_to_seq, dropped_by_topic }` — and it is **length-prefixed JSON**, which a Swift or Kotlin shell decodes without linking a Rust type. So `encode_event` now frames through it, which is MI-20 applied to the ABI: the C ABI is a *carriage*, not an exception to the rule. Three things moved with it. (1) `topic_of` was a **shell's** function, in `shells/linux` and nowhere else — a carriage authoring a fact about the event — and is now `CoreEventKind::topic()`, with a drift test binding it to the fan-out's copy. (2) `op` is a new `#[serde(default)]` field on `Body::Event`, needed **because of this ABI**: `tw_core_submit` is fire-and-forget and returns no request id, so a shell on the far side has nothing else to correlate a completion against; a socket carriage settles from memory and did not need it, and carries it now anyway. (3) `twinvpn.h` states the bytes normatively, and eight tests decode them — one per shape M-1 lists, plus the length-prefix-and-JSON assertion that is M-2's objection answered by the encoding rather than by a second declaration. The MI frame decoder also gained the three fuzz targets it had never had. |
| **M-2** | **defect** | **This is X-4 and W-38 seen from a non-Rust shell, and it is worse there.** X-4 recorded the MI envelope declared three times and assigned *"move it into `twinvpn-mgmt`"*. That closes it for the three Rust desktop shells, which link the crate. **A Swift or Kotlin shell cannot link a Rust type**, so the assigned fix does not reach the two mobile shells at all — they need the envelope as a **generated contract message**. Five domains across two waves have now reported the same defect from five directions. | **CLOSED with M-1, and the premise corrected.** The `twinvpn-mgmt` half stands unchanged. The wire half needed no generated message: the envelope is serde JSON behind a four-byte big-endian length, so *"a Swift or Kotlin shell cannot link a Rust type"* is true and does not bite — it decodes the bytes and links nothing. Asserted rather than asserted-about: `the_frame_is_length_prefixed_so_a_foreign_shell_can_read_it_without_rust` parses the frame with a general-purpose JSON reader instead of with `twinvpn-mgmt`'s own types, which would only have proved the encoder agrees with itself. |
| **M-3** | **defect — corrected** | **ADR-0012 KS-9(1) asserts something false about Android.** It grouped iOS and Android as *"the provider's own sockets are excluded from its own tunnel by construction"*. Exact on iOS; the opposite of the truth on Android, where a `VpnService` claiming `0.0.0.0/0` captures the agent's own sockets and exclusion is an explicit `VpnService.protect(int)` per descriptor. An implementation reading the clause literally builds a **bootstrap deadlock** — the socket that must reach the relay is captured by the tunnel it exists to establish — which fails closed, silently, always, and presents as a NAT-traversal fault. Reported by `mobile-android`. | **Fixed.** ADR-0012 clause 1 split, and **KS-9c** added in KS-9b's established form, carrying the mechanism, the normative obligation and the create-to-`protect()` residual. |
| **M-4** | finding — **closed** | Both mobile domains independently reported ~17 normatively-named `reason_code`s absent from the registry, and **neither invented one**; each substituted a registered near-neighbour and left a tripwire. | **Closed by Amendment 1** (201 -> 454 codes), and **the deletion is done**, on the pass that integrated the two crates. All seventeen Android substitutions are gone; `UNREGISTERED` is empty and its tripwire is inverted rather than deleted, so a future ADR code that outruns the registry still lands visibly. Two things the deletion surfaced, both recorded rather than smoothed over. **One substitution survives on purpose:** the leak verdict keeps `POLICY.LEAK.DETECTED` instead of the newly registered `POLICY.LEAK.EGRESS_OBSERVED`, because the two describe the same condition in the same words and only the first declares `family` — repointing would have attached the family and had the builder drop it (W-6), and a leak verdict that cannot say which family leaked is the asymmetry §4.2 and ADR-0010 R1 forbid. **The registry now carrying two identifiers for one condition is a finding**, against the same `reliability.md` §3.3 rule that had `MGMT.SCOPE_DENIED` withdrawn before registration. And `STORE.KEYSTORE_LOCKED` is now emittable by name while `PlatformError::SecureStoreUnavailable` still flattens to `AUTH.KEY_STORE_UNAVAILABLE` in the shared seam — a named residual, asserted both ways. iOS had no substitution table to delete. |
| **M-5** ✅ | defect — **FIXED** | **`xtask lint`'s CD-I5 check counts dev-dependencies.** It reads `cargo metadata`'s dependency list without filtering on `kind`, so a **dev**-dependency on `twinvpn-core` fails CD-I5 — though a dev-dependency is not a path between the planes in any shipped artifact. `mobile-android` therefore could not write the one test joining `NetworkChange -> event_for_change -> MIGRATING` end to end, and asserted the two halves separately. **Fixed.** `xtask` now parses `cargo metadata`'s `kind` and CD-I5 walks `non_dev_dependencies`; CD-I2 keeps reading every kind, because a cipher a test pulls in is still a name a reviewer must find. Two tests: a dev-edge to the composition root is not a violation, and the same edge promoted to a real dependency still fires — so the fix is a filter, not a hole. |
| **M-6** ✅ | gap — **FIXED** | **`EnforcementCustody::survives_core_exit` is a `bool`, and iOS is `!`.** ADR-0012 §11.6's durability table gives iOS a partial for both agent crash and `SIGKILL`. `true` asserts CB-6's guarantee the platform does not give; `false` understates the OS re-arm. `mobile-ios` chose `false` per O-18 and said so at the value. **The seam cannot express a partial guarantee at all.** **Fixed at the seam**, which is X-10's disposition applied. `EnforcementCustody.survives_core_exit: bool` is now `ruleset_custody: RulesetCustody` with three values — `OsHeld`, `ProcessHeld`, `OsReArmed` — following `BootEnforcement`'s precedent in the same file. CB-6's predicate survives as a derived method so no caller re-derives it, and `os_rearms()` carries the re-arm as its own fact rather than widening it. The **mock** takes the enum, so `OsReArmed` is reachable without a device — CD-5's payoff, and the posture iOS actually has. |
| **M-7** ✅ | **conflict — RULED** | **Three documents disagree on the iOS contract-fetch split.** `networking.md` §5.4 (corrected) with ADR-0018 §11.12/§11.16(m): *extension fetches, `core-lite` verifies*. ADR-0020 **ST-31**: *app fetches and structurally validates, provider verifies*. ADR-0022 **LC-17**: *app fetches **and** verifies and compiles*. Fetch is placed in two different processes across the three, and verify likewise. | `mobile-ios` implemented §11.12's reading — the one PS-24 condition 3 makes reachable under `includeAllNetworks` — and documented the conflict at the head of `ContractCourier.swift`. **Ruled, and both dissenting rules amended.** §11.12's split stands, because ADR-0016 PS-24 condition 3 makes it the only reachable one: under `includeAllNetworks` the app has no network, so an app-process fetch fails exactly when the contract is most needed. **ADR-0020 ST-31a**: the courier runs the other way (the extension fetches), and ST-31's *"verification happens at the writer"* was applied to the wrong artifact — LC-17 makes the **app** sole writer of the compiled generation and the **provider** sole writer of session state, so the principle holds unchanged once the writer is correctly identified. **ADR-0022 LC-17b**: the fetch row is corrected to the extension; the verification-and-compilation row is untouched, because what LC-17 exists to keep out of the 12 MB provider is the parse and the hash, and both stay in the app. I8 is preserved on both stores. |
| **M-8** | finding | **`set_mtu` after `establish()` cannot be honoured on Android.** `VpnService.Builder.setMtu` is read only at `establish()`; honouring a later change means re-establishing, which opens the no-claim window §5.1 exists to close. | Accepted. `mobile-android` reports `OsUnsupported` and keeps the leak-free swap. **The inner MTU is fixed for the life of a generation on Android**; DPLPMTUD still probes the outer path, but the inner MTU cannot follow it down without a new generation. |
| **M-9** | gap | **`SocketKeepalive` is not bound to the platform API.** It needs a connected `DatagramSocket`; the socket lives in Rust. **No fallback was added, deliberately** — the only fallback is an app-side alarm cadence, which §10.2(2) forbids. | Accepted with its cost stated: the NAT binding is maintained by the core's own keepalive traffic, which is more wakeful and not incorrect. |
| **M-10** | defect — closed | **`in6_pktinfo.ipi6_ifindex` is `int` on bionic and `unsigned int` on glibc.** Caught by `make cross-check` and by nothing else. | Fixed as a total narrowing that rejects an out-of-range kernel value with a registered code — **not** `try_into().unwrap()`, which clippy suggests and which would place a panic on a kernel-supplied value in the receive path. **The wave's evidence that `cross-check` earns its cost.** |
| **M-11** | defect — fixed | **Running the mandated gate rewrote six lockfiles across five other domains**, so a domain obeying §7 and §10.7 finished with a dirty tree in files it does not own — and a `git add -A` after it commits the cross-write §10.6 forbids. Reported by `mobile-ios`. | **Fixed** in `7c2f88d`: 110 stale entries pruned, zero added, no version moved, regenerated against a clean checkout of `HEAD` and verified idempotent. `--locked` on the gate targets is the other half and is **not** done — the `Makefile` carries uncommitted concurrent changes. Integrating the two mobile crates rewrote no lockfile outside `core/`, so the fix holds. |
| **M-12** ✅ | **defect — the one no register had, FIXED** | **`shells/windows` and `shells/macos` never drained the core's event stream.** `next_event` appeared nowhere in either shell — Rust or Swift. Both built a `Core`, both linked `twinvpn-mgmt`, both served the management interface, and neither ever popped the one totally ordered stream F-5 puts every state change on. Only `shells/linux/twinvpnd` ran a drain. Three consequences, all live: no client on two of three desktop platforms could be told anything had changed; **every `Response.result` was `Vec::new()`**, because `Core::submit` publishes an operation's outcome as an *event* before it returns `Ok(())` and nothing read it; and the core's bounded ring filled behind an absent consumer and dropped oldest-first with `INTERNAL.BUFFER_OVERFLOW` having nobody to report to. Windows said so at its own `event.resync`, which returned `MGMT.STREAM_COMPACTED` unconditionally with the comment *"this build has no subscribed-topic snapshot to take"*, and `runtime::Service::shutdown` had documented a drain thread that did not exist. | **FIXED, and the ladder moved rather than being copied.** X-4 found the MI *envelope* declared three times; the §11.10 ladder that carries it was declared **once**, and the consequence was not drift but absence. It is now `twinvpn_mgmt::fanout` — the watermarks, the three eviction rungs, MI-19's marker ordering, the MI-9 snapshot and the pending-completion registry — `std` only, synchronous, and taking no lock, because a `Notify` is a property of a carriage's runtime and that crate has none and wants none. `shells/linux` lost ~400 lines and kept its 172 tests green through the shared code; Windows and macOS gained a drain thread, a subscriber pump, a real `Response.result` and a `event.resync` that answers. macOS's drain lives in `crate::host` rather than in `mgmt/`, because **PS-22** keeps `twinvpn_core` out of that module and the source scan asserting it still passes. |
| **M-13** ✅ | **defect — FIXED** | **`twinvpn-mgmt::codes`' helpers still substituted after `SUBSTITUTIONS` was emptied.** X-1 emptied the table and inverted its tripwire, and `substituted()` became a plain registry lookup — but `resync_required()`, `op_unknown()` and `unavailable()` were **separate functions** that kept returning the codes the table used to justify. So the same crate answered with the right name through one entry point and the wrong one through another, and no test compared them. The worst was `MGMT.RESYNC_REQUIRED -> MGMT.STREAM_COMPACTED`, which X-1 itself called out by name: it makes MI-9a's two conditions indistinguishable at exactly the point a client must tell them apart — *"the stream dropped events, resnapshot"* and *"your offered cursor is unserviceable"* are different recoveries. | **FIXED.** All three emit their own registered names, `not_ready()` and `shutting_down()` are split apart (they had both collapsed onto `MGMT.UNAVAILABLE`, which told a client "not now" without telling it whether to retry), and two tests hold it: every helper's output must equal the spelling its document uses, and `resync_required() != MGMT.STREAM_COMPACTED`. **The general lesson is the one worth keeping: an empty substitution table proves nothing on its own.** |
| **M-14** ✅ | **defect — FIXED on integration** | **Both mobile crates predated X-10 and M-6 and did not compile against the seam.** Expected — they branch from `35ccd94`/`7c2f88d` — and recorded because *what* they predated is the interesting part. Each had **written the defect down and deferred it**: `twinvpn-platform-ios/src/pathmon.rs` said the `IpPrefix` conflation's replacement "lands as a coordinated commit across those domains rather than as a red build from this one", `twinvpn-platform-android/src/netchange.rs` said the same in the same words, and `twinvpn-platform-ios/src/enforce.rs` explained at length why a `bool` could not say `◐` and reported the seam. | **FIXED, and this was that commit.** `InterfaceFacts.addresses` and `NetworkContract.addresses` take `InterfaceAddress`, so nothing is masked or dropped: on iOS **every interface's link-local address stops vanishing** (the `V6Addr`-demands-a-zone / `IpPrefix`-rejects-one conjunction, W-39), and on Android the JNI bridge **stops rejecting ordinary host addresses outright** — `192.168.1.10/24` is the shape `LinkProperties.getLinkAddresses()` reports and it was refused at the boundary. iOS custody becomes `RulesetCustody::OsReArmed`, which is the value M-6 added the enum for; Android becomes `OsHeld` under confirmed lockdown and `ProcessHeld` otherwise, and **emphatically not `OsReArmed`** — iOS's on-demand re-arm has no Android equivalent, and rounding them together would assert a recovery that never happens. Three tripwires fired and were **inverted rather than deleted**: the two "this address cannot be represented" tests now assert it survives, and Android's "a non-canonical prefix is refused" now asserts a host address crosses the bridge whole. |
| **M-15** ✅ | gap — **CLOSED** | **`NetworkContract.tunnel_remote_address` exists and neither Apple adapter reads it.** The field was added so `NEPacketTunnelNetworkSettings(tunnelRemoteAddress:)` could be built from the contract alone — *"a value the shell holds and the core does not is a fact the two sides can disagree about"* — and both `twinvpn-platform-macos::nesettings::render` and `twinvpn-platform-ios::settings::render` still take it as a **separate `&str` parameter**. | **CLOSED, in the one place the derivation belongs.** Both renderers read the contract, and neither takes the address as a parameter any more — `twinvpn-platform-ios`' `IosNetworkConfig` held it as a **constructor** field for the life of the process, so a contract whose remote had moved rendered against the old one, which is the disagreement the field exists to prevent in its most durable form. The rule is `NetworkContract::tunnel_remote_for_settings`, written once beside the data it derives from because two adapters needing the same derivation is the shape X-4 found in the MI envelope. **Three cases, one of them an error:** a remote renders as given; **no remote in `Blocked` renders `0.0.0.0`**, which is not the placeholder the field's own documentation forbids — a placeholder stands in for a fact nobody knows, and here every side agrees there is none, and it must render rather than refuse because on iOS the blocked posture is installed *through* a settings object and a refusal would leave the kill-switch uninstalled; **no remote in `Protected` is refused by name**, because a protected generation asserts a validated path and a validated path has a remote. |
| **M-16** ✅ | **defect — FIXED** | **The Android JNI bridge threw a registered refusal into a platform callback, and it killed the process.** `bridge::entry`'s `guard` reported every `PlatformError` with `env.throw_new("java/lang/IllegalStateException", reason_code)`. All five entry points there are PLATFORM CALLBACKS, and AOSP admits no survivable path out of one: `ConnectivityManager$CallbackHandler.handleMessage` (android11-release:3574-3645) has no `try`/`catch`, `Looper.loop` (:222-232) rethrows after notifying its observer, and `RuntimeInit`'s `KillApplicationHandler` (:142-175) ends in `Process.killProcess` + `System.exit(10)` inside a `finally`. Four of the five were fatal; `nativeOnRevoked` is survivable only because `Binder.execTransactInternal` catches — and there the refusal is silently discarded by `system_server`, which is its own defect. **Nothing caught it for three waves because the Android shell had never executed**: run 33298081071 booted an emulator for the first time and PID 3277 died on the first `onAvailable`. | **FIXED.** `entry.rs` throws nowhere; `guard` routes refusals and caught panics to `refused()`, which logs. `catch_unwind` stays — panicking into the JVM is still UB. Four independent production clients were checked and agree: Mullvad's Rust entry logs and returns (`talpid-core/src/connectivity_listener.rs:169-173`), Tailscale `Log.w`s and returns, WireGuard's JNI returns a `jint` and never throws; libsignal throws but only from methods its own Java calls. **This is ADR-0019 X3(5)'s Android discharge**, which did not previously exist — see that row, corrected the same day. Pinned per entry by name, not by count, in `bridge::tests::no_bridge_entry_point_throws_into_the_jvm`. |
| **M-17** ✅ | **defect — FIXED; W-39's third instance** | **Android could never send a usable IPv6 link-local address.** `NetworkCodec` wrote `Inet6Address.scopeId`, and AOSP's `LinkAddress` parcelling destroys it — `writeToParcel` (LinkAddress.java:525-531) writes only `address.getAddress()` and `createFromParcel` (:539-556) rebuilds via `InetAddress.getByAddress(byte[])`. So every `fe80::/64` from `LinkProperties` arrived with zone 0, `ZoneIndex::new(0)` is `None`, and `wire.rs:287` refused the whole payload. **M-14 declared W-39 fixed and it landed only half of it on Android**: the prefix half, so ordinary host addresses cross whole; the link-local half was fixed on *iOS*, where the platform supplies a scope id. Android cannot, and the residual sat one line below M-14's own fix. | **FIXED at the encoder**, the only layer that can hold `fe80::` both present and usable. `NetworkCodec` resolves the zone from the interface name it already has; `NetworkInterface.getIndex()` is `if_nametoindex`, which is what `v6_from_kernel` documents as its input, so `ZoneIndex` means the same thing on both sides. The decoder was NOT relaxed — `docs/protocol.md:546` makes the zone a MUST and `v6_from_kernel` is shared with the socket path where the kernel does supply an index — and link-locals were NOT dropped, which is W-39 itself. One fix covers the address and resolver loops, which share `read_address`. No wire change: the 4-byte BE zone field already existed, `WIRE_VERSION` stays 1, `contracts/` untouched. Verified on a device in run 33306033416. |
| **M-18** | **defect — OPEN, latent** | **`jni` 0.21.1 makes JNI calls with an exception pending, which is UB.** The crate checks `ExceptionCheck` only AFTER issuing a call (`src/wrapper/macros.rs`), and `Error::JavaException` does not clear. So `.unwrap_or_default()` / `.map_or_else()` on a JNI `Result` discards the error, leaves the exception pending, and the next call is issued illegally — `throw_new` resolves its class through `FindClass`, and `take_buf` uses `NewByteArray`, neither on the JNI spec's exception-safe list. Six sites: `bridge/entry.rs`'s `convert_byte_array`, and five in `shells/android/jni/src/lib.rs` (`nativeCoreCreate:223`, `nativeCoreSubmit:299`, `nativeRenderDiagnostic:412-419`). Upstream agrees it was a wrong assumption — jni-rs **#731**, fixed by #733/#737/#738. | **The one site reachable from the crash is fixed** (`entry.rs` clears rather than decoding an empty payload). The remaining five are latent and low-probability. **Do not sell an upgrade as a crash fix**: 0.22.2+ closes the UB and changes nothing about a pending exception becoming a real Java exception on return. 0.22.0 and 0.22.1 are **YANKED**; 0.22.2 is the first usable release. Needs its own decision. |
| **M-19** | **gap — OPEN** | **`ConnectivityWatcher` observes TwinVPN's own tunnel, and nothing has ever exercised that.** `removeCapability(NET_CAPABILITY_NOT_VPN)` lifts the `NOT_VPN` filter in `DEFAULT_CAPABILITIES` (NetworkCapabilities.java:381-384), so `Builder.establish()` fires a fresh `onAvailable` fan-out for the app's own network straight back into `nativeOnNetwork`. `bridge/mod.rs:188-192` documents observing VPN transports as deliberate, so the capability is right; what is unproven is the re-entrancy. AOSP additionally hands a **non-null but EMPTY** `LinkProperties` for the caller's own VPN on this path (`ConnectivityService.java:1722-1724`). | Not implicated in M-16/M-17 — logcat shows `NetReassign [no changes]`, so that crash was the pre-existing underlay at registration, before any `establish()`. It stays open because **no `establish()` has ever run**: `NativeLinkRunTest` asserts lifecycle only. The inline comment claiming "No capability filter" and crediting arrival+departure to `removeCapability` was false on both halves and is corrected; the behaviour is not. |

### 10.6 Concurrency

Each domain works in an isolated worktree with a non-overlapping file scope, per
`CLAUDE.md` and §9.3. `core/Cargo.toml`, `contracts/`, the `Makefile`, `build/`
and `docs/` stay with the integration lead — including this file. The two
adapter crate directories and their own `Cargo.toml`s are the domains'.

### 10.7 Integration order

```
1. mobile-android  — more of its surface is reachable from a Linux host
2. mobile-ios
```

After each, the wave-1 gate must be green **plus** `make cross-check`:

```
make contracts && make test-contracts && make build && make lint && make test && make cross-check
```

**Do not continue integrating onto a broken `master`.**

### 9.5 Wave-2 decisions taken by the integration lead

| # | Question | Decision |
|---|---|---|
| **D-1** | **The CLI's name — `twinvpn` or `twinvpnctl`?** Open since wave 1 (W-41) and raised again by all three desktop domains. | **`twinvpn` is the installed name.** This is not a preference; the documents already settled it and the shells diverged. [ADR-0016](../adr/ADR-0016-client-process-and-privilege-separation.md) §11.2's macOS component row lists a `twinvpn` CLI and `twinvpn-unblock`; [ADR-0017](../adr/ADR-0017-local-management-interface.md) §11.12 names `twinvpn`; [ADR-0023](../adr/ADR-0023-headless-cli-and-embedded-profile.md) EM-11 renders `twinvpn config check` and EM-42 renders `run 'twinvpn peer disconnect nas-attic'` — a **next action that names a command no host has installed**, which is an I6 failure at the last inch. The cargo target stays `twinvpnctl` (renaming it churns three shells for nothing a user sees) and **the package installs it as `twinvpn`**, with `twinvpnctl` kept as a compatibility alias. `desktop-linux` recommended exactly this; it is adopted for all three desktops. |
| **D-2** | **Does `make cross-check` cover the shells whole, or only their platform surface?** | **Whole.** `snow` 0.10's `std` feature list contains `ring/std` written without the `?`, so enabling `std` force-enabled the optional `ring` dependency, and `ring` builds C. That single edge is why neither wave-2 shell could be cross-compiled, why both pushed their core-hosting code outside the gate, and why the three Windows files that name the core had never been compiled by anything on any host. Selecting snow's default resolver keeps [ADR-0001](../adr/ADR-0001-tunnel-protocol-and-cryptographic-foundation.md) §11's primitives exactly — the same crates `core/Cargo.toml` already pins under CD-I2 — and removes the edge. The first full run then found a real error in exactly those never-compiled lines, which is the whole argument for widening a gate rather than documenting the hole. |
| **D-3** | **ADR-0016 §11.6 step (1): does a missing KS-19 boot artifact refuse the start?** | **No — report and continue.** All three shells read it that way independently. Recorded as **PS-7a**. |
| **D-4** | **The Windows service start type.** | **`SERVICE_AUTO_START`, not delayed.** ADR-0022 LC-12 owns lifecycle and reasons it out; ADR-0016's clause was an unreasoned aside and is amended. |
| **D-5** | **The health file's directory on `H-SRV`.** | **The runtime directory, not the state directory.** Recorded as **EM-69a**: a health line that survives a reboot is a stale green arriving through a file. |

### 9.6 Wave-2 findings register

A **ruling** is an interpretation applied now; a **defect** needs a contract or an ADR amended; a
**gap** is something the corpus does not say and someone must decide.

| # | Kind | Finding | Disposition |
|---|---|---|---|
| **X-1** ✅ | **defect — the largest of the wave, CLOSED** | **The reason-code registry is a thin transcription of the ADRs.** `contracts/registry/reason_codes.json` carries **201** codes; the ADRs normatively name roughly **490**, most in tables that already fill in the severity, terminal and user-actionable columns. Every domain must therefore substitute, and the substitutions are not neutral: `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` → `POLICY.POLICY_DENIED` loses ADR-0017 §11.12's dedicated exit code and tells a correct script to stop retrying something a group change would fix; `MGMT.RESYNC_REQUIRED` → `MGMT.STREAM_COMPACTED` makes MI-9a's two conditions indistinguishable at the point a client must tell them apart. Reported independently by `desktop-windows` (3 of 19 `PLATFORM.SERVICE`/`PRIV`, 4 of 38 `MGMT`, 0 of ADR-0022's `PLATFORM.LIFECYCLE`) and `desktop-macos` (W-18), and confirmed by the integration lead against the registry. | **CLOSED — `registry_version` 2, 2026-08-28.** Approved by the owner and landed: **201 → 454** codes, 249 transcribed from the ADR tables that declare them and 4 derived from `reliability.md`'s prose. Seven substitution tables are empty and every tripwire that guarded them is **inverted rather than removed** — each was written to fail the day its code was registered, each fired exactly as designed. **Fourteen substitutions used to cross a reason-code domain and now none does.** One row survives on purpose: `RELAY.FRAME_WRONG_DIRECTION` appears in no document, and registering a code no ADR defines would be a worse defect than substituting it. Additive and wire-compatible: codes travel as strings, no `.proto` changes, the closed domain set is unchanged. Requires `contracts/SCHEMA_DIGEST` to move and `contracts/FROZEN` to be re-declared, which is the deliberate act §3 intends. |
| **X-2** ✅ | **defect, CLOSED** | **ADR-0011 §11.9's known-encrypted-resolver endpoint list does not exist.** §11.9 states it "ships with the reason-code registry, is versioned, and is explicitly incomplete". Without it, no platform can install the DoH containment ADR-0011's own platform table requires of **all three** of WFP, pf and nftables — so a browser with a pinned DoH endpoint resolves off-tunnel everywhere. Reported by `desktop-windows`. | **CLOSED** — `contracts/registry/encrypted_resolvers.json`, 8 providers, 20 v4 and 20 v6 addresses, carrying `EXPLICITLY_INCOMPLETE` and `guarantee: NONE` **as data** so no consumer can mistake a detection aid for a guarantee. |
| **X-3** ✅ | **defect, CLOSED** | **`twinvpn-gateway` has no caller anywhere in the workspace**, and the MI catalogue has no `gateway` noun (ADR-0023 EM-35 requires one). ADR-0013's multi-client gateway is therefore not merely unimplemented but **unaddressable through the only interface a headless host has**. Reported by `desktop-linux`, verified by the integration lead. | **CLOSED** — the `gateway` noun is in the catalogue and `twinvpn-core::gateway` is the caller; the noun appears in all three CLIs with no per-shell edit (MI-C1). `gateway.set` is refused by name for ADR-0013 MG-15's own reason. |
| **X-4** ✅ | **defect, CLOSED** | **The MI envelope is declared three times.** It is in no contract, so each shell declares its own — MI-20's *"one contract, two carriages, never two contracts"* failing one level up, with three carriages. Reported by `desktop-macos`. | **CLOSED** — moved to `twinvpn_mgmt::envelope`. The three copies **had already drifted**: macOS was a third dialect whose `Compacted` had lost MI-19's `up_to_seq` and whose `Diagnostic` carried MI-14's whole attribute set where the other two carried four of eight. Two of its three divergences were right and are now every carriage's. |
| **X-5** | **defect, closed** | **The `fwmark` policy rule was installed un-inverted.** Table 52 held exactly the right overlay routes and was consulted only for the agent's own marked packets; `program()` returned `Ok`, the table read back correctly, and all 111 wave-1 tests passed while the routing half of the product carried nothing. `route.rs`'s own doc comment had described the correct rule all along. | **Fixed** by `desktop-linux` and verified against a kernel. The lesson is the one the wave-2 test matrix is built on: only a test that asks the kernel `ip route get` could see it. |
| **X-6** | **defect, closed** | **A runtime commit deleted the KS-19 boot artifact** — the leak KS-19 exists to close, reached from inside our own transaction — and **a reclaim that found only the boot artifact returned early**, leaving the service permanently unable to reach the control plane while reporting itself healthy. | **Fixed** by `desktop-windows`; both were caught by tests it wrote, not by review. |
| **X-7** ✅ | **gap, CLOSED by investigation — the premise was wrong** | **ADR-0016 §11.2's macOS row and the shipped macOS shell disagree about who the authority is.** §11.2 says normatively that the system extension is the authority and that `ksd` "MUST NOT accept any request other than (a) apply the boot anchor and (b) the unblock command". `shells/macos/twinvpnd` is a full authority: it builds the adapter, hosts the core and serves the MI. `desktop-macos`'s reason is W-24/W-25 — the C ABI has no socket capability, no interface enumeration and no `installed_ruleset` getter, so a Swift-only extension cannot be the authority. But its own `twinvpn-bridge` staticlib answers that, which suggests the extension *could* remain the authority. The unresolved half is real and is not addressed by either document: **the NE extension is started on-demand, so if it is the sole authority the management interface is unavailable exactly when the tunnel is down** — which is when a user most needs it. | **CLOSED — ADR-0016 keeps its architecture; the shell is wrong and moves.** Recorded as **PS-25** (renumbered from PS-22, which ADR-0016 §11.3 already uses — the collision was found by `desktop-macos` while implementing it). The domain's reasoning — W-24/W-25 make a Swift extension unable to be the authority — does not follow: those findings are about a shell bound **only to the C vtable**, and ADR-0016 §11.14 (f) already requires the core to *link into* the extension as a Rust staticlib. §10.4's ruling for the mobile Swift/Kotlin shells is the same mechanism and is now general. The domain built exactly that bridge and then used it for the **adapter only**, leaving the core in the daemon. **The decisive constraint is physical:** `NEPacketTunnelProvider.packetFlow` exists only inside the provider, the core owns the datapath, and §11.16 (a) / S-47 allow exactly one process a mutating core handle — so no split puts the core in the daemon. **The availability half I flagged is answered for two of three rules and NOT for the third, and my first draft was wrong to say otherwise:** MI-A3 makes a client connecting to an absent agent receive `MGMT.UNAVAILABLE` rather than hang (M-P17-17 names socket activation as the defect for that reason), MI-I5-5 is scoped to phases *in which a process exists*, but **§11.14 (d) / PS-9 (2) do not hold on macOS**: NE starts the provider for a *tunnel*, not for a management request, so a quarantined authority is a process that does not exist and cannot be supervised into a stub. `desktop-macos` found this by implementing the amendment. **PS-25a** closes it with the narrowest possible third accepted request — `ksd` answers the read-only degraded-state subset, and only while the authority is absent. It forwards nothing and holds no core, no keys and no sockets, so it is not the general-purpose privileged helper §11.2 forbids; without it, `blocked` and `bricked` are indistinguishable on macOS alone. |
| **X-8** | ruling | **KS-5's structural dual-family guarantee does not survive the port.** nftables gets it free from the single `inet` table; `pf` has no dual-family object. | Accepted. On macOS it comes from the anchor renderer being **one function** that cannot emit v4 without v6, asserted by test. A structural guarantee re-established by construction is still structural; one re-established by convention would not be. |
| **X-9** ✅ | gap — **CLOSED** | **`100.64.0.0/10` is RFC 6598 carrier space.** A host behind CGNAT holds an address in it, and the Tier-2 deny also blocks its traffic to a `100.64.x.x` DHCP or DNS server. Linux and macOS behave identically. Named by `desktop-macos`; **no ADR names it**. | **CLOSED.** It was right not to be worked around by one platform alone, so the predicate is written once — `twinvpn_platform::on_link_is_underlay_path`, beside the contract both adapters render — and Linux and macOS both read it. **The rule:** an on-link prefix inside RFC 6598 is the host's own *underlay path*, not its LAN, so it is passed off-overlay **unconditionally** rather than under KS-4's gate. That is not a widening of KS-4: the set is bounded by what the OS reports as on-link on a non-overlay interface, it is recomputed on every network-change event, and an ordinary `192.168/16` LAN is still the user's to deny. It is the same argument ADR-0010 §11.5 clause 5 already makes for DHCP — *"blocking them breaks the underlay itself"* — reached by address instead of by port, and denying it protects nothing because the overlay's own traffic egresses the overlay interface either way. Six tests: four on the predicate (including that a supernet of the shared space is **not** exempt, and that the v6 half has no collision to resolve because the product ULA is ours alone), and one per adapter asserting the pass appears with `local_network_access: false` while the LAN does not. |
| **X-10** ✅ | ruling, CLOSED | **Two adapters disagreed about link-local prefixes** — Linux drops them, Windows reports them. | **CLOSED** by task C. It was worse than reported: Linux **dropped** every link-local (a zoned address is not a prefix) while Windows **stripped the zone and kept it**, so the core saw a different address set for one host depending on which adapter was bound. |

### 9.7 Residuals from the X-7 move (macOS authority → system extension)

Raised by `desktop-macos` while implementing PS-25. Two of them make the macOS
posture **worse** than wave 2's, and both are recorded rather than absorbed.

| # | Kind | Finding | Disposition |
|---|---|---|---|
| **X-11** | **residual — the move made this worse** | **`audit_token_t` carries no supplementary group list, and PS-12a needs one.** There is no `audit_token_to_groups` and no XPC API that supplies one — only euid/egid. `LOCAL_PEERCRED` returns up to sixteen groups, which is why wave 2 recorded macOS as *better* than Linux here. So an XPC client reaches an authorization class only if that class's gid is its **effective** gid. | **Accepted, and it fails closed** — strictly narrower than the socket carriage, never wider, and flagged (`groups_possibly_truncated` always true). Deliberately **not** patched with a Directory Services lookup: that answers about the *account*, and MI-A1 asks about the connected *process*. The `AF_UNIX` carriage is unaffected, which is why §11.2 gives the CLI that one. |
| **X-12** | gap | **§11.14 (a) requires an API Apple does not publish.** `xpc_connection_get_audit_token` is SPI (`<xpc/private.h>`). The public four (`NSXPCConnection.effectiveUserIdentifier` and siblings) cover the authorization fields but lose `pidversion`, and using them would mean fabricating four words of a struct that claims to be a kernel snapshot. | Declared in `TwinVPNXPCShim.h` with the trade stated, and confined to one Swift function. **§11.14 (a) should name what is actually available on macOS** rather than an API that is not. |
| **X-13** ✅ | gap — **CLOSED** | **`SecCodeCheckValidity` against a Team-ID-pinned requirement (§11.2's macOS row) is not implemented** — it needs `Security.framework`. Until it is, any local process whose euid/egid land in a TwinVPN group can attach. | **CLOSED as far as this host can close it, and the residue is named rather than implied.** `mgmt::codesign` splits the two halves §9.2 distinguishes. **The decision is target-free and executes here:** a `TeamIdPin` that refuses anything which is not a ten-character Team ID (a mistyped pin compiles into a *valid* requirement naming an identifier nobody holds, which denies every client — a typo presenting as an outage), the requirement string assembled from it rather than configured as text, and a four-value `Verdict` whose `admits()` refuses `Unavailable` as well as `Invalid` under O-18. **The `Security.framework` call is `#[cfg(target_os = "macos")]`**, type-checked for `aarch64-apple-darwin` by `make cross-check`, and **has never executed** — CoreFoundation's Create Rule is held by a `Drop` type rather than by hand, because four creates and three early returns is how a leak gets in. Wired at `tvb_mgmt_open`, before a `SessionHandle` exists, so MI-A5 closes on failure. The pin is `option_env!` at **compile** time, not configuration: a requirement settable by whoever launched the process is settable by the attacker. `Unpinned` admits and is reported on every attach — a development build must stay usable, and a shipped build that reaches it has a packaging defect the operator is told about. |
| **X-14** ✅ | gap — **CLOSED** | **`twinvpn-unblock` meets "runs as root", not MI-13 (1)'s "authenticated administrator act".** A root cron job could invoke it. **`shells/linux` is short of the same rule in the same way**, so this is a two-platform gap and not a macOS one. | **CLOSED on both shells, with the residue stated.** Both now require a **controlling terminal on standard input** and refuse `MGMT.DISARM_NO_LOCAL_AUTHORITY` without one — a code `registry_version` 2 registered for exactly this (*"no interactive local principal exists (headless, cron, automation)"*). That is the one thing available to a `#![forbid(unsafe_code)]` binary on both platforms which separates a human at a console from a `cron` job, a timer, a `launchd` job, or a daemon compromised into spawning it — and, decisively, from a control plane, which is KS-22's actual adversary and cannot produce a local terminal. **It is not re-authentication**, and the module says so: `polkit` and Authorization Services would prompt for a credential and this does not, so it establishes *that a human is present, not which human*. **Headless hosts are not locked out:** the refusal names ADR-0012 **KS-21a**, whose whole purpose is that on `HC-3` a caller on the local management socket authenticated by kernel peer credentials satisfies the clause — so KS-20's *"blocked must not mean bricked"* still holds and the operator is told where disarm lives. The register's question stands answered by KS-21a rather than by a new ADR clause. |
| **X-15** | gap | **MI-12 names `ksd` as the unblock's serving component on macOS**, and §11.2's *"MUST NOT accept any request **other than** … (b)"* implies there is a request to accept — but the integration lead directed a self-contained binary matching `shells/linux`. Both were built; the tension is recorded rather than resolved silently. | **CLOSED — the two binaries do not overlap, and the premise of the tension was wrong.** Read against the tree rather than against the ADRs: `shells/macos/ksd` **installs** the boot anchor (`--apply-boot-anchor`) and reports what the kernel holds (`--status`), refusing every other argument; `shells/macos/twinvpn-unblock` **removes** the owner-tagged anchor behind `--confirm-unprotected`, root-only, writing its `UnblockRecord` before mutating (MI-13(3)). Zero functional overlap, so there is no duplicated authority to reconcile — one installs, the other removes. Neither is a server: `ksd`'s plist declares **no `MachServices`, no `Sockets`, no `WatchPaths`**, and `twinvpn-unblock` says in terms that it "speaks to no socket and to no Mach service". **MI-12's own reading supports this**, which is what dissolves the tension: its other two named "serving components" are not servers either — `twinvpn-killswitch` is a systemd unit and the Windows one is literally "the installer-written persistent set" — so "served by" names the *package-owned artifact*, not a request handler. ADR-0016 §11.2's own table at `:429` already records that `ksd` holds "no management interface", and `:571` row O13 already names the macOS binary `twinvpn-unblock`. **Correction to this row's premise, and it matters more than the row did:** PS-25a is **not in the tree at all** — `grep -rn "PS-25a" shells/` returns nothing, `ksd` has no `twinvpn-mgmt` dependency and no envelope handling, and its `--status` is a CLI flag reporting `pfctl` state rather than the authority's lifecycle. So the shipped `ksd` accepts **no** request — not (b), not PS-25a's (c) — and the sentence in this row saying PS-25a "narrows the question" was true of the ADR and false of the build. **PS-25a is specified-but-unbuilt and is carried forward as its own open item**, because its purpose is real: without it, `blocked` and `bricked` are indistinguishable on macOS. |


---

## 11. The first-wave acceptance gate — passes of 2026-08-28 and 2026-08-29

**Status:** a full read of the integrated tree against the wave's acceptance
gate, by the integration lead, on `fix/wave1-final-review-register`. It is a
*review* section: §§1–7 still bind, and nothing here changes a rule.

### 11.1 What was actually run, and what it produced

| Check | Result |
|---|---|
| `make test-contracts` | **44772 checks, 0 failures** |
| `make test-rust` (core, services, shells/linux, lab, tests) | **3845 tests, 0 failed, 0 ignored** |
| `make lint` | **failed** on entry — finding **G-1** — then clean |
| `make gate` (bootstrap, lint, contracts, verify-bindings, test-contracts, freeze, freeze-scope) | green after G-1 |
| `make cross-check` | **failed** on entry — finding **G-4** — then green over the crates this host can still reach |
| `contracts/FROZEN` | re-declared as **Amendment 3** (G-3), digest `97b0959caa9fcd03…` |

**Re-run of 2026-08-29, on the same branch after Amendments 4 and 5 and the
G-6…G-11 passes.** Nothing in it was taken on trust from the run above; every
line was executed again.

| Check | Result |
|---|---|
| `make gate` (bootstrap, lint, contracts, verify-bindings, test-contracts, freeze, freeze-scope) | **green on entry** — 31/31 gate conditions, freeze declared at digest `06f0464b5c961bb9…` |
| `make test-contracts` | **44785 checks, 0 failures** |
| `make test-rust` (core, services, shells/linux, lab, tests) | **3856 tests, 0 failed, 0 ignored** |
| `make cross-check` | **green**, and PARTIAL in the terms G-6/G-7 fixed it to print — `twinvpnsvc` `core-host`, `twinvpn-bridge` full and `twinvpn-android-jni` full still NOT CHECKED, cause named in the output |
| `make arch-lint` | **green** — CD-3, CD-I2, CD-I5, CB-3 all clean — **and it was not reachable from `make gate`: finding G-12** |
| `contracts/FROZEN` | **Amendment 5**, digest `06f0464b5c961bb9…`, unchanged by this pass |

**Re-run of 2026-08-29, same branch, after G-12 and G-13.** Every check executed
again from a clean entry; no number below is carried from the table above.

| Check | Result |
|---|---|
| `make gate` (bootstrap, lint — now including `arch-lint` per G-12 — contracts, verify-bindings, test-contracts, freeze, freeze-scope) | **green on entry** — 31/31 gate conditions, freeze declared at digest `06f0464b5c961bb9…` |
| `make test-contracts` | **44785 checks, 0 failures** |
| `make test-rust` (core, services, shells/linux, lab, tests) | **3893 tests, 0 failed, 0 ignored** |
| `make cross-check` | **green**, and PARTIAL in far fewer terms after G-18: `twinvpnsvc` `core-host` and `twinvpn-android-jni` `full` are now **compiled**, the Swift shells are **parsed** (G-15), and the one line left is `shells/macos` `twinvpn-bridge` `full` — an Apple SDK, on Apple hardware |
| `make arch-lint` | **green** — CD-3, CD-I2, CD-I5, CD-CB3 clean, and **reachable from `make gate`** for the first time (G-12) |
| `contracts/FROZEN` | **Amendment 5**, digest `06f0464b5c961bb9…`, unchanged by this pass |

The delta from 3856 to 3893 is G-13's `pairing_offer` tests and its two fuzz
targets. **The sixth pass re-ran all four checks after G-15/G-17/G-18 and the
numbers are unchanged** — 31/31, 44785, 3893/0/0, `cross-check` green — which is
the point: G-15 and G-18 added *coverage*, not tests, and G-14 and G-17 corrected
*prose*, not behaviour. The one test-visible change is that seven Swift files
that no compiler had ever read now parse.

A test count is evidence of a suite, not of a product. What the numbers above do
and do not license is §11.3.

### 11.2 Gate findings register

`G-` for the gate pass. Same three kinds as §8: a **ruling** interprets Phase 1,
a **defect** needs a contract or an ADR moved, a **gap** is undecided.

**G-1 … G-5 are the pass of 2026-08-28. G-6 … G-9 are a second pass, of
2026-08-29**, run in two isolated worktrees: **G-6** and **G-7** came from the
G-4 follow-up (the `CryptoProvider` fix that does not exist, and the crate the
exclusion was hiding), **G-8** and **G-9** from §8's two "needs approval" rows —
**W-24** and **W-21** —
and carried each as far as it could go without an approval: one turned out not to
need one and landed, the other stops at the ask. **G-10 and G-11** are a third
pass, also of 2026-08-29: **G-10** from the gate's own flakiness, **G-11** from
the last of §8's rows that pointed at the W-24 amendment — **W-25** — which was
carried down G-8's road and turned out not to belong on it. **G-12 is a fourth
pass, also of 2026-08-29**, which re-ran every check in §11.1 from a clean start
rather than reading the earlier pass's numbers, and found the gate's own coverage
short by one target. **G-13 and G-14 are a fifth pass, of 2026-08-29**, against
the one gate clause §11.3 named as closable by writing code: **G-13** implemented
the payload Amendment 4 had contracted, and **G-14** is what re-reading the
clause afterwards found — that the refusal left behind states a reason which is
measurably not the reason. **G-15 and G-16 are a sixth pass, also of
2026-08-29**, against the *other* standing clause — the platform one — asking
not "can this host run the platforms" (it cannot) but "what does this host check
that nobody wired up". **G-15** is the answer and it was a language: Swift.
**G-16** is what wiring it exposed about where the non-host proof runs at all.
**G-18** is what re-testing G-4's blocker rather than re-reading it produced: two
of its three NOT CHECKED lines were never blocked.
**G-20 … G-24 are a seventh pass, of 2026-08-29**, and it is the first pass that
was mostly *implementation*: the integration lead ruled on the two questions the
sixth pass had recorded (§11.4 **D-6** and **D-7**), which turned G-16 and G-17
from asks into work. **G-20** and **G-21** are what writing G-14's two unblocked
producers found — one contract divergence and one finding measured over too
narrow a tree. **G-22**, **G-23** and **G-24** are what wiring `cross-check` into
CI and implementing **D-1** found at their edges: a required check that may be
required by nothing, a banner that asserts on a runner what holds only here, and
a user-facing sentence that turns out not to exist.
**G-25 and G-26 are an eighth pass, also of 2026-08-29**, against the one
`pair.confirm` blocker §8 still carried, and it is the first pass whose product
is a refusal to write code. **G-26** is the blocker re-measured: the handover
reported `PairingAttestation` as structurally unspecified, and the frozen CDDL
says otherwise — the statement is complete and it is the `transcript_hash`
*preimage*, one sentence of §7.4 rationale that §11.1 never made a rule, which
is missing. **G-25** is unrelated and was surfaced by reading `pairing/enrol.rs`
in full: F-2's C-D authorization residual is disclosed in the module doc and
warned by the daemon at every start, and had reached the register nowhere.
**G-17** is the sixth pass turning the same question on the pairing clause —
asking the corpus what it actually says rather than asking the tree what it
believes — and it corrects both G-14 and this section: two of the three producer
gaps are implementations that ADR-0007 already requires, the third is a
four-part ruling nobody has taken, and C-B never needed SPAKE2. They are in this
register rather than in §8 because §8 records what wave 1 found and this records
what was done about it, which is the convention G-5 states.

| # | Kind | Finding | Disposition |
|---|---|---|---|
| **G-1** | **defect — the gate itself** | **`make lint` was red on the integrated branch, and it was not only formatting.** `cargo fmt --check` differed in eight places across `twinvpn-core` — the L-DATA and L-CONTROL commits `a6de458` and `ee542b0` — and because `lint-rust` runs fmt **before** clippy, the fmt failure was masking **six clippy errors under `-D warnings`** in the same new code: `similar_names` (`code` beside `core`), `single_match` twice, `match_same_arms`, `needless_pass_by_value` (a `Box<Diagnostic>` taken by value and only read), `too_many_arguments` (`handshake::drive`, 9/7) and `too_many_lines` (`execute::connect`, 125/100). `doc-check` was behind both and had its own failure: an unresolved intra-doc link to `crate::core::Core::start_pump`, a function that does not exist. §7 requires the full gate green **after each integration**; on this branch it had never been run to completion. | **Fixed, and the fixes are code rather than `allow`s.** `make fmt`; `code` → `refused_with`; both `match`es → `if let`; the two identical `Failover` arms merged with one comment that says why two different verdicts produce the same action; `failed` takes `&Diagnostic`; `drive`'s six travelling parameters became `handshake::Attempt`, which also stops a caller pairing one session's `keying` with another's `peer`; `connect`'s steps 7–8 became `recorded`, taking the session lock **after** the check that releases it rather than holding it across the call; the doc link now names `execute::carriage::start`, which is what actually sets the field. `make lint` is green for the first time on this branch. Recorded rather than quietly corrected: a gate that was red on arrival is the one fact a gate report may not omit.
| **G-2** | **defect — a substitution that outlived its cause** | **`twinvpn-store` was still emitting six conditions under other conditions' codes**, on the strength of a module header that Amendment 1 falsified. The header said fourteen `STORE.*` codes and ST-23's `CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED` were absent from the registry; all fifteen have been registered since (454 codes, W-18). Consequences while it stood: an L1 single-record tag failure (`STORE.RECORD_CORRUPT`, `TRANSIENT`/`WARN`, "wait") told the user their local data "has been rebuilt" (`STORE.VAULT_CORRUPT`, `PERSISTENT`/`ERROR`, user-actionable); a **survivable** migration failure said the same of a store the variant's own contract guarantees is intact; a contended lock — ADR-0020 SI-5's *security event* — was indistinguishable from a corrupt vault; a missing anchor was reported `FATAL`/`terminal` under `ANCHOR_MISMATCH`; and every Tier-1 refusal degraded on the `AUTH` prefix (ADR-0015 §11.2 rule 5) to "authentication problem" when the truth was "this device's local secure storage is not answering". | **Fixed** — `core/crates/twinvpn-store/src/error.rs`. Every condition is emitted under its own registered code, the `VaultIo` file-set is split by `vault::io_error`'s ST-32a detector into `WRITE_SPACE_EXHAUSTED` / `READONLY_FILESYSTEM` / `LOCK_CONTENDED` / `PATH_UNSUITABLE` with an unnamed detector staying `VAULT_CORRUPT` rather than being guessed, and the evidence Amendment 1 declared (`namespace`/`detector`, `schema_from`/`schema_to`/`step`) is attached and asserted to survive `Evidence`'s declared-set filter. **Why it went stale and the others did not:** every other domain carries a table plus a tripwire test — `twinvpn-session`, `twinvpn-route`, `twinvpn-enforce`, `twinvpn-mgmt` and `twinvpn-platform-android` all emptied theirs when Amendment 1 landed, because the test failed the moment a spelling became registered. This module had prose. It now has `INTENDED` and the **inverse** tripwire: each code must be *present*. |
| **G-3** | **defect — `contracts/`, and it needs approval** | **Six `STORE.*` entries added by Amendment 1 carry `evidence_fields` that were tokenized out of ADR-0020 §11.12's prose.** `STORE.READONLY_FILESYSTEM` declares `the`, `path`, `itself`, `and`, `pseudonymized`; `STORE.RESTORED_FOREIGN_HOST` declares `bool`, `only`, `the`, `host`, `identifiers`, `themselves`, `are`; `STORE.KEYSTORE_UNAVAILABLE` declares `coarse`, `category`, `never`, `the`, `raw`, `status`; `KEY_INVALIDATED`, `LOCK_CONTENDED` and `WIPE_INCOMPLETE` carry the same kind of debris. **Two consequences, and the first is a security one.** (1) The declared-set filter is what makes "never log a secret" a *mechanism* rather than a review item — and for these two codes it now **admits** exactly the fields the ADR forbids: §11.12 says of `READONLY_FILESYSTEM` "the path itself is SENSITIVE and pseudonymized" and of `RESTORED_FOREIGN_HOST` "the host identifiers themselves are SENSITIVE and MUST NOT be attached". An emitter attaching `path` or `host` would pass. (2) Each damaged list is exactly **8** entries and the real trailing fields are truncated: `READONLY_FILESYSTEM` keeps `errno` and loses `syscall`/`os_error_code`/`platform`, which W-6 put there. | **APPROVED and landed as Amendment 3** (`contracts/FROZEN`, 2026-08-28), on the repository owner's explicit approval under §3 steps 3 and 6, after being shown that the declared-set filter was admitting two fields ADR-0020 §11.12 forbids. **Nine** entries were corrected, not six: re-reading all 254 of Amendment 1's codes against their owning documents added `PATH_UNSUITABLE` (`locking`), `KEYSTORE_LOCKED` (`pre_first_unlock`) and `BACKUP_EXCLUSION_FAILED` (`cloud`) — enum **values** promoted to field names by the same split. `registry_version` 3 → 4; no code added, renamed or reclassified; no `.proto`, no `.cddl`, `contracts/gen/**` byte-identical. `test_registries.py` gained a `PROSE_DEBRIS` tripwire so the generation bug cannot return silently. This is a genuine contract defect (step 1), documented here (step 2). Compatibility (step 5) is favourable: `evidence_fields` is **not** in `check_registry_append_only.py`'s `FROZEN_REASON_ATTRS`, so correcting it does not violate ADR-0015 §11.2 rule 1, no `.proto` moves, and no binding regenerates; the wire is unaffected because these keys have no emitter. It is still an Amendment 3 with a `contracts/FROZEN` re-declaration, and the acceptance gate's own first clause makes an unapproved `contracts/` change a failure — so it stops here, at the ask. **No current emitter attaches any of the debris**, so the exposure is latent rather than live. |
| **G-4** | **defect — a wave-2 guarantee regressed** | **`ring` is back in the dependency graph, and it took every core-hosting shell crate out of `make cross-check` with it.** The Makefile records that both shell workspaces became checkable **whole** only when `ring` left the graph, and that the first full run then found a real error in Windows lines nothing had ever compiled. L-CONTROL reintroduced the edge by another road — `twinvpn-cp-client` → `quinn` → `quinn-proto`/`rustls` → `ring` — whose build script needs an MSVC, Darwin or NDK C toolchain that this host does not have. `make cross-check` **failed at its third step**, so `twinvpn-platform-ios` and `twinvpn-platform-android` were not checked either. Uncompiled by anything on this host: `shells/windows` (`twinvpnsvc`, `twinvpnctl`), `shells/macos` `twinvpn-bridge`, `shells/android/jni`. M-5's "the Rust half is clippy-clean for `aarch64-linux-android` under `make cross-check`" no longer holds. | **Mitigated, not fixed, and the difference is stated.** `cross-check` now checks everything this host can still reach — the four macOS crates that do not host a core, both mobile platform crates, both desktop platform crates — and **names the blocked crates and the cause** in its own output instead of dying at the first one. A `cargo tree -i ring` probe per blocked workspace is the tripwire: **if `ring` ever leaves that graph, the target fails and demands the exclusion be deleted**, so the coverage cannot stay lost by inertia. The real fix is a rustls `CryptoProvider` decision for `twinvpn-cp-client` — the pure-Rust providers are unaudited and CD-I2 governs the choice — and it is **owed to `core-controlplane` and the integration lead**, not to a Makefile. Until then a Windows builder and a macOS builder are owed for these crates, which is §9.2's row rather than a new debt. |
| **G-5** | record correction | **§8's disposition table is behind the tree in four places.** (a) **R-5**, **R-11** and **R-15** have no disposition row at all, though all three are fixed in the tree: `pump.rs` compares `pair.ingress_peer(flow)` against the datagram's actual source before forwarding (R-5); `RELAY.PAIR_UNMATCHED` is its own condition and reaches `Refusal::Other`, never `CapacityUnspecified`, so it no longer collapses onto `RELAY.CAPACITY_REJECTED` → `Attribution::Capacity` → fail over (R-11); `twinvpnctl` calls `twinvpn_diag::render` and `twinvpnd` carries `next_action_key` for every **registered** code (R-15). (b) **item 2** still reads *"Still open: there is no handshake and no key exchange"*, which `a6de458`, `ee542b0` and `415bbe5` closed: `execute::handshake` drives `Noise_IKpsk2` through `twinvpn_tunnel::bind`, and `tests/e2e/real_crypto_crossing.rs` carries a packet between two composed endpoints under production `SessionKeys`. (c) **W-11**'s "Not patched" predates Amendment 1, which registered all eight `CONTROL.*` codes it names. (d) Amendment 2's own "STILL OPEN after this amendment: the `twinvpn-platform` mapping itself" is closed — `PlatformError::Transient` maps to `codes::PLATFORM_ADAPTER_BUSY` in `twinvpn-platform/src/error.rs`, with the Windows adapter's tripwire asserting it, so **W-40 is closed in both halves**. | **Corrected here rather than by editing the rows**, so the record of what was found stays readable beside what was done — §8's own convention. The one thing G-5 is not: evidence that the register is unreliable. Every correction above was verified in the tree by this pass, and three of them are the register lagging *good* news. |
| **G-6** | **gap — the fix G-4 named does not exist** | **A rustls `CryptoProvider` decision cannot get `ring` out of the graph, so G-4's stated real fix would not have restored a single crate.** G-4 read the edge as `twinvpn-cp-client` → `quinn` → `quinn-proto`/`rustls` → `ring` and concluded that choosing a different provider ends it. It does not, for two independent reasons, both in `quinn-proto` 0.11.17. (a) **The feature graph offers no third option.** `rustls = ["rustls-ring"]`, and `rustls-ring = ["dep:rustls", "rustls?/ring", "ring"]` where the bare `ring` feature is `["dep:ring"]`; the only alternative spelling is `rustls-aws-lc-rs`, which pulls `aws-lc-sys` — C, cmake and bindgen — and is strictly worse on this host than `ring`. There is no way to compile quinn's rustls integration without one of the two. (b) **quinn-proto uses `ring` outside the provider seam.** `crypto/ring_like.rs` implements `crypto::HmacKey`, `crypto::HandshakeTokenKey` and `crypto::AeadKey` **on ring's own types**; `config/mod.rs` builds the default `EndpointConfig` reset key and token key with `ring::hmac`/`ring::hkdf`; `crypto/rustls.rs` takes `use ring::aead` for the Retry integrity tag and picks the provider in `configured_provider()` under `#[cfg]`, with no injection point. A provider swap reaches none of that. This is not a stale pin: `quinn` 0.11.11 and `quinn-proto` 0.11.17 are the newest published versions of either crate, so it is current upstream. The host half was re-probed rather than assumed — `ring` 0.17.14 alone fails for all three targets here: `failed to find tool "lib.exe"` (MSVC), `cc: unrecognized command-line option '-arch'` (Darwin), `failed to find tool "aarch64-linux-android-clang"` (NDK) — and `build.rs` has no escape hatch, `RING_PREGENERATE_ASM` regenerates assembly and does not skip the C. | **The edge stays; the exclusion does not.** Two separable things were wrong, and only the first is still open. **(i) The edge is still there**, so the three `cargo tree -i ring` tripwires stay — each now says which *profile* it is asserting about (`core-host` on Windows, `full` on the other two), because that is the condition under which deleting it would be right. The Makefile's account of the cause, which named a fix that would not work, now records (a) and (b) and points here. **(ii) The coverage did not have to stay lost, and it no longer is.** `make cross-check` compiles all four crates under the reduced profile the repository already declares — `core-lite`, ADR-0018 §11.12's parse-and-verify-only profile (S-46), which carries no data-plane crate and no `twinvpn-cp-client`, hence no `quinn`, no `rustls`, no `ring`, no C. Every shell keeps `default = ["full"]`, so **nothing that ships changes**; the feature pairs added to `twinvpn-bridge`, `twinvpn-ffi` and `shells/android/jni` forward a profile and switch none of their own code. **This is a partial proof and the banner says so in those words:** the shipping profile is `full`, the lines reachable only under it are still compiled by nothing on this host, and that residue is exactly what a real Windows/macOS/Android builder is for. It is the difference between three workspaces exempted wholesale and three workspaces checked with a named, visible hole — which is also how G-7 stopped being invisible. **Adopting `core-lite` for this purpose is the repository owner's decision**, on the condition that the target name the profile in its own output and state the residue rather than imply it away; the banner does, per crate, with `NOT CHECKED` against the profile that is not covered. One wording note that decision carries: every `NOT CHECKED` is scoped to *what this target runs*, not to the machine. This host is Windows 11 under WSL2 with interop enabled, so a native Windows build lane — separate work, not this pass's — would make a machine-scoped claim false the day it lands while leaving a target-scoped one exactly as true as it is now. **Four options remain for the edge itself, none of them a Makefile edit and none of them this pass's to take.** (1) **Fork `quinn-proto` under `[patch.crates-io]`** — make the rustls integration provider-agnostic and rebuild `ring_like.rs` on the RustCrypto primitives `twinvpn-crypto` already pins. Cost: a maintained fork of a QUIC state machine's crypto seam, and it *still* needs a pure-Rust rustls provider, every candidate being unaudited (`rustls-rustcrypto` is published at `0.0.2-alpha`), which CD-I2 makes a security decision and not a build convenience. (2) **Leave `quinn`** — `s2n-quic`, `quiche` and `neqo` bind `s2n-tls`, BoringSSL and NSS respectively, so all three are worse to cross-compile, and ADR-0001 §11's mutual raw-public-key auth is today rustls' `AlwaysResolvesClientRawPublicKeys` and would have to be rebuilt against a new API. (3) **Provision the target C toolchains** — the Android NDK is freely obtainable and wave 3 needs it regardless; MSVC needs `xwin` plus `clang-cl`/`llvm-lib` and a Microsoft licence accepted on the build host; the Darwin SDK's licence confines it to Apple hardware, so **`shells/macos` `twinvpn-bridge` cannot be reached this way at all** — a partial fix, and an `infrastructure` change rather than a core one. (4) **Retarget the Windows proof at `x86_64-pc-windows-gnu`**, where `ring` builds under mingw-w64: cheap, but it proves a target we do not ship and the banner would have to say so. Owed to `core-controlplane` and the integration lead, as G-4 already says; what G-6 changes is *which* decision is owed. |
| **G-7** | **defect — a crate that compiled for no target at all, and an exemption that hid it** | **`twinvpnsvc` did not build under the one command its own `Cargo.toml` names as its only compile proof.** That manifest documents `cargo clippy -p twinvpnsvc --no-default-features --features service --target x86_64-pc-windows-msvc -- -D warnings` and says of it, in the file, that it "is the only compile proof this domain's `#[cfg(windows)]` service code has, and without the split there would be none". It fails: `service/mod.rs` gates `pub mod runtime;` and `pub mod server;` behind `#[cfg(feature = "core-host")]` and does **not** gate `pub mod events;`, while `events.rs` names `twinvpn_core` at lines 9, 49 and 230 — and `twinvpn-core` arrives only with `core-host`. Two `E0433`s, on the lib and again on the lib test. So the whole Win32 service surface — SCM registration, the trimmed privilege posture, the pipe DACL, `SERVICE_CONTROL_POWEREVENT`, the WTS console-seat check of PS-14, the start sequence — plus the Windows CLI, was compiled by **nothing, on any target, including this host**. **Why nothing caught it is the more serious half.** G-4's mitigation exempted `shells/windows` wholesale: the block ran the `cargo tree -i ring` tripwire and **no `clippy` at all**. An exemption written to preserve honesty about coverage had become a place a compile error could sit unseen — which is the failure mode a tripwire is supposed to prevent, arriving through the door the tripwire left open. | **Fixed, in one line, and the exemption that hid it is gone.** `#[cfg(feature = "core-host")]` above `pub mod events;` — correct on its own terms and not merely convenient: `events` is used by `runtime` and `server` and by nothing else, both already gated the same way, so the attribute removes no code from any build that ships. Both `-p twinvpnsvc --no-default-features --features service` and `-p twinvpnctl` then pass clean at `-D warnings` for `x86_64-pc-windows-msvc`. **`make cross-check` now runs both**, so the workspace can no longer be silent: under G-4's arrangement this defect would have survived any number of green gate runs. The `ring` tripwire stays beside them, because `ring` is still in the graph under `core-host` and the exclusion it guards is still real — what changed is that the exclusion is now one *feature* wide instead of one *workspace* wide. |
| **G-8** | **defect — W-24, CLOSED as a compatible ABI addition** | **§8's W-24: ADR-0018 §11.4's F-9 vtable has no `installed_ruleset` read-back and no `current_generation`, so ADR-0015 §11.6 rule 1's `ProtectionAssertion` — "produced by **querying the enforcement layer** … never of the agent's belief" — could not be produced across this ABI at all.** The disposition asked for "ADR-0018 §11.4 amended, or an explicit acceptance that a vtable-only shell cannot assert protection". **Neither was needed, and the reason is in §11.4's own words**: "Its first field is `uint32_t size`, so entries may be added without an `abi_major` bump". That is the mechanism §8's **W-26** already used, on the integration lead's approval, for four earlier entries. | **Landed as a `TW_ABI_MINOR` addition, 1 → 2, under VR-1** — `core/ffi/include/twinvpn.h`, `twinvpn-ffi/src/vtable.rs`, `twinvpn-core`'s `ABI_MINOR`. Two entries **appended** after `boot_id`: `installed_ruleset(ctx, h, ruleset_out, present_out, err)` and `current_generation(ctx, h, generation_out, present_out, err)`. Nothing was removed, no signature changed, and **no existing entry moved** — position is an ABI constraint, not taste, and the header says so at the definition, because moving one changes the prefix every older shell already compiled. **Three outcomes are kept apart** rather than collapsed: the entry *absent* is still the typed refusal, because an unreadable posture is not an asserted one and `Ok(None)` would read as "nothing installed" — the opposite of the truth; `present == 0` is `Ok(None)`, now an *answer*, because the shell queried the OS and found no rules of ours; and a posture value this core does not recognize is **refused**, never rounded, since rounding up asserts protection nobody stated and rounding down hides a shell defect. Both out-parameters are initialized core-side, so a shell returning `TW_OK` without writing them cannot leave a `0` to be read as `TW_RULESET_BLOCKED`. **R-3's clamping rule is tested against exactly this change**: a buffer that genuinely ends at the minor-1 struct, poisoned past it, proves the two new entries read as absent, that the poison is never called, and that an entry the older shell *did* declare still works — which is the whole claim of a minor bump. §10.4's wave-3 ruling stands and is now narrower: the mobile bridges may keep sockets and interfaces in Rust for **W-25's** reasons, but "a vtable-only shell cannot assert protection" is no longer true. **Two residues corrected with it**, on §4.3's lesson that a reason outliving its cause is the failure mode: `dispatch.rs`'s `killswitch.get`/`killswitch.exempt.get` refusal no longer blames F-9 — the read-back exists on every adapter and the operation is simply not wired to it — and `killswitch.mode.set` is recorded as a **different fact entirely**, since MI-S3's `OFF < ARMED_ON_INTENT < ALWAYS_ON` order over S-18 is not the `BLOCKED`/`PROTECTED` posture and no adapter reports it. That refusal had been filed under W-24 and never belonged there. **One thing this does not close, and it is worth counting:** ADR-0018 §11.4's printed struct declares 16 fields where `twinvpn.h` now declares 25 — the six this domain added plus `buf_free`, `secure_item_delete` and `record_aead_custody`, none of which §11.4's code block names. The header is the ABI of record (§11.12); reconciling the ADR's listing to it is the integration lead's. |
| **G-9** | **defect — W-21, brought to the point of decision and stopped there** | **§8's W-21: `PairingOffer` — ADR-0007 §7.4's deterministic-CBOR C-B payload — is in no contract.** Three things make it a §3 defect rather than an inconvenience. (1) **It is the whole of enrolment, not one message**: ADR-0023 EM-22's four channels (terminal QR, text offer, reverse ceremony, first-boot provisioning) are all C-B, and W-22 already ruled C-A unimplementable, so every shippable enrolment path carries a payload the contract does not define. (2) It is the **most** untrusted input in the system — parsed by a device holding no trust anchor, from a camera or a paste buffer — and §6 rule 9 requires it validated against `limits.json` before any length-proportional allocation, while `limits.json`'s `pairing` object bounds the ceremony and says nothing about the offer. (3) §7.4 prints field names and types but not the encoding decisions that determine the bytes, so two independent implementations would fail to interoperate at a real ceremony with no diagnosis. | **A §3 amendment proposal, written and NOT applied**: [`w21-pairing-offer-amendment.md`](w21-pairing-offer-amendment.md), answering steps 1, 2, 4 and 5 with the exact diff. **Nothing under `contracts/` was touched.** It asks for one new `cddl/twinvpn/v1/pairing_offer.cddl`, six new `pairing.*` keys in `limits.json`, and three assertions in `test_registries.py`. **It is the smallest of the four amendments to date: no `.proto`, no reason code added or reclassified — every condition the payload can raise is already registered (`PROTO.NON_CANONICAL_CBOR`, `PROTO.SIZE_EXCEEDED`, `PROTO.DEPTH_EXCEEDED`, `AUTH.PAIRING_EXPIRED`, `AUTH.PAIRING_ATTEMPTS_EXCEEDED`) — and `contracts/gen/**` byte-identical.** The one wire-visible consequence is `SchemaDescriptor.schema_digest`, which all three earlier amendments moved for the same reason. **The placement argument is the part worth reviewing**: it is *not* `pairing.proto`, whose own header forbids it in terms ("`pairing_secret` … NEVER appear in this schema and MUST NOT be added") and whose messages are C1/C2 wire messages, where embedding the secret would hand the rendezvous the one value C-B's security argument requires it never see; and it is *not* `signed_statements.cddl`, because the joining device is by definition unenrolled, holds no anchor, and has no key to verify a signature against — C-B's authentication is the optical channel, so a COSE_Sign1 there would be bytes shaped like a proof, verified by no one. **Three findings came out of writing it, and the first is the significant one.** **F-1: the offer does not fit its own default channel, measured.** Encoded to RFC 8949 §4.2.1 with `attestation` absent and a 27-character hint it is **377 bytes**; ADR-0023 E1 makes the terminal QR the default "whenever the terminal is ≥ 71 columns × 37 rows", and 71 columns with a conforming 4-module quiet zone admits at most a 61-module symbol — QR version 11, **321 bytes at EC level L**, the *weakest* correction level for a symbol photographed off a glowing screen. **56 bytes over, before any attestation blob.** No document fixes the QR version, the error-correction level or the quiet zone, and those three decide whether the product's default enrolment channel works at all. Two exits, both somebody else's: E1's geometry grows to **77 × 39**, or `binding` shrinks — it is **219 of the 377 bytes** and the `TunnelKeyBinding` inside it re-states `tk_pub`, which field 3 already carries. W-23 is the standing lesson that a specified derivation is not ours to improve, so neither is taken here. **F-2:** `tk_pub` is spelled `bstr(32)` in §7.4 and `cose-key` in `signed_statements.cddl`'s `tunnel-key-binding` and `device-identity-record` — one key, two spellings, both inside the same 377 bytes. **F-3:** §4.3 ruled that `limits.json`'s stale `_max_name_bytes_note` should be folded "into the next amendment that opens `contracts/` for a real reason". This is that amendment, and the diff deliberately does **not** fold it in, so the approver is not shown a second unasked edit — but it is the cheapest it will ever be. **APPROVED and landed as Amendment 4** (`contracts/FROZEN`, 2026-08-29), on the repository owner's explicit approval under §3 steps 3 and 6: the new `.cddl`, the six `pairing` bounds at `registry_version` 3, and the contract tests. F-3 **was** folded in on approval, as the row above said it should be once the approver had seen the ask. No `.proto` and no existing `.cddl` moved; `contracts/gen/**` byte-identical, because CDDL has no codegen here. **F-1 is NOT resolved and this amendment says so in its own text**: the contract is now nameable and ADR-0023 E1's default channel still does not fit it, which is an ADR owner's call and not an implementation agent's. — **F-1 CLOSED as far as ADR-0023 can close it, by new rule EM-22a**, and the arithmetic corrected twice on the way. E1 named a terminal size and *nothing else*: no QR version, no error-correction level, no quiet zone, which is the half of F-1 that was a specification defect rather than a size problem, and is unambiguously ADR-0023's to fix. EM-22a pins v13 / level L / a 4-module quiet zone / the half-block model, and **derives** the geometry from them: **79 × 41**, not the 77 × 39 first reported — that figure omitted the 1-character border E1's own 71 × 37 implies (61 + 8 + 2 = 71, ceil(69/2) + 2 = 37), and the model reproducing E1's existing number is the evidence it is the right model. 79 ≤ 80 keeps EM-44's 80-column rule, with one column to spare. **Level L is forced, not chosen:** v13-M holds 331 < 377, and the smallest level-M symbol that holds 377 is v15 at 87 columns, which breaks EM-44 — so at this payload size no level-M configuration fits a compliant terminal. **That is the argument for the other exit, and it now has numbers:** `binding` by reference gives a ≈224-byte offer, which fits **v11 at level M** — the original 71 × 37, at the stronger level, better on every axis. It is an ADR-0007 §7.4 change and belongs to SECURITY under W-23, and EM-22a says in terms that it reverts if that lands. **One residue, and it needs approval:** `PLATFORM.EMBEDDED.ENROLMENT_TERMINAL_TOO_SMALL`'s registry `condition` still reads "smaller than 71×37". `condition` is not among `check_registry_append_only.py`'s frozen attributes so correcting it is compatible, but it is still a `contracts/` edit and therefore an Amendment 5 ask, not a patch to land. — **APPROVED and landed as Amendment 5** (2026-08-29): one `condition` string, 71×37 → 79×41. **No `registry_version` bump, deliberately**: ADR-0015 §11.2 rule 4 makes human text rewordable, `condition` is not a frozen attribute, no consumer validates against it, and Amendment 2's own rule cuts the other way — bumping would claim a change a reader could not find in any machine-readable field. The digest moves, which is the honest signal that bytes changed and meaning did not. `twinvpn-diag` derives its neutral text from this field at build time, so the sentence an operator actually reads followed automatically — which is also why leaving it stale would have shipped the wrong number to the one person it exists for. One correction while applying: the proposal's `pairing.proto` tripwire searched raw text, so it failed on the prohibition sentence that necessarily names what it forbids — it now cuts comments and inspects declarations. |
| **G-10** | **defect — a flaky test, which is a flaky gate** | **`lock::tests::a_closed_descriptor_is_an_errno_and_never_a_silent_false` fails at random, and when it passes it is sometimes locking a stranger's file.** It closed a `File` and called `flock` on the retained raw descriptor expecting `EBADF`. `cargo test` runs a crate's tests on threads of ONE process, so any other test opening a file between the `drop` and the `flock` takes the freed descriptor number — the call then succeeds against that file and the assertion fails as `EBADF: true`. Caught by the integration gate on the merged tree, not by the domain: it needs the whole crate's suite running concurrently to lose the race. The gate's own last fail condition is *"repository tests do not pass"*, and a test that fails on a schedule nobody controls makes that condition non-deterministic. | **Fixed** — the descriptor is now one that CANNOT be open rather than one the test closed: `RawFd::MAX` is above any `RLIMIT_NOFILE` a process can raise, so no thread can make it valid and the errno is the same one every time. The property under test is unchanged and is the one the name states — an invalid descriptor surfaces its `errno` and never reads as "somebody else holds it", which would report PS-1's violation for a programming error and send an operator looking for a second agent that does not exist. Renamed to `an_invalid_descriptor_…` because *closed* was never the property; it was the mechanism, and it was the wrong one. Five consecutive runs green. |
| **G-11** | **ruling — W-25, and the answer is that the ABI is right and the row's premise is too wide** | **§8's W-25: F-9 has no socket provider and no interface enumerator, though ADR-0018 §11.2 row 2.10 puts *all* NAT traversal in the core "with sockets via the adapter" and `twinvpn-platform` requires both.** The disposition said "same amendment as W-24", so this pass carried it down the road **G-8** had just proved passable — F-9's `size` field makes an append a minor bump — and found that the two halves of W-25 do not travel it together, and that one of them must not travel it at all. **Sockets are the datapath, and the seam is async where the ABI is not.** Four carriages were considered. (1) **Blocking with a deadline**: `recv` blocks on the *network*, not on a bounded unit of adapter work, which is what §11.6's "bounded by the adapter's own contract" licenses; §3.6's birthday-paradox port prediction opens many sockets at once, so it costs either many parked threads or a poll interval — and §5.1 rejects a poll interval for exactly the reason it would bite here, that the interval is added directly to `T_FAILOVER_TARGET`. (2) **Readiness/poll**, the `NEPacketTunnelProvider`/`VpnService` shape: removes the parked thread, keeps one crossing per datagram to drain. (3) **The F-9 inversion**, which `subscribe_network_change` already uses: this one is the closest precedent and is still wrong here, because it puts every datagram through an F-8 encode/decode and onto the *single ordered command stream* S-47 serializes — and F-8's own budget says that encoding is "free at the event rates §9 establishes, and a §14 revisit trigger if those rates change", which this changes by four orders of magnitude. (4) **Do not cross at all.** | **(4), and it is already the tree's answer rather than a new one.** **The arithmetic refutes 1–3 without a benchmark:** PB-1's headline is *zero* FFI crossings per packet and its table reads `0` for every target but the Apple app-extension's `NEPacketTunnelFlow` (a Swift API, not this ABI); PB-4 then prices the split at **0 ns/packet** on Linux, Windows, Android and OpenWrt. At PB-3's desktop **userspace** gate — ≥ 60 % of ≥ 90 % of 1 GbE, so ≈ 540 Mbit/s — a 1420-byte payload is **≈ 47 500 datagrams/s per direction, ≈ 95 000 crossings/s for one peer**. A per-datagram entry therefore falsifies PB-1 and PB-4 **by construction**: the floor for an F-9-shaped indirect call measured on this host is **1.41 ns**, and 1.41 ≠ 0. The cost that actually decides it is not the call: **F-6 forbids a vtable callee from re-entering a mutating core function**, so every received datagram owes a hop to the one mutating thread S-47 allows — measured here at **≈ 34.5 µs** for a thread-to-thread round trip, against a **21 µs** whole-packet budget at that gate. On Swift and Kotlin the callee is not even C. **The premise is narrower than the row states, and that is this finding's substance.** W-25 says "a Swift or Kotlin shell binding only this ABI". **No shell in the tree is that shell**, and none can become one: `shells/linux` links `twinvpn-platform-linux`; `shells/macos/twinvpn-bridge`, `shells/ios/Sources/TwinVPNBridge` and `shells/android/jni` are per-platform `extern "C"` bridges over `twinvpn-platform-{macos,ios,android}`, each of which implements `SocketProvider`, `UdpSocket` and `InterfaceProvider` in Rust. §10.4 ruled this for the two mobile shells and **X-7 generalised it**; PB-1 is why it is the *only* available shape rather than a concession. **Interface enumeration is the other half and gets a different answer: admissible, and blocked on something else.** It is control-rate, so PB-1 and PB-4 do not reach it — but **F-8** requires it to cross as a blob generated from an ADR-0003 contract artifact, and `contracts/` has none that can carry `InterfaceFacts`. `twinvpn.v1.NetworkInterface` is the only candidate and is lossy three ways: **no interface index** (the identity `InterfaceIndex` exists to be, *"deliberately not a name"*), **no `link_class`** (so `NET.LINK.DOWN_WIFI` and `NET.LINK.DOWN_CELLULAR` collapse to one code), and `addresses` as `repeated IPPrefix` — the exact shape `InterfaceFacts::addresses` records as *"the defect"* three domains reported independently, and the one **W-39** shows drops `fe80::/10` outright. Encoding over it would reinstate a defect the corpus has already fixed once, so this stops at the ask, as **G-9** did for W-21: **`contracts/` is untouched.** **What landed is code, and it is an honesty fix rather than a capability.** `NoSockets` and `NoInterfaces` refused with `PLATFORM.ADAPTER_UNAVAILABLE`, which the registry classes `LOCAL_ACTION` — it sends a user to go and fix something locally, and **nothing local gives a vtable-only binding a socket**. They now refuse with `PLATFORM.OS_UNSUPPORTED`, `UPDATE_REQUIRED`, which is both true and what the file's other three structurally-absent capabilities (`read_packet`, `write_packet`, `query_link_facts`) already said — a one-file inconsistency about one fact. `twinvpn.h` gains two "WHAT IS DELIBERATELY ABSENT" bullets, one per half, because the next reader will otherwise re-derive this; **`TW_ABI_MINOR` stays at 2 and no entry was added, moved or removed.** Three tests pin it, including one asserting that **no entry this ABI carries is on the datapath** — a future `udp_send`/`udp_recv` breaks it, which is the point. **This does not discharge W-25 in the direction §10.4 already reserved:** the general claim "a vtable-only shell can do NAT traversal" is still false, and is now recorded as false **on purpose** rather than by omission. What ADR-0018 owes is not F-9 entries — it is §11.2 row 2.10's "sockets via the adapter", which reads as *across this ABI* and means *in the Rust adapter beside it*. **Referred to ADR-0018's owner as a wording defect, not a capability one.** |
| **G-12** | **defect — the gate itself, and the same class as G-1** | **The ADR-0018 T1 architectural lints were not reachable from `make gate`.** `arch-lint` runs `cargo run -p xtask -- lint`, which is CD-3's crate-boundary deny-list, CD-I2's cryptographic-dependency confinement, CD-I5's composition-root check and CB-3. It was a **named target and a CI job only**: `lint: contracts-lint lint-rust doc-check redaction-check` never listed it, and `gate` reaches the T1 lints through `lint` or not at all. The Makefile's own comment above `lint-rust` asserted the opposite — *"rustfmt --check and clippy -D warnings across every workspace, **then the ADR-0018 T1 architectural lints**"* — describing a recipe that does fmt and clippy and nothing else, so a reader auditing the gate would have concluded the lints ran when they did not. **This is the mechanism behind two of the wave's own gate clauses**: *no implementation-specific shadow contracts exist* and *no platform has independently redefined shared enums/messages* are enforced by CD-3's deny-list, which ADR-0018 CD-3 calls "the actual mechanism", and by CD-I2. A green `make gate` was therefore asserting two properties nothing in it checked. The lints were **not** red — they pass — which is why this went unseen: the defect is the coverage, not a violation behind it. The precedent for the fix is stated four lines above in the same file, where `doc-check` was left a named target with the instruction *"wire it into `lint` once the six crates are clean"* and was wired in when they were. | **Fixed.** `arch-lint` is now a prerequisite of `lint`, between `lint-rust` and `doc-check`, so it is reached by `make lint`, by `make gate` and by every integration §7 requires a green gate after. The stale comment is corrected to describe what `lint-rust` does and to name `arch-lint` as the sibling that carries the T1 lints. `make gate` re-run end to end afterwards: the lints report **CD-3, CD-I2, CD-I5, CD-CB3 — all clean**, 31/31 gate conditions satisfied, freeze declared at `06f0464b5c961bb9…`. Recorded rather than quietly wired in, for G-1's reason: a gate that was not checking what it claimed is the one fact a gate report may not omit. |
| **G-13** | **the first implementation of a frozen definition, and the gate clause it moves** | **Amendment 4 landed `PairingOffer`'s contract and nothing implemented it.** The proposal's §7 lists what lands outside `contracts/` next and says the order "is not negotiable: the contract lands first" — so `contracts/` was ahead of the tree in the one place the wave's own gate reads as a CONTROL PLANE clause. Concretely: `limits.json`'s six new `pairing.*` bounds were enforced by **nothing** (`twinvpn-schema/build.rs`'s table is the only path from the registry to a validator and none of the six was in it); no crate could parse or emit the payload; and `twinvpn-core`'s four `pair.*` refusals were still citing **W-21**, a finding closed the previous day — a refusal naming a closed cause sends an operator to read an amendment that has already landed. | **Implemented, and the scope is stated exactly because the clause is only partly moved.** (1) **`twinvpn-schema`**: the six bounds are generated constants, so no validator takes a literal; the drift test checks all six against the embedded registry, and two new tests pin the relations the CDDL's arithmetic rests on — the per-field bounds summing at or below the payload cap, and `max_offer_attestation_bytes` being zero, which is what makes `null` the only admissible attestation. (2) **`twinvpn-crypto::pairing_offer`**: decode, emit, `build`, the E2 text form, `K_pair`, and `pairing_id`. The CDDL's three secret-handling rules are types rather than comments — a hand-written `Debug` that renders `<redacted>`, `Drop` that zeroizes, and an `OfferReject` that **has no field an input byte can reach**, which is stricter than both `DcborError` and `twinvpn_schema::Reject` and is the CDDL's "NO evidence drawn from the input" made structural. Rule 2's ordering is the first line of `decode`. 25 tests, one per rule the CDDL names, plus **three fuzz targets** — the offer is what G-9 called "the MOST untrusted input in the system" and it had none. (3) **`twinvpn-types::crockford`**: E2's alphabet, declared once. The workspace already held two base32 renderings in one file, one of them not Crockford at all, and E2 would have been a third; `DeviceId::fingerprint` now takes the alphabet from the same constant. The decoder is the part that matters — it maps `O`/`I`/`L` and folds case because E2 exists for a serial console, and it **refuses** an unmapped character rather than skipping it, since a skip turns a mistyped offer into a different valid-looking one. (4) **`twinvpn-core`**: the four `pair.*` arms are **unmerged**, because they no longer share a cause. `pair.begin`, `pair.cancel` and `pair.status` are blocked on the composed core holding a `PairingLedger`; `pair.confirm` is additionally blocked on N-18's second `PairingAttestation`, which crosses the same C1 ceremony transport as `device.revoke`. **What this does NOT do, stated so the gate report cannot be misread:** the ceremony still cannot complete. The offer is now producible, transportable and parseable; the wiring that would let `Core::submit` run one is not written, and C-A remains what **W-22** ruled it — unimplementable, because no audited RFC 9382 P-256 Rust implementation exists and adding an unaudited one would breach I2 and DP-3 worse than the gap. **One discrepancy found and recorded rather than reconciled:** this encoder puts Amendment 4's own stated inputs at **378 bytes**, one above the 377 the amendment measured and ADR-0023 EM-22a derived the 79x41 geometry from. The amendment's note does not state the `not_after_ms` it measured, and a real epoch-millisecond value needs CBOR's 8-byte `uint` head where any value below 2^32 needs 5. The direction is the safe one — EM-22a's v13-at-level-L symbol holds 425 — and the assertion pins 378 rather than being adjusted to whatever the code emits. It belongs to whoever owns the measurement. |
| **G-14** | **defect — a refusal whose stated reason was wrong, and wrong in the optimistic direction** | **`pair.begin` is refused as "composition-root wiring, not a missing contract", and it is not.** G-13 implemented `twinvpn_crypto::pairing_offer`, which *decodes* an offer and *assembles* one from parts. Measured over the tree, three of the six parts `build` takes have no producer anywhere outside a testkit: field 2 `ik_pub` needs an ES256/P-256 `COSE_Key` encoder, and production holds `cose::from_cose_key` (a decoder) and `cose::x25519_cose_key` (the wrong curve) — the ES256 encoder is `twinvpn_crypto::testkit`, behind `cfg(any(test, feature = "test-support"))`; field 3 `tk_pub` is this device's L-DATA static, which `custody.rs` says "reaches the core as a sealed blob through `SecureStore`" — and `twinvpn-store` names exactly two Tier-1 items, `SEK_ITEM` and `ANCHOR_ITEM`, so nothing generates, seals, names or unseals TK; field 4 `binding` needs a `TunnelKeyBinding` emitter, and every construction of one in the workspace is `twinvpn_crypto::testkit` or `twinvpn_trust::testkit` — `binding.rs` verifies and never emits. The absent `PairingLedger` the reason named is real and is the **fourth and smallest** of the four. | **The refusal stands; its reason is corrected.** `dispatch.rs`'s `PairBegin` arm and `twinvpn-core/README.md` §6.2 now name all four, because a reason that reads "wiring" invites the next agent to add a field to `Core` and discover the other three at compile time — G-7's failure mode exactly, one level up. **No code was written to close it**, and that is the disposition rather than an omission: two of the three gaps are key-custody decisions, not implementations. **Corrected by G-17, which asked the corpus rather than the tree: (a) and (c) are implementations nobody wrote and owe no approval; only (b) is a decision.** Where the device's TK is generated, which Tier-1 item name holds it, under what accessibility class, and who unseals it are ADR-0020 and CB-5/CB-7 questions owned by `core-security` and the integration lead; §6 forbids an implementation agent from settling them. On the one host that runs, `AbsentElement` refuses `identity_sign` with `AUTH.KEY_UNAVAILABLE` (§11.16 (l)), so even a fully wired `pair.begin` would refuse here. **The gate clause CONTROL PLANE *pairing* is unchanged: "refuses correctly", not "works"** — what changed is that the register no longer implies one commit closes it. **Updated 2026-08-29:** §11.4 **D-6** rules on (b), so all three producer gaps are now implementations rather than asks. (a) the ES256/P-256 `COSE_Key` encoder, (b) TK generation and sealing, and (c) the `TunnelKeyBinding` emitter are written; the **fourth and smallest, the absent `PairingLedger`, stands**. The clause still does not move: it moves when all four exist *and are wired into the composition root*, and on this host `AbsentElement` refuses `identity_sign` with `AUTH.KEY_UNAVAILABLE` regardless. **`dispatch.rs`'s `PairBegin` reason was re-measured, not inherited** — it now says the `PairingLedger` is the whole of what is missing, because leaving it naming three gaps that had just been closed would have been this row's own defect committed a second time. `twinvpn-core/README.md` §6.2 likewise. |
| **G-15** | **defect — a whole language was checked by nothing, and it was hiding real errors** | **`shells/ios` and `shells/macos` are 28 Swift files that no `make` target and no CI job ever fed to a compiler.** §9.2 recorded them as WRITTEN, NOT COMPILED and `cross-check`'s banner said so honestly, but the honesty was load-bearing for nothing: the standing reason — a Linux Swift has no NetworkExtension, SystemExtensions, SwiftUI, Security or Network, so `-typecheck` cannot run and will not until a Darwin SDK exists (Apple hardware for `shells/macos`, by licence) — is a reason `-typecheck` cannot run, **not** a reason `-parse` cannot. `swiftc -parse` needs no SDK, and the pinned Swift 6.1.2 has been on this host all along, reachable through `build/toolchain/env.sh` and already used by `verify-bindings`. Running it found **seven invalid string-literal line continuations** in `shells/ios/TwinVPNTests/LeakAndArmTests.swift` and `LifecycleTests.swift`: a `\` at end of line inside a plain `"…"` literal, which is valid in a `"""` multiline literal and is a syntax error in a single-line one. Every one of them had reached the branch. | **Fixed, and the lane is wired so it stays fixed.** The seven literals became adjacent-literal concatenation (`"… " + "…"`), preserving the message text and its wrapping; `swiftc -parse` is now clean over both shells. `make swift-parse` is the **one definition** of the check — W-20/X-4/R-14's rule applied before it could become a fourth instance — and it has two callers: `make cross-check`, and a new `swift-parse` job in `.github/workflows/rust-t1.yml` that runs in a pinned `swift:6.1.2` container, so the check does not depend on a developer's local Swift. **The claim is stated at exactly its strength in three places** (the target's comment, the `cross-check` banner, the CI job's failure text): *the Swift sources parse under the pinned compiler*. Not type-check, not link, not run. §9.2's row for Swift moves from **WRITTEN, NOT COMPILED** to **PARSED, NOT TYPE-CHECKED**, and moves no further. Type-checking is not merely unwired but unavailable: `swiftc -typecheck` fails on even the most Linux-friendly file in the tree (`cannot find type 'CFNotificationName' in scope`) because Linux Foundation is not Apple Foundation. **Kotlin gets no equivalent and the reason is specific:** `kotlinc` has no parse-only mode, there is no `android.jar` anywhere on this machine, and the two import-free `.kt` files still fail on a cross-file reference into one that imports `android.*`. The true peer of `swiftc -parse` for Kotlin would be **ktlint's fat jar** — one ~50 MB download, runs on the JDK 21 already installed, needs no root — and that is a dependency decision rather than a wiring one, so it is named here and not taken. |
| **G-16** | **gap — the non-host compile proof is reachable from no automated gate** | **`make cross-check` is run by nothing but a human typing it.** `make gate` is `bootstrap lint contracts verify-bindings test-contracts` plus the two freeze scripts, and `cross-check` is in none of them; `.github/workflows/` has jobs for `fmt`, `workspace`, `arch-lint` and the contracts/infra/lab/supply-chain suites, and **no job runs `cross-check`**. So every claim the wave makes about Windows, macOS, iOS and Android compiling at all rests on someone remembering a command — which is G-12's defect exactly, one target over, and G-12 was found by looking for this class. | **Half-closed, and the half is named.** The Swift lane G-15 added is wired into CI directly, so it is not exposed to this. The **Rust** half is not, and the fix is not `gate: … cross-check`: the target needs four `rustup target add`s that a fresh clone does not have, so folding it into `gate` would fail every new developer's first run — the reason it was split out originally. The honest options are a CI job that installs the four targets, or a documented `make gate-full`. **Both are CI-topology decisions and CI topology is the integration lead's**, so this was recorded rather than taken: §6 rule 14, and the same rule `.github/workflows/rust-t1.yml` quotes at itself about `continue-on-error`. **Superseded in part by G-18**, which found that the Windows lane needs no CI decision at all because it needs no `cl.exe`. **CLOSED by §11.4 D-7**: the decision is the CI job, not `gate-full`, and `.github/workflows/rust-t1.yml` now carries a `cross-check` job that installs the four targets and calls the one Makefile definition. `make gate` is unchanged, so a fresh clone still works. What the job proves is what the target proves and no more — a compile, with several lanes reporting NOT CHECKED by design. |
| **G-17** | **defect — two production modules place the same secret in two different tiers, and the corpus settles neither** | **Where does this device's sealed `TK` live?** `core/crates/twinvpn-platform/src/custody.rs:31` says it "reaches the core as a sealed blob through `SecureStore`" — that is **Tier 1**, the `secure_item_*` path. `core/crates/twinvpn-store/src/namespace.rs:172` says "the sealed `TK` lives in `identity/`" — that is **Tier 2**, a vault namespace. Both are production, both are load-bearing comments beside code, and they cannot both be right. The corpus does not break the tie: **three independent enumerations of the Tier-1 set name exactly three items and TK is in none of them** — ADR-0018 §11.16 "Tier-1 secure items — SEK, `K_bind`, the S-53 anchor", the `twinvpn.h` comment "Tier 1 ONLY … (SEK, K_bind, the S-53 anchor). … NOT a general store", and ADR-0020 §11.7 "Tier 1: `SEK`, `K_bind`, and the `StoreAntiRollbackAnchor` (S-53)". ADR-0020 §11.3's ten-target table heads its column "SEK + ANCH realization" and gives TK no column; ST-1 places the TK **wrapping key** in Tier 1, which is not TK. ADR-0007 says only "X25519, generated on-device, sealed under a hardware-bound wrapping key" — no component, no trigger, no item name, no accessibility class, no unseal actor — and its §11.2 "Interfaces required from other ADRs" has **no ADR-0020 row at all**, which is why nobody noticed the question was never asked. | **Recorded, not resolved — this is the ruling G-14's (b) was waiting for and it is not an implementation agent's.** It decides where a long-lived private key lives, so §6's non-negotiable security rules and rule 14 both bite. The ruling owed to `core-security` and the integration lead has **four parts**: which component generates TK and on what trigger; Tier-1 item name **or** Tier-2 namespace; the ADR-0007 §7.3.1 availability class (`ALWAYS` / `AFTER_FIRST_UNLOCK` / `WHILE_UNLOCKED`); and which side unseals — where "the shell unseals" is an **ABI change**, because `tw_host_vtable` has no wrap or unwrap entry. Two facts bound the blast radius. **No production X25519 keygen exists anywhere**: the only `StaticSecret` uses in `core/`, `services/` and `shells/` are `StaticSecret::from(raw)` public-half derivations in `noise.rs` and `relay_leg.rs`, over bytes already held. And **the device cannot compute its own `identity_id`**: ADR-0007 N-2 fixes it as `SHA-256("TwinVPN/DeviceIdentity/v1" ‖ 0x00 ‖ dCBOR(COSE_Key(IK_pub)))`, `deviceid.rs`'s `derive_identity_id` **consumes** a COSE_Key and nothing **produces** one, and the only candidate input — `IdentityPublic::public_key` — is documented as "the element's own encoding", which `cp_binding/transport.rs` had already reported as a seam that "owes a declared encoding, or `IdentityCustody` owes an `spki()`". So the adapter's asserted `identity_id` is checked against N-2 by nothing. | **RESOLVED by §11.4 D-6, and the resolution cost less than this row priced it at.** This row's premise — "the corpus does not break the tie" — is true of the three Tier-1 *enumerations* it checked and **false of the rule**. **ST-1**, which ADR-0020 §11.1 calls "normative and decidable", was never run against `TK`: its rule 1 asks whether the value must be usable *only* through a platform key-API operation and never readable by the process, and CB-5 row 2, ADR-0018 §11.16 (c), B-09 and ADR-0007 N-5 all answer **no** in the same words — TK is unsealed *into locked core memory* precisely because platform key APIs do not offer X25519 ECDH. Rule 2 (live `Tunnel` state) is also no; that is S-13, Tier 0. ST-1's else-branch is **Tier 2**, so `namespace.rs:172` stands and `custody.rs`'s sentence is the error. **The three Tier-1 enumerations were never wrong** — ST-1 puts "the `TunnelStaticKey` *wrapping* key" in Tier 1 and ST-34 says "the IK/TK *handles*", and none of that is TK. **No ADR enumeration is amended and `tw_host_vtable` does not change**: the core already holds `os_csprng` for generation and the locked allocator for unsealing, so the ABI ask this row anticipated does not exist. What *was* genuinely missing is narrower and is now supplied: **ADR-0020 §11.2's residence table had no row for TK at all** (S-01 is `DeviceKey`, i.e. IK) and **ADR-0007 §11.2 had no ADR-0020 row**, which is the structural reason the question went unasked. Both amended. **TM-14 is unmoved** — TK extraction from process memory stays undefended, as `custody.rs` already states; B-09 bought PB-1/PB-2 with exactly that. The two facts this row raised to bound the blast radius both stand and are now discharged rather than recorded: the missing production X25519 keygen is written, and the `identity_id` seam — that nothing *produces* a `COSE_Key` for N-2 to consume — is closed by the same ES256 encoder G-14 (a) needed. |
| **G-18** | **ruling — G-4/G-6/G-7's blocker was real and its scope was twice too wide** | **Two of the three NOT CHECKED lines were never blocked, and the sentence that made them look blocked is in this register.** Since G-4 the target has said `ring` "needs an MSVC, Darwin or NDK C toolchain and this target invokes none". The premise is right; the inference from it was that no such toolchain could exist here, and that is false twice over. **Windows:** `ring` 0.17.14's `build.rs` branches on `is_like_clang_cl()` — `cl.exe` is one MSVC-target compiler, not the only one — and the **pinned Swift 6.1.2 toolchain already on this host ships a whole LLVM 17**, `clang-cl`, `lld-link` and `llvm-ar` as native Linux ELF binaries. `clang-cl` takes Linux paths and reads the MSVC and Windows SDK headers off `/mnt/c` as ordinary files, so no WSL interop boundary is crossed, `lib.exe` is unwanted (`llvm-ar` serves) and NASM is unwanted (ring ships 17 pre-assembled COFF objects for any non-git checkout). **Android:** `clang --target=aarch64-linux-android21 -nostdlibinc -DRING_CORE_NOSTDLIBINC=1` compiles ring with **no NDK at all**. Both were run and reproduced: `twinvpnsvc` at default features — service **and core-host**, pulling `rustls`, `quinn-proto`, `quinn`, `twinvpn-cp-client` and `twinvpn-core` — and the whole `shells/android/jni` workspace in its **full** profile, each `clippy … -D warnings`, each clean. | **Both lanes wired into `make cross-check`, at the strength each actually has.** The Windows lane is **guarded** on an MSVC header tree being visible and prints `NOT CHECKED (no MSVC headers)` when it is not — the recipe may not require a Windows installation, and `ubuntu-latest` has no `/mnt/c`. The Android lane needs nothing but the pinned toolchain and runs always. **The Android lane's caveat is printed, not buried:** `-nostdlibinc` substitutes ring's own headers for bionic's, which `ring` itself does only for wasm32 and non-x86_64 musl, so it proves the Rust half type-checks for bionic and yields **no shippable object** — weaker than an NDK build and labelled as such. **macOS and iOS do not move, and now for a specific cause rather than a general one:** ring's `include/ring-core/base.h` includes `<TargetConditionals.h>`, which `-nostdlibinc` cannot supply, and cc-rs needs `xcrun` for iOS whatever `CC` says. Apple SDK, Apple hardware — G-6's third option, and the one the licence confines. **The correction worth carrying forward:** G-4 measured a real blocker and then stated it as a property of the machine. It was a property of one compiler. `CC_SHELL_ESCAPED_FLAGS=1` is load-bearing on the Windows lane — the SDK paths contain spaces and cc-rs word-splits `CFLAGS` without it, and the failure reads exactly like the path problem everyone assumed was fatal. |
| **G-19** | **gap — the register under-reports its own completeness** | **§8's Dispositions table has a row for fourteen of the sixteen review findings, and none for R-5 or R-11.** R-5 is the wave's HIGH-severity relay authorization defect and R-11 a relay/device failover disagreement, so a reader auditing this document — which is what an acceptance gate is — would conclude the two most consequential relay findings were never dispositioned. | **Both are FIXED in the tree; only the record was missing, and it now says so.** Verified rather than assumed: `pump.rs:250` takes `from: SocketAddr` and drops a datagram whose `flow_id` names a half-flow that source does not own, carrying an explicit `R-5:` comment; `PairUnmatched` has its own `RELAY.PAIR_UNMATCHED` code with a 30 s slot lifetime rather than collapsing onto `RELAY.CAPACITY_REJECTED`. **The lesson is the one G-14 and G-18 both taught in other registers:** this document is evidence, and an omission in it reads as an open defect to everyone downstream. A disposition table that silently skips its two worst findings is a gate reporting failure even when the code is right. |
| **G-20** | **defect — the corpus spells one key encoding two ways, and the two derive different device names** | **Is `ik_pub` a compressed or an uncompressed P-256 `COSE_Key`?** ADR-0007 §7.4's `PairingOffer` sketch says "P-256, compressed point" and `pairing_offer.cddl` field 2 repeats it, adding that its 80-byte bound "admits the uncompressed form so a producer that ignores §7.4's *compressed point* is refused by THIS FILE'S words rather than by a length accident". **Everything that exists says the opposite.** `contracts/docs/identifiers.md` §2's golden vector — `dbf92e89…` in `deviceid.rs`, whose own comment reads "Moving this literal renames every device in the fleet" — is computed over `{1: 2, -1: 1, -2: Gx, -3: Gy}`, uncompressed. So is `twinvpn-service-common`'s `spki_to_es256_cose_key`, which refuses a compressed point **by name**. These cannot both hold, because **N-2 derives `identity_id` from exactly these octets**: a compressed encoding is not a smaller spelling of the same name, it is a different name for every device in the system. | **Implemented uncompressed; the divergence is recorded, not resolved.** `twinvpn_crypto::cose::es256_cose_key` emits the uncompressed form, which is what the frozen golden vector, the frozen contract test and every existing producer already require — the choice with a blast radius of zero against a choice that renames the fleet. **The ADR text is what is wrong and amending it is the integration lead's**, so §6 rule 14 applies and it is carried here. This is **G-9 one field over**: same file, same shape — `pairing_offer.cddl` field 3 already carries `tk_pub` as `bstr(32)` where `signed_statements.cddl` §2 carries it as `cose-key`, and that divergence is likewise recorded rather than taken. **CLOSED 2026-08-29.** The integration lead ruled for the frozen form and both asides are amended: ADR-0007 §7.4's `PairingOffer` sketch, and `pairing_offer.cddl`'s two comments, under the §3 procedure as **freeze Amendment 6** — comments only, the CDDL grammar is character-identical and `contracts/gen/**` byte-identical. **It cost something and the cost is recorded**: Amendment 4 measured the offer at 377 bytes with a compressed 43-byte `ik_pub`, and the uncompressed key measures **75** bytes, so the honest figure is **409**. `max_offer_cose_key_bytes` is 80 and already admitted it, so no bound moved — but **F-1 is 32 bytes worse**, and `limits.json`'s `_offer_note` is corrected to say so rather than leaving the stale number to be re-derived. |
| **G-21** | **ruling — G-14 (a) was measured against `core/` and the tree is wider than `core/`** | **A production ES256 `COSE_Key` encoder already existed.** G-14 reported field 2's producer as absent because "production holds `cose::from_cose_key` (a decoder) and `cose::x25519_cose_key` (the wrong curve) — the ES256 encoder is `twinvpn_crypto::testkit`". True of `core/`, and `services/twinvpn-service-common/src/binding/spki.rs` has emitted that exact map in production since **RZ-8**, whose module banner is the sentence "the one conversion that must not exist twice". So the gap was not a missing encoder; it was **a specified encoding living in two workspaces and a fixture**, which is the defect RZ-8 exists to prevent, reintroduced by the two later copies. | **One definition, three callers, and RZ-8 restored.** `twinvpn_crypto::cose::es256_cose_key` is now the single home; `spki.rs` keeps the DER half and calls it; `testkit::FixtureIdentity::cose_key` delegates instead of re-encoding, exactly as `testkit::x25519_cose_key` already did one curve over. **Byte-identical output verified rather than assumed**: `identifiers.md` §2's golden vector and `the_conversion_produces_the_canonical_identity_cose_key` both pass unchanged. The lesson for this register is the one G-19 taught about itself — **a finding measured over one workspace states a fact about that workspace**, and `core/`, `services/`, `shells/` and `lab/` are four. |
| **G-22** | **gap — every T1 job is a required check that may be required by nothing** | **There is no `needs:` anywhere in any of the six workflows, no summary or gate job, and no branch-protection-as-code.** `.github/` contains only `workflows/`. So whether `cross-check`, `swift-parse`, `arch-lint` or any other job actually **blocks a merge** depends entirely on GitHub branch-protection settings that live outside the repository and that nothing in the tree can assert. | **Recorded, and it bounds what D-7 bought.** G-16 said the non-host compile proof "rests on someone remembering a command"; D-7 replaced that with a job. If branch protection does not list the job, the proof now rests on someone remembering a **setting** — the same defect one layer out, and less visible, because a job that runs and reports green looks identical to one that runs and blocks. `swift-parse` has been in this position since G-15 and nobody noticed, which is the argument for writing it down. **Settings outside the repo are the integration lead's**; the tree cannot close this. **Ruled 2026-08-29: recorded, not aggregated.** No `gate` job is added — one more job to forget to require is not obviously better than five, and an aggregator would let a green square stand for jobs it did not actually gate. What the tree can do is name the list, so here it is. **Branch protection on `main` MUST require all five checks:** `cargo fmt --check`, `workspace`, `swift-parse (shells/ios, shells/macos -- SYNTAX ONLY)`, `arch-lint (ADR-0018 CD-3 / CD-I2 / CD-I5 / CB-3)`, and `cross-check (win/mac/ios/android -- COMPILE ONLY)`, plus the jobs in `contracts.yml`, `infra-t1.yml`, `lab-t1.yml` and `supply-chain-t1.yml`. **Any job added to a T1 workflow after this date must be added to that setting in the same change**, and this row is where a reviewer checks. |
| **G-23** | **defect — a banner asserts on a runner what is only true on this host** | **`make cross-check`'s closing banner states two host facts unconditionally.** "Swift (shells/ios, shells/macos): PARSED, NOT TYPE-CHECKED" and "kotlinc IS on this host; an android.jar is not" are printed even on a run that two lines earlier printed `parse-check Swift  NOT CHECKED (no swiftc)`. A CI log therefore claims a parse that did not happen. | **Half fixed, half recorded.** The **Android** `full` lane had the same defect in executable form — `AR_…=llvm-ar` with no guard, where `llvm-ar` reaches this host only through the pinned Swift toolchain's LLVM — and it is now guarded on `llvm-ar` **and** `clang`, with the per-crate coverage line and the banner prose corrected to say *when* it runs. The two Swift/Kotlin sentences are left: they are G-15's prose, the same class, and correcting another finding's claim without its author is how a register loses track of who asserted what. **Related, outside the changed file's scope and reported not fixed:** the `workspace` job's `cmake --version \| head -1` presence check cannot fail, because a step's default shell here is `bash -e` with **no `pipefail`**, so a missing tool at the head of a pipe leaves the pipeline's status at `head`'s zero. The new `cross-check` job deliberately uses `command -v` instead. |
| **G-24** | **gap — W-41's user-visible half cannot be closed because the sentence does not exist** | **EM-42's rendered next action is authored nowhere.** W-41's defect is that ADR-0023 EM-42 tells a user to `run 'twinvpn peer disconnect …'`, naming a command no host installs. D-1's implementation makes that command exist — but `core/crates/twinvpn-diag/catalogue/en.json` holds nine hand-authored entries with two `next_action`s between them and **no entry for the code EM-42 describes**. Every unauthored code falls back to `build.rs`'s seed, "Try again. If the problem continues, create a diagnostic report and share it with support", which names no command at all. | **The naming half is CLOSED; the authoring half is named and open.** So today nothing renders `twinvpnctl` — there was no wrong string to fix — and nothing renders EM-42's sentence either. What D-1 guarantees is that **when that entry is authored, the command it names will be installed on all three desktops**, which is the failure W-41 actually reported. Authoring the catalogue entry is `core-diagnostics`' and is not a naming decision. |
| **G-25** | **gap — F-2's authorization residual was disclosed everywhere except the register** | **C-D is enforced as a STANDING delegation, not a per-ceremony approval.** ADR-0007 §7.4 makes authorization "always required" and discharges it with C-D: "an OSK device holding `ENROLL` power **approves**" — a signature over *this enrolment*. That signature arrives over C1 and **C1 has no transport in this build (W-12)**. What F-2 shipped instead is `OwnerMaterial::into_enrolment` naming as approvers exactly the OSKs whose ORK-signed delegation carries `ENROLL` — an offline-verifiable, ORK-signed fact, and **weaker than §7.4**: it authorizes "an ENROLL-powered OSK exists in this TwinNet" where §7.4 wants "one approved this ceremony". A coordination service cannot exploit it (the delegation is ORK-signed and pinned), but a **compromised or coerced ENROLL-powered OSK enrols devices without a per-ceremony act by its holder**, and no evidence distinguishes the two cases after the fact. It is stated in `core/crates/twinvpn-core/src/pairing/enrol.rs`'s module doc and warned by `shells/linux/twinvpnd/src/agent/enrolment.rs:181` at every start that reaches an enrolment — and **it had never been written down here**, which is the only place a reviewer looks for what is still open. | **Recorded, and it stays open until C1 has a transport.** No code change: the implementation is the strongest offline-verifiable reading available, the divergence is already disclosed in the two places that execute, and narrowing it needs W-12 and nothing else. Two consequences are named so they are not rediscovered: the residual is **invisible to the acceptance gate**, because a standing approval and a per-ceremony one are observationally identical on a host with no C1; and it **must be re-measured, not inherited, when W-12 lands** — a C1 transport does not by itself make the approval per-ceremony, it only makes one possible. `core-composition`. |
| **G-26** | **defect — the value two devices must agree on for a ceremony to confirm has no defined preimage** | **`PairingAttestation.transcript_hash` is specified as a type and never as a construction.** `signed_statements.cddl:140` fixes the statement completely — six labels, `4: digest256` — and `decode_pairing_attestation` reads that field with `fixed::<32>`, never building or checking a transcript, so **the decoder specifies everything except the preimage**. The construction appears **once in the corpus**: one sentence of ADR-0007 **§7.4** (line 556), inside §7 *Security Implications*, and it is **never restated as a rule in §11.1** — the contrast is N-20 three rules later, which does say `identity_binding_hash` is contributed "exactly as defined in §7.6". The sentence leaves **nine encoding decisions** open (domain separator; length framing over variable-length members, which makes the preimage non-injective; the ordering and the grouping of the three paired members; `ik_pub`'s octets; whether a `TunnelKeyBinding` contributes its received COSE_Sign1 or a re-encoding, where only the first satisfies ADR-0003 §11 rule 1; four candidate spellings of "the ceremony method", two of which number C-A and C-B **oppositely**; `anchor_version`'s width and endianness; and "`Capability` hashes", a plural noun with no referent anywhere in the corpus). Each produces a different digest, and `check_attestation_pair` can only test that the two halves **agree**, never that either is right — so a divergence surfaces as "attestations disagree on the ceremony transcript", an error naming the peer rather than the specification. `peer_key_id`/`own_key_id` are a second gap: `key-id = tstr .size (1..64)` is a type, `identifiers.md` does not list them, and `check_attestation_pair` compares them byte-for-byte. | **Raised as an ask, not patched. `contracts/` untouched; `docs/adr/` untouched.** [`pair-confirm-attestation-defect.md`](pair-confirm-attestation-defect.md) documents §3 steps 1, 2, 4 and 5. **The owner is ADR-0007's**, not `core-crypto`'s: the fix is a §7.4 preimage block in ADR-0001 §7.3.1 **P-1**'s form — which answers six of the nine rows for the Noise prologue and is implemented in `prologue.rs` in twenty lines *because* nothing was left to decide — plus a §11.1 rule binding it, plus a `key_id` format in `identifiers.md`, plus a golden vector so the Swift and Kotlin shells are checked against bytes rather than against the Rust implementation. **No emitter was written**, including the statement half that IS fully determined by the frozen CDDL: it unblocks nothing, would have no caller, and an `emit_pairing_attestation` taking an opaque 32-byte parameter reads as "solved — supply the hash", which invites the invention this pass was told to refuse. `pair.confirm`'s refusal is re-measured to name this root cause and is **not** lifted — N-18 needs both halves and the peer's still crosses W-12's absent transport, so the two blockers are independent and both are required. |

### 11.3 What the gate can and cannot say

The wave's acceptance gate asks for named properties, not for a test count, and
three of its clauses are answered "yes, on this host" rather than "yes":

- **Platforms.** Nothing links and nothing runs. Windows, macOS, iOS and Android
  are compile-checked only, and after G-4 the crates that host a core are not
  even that. Swift and Kotlin are not compiled at all (§9.2, §10.3).
  **G-15 and G-18 narrow the second and third sentences without touching the
  first.** Windows `core-host` and Android `full` are now compiled — the crates
  that host a core, in their shipping profiles, `rustls`/`quinn` included — and
  the Swift shells are parsed by the pinned compiler. `shells/macos`
  `twinvpn-bridge` `full` is the one line left, and its cause is an Apple SDK.
  **Nothing links and nothing runs is unchanged, and it is the sentence that
  decides the clause.**
- **Fail-safe networking.** The leak, kill-switch and dual-stack properties are
  asserted against `twinvpn_platform`'s adapter and `nft`'s renderer, with
  `e2e/fail_closed_leak.rs`'s positive controls. On a *kernel*, only Linux has
  been exercised.
- **Relays never see plaintext (I1).** Structural, and it is the strongest of the
  three: the forwarding provider has no decrypt operation to call, and
  `relay_can_decrypt_payload()` is a function rather than a comment so that a
  change to it fails a test.

**G-3 is closed** by Amendment 3, so no gate clause is left open by this pass on
the properties it could reach. What remains open is what §11.3 says it is: the
platform clauses are answered *on this host*, and G-4 narrowed even that. **G-6
narrows it back, part of the way, and says exactly how far:** the four
core-hosting crates in three workspaces are compiled again, but only under the
reduced `core-lite` / `--features service` profile, so the lines reachable only
under the shipping profile are still compiled by nothing here. **G-6 also
corrects what is owed** for the rest: not a rustls `CryptoProvider` decision,
which would leave the edge untouched, but a decision to fork `quinn-proto`, to
leave `quinn`, or to provision target C toolchains — and the third cannot reach
`shells/macos` `twinvpn-bridge` at all, because the Darwin SDK's licence
confines it to Apple hardware. That decision is still owed to
`core-controlplane` and the integration lead. **G-7 is the reason to state all
of this in the output rather than in a comment:** while `shells/windows` was
exempted wholesale, `twinvpnsvc` did not compile for any target at all and no
gate run said so. A wave that has never been linked or run on Windows,
macOS, iOS or Android is not a wave anyone should call complete on the strength
of a Linux host's green tests.

**What the 2026-08-29 pass changes about that paragraph, and what it does not.**
One gate property genuinely moved: after **G-8**, the `ProtectionAssertion` is
producible across the C ABI, so the fail-safe-networking clause is no longer
answered "only where the shell links Rust". It is still answered *on this host* —
nothing links and nothing runs on the three platforms that needed it, which is
§11.3's standing qualification and not something an ABI addition can touch.
**G-9 leaves a clause open that was already open**: enrolment is not implemented,
because `PairingOffer` has no contract, and the amendment that would close it is
an ask rather than a change. A gate that reports "pairing refuses by name" is
reporting a correct refusal, not a working ceremony, and the difference is the
one this section exists to keep visible.

**What the fourth pass changes, and the one sentence above it makes stale.**
`PairingOffer` now has a contract — Amendment 4 landed it as
`cddl/twinvpn/v1/pairing_offer.cddl` with six measured bounds — so the paragraph
above should be read as: the *contract* half of G-9 closed, and the *enrolment*
half did not. Amendment 4 says so in its own words: it "does NOT authorize
implementing the offer". `twinvpn-trust`'s ceremony state machine, its
five-attempt budget and its 120-second window are real, and `Spake2Exchange` is
a trait with **no implementation in the workspace**, because W-22 stands — no
audited RFC 9382 P-256 Rust implementation exists, and writing one is the novel
cryptography §6 forbids. So **pairing is contracted, driven, and cannot
complete**, and neither channel authenticator is finished. That is one gate
clause — CONTROL PLANE *pairing* — answered "refuses correctly" rather than
"works", and it is the only clause the tree can close by writing code that no
approval and no missing dependency blocks.

**G-13 wrote the part of that code which was unblocked, and the clause is still
not closed.** The offer is now producible, transportable over EM-22 E2's text
channel and parseable, with the CDDL's secret-handling rules held by types rather
than by comments and its decoder fuzzed for the first time. What is not written
is the composed core's ceremony wiring; what cannot be written is C-A. So
*pairing* moves from "the payload has no implementation" to "the payload has one
and no ceremony drives it". That is a real move and it is not the clause, and the
difference is the one §11.3 exists to keep visible.

**G-14 corrects the sentence above.** "What is not written is the composed core's
ceremony wiring" is what `dispatch.rs` said, and it is not what the tree
measures. `pairing_offer::build` takes six inputs and **three of them have no
producer outside a testkit**: an ES256 `COSE_Key` encoder for `ik_pub`, this
device's sealed TK for `tk_pub` — which nothing generates, seals, names as a
Tier-1 item, or unseals — and a `TunnelKeyBinding` emitter for `binding`. The
`PairingLedger` is the fourth gap and the only one that *is* wiring. So the
honest reading of §11.3's "the one clause the tree can close by writing code that
no approval and no missing dependency blocks" is that **it was wrong about that
clause**: two of the three remaining gaps are ADR-0020 / CB-5 / CB-7 key-custody
decisions that §6 forbids an implementation agent from settling, and on the one
host that runs, `AbsentElement` refuses `identity_sign` outright under §11.16 (l).
Nothing about the gate verdict moves — *pairing* was "refuses correctly" before
G-13 and is "refuses correctly" after G-14 — but the register no longer tells the
next agent that one field on `Core` finishes it.

**G-17 finds the ruling that was actually owed, and corrects this section's
standing account of why pairing is blocked.** §11.3 has said since the first pass
that pairing cannot complete because **C-A** needs SPAKE2 and W-22 says no
audited RFC 9382 P-256 Rust implementation exists. That is true and it is not the
binding constraint, because **C-B needs no SPAKE2 at all**. ADR-0007 §7.4 makes
the two ceremonies alternatives — "Channel authentication … C-B (QR) where a
camera and a screen exist; C-A (SPAKE2/P-256) otherwise | **Yes, exactly one**" —
and puts C-B's security in the channel: "MITM at the rendezvous is defeated by
construction: the adversary never sees `pairing_secret`", 256 bits optical,
brute-force "infeasible (2^256)". `pairing_offer.cddl` says the same in its own
words, and ADR-0023 EM-21 confirms a headless target uses "C-B, unchanged, and
[does] not fall back to C-A's ~2^29.9". SPAKE2 appears in ADR-0007 only under
C-A, and in the tree only behind `CeremonyType::Spake2Code`.

So the accurate statement is: **W-22 blocks C-A and nothing else; C-B is blocked
by G-17's TK ruling alone.** Of G-14's three producer gaps, two — the ES256
`COSE_Key` encoder and the `TunnelKeyBinding` emitter — are implementations that
ADR-0007 N-2 and N-4 already require in production and that no approval blocks;
the third is TK. That is a materially different position from "pairing waits on
cryptography nobody may write", and it is the one an owner can act on: **one
four-part ruling stands between this tree and a working C-B enrolment.** The gate
clause does not move today, and what moves is the size and the owner of what is
left.

**G-12 does not move a product property; it moves what the gate is entitled to
say.** Before it, *no implementation-specific shadow contracts exist* and *no
platform has independently redefined shared enums/messages* were true in the
tree and unchecked by `make gate` — the deny-list that proves them ran only in
CI. After it they are checked by the same command every integration is required
to run. Nothing in the three qualified clauses above changes: Windows, macOS,
iOS and Android are still compiled-only at best, Swift and Kotlin are still
compiled by nothing here, and the fail-safe properties are still exercised on a
Linux kernel and asserted structurally everywhere else.

### 11.4 Gate decisions taken by the integration lead — 2026-08-29

The gate's sixth pass recorded two questions rather than answering them, on the
correct grounds that §6 rule 14 puts both out of an implementation agent's
reach: **G-17**, where this device's `TK` lives, and **G-16**, where the non-host
compile proof runs. Both are answered here. The rows below are the authority the
code and the ADR amendments cite; **G-16** and **G-17** are closed against them.

A third row is recorded because the register mis-stated its own state: **W-41**
was carried as an open decision in §8 while §9.5 **D-1** had already settled it
in wave 2. Nothing was decided today — what was owed was implementation, and the
stale row is corrected.

| # | Question | Decision |
|---|---|---|
| **D-6** | **G-17's four-part TK ruling — where does this device's sealed `TK` live, who generates it, under what availability class, and who unseals it?** | **Four answers, and three of them the corpus already contained.** See the derivation below. **(a) Residence: Tier 2 `identity/`.** `namespace.rs:172` is right and `custody.rs`'s "reaches the core as a sealed blob through `SecureStore`" is the error. **(b) The wrapping key is the Tier-1 item**, which is what ST-1 already says in the words "the `TunnelStaticKey` wrapping key" — so the three Tier-1 enumerations that name only SEK, `K_bind` and the S-53 anchor were never wrong, and none is amended. **(c) Generation: `twinvpn-crypto`, at enrolment**, from the vtable's `os_csprng` — CD-3 bans `getrandom` inside the core, so it is the only permitted source — triggered with the `DeviceIdentity`, because N-1 makes IK and TK one identity. `tk_generation` advances on TK rotation independently of IK's `generation`, which N-4's payload already carries. **(d) The core unseals**, into the locked, non-swappable, non-dumpable allocator. **`tw_host_vtable` is UNCHANGED and stays at minor 2** — there is no ABI ask here, which was the part of G-17 that made it look expensive. **Availability class: per target, mirroring the IK row of ADR-0007 §7.3** — `ALWAYS` on Linux, Windows and OpenWrt, `AFTER_FIRST_UNLOCK` on iOS, macOS and Android. |
| **D-7** | **G-16 — `make cross-check` runs in no CI workflow.** | **A CI job that installs the four targets, wired the way G-15 wired `swift-parse`.** `make gate` is **not** touched: `cross-check` needs four `rustup target add`s a fresh clone does not have, and folding it in would fail every new developer's first run, which is the reason it was split out. `make gate-full` is **not** added either — a target someone must choose to type is G-16's defect restated, not fixed. One definition in the `Makefile`, two callers, which is the W-20 / X-4 / R-14 rule `swift-parse` already follows. |
| **D-8** | **W-41's status.** | **Not a decision — a stale register row.** §9.5 **D-1** settled the CLI's name in wave 2: the cargo target stays `twinvpnctl`, the package installs it as `twinvpn`, `twinvpnctl` remains a compatibility alias. §8's W-41 row said "needs a decision" nineteen months of document-time after one was taken. The row is corrected to point at D-1 and the implementation is what was actually owed. |

**How D-6 (a) and (b) were derived, since G-17 recorded the corpus as silent.**
It is not silent; the rule that decides it is **ST-1**, which ADR-0020 §11.1
calls "normative and decidable", and it was never run against `TK`. Rule 1 asks
whether the value "must be usable only through an operation the platform key API
can perform (sign, agree, wrap, unwrap, AEAD), with the value itself never
readable by the process". For `TK` the answer is **no**, and three independent
clauses say so in the same words: **CB-5 row 2** and **ADR-0018 §11.16 (c)** —
TK is hardware-*wrapped* and unsealed into locked core memory "precisely because
platform key APIs largely do not offer X25519 ECDH"; **B-09** — "the L-DATA
static private key may reside in core process memory"; and **ADR-0007 N-5** —
"TK MUST be sealed under a hardware-bound wrapping key and unsealed only into
locked, non-swappable, non-dumpable memory". Rule 2 asks whether it is live
`Tunnel` state; it is not — S-13 is that, and it is Tier 0 and non-durable,
whereas TK survives reboot. ST-1's own else-branch therefore reads **Tier 2**.
ST-1's Tier-1 sentence then names "the `TunnelStaticKey` **wrapping** key"
explicitly, and ST-34's crypto-erase ladder says "delete … the IK/TK **handles**
from Tier 1" — a handle, not the key. **ST-2 raises no objection**: it forbids
Tier 2 to hold "`DeviceKey` private material or live tunnel keys", and TK is
neither IK nor a live tunnel key. **ST-3 requires exactly this treatment** —
Tier 2 already holds `PairSecret` and the sealed `EpochSeed` set, both
`SECRET`-classified and sealed unconditionally on every platform.

So G-17's premise — "the corpus does not break the tie" — was true of the three
Tier-1 *enumerations* it checked and false of the *rule*. What was genuinely
absent is narrower and is now supplied: ADR-0020 §11.2's residence table had **no
row for TK at all** (S-01 is `DeviceKey`, which is IK), and ADR-0007 §11.2's
"Interfaces required from other ADRs" had **no ADR-0020 row**, which is the
structural reason nobody noticed the question was never asked. Both are amended.

**What D-6 does not do.** It does not weaken TM-14. **TK extraction from process
memory remains undefended**, exactly as `custody.rs` already states as a
residual, and putting the sealed blob in Tier 2 rather than Tier 1 does not move
that residual by one bit — the unsealed key was always going to be in core
memory, which is what B-09 buys PB-1 and PB-2 with. What changes is that the
sealed form now has one declared home instead of two contradictory ones.

**What D-6 unblocks, precisely.** G-14's three producer gaps for `pair.begin`
field-by-field. **(b)** was the TK gap and D-6 closes it:
`twinvpn_crypto::tk::TunnelStaticKey` generates from the host CSPRNG, seals under
the Tier-1 wrapping key and unseals into the locked allocator. **(a)** and **(c)**
were never blocked on anything — ADR-0007 N-2 and N-4 require both in production
and G-17 said so — and both are now written, as
`twinvpn_crypto::cose::es256_cose_key` and
`twinvpn_crypto::binding::emit_tunnel_key_binding`. **G-21 corrects (a)'s
premise**: an ES256 encoder already existed in `services/`, so the work was
single-homing an encoding that had quietly acquired three copies, not writing a
first one. **G-20 records what writing it exposed** — §7.4 says compressed, the
frozen golden vector is uncompressed, and N-2 makes those two different names for
every device in the fleet. The fourth and smallest gap, the absent
`PairingLedger`, is unaffected and still stands. **`pair.begin` is therefore no longer refused for want of a ruling**, and
the gate clause **CONTROL PLANE *pairing*** moves only when the four producers
exist and are wired — not on this decision.
