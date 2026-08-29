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
closed it. No contract defect is open.

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
| **W-7** | gap | **`ElapsedClock`, `Entropy` and `BootIdSource` are required shell interfaces that ADR-0018 §11.16 does not list.** `std` has no suspend-inclusive clock, and the platform calls need `unsafe` (DP-4) or `cfg(target_os)` (CB-3), so the shell must supply them. | Accepted as a real gap — and it is precisely the invisible-on-Linux-CI failure LC-8 warns about. Every shell brief names all three as required. **Should be recorded in ADR-0018 §11.16.** |
| **W-8** | gap | **`limits.json`'s `ports` section is a validation bound (`{min:1,max:65535}`), not a port assignment.** | Correct reading. Ports come from ADR-0002 §11.2 and ADR-0005 §11.4. The `:9090` admin listener is an infrastructure-domain decision, recorded as one. |
| **W-9** | gap | **Tier-2 `nat_class` is singular; "outcome by NAT class pair" needs two.** ADR-0015 §11.1's tuple names one; `docs/testing-strategy.md` §3.6 and the wave objective both speak of pairs — and a pair carries k-anonymity consequences. | A decision, not an oversight. Dashboards query `nat_class_local`/`nat_class_remote` with the divergence flagged in the panel. **Referred to ADR-0015's owner.** |
| **W-10** | gap | **ADR-0015 §9's router-class observability budget (< 512 KB) cites no `GC-*` class**, which under ADR-0018 BM-1 makes it an unqualified budget. | Transcribed as written in `build/budgets.toml` and flagged, rather than attributed to `GC-0` or `GC-0U` on a guess. **Referred to ADR-0015's owner.** |

| **W-11** | **defect** | **Eight `CONTROL.*` reason codes that ADR-0009 §11 names are absent from the frozen registry.** Present: `CONTROL.CONSISTENCY.REPLICA_BEHIND_CURSOR`, `CONTROL.STALENESS.DOCUMENT_STALE`, `CONTROL.STALENESS.TRUST_LIST_EXPIRED`. **Missing:** `CONTROL.CONSISTENCY.{VERSION_ROLLBACK_REJECTED, FORKED_HISTORY_DETECTED, CURSOR_INVALIDATED, CLOCK_SKEW_EXCESSIVE, SIGNATURE_UNVERIFIABLE}` and `CONTROL.STALENESS.{POLICY_GRANT_SUSPENDED, RELAY_SET_EXPIRED, TRUST_EPOCH_BEHIND_PEER}` — 8 of the 11 names ADR-0009 uses. Verified directly against the registry rather than taken on report: `core-controlplane` reported five; `CLOCK_SKEW_EXCESSIVE` and `TRUST_EPOCH_BEHIND_PEER` were also missing and unreported. | Not patched. The interim mapping onto the nearest registered codes (`AUTH.TRUST_EPOCH_ROLLBACK`, `AUTH.TRUST_HISTORY_FORKED`, `POLICY.EXPIRY.BUNDLE_EXPIRED`) is **defensible and accepted for now**, but it has a real cost: it loses the `CONTROL.CONSISTENCY.*` namespace ADR-0009 asked for, and ADR-0015 §11.2's whole forward-compatibility story is **prefix degradation** — an older client meeting `AUTH.*` where a consistency failure occurred degrades to the wrong diagnosis, which is the failure mode the closed-domain rule exists to prevent. The registry is **append-only**, so adding these breaks nothing and is the sanctioned evolution path — but it is still a `contracts/` change. **Needs approval.** |
| **W-12** | ruling | **Where does the L-CONTROL QUIC/TLS stack live?** ADR-0001 §11 item 3 requires QUIC + TLS 1.3 with mutual raw-public-key auth in the core, but CD-I2 permits a cryptographic dependency only in `twinvpn-crypto`, and `rustls` is one. `core-controlplane` was blocked on this and shipped the ladder policy without a production binding. | **Split by what is actually cryptographic.** `rustls` — the TLS implementation, the raw-public-key verifier, the cipher-suite policy, the `CryptoProvider` — belongs to **`twinvpn-crypto`**: those are exactly the decisions a reviewer auditing *what cryptography do we use* must read, which is CD-I2's stated purpose. `quinn` is a **transport protocol** implementation — framing, loss recovery, congestion control — that takes its cryptography from rustls and implements none itself, so **`twinvpn-cp-client` may declare it**, constructing its endpoint from configuration `twinvpn-crypto` vends. `twinvpn-core` wires the two. **Not the shell:** CB-1 puts code in a shell only when it must call a platform API with no stable C-callable form; QUIC is not one, and CB-1 says ambiguity resolves to the core. |

| **W-13** | **defect** | **No registered reason code covers "shutdown grace period expired with work still in flight."** `INTERNAL.INVARIANT_VIOLATED` would overclaim — grace expiry under load is not necessarily a defect. | **CLOSED — and the answer is that the condition should not have a code.** The search for an owning ADR found there was none: ADR-0002 §11.7 rule 1 fixed what a server *announces* at drain start and said nothing about the deadline arriving; ADR-0015 C-5 points the other way, ADR-0016 is client-side, ADR-0022 is mobile lifecycle, and ADR-0005 §8 / `reliability.md` §8.3 govern the *relay's* drain, a different condition. **ADR-0002 §11.7 rule 5 (amended 2026-08-28) now owns it**, because that ADR already owns the drain and the 120 s default. The rule refuses a `reason_code` on the merits rather than for want of one: a `reason_code` is a fact reported to a peer about that peer's request, and by grace expiry the affected requests are being abandoned on a connection that is closing — there is nobody left to tell, so a registered code would be one no receiver could ever act on. It also **explicitly forbids `INTERNAL.INVARIANT_VIOLATED`**, whose registry entry reads "EVERY OCCURRENCE IS A DEFECT": expiry under genuine load is the bound working, and reporting it that way would page an engineer for a correct outcome and devalue the one code that depends on never being cried wolf. Required reporting is the metric pair `twinvpn_shutdown_grace_expired_total` / `twinvpn_shutdown_inflight_at_deadline` plus one WARN carrying `twinvpn.outcome = "grace_expired"` and the count — which is what `services/twinvpn-service-common/src/shutdown.rs` already emitted. **No contracts amendment was needed**; the registry is untouched. |
| **W-14** | gap | **`/metrics` is scraped by Prometheus directly, so the collector's *positive* allowlist is not in that path** — only a `labeldrop` denylist is. | The positive control therefore had to move to **emit time**, which is where it belongs anyway. Consequence to be aware of: ADR-0015 §9's five labels are the *entire* metric-label vocabulary, so per-dependency readiness detail lives in the `/readyz` JSON body rather than as a metric label. Widening that is a §9 conversation, not a code change. |
| **W-15** | gap | **`service.instance.id` is allowlisted by the collector but nothing in `docker-compose.yml` supplies it.** | `twinvpn-service-common` takes it as an explicit caller argument rather than silently reading a hostname or generating entropy — the right call, since an instance id invented per process makes fleet queries lie. **`infrastructure` to supply it in compose.** |
| **W-16** | gap | **ADR-0015 §11.5 names a `CRITICAL` log level; `tracing` has none.** | `TWINVPN_LOG_LEVEL=critical` is accepted and mapped to `ERROR`, so a value copied verbatim from the ADR configures the service rather than failing it. Documented at the mapping. Flag if a genuinely distinct level is wanted. |
| **W-17** | ruling | **`infra/README.md` §4.2 marks `TWINVPN_LIMITS_PATH`/`TWINVPN_REASON_CODES_PATH` "Required: no" but "if absent the service must refuse to start"** — apparently contradictory. | **Read as: the variable has a default; the resulting *file* must exist.** `service-common`'s `RegistryCheck::Required` goes further and asserts the mounted `limits.json` equals the compiled-in one and that `reason_codes.json`'s `registry_version` matches the build. **That stronger check is endorsed:** the bounds actually enforced are the compiled-in ones, so a service validating against a *different* mounted registry would pass its own tests and reject real traffic — a divergence that is invisible until production. |

| **W-18** | **DEFECT — the dominant finding of the wave** | **316 of the 514 reason codes named normatively across the Phase 1 corpus are absent from the frozen 201-code registry.** Measured by the integration lead over all of `docs/`, not extrapolated from one domain: three domains hit it independently (`core-controlplane` 8 `CONTROL.*`, `core-security` 14 `STORE.*`, `core-dataplane` ~50 across `POLICY`/`RELAY`/`NET`/`NAT`/`ROUTE`) and each saw only its own slice. By domain: `PLATFORM` 73, `RELAY` 47, `MGMT` 38, `NET` 35, `POLICY` 34, `DNS` 20, `UPDATE` 17, `RESOURCE` 16, `STORE` 14, `CONTROL` 10, `NAT` 5, `CRYPTO` 3, `AUTH` 2, `ROUTE` 1, `PROTO` 1. By source: `reliability.md` 52, ADR-0023 45, ADR-0022 36, ADR-0017 36, ADR-0006 33. Only **3** registered codes are never cited, so this is a one-directional shortfall, not a mismatch. | **Systemic, and Phase 1 predicted it.** `reliability.md` §3.5 says plainly that "a contribution is a request for registration, not an act of registration" — the requests were made across the corpus and the registry never granted them. The consequences are not cosmetic: `POLICY.LEAK.EGRESS_OBSERVED` is the **leak canary's own verdict**, `NET.PATH.DEAD_NO_ALTERNATE` is the most-taken transition on mobile, `RELAY.FLEET.UNREACHABLE` drives §6.3's global brake, and `NAT.CLASS_OBSERVED` is declared a *guaranteed observable*. Not patched — the registry is append-only so adding is the sanctioned path and breaks nothing, but it is a `contracts/` change of real size. **Every domain documents its substitution in a `SUBSTITUTIONS`/`UNREGISTERED` table with a tripwire test asserting the spelling is still absent, so registering a code fails the build and points at the line to delete.** That pattern, from `core-dataplane`, is now the standard. **CLOSED by `registry_version` 2** (§9.6 X-1, 2026-08-28): 201 → 454 codes, every substitution table emptied and every tripwire inverted rather than deleted. W-5, W-6 and W-11 closed with it; W-13 partly, because no ADR names its condition. |
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

| **W-32** | **defect** | **A device authenticates an inbound relay frame it should never have been sent.** `device_may_send` refuses `BOUND`/`DRAIN`/`RELAY_STATUS` on the *send* path, but `InboundFrame::verify` never checks direction — so a device accepts and **authenticates** a `BIND` or `CAPS` arriving *from* the relay. Not a MAC forgery; a **confused-deputy surface** on a compromised or misbehaving relay. | Routed to `core-dataplane`. Direction belongs on the receive side too. |
| **W-33** | gap | **The ADR-0005 §9.1 golden vector is replicated as source in four places and shared as a constant in none.** `twinvpn-crypto`'s copy is `#[cfg(test)]` and therefore unimportable, so each side fails separately and a regeneration in one place does not fail the others. | The vector is the only thing making the two ends of the relay wire provably agree; four independent copies is the shape that lets them drift. Routed to `core-security` to expose it importably. |
| **W-34** | gap | **`SessionRuntime` re-arms only on a state *change*.** A timer that fires and matches no transition row leaves the state with that deadline consumed and nothing re-arming it. | Not reachable from a driver that delivers `EV_CANDIDATES_READY`, so recorded rather than tripwired — but it is the shape of an unbounded state, which `docs/reliability.md` §4.4 bounds deliberately for every transient state. Routed to `core-composition`. |
| **W-35** | amendment to **W-28** | **The write-behind journal delays *deletions* too.** An unflushed `forget` returns `Ok` and leaves the record durable, so a restarted client **resumes a peer the caller believed it had dropped**. | Measured by `test-engineering`'s chaos suite, which also confirmed W-28's acceptance holds in the direction it was granted (loss bounded to the most recent transition; the `Session` survives; `resume_state()` is still `RECONNECTING`). This is the opposite direction with a different consequence, and it strengthens the case that making `SessionJournal` async is a wave-2 requirement rather than an improvement. |

| **W-36** | **defect — the lints contradict each other** | **No location in the tree may legally read a platform clock.** CB-3 and DP-4 put platform syscalls in `twinvpn-platform-*`; **CD-3's deny-list denies `clock_gettime` and `getrandom` there too**. Verified: `checks.rs` has `cb3_crate_is_exempt` for `target_os` and **no equivalent for the CD-3 needles**. The shells are outside the lint but carry `#![forbid(unsafe_code)]`. | `desktop-linux` reached `CLOCK_BOOTTIME` via `/proc/uptime` and entropy via `/dev/urandom` — correct, and 10 ms quantised where a syscall is not. **Fix: one exemption in `checks.rs` for `twinvpn-platform-*`, exactly as `cb3_crate_is_exempt` already does.** Routed to `core-foundation`. |
| **W-37** | **defect** | **The seam cannot express Linux kernel offload.** ADR-0018 §11.2 row 2.3 says the core *programs the kernel WireGuard module* on Linux, and `Datapath::KernelOffload` exists to declare it — but `TunnelDevice` has **no method carrying a WireGuard peer, private key, endpoint, allowed-IP set or keepalive**. | A Linux adapter can **declare** offload and cannot **achieve** it. `desktop-linux` reports `Datapath::Userspace` honestly; declaring the other "would produce a tunnel that carries nothing and calls itself offloaded". **Needs ADR-0018 §11.4/§11.6 amended.** |
| **W-38** | **defect** | **`MgmtEnvelope` is in no contract.** ADR-0017 §11.3 specifies it as protobuf and prints the `.proto`; `contracts/` has no `mgmt.proto`. OQ-2 excluded one so the MI could not acquire an independent vocabulary — which worked — but leaves the **carriage** unspecified. Same class as **W-21** (`PairingOffer`). | §11.3's field list carried verbatim over B5 JSON, so a later `mgmt.proto` is a re-encoding rather than a redesign. |
| **W-39** | **defect** | **`fe80::/10` is unrepresentable as an `IpPrefix`.** `V6Addr::new` requires a zone on link-local; `IpPrefix::new` rejects any zone. **Both rules are individually right**; their conjunction silently drops link-local prefixes from `InterfaceFacts.addresses`. | Enforcement is unaffected (`nft` emits the literal). Pinned as a test. |
| **W-40** | **defect** (W-18 instance) | **No `PlatformError` is retryable under the frozen registry.** `Transient` → `PLATFORM.ADAPTER_UNAVAILABLE` → class `PERSISTENT`, so `is_retryable()` is `false` for `EAGAIN`. There is no `TRANSIENT`-class `PLATFORM.*` code to name. | Pinned as a test. Goes with W-18 to the amendment. |
| **W-41** | gap — **needs a decision** | **The CLI binary is `twinvpnctl`; ADR-0016 §11.2 and ADR-0017 §11.12 both name it `twinvpn`**, and ADR-0023 EM-42's rendered next actions instruct the user to `run 'twinvpn peer disconnect …'` — **naming a command not installed under that name**. | A user-facing next action that names a nonexistent binary is the R-31 defect class in its most literal form. **Rename, symlink, or amend the ADRs — integration lead / user decision.** |
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

## 11. The first-wave acceptance gate — pass of 2026-08-28

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
need one and landed, the other stops at the ask. They are in this register rather
than in §8 because §8 records what wave 1 found and this records what was done
about it, which is the convention G-5 states.

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
| **G-9** | **defect — W-21, brought to the point of decision and stopped there** | **§8's W-21: `PairingOffer` — ADR-0007 §7.4's deterministic-CBOR C-B payload — is in no contract.** Three things make it a §3 defect rather than an inconvenience. (1) **It is the whole of enrolment, not one message**: ADR-0023 EM-22's four channels (terminal QR, text offer, reverse ceremony, first-boot provisioning) are all C-B, and W-22 already ruled C-A unimplementable, so every shippable enrolment path carries a payload the contract does not define. (2) It is the **most** untrusted input in the system — parsed by a device holding no trust anchor, from a camera or a paste buffer — and §6 rule 9 requires it validated against `limits.json` before any length-proportional allocation, while `limits.json`'s `pairing` object bounds the ceremony and says nothing about the offer. (3) §7.4 prints field names and types but not the encoding decisions that determine the bytes, so two independent implementations would fail to interoperate at a real ceremony with no diagnosis. | **A §3 amendment proposal, written and NOT applied**: [`w21-pairing-offer-amendment.md`](w21-pairing-offer-amendment.md), answering steps 1, 2, 4 and 5 with the exact diff. **Nothing under `contracts/` was touched.** It asks for one new `cddl/twinvpn/v1/pairing_offer.cddl`, six new `pairing.*` keys in `limits.json`, and three assertions in `test_registries.py`. **It is the smallest of the four amendments to date: no `.proto`, no reason code added or reclassified — every condition the payload can raise is already registered (`PROTO.NON_CANONICAL_CBOR`, `PROTO.SIZE_EXCEEDED`, `PROTO.DEPTH_EXCEEDED`, `AUTH.PAIRING_EXPIRED`, `AUTH.PAIRING_ATTEMPTS_EXCEEDED`) — and `contracts/gen/**` byte-identical.** The one wire-visible consequence is `SchemaDescriptor.schema_digest`, which all three earlier amendments moved for the same reason. **The placement argument is the part worth reviewing**: it is *not* `pairing.proto`, whose own header forbids it in terms ("`pairing_secret` … NEVER appear in this schema and MUST NOT be added") and whose messages are C1/C2 wire messages, where embedding the secret would hand the rendezvous the one value C-B's security argument requires it never see; and it is *not* `signed_statements.cddl`, because the joining device is by definition unenrolled, holds no anchor, and has no key to verify a signature against — C-B's authentication is the optical channel, so a COSE_Sign1 there would be bytes shaped like a proof, verified by no one. **Three findings came out of writing it, and the first is the significant one.** **F-1: the offer does not fit its own default channel, measured.** Encoded to RFC 8949 §4.2.1 with `attestation` absent and a 27-character hint it is **377 bytes**; ADR-0023 E1 makes the terminal QR the default "whenever the terminal is ≥ 71 columns × 37 rows", and 71 columns with a conforming 4-module quiet zone admits at most a 61-module symbol — QR version 11, **321 bytes at EC level L**, the *weakest* correction level for a symbol photographed off a glowing screen. **56 bytes over, before any attestation blob.** No document fixes the QR version, the error-correction level or the quiet zone, and those three decide whether the product's default enrolment channel works at all. Two exits, both somebody else's: E1's geometry grows to **77 × 39**, or `binding` shrinks — it is **219 of the 377 bytes** and the `TunnelKeyBinding` inside it re-states `tk_pub`, which field 3 already carries. W-23 is the standing lesson that a specified derivation is not ours to improve, so neither is taken here. **F-2:** `tk_pub` is spelled `bstr(32)` in §7.4 and `cose-key` in `signed_statements.cddl`'s `tunnel-key-binding` and `device-identity-record` — one key, two spellings, both inside the same 377 bytes. **F-3:** §4.3 ruled that `limits.json`'s stale `_max_name_bytes_note` should be folded "into the next amendment that opens `contracts/` for a real reason". This is that amendment, and the diff deliberately does **not** fold it in, so the approver is not shown a second unasked edit — but it is the cheapest it will ever be. **APPROVED and landed as Amendment 4** (`contracts/FROZEN`, 2026-08-29), on the repository owner's explicit approval under §3 steps 3 and 6: the new `.cddl`, the six `pairing` bounds at `registry_version` 3, and the contract tests. F-3 **was** folded in on approval, as the row above said it should be once the approver had seen the ask. No `.proto` and no existing `.cddl` moved; `contracts/gen/**` byte-identical, because CDDL has no codegen here. **F-1 is NOT resolved and this amendment says so in its own text**: the contract is now nameable and ADR-0023 E1's default channel still does not fit it, which is an ADR owner's call and not an implementation agent's. One correction while applying: the proposal's `pairing.proto` tripwire searched raw text, so it failed on the prohibition sentence that necessarily names what it forbids — it now cuts comments and inspects declarations. |
| **G-10** | **defect — a flaky test, which is a flaky gate** | **`lock::tests::a_closed_descriptor_is_an_errno_and_never_a_silent_false` fails at random, and when it passes it is sometimes locking a stranger's file.** It closed a `File` and called `flock` on the retained raw descriptor expecting `EBADF`. `cargo test` runs a crate's tests on threads of ONE process, so any other test opening a file between the `drop` and the `flock` takes the freed descriptor number — the call then succeeds against that file and the assertion fails as `EBADF: true`. Caught by the integration gate on the merged tree, not by the domain: it needs the whole crate's suite running concurrently to lose the race. The gate's own last fail condition is *"repository tests do not pass"*, and a test that fails on a schedule nobody controls makes that condition non-deterministic. | **Fixed** — the descriptor is now one that CANNOT be open rather than one the test closed: `RawFd::MAX` is above any `RLIMIT_NOFILE` a process can raise, so no thread can make it valid and the errno is the same one every time. The property under test is unchanged and is the one the name states — an invalid descriptor surfaces its `errno` and never reads as "somebody else holds it", which would report PS-1's violation for a programming error and send an operator looking for a second agent that does not exist. Renamed to `an_invalid_descriptor_…` because *closed* was never the property; it was the mechanism, and it was the wrong one. Five consecutive runs green. |

### 11.3 What the gate can and cannot say

The wave's acceptance gate asks for named properties, not for a test count, and
three of its clauses are answered "yes, on this host" rather than "yes":

- **Platforms.** Nothing links and nothing runs. Windows, macOS, iOS and Android
  are compile-checked only, and after G-4 the crates that host a core are not
  even that. Swift and Kotlin are not compiled at all (§9.2, §10.3).
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
