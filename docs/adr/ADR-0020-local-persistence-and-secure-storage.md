# ADR-0020: Local Persistence and Secure-Storage Realization

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0018](ADR-0018-shared-core-and-build-architecture.md),
  [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md),
  [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md)

This ADR owns the **physical realization of local persistence**: which platform API holds which
key on each of the ten targets, what the durable local store is made of, where it sits on disk,
who may open it, what is encrypted and under what key, how a whole-file or whole-image rollback
is detected, what survives reinstall / OS restore / hardware migration, and the named recovery
ladder when the store is corrupt, full, read-only, or locked. It converts
[docs/architecture.md](../architecture.md) §2.6 and §2.20 — which define two components and defer
the mechanism — into a specification an implementer can build against, and it is what makes **I4**
("private half generated in, and never exported from, platform secure storage") a mechanism rather
than a sentence.

It does **not** own the identity or trust *semantics* ([ADR-0007](ADR-0007-device-identity-and-pairing.md)),
the consistency rules that govern documents in flight ([ADR-0009](ADR-0009-state-consistency.md)),
the encoding of any signed statement ([ADR-0003](ADR-0003-network-contract-schema-format.md)), the
durability of the kill-switch rule set ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
§11.6, which is an OS-level object and deliberately **not** in this store), the DNS restore point
([ADR-0011](ADR-0011-dns-handling.md), which must be readable without this store), the process and
privilege split ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)), the local management interface ([ADR-0017](ADR-0017-local-management-interface.md)), the shared core and build
matrix ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)), packaging and update delivery ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)), or background lifecycle ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)).
Where those are needed here, the required interface is stated in §11.14 and nothing about their
internals is invented.

---

## 1. Context

[docs/architecture.md](../architecture.md) §2.6 (Device Identity Subsystem) and §2.20
(Configuration / State Storage) each end with the same sentence in different words: *"Depends on
platform secure storage. Choice deferred to [ADR-0007]."*
[ADR-0007](ADR-0007-device-identity-and-pairing.md) then decided the *semantics* — what a key
authenticates, what `hardware_backed` means to a relying peer, what happens when an identity
cannot be loaded — and gave a per-platform custody table in §7.3 that names the right APIs. What
neither document decided is the part that determines whether the product works:

1. **Which Keychain accessibility class**, which Keystore authentication flags, which CNG provider
   and key scope. These are not security garnish: `kSecAttrAccessibleWhenUnlocked` and
   `setUserAuthenticationRequired(true)` each produce a tunnel that cannot rekey while the screen
   is off — a functional defect that ships as a security decision.
2. **What the durable store physically is.** §2.20 requires atomic crash-consistent writes, schema
   versioning and migration, integrity verification of cached signed documents, and
   monotonic-version enforcement on write. Nothing names the engine, the file, the format, the
   footprint, or who is allowed to open it.
3. **Where the anti-rollback floor lives.** §2.20's "refuse a lower version" defeats an attacker who
   goes *through* the API and does nothing against one who restores the whole file from a month-old
   backup — the cheaper attack, and the one that resurrects a revoked device.
   [ADR-0009](ADR-0009-state-consistency.md) R-7/R-9 and
   [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-26 both require monotone durable floors;
   neither says where they physically sit.
4. **What happens on restore, reinstall, and migration.** [ADR-0007](ADR-0007-device-identity-and-pairing.md)
   §7.3 states the consequence — "there is no cloud restore of a device identity" — and
   [docs/threat-model.md](../threat-model.md) §13 builds the lost-device runbook on it. Neither
   states the flags, exclusion lists, and detection logic that make it true per OS.
5. **The router case, honestly.** A device with no secure element cannot uphold **I4**. The corpus
   says so in one line ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3); `docs/vision.md`
   §4.1 requires the residual exposure to be stated rather than silently relaxed.

There is also a fact the corpus states but never reconciles: **the durable store is not a
non-secret store.** [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-19 requires both devices
to durably write a `TrustedPeer` containing `PairSecret`, and S-33 requires each device to hold its
HPKE-sealed `EpochSeed` set durably. Both are on
[docs/threat-model.md](../threat-model.md) §9's never-loggable `SECRET` list.
[docs/architecture.md](../architecture.md) §2.20's non-responsibilities list ("MUST NOT store
`DeviceKey` private material; MUST NOT store live tunnel keys") is correct as written but reads as
if the store held nothing sensitive. It does. The tier rule in §11.1 is written so that this is
decidable rather than inferred, and §11.6 encrypts accordingly.

---

## 2. Requirements

### 2.1 New requirements proposed for [docs/vision.md](../vision.md) §5

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-37** | Products claim "hardware-backed keys" uniformly, then fall back to a file on disk on the platforms where it matters most, without telling anyone. | Private identity material MUST be generated inside, and used from, platform secure storage wherever the target provides one, and MUST be marked non-exportable. Where no secure element exists, the `Device` MUST declare a **degraded custody class** that peers and the `Owner` can see, and MUST NOT present itself as hardware-backed. The degradation and its residual exposure MUST be stated, never silently relaxed. | Three-tier storage model with a decidable tier rule; per-platform Tier-1 realization table; `KeyCustodyDescriptor` (S-54) feeding [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `hardware_backed` claim and the `Capability` advertisement (S-19) | **ADR-0020** §11.1, §11.3, §11.4; [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 |
| **R-38** | Restoring an old profile, config file, or device backup silently reinstates a revoked peer, an older `AccessPolicy`, or an older revocation list. | Every monotone local fact MUST be anchored **outside** the durable file, in secure storage, and written **before** the commit it admits. Restoring the durable file alone MUST be detected and refused; no recovery path — including corruption recovery and schema migration — may lower a floor. Where the platform cannot detect the rollback, the limitation MUST be declared as residual exposure. | `StoreAntiRollbackAnchor` (S-53) co-located with the identity key; write-ahead floor commit; hardware monotone counter on TPM targets; `STORE.ROLLBACK_DETECTED` | **ADR-0020** §11.7, §11.11; [ADR-0009](ADR-0009-state-consistency.md) §11.3 R-7/R-9; [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-26 |
| **R-39** | A corrupt config file bricks the client, or the client silently resets to defaults — losing protection, losing trust state, or minting a fresh identity that is indistinguishable from a compromise. | Store corruption, exhaustion, read-only media, and temporarily unavailable secure storage MUST each be a **named, recoverable** condition with a defined recovery rung. Recovery MUST NOT regenerate identity, MUST NOT disengage the kill switch, and MUST NOT lower any monotone floor. An in-place update or reinstall MUST NOT destroy the store; a restore onto different hardware MUST NOT yield a working identity. | Recovery ladder L0–L5 with one `STORE.*` code per rung; floors re-seeded from Tier 1, never from the quarantined vault; `StoreBindingToken` (S-56); backup-exclusion obligations on [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | **ADR-0020** §11.8, §11.11, §11.12 |

### 2.2 Requirements inherited from the corpus that bind this ADR

| # | Requirement | Source |
|---|---|---|
| RQ-1 | Atomic, crash-consistent writes; schema versioning with forward/backward migration; integrity verification of cached signed documents; monotonic-version enforcement on write | [docs/architecture.md](../architecture.md) §2.20 |
| RQ-2 | The store MUST NOT hold `DeviceKey` private material or live tunnel keys; a document at a lower version MUST NOT be accepted | [docs/architecture.md](../architecture.md) §2.20 non-responsibilities |
| RQ-3 | Corrupt store ⇒ identity-only bootstrap, a **named recoverable** error, re-pull of cached state, and **no** silent identity regeneration | [docs/architecture.md](../architecture.md) §2.20, §2.6 |
| RQ-4 | `TrustedPeer` (S-05) durably contains peer `device_id`, `ik_pub`, `tk_pub`, the verified `TunnelKeyBinding`, `PairSecret`, the pinned anchor and delegation chain, and the current `EpochSeed`; `PairSecret` MUST NOT be transmitted, backed up, or replicated | [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-19 |
| RQ-5 | `trust_epoch`, `anchor_version`, `generation`, `tk_generation` MUST be monotone **in durable local state**; a lower value is refused with `AUTH.TRUST_EPOCH_ROLLBACK` | [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-26 |
| RQ-6 | High-water marks are durable and MUST be written **before** the document they admit is acted upon, so a crash between the two cannot lose the floor | [ADR-0009](ADR-0009-state-consistency.md) §11.3 R-9 |
| RQ-7 | A signed statement MUST NOT be represented in more than one encoding; verification is over received octets; implementations MUST NOT re-serialize | [ADR-0003](ADR-0003-network-contract-schema-format.md) §11 rule 1 |
| RQ-8 | A restarted client resumes into `RECONNECTING` per known peer, not `DISCONNECTED` from scratch; `Session` identity and last `ConnectionState` are durable (S-12) | [docs/reliability.md](../reliability.md) §6.5 |
| RQ-9 | `SECRET`-classified material has **no rendering path in any build at any log level**; the store is subject to the same list | [docs/threat-model.md](../threat-model.md) §9; [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4 |
| RQ-10 | S-18 (kill-switch engagement) is durable **at OS level**, surviving process death, crash, update and reboot; this store is not its durability mechanism | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, §11.13 |
| RQ-11 | S-34 (`HostResolverRestorePoint`) MUST be readable by the boot restore entry point **without the agent running** | [ADR-0011](ADR-0011-dns-handling.md); [docs/architecture.md](../architecture.md) §5 S-34 |
| RQ-12 | Every timer, clock and random source is injectable at a component boundary, so the lab can run deterministically — confirmed as a responsibility of 2.20 | [docs/architecture.md](../architecture.md) §9 A-21 |

---

## 3. Constraints

| # | Constraint | Consequence for this ADR |
|---|---|---|
| C-1 | **iOS/iPadOS**: the `NEPacketTunnelProvider` runs in a memory-constrained app extension; [docs/networking.md](../networking.md) §5.4 already moves contract fetch/parse and diagnostics to the app process for this reason. | The vault's read cache is a hard budget, not a tuning knob (§11.5). The app process that fetches a document is a **courier**, not a writer (§11.9). |
| C-2 | **iOS/iPadOS**: no host firewall; the extension may be started by the system on network attach **before the user has unlocked the device since reboot**. | The accessibility class must permit background use while locked but after first unlock. Anything stricter makes on-demand start fail (§11.3). |
| C-3 | **Android**: Doze, background-start restrictions, always-on VPN starting at boot, Direct Boot. Credential-encrypted storage is unavailable before first unlock. | The identity key and SEK live in the credential-encrypted domain; only a non-secret bootstrap record may live in device-encrypted storage (§11.3). |
| C-4 | **Windows**: the service starts before any interactive logon. User-scope DPAPI is unavailable then. | Machine-scope key material only; the confidentiality boundary is `LocalSystem`/local administrator, matching [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) K5 (§11.3, §11.9). |
| C-5 | **macOS**: system extension vs app extension vs `launchd` daemon, App Store sandbox vs Developer ID, and Apple silicon vs pre-T2 Intel are four independent axes with different key APIs. | Four rows, not one (§11.3). |
| C-6 | **Linux**: no desktop session may exist. `gnome-keyring`/KWallet require one. | The daemon MUST NOT depend on the Secret Service; TPM 2.0 where present, restrictive file permissions as the honest floor (§11.3). |
| C-7 | **OpenWrt/routers/headless**: ≤128 MB RAM, musl/uclibc, 32-bit mips/mipsel/armv7, read-only squashfs rootfs with a JFFS2/UBIFS overlay, `/var` is tmpfs, flash write endurance is finite, and there is usually **no secure element at all**. | Footprint and write-rate budgets are normative (§9); **I4 degrades** and the residual is declared (§11.4, §7). |
| C-8 | H1 ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)) places the store inside a portable core behind a C ABI. | No engine may require a native shell to touch the file, and the engine must build for every target in [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s matrix (§11.5). |
| C-9 | H2 ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)) and H3 ([ADR-0017](ADR-0017-local-management-interface.md)) give exactly one privileged process and exactly one control contract. | Single-writer, single-*opener* is available as a design property rather than an aspiration (§11.9). |
| C-10 | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) must be able to update and to roll back the client without destroying the store. | A two-version backward migration window and a refusal (not a reset) on `schema_version` too new (§11.5). |
| C-11 | Secure deletion on flash is not achievable by overwriting: FTL wear-levelling, eMMC/NAND remapping, and copy-on-write filesystems (APFS, btrfs, JFFS2, UBIFS, ZFS) all retain prior extents. | Erasure is **crypto-erase** or it is nothing (§11.10). |
| C-12 | TPM NV counters have finite write endurance and NV writes cost tens of milliseconds. | The hardware counter is advanced on **trust-floor advance only**, not per commit (§11.7, §9). |

---

## 4. Considered Alternatives

Two groups. **Group V** decides what the durable local store physically is. **Group M** decides
where the monotone anti-rollback floor lives, which is a separate decision with its own honest
limits and is the one that actually determines whether a restored backup can resurrect a revoked
peer.

### Group V — durable store realization

| # | Alternative | Shape |
|---|---|---|
| **V1** | **Embedded transactional key-value vault** — one file, copy-on-write B-tree, single writer, atomic multi-key commit, per-record AEAD; keys are `namespace/key`, values are CBOR record envelopes; platform secure storage holds only keys. |
| **V2** | **Embedded SQL store** — SQLite in WAL mode, relational schema, `PRAGMA user_version` migrations, `SQLCipher`-class page encryption or per-column AEAD; platform secure storage holds only keys. |
| **V3** | **Platform-native stores throughout** — Keychain + `UserDefaults`/Core Data on Apple, Keystore + Room/`SharedPreferences` on Android, DPAPI + registry/`%ProgramData%` on Windows, libsecret + GSettings on Linux, UCI on OpenWrt. One implementation per platform. |
| **V4** | **Document vault** — a directory of individually atomically-replaced files (write-temp, `fsync`, `rename`, `fsync` dir), one file per fact, plus a signed manifest naming the current generation. No engine at all. |
| **V5** | **Local append-only ledger** — a single hash-chained, encrypted append-only log of state mutations with periodic compaction into a snapshot; current state is a fold of the log. |

### Group M — anti-rollback anchor placement

| # | Alternative | Shape |
|---|---|---|
| **M1** | **In-store only** — the floors are rows in the vault; monotonicity is enforced on write. (This is literally what §2.20 says today.) |
| **M2** | **Secure-storage anchor, co-located with the identity key** — a small record (`store_seq`, `vault_digest`, floor set) held as a Tier-1 item in the *same* backend and under the *same* custody class as the `DeviceIdentityKey`, written ahead of the commit it admits. |
| **M3** | **Hardware monotonic counter** — TPM 2.0 NV counter (`TPM2_NV_Increment`), or an equivalent platform counter, incremented on every floor advance; the vault carries the last observed value. |
| **M4** | **Remote attestation of the floor** — the device publishes its floor to the control plane, which refuses to serve a device presenting a lower one. |

---

## 5. Advantages of Each Alternative

### Group V

| # | Advantages |
|---|---|
| **V1** | Matches the actual data shape: every durable fact is either a verbatim signed blob or a small structured record retrieved by an exact key. No query planner, no SQL surface, no dialect. Atomic multi-key transactions give RQ-1 and RQ-6 directly. Copy-on-write makes a torn write structurally impossible rather than recovered-from. Small: a few hundred KiB of code, no C toolchain requirement beyond the H1 core's, and it cross-compiles to musl and 32-bit mips because it is ordinary portable code with `pread`/`pwrite`/`fsync`. Per-record AEAD gives per-record integrity *and* the natural place to bind anti-rollback AAD. |
| **V2** | The most familiar engine in the industry; every platform has bindings; migrations are a solved idiom (`user_version` + versioned scripts); WAL gives good crash consistency and concurrent readers; page checksums are available; the tooling for offline inspection is excellent, which matters for support. Available as an OpenWrt package. |
| **V3** | Idiomatic on every platform, so each store behaves the way that OS's users and its backup system expect; zero third-party engine to audit, ship, or sign; smallest possible binary growth; on Apple platforms Keychain and file protection classes compose naturally; on OpenWrt, UCI is what an operator already knows how to read and edit. |
| **V4** | The least machinery of any option and the easiest to reason about under crash: POSIX `rename` atomicity is a well-understood primitive with well-understood failure modes, and Windows `ReplaceFile`/`MoveFileEx` are its equivalents. Signed documents are stored exactly as received with no framing at all, so RQ-7 is free. Trivially inspectable by a support engineer with `ls` and `xxd`. Lowest RAM ceiling of any option: reads are per-file and never touch a shared cache. Degrades gracefully on a nearly-full flash because each write is independent. |
| **V5** | The strongest integrity story: a hash chain over mutations makes truncation and reordering detectable without any external anchor, and gives a local audit trail that directly serves **P10** (diagnosability is designed, not added). Crash consistency is inherent — a partial trailing record is discarded. Write pattern is purely sequential, which is the friendliest pattern for raw NAND. |

### Group M

| # | Advantages |
|---|---|
| **M1** | Zero platform dependency; works identically on all ten targets; no extra failure mode; exactly what [docs/architecture.md](../architecture.md) §2.20 already asks for. |
| **M2** | Available on **every** target that has secure storage at all, which is nine of ten. Detects the attack that actually happens — restoring the data file — because the file and the anchor live in different storage domains with different backup semantics. Co-location with the identity key converts "delete the anchor" into "delete the identity", whose consequence is already specified and safe: `AUTH.IDENTITY_MISSING` ⇒ re-enrolment ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3, N-7). Cheap: a few hundred bytes, written a few times a minute at worst. |
| **M3** | The only mechanism that survives a **whole-device-image** rollback on real hardware, because the counter is inside a chip that the image does not contain. Standard, attestable, and already required by ADR-0007's Windows/Linux rows for other reasons (the TPM is present anyway). |
| **M4** | Detects rollback even on a fully file-backed device with no secure element — the one case M2 and M3 cannot cover — and the control plane already holds the linearizable ordering ([ADR-0009](ADR-0009-state-consistency.md) §11.2), so the floor is knowable there. |

---

## 6. Disadvantages of Each Alternative

### Group V

| # | Disadvantages |
|---|---|
| **V1** | An engine we must select, audit, and pin. Fewer offline inspection tools than SQL. Single-writer means the design must *forbid* a second opener rather than merely discourage one — acceptable here only because C-9 grants it. No ad-hoc query surface if a future feature wants one. |
| **V2** | Large: SQLite plus an encryption layer is a substantial dependency to ship on a 128 MB router, and page-level encryption products (SQLCipher-class) carry their own licensing and audit burden. WAL introduces a second and a third file whose lifecycle must be managed on uninstall and backup-exclusion (three paths to exclude, not one — and a missed one leaks). The relational surface is unused: there is not a single join in the workload. `fsync` behaviour under WAL on Android eMMC is a known source of surprise. Offers a query surface that invites exactly the "just add a table" growth the store must not have. |
| **V3** | **Directly contradicts H1.** Six to ten independent persistence implementations means six to ten independent anti-rollback implementations, six to ten migration paths, and six to ten places for RQ-2 to be violated. `UserDefaults`, `SharedPreferences`, GSettings and the registry are all *designed to be backed up and synced* — precisely the property that must not hold for a store containing `PairSecret`. UCI is a plaintext config tree an operator is expected to edit, back up, and copy between routers. There is no plausible way to make these ten behave identically under crash, and the corpus's whole argument rests on identical behaviour. |
| **V4** | No cross-file atomicity: committing "new `TrustedPeer` **and** advanced `trust_epoch` floor" requires a manifest generation swap, at which point a manifest has been reinvented as a single-file transaction log with worse properties than V1's. Directory `fsync` semantics differ meaningfully between ext4, APFS, JFFS2, and NTFS. File-per-fact multiplies inode and erase-block pressure on JFFS2/UBIFS, which is the opposite of the intended benefit. Enumerating a directory is not a stable snapshot. |
| **V5** | Compaction is the hard part and it is on the critical path of an unattended router: a compaction interrupted by power loss must be recoverable, which reintroduces exactly the atomic-swap problem V4 has. Read amplification on cold start grows with log length, hurting the platform where cold start matters most (C-1). Memory to fold the log is unbounded unless the snapshot cadence is aggressive, and an aggressive cadence is just V1 with extra steps. The audit-trail benefit is already delivered by the diagnostic event stream ([ADR-0015](ADR-0015-observability-and-diagnostics.md)), so it is paid for twice. |

### Group M

| # | Disadvantages |
|---|---|
| **M1** | **Defeats only the attacker who goes through the API.** Copy the file, revoke a device, copy the file back, and the floor comes back with it. This is the cheapest attack in the class and M1 does not see it. It is also the one an ordinary user performs accidentally, by restoring a backup. |
| **M2** | Absent on a device with no secure storage (OpenWrt/routers, and Linux/Windows with no TPM using file-backed custody), which is exactly where the store is easiest to copy. Adds a Tier-1 write to the commit path, whose latency varies by platform. A platform that silently migrates or re-encrypts its secure-storage items across an OS upgrade can produce a spurious anchor loss; the design must treat "anchor missing" differently from "anchor lower". |
| **M3** | Available only on TPM 2.0 targets — no app-accessible monotonic counter exists on iOS/iPadOS, macOS, or Android. Finite NV write endurance and tens of milliseconds per increment (C-12) forbid a per-commit cadence. A **virtual** TPM snapshotted together with the VM image defeats it entirely, so its guarantee is "real hardware only" and must be stated that way. |
| **M4** | **Makes the control plane a liveness dependency of local state.** A device that cannot reach the control plane could not validate its own floor, which breaks **I5** and **R-11** outright, and the corpus has already rejected this shape three times ([docs/architecture.md](../architecture.md) §4.4, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, [ADR-0009](ADR-0009-state-consistency.md) §11.5). It also hands the control plane a lever over local enforcement, which §10.1 of [docs/threat-model.md](../threat-model.md) spends its length denying it. |

---

## 7. Security Implications

| # | Implication | Enforcement mechanism (not an intention) |
|---|---|---|
| **SI-1** | **I4 is realized here or nowhere.** §11.3 enumerates what "generated in secure storage" means per API; §11.4 declares where it is not true | The platform flag in each §11.3 row — `kSecAttrTokenIDSecureEnclave` + `kSecAccessControlPrivateKeyUsage`, `setIsStrongBoxBacked`, `NCRYPT_ALLOW_EXPORT_FLAG` unset, `fixedTPM\|fixedParent` — not a review rule. Where no secure element exists, the invariant is **not** upheld and §11.4 states the class, the residual, and how a peer learns it |
| **SI-2** | **The store holds `SECRET` material.** RQ-4 puts `PairSecret` and the `EpochSeed` seals in it, so store confidentiality reduces to the custody class of the store key | Per-record AEAD under a Tier-1-held `SEK` (§11.6), unconditionally on every platform. On `HARDWARE_*` a copied vault is unopenable; on `SOFTWARE_PORTABLE` the key sits beside it and encryption buys nothing against a local reader — stated in ST-20, not hidden |
| **SI-3** | **Anti-rollback is a security control with an asymmetric guarantee.** It stops the file-restore attack on nine of ten targets and the device-image attack only where a real hardware counter exists | §11.7's anchor, ST-23's commit ordering, and ST-24's open-time classification. What it *always* does is refuse to lower a floor; what it *never* does is silently accept an older trust state. The residual is in §13 |
| **SI-4** | **The never-persisted list is a type property, not a review rule** | The core implements no encoder for the tunnel key state, the unsealed `PairSecret` working copy, or the ORK, so "persist it" is a compile error. Same fail-closed shape as [ADR-0015](ADR-0015-observability-and-diagnostics.md)'s emitter-side redaction (O-14), rather than a scrubbing step that fails open |
| **SI-5** | **Two openers is two writers for one fact — an I8 violation at the physical layer**, and on a shared App Group container a privilege crossing too | ST-30: the privileged process is the sole opener, enforced by an exclusive lock plus an owner record; everything else goes through [ADR-0017](ADR-0017-local-management-interface.md). A second opener is refused with `STORE.LOCK_CONTENDED`, a security event rather than a retryable condition |
| **SI-6** | **Crypto-erase is the only honest deletion** (C-11) | ST-34: key destruction first, file removal second, with `STORE.WIPE_INCOMPLETE` when step 1 fails and an explicit statement of what remains per custody class |
| **SI-7** | **Backup is an exfiltration channel.** An included vault ships `PairSecret` ciphertext to a cloud the threat model does not trust; an included identity makes a restored device a clone (TM-13) | ST-26: per-platform exclusion flags, **re-verified at every start**, with `STORE.BACKUP_EXCLUSION_FAILED` on failure rather than a silent success |

---

## 8. Reliability Implications

- **RL-1 — restart resumes, it does not reset.** S-12 lives in the vault's `session/` namespace
  (§11.2), which is why a restarted client re-enters `RECONNECTING` per peer (RQ-8).
- **RL-2 — the store is not on the established-session path.** A vault that is corrupt, full, or on
  read-only media MUST NOT tear down an established `Session` (**I5**); it degrades *new* operations
  only, and every rung of §11.11's ladder is written to preserve that.
- **RL-3 — a full disk cannot block a floor**, because the floor lives in Tier 1 and Tier 1 is not
  the filesystem: `STORE.WRITE_SPACE_EXHAUSTED` degrades caching, not anti-rollback.
- **RL-4 — corruption is recoverable by design.** RQ-3's identity-only bootstrap is rung L3, and it
  re-seeds floors from Tier 1 rather than from the quarantined file, so recovery cannot be used as a
  rollback primitive.
- **RL-5 — the kill switch does not depend on this store** (RQ-10). If the vault is unopenable at
  boot, the OS-level rule set is already installed and stays installed
  ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6); the vault holds a reporting
  replica of `EnforcementRecord` only.
- **RL-6 — DNS restore does not depend on this store** (RQ-11). S-34 is a plain sidecar precisely so
  the boot restore entry point can read it with the agent absent and the vault unopenable.
- **RL-7 — deterministic replay.** RQ-12: clock, nonce randomness, and debounce timers are injected,
  so TwinLab can drive commit ordering and crash points deterministically.

---

## 9. Performance Implications

Budgets are normative; [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) owns whether the chosen engine meets them, and §14 turns each into
a falsifiable revisit trigger.

| Metric | Desktop / server | iOS / iPadOS / Android | **`GC-0`** — the *envelope*, not one SoC ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54d: **single core, ~580–700 MHz, no crypto extensions**, 128 MB RAM of which **~24 MB is realistically free**, 16 MB flash, squashfs + overlay; `ath79` MIPS is the canonical member, and a single-core ARM member of the same envelope is an equally valid gating unit) |
|---|---|---|---|
| Steady-state vault size, 8 peers | ≤ 128 KiB | ≤ 128 KiB | ≤ 128 KiB |
| Hard vault cap (LRU-evicting cached documents beyond it) | 8 MiB | 4 MiB | 1 MiB |
| Read cache ceiling | 8 MiB | **2 MiB** (C-1) | **512 KiB** (C-7) |
| Whole-file `mmap` | permitted | not permitted | **forbidden** (32-bit address space) |
| Cold open, p95 | ≤ 30 ms | ≤ 50 ms | **≤ 400 ms, provisional** (see below) |
| Commit with durability barrier, p95 | ≤ 15 ms | ≤ 25 ms | **≤ 500 ms, provisional** (see below) |
| Sustained commit rate, steady state | ≤ 1 /s | ≤ 1 /s | ≤ 0.2 /s |
| Tier-1 anchor write (floor-bearing commit), p95 | ≤ 50 ms | ≤ 50 ms | n/a (file-backed) |
| Hardware counter increment | ≤ 150 ms, **floor advances only** | n/a | n/a |
| Diagnostic ring file (separate, pre-allocated, non-transactional) | 4 MiB | 1 MiB | 256 KiB |

**The two `GC-0` latency budgets are provisional, and the derivation matters more than the number.**
Both were first sized against the dual-core Cortex-A53 reference that
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) BM-1.4 has since withdrawn as a chimera,
so they are re-derived here against the EM-54d envelope and **the first measurement on real `GC-0`
hardware replaces them rather than being judged against them** — which is BM-1.4's own lesson
applied to this ADR.

The decomposition is stated so the derivation can be checked, because a blanket CPU multiplier
would be wrong here:

| Term | Share of cold open on `GC-0` | Why |
|---|---|---|
| Flash read of the vault (≤ 128 KiB steady state) | **Dominant** | SPI NOR / raw NAND through the overlay, single-digit MB/s realistic |
| Engine init, B-tree walk, page checksums | Significant | Single-issue core at ~580 MHz, cold caches |
| **Record AEAD** | **Minor — roughly 5 ms** | ChaCha20-Poly1305 at ~15–25 cycles/byte without crypto extensions is ~30 MB/s at 580 MHz, and only the header, the anchor, and the namespaces actually touched are opened (ST-12a's lazy open) |

So the AEAD cost does **not** scale the budget by the core's throughput ratio: a 3–4× loosening
justified on "the open path touches the AEAD" would be reasoning from the smallest term. The 400 ms
and 500 ms figures are instead a ~2.5–3× allowance for the I/O and init terms on single-core
silicon, and the commit figure additionally absorbs a JFFS2/UBIFS erase-block or garbage-collection
event landing inside a durability barrier, which is the realistic tail on this medium.

**Write-rate control is a flash-endurance requirement, not an optimisation** — and the split is a
*security* boundary, not a tuning knob, because **a coalesced monotone write is a rollback window**.
Every durable row therefore belongs to exactly one write class:

| Write class | Rows | Cadence | Loss on power failure |
|---|---|---|---|
| **Write-once** | S-01 identity, S-05 `TrustedPeer` + `PairSecret` | Once, at generation or pairing | n/a |
| **Synchronous / security-bearing** | Any monotone floor (S-03, S-32, S-33, S-37, S-27 high-water, `contract_seq`), the `RelayCapabilityToken` (S-30), `IntentGeneration` (S-65), and the S-18 reporting replica | **Never coalesced.** Written, with its durability barrier, **before** the action it authorizes (RQ-6, ST-23, [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) **EM-53**) | Not permitted — this is what ST-24 detects if it happens |
| **Coalesced / convenience** | `Endpoint` cache (S-15), measured relay quality (S-31), preferences (S-24), last `ConnectionState` (S-12) | Debounced **≥ 30 s, profile-configurable, with `H-EMB` at 60 s** ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-52), **plus a write on clean shutdown** | **Permitted and safe.** Losing S-12 resumes into `RECONNECTING`, which is the fail-safe direction (RQ-8) |
| **Never durable** | S-13, S-14, S-21, S-35, and [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s S-66 ephemeral overrides | No encoder exists (ST-2, SI-4) | n/a |

S-18 needs one clarification: its **authoritative** durable write is the OS-level object and is
synchronous by [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6. Only the vault's
reporting replica is at issue here, and it follows the authority rather than leading it.

**`GC-0` flash budget (normative).** Total store writes MUST NOT exceed **4 KB/day** in steady state
on 16 MB OpenWrt flash ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-52). Enforcement
and the per-UTC-day byte counter are [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s
(S-68, `PLATFORM.EMBEDDED.FLASH_WRITE_BUDGET_EXCEEDED`), and on exceedance the store MUST stop
non-essential writes while continuing every synchronous security write — never the reverse. This is
achievable because the synchronous class is driven by `Owner` and control-plane events measured in
units per week, not per second, and the coalesced class is bounded by its debounce. A build that
exceeds it is wearing out the user's router, which is an unrecoverable hardware fault rather than a
performance regression — hence §14 trigger 11.

Diagnostics never enter the vault: the ring file is a pre-allocated circular region written without
`fsync`, so an event burst cannot cause a burst of transactional commits, and it is excluded from
the 4 KB/day budget by being a fixed-extent overwrite rather than an allocating write. C-1's
extension memory budget is why the 2 MiB read-cache ceiling and the `mmap` prohibition bind, and
why the vault is opened lazily per namespace rather than faulted in whole.

---

## 10. Operational Implications

1. **A support engineer cannot read the store, and that is the point.** Schema version, custody
   class, floors, health state, and per-namespace record counts are exposed through [ADR-0017](ADR-0017-local-management-interface.md)'s
   status surface and the [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8 connectivity
   report, pseudonymized. There is deliberately no "dump the vault" command: that command is an
   exfiltration primitive ([docs/threat-model.md](../threat-model.md) §9, threat 3).
2. **Re-enrolment is a routine operation, not an incident.** Restore-to-new-hardware, a
   `sysupgrade` that drops the store, and a permanent key invalidation all land on the same flow
   ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3), and operator documentation must
   present it as the expected outcome rather than a failure.
3. **`sysupgrade` on OpenWrt is a decision about identity.** §11.8 keeps the store across upgrade so
   [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)'s requirement holds; a user-taken config backup therefore contains a usable identity.
   The CLI must warn at backup time and the custody class must be visible (§13).
4. **Backup exclusion is verified, not assumed** — re-checked at every start, with
   `STORE.BACKUP_EXCLUSION_FAILED` when the platform reports the store as included. An OS update
   that changes backup semantics surfaces as a diagnostic rather than as a silent leak.
5. **Signing-identity changes are a store migration.** The macOS keychain item ACL binds to the
   code-signing identity, and Windows key-container access is governed by the service identity. A
   change of Team ID, service account, or package identity is an event [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) must schedule.
6. **Two-version downgrade window.** Beyond it the store refuses to open with
   `STORE.SCHEMA_TOO_NEW` and the older client runs identity-only. Refusal, never a reset.

---

## 11. Decision

**TwinVPN adopts V1 + M2, with M3 as a platform-conditional reinforcement.** The durable local
store is a single-file, single-opener, embedded transactional key-value vault with copy-on-write
commit and per-record AEAD; platform secure storage holds only keys and a small anti-rollback
anchor; the anchor is co-located with the identity key and written ahead of the commit it admits;
and a TPM NV counter is additionally advanced on trust-floor advances where a TPM exists. V2, V3,
V4, V5 and M1, M4 are rejected as primary mechanisms; M1's in-store version check is retained as a
*first* line and M3 as a *third*.

### 11.1 The three-tier model and the tier-assignment rule

| Tier | Name | What it is | Durability |
|---|---|---|---|
| **Tier 0** | **Volatile** | Live cryptographic and path state | **Non-durable by requirement.** No encoder exists (SI-4). |
| **Tier 1** | **Custody** | Platform secure storage: non-exportable key handles plus the anti-rollback anchor | Durable, survives reinstall per platform, excluded from backup/sync |
| **Tier 2** | **Vault** | The single-file durable local store, encrypted under a Tier-1 key | Durable, survives reboot and in-place update; excluded from OS backup |

**Rule ST-1 (tier assignment — normative and decidable).** A new durable fact is assigned by
answering two questions in order:

1. *Must this value be usable only through an operation the platform key API can perform (sign,
   agree, wrap, unwrap, AEAD), with the value itself never readable by the process?* If yes ⇒
   **Tier 1**. This is true of `DeviceIdentityKey` private material, the `TunnelStaticKey` wrapping
   key, an `OwnerSigningKey`, the `SEK`, the binding key `K_bind`, and the anti-rollback anchor.
2. *Is this value part of an established `Tunnel`'s live cryptographic or path state?* If yes ⇒
   **Tier 0**, and it MUST NOT be persisted anywhere. Otherwise ⇒ **Tier 2**.

**Rule ST-2.** Tier 2 MUST NOT contain `DeviceKey` private material or live tunnel keys
(RQ-2). Enforcement is SI-4: the types carrying them have no serialization.

**Rule ST-3.** Tier 2 is **not** a non-secret store. It contains `PairSecret` and the sealed
`EpochSeed` set by RQ-4, both `SECRET`-classified, and it is therefore encrypted under §11.6
unconditionally, on every platform, including those where no hardware backing exists.

**Rule ST-4.** A fact that must be readable when the vault cannot be opened — the DNS restore point
(RQ-11), the store health state (S-55), the kill-switch OS artifacts (RQ-10) — MUST live outside
the vault as a named sidecar or an OS-owned object, and MUST NOT be `SECRET`-classified. If a fact
is both boot-critical and secret, that is a design error to resolve, not to encode.

### 11.2 Physical residence of every locally-held state row

This is the table [docs/architecture.md](../architecture.md) §5 could not carry: for each row that
lives on a device, *where it physically is*. Rows S-01…S-37 are **cited, not redeclared**.

| Row | Fact | Physical residence | Notes |
|---|---|---|---|
| S-01 | `DeviceKey` private material | **Tier 1** | §11.3 per platform; never in the vault (RQ-2) |
| S-01b | `TunnelStaticKey` (`TK`) — the **sealed** blob | Tier 2 **`identity/`**; its **wrapping key** is Tier 1 | The second half of the `DeviceIdentity` [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-1 defines; S-01 is the IK half. **ST-1 decides this and was never run against `TK`**: rule 1 admits only a value never readable by the process, and N-5, CB-5 row 2, [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.16 (c) and B-09 all require `TK` to be unsealed **into** locked core memory, because platform key APIs largely do not offer X25519 ECDH. Rule 2 is no — live tunnel key state is S-13, Tier 0. `SECRET` ⇒ ST-3; erased by ST-34 step 1 with the handles. Availability class per target: ADR-0007 §7.3. This row was missing entirely until 2026-08-29 — ownership.md §11.2 **G-17**, ruled by §11.4 **D-6** |
| S-02 | `DeviceIdentity` record + membership | Tier 2 `doc/membership` | verbatim signed octets (RQ-7) |
| S-03 | Revocation list / trust epoch | Tier 2 `doc/trust` + **floor mirrored in Tier 1** | floor is the load-bearing half (§11.7) |
| S-04 | `Pairing` record | Tier 2 `peer/<device_id>/pairing` | includes the `CEREMONY` idempotency key ([ADR-0008](ADR-0008-idempotency.md) N-4) |
| S-05 | `TrustedPeer` (local view) | Tier 2 `peer/<device_id>` | contains `PairSecret` ⇒ `SECRET` ⇒ ST-3 |
| S-06 / S-07 | `AccessPolicy` / `DNSPolicy` | Tier 2 `doc/policy`, `doc/dnspolicy` | verbatim; `doc_version` floor in Tier 1 |
| S-08 | `TwinNet` address allocation | Tier 2 `doc/contract` | inside the signed network contract ([ADR-0003](ADR-0003-network-contract-schema-format.md) §11.5) |
| S-09 | `Relay` fleet registry + ranking | Tier 2 `doc/relayset` | stale-but-usable; LRU-evictable |
| S-10 / S-11 / S-25 | Relay health, presence, control-channel attachment | **Tier 0** | non-durable by requirement |
| S-12 | `Session` identity + last `ConnectionState` | Tier 2 `session/<peer>` | RQ-8 |
| S-13 | `Tunnel` key state | **Tier 0** | ST-2; no encoder exists |
| S-14 | `Path` set + candidate ledger | **Tier 0** (ledger copy in the ring file) | S-22 residence, below |
| S-15 | `Endpoint` cache | Tier 2 `net/endpoint` | cache-class, 30 s debounce (§9) |
| S-16 | `Route` advertisement | Tier 2 `net/route_adv` | monotone per advertiser |
| S-17 | Installed routes | **Tier 0** | re-derived at connect |
| S-18 | Kill-switch engagement | **OS-level object** ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6); vault holds a reporting replica at `policy/enforcement` | RQ-10; on divergence the OS object wins and the replica is refreshed |
| S-19 / S-20 | `Capability` / `ProtocolVersion` advertisement | Tier 2 `cap/` | advisory |
| S-21 | Per-peer gateway datapath state | **Tier 0** | reconstructible |
| S-22 | Telemetry / diagnostic ring buffer | **Sidecar ring file**, pre-allocated, encrypted under `K_ring`, non-transactional | never in the vault (§9); losable |
| S-23 | Released-version registry cache | Tier 2 `doc/release` | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns the fact |
| S-24 | User preferences / local config | Tier 2 `pref/<account_scope>` | §11.9 for the multi-user key |
| S-50 | `RouteConsentRecord` ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)) | Tier 2 **`consent/`** | Separate namespace by requirement (ST-14a); no non-local writer, no replication (ST-14b) |
| S-51 | UI presentation preferences ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)) | Tier 2 `pref/ui/<account_scope>` | Written by the UI surface **through** [ADR-0017](ADR-0017-local-management-interface.md), never by opening the file (ST-30) |
| S-65 | Compiled `IntentGeneration` ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)) | Tier 2 `policy/intent`, on the `sysupgrade`-preserved path (§11.9) | Monotone generation; floor mirrored in Tier 1 like any other |
| S-67 | `HeadlessEnrolmentOffer` ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)) | **Tier 0** | Confirmed non-durable and outside the vault: it carries a `pairing_secret`, which ST-33 forbids persisting |
| S-26 / S-28 | Control-plane log position, shard lease | **not on the device** | control-plane rows |
| S-27 | Control-channel cursor + per-type version high-water | Tier 2 `session/cursor` + **floors mirrored in Tier 1** | RQ-6 |
| S-29 | Relay half-flow table | **not on the device** (relay-side, non-durable) | — |
| S-30 | `RelayCapabilityToken` | Tier 2 `net/relay_token` | durable by requirement (S-30) |
| S-31 | Per-relay measured quality | Tier 2 `net/quality` | LRU 64 fingerprints; cache-class debounce |
| S-32 | `OwnerTrustAnchor` + delegations | Tier 2 `trust/anchor` + **`anchor_version` floor in Tier 1** | verbatim COSE_Sign1 |
| S-33 | `EpochSeed` set (current + two prior) | Tier 2 `peer/<device_id>/epochseed` | HPKE seals; `SECRET`; ST-3 |
| S-34 | `HostResolverRestorePoint` | **Plain sidecar file**, integrity-tagged, outside the vault | RQ-11: boot restore must read it without the agent |
| S-35 | `PortalExemptionGrant` | **Tier 0** | non-durable by requirement ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.13) |
| S-66 | Ephemeral runtime overrides ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)) | **Tier 0** | Deliberately not written to the `IntentGeneration`; confirmed no encoder exists (EM-52) |
| S-36 | Live gateway grant set | **Tier 0** | reconstructible |
| S-37 | Per-peer negotiation floor | Tier 2 `session/floor/<peer>` + **digest mirrored in Tier 1** | MUST NOT decrease; §11.7 |

### 11.3 Tier 1 — per-platform secure-storage realization

Ten targets. `IK` is the `DeviceIdentityKey`, `SEK` the store encryption key, `ANCH` the
anti-rollback anchor, `K_bind` the host-binding key. Where [ADR-0007](ADR-0007-device-identity-and-pairing.md)
§7.3 already fixed a choice for IK/TK, this table **confirms and extends** it to SEK/ANCH and adds
the availability semantics that §7.3 did not state.

| Target | Backend and API | Accessibility / availability class | SEK + ANCH realization | Sharing across processes | Availability before first unlock after reboot |
|---|---|---|---|---|---|
| **iOS** | Keychain, data-protection; `SecKeyCreateRandomKey` P-256 with `kSecAttrTokenIDSecureEnclave` + `kSecAccessControlPrivateKeyUsage` | **`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** | SEK: 32 random bytes as a `kSecClassGenericPassword` item, same accessibility, wrapped for use via a second SEP key. ANCH: a second generic-password item in the **same** access group and accessibility class (M2 co-location) | `kSecAttrAccessGroup` = the shared keychain access group from the App ID; the vault file lives in the App Group container | **Unavailable.** On-demand start before first unlock cannot open Tier 1 ⇒ `STORE.KEYSTORE_LOCKED`; the OS-level posture from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) holds the fail-closed state |
| **iPadOS** | as iOS | as iOS | as iOS | as iOS; **Shared iPad** (Apple School Manager) gives each user their own data partition ⇒ **one identity per user**, not per device | as iOS |
| **macOS (system extension, Apple silicon / T2)** | Data-protection keychain (`kSecUseDataProtectionKeychain = true`) + Secure Enclave | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | as iOS | Keychain access group via the system extension's entitlement; vault under `/Library/Application Support/TwinVPN/` | Available after the first user unlock; a headless-reboot Mac (no console login) cannot open Tier 1 until then ⇒ `STORE.KEYSTORE_LOCKED` |
| **macOS (`launchd` daemon, Developer ID)** | **System keychain** (`/Library/Keychains/System.keychain`), item ACL created with `SecAccessCreateWithOwnerAndACL` bound to the Team-signed binary | System keychain unlocks at boot — the property a daemon requires | SEK/ANCH as system-keychain generic-password items with the same ACL; SEP-wrapped where available | Root-owned; no sharing — the daemon is the only opener | **Available**: system keychain is unlocked by the system, no user session needed |
| **macOS (pre-T2 Intel)** | File-based keychain item, no SEP | as above | SEK/ANCH file-keychain items | as above | as above |
| **macOS (App Store sandbox)** | Data-protection keychain + NE **app** extension only; no system keychain, no system extension | as iOS | as iOS | App Group container | as iOS |
| **Android** | Android Keystore, EC P-256, `setIsStrongBoxBacked(true)` (API 28+), falling back to TEE, falling back to software keymaster; `setAttestationChallenge(nonce)` | **`setUserAuthenticationRequired(false)`** and **`setUnlockedDeviceRequired(false)`**, with the key and the vault in **credential-encrypted (CE) storage** — see the amendment note below | SEK: Keystore AES-256-GCM key, same `SecurityLevel`, `setRandomizedEncryptionRequired(true)`. ANCH: a Keystore-MAC'd record in CE app storage, co-located with the CE domain that holds the IK | Single app process per user; work profiles and secondary users each get their own CE domain ⇒ **one identity per Android user** | **Unavailable** (CE storage is locked pre-first-unlock). Only a non-secret bootstrap record may live in device-encrypted (DE) storage; always-on VPN at boot fails closed with `STORE.KEYSTORE_LOCKED` until unlock |
| **Windows** | CNG, **Microsoft Platform Crypto Provider** (TPM 2.0), `ECDSA_P256`, `NCRYPT_MACHINE_KEY_FLAG`, `NCRYPT_ALLOW_EXPORT_FLAG` **not** set; `NCRYPT_USE_VIRTUAL_ISOLATION_FLAG` (VBS key isolation) where VBS is on | Machine scope — the service starts before any logon (C-4) | SEK sealed with **DPAPI-NG** `NCryptProtectSecret` to a local descriptor (`SID=S-1-5-18`) whose protector is a TPM-bound key; ANCH stored beside it **and** mirrored to a TPM NV counter (M3, §11.7) | The `LocalSystem` service is the only opener; the UI has no access | **Available**: machine-scope keys need no interactive logon |
| **Windows (no TPM)** | Microsoft Software KSP, machine key container | as above | DPAPI-NG machine descriptor without a TPM protector | as above | Available; `custody_class = SOFTWARE_LOCAL` (§11.4) |
| **Linux (TPM 2.0 present)** | tpm2-tss; key under the SRK with `fixedTPM \| fixedParent`; runtime handle held in the kernel keyring (`logon` key, non-readable) | System scope; no session required | SEK TPM-sealed (**no PCR policy by default** — a firmware or kernel update would otherwise brick the store); or `systemd-creds encrypt` with `LoadCredentialEncrypted=` on systemd ≥ 250. ANCH sealed the same way **and** mirrored to a TPM NV counter | The `twinvpn` service user is the only opener | Available at boot |
| **Linux (no TPM)** | File at mode `0600` in a `0700` directory owned by the service user; SELinux/AppArmor label as defence in depth | System scope | SEK and ANCH in the same protected directory; Argon2id passphrase wrapping is **available but off by default**, because it requires an interactive unlock and would break unattended start | as above | Available at boot; `custody_class = SOFTWARE_LOCAL` |
| **Linux desktop session (informational)** | `gnome-keyring`/KWallet via the Secret Service D-Bus API | Requires a live desktop session | **Not used.** The daemon MUST NOT depend on the Secret Service (C-6) | — | Unavailable headless — the reason it is rejected |
| **OpenWrt / routers / headless / CLI-only** | **None.** No secure element in the general case | n/a | SEK and ANCH are files at `0600` in `/etc/twinvpn/` (mode `0700`), on the JFFS2/UBIFS overlay; `/var` is tmpfs and MUST NOT be used | The `procd` service is the only opener | Available at boot; `custody_class = SOFTWARE_PORTABLE` (§11.4) |

**The CB-6a declaration, per target.** [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)
CB-6a requires the platform key API to perform the record AEAD wherever it can, and requires the
software-held fallback to be *declared* rather than inferred (ST-12d). This table is that
declaration; it is recorded per target in `CoreBuildIdentity` (S-46) and surfaced in the diagnostic
bundle.

| Target | Platform key API performs the record AEAD? | Consequence |
|---|---|---|
| **Android** | **Yes** — Keystore AES-256-GCM with `setRandomizedEncryptionRequired(true)`, at the same `SecurityLevel` as the identity key | `SEK` is never materialized in core memory |
| **Windows (TPM)** | **Yes** — CNG symmetric operations under the Platform Crypto Provider | `SEK` is never materialized |
| **Windows (no TPM)** | No — the software KSP offers no non-exportable symmetric AEAD worth the name | Declared software-held fallback |
| **iOS / iPadOS / macOS** | **No.** The Secure Enclave exposes key *agreement* and signing, not an arbitrary-length AEAD over caller data; `SecKeyCreateEncryptedData` is an asymmetric envelope, not a per-record AEAD at vault write rates | Declared software-held fallback: `SEK` is unwrapped by a SEP key, then held in the locked allocator |
| **Linux (TPM 2.0)** | No — TPM symmetric bulk operations are far too slow for per-record use | Declared software-held fallback; `SEK` is TPM-**sealed** at rest and unwrapped once per process |
| **Linux (no TPM)**, **OpenWrt / routers / headless / CLI-only** | No — there is no key API at all | Declared software-held fallback. On `SOFTWARE_PORTABLE` this is moot anyway: the key sits beside the file (ST-20) |

The honest reading of this table is that the mandatory-platform-AEAD path exists on **two** of the
ten targets. That is not a reason to weaken CB-6a — it is the reason CB-6a demands the fallback be
declared, because the fallback is the common case and an undeclared common case reads as an
exception.

**Rule ST-5 (iOS/iPadOS accessibility, stated as a functional requirement).**
`kSecAttrAccessibleWhenUnlocked` MUST NOT be used for IK, SEK, or ANCH. The
`NEPacketTunnelProvider` must sign, rekey, and re-derive `psk2` while the screen is locked; a
`WhenUnlocked` item makes every rekey after a screen lock fail, which surfaces as a random
disconnect and is the exact defect class **R-05** exists to prevent.
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` is chosen because it is the weakest class that
permits background use while locked, and `…ThisDeviceOnly` is what excludes the item from iCloud
Keychain and from any backup restorable to different hardware — which is where **I4** is actually
enforced on Apple platforms.

**Rule ST-6 (file protection class).** The vault file in the App Group container MUST be created
with `NSFileProtectionCompleteUntilFirstUserAuthentication`. `NSFileProtectionComplete` MUST NOT be
used: it makes the vault unreadable while the device is locked, which breaks the extension for the
same reason ST-5 does.

**Rule ST-7 (Android availability semantics — an amendment obligation on
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3).** §7.3's Android row specifies
`setUnlockedDeviceRequired(true)`. That flag makes the key usable **only while the device is
currently unlocked**, which is strictly stronger than the iOS choice in the same table and produces
the failure ST-5 forbids: a phone whose screen locks during an active session cannot rekey. The
Android equivalent of `AfterFirstUnlock` is *credential-encrypted storage with no user-auth
binding*: `setUserAuthenticationRequired(false)`, `setUnlockedDeviceRequired(false)`, key and vault
in the CE domain, and the app **not** Direct-Boot-aware for anything secret. This ADR adopts that,
and records the amendment to §7.3's Android row as an obligation in §11.14 rather than editing it.

**Rule ST-8 (attestation is a Tier-1 output, not a Tier-2 record).** The platform attestation blob
(`SecKeyCreateAttestation`, Android Key Attestation chain, `TPM2_Certify` under an AK) is produced
by Tier 1 at enrolment, consumed by the approving OSK device
([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6), and stored in the vault only as the
*verified outcome* in S-54. A stored blob is not evidence of anything at a later date and MUST NOT
be re-presented as though it were.

### 11.4 Custody classes and honest declaration

**Rule ST-9.** Every `Device` computes a `custody_class` at each start, from a live probe of the
Tier-1 backend — never from a stored claim.

**Rule ST-9a — two probes, one class, and the minimum wins.** There are two Tier-1 assets with
potentially different backings: the **identity private half** (S-01; component 2.6 is its custodian
under [docs/architecture.md](../architecture.md) §2.6) and the **vault key set** (`SEK`, `K_bind`,
and the anchor; component 2.20's own). They can genuinely differ — a macOS Developer ID daemon may
hold a SEP-backed IK while its `SEK` is a System-keychain item. S-54 records **both** probe results,
and `custody_class` is the **minimum** of the two under the §11.4 ordering, so the advertised class
can never overstate either. On every `SOFTWARE_PORTABLE` target both are files and the value is
unchanged.

**Rule ST-9b — 2.20 observes and records; 2.6 remains the custodian.** The probe asks each backend
*what it is* and never reads key material, so recording the answer does not make 2.20 a second
writer of S-01. This is the CB-5 shape applied to metadata: the core asks the shell a question about
a capability it can never hold. `custody_class` therefore has exactly **one** writer (2.20, S-54),
which is what [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-28 relies on when it
consumes S-54 and declares no second copy, and what
[ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `hardware_backed` claim is computed from.

**Rule ST-9c — the two directions are not symmetric, and the *upward* one is the security-relevant
one.** A change in `custody_class` is accepted differently depending on which way it moves:

| Direction | Local acceptance | Effect on any peer's trust |
|---|---|---|
| **Downward** (e.g. `HARDWARE_ATTESTED` → `SOFTWARE_LOCAL`) | **Always accepted**, unconditionally, with no attestation required. A device claiming *worse* custody than it has harms nobody, so the claim is self-authenticating in the useful direction | Peers MUST act on it: `AUTH.HARDWARE_BACKING_LOST`, and IK rotation is forced ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-24) |
| **Upward** (e.g. `SOFTWARE_PORTABLE` → `HARDWARE_ATTESTED`) | Recorded locally as the probe result, because the probe is the writer | **MUST NOT raise any peer's trust without a verified platform attestation** ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6). An unattested upgrade is an unverifiable self-report; it is displayed to the `Owner` as *claimed*, never as *established*, and no policy gate — including an `AUTH.ATTESTATION_REQUIRED` requirement — may be satisfied by it |

This asymmetry is why one writer is sufficient. The dangerous direction requires evidence the
device cannot manufacture, and the safe direction requires none; a fact whose only unverifiable
movement is harmless does not need a second authority to check it. It is also the property
[docs/testing-strategy.md](../testing-strategy.md) **G-5** needs in order to assert that a *false*
flag is impossible: with one writer, one conflict rule, and a stated direction, "the flag
overstates custody" reduces to "an upward transition was accepted without attestation", which is a
single mechanically checkable condition rather than a judgement.

| `custody_class` | Meaning | `hardware_backed` | Clone resistance | Typical targets |
|---|---|---|---|---|
| `HARDWARE_ATTESTED` | Key generated in a secure element, non-exportable, and the platform produced an attestation the approving OSK device verified | `true`, attested | A disk image does not clone the key | iOS/iPadOS, Apple silicon macOS, Android StrongBox/TEE, Windows with TPM 2.0, Linux with TPM 2.0 |
| `HARDWARE_UNATTESTED` | Key in a secure element, non-exportable, but no attestation was obtainable or its format was unrecognised | `true`, **unattested** — a peer MUST NOT treat it as evidence ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6) | As above in fact, unproven to peers | Some Android OEM builds, VBS-only Windows |
| `SOFTWARE_LOCAL` | No secure element. Key encrypted at rest under a machine- or account-bound OS facility (DPAPI-NG machine descriptor, file-keychain, `0600` file) that does not transfer to other hardware without effort | `false` | A disk image **does** clone the key | Pre-T2 Intel macOS, Windows/Linux without TPM |
| `SOFTWARE_PORTABLE` | No secure element and no host binding: the key is a file that works wherever it is copied | `false` | **None** | OpenWrt, routers, headless boxes, CLI-only installs, containers |

**Rule ST-10 (the declaration path).** `custody_class` is recorded in S-54, is the input from which
[ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `DeviceCertificate` `hardware_backed` claim is
computed, is advertised as a `Capability` (S-19) so peers and the `Owner` UI can see it, and is
rendered by [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) wherever a device is listed. A `TwinNet` policy MAY require
`HARDWARE_ATTESTED` for enrolment, in which case a non-conforming device is refused with
`AUTH.ATTESTATION_REQUIRED` — that code is [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s and
is not duplicated here.

**Rule ST-11 (degradation is a named event, and only a *transition* is one).** If the probe returns
a class lower than the one recorded in S-54, the device MUST emit `STORE.CUSTODY_DEGRADED`, MUST
force IK rotation and re-attestation per
[ADR-0007](ADR-0007-device-identity-and-pairing.md) N-24, and peers surface
`AUTH.HARDWARE_BACKING_LOST`. A device MUST NOT quietly continue presenting the higher class.

`STORE.CUSTODY_DEGRADED` names a **transition only**, and MUST NOT be emitted by a device that has
always been `SOFTWARE_PORTABLE` — that is a permanent, disclosed steady state, not a degradation
event, and it is reported as `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE`, which
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns. This ADR adopts that ADR's EM-29a
split verbatim; implementing the steady state as a boot-time degradation warning is a defect.

**Rule ST-11a — this ADR restricts no role by custody class.** A `SOFTWARE_PORTABLE` device MAY act
as `LANGateway` or `ExitNode`; refusing would abandon **R-21** and the home-lab persona.
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-30 owns the disclosure obligation and
EM-31 owns the one hard prohibition (no `ENROLL`/`REVOKE`/`DELEGATE` `OwnerSigningKey` on
`SOFTWARE_PORTABLE` or `SOFTWARE_LOCAL`). ST-1 places the OSK in Tier 1 without asserting that any
given device may hold one, so there is no contradiction to resolve.

**The residual, for `SOFTWARE_PORTABLE` — stated as `docs/vision.md` §4.1 requires.**
On a router, a headless gateway, a CLI-only install, or any container image, **I4 is not upheld.**
The private half is a file. Anyone who can read the filesystem — by pulling the flash, by mounting
the image, by taking a `sysupgrade` config backup, or by copying a container volume — obtains a
fully working identity, and the clone is cryptographically indistinguishable from the original.
The store's encryption does not help, because the key that decrypts it sits beside it. What
remains is: (a) the `Owner`'s ability to revoke, whose propagation and residual window are
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7's; (b) the epoch-seed exclusion, which
denies the clone `psk2` at the new epoch **without** depending on the clone's own store; and (c)
detection — concurrent use of one `device_id` from distinct networks raises
`AUTH.IDENTITY_CONCURRENT_USE`. That is detection and containment, not prevention, and it is the
honest cost of supporting router-class hardware.

### 11.5 Tier 2 — the vault: engine, layout, records, schema

**Rule ST-12 (engine property contract).** The vault engine MUST satisfy all of:

| # | Property |
|---|---|
| E1 | One file plus at most one lock sidecar. No server process, no background thread required for correctness. |
| E2 | Atomic, crash-consistent commit of a **multi-key** transaction. A torn or interrupted write MUST leave the previous committed state fully readable. Copy-on-write is the preferred realization; a WAL with a durable commit record is acceptable only if E1 still holds. |
| E3 | **Single writer and single opener.** Multi-process concurrency is not required and MUST NOT be relied upon (§11.9). |
| E4 | Page or record checksums, so silent corruption is *detected* rather than returned as data. |
| E5 | Configurable read-cache ceiling, honouring §9; MUST operate without mapping the whole file, for 32-bit targets. |
| E6 | Builds for every target in [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s matrix, including musl and 32-bit mips/mipsel/armv7, with no C dependency the core does not already carry. |
| E7 | Explicit, versioned, deterministic on-disk format with the version in the file header. |
| E8 | An explicit durability barrier on commit (`fsync` / `fcntl(F_FULLFSYNC)` on Apple / `FlushFileBuffers`), and correctness that does not depend on the barrier being honest — copy-on-write ordering must still yield a valid older state if the device lies. |

**The Phase 2 default is a pure-Rust, single-file, copy-on-write B-tree store (`redb`-class) inside
the H1 core**, now confirmed by [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s
adoption of a Rust core. SQLite is rejected as the default for the reasons in §6/V2 and §12; **LMDB**
remains the named substitute for a future non-Rust embedder, with E5 waived only on 64-bit targets
(LMDB maps the whole file, which is unacceptable on `GC-0`).

**Rule ST-12a — the vtable split, discharging [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) B-03.**
An earlier revision of B-03 assigned this ADR the realization of `Store` and `SecureStorage`
"behind the §11.4 vtable entries". Those obligations are accepted, but they do **not** all sit on
the same side of the ABI. [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) has since
corrected B-03 and renamed the entries to `secure_item_read` / `secure_item_write_atomic`, which
states their true scope. The split below is **confirmed by both ADRs**, and it derives from that
ADR's CB-1/CB-7 line rather than from a rough "logic versus I/O" cut:

| Concern | Side | Why |
|---|---|---|
| Transaction engine: write-ahead ordering, crash recovery, monotone rejection (ST-23), migration (ST-15), **multi-key commit**, record envelopes, per-record AEAD, namespaces, the recovery ladder (§11.11) | **Core** | All decision, so CB-1/CB-2 place it in the core. Ten shells implementing crash-consistent multi-key transactions is alternative V3 and R-31's defect class |
| Tier-2 vault file I/O (`vault.tv` and its sidecars) | **Core**, beneath a shell-vended `store_root` | `open`/`read`/`write`/`fsync`/`rename` have a stable C-callable form on all ten targets, so CB-1 *requires* this to be core-side. Not a concession extracted from ADR-0018 — its own rule produces it |
| Vending `store_root`, the file-protection class (ST-6), the backup-exclusion attributes (ST-26) | **Shell** | These genuinely have no stable C form: on iOS the app-group container URL, the protection class and the exclusion flag are Objective-C |
| Tier 1: `SEK`, `K_bind`, and the `StoreAntiRollbackAnchor` (S-53) | **Shell**, via `secure_item_read` / `secure_item_write_atomic` | Small, whole-blob, atomically-replaced items — the shape Keychain, Keystore, DPAPI and libsecret actually have. ST-23 steps 3 and 6 are one `secure_item_write_atomic` each |
| The identity private half (S-01) | **Shell only**, via `identity_sign` / `identity_public` / `identity_attestation` | **CB-5, untouched.** The core never receives IK bytes and has no API that could return them |

**Rule ST-12b — why a per-key atomic write is not a vault.** E2 requires an atomic **multi-key**
transaction: "this `TrustedPeer` **and** this advanced `trust_epoch` floor commit together". A
per-key `secure_item_write_atomic(key, val)` is individually atomic and cannot express that, and
composing several reintroduces the manifest problem that lost V4 (§12). The failure is a
**correctness** bug, not a performance one: if the `TrustedPeer` record commits and the floor
advance does not, the device admits a peer under an epoch its floor does not reflect; reversed, it
refuses a peer it should accept. Both break the anti-rollback machinery of
[ADR-0009](ADR-0009-state-consistency.md) and
[ADR-0007](ADR-0007-device-identity-and-pairing.md). The `secure_item_*` entries therefore realize
**Tier 1**, whose writes genuinely are single small blobs, and the vault is core-side.

**Rule ST-12c — `SEK` in core memory is not a second CB-5 inversion, because CB-5's boundary is the
*authentication path*, not "secrets".** [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)
CB-5 now states the test directly, and this ADR adopts it:

| Key kind | Core-held? | Consequence of a core-memory read |
|---|---|---|
| **Authentication path** — `DeviceIdentityKey`, `OwnerSigningKey`, `OwnerRootKey` | **Never.** Operations are vtable calls | The attacker can *act as* this `Device`, and the compromise **outlives the device** rather than ending at revocation (**I4**, TM-14) |
| **Data at rest** — `SEK`, and the L-DATA static of [ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)'s L-STORE decision | **Yes**, in the locked, non-swappable, non-dumpable allocator, residual stated | Yields vault plaintext an attacker at that privilege largely reaches anyway. Confers **no** ability to authenticate as this `Device` |

This is not a new exception. The corpus already holds a strictly *more* sensitive secret in core
memory by the same mechanism — the `TunnelStaticKey`, hardware-wrapped and unsealed into locked,
non-dumpable memory per [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5, with the residual
stated at [docs/threat-model.md](../threat-model.md) §12. TK compromise lets an attacker decrypt
tunnel traffic and impersonate the tunnel endpoint; `SEK` compromise yields local vault plaintext
only. ST-12c is therefore the same grant already made, applied to a lesser secret.

**Rule ST-12d — the platform AEAD is mandatory where it exists, and the core-held key is a
*declared* fallback ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) CB-6a).** Where the
platform key API can perform the record AEAD itself, it **MUST**, and `SEK` is never materialized
(ST-18). The core-held path is only what a target lacking that capability falls back to; that
fallback **MUST** be recorded per target in `CoreBuildIdentity` (S-46) and **MUST** be surfaced in
the diagnostic bundle, so "this device's vault key was software-held" is a readable fact rather
than an inference. Extending this rule to any authentication-path key requires a new ADR under
**I4**, not a review comment. §11.3 carries the per-target answer.

**Rule ST-12e — `store_root` is vended at construction, never discovered.** The core MUST receive
`store_root` as an injected value whose platform attributes are **already applied**, and MUST NOT
derive, probe for, or fall back to a path of its own choosing: a self-discovered path is ambient
state and breaches [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) CD-2. Beyond
testability, this is what makes the embedded tier correct — a `GC-0` router has a read-only
squashfs root with a writable overlay, and only the shell's `procd`/UCI integration knows the
overlay path (§11.9). A core that discovered its own path would get this wrong on precisely the
tier with the least margin for error.

**File set.**

```
<store_root>/
  vault.tv                 # the transactional vault (Tier 2)
  vault.lock               # advisory exclusive lock + owner record
  ring.tvr                 # pre-allocated diagnostic ring (S-22), non-transactional
  resolver.restore         # S-34, plain + integrity tag, boot-readable (RQ-11)
  health.json              # S-55, plain, writable when the vault is not
  vault.v<N>.bak           # pre-migration copy, retained one release (space permitting)
  vault.corrupt.<ts>       # quarantined vault (§11.11 L3)
```

**Record envelope.** Keys are `namespace/key` byte strings. Values are:

```
RecordEnvelope {
  1 rec_schema : uint          # per-namespace record schema version
  2 rec_seq    : uint          # per-record monotone counter
  3 flags      : uint          # VERBATIM_SIGNED | DERIVED | SECRET_BEARING
  4 nonce      : bstr(24)
  5 ct         : bstr          # XChaCha20-Poly1305(K_ns, nonce, plaintext, aad)
}
aad = store_id || namespace || key || rec_schema || rec_seq
```

**Rule ST-13.** A record whose `flags` carry `VERBATIM_SIGNED` stores the **received octets
unchanged** (RQ-7). The vault MUST NOT decode-and-re-encode a signed statement, and signature
verification happens at the writer before commit, never at read time from a re-serialized form.

**Rule ST-14 (namespaces).**
`identity/ peer/ trust/ doc/ session/ net/ policy/ consent/ pref/ cap/ store/`. Each namespace
declares its `rec_schema` and its secrecy class in a compiled-in table. Writing a key outside the
declared namespaces is `INTERNAL.INVARIANT_VIOLATED`.

**Rule ST-14a — `consent/` and `pref/` are separable by construction (discharging
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) X4).** `RouteConsentRecord`
(S-50) is an **authorization decision**; UI presentation preferences (S-51) are **cosmetic**. They
occupy different namespaces, and every bulk operation the management interface exposes is
**namespace-scoped**: a "reset UI settings" action addresses `pref/` and has no representation
capable of naming `consent/`. There is no wildcard clear, no "reset all local state" verb, and no
key pattern that spans both — an operation that could clear a consent record as a side effect of a
cosmetic reset is a schema violation, mechanically checkable in CI.

**Rule ST-14b — `consent/` has no non-local writer and no replication path.** S-50 records are
written only from an authenticated local `Owner` action arriving over
[ADR-0017](ADR-0017-local-management-interface.md), are never included in any document the control
plane can author or distribute, are never transmitted, and are excluded from OS backup with the
rest of the vault (ST-26). This is the mechanism behind
[docs/threat-model.md](../threat-model.md) §7's requirement that a remote writer cannot grant a
route to itself: there is no ingress path — no wire message type, no document type, and no
namespace binding — by which a non-local actor can produce a `consent/` record. Absence of a
consent record is the safe state, and is never inferred from policy.

**Rule ST-15 (schema versioning and migration).**

1. The vault header carries `schema_version` (whole-store) and each record carries `rec_schema`.
2. Opening a vault with `schema_version > MAX_SUPPORTED` MUST refuse with `STORE.SCHEMA_TOO_NEW`.
   It MUST NOT delete, reset, downgrade, or "repair" the store. This is what makes an [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)
   rollback non-destructive.
3. `MIN_SUPPORTED = MAX_SUPPORTED − 2`. A vault below `MIN_SUPPORTED` migrates through the chain;
   each step is a single transaction; a pre-migration copy is retained for one release.
4. Unknown namespaces, unknown keys, and unknown record fields MUST be **preserved verbatim**
   across migration, so downgrade-then-upgrade does not lose data — the local mirror of
   [ADR-0003](ADR-0003-network-contract-schema-format.md)'s unknown-field preservation rule.
5. A migration MUST NOT advance a monotone floor and MUST NOT be capable of lowering one. Floors
   are read from Tier 1 after migration and re-asserted.
6. A failed migration leaves the pre-migration store in place and emits `STORE.MIGRATION_FAILED`.

### 11.6 Encryption at rest and the store key hierarchy

```
Tier 1:  SEK  (256-bit, non-exportable or platform-wrapped; §11.3 per target)
           |
           +-- K_ns   = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/ns/v1" || namespace)
           +-- K_ring = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/ring/v1")
           +-- K_bind = HKDF-SHA-256(SEK, salt = store_id, info = "TwinVPN/store/bind/v1")
```

- **ST-16.** AEAD is XChaCha20-Poly1305 with a random 192-bit nonce per write, chosen because
  random nonces are safe at this size without a counter that a rollback could reuse. AES-256-GCM
  is permitted where the platform provides a hardware AEAD and the nonce is drawn from a
  Tier-1-backed counter; a random 96-bit GCM nonce MUST NOT be used.
- **ST-17.** Per-**record** AEAD, not whole-file encryption. This yields per-record integrity, binds
  every record to its namespace, key, and `rec_seq` through the AAD, and means a corrupt page
  damages the records on it rather than the file.
- **ST-18.** Where the platform key API can perform the AEAD itself without exposing SEK
  (Android Keystore AES-GCM, Windows CNG under the PCP), it **MUST** be used and SEK is never
  materialized — this is [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) CB-6a's
  "where the platform can, it must", not a preference. Where it cannot, SEK is unwrapped into
  `mlock`ed, `MADV_DONTDUMP` memory with core dumps disabled (`prctl(PR_SET_DUMPABLE, 0)`;
  `VirtualLock` + `CryptProtectMemory` on Windows), matching
  [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5's treatment of TK — and that fallback is
  **declared**, per target, in `CoreBuildIdentity` (S-46) and in the diagnostic bundle (ST-12d).
- **ST-19.** SEK rotation is supported and is a full re-encryption of the vault in one transaction;
  it is triggered by custody-class change (ST-11) and by `Owner` action, and it does **not** change
  `store_id`.
- **ST-20 — what the encryption is worth, per custody class.** `HARDWARE_*`: copying the vault
  yields ciphertext with no key. `SOFTWARE_LOCAL`: the key is machine-bound, so copying the vault
  to different hardware yields ciphertext with no key, but a local attacker with the OS account has
  both. `SOFTWARE_PORTABLE`: the key is next to the file and encryption buys **nothing** against
  anyone who can read the filesystem. It is still applied, because it costs nothing and it protects
  against the accidental case (a backup archive read by a tool that does not carry the key file).

### 11.7 Anti-rollback: the anchor, commit ordering, and what is actually stopped

**The floor set** — the facts that must never decrease: `trust_epoch` / `min_acceptable_epoch` and
`anchor_version` ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-26, §7.7); per-peer
`generation` and `tk_generation` (N-22); `doc_version` high-water per `doc_type`
([ADR-0009](ADR-0009-state-consistency.md) R-5, R-7); `contract_seq`
([ADR-0003](ADR-0003-network-contract-schema-format.md) NC-3); the S-37 negotiation-floor digest
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)); and `store_seq`, this
ADR's own vault commit counter.

**Rule ST-21 (the anchor).** `StoreAntiRollbackAnchor` (S-53) is a Tier-1 item of ≤ 512 bytes:

```
StoreAntiRollbackAnchor {
  1 store_id     : bstr(16)
  2 store_seq    : uint          # strictly increasing vault commit counter
  3 vault_digest : bstr(32)      # digest of the committed vault root at store_seq
  4 floors       : { floor_id -> uint }   # the table above
  5 floor_digest : bstr(32)      # over floors, for cheap equality checks
}
```

**Rule ST-22 (co-location — the load-bearing rule).** ANCH MUST be stored in the **same Tier-1
backend, under the same custody class and the same accessibility class, as the
`DeviceIdentityKey`.** This converts "delete or roll back the anchor" into "delete or roll back the
identity", whose consequence is already specified and safe: `AUTH.IDENTITY_MISSING` ⇒ re-enrolment
([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3, N-7). Without ST-22, an attacker could
strip the anchor and keep a working identity, which is strictly the best case for them.

**Rule ST-23 (commit ordering — the realization of [ADR-0009](ADR-0009-state-consistency.md) R-9).**
A commit that advances any floor MUST proceed:

```
1. verify the document (signature over received octets, ADR-0003)
2. compute new floor set;  if any floor would decrease -> REFUSE (AUTH.TRUST_EPOCH_ROLLBACK
                                                                 or CONTROL.CONSISTENCY.VERSION_ROLLBACK_REJECTED)
3. write ANCH with floors' = new floors, store_seq' = store_seq + 1   [Tier 1, durable]
4. where a hardware counter exists AND a trust floor advanced: TPM2_NV_Increment  [M3]
5. commit the vault transaction, recording store_seq' and the new records          [Tier 2]
6. write ANCH again with vault_digest' = digest(new vault root)                    [Tier 1]
```

A crash between 3 and 5 leaves `anchor.store_seq > vault.store_seq`, which is indistinguishable
from a rollback and is treated as one: the floors from the anchor win, the affected documents are
re-pulled, and `STORE.ROLLBACK_DETECTED` is emitted at `WARN` with the crash-recovery evidence
field set. **Erring toward "rollback" on an ambiguous crash is the correct direction**, because the
cost is a re-pull and the alternative cost is a resurrected revocation.

**Rule ST-24 (open-time classification).**

| Observation | Classification | Action |
|---|---|---|
| `anchor.store_seq == vault.store_seq`, digests match | healthy | proceed |
| `anchor.store_seq > vault.store_seq` | **vault rolled back or crash-truncated** | floors := anchor floors; quarantine nothing; re-pull every document below its floor; `STORE.ROLLBACK_DETECTED`; suspend granted authority until a document at ≥ floor verifies |
| `anchor.store_seq == vault.store_seq`, digests differ | **tamper or fork** | `STORE.ANCHOR_MISMATCH` (FATAL); vault quarantined; identity-only bootstrap (L3) |
| `anchor.store_seq < vault.store_seq` | anchor lost an update (Tier-1 rollback, or a platform re-provisioning) | floors := `max(anchor, vault)`; re-write anchor; `STORE.ANCHOR_MISMATCH` at `WARN` |
| ANCH absent, IK present | anchor lost independently — possible on a platform that re-provisions secure storage | `STORE.ANCHOR_MISSING`; floors treated as **unverified**: every *granted* authority is suspended (the `trust_state_expired` guard input of [ADR-0009](ADR-0009-state-consistency.md) §11.4) until a fresh signed document at ≥ the vault's stored floors verifies; anchor rebuilt from the verified result |
| ANCH absent **and** IK absent | restored image / re-provisioned device | `AUTH.IDENTITY_MISSING` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)'s code) ⇒ re-enrolment. **This is the ST-22 payoff.** |
| Vault absent, ANCH present | reinstall that preserved secure storage | fresh vault seeded from ANCH's floors; re-pull everything; no code — this is the normal reinstall path (§11.8) |

**Rule ST-25 (hardware counter cadence).** Where a TPM NV counter is used, it is incremented **only
when a trust floor advances** (`trust_epoch`, `anchor_version`, `min_acceptable_epoch`, or a
`doc_version` high-water for `TRUST_LIST` / `MEMBERSHIP` / `POLICY_BUNDLE`). Expected rate is units
per year. It MUST NOT be incremented per commit (C-12: NV endurance and latency).

**What is stopped, and what is only detected — stated honestly.**

| Attack | `HARDWARE_ATTESTED` / `HARDWARE_UNATTESTED` | `SOFTWARE_LOCAL` | `SOFTWARE_PORTABLE` |
|---|---|---|---|
| Feed an older signed document through the API | **Stopped** (M1 + floors) | **Stopped** | **Stopped** |
| Restore the vault file alone from an older backup | **Stopped** (ST-24 row 2) | **Stopped** | **Stopped** |
| Restore the vault **and** delete Tier 1 | **Stopped** — becomes `AUTH.IDENTITY_MISSING` ⇒ re-enrolment (ST-22) | Stopped | Stopped |
| Restore the vault **and** the Tier-1 items together (whole app-data or whole-machine restore) | **Detected** where a hardware counter exists (M3); **not detected** otherwise | **Not detected** | **Not detected** |
| Whole-device-image rollback on real hardware with a TPM | **Stopped** (NV counter is not in the image) | n/a | n/a |
| Whole-VM rollback including a vTPM snapshot | **Not detected** | **Not detected** | **Not detected** |
| Copy the whole install to a second machine and run both | Stopped (key does not clone) | Detected only (`AUTH.IDENTITY_CONCURRENT_USE`) | **Detected only** |

Where the row says *not detected*, the defence is not local and does not pretend to be: it is the
peer-side floors held by **other** devices (S-37, `min_acceptable_epoch`) and the `EpochSeed`
exclusion of [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, which denies the rolled-back
device `psk2` at the current epoch regardless of what its own store says. A rolled-back device
therefore reverts to a *lagging* device, not to an authoritative one.

### 11.8 Backup, restore, migration, reinstall, uninstall

**Rule ST-26.** The vault, its sidecars, and every Tier-1 item MUST be excluded from OS backup and
from device-to-device transfer, on every platform where an exclusion mechanism exists. Exclusion is
**re-verified at every start**; a failure is `STORE.BACKUP_EXCLUSION_FAILED`, not a silent success.

| Platform | Backed up by default? | Exclusion mechanism (MUST) | Restore onto **new** hardware | Restore onto the **same** hardware |
|---|---|---|---|---|
| iOS / iPadOS | Yes — App Group container files go to iCloud and to encrypted local backups | `URLResourceValues.isExcludedFromBackup = true` on `vault.tv`, `ring.tvr`, sidecars. Keychain items: `kSecAttrSynchronizable = false` + `…ThisDeviceOnly` | Keychain `…ThisDeviceOnly` items are not restorable to different hardware, and an SEP-referenced key blob is meaningless to a different SEP ⇒ identity absent ⇒ `AUTH.IDENTITY_MISSING` ⇒ re-enrolment | Identity returns (same SEP); vault was excluded, so it is rebuilt from ANCH and re-pulled. **Correct**: same device, same custody |
| Android | Yes — Auto Backup and device-to-device transfer | `android:allowBackup="false"`, or `dataExtractionRules` excluding the store path in **both** `<cloud-backup>` and `<device-transfer>` (API 31+) and `fullBackupContent` below that | Keystore keys never leave the device ⇒ identity absent ⇒ `AUTH.IDENTITY_MISSING` ⇒ re-enrolment | Keystore keys are not restored by backup either; a factory reset destroys them ⇒ re-enrolment. Stated plainly in the UI |
| macOS | Yes — Time Machine covers `/Library/Application Support/` | `NSURLIsExcludedFromBackupKey` on the store root **and** a `tmutil addexclusion` registered by the installer ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) | Keychain items with the daemon's ACL and SEP-backed keys do not transfer ⇒ re-enrolment | Identity returns; vault rebuilt |
| Windows | No — `%ProgramData%` is outside File History and Known Folder Move scope | None required for File History; the installer MUST still place the store under `%ProgramData%\TwinVPN\` and MUST NOT place it in a user profile. Volume Shadow Copy and full-image backups **do** capture it — see §11.7's honesty table | TPM-bound keys do not restore to different hardware ⇒ re-enrolment. With the software KSP the key **does** restore ⇒ a clone, and the class is `SOFTWARE_LOCAL` (declared) | Whole-image restore returns both vault and keys ⇒ a rollback the NV counter detects on TPM machines and nothing detects otherwise |
| Linux | No OS-level backup; third-party tools commonly cover `/var/lib` | Ship a `/etc/twinvpn/backup-exclude` hint and document it; TPM-sealing SEK is the real mitigation, because a restore onto other hardware yields an unopenable vault | TPM-sealed ⇒ unopenable ⇒ `STORE.KEY_INVALIDATED` ⇒ re-enrolment. Without a TPM ⇒ a clone (`SOFTWARE_LOCAL`) | Restores cleanly |
| OpenWrt / routers / headless | `sysupgrade` keeps the configured file set; `sysupgrade -b` produces a user-held archive | The store is registered in `/lib/upgrade/keep.d/twinvpn` so an upgrade **preserves** it ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)'s requirement). OpenWrt cannot express "keep on upgrade but exclude from backup" | A config archive restored to another router **is a working clone**. Declared residual (§11.4); the CLI MUST warn at backup time and the class is `SOFTWARE_PORTABLE` | Restores cleanly |

**Rule ST-26a — on OpenWrt, preservation is verified at every start, because getting it wrong
de-enrols a fleet silently.** `/etc/config` survives `sysupgrade` by default; **every other `/etc`
path survives only if it is listed in `/lib/upgrade/keep.d/`**. The store is deliberately *not* in
`/etc/config` (ST-30 forbids the UCI tree, and
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) requires it), so an absent or incorrect
keep-list entry means the next firmware upgrade destroys the identity and the trust set of every
device it is pushed to — with no error at the time, and no signal until each device fails to
re-establish. That is the worst failure shape in this ADR: silent, deferred, and fleet-wide.

The daemon therefore MUST, at every start on an OpenWrt-class target, verify that
`/lib/upgrade/keep.d/twinvpn` exists and names every path in the §11.5 file set plus the Tier-1
key files. If it does not, the device MUST emit `STORE.PRESERVE_RULE_MISSING` and surface it as a
persistent, unmissable condition — **before** an upgrade is attempted, which is the only moment at
which the operator can still act. This is a check, not a repair: the daemon MUST NOT write the
keep-list itself, because that file is package-owned and silently recreating it would mask a
broken package rather than fix it ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)
obligation (f)).

**Rule ST-27 (reinstall must not destroy the store).** An in-place update or reinstall MUST leave
`vault.tv` and Tier 1 intact. Where the platform destroys app data on uninstall (iOS, Android,
macOS App Store), uninstall-then-install is *not* a reinstall and lands on re-enrolment. [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)
owns the packaging obligation; §11.14 states the interface.

**Rule ST-28 (the device MUST NOT silently mint a replacement identity).** This is
[docs/architecture.md](../architecture.md) §2.6's rule and
[ADR-0007](ADR-0007-device-identity-and-pairing.md) N-7's. Its realization here: the only code path
that creates an identity is the enrolment flow, which requires an `Owner` approval from an OSK
device. There is no path from "open the store" to "generate a key" — the store-open code has no
key-generation capability in scope. This is a structural property of the module boundary, not a
guard.

**Rule ST-29 (host binding and the restored-image detector).** `StoreBindingToken` (S-56) is
`HMAC(K_bind, host_id)`, where `host_id` is the platform host identifier
(`IOPlatformUUID` on macOS, the TPM EK public digest or `/etc/machine-id` on Linux, `MachineGuid`
plus the TPM EK digest on Windows, the per-app-per-user Android secure identifier, the board serial
on OpenWrt) and `K_bind` is Tier-1-derived. A mismatch at open means the vault arrived from
elsewhere: emit `STORE.RESTORED_FOREIGN_HOST`, quarantine the vault, and require re-enrolment. On
iOS/iPadOS no host identifier is needed — a restored vault without a usable SEP key already fails.

### 11.9 On-disk location, account scoping, permissions, and the single-opener rule

| Target | `store_root` | Ownership / permissions | Who may open |
|---|---|---|---|
| iOS / iPadOS | App Group container (`containerURL(forSecurityApplicationGroupIdentifier:)`) | App sandbox; file protection per ST-6 | **The `NEPacketTunnelProvider` only.** The app process is a courier (below) |
| macOS (system extension / daemon) | `/Library/Application Support/TwinVPN/` | `root:wheel`, `0700` | The system extension / `launchd` daemon only |
| macOS (App Store) | App Group container | App sandbox | The NE app extension only |
| Android | CE app storage (`Context.createCredentialProtectedStorageContext()` is **not** used; the default CE context is) | App UID, `0700` | The `VpnService` process only |
| Windows | `%ProgramData%\TwinVPN\store\` | `SYSTEM:F`, `Administrators:F`, **`Users` denied**; inheritance disabled | The `LocalSystem` service only |
| Linux | `/var/lib/twinvpn/` | `twinvpn:twinvpn`, `0700` | The `systemd` service only |
| OpenWrt / routers / headless | `/etc/twinvpn/` (**never `/var`** — tmpfs) | `root:root`, `0700` | The `procd` service only |

**Rule ST-30 (single opener).** Exactly **one** process opens the vault, for read or for write: the
privileged daemon/extension of H2. The UI, the CLI, and any local automation MUST NOT open the
store file and MUST NOT be granted a path to it; they read and write through [ADR-0017](ADR-0017-local-management-interface.md)'s management
interface. Enforcement is an advisory exclusive lock (`flock` / `LockFileEx`) plus an owner record
(`pid`, boot id, process start time) in `vault.lock`; a second opener refuses with
`STORE.LOCK_CONTENDED` and MUST NOT fall back to read-only sharing.

**Rule ST-31 (the iOS courier rule).**

> **AMENDED — ST-31a. The courier runs the other way, and the writer this rule protects is not the
> provider.** The original text is preserved below because its *principle* is untouched and only
> its two role assignments were wrong. Amended by the wave-3 integration lead after `mobile-ios`
> reported that this rule, [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)
> LC-17 and [docs/networking.md](../networking.md) §5.4 place fetch in two different processes and
> verification in two different processes — three documents, three answers
> (`ownership.md` §10.8 **M-7**).
>
> **Two corrections, and neither weakens I8:**
>
> 1. **The app cannot fetch.** [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)
>    **PS-24 condition 3**: under `includeAllNetworks` the app process has **no network** — its
>    traffic is [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) class 1/2 and dropped, and
>    it cannot match the class-7 bootstrap exemption because KS-9(1)'s predicate names the
>    **provider**. An app-process fetch therefore fails in exactly the state where the contract is
>    most needed, and fails *silently from the extension's point of view*. **The extension fetches**
>    — it is the process that holds the exempted socket — and hands the verbatim signed octets to
>    the app over [ADR-0017](ADR-0017-local-management-interface.md). The courier direction is
>    reversed; the courier concept is not.
>
> 2. **"Verification happens at the writer" was applied to the wrong artifact.** This rule read
>    *provider* for *writer*. But LC-17's division makes the **app** the sole writer of the compiled
>    contract generation, and the **provider** the sole writer of the session state
>    (S-12, S-15, S-31, S-37, S-62). Those are two different stores with two different writers.
>    Signature verification and floor enforcement belong at the writer **of the document being
>    committed**, which for a signed contract is the app. So the principle holds exactly as written
>    once the writer is correctly identified — and it also puts the verification where C-3 needs it,
>    because the multi-hundred-KB CBOR decode and the hash over it are the memory spike the 12 MB
>    provider budget exists to keep out.
>
> **Normative form:** the **extension fetches**; it hands **verbatim signed octets** to the app; the
> app's `core-lite` **verifies the signature and compiles** a compact pre-validated generation and
> is the sole writer of it; the provider **consumes that generation read-only** and remains sole
> writer of session state. The provider performs **no** general-purpose parse of a signed document
> and makes **no** allocation proportional to one, per LC-17. I8 is preserved on both stores: each
> has exactly one writer, and each writer verifies what it commits.

The original text, superseded in its two role assignments only:

> [docs/networking.md](../networking.md) §5.4 assigns contract
> fetch and parse to the *app* process because of C-1. That does not make the app a writer. The app
> fetches, performs structural validation only, and hands the **verbatim signed octets** to the
> provider over [ADR-0017](ADR-0017-local-management-interface.md); the provider verifies the signature over received octets
> ([ADR-0003](ADR-0003-network-contract-schema-format.md)) and performs the ST-23 commit. Signature
> verification and floor enforcement happen at the writer, never at the courier. This is what keeps
> **I8** true across the iOS process split.

**Rule ST-32 (the store path must be suitable).** At open, the daemon checks that `store_root` is a
local filesystem supporting `fsync` and advisory locking. A network mount, a filesystem without
working locks, or a path on removable media is refused with `STORE.PATH_UNSUITABLE`.

**Multi-user and account scoping.**

- **The unit of identity is the `Device`, not the OS user.** On Windows, macOS, and Linux a machine
  has exactly one TwinVPN identity, held at machine scope, shared by every interactive user. Per-user
  preferences (S-24) are records **inside** the vault keyed by an OS account scope (SID on Windows,
  uid on macOS/Linux), not per-user files. Who is authorized to change what through the management
  interface is [ADR-0017](ADR-0017-local-management-interface.md)'s question, not this ADR's.
- **Android and Shared iPad invert this.** Each Android user or work profile, and each Shared iPad
  user, has its own credential-encrypted domain and therefore its own identity and its own vault.
  A device with three Android users is three `Device`s to a `TwinNet`.
- **iPadOS specifics.** Stage Manager and multi-window mean several UI scenes may be live at once;
  all of them are [ADR-0017](ADR-0017-local-management-interface.md) clients and none of them touches the store, so multi-window changes
  nothing about persistence. The store MUST NOT be placed anywhere reachable by the Files app:
  `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace` MUST be false, or the store MUST
  NOT be in `Documents/`. An external display or hardware keyboard has no storage effect.
- **Headless and CLI-only.** There is no interactive user at all. The store is root-owned, the
  daemon is the only opener, and authorization for control operations is peer-credential-based over
  [ADR-0017](ADR-0017-local-management-interface.md)'s local socket.

### 11.10 Never-persisted list, and crypto-erase

**Rule ST-33 — the never-persisted list.** The following MUST NOT be written to Tier 2, to any
sidecar, to the ring file, to a crash dump, or to a diagnostic bundle. This is
[docs/threat-model.md](../threat-model.md) §9's `SECRET` list projected onto storage:

| Never persisted | Why |
|---|---|
| Tunnel plaintext, packet payloads | threat model §9 |
| `Tunnel` transport keys and the anti-replay window (S-13) | RQ-2; [docs/reliability.md](../reliability.md) §6.5 |
| The `OwnerRootKey`, and the 24-word recovery phrase | [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-10: ORK is materialized only during a ceremony and zeroized after |
| Unsealed `PairSecret` / `EpochSeed` **working copies** | the sealed forms are stored (RQ-4); the unsealed forms are Tier 0 |
| `K_pair`, `TwinNetPSK`, any derived `psk2` | derived per handshake, Tier 0 |
| DNS query names, browsing or destination history | threat model §9; [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.10 |
| The peer-pair correlation on any infrastructure component | threat model §9 (does not arise on a device, stated for completeness) |

Enforcement is SI-4 (no encoder exists for these types) plus a CI check that no namespace's record
schema declares a field whose classification is `SECRET` outside the enumerated sealed forms.

**Rule ST-34 — erasure is crypto-erase.** Overwriting is not a guarantee on any storage TwinVPN
runs on (C-11). Both wipe paths therefore destroy keys first:

```
1. delete SEK, K_bind, ANCH, and the IK/TK handles from Tier 1
2. delete the OSK handle if this device holds one
3. unlink vault.tv, ring.tvr, sidecars, and any .bak / .corrupt.* files
4. emit the wipe event; the device is now unenrolled
```

- **Uninstall.** iOS (since the platform deletes an app's keychain items on uninstall) and Android
  (Keystore keys are deleted with the app) perform step 1 automatically. Windows, macOS Developer
  ID, Linux, and OpenWrt MUST perform it explicitly from the uninstaller — an [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) obligation.
  A forced removal that skips the uninstaller leaves vault ciphertext behind; on `HARDWARE_*` and
  `SOFTWARE_LOCAL` it is inert, on `SOFTWARE_PORTABLE` it is not, and that is disclosed.
- **`Owner`-initiated wipe.** Same sequence, invoked through [ADR-0017](ADR-0017-local-management-interface.md) with `Owner` authorization,
  and it MUST NOT disengage the kill switch as a side effect: the OS-level rule set stays until the
  `Owner` separately disarms it ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.10).
- **What crypto-erase does not do.** It does not remove the ciphertext from a cloud backup taken
  before ST-26 was in force, from a flash block the FTL has retired, or from a filesystem snapshot.
  A step 1 failure is `STORE.WIPE_INCOMPLETE`, surfaced to the user with the honest statement that
  the remaining data is unreadable *if and only if* the custody class is `HARDWARE_*`.

### 11.11 Failure, corruption, and the recovery ladder

**Detection** happens at four independent points: the vault header checksum and `schema_version`;
the engine's page checksums (E4); the per-record AEAD tag (ST-17); and the ST-24 anchor
classification. Any of the four failing enters the ladder at the lowest rung that covers it.

| Rung | Condition | Action | Code | Floors |
|---|---|---|---|---|
| **L0** | Healthy | — | — | intact |
| **L1** | One record fails its AEAD tag or its checksum | Quarantine that record; if it is cache-class (S-09, S-15, S-30, S-31, S-23) re-pull or re-derive it; if it is floor-bearing, escalate to L3 | `STORE.RECORD_CORRUPT` (TRANSIENT) | intact |
| **L2** | A whole namespace is unreadable | Drop the namespace, recreate it empty, re-pull. `peer/` and `trust/` MUST NOT be dropped at this rung — they escalate to L3 | `STORE.NAMESPACE_REBUILT` (TRANSIENT) | intact |
| **L3** | The engine cannot open the vault, the header is invalid, or `trust/`/`peer/` is unreadable | **Identity-only bootstrap** (RQ-3): rename to `vault.corrupt.<ts>`, create a fresh vault, **seed the floors from the Tier-1 anchor — never from the quarantined file**, re-pull every document, and re-enter `RECONNECTING` per known peer. Identity is untouched (it is in Tier 1) and MUST NOT be regenerated (ST-28) | `STORE.VAULT_CORRUPT` (PERSISTENT) | **from Tier 1** |
| **L4** | ANCH absent or inconsistent | Per the ST-24 table: unverified floors ⇒ suspend granted authority until a fresh signed document at ≥ the stored floors verifies; ANCH **and** IK absent ⇒ re-enrolment | `STORE.ANCHOR_MISSING` / `STORE.ANCHOR_MISMATCH` | held at `max(anchor, vault)` |
| **L5** | Rollback classified at open | Adopt the anchor's floors, refuse every document below them, re-pull, suspend granted authority | `STORE.ROLLBACK_DETECTED` (POLICY) | **anchor wins** |

**Rule ST-35 (the ladder never violates I5 or I3).** No rung tears down an established `Session`
(**I5**), no rung disengages the kill switch (**I3**, RQ-10 — the rule set is an OS object that the
store cannot touch), and no rung lowers a floor. A rung may only make the device *less*
authorized — which is [ADR-0009](ADR-0009-state-consistency.md) §11.4's grant/deny asymmetry
applied to storage failure.

**Other operational failures.**

| Condition | Behaviour | Code |
|---|---|---|
| **Disk full** | Commits fail. The store enters `DEGRADED_READONLY`: established sessions continue (I5), cached documents are LRU-evicted to recover space, and new documents are refused rather than half-applied. Floor advances are **unaffected**, because floors live in Tier 1 and Tier 1 is not the filesystem (RL-3) | `STORE.WRITE_SPACE_EXHAUSTED` |
| **Read-only filesystem** (failed OpenWrt overlay mount, read-only container, recovery boot) | The device runs in **volatile mode**: the vault is memory-only, everything is re-pulled at every boot, and the `volatile_store` capability is advertised so the `Owner` sees it. Identity may still work if Tier 1 is a TPM or a keyring | `STORE.READONLY_FILESYSTEM` |
| **Secure storage locked** (pre-first-unlock, screen-locked on a misconfigured build) | Transient. The daemon retries with the [docs/reliability.md](../reliability.md) §6.1 backoff, does not fail the device, and does not start a tunnel it cannot key. The kill switch holds the fail-closed posture meanwhile | `STORE.KEYSTORE_LOCKED` |
| **Secure storage unavailable** (TPM in a failed state, Keystore service restarting after an OS update, SEP busy) | Transient, same handling; escalates to `PERSISTENT` after `T_STORE_KEYSTORE_GIVEUP` = 5 min | `STORE.KEYSTORE_UNAVAILABLE` |
| **Key permanently invalidated** (Android `KeyPermanentlyInvalidatedException` after the screen lock is removed; TPM cleared; keychain item destroyed by an OS migration) | Fatal for the SEK: the vault is unopenable and unrecoverable. Quarantine it, rebuild empty from ANCH if ANCH survives, otherwise re-enrol | `STORE.KEY_INVALIDATED` |
| **Two openers** | Refused, never shared | `STORE.LOCK_CONTENDED` |

### 11.12 `STORE.*` reason-code registry

Registered into [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's machine-readable
registry, in its `DOMAIN.CONDITION` form, with the attribute set that section requires. **`STORE`
is a new domain** and its registration obligation is stated in §11.14.

**Rule ST-32a — no store failure crosses the ABI as an errno
([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-4).** Every fallible store operation
— core-side vault I/O and the shell-side Tier-1 vtable entries alike — yields on failure a
`{ reason_code, evidence }` pair from the table below, never a negative errno, a `bool`, or a raw
platform status. Evidence is restricted to the declared `evidence_fields` and is redacted by the
emitter from its schema classification
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4, O-14), not scrubbed afterwards. Raw
OS status values (`OSStatus`, `NTSTATUS`, `errno`, a Keystore exception class) MUST NOT be
attached: they are coarsened to the declared category field, because a raw status is both
unstable across OS versions and a fingerprinting surface. The shell MUST NOT synthesize error text
(CB-4); it renders what the registry gives it.

**Domain boundary rule.** `STORE.*` covers the Tier-2 vault, its sidecars, and the Tier-1 items
this ADR owns (`SEK`, `ANCH`, `K_bind`). Conditions concerning the `DeviceIdentityKey`, `TK`, or an
`OwnerSigningKey` are [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s and use `AUTH.*` — where
that ADR already registers the condition, **its** code wins, exactly as
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rules for the credential family.

| Code | Class | Severity | Terminal | Actionable | Meaning | User-facing text (summary key) | Suggested next action | `evidence_fields` (F-4) |
|---|---|---|---|---|---|---|---|---|
| `STORE.VAULT_CORRUPT` | PERSISTENT | ERROR | no | yes | The durable local store failed integrity and was quarantined; it has been rebuilt | "Local data was damaged and has been rebuilt. Your identity and settings are safe." | None; the device is re-fetching its data. Report if it recurs | `rung`, `detector`, `quarantine_ref`, `namespaces_lost[]` (all OPERATIONAL) |
| `STORE.RECORD_CORRUPT` | TRANSIENT | WARN | no | no | One record failed its integrity tag; quarantined and re-fetched | "A cached item was damaged and is being refreshed." | None | `namespace`, `record_class`, `detector` (OPERATIONAL) |
| `STORE.NAMESPACE_REBUILT` | TRANSIENT | WARN | no | no | A whole class of cached data was discarded and re-fetched | "Cached data was rebuilt." | None | `namespace`, `record_count_lost` (OPERATIONAL) |
| `STORE.ROLLBACK_DETECTED` | POLICY | **CRITICAL** | no | yes | The store is older than the anti-rollback anchor — a restore or a rollback attempt | "Local data appears to have been restored from an older copy. Elevated access is paused until this device re-verifies with your network." | Reconnect to the control plane or to another of your devices; if you did not restore a backup, treat this as a security event | `store_seq_anchor`, `store_seq_vault`, `floors_restored{}`, `crash_recovery` (bool) (all OPERATIONAL) |
| `STORE.ANCHOR_MISSING` | PERSISTENT | ERROR | no | yes | The secure-storage anti-rollback anchor is absent; floors are unverified | "This device cannot confirm its security state is current. Elevated access is paused." | Bring the device online to re-verify | `backend`, `floors_unverified{}` (OPERATIONAL) |
| `STORE.ANCHOR_MISMATCH` | FATAL | CRITICAL | yes | yes | Anchor and vault disagree at equal sequence — tamper or a forked store | "Local data does not match its security record." | Re-enrol this device | `store_seq`, `digest_expected`, `digest_found` (OPERATIONAL) |
| `STORE.SCHEMA_TOO_NEW` | FATAL | ERROR | yes | yes | The store was written by a newer client than this build | "This version is too old to read its own data." | Update the app; do not delete its data | `schema_found`, `schema_max_supported` (PUBLIC) |
| `STORE.MIGRATION_FAILED` | PERSISTENT | ERROR | no | yes | A schema migration failed; the previous store was retained | "Updating local data failed. The previous data is intact." | Retry the update; report if it recurs | `schema_from`, `schema_to`, `step` (OPERATIONAL) |
| `STORE.READONLY_FILESYSTEM` | PERSISTENT | WARN | no | yes | The store location is not writable; running without durable local state | "This device cannot save its settings and will re-fetch them each start." | Check available storage or the read-only mount | `fs_type`, `mount_flags` (OPERATIONAL); the path itself is SENSITIVE and pseudonymized |
| `STORE.WRITE_SPACE_EXHAUSTED` | PERSISTENT | ERROR | no | yes | No space for a durable commit | "There is no space left to save settings." | Free space on the device | `bytes_free`, `bytes_required` (OPERATIONAL) |
| `STORE.PATH_UNSUITABLE` | PERSISTENT | ERROR | yes | yes | The store path is not a local filesystem with working locks and flush | "The chosen data location cannot be used safely." | Move the data directory to local storage | `fs_type`, `missing_capability` (`locking`\|`fsync`\|`local`) (OPERATIONAL) |
| `STORE.KEYSTORE_LOCKED` | TRANSIENT | INFO | no | yes | Secure storage present but locked (before first unlock after restart) | "Unlock this device to finish connecting." | Unlock the device | `backend`, `lock_reason` (`pre_first_unlock`\|`device_locked`) (OPERATIONAL) |
| `STORE.KEYSTORE_UNAVAILABLE` | TRANSIENT | WARN | no | no | The secure-storage backend is not responding | "Secure storage is temporarily unavailable." | None; retrying | `backend`, `platform_status` (a coarse category, **never** the raw OS status) (OPERATIONAL) |
| `STORE.KEY_INVALIDATED` | FATAL | CRITICAL | yes | yes | The store key was permanently invalidated by the platform | "Secure storage for this app was reset by the system." | Re-enrol this device | `backend`, `invalidation_cause` (coarse) (OPERATIONAL) |
| `STORE.CUSTODY_DEGRADED` | PERSISTENT | ERROR | no | yes | Secure-storage backing dropped below the declared custody class | "This device's key protection has been downgraded." | Re-enrol so your other devices can verify it again | `class_from`, `class_to`, `asset` (`identity`\|`vault`), `backend` (OPERATIONAL) |
| `STORE.BACKUP_EXCLUSION_FAILED` | PERSISTENT | WARN | no | yes | The store could not be excluded from OS backup | "This device's data may be included in system backups." | Review the platform's backup settings for this app | `platform_mechanism`, `scope` (`cloud`\|`device_transfer`) (OPERATIONAL) |
| `STORE.PRESERVE_RULE_MISSING` | PERSISTENT | **CRITICAL** | no | yes | The platform's upgrade keep-list does not cover the store, so the next firmware upgrade will destroy this device's identity (ST-26a) | "A firmware upgrade would erase this device's identity and it would have to be set up again." | Reinstall the TwinVPN package so it restores its upgrade keep-list; do not run a firmware upgrade until this clears | `keep_list_path`, `paths_missing[]` (names only) (OPERATIONAL) |
| `STORE.RESTORED_FOREIGN_HOST` | PERSISTENT | CRITICAL | yes | yes | The store was restored onto different hardware or a different install | "This data came from a different device." | Re-enrol this device; identities are not transferable | `binding_mismatch` (bool only — the host identifiers themselves are SENSITIVE and MUST NOT be attached) (OPERATIONAL) |
| `STORE.LOCK_CONTENDED` | PERSISTENT | ERROR | yes | yes | Another process holds the store lock | "Another copy of TwinVPN is already running." | Stop the other instance | `holder_pid`, `holder_start_time`, `same_boot` (bool) (OPERATIONAL) |
| `STORE.WIPE_INCOMPLETE` | PERSISTENT | ERROR | no | yes | Crypto-erase could not remove a key handle | "Some secure data could not be erased." | Re-run the removal, or reset the device's secure storage | `assets_remaining[]` (names only, never values), `backend` (OPERATIONAL) |

### 11.13 Platform summary — all ten targets on one page

| Target | Tier 1 | `custody_class` | Vault location | Backup posture | I4 upheld? | Deferred |
|---|---|---|---|---|---|---|
| **iOS** | Keychain + SEP, `AfterFirstUnlockThisDeviceOnly` | `HARDWARE_ATTESTED` | App Group container | excluded (`isExcludedFromBackup`, `ThisDeviceOnly`) | **Yes** | — |
| **iPadOS** | as iOS | `HARDWARE_ATTESTED` | App Group container; **per-user on Shared iPad** | as iOS | **Yes** | Shared-iPad multi-identity UX is [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)'s |
| **Android** | Keystore, StrongBox → TEE → software; CE storage | `HARDWARE_ATTESTED` / `HARDWARE_UNATTESTED` / `SOFTWARE_LOCAL` on a software keymaster | CE app storage, **per Android user** | excluded (`dataExtractionRules`, both sections) | **Yes** on StrongBox/TEE; **no** on a software keymaster (declared) | — |
| **macOS** | Data-protection keychain + SEP (Apple silicon/T2); System keychain + ACL for a Developer ID daemon; file keychain pre-T2 | `HARDWARE_ATTESTED` **only if the `SEK` is also SEP-wrapped**; a SEP-backed IK beside a plain System-keychain `SEK` yields **`SOFTWARE_LOCAL`** under the ST-9a minimum. `SOFTWARE_LOCAL` pre-T2 | `/Library/Application Support/TwinVPN/` or App Group | excluded (`tmutil` + URL key) | **Yes** on T2/Apple silicon; **no** pre-T2 (declared) | — |
| **Windows** | CNG PCP (TPM 2.0), VBS isolation where on; DPAPI-NG for SEK | `HARDWARE_ATTESTED` / `HARDWARE_UNATTESTED` (VBS only) / `SOFTWARE_LOCAL` (no TPM) | `%ProgramData%\TwinVPN\store\` | outside File History; image backups capture it (declared) | **Yes** with TPM; **no** with the software KSP (declared) | — |
| **Linux** | TPM 2.0 via tpm2-tss / `systemd-creds`; kernel keyring for runtime handles; **never** the Secret Service | `HARDWARE_ATTESTED` / `SOFTWARE_LOCAL` | `/var/lib/twinvpn/` | no OS backup; TPM sealing is the mitigation | **Yes** with TPM; **no** without (declared) | — |
| **OpenWrt** | **None** — files at `0600` | `SOFTWARE_PORTABLE` | `/etc/twinvpn/` (overlay; never `/var`) | kept across `sysupgrade`; **present in `sysupgrade -b` archives** (declared) | **No** — §11.4 residual | Hardware-root support if a target ships a usable secure element |
| **Routers (non-OpenWrt)** | Vendor-dependent; probe at start | `SOFTWARE_PORTABLE` unless a probe proves otherwise | vendor-persistent partition | vendor-dependent; assume included | **No** unless probed otherwise | Per-vendor Tier-1 adapters |
| **Headless gateways** | TPM 2.0 where present, else files | `HARDWARE_ATTESTED` / `SOFTWARE_PORTABLE` | `/var/lib/twinvpn/` | operator-controlled | Conditional | Ties to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s profile |
| **CLI-only installs** | as the host OS row | as the host OS row | as the host OS row | as the host OS row | as the host OS row | Container images MUST declare `SOFTWARE_PORTABLE` unless a device-mapped TPM is proven |

### 11.14 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| **[ADR-0016](ADR-0016-client-process-and-privilege-separation.md)** (H2) | Exactly one privileged process per device (per Android user / Shared iPad user) holds the store open. The unprivileged UI process MUST NOT be granted a filesystem path to `store_root`. On iOS/iPadOS the `NEPacketTunnelProvider` is that process. |
| **[ADR-0017](ADR-0017-local-management-interface.md)** (H3) | (a) A method that hands **verbatim signed octets** to the daemon for verification and commit (ST-31). (b) A status surface exposing `schema_version`, `custody_class`, `store_state`, the floor set, and the last `STORE.*` diagnostic. (c) An `Owner`-authorized `wipe` operation invoking ST-34. (d) No method that returns raw store contents. |
| **[ADR-0018](ADR-0018-shared-core-and-build-architecture.md)** (H1) | **Settled — B-03 corrected and confirmed from both ends** (ST-12a…ST-12e). What this ADR **supplies**, per that ADR's §11.16(c): (i) Tier-1 custody behind `secure_item_read` / `secure_item_write_atomic`; (ii) a `store_root` vended at construction with its platform attributes already applied (ST-12e); (iii) a `Signer` that signs and agrees **without exporting the private half** — `identity_sign` for the `DeviceIdentityKey`, with the `TunnelStaticKey` unsealed into the locked allocator per [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5 rather than held in the element; and (iv) the CB-6a per-target declaration of whether the platform key API performs the record AEAD, recorded in `CoreBuildIdentity` (S-46). **In one line: this ADR supplies custody and a directory, not a database.** Also required: the §11.9 build rows keep aarch64/armv7/mipsel musl, and the selected engine satisfies E1–E8 on each. |
| **[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)** | (a) A presentation contract for `STORE.*`: `STORE.ROLLBACK_DETECTED` and `STORE.RESTORED_FOREIGN_HOST` MUST be unmissable, not toast; `AUTH.IDENTITY_MISSING` MUST route into re-enrolment as a first-class path; `custody_class` MUST be visible per device. (b) **X4 is discharged by ST-14a/ST-14b**: S-50 lives in `consent/` and S-51 in `pref/ui/`, every bulk operation is namespace-scoped so a preference reset cannot name a consent record, and `consent/` has no non-local writer, no wire ingress, and no replication path. |
| **[ADR-0021](ADR-0021-packaging-distribution-and-updates.md)** | (a) An update or reinstall MUST preserve `store_root` and Tier 1 (ST-27). (b) The installer MUST register the platform backup exclusions of ST-26 and MUST fail the install loudly if it cannot. (c) The uninstaller MUST invoke ST-34 step 1 before removing files. (d) The rollback window MUST NOT exceed two schema versions (ST-15). (e) A change of code-signing identity, service account, or package identity is a store-migration event, because the macOS keychain ACL and the Windows key-container ACL bind to it. (f) On OpenWrt the package MUST install `/lib/upgrade/keep.d/twinvpn`. |
| **[ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)** | The store MUST be committed and quiesced before the process accepts an OS suspension; a commit MUST NOT be in flight across an iOS `NEProvider.sleep()`. On wake, the daemon re-reads ANCH and re-runs the ST-24 classification before any document is applied. |
| **[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)** | The headless/router profile MUST NOT place the store in the UCI config tree and MUST NOT expose it through `ubus`. It MUST provide a CLI that prints `custody_class`, `store_state`, and the floor set, and MUST warn at config-backup time that the archive contains a transferable identity (§11.4 residual). **Its four asks are accepted:** EM-52's cadence split is §9's synchronous-floor / debounced-cache rule; S-54 is the sole `custody_class` writer per EM-28 with `SOFTWARE_PORTABLE` as the H-EMB value; EM-29a's transition-vs-steady-state code split is adopted in ST-11; and **S-67 is confirmed non-durable and outside the vault**, because it carries a `pairing_secret` that ST-33 forbids persisting. S-65 lands at `policy/intent` on the `sysupgrade`-preserved path. |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | **Two amendment obligations.** (1) §7.3's Android row: `setUnlockedDeviceRequired(true)` is functionally wrong for a background VPN and should read `setUserAuthenticationRequired(false)` + `setUnlockedDeviceRequired(false)` with credential-encrypted storage (ST-7). (2) N-26's "monotone in durable local state" is realized by ST-21/ST-22/ST-23, which require the anchor to be **co-located with IK** — that co-location should be recorded in §7.3 as a custody requirement, not left to this ADR alone. |
| [ADR-0009](ADR-0009-state-consistency.md) | R-9's write-ahead high-water rule is realized by ST-23 steps 3–5. R-7's "outside the log's compaction scope" has its device-side analogue in Tier 1. The `trust_state_expired` guard input is the mechanism by which `STORE.ROLLBACK_DETECTED` and `STORE.ANCHOR_MISSING` suspend granted authority. |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | Confirmed unchanged: S-18's authoritative durability is the OS-level object of §11.6. This store holds a reporting replica only, and no store failure may disengage enforcement (ST-35). |
| [ADR-0011](ADR-0011-dns-handling.md) | Confirmed: S-34 stays **outside** the vault as a plain, boot-readable sidecar (RQ-11, ST-4). |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the `STORE` **domain** in §11.2's domain table, and of the nineteen codes in §11.12 with class, severity, `summary_key`, `next_action_key`, and `evidence_fields`. §11.2 currently states "the thirteen above are closed"; that sentence must be amended to admit the domains this workstream adds, or these codes must be re-homed. See §13. |
| [ADR-0003](ADR-0003-network-contract-schema-format.md) | Confirmed: signed statements are stored as received octets and verified over them (RQ-7, ST-13). No second encoding of any B2 statement exists on disk. |
| [docs/testing-strategy.md](../testing-strategy.md) | (a) Registration of **P19** (§11.17) and of `T_STORE_KEYSTORE_GIVEUP` = 5 min as a store-lifecycle constant. (b) **Gap G-5 — the half this ADR closes.** G-5 asks that §2.14's key-custody battery assert the `hardware_backed` flag's *accuracy* per target and that a false flag be impossible. ST-9/ST-9a/ST-9b supply the mechanism (live probe at every start, two probes, minimum wins, exactly one writer) and §11.17's `custody_probe_evidence` supplies the observable, so the battery can assert per target that the derived class equals the minimum of the two probes and that no stored value can raise it. What this ADR **cannot** close is the other half: on `SOFTWARE_PORTABLE` targets non-exportability is false *by construction* (§11.4 residual), so the only sound assertion there is that the flag reads `false` — accuracy, not non-exportability. G-5's remedy should be split along that line rather than left as one gap. |

### 11.15 State ownership

New rows for [docs/architecture.md](../architecture.md) §5, in its seven-column format. Rows
S-01…S-37 are cited in §11.2 and are **not** redeclared.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-52** | `StoreInstanceDescriptor` — `store_id`, `schema_version`, `format_generation`, `created_at` | **Config/State Storage (2.20)**, on the device | None | `LOCAL` | Durable in the vault header (Tier 2) | Local wins. A `schema_version` above this build's maximum is refused, never downgraded (`STORE.SCHEMA_TOO_NEW`) |
| **S-53** | `StoreAntiRollbackAnchor` — `store_seq`, `vault_digest`, and the floor set of §11.7 | **Config/State Storage (2.20)**, on the device | The vault header holds a replica with **zero** staleness tolerance — divergence is the detector, not a tolerance | `MONOTONIC` (no component may decrease) | **Durable in Tier 1**, co-located with `DeviceKey` (ST-22); additionally mirrored to a TPM NV counter on trust-floor advance where present | Every floor resolves to `max(anchor, vault)`. `anchor.store_seq > vault.store_seq` ⇒ `STORE.ROLLBACK_DETECTED`; equal `store_seq` with differing digests ⇒ `STORE.ANCHOR_MISMATCH`. A decrease is never applied |
| **S-54** | `KeyCustodyDescriptor` — the **two** Tier-1 backend probe results (identity backend, vault-key backend), each with its attestation outcome and handle references, and the single derived `custody_class` = **min** of the two (ST-9a) | **Config/State Storage (2.20)**, from a live probe at each start. 2.20 *observes and records*; **Device Identity (2.6) remains the custodian of S-01** and no key material is read (ST-9b) | Mirrored into the vault for reporting; advertised as a `Capability` (S-19); consumed by [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `hardware_backed` claim and by [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-28, **which declares no second copy** | `LOCAL` | Durable: handles in Tier 1, the descriptor in Tier 2 | The live probe always wins over any stored value, and the lower of the two probes always wins over the higher. A **transition** downward ⇒ `STORE.CUSTODY_DEGRADED` + forced IK rotation ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-24); a permanent `SOFTWARE_PORTABLE` **steady state** is *not* a degradation and is [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE` (ST-11, EM-29a) |
| **S-55** | `StoreHealthState` — `HEALTHY \| VOLATILE \| DEGRADED_READONLY \| REBUILDING \| QUARANTINED`, last recovery rung, quarantine reference | **Config/State Storage (2.20)** | None | `LOCAL` | Durable in a **plain sidecar outside the vault**, so it is writable exactly when the vault is not (ST-4) | Within one boot the most severe observed state wins; each start re-probes from scratch, so a stale severe state cannot pin the device |
| **S-56** | `StoreBindingToken` — `install_id` plus `host_binding = HMAC(K_bind, host_id)` | **Config/State Storage (2.20)** | None | `LOCAL` | `install_id` durable in the vault; `K_bind` in Tier 1; `host_binding` recomputed at every open | Never reconciled. A mismatch means the store arrived from elsewhere ⇒ `STORE.RESTORED_FOREIGN_HOST`, quarantine, re-enrolment |

### 11.16 Assumptions register

In [docs/architecture.md](../architecture.md) §9's column format.

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **A-01** | **H1 — CONFIRMED** by [ADR-0018](ADR-0018-shared-core-and-build-architecture.md): a Rust portable core over a hand-written C ABI, with thin native shells. The vault's logic lives in that core | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | No longer open. Were it reversed, V3 becomes the de-facto outcome and §6/V3's objections go live: ten anti-rollback implementations, ten migration paths, and R-38 unverifiable in one place |
| **A-01a** | **CB-5 holds without divergence.** The core never receives identity private-key bytes; identity operations are shell-side `identity_sign` / `identity_public` / `identity_attestation` calls. ST-12a maps this ADR onto that inversion | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.1, §11.4 | Nothing here changes: this ADR's Tier 1 *is* the shell side of CB-5. If CB-5 were relaxed to let the core hold IK, **I4** would be violated before this ADR was reached |
| **A-01b** | **B-03 — CORRECTED AND CONFIRMED from both ends.** The vtable's `secure_item_read`/`secure_item_write_atomic` realize **Tier 1**; the Tier-2 vault is core-side file I/O beneath a shell-vended `store_root` (ST-12a…ST-12e). No longer an assumption | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) B-03, CB-7, §11.16(c) | Nothing open. Were the vault pushed back behind a per-key atomic write, E2's multi-key commit would be lost — a correctness bug in anti-rollback, not a performance one (ST-12b) — or every shell would implement a transaction engine, which is V3 |
| **A-02** | **H2 — CONFIRMED.** A single privileged long-lived service/daemon exists per device (per user on Android/Shared iPad), and the OS-hosted extension plays that role on iOS/iPadOS/Android | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | ST-30's single-opener rule fails. The engine would need multi-process concurrency (E3 waived), the lock becomes mandatory rather than a backstop, and §11.9's iOS courier rule becomes load-bearing in a way it is not today |
| **A-03** | **H3 — CONFIRMED.** One authenticated, schema-versioned local management interface exists, and the GUI has no privileged side channel | [ADR-0017](ADR-0017-local-management-interface.md) | ST-31 has no carriage: the app process would need direct store access on iOS, reintroducing two openers and an **I8** violation across the process split. §11.14's [ADR-0017](ADR-0017-local-management-interface.md) row is the substitute contract |
| **A-04** | Enrolment is the only path that creates an identity, and it requires `Owner` approval from an OSK device | [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4, N-7 | ST-28's structural argument weakens to a guard, and "MUST NOT silently mint a replacement identity" would need an explicit runtime check plus a proof test of its own |
| **A-05** | `PairSecret` and the sealed `EpochSeed` set are **durable local state** on each device | [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-19, S-33 | If they became ephemeral, ST-3 relaxes and the vault could be unencrypted on `SOFTWARE_PORTABLE` targets — but reconnection after restart would then require a control-plane call, breaking **I5** |
| **A-06** | Revocation refusal rests on the OSK signature alone and does not need an epoch number | [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-25(1) | A rolled-back store would be able to un-revoke locally, and §11.7's "not detected" rows would become "not defended" rather than "detected elsewhere" |
| **A-07** | High-water marks are durable and written before the document they admit | [ADR-0009](ADR-0009-state-consistency.md) R-9 | ST-23's ordering has no upstream requirement and the crash window between steps 3 and 5 would need a different resolution |
| **A-08** | An update or reinstall preserves `store_root` and Tier 1 | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | Every update becomes a re-enrolment, which is a product-breaking outcome on desktop and a fleet event on routers. §11.8 would have to specify an export/import path, which **I4** forbids for the identity half |
| **A-09** | The headless/router profile does not require the store to be operator-editable | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | The vault would have to be plaintext or shadowed by a UCI mirror, creating two writers for the same facts (**I8**) |
| **A-10** | The store may be quiesced before OS suspension, and re-opened on wake | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | Commits in flight across suspension would need a recovery path beyond copy-on-write's, and iOS/iPadOS reliability would rest on the engine's crash behaviour alone |
| **A-11** | S-18's durability is the OS-level object, not this store | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 | A corrupt store would be able to drop protection, violating **I3**, and ST-35 would be false |
| **A-12** | S-34 may live outside the vault, unencrypted but integrity-tagged | [ADR-0011](ADR-0011-dns-handling.md), RQ-11 | Either boot-time DNS restore breaks, or the vault must be openable by a minimal boot binary — which would require Tier 1 access from an unprivileged context |
| **A-13** | `STORE` may be added as a new reason-code domain | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 | If the thirteen domains are genuinely closed, these nineteen codes re-home under `PLATFORM.STORE.*` — which fits the three-segment limit but makes `PLATFORM` the owner of a component it does not own. See §13 |
| **A-14** | The chosen engine builds, with the §9 footprint, for every member of the `GC-0` **envelope** ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54d) — including the 32-bit `mips*-musl` triples, which are a portability target rather than the definition of the class | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.9 rows 8–9, EM-54d | A failure on the **gating envelope member** makes V4 (document vault) the `GC-0` fallback and gives the corpus a second persistence implementation, with §14 trigger 1 as the decision gate. A failure confined to the `mips*-musl` triple is a **portability regression**, not a class failure, and does not by itself reopen V1-vs-V4 |

### 11.17 Conformance surface for P19

This is the observable set P19 consumes verbatim ([docs/testing-strategy.md](../testing-strategy.md)
rule PT-4); the test does not re-derive it.

| Observable | Source | Shape |
|---|---|---|
| `store_open_result` | [ADR-0017](ADR-0017-local-management-interface.md) status surface | `{store_seq_vault, store_seq_anchor, floors{}, classification}` per ST-24 |
| `effective_floor_set` | [ADR-0017](ADR-0017-local-management-interface.md) status surface | the resolved floor set after open, per floor id |
| `store_state` | S-55 | `HEALTHY \| VOLATILE \| DEGRADED_READONLY \| REBUILDING \| QUARANTINED` |
| `custody_class` | S-54 | the derived class, **plus both probe results** (identity backend, vault-key backend) so an assertion can check the min rule of ST-9a rather than trusting the derived value |
| `custody_probe_evidence` | S-54 | per probe: backend name, non-exportability flag as reported by the platform, attestation outcome. This is the surface [docs/testing-strategy.md](../testing-strategy.md) **G-5** needs to assert the `hardware_backed` flag's *accuracy* per target |
| `granted_authority_suspended` | [ADR-0009](ADR-0009-state-consistency.md) §11.4 guard input | boolean, with the guard that set it |
| `STORE.*` diagnostic stream | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.3 | `Diagnostic` records with `reason_code`, `class`, `evidence` |
| Crash-injection point | RQ-12 injected clock/step source | the ST-23 step number at which the process is killed |

---

## 12. Why the Selected Option Won

| Beat | Decisive reason it lost |
|---|---|
| **V2** (SQL) | The workload has **no queries**: every fact is fetched by an exact key and the largest object is an opaque blob that must not be decoded. SQL's value proposition is unused while all its costs are paid — footprint on a 128 MB router, an encryption layer with its own audit surface, a three-file lifecycle (`.db`, `.db-wal`, `.db-shm`) each of which must be backup-excluded and removed on uninstall *without missing one*, and a table surface that invites growth ST-14 exists to prevent |
| **V4** (document vault) | **The closest runner-up.** `rename` atomicity is the best-understood durability primitive there is, and it stores signed octets with zero framing. It loses on exactly one thing, and it is decisive: ST-23 requires a floor advance and its document to commit **together**. V4 can only do that with a manifest generation swap — a single-file transaction log with worse crash properties and worse `fsync` portability across ext4 / APFS / JFFS2 / NTFS. **Retained as the named router-class fallback** if §14 trigger 1 fires |
| **V5** (append-only ledger) | Its hash chain defends against an attacker who edits the file in place — not the one who restores the whole file, which is the attack that matters (§6/M1) and which M2 defeats without a log. Compaction must be crash-safe on an unattended router, reintroducing V4's problem; cold-start read amplification lands on the tightest memory budget (C-1); and the audit trail is already paid for by [ADR-0015](ADR-0015-observability-and-diagnostics.md) |
| **V3** (platform-native) | Rejected on the corpus's own terms. [docs/architecture.md](../architecture.md) §5's whole argument is that every fact behaves identically everywhere; ten persistence stacks cannot deliver that. Worse, the stores V3 would use (`UserDefaults`, `SharedPreferences`, GSettings, the registry, UCI) are *designed to be backed up and synced* — exactly the property ST-26 must negate for a store holding `PairSecret`. It also contradicts H1 directly |
| **M1** (in-store floors) | What the corpus specifies today. It stops the attacker who goes through the API and misses the one who copies the file — the cheaper attack, and the one users perform by accident on every backup restore. M2 costs a few hundred bytes and one extra write on floor-bearing commits |
| **M3 alone** (hardware counter) | Strictly stronger where it exists, strictly absent on four of the six required targets — no app-accessible monotonic counter exists on iOS, iPadOS, macOS, or Android. **Adopted in addition**, on the platforms that have it, at a cadence NV endurance sustains (ST-25) |
| **M4** (remote floor attestation) | Would cover even `SOFTWARE_PORTABLE`, the one case M2 cannot — and is rejected anyway, because it makes the control plane a liveness dependency of local enforcement. **I5**, **R-11**, and three prior decisions ([docs/architecture.md](../architecture.md) §4.4, [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7, [ADR-0009](ADR-0009-state-consistency.md) §11.5) all forbid that shape |

**ST-22 (co-location) is the quiet keystone.** Without it, M2 is defeated by deleting one keychain
item. With it, deleting the anchor deletes the identity, and the consequence of a missing identity
is already specified, already safe, and already a first-class product flow
([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3). It costs nothing to implement and is
the rule an implementer is most likely to get wrong; P19 variant 2 exists to fail the build that
does.

---

## 13. Known Tradeoffs

| Tradeoff | What we accept | Why it is the right cut |
|---|---|---|
| **I4 is not upheld on `SOFTWARE_PORTABLE` targets** | On routers, headless gateways, CLI-only installs, and containers without a mapped TPM, the identity is a file and cloning succeeds. The clone is cryptographically indistinguishable from the original | Refusing to run there would abandon **R-21**, a named product requirement. The alternative — pretending the class does not exist — is what `docs/vision.md` §4.1 forbids. We declare the class, advertise it to peers, contain via revocation and epoch exclusion, and detect via `AUTH.IDENTITY_CONCURRENT_USE` |
| **A router config backup contains a working identity** | `sysupgrade -b` archives the store, because OpenWrt cannot express "keep on upgrade but exclude from user backup" and [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) requires the store to survive an upgrade | Losing the store on every `sysupgrade` would make routine firmware updates a fleet-wide re-enrolment event. We take the update-safety and pay with a declared residual plus a mandatory CLI warning (§11.14, [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) row). The warning MUST say **"this archive contains this device's identity; restoring it onto different hardware produces a clone, not a migration"** — a generic backup caution understates it, because on `SOFTWARE_PORTABLE` hardware this is TM-13 with a convenient UI. The archive is not an artifact we *ship*, so [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-23's "no TwinVPN artifact may contain a pre-shared enrolment secret" is not violated — but it is an artifact that *clones an identity*, and both documents state it |
| **Whole-app-data and whole-image rollback are undetected without a TPM** | Restoring the vault *and* Tier 1 together is not caught on iOS, iPadOS, macOS, Android, or TPM-less desktops | No app-accessible monotonic counter exists on those platforms, and M4 was rejected on **I5** grounds. The device reverts to a *lagging* device rather than an authoritative one, because the `EpochSeed` exclusion runs at the peer, not at the rolled-back device |
| **Pre-first-unlock the tunnel cannot start on iOS/iPadOS and Android** | On-demand VPN start after a reboot fails until the user unlocks once, with `STORE.KEYSTORE_LOCKED` | The alternative accessibility classes either leak the key to backups (`AfterFirstUnlock` without `ThisDeviceOnly`) or break rekey while the screen is off (`WhenUnlocked`, `setUnlockedDeviceRequired(true)`). The OS-level fail-closed posture covers the window ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6), so this is an availability gap, not a leak |
| **One store, one opener** | The UI cannot render anything the daemon does not expose through [ADR-0017](ADR-0017-local-management-interface.md), and a "read the config file" support workflow does not exist | Two openers is two writers (**I8**) and, on iOS, a privilege boundary crossing. Everything legitimately needed is exposed as status (§10.1) |
| **Machine-scope identity on multi-user desktops** | Every OS user on a Windows/macOS/Linux machine shares one TwinVPN identity | The unit of trust in this product is the `Device` ([docs/vision.md](../vision.md) §1). Per-user identities on a shared desktop would multiply enrolments and give the `Owner` a device list that does not match the hardware. Android and Shared iPad differ because the OS itself partitions storage |
| **The registry gains a new domain** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 says "the thirteen above are closed", and this ADR adds `STORE` | The brief for this workstream assigns `STORE.*` as a new domain, and the alternative (`PLATFORM.STORE.*`) makes the Platform Network Adapter the registry owner of a component it does not own. Recorded in §11.14 as an amendment obligation; if the closure is upheld instead, the re-homing is mechanical and the codes are already three-segment-safe |
| **Erasure is only as good as the custody class** | On `SOFTWARE_PORTABLE`, crypto-erase leaves both ciphertext and key on retired flash blocks | C-11 makes overwriting worthless anyway. We state what erasure means per class rather than claiming a guarantee the medium cannot give |
| **The vault sits on the core side of the ABI; the ABI carries a shell-vended `store_root`** | One more vtable entry and a construction-time injection, rather than reusing the two Tier-1 blob entries for everything | E2's atomic **multi-key** commit is not expressible as a sequence of per-key atomic writes, and composing them reinvents V4's manifest; a transaction engine in each of ten shells is alternative V3. [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) reached the same split independently from its own CB-1 line and corrected B-03, so this is settled rather than traded |

---

## 14. Revisit Conditions

Each is a measurement, not a change of mind.

1. **Router footprint.** If the selected engine's measured p95 cold open on a `GC-0` envelope member
   ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54d) exceeds the §9 provisional
   **400 ms**, or steady-state `vault.tv` exceeds **512 KiB** with 8 `TrustedPeer`s, revisit V1
   against V4 for `GC-0`. **The first measurement sets the budget rather than failing against it**
   (§9): both latency figures are re-derived estimates, and only the vault-size figure is a real
   threshold today. Once a measured baseline exists, a **regression of more than 50 %** against it
   is what fires this trigger.
2. **Build reach and flash share.** If the selected engine fails to build for any target in
   [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.9 rows 8–9 (aarch64/armv7/mipsel
   musl), or if it exceeds **400 KiB** stripped — 10 % of the ≤ 4 MB whole-artifact budget for 16 MB
   flash (BM-1.1) — revisit V1 against V4 and re-open A-14. **`GC-0` gates**: the earlier
   "`GC-0U` gates, `GC-0` nightly" position is withdrawn by
   [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-54b, on the R-32 ground that
   `ath79` is the modal cheap OpenWrt router and leaving it ungated ships R-21 as a claim nothing
   tests. What is nightly is a **triple**, not a class (EM-54d): the `build-std` fragility belongs
   to `mips*-musl`, so the gate may run on a single-core ARM envelope member with prebuilt `std`
   while the MIPS triple stays a portability build. A failure on the **gating envelope member**
   therefore blocks a release; a MIPS-triple-only failure is a portability regression.
3. **Anchor write cost.** If the Tier-1 anchor write on Android exceeds p95 **20 ms**, or is
   measured to contend with the tunnel's own Keystore operations such that handshake p95 rises by
   more than **10 ms**, revisit M2's realization toward a Keystore-MAC'd file in CE storage.
4. **Anchor brittleness.** If field telemetry shows more than **1 %** of installs raising
   `STORE.ANCHOR_MISSING` following a routine OS update (as distinct from a restore), the anchor's
   platform binding is too fragile and ST-22's co-location must be re-derived for that platform.
5. **A new hardware counter.** If any of iOS, iPadOS, macOS, or Android ships an app-accessible
   monotonic counter, promote M3 from "where available" to required on that platform and rewrite
   §11.7's honesty table; the "not detected" rows shrink and §13's third row must be revised.
6. **NV endurance.** If TPM NV counter increments exceed **10,000 per device per year** in field
   telemetry, the "floor advances are rare" assumption behind ST-25 is wrong and the cadence must
   be re-derived before endurance becomes a support issue.
6a. **`GC-0` memory share.** If the store's steady-state RSS on `GC-0` exceeds **1.5 MiB** — an
   eighth of [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) PB-6's ≤ 12 MB whole-core
   budget at 8 peers, against **~24 MB realistically free**, not 128 MB — the 512 KiB read-cache
   ceiling is not holding and the engine's cache accounting must be re-derived before PB-6 is
   missed.
7. **Update preservation.** If [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) concludes that any required platform cannot preserve
   `store_root` and Tier 1 across an update, A-08 is falsified and §11.8 must be rewritten around
   an unavoidable re-enrolment on that platform.
8. **Two openers.** If [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) concludes that more than one process must open the vault, ST-30 and
   E3 both fail; the engine selection, the lock design, and SI-5 must all be revisited together.
9. **Store growth.** If any deployed `TwinNet` exceeds **256** `TrustedPeer`s, or the durable
   document set exceeds **32** types, the "no query surface needed" premise behind V1 over V2
   weakens and §12's first argument must be re-measured.
10. **Corruption rate.** If `STORE.VAULT_CORRUPT` (rung L3) is observed at more than **0.1 %** of
    installs per quarter, the E2/E4 properties of the selected engine are not being delivered on
    real storage and the engine must be re-selected, not merely patched.
11. **`GC-0` flash wear.** If measured steady-state store writes on `GC-0` exceed **4 KB/day**
    ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-52), the §9 write-class split is
    not holding. The synchronous class MUST NOT be coalesced to fix it — a coalesced monotone write
    is a rollback window — so the correct response is to move the offending row into the coalesced
    class *and prove it is not floor-bearing*, or to raise the debounce. Exceeding the budget wears
    out the user's flash, which is an unrecoverable hardware fault, not a performance regression.

---

## 15. Proof test P19 — a restored store cannot resurrect a revoked peer

Specified here for [docs/testing-strategy.md](../testing-strategy.md) §4, in that section's format.

| | |
|---|---|
| **Proves** | **R-38**, **R-39**; supports **R-24**, **I4**, **I8**; exercises [ADR-0007](ADR-0007-device-identity-and-pairing.md) N-25/N-26 and [ADR-0009](ADR-0009-state-consistency.md) R-5/R-9 |
| **Lab scenario** | `S-STORE-ROLLBACK-*`, one scenario per custody class (`HARDWARE_ATTESTED`, `SOFTWARE_LOCAL`, `SOFTWARE_PORTABLE`) across the ten targets of §11.13 |
| **Preconditions (V3)** | Three devices A, B, C in one `TwinNet`, all paired; A's `custody_class` asserted and recorded; A's `store_open_result.classification` is `healthy` at the start of the run; an established `Session` A↔B carrying application traffic |
| **Assumptions** | A-02, A-04, A-06, A-07 |

**Procedure.**

1. Record A's `effective_floor_set` and `store_seq` at `t0` (`trust_epoch = e0`, `TrustedPeer(C)`
   present). Take a **byte-level** snapshot of A's `store_root` — every file in §11.5's file set.
2. From an OSK device, revoke C. Wait until A reports `trust_epoch = e1 > e0`, `TrustedPeer(C)`
   absent, and both the vault and the anchor at the new floor.
3. Stop A's daemon. Restore `store_root` verbatim from the `t0` snapshot. **Do not touch Tier 1.**
4. Start A. Capture on every interface of A, B, and C.
5. C attempts to establish a `Tunnel` to A, and then attempts to obtain `ExitNode` egress through B.
6. Drive the pre-existing A↔B application flow throughout.

**Oracle.**

- (a) A emits `STORE.ROLLBACK_DETECTED` at store open, with `store_open_result.classification` =
  rolled-back and `store_seq_anchor > store_seq_vault`.
- (b) A's `effective_floor_set` after open shows `trust_epoch = e1`, **not** `e0`.
- (c) C's handshake to A is refused. The wire oracle (PT-2) shows no responder message that would
  complete a handshake, and A's `Diagnostic` stream carries
  [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `AUTH.DEVICE_REVOKED` or
  `AUTH.PEER_UNTRUSTED` — never a `STORE.*` code in place of one.
- (d) `granted_authority_suspended = true` until A verifies a signed document at `trust_epoch ≥ e1`;
  C obtains no egress through B in the interim.
- (e) The A↔B `Session` is **not** torn down: its `session_id` is unchanged and the application flow
  continues across the restart into `RECONNECTING`→ re-establishment (**I5**, RQ-8).
- (f) The kill-switch `ruleset_digest` observed before and after the restore is identical
  ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.9) — no store event touched
  enforcement (**I3**, ST-35).

**Variant 2 — anchor stripped.** Repeat steps 1–4 but also delete A's Tier-1 items. Oracle: A does
**not** come up with `trust_epoch = e0`. Because ST-22 co-locates the anchor with the identity key,
the identity is gone too, and A emits
[ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `AUTH.IDENTITY_MISSING` and enters
re-enrolment. C is refused throughout. This variant is what makes ST-22 testable rather than
advisory.

**Variant 3 — device-image rollback.** On a `HARDWARE_ATTESTED` target with a physical TPM 2.0,
snapshot and restore the whole OS image between steps 1 and 3. Oracle: `STORE.ROLLBACK_DETECTED`
still fires, driven by the NV counter (M3). On a vTPM whose state is snapshotted with the VM, the
oracle is **inverted**: the test asserts that the rollback is *not* detected, and that A's
`custody_class` and §11.7 honesty table match that outcome. A build that claimed detection here
would be claiming a property it does not have, which is the defect this variant catches.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P19-1` | Floors kept only in the vault (M1 alone; anchor never written) | Oracle (a) and (b) fail: A comes up at `e0` and C connects |
| `M-P19-2` | L3 corruption recovery re-seeds floors from the quarantined vault instead of Tier 1 | The corruption-injection variant lands at `e0`; (b) fails |
| `M-P19-3` | ST-23 reordered so the anchor is written **after** the vault commit | Crash injected between the two: the floor is lost, (b) fails |
| `M-P19-4` | Anchor stored in a plain file beside the vault instead of co-located in Tier 1 | Variant 2 fails: A comes up with a working identity at `e0` |
| `M-P19-5` | `STORE.ROLLBACK_DETECTED` emitted but `granted_authority_suspended` never set | (d) fails: C obtains egress through B |
| `M-P19-6` | Store-open failure path tears down established `Session`s | (e) fails: the A↔B flow breaks (**I5**) |

**Positive control (V4).** The identical run **without** step 3 (no restore) must show: C revoked
and refused, A opening with `classification = healthy` and **no** `STORE.*` diagnostic at any
severity above `INFO`, and `granted_authority_suspended = false`. This proves the oracle can
observe a clean open before any rollback assertion is believed.

**Pass criteria.** Every custody-class scenario reaches its declared outcome in 20/20 runs; all six
mutants fail with the expected oracle; variant 2 passes on all nine targets that have secure
storage; variant 3 passes in both its normal and its inverted form.

**Known limits.** P19 measures **detection and consequence**, not prevention. On
`SOFTWARE_PORTABLE` targets and on vTPM-snapshotted VMs the local rollback is undetectable by
construction (§11.7), and the test asserts that the product *says so* rather than that it stops it.
Whether the peer-side defence actually contains a rolled-back device is
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.7's property and is measured by **P10**, not
here.
