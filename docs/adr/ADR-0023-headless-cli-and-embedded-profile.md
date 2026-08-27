# ADR-0023: Headless, CLI, and Router/Embedded Deployment Profile

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0010](ADR-0010-ipv4-ipv6-routing.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0018](ADR-0018-shared-core-and-build-architecture.md),
  [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md),
  [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md),
  [docs/vision.md](../vision.md)

This ADR owns the **deployment profile in which there is no graphical shell, no user session, no
app store, no camera, and — on the smallest targets — no secure element and 128 MB of RAM shared
with the entire system**. Concretely it owns: the profile taxonomy and what each profile is
committed to in Phase 1; the configuration document as a first-class control surface and its
authority relationship with daemon-held runtime state; headless enrolment and its security
analysis; the deployment consequences of identity custody without a secure element; the CLI as a
*complete* control surface and the parity rule that keeps it complete; diagnostics and log
handling with no GUI and 16 MB of flash; the resource envelope of the embedded build and what is
compiled out of it; coexistence with a router's own `netifd`/`fw4`/`dnsmasq` stack; and unattended
operation, escalation, and watchdog integration.

It does **not** own: the local management contract itself
([ADR-0017](ADR-0017-local-management-interface.md) — this ADR is its most demanding consumer and
states requirements against it, never internals); the process/privilege split
([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)); the build matrix or the shared
core's language and ABI ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)); the
presentation contract for `reason_code`s ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)
— consumed here and specialised to a terminal renderer); secure-storage realization
([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)); packaging and `opkg` mechanics
([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)); the pairing ceremonies
([ADR-0007](ADR-0007-device-identity-and-pairing.md) — consumed verbatim, with a **transport**
specified here); the gateway datapath and its capacity model
([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) — consumed, with one sub-class added
below its smallest reference class); kill-switch policy
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)); the `ConnectionState` machine, timers,
or backoff ([docs/reliability.md](../reliability.md)); or the `reason_code` taxonomy
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 — this ADR contributes codes into it).

---

## 1. Context

[docs/vision.md](../vision.md) §5.6 states **R-21** as a defect-derived requirement, not an
aspiration: *"Linux and router-class targets (OpenWrt-class, low-memory, no GUI) MUST be
first-class: headless operation, config-file and CLI control, and a userspace datapath option."*
The home-lab / self-hoster persona in §2 is defined by wanting "an entire home subnet, not just
one host; run on Linux and routers," and [docs/architecture.md](../architecture.md) §2.1 makes it a
client responsibility: *"run headless on Linux/router targets with the same control contract as the
GUI (R-21)."* Four facts fix the shape of the answer before any alternative is weighed.

**1. This is the inverse of the other seven ADRs in this workstream.** They treat six GUI platforms
as primary and the embedded tier as a column; here the GUI is the column. The consequence is not
stylistic: every affordance the others lean on — a dialog to confirm a consequence, a camera to
scan a QR, a notification centre to escalate to, a settings screen to warn on — is *absent*, and
each absence must be discharged by a named mechanism rather than deferred to "the app handles it."

**2. "Router-class" is several different machines, and the corpus conflates them.**
[ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.5 names its smallest reference class
"G1 — Router class" and gives its reference hardware as "OpenWrt-class / RPi 4B, 4×Cortex-A72
@1.5 GHz, no AES-NI, 2 GB." A Raspberry Pi 4B has roughly sixteen times the RAM and an order of
magnitude more aggregate crypto throughput than an `ath79`-class OpenWrt 21.02 router, which is
what [docs/networking.md](../networking.md) §5.2 actually pins as the minimum. Designing against
that and shipping to a 128 MB MIPS router is how R-21 becomes a marketing claim. §11.13 adds **GC-0**
and **GC-0U** below it as a distinct *silicon* axis, cites ADR-0013's classes unambiguously as
GC-1/GC-2/GC-3 in their hardware sense, and confirms MG-14's sixteen-peer floor against both new
classes.

**3. The hardest problem here is enrolment, and it is a security problem, not a UX problem.**
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 makes the QR ceremony (C-B, 256 bits,
optical) primary and SPAKE2 with a 9-digit code (C-A, ~2^29.9 with attempt limiting) the fallback
"where no camera exists." Taken literally, every headless device lands on the weaker ceremony —
and ADR-0007's revisit condition V3 anticipates exactly that. §11.6 shows the fallback is
unnecessary, because C-B never required a camera: it required a *confidential out-of-band channel*,
and a terminal on an operator's own authenticated shell session is one.

**4. Fail-closed on a router is not "block everything."** A naive reading of **I3** on a device
that is also the household's only Internet gateway produces a design that bricks the house when a
config typo survives a reboot. [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.1
already defines *protected traffic* normatively; the correct embedded answer is to get the
protected scope right (§11.16, rule EM-73) rather than widen the blast radius of every failure. Getting
this wrong in either direction is product-ending: too wide and the router is unusable, too narrow
and R-13 is unmet.

## 2. Requirements

Requirements this ADR **discharges** from [docs/vision.md](../vision.md) §5: **R-21** (primary),
plus the embedded realization of **R-13**, **R-16**, **R-17**, **R-19**, **R-22**, **R-23**. Three
new requirements are proposed for §5, in its table format.

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-47** | The "server build" is the desktop build with the GUI deleted: it still assumes a writable disk, a logged-in user, a camera for enrolment, and an app-store update path. The router target is a README section. | A headless/embedded deployment MUST be a **declared build profile** with a stated, measured resource envelope, and every capability reachable from the GUI MUST be reachable with no GUI, no user session, no camera, no screen, and no app store. A build that cannot enrol, diagnose, or reconfigure a device without a GUI is non-conforming. | Profile taxonomy and per-profile feature matrix (§11.1, §11.2); headless enrolment channels E1–E4 (§11.6); the CLI surface generated from [ADR-0017](ADR-0017-local-management-interface.md)’s operation catalogue under MI-1, asserted by **P17** clause A and re-asserted per build profile by **P22** (§11.9) | ADR-0023, [ADR-0017](ADR-0017-local-management-interface.md), [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) |
| **R-48** | A config change is applied partially, a typo'd key is silently ignored, and an invalid configuration at boot leaves the device either unprotected or unrecoverable. | Configuration MUST be a schema-versioned document, validated **in full before any system state changes**, applied as an all-or-nothing generation with rollback, MUST **reject** unknown keys rather than ignore them, and MUST NOT fail open on an invalid, absent, or unreadable configuration. | Three-stage validation with an offline dry run (§11.3); generation apply/rollback over [docs/networking.md](../networking.md) §5.1 and [ADR-0008](ADR-0008-idempotency.md) (§11.5); safe hold plus [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-19's OS-applied boot ruleset (§11.5) | ADR-0023, [ADR-0008](ADR-0008-idempotency.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| **R-49** | An unattended device fails silently, or resolves a failure by dropping protection because nobody is watching and nobody complains. | An unattended deployment MUST escalate every terminal or persistently-degraded condition through at least one channel that requires **no TwinVPN-operated service**, MUST NOT reduce enforcement on any automatic path, and MUST NOT leave enforcement removed after a crash, crash loop, OOM kill, resource-budget exhaustion, or a failed reload. | Escalation ladder with a local-first floor (§11.16); watchdog credential derived from a fresh `ProtectionAssertion` (§11.16); shedding ladder that structurally excludes enforcement (§11.14); KS-21 unreachable from any automatic path (§11.9, §11.16) | ADR-0023, [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0015](ADR-0015-observability-and-diagnostics.md) |

Requirements this ADR imposes on itself: **E-01** every OpenWrt statement names the actual
subsystem (`procd`, `netifd`, `fw4`, `ubus`, UCI, `logd`) and its behaviour; **E-02** every
resource number is a **budget with its hardware class**, falsifiable by §14; **E-03** no mechanism
here may require a TwinVPN-operated network service for enrolment, configuration, diagnosis, or
escalation; **E-04** where a platform affordance does not exist, the ADR says what is *deferred*
versus *committed* rather than silently narrowing R-21.

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| **C-01** | OpenWrt **21.02** is the pinned minimum; datapath is in-tree `wireguard`, route/address control is UCI + `netifd`, firewalling is `fw4`/nftables, change events arrive on `ubus` `network.interface`. | [docs/networking.md](../networking.md) §5.2 |
| **C-02** | The smallest supported target has **64–128 MB RAM shared with the whole system** and **8–16 MB flash** with a read-only squashfs root plus a JFFS2/UBIFS overlay. Flash has a finite erase-cycle budget; a log written to it is a hardware failure with a delay fuse. | Brief §10; OpenWrt 21.02 targets |
| **C-03** | The C library is **musl** or uClibc. There is no `systemd`, no `journald`, no D-Bus, no `polkit`. The shell is busybox `ash`. | OpenWrt |
| **C-04** | **No secure element.** [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 fixes `hardware_backed = false`, file-backed, no attestation, for router/OpenWrt — *always*. Cloning is undefended there ([docs/threat-model.md](../threat-model.md) TM-13, AD-10). | [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3, C5 |
| **C-05** | No camera, no screen, no notification centre, no app store, no user session, and frequently no human within a hundred metres of the device when it fails. | R-21 |
| **C-06** | The device is usually **not idle infrastructure**: it is the household's only router. Its LAN, WAN, DHCP, DNS, and firewall are already configured and load-bearing before TwinVPN is installed. | [docs/networking.md](../networking.md) §5.5 |
| **C-07** | Enforcement must be installable by an artifact the **OS itself applies** before the agent starts (KS-19), and two-rulesets-never-zero (KS-17) holds here as everywhere. | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, §11.8 |
| **C-08** | The registry admits **thirteen domains** and at most three segments. `MGMT` is a new domain owned by [ADR-0017](ADR-0017-local-management-interface.md); `PLATFORM` is owned by [docs/architecture.md](../architecture.md) §2.5. This ADR may contribute only **subdomains**, by delegation. | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2; [docs/reliability.md](../reliability.md) §3.1 |
| **C-09** | iOS, iPadOS, and Android admit **no** headless profile: no unsandboxed long-lived process the operator can run, no shell, no config file with an authority, no CLI. A platform fact, not a scoping choice. | Brief §10; [docs/networking.md](../networking.md) §5.4 |
| **C-10** | macOS system-extension approval and the Windows WinTun driver install each require **one** interactive administrative act (or an MDM/Group Policy equivalent) that cannot be performed from a shell on a never-touched machine. | [docs/networking.md](../networking.md) §5.2, §5.3 |

## 4. Considered Alternatives

The decision is a single package: *how the headless/embedded profile is realized, and what is
authoritative for configuration*. Splitting those two questions produces designs that are
individually coherent and jointly contradictory — which is exactly the **I8** failure this ADR
exists to prevent.

| | Alternative |
|---|---|
| **A** | **Separate headless product.** A distinct `twinvpnd` for Linux/router with its own configuration language, control path, and release train, developed alongside the GUI clients. |
| **B** | **Headless as a degraded mode of the GUI build.** One build; the daemon runs with no UI attached; the durable settings store the GUI writes *is* the configuration; the CLI is a thin client poking the same store. No config file with independent standing. |
| **C** | **Imperative CLI only, daemon-owned durable intent.** One product, one management contract, no configuration file. All intent lives in the daemon's durable store and is mutated by CLI calls; provisioning is a script of those calls; `config show` is an export, never an input. |
| **D** | **Fully declarative: the config file is the sole authority for everything.** The daemon holds no independent durable intent and is a pure reconciler; every fact it enforces — including peer trust — is declared in the file; the CLI writes the file. |
| **E** | **One product, one management contract; a declarative `IntentDocument` authoritative for a *declared subset* of facts and explicitly not authoritative for learned or `Owner`-signed facts; compiled by the daemon into a monotone `IntentGeneration`; platform-native front-ends (UCI on OpenWrt) render into the same document; embedded is a build profile of the same core.** *(selected)* |

## 5. Advantages of Each Alternative

**A.** The embedded build can be ruthlessly minimal, sharing nothing with a GUI codebase that does
not care about 8 MB of flash. Router idioms (UCI, `ubus`) are native rather than adapted. Release
cadence decouples from app-store review, a real scheduling advantage for
[ADR-0021](ADR-0021-packaging-distribution-and-updates.md). It is the fastest route to a working
`.ipk`, and the first thing most teams reach for.

**B.** Minimum new surface: no second configuration language, no second persistence format, and no
parity question at all, because the CLI and GUI demonstrably read the same bytes. Cheapest to
build and cheapest to keep correct in the small.

**C.** Exactly one writer for every fact, by construction — **I8** is trivially satisfied and the
whole class of "the file says one thing and the running system another" bugs cannot occur.
Idempotency is [ADR-0008](ADR-0008-idempotency.md)'s already-solved problem. Provisioning scripts
are ordinary programs: easy to write, test, and re-run.

**D.** The most operator-legible model there is: the device's entire state is a file you can read,
diff, version, and re-apply. Fleet management is `scp` plus `reload`; disaster recovery is
restoring one file; drift has exactly one definition. It has won in infrastructure tooling for a
decade and operators arrive already knowing it.

**E.** Keeps D's legibility for the facts an operator actually authors while refusing to let a file
become a trust root — the one place D is structurally unsafe here. One management contract
satisfies **H3** and makes CLI/GUI parity mechanically checkable rather than aspirational. The UCI
front-end means LuCI, `uci`, `sysupgrade` backup/restore, and the CLI all agree with no second
config database. Embedded being a *profile* rather than a fork means an embedded-tier defect is
caught by the same conformance suite as the desktop, and the feature matrix is a build input rather
than a code path.

## 6. Disadvantages of Each Alternative

**A.** Two implementations of the state machine, policy evaluator, and contract handling is the
defect factory this corpus exists to avoid; it contradicts **H1** directly and makes
**R-04**/**R-20** compatibility claims unverifiable across the two. Worse, it makes R-21's *"the
same control contract as the GUI"* false by construction — the phrase in
[docs/architecture.md](../architecture.md) §2.1 is not decorative — and every ADR in the corpus
acquires an "and on the headless product…" clause.

**B.** A GUI's settings store is a record of what the user clicked, not a document with a schema, a
version, a validator, or a diff. Making it the configuration means no dry run, no review before
apply, no fleet distribution, no comment explaining why `max_admitted_peers` is 24, and no way to
answer "what changed" after an incident. It fails R-21 on its face — "config-file and CLI control"
is the requirement and a settings blob is neither. On H-EMB it also means a config database
parallel to UCI, which `sysupgrade` will silently drop.

**C.** Provisioning becomes a *script*, and a script is not a description of desired state: it is
one path to it, correct only from one starting state. Reviewing intent means reading a program;
restoring a device means replaying one. It has no answer for the OpenWrt operator whose entire
tooling is declarative UCI. The most damaging version of the failure is silent: two devices
provisioned by the same script from different starting points end up different, and nothing
detects it.

**D.** Fatal here, for a specific reason. A file authoritative for *everything* is authoritative
for the `TrustedPeer` set — so a file on disk can add a peer to the `TwinNet`. That is a second
writer for S-02/S-05 (**I8**) and, far worse, it makes a plaintext file on a
`custody_class = SOFTWARE_PORTABLE` router into an authorization path, directly violating **I4**/**P4**.
It also has no honest home for learned state — S-14, S-15, S-31 — so a pure reconciler either
discards them at every reload (destroying **R-11**'s control-plane-free reconnect) or keeps a
second undeclared store, which is D with the **I8** violation merely hidden.

**E.** The genuine cost is a **classification boundary that must be maintained**: every new fact has
to be assigned to Class I, L, or T (§11.4), and a misassignment is exactly the two-writer bug the
model exists to prevent. It is also two authoring front-ends rendering to one model — one more
parser and one more round-trip property to test — and the CLI-writes-the-file path introduces a
compare-and-swap failure mode (`MGMT.CONFIG.GENERATION_CONFLICT`) that C does not have. §14
condition 4 is the falsification trigger for whether that friction is acceptable.

## 7. Security Implications

**7.1 The bearer-credential question, stated before it is answered.** Every headless-enrolment
design reaches for a token, and a token is a bearer credential. **P4** rejects "any account
password, shared secret, exportable credential, or server-escrowed private key **as an
authentication path**." The load-bearing words are the last four. §11.7 resolves the tension by
showing that the mechanism of §11.6 introduces no secret any subsequent authentication consults,
and names the residual that remains.

**7.2 Identity custody is the dominant residual, and it is not new.**
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 already fixes router/OpenWrt at
file-backed with no attestation, and [docs/threat-model.md](../threat-model.md) TM-13 already lists
cloning among the **accepted residual risks**. What this ADR adds is the *deployment* consequence
(§11.8): an H-EMB device is typically physically accessible, its flash unencrypted, and it is never
inspected — so "an attacker with disk access" is not hypothetical here the way it is for a phone.
The hard prohibition that follows is EM-31: a `SOFTWARE_PORTABLE` device MUST NOT hold an OSK bearing
`ENROLL`, `REVOKE`, or `DELEGATE`, because a cloned router that can enrol devices is compromise of
the `TwinNet` rather than of one node ([docs/threat-model.md](../threat-model.md) TM-12).

**7.3 The management surface must not become a network surface.**
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-22 makes remote disarm structurally
impossible by ensuring **no wire message means "disarm."** On OpenWrt there is a second bus that is
not the wire: `ubus`. `rpcd` + `uhttpd` bridge it to HTTP for LuCI, so an `ubus` method is one
configuration line from being network-reachable. §11.9 makes it normative that TwinVPN registers no
`ubus` method reducing enforcement — which is the platform-specific complement to
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-14: PS-14 permits an
administrative action over SSH on a headless host, and an `ubus` method behind `rpcd` is an HTTP
method wearing a local transport's clothes.

**7.4 A config file is an authorization surface if you let it be one.** §11.4's Class-T rule is a
security control, not a tidiness rule: it is what keeps a world-readable mistake on a router from
being a `TwinNet` membership change.

**7.5 Diagnostics are an exfiltration surface with no human to inspect the preview.**
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9 step 3 relies on a rendered preview a
user reads. §11.11 replaces "a human looked at it" with "the artifact is mechanically verifiable and
the preview is byte-derived from the artifact that would be shared" — which is stronger, and is the
one place the headless profile is *more* defensible than the GUI one.

**7.6 What is unchanged.** Nothing here alters **I1** (relays still see ciphertext), **I2** (no new
primitive; the terminal QR is a rendering of an existing `PairingOffer`), or **I5** (§11.16's
optional escalation to the `Owner`'s admin devices is explicitly best-effort and non-gating).

## 8. Reliability Implications

**8.1 Nobody is watching, so silence is the dominant failure mode.**
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's four anti-silence mechanisms survive
here except the fourth's presentation half: there is no screen to be red. §11.16 replaces the
screen with a local-first escalation ladder whose floor — syslog carrying `reason_code` as a
structured field — needs no TwinVPN service and no network.

**8.2 The watchdog is the mechanism most often built wrong.** A watchdog fed by a dedicated timer
thread proves the timer thread is alive, which is not the property anyone wants: it converts a
wedged reconciler into a green light. §11.16 requires the credential to derive from a **fresh
`ProtectionAssertion`** ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6(1)),
composing with assertion expiry (O-18) rather than duplicating it.

**8.3 Restart is the normal recovery path, and must be cheap and safe.** `procd` (H-EMB) or
`systemd` (H-SRV) respawns into the architecture §2.1 contract: rehydrate, re-enter
`RECONNECTING`, never `DISCONNECTED`-from-scratch. What makes that safe is that enforcement rules
are kernel-resident and outlive the process
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, OpenWrt row: ✔ across crash,
`SIGKILL`, update, and reboot). A crash loop must therefore be *held*, not resolved by disarming
(§11.16).

**8.4 Resource exhaustion is a reliability event with a security failure mode.** The tempting
response to memory pressure — shed a peer, shed the ledger, shed the firewall reconciler — is
correct for the first two and catastrophic for the third. §11.14 fixes the shedding order and makes
enforcement structurally not a candidate.

**8.5 Flash is a consumable.** A design writing a log line per state transition to a JFFS2 overlay
destroys a 16 MB flash chip on a normal duty cycle. §11.11 and §11.12 budget write *rate* rather
than file size, and default to a RAM ring with no flash write at all.

## 9. Performance Implications

**9.1 The binding constraint on GC-0/GC-0U is CPU, not memory — which inverts the usual tuning.** §11.13
works the arithmetic: sixteen peers of fixed state on a GC-0 router cost single-digit megabytes
against a 128 MB system, while aggregate ChaCha20-Poly1305 throughput on a 580 MHz MIPS 24Kc core
without crypto acceleration is tens of megabits per second. The correct knob at saturation is a
**per-peer rate ceiling** plus [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s fairness
machinery — not a lower `max_admitted_peers`, which would reintroduce the one-client-at-a-time
defect (**I7**) as a performance tuning.

**9.2 The userspace datapath is where R-21 and physics meet.** R-21 requires that a userspace option
*exist*, and one is shipped; on H-SRV and H-CTR it is a supported steady state. On GC-0 it is three
to five times slower than the kernel module with a real resident-set cost, so §11.14 makes the
daemon refuse *gateway* peers on it unless explicitly forced. The second-order consequence for
**H1**: a garbage-collected-runtime userspace datapath would carry a resident set of tens of
megabytes and disqualify this tier on memory grounds alone. The embedded profile is therefore an
independent argument for [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s memory-safe
*systems* language, recorded as a dependency in §11.20.

**9.3 Cold start is a protection-window question, not a UX one.** What matters is **time to
`RULESET_BLOCKED` installed**, and on H-EMB that is not the daemon's to control: KS-19 requires the
boot ruleset to be applied by `fw4` before the daemon runs. §11.14 budgets both; §14 falsifies them.

**9.4 Startup cost is dominated by validation, and that is the right trade.** Full three-stage
validation before any system state changes costs milliseconds and buys R-48. A design validating
lazily would start faster and occasionally start *wrong*.

## 10. Operational Implications

**10.1 The operator's toolchain is SSH, `scp`, `logread`, `uci`, and cron.** Everything here is
designed to compose with those: single-file bundles, `--out -` to stdout, line-delimited JSON, a
parse-stable health file, and exit codes that mean something to `set -e`.

**10.2 `sysupgrade` is the OpenWrt event most likely to lose state.** `/etc/config` survives by
default; other files under `/etc` survive only if listed in `/lib/upgrade/keep.d/`. §11.19 places
S-65 and the identity/trust set under both mechanisms, and
[ADR-0021](ADR-0021-packaging-distribution-and-updates.md) owns shipping the `keep.d` entry.
Getting this wrong silently de-enrols every router in a fleet on a firmware upgrade — a failure
discovered days later.

**10.3 There is no rollback of an operator, only of a generation.** §11.5's transactional reload
means the worst outcome of a bad edit is a device running the previous generation, saying so
loudly, and still reachable over SSH — never one that must be power-cycled and re-flashed.
"Blocked must not mean bricked" ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-20) is
the same principle at the enforcement layer, and §11.16 extends it: the management socket and the
diagnostic path remain available in every hold state.

**10.4 Fleet operation is out of Phase 1 scope, and must not be foreclosed.** No fleet-management
service, remote configuration push, or central inventory is specified. What is committed is the
*shape* that makes one possible later: a schema-versioned intent document any existing tooling can
generate and distribute, an offline `config check` to run before distribution, and a
machine-readable health surface. **E-03** forbids making any of it depend on a TwinVPN-operated
service.

---
## 11. Decision

**Alternative E is adopted.** The normative content follows.

### 11.1 The deployment-profile taxonomy (normative)

**Rule EM-1.** These are four profiles, not one target. A build declares exactly one, and the
profile is a build-matrix input to
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md), not a runtime branch.

Every profile below is [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s host
class **HC-3 (headless)**; this ADR subdivides HC-3 by *deployment shape*. **Silicon is a third,
separate axis — `GC-*`, §11.13** — and the three MUST NOT be conflated: `H-EMB` names a deployment
profile and has no clock speed, so it MUST NOT be used as a silicon label, and `HC-0` MUST NOT be
minted for silicon either, because `HC-*` is already ADR-0016's host-class axis. An `HC-0` meaning
"128 MB MIPS" beside an `HC-1` meaning "attended, privilege-separated" would recreate, in a second
document, exactly the ambiguity that makes ADR-0013's `G1` unusable. See EM-54 for the full
three-axis table.

| Profile | Target | Supervisor / init | libc | Config front-end | Phase-1 status |
|---|---|---|---|---|---|
| **H-SRV** | Headless Linux server / always-on gateway; x86-64 or arm64; ≥ 512 MB RAM; writable disk; also **Windows Server Core 2019+** and **macOS with no user session** | `systemd` (Linux), SCM (Windows), `launchd` (macOS) | glibc or musl | TOML `IntentDocument` | **Committed** |
| **H-EMB** | OpenWrt 21.02+ router; MIPS/ARM; 64–128 MB RAM; 8–16 MB flash, squashfs + overlay | `procd` | musl / uClibc | **UCI** (`/etc/config/twinvpn`) | **Architecture, contract, build target, and resource envelope committed. The shipped `opkg` feed and per-target images are future-compatible** (see EM-3) |
| **H-CTR** | OCI container or minimal VM appliance; ephemeral rootfs; config injected at start | PID 1 is the daemon, or an external orchestrator | glibc or musl | TOML, injected read-only | **Committed** |
| **H-CLI** | CLI-only use on an otherwise-GUI-capable host (Linux, macOS, Windows) where the GUI is absent, not installed, or simply never opened | Whatever [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) specifies for that platform | native | TOML | **Committed** |

**Rule EM-2 — what "future-compatible" means for H-EMB, precisely.** It means: the architecture
MUST NOT foreclose it, the resource envelope of §11.14 is a **binding budget on the Phase-2 core**,
the coexistence design of §11.15 is normative, and P22 is a mandatory proof test that runs on real
GC-0 hardware. It does **not** mean an `opkg` feed, per-target images for the full OpenWrt target
matrix, or a LuCI application ship in the first release. The line is drawn at **artefact
production and distribution breadth**, never at architecture or contract: a design that cannot
serve H-EMB is non-conforming today, whereas a release that has not yet built an `ath79` image is
merely incomplete.

**Rule EM-3 — the platform matrix, all ten targets.**

| Target | Headless profile | Config file | CLI | Notes and named limits |
|---|---|---|---|---|
| **Linux** | H-SRV, H-CTR, H-CLI | ✔ TOML | ✔ | The reference profile. `systemd` unit, `CAP_NET_ADMIN`, no desktop session assumed. |
| **OpenWrt / routers** | **H-EMB** | ✔ **UCI** | ✔ | §11.13, §11.14, §11.15. Kernel `wireguard`, `netifd` proto handler, `fw4` include, `procd` supervision, `logd`/`logread`. |
| **Windows** | H-SRV (**Server Core / Nano**), H-CLI | ✔ TOML | ✔ | Server Core has no desktop shell, so H-SRV is real and not a curiosity. **Named limit:** WinTun driver installation requires an administrative act; on a never-touched machine that is Group Policy / MSI silent install, not a shell command — `PLATFORM.EMBEDDED.APPROVAL_REQUIRES_UI`. |
| **macOS** | H-SRV (`launchd` daemon, no user session), H-CLI | ✔ TOML | ✔ | **Named limit:** a NetworkExtension **system extension** requires one interactive user approval or an MDM `SystemExtensionPolicy` payload. There is no shell-only path. Committed with that dependency stated; `PLATFORM.EMBEDDED.APPROVAL_REQUIRES_UI`. |
| **Containers / VMs** | H-CTR | ✔ injected | ✔ | `NET_ADMIN` required; identity custody is `SOFTWARE_PORTABLE` unless a host secrets store is mounted (§11.8). |
| **iOS** | **none** | ✘ | ✘ | C-09. No unsandboxed process, no shell, no config file with authority. Configuration is by MDM profile, which is [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)/[ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) territory, not this ADR's. `PLATFORM.EMBEDDED.NO_HEADLESS_PROFILE`. |
| **iPadOS** | **none** | ✘ | ✘ | As iOS, and **explicitly not "iOS but bigger" here**: Stage Manager, an external display, a hardware keyboard, and Files integration do **not** create a control surface. A configuration file dropped into Files is specifically **refused** — an unmediated file in a user-writable location would be a second writer for Class-I intent (**I8**) with no authority path, which is precisely the mistake §11.4 exists to prevent. |
| **Android** | **none** | ✘ | ✘ | C-09. `adb shell` is a debugging channel, not a supported control surface, and MUST NOT be one. Managed configuration is a DPC concern. |
| **Headless gateways (generic)** | H-SRV | ✔ | ✔ | Same as Linux; the distinguishing property is "no user ever logs in", handled by §11.16. |
| **CLI-only on a GUI host** | H-CLI | ✔ | ✔ | The GUI may be installed and simply unused. §11.9's parity rule is what makes this identical in capability to the GUI. |

### 11.2 Per-profile feature matrix (what is compiled out)

**Rule EM-4.** Feature selection is a **compile-time** decision expressed in
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s build matrix. A feature compiled out
MUST NOT be reachable at runtime and MUST NOT merely be hidden; a request for it over the
management interface returns `PROTO.CAPABILITY_MISSING` (existing, [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md))
and the capability is absent from the device's advertised `Capability` set (S-19).

| Feature | H-SRV | H-EMB | H-CTR | H-CLI |
|---|---|---|---|---|
| GUI / native shell | absent | absent | absent | present, unused |
| Localization catalogues | all | **one locale + `DOMAIN` fallbacks** ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) X7), ≤ 96 KB | all | all |
| Tier-0 structured ledger ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.1) | full, on disk | **reduced ring, tmpfs, 256 KB** | full | full |
| Tier-1 bundle generation | ✔ | ✔, **capped at 512 KB** | ✔ | ✔ |
| Tier-2 aggregate telemetry | opt-in | **compiled out** — it is opt-in and there is no user present to opt in | opt-in | opt-in |
| Crash reporting | opt-in | **compiled out** | opt-in | opt-in |
| QR **encoder** (terminal pairing offer, §11.6) | ✔ (~6 KB) | ✔ (~6 KB) | ✔ | ✔ |
| QR **decoder** (camera) | absent | absent | absent | absent |
| Kernel datapath | ✔ | ✔ (in-tree `wireguard`) | ✔ | ✔ |
| Userspace datapath (R-21) | ✔ supported steady state | ✔ **constrained**, §11.13 | ✔ | ✔ |
| DNSSEC validation | ✔ | **compiled out by default**; a `+dnssec` build variant exists | ✔ | ✔ |
| In-product update client | ✔ | **compiled out** — `opkg` is the updater ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) | ✘ (image is the unit) | ✔ |
| Per-app routing | n/a (Linux) | n/a | n/a | platform-dependent |
| Multi-window / external display | n/a | n/a | n/a | n/a |

**Rule EM-5.** The **English** `summary`/`next_action` catalogue MUST NOT be compiled out of any
profile. It is the realization of **I6** on a device with no other explanation surface; a build
that emits bare `reason_code`s with no text is non-conforming.

### 11.3 The configuration document: format, schema, and validation

**Rule EM-6 — one model, two authoring front-ends.** The normative model of a TwinVPN
configuration is an `IntentDocument` whose schema is defined in
[ADR-0003](ADR-0003-network-contract-schema-format.md)'s deterministic-CBOR schema language, the
same language the wire contract uses. Two human-authoring front-ends deserialize into it:

| Profile | Authoring form | Location | Why |
|---|---|---|---|
| H-SRV, H-CTR, H-CLI | **TOML** | `/etc/twinvpn/twinvpn.toml` (+ `conf.d/*.toml`, merged in lexical order) | Comments, unambiguous scalars, a small parser |
| H-EMB | **UCI** | `/etc/config/twinvpn` | It is the platform's configuration database |

Format alternatives evaluated: **YAML** is rejected — implicit typing (the "Norway problem"),
indentation-sensitivity in a file an operator edits over a serial console, anchors and merge keys
that make a config file a small programming language, and a parser an order of magnitude larger
than TOML's, which is both a flash cost and a fuzz surface ([docs/threat-model.md](../threat-model.md)
TM-24). **JSON** is rejected: no comments, and a configuration a human maintains needs to record
*why*. **Raw dCBOR** is rejected as an authoring form: it is the model, not the file. **INI** is
rejected: no nesting, no arrays, no types.

**Rule EM-7 — UCI is the platform-native answer on OpenWrt and MUST NOT be fought.** Shipping a
TOML file on OpenWrt would create a second configuration database that `uci`, LuCI, and
`sysupgrade` do not know about, and that `sysupgrade` will drop. The UCI front-end is therefore
normative for H-EMB, not an alternative to the TOML one. The two front-ends MUST round-trip: for
every `IntentDocument`, both renderings exist and both parse back to the identical document. This
is a property test obligation on
[docs/testing-strategy.md](../testing-strategy.md) §2.11.

**Rule EM-8 — versioning.** The document MUST carry `schema_version` (integer, monotone,
required, and the first key of the TOML file / a `config twinvpn 'meta'` section in UCI). A build
MUST accept any `schema_version` in its declared supported range and MUST refuse a higher one with
`MGMT.CONFIG.SCHEMA_VERSION_UNSUPPORTED` rather than parsing it partially. Migration of an older
document to a newer schema is performed **in memory at compile time**; the file on disk is never
silently rewritten, because a tool that edits the operator's file is a second author.

**Rule EM-9 — unknown keys are a hard error.** An unrecognised key at any level MUST produce
`MGMT.CONFIG.UNKNOWN_KEY`, naming the key, its location, and the nearest known key by edit
distance. This deliberately **inverts** the forward-compatibility rule that governs the wire
([ADR-0003](ADR-0003-network-contract-schema-format.md), [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)),
and the inversion is correct: on the wire, an unknown field comes from a peer that may legitimately
be newer, so ignoring it preserves interoperability. In a local config file, an unknown key comes
from a human on this device, and ignoring it is how `kill_swtich = "always_on"` becomes an
unprotected router with a confident operator. The failure modes are opposite, so the rules are
opposite.

**Rule EM-10 — three validation stages, all before any system state changes.**

| Stage | Checks | Code on failure |
|---|---|---|
| **1. Parse** | Syntax of the authoring form | `MGMT.CONFIG.PARSE_ERROR` — evidence `file`, `line`, `column` (`OPERATIONAL`) |
| **2. Schema** | Types, ranges, enums, required keys, unknown keys, cross-field constraints expressible in the schema | `MGMT.CONFIG.SCHEMA_INVALID`, `MGMT.CONFIG.UNKNOWN_KEY` — evidence `pointer`, `expected` |
| **3. Admissibility** | The document against **live facts**: referenced `device_id`s are `TrustedPeer`s (S-05); declared prefixes do not collide (§11.15); declared limits fit the measured envelope ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) MG-15); the platform supports every declared mode (e.g. per-app routing on Linux → `NET.PERAPP_UNSUPPORTED`, [docs/networking.md](../networking.md) §7.1) | `MGMT.CONFIG.SEMANTIC_INVALID`, `MGMT.CONFIG.PEER_UNKNOWN`, `MGMT.CONFIG.RESOURCE_ENVELOPE_EXCEEDED` |

**Rule EM-11 — the dry run is a first-class command.** `twinvpn config check [--file F]` MUST run
all three stages, MUST mutate nothing, MUST be runnable **while the daemon is stopped** (stages 1
and 2 fully; stage 3 degrades to the checks that do not need live state, and says which it
skipped), and MUST exit non-zero on any failure. This is what makes fleet distribution safe
without a fleet-management service (**E-03**).

### 11.4 Configuration authority: the three fact classes (the **I8** rule)

**Rule EM-12.** Every fact the daemon acts on belongs to exactly one class, and the class fixes
its writer.

| Class | Definition | Authoritative writer | Examples |
|---|---|---|---|
| **Class I — `Owner` intent** | What the operator wants to be true, and would want restored after a reinstall | **The `IntentDocument`**, authored by the `Owner` via the file or the CLI, compiled by the daemon into **S-65** | enforcement mode, routing mode, protected scope, advertised subnets, `max_admitted_peers`, log level and destination, LAN-discovery on/off, which peers to auto-connect, per-peer route acceptance |
| **Class L — learned or derived** | What the daemon discovered, measured, or negotiated | **The daemon**, under existing rows | `Endpoint` cache (S-15), `Path` set and candidate ledger (S-14), measured relay quality (S-31), per-peer datapath state (S-21), measured custody (S-54, [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)), resource envelope (**S-68**) |
| **Class T — `Owner`-signed trust** | Who is a member, what is revoked, what policy says | **`Owner` authority (2.22)** / control plane, under existing rows | S-02, S-03, S-05, S-06, S-07, S-32, S-33 |

**Rule EM-13 — the `IntentDocument` MUST NOT declare a Class-T fact.** This is the direct answer
to "the config file declares a peer and the daemon also holds runtime peer state." It does not.
A configuration file **references** a `device_id` and expresses intent *about* it; it can never
establish that the `device_id` is trusted. A reference to a `device_id` that is not a
`TrustedPeer` under S-05 is a stage-3 validation failure with `MGMT.CONFIG.PEER_UNKNOWN` and the
next action "pair the device first" — **never** an implicit enrolment. There is therefore no
merge, no reconciliation, and no second writer: trust and intent are different facts.

Attempting to express one anyway (a hand-added `[peer.trusted]` block, a pasted public key) is
refused with `MGMT.CONFIG.IMMUTABLE_FIELD_WRITE_REFUSED` at stage 2, because the key is not in the
schema (EM-9 catches it) and the diagnostic names the reason rather than the typo.

**Rule EM-14 — within Class I, the document is authoritative and the daemon's copy is compiled.**
The daemon compiles the document into an `IntentGeneration`: a monotone integer plus the content
hash of the canonical dCBOR encoding, stored durably as **S-65**. The daemon never writes the
document. The CLI writes the document *as the operator's proxy* and then asks the daemon to
recompile. There is exactly one authoring path and exactly one compile path.

**Rule EM-15 — CLI mutation is compare-and-swap on the document.** `twinvpn config set …` MUST:
(1) take an exclusive advisory lock (`flock`) on the document; (2) read it and compute its hash;
(3) refuse with `MGMT.CONFIG.GENERATION_CONFLICT` if that hash differs from the one the daemon
last compiled *and* `--force` was not given; (4) write via `write` + `fsync` + `rename` to be
crash-atomic; (5) request a recompile. On H-EMB steps 1–4 are performed through `uci set` /
`uci commit`, so LuCI, `uci`, and the CLI cannot diverge. If a `uci` change lands without a
recompile, the daemon detects the hash mismatch at its next reconciler tick and reports
`MGMT.CONFIG.FRONTEND_DIVERGED` — it does **not** auto-apply, because auto-applying a
half-finished edit is worse than reporting one.

**Rule EM-16 — durable intent versus ephemeral action.** A command that changes behaviour **across
a restart** MUST write intent. A command that does not MUST NOT. `twinvpn peer connect X` is an
action; `twinvpn config set peer.X.auto_connect true` is intent; `twinvpn peer connect X --persist`
is the explicit promotion of one into the other. Ephemeral deltas live in **S-66**, are
non-durable by requirement, and are enumerated by `twinvpn config diff`, which shows compiled
intent versus effective state. A device whose behaviour after a reboot would differ from its
behaviour now MUST be able to say so, and that command is how.

### 11.5 Reload, conflict, and invalid configuration at boot

**Rule EM-17 — reload is a transaction over a generation.** `twinvpn config reload` (also `SIGHUP`
on H-SRV, `reload_config` / `/etc/init.d/twinvpn reload` on H-EMB) MUST: validate all three stages
→ compile a candidate generation → compute an ordered apply plan against the live generation →
apply it through [docs/networking.md](../networking.md) §5.1's `apply(contract_generation)`, which
is all-or-nothing and idempotent on the generation id ([ADR-0008](ADR-0008-idempotency.md)) → on
any step's failure, `rollback(previous_generation)` in full and emit
`MGMT.CONFIG.RELOAD_ROLLED_BACK` naming the failed step and the generation still in force. A
partially applied configuration is never a resting state.

**Rule EM-18 — reload MUST NOT open an enforcement window.** During the transition the effective
enforcement mode is `max(live, candidate)` over
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-22's total order
(`OFF < ARMED_ON_INTENT < ALWAYS_ON`). A candidate that *lowers* enforcement takes effect only
after the new rule set is installed and a `ProtectionAssertion` confirms it, by the atomic swap of
KS-17 — never by removing rules first. This is KS-23's update rule applied to configuration
reload, and it is stated here because a reload is the more frequent event.

**Rule EM-19 — some fields are not reloadable, and the daemon says so instead of half-applying.**
Changing the profile, the state directory, the identity store location, or the management-socket
path requires a restart. A reload touching one MUST refuse the whole generation with
`MGMT.CONFIG.RESTART_REQUIRED`, naming the fields, and MUST continue running the live generation.

**Rule EM-20 — invalid configuration at boot MUST NOT fail open, and MUST NOT brick the host.**
Three cases, exhaustively:

| Case | Behaviour |
|---|---|
| A previously compiled, valid generation exists in S-65 | Start on that generation. Enter the enforcement posture it implies. Emit `MGMT.CONFIG.INVALID_AT_BOOT` **persistently** (not once) naming the live generation number and the validation failure. **Refuse all mutations** until the document is fixed or explicitly superseded — a device running configuration the operator cannot see in the file is a trap, so it is loudly announced and frozen rather than quietly accepted. |
| No valid generation exists (first boot; wiped state) | Enter **safe hold**: the daemon runs, serves only the management interface (`status`, `config check`, `diag`, `pair`), and **programs zero network state** — no interface, no route, no address, no resolver change, no forwarding. Emit `MGMT.CONFIG.NO_VALID_GENERATION` and `PLATFORM.EMBEDDED.SAFE_HOLD`. |
| The document is absent entirely | Identical to the previous row. Absence is not consent to a default configuration. |

**Why safe hold is the correct fail-closed behaviour and "block everything" is not.**
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.1 defines *protected traffic*
normatively. With no valid generation there is no `TwinNet`, no peer, and no declared protected
scope, so **the protected set is empty** and fail-closed over the empty set is a no-op. Blocking
the household's Internet because TwinVPN cannot parse its own configuration would not discharge
**I3**; it would be an unrelated denial of service wearing I3's clothes. What **I3** does require
is that TwinVPN emit nothing on behalf of any peer and claim nothing — which is exactly safe hold.

**The boot ruleset is what actually holds the line, and it is not the daemon's.** KS-19 requires
the interval between the network stack coming up and the agent starting to be covered by an
artifact **the OS applies**. On H-EMB that is a `fw4` include, part of persisted configuration
(§11.15); on H-SRV it is `twinvpn-killswitch.service`, `Before=network-pre.target`. That artifact
is a persisted product of the **last known-good generation** and is applied regardless of whether
the current document parses. An invalid document therefore cannot open a protected scope that was
previously closed — the fail-closed property does not depend on the daemon reading its config at
all, which is the whole point of KS-19.

### 11.6 Headless enrolment (normative)

**Rule EM-21 — the C-B ceremony does not require a camera; it requires a confidential channel.**
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4's C-B path is defined by a 32-byte
`pairing_secret` that "never transits the network" and reaches the approving device over an
out-of-band channel. A camera reading a screen is one such channel. **An operator's authenticated
shell session on the device, plus their own eyes, is another**, and it carries the same 256 bits.
Headless targets therefore use **C-B, unchanged**, and do not fall back to C-A's ~2^29.9.
This is a *transport* specified by this ADR, not a new ceremony, and it introduces no new
cryptography (**I2**).

**Rule EM-22 — four enrolment channels.**

| # | Channel | Ceremony | When | Authorization |
|---|---|---|---|---|
| **E1** | **Terminal QR.** `twinvpn pair begin --qr` renders the `PairingOffer` as a QR made of Unicode half-block glyphs (or `--qr=ascii` using `##`/`  ` pairs where `LANG` is not UTF-8) on the controlling terminal. The operator's paired admin device photographs the terminal. | [ADR-0007](ADR-0007-device-identity-and-pairing.md) **C-B**, 256-bit | Default whenever the terminal is ≥ 71 columns × 37 rows | OSK holding `ENROLL` (C-D) |
| **E2** | **Text offer.** `twinvpn pair begin --text` renders the same dCBOR bytes as Crockford base32 in groups of eight, for copy-paste into the admin device. | **C-B**, 256-bit | Small terminals; serial consoles; `PLATFORM.EMBEDDED.ENROLMENT_TERMINAL_TOO_SMALL` steers here automatically | OSK `ENROLL` |
| **E3** | **Reverse ceremony.** The admin device generates the offer; the operator transports it into the headless device: `twinvpn pair accept --offer -`. The headless device displays nothing. | **C-B**, 256-bit | Operator has physical access to an admin device with a camera and shell access to the target | OSK `ENROLL` |
| **E4** | **First-boot provisioning.** At first boot the device generates its identity and **emits** a `PairingOffer` to a declared local sink: a file (mode 0600), the serial console, or a `ubus` event. A provisioning system carries it to an OSK holder. | **C-B**, 256-bit | Appliance and fleet installation | OSK `ENROLL`, offline, batchable |
| — | SPAKE2 9-digit code | [ADR-0007](ADR-0007-device-identity-and-pairing.md) **C-A**, ~2^29.9 | **Retained as the last resort only**, e.g. a 7-bit 40-column serial line where even E2 is impractical | OSK `ENROLL` |

**Rule EM-23 — no TwinVPN artifact may contain a pre-shared enrolment secret.** Not an image, not
a package, not a configuration file, not a `keep.d` entry. An image is copied; a secret in an
image is a shared secret across every unit produced from it, which is precisely what **P4**
rejects. E4's direction of travel is therefore **outbound from the device** — the device generates
its own identity and *emits* an offer — never inbound. First-boot generation MUST be gated on a
first-boot marker written to the **overlay** (not the read-only root), so re-imaging produces a
new identity and snapshotting a provisioned unit is detectable rather than routine.

**Rule EM-24 — offer handling.** The `PairingOffer` is classified `SECRET` in
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4 terms: **no rendering path into the
ledger, syslog, bundle, or any log level exists**. The CLI MUST refuse to write it to a
non-terminal stdout unless `--offer-out <path>` is given explicitly, and MUST then create that
path with mode 0600 — `PLATFORM.EMBEDDED.ENROLMENT_CHANNEL_UNSAFE`. `pairing_id` is public and MAY
be logged; `pairing_secret` MUST NOT be. The offer is invalidated at the daemon on first use or at
120 s, whichever is first ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4); a second use
is `AUTH.PAIRING_ATTEMPTS_EXCEEDED` (existing).

**Rule EM-25 — what the CLI presents.** After a ceremony the CLI MUST print the peer's label and
the **full twenty-character** `fingerprint` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)
N-3 — never truncated), the ceremony method used (`C-B` / `C-A`), and the joining device's
`custody_class` (§11.8). For E4 the approving side's prompt MUST be gated on an
`expected_fingerprint` supplied out of band by the provisioning record (a label on the unit, a
manufacturing record); where none exists, approval is manual and the CLI says so.

### 11.7 The enrolment token and **I4**/**P4** — the tension resolved, and the residual named

**The claim.** `pairing_secret` is **not an authentication path**, and therefore the mechanism of
§11.6 does not violate **P4**.

**Why, in three steps.**

1. **What is enrolled is a key that never existed anywhere else.** The headless device's
   `DeviceIdentityKey` is generated *on the device* and is non-exportable
   ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-5). `pairing_secret` does not become,
   derive, wrap, or escrow it. **I4** is untouched.
2. **No subsequent authentication ever consults it.** After the ceremony, every authentication is
   the data-plane handshake against `TrustedPeer`/`PairSecret`
   ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.6). `pairing_secret` is destroyed with
   the ceremony. There is no code path in which presenting it authenticates anything, which is the
   exact property **P4** demands ("reject any … shared secret … **as an authentication path**").
3. **What it authenticates is a channel, for 120 seconds, once.** Its role is identical to the QR
   code's, and it is bounded by the same expiry, the same single-use `pairing_id`, and the same
   independent authorization gate: an OSK holding `ENROLL` must approve, and the approval displays
   the joining device's fingerprint (EM-25).

**The residual, stated plainly.** An adversary who reads the offer inside the 120-second window
and wins the race can complete the ceremony **as a device they control** — enrolling *their* key,
never impersonating the router and never obtaining the router's key. The OSK holder is the
remaining defence, and they defend only if they read the fingerprint. This is exactly
[docs/threat-model.md](../threat-model.md) **TM-11**, already accepted corpus-wide for the QR path.

**What is genuinely new here, and its mitigation.** The offer transits an SSH session, and SSH
sessions land in scrollback buffers, `tmux` capture files, `script(1)` typescripts, and terminal
recorders. Camera-and-screen has no such artifact. EM-24's rules exist for that reason, and one
more is added:

**Rule EM-26.** The CLI MUST print, immediately above every rendered offer, a one-line warning
naming the exposure ("this block is a 120-second pairing secret; do not paste it into a ticket, a
chat, or a terminal recording"), and MUST emit a terminal-clear sequence over the offer region on
completion or expiry where the terminal supports it. Neither mitigates a recorder, and the ADR
does not claim they do — they reduce accidental persistence, which is the actual observed failure
mode.

**Rule EM-27 — the residual is recorded, not absorbed.**
[docs/threat-model.md](../threat-model.md) TM-11's residual column MUST be extended to state:
*"On a headless target the offer transits the operator's terminal session and may persist in
scrollback or a session recording; the 120-second window is a wall-clock bound on the ceremony,
not on the artifact."* This is registered as a required interface in §11.18.

### 11.8 Identity custody with no secure element

[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 already decides the *mechanism* (file
backed, `hardware_backed = false`, always, for router/OpenWrt). This ADR owns the **deployment
consequence**.

**Rule EM-28 — `custody_class` has exactly one writer, and it is not this ADR.**
[ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) ST-9 computes `custody_class` at each
start from a live probe of the Tier-1 backend and records it in **S-54**
(`KeyCustodyDescriptor`), whence it feeds
[ADR-0007](ADR-0007-device-identity-and-pairing.md)'s `hardware_backed` claim and the `Capability`
advertisement (S-19). This ADR **consumes S-54 and declares no second copy** — a device that
measured its own custody independently would be exactly the two-writer defect §11.4 exists to
prevent. What this ADR owns is the **deployment consequence of each class**.

**`custody_class` is a minimum, not a location.** ADR-0020 probes **two** Tier-1 backends — the one
holding the identity private half (IK, whose custodian is
[docs/architecture.md](../architecture.md) §2.6) and the one holding the vault's own encryption key
and anti-rollback anchor (SEK/ANCH, §2.20's) — and records `custody_class` as the **weaker of the
two**, so it can never overstate. This ADR consumes that fail-safe reading and MUST NOT quote S-54
as "where the identity lives". It changes nothing on H-EMB, where both backends are files and both
are `SOFTWARE_PORTABLE`; it matters on **H-SRV/H-CLI under macOS Developer ID**, where a SEP-backed
IK alongside a System-keychain SEK yields `SOFTWARE_LOCAL` rather than `HARDWARE_ATTESTED`, and on
**H-CTR**, where a mounted host secrets store raises only whichever half it actually covers.

| `custody_class` (S-54, ADR-0020 ST-9) | Where it lands here | Deployment consequence owned by this ADR |
|---|---|---|
| `HARDWARE_ATTESTED` | Not reachable on H-EMB; reachable on H-SRV/H-CLI with a TPM | No restriction. |
| `HARDWARE_UNATTESTED` | H-SRV/H-CLI with a TPM but no usable attestation | No restriction, but peers MUST NOT treat the claim as evidence ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6). |
| `SOFTWARE_LOCAL` | H-SRV/H-CLI without a TPM; H-CTR with a host secrets store | Gateway roles permitted. **OSK powers prohibited** (EM-31). |
| `SOFTWARE_PORTABLE` | **H-EMB, always** (C-04); H-CTR with no secrets store | Gateway roles permitted **with disclosure** (EM-30). **OSK powers prohibited** (EM-31). Steady-state `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE`. |

**Rule EM-29 — the claim is advisory, and trustworthy only downward.** No attestation exists on
`SOFTWARE_PORTABLE` targets *by construction* (C-04), so the advertised class is worth nothing
against an adversary: a peer MUST NOT treat an unattested claim of *better* custody as evidence
([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6). It is trustworthy in the **downward**
direction only — a device claiming worse custody than it has harms no one — which is what makes it
operationally useful (telling the `Owner` what they own) while being security-inert (never a trust
input). Say that to the `Owner` rather than implying a guarantee.

**Rule EM-29a — two distinct conditions, two distinct codes.**
[ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)'s `STORE.CUSTODY_DEGRADED` names a
**transition**: backing dropped below the previously declared class, which forces IK rotation
([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-24).
`PLATFORM.EMBEDDED.IDENTITY_CLONEABLE` names a **steady state**: this device has always been
`SOFTWARE_PORTABLE` and its identity is copyable, which is not a degradation event and must not be
reported as one — it is the permanent, disclosed condition of the entire H-EMB tier.

**Rule EM-30 — a `SOFTWARE_PORTABLE` device MAY be a `LANGateway` or `ExitNode`, and refusing would be
the wrong answer.** R-21 and the home-lab persona exist precisely so that a router can serve a
home subnet; that is the single most valuable thing this target does. But the `Owner` must be
*informed*: at enrolment the approving OSK device MUST display the class and name the consequence
("this device's identity can be copied by anyone who can read its storage; if it is stolen or
imaged, assume the identity is cloned"), matching
[ADR-0007](ADR-0007-device-identity-and-pairing.md) N-16's ceremony-strength disclosure rule; and
the condition is surfaced persistently thereafter as
`PLATFORM.EMBEDDED.IDENTITY_CLONEABLE`. An `Owner` MAY require better via TwinNet policy,
in which case enrolment is refused with the existing `AUTH.ATTESTATION_REQUIRED`.

**Rule EM-31 — the one hard prohibition.** A device whose `custody_class` is `SOFTWARE_PORTABLE` or
`SOFTWARE_LOCAL` MUST NOT hold an `OwnerSigningKey` bearing `ENROLL`, `REVOKE`, or `DELEGATE` power.
This **confirms** [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.5 (OSKs are
secure-element-resident on admin devices) rather than extending it, and the reason is the escalation
noted in [docs/threat-model.md](../threat-model.md) TM-12: a cloned router that can enrol devices
is compromise of the `TwinNet`, not of one node.

**Rule EM-32 — at-rest passphrase wrapping on an unattended device is refused as offered.**
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 permits an Argon2id-passphrase-wrapped
file on Linux. On an unattended device the passphrase must be supplied at every boot, so it either
requires a human at boot — defeating unattended operation — or is stored beside the key, defeating
the wrapping. TwinVPN MUST NOT offer a configuration key that stores an identity passphrase in the
`IntentDocument`. What it MAY offer is `identity.passphrase_command`: an executable that obtains
the passphrase from **outside the device**. If it is set and fails, the daemon MUST enter safe
hold with `PLATFORM.EMBEDDED.IDENTITY_LOCKED` — it MUST NOT proceed without an identity, and MUST
NOT generate a replacement ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-7).

**Rule EM-33 — the deployment residual, for [docs/threat-model.md](../threat-model.md) TM-13.**
An H-EMB device is typically (a) physically accessible in a hallway or a cupboard, often with an
exposed UART header; (b) stored on unencrypted flash readable by removing the chip; and (c) never
inspected by a human. TM-13's "cloning is undefended where `hardware_backed = false`" is therefore
not a theoretical residual on this target but the expected outcome of physical access. The
available response remains detection only — `AUTH.IDENTITY_CONCURRENT_USE` and non-increasing
TAI64N handshake timestamps — and revocation. This text is registered as a required amendment in
§11.18.

### 11.9 The CLI as the complete control surface

[ADR-0017](ADR-0017-local-management-interface.md) **owns the CLI's shape** — the
`twinvpn <noun> <verb>` form generated from its operation catalogue (MI-1), the three output modes,
the exit-code table, the stderr `reason_code` line, and the parity rule (R-28, proof test **P17**
clause A). This ADR is that surface's most demanding consumer, because here it is the *only*
surface. It therefore **consumes those rules verbatim** and adds only what the headless profile
requires on top.

**Rule EM-34 — consumed without modification.** `twinvpn <noun> <verb>` mapped 1:1 onto the
catalogue; `--output human | json | json-lines` with ADR-0017's defaults; exit codes 0–5 with 64+
prohibited; the `reason_code` on stderr in every mode; MI-1's build-failure rule for a verb with no
catalogue entry, or an entry with no verb. This ADR defines **no** competing command table, output
mode, or exit code, and MUST NOT be read as defining one.

**Rule EM-35 — the catalogue nouns this profile requires to exist.** Stated as a requirement on
[ADR-0017](ADR-0017-local-management-interface.md)'s catalogue, not as a CLI design: `status`,
`session`, `peer`, `pair`, `route`, `policy`, `killswitch`, `diag`, `identity`, `gateway`,
`event`, `version`, and — owned here — **`config`** (`check`, `show`, `get`, `set`, `unset`,
`diff`, `reload`). Every operation any GUI performs must appear among these, because on H-EMB and
H-SRV there is nothing else. A capability with no catalogue entry is unreachable on this profile,
which is what makes R-21's "same control contract as the GUI" load-bearing rather than decorative.

**Rule EM-36 — an explicit `--output human` MUST remain available on a non-TTY.**
[ADR-0017](ADR-0017-local-management-interface.md) makes `--output json` the default when stdout is
not a TTY; that default is consumed unchanged. The headless addition is that the operator can still
force the human rendering when stdout is a pipe — `twinvpn status get --output human | tee
incident.txt`, `script(1)` on a serial console, `logger` — because on a headless box the human
rendering is the incident record and there is no window to screenshot. Colour, animation, and
Unicode remain suppressed on a non-TTY (§11.10).

**Rule EM-37 — automation switches on `class`, not on the exit code, for retry decisions.** Exit
codes distinguish *what kind of thing went wrong* (ADR-0017's five). The retry policy is driven by
`Diagnostic.class` ([docs/reliability.md](../reliability.md) §3.1, §6), which is present in the
`--output json` body. An operator's script therefore implements the **same** retry discipline the
daemon does, from the same discriminator: `TRANSIENT` → back off and retry; `PERSISTENT` → wait for
the named `retry_precondition`; `POLICY` → never satisfied by retrying; `FATAL` → stop. Scripts
MUST NOT infer retryability from the exit code alone.

**Rule EM-38 — non-interactive by default.** Every command MUST complete with no TTY and MUST never
prompt. Destructive operations (`identity reset`, `peer forget`, `killswitch disarm`) require an
explicit `--yes`, or `--confirm <expected-value>` where naming the target matters; absent it, and
with no TTY, they exit `2` (usage) rather than prompting, defaulting, or hanging. A command that
blocks on a terminal read is a hung cron job, which on an unattended device is indistinguishable
from a wedge.

**Rule EM-39 — `killswitch disarm` on a headless device: PS-14 consumed, not re-derived.**
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21(1) requires "a local interactive
action on the device itself. No network path, no remote management channel", which is
**unsatisfiable** on a host that never has a local interactive session — the exact targets R-21
makes first-class. [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) **PS-14**
resolves it by host class and owns that resolution; this ADR adopts it verbatim rather than
offering a second reading. For every H-* profile (all of them ADR-0016 host class **HC-3**) the
consequences are:

1. A remote administrative session — SSH, serial-over-network — **is** the headless realization of
   "the `Owner`, present", and an `ADMINISTER` action from it is **permitted and disclosed**, with
   `PLATFORM.PRIV.REMOTE_ADMIN_USED` recording principal, session type, and source
   ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.12). It is never silent.
   On HC-1/HC-2 hosts the same action from a non-console session is refused; that asymmetry is
   PS-14's, and H-CLI running on an attended desktop inherits the **refusal**, not the permission.
2. The principal is established by the transport's attested credentials, never self-asserted
   ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.7): on OpenWrt that is
   `root` over the local `AF_UNIX` transport, because §11.10 gives that tier no second identity.
3. **Parity is not privilege** ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)
   HP-4). Reaching disarm from the CLI is a *request* subject to the same OS-mediated authority as
   any other surface; the CLI bypasses nothing. The consequence text and `--confirm-unprotected`
   of KS-21(3) still apply, and `POLICY.KILLSWITCH.DISARMED_BY_OWNER` is still emitted.

What this ADR adds on top of PS-14 is one platform-specific closure, EM-40.

**Rule EM-40 — the `ubus` bridge is status-and-events only, and off by default.** Consuming
[ADR-0017](ADR-0017-local-management-interface.md)'s OpenWrt row, which makes the bridge optional,
default-off, and this ADR's to own: TwinVPN MAY register read-only `ubus` methods (`status`,
`peers`, `diagnostics`) and MAY emit `ubus` events. It MUST NOT register any method that changes
enforcement, changes trust, mutates the `IntentDocument`, or produces a `PairingOffer`. The reason
is specific rather than general: `rpcd` + `uhttpd` bridge `ubus` to HTTP for LuCI, so an `ubus`
method is one configuration line away from being network-reachable, and enabling the bridge puts
`ubusd` in the TCB. Concretely: **PS-14 permits an administrative action over SSH; it does not
permit one over HTTP**, and an `ubus` method reachable through `rpcd` is an HTTP method wearing a
local transport's clothes.

**Rule EM-40a — the LuCI status page is a read-only subscriber.** Consuming
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) X7 and the router-status-page
delegation in [ADR-0017](ADR-0017-local-management-interface.md): where a LuCI application ships,
it renders the same three parts from the same `tv_render_diagnostic` resolver as the CLI, over the
read-only `ubus` subset of EM-40, and **submits no intents** — no connect, no disconnect, no route
acceptance, no configuration write, and above all no disarm. A write-capable LuCI application is
**deferred**, not foreclosed (§11.1 EM-2); when it ships it MUST arrive as a client of the
[ADR-0017](ADR-0017-local-management-interface.md) catalogue with its own authorization, never as a
widening of the `ubus` bridge.

**Rule EM-41 — parity is [ADR-0017](ADR-0017-local-management-interface.md)'s mechanism, asserted
here on the profile where it matters most.** MI-1 makes a catalogue entry with no verb, or a verb
with no entry, a **build failure**, and P17 clause A asserts it. This ADR adds no second mechanism.
What P22 adds is the *profile* dimension: the same enumeration is run on an H-EMB build, where the
feature matrix (§11.2) has compiled features out — so the assertion becomes "every catalogue
operation **this build advertises** has a verb, and every compiled-out capability is absent from
the catalogue and from S-19 rather than present-but-failing" (EM-4).


### 11.10 Rendering `reason_code`s in a terminal

[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) owns the presentation contract for
codes; this section specifies the **terminal renderer** that consumes it, and binds to
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's explicit obligation that `DEGRADED`
and `BLOCKED` "MUST be visually distinct from the connected state in every surface (GUI, CLI, tray,
headless status output, router status page)."

**Rule EM-42 — the four-line form is ADR-0019’s three parts plus a state line.**
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) §11.4 makes
`tv_render_diagnostic` a **pure** in-core resolver producing three parts, and HP-3/X7 require the
headless surface to consume that resolver and no other. Lines 2–4 below are exactly those three
parts, unmodified; line 1 is the `ConnectionState` and severity, which the GUI carries in chrome
the terminal does not have. The CLI MUST NOT re-word, re-order, or re-translate parts 2–4 — text
rendered for one `Diagnostic` in one locale is identical across GUI and CLI
([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) R-36, asserted by its **P18**
oracle 6). Every terminal or degraded condition renders as exactly:

```
[CRIT] BLOCKED  (peer: nas-attic)
       POLICY.KILLSWITCH.ENGAGED
       Protected traffic is blocked because no authorized secure path exists.
       Next: wait for reconnection, or run 'twinvpn peer disconnect nas-attic'.
```

Line 1 is severity token + state; line 2 is the code, **verbatim and never translated**; line 3 is
`summary`; line 4 is `next_action`, present whenever `user_actionable` is true.

**Rule EM-43 — severity is never carried by colour alone.** The leading ASCII token (`[CRIT]`,
`[ERR!]`, `[WARN]`, `[info]`) is always present. Colour is applied only when stdout is a TTY,
`NO_COLOR` is unset, and `TERM` advertises colour — none of which is true on a busybox `ash`
session over a serial console. The renderer MUST be fully legible in **US-ASCII**; box-drawing and
symbols are used only when `LANG`/`LC_ALL` indicates UTF-8.

**Rule EM-44 — width.** Human output MUST wrap to `min(COLUMNS, 100)` and MUST remain legible at
**80** and at **40** columns. No table in default human output may exceed 80 columns; wider data
requires `--wide` or `--output json`. A serial console at 80×24 is a supported reading environment.

**Rule EM-45 — the aggregate line is unmissable.** `twinvpn status` MUST print the derived
`TwinNet`-scope state ([docs/reliability.md](../reliability.md) §4.7) as its first line, with the
worst active `reason_code`, and MUST NOT render `DEGRADED` or `BLOCKED` in the same visual form as
a steady state. `PERMISSIVE_ANNOUNCED` MUST be printed on every invocation while it holds
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 clause 3).

### 11.11 Diagnostics with no GUI

**Rule EM-46 — the report is a command whose output is the report.** `twinvpn diag report` renders
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8's eight-part connectivity report to
stdout in human form (`--output json` for the structured form). It runs offline and with the control plane
unreachable ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-07). This *is* the headless
equivalent of the button; there is nothing else to invoke.

**Rule EM-47 — the bundle is a file, and on constrained flash it is a stream.**
`twinvpn diag bundle --window 15m --out <path|->`. `--out -` writes the bundle to stdout, so
`ssh router twinvpn diag bundle --window 15m --out - > incident.tvb` produces a bundle with **zero
bytes written to flash**. On H-EMB `--out -` is the documented default workflow and the default
path is `/tmp` (tmpfs); writing to flash requires `--allow-flash-write`.

**Rule EM-48 — redaction is verified mechanically, because there is no preview UI.**
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9 step 3 relies on a human reading a
rendered preview. Headless replaces that with three properties, and the first is load-bearing:

1. **The transcript is byte-derived from the artifact that would be shared.** One pass produces the
   redacted bundle and a human-readable `.txt` transcript **rendered from the redacted structure**,
   never from the raw ledger. `twinvpn diag preview <bundle>` re-renders any bundle offline and
   MUST produce a byte-identical transcript. If the transcript were rendered from raw data, the
   preview would be a lie about the artifact — which is why this is a rule and not an
   implementation note.
2. **The bundle carries a redaction manifest**: per field, its
   [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4 class and the pseudonym token used.
   The per-bundle pseudonym mapping itself is **never** included.
3. **`twinvpn diag verify <bundle>` is a falsifiable check**, exit 0/1, asserting: no
   `SENSITIVE`-classified field appears in raw form; no `SECRET`-classified field *type* appears at
   all; the pseudonym map is absent; the `DeviceKey` signature verifies; the expiry is in the
   future. Redaction remains emitter-side and schema-driven
   ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4, "no scrub-with-regexes step") —
   `verify` is an **independent second check**, not the mechanism.

**Rule EM-49 — size and retention budgets.**

| Artifact | H-SRV / H-CTR | **H-EMB** |
|---|---|---|
| Tier-0 ledger | 64 MB on disk, 30 days | **256 KB ring in tmpfs**, ≈ 2 000 events, **no flash write**; wrap emits `PLATFORM.EMBEDDED.LEDGER_OVERWRITTEN` |
| Tier-1 bundle | up to 16 MB | **hard cap 512 KB**; the requested window is automatically narrowed to fit and `PLATFORM.EMBEDDED.BUNDLE_TRUNCATED` names the window actually achieved |
| Default bundle location | `$STATE_DIR/diag`, 3 most recent | `/tmp`, 1 most recent; `--out -` preferred |
| Bundle retention | 30 days or 3 artifacts | until reboot (tmpfs) |

Narrowing the window rather than truncating the file is deliberate: a bundle cut off mid-structure
is not diagnosable, whereas a shorter *complete* window is.

### 11.12 Logging destination, rotation, and protecting the flash

**Rule EM-50 — log destination per profile.**

| Profile | Destination | Rotation |
|---|---|---|
| H-SRV (Linux) | `journald` via `sd_journal_send` with `REASON_CODE=` as a structured field; `stderr` when `journald` is absent | journald's |
| H-SRV (Windows) | Windows Event Log, one channel, `reason_code` as an event data field | OS |
| H-SRV (macOS) | `os_log` subsystem `com.twinvpn.daemon` | OS |
| **H-EMB** | **`syslog(3)` → `logd` ring, read with `logread`**; `REASON_CODE` as a structured field | `logd`'s in-RAM ring; **no file** |
| H-CTR | stdout, line-delimited JSON | the orchestrator's |

**Rule EM-51 — no log, ledger, or diagnostic artifact is written to flash on H-EMB by default.**
Opting in (`log.file` set) MUST be rate-limited by **bytes per day**, not by file size, because the
resource being consumed is a finite erase-cycle budget and the correct budget for a write-rate
resource is a rate. Default when opted in: **1 MB/day**. Exceeding it emits
`PLATFORM.EMBEDDED.FLASH_WRITE_BUDGET_EXCEEDED`, and the response is to **stop writing and keep
running** — never to stop protecting, and never to exit.

**Rule EM-52 — the durable-write set on H-EMB, and its coalescing rule.** Some state must survive
a reboot even here.

| State | Write cadence on H-EMB |
|---|---|
| S-01 identity, S-05 `TrustedPeer` + `PairSecret` | Once, at generation / pairing |
| **S-18 kill-switch latch**, S-03 revocation epoch, S-32 anchor, S-33 `EpochSeed`, S-37 negotiation floor, S-30 relay-token epoch | **Synchronously, before the action they authorize** |
| **S-65** compiled `IntentGeneration` | Synchronously, on successful compile |
| S-15 `Endpoint` cache, S-31 measured relay quality, S-24 preferences, **the relay clock offset (EM-77)** | **Coalesced**: minimum 60 s between writes per row class, plus a write on clean shutdown |
| S-12 `Session` identity + last state | Coalesced, 60 s |
| S-13 tunnel keys, S-14 path set, S-21 datapath state, S-35 portal grant, **S-66** ephemeral overrides | **Never** (non-durable by requirement) |

**Rule EM-53.** Anti-rollback and enforcement facts MUST NOT be coalesced. A coalesced write of a
monotone security fact is a rollback window: a power cut between the decision and the write leaves
the device believing an older epoch, which is exactly the attack
[docs/threat-model.md](../threat-model.md) TM-29 and
[ADR-0009](ADR-0009-state-consistency.md) §7 defend against. The flash-write budget is spent on
correctness first.

### 11.13 The router as a `LANGateway`, at real scale

**Rule EM-54 — `GC-*` is the silicon axis, and it is a third axis, not a rename of anyone's.**
Three taxonomies exist and they answer three different questions. Conflating any two is what
produced the defects this rule exists to avoid:

| Axis | Question it answers | Owner | Values |
|---|---|---|---|
| **`H-*`** | What is the *deployment shape*? | this ADR (§11.1) | H-SRV · H-EMB · H-CTR · H-CLI |
| **`HC-*`** | What is the *process and privilege shape*? | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11 | HC-1 attended-separable · HC-2 OS-mediated · HC-3 headless |
| **`GC-*`** | What is the *silicon*? | this ADR (§11.13), extending [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s series downward | **GC-0** · **GC-0U** · GC-1/GC-2/GC-3 = ADR-0013's G1/G2/G3 |

Every H-* profile sits in ADR-0016's `HC-3`; only H-EMB is `GC-0`/`GC-0U`. `H-EMB` MUST NOT be used
as a silicon label — it names a deployment profile, and a profile does not have a clock speed.
`HC-0` MUST NOT be used for silicon either, because `HC-*` is already ADR-0016's host-class axis.

**Rule EM-54a — ADR-0013's smallest class is not router silicon, and GC-0 is added below it.**
[ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.5 labels its smallest class "G1 —
Router class" but gives its reference hardware as an RPi 4B (4×Cortex-A72, 2 GB) — a capable
single-board computer, not the OpenWrt 21.02 minimum [docs/networking.md](../networking.md) §5.2
pins. ADR-0013 also reuses `G1…G3` for its **requirement ids**, so "G1" is ambiguous inside its own
text; `GC-1/GC-2/GC-3` here means unambiguously the *hardware-class* sense, and ADR-0013 is asked
to disambiguate its own prefix ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) makes the
same request, and additionally scopes ADR-0013's ~300 Mbit/s figure to *G1-a*). ADR-0013's per-peer
cost model, fairness machinery, admission rules, and the **MG-14 sixteen-peer conformance floor**
are consumed unchanged.

**Rule EM-54b — both classes gate; what is nightly is a *triple*, not a *class*.** An earlier
draft of this rule said "GC-0U gates, GC-0 is nightly". That was **wrong**, and
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) was right to object. The reasoning that
corrects it:

1. **GC-0 is a separately supported target, not merely H-EMB's floor.** `ath79`-class single-core
   MIPS is the modal cheap OpenWrt router; a user who installs on one is someone this product
   claims to support under **R-21**. Leaving it ungated would ship "router-class targets are
   first-class" as a claim nothing tests at release — which is precisely the R-21 defect this ADR
   exists to close. **R-32** ("a supported target MUST meet a gated budget") therefore binds, and
   ADR-0018's promotion of its row 9 to a release gate is correct.
2. **The fragility ADR-0018 worried about is a property of the MIPS *triple*, not of the GC-0
   *envelope*.** `-Z build-std` and a pinned nightly are needed for `mips*-unknown-linux-musl`;
   they are not needed for the class. By **EM-54d** a class is an envelope, and a single-core
   ARMv7 member of the GC-0 envelope has a Tier-2 prebuilt-`std` triple and no nightly dependency
   at all.
3. **Therefore GC-0 gates — but which budgets gate where follows EM-54d's split.**
   [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) made the sharper observation and it
   is adopted here: gating GC-0U at ≤ 13 MB RSS **does not verify** GC-0's ≤ 10 MB, and memory is
   the number that decides whether the thing survives on real hardware — throughput merely
   disappoints, memory kills. So:

   | Budget | GC-0 | GC-0U |
   |---|---|---|
   | RSS (idle, 8 peers, 16 peers) | **Release gate.** Build-derived, so it may be measured on an ARM envelope member if the MIPS build is broken | **Release gate** |
   | Stripped binary / installed / `.ipk` / flash write rate | **Release gate**, same portability | **Release gate** |
   | Kernel and userspace throughput | **Nightly floor on the canonical `ath79` member**, disciplined by §14 condition 1a — *not* a release gate, because it is silicon-derived and an ARM stand-in would measure the stand-in (EM-54d) | **Release gate** (≥ 80 / ≥ 40) |

   This closes the memory hole — the modal cheap router's RSS budget is now verified at every
   release — without putting a release gate behind either an uncontrolled nightly toolchain or a
   throughput number measured on the wrong silicon.

Selection of the specific gating unit is [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s
— it owns the build matrix. This ADR requires only that the unit lie inside the GC-0 envelope of
EM-54d and that its triple ship prebuilt `std`.

| | **GC-0 — no SIMD** | **GC-0U — SIMD present** | *(GC-1, for reference)* |
|---|---|---|---|
| **Class discriminator** | **No SIMD / crypto acceleration** — ChaCha20-Poly1305 runs in scalar code | **SIMD present** (ARM NEON), so the AEAD is 2–4× faster at the same clock | — |
| Canonical member (sets the floor) | MIPS 24Kc @ 580 MHz, **1 core**, 128 MB RAM, 16 MB flash (`ath79`) | Cortex-A53 ×2 @ ~1 GHz, 128 MB RAM, 16 MB flash (`mt7622`) | RPi 4B, 4×A72, 2 GB |
| Other members | MIPS 1004Kc ×2 @ 880 MHz (`mt7621`) — faster than the canonical member, still no SIMD | `ipq40xx` and other NEON-bearing dual-core parts; 256–512 MB variants raise only the peer ceiling, via S-68 | — |
| RAM realistically free for TwinVPN | **~24 MB** | ~24 MB | ~1.5 GB |
| `max_admitted_peers` default | **16** (= MG-14 floor) | **16**, raised to 32 only where S-68's live measurement supports it | 64 |
| **Binding constraint** | **CPU — aggregate ChaCha20-Poly1305 throughput** | **CPU** | aggregate throughput |
| Kernel-datapath aggregate budget | **20–35 Mbit/s** on the canonical member; ~40–70 Mbit/s on `mt7621` (**estimate, unmeasured**) | **≥ 80 Mbit/s** ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) PB-3, derived on A53 — correct for this class as now defined) | ~300 Mbit/s (ADR-0013, scoped to G1-a) |
| Userspace-datapath aggregate budget (shared core, **H1**) | **8–15 Mbit/s** canonical; ~15–30 on `mt7621` (**estimate**), +3–6 MB RSS | **≥ 40 Mbit/s** (PB-3), +3–6 MB RSS | ~90 Mbit/s |
| Per-peer conntrack soft / hard | 128 / 512 | 128 / 512 | 512 / 2 048 |
| Per-peer queue backlog cap | 64 KB | 64 KB | 256 KB |
| Per-peer new-flow rate (burst) | 12/s (48) | 25/s (100) | 50/s (200) |
| Gateway handshake admission rate (burst) | **2/s (8)** | 4/s (16) | 8/s (32) |
| Per-peer memory, typical (128 conntrack) | 5.5 KB fixed + 41 KB + 64 KB ≈ **110 KB** → **~1.8 MB at 16 peers** | as GC-0 | ~326 KB → ~21 MB at 64 |
| Per-peer memory, worst case (hard cap) | ≈ **234 KB** → **~3.7 MB at 16 peers** | as GC-0 | ~900 KB → ~58 MB at 64 |

**Rule EM-54e — a class boundary MUST fall where the binding constraint changes discontinuously.**
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) BM-2c proposes that a silicon-derived
budget name its *measuring member*, not merely its class. That is the right diagnosis and the wrong
remedy. **If a silicon-derived budget needs a measuring-member qualifier to be meaningful, the class
is drawn on the wrong axis and MUST be split — not annotated.** An annotation documents the
ambiguity; a split removes it, and it removes it for every future budget rather than one at a time.

This rule condemns an earlier version of this very table, which grouped `mt7622` (A53, NEON) with
`mt7621` (1004Kc, no SIMD) as "GC-0U — upper embedded", discriminating on **core count** while
§11.13's own binding constraint is **crypto throughput**. On that axis the presence of SIMD is a
larger discontinuity than the second core: NEON is worth 2–4× on ChaCha20-Poly1305, a second
880 MHz scalar core is worth about 2×. The old GC-0U was therefore a chimera by exactly the
standard EM-54a applies to ADR-0013's G1 and BM-1.4 applies to ADR-0018's withdrawn reference —
mine, made the same way, and found by the same question asked one tier up.

**The boundary is now SIMD presence, and `mt7621` moves from GC-0U to GC-0.** Consequences, all of
which cost less than the annotation would have:

- **[ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s ≥ 80 / ≥ 40 needs no
  re-derivation.** It was derived on A53 and GC-0U is now A53-class by definition, so the number is
  correct for its class. BM-2c's open item is closed by construction rather than by choosing a
  weaker member to measure.
- **GC-0's throughput band widens to 20–70 Mbit/s**, which costs nothing: EM-54b already makes GC-0
  throughput a *nightly floor on the canonical member*, and a floor is set by the weakest member —
  `ath79` at 20–35 — not by the band's width. The `mt7621` figures are estimates and are labelled
  as such until measured (**E-02**).
- **No build-derived budget moves.** RAM and flash are 128 MB / 16 MB across both classes, so
  every RSS and size gate in §11.14 is unaffected. Only the silicon-derived rows re-sort, which is
  precisely what EM-54d predicts.

All figures are **budgets with their hardware class stated** (**E-02**); §14 conditions 1 and 1a
falsify them against measurement.

**Rule EM-54d — a class is an envelope, not one SoC.** `GC-0` means *no SIMD / crypto acceleration, 128 MB RAM, 16 MB flash* (EM-54e); `ath79` MIPS single-core is its **canonical member** because that
is what the installed base actually runs, not because the class is MIPS. Any device inside the
envelope is a valid GC-0 reference unit, but **substitution is valid for build-derived budgets
only**. This qualifier is load-bearing and was missing from an earlier draft:

| Budget kind | Examples | Transfers across envelope members? | Gating unit |
|---|---|---|---|
| **Build-derived** | stripped binary, installed size, `.ipk`, RSS at idle and at N peers, persistent-state size, flash write rate | **Yes** — these are properties of the compiled artefact and its allocations, identical on any member built from the same source | Any envelope member, including an ARM stand-in |
| **Silicon-derived** | kernel and userspace datapath throughput, cold-start time, CPU headroom | **No** — a 24Kc MIPS core and a Cortex-A7 at a similar clock differ materially | **The canonical member only.** Measuring a stand-in and reporting it as the class's number would be measuring one thing and naming another | This matters for one concrete reason:
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) needs `-Z build-std` and a pinned
nightly toolchain for the MIPS triples (its BM-2a), and a build-std target has no upstream CI — so a
toolchain advance can break the gate with no external warning. Under this rule the response is to
run the gate on a **single-core ARM member of the same envelope** and keep gating, rather than
losing the class. The class MUST NOT be redefined as ARM to avoid the toolchain problem: defining
hardware around our build tooling rather than around the installed base would quietly drop the most
common cheap router from the supported set while leaving R-21's "first-class" claim standing.

**H-EMB is not equal to GC-0.** H-EMB is a deployment profile and runs on **both** GC-0 and GC-0U;
a budget gate MUST key off the **silicon class**, never off the profile, or GC-0U hardware is
gated at GC-0's floor — the same category error that put a dual-core CPU next to a single-core
memory budget in the first place.

**Rule EM-54c — answering [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s interface
(f), and naming the conflict it exposes.** ADR-0018 BM-1 labels **dual-core Cortex-A53 @ ~1 GHz
(MT7622-class), 128 MB, 16 MB flash** as "H-EMB" and sets PB-3 at ≥ 80 Mbit/s kernel and
≥ 40 Mbit/s userspace. That silicon is **GC-0U**, not GC-0: GC-0 is single-core 24Kc at 580 MHz
with the same 128 MB, and its budgets are 20–35 / 8–15 — a **2–3× gap**, which a single label
hides. The recommendation from this ADR is therefore:

- **ADR-0018 SHOULD scope its PB-3 *throughput* thresholds per class**, with GC-0U at ≥ 80 / ≥ 40
  as a release gate and GC-0's 20–35 / 8–15 as a nightly floor on the canonical member under §14
  condition 1a (EM-54b). After EM-54e re-cut the class boundary on SIMD presence, ≥ 80 / ≥ 40 is
  correct **as derived** — it was measured on A53 and GC-0U is now A53-class — so no re-derivation
  is owed.
  **Two earlier statements in this ADR are withdrawn:** the recommendation to leave GC-0 ungated
  altogether, and an objection to "re-baselining PB-3" — ADR-0018's PB-3 has carried per-class rows
  since BM-1 and never proposed a single global threshold, so that objection was aimed at something
  not in its file.
- **`H-EMB` remains valid in ADR-0018 as the *build-profile* selector** — row 8's target triples,
  the static-link decision, and the feature matrix are profile facts and are unaffected. Only the
  *performance and silicon-derived* numbers need the GC-0U qualifier.
- **Size budgets are unaffected and remain ADR-0018's**: BM-1.1's ≤ 4 MB stripped binary governs
  both classes, because flash is 16 MB on each.

**Rule EM-55 — the honest finding: at 16 peers a GC-0 router runs out of *crypto*, not *memory*.**
Sixteen peers cost under 4 MB worst-case against ~24 MB free. The correct response to saturation is
therefore [ADR-0013](ADR-0013-multi-client-gateway-architecture.md)'s per-peer rate ceiling and
deficit-round-robin fairness with `RESOURCE.CAPACITY.CPU_SATURATED`, **not** a lower
`max_admitted_peers`. Lowering the peer count to make the throughput number look better would
reintroduce the one-client-at-a-time defect (**I7**, R-16) as a tuning parameter, which is exactly
the failure class [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) exists to close.

**Rule EM-56 — admission at the limit is ADR-0013's, unchanged.** At
`admitted_peers = max_admitted_peers` a further peer is refused with
**`RESOURCE.ADMISSION.PEER_LIMIT_REACHED`** ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md)
MG-21), carrying the configured maximum and current count. **No admitted peer is displaced**;
there is no LRU eviction. Handshake bursts are governed by MG-22's token bucket with
`RESOURCE.ADMISSION.DEFERRED` and a `retry_after_ms` hint — note the GC-0 rate above is 2/s (burst
8), so a sixteen-peer herd takes roughly eight seconds to admit, which MG-24 already accepts as
adequate without priority tiers.

**Rule EM-57 — the userspace datapath on GC-0 is not a gateway-grade steady state.** R-21 requires
that a userspace option *exist*, and it does (EM-4). While running it on GC-0, the daemon MUST refuse
to admit new **gateway** peers unless `datapath.allow_userspace_gateway = true` is explicitly set,
and MUST emit `PLATFORM.EMBEDDED.DATAPATH_USERSPACE_CONSTRAINED` naming the measured budget.
Client-role operation on the userspace datapath is unrestricted on every profile.

### 11.14 The embedded resource envelope, and what happens when it is exceeded

**Rule EM-58 — hard budgets.** A build that exceeds these on its reference hardware is
non-conforming; §14 falsifies each.

| Budget | **GC-0** | **GC-0U** | H-SRV |
|---|---|---|---|
| Daemon RSS, idle, 0 peers | ≤ 8 MB | **≤ 8 MB** | ≤ 40 MB |
| Daemon RSS, 8 peers | ≤ 9 MB | **≤ 12 MB** ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) row 8) | — |
| Daemon RSS, 16 peers, typical load | ≤ 10 MB | **≤ 13 MB** | — |
| Incremental RSS per admitted peer (typical) | ≤ 110 KB | ≤ 110 KB | ≤ 326 KB (GC-1) |
| Tier-0 ledger | 256 KB (tmpfs) | 256 KB (tmpfs) | 64 MB (disk) |
| **Stripped binary** | ≤ 4 MB | **≤ 4 MB** ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) BM-1.1 — governing) | — |
| Installed package (binary + English catalogue ≤ 96 KB + scripts) | ≤ 4.5 MB | **≤ 4.5 MB** | ≤ 20 MB |
| Compressed package (`.ipk`) | ≤ 1.8 MB | **≤ 1.8 MB** | — |
| Persistent state on flash, steady | **≤ 64 KB** | **≤ 64 KB** | ≤ 16 MB |
| **Flash write rate, steady** | **≤ 4 KB/day** | **≤ 4 KB/day** | unbounded |
| CPU, idle, 8 peers, no traffic | ≤ 1 % of one core | ≤ 1 % | ≤ 1 % |
| Cold start → `RULESET_BLOCKED` installed | ≤ 2 s (by `fw4`, before the daemon) | **≤ 2 s** | ≤ 1 s |
| Cold start → first peer `WAN_DIRECT` from a cached `Endpoint` | ≤ 8 s | ≤ 6 s | ≤ 3 s |

**Which of these gate a release is EM-54b's split**, not a property of the table: every
**build-derived** row (RSS, binary, installed, `.ipk`, persistent state, flash write rate) is a
release gate on **both** classes; the **silicon-derived** rows (throughput in §11.13, cold start
below) gate on GC-0U and are a nightly floor on GC-0's canonical `ath79` member.

**Size budgets are [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s, not this ADR's.**
BM-1.1's ≤ 4 MB stripped binary governs both silicon classes — flash is 16 MB on each — and the
installed and `.ipk` rows are *derived* from it, to be re-derived rather than defended if BM-1.1
moves. An earlier draft of this ADR carried a ≤ 1.5 MB installed budget, set before ADR-0018 fixed
the Rust static-link floor; it is **withdrawn**.

**Rule EM-59 — the shedding ladder, in fixed declared order, with enforcement structurally
excluded.** RSS is self-sampled every `T_RESOURCE_SAMPLE` (30 s) into **S-68**. On exceeding the
envelope, `PLATFORM.EMBEDDED.MEMORY_PRESSURE` is emitted naming the step reached, and the daemon
sheds in this order and no other:

1. Shrink the Tier-0 ledger ring to 25 % of its budget.
2. Refuse **new** Tier-1 bundle generation (`RESOURCE.CAPACITY.MEMORY_EXHAUSTED`).
3. Reduce the **effective** `max_admitted_peers` to the current admitted count, so no new peer is
   admitted — reported as `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` with the *reduced* limit named,
   never as a silent refusal.
4. Reduce per-peer conntrack hard caps toward their soft caps.
5. **Stop.** There is no step 5. The ladder does not contain "disconnect a peer", because that is
   the **I7** defect, and it does not contain anything touching enforcement, because that is the
   **I3** defect. Enforcement is not a candidate at any step, which is what makes "MUST NOT reduce
   protection" a structural property rather than a promise.

**Rule EM-60 — budget-exceeded behaviour, per budget.**

| Exceeded | Detection | Response | Code |
|---|---|---|---|
| RSS envelope | 30 s self-sample (S-68) | The EM-59 ladder | `PLATFORM.EMBEDDED.MEMORY_PRESSURE` |
| Killed by the OOM killer | Supervisor restart; the nftables rule set survived (kernel-resident) | Restart → rehydrate → `RECONNECTING` (architecture §2.1); emit at `CRITICAL` | `PLATFORM.EMBEDDED.OOM_RESTART` |
| Flash write budget | Per-UTC-day byte counter (durable, S-68) | Stop non-essential writes; keep EM-52's synchronous security writes | `PLATFORM.EMBEDDED.FLASH_WRITE_BUDGET_EXCEEDED` |
| Flash free < 512 KB | `statvfs` at start and hourly | Refuse non-essential writes; if the **essential** set cannot be written, **safe hold** — a device that cannot record a revocation epoch must not act as though it had | `PLATFORM.EMBEDDED.FLASH_EXHAUSTED` |
| Forwarding CPU saturated | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.4 | ADR-0013's fairness and shaping; all peers degrade, none preferentially | `RESOURCE.CAPACITY.CPU_SATURATED` (ADR-0013's) |
| Declared config exceeds measured capacity | Stage 3 validation (MG-15) | Refuse the generation; keep the live one | `MGMT.CONFIG.RESOURCE_ENVELOPE_EXCEEDED` + `RESOURCE.CAPACITY.MEMORY_EXHAUSTED` |

### 11.15 Coexistence with `netifd`, `fw4`, and `dnsmasq`

This realizes [docs/networking.md](../networking.md) §5.5's four coexistence rules on OpenWrt.
The organising principle: **the router's own subsystems are made allies, not obstacles**, because
a subsystem you fight will win at 3 a.m. after a WAN flap.

**Rule EM-61 — the interface is created through a `netifd` protocol handler, not behind
`netifd`'s back.** TwinVPN ships `/lib/netifd/proto/twinvpn.sh`, so a `config interface` with
`option proto 'twinvpn'` is valid UCI and `netifd` owns the interface lifecycle. Consequences:
`netifd` re-invokes us on `ifup`/`ifdown` and on WAN changes instead of tearing our interface down
underneath us; the addresses and routes we install are **declared to `netifd`**, so its own
reconciliation does not delete them — which discharges §5.5 rule 1 ("never delete routes you did
not create") *symmetrically* on this platform; and `ubus` `network.interface` events become our
`subscribe_network_change` source ([docs/networking.md](../networking.md) §5.1, §5.2) with no
polling. A `netifd`-initiated teardown is reported as `PLATFORM.EMBEDDED.NETIFD_TEARDOWN`.

**Rule EM-62 — `netifd` is the applier; the device remains the authority.** S-17 (route
acceptance) keeps its existing writer — the local `Device`. `netifd` holds a derived copy with
`LOCAL` semantics. Concretely, `apply(contract_generation)` is realized as a `proto_send_update`
carrying the generation's addresses, routes, and MTU, followed by awaiting the corresponding
`ubus` `network.interface` event; `rollback` re-issues the previous generation's update.
Idempotency on the generation id ([ADR-0008](ADR-0008-idempotency.md)) is preserved because a
`netifd` proto update is declarative and last-writer-wins per interface. No new writer is
introduced.

**Rule EM-63 — two firewall artifacts, and never zero rules.** KS-17 requires two rule sets and
never zero; on OpenWrt that becomes two *tables* with a strict handover.

| Artifact | Contents | Written to flash? | Applied by |
|---|---|---|---|
| `/etc/twinvpn/killswitch.nft`, referenced by a `config include` (`option type 'nftables'`) in `/etc/config/firewall` | The **boot** rule set — `table inet twinvpn_boot`, fail-closed over the last known-good protected scope | ✔ (this is the persisted artifact KS-19 requires) | **`fw4`, at boot, before the daemon** |
| `table inet twinvpn` | The **live** rule set (`RULESET_BLOCKED` / `RULESET_PROTECTED`), swapped atomically | ✘ — installed over the nftables netlink API, never via a file | the daemon |

Handover: the daemon installs `table inet twinvpn` **and deletes `table inet twinvpn_boot` in the
same nftables transaction**, so there is no instant with zero coverage and no instant with two
independently-dropping base chains at one hook (in nftables an `accept` in one base chain does not
suppress a `drop` in another at the same hook, so two live drop tables would be a self-inflicted
outage, not defence in depth).

**Rule EM-64 — surviving `fw4 reload`.** Any firewall edit in LuCI runs `fw4 reload`, which
flushes and rebuilds `table inet fw4` and **re-runs the includes**. Our live table is untouched,
but our include would re-create `twinvpn_boot`. Three composing mitigations:

1. The include script is **idempotent and self-suppressing**: it no-ops when `table inet twinvpn`
   is already present.
2. The residual TOCTOU window fails in the **safe** direction — a spurious extra drop table blocks
   more, never less — which is the correct direction for **I3**.
3. The [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6(1) `ProtectionAssertion`
   reconciler already queries the installed rule set every tick; it observes the spurious table,
   removes it, and emits the existing `POLICY.KILLSWITCH.ASSERTION_MISMATCH`. No new mechanism is
   invented for a condition the existing one already detects.

Additionally, the `procd` init script MUST register
`procd_add_config_trigger "config.change" "firewall"` and `"network"`, so a UCI change to either
triggers a re-assertion rather than being discovered a tick later.

**Rule EM-65 — `dnsmasq` is extended, never replaced, and our stanza lives in tmpfs.**
[ADR-0011](ADR-0011-dns-handling.md) DN-21's OpenWrt row fixes the mechanism (a
`server=/<zone>/<anycast>` stanza via UCI; `dnsmasq` is not replaced). The realization: the package
sets `dnsmasq`'s `confdir` **once** at install time (the only persistent change TwinVPN makes to
`/etc/config/dhcp`, owner-tagged as a package postinst action), and the stanza itself is written to
a **tmpfs** directory under that `confdir` and regenerated at every daemon start, followed by
`/etc/init.d/dnsmasq reload`. The consequence is that our resolver configuration **cannot survive
us across a reboot and cannot be left behind after an unclean exit** — [docs/networking.md](../networking.md)
§5.5 rule 3's reclamation requirement is discharged by construction rather than by cleanup code
that must itself run. Within a single boot, [ADR-0011](ADR-0011-dns-handling.md)'s
`HostResolverRestorePoint` (S-34) and DN-20's restore entry point remain required and unchanged.
This is offered to [ADR-0011](ADR-0011-dns-handling.md) as a refinement of its OpenWrt row, not a
contradiction of it (§11.18).

**Rule EM-66 — DNS for downstream LAN clients is gateway policy, not this ADR's and not
[ADR-0011](ADR-0011-dns-handling.md)'s.** Confirmed as
[ADR-0011](ADR-0011-dns-handling.md) §10 states; it belongs to
[ADR-0013](ADR-0013-multi-client-gateway-architecture.md).

**Rule EM-67 — router-specific overlay-prefix collision detection.**
[docs/networking.md](../networking.md) §7.5 owns the general CGNAT-collision case (detect at
bring-up against on-link underlay prefixes; request reallocation with
`NET.OVERLAY_PREFIX_COLLISION`). A router adds a case the general rule misses: **its own
configured-but-inactive networks**. A `guest` or `iot` VLAN that is down at boot and comes up an
hour later can collide with the overlay after the check has already passed — the worst variant,
because it appears long after the operator stopped watching.

- At start, and on every `config.change` trigger for `network`, the daemon MUST enumerate the
  **whole configured set**: every `network.@interface[*]` `ipaddr`/`netmask` and `ip6addr`, every
  DHCP pool in `/etc/config/dhcp`, and every `ip6assign` delegated prefix — not merely the
  currently on-link prefixes.
- A collision with a configured-but-inactive prefix is reported **before** it becomes active, as
  `PLATFORM.EMBEDDED.UCI_PREFIX_COLLISION` at `WARN`, naming the UCI section and the prefix. When
  that interface comes up it escalates to the existing `NET.OVERLAY_PREFIX_COLLISION` at `ERROR`
  and the §7.5 reallocation path runs.
- The WAN case is common on this target specifically: an ISP that assigns a `100.64.0.0/10` WAN
  address to the router is the modal CGNAT deployment, and §7.5's reallocation to a different `/22`
  is the answer.
- The other router-specific collision — an advertised LAN subnet colliding with the *client's*
  local LAN, i.e. two homes on `192.168.1.0/24` — is [docs/networking.md](../networking.md) §7.4's,
  already owned. For a home-lab `LANGateway` this is the **modal** case, not the exception, so
  §7.4's remediation 3 (**site remap** into a per-site IPv6 `/96`) is the recommended default
  presentation for H-EMB, with remediation 1 (do nothing, local LAN wins) as the fallback and
  gateway-side NAT (remediation 4) never offered by default.

### 11.16 Unattended operation

**Rule EM-68 — what recovers automatically and what escalates.**

| Condition | Automatic recovery | Escalates |
|---|---|---|
| Path death, peer unreachable, relay failover | ✔ ([docs/reliability.md](../reliability.md) §6, §8) | no (informational) |
| Config reload failed, rolled back | ✘ | **yes** |
| Invalid config at boot | ✘ | **yes** (persistent) |
| Daemon crash | ✔ supervisor restart | only if it recurs |
| Crash loop | ✘ — **held**, see EM-71 | **yes** |
| OOM kill | ✔ restart | **yes** |
| `BLOCKED` persisting beyond `T_UNATTENDED_ALERT` | ✘ | **yes** |
| Retry budget exhausted → `FAILED` | ✘ | **yes** |
| Identity missing or unloadable | ✘ — safe hold | **yes** |
| Flash exhausted for the essential write set | ✘ — safe hold | **yes** |
| Resource shedding engaged (EM-59) | partial | **yes** |

**Rule EM-69 — escalation with no notification centre.** Escalation is **pull-first with three
local push sinks**, and **no escalation path may be a TwinVPN-operated network service**
(**E-03**).

| # | Channel | Availability | Notes |
|---|---|---|---|
| 1 | **Syslog / journald at `ERROR` and `CRITICAL`, with `reason_code` as a structured field** | Always on, every profile | The floor. A router already has a log pipeline; using it beats inventing one. |
| 2 | **A health file**: `$STATE_DIR/health` (tmpfs) holding one parse-stable line — derived `TwinNet`-scope state, worst active `reason_code`, timestamp | Always on | Readable by `cat`, `collectd`, Nagios, or a cron job with no daemon interaction and no management-interface call |
| 3 | **`twinvpn status get --output json`** | Always on | An exec check for any monitoring system, keying on `class` per EM-37 |
| 4 | **A `ubus` event** (`twinvpn.diagnostic`) on H-EMB; `sd_notify(STATUS=…)` plus a `systemd` `OnFailure=` hook on H-SRV | Always on | Read-only, EM-40 |
| 5 | **In-band to the `Owner`'s paired admin devices** over the existing control-plane event channel | **Default: `CRITICAL` only**; configurable, disableable | Best-effort and **non-gating** — it MUST NOT be a control-plane dependency (**I5**). It carries only `PUBLIC`/`OPERATIONAL` fields ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4) because it crosses B3. It is a **device-initiated push to the `Owner`'s own devices**, never a support-initiated pull ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9 — that prohibition is preserved). **Disclosed tradeoff:** enabling it lets the control plane observe that this device is unhealthy, which is metadata it would not otherwise hold; the default is `CRITICAL`-only because for an unattended device with no user, silence is the failure mode **I6** exists to prevent, and a phone in the `Owner`'s pocket is the only screen that exists. |

`T_UNATTENDED_ALERT` (proposed default **300 s**) is requested for registration in
[docs/reliability.md](../reliability.md) §5; until it lands, `T_DEGRADED_MAX` is used
(§11.18). No new state or transition is requested.

**Rule EM-70 — the watchdog credential is a `ProtectionAssertion`, not a heartbeat.**

| Profile | Mechanism |
|---|---|
| H-SRV (Linux) | `systemd` `Type=notify`, `WatchdogSec=60`, `NotifyAccess=main`; `sd_notify(WATCHDOG=1)` |
| H-EMB | `procd` `procd_set_param respawn <threshold> <timeout> <retries>`; **TwinVPN MUST NOT open `/dev/watchdog`** — on OpenWrt `procd` owns the hardware watchdog, and a package that takes it stops `procd` petting it and reboots the router |
| H-CTR | The orchestrator's liveness probe, bound to channel 3 above |
| Absent | `PLATFORM.EMBEDDED.WATCHDOG_UNAVAILABLE` at start; the profile still runs |

The ping MUST be emitted only from a health check that includes a **fresh** `ProtectionAssertion`
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6(1), with its expiry semantics from
O-18). A watchdog fed by a timer thread proves that the timer thread is alive, which is not the
property anybody wants: it converts a wedged reconciler into a green light. This composes with
assertion expiry rather than duplicating it — expiry turns the indicator `UNKNOWN`, and the
watchdog turns a wedge into a restart.

**Rule EM-71 — a crash loop is held, never resolved by disarming.** If the daemon exits abnormally
more than N times within T (defaults: 5 within 300 s), the supervisor MUST stop respawning into a
loop and the device MUST enter **safe hold with the enforcement rule set left installed**, emitting
`PLATFORM.EMBEDDED.CRASH_LOOP_HELD` at `CRITICAL`. The management socket and the diagnostic path
remain available. A crash loop that ends with an unarmed device is the leak
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-20: blocked must not mean bricked, and
its converse — recoverable must not mean unprotected).

**Rule EM-72 — an unattended device MUST NOT resolve a failure by reducing protection, and this is
structural.** Two properties, not two checks:

- **The disarm path is unreachable from any automatic path.** EM-39 makes it require a
  peer-credentialed local caller on the `AF_UNIX` socket plus an explicit verbatim confirmation
  flag. No timer, no reconciler, no supervisor, no policy document, and no `ubus` method can
  satisfy those preconditions.
- **No timer may transition out of `BLOCKED`.** Exit from `BLOCKED` occurs only by an authorized
  secure path being restored ([docs/reliability.md](../reliability.md) §4.4, T30). A "if `BLOCKED`
  for more than N minutes, let traffic flow" convenience is **prohibited** — and it is named here
  because it is exactly the feature an operator will request when a router's household loses
  connectivity.

**Rule EM-73 — the correct answer to that pressure is the protected scope, not a timeout.** On an
H-EMB device acting as a `LANGateway`, the default `protected_scope` is **overlay-only**: TwinVPN's
own overlay traffic, and the traffic of LAN clients the operator has *explicitly* routed through
the tunnel. The household's ordinary Internet traffic is not in the protected set and is therefore
unaffected by `BLOCKED`. Full-tunnel egress for LAN clients is opt-in **per client**. This
dissolves the pressure that produces auto-unblock features, without weakening **I3** for anything
that was ever protected, and it is the deliberate H-EMB deviation from the desktop default where
the user's own machine is the protected scope.


### 11.16a No real-time clock: the RTC-less boot state (normative)

**Rule EM-74 — the deployment fact.** A large fraction of OpenWrt-class hardware ships with **no
RTC**. Such a device boots to epoch 0 or to a fixed build date on **every power cycle**, and there
is no user present to correct it. This is the normal boot state of GC-0/GC-0U silicon, not a corner
case, and it is stated here because no document in the corpus records it. The device MUST detect
the absence of a usable RTC at start and emit `PLATFORM.EMBEDDED.NO_RTC` once per boot as an
informational disclosure carrying the observed boot time.

**Rule EM-75 — first boot is safe hold, so time acquisition is unimpeded.** This is the asymmetry
that makes the problem small, and it follows from EM-20 rather than from anything new. On a first
boot with no valid `IntentGeneration`, the daemon is in **safe hold**: it programs *zero* network
state — no interface, no route, no ruleset. The protected set is empty, so the host's own NTP (or
whatever `sysntpd` the operator configured) is not TwinVPN traffic and is not affected by anything
TwinVPN has installed. **A device therefore acquires time normally before it is ever enrolled**, and
the wall-clock-bounded ceremony expiry of
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 (`not_after_ms = issued + 120 000`) is
evaluated against a clock that has already been set. Enrolment (§11.6) is not exposed.

**Rule EM-76 — the exposed case is re-boot after enrolment under an armed latch, and it is already
solved by [ADR-0005](ADR-0005-relay-architecture.md).** After enrolment, in full-tunnel mode, the
host's NTP is class-2 protected traffic and is dropped
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.2); the KS-19 boot ruleset is applied
by `fw4` before the daemon, so this holds from the instant the network comes up. An RTC-less device
therefore re-enters service with a wrong clock and a durable relay token whose `nbf` lies in its
future. It is **not** deadlocked, for a reason already written down:

- [ADR-0005](ADR-0005-relay-architecture.md) §11.3 — on `RELAY.TOKEN_EXPIRED` the relay returns
  **its own current time**; the device computes an offset, retries once, and holds the offset **for
  token-validity evaluation only**. It MUST NOT set its system clock from it, and does not need to.
- [ADR-0009](ADR-0009-state-consistency.md) K-6 requires exactly this — the relay validates against
  its own clock, never the device's, and the token lifetime must exceed the tolerated skew plus the
  failover budget **"so that a clock-skewed device cannot be locked out of failover"**.
- [ADR-0009](ADR-0009-state-consistency.md) K-2/K-4 make every TTL monotonic-elapsed-since-receipt
  rather than a wall-clock comparison, and state that excessive skew **never blocks a `Session`**.

**No new traffic class is requested from
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), and one MUST NOT be added.** A time-sync
exemption would widen the bootstrap exception — the narrowest and most dangerous row in §11.2, and
the subject of [docs/threat-model.md](../threat-model.md) TM-21 — to obtain a capability the
offset mechanism already supplies without any egress at all. The correct answer to "the router has
no clock" is that **no security decision may need one** ([ADR-0009](ADR-0009-state-consistency.md)
K-1, RQ-9), not that the router should be allowed to ask the Internet what time it is.

**Rule EM-76a — reading the clock naively is unsafe even though the path is not deadlocked.**
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) **CD-1a** is consumed here and is the
mechanism this section depends on: `Clock::wall()` returns `Unset | Offset{source} | Trusted`,
never a bare timestamp, and the core MUST NOT evaluate any validity window — `nbf`/`exp`, TTL,
`not_after`, ceremony expiry — against an `Unset` clock. The reason is the **failure direction**: a
bare epoch-0 read makes **every `nbf` check pass and every `exp` check fail**, which is the worst
possible direction for admission control and is silent. Monotonic time is unaffected, which is why
every [docs/reliability.md](../reliability.md) §5 timer behaves correctly before any offset
arrives. Absence of a deadlock (EM-75, EM-76) is therefore **not** sufficient on its own; the clock
must also be unreadable-as-a-number until it is qualified.

**Rule EM-77 — the one gap this tier actually has: the offset is not durable.** The relay offset of
[ADR-0005](ADR-0005-relay-architecture.md) §11.3 and the skew estimate of
[ADR-0009](ADR-0009-state-consistency.md) K-4 are both derived at runtime and neither is in any
durable-state row. On hardware with an RTC that costs nothing. On an RTC-less device it means the
offset is re-learned **on every boot**, at the price of one deliberately-failed relay bind, and any
condition that fires *before* that first bind completes is evaluated against an epoch-0 clock.
Therefore, on H-EMB:

- The device MUST persist its most recent clock offset alongside the relay token (S-30) as part of
  the **coalesced** write class of EM-52, and MUST re-apply it at start **before** the first relay
  bind and before evaluating any validity window.
- A persisted offset is a **performance and legibility optimisation, never an authority**. It MUST
  NOT be used to set the system clock, MUST be re-derived from the relay on first use each boot,
  and a persisted offset that disagrees with the relay's answer loses.
- If no offset is available and no relay has yet answered, the device MUST proceed with the bind
  anyway and let the retry supply it. It MUST NOT refuse to try on the grounds that its clock is
  implausible — refusing here would convert a one-round-trip delay into the deadlock this section
  exists to rule out.

**Rule EM-78 — the residual, which is not this ADR's to close.**
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §10 makes `not_after_ms`, `effective_from_ms`,
and ceremony expiry wall-clock, and registers **`AUTH.CLOCK_IMPLAUSIBLE` as `PERSISTENT` with
`terminal = yes` and `user_actionable = yes`**. On an attended host that is correct: a human fixes
the clock. **On an unattended RTC-less router it is a terminal state whose remediation nobody is
present to perform** — and its `user_actionable = true` is, for this tier, false. Whether that code
*gates* an operation or merely *reports* is the difference between one slow boot and a bricked
router, and it is [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s to answer. This ADR's
position: under [ADR-0009](ADR-0009-state-consistency.md) K-1/RQ-9 ("no security decision may depend
on the device's clock being correct") it MUST report and MUST NOT gate, and
[docs/threat-model.md](../threat-model.md) **O-6** already records the contradiction between RQ-9
and the corpus's wall-clock security decisions. This tier is where that contradiction stops being
theoretical, and §11.18 carries the interface request.


### 11.17 Reason codes contributed

Registered into [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's machine-readable
registry, in its `DOMAIN.SUBDOMAIN.CONDITION` form. Every code is three segments, ≤ 64 bytes, and
sits inside one of two **delegated subdomains**:

- **`MGMT.CONFIG.*`** — the `MGMT` domain is a **new domain owned by
  [ADR-0017](ADR-0017-local-management-interface.md)**, which **delegates the `CONFIG` subdomain to
  this ADR**. This ADR does not own `MGMT` and MUST NOT register a code outside `MGMT.CONFIG.*`.
  The delegation is recorded as a required interface in §11.18.
- **`PLATFORM.EMBEDDED.*`** — the `PLATFORM` domain is owned by
  [docs/architecture.md](../architecture.md) §2.5, the Platform Network Adapter
  ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2). The `EMBEDDED` subdomain is
  contributed here by delegation, likewise recorded in §11.18.

Codes owned by other ADRs are **cited, never redefined**: `RESOURCE.ADMISSION.PEER_LIMIT_REACHED`,
`RESOURCE.ADMISSION.DEFERRED`, `RESOURCE.CAPACITY.MEMORY_EXHAUSTED`,
`RESOURCE.CAPACITY.CPU_SATURATED` ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md));
`POLICY.KILLSWITCH.*` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)); `AUTH.*`
([ADR-0007](ADR-0007-device-identity-and-pairing.md)); `NET.OVERLAY_PREFIX_COLLISION`,
`NET.PERAPP_UNSUPPORTED` ([docs/networking.md](../networking.md)); `ROUTE.*`
([ADR-0010](ADR-0010-ipv4-ipv6-routing.md)); `DNS.*` ([ADR-0011](ADR-0011-dns-handling.md));
`PROTO.CAPABILITY_MISSING` ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)).

| `reason_code` | class | severity | terminal | actionable | Meaning / user-facing text / next action |
|---|---|---|---|---|---|
| `MGMT.CONFIG.PARSE_ERROR` | PERSISTENT | ERROR | no | yes | The configuration file could not be read. *"Line N of `<file>` is not valid `<format>`."* Next: fix the line; run `twinvpn config check`. |
| `MGMT.CONFIG.SCHEMA_INVALID` | PERSISTENT | ERROR | no | yes | A value has the wrong type or is out of range. Names the pointer and the expectation. Next: correct the value; `config check`. |
| `MGMT.CONFIG.UNKNOWN_KEY` | PERSISTENT | ERROR | no | yes | An unrecognised key was found and **rejected, not ignored** (EM-9). Names the key and the nearest known key. Next: fix the spelling or remove it. |
| `MGMT.CONFIG.SCHEMA_VERSION_UNSUPPORTED` | PERSISTENT | ERROR | no | yes | The document declares a `schema_version` newer than this build supports. Next: upgrade TwinVPN, or lower the document's version. |
| `MGMT.CONFIG.SEMANTIC_INVALID` | PERSISTENT | ERROR | no | yes | The document is well-formed but inadmissible against live facts. Names the conflicting fact. Next: as stated in the evidence. |
| `MGMT.CONFIG.PEER_UNKNOWN` | PERSISTENT | ERROR | no | yes | The document references a `device_id` that is not a `TrustedPeer`. A configuration file **cannot** enrol a device (EM-13). Next: `twinvpn pair begin` first. |
| `MGMT.CONFIG.IMMUTABLE_FIELD_WRITE_REFUSED` | POLICY | ERROR | no | yes | The document attempted to declare a trust fact (Class T). Next: use the pairing or policy path; trust is never file-authored. |
| `MGMT.CONFIG.RESOURCE_ENVELOPE_EXCEEDED` | PERSISTENT | ERROR | no | yes | The declared limits exceed measured capacity ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) MG-15). Names the limit, the requirement, and the measurement. Next: lower the limit. |
| `MGMT.CONFIG.INVALID_AT_BOOT` | PERSISTENT | CRITICAL | no | yes | The device is running the last valid generation N because the current document is invalid; mutations are refused (EM-20). Next: fix the document and reload. **Persistent while it holds.** |
| `MGMT.CONFIG.NO_VALID_GENERATION` | PERSISTENT | CRITICAL | no | yes | No valid configuration has ever been compiled; the device is in safe hold and programs no network state. Next: `twinvpn config check` then `reload`. |
| `MGMT.CONFIG.GENERATION_CONFLICT` | TRANSIENT | WARN | no | yes | The document changed beneath a CLI mutation (EM-15). Next: re-read and retry, or `--force`. |
| `MGMT.CONFIG.RESTART_REQUIRED` | PERSISTENT | WARN | no | yes | A field that cannot be reloaded changed; the live generation is unchanged (EM-19). Next: restart the service. |
| `MGMT.CONFIG.RELOAD_ROLLED_BACK` | PERSISTENT | ERROR | no | yes | Applying a generation failed part-way and was rolled back in full; names the failed step and the generation still in force. Next: as stated in the evidence. |
| `MGMT.CONFIG.FRONTEND_DIVERGED` | PERSISTENT | WARN | no | yes | The authoring front-end (UCI) no longer matches the compiled generation — an edit landed without a reload. Next: `twinvpn config diff`, then `reload`. |
| `PLATFORM.EMBEDDED.SAFE_HOLD` | PERSISTENT | CRITICAL | no | yes | The daemon is running but programs **no** network state; the management and diagnostic surfaces remain available. Names the precondition. Next: satisfy it. |
| `PLATFORM.EMBEDDED.MEMORY_PRESSURE` | TRANSIENT | WARN | no | yes | The RSS envelope was exceeded; names the shedding step reached (EM-59). Next: reduce `max_admitted_peers`, or move to larger hardware. |
| `PLATFORM.EMBEDDED.OOM_RESTART` | PERSISTENT | CRITICAL | no | yes | The daemon was killed by the OOM killer and restarted; enforcement rules survived. Next: inspect the envelope; see the evidence for peak RSS. |
| `PLATFORM.EMBEDDED.CRASH_LOOP_HELD` | PERSISTENT | CRITICAL | no | yes | Respawn was suppressed after repeated abnormal exits; **enforcement is retained** (EM-71). Next: collect a bundle and restart deliberately. |
| `PLATFORM.EMBEDDED.FLASH_WRITE_BUDGET_EXCEEDED` | POLICY | WARN | no | yes | The daily flash-write budget was reached; non-essential writes stopped, operation continues. Next: reduce logging, or direct logs off-device. |
| `PLATFORM.EMBEDDED.FLASH_EXHAUSTED` | PERSISTENT | CRITICAL | no | yes | Free flash is below the floor. If the essential write set cannot be written the device enters safe hold. Next: free space on the overlay. |
| `PLATFORM.EMBEDDED.LEDGER_OVERWRITTEN` | TRANSIENT | INFO | no | no | The Tier-0 ring wrapped; the retained window is shorter than requested. Names the achieved window. |
| `PLATFORM.EMBEDDED.BUNDLE_TRUNCATED` | TRANSIENT | INFO | no | yes | The requested bundle window was narrowed to fit the size cap. Names the window achieved. Next: request a shorter window explicitly. |
| `PLATFORM.EMBEDDED.DATAPATH_USERSPACE_CONSTRAINED` | PERSISTENT | WARN | no | yes | Running the userspace datapath on constrained hardware; names the throughput budget. New gateway peers are refused unless explicitly allowed (EM-57). Next: install the kernel module, or set `datapath.allow_userspace_gateway`. |
| `PLATFORM.EMBEDDED.IDENTITY_LOCKED` | PERSISTENT | CRITICAL | no | yes | `identity.passphrase_command` did not yield a usable passphrase; the device holds rather than proceeding without an identity (EM-32). Next: supply the passphrase source. |
| `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE` | PERSISTENT | WARN | no | yes | Steady state, not a degradation: `custody_class = SOFTWARE_PORTABLE` (S-54), so this device's identity can be copied by anyone who can read its storage; if it is stolen or imaged, assume it is cloned (EM-29a, EM-30). Next: acknowledged at enrolment; use hardware with a secure element where the gateway role warrants it. |
| `PLATFORM.EMBEDDED.NO_HEADLESS_PROFILE` | PERSISTENT | ERROR | yes | yes | This platform admits no headless profile (iOS, iPadOS, Android — C-09). Next: manage this device from its application. |
| `PLATFORM.EMBEDDED.APPROVAL_REQUIRES_UI` | PERSISTENT | ERROR | no | yes | A one-time interactive or MDM approval is required (macOS system extension, Windows driver install) and cannot be performed from a shell. Next: approve locally once, or deploy the MDM/Group Policy payload. |
| `PLATFORM.EMBEDDED.UCI_PREFIX_COLLISION` | PERSISTENT | ERROR | no | yes | A configured-but-inactive UCI network overlaps the overlay prefix (EM-67). Names the UCI section and prefix. Next: renumber that network, or request overlay reallocation. |
| `PLATFORM.EMBEDDED.NETIFD_TEARDOWN` | TRANSIENT | WARN | no | no | `netifd` brought the overlay interface down; re-establishing. |
| `PLATFORM.EMBEDDED.ENROLMENT_CHANNEL_UNSAFE` | POLICY | ERROR | no | yes | Refused to write a `PairingOffer` to a non-terminal sink (EM-24). Next: run on a terminal, or pass `--offer-out <path>` deliberately. |
| `PLATFORM.EMBEDDED.ENROLMENT_TERMINAL_TOO_SMALL` | PERSISTENT | WARN | no | yes | The terminal is smaller than 71×37, so the QR form is unavailable. Next: enlarge the terminal, or use `--text`. |
| `PLATFORM.EMBEDDED.NO_RTC` | PERSISTENT | INFO | no | no | This device has no real-time clock and boots with a wrong wall clock every power cycle (EM-74). Carries the observed boot time. Not a fault: validity windows are evaluated monotonically and via the relay-supplied offset (EM-76/EM-77). |
| `PLATFORM.EMBEDDED.WATCHDOG_UNAVAILABLE` | PERSISTENT | WARN | no | yes | No supervisor watchdog is available on this profile; a wedge will not be detected by restart. Next: run under `systemd`/`procd`, or configure an external liveness check. |

### 11.18 Interfaces required from other ADRs

| Required from | Interface |
|---|---|
| [ADR-0017](ADR-0017-local-management-interface.md) | (a) Explicit **delegation of the `MGMT.CONFIG.*` subdomain** to this ADR. (b) Runtime enumeration of the operation catalogue (`mi.catalogue.get`) **per build profile**, so P22 can assert that a compiled-out capability is absent from the catalogue rather than present-but-failing (EM-4, EM-41). (c) **Peer-credential authorization** on a local `AF_UNIX` transport (`SO_PEERCRED` / `LOCAL_PEERCRED`) resolving to an OS principal, which is what EM-39 rests on. (d) A guarantee that **no management transport is network-exposed by default**, and that a privileged sub-surface (disarm, identity reset) is reachable **only** on the local socket. (e) A resumable **event stream** with a cursor, so `twinvpn watch --since` and the health file survive a daemon restart. |
| [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | (a) A **build matrix** in which `profile ∈ {H-SRV, H-EMB, H-CTR, H-CLI}` selects the §11.2 feature set at compile time, with musl and MIPS/ARM soft-float targets present. (b) A confirmation that the shared core's **userspace datapath** meets §11.13's budgets — **GC-0** ≈ 8–15 Mbit/s and **GC-0U** ≥ 40 Mbit/s (PB-3), +3–6 MB RSS. **Interface (f) is answered by EM-54b/EM-54c: ADR-0018's original PB-3 silicon is GC-0U, and a *separate* GC-0 gate is required — both classes are supported, so under R-32 both gate. The GC-0 gating unit MUST be an ARM member of the EM-54d envelope, so the gate carries no `build-std` dependency; the MIPS triple stays a nightly portability build**; a garbage-collected runtime does not, and that is an embedded-tier argument for H1. (c) A **static or fully-relocatable** link for H-EMB (R-21 names static/relocatable builds). |
| [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | (a) **PS-14 consumed verbatim** (EM-39), including `PLATFORM.PRIV.REMOTE_ADMIN_USED` on every headless `ADMINISTER` action. (b) Confirmation that H-EMB is `privilege_separated = false` — a single root `procd`-supervised daemon with the residual declared in S-38 — which this ADR's §11.1 and §11.16 assume. (c) **One disagreement to resolve:** §11.10 describes the headless build as having "no bundle generator, and no document renderer". This ADR keeps **Tier-1 bundle generation on H-EMB, capped at 512 KB** (EM-47, EM-49), because R-23 and [ADR-0015](ADR-0015-observability-and-diagnostics.md) O-07 require a self-contained connectivity report producible offline, and a router with no bundle generator cannot be diagnosed at all — there is no second surface to fall back to. The *document renderer* may indeed be absent; the bundle generator may not. |
| [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) *(clock)* | **CD-1a** — `Clock::wall()` as `Unset \| Offset{source} \| Trusted`, with no validity window evaluable against `Unset` (EM-76a). This ADR consumes it and does not restate it. |
| [ADR-0005](ADR-0005-relay-architecture.md) / [ADR-0009](ADR-0009-state-consistency.md) | Confirmation that the relay-supplied clock offset (ADR-0005 §11.3) and the K-4 skew estimate MAY be **persisted locally** as a non-authoritative hint, re-derived from the relay on first use each boot (EM-77). Neither ADR currently places them in a durable row, which costs an RTC-less device one failed bind per boot and exposes any pre-bind validity check to an epoch-0 clock. |
| [ADR-0007](ADR-0007-device-identity-and-pairing.md) | (a) Confirmation that **C-B is defined by a confidential out-of-band channel, not by a camera**, so EM-21's terminal transport inherits C-B's 256-bit strength (this removes the pressure behind ADR-0007's revisit condition V3). (b) Confirmation that the `custody_class` consumed here is [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)’s S-54 value feeding `hardware_backed`, and that this ADR declares no second copy. (c) Confirmation of EM-31 (no `ENROLL`/`REVOKE`/`DELEGATE` OSK on a `SOFTWARE_PORTABLE` device) as a restatement of §7.5, not an extension. (d) **A ruling on whether `AUTH.CLOCK_IMPLAUSIBLE` gates or merely reports** (EM-78). This ADR's position is that under [ADR-0009](ADR-0009-state-consistency.md) K-1/RQ-9 it MUST report and MUST NOT gate; on an unattended RTC-less router a terminal, `user_actionable` clock error is a bricked device, and its `user_actionable = true` is false for this tier. Related: [docs/threat-model.md](../threat-model.md) **O-6**. |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | (a0) **No time-sync traffic class is requested, and none should be added** (EM-76). The relay-offset mechanism supplies clock correction with no egress, so a time-sync exemption would widen the bootstrap exception ([docs/threat-model.md](../threat-model.md) TM-21) for a capability already available without it. (a) Confirmation of **[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-14**, which this ADR consumes rather than re-deriving: KS-21(1) is unsatisfiable on a host that never has a local interactive session, and PS-14 resolves it by host class. If ADR-0012 overrules PS-14, a headless device can never be disarmed at all — which collides with KS-20's "blocked must not mean bricked". (b) Confirmation that **safe hold over an empty protected set** (EM-20) satisfies I3, and that the OS-applied boot ruleset of KS-19 is a product of the last known-good generation. (c) Confirmation of the H-EMB two-table handover of EM-63/EM-64 as the OpenWrt realization of KS-17/KS-19. |
| [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) | Acceptance of **GC-0 and GC-0U as silicon classes below its smallest gateway class**, with MG-14's sixteen-peer floor, MG-15's configuration-time refusal, and MG-21/MG-22's admission codes consumed unchanged. This ADR renames none of ADR-0013's classes; ADR-0013 is asked to disambiguate its own `G` prefix (requirement ids vs hardware classes) and to scope its ~300 Mbit/s figure, as [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) also requests. |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) | (a) Registration of the §11.17 codes. (b) Confirmation that a `PairingOffer` is `SECRET`-classified with **no rendering path in any tier or log level** (EM-24). (c) A **redaction manifest** in the Tier-1 bundle and the guarantee that the human transcript is rendered from the redacted artifact, so EM-48(1) holds. (d) Confirmation that `PLATFORM.EMBEDDED.*` is an acceptable subdomain under the `PLATFORM` domain owned by [docs/architecture.md](../architecture.md) §2.5. |
| [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | **X7 accepted in full**: the headless surface consumes the same `tv_render_diagnostic` resolver and the same operation set, ships one locale plus `DOMAIN` fallbacks, and the LuCI status page is a read-only subscriber submitting no intents (EM-40a). Required in return: the three parts must be renderable with **no colour, no Unicode, and a 40-column floor** (§11.10 EM-43/EM-44) — a resolver that emits box-drawing or relies on colour for severity is unusable on a busybox serial console, which would break HP-3 on the profile it matters most for. |
| [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | (a) A durable store that meets EM-52's per-row cadence, distinguishing **synchronous security writes** from **coalesced convenience writes**, on a flash-backed overlay. (b) **S-54 as the sole writer of `custody_class`**, with `SOFTWARE_PORTABLE` as the H-EMB value (ST-9) — consumed here, never duplicated — and acceptance of EM-29a’s split between `STORE.CUSTODY_DEGRADED` (a transition) and `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE` (a steady state). (c) A location for S-65 and the identity/trust set that survives `sysupgrade`. (d) Confirmation that **S-67 holds no key material** and is non-durable, so it lies outside the vault entirely. (e) S-54 SHOULD carry the **asymmetry rule** this ADR relies on and does not own: a *downgrade* of `custody_class` is always accepted and is self-authenticating in the useful direction, whereas an *upgrade* without a verified attestation MUST NOT raise any peer's trust ([ADR-0007](ADR-0007-device-identity-and-pairing.md) N-6). That asymmetry, plus a single writer and a single conflict rule, is what makes [docs/testing-strategy.md](../testing-strategy.md) **G-5**'s demand — that the key-custody battery assert the flag's *accuracy* per target and that a false flag be impossible — assertable at all; a flag with two writers cannot be asserted accurate. |
| [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | (a) `opkg` packaging within EM-58's size budget, shipping the `netifd` proto handler, the `procd` init script with EM-64's config triggers, the `fw4` include, and the `dnsmasq` `confdir` postinst. (b) A `/lib/upgrade/keep.d/` entry covering the identity, trust, and S-65 paths — **without it a firmware upgrade silently de-enrols the fleet** (§10.2). (c) Confirmation that the in-product updater is compiled out of H-EMB. |
| [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | Confirmation that the H-* profiles have **no background/foreground transition at all** — no `EV_BACKGROUND`, no parking ([docs/reliability.md](../reliability.md) §11.2), no wake-to-traffic ladder — so the mobile lifecycle machinery is inert here and the always-on posture is the only posture. |
| [ADR-0011](ADR-0011-dns-handling.md) | Acceptance of EM-65 as a **refinement** of DN-21's OpenWrt row: the stanza in tmfps under `dnsmasq`'s `confdir` makes the row `✔` across reboot while leaving the in-boot `RestorePoint` (S-34) and DN-20 unchanged. |
| [docs/reliability.md](../reliability.md) | Registration of **`T_UNATTENDED_ALERT`** (proposed default 300 s) in §5 as an operability constant. **No new state and no new transition is requested.** |
| [docs/threat-model.md](../threat-model.md) | (a) TM-11's residual column extended with EM-27's terminal-persistence text. (b) TM-13's residual extended with EM-33's physical-access text for H-EMB. Both are additions to existing accepted residuals, not new threat rows. |
| [docs/vision.md](../vision.md) | Merge of R-47…R-49 into §5, and of ADR-0023 into the §7 index against R-21, R-47, R-48, R-49. |

### 11.19 State ownership

Four new rows for [docs/architecture.md](../architecture.md) §5. Existing rows S-01…S-64 are
consumed unchanged; in particular **S-18** (kill-switch engagement), **S-21** (per-peer gateway
datapath state), **S-24** (user preferences), and **S-34** (`HostResolverRestorePoint`) are cited,
not redeclared.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-65** | Compiled `IntentGeneration` — monotone generation number, the content hash of the canonical dCBOR encoding of the `IntentDocument`, and the compiled Class-I intent in force | **Local `Device` — the configuration compiler (2.20)**, whose sole input is the `IntentDocument` authored by the `Owner` | None remote. The authoring file (`/etc/twinvpn/twinvpn.toml`, or `/etc/config/twinvpn` on H-EMB) is the `Owner`'s **input**, not a replica: it records what the `Owner` asked for, S-65 records what the daemon accepted and is enforcing | `LOCAL`; `MONOTONIC` in `generation` | Durable; written synchronously on successful compile; survives `sysupgrade` | Local wins. A document whose hash differs from the stored generation is a **new candidate**, never a merge (EM-15). A `generation` lower than the stored one MUST be rejected as a rollback |
| **S-66** | Effective ephemeral overrides — runtime intent deltas deliberately not written to the `IntentDocument` (EM-16) | **Local `Device` (the daemon)** | None | `LOCAL` | **Non-durable by requirement** — MUST NOT survive process restart; restart restores S-65 exactly | Local wins; absence is the declared safe state, and `twinvpn config diff` is the mechanism that makes divergence visible rather than surprising |
| **S-67** | `HeadlessEnrolmentOffer` — the in-flight `PairingOffer` on a headless device: `pairing_id`, the declared sink (terminal / file / serial / `ubus`), the rendered form, `not_after_ms`, and the single-use consumption flag (§11.6, EM-22…EM-26) | **Local `Device` — Pairing Subsystem (2.7)**. This is the **transport state of a ceremony**, not the ceremony: [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 owns C-B/C-A and S-04 owns the resulting `Pairing`; this row exists only because EM-23/EM-24/EM-26 place rules on the offer's sink, lifetime, and single use that something must hold | None. **`pairing_secret` is `SECRET`-classified and has no rendering path into the ledger, syslog, or a bundle** ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4, EM-24) | `LOCAL` | **Non-durable by requirement** — it MUST NOT survive process restart, and MUST be zeroized on consumption or at 120 s, whichever is first | Local wins; absence is the safe state. A second presentation of a consumed `pairing_id` is `AUTH.PAIRING_ATTEMPTS_EXCEEDED` ([ADR-0007](ADR-0007-device-identity-and-pairing.md)), never a re-issue |
| **S-68** | Embedded resource envelope — measured RAM, free flash, CPU class, and daily flash-write counter; the derived effective limits; and the current shedding step (§11.14) | **Local `Device`** | None | `LOCAL` | Non-durable, **except** the flash-write counter, which is durable and keyed by UTC day | Local wins. A measurement below a configured requirement **refuses the configuration** at compile time ([ADR-0013](ADR-0013-multi-client-gateway-architecture.md) MG-15), and never silently lowers it at runtime |

There is no **I8** violation between S-65 and S-24 (user preferences): S-24 is the local device's
own record of preferences on a GUI platform, whereas S-65 is the compiled form of an
`Owner`-authored document. On a profile where both exist, the `IntentDocument` is authoritative for
every key it declares and S-24 holds only keys it does not — a partition, not an overlap, and one
[ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) must realize.

### 11.20 Assumptions register

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **AS-01** (**H1**) | One portable core in a memory-safe **systems** language behind a stable C ABI holds the engine, state machine, policy evaluation, and contract handling; no business logic is reimplemented per platform | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | §11.1's "profile, not fork" claim collapses into alternative A; §11.2's compile-time feature matrix has no home; §11.13's userspace-datapath budget and §11.14's RSS budgets are both unmeetable with a GC runtime, so the whole H-EMB tier becomes future work rather than committed |
| **AS-02** (**H2**) | On desktop/server-class platforms the client is a privileged long-lived daemon plus a separate unprivileged UI process | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | If the daemon is not privileged and long-lived, EM-39's peer-credential model and §11.16's supervisor integration both need respecifying, and R-21's "headless daemon" is not available |
| **AS-03** (**H3**) | UI, CLI, and local automation reach the daemon over exactly **one** authenticated, schema-versioned management contract, and the GUI has no privileged side channel | [ADR-0017](ADR-0017-local-management-interface.md) | EM-41's parity rule becomes unenforceable and reverts to review; R-21's "same control contract as the GUI" becomes aspirational; §11.9's whole command surface would need its own transport, i.e. alternative A |
| **AS-04** | C-B's security rests on a confidential out-of-band channel, not on optics; `pairing_secret` is never consulted by any later authentication | [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 | §11.6 collapses to C-A everywhere, headless enrolment drops from 2^256 to ~2^29.9 with attempt limiting, and ADR-0007's V3 revisit condition fires immediately |
| **AS-05** | A `SOFTWARE_PORTABLE` device may hold a `DeviceKey` and serve as `LANGateway`/`ExitNode`, with cloning accepted as a residual, and `custody_class` is computed and owned by [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) S-54 | [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3, [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) ST-9, [docs/threat-model.md](../threat-model.md) TM-13 | If hardware backing is made mandatory for gateway roles, R-21 and the home-lab persona lose their primary use case and H-EMB becomes client-only |
| **AS-06** | MG-14's sixteen-peer floor, the per-peer cost model, and the admission codes of [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) apply unchanged to hardware below ADR-0013’s smallest class | [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.5 | §11.13's GC-0/GC-0U rows must be re-derived; if the floor is instead lowered for constrained hardware, **I7** acquires a hardware exemption, which this ADR would contest |
| **AS-07** | The presentation contract exposes `summary`/`next_action` in a form renderable with no colour, no Unicode, and 80 columns | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | §11.10's renderer needs its own text catalogue, duplicating the i18n surface and risking drift from the GUI's |
| **AS-08** | The durable store can distinguish synchronous security writes from coalesced convenience writes, on a flash overlay | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | EM-52/EM-53 cannot be realized; either the flash-write budget of §11.14 is blown, or anti-rollback writes acquire a rollback window |
| **AS-09** | `opkg` packaging can ship a `netifd` proto handler, a `procd` init script, an `fw4` include, and a `keep.d` entry, within EM-58's size budget | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | §11.15's coexistence design is unshippable and H-EMB falls back to a self-managed interface, which fights `netifd` and loses |
| **AS-10** | The H-* profiles have no background/foreground lifecycle; always-on is the only posture | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | If a headless profile can be suspended (a laptop running H-CLI, a container paused by its orchestrator), §11.16's escalation and watchdog assumptions need a suspend case |
| **AS-11** | The Tier-1 bundle's human transcript can be rendered from the redacted artifact, and a redaction manifest can be carried in it | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | EM-48(1) fails and the headless preview becomes a claim about data the operator cannot see, which is worse than the GUI preview it replaces |
| **AS-12** | OpenWrt 21.02+ continues to provide `netifd` protocol handlers, `fw4` includes applied before the daemon, `procd` config triggers, and `procd`-owned `/dev/watchdog` | OpenWrt upstream | §11.15 and EM-70 must be respecified per release; §14 condition 7 is the trigger |

### 11.21 Conformance surface for proof test P22

This ADR guarantees the following observables, so
[docs/testing-strategy.md](../testing-strategy.md) can write P22 against a mechanism rather than an
intention (its Rule PT-4 consumes this surface verbatim).

1. The ceremony method actually used (`C-B` / `C-A`) is recorded in the pairing transcript and is
   readable from the Tier-0 ledger.
2. The daemon's compiled `IntentGeneration` number and content hash (S-65) are readable via
   `twinvpn config show --output json`, before and after every reload.
3. `twinvpn config check` exits non-zero on each of the three validation stages, distinguishably by
   `reason_code`.
4. The set of nftables tables present is queryable by an external observer at any instant,
   including while the daemon is dead.
5. The measured resource envelope and the current shedding step (S-68) are readable via
   `twinvpn status get --output json`.
6. Flash writes are attributable: the daemon's durable-write set is confined to declared paths, so
   a block-device counter delta is a valid oracle.
7. `twinvpn diag verify` is a total function over a bundle with a boolean result.
8. The operation catalogue is enumerable **on the built profile**, so the compiled-out set of §11.2 is observable as absence rather than as failure.

---

#### P22 — A headless device is enrolled, configured, diagnosed, and recovered with no GUI, and never fails open

| | |
|---|---|
| **Proves** | R-21, **R-47**, **R-48**, **R-49**; I3, I4, I6, I7, I8 |
| **Lab scenario** | `S-EMB-*` on the OpenWrt rig of [docs/testing-strategy.md](../testing-strategy.md) §3.7 row 2 — **real GC-0 and GC-0U hardware**. Per EM-54b, P22's build-derived assertions (RSS, flash writes, package size) gate on **both** classes and MAY run the GC-0 leg on an ARM envelope member; its throughput assertions gate on GC-0U and run nightly on GC-0's canonical `ath79` member. Plus a memory- and flash-constrained namespace variant for per-PR CI |
| **Preconditions (V3, each asserted)** | A fresh image on a **GC-0** unit (single core, ~580–700 MHz, no crypto extensions, 128 MB RAM, 16 MB flash, JFFS2 overlay) **and** on a **GC-0U** unit (dual-core, same memory and flash). The GC-0 leg's throughput measurements MUST be taken on the canonical `ath79` member (EM-54d), no display, reachable only over SSH; `custody_class = SOFTWARE_PORTABLE`; a separate paired admin device holding an OSK with `ENROLL`; the TwinLab personality and impairment library attached per Rule L-4; instantiated for `v4-only`, `v6-only`, and `dual` per Rule L-5 |
| **Assumptions** | AS-01, AS-03, AS-04, AS-05, AS-06, A-08 ([docs/testing-strategy.md](../testing-strategy.md) §0) |

**Procedure.**

1. **Enrol.** From the fresh image, over SSH: `twinvpn pair begin --qr`. The admin device
   photographs the terminal; an OSK holding `ENROLL` approves.
2. **Configure.** Write `/etc/config/twinvpn` declaring the `LANGateway` role, one advertised
   subnet per family, and `max_admitted_peers = 16`. Run `twinvpn config check`, then `reload`.
3. **Serve.** Bring up 16 concurrent peers, drive traffic, and attempt a 17th. Sample RSS and the
   block-device write counter throughout a one-hour steady state.
4. **Break it**, as separate runs: (a) an invalid document + `reload`; (b) an invalid document +
   reboot; (c) `SIGKILL` of the daemon; (d) an OOM kill by cgroup squeeze; (e) an `fw4 reload`
   triggered by a simulated LuCI firewall edit; (f) `/overlay` filled to zero free.
5. **Diagnose.** `twinvpn diag bundle --window 15m --out -` over SSH; then `diag verify` and
   `diag preview` on the retrieved artifact.
6. **Parity.** Enumerate the operation catalogue on this H-EMB build and assert MI-1 in both
   directions, plus the absence of every capability §11.2 compiles out.

**Oracle (exact).**

- **Enrolment method.** The transcript records method `C-B`, not `C-A`. The 32-byte
  `pairing_secret` appears **nowhere**: a byte-search over the full flash image, the `logd` ring
  (`logread`), the Tier-0 ledger, the generated bundle, and a wire capture returns **zero** hits
  (PT-2's independent wire oracle).
- **Identity.** The IK was generated on-device and is non-exportable; `custody_class = SOFTWARE_PORTABLE`
  is advertised, appears in the admin device's approval transcript, and
  `PLATFORM.EMBEDDED.IDENTITY_CLONEABLE` is present and persistent thereafter.
- **Multi-peer (I7).** 16 peers are concurrently admitted. The 17th receives
  `RESOURCE.ADMISSION.PEER_LIMIT_REACHED` and **no admitted peer is displaced** — all 16
  `session_id`s are unchanged across the refusal.
- **Envelope.** RSS ≤ 8 MB at idle, ≤ 12 MB at 8 peers, ≤ 13 MB at 16 peers (§11.14). Steady-state flash writes over the
  one-hour run ≤ 4 KB, measured as a `/proc/diskstats` delta on the backing `mtdblock`/`ubi`
  device.
- **(a) invalid reload.** The daemon remains on generation N; `MGMT.CONFIG.SCHEMA_INVALID` is
  emitted; `MGMT.CONFIG.INVALID_AT_BOOT` is **absent**; the installed nftables ruleset is
  byte-identical before and after.
- **(b) invalid at boot.** `table inet twinvpn_boot` is present **before the daemon's first log
  line**, asserted by timestamp ordering between a continuous nftables sampler and `logread`. The
  daemon starts on generation N and emits `MGMT.CONFIG.INVALID_AT_BOOT`. **Zero protected bytes
  egress across the entire boot window**, corroborated on the wire.
- **(c)/(d) death.** The nftables table survives, queried from a separate process while the daemon
  is dead. Restart re-enters `RECONNECTING`, never a fresh `DISCONNECTED`.
  `PLATFORM.EMBEDDED.OOM_RESTART` at `CRITICAL` for (d).
- **(e) `fw4 reload`.** Continuous ruleset sampling at 50 ms shows **no instant** in which the
  protected scope is unfiltered; a spurious `twinvpn_boot` is removed within one reconciler tick
  with `POLICY.KILLSWITCH.ASSERTION_MISMATCH`.
- **(f) flash exhausted.** `PLATFORM.EMBEDDED.FLASH_EXHAUSTED`; the daemon keeps serving all 16
  admitted peers, keeps enforcement installed, and refuses only non-essential writes. It does not
  exit and does not disarm.
- **Diagnostics.** The bundle is ≤ 512 KB and the `/overlay` write delta for step 5 is **exactly
  zero**. `diag verify` exits 0. An independent scanner finds no `SENSITIVE`-class value in raw
  form and no `SECRET`-class field type. `diag preview` of the retrieved bundle is **byte-identical**
  to the transcript produced alongside it.
- **Escalation (R-49).** Every `CRITICAL` raised in step 4 appears in `logread` with its
  `reason_code` as a structured field within 5 s, and in `$STATE_DIR/health`.
- **Never fails open (I3).** Across the whole run, zero transitions out of `BLOCKED` occur other
  than by path restoration, and zero enforcement-mode decreases occur without a preceding
  `POLICY.KILLSWITCH.DISARMED_BY_OWNER` carrying peer-credential evidence.
- **Parity (R-47).** Enumerating the catalogue on this H-EMB build finds a verb for every advertised operation and no verb without one (MI-1); every capability §11.2 compiles out is **absent** from both the catalogue and S-19, not present-and-failing.

**Mutants (V2).** Each is a buildable, version-controlled patch against the release commit.

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P22-1` | Headless enrolment falls back to C-A whenever no camera is present | Method assertion fails; enrolment entropy drops to ~2^29.9 |
| `M-P22-2` | The `PairingOffer` is logged at `DEBUG` | The byte-search oracle hits in `logread` and in the flash image |
| `M-P22-3` | Unknown config keys are ignored rather than rejected | A deliberately misspelled `kill_swtich` key is silently dropped; the asserted posture differs from the declared one |
| `M-P22-4` | The boot ruleset is installed by the daemon instead of by `fw4` | (b)'s timestamp-ordering assertion fails; protected bytes egress in the boot window |
| `M-P22-5` | Memory shedding disconnects the least recently active peer | The 16-stable-`session_id` assertion fails; **I7** violated |
| `M-P22-6` | The watchdog is fed from a timer thread rather than a fresh `ProtectionAssertion` | With the reconciler wedged, no restart occurs and the indicator stays `PROTECTED` |
| `M-P22-7` | `BLOCKED` auto-releases after ten minutes on an unattended device | The `BLOCKED`-exit assertion fires with no path restoration |
| `M-P22-8` | The Tier-0 ledger is written to `/overlay` | The flash-write-rate assertion fails by orders of magnitude |
| `M-P22-9` | The bundle transcript is rendered from the raw ledger rather than the redacted artifact | `diag preview` is not byte-identical, and a `SENSITIVE` value appears in the transcript but not in the bundle |
| `M-P22-10` | A capability compiled out of H-EMB is still advertised in the catalogue and in S-19, and fails at call time | The profile-parity assertion finds an advertised operation that cannot succeed (EM-4) |
| `M-P22-11` | The `netifd` proto handler is dropped and the interface is created directly | A simulated WAN flap tears the interface down; `PLATFORM.EMBEDDED.NETIFD_TEARDOWN` never fires because nothing is registered, and the route set is deleted by `netifd` |

**Positive control (V4).** With the `config include` deliberately removed from
`/etc/config/firewall`, run (b) MUST show protected bytes on the wire during the boot window and
MUST fail — proving the wire oracle can observe a leak, so a clean pass is evidence rather than
inertness.

**Pass criteria.** All six break variants, all three address-family instantiations (Rule L-5),
10/10 runs, on **real GC-0 and GC-0U hardware**, gated per EM-54b's build-derived/silicon-derived split; every mutant fails with its
expected oracle.

**Known limits.** Vendor-kernel quirks outside the reference image are untested
([docs/testing-strategy.md](../testing-strategy.md) §3.7). The flash-wear claim is asserted as a
**write rate** over a one-hour window under the measured workload; the long-horizon claim is a soak
obligation (§2.17) and is declared `STATISTICAL`, not `BIT`.

---

## 12. Why the Selected Option Won

- **It is the only alternative that keeps R-21 literally true.** R-21 and
  [docs/architecture.md](../architecture.md) §2.1 both say *the same control contract as the GUI*.
  Alternative A makes that false by construction — two contracts, two implementations, and every
  other ADR acquiring an "and on the headless product…" clause. E makes it true and, via EM-41,
  **checkable in CI**, which is the difference between a requirement and a slogan.
- **It beats D on the one axis that matters, and D is otherwise the closest.** D's legibility is
  genuinely superior and E adopts it wholesale for Class-I facts. D fails on Class T: a file that
  can declare a `TrustedPeer` is a second writer for S-02/S-05 (**I8**) and, on a `SOFTWARE_PORTABLE`
  router, an authorization path made of plaintext (**I4**/**P4**). E keeps everything D offers and
  removes exactly the part that is unsafe. It also gives learned state (S-14, S-15, S-31) an honest
  home, which a pure reconciler cannot — D would either discard the `Endpoint` cache at each
  reload, destroying R-11's control-plane-free reconnect, or keep an undeclared second store, which
  is D with the **I8** violation merely hidden.
- **It beats C on operability, and C's advantage was smaller than it looked.** C's single-writer
  purity is real, but provisioning becomes a *script* — a path rather than a description, correct
  only from one starting state and silently divergent when re-run from another. E's compare-and-swap
  is the price of buying back declarative intent, and §14 condition 4 falsifies whether that price
  is acceptable in the field.
- **It beats B because a settings blob is not a configuration** — no schema, no version, no diff, no
  dry run, no comments, no fleet distribution, and on OpenWrt a second config database `sysupgrade`
  drops. B fails R-21 on the plain text of the requirement.
- **The embedded tier is treated as an engineering problem with numbers, not a compatibility
  promise.** §11.13 and §11.14 state budgets with their hardware class; §14 falsifies each; P22
  measures them on real hardware. The alternative — "we support OpenWrt" with no envelope — is how
  the R-21 defect happened in the first place.
- **Every hard question was answered in the direction that costs more to build.** The config file
  cannot declare trust (EM-13). The enrolment offer travels outbound from the device, never inbound
  (EM-23). The shedding ladder has no step touching enforcement (EM-59). There is no auto-unblock
  timer (EM-72), and the pressure behind it is dissolved by scoping instead (EM-73). Each is the
  more expensive choice, and each is what an unattended device with a cloneable identity requires.

## 13. Known Tradeoffs

| # | Tradeoff | Why it is accepted | Residual, and what carries it |
|---|---|---|---|
| **K1** | **H-EMB identity is `SOFTWARE_PORTABLE` and clones.** Anyone with the flash contents has the device's identity. | Requiring hardware backing would exclude every OpenWrt router and therefore R-21 and the home-lab persona (C-04, [ADR-0007](ADR-0007-device-identity-and-pairing.md) C5) | Detection only — `AUTH.IDENTITY_CONCURRENT_USE`, TAI64N regression — plus revocation. Disclosed at enrolment (EM-30), prohibited from holding an `ENROLL`/`REVOKE`/`DELEGATE` OSK (EM-31), and recorded in [docs/threat-model.md](../threat-model.md) TM-13 (EM-33) |
| **K2** | **The enrolment offer can persist in a terminal recording.** Camera-and-screen leaves no artifact; SSH does. | The alternative is C-A at ~2^29.9, which is *worse* against the same adversary and worse against every other | EM-24/EM-26 reduce accidental persistence and do not claim to defeat a recorder; TM-11's residual is extended (EM-27) |
| **K3** | **Two authoring front-ends (TOML and UCI) and one model.** | Shipping TOML on OpenWrt creates a config database `sysupgrade` drops; shipping UCI everywhere is unusable off OpenWrt | A round-trip property-test obligation on [docs/testing-strategy.md](../testing-strategy.md) §2.11, and one more parser to fuzz |
| **K4** | **CLI mutations can conflict with a hand edit** (`MGMT.CONFIG.GENERATION_CONFLICT`). | The price of file-as-authority. Alternative C has no such failure because it has no file | Operator friction, measured by §14 condition 4 |
| **K5** | **The in-band escalation channel (EM-69 #5) tells the control plane that a device is unhealthy.** | An unattended device with no screen has no other way to reach a human, and silence is the failure **I6** exists to prevent | Metadata exposure, disclosed; `CRITICAL`-only by default; disableable; carries only `PUBLIC`/`OPERATIONAL` fields |
| **K6** | **H-EMB's default `protected_scope` is overlay-only**, which is narrower than the desktop default. | A router is the household's gateway; making the whole household the protected scope turns any TwinVPN fault into a total outage and creates unstoppable pressure for the auto-unblock feature EM-72 prohibits | Full-tunnel egress for LAN clients is opt-in per client and is fully protected once opted in; the narrower default is announced, not silent |
| **K7** | **Tier-2 telemetry and crash reporting are compiled out of H-EMB**, so the embedded fleet is the least observable tier. | Both are opt-in and there is no user present to opt in; both cost flash | Embedded regressions are found by P22 and the soak suite rather than by fleet aggregates; §14 condition 2 is the pressure valve |
| **K8** | **`--out -` for diagnostics means the bundle exists only in the operator's SSH pipe.** | It is the only way to produce a 512 KB artifact on a device with a 16 MB flash and a write budget | If the pipe breaks, the bundle is gone and must be regenerated; the Tier-0 ring may have wrapped by then (`PLATFORM.EMBEDDED.LEDGER_OVERWRITTEN`) |
| **K9** | **macOS and Windows headless profiles carry a one-time interactive dependency** (system-extension approval, driver install). | It is a platform fact, not a design choice (C-10) | Named as `PLATFORM.EMBEDDED.APPROVAL_REQUIRES_UI` with MDM/Group Policy as the fleet answer, rather than claimed away |
| **K10** | **iOS, iPadOS, and Android have no headless profile at all.** | C-09. There is no process to run and no file with authority | Stated as a platform limitation with its mechanism, not as future work; the iPadOS Files-import path is specifically refused rather than left open |

## 14. Revisit Conditions

Each condition is measurable, and each names what must be re-decided.

1. **If a *GC-0U* unit's measured aggregate ChaCha20-Poly1305 forwarding throughput on
   the shipped kernel datapath falls below 80 Mbit/s at 16 peers**
   ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) PB-3), §11.13's GC-0U row and the
   "router as `LANGateway`" claim must be re-derived, and a published hardware floor must replace
   "OpenWrt 21.02" as the minimum for the gateway role.

1b. **If a measured `mt7621` unit falls outside the 40–70 Mbit/s estimate of §11.13**, that row is
   replaced with the measurement and EM-54e's boundary is re-examined: a member landing at or above
   GC-0U's ≥ 80 floor without SIMD would falsify the claim that SIMD presence is the right
   discriminator, and the boundary would have to be re-cut on measured throughput instead.

1a. **If a *GC-0* unit falls below 20 Mbit/s at 16 peers**, GC-0 is dropped from the
   supported set rather than the budget being lowered — and dropping it means withdrawing the
   R-21 claim for that hardware explicitly, not quietly leaving it ungated — an ungated tier that cannot carry a
   household's traffic is not a supported gateway, and saying so beats shipping a number nobody met.
2. **If daemon RSS at 8 peers on GC-0U exceeds 12 MB at the p95 across the supported target set for
   two consecutive releases** ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md) row 8), either another tier moves out of the §11.2 feature matrix, or the H-EMB
   RAM floor rises from 128 MB and the `ath79` class is dropped from the committed target set.
3. **If more than 5 % of headless enrolments use the C-A fallback rather than E1–E4** over two
   consecutive quarters, the terminal channel is not working in the field and a dedicated
   file-transported ceremony must be specified. This refines
   [ADR-0007](ADR-0007-device-identity-and-pairing.md)'s V3 (10 %) for this profile, because a
   headless target reaching C-A at all indicates E1–E4 failed, not that a camera was absent.
4. **If `MGMT.CONFIG.GENERATION_CONFLICT` exceeds 1 % of CLI mutations**, file-as-authority is
   producing real contention and alternative C (daemon-owned intent with the file as an export)
   must be reconsidered.
5. **If `PLATFORM.EMBEDDED.FLASH_WRITE_BUDGET_EXCEEDED` fires on more than 0.5 % of H-EMB devices
   per month**, EM-52's durable-write set is too large and S-15 and S-31 must be made non-durable
   on this profile — with the cost to R-11's control-plane-free reconnect stated explicitly at that
   time.
6. **If the stripped binary on GC-0/GC-0U exceeds [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) BM-1.1's 4 MB, or the `.ipk` exceeds 1.8 MB**, §11.2's
   feature matrix must remove a tier before the release ships; the budget is a gate, not a target.
7. **If an OpenWrt release removes `netifd` protocol handlers, changes `fw4` include ordering
   relative to service start, or moves `/dev/watchdog` ownership away from `procd`**, §11.15 and
   EM-70 must be respecified for that release before it enters the supported set.
8. **If measured cold start to `RULESET_BLOCKED` installed exceeds 2 s at the p95 on GC-0U**, the boot
   rule set must move earlier than `fw4` (into `preinit`) or
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-19's OpenWrt row must be respecified.
9. **If P22's `M-P22-5` or `M-P22-7` mutant ever passes**, the shedding ladder or the `BLOCKED`
   exit guard has drifted, and §11.14/§11.16 must be re-derived before the next release — this is a
   defect at the same severity as a product defect ([docs/testing-strategy.md](../testing-strategy.md)
   Rule PT-1).
10. **If `PLATFORM.EMBEDDED.NO_RTC` devices show a measurably higher rate of
    `RELAY.CLOCK_SKEW_EXCESSIVE` than RTC-equipped ones after EM-77's offset persistence ships**,
    the offset is not surviving reboot or is being rejected, and EM-77 must be re-derived — the
    fallback is a durable *monotone floor* on observed time (never decreasing across boots), which
    is strictly weaker than an RTC and strictly stronger than epoch 0.

11. **If a second `Owner` per device, delegated guest access, or mesh subnet routing between
    multiple `LANGateway`s leaves [docs/vision.md](../vision.md) §3.5's deferred set**, §11.4's
    three-class partition must be re-examined: each of those introduces intent authored by someone
    who is not the sole `Owner`, which is the assumption Class I rests on.
