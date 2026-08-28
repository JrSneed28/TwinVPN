# ADR-0022: Application Lifecycle and Background Execution

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0011](ADR-0011-dns-handling.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0017](ADR-0017-local-management-interface.md),
  [ADR-0018](ADR-0018-shared-core-and-build-architecture.md),
  [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md),
  [ADR-0021](ADR-0021-packaging-distribution-and-updates.md),
  [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md)

This ADR owns the **application and process lifecycle** layer: how the TwinVPN agent is started,
kept alive, backgrounded, suspended, terminated and resurrected by each operating system; how its
durable state is rehydrated so that a restarted client resumes rather than restarts; how the
UI/daemon and app/extension halves survive each other's death; how crash and crash-loop are
contained without relaxing protection; what the application layer does with the OS's power,
thermal and metering signals; and the policy surface for always-on, connect-on-demand, and the
trusted-network exception.

It does **not** own the reliability semantics of background operation — the background timer
profile, parking, wake-to-traffic and the platform background-limit cost table are
[docs/reliability.md](../reliability.md) §11's, and are consumed here unchanged. It does not own
the networking hazards or their mechanisms ([docs/networking.md](../networking.md) §5.4), the
`ConnectionState` machine ([docs/reliability.md](../reliability.md) §4), the kill-switch policy or
its enforcement points ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)), the durable
store's realization ([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)), the privilege split ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)), the local management
contract ([ADR-0017](ADR-0017-local-management-interface.md)), packaging and update delivery ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)), or the headless profile
itself ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)). Where those documents are underspecified *for the application layer*, this
ADR says so as a finding rather than re-deciding them.

> **Link note for the integrator.** [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)
> had not been written when this file was authored; its filename here is the canonical one
> confirmed by the integrator, so the link resolves once that ADR lands.

---

## 1. Context

[docs/vision.md](../vision.md) **R-08** is this ADR's central requirement: *background operation
MUST use platform-sanctioned VPN lifecycle APIs and MUST tolerate OS-initiated process suspension
and termination without losing `Session` continuity or leaking traffic on resume.*
[docs/architecture.md](../architecture.md) §2.1 states the consequence in one sentence — *"on
restart the client rehydrates from durable local state and re-enters `RECONNECTING`, not
`DISCONNECTED`-from-scratch"* — and names no mechanism. [docs/reliability.md](../reliability.md)
§6.5 makes the same claim from the state-machine side (`Session` identity survives process
restart, S-12) and §11 specifies what the *network* does on wake. Nothing in the corpus specifies
how the process gets to exist again, in what order it reads what, or what happens when the OS
refuses to let it exist at all.

That gap is where the defect class lives. The failure modes this ADR exists to close are:

| Observed defect in comparable products | Why it happens | Where this ADR closes it |
|---|---|---|
| VPN is off after a reboot; the user notices minutes later | No boot-start, or boot-start ordered behind a network target that never fires | §11.3 |
| VPN "reconnects" after a crash but every peer starts from scratch and inner TCP flows that could have survived are killed anyway | No durable lifecycle journal; restart is a cold start | §11.2 |
| The app is killed by the OS on a phone and protection quietly stops | Enforcement lives in the process | §11.4, and [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 which already puts it in the kernel |
| A crash loop flaps the interface and the firewall until the user disables the product | No crash-loop containment; "recovery" is fail-open | §11.7 |
| Closing the GUI window disconnects the tunnel | UI owns the lifecycle | §11.5 |
| Laptop wakes from sleep and leaks for two seconds | Resume emits traffic before re-asserting enforcement | §11.6 |
| A crash dump uploaded to a vendor contains key material | Crash reporting designed after the fact | §11.7 |
| "Don't connect on my home Wi-Fi" is defeated by an attacker naming their AP the same thing | Trust identified by SSID | §11.10 |

The lifecycle layer is also where invariant **I3** is most easily broken by accident, because
almost every lifecycle event is an opportunity to have *no process* and *no rules* at the same
moment. The organising rule of this ADR is therefore: **the process is never the safety property.**
Enforcement is kernel-resident and outlives every lifecycle event (S-18,
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6); the process's job is to be able to
come back, know what it was doing, and prove protection is still installed before it does anything
else.

---

## 2. Requirements

Existing requirements this ADR discharges or depends on: **R-06** (unattended recovery), **R-08**
(background operation — central), **R-13** (fail-closed on crash, update and boot), **R-19**/**R-20**
(platform integration named, not hand-waved), **R-21** (headless with the same control contract),
**R-22**/**R-23** (named failures, diagnosability).

New requirements proposed for [docs/vision.md](../vision.md) §5, in that table's format:

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-44** | After a reboot, crash, or OS-initiated kill, the client returns as if it had never run: every peer starts cold, the user must reconnect by hand, and the interval between the network coming up and the agent running is unprotected | The client MUST resume **unattended** from durable local state after clean stop, crash, OS-initiated termination, suspend, hibernate and reboot; it MUST re-enter `RECONNECTING` for every peer it was maintaining rather than `DISCONNECTED`-from-scratch; it MUST re-assert and *verify* enforcement **before** emitting any packet; and it MUST NOT require a logged-in user session, a desktop, a keyring daemon, or a session bus to do any of this | Durable `LifecycleJournal` (S-62) with a clean-shutdown marker and `boot_id`; the ordered rehydration contract with a declared budget `T_REHYDRATE`; per-platform OS-supervisor start triggers; single-instance lock enforcing I8 across restarts | ADR-0022 §11.2, §11.3, §11.9 |
| **R-45** | The agent crashes repeatedly, flapping the interface, routes and firewall on every attempt, and the product's eventual "recovery" is to stop protecting | Repeated abnormal termination MUST be detected within a bounded window and contained. Containment MUST NOT relax enforcement, MUST NOT re-apply network configuration faster than a declared rate, MUST quarantine a configuration generation that correlates with the crashes, and MUST leave a working local control path so the device is *blocked, not bricked*. A crash artifact MUST NOT be able to carry `SECRET`-classified material off the device | Restart policy, crash-loop hold, safe mode and generation quarantine are **ADR-0016 §11.6 PS-9/PS-10/PS-11**'s mechanism (ceded, LC-27); this ADR supplies the write-ahead evidence they key on (S-62), the `apply()` rate limit `N_LIFECYCLE_APPLY_MAX`, the surviving-control-path obligation, and the `SecretArena` with platform dump exclusion and a module-range crash-handler filter | **ADR-0016** §11.6; ADR-0022 §11.7 (LC-28, LC-30) |
| **R-46** | Background operation is either a battery disaster the user uninstalls over, or so aggressively throttled that the tunnel is dead and nobody is told | Each background posture MUST have a **declared, measured** battery, wake, memory and CPU budget; the client MUST consume the OS's own `metered`, `low_power` and thermal signals rather than a fixed profile; and no budget-driven reduction may weaken enforcement, lengthen dead-path detection beyond `T_DEAD` while traffic is offered, or defer rekey. Every budget-driven reduction MUST be announced with a `reason_code` | The budget table and its measurement method; the closed list of forbidden reductions; `query_link_facts()` consumption; the iOS/iPadOS extension memory ceiling with pre-emptive shedding before the OS kills the provider | ADR-0022 §11.4, §11.8 |

---

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| C1 | The twelve `ConnectionState` names are closed. This ADR MUST NOT add a state or a transition; a host-lifecycle phase is a **separate** fact that maps onto them | [docs/reliability.md](../reliability.md) §4 |
| C2 | No ADR owns a timer value; ADRs propose, [docs/reliability.md](../reliability.md) §5 registers | [docs/reliability.md](../reliability.md) §5.3 |
| C3 | Enforcement is kernel-resident and survives process death, `SIGKILL`, update and reboot. The lifecycle layer MUST NOT be its custodian | S-18, [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 |
| C4 | Every persistent fact has exactly one writer (**I8**). On a single device the writer is a *process*, so restart and multi-instance are I8 events | [docs/architecture.md](../architecture.md) §5 |
| C5 | An established `Session` MUST NOT require a control-plane call (**I5**). Rehydration therefore MUST work with the control plane down | [docs/architecture.md](../architecture.md) §4.4 |
| C6 | The private half of `DeviceKey` never leaves platform secure storage (**I4**), and no crash artifact may render `SECRET` material | [docs/threat-model.md](../threat-model.md) §9 |
| C7 | Wall clock is evidence only; timers are monotonic | [docs/reliability.md](../reliability.md) §11.4 E5 |
| C8 | The iOS/iPadOS `NEPacketTunnelProvider` runs in a memory-constrained app extension; contract fetch/parse and diagnostics are already assigned to the app process | [docs/networking.md](../networking.md) §5.4 |
| C9 | Minimum platform versions are fixed: iOS 15, Android API 26 (API 29 target behaviour), Windows 10 21H2 / Server 2019, macOS 11, Linux 5.6 (5.4 with userspace fallback), OpenWrt 21.02 | [docs/networking.md](../networking.md) §5.2 |
| C10 | Phase 1 is documents only | brief §0 |

---

## 4. Considered Alternatives

**A — Per-platform ad hoc lifecycle.** Each native shell implements start, stop, background,
resume and restart in its own idiom. There is no shared lifecycle model and no shared rehydration
contract; the core is started and stopped like a library.

**B — Fight the OS.** Assume the process should always be running and spend the engineering budget
on keeping it alive: wake locks, permanently-foreground services, repeating alarms, background
fetch abuse, watchdog processes that restart each other.

**C — Portable lifecycle supervisor in the core, thin per-platform host adapter, durable
rehydration journal, OS supervisor owns restart.** One `HostLifecycleState` machine lives in the
shared core (H1); each platform's shell translates OS lifecycle callbacks into a small closed set
of lifecycle events and nothing else; restart is delegated to the platform's own supervisor
(`systemd`, SCM, `launchd`, `procd`, `nesessionmanager`, Android always-on) rather than to a
TwinVPN-owned babysitter; a durable `LifecycleJournal` makes every restart a *resume*.

**D — Crash-only software.** No lifecycle model and no clean-shutdown path at all. Every start is
a cold start; all state is rebuilt from configuration; stopping is `SIGKILL` by design.

**E — UI-owned lifecycle.** The GUI process is the lifecycle authority: it starts the tunnel, owns
the state, and the privileged helper exits when the UI exits. On mobile the app drives the
extension and tears it down when backgrounded.

---

## 5. Advantages of Each Alternative

| | Advantages |
|---|---|
| **A** | Each platform gets exactly the idiom its OS documentation describes; no impedance mismatch; the shell author needs no knowledge of the core; fastest path to a first working build on any single platform |
| **B** | Maximises the window in which the tunnel is genuinely up and reachable; simplest mental model for inbound reachability; avoids the whole re-establishment problem when it works |
| **C** | One lifecycle model to reason about, test and prove (P21 is writable at all); rehydration is specified once and identical everywhere, which is what makes R-08 and [docs/architecture.md](../architecture.md) §2.1 true rather than aspirational; restart policy, backoff and crash-loop containment come from the platform supervisor that the sysadmin already knows how to configure; the shell stays thin enough to be reviewed |
| **D** | Genuinely robust — there is only one code path into `RUNNING`, so it is exercised on every start and cannot rot; no clean-shutdown bugs because there is no clean shutdown; trivially correct after `SIGKILL` |
| **E** | The simplest possible privilege story and the simplest possible "one writer" story, because there is only one lifetime; matches the naive user model ("I closed the app, so it stopped"); no orphaned background process to explain |

---

## 6. Disadvantages of Each Alternative

| | Disadvantages |
|---|---|
| **A** | Six divergent rehydration orders means six chances to emit a packet before enforcement is verified — the exact I3 hole. No single proof test can cover it. Bugs found on one platform are not fixed on the others. Directly contradicts H1's "no business logic reimplemented per platform" |
| **B** | Loses on the arithmetic. [docs/reliability.md](../reliability.md) §6.6 shows a 25 s keepalive is ~3,456 radio wakes/day; §11.2 concludes that a UDP NAT binding *cannot* be held at acceptable battery cost and that parking is the honest answer. Wake locks and permanent foreground services are also the fastest route to a Play policy rejection and to being killed by OEM battery managers anyway. It optimises the case the OS has decided not to support |
| **C** | The host adapter is a real abstraction with a real cost: some platform affordances (iPadOS scene lifecycle, Windows Modern Standby power settings, Android App Standby buckets) do not map onto a small closed event set without loss, and the loss must be re-added as platform-specific policy. Delegating restart to the OS supervisor means restart policy is *configuration we do not control* on Linux and OpenWrt |
| **D** | Discards the thing that makes recovery fast. [docs/reliability.md](../reliability.md) §6.2's ladder (re-validate → warm standby → cached endpoints → cached relay map) exists precisely because steps 1–4 are cheap, and every one of them depends on durable state a crash-only design would refuse to keep. It also throws away `session_id` continuity (S-12), which is what makes a diagnostic reconstructable across a crash, and it cannot distinguish crash from clean stop, which is what `absence_cause` needs |
| **E** | **Rejected on invariant grounds.** A UI process that can be killed by the user, by the window manager, or by memory pressure would take protection with it — an I3 violation, and exactly the "closing the window disconnects the VPN" defect. It also makes the GUI a privileged path, contradicting H3's "the GUI has no privileged side channel" and R-21's "same control contract as the GUI". On mobile it is not even available: the extension's lifetime is the OS's to decide, not the app's |

---

## 7. Security Implications

1. **The lifecycle layer must never be an enforcement gap (I3).** Every transition where the
   process does not exist is covered by kernel-resident rules installed by an artifact the OS
   applies ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-19). §11.2's ordering rule
   — *nothing is emitted before enforcement is queried and verified* — is the application-layer
   half of that, and is what P21's first oracle measures.
2. **Restart is an I8 event.** The `LOCAL`-class rows S-12, S-15, S-24, S-27, S-31, S-37, S-62 all
   name "the local `Device`" as the writer, which in practice means *the agent process*. Two
   concurrently-running agents would be two writers. §11.2's single-instance lock is the mechanism;
   its absence is a silent corruption path, not merely a duplicate.
3. **Crash artifacts are an exfiltration surface (I4).** Transport keys (S-13) are necessarily in
   process memory, so any dump containing stack or heap bytes can carry them.
   [docs/threat-model.md](../threat-model.md) §9 states the intention ("dump-excluded memory
   regions"); §11.7 supplies the mechanism and names the residual honestly.
4. **The trusted-network exception is a deliberate hole in protection**, and an SSID is not an
   authenticator. §11.10 requires a cryptographic proof and constrains what the exception may
   change, so the worst outcome of a spoofed network is a *narrower* protected scope, never a
   disarmed kill switch.
5. **Boot-before-login is a credential-availability problem, not just an ordering problem.** On
   iOS/iPadOS before first unlock, and on Android with an unlock-bound key, `DeviceKey` may be
   unreadable while the agent is running. The fail-closed default (§11.3) is to come up blocked
   and named rather than to weaken key protection so that boot-start works.
6. **On-demand activation is attacker-triggerable.** A rule that starts the tunnel on network
   attach can be driven by anyone who can present a network. That direction is safe (more
   protection); the reverse direction — a rule that *stops* or *ignores* on a matched network — is
   not, and §11.10 forbids it.

---

## 8. Reliability Implications

1. Rehydration into `RECONNECTING` is what makes [docs/reliability.md](../reliability.md) §6.2's
   cheap-recovery ladder reachable after a restart: cached endpoints (S-15), the cached signed
   relay map, and the per-relay quality history (S-31) are all durable, so steps 3 and 4 work with
   the control plane down (I5).
2. The `absence_cause` field turns "we are starting" into a diagnosable event. A restart after a
   clean stop, after a crash, after an OS memory kill and after a reboot produce different
   evidence and different user-facing text, which is I6 applied to the lifecycle itself.
3. Crash-loop containment deliberately trades availability for stability: while held, the device
   is `BLOCKED` and stays there. That is the correct direction (I3) and it is why the management
   interface must survive the hold — otherwise "blocked" becomes "bricked"
   ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-20).
4. The `apply()` rate limit bounds the damage a lifecycle bug can do to the host's network stack.
   Without it, a restart loop is a route/firewall flap generator affecting every other application
   on the machine.
5. Treating every wake as a network-change event ([docs/networking.md](../networking.md) §5.4,
   generalised in §11.6) costs one path validation and buys correctness on every platform where
   sockets silently survive a suspend they should not have survived.

---

## 9. Performance Implications

| Budget | Value | Why this number | How measured |
|---|---|---|---|
| `T_REHYDRATE` | **400 ms** p95, cold start to enforcement-verified and state machines instantiated, on reference hardware | Below the threshold at which a boot-time or resume-time gap is user-perceptible, and comfortably inside the 5 s `logind` inhibitor delay window §11.6 relies on | Instrumented span from process entry to the first `ProtectionAssertion`, in the transition-event stream |
| `T_REHYDRATE_MAX` | **3 s** hard bound | Beyond this the state is not merely slow, it is suspect. Exceeding it raises `PLATFORM.LIFECYCLE.REHYDRATE_TIMEOUT` and routes to `BLOCKED` rather than proceeding on partial state | Same span; a hard assertion, not a warning |
| *(both rows above)* | quoted **for the desktop, server and mobile reference classes only** | A 400 ms snapshot budget is a desktop/mobile number and MUST NOT be imposed on a MIPS router. On the embedded class the value is [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s to set against `GC-0` silicon, within its own cold-start budget; the **ordering** rule of LC-4 is class-independent and is not relaxed anywhere | per class |
| Wake-to-traffic | **300 ms** on a surviving path | Not this ADR's — registered by [docs/reliability.md](../reliability.md) §11.3 and consumed here | §11.3's ladder |
| iOS/iPadOS extension resident memory | **12 MB** provider-wide engineering budget, against a **15 MB** platform *ceiling* no design may consume; 10 MB shed threshold. This ADR owns the ceiling and the provider-wide budget; [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) owns the **core's share within it** — see F5 | Apple publishes no contractual figure for `NEPacketTunnelProvider`; the observed ceiling has sat at roughly 15 MB across the supported releases, with jetsam and no notice on breach. Budgeting at 12 MB leaves headroom for a transient allocation spike | CI memory gate on the extension target plus a runtime high-water counter that sheds cache at 10 MB (§11.4) |
| Parked background battery | **≤ 2%** of a reference handset's battery per 24 h with zero user traffic | The park state has no keepalives ([docs/reliability.md](../reliability.md) §11.1), so the residual cost is wake-window scheduling and enforcement assertion only | Platform attribution over a 24 h idle lab run |
| Maintained-path background battery | **≤ 5%** per 24 h | The 60 s coalesced cadence of §11.1 is ~1,440 wakes/day shared across all `Session`s; this budget is what makes that cadence defensible rather than assumed | Same |
| Radio wakes, parked | **≤ 96/day** (≤ 1 per 15 min) | One coalesced wake window per 15 min is enough to notice a delivered push-style wake and to renew a protection assertion, and is two orders of magnitude below the 25 s cadence §6.6 rejects | Wake counters attributed per process |
| Idle-connected CPU | **≤ 0.5%** average on the reference handset; on the embedded class, [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s figure governs | Idle CPU is the cost users attribute to "the VPN app"; a measurable ceiling is what prevents a probe cadence regression from shipping | Sampled over a 1 h idle-connected run |
| Client agent RSS, embedded | **Deferred to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s `H-EMB` profile envelope** (≤ 8 MB idle, ≤ 10 MB at 16 peers), whose numbers are derived against the **`GC-0`** silicon class — MIPS 24Kc @ 580 MHz, 1 core, ~24 MB free of RAM, 16 MB flash. This ADR asserts no independent number — see F8 | An earlier draft of this row derived a ceiling from [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.5's "G1 — Router class", whose reference hardware (RPi 4B, 2 GB) is not router-class. Only ADR-0013's **per-peer byte model** is sound and reusable; its **hardware premise** is not, and this ADR does not build on it | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) §11.14, EM-58 |

Every budget above is a **gate**, not a target: a build that exceeds one fails the same way a
failing test does.

---

## 10. Operational Implications

- Restart policy, backoff and crash-loop thresholds are expressed in the **platform supervisor's
  own configuration** (`systemd` unit, SCM failure actions, `launchd` plist, `procd` respawn
  parameters). An operator who overrides them is overriding the product's containment; §11.7
  requires the agent to *detect* that its supervisor's policy is weaker than the declared one and
  to say so (`PLATFORM.LIFECYCLE.SUPERVISOR_ABSENT`), because a silently-unsupervised agent is a
  reliability claim that is no longer true.
- Autostart posture is a support question on every platform and an unreliable one on Android.
  §11.10 requires the product to report `UNVERIFIED` rather than to claim a posture it cannot
  observe.
- Log volume on an embedded device with a read-only rootfs and a small overlay is a real failure
  mode; §11.9 makes the bounded in-memory ring the primary sink and makes a full filesystem a
  named, rate-limited diagnostic rather than a crash.
- The lifecycle journal is the first artifact support should ask for: it answers "when did this
  device last run, and why did it stop" without any telemetry backend.

---

## 11. Decision

**Alternative C is selected**, with a hard constraint borrowed from D (there is exactly one
`RUNNING` entry path, and the clean-shutdown path is never load-bearing for correctness) and with
E explicitly rejected on I3 grounds.

### 11.1 The host lifecycle model, and its mapping onto `ConnectionState`

**Rule LC-1 (normative).** `HostLifecycleState` is a **separate fact** from `ConnectionState`,
tracked alongside it exactly as traffic disposition and enforcement mode are
([docs/reliability.md](../reliability.md) §4.1). It MUST NOT be rendered as a `ConnectionState`,
MUST NOT add a state or transition to [docs/reliability.md](../reliability.md) §4, and MUST NOT
appear in the §4.7 aggregation. It has exactly these members:

| `HostLifecycleState` | Meaning | Process exists | Who decides entry |
|---|---|---|---|
| `ABSENT` | No agent process. Carries `absence_cause` ∈ {`CLEAN_STOP`, `CRASH`, `OS_TERMINATION`, `NEVER_STARTED`, `UNKNOWN`} | no | the OS, the supervisor, or the user |
| `COLD_START` | Process image created; no durable state read yet; no OS handles held | yes | a start trigger (§11.3) |
| `REHYDRATING` | The §11.2 ordered contract is executing | yes | the agent |
| `RUNNING_ATTENDED` | Normal operation with a user session present | yes | the agent |
| `RUNNING_HEADLESS` | Normal operation with **no** user session — boot-before-login, server, router, or a desktop before first login | yes | the agent |
| `BACKGROUND` | Alive but deprioritised: mobile background, macOS App Nap on the UI, Windows Modern Standby with the display off, Android App Standby bucket below `working_set` | yes | the OS, observed by the shell |
| `SUSPENDED` | Frozen: no scheduler time, memory retained. iOS/iPadOS extension suspension, Android Doze, system sleep (S3), hibernate (S4) | yes (nominally) | the OS |
| `STOPPING` | Orderly shutdown in progress, bounded by `T_LIFECYCLE_STOP` | yes | user, policy, or the OS's shutdown sequence |
| `HELD` | Crash-loop containment: restart suppressed, safe mode, enforcement retained | no or minimal | the agent's own hold marker plus the supervisor's limit |

`TERMINATED_BY_OS` is deliberately **not** a state. A state is held by a process, and a terminated
process holds nothing; it is an *edge into* `ABSENT` carrying `absence_cause = OS_TERMINATION`.
This is what makes the distinction mechanical rather than aspirational: the only evidence that
survives is what was written to the journal *before* the kill, so the design is forced to write it
in advance rather than at exit.

**Rule LC-2 — the mapping.** For each `TrustedPeer`, the rehydrated `ConnectionState` is
determined by the peer's **last durable state** (S-12) and by nothing else:

| Last durable `ConnectionState` | Rehydrated `ConnectionState` | Why |
|---|---|---|
| `LOCAL_DIRECT`, `WAN_DIRECT`, `RELAYED`, `MIGRATING`, `DEGRADED`, `RECONNECTING`, `BLOCKED` | **`RECONNECTING`**, entered with `PLATFORM.LIFECYCLE.REHYDRATED` | [docs/architecture.md](../architecture.md) §2.1 and [docs/reliability.md](../reliability.md) §6.5. Transport keys are gone (S-13), so the tunnel must be re-established, but the `Session` is not |
| `BLOCKED` **and** enforcement mode is `FAIL_CLOSED` | `RECONNECTING`, and the device-scope aggregate is `BLOCKED` per §4.7 rule 1 until a path returns | The blocking condition is a property of the device, not of the dead process |
| `FAILED` with a `FATAL`- or `PERSISTENT`-class code whose `retry_precondition` is unmet | **`FAILED`**, re-entered with the original terminal code | Retrying a revoked peer or an unsupported version on every restart is exactly the "retry forever with no diagnosis" defect R-09 names |
| `DISCONNECTED` reached via T38 (explicit user request) | **`DISCONNECTED`** | Restarting the agent MUST NOT silently reconnect a peer the user deliberately disconnected. A restart is not consent |
| absent / unreadable | `DISCONNECTED`, and the whole rehydration is treated as incomplete — see LC-6 | |

> **Finding (F1).** [docs/architecture.md](../architecture.md) §2.1 states the
> `RECONNECTING`-not-`DISCONNECTED` rule without exceptions. Read literally it re-dials a peer the
> user disconnected and re-attempts a `FATAL` failure on every boot. Rows 3 and 4 above are the
> narrowing this ADR proposes; the integrator should carry them back into §2.1 or explicitly
> overrule them.

**Rule LC-3.** The host lifecycle phase MUST be published on the management interface event stream
([ADR-0017](ADR-0017-local-management-interface.md)) as its own typed event, never inferred by the UI from the absence of other events.
A UI that guesses "the daemon must have died because nothing arrived" cannot distinguish death
from an idle tunnel, and will show stale truth.

### 11.2 The rehydration contract

**Rule LC-4 — the order is the safety property.** Every start, on every platform, executes exactly
these steps in this order. No step may be reordered, and no network activity of any kind — not a
DNS query, not a candidate gather, not a control-plane call — may occur before step 4 completes.

```text
 1. acquire the single-instance lock                       ── I8; see LC-5
 2. read boot_id and the suspend-inclusive monotonic clock  ── C7; see LC-8
 3. query the enforcement layer for the installed ruleset,  ── ADR-0012 KS-17, both families
    for v4 AND v6, and compare against the intended policy     ADR-0015 O-17
 4. re-assert to RULESET_BLOCKED if the query disagrees,    ── never "remove rules"; atomic swap
    and emit the first ProtectionAssertion
 ───────────── no packet may be emitted before this line ─────────────
 5. open the durable store and verify its schema version    ── ADR-0020; ADR-0014 for the range
 6. read the LifecycleJournal (S-62): instance_epoch,
    clean_shutdown marker, absence_cause, boot_id,
    last_applied_contract_generation, abnormal-exit ring
 7. read, in one consistent snapshot:
      S-12 Session identity + last ConnectionState
      S-15 Endpoint cache            S-24 user config / ActivationPolicy (S-63)
      S-27 control-channel cursor    S-31 per-relay measured quality
      S-37 per-peer negotiation floor
      cached signed documents: RelayMap (S-09), AccessPolicy (S-06),
      DNSPolicy (S-07), OwnerTrustAnchor (S-32), EpochSeed set (S-33)
 8. verify every signed document against its pinned anchor and its monotone version floor
 9. instantiate one ConnectionState machine per TrustedPeer at the LC-2 state
10. publish HostLifecycleState = RUNNING_* on the management event stream
11. only now: start network activity, and hand the wake/reconnect ladder to
    docs/reliability.md §6.2 (restart) or §11.3 (resume)
```

**Rule LC-5 — single instance.** The lock is an OS-level exclusive object held for the process's
lifetime and released by the kernel on death: an `flock` on the state directory plus an abstract
`AF_UNIX` socket name on Linux/OpenWrt; a named kernel mutex in the `Global\` namespace on Windows,
held by the service SID; an exclusive `flock` on the state directory on macOS; the OS-enforced
singleton nature of the provider/service on iOS, iPadOS and Android. Failure to acquire is
**fatal to the starting instance**, which exits with `PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT`
and MUST NOT proceed to step 3 — a second instance that "helpfully" re-asserts rules is a second
writer for S-18.

**Rule LC-6 — rehydration is all-or-nothing.** If any object in step 7 fails to load, fails
verification in step 8, or the whole sequence exceeds `T_REHYDRATE_MAX`, the agent MUST NOT
continue on partial state. It raises `EV_POLICY_VIOLATION{kind: lifecycle_state_unavailable}` with
`PLATFORM.LIFECYCLE.REHYDRATE_INCOMPLETE` (or `PLATFORM.LIFECYCLE.REHYDRATE_TIMEOUT`), which routes
to `BLOCKED` via the existing T29, keeps `RULESET_BLOCKED` live, brings up the management interface
so the user can act, and stops. Proceeding with half a peer set is how a client silently stops
protecting a peer it has forgotten.

**Rule LC-7 — the journal is written ahead, not at exit.** The `clean_shutdown` marker (S-62) is
cleared and flushed at step 10 and set only in `STOPPING`; `last_applied_contract_generation` is
flushed **before** the `apply()` it describes, mirroring S-34's write-ahead pattern. An
`OS_TERMINATION` or a crash therefore leaves the marker clear, and the next start reads
`absence_cause = CRASH` (or `UNKNOWN`, which is treated as `CRASH` — the fail-safe direction)
without needing to have run any code at exit. This is what makes the model work on iOS jetsam and
the Linux OOM killer, where no exit handler runs.

**Rule LC-8 — three clock domains, and the answer to "does the monotonic clock advance across
suspend".** It does **not** — because there are **two** injected monotonic clocks, not one, and
neither can do the other's job. This is the position
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.16(e) asks for; it is owned here.

| Clock | Advances across suspend | Primary use | Never used for |
|---|---|---|---|
| **`MonotonicClock`** | **No.** Paused while the host is suspended | **Every timer in [docs/reliability.md](../reliability.md) §5** except those named in the two rows below: establishment, liveness, recovery, migration, quality, dwell, backoff, and the LC-37 watchdog | measuring a suspend gap; any policy deadline |
| **`ElapsedClock`** | **Yes.** Includes suspend and hibernate | Measuring the suspend gap (LC-24 step 1); the rekey-window comparison of [docs/reliability.md](../reliability.md) §11.3; NAT binding-lifetime attribution; the `T_REHYDRATE` span | driving a liveness or recovery timer |
| **`WallClock`** | (unrelated — it can jump in both directions) | **Evidence only** (C7): rendering timestamps, `occurred_at`, and verifying a signed document's own validity window | any timer input whatsoever |

**Why `MonotonicClock` MUST pause.** If a single clock advanced across suspend, then on resume from
an eight-hour laptop sleep every short-horizon timer would fire its entire accrued backlog at once:
`T_DEAD` (15 s) would declare every path dead **before** the §11.3 wake ladder had a chance to
re-validate one, and `T_HEARTBEAT_ACTIVE` (3 s) would have thousands of missed deadlines to
reconcile. The suspend window is already handled — T34 parks the `Session` and LC-24 re-validates —
so accruing timers through it is not merely wasteful, it actively defeats the recovery path.

**The trap that makes this non-obvious, and why two implementations really will disagree.** The
identically-spelled POSIX constant means **opposite things** on the two OS families:

| Platform | `MonotonicClock` (suspend-**exclusive**) | `ElapsedClock` (suspend-**inclusive**) |
|---|---|---|
| Linux | `clock_gettime(CLOCK_MONOTONIC)` | `clock_gettime(CLOCK_BOOTTIME)` |
| Android | `System.nanoTime` / `CLOCK_MONOTONIC` | `SystemClock.elapsedRealtime` / `CLOCK_BOOTTIME` |
| macOS, iOS, iPadOS | `mach_absolute_time()` / `clock_gettime(CLOCK_UPTIME_RAW)` | `mach_continuous_time()` — and note **Darwin's `CLOCK_MONOTONIC` is suspend-inclusive**, the reverse of Linux's |
| Windows | `QueryUnbiasedInterruptTimePrecise` (**"unbiased" means sleep is excluded**) or `GetTickCount64` | `QueryInterruptTimePrecise` (biased — includes sleep) |
| OpenWrt / headless | `CLOCK_MONOTONIC` (the distinction is moot: these hosts do not suspend) | `CLOCK_BOOTTIME` |

An earlier draft of this rule attributed `QueryUnbiasedInterruptTimePrecise` to the *inclusive*
clock; that was backwards and is corrected above. A Rust core that reaches for
`std::time::Instant` gets `CLOCK_MONOTONIC` on Linux and `mach_absolute_time()` on Darwin — both
suspend-exclusive, which is correct for `MonotonicClock` and silently wrong for anything needing
the gap. **Neither clock may be obtained from a global**; both are injected at the component
boundary per [docs/architecture.md](../architecture.md) A-21, and A-21's wording ("timers … are
injectable") must be extended to name *which of the three* each call site takes, because
"injectable" without a named domain is what leaves the ambiguity.

`boot_id` is the third discriminator and is not a clock: Linux `/proc/sys/kernel/random/boot_id`,
`kern.boottime` on Apple platforms, the Windows boot time, Android's `elapsedRealtime` base. It
separates **reboot from resume**, which no clock can do — after a reboot both monotonic clocks
restart at zero, which is indistinguishable from "no time passed."

> **Finding (F2) — the corpus mixes two timer horizons under one word.**
> [docs/reliability.md](../reliability.md) §5.3's "constants registered on behalf of other ADRs"
> table places short-horizon liveness constants alongside **long-horizon policy deadlines** —
> `T_TRUST_REFRESH` (6 h), `T_TRUST_STALE` (24 h), `T_TRUST_HARD` (30 d), `T_IK_OVERLAP` (30 d),
> `T_TK_OVERLAP` (14 d) — and §11.4 E5's blanket "monotonic clocks for every timer" would put all of
> them on `MonotonicClock`. That is a **security defect**, not a style question: a laptop closed for
> sixty days would accrue no monotonic time, so `T_TRUST_HARD` would never expire and the device
> would keep exercising granted authority — exit egress, LAN access, route acceptance, new pairing —
> that **R-24 exists to suspend** precisely so that a revocation the device has not learned has a
> bounded blast radius. Long-horizon policy deadlines MUST therefore read `ElapsedClock`, or better,
> compare against the **signed validity window** carried in the document itself
> ([ADR-0007](ADR-0007-device-identity-and-pairing.md)) so the deadline survives even a reboot, which
> `ElapsedClock` does not. The same applies to `PortalExemptionGrant` expiry (S-35) and to credential
> expiry. This is a third row that §5.3's table does not currently have, and E5's wording needs the
> exception.

> **Finding (F3).** [docs/reliability.md](../reliability.md) §11.3 decides whether to force a full
> handshake by comparing a **wall-clock delta** against the rekey window, while §11.4 E5 says wall
> clock is evidence only and every timer must be monotonic. A wall-clock jump across a suspend is
> also a timezone change, an NTP step, or a user setting the clock. The suspend-inclusive monotonic
> clock is the correct measure of the gap and `boot_id` is the correct discriminator for "this is
> not a resume at all, it is a new boot". §11.3's rule is otherwise adopted unchanged.

### 11.3 Start triggers, per platform

**Rule LC-9.** Every supported platform MUST have at least one **OS-owned** start trigger — one
the operating system fires without any TwinVPN process already running. A product whose only start
path is "the user opens the app" cannot satisfy R-08 or R-13.

| Platform | Boot start | Login / session start | On-demand / traffic-triggered | User-initiated | If the trigger does not fire |
|---|---|---|---|---|---|
| **Linux** | `twinvpn.service`, `WantedBy=multi-user.target`, `Type=notify`, `After=network-pre.target local-fs.target`, `Wants=network-pre.target`, `Requires=twinvpn-killswitch.service` and `After=` it, `RequiresMountsFor=` the state directory. **Deliberately NOT `After=network-online.target`** — see LC-10 | none required; the daemon is system-scoped. A per-user LaunchAgent equivalent (`systemd --user`) hosts the **UI only** | `subscribe_network_change` inside the running daemon; no socket activation (LC-11) | `systemctl start`, CLI, GUI via the management interface | The boot ruleset from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 is still installed by `twinvpn-killswitch.service`, so the host is fail-closed and offline. First interactive contact raises `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED`, user-actionable |
| **Windows** | Service, start type **`SERVICE_AUTO_START` (not delayed)**, `ServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED`, dependencies on `BFE` and `Tcpip`. A user-mode service cannot be `SERVICE_BOOT_START`; boot coverage is the WFP `FWPM_FILTER_FLAG_BOOTTIME` + `FWPM_FILTER_FLAG_PERSISTENT` pair applied by BFE ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6) — see LC-12 | UI autostart via the packaged startup-task registration ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)); the UI never starts the tunnel, it attaches to it | in-daemon network-change notifications (`NotifyIpInterfaceChange`, `NotifyRouteChange2`) | `sc start`, CLI, GUI | BOOTTIME filters hold the host closed; the service's absence is an **availability** gap, not a leak — [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 already records this as deliberate. `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED` on next contact |
| **macOS** | `launchd` **daemon** in `/Library/LaunchDaemons`, `RunAtLoad=true`, `KeepAlive={SuccessfulExit=false, Crashed=true}` (never bare `KeepAlive=true`, LC-13). The `NEPacketTunnelProvider` ships as a **system extension** (Developer ID), activated once and loaded by the system thereafter | UI is a `LaunchAgent` in `/Library/LaunchAgents`, or a login item; UI only | on-demand rules on the `NETunnelProviderManager` configuration; `NWPathMonitor` inside the running daemon | menu-bar UI, CLI | `pf` anchor from `/etc/pf.conf` holds; `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED`. Recovery and safe boot do not load the daemon — residual already disclosed in [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 |
| **iOS** | **None available** for an unsupervised device. Supervised/MDM devices get true boot start via an Always-On VPN payload | app launch MAY call `startVPNTunnel()`; this is a *user-session* trigger, not a boot trigger | **`NEOnDemandRuleConnect`** evaluated by the system on network attach/change (`interfaceTypeMatch`, `SSIDMatch`, `probeURL`), with `disconnectOnDemandEnabled = false`. This is the primary OS-owned trigger | foreground app tap | The device is unprotected between boot/network-attach and the first on-demand evaluation. This is exactly [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE`, whose window P09 measures. The application-layer response is `PLATFORM.LIFECYCLE.ONDEMAND_RULES_ABSENT` at first run if no rules are installed, presented as an unmissable posture, plus a guided flow to supervised Always-On for managed fleets |
| **iPadOS** | as iOS | as iOS, **plus** multi-window: `UIScene` lifecycle is per-scene and the app is background only when **every** scene is; an external display or Stage Manager can keep a scene foreground while the device is locked; a Slide Over scene is backgrounded far more aggressively than a full-screen one | as iOS | as iOS | as iOS. The extra hazard is a shell that maps a *single* scene's background transition to `EV_BACKGROUND` and parks a `Session` while another scene is still visible — forbidden by LC-14 |
| **Android** | `BOOT_COMPLETED` receiver (`RECEIVE_BOOT_COMPLETED`), which is one of the exemptions to the Android 12+ background foreground-service-start restriction; **and** always-on VPN, under which the *system* starts `VpnService` at boot and restarts it if it dies | none needed | `onRevoke()`, `ConnectivityManager.NetworkCallback` inside the running service; always-on restart | user tap after `VpnService.prepare()` consent | If always-on is not configured and the receiver does not fire — most commonly because the user **force-stopped** the app, which puts it in the stopped state and disables manifest receivers until the next manual launch — there is no protection at all and the app cannot fix it. `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS`, user-actionable, plus the always-on guidance flow. OEM battery managers produce the same outcome |
| **OpenWrt / routers** | `procd` init script `/etc/init.d/twinvpn`, `START` ordered after `network`, with `procd_set_param respawn`, `procd_set_param watchdog`, and UCI `reload_config` triggers on `/etc/config/twinvpn` | n/a | `ubus` `network.interface` events inside the running daemon | `/etc/init.d/twinvpn start`, `ubus call`, CLI | The `fw4`/nftables include is part of persisted config and is applied by the firewall at boot, so the router is fail-closed. `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED` on the status surface. [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns the profile |
| **Headless gateways / CLI-only** | the platform's own supervisor (systemd, procd, or an OS-appropriate equivalent), configured as above | none, by requirement — see §11.9 | in-daemon | CLI | as the underlying platform |

**Rule LC-10 — the `network-online` decision (Linux).** `twinvpn.service` MUST NOT be ordered
`After=network-online.target`. Three reasons, in order of weight:

1. It would *create* a gap. `network-online.target` fires after the network is up; ordering behind
   it guarantees an interval in which the host has a network and TwinVPN does not. The boot race
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-19 closes is closed by a *separate*,
   earlier unit that installs rules before `network-pre.target`; the agent has no reason to wait.
2. It is not portable. Which implementation provides it (`NetworkManager-wait-online`,
   `systemd-networkd-wait-online`, an `ifupdown` shim) and what it means varies by distribution,
   and on several it never becomes ready on a box with a DHCP-less or bridged interface — which
   would mean the agent never starts at all.
3. The agent does not need it. "No network" is an ordinary, named condition
   (`DISCOVERING` → T04 → `RECONNECTING` with `NET.NO_USABLE_CANDIDATES`), and the adapter's
   `subscribe_network_change` ([docs/networking.md](../networking.md) §5.1) delivers the link event
   when it arrives. Waiting converts a handled condition into an unhandled one.

**Rule LC-11 — no socket activation for the agent.** Socket-activating the daemon on a management
connection would mean the agent does not run unless a UI or CLI connects, which is precisely the
E-shaped failure. The management socket is created *by* the running daemon ([ADR-0017](ADR-0017-local-management-interface.md)), never
the other way round.

**Rule LC-12 — the Windows start-type decision.** The choice is Automatic versus Automatic
(Delayed Start), and Automatic wins: delayed start defers the service by ~2 minutes after boot,
which lengthens exactly the window in which the host is fail-closed-and-offline, and buys only a
boot-time perception improvement the product does not need. `SERVICE_BOOT_START` is not available
to a user-mode service. The residual — the interval between BFE applying the persistent filters and
our service reaching step 4 of LC-4 — is an availability gap in the correct direction and is what
`T_REHYDRATE` bounds.

**Rule LC-13 — restart is the supervisor's job, and `KeepAlive` must be conditional.** A bare
`KeepAlive=true` on macOS (and its equivalents elsewhere) restarts the daemon after an intentional
stop and defeats crash-loop containment by making every hold ineffective. The dictionary form,
restarting only on crash or unsuccessful exit, is required.

**Rule LC-14 — background is an app-level fact, not a scene-level one.** On iPadOS and on any
platform with multiple UI surfaces over one agent, `EV_BACKGROUND`
([docs/reliability.md](../reliability.md) §4.3) MUST be derived from *all* surfaces being
background, and MUST NOT be emitted while any scene, window, or external-display surface is
foreground. The shell computes this; the core sees one event.

**Rule LC-15 — pre-unlock key availability.** Where a start trigger fires before the user's
credentials are available — iOS/iPadOS before first unlock after reboot, Android with a Direct-Boot
start or an unlock-bound `DeviceKey`, and any platform where [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) binds the key to user
authentication — the agent MUST come up **fail-closed and named**: enforcement asserted, no
handshake attempted, `PLATFORM.LIFECYCLE.KEY_UNAVAILABLE_PRE_UNLOCK` raised, and rehydration
completed on the first unlock. The alternative — weakening key protection so that boot-start works
— is refused (I4). Where the platform offers device-protected storage available before first unlock
(Android's device-encrypted storage), the `LifecycleJournal`'s **minimal** subset (`boot_id`,
`clean_shutdown`, `absence_cause`) MAY live there so that the pre-unlock agent can at least know
what it should be doing; no `SECRET` or `SENSITIVE` field may.

> **Finding (F4).** [ADR-0007](ADR-0007-device-identity-and-pairing.md) specifies custody of
> `DeviceKey` but not its **availability class** — whether the key is readable before first unlock,
> and whether it is bound to user authentication. Boot-start protection and I4 pull in opposite
> directions here, and the corpus does not name the tradeoff. LC-15 states this ADR's default;
> ADR-0007 and [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) should carry an explicit availability class per platform.

### 11.4 OS-initiated suspension and termination

**Rule LC-16.** Every row below is a condition under which the agent stops running or stops being
scheduled, with **no** cooperation from the agent. For each, the product's response is specified,
and in every case the response is a property of state that already exists outside the process.

| Platform | What ends or freezes the process | Notice | Condition | Product response | What the user sees |
|---|---|---|---|---|---|
| **iOS / iPadOS** | jetsam kills the extension | **none** (`SIGKILL`) | provider resident memory over the platform ceiling, or system-wide pressure | Nothing to do at kill time; LC-7's write-ahead journal makes the next start a resume. Pre-emptively: the provider sheds its bounded caches at 10 MB and raises `PLATFORM.LIFECYCLE.MEMORY_BUDGET_EXCEEDED` before the OS acts | Tunnel drops, on-demand rules re-arm on the next network event; posture indicator goes `UNKNOWN`, never green ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18) |
| **iOS / iPadOS** | system stops the provider | `stopTunnelWithReason:` with an `NEProviderStopReason`, ~5 s | user disconnects, configuration removed, on-demand re-evaluation, device shutdown | Map the stop reason onto `absence_cause`; set `clean_shutdown` only for user/policy reasons; flush within 1 s | Named reason, not "disconnected" |
| **iOS / iPadOS** | the **app** is killed while the extension lives | none | ordinary app-process reclamation | Nothing: the app holds no runtime authority (§11.5). Contract fetch resumes when the app next runs | Nothing — this is the normal steady state |
| **Android** | Doze / App Standby | none; timers are deferred, the process is not killed | screen off + stationary; bucket below `working_set` | Park per [docs/reliability.md](../reliability.md) §11.2; detect the gap on wake from the suspend-inclusive clock, never from a timer that did not run | `PLATFORM.BACKGROUND_SUSPENDED`, informational |
| **Android** | low-memory kill of the whole process | none | memory pressure; a foreground service is late in the LMK order but not exempt | Always-on VPN has the system restart the service; otherwise `START_STICKY`. `absence_cause = OS_TERMINATION` | Brief drop; `PLATFORM.LIFECYCLE.OS_TERMINATED` |
| **Android** | user force-stop, or an OEM battery manager | none | user action; vendor policy | The app cannot restart itself; manifest receivers are disabled until the next manual launch | `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS`, user-actionable, with per-OEM guidance |
| **Android** | `onRevoke()` | a callback | another app becomes the active VPN | Tear down our tunnel cleanly; do **not** fight for the slot; report the competing app | `NET.CONCURRENT_VPN` ([docs/networking.md](../networking.md) §5.5.4) |
| **Windows** | SCM stop / shutdown timeout | `SERVICE_CONTROL_STOP`, then `SERVICE_CONTROL_PRESHUTDOWN` at shutdown | user or installer stops the service; system shutdown | Register for `SERVICE_ACCEPT_PRESHUTDOWN`; keep the whole stop path under `T_LIFECYCLE_STOP` = **2 s** so it fits inside the plain 5 s `WaitToKillServiceTimeout` as well as the longer pre-shutdown budget. **Shutdown MUST NOT remove enforcement** — persistent WFP filters stay | Clean stop; next boot resumes |
| **Windows** | Modern Standby (S0 low-power idle) | power-setting notifications, **no** `PBT_APMSUSPEND` | lid close / idle on a Modern Standby system | Treat display-off plus no user presence as `BACKGROUND` and apply [docs/reliability.md](../reliability.md) §11.1's background profile — see F7 | Nothing; the tunnel stays up at a lower cadence |
| **macOS** | `launchd` `SIGTERM` then `SIGKILL` after `ExitTimeOut` (20 s default) | signal | daemon unload, system shutdown | Same 2 s stop budget; enforcement stays | Clean stop |
| **macOS** | App Nap on the **UI** process | none | UI window occluded and idle | UI only. The daemon is not App-Napped. The UI's reconnect to the event stream on un-nap is §11.5's resync | Nothing |
| **Linux** | `systemd` `TimeoutStopSec` (90 s default) then `SIGKILL`; kernel OOM killer; `systemd-oomd` cgroup pressure | none for the OOM paths | memory pressure | `OOMScoreAdjust=-500` and `ManagedOOMPreference=avoid` on the agent unit; the UI/CLI gets a positive adjustment so it dies first | `PLATFORM.LIFECYCLE.OS_TERMINATED`; restart per §11.7 |
| **OpenWrt / routers** | kernel OOM killer on a 64–128 MB device; `sysupgrade`; overlay exhaustion | none | memory pressure; flashing | Declared memory ceiling with worst-case reservation refused at configuration time (§11.9); `oom_score_adj` written directly; a full overlay is a named diagnostic, never a crash | `PLATFORM.LIFECYCLE.OS_TERMINATED` / `PLATFORM.LIFECYCLE.STATE_UNWRITABLE` |
| **All** | power loss | none | — | `boot_id` change on next start ⇒ `COLD_START`, `absence_cause = UNKNOWN` ⇒ treated as `CRASH` | Resume |

**Rule LC-17 — the iOS/iPadOS extension budget and what it forbids.** The provider's engineering
budget is **12 MB resident**, against a platform ceiling the design MUST NOT assume exceeds
**15 MB** (§9). This is not a tuning target; it dictates the app/extension division of
responsibility. [docs/networking.md](../networking.md) §5.4 already assigns contract fetch/parse
and diagnostics to the app process for this reason. That division is completed here:

| Responsibility | App process | Extension (provider) | Rationale |
|---|---|---|---|
| Packet datapath, crypto, framing | — | **owns** | It is the only process with the tunnel fd |
| `ConnectionState` machine, path probing, migration, keepalives | — | **owns** | I5: an established `Session` cannot depend on another process being alive |
| Enforcement posture query + `ProtectionAssertion` | — | **owns** | Must be true when the app is dead |
| Durable writes of S-12, S-15, S-31, S-37, S-62 | — | **owns** (sole writer) | I8 |
| Fetch of `RelayMap`, `AccessPolicy`, `DNSPolicy`, trust documents | — | **owns** (LC-17b) | **Corrected.** Under `includeAllNetworks` the app has no network at all — see LC-17b |
| **Verification and compilation** of those documents into a compact, pre-validated binary generation | **owns** | — | Signature verification over a multi-hundred-KB document, and the allocator churn of a general parser, are the two largest transient costs |
| `RelayCapabilityToken` (S-30) — acquisition | **owns** | — | Control-plane I/O; held durably so relay reconnect needs no control plane (LC-17a) |
| Consumption of a compiled generation, and of S-30 | — | reads, **never writes** | One writer, many readers: the app publishes an immutable generation atomically; the extension consumes it read-only |
| Durable writes of S-24 user config and S-63 `ActivationPolicy` | **owns** (sole writer) | — | I8; disjoint from the extension's rows |
| Diagnostic ring beyond a bounded 64 KB tail | **owns** | bounded tail only | [docs/networking.md](../networking.md) §5.4 |
| Diagnostic bundle generation, redaction, rendering | **owns** | — | Requires the full ring and a user act ([docs/threat-model.md](../threat-model.md) §9) |
| Pairing ceremony, QR, `Owner` flows | **owns** | — | UI-bound and memory-hungry |
| Update check and download ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) | **owns** | — | |
| Crash-handler capture (§11.7) | both, independently | both | Each process crashes independently |

**Amendment LC-17b — the app cannot fetch, and the row above is corrected rather than annotated.**
This table originally gave the app process the fetch row, following
[docs/networking.md](../networking.md) §5.4's pre-correction wording. It is unbuildable.

[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) **PS-24 condition 3**: under
`includeAllNetworks` the app process has **no network**. Its traffic is
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) class 1/2 and dropped, and it cannot match
the class-7 bootstrap exemption because KS-9(1)'s predicate names the **provider**. An app-process
fetch fails in precisely the state where the contract is most needed — a device that has just
attached to a network and has no valid generation — and it fails *silently from the extension's
point of view*, which is the deadlock shape where the component that can recover is not the
component that holds the network.

**The extension fetches**, because it is the process that holds the exempted socket, and hands the
verbatim signed octets to the app over [ADR-0017](ADR-0017-local-management-interface.md).

**The verification and compilation row is unchanged and is the reason this costs nothing.** What
LC-17 exists to keep out of the provider is *"signature verification over a multi-hundred-KB
document, and the allocator churn of a general parser"* — and both stay in the app. Fetching costs
the extension a socket and a bounded buffer, not a parser: it streams into a fixed-size buffer,
never decodes, and never allocates proportionally to the document. The division this rule derives
from the 12 MB budget is therefore preserved exactly; only the row that named the wrong process for
a socket has moved.

Reported by `mobile-ios`, which found this rule, [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)
ST-31 and [docs/networking.md](../networking.md) §5.4 giving three different answers
(`ownership.md` §10.8 **M-7**). ST-31 is amended as **ST-31a** in step with this.

**Forbidden inside the provider, normatively:** general-purpose document parsing of any
`Owner`-signed or control-plane document; any allocation proportional to the size of a fetched
document; diagnostic bundle assembly; symbolication; image or asset handling; any unbounded cache;
and any synchronous dependency on the app process being alive. An implementation that violates the
last of these has moved the I5 boundary into an app that the OS kills routinely.

> **Finding (F5) — two numbers for one fact: the iOS/iPadOS extension budget.**
> [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) PB-6 budgets the extension at
> **≤ 15 MB RSS total (core + shell + buffers)**, allots the core **≤ 12 MB** of it, and sets its
> revisit trigger at **13 MB p95**. This ADR budgets the whole provider at **12 MB** with shedding
> at 10 MB. The two are not reconcilable as written, and the arithmetic is the sharper problem: a
> 12 MB core inside a 15 MB extension leaves 3 MB for the Swift shell, the per-packet `Data` copy
> ADR-0018 PB-1 concedes is unavoidable on `NEPacketTunnelFlow`, and framework overhead — and if
> this ADR's provider-wide 12 MB stands, it leaves the core **zero**.
>
> The substantive objection is that **15 MB is a ceiling, not a budget**. It is an *observed*
> jetsam threshold that Apple does not publish or guarantee, and jetsam arrives with no notice; a
> design that budgets to the ceiling dies on its first allocation spike. A budget at 80 % of an
> unguaranteed hard limit is the ordinary engineering discipline, and 12/15 is exactly that.
> ADR-0018's 13 MB revisit trigger has the same defect in miniature: it fires *after* the budget is
> already blown rather than before.
>
> **Proposed resolution, for the integrator to arbitrate.** Ownership splits cleanly: the platform
> ceiling and the provider-wide budget are a *platform-termination* fact and belong to this ADR
> (they are what LC-17's app/extension division is derived from); the **core's share within that
> budget** is [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s. Concretely — 15 MB
> ceiling (consumable by no design), 12 MB provider-wide budget, 10 MB shed threshold, core
> **≤ 9 MB** rather than ≤ 12 MB, and ADR-0018's revisit trigger moved from 13 MB to **11 MB**.
> Note that tightening the budget does **not** weaken ADR-0018's language decision: a smaller
> memory envelope makes a no-GC runtime's advantage larger, not smaller, so the ground on which it
> beat Go survives the change intact.

**Rule LC-17a — every recovery step MUST be satisfiable by the authority alone, from
pre-materialized state.** Under `includeAllNetworks` with no authorized secure path, the iOS/iPadOS
**app process has no network**: its traffic is [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
class 1/2 protected traffic and is dropped, and it cannot match the class-7 bootstrap exception
because KS-9(1)'s predicate names the *provider*, and no host firewall exists on iOS to carry an
exemption. Any recovery step routed through the app is therefore unreachable **exactly when it is
needed**. This is an instance of a defect class the integrator is tracking corpus-wide — a recovery
path routed through a channel the armed fail-closed state has already cut — and the following is this
ADR's closure of it.

| Recovery input | Must be readable by the authority alone | Materialized by | Rule |
|---|---|---|---|
| `Session` identity + last state (S-12), `Endpoint` cache (S-15), per-relay quality (S-31), negotiation floor (S-37), journal (S-62) | yes | the authority itself (sole writer, LC-17) | already satisfied |
| Cached signed `RelayMap` (S-09) | yes | app fetches, verifies and **compiles**; authority consumes the last published generation **read-only** | a **stale** map is used as-is — S-09 is `EVENTUAL` and explicitly stale-but-usable |
| `RelayCapabilityToken` (S-30) | yes | as above; held durably device-side precisely to enable control-plane-free relay reconnect | must be present before it is needed, never fetched on the recovery path |
| `AccessPolicy` (S-06), `DNSPolicy` (S-07), `OwnerTrustAnchor` (S-32), `EpochSeed` set (S-33) | yes | as above | last verified generation, anti-rollback per its own row |

Three normative consequences:

1. **No recovery step may block on, wait for, message, or launch the app process.** Not to refresh a
   document, not to re-verify one, not to fetch a token.
2. **Staleness is not a reason to stop.** Where the pre-materialized generation is stale, recovery
   proceeds with it. Where it is **absent or fails verification**, recovery fails to `BLOCKED` with a
   named code (LC-6) — never to a wait on the app.
3. **The memory-shed ladder (LC-31) MUST NOT evict recovery-path state.** The shed list is closed —
   candidate-ledger tail, quality history, diagnostic tail — and excludes every row in the table
   above, in the same way [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) EM-59 structurally
   excludes enforcement from its ladder.

A corollary for [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s **core-lite**: it is
consistent with this rule only while it is off every recovery path, which is that ADR's condition 3.
Nothing in this ADR places core-lite on one, and LC-17's division is what keeps it that way.

**Rule LC-18 — nothing in this table is a `ConnectionState`.** An OS termination produces no
transition, because there is no machine to transition. It produces a *journal fact* which becomes a
`reason_code` on the next start. This is the honest model, and it is why P21 asserts on the first
transition **after** restart rather than on a transition that cannot exist.

### 11.5 The UI/daemon and app/extension split at lifecycle boundaries

**Rule LC-19 — the survivor rule.** For each pair, exactly one side holds runtime authority, and
the other is a **replica with a declared staleness tolerance** (I8). The authority is always the
side the OS keeps alive longest for the tunnel's sake.

| Pair | Authority | Replica | What is lost when the replica dies | What is lost when the authority dies |
|---|---|---|---|---|
| Desktop/server UI ↔ daemon | **daemon** | UI | Nothing. The tunnel, enforcement, state and journal are all the daemon's | Everything runtime; enforcement survives (S-18); the UI shows `UNKNOWN`, never green |
| CLI ↔ daemon | **daemon** | CLI | Nothing; the CLI is stateless between invocations | As above |
| iOS/iPadOS app ↔ NE provider | **provider** | app | Contract refresh, diagnostics assembly, pairing, updates — all deferrable | Tunnel drops; on-demand rules re-arm; app shows `UNKNOWN` |
| Android UI ↔ `VpnService` | **service** | UI (same process, separate lifetime) | Nothing | Whole process dies; always-on or `START_STICKY` restarts it |
| macOS UI ↔ daemon ↔ system extension | **daemon + system extension** | UI | Nothing | As desktop |

**Rule LC-20 — death detection is affirmative, never inferred.** Each side detects the other's
death from an **OS-level** signal, not from silence:

- The daemon detects UI death from the management transport's own close/EOF or peer-credential
  invalidation ([ADR-0017](ADR-0017-local-management-interface.md)), and MUST NOT change any tunnel state as a result. A UI disconnect
  emits `PLATFORM.LIFECYCLE.UI_DETACHED` at `INFO` and nothing else. **A UI that dies MUST NOT
  disarm the kill switch, tear down a tunnel, or park a `Session`** — this is the single most
  important rule in this subsection and the direct negation of alternative E.
- The UI detects daemon death from transport close, and from the **assertion freshness rule**: if
  the last `ProtectionAssertion` in the event stream is older than its declared freshness window,
  the indicator becomes `UNKNOWN` regardless of what the transport says
  ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18). Silence is never rendered as health.
- On iOS/iPadOS the app detects provider status from the OS's own
  `NEVPNStatus`/`NETunnelProviderSession` state, which is authoritative and survives the app's
  death; it does not infer status from whether its own IPC replied.

**Rule LC-21 — resynchronisation is a cursor resume, not a refetch.** When a UI or CLI attaches or
re-attaches, it MUST resynchronise through [ADR-0017](ADR-0017-local-management-interface.md)'s event stream using its last cursor, and
the daemon MUST serve either (a) the missed events from that cursor, or (b) an explicit
`RESYNC_REQUIRED` marker followed by a full snapshot. It MUST NOT serve a partial stream that
silently skips events. The pattern is the one [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md)
and S-27 already establish for the control channel, applied locally.

**Rule LC-22 — no stale truth at the join.** A re-attaching UI MUST render `UNKNOWN` — not the last
value it remembers — until it has received either a snapshot or a fresh `ProtectionAssertion`. The
race this closes is: the daemon restarted while the UI was away, the UI reconnects and paints its
cached "Connected" for the 200 ms before the first event arrives, and the user acts on a screen that
was true two minutes ago. The presentation of `UNKNOWN` is [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)'s to specify; the obligation
to enter it is here.

**Rule LC-23 — the app may not be a required participant in any runtime path.** On iOS/iPadOS this
is testable: with the app force-quit, every steady-state behaviour — keepalive, liveness, rekey,
path migration, relay failover, enforcement reconciliation — MUST continue. This is I5 restated at
the process boundary, and it is asserted as a variant of P21.

### 11.6 Sleep, wake, hibernate, and fast resume

| Platform | Sleep notification | Wake notification | Bounded pre-sleep window | Kill switch across the sleep window |
|---|---|---|---|---|
| **macOS** | `IORegisterForSystemPower` → `kIOMessageSystemWillSleep` (must be acknowledged; the system waits, bounded); `NSWorkspaceWillSleepNotification`; provider `sleep(completionHandler:)` | `kIOMessageSystemHasPoweredOn`, `NSWorkspaceDidWakeNotification`, provider `wake()` | yes — acknowledge promptly, flush within 500 ms | `pf` anchor is kernel-resident and unaffected by S3; on wake the anchor is re-queried before traffic (LC-24) |
| **iOS / iPadOS** | provider `sleep(completionHandler:)` | provider `wake()` | yes, short | `includeAllNetworks` is system-maintained across sleep; settings are not removed |
| **Windows** | service `SERVICE_CONTROL_POWEREVENT` with `PBT_APMSUSPEND` (S3/S4 only); on **Modern Standby** there is no suspend event at all — `PowerSettingRegisterNotification` for `GUID_CONSOLE_DISPLAY_STATE`, `GUID_SESSION_USER_PRESENCE`, `GUID_ACDC_POWER_SOURCE`, `GUID_BATTERY_PERCENTAGE_REMAINING`, `GUID_LIDSWITCH_STATE_CHANGE` is the only signal | `PBT_APMRESUMEAUTOMATIC` (no user present) and `PBT_APMRESUMESUSPEND` (user present); on Modern Standby, display-on plus user presence | yes for S3/S4; **none** for Modern Standby | WFP filters are kernel objects; they survive S3, S4 (restored with the kernel image) and Modern Standby. A fresh boot is covered by the BOOTTIME + PERSISTENT pair |
| **Linux** | `logind` `PrepareForSleep(true)` after taking a **delay** inhibitor (`Inhibit(what="sleep", mode="delay")`, bounded by `InhibitDelayMaxSec`, 5 s default); on a headless box without `logind`, a `/usr/lib/systemd/system-sleep/` hook | `PrepareForSleep(false)` | yes, ≤ 5 s — used only to flush the journal and mark a clean park | nftables `table inet twinvpn` is kernel-resident; hibernate restores it with the kernel image; a cold boot is covered by `twinvpn-killswitch.service` |
| **Android** | `ACTION_DEVICE_IDLE_MODE_CHANGED` (Doze entry), `ACTION_POWER_SAVE_MODE_CHANGED`, `ACTION_SCREEN_OFF` | Doze exit via the same broadcast; `ACTION_SCREEN_ON`; network callbacks | no meaningful window | Lockdown is OS state and is unaffected by Doze |
| **OpenWrt / routers / headless** | none — these platforms do not sleep in this sense | — | — | Persisted `fw4` config |

**Rule LC-23a — where the lifecycle events actually come from.**
[docs/reliability.md](../reliability.md) §4.3 lists the source of `EV_BACKGROUND`,
`EV_FOREGROUND`, `EV_SUSPEND` and `EV_RESUME` as "OS lifecycle" and §11 builds its entire timer
profile on them, but on half the required platforms there is no native event to map. The mapping is
therefore application-layer work, and it is specified here:

| Platform | `EV_BACKGROUND` / `EV_FOREGROUND` source | `EV_SUSPEND` / `EV_RESUME` source |
|---|---|---|
| **iOS** | **Optimization-bearing only** (LC-23b). There is no NE API by which the provider can observe app foreground state, so it runs the background profile by default and enters the foreground profile only under an expiring app-liveness lease. No correctness-bearing event is relayed | `NEProvider.sleep` / `wake`, delivered by the OS **directly to the provider** |
| **iPadOS** | as iOS, under the all-scenes rule LC-14 | as iOS |
| **Android** | Doze entry (`ACTION_DEVICE_IDLE_MODE_CHANGED`) or App Standby demotion below `working_set` ⇒ `EV_BACKGROUND`; Doze exit or `ACTION_SCREEN_ON` ⇒ `EV_FOREGROUND` | Doze is the suspend analogue; there is no S3 equivalent |
| **Windows** | **synthesized** — `GUID_CONSOLE_DISPLAY_STATE` off **and** `GUID_SESSION_USER_PRESENCE` absent. A service has no native background concept | `PBT_APMSUSPEND` / `PBT_APMRESUMEAUTOMATIC` on S3/S4 only. **On Modern Standby neither fires**, and `EV_SUSPEND` MUST NOT be synthesized there — the process keeps running, so parking it would be a lie |
| **macOS** | **synthesized** — display sleep plus no console-user activity. App Nap applies to the UI, never to the daemon, so the daemon has no native source | `kIOMessageSystemWillSleep` / `kIOMessageSystemHasPoweredOn` |
| **Linux desktop** | **synthesized** — `logind` session idle hint / display power state where exposed | `PrepareForSleep(true)` / `PrepareForSleep(false)` |
| **Linux server, OpenWrt, headless** | **none, by design** — the host is permanently `RUNNING_HEADLESS` and the background profile never applies | none |

A synthesized event is still a real event: it is emitted once, at a debounced edge, through the same
path as a native one, so [docs/reliability.md](../reliability.md) §4.3's consumers cannot tell the
difference. What they MUST NOT do is poll for the condition.

> **Finding (F6) — the application-layer gap in [docs/reliability.md](../reliability.md) §11 and
> [docs/networking.md](../networking.md) §5.4.** Both documents specify what the client *does* when
> backgrounded or suspended, and neither specifies **who decides that it is**. §11's profile is
> unreachable on any platform where the event has to be synthesized, and the failure is silent
> rather than loud: on a Windows **Modern Standby** laptop no suspend event fires at all, so T34's
> park never happens, and the device runs the **foreground** timer profile with the lid closed all
> night — the precise battery defect §6.6's arithmetic exists to prevent, on the platform nobody
> checked because §11 was titled "Mobile background operation" (since retitled "Background and suspended operation", with R-BG-1 naming the per-platform event source). macOS has the mirror-image gap: App
> Nap never applies to a `LaunchDaemon`, so the desktop daemon has no `EV_BACKGROUND` source
> whatsoever unless one is manufactured. The table above and LC-14 are this ADR's closure of that
> gap; §11's scope statement should be broadened to match (this is the same root cause as F7, seen
> from the input side rather than the profile side).

**Rule LC-23b — correctness-bearing lifecycle events MUST reach the authority directly.** Split the
events of LC-23a into two classes, because they have different failure consequences:

| Class | Events | Delivery rule | Consequence of loss |
|---|---|---|---|
| **Correctness-bearing** | network change, suspend/resume, Doze entry/exit, on-demand wake, interface and address change, `NEProvider.sleep`/`wake`, `onRevoke` | MUST be delivered by the OS **directly to the process holding authority** — the provider, service or daemon. MUST NOT be routed through, relayed by, or conditioned on the liveness of the UI or app process | the tunnel silently stops recovering |
| **Optimization-bearing** | foreground/background, screen lock, App Standby bucket | MAY be relayed from the app where the OS exposes them nowhere else, and MUST degrade safely in its absence (below) | a suboptimal timer profile |

**Why the split, rather than a blanket rule.** On iOS and iPadOS every correctness-bearing event
above is already delivered to the provider by the OS; **foreground state alone is not observable
there without the app**. A blanket "never relay" would therefore be unimplementable, and a blanket
"relay it all" would make failure mode **F-1 (UI dead, authority alive)** a functional outage on
mobile — [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s R-25 failing exactly
where nobody would notice. This is the I5 argument applied to lifecycle events: the data plane
outlives the control plane, and it must equally outlive the *UI*.

**The safe degradation is asymmetric, and that asymmetry is the mechanism.** The authority runs the
**background** profile by default and enters the foreground profile only while holding an
unexpired `foreground_lease` — an app-liveness signal with a TTL, renewed by the app while it is
actually foreground. A dead app therefore cannot pin the authority in the foreground profile; the
lease simply expires. Defaulting the other way — assuming foreground when no signal arrives — would
mean a dead app burns the radio at the foreground cadence indefinitely, which is
[docs/reliability.md](../reliability.md) §6.6's rejected arithmetic arrived at by accident. Because
the default is also the *correct* state (an app that is not running is not foreground), F-1 is not
a degraded mode here — it is the battery-optimal one.

**Rule LC-24 — the resume sequence.** Generalising the rule
[docs/networking.md](../networking.md) §5.4 already states for iOS — *treat every wake as a
network-change event and re-validate every path rather than assuming continuity* — to **every**
platform, and adding the application-layer steps §11.3 does not cover:

```text
resume ─► 1. classify the resume:
              boot_id changed        ⇒ this is NOT a resume; run LC-4 as a COLD_START
              boot_id same, gap > 0  ⇒ suspend or hibernate resume; gap from the
                                        suspend-inclusive monotonic clock (LC-8), not wall clock
       ─► 2. query the enforcement layer for both families and verify the installed
              ruleset; re-assert RULESET_BLOCKED on any mismatch
              ───── no packet may be emitted before this line ─────
       ─► 3. re-acquire OS objects that do not survive: sockets, interface handles,
              network-change subscriptions, power/thermal notification registrations
       ─► 4. hand off to docs/reliability.md §11.3's wake ladder (re-read interfaces,
              re-assert Route/DNSPolicy, compare the gap against the rekey window,
              then steps 1–5 of §6.2)
       ─► 5. emit PLATFORM.RESUMED with the measured gap, or
              PLATFORM.LIFECYCLE.HIBERNATE_RESUMED where the platform distinguishes S4
```

Step 2 precedes step 4, which is the same ordering
[docs/reliability.md](../reliability.md) §11.3 already requires ("enforcement first, always"); it
is restated here because on desktop platforms the resume path is written by the shell and the
temptation to re-open sockets first is strong. Step 1 is new: §11.3 has no reboot discriminator.

**Rule LC-25 — pre-sleep is a flush, never a teardown.** In the bounded pre-sleep window the agent
MUST: flush the `LifecycleJournal` and any pending durable writes; record the suspend-inclusive
clock value; and record that the park is expected (so the next start does not read `CRASH`). It
MUST NOT: tear down the interface, remove routes, swap the ruleset toward anything less restrictive,
or release relay allocations. A teardown at sleep is a teardown the wake path then has to undo,
during exactly the interval in which the machine is most likely to emit its first packet.

> **Finding (F7).** [docs/reliability.md](../reliability.md) §11 is titled *Mobile background
> operation* and its profile table is framed for mobile. Windows Modern Standby, macOS Power Nap,
> and any laptop with an aggressive suspend policy present the same problem class on desktop: the
> process is alive, timers are coalesced hard, and the radio/NIC is in a low-power mode. This ADR
> applies §11.1's background timer profile to `HostLifecycleState = BACKGROUND` on **every**
> platform, not only mobile, and applies §11.2's parking rule only where an inbound requirement is
> absent — identical semantics, wider scope. If [docs/reliability.md](../reliability.md) intends
> §11 to be mobile-only, that is a contradiction with R-08's spirit and should be resolved by
> broadening §11's scope statement rather than by adding a second desktop profile here.

### 11.7 Crash, restart, and crash-loop containment

**Rule LC-26 — what a crash leaves behind.**

| Artifact | State after an abnormal agent exit | Owner |
|---|---|---|
| Enforcement rule set | **Survives, still fail-closed.** Kernel-resident, owner-tagged, reclaimable | S-18, [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6, KS-20 |
| Transport keys, replay windows | Lost — non-durable by requirement | S-13 |
| Relay allocations, `SessionTag` | Lost; re-allocated on reconnect | [docs/reliability.md](../reliability.md) §6.5 |
| Virtual interface | Reclaimed, not duplicated: owner-tagged and GUID-stamped, `destroy_interface()` idempotent after crash | [docs/networking.md](../networking.md) §5.3, §5.5.3, §5.1 |
| Routes, resolver config, policy-routing rules | Owner-tagged and reclaimable by the fresh process; `S-34` restore point readable without the agent | [docs/networking.md](../networking.md) §5.5.3, [ADR-0011](ADR-0011-dns-handling.md) |
| `PortalExemptionGrant` | Gone by requirement — never survives a restart | S-35 |
| Durable store | Crash-consistent: the fresh process opens it without a repair tool, or rehydration fails closed under LC-6. **Requirement on ADR-0020** | S-62, [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) |
| `LifecycleJournal` | `clean_shutdown` clear ⇒ `absence_cause = CRASH` | LC-7 |

**Rule LC-27 — supervision is [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s,
and this ADR yields it.** Restart policy, backoff, crash-loop detection and containment, safe mode,
and configuration-generation quarantine are specified by
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.6, rules **PS-9/PS-10/PS-11**,
and are **not restated here**. An earlier draft of this ADR specified them, which would have made
two owners for one mechanism.

The cession is on the merits, not on seniority: **quarantine has to interlock with the enforcement
rule set** — a hold that cannot see whether the latch is up is not containment, it is a delay — and
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) owns the privilege boundary that
rule set lives behind. Supervision also *is* the authority's own lifetime, which is that ADR's
subject; what remains here is OS-scheduled execution **within** a running authority.

**Rule LC-28 — what this ADR owns on the containment seam, stated as obligations on PS-9/PS-10/PS-11
rather than as a second mechanism.** The clean split is that **this ADR owns the evidence and
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) owns the policy**:

1. **The evidence is S-62.** `absence_cause`, the abnormal-exit ring, and
   `last_applied_contract_generation` are written **write-ahead** (LC-7) by the process holding the
   single-instance lock, and they are the only record that survives a kill in which no exit handler
   runs — jetsam, the OOM killer, `SIGKILL`. PS-10's crash-loop counter and PS-11's quarantine both
   key on facts this ADR guarantees exist and are truthful; neither can be built on an exit path.
2. **`apply()` and `set_ruleset()` are rate-limited** to `N_LIFECYCLE_APPLY_MAX` = **6** per 60 s
   across all restarts, and suppressed entirely while held. Network-stack flap is a *lifecycle-visible
   harm to the whole host*, not only to us, and the limit is therefore stated here as a constraint on
   any restart policy — including one an operator has weakened.
3. **The hold marker in S-62 is durable**, so a containment decision survives a supervisor whose
   configuration an operator has changed underneath it.
4. **The management interface MUST remain available while held or in safe mode.** This is what makes
   the device *blocked, not bricked* ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-20);
   it is stated here because it is an obligation on **ADR-0017**'s transport (I-02(d)), not on the
   supervision mechanism itself.
5. **Enforcement is never a containment lever.** No hold, backoff, quarantine or safe-mode path may
   remove or weaken the rule set, on any platform, for any reason. Mutant `M-P21-3` exists to falsify
   this, and P21's crash-loop cell measures it end to end.

**Rule LC-29 — supervision posture is reported, whoever owns the policy.** Whether a supervisor will
in fact restart the agent is observable at LC-4 step 10, and when nothing will,
`PLATFORM.LIFECYCLE.SUPERVISOR_ABSENT` is raised at `WARN`. An unsupervised agent is not a bug; a
reliability claim that is silently no longer true is. The *policy* behind this is
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-9's; only the reason code and the
obligation to surface it are registered here, and §11.11 marks that code and the three containment
codes as withdrawable into `PLATFORM.SERVICE.*` if that ADR prefers to carry them.

**Rule LC-30 — crash reporting cannot carry `SECRET` material.** The mechanism, not the intention:

1. **One arena.** All `SECRET`-classified material — static and ephemeral key material, handshake
   state, `EpochSeed`s, `TwinNetPSK`, packet plaintext buffers — is allocated exclusively from a
   `SecretArena`: a dedicated allocator with guard pages, `mlock`/`VirtualLock`, zero-on-free, and
   the platform's dump exclusion applied to the whole arena at creation
   (`madvise(MADV_DONTDUMP)` on Linux/Android; `WerRegisterExcludedMemoryBlock` plus a
   `MiniDumpWriteDump` callback that declines the arena's ranges on Windows; the arena's ranges
   excluded from our own handler's capture set on Apple platforms). The core's type system enforces
   the "exclusively" — a `Secret<T>` wrapper whose only constructor allocates from the arena — and a
   CI test fails the build on any direct allocation of a key-bearing type outside it (H1 makes this
   one check for all platforms).
2. **No OS crash reporter uploads.** `RLIMIT_CORE=0` and `LimitCore=0`; `PR_SET_DUMPABLE=0` on
   Linux/Android for the agent; Windows Error Reporting consent declined for our binaries; Apple
   analytics sharing not requested. The system `core_pattern` and equivalent host configuration are
   **not** modified ([docs/networking.md](../networking.md) §5.5.2's spirit).
3. **Our handler captures no memory contents.** The in-process handler serialises: `reason_code`,
   build id and module list, the faulting thread's unwound **return addresses**, and thread states —
   and **no stack bytes and no heap bytes**. Registers are captured only for threads whose faulting
   frame is outside the crypto and arena module ranges.
4. **The residual, named.** A key byte can transiently live in a register or a spilled stack
   temporary inside the crypto module. Mitigations: crypto entry points are non-inlined boundaries
   that zeroise their spilled frame before returning; and where the faulting frame **is** inside the
   crypto or arena module range, the handler emits **no register set and no unwind at all** — only
   `INTERNAL.INVARIANT_VIOLATED`, module identity and offset — and raises
   `PLATFORM.LIFECYCLE.CRASH_REPORT_SUPPRESSED`. The residual that remains is the platform's own
   device-side crash log on iOS/iPadOS and the Android tombstone, neither of which a third-party app
   can prevent being written; they are not uploaded by us, and this is disclosed.
5. **Reports never leave without a user act.** Same rule as the diagnostic bundle
   ([docs/threat-model.md](../threat-model.md) §9(3)): generated locally, rendered for inspection,
   `DeviceKey`-signed, rate-limited, pushed by the user. **No remote "collect a crash report"
   command exists.**

### 11.8 Battery, power, thermal, and resource posture

The keepalive/battery tradeoff is [docs/reliability.md](../reliability.md) §6.6's and is not
re-decided. This subsection owns the **application-layer** half: the budgets (§9), the OS signals
consumed, and the closed list of what a budget may never buy.

**Rule LC-31 — signals consumed.** `query_link_facts()`
([docs/networking.md](../networking.md) §5.1) returns `metered` and `low_power`; both MUST be
consumed, and thermal state MUST be read from the platform (`ProcessInfo.thermalState` on Apple
platforms; `PowerManager.getCurrentThermalStatus()` on Android API 29+; power/thermal notifications
on Windows and Linux).

| Signal | Application-layer response | Announced as |
|---|---|---|
| `low_power = true` (iOS Low Power Mode, Android battery saver, Windows/macOS battery saver) | Adopt the `BACKGROUND` timer profile even if attended; suppress the warm relay standby; move the direct-upgrade prober from timer-driven to event-driven; defer update checks ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)); defer telemetry flush | `PLATFORM.LIFECYCLE.LOW_POWER_PROFILE`; standby suppression uses the existing `RELAY.STANDBY.SUPPRESSED_POWER` ([docs/reliability.md](../reliability.md) §11.4) |
| `metered = true` | Suppress the warm relay standby; defer update **download** (not the check) to an unmetered link; require explicit consent for any bundle or telemetry upload | existing `RELAY.STANDBY.SUPPRESSED_METERED` |
| Thermal `serious` or worse | Reduce probe cadence to the background floor; disable opportunistic direct-upgrade probing; cap crypto worker threads to one | `PLATFORM.LIFECYCLE.THERMAL_THROTTLED` |
| Extension resident memory over 10 MB | Shed bounded caches (candidate ledger tail, quality history, diagnostic tail) before the OS acts | `PLATFORM.LIFECYCLE.MEMORY_BUDGET_EXCEEDED` |

**Rule LC-32 — the closed list of forbidden reductions.** No power, thermal, metering or memory
pressure may cause the client to: disarm or weaken the kill switch or its rule set; skip or defer a
rekey; lengthen liveness detection such that a dead path is undetected beyond `T_DEAD` **while user
traffic is being offered**; suppress or delay a `reason_code` for a degraded or terminal condition;
stop renewing the `ProtectionAssertion`; or silently reduce protection scope. Every permitted
reduction is in the LC-31 table and every one of them is announced. A silent downgrade is the defect
this rule exists to make reviewable.

**Rule LC-33 — Android foreground-service posture.** A user-started `VpnService` runs as a
foreground service with an ongoing notification for as long as the tunnel is up. The notification
MUST render the derived `ConnectionState` per [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)'s presentation contract, MUST be visually
distinct for `DEGRADED` and `BLOCKED` ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's
presentation obligation), and MUST NOT be a static "VPN active". The system's own VPN key indicator
is in addition to, not instead of, this. The manifest `foregroundServiceType` declaration required
by recent Android releases is a packaging concern and is stated as an interface on [ADR-0021](ADR-0021-packaging-distribution-and-updates.md).
Where the tunnel is started by the system as an always-on VPN, no TwinVPN-owned foreground
notification is required and one MUST NOT be forced.

**Rule LC-34 — the budgets are gates.** Every value in §9 is asserted in the lab per release. A
build that exceeds one fails; there is no "battery regression" triage lane that ships.

### 11.9 The headless, server, and router lifecycle

This shape is genuinely different: no user session ever, no sleep, indefinite uptime, correct
behaviour at boot before any human is present, and on a router a 64–128 MB budget shared with the
whole system. [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns the profile; the following are stated as requirements on it.

**Rule LC-35 — no session dependencies.** The agent MUST NOT require, at any point in LC-4 or in
steady state: a logged-in user, a desktop session, a display, a D-Bus **session** bus, a keyring or
secret-service daemon, a notification daemon, or a browser. Any one of these as a hard dependency is
a defect against R-21 and is a named startup failure, not a hang. This is a hard requirement on
[ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)'s secure-storage realization: the headless custody path must work with no user session.

**Rule LC-36 — start ordering.** `After=local-fs.target` and `RequiresMountsFor=` the state
directory, so the journal is never read from a not-yet-mounted path; `After=` and `Requires=` the
enforcement unit; **not** `After=network-online.target` (LC-10). On OpenWrt, `START` after `network`
with the `fw4` include already persisted, and UCI `reload_config` triggers so a configuration change
is a reload rather than a restart — a restart on a router is a datapath outage.

**Rule LC-37 — the watchdog must be conditional.** `WatchdogSec` (systemd) and
`procd_set_param watchdog` are used, and the keep-alive ping MUST be emitted only by a supervisor
thread that has verified, in that interval, that (a) the state-machine tick has advanced and (b) the
most recent `ProtectionAssertion` is within its freshness window. A ping that a hung agent can still
emit is not a watchdog; it is a liveness claim with no evidence behind it. On Windows, where the SCM
provides no watchdog, the equivalent is an in-process supervisor thread plus the health check
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) specifies.

**Rule LC-38 — log rotation pressure.** On embedded and headless profiles the primary sink is the
bounded in-memory ring ([ADR-0015](ADR-0015-observability-and-diagnostics.md) Tier 0), optionally
mirrored to the platform's own logger (`syslog`, `logd`, the journal). File logging is **opt-in**,
size-capped with internal rotation, and MUST NOT depend on an external `logrotate`. A full or
read-only filesystem MUST NOT crash the agent, block the datapath, or fail a durable write silently:
it raises `PLATFORM.LIFECYCLE.STATE_UNWRITABLE` once, rate-limited, and — because the durable store
is then unable to record state — the agent holds `RULESET_BLOCKED` rather than continuing with an
unrecordable session set (LC-6's reasoning applied at runtime).

**Rule LC-39 — memory pressure.** The agent declares a memory ceiling at startup and refuses, at
**configuration** time, any peer count or feature set whose worst-case reservation exceeds it —
following [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) MG-15's *pattern* (refuse at
configuration time, not when the last peer connects). The ceiling's **value**, and the ordered
shedding ladder applied when it is approached, are
[ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)'s (§11.14, EM-58/EM-59) and are consumed
here unchanged; this ADR adds only the lifecycle-side obligations that ladder depends on — that
enforcement is never a shedding candidate at any step, and that an OOM kill is an ordinary
`absence_cause = OS_TERMINATION` resolved by LC-4 rather than a special case. > **Finding (F8).** [ADR-0013](ADR-0013-multi-client-gateway-architecture.md) §11.5 names its
> smallest reference class "**G1 — Router class**" and then gives its hardware as "OpenWrt-class /
> RPi 4B … 2 GB". A 2 GB quad-core Cortex-A72 is not router-class; a real OpenWrt 21.02 target is
> 64–128 MB of RAM shared with the entire system, which is the figure this ADR's §11.9 is written
> against. Sizing the lifecycle layer against G1 would have produced a budget roughly an order of
> magnitude too generous. [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) introduces a
> genuinely router-class tier below G1 — the **`H-EMB`** deployment profile, whose numbers are
> derived against the **`GC-0`** silicon class (MIPS 24Kc @ 580 MHz, 1 core, ~24 MB free, 16 MB
> flash) — and this ADR aligns with it rather
> than with G1. Two things the integrator must reconcile: ADR-0013 §11.5's hardware premise is an
> amendment owed by its owner, and the tier is spelled `G0` in the ADR-0023 draft on disk while
> `H-EMB` is the agreed designation. An intermediate proposal to call it `HC-0` was **withdrawn**,
> because it reproduced the same category error one level up:
> [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s `HC-1`/`HC-2`/`HC-3` are **host
> classes on a process-topology axis** (attended-separable / OS-mediated / headless), while `H-EMB`
> is not. There are **three orthogonal axes** and `HC-0` would have joined the wrong one's ordinal
> series: **`GC-*`** is silicon ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)),
> **`HC-*`** is process topology
> ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)), **`H-*`** is deployment profile.
> They **compose**: a router is `HC-3` by topology, `H-EMB` by profile, and `GC-0` by silicon. This
> ADR uses all three — §11.9 is the `HC-3` lifecycle, §9's memory row is the `H-EMB` envelope, and
> the number inside it is `GC-0`-derived.
> ADR-0013's **per-peer byte model** is unaffected by any of this and remains sound.

It sets a protective `oom_score_adj` (−500 on Linux, written
directly on OpenWrt where cgroups are unavailable) so the datapath is not the kernel's first victim,
and a positive adjustment on any UI/CLI helper so those die first. Where cgroup limits exist,
`MemoryMin` is set so the agent is protected from `systemd-oomd` reclaim
(`ManagedOOMPreference=avoid`).

### 11.10 Always-on, connect-on-demand, and the trusted-network exception

| Platform | Always-on mechanism | Who can enable it | What TwinVPN can observe |
|---|---|---|---|
| **Android** | System always-on VPN + "Block connections without VPN" (lockdown) | the **user** in Settings, or a DPC/MDM | **Not reliably observable by a non-DPC app.** See LC-40 |
| **iOS / iPadOS** | Supervised Always-On VPN payload (MDM); otherwise `NEOnDemandRuleConnect` with `disconnectOnDemandEnabled = false` | MDM for true always-on; the app installs on-demand rules with user consent | The `NETunnelProviderManager` configuration is ours to read; the supervised payload's presence is observable through the managed configuration |
| **macOS / Windows** | Daemon/service connects at boot; UI attaches later | installer + local `Owner` | Fully observable — it is our own service |
| **Linux / OpenWrt / headless** | The unit is enabled; there is no other mode | operator | Fully observable |

**Rule LC-40 — report `UNVERIFIED`, never a posture you cannot observe.** On Android 10 and later a
non-DPC application cannot read whether it is configured as the always-on VPN, nor whether lockdown
is enabled. The obvious in-app probe does not work either: under lockdown the VPN app's *own*
sockets are the ones still permitted, so a successful off-tunnel probe from our own process proves
nothing about other apps. Therefore the posture surface has three values —
`LOCKDOWN_CONFIRMED` (DPC-provisioned, or reported by the managed configuration),
`LOCKDOWN_UNVERIFIED`, `LOCKDOWN_ABSENT` — and `LOCKDOWN_UNVERIFIED` MUST be presented as *not
protected by lockdown*, with the guided flow to `Settings.ACTION_VPN_SETTINGS`.

> **Finding (F9).** [docs/networking.md](../networking.md) §5.4 says "the app detects whether it is
> enabled and reports it as part of the kill-switch posture", and
> [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's limitation table consumes that
> claim. For a non-DPC app on a modern Android release the detection is not available. The claim
> should be replaced by LC-40's three-valued posture in both documents; otherwise the corpus
> promises a detection that cannot be built, and a product would be tempted to guess.

**The trusted-network exception.** "Don't connect on my home Wi-Fi" is a real user request and a
real security decision. The identification question decides whether it can be offered at all.

| Candidate identifier | Can an attacker replicating the network defeat it? | Verdict |
|---|---|---|
| SSID | Yes, trivially — an SSID is a name anyone may choose | **MUST NOT** be the decision |
| BSSID / AP MAC | Yes — a MAC address is settable | insufficient |
| Gateway MAC, subnet, DHCP fingerprint, DNS suffix | Yes — all are attacker-chosen on an attacker-run network | insufficient |
| WPA2/WPA3-Personal association | Not by an outsider (association proves the AP holds the PMK), but yes by anyone who knows the passphrase; and the platform APIs do not expose *which* credential authenticated | insufficient as the sole basis |
| **An authenticated handshake with a `TrustedPeer` on the same L2 segment** | **No.** It requires the peer's private key ([ADR-0007](ADR-0007-device-identity-and-pairing.md), I4). Replicating a name proves nothing | **sufficient** |

**Rule TN-1 — proof, not name.** A network is `TRUSTED` only while at least one `TrustedPeer` is
reachable on the same L2 segment and has completed an authenticated handshake
([ADR-0001](ADR-0001-tunnel-protocol-and-cryptographic-foundation.md)) within
`T_TRUSTED_NET_PROOF` = **60 s**. SSID, BSSID and gateway identity MAY be used as a cheap *hint* to
decide when to attempt the proof — never as the decision.

**Rule TN-2 — what the exception may change, and what it may not.** A trusted-network proof MUST NOT
disarm the kill switch, remove the rule set, or change the enforcement mode. What it may change is
**scope**: whether the default route is claimed and whether the `ExitNode` is engaged. "Don't route
through my exit node at home" is expressible and safe; "turn protection off at home" is not, and is
only reachable by the authenticated user action
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.10 already requires. This constraint is
what bounds the worst case of a mis-identified network to a narrower protected scope rather than to
an open device.

**Rule TN-3 — losing the proof re-engages first.** When the proof expires or the segment changes,
the wider scope is re-engaged **before** any traffic is emitted on the new network, in the
protected-first order of LC-24 step 2. Expiry is not a graceful degradation.

**Rule TN-4 — unprovable means unavailable.** On a network where no `TrustedPeer` is present — a
home network where the phone is the only TwinVPN device — the feature is **unavailable** and MUST be
presented as unavailable with `PLATFORM.LIFECYCLE.TRUSTED_NET_UNPROVABLE` and its explanation. It
MUST NOT silently fall back to SSID matching. The residual is stated plainly: users who want
SSID-based trust cannot have it, deliberately.

**Rule TN-5 — the iOS/iPadOS constraint.** On-demand rules are evaluated by the **system**, using
`SSIDMatch`, and we cannot inject a cryptographic predicate into that evaluation. Therefore
`SSIDMatch` MAY be used only in `NEOnDemandRuleConnect` rules — biasing *toward* connecting, which
is safe under a spoofed SSID — and MUST NOT be used in a `Disconnect` or `Ignore` rule, which would
be exactly the spoofable exception. The scope narrowing of TN-2 is applied inside the running
provider, where the proof is available, not by the system's rule evaluation.

### 11.11 Reason codes contributed

All codes are in the assigned `PLATFORM.LIFECYCLE.*` namespace, three segments, registered in
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 form. The existing `PLATFORM.*`
lifecycle codes in [docs/architecture.md](../architecture.md) §2.5.1 — `PLATFORM.PROCESS_RESTARTED`,
`PLATFORM.PROCESS_CRASHED`, `PLATFORM.CRASH_LOOP`, `PLATFORM.SUSPENDED`, `PLATFORM.RESUMED`,
`PLATFORM.BACKGROUND_SUSPENDED`, `PLATFORM.SCREEN_LOCKED` — are **consumed unchanged and not
duplicated**.

| Code | Class | Sev | Terminal | Actionable | Meaning / user-facing text / next action |
|---|---|---|---|---|---|
| `PLATFORM.LIFECYCLE.COLD_START` | TRANSIENT | INFO | no | no | Agent started with no prior in-memory state. *"TwinVPN started."* Evidence: `absence_cause`, absence duration, `boot_id` continuity |
| `PLATFORM.LIFECYCLE.REHYDRATED` | TRANSIENT | INFO | no | no | Durable state restored; sessions re-entered per LC-2. *"Restoring N connections."* Evidence: session count, per-peer rehydrated state |
| `PLATFORM.LIFECYCLE.REHYDRATE_INCOMPLETE` | POLICY | CRITICAL | no | **yes** | A required durable object was missing or failed verification; traffic is held. *"TwinVPN cannot confirm what it should be protecting, so it is blocking traffic."* Next: run the repair/reset flow |
| `PLATFORM.LIFECYCLE.REHYDRATE_TIMEOUT` | POLICY | CRITICAL | no | **yes** | `T_REHYDRATE_MAX` exceeded. Same disposition and next action |
| `PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT` | PERSISTENT | ERROR | yes | **yes** | Another agent instance holds the lock; this one exits without touching any state. Next: stop the other instance |
| `PLATFORM.LIFECYCLE.STATE_UNWRITABLE` | PERSISTENT | ERROR | no | **yes** | The state directory is full or read-only. Next: free space / remount the overlay |
| `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED` | PERSISTENT | WARN | no | **yes** | The OS start trigger is not registered or is disabled. Next: enable it (per-platform instructions) |
| `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` | PERSISTENT | WARN | no | **yes** | The OS or a vendor battery manager is preventing autostart (Android force-stop, OEM policy, disabled login item). Next: the per-vendor allowlist flow |
| `PLATFORM.LIFECYCLE.ONDEMAND_RULES_ABSENT` | PERSISTENT | WARN | no | **yes** | iOS/iPadOS: no on-demand rules installed, so nothing will start the tunnel automatically. Next: enable automatic connection |
| `PLATFORM.LIFECYCLE.OS_TERMINATED` | TRANSIENT | WARN | no | no | The OS ended the process (jetsam, low-memory kill, OOM). Evidence: which mechanism, resident high-water |
| `PLATFORM.LIFECYCLE.MEMORY_BUDGET_EXCEEDED` | PERSISTENT | ERROR | no | no | The provider crossed its shed threshold; caches were dropped to avoid an OS kill |
| `PLATFORM.LIFECYCLE.RESTART_HELD` | PERSISTENT | CRITICAL | no | **yes** | Restart suppressed after repeated crashes; traffic remains blocked. Next: view the diagnostic, then reset or repair. **Raised by ADR-0016's supervision layer (PS-10); withdrawable into `PLATFORM.SERVICE.*`** |
| `PLATFORM.LIFECYCLE.SAFE_MODE_ENTERED` | PERSISTENT | CRITICAL | no | **yes** | Started in reduced mode: enforcement only, no tunnel, control interface available. Next: as above. **Raised by ADR-0016 (PS-10); withdrawable into `PLATFORM.SERVICE.*`** |
| `PLATFORM.LIFECYCLE.GENERATION_QUARANTINED` | PERSISTENT | ERROR | no | no | A configuration generation correlated with repeated crashes and was set aside; the previous good generation is in use. **Raised by ADR-0016 (PS-11) off this ADR's S-62 evidence; withdrawable into `PLATFORM.SERVICE.*`** |
| `PLATFORM.LIFECYCLE.CRASH_REPORT_SUPPRESSED` | TRANSIENT | INFO | no | no | The fault was inside a secret-bearing module, so no memory, registers or unwind were captured |
| `PLATFORM.LIFECYCLE.KEY_UNAVAILABLE_PRE_UNLOCK` | TRANSIENT | WARN | no | **yes** | Started before first unlock; the device key is not yet available, so traffic is blocked. Next: unlock the device |
| `PLATFORM.LIFECYCLE.BOOT_BEFORE_LOGIN` | TRANSIENT | INFO | no | no | Running with no user session; capabilities that need one are unavailable |
| `PLATFORM.LIFECYCLE.HIBERNATE_RESUMED` | TRANSIENT | INFO | no | no | Resumed from hibernation; the full wake sequence ran. Evidence: measured gap |
| `PLATFORM.LIFECYCLE.LOW_POWER_PROFILE` | TRANSIENT | INFO | no | no | Reduced background activity because the OS reports low-power mode. Evidence: which reductions applied |
| `PLATFORM.LIFECYCLE.THERMAL_THROTTLED` | TRANSIENT | WARN | no | no | Probing and crypto parallelism reduced because the device is hot |
| `PLATFORM.LIFECYCLE.SUPERVISOR_ABSENT` | PERSISTENT | WARN | no | **yes** | No supervisor will restart the agent if it exits. Next: enable the service/unit. **Policy is ADR-0016 PS-9's; withdrawable into `PLATFORM.SERVICE.*`** |
| `PLATFORM.LIFECYCLE.UI_DETACHED` and `PLATFORM.LIFECYCLE.UI_REATTACHED` | TRANSIENT | INFO | no | no | A management client disconnected or reconnected. **No tunnel effect** (LC-20) |
| `PLATFORM.LIFECYCLE.TRUSTED_NET_ENGAGED` and `PLATFORM.LIFECYCLE.TRUSTED_NET_RELEASED` | TRANSIENT | INFO | no | no | The trusted-network scope narrowing took or released effect. Evidence: proving peer, proof age |
| `PLATFORM.LIFECYCLE.TRUSTED_NET_UNPROVABLE` | PERSISTENT | WARN | no | **yes** | No TwinVPN peer is reachable on this network, so it cannot be proven trusted; the exception is unavailable here. Next: none required — this is the safe outcome |

### 11.12 Proof test P21 — conformance surface

**P21 — The client resumes protected and unattended from every way it can be stopped.**

| | |
|---|---|
| **Proves** | R-08, R-13, **R-44**, **R-45**; invariants I3, I4, I6, I8 |
| **Lab scenario** | The lifecycle matrix: {each supported platform} × {clean stop, `SIGKILL`, OS memory termination, crash loop, reboot, suspend/resume, hibernate/resume, user force-stop, OS-update service restart}. Embedded rows run on the emulated OpenWrt target of [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| **Preconditions (V3)** | At least two peers paired and `TrustedPeer` present; enforcement mode `FAIL_CLOSED`; a marked, continuous bidirectional traffic generator running throughout, in **both** families; a 32-byte **canary key** installed in the `SecretArena` in place of a transport key; wire capture on every physical interface of the device namespace for the whole run |

**Procedure.** 1. Reach a steady state (`WAN_DIRECT` or `RELAYED`) with traffic flowing. 2. Inject
the cell's termination event. 3. Hold for 60 s. 4. Allow the platform's own start trigger to fire —
do **not** start the agent by hand except in the user-initiated cell. 5. Hold for 120 s past
recovery. 6. Collect: the transition/`Diagnostic` stream, the `LifecycleJournal`, the wire capture,
and **every** crash artifact the run produced (our reports, core files, OS crash logs, tombstones).

**Oracle.**
1. **Zero off-tunnel egress of protected-scope traffic** on any physical interface, in either
   family, from the instant of termination to the instant the agent reaches LC-4 step 11. One
   marked packet is a failure.
2. The first per-peer transition after restart carries `PLATFORM.LIFECYCLE.REHYDRATED`, and the
   rehydrated state matches LC-2's table for that peer's last durable state. A peer that was
   established resumes in `RECONNECTING` — **`DISCONNECTED` is a failure**.
3. `session_id` is byte-identical across the restart (S-12), and `absence_cause` in the journal
   matches the injected termination.
4. Process start to first `ProtectionAssertion` ≤ `T_REHYDRATE` at p95 across runs, and
   ≤ `T_REHYDRATE_MAX` in every run.
5. **Crash-loop cell only** — the containment mechanism is [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.6's and this oracle **consumes its conformance surface rather than re-deriving it** ([docs/testing-strategy.md](../testing-strategy.md) PT-4); what P21 adds is the end-to-end egress assertion across the hold. `apply()` invocations ≤ `N_LIFECYCLE_APPLY_MAX` in any 60 s window;
   `PLATFORM.CRASH_LOOP` and `PLATFORM.LIFECYCLE.RESTART_HELD` both emitted; the management
   interface answers a status request while `HELD`; oracle 1 still holds throughout.
6. **The canary is absent from every collected artifact.** The oracle greps every byte of every
   crash artifact for the canary value; one occurrence is a failure (I4).
7. **Suspend/resume and hibernate cells:** the enforcement query of LC-24 step 2 appears in the
   stream **before** the first post-resume packet on any interface, and a `boot_id` change routes
   through `COLD_START` rather than the resume path.

**Mutants (V2).**

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P21-1` | Rehydration starts network activity before the enforcement query (LC-4 steps 3–4 moved after step 11) | Oracle 1: marked packets on the physical interface during the start window |
| `M-P21-2` | Restart resets every peer to `DISCONNECTED` | Oracle 2 |
| `M-P21-3` | Crash-loop containment removes the rule set to "recover" | Oracle 1 and oracle 5 |
| `M-P21-4` | A transport key allocated outside the `SecretArena` | Oracle 6: the canary appears in a crash artifact |
| `M-P21-5` | `N_LIFECYCLE_APPLY_MAX` removed | Oracle 5 |
| `M-P21-6` | UI disconnect tears down the tunnel (alternative E reintroduced) | Oracle 1 in the UI-kill variant; `PLATFORM.LIFECYCLE.UI_DETACHED` followed by a teardown transition |

**Positive control (V4).** The same rig with enforcement mode `PERMISSIVE_ANNOUNCED` and a
deliberately permissive rule set MUST show the marked packets on the physical interface — proving
the wire oracle can observe a leak at all before any zero-egress result is believed.

**Pass criteria.** 20/20 runs per platform × termination cell; every mutant fails with its named
oracle; oracle 6 clean in every cell on every platform.

**Known limits.** iOS/iPadOS unsupervised devices have no boot-start, so that cell asserts the
`POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` window P09 already measures rather than a resume.
Injected memory termination on iOS/iPadOS is an approximation of jetsam under real system pressure.
The device-side OS crash log on iOS/iPadOS and the Android tombstone are collected and scanned, but
their contents are not under our control — a canary hit there is reported as a **platform residual**
finding rather than a build failure, and is the residual LC-30(4) names.

### 11.13 Interfaces required from other ADRs

| # | Required from | Interface (stated as an interface, not an internal) |
|---|---|---|
| I-01 | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | A privileged long-lived agent whose lifetime is independent of any UI process, and whose privilege is sufficient to query and swap the enforcement rule set without a user session |
| I-01a | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | **Supervision, ceded to it (LC-27).** In return this ADR requires that PS-9/PS-10/PS-11: (a) key their crash and quarantine counters on S-62's **write-ahead** fields, since no exit path runs under jetsam, the OOM killer or `SIGKILL`; (b) honour `N_LIFECYCLE_APPLY_MAX` — network-stack flap harms the whole host, not only us; (c) never use enforcement as a containment lever (LC-28(5)); (d) keep the management interface up while held or in safe mode; (e) treat a supervisor whose configuration an operator weakened as still bound by the durable hold marker |
| I-01b | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | **Confirmed: correctness-bearing lifecycle events reach the authority directly and never via the app (LC-23b).** This ADR adds the part its requirement leaves open — foreground state is *not* observable by the iOS/iPadOS provider without the app, so it is classed optimization-bearing and degrades through an expiring `foreground_lease` whose default is the background profile. F-1 is therefore battery-optimal rather than a functional outage. Core-lite stays off every recovery path by LC-17a |
| I-02 | [ADR-0017](ADR-0017-local-management-interface.md) | (a) A management transport created **by** the running agent, never socket-activating it; (b) a cursor-resumable event stream with an explicit `RESYNC_REQUIRED` marker (LC-21); (c) a typed `HostLifecycleState` event (LC-3); (d) the interface remains available while `HELD`/safe mode (LC-28(4)); (e) client disconnect has **no** tunnel-state effect (LC-20) |
| I-03 | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | (a) A `Secret<T>` type whose only allocator is the `SecretArena`, with a build-time check for direct allocation elsewhere; (b) **three distinct injected clock types — `MonotonicClock`, `ElapsedClock`, `WallClock` — that are not interchangeable at the type level**, so a call site cannot silently take the wrong one; the per-platform primitive for each is LC-8's table. This discharges [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.16(e): the answer is that `MonotonicClock` does **not** advance across suspend, and that the gap is a separate clock rather than a property of that one; (c) one portable lifecycle state machine callable from every shell over the C ABI |
| I-04 | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | Presentation of `HostLifecycleState`, of `UNKNOWN` protection (LC-22), and of the `PLATFORM.LIFECYCLE.*` codes' summary and next-action text |
| I-04a | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) **X6(a) — confirmed.** Foreground, background, suspend and resume reach the UI **as typed events** on the management stream (LC-3, LC-23a), never as something the UI must infer or poll for. This ADR additionally guarantees they are emitted on platforms where the OS provides no native event, by synthesis (LC-23a). ADR-0019's §11.9(4) is right to refuse wall-clock arithmetic: F3 records that the corpus's own suspend-gap measure is a wall clock, which jumps, and that the suspend-inclusive monotonic clock is the correct one — the UI should not be doing that arithmetic at all | |
| I-04b | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) **X6(b) — confirmed, with one boundary.** The Android foreground-service notification is a UI surface: this ADR owns **whether the service exists and when** (LC-33), ADR-0019 owns **what the notification says and when it must go `UNKNOWN`** under its freshness gate and PC-7. The boundary ADR-0019 must handle: under system-started **always-on** VPN there may be no TwinVPN-owned notification at all (LC-33 forbids forcing one), so the freshness gate must tolerate the surface being **absent**, not merely stale. The stale-"Connected"-notification defect it names is real and is why LC-33 already forbids static chrome | |
| I-05 | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | (a) A crash-consistent store openable by a fresh process with no repair tool; (b) a **consistent snapshot** read across S-12/S-15/S-24/S-27/S-31/S-37 within `T_REHYDRATE`; (c) write-ahead durability for S-62 with an explicit flush barrier; (d) a headless custody path with no user-session dependency (LC-35); (e) a declared **availability class** per platform for `DeviceKey` (pre-first-unlock, unlock-bound, always) — see F4; (f) optional device-protected storage for the journal's minimal subset (LC-15) |
| I-06 | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | (a) Installation and removal of the OS start-trigger registration per platform (unit, service start type, launchd plist, procd script, on-demand rules, receiver, manifest `foregroundServiceType`); (b) update installation that does **not** leave the host unprotected — enforcement persists across the swap ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6); (c) the WinTun driver install/uninstall lifecycle ([docs/networking.md](../networking.md) §5.3) sequenced so that the agent's start is never blocked on a pending reboot without a named diagnostic |
| I-07 | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | (a) The headless profile meets LC-35 through LC-39; (b) a health-check surface the Windows/embedded watchdog equivalents can call; (c) **ownership of every embedded resource number**, including the RSS envelope, the shedding ladder, and the embedded `T_REHYDRATE` value — this ADR asserts none of them and defers (F8); (d) UCI/config-file reload as a **reload**, not a restart; (e) the **`H-EMB`** deployment profile and its **`GC-0`** silicon class (not `HC-0` — see F8), below ADR-0013's G1, composing with [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s `HC-3` topology class rather than extending any ordinal series; **(f) the embedded `T_REHYDRATE` value, derived against `GC-0`, not inherited from this ADR's desktop figure** |
| I-08 | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | The enforcement layer exposes a **query** returning the installed rule set for both families, cheaply enough to be called at LC-4 step 3 and LC-24 step 2 on every start and every resume (already implied by `ProtectionAssertion`; stated here as a latency requirement — ≤ 50 ms) |
| I-09 | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Registration of the §11.11 codes; and the `ProtectionAssertion` freshness window as a named constant the UI can compare against (LC-20) |
| I-10 | [docs/reliability.md](../reliability.md) | Registration of `T_REHYDRATE`, `T_REHYDRATE_MAX`, `T_LIFECYCLE_STOP`, `T_LIFECYCLE_CRASH_WINDOW`, `N_LIFECYCLE_CRASH`, `N_LIFECYCLE_APPLY_MAX`, `T_TRUSTED_NET_PROOF` in §5.3's "constants registered on behalf of other ADRs" table (C2); and resolution of findings F2, F3, F6 and F7 |

### 11.14 State ownership

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-61** | `HostLifecycleState` — the live host-lifecycle phase of the agent process (§11.1) | **The agent process's lifecycle supervisor** (the extension/service on mobile; the daemon elsewhere) | UI and CLI hold a replica delivered on the [ADR-0017](ADR-0017-local-management-interface.md) event stream (staleness ≤ one stream tick, ≤ 2 s); a replica older than the `ProtectionAssertion` freshness window MUST be rendered `UNKNOWN` | `LOCAL` | **Non-durable by requirement** — a phase is held by a process and a dead process holds nothing; `ABSENT` is inferred, never stored | The running instance wins. A replica that disagrees is stale by definition and is discarded, never merged |
| **S-62** | `LifecycleJournal` — `instance_epoch`, `boot_id`, `clean_shutdown` marker, `absence_cause`, `last_applied_contract_generation`, the abnormal-exit ring, and the crash-loop hold marker | **The agent process holding the single-instance lock** (LC-5) | None | `LOCAL` | **Durable, written write-ahead**: each field is flushed *before* the event it describes (LC-7), and the minimal subset MAY live in device-protected storage on platforms that have it (LC-15) | Local wins. A journal whose `instance_epoch` is not the current lock holder's is stale ⇒ `absence_cause = UNKNOWN` ⇒ treated as `CRASH`, the fail-safe direction |
| **S-63** | `ActivationPolicy` — the desired start triggers and always-on/on-demand policy for this device, plus the last **observed** OS registration result | **The local `Device`**, on `Owner` instruction through the management interface | None. The OS's own registration is **evidence**, never a replica of this fact | `LOCAL` | Durable | Local wins. A divergence between desired policy and observed OS registration raises `PLATFORM.LIFECYCLE.AUTOSTART_DISABLED` or `PLATFORM.LIFECYCLE.AUTOSTART_BLOCKED_BY_OS` and the policy is re-applied where the platform permits — the desired value is **never** silently rewritten to match the OS |
| **S-64** | `TrustedNetworkProof` — the live proof that the attached network is trusted: proving `TrustedPeer`, handshake time, expiry, and the resulting scope narrowing (§11.10) | **The local `Device` (2.16 via 2.5)** | None | `LOCAL` | **Non-durable by requirement** — MUST NOT survive process restart, resume, or reboot, and MUST NOT be cached per network fingerprint. A stale proof is a bypass | Local wins; **absence is the safe state**, and absence re-engages the wider scope before any traffic is emitted (TN-3) |

The user's *choice* of which networks to treat as trusted is user configuration and lives in
**S-24**; it is cited, not redeclared. S-64 is only the live, unstorable proof.

### 11.15 Assumptions register

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| L-01 (**H1**) | One portable core holds the lifecycle state machine, the rehydration sequence and the `SecretArena`, behind a stable C ABI, with thin native shells | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | §11.1–§11.2 become six per-platform implementations; P21 loses its single oracle and must be re-derived per platform; LC-30(1)'s single CI check becomes six; the `Secret<T>` enforcement mechanism disappears and LC-30 degrades to a review convention |
| L-02 (**H2**) | Desktop/server is a privileged long-lived daemon plus an unprivileged UI; mobile's "daemon" is the OS-hosted extension/service | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | §11.5's authority column inverts; if the UI were privileged, alternative E returns and LC-20 becomes unenforceable; on mobile a different hosting model would invalidate LC-17's app/extension division |
| L-03 (**H3**) | One authenticated, schema-versioned local management contract with a resumable event stream serves UI, CLI and automation, with no privileged GUI side channel | [ADR-0017](ADR-0017-local-management-interface.md) | LC-3, LC-21 and LC-22 lose their transport; the UI would have to poll, and "no stale truth at the join" becomes unachievable; LC-28(4)'s safe-mode control path needs a second, separately-specified channel |
| L-04 | The durable store is crash-consistent and offers a consistent multi-row snapshot within `T_REHYDRATE` | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) | LC-6 fires routinely rather than exceptionally; the product would boot into `BLOCKED` after ordinary crashes, and `T_REHYDRATE` would have to be relaxed or the store replaced |
| L-05 | `DeviceKey` has a declared per-platform availability class, and a headless custody path exists with no user session | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md), [ADR-0007](ADR-0007-device-identity-and-pairing.md) | LC-15's fail-closed default becomes the *only* behaviour on more platforms than expected; boot-start protection is unavailable wherever the key is unlock-bound, and that must be disclosed as a residual per platform |
| L-06 | Packaging installs and removes the OS start-trigger registration, and an update never leaves the host unprotected | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | LC-9 is unsatisfiable on the platforms where the registration is an installer artifact; R-13's "fail-closed on update" would need a mechanism here instead |
| L-07 | The headless profile accepts LC-35…LC-39 as requirements | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | §11.9 becomes normative content in this ADR and the two documents must be re-partitioned |
| L-08 | [docs/reliability.md](../reliability.md) §11's background profile applies to any `BACKGROUND` host phase, not only mobile, and §5.3 registers this ADR's constants | [docs/reliability.md](../reliability.md) | F7 stands as a contradiction; desktop low-power behaviour would need a second profile defined here, duplicating §11.1 — the outcome the corpus's cite-don't-restate rule exists to prevent |
| L-09 | Enforcement is kernel-resident, locally authoritative, and survives every lifecycle event, with a cheap both-families query | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) | The entire ordering argument of LC-4 and LC-24 collapses; the lifecycle layer would have to become the enforcement custodian, which is the I3 hole this ADR is built to avoid |
| L-10 | The presentation of `UNKNOWN`, of lifecycle phases, and of `PLATFORM.LIFECYCLE.*` text is owned elsewhere | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | LC-22's obligation has no renderer, and the "stale truth at the join" race returns as a UI defect |

---

## 12. Why the Selected Option Won

**C over A.** The decisive argument is not elegance, it is provability. R-08 and
[docs/architecture.md](../architecture.md) §2.1 make a claim about *every* platform; with six
independent rehydration orders there is no single artifact that can be shown correct, and P21 would
degrade into six loosely-related tests whose oracles drift. LC-4's ordering rule — nothing on the
wire before enforcement is verified — is exactly the kind of property that is easy to state once and
impossible to maintain in six places. A also contradicts H1 directly.

**C over B.** B loses on arithmetic already published in the corpus:
[docs/reliability.md](../reliability.md) §6.6 shows the keepalive cost and §11.2 concludes that the
binding cannot be held. Everything B would build — wake locks, permanent foreground services, alarm
abuse — is effort spent on a state the OS has decided not to grant, and on mobile it is also the
fastest route to store-policy rejection and to OEM battery-manager termination. C accepts the OS's
authority and spends the same effort on making the return cheap, which is what the 300 ms
wake-to-traffic target already assumes.

**C over D.** D is genuinely attractive — one entry path, no clean-shutdown bugs — and C takes its
best idea (LC-4 is the *only* path into `RUNNING`, and LC-7 means the clean-shutdown path is never
load-bearing for correctness). What C refuses to take is D's discarding of durable state. Every step
of [docs/reliability.md](../reliability.md) §6.2's recovery ladder except the last depends on
durable state a crash-only design would not keep, `session_id` continuity (S-12) is what makes a
diagnostic reconstructable across a crash, and `absence_cause` cannot exist at all without a journal.
D would make recovery correct and slow; the product's thesis is that recovery must be fast.

**C over E.** E is rejected on invariant grounds rather than on trade-off. A UI-owned lifetime means
a killable process is the custodian of protection — an I3 violation — and it makes the GUI a
privileged path, contradicting H3 and R-21's "the same control contract as the GUI". It is also
simply unavailable on iOS, iPadOS and Android, where the OS decides the extension's lifetime.
E survives in this document only as mutant `M-P21-6`.

---

## 13. Known Tradeoffs

1. **Restart policy is configuration we do not own** on Linux and OpenWrt. An operator can weaken
   or remove it. LC-28(3)'s hold marker and LC-29's `PLATFORM.LIFECYCLE.SUPERVISOR_ABSENT` make the
   weakening visible; they cannot prevent it, and we accept that.
2. **Crash-loop containment trades availability for safety.** A held device is offline and stays
   offline until a human acts. That is the correct direction under I3, and it is why LC-28(4)
   insists the management interface survives the hold — but a user whose only device is held has a
   genuinely bad day.
3. **The host adapter loses platform nuance.** iPadOS scene lifecycle, Android App Standby buckets
   and Windows Modern Standby do not map cleanly onto one closed event set; LC-14 and the §11.4
   matrix re-add the lost nuance as platform policy, which is exactly the seam where drift will
   appear first.
4. **The trusted-network exception is much narrower than users expect.** TN-4 means the feature is
   simply unavailable on a network with no second TwinVPN device — the common case for a
   single-phone user. We are choosing to disappoint that user rather than to ship an SSID check.
5. **`T_REHYDRATE` = 400 ms constrains [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md).**
   A store design that cannot deliver a consistent multi-row snapshot in that budget forces either a
   slower boot window or a relaxation of LC-6's all-or-nothing rule. We are pushing a real constraint
   onto a sibling — and deliberately quoting it only for the desktop, server and mobile classes,
   because imposing a desktop timing on a `GC-0` MIPS core is the mistake F8 exists to avoid.
6. **Crash reports are deliberately thin.** No memory, no stack bytes, and no registers at all when
   the fault is inside the crypto module. Some crashes will be materially harder to diagnose than
   they would be with a full dump. Given the never-loggable list, that is the trade we take.
7. **The iOS/iPadOS extension budget shapes the product.** Every feature that needs to parse a
   document must be app-side, which means every such feature is unavailable while the app is dead —
   an acceptable outcome only because LC-17 keeps all *runtime* responsibilities in the provider.

---

## 14. Revisit Conditions

Each is measurable, and each names the change it would force.

1. **Measured cold-start on the iOS/iPadOS provider exceeds `T_REHYDRATE` = 400 ms at p95** across
   the reference device set for two consecutive releases ⇒ either the store ([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)) or LC-6's
   all-or-nothing rule must change; revisit whether a two-phase rehydration (enforcement plus a
   minimal peer set first, full state second) is compatible with I3.
2. **The observed `NEPacketTunnelProvider` memory ceiling on a supported iOS/iPadOS release falls
   below 12 MB**, or the provider's measured high-water exceeds 12 MB in the reference workload
   ⇒ LC-17's division must move further work into the app, and §9's budget row is re-derived.
3. **P21 oracle 6 (the canary) fires anywhere other than a platform-owned crash log**, in any
   release ⇒ LC-30 is insufficient; treat as an I4 incident and revisit whether crash capture may
   exist at all on that platform.
4. **Crash-loop holds occur on more than 0.1% of active devices in any 30-day window** ⇒ the
   thresholds `N_LIFECYCLE_CRASH` = 5 / `T_LIFECYCLE_CRASH_WINDOW` = 300 s are mis-set, or the
   generation-quarantine mechanism is not catching the real poison class; revisit both before
   relaxing either.
5. **Measured parked background battery exceeds 2% per 24 h**, or radio wakes exceed 96/day, on the
   reference handset for a shipped release ⇒ the background profile's application-layer half is
   wrong; revisit LC-31's reduction set before revisiting
   [docs/reliability.md](../reliability.md) §11.1's timers, which are not ours.
6. **A supported Android release makes always-on/lockdown posture readable by a non-DPC app** ⇒
   LC-40's three-valued posture collapses to two, and F9's proposed amendment to
   [docs/networking.md](../networking.md) §5.4 is withdrawn.
7. **A supported platform introduces a boot-start path for an unsupervised mobile device** ⇒ the
   iOS/iPadOS row of §11.3 changes and
   `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE`'s residual narrows; P09 and P21's iOS cell are
   both re-derived.
8. **`systemd` `network-online.target` semantics become uniform across supported distributions, or
   a supported distribution makes the agent's start dependent on it** ⇒ LC-10 is re-argued;
   the "it would create a gap" argument survives such a change and the portability argument does not,
   so the conclusion is expected to stand.
9. **More than one TwinVPN process is observed writing S-62 in the field**, at any rate ⇒ LC-5's
   lock is insufficient on that platform; treat as an I8 incident.
10. **A trusted-network proof is observed to survive a network change or a process restart** in any
    build ⇒ S-64's non-durability is not enforced; treat as a security defect at the same severity
    as a kill-switch bypass.
