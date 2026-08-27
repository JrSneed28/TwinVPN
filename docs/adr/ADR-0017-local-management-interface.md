# ADR-0017: Local Management Interface

- **Status:** Accepted (Phase 1 architecture)
- **Date:** 2026-08-27
- **Owner:** APPLICATION
- **Related:** [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md),
  [ADR-0016](ADR-0016-client-process-and-privilege-separation.md),
  [ADR-0003](ADR-0003-network-contract-schema-format.md),
  [ADR-0007](ADR-0007-device-identity-and-pairing.md),
  [ADR-0008](ADR-0008-idempotency.md),
  [ADR-0009](ADR-0009-state-consistency.md),
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md),
  [ADR-0013](ADR-0013-multi-client-gateway-architecture.md),
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md),
  [ADR-0015](ADR-0015-observability-and-diagnostics.md),
  [docs/architecture.md](../architecture.md), [docs/networking.md](../networking.md),
  [docs/protocol.md](../protocol.md), [docs/reliability.md](../reliability.md),
  [docs/testing-strategy.md](../testing-strategy.md), [docs/threat-model.md](../threat-model.md),
  [docs/vision.md](../vision.md)

This ADR owns the **Management Interface (MI)**: the single local control contract between the
privileged TwinVPN agent and every local caller — the graphical client, the command-line client,
the router status page, and any local automation. It owns the MI transport binding per platform,
the authentication of local callers, the scope-based authorization model, the request/response and
event-stream shapes, the local version and capability-negotiation rules, the operation catalogue,
and the CLI's binding to that catalogue. It owns the `MGMT.*` reason-code domain.

It does **not** own: the process and privilege split, the uid the agent runs as, or the OS groups
that exist ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md)); the shared core's
language, ABI, or build ([ADR-0018](ADR-0018-shared-core-and-build-architecture.md)); the
presentation of state or of `reason_code`s to a human
([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)); local durable storage
([ADR-0020](ADR-0020-local-persistence-and-secure-storage.md)); packaging, the installer, the
polkit policy file, or the pipe DACL's provenance
([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)); when the agent is running at
all ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)); the headless profile,
the configuration-file format, or the `MGMT.CONFIG.*` codes
([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)). It does not own the wire
protocol ([docs/protocol.md](../protocol.md), [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md)),
the serialization rules ([ADR-0003](ADR-0003-network-contract-schema-format.md)), the reason-code
taxonomy ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2), the `ConnectionState`
machine ([docs/reliability.md](../reliability.md) §4), or kill-switch policy
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)) — all of which it consumes and cites.

---

## 1. Context

[docs/vision.md](../vision.md) **R-21** requires Linux and router-class targets to be first-class:
"headless operation, config-file and CLI control, and a userspace datapath option", discharged by a
"headless daemon with **the same control contract as the GUI client**".
[docs/architecture.md](../architecture.md) §2.1 repeats the claim in the TwinVPN Client's
responsibilities: "run headless on Linux/router targets with the same control contract as the GUI
(R-21)."

**Nothing in the Phase 1 corpus specifies that contract.** R-21's "Specified in" column points at
`architecture.md` §2.1, which restates the requirement rather than discharging it. This is the gap
this ADR closes. Until it is closed, R-21 is an aspiration: there is no artifact against which a
reviewer could reject a design where the GUI reaches into the agent by a private channel and the
CLI gets a thinner one. **If the GUI can do something the CLI cannot, R-21 is false**, and the
only way to make that statement checkable is to make both of them clients of one enumerable
contract.

Five other documents already depend on a local interface they do not define:

| Document | What it assumes | Status before this ADR |
|---|---|---|
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.7 | Client metrics "exposed on a local status interface" | Interface unowned |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6 | `DEGRADED`/`BLOCKED` visually distinct "in every surface (GUI, CLI, tray, headless status output, router status page)" | Four surfaces, no shared source of truth |
| [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8 | "One user-invocable command/button" producing the connectivity report | The command has no defined API |
| [docs/protocol.md](../protocol.md) §7 | `SessionStateChanged` is device-authoritative, "Ephemeral (management mirror)" | The mirror is undefined |
| [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.10 (KS-21) | Disarm requires a local interactive action plus OS-mediated authentication | No API boundary at which that ceremony is expressed |
| [ADR-0008](ADR-0008-idempotency.md) §11.3 | Kill-switch disengage "requires local user authorization" | The authorization mechanism at the API boundary is unstated |
| [docs/threat-model.md](../threat-model.md) §15 | **O-11** — "The local management IPC is unspecified … Neither's authentication, authorization, or audit contract is defined." Classified there as a **defect in the corpus**, not an accepted residual risk | Open. Discharged in **§11.21** |

There is also a load-bearing obligation that **silently changes shape** under working hypothesis
H2. [docs/protocol.md](../protocol.md) §5.1 requires that "every mutating C1 response carries
`committed_at_net_seq`, and **the client library MUST NOT report the operation complete to the UI**
until the C2 cursor has advanced to or past it. That is a protocol obligation, not a client
convenience." That sentence assumes the client library and the UI are in one process. Under H2 they
are not: the UI is a separate, unprivileged process reached over IPC. The read-your-writes
obligation therefore has to cross a process boundary, and nothing in the corpus expresses it there.
§11.7 and §11.10 of this ADR do.

**Why the local interface is a genuinely different problem from the wire protocol**, and not a
special case of it:

1. **The peer has an OS-attested identity.** On the wire, a peer is authenticated by a keypair
   because nothing else is available. Locally, the kernel already knows who is calling, for free
   and unforgeably. Building a second PKI here would be strictly worse and would create a local
   credential that could be stolen.
2. **The version skew is involuntary and intra-machine.** A package manager can replace the agent
   under a running tray icon. A distribution can ship the CLI in a separate package on a different
   upgrade cadence. Nobody chose this skew and nobody can negotiate it away — unlike the wire,
   where both endpoints are TwinVPN devices whose fleet distribution is measurable
   ([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.7 G2).
3. **The channel is not network-observable but is locally reachable.** Confidentiality is supplied
   by the OS; authorization is not. Local malware running as the user is on the other side of this
   socket, and the design must be honest about which properties survive that and which do not.
4. **Invariant I5 makes the whole surface optional.** No established `Session` may depend on it. A
   contract whose consumer may be dead, wedged, or absent is a different engineering object from
   one whose consumer is required.

Working hypothesis **H3** states that there is exactly one such contract with no privileged GUI
side channel. This ADR owns H3 and treats it as open: §4 presents the real alternatives, including
rejecting it.

## 2. Requirements

New requirements proposed for [docs/vision.md](../vision.md) §5, in that table's format. R-28 and
R-29 belong in §5.6 (Platform integration); R-30 belongs in §5.4 (Correctness of protection).

| ID | Historical defect | TwinVPN requirement | Mechanism | Specified in |
|---|---|---|---|---|
| **R-28** | GUI-first products where the CLI is a lagging second implementation, so headless and router deployments cannot do what a desktop user can — the concrete failure behind "no Linux/router support" | Every control operation MUST be expressible on **one** local management contract. The graphical client MUST NOT hold a privileged side channel, and the CLI MUST NOT contain a control verb that is not an operation of that contract. The set of operations MUST be machine-enumerable at runtime. | Single MI operation catalogue with runtime enumeration (`mi.catalogue.get`); CLI subcommand table **generated** from the catalogue; parity asserted by proof test **P17** clause A | **This ADR** §11.1, §11.9, §11.12 |
| **R-29** | A management UI whose death, hang, or slow consumption stalls or tears down the tunnel — the "kill the tray icon and lose the VPN" defect | The data plane MUST NOT depend on the management interface. An absent, dead, wedged, or slow local client MUST NOT affect an established `Session`, MUST NOT change enforcement, and MUST NOT delay any state transition. | No daemon→client RPC exists; event emission is a non-blocking offer into a bounded per-connection queue with compaction then eviction; MI server module not linked into the datapath module (build-time dependency assertion); asserted by **P17** clause B | **This ADR** §11.10, §11.11 |
| **R-30** | Unauthenticated or coarsely authorized local IPC, where any local process can disable protection or read everything — the local-privilege-escalation class in VPN clients | Every MI call MUST be authenticated to an OS-attested local principal obtained from the kernel, and authorized against a declared scope. No MI operation may lower enforcement. Kill-switch disarm MUST NOT be reachable by scope alone and MUST require the [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 ceremony evaluated by the agent against the OS. | Peer-credential attestation (`SO_PEERCRED` / named-pipe client token / XPC audit token / Binder uid); attach-time immutable scope set; monotone-safe enforcement rule; two-phase OS-evaluated disarm ceremony; asserted by **P17** clause C | **This ADR** §11.4, §11.5, §11.14 |

## 3. Constraints

| # | Constraint | Source |
|---|---|---|
| **C-1** | Invariant **I5**: no established-`Session` path may depend on the control plane; by extension of `architecture.md` §4.2's directional rule, the management plane observes and has **no reverse edge** into the data plane. | [docs/vision.md](../vision.md) §4.1, [docs/architecture.md](../architecture.md) §4.2 |
| **C-2** | Invariant **I3/I8**: kill-switch engagement (S-18) has one writer, no remote replica, and the control plane MUST NOT be able to disengage it. Effective enforcement mode is monotone in the safe direction. | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21, KS-22 |
| **C-3** | Invariant **I4**: no operation may export private key material. There is no such operation to design. | [docs/vision.md](../vision.md) §4.1, [ADR-0007](ADR-0007-device-identity-and-pairing.md) |
| **C-4** | Invariant **I6**: every terminal or degraded MI condition carries a `reason_code` in the [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 form — two or three segments, string on the wire, stable forever. | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 |
| **C-5** | Serialization is not this ADR's to choose. B1 is protobuf, B2 is deterministic CBOR in COSE_Sign1, **B5 (local config, CLI, diagnostics) is JSON with 64-bit integers rendered as strings**. | [ADR-0003](ADR-0003-network-contract-schema-format.md) §11 |
| **C-6** | Idempotency semantics are ADR-0008's. Ceremonies carry a client-generated key ≥128 bits; declarative state carries `if_version`. | [ADR-0008](ADR-0008-idempotency.md) N-2, N-4 |
| **C-7** | The twelve `ConnectionState`s are fixed and owned elsewhere. MI reports them; it does not extend, rename, or aggregate them differently from `reliability.md` §4.7. | [docs/reliability.md](../reliability.md) §4 |
| **C-8** | Diagnostics may not be remotely triggerable, must be rate-limited, and must require local user authorization. "Support pulls nothing; the user pushes." | [docs/threat-model.md](../threat-model.md) §9, [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9 |
| **C-9** | `SECRET`-classified values have no rendering path in any observability tier. `SENSITIVE` values are renderable on the `Owner`'s own device. | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4, §11.10 |
| **C-10** | iOS/iPadOS: the NetworkExtension provider is a memory-constrained app extension in a separate sandbox. There is no sanctioned free-form local socket between the containing app and the provider, and no provider-initiated push to the app. | [docs/networking.md](../networking.md) §5.4 |
| **C-11** | Android: `VpnService` lives in the app's process; cross-application binding is gated by export flags and signature permissions. `adb shell` and terminal apps run as different UIDs. | [docs/networking.md](../networking.md) §5.2 |
| **C-12** | Router/OpenWrt: ≤128 MB RAM is common, musl/uclibc, read-only rootfs with overlay, `ubus`/`procd` are the native idioms, no GUI, no interactive desktop session. | Brief §10, [docs/networking.md](../networking.md) §5.2 |
| **C-13** | **Phase 1 macOS is the Developer-ID system-extension shape only.** [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §12.6 rejects the Mac App Store app-extension variant (MX-2) on a security ground: the App Sandbox forbids the `LaunchDaemon` and the `pf` anchor [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6 names for macOS, so shipping it would silently downgrade boot enforcement on a desktop platform. Its §14 fallback if the NE entitlement is not granted is MX-3 (a `LaunchDaemon` owning `utun` directly), which still yields a root daemon and XPC — never MX-2. | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.2, §12.6 |
| **C-14** | Windows: the agent is a service (LocalSystem class); UAC governs elevation; named pipes are the native IPC and carry well-known impersonation hazards. | [docs/networking.md](../networking.md) §5.3 |

## 4. Considered Alternatives

| # | Alternative | One-line shape |
|---|---|---|
| **A** | **No dedicated contract — platform-native management, per platform** | Each shell talks to the agent in whatever idiom its OS prefers, with a per-platform operation surface. Explicitly rejects H3. |
| **B** | **Local HTTP/JSON REST API on loopback TCP with a bearer token** | One well-understood contract; `127.0.0.1:<port>`; token in a mode-0600 file; Server-Sent Events for the event stream. |
| **C** | **gRPC over a Unix domain socket / named pipe** | Protobuf service definitions, generated stubs in every language, native server-streaming for events, native deadline and status-code plumbing. |
| **D** | **A transport-agnostic MI contract: one schema-defined operation catalogue plus one event stream, bound to a per-platform local channel with uniform framing** | The contract is the catalogue and the envelope; the channel is chosen per OS (AF_UNIX / named pipe / XPC / provider-message / Binder). Clients negotiate `mi_version` and read the catalogue at attach. |
| **E** | **Filesystem-mediated declarative control** | A desired-state configuration file the agent watches, plus a status file and a log file it writes. The router idiom, generalized to every platform. No socket at all. |

## 5. Advantages of Each Alternative

| # | Advantages |
|---|---|
| **A** | Each platform gets the most idiomatic possible integration and the least impedance mismatch: XPC on macOS, Binder on Android, `ubus` on OpenWrt, D-Bus on a Linux desktop. Nothing is emulated. Fastest to a good-looking first release on any single platform. No new framing, versioning, or authorization machinery to design — each OS's IPC already has some. |
| **B** | Every language on earth has an HTTP client, so third-party automation is trivial. Human-debuggable with `curl`. Browser-based and remote-capable status pages are free, which matters for a router. Server-Sent Events is a well-trodden one-way stream. JSON matches [ADR-0003](ADR-0003-network-contract-schema-format.md) B5 exactly, so no new encoding appears in the product. |
| **C** | Streaming, deadlines, cancellation, flow control, and status codes come from the framework rather than from us — the most engineering leverage per line. Protobuf is already in the product at B1, so no new toolchain. Generated stubs in Swift, Kotlin, C#, Rust and Go make thin native shells genuinely thin. Reflection gives a catalogue for free. Interceptors give a clean place to hang authorization. |
| **D** | The contract is separable from the channel, which is the only structure that survives C-10 and C-11 — platforms where the OS forbids a socket still carry the same operations, the same schema, the same scopes, and the same reason codes, over the channel the OS does sanction. The catalogue is a first-class runtime object, so "what can this build do" is answerable by a stale client, which is what makes R-28 checkable and version skew survivable. Framing, backpressure, and eviction are ours to specify, which is what makes R-29's structural I5 argument possible instead of dependent on a framework's defaults. Reuses B1 protobuf and B5 JSON without adding a format. |
| **E** | Trivially survives every process boundary and every platform sandbox that permits shared files. Naturally declarative and therefore naturally idempotent ([ADR-0008](ADR-0008-idempotency.md) ALT-C). Zero listening surface — nothing to attack, nothing to bind, nothing to squat. Zero steady-state memory on a router. Config-as-code, version control, and configuration management integrate with no adapter. Matches OpenWrt UCI practice exactly. |

## 6. Disadvantages of Each Alternative

| # | Disadvantages |
|---|---|
| **A** | **Directly falsifies R-21 and H3.** Per-platform surfaces diverge the moment one platform's team ships a feature; there is no artifact that could fail a review for a GUI-only capability. It multiplies the authorization model by the number of platforms, so the kill-switch disarm rule (C-2) would have to be re-argued six times and would be got wrong at least once. It makes P17 unwritable: parity between two surfaces that were never one contract cannot be asserted mechanically. It also multiplies the reason-code surface, since each idiom's error model would leak upward as untyped errors — the exact defect `architecture.md` §2.5 forbids for the platform adapter. |
| **B** | Loopback TCP has **no peer credentials**: the kernel will not tell the server who is calling, so authentication collapses to a bearer token, which is a secret on disk that can be read by any process running as the user, copied into a backup, or captured in a diagnostic bundle — a new asset with a new lifecycle for no gain over filesystem permissions. A listening TCP port is reachable by every local user, by containers and WSL in some Windows configurations, and is a standing target for browser-originated request forgery against a local service. It cannot express "only this user", only "whoever has the token". The framing is HTTP, so a wedged consumer is a stalled `write()` on a socket with HTTP's own buffering semantics rather than a bounded queue we control. On iOS and Android there is no way to expose it at all, so it needs alternative D underneath anyway. |
| **C** | gRPC's channel abstraction is exactly the thing C-10 and C-11 forbid: there is no gRPC over `sendProviderMessage` and none over Binder, so iOS, iPadOS and Android fall out of the model and need a second contract — reintroducing alternative A's divergence at the worst platforms. The runtime is heavy for C-12: an HTTP/2 stack plus gRPC framing is a poor fit for a 128 MB router, and the smallest usable implementations are still an order of magnitude larger than the framing this contract needs. Server-streaming's flow control backpressures the **producer**, which is precisely the wrong direction for R-29 — the correct behaviour for a slow local UI is to drop and resync, not to slow the agent. Status codes are an enum, which collides with [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2's normative "carried as a **string**, never as an enum" rule, so codes would have to travel in trailers anyway. Reflection-derived catalogues describe *methods*, not scopes or build profiles. |
| **D** | Everything gRPC would have supplied must be specified here: framing, `Hello` negotiation, catalogue semantics, backpressure watermarks, eviction, dedup, and the per-platform authentication table. That is the bulk of §11, and each of those is a place to be wrong. Client authors get no generated stub for free; the mitigation is that the catalogue is machine-readable and the CLI table is generated from it, but a third-party automation author writes more code than they would against REST. Two bindings on macOS (XPC for entitled clients, `AF_UNIX` for the CLI) means two code paths to test on one OS. |
| **E** | **Cannot express a ceremony.** Pairing ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4) has a 120-second expiry, a live QR or 9-digit code, and a confirmation step; a file cannot carry it. Neither can diagnostics export, which is request/response by nature. It has no event stream, so every consumer polls a file, which is worse for battery than a socket on every mobile platform and cannot deliver the sub-second state changes ADR-0015 §11.6's anti-silence indicator needs. Worst: **file permissions are the entire authorization model**, so it cannot distinguish read-only status from kill-switch disarm without a directory per scope, and it cannot express KS-21's "local interactive action" at all — a config key that disarms would be settable by any process that can write the file, including a cron job, which is precisely the C-2 violation. It also cannot report `MGMT.NOT_READY`: a status file is either stale or absent, and neither is distinguishable from "the agent is starting". |

## 7. Security Implications

The MI is a **privilege boundary**: an unprivileged caller asks a process holding `CAP_NET_ADMIN`,
`LocalSystem`, or a NetworkExtension entitlement to change system network state. The process model
that creates that asymmetry is [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s;
the API at the seam is this ADR's.

**What is authenticated, what is authorized, and what is merely obscured** — stated plainly,
because conflating the three is how local IPC holes are shipped:

| Property | Status | Mechanism | Honest limit |
|---|---|---|---|
| The caller's **OS principal** (uid / SID / Binder uid / audit token) | **Authenticated** | Obtained from the kernel on the connected socket (§11.4). Never from anything the client sends. | None on Linux/Windows/macOS/Android. On the iOS provider-message channel there is exactly one possible caller, so the question does not arise. |
| The **operation** | **Authorized** | Attach-time immutable scope set derived from the principal (§11.5), checked per call against the catalogue's `required_scope`. | A principal with a scope can use every operation in it. Scope granularity is the whole authorization resolution. |
| **Kill-switch disarm** | **Authorized separately, by the OS** | Two-phase ceremony evaluated by the agent against polkit / UAC / Authorization Services (§11.14). Not a grantable attach scope. | On a headless host with no interactive session the operation is **refused**, not degraded (§11.14). |
| Which **program** is calling | **Merely obscured** on Linux, Windows, and the macOS Developer-ID socket variant | Advisory image inspection only (§11.4 MI-A2) | Any binary the authorized user runs is indistinguishable from the GUI. This is a property of the OS DAC model, not a defect of this design. |
| The **contents of status and diagnostics** | **Not confidential from the authorized user** | Filesystem permissions on the channel keep *other* users out | A compromised process in the user's own session can read everything the user can read. §11.15 makes exfiltration loud; it cannot make it impossible. |

**Threats and their disposition.**

| Threat | Disposition | Residual |
|---|---|---|
| **Local malware calls the MI** as an unprivileged service account or another user | Denied: the channel's filesystem/DACL permissions exclude it; every call is scope-checked (§11.5); `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` | None for a different principal |
| **Local malware calls the MI as the authorized user** | Not prevented. It can do what the user can do — including disconnect and read status. It **cannot** disarm the kill switch (§11.14 requires an OS re-authentication the malware would have to defeat separately), **cannot** export key material (no such operation exists, I4/C-3), and **cannot** lower enforcement (§11.5 MI-S3 monotone rule) | Full read of `SENSITIVE` local state and full connect/disconnect control. Stated, not mitigated |
| **Confused deputy** — the privileged agent is induced to act on a client-supplied capability | Removed structurally: **MI-D4** forbids any operation from accepting a filesystem path, URL, command, file descriptor, or other handle from the client, and **MI-D5** forbids any operation from causing an outbound request to a client-supplied destination | None; the class is absent rather than validated |
| **TOCTOU / squatting on the channel path** | Removed structurally: the socket directory is created by the OS init system with a privileged owner, and the endpoint is created into it by bind-and-rename, never unlink-and-rebind; the Windows pipe uses `FILE_FLAG_FIRST_PIPE_INSTANCE` with an explicit DACL (§11.4 MI-A3) | A host where the init system's directory ownership is already compromised is out of scope — that adversary has root |
| **Symlink attack on endpoint or artifact creation** | Diagnostic artifacts are written to agent-chosen paths in an agent-owned directory with mode `0600` (§11.15 MI-D3); no client-supplied path exists (MI-D4) | None |
| **A malicious CLI impersonating the UI** | Not prevented on Linux/Windows, and **deliberately not attempted**: per-binary allowlisting is defeated by an attacker already running as that user, and would break every legitimate third-party client. On macOS (XPC), iOS, and Android the OS supplies code identity and it *is* enforced | Named above. The security boundary is the **user**, not the application |
| **Information disclosure through status and diagnostics** | `SECRET` never crosses MI, with one named exception (§11.15 MI-P1). `SENSITIVE` crosses, because the `Owner` is entitled to see their own device's endpoints ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.10). Bundle creation is rate-limited and emits a persistent, every-surface `MGMT.DIAG.BUNDLE_CREATED` | An authorized-user-level compromise reads local state. The mitigation is visibility, not prevention |
| **Denial of service by a hostile local client** (connection flood, subscribe-and-stall) | Bounded: per-principal connection cap, per-connection bounded queue, eviction on backpressure (§11.10). None of it touches the datapath (§11.11) | A local attacker can deny *management*, not *protection*. Correct ordering |
| **Remote disarm via a compromised control plane** | Impossible by construction: KS-22's three properties hold unchanged; MI adds no wire message that reduces enforcement, and MI itself has no network binding | Unchanged from [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| **Remote disarm by a host administrator over SSH** | **Possible, and correctly so.** See §11.14's honest note: an administrator with root can remove the rules directly, so refusing it over MI would buy nothing and would break legitimate remote administration of a headless gateway, which R-21 requires | Stated explicitly rather than implied |

## 8. Reliability Implications

1. **The MI is optional to the product's core promise.** The agent MUST start, establish `Session`s,
   reach a steady state, migrate paths, fail over relays, and hold enforcement with **zero MI
   clients ever attached**. §11.11 makes this structural rather than careful, and P17 clause B
   measures it.
2. **Failure to bind the channel is not a failure to protect.** If the endpoint cannot be created at
   startup, the agent MUST continue running, MUST NOT disarm, and MUST emit `MGMT.LISTEN_FAILED`
   into the Tier-0 ledger. An agent that refuses to run because nobody can manage it is an
   availability defect wearing a safety costume.
3. **A slow consumer is evicted, never tolerated.** The alternative — backpressuring the producer —
   would let a hung UI stall a state machine that is holding a tunnel up. §11.10's watermark →
   compaction → eviction ladder is chosen for this reason and is the opposite of what a streaming
   RPC framework does by default (§6, alternative C).
4. **Reconnection is the recovery idiom, and it is race-free.** A client that reconnects calls
   `event.resync`, receives a snapshot taken under the agent's state lock with the cursor assigned
   *inside* that lock, then live events from that cursor. There is no window in which an event is
   both missing from the snapshot and skipped by the stream.
5. **Version skew degrades explicitly.** Every mismatch produces a `reason_code` with a next action
   and never a silent socket close (§11.7). A silent close is indistinguishable from "the agent is
   dead", which sends the user to reinstall rather than to update — the concrete cost of getting
   this wrong.
6. **`MGMT.NOT_READY` exists so that "starting" is not reported as "disconnected".** During
   rehydration ([docs/architecture.md](../architecture.md) §2.1: restart re-enters `RECONNECTING`,
   not `DISCONNECTED`-from-scratch) the agent's answer is "not yet authoritative", never a
   fabricated state. Reporting `DISCONNECTED` during rehydration would be a `reliability.md` §10
   silent-failure defect committed at the presentation boundary.

## 9. Performance Implications

| Concern | Budget / rule | Rationale |
|---|---|---|
| Steady-state memory, zero clients (embedded hardware class **H-EMB**, [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md); C-12) | ≤ **256 KiB** resident for the MI server | An always-listening server on a 128 MB device must be a rounding error. Falsifiable; §14 revisit condition 1 |
| Per attached client | ≤ **64 KiB** including its event queue | Bounds the fan-out cost of a multi-window UI |
| Event queue watermark | **64 KiB or 256 events**, whichever first; **16 KiB / 64 events** on the router build profile | Sized from [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.6's shape, scaled down: MI events are local, small, and re-derivable by snapshot, so a shallow queue is correct |
| `status.get` latency | p95 ≤ **25 ms** on the reference low-end device | A UI that cannot read status in a frame budget will poll harder, which is the failure this budget prevents. §14 revisit condition 2 |
| Steady-state client request rate | ≤ **2 requests/s** per client with the event stream healthy | Push is the primary mechanism; polling is the iOS/iPadOS fallback only (§11.2.1). A desktop UI polling instead of subscribing is a defect, detectable from this number |
| Datapath cost | **Zero.** No MI code runs on a packet path, and no allocation for MI occurs under a datapath lock | §11.11 |
| Event emission cost | One bounded-queue offer; **no blocking send primitive exists in the API** | The absence of the primitive is the mechanism (§11.11 step 3) |
| iOS/iPadOS poll cadence | 1 s while a relevant scene is **visible**; 0 when no scene is visible | Bound to scene visibility rather than app foreground, because Stage Manager and external displays extend foreground time indefinitely (§11.2.1) |
| Serialization | B1 protobuf for the MI envelope; B5 JSON only at the CLI's rendering boundary | No new format enters the product (C-5) |

## 10. Operational Implications

1. **Endpoint locations are stable and documented**, because scripts and configuration-management
   tooling will hard-code them: `/run/twinvpn/mgmt.sock` (Linux, OpenWrt),
   `\\.\pipe\TwinVPN\mgmt` (Windows), `/var/run/twinvpn/mgmt.sock` or the Mach service name
   `com.twinvpn.agent.mgmt` (macOS). Relocation is an `mi_version` event, not a patch-level change.
2. **The socket directory is created by the init system, not by the agent** —
   systemd `RuntimeDirectory=twinvpn` (or `tmpfiles.d`), `procd` on OpenWrt, the installer's DACL
   on Windows. This is what makes MI-A3's TOCTOU argument hold without the agent doing privileged
   filesystem gymnastics at startup. Ownership of those artifacts is
   [ADR-0021](ADR-0021-packaging-distribution-and-updates.md)'s.
3. **Socket activation is prohibited** (MI-A3, [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)
   I-02(a)). The unit MUST NOT carry a `.socket` companion, and `launchd` MUST NOT declare
   `Sockets` for the management endpoint. The agent creates the endpoint at every start by
   bind-and-rename, and it disappears with the agent — so "the socket is absent" and "the agent is
   not running" are the same observable fact, which is what lets a client answer `MGMT.UNAVAILABLE`
   immediately instead of connecting to a socket nobody serves.
4. **Live upgrade is the normal skew case.** Replacing the agent under a running UI is expected;
   the UI's connection dies, it reconnects with backoff, re-`Hello`s, and re-reads the catalogue
   (§11.7). An installer MUST NOT require the user to close the UI first, and MUST NOT assume it
   can.
5. **Split packaging is permitted and bounded.** A distribution may ship agent and CLI separately;
   the two-epoch MI window (§11.7) is what makes that safe, and the `MGMT.VERSION_TOO_OLD` /
   `MGMT.VERSION_TOO_NEW` codes name which side is behind so a package maintainer's bug report is
   actionable on first read.
6. **Exit codes are an operations contract** (§11.12). Automation distinguishes "the service isn't
   running" from "the operation was refused" from "your CLI is too old" without parsing text.
7. **`twinvpn down` does not disarm.** The most likely operator mistake this ADR can prevent is
   assuming that disconnecting drops protection. It does not: `net.down` clears the M2 session
   intent and leaves the latch armed ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
   §11.13). The CLI's human output says so on every invocation that leaves traffic blocked.
8. **Every MI mutation is auditable.** Mutating calls emit a Tier-0 ledger entry carrying the
   principal, the operation, and the outcome code. This is a local audit trail, never telemetry
   (Tier 0 never leaves the device, [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.1).

## 11. Decision

**Adopt Alternative D: one transport-agnostic Management Interface contract — a single
schema-defined operation catalogue plus one event stream, carried over a per-platform local channel
with uniform framing, with callers authenticated from kernel-supplied peer credentials and
authorized by an attach-time immutable scope set.**

**H3 is CONFIRMED.** There is exactly one local control contract; the graphical client has no
privileged side channel; the CLI is a generated thin client over the same catalogue.

### 11.1 The rule that makes R-21 true

> **MI-1 (the parity rule).** Every control operation the agent performs on behalf of a local
> caller MUST be an entry in the MI operation catalogue. There is no second local control path.
> The graphical client, the command-line client, the router status page, and any local automation
> are peers: they differ only in the **scope set their principal is granted** and in **presentation**,
> never in the set of operations that exist.

Three consequences that make MI-1 checkable rather than aspirational:

- The catalogue is a **runtime object**, retrievable by `mi.catalogue.get`. "What can this build
  do" is answerable by a client that is older than the build.
- The CLI's subcommand table is **generated** from the catalogue at build time (MI-C1, §11.12). A
  CLI verb with no catalogue entry, or a catalogue entry with no CLI verb, is a build failure.
- Proof test **P17 clause A** asserts `GUI_ops ⊆ CLI_ops = catalogue_ops` against the agent's own
  MI access log during a scripted UI walkthrough. A privileged side channel added later fails a
  test rather than passing a review.

#### 11.1.1 One vocabulary, not merely one contract

[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.16(b) asks for more than H3 as
worded, and it is right to: H3 says "one local management contract", which would still permit this
ADR to define an independent vocabulary that merely happens to be singular. It does not.

> **MI-20 (the catalogue is derived, not defined).** The MI operation catalogue is **derived from
> the core's command/event set**, not specified beside it. Every MI operation that observes or
> mutates core state **is** a core command — same name, same parameters, same result shape — and MI
> adds only carriage, authorization, and framing around it. MI MUST NOT rename, re-shape, merge,
> split, or reorder a core command, and MUST NOT introduce an operation that duplicates one.
> `tw_core_submit` in-process and the MI transport out-of-process are **two carriages of one
> vocabulary**, which is [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-5's claim,
> confirmed here normatively rather than assumed.

The generation step makes this mechanical rather than disciplinary. **One source, three artifacts:**
the core's command table generates the MI catalogue, and the MI catalogue generates the CLI verb
table (MI-C1). A core command with no catalogue entry, a catalogue entry with no core command, or a
CLI verb with no catalogue entry is a **build failure**, not a review finding.

> **MI-21 (the transport-layer set is closed, and exists to keep the ABI small).** Exactly **four**
> MI operations have no core counterpart, and this set is **closed**: the `Hello`/`HelloAck` version
> and scope negotiation (§11.7), `mi.catalogue.get`, `event.resync` (§11.10), and the MI half of
> `version.get` — `mi_version` range, channel identity, and catalogue digest, which it returns
> alongside the core's own version. Every one of them is about **the connection**, a thing that does
> not exist in-process. Each **MUST NOT** acquire an ABI counterpart. Adding a fifth requires
> amending this ADR.

**This protects [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-1 rather than
threatening it.** F-1's argument is that the ABI is roughly a dozen functions and "every exported
function is a compatibility obligation forever". The four operations above are precisely the ones
that would otherwise have to become exported functions — connection negotiation, catalogue
discovery, stream resync — each carrying a permanent obligation for a concern the in-process caller
does not have. Confining them to the MI layer is what **keeps** the ABI at a dozen functions. The
alternative that would genuinely collapse F-1 is the one MI-20 forbids: an independently-named MI
vocabulary, which would make every MI operation a second thing the ABI must eventually satisfy.

**A correction to an earlier statement of this ADR's.** §11.18(c2) previously listed
`killswitch.exempt.get` among the operations with no core counterpart. That was wrong: it reads
enforcement-layer state, which is a core module, so it is an ordinary core command and sits inside
the shared vocabulary. The transport-layer set is four, not five.

### 11.2 Transport binding per platform

The contract is the catalogue and the envelope; the **channel** is per platform. Uniform framing
means one `MgmtEnvelope` per message in every binding, so a message that is valid on one channel is
byte-identical on another.

| Target | Channel | Peer attestation | Event stream | Notes |
|---|---|---|---|---|
| **Linux** (kernel 5.6; 5.4 fallback) | `AF_UNIX` **`SOCK_SEQPACKET`** at `/run/twinvpn/mgmt.sock`, mode `0660`, group `twinvpn`; created by the agent into a systemd `RuntimeDirectory`, **never socket-activated** (MI-A3) | `SO_PEERCRED`, plus `SO_PEERSEC` where SELinux/AppArmor is present | full | `SOCK_SEQPACKET` is chosen so message boundaries are kernel-preserved: a length-prefix bug cannot desynchronize the stream. `SOCK_STREAM` + length prefix is the fallback where SEQPACKET is unavailable |
| **Windows** (10 21H2 / Server 2019) | Named pipe `\\.\pipe\TwinVPN\mgmt`, **message mode**, `PIPE_REJECT_REMOTE_CLIENTS`, explicit DACL granting the `TwinVPN Users` group, `FILE_FLAG_FIRST_PIPE_INSTANCE` | `GetNamedPipeClientProcessId` + client token query | full | Message mode gives the same boundary property as `SOCK_SEQPACKET`. `PIPE_REJECT_REMOTE_CLIENTS` is **mandatory**: without it the pipe is reachable over SMB |
| **macOS 11+**, Developer ID (system extension + `launchd` daemon) | `NSXPCConnection` to Mach service `com.twinvpn.agent.mgmt`; `AF_UNIX` at `/var/run/twinvpn/mgmt.sock` for non-XPC clients such as the CLI | **XPC audit token** → `SecCodeCheckValidity` against a Team-ID-pinned code requirement; `LOCAL_PEERCRED` on the socket | full | XPC preferred: audit-token attestation is not pid-based and therefore not TOCTOU-able |
| *(future-compatible only)* macOS App Store app extension | App Group container + `NETunnelProviderSession.sendProviderMessage` | implicit | **subset** (§11.2.1) | **Not a Phase 1 variant** (C-13). Listed so the architecture does not foreclose it: were it ever shipped, MI would degrade to the iOS provider-message subset unchanged, because the contract is transport-agnostic. No Phase 1 macOS residual is claimed from it |
| **iOS 15+ / iPadOS 15+** | App Group container + `NETunnelProviderSession.sendProviderMessage`; `NEVPNManager.providerConfiguration` for boot-time settings | implicit | **subset** (§11.2.1) | The hard case. Named honestly rather than papered over |
| **Android API 26+** (target 29 behavior) | Bound `Service` + **AIDL**, `android:exported="false"` (or `signature`-level permission for a companion app), agent in the `:vpn` process | `Binder.getCallingUid()` + `PackageManager` signature check | full within the app | Binder identity is kernel-attested and unspoofable — stronger than a socket. Reach is narrower: see §11.2.2 |
| **OpenWrt 21.02** | `AF_UNIX` as Linux, plus an **optional** `ubus` object `twinvpn` bridging a read-only subset | `SO_PEERCRED`; `ubus` session ACL where the bridge is enabled | full on the socket; read-only subset over `ubus` | The `ubus` bridge is a thin adapter over the catalogue, **not a second contract**. Enabling it puts `ubusd` in the TCB; it is therefore off by default and owned by [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| **Routers (non-OpenWrt), headless gateways** | `AF_UNIX` | `SO_PEERCRED` | full | Profile owned by [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| **CLI-only deployments** | `AF_UNIX` / named pipe | as the host OS | full | No GUI exists; the catalogue is unchanged, which is exactly R-21's claim |
| **Future: containers / network namespaces** | `AF_UNIX`, bind-mounted into the namespace | `SO_PEERCRED` (uid translated by the userns mapping — the agent MUST resolve the principal in **its own** namespace) | full | Not foreclosed. This is a second reason abstract sockets are rejected (MI-A4) |

**Rejected channel options, with reasons** (the brief's alternatives, decided rather than surveyed):

- **Linux abstract-namespace sockets (`@twinvpn`) — rejected.** They have no filesystem
  permissions, so the only access control available is `SO_PEERCRED` checked after the connection
  is accepted, which means every local process can reach the accept path. They are also visible
  across network namespaces that share the abstract namespace, which breaks the container case
  above. The filesystem socket is chosen precisely *because* its access control is the
  filesystem's, evaluated by the kernel before the agent sees the connection.
- **Local TCP on loopback — rejected.** No peer credentials (§6, alternative B), reachable by every
  local user, reachable from WSL and some container configurations on Windows, and it forces a
  bearer-token secret into existence with its own storage, rotation, and leak-into-diagnostics
  lifecycle.
- **D-Bus (Linux) — rejected as the primary channel.** It adds a broker to the TCB of a security
  product, makes the agent depend on a session or system bus that is absent on OpenWrt and on
  minimal server images, and its policy language would become a second authorization model beside
  §11.5's. A D-Bus **adapter** over the catalogue is permitted on desktop Linux for desktop-shell
  integration, under the same rule as the `ubus` bridge: an adapter, never a second contract.

#### 11.2.1 iOS and iPadOS — the honest subset

**The mechanism, named exactly.** `NETunnelProviderSession.sendProviderMessage(_:responseHandler:)`
delivers an opaque `Data` payload to `NEPacketTunnelProvider.handleAppMessage(_:completionHandler:)`
in the extension, and returns the extension's reply to the app. This is the only Apple-sanctioned
app↔provider message path. A free-form `AF_UNIX` socket between the two is **not** available in the
general case: the extension is a separate process in a separate sandbox, and the App Group
container is a shared *filesystem* container rather than an IPC rendezvous. The architecture MUST
NOT depend on binding a socket there.

**What the channel carries, and what it cannot:**

| Property | Status |
|---|---|
| The full request/response half of the contract, byte-identical framing | **Carried.** The payload is opaque `Data`; one `MgmtEnvelope` per message |
| The full operation catalogue, scopes, schema, and `MGMT.*` codes | **Carried.** The contract is unchanged; only the channel differs |
| Agent-initiated push (the event stream) | **Not carried.** There is no reverse `sendAppMessage` |
| Any message while the tunnel session is not connected | **Not carried.** `sendProviderMessage` fails when the session is stopped, so **the status of a stopped tunnel is not obtainable from the provider** |
| A caller that is not the containing app | **Not applicable.** There is no second local principal, no CLI, and no third-party local automation on these platforms |

**The residual, and how it is emulated** — three mechanisms, none of which pretends to be the
event stream:

1. **Scene-bound polling.** The app polls `status.get` at 1 s while a relevant scene is visible and
   at 0 otherwise. The cost is real and is bounded by scene visibility.
2. **A change hint, treated exactly as C3 push is treated.** On every state transition the provider
   writes a compact status record into the App Group container under `NSFileCoordinator` and posts
   a **Darwin notification** (`CFNotificationCenterGetDarwinNotifyCenter`). Darwin notifications
   carry no payload and are best-effort, so they are treated the way
   [docs/protocol.md](../protocol.md) §4 treats C3: **a hint that triggers a declarative re-read,
   never a state delta.** Reusing that idiom is deliberate — the product has one recovery pattern,
   not two.
3. **Stopped-session rendering is marked not-live.** When the session is stopped the app renders
   from the last App Group status record plus `NEVPNManager.connection.status` and MUST mark the
   view as **not live**, never as current. This is
   [ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18 ("assertions expire ⇒ `UNKNOWN`,
   never `PROTECTED`") applied at the presentation boundary. Any operation the channel cannot carry
   in the current session state returns `MGMT.CHANNEL_UNSUPPORTED`.

**iPadOS is not iOS but bigger**, and three differences bite here:

- **Multi-window / Stage Manager.** Several scenes of the same app may be attached simultaneously.
  `sendProviderMessage` is per-`NETunnelProviderSession` and the app holds **one** session object,
  so the app MUST multiplex all scenes onto **one** MI client. Opening one client per scene would
  multiply the 1 s poll by the scene count — an N× battery cost for no information gain.
- **External display and hardware keyboard** extend foreground time indefinitely, which is why the
  poll cadence in §9 is bound to *scene visibility* rather than to app foreground. An iPad docked
  to a monitor with the app on a background scene must not poll.
- **Files integration** gives iPadOS a real export path for a Tier-1 bundle
  (`UIDocumentPickerViewController` / a Files provider) where iPhone-shaped flows use a share
  sheet. The **MI operation is identical** — `diag.bundle.create` returns a container-relative
  artifact identifier — and only the presentation differs. That is precisely the property this ADR
  exists to guarantee.

**The finding, stated as required.** On iOS and iPadOS the MI transport carries a **subset**: request/response only, app-initiated only, and only while the
session is connected. The **contract** is not subset — same operations, same scopes, same schema,
same reason codes. R-21 concerns Linux and router parity with the GUI and is therefore unaffected;
the honest statement for these platforms is that there is no second local client to be unequal to,
so parity is vacuous rather than achieved. The residual is the **battery cost of polling** and the
**inability to query a stopped provider**, both named above and both surfaced with
`MGMT.CHANNEL_UNSUPPORTED` rather than hidden.

#### 11.2.2 Android — stronger authentication, narrower reach

`VpnService` runs in the app's process (or a declared `:vpn` process). The MI server lives in the
agent-equivalent; the UI binds it with `bindService` and speaks AIDL. `Binder.getCallingUid()`
returns a kernel-attested caller uid that cannot be spoofed — strictly stronger than a socket's
`SO_PEERCRED`, because Binder identity is maintained by the driver across the whole transaction.

The service is **not exported**. If a companion app must reach it, the export is guarded by a
`signature`-level `<permission>`, so only code signed with the same key can bind. The consequences
are stated rather than worked around:

- **There is no CLI on stock Android.** `adb shell` and terminal apps run as different UIDs and
  cannot bind. Local automation is limited to the app's own UI and to a signature-matched companion
  app.
- **An exported intent that could disconnect the VPN is deliberately not offered.** It would be a
  confused-deputy primitive available to every app on the device, and no scope model can repair it
  because intents carry no usable caller identity.
- **Always-on VPN and "Block connections without VPN" are set in Settings, not over MI.** So
  `killswitch.mode.set` on Android reports the OS-owned posture **read-only**, and the disarm
  operation returns `MGMT.CHANNEL_UNSUPPORTED` with a next action that deep-links the Settings VPN
  page. That is the correct answer: the OS is the authority, and pretending otherwise would make
  the reported posture a lie.
- **The foreground-service notification is a status surface** and MUST therefore satisfy
  [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6's "visually distinct `DEGRADED` /
  `BLOCKED`" obligation. Its content is derived from the same MI status snapshot as every other
  surface — one source of truth, which is MI-1 applied to a notification.

### 11.3 Framing and the envelope

Framing is **one `MgmtEnvelope` per channel message**, encoded as [ADR-0003](ADR-0003-network-contract-schema-format.md)
**B1 protocol buffers**. On `SOCK_SEQPACKET`, Windows message-mode pipes, XPC, Binder, and
`sendProviderMessage` the boundary is supplied by the channel; on `SOCK_STREAM` fallback a 4-byte
big-endian length prefix supplies it. Maximum envelope size is **1 MiB**, enforced before parse
(`MGMT.PAYLOAD_TOO_LARGE`); parse depth limit 8, as B1.

```proto
// Illustrative. The normative artifact is the published .proto, per ADR-0003 rule 4.
message MgmtEnvelope {
  uint32 mi_version     = 1;  // fixed for the life of a connection; see 11.7
  bytes  request_id     = 2;  // 16B UUIDv7, unique per emission (never reused on retry)
  bytes  correlation_id = 3;  // the request_id this responds to; 0 on a pushed event
  uint64 seq            = 4;  // per-connection, strictly increasing, events only
  bytes  idempotency_key= 5;  // >=128 bits, CEREMONY-class operations only (ADR-0008 N-4)
  uint64 as_of_ms       = 6;  // agent-stamped boot-time monotonic age; see 11.3.2
  oneof body {
    Hello       hello        = 10;  // client -> agent, first message, exactly once
    HelloAck    hello_ack    = 11;  // agent -> client
    Reject      reject       = 12;  // agent -> client, then close
    Request     request      = 13;  // client -> agent
    Response    response     = 14;  // agent -> client
    Event       event        = 15;  // agent -> client, fire-and-forget
    Compacted   compacted    = 16;  // agent -> client, events were dropped
    Goodbye     goodbye      = 17;  // agent -> client, drain notice
  }
}

message Request  { string operation = 1; bytes params = 2; uint64 if_version = 3; }
message Response { bool ok = 1; bytes result = 2; Diagnostic diagnostic = 3;
                   uint64 committed_at_net_seq = 4; }   // see 11.7 / protocol.md 5.1
```

`Diagnostic` is [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.3's record, carried
verbatim and **extended by §11.3.1 below**. MI does not define a second error shape, and
`reason_code` inside it is a **string**, per §11.2 of that ADR — which is the concrete reason gRPC
status enums were rejected (§6, alternative C).

#### 11.3.1 The `Diagnostic` envelope carries structure, never prose

Two rules, and the first closes a genuine corpus defect that
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) files as **D2**.

> **MI-14 (resolved attributes travel with the code).** Every `Diagnostic` crossing MI MUST carry
> the **resolved** attribute set inline, not by registry lookup: `reason_code`, `class`, `severity`,
> `terminal`, `user_actionable`, `remediation_class`, `scope`, and `doc_anchor` — for **every** code,
> including codes the receiving client does not recognize. The **agent** resolves them from **its
> own** registry at emission time.

**Satisfied core-side.** [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) has widened F-4
from `{reason_code, evidence}` to `{reason_code, evidence, resolved}`, with `resolved` carrying
exactly these fields, looked up core-side at emission because
[ADR-0018](ADR-0018-shared-core-and-build-architecture.md) CB-4 makes the core the registry owner.
MI therefore **carries** the resolution rather than performing it — had the ABI shipped the bare
code, MI would have needed a second registry outside the core, which is the defect class R-31
exists to prevent. That ADR also makes the metadata/text distinction normative and prohibits adding
a `summary`, `message`, or `title` field to `resolved`: every member is an enum, a boolean, or a
stable anchor, so carrying it breaches neither CB-4 nor MI-15. The two rules are complementary and
now say so on both sides.

This is the mechanism that makes [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 5
implementable at the application layer. Rule 5 requires a receiver to degrade an unknown code to its
`DOMAIN` prefix **and** not to display the raw code as the primary signal. If only the code *string*
crossed the boundary, those two obligations would be jointly unsatisfiable: a client cannot choose a
correct affordance — non-dismissible for a `POLICY`-class condition, transient for an `INFO` one —
from a bare identifier it has never seen. Under MI-14 it can: the **headline** degrades by `DOMAIN`
prefix from the client's own registry, and the **affordance** is chosen from the transmitted
structure. The two halves of rule 5 are served by two different fields.

The principle is not new; it is [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4's own —
"redaction is applied by the emitter based on the schema classification" — applied to attribute
resolution for the same reason. **The party that holds the registry is the party that must resolve
against it**, and after an upgrade that party is always the agent, never the client.

Concretely, `class` and `severity` are already fields of §11.3's record; `terminal` and
`user_actionable` are registry attributes that §11.3's record does **not** carry, and `scope` and
`remediation_class` are the two additional declared evidence fields
[docs/reliability.md](../reliability.md) §3.1 requires. MI-14 promotes all four to first-class
envelope fields rather than leaving them to be inferred, looked up, or dug out of `evidence` by a
client that does not know which fields to expect:

```proto
// Illustrative; extends ADR-0015 11.3 rather than replacing it.
message Diagnostic {
  string reason_code       = 1;   // string, never an enum (ADR-0015 11.2)
  Class  class             = 2;   // TRANSIENT | PERSISTENT | POLICY | FATAL
  Sev    severity          = 3;   // INFO | WARN | ERROR | CRITICAL
  bool   terminal          = 4;   // registry attribute, resolved by the agent
  bool   user_actionable   = 5;   // registry attribute, resolved by the agent
  Remed  remediation_class = 6;   // user-action|wait|automatic|network-operator|unsupported
  Scope  scope             = 7;   // session|device|relay|region|twinnet
  string doc_anchor        = 8;
  // state_from, state_to, component, occurred_at, correlation_id, evidence[]
  //   as ADR-0015 11.3. NO rendered text field exists; see MI-15.
}
```

> **MI-15 (no rendered text over MI).** MI payloads carry **codes and typed evidence, never rendered
> human text.** There is no `summary`, `message`, `title`, `description`, or per-code "user message"
> field in any MI message, in any version. `summary_key` and `next_action_key` are i18n **keys**, and
> even those are carried only as the registry's identifiers, never as resolved strings. Rendering
> happens at the surface that has a locale and a viewport, from `(reason_code, class, evidence)`.

MI-15 forbids rendered text **on the wire**; it does not forbid a shared renderer. The consumer
calls [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s `tw_render_diagnostic` **on its
own side** of the MI boundary, after receiving the structure — which is how
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) gets one resolver serving all
six platforms plus the CLI while nothing localized ever crosses MI. The rule is about what is
transmitted, not about where the strings live.

MI-15 is why [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 4 — "the code is the
contract; the human text is not" — survives a process boundary, and it is what lets
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) place a single presentation
resolver inside the H1 core and compute its "what this means for your traffic right now" sentence
from `(state_to, traffic_disposition, enforcement_mode)` rather than from a per-code string. A UI
three versions behind still tells the truth, because the truth was never in the prose. It also
agrees with [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-4, which specifies core
failures as `{reason_code, evidence}` with declared `evidence_fields` and no localized string. All
three ADRs converge; MI-15 states it normatively so it is checkable rather than inferable.

#### 11.3.2 `as_of` — the freshness stamp, and why it must be boot-time monotonic

> **MI-16.** Every MI `Response`, every `Event`, and every snapshot row MUST carry `as_of_ms`: the
> time at which the carried value **was true**, stamped by the **agent**, on a **boot-time
> monotonic** clock.

Three properties, each load-bearing, each a bug if dropped:

1. **Stamped by the agent, never by the client on receipt.** A client-side stamp measures transport
   latency, not value age. It would read "fresh" for a value the agent computed twenty seconds ago
   while wedged or descheduled — the precise case the stamp exists to catch.
2. **Monotonic, never wall-clock.** Wall clocks jump across suspend and across timezone and NTP
   corrections ([docs/reliability.md](../reliability.md) §10.2 E5), and
   [docs/protocol.md](../protocol.md) §2 already makes `sender_time_ms` **advisory only** for exactly
   this reason. A wall-clock stamp yields negative or absurd ages precisely when the gate matters.
3. **Boot-time monotonic, not merely monotonic** — and this is the refinement that decides the
   common case. `CLOCK_MONOTONIC` on Linux does **not** advance while the host is suspended, so
   after an hour's suspend a value computed before the suspend reads as ~0 ms old and a stale
   indicator renders green. The required clock is the suspend-inclusive one: `CLOCK_BOOTTIME`
   (Linux, OpenWrt, Android via `SystemClock.elapsedRealtime()`), `mach_continuous_time()`
   (macOS, iOS, iPadOS), `QueryUnbiasedInterruptTimePrecise` — or `GetTickCount64` — (Windows).
   Suspend and resume are the most common transition-producing events on a laptop and a phone, so
   the clock that ignores them is the wrong clock. **The corpus now has a name for it:**
   [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) LC-8 defines three
   non-interchangeable injected clocks, and `as_of_ms` MUST be stamped from **`ElapsedClock`**
   (suspend-inclusive), never `MonotonicClock` (suspend-exclusive, and correct for every
   [docs/reliability.md](../reliability.md) §5 timer) and never `WallClock`. That ADR's per-platform
   primitives for `ElapsedClock` are the ones named above; this ADR adopts its vocabulary rather than
   describing the same clock twice.

**Why an agent-stamped clock is comparable by the client at all**, which would not be true on a
network contract: MI is **local by construction**, so agent and client share one host and therefore
one boot-time monotonic timebase. `now - as_of_ms` is a real age, not a clock-skew artifact. This is
a property the local interface has and the wire protocol does not, and it is the reason
[docs/protocol.md](../protocol.md) §5's refusal to let any decision depend on a peer's clock does
not bind here. On iOS and iPadOS the containing app and the provider are different processes on one
device and share `mach_continuous_time()`, so the property holds across the subset channel too.

**What consumes it.** `as_of_ms` is the input to a consumer-side staleness gate — the mechanism
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) UI-4 uses to make a stale
positive state unrenderable rather than merely discouraged. MI supplies the fact; the thresholds and
the affordance are the consumer's. This is deliberately **not** the same mechanism as
[ADR-0015](ADR-0015-observability-and-diagnostics.md) O-18's `ProtectionAssertion` expiry: that one
governs the **protection indicator** and is already carried on the `protection` topic. `as_of_ms`
governs **everything else** — `ConnectionState`, the peer list, per-peer rows, path and relay
data — which O-18 does not cover, and which would otherwise keep rendering as current behind an
intact, perfectly contiguous cursor while the agent was wedged. A contiguous `seq` proves **no event
was lost**; it does not prove **any event was recent**. Those are different claims, and R-29's
"management independence" is only honest if the consumer can tell them apart.

**MI-2.** `request_id` MUST be unique per emission, including per retransmission of a logically
identical request. A retry reuses `idempotency_key`, never `request_id` — the same separation
[docs/protocol.md](../protocol.md) §2 makes on the wire, for the same diagnostic reason.

**MI-3.** The agent MUST NOT initiate a request. The only agent→client messages are `HelloAck`,
`Reject`, `Response`, `Event`, `Compacted`, and `Goodbye`, and none of them expects a reply. **No
daemon→client RPC exists.** This is not a simplification; it is the mechanism that makes "wait for
the UI" unexpressible in the agent's code (§11.11).

### 11.4 Authentication of local callers

**MI-A1 (kernel-sourced identity).** The calling principal MUST be obtained from the kernel on the
connected channel. **No field carrying a client-asserted identity exists in the schema**, in any
message, at any version. Removing the field removes the class of bug: there is nothing to forget to
validate.

**MI-A2 (pid lookups are advisory).** Identifying the caller's *image* via its pid —
`/proc/<pid>/exe`, `GetModuleFileNameEx`, `proc_pidpath` — is **advisory only** and MUST NOT gate
any scope. Pids are reused and processes can be replaced between the credential read and the
lookup. The one exception is macOS's **audit token**, which is used precisely because it is not a
pid and is therefore not subject to that race.

**MI-A3 (endpoint creation).** The endpoint MUST be created such that no lower-privileged process
can win a race for its path:

- The containing directory MUST be created by the OS init system with a privileged owner and no
  non-privileged write — systemd `RuntimeDirectory=twinvpn` or `tmpfiles.d` on Linux, `procd` on
  OpenWrt, the installer on Windows and macOS. The agent MUST verify the directory's ownership and
  mode before binding and MUST refuse to bind into a directory it does not own
  (`MGMT.LISTEN_FAILED`).
- The socket MUST be created by `bind()` on a fresh temporary name in that directory followed by
  `rename()` into place. **`unlink()`-then-`bind()` is prohibited** — it opens a window in which a
  squatter can place its own socket at the path.
- On Windows the pipe MUST be created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and an explicit DACL, so
  a pre-created squatting instance causes creation to fail loudly rather than silently yielding the
  name.
- **The installer/runtime split is explicit** ([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)
  §11.18(f), confirming §11.18(f) here): the **package** creates the groups and the containing
  directories; the **agent** creates the endpoint and writes its DACL at every start. An
  installer-written endpoint ACL would be **stale after the first agent restart** — group membership
  and SIDs can change between install and run — so the runtime is the only correct author of the
  access control on the endpoint itself. The package owns what outlives the process; the agent owns
  what is recreated with it.
- **Socket activation MUST NOT be used** — a reversal of an earlier draft of this ADR, which called
  the inherited listening fd "preferred" because it removes the bind race. That reasoning was wrong
  on two counts, and [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) I-02(a)
  is right to forbid it outright. First, it bought a **solved** problem: bind-and-rename above
  already closes the race, so socket activation was paying topology for nothing. Second, and
  decisively, it **inverts the dependency direction §11.11 exists to make one-way**. Under socket
  activation the init system holds the listening socket and a client connection can *cause the agent
  to start* — so the agent's lifetime becomes a function of management-client behaviour, which is
  exactly the on-demand topology [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)
  PS-1/PS-3 rejects and which MI-I5-3 declares impossible. There is a third, quieter failure too:
  the activation socket **outlives the agent**, so a client connects successfully and then hangs
  against a socket nobody is serving — strictly worse than an immediate, nameable
  `MGMT.UNAVAILABLE`. **The endpoint is created by the running agent, at every start, and ceases to
  exist when the agent does.**

**MI-A4 (no impersonation work).** On Windows the server MAY call `ImpersonateNamedPipeClient` only
to read the client's token, and MUST `RevertToSelf` before performing any work. Performing
privileged work while impersonating a client is the classic named-pipe confused deputy, and the
`SECURITY_IDENTIFICATION` level the client requests is the client's choice, not ours — so the
server must not depend on it.

**MI-A5 (fail closed on unverifiable identity).** If peer credentials cannot be obtained for any
reason, the agent MUST reject the attach with `MGMT.PRINCIPAL_UNVERIFIABLE` and close. It MUST NOT
fall back to a default principal, a "local user" assumption, or an anonymous read-only tier.

| Platform | What is proven | What is **not** proven |
|---|---|---|
| Linux / OpenWrt | uid, gid, pid at connect time; SELinux/AppArmor context where present | *Which program* is calling: any binary the user runs has the user's uid |
| Windows | The client's token, SID set, and integrity level | Image identity across a TOCTOU; an Authenticode check on the image is advisory (MI-A2) |
| macOS (XPC) | uid **and** a code-signing identity, checked against the audit token | Nothing meaningful is lost here; the audit token is the strongest attestation of the five |
| macOS (socket, Developer ID) | uid, gid via `LOCAL_PEERCRED` | Program identity, as Linux |
| iOS / iPadOS | The caller is the containing app | Nothing — there is no other possible caller |
| Android | The caller's uid, and (where exported) its signing certificate | Nothing on a non-rooted device; a rooted device is outside this boundary |

**The honest paragraph.** On Linux, Windows, and the macOS Developer-ID socket variant, **the MI
authenticates a user, not a program.** Any process the authorized user runs can do everything the
GUI can do. That is a property of the operating systems' discretionary access control, not a defect
of this design, and the alternative — per-binary allowlisting — is defeated by an attacker who is
already running as that user while breaking every legitimate third-party client. The security value
of MI's authentication is that it keeps *other local users* and *unprivileged service accounts*
out. Everything that must survive a compromised user session is bound to an OS re-authentication
ceremony instead, which is exactly why §11.14 exists and why `mgmt.disarm` is not a grantable
attach-time scope.

### 11.5 The scope model

Scopes are the authorization resolution. Six are grantable at attach; one exists only as an
ephemeral, OS-minted, per-operation grant.

| Scope | Grants | Typical principal |
|---|---|---|
| `mgmt.status` | Read connection state, sessions, peers, paths and the candidate ledger, policy view, enforcement posture, capabilities, metrics, version, catalogue | Any member of the TwinVPN local group |
| `mgmt.events` | Subscribe to the event stream and resync | Same |
| `mgmt.diagnostics` | Connectivity report, log tail, exempt-socket registry — **read only** | Same |
| `mgmt.connect` | Connect / disconnect / reconnect a `Session`; force a path re-probe; `net.up` / `net.down` | Same |
| `mgmt.settings` | Local settings, route **acceptance**, exit-node selection, DNS preference, autostart, portal-exemption request, diagnostics-bundle creation, capture-level raise; **requesting** a disarm challenge | Same |
| `mgmt.admin` | Pairing and enrolment, device revocation, key rotation, **enforcement-mode change**, `AccessPolicy` authoring, host-profile change | An administrative principal — these mint, withdraw, or re-scope trust |
| `mgmt.disarm` | Commit a kill-switch disarm | **Never granted at attach.** Minted per-operation by the OS ceremony (§11.14) |

Four normative rules:

- **MI-S1 (grant, never request).** `Hello.requested_scopes` is a **reduction** request only. The
  granted set is `policy(principal) ∩ requested`. A client may drop capabilities it does not need;
  it can never add one. A client that requests a scope its principal lacks is granted the
  intersection and told which scopes were withheld in `HelloAck.withheld_scopes` — it is not
  rejected, because a status-only client should still work.
- **MI-S2 (attach-time immutability).** The granted set is computed at attach and is **immutable
  for the life of the connection**. There is no scope-escalation message. A client that needs more
  reconnects. This mirrors [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)
  N-16's per-`Session` immutability for the same reason: a mutable negotiated set is a downgrade
  surface and a source of time-of-check bugs.
- **MI-S3 (monotone-safe enforcement).** No MI operation may lower enforcement. `killswitch.mode.set`
  computes `max(current_mode, requested_mode)` over the total order
  `OFF < ARMED_ON_INTENT < ALWAYS_ON`, exactly as
  [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-22's third property requires of the
  control plane. A request that would lower it is refused with `MGMT.MONOTONE_REFUSED`, not
  silently clamped — a silent clamp would leave the client believing it succeeded.
- **MI-S4 (local preference is bounded by signed policy).** S-06 `AccessPolicy` and S-07 `DNSPolicy`
  are `Owner`-authored, `MONOTONIC`, and distributed as signed documents. An MI preference can only
  choose **within** what the effective bundle permits. A request outside it is refused with
  `MGMT.POLICY_FORBIDS`. MI is not a second writer for S-06 or S-07, and **I8 is preserved**:
  MI writes only S-24 (local preferences), S-17 (route acceptance) and S-18 (enforcement, raise-only
  plus the §11.14 ceremony), each of which already has the local `Device` as its single writer.

**Reconciliation with [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) Q6.** That ADR
requires every privileged operation to be classified into exactly one of three authorization
classes — `OBSERVE`, `OPERATE`, `ADMINISTER` — and requires every `ADMINISTER` operation to carry
**per-action OS-mediated authentication, never cached beyond it**. The two models compose rather
than compete: **ADR-0016 owns the principal → class grant; this ADR owns the operation → scope
mapping**, and every scope belongs to exactly one class.

| MI scope | ADR-0016 class | Per-action OS authentication |
|---|---|---|
| `mgmt.status`, `mgmt.events`, `mgmt.diagnostics` | `OBSERVE` | No |
| `mgmt.connect`, `mgmt.settings` | `OPERATE` | No — but `diag.bundle.create` additionally requires an **interactive** principal (MI-D6) |
| `mgmt.admin` | **`ADMINISTER`** | **Yes**, per action (§11.14) |
| ephemeral `mgmt.disarm` | **`ADMINISTER`**, strictest instance | **Yes**, per action, plus KS-21's interactive-action and consequence-naming requirements (§11.14) |

Three consequences follow and are normative here. First, `mgmt.admin` is **not** satisfied by group
membership alone: `pair.begin`, `pair.confirm`, `device.revoke`, `key.rotate` and
`killswitch.mode.set` each require the §11.14 ceremony, freshly, per call. Second, **every scope
maps to exactly one class** — an earlier draft of this ADR had a single `mgmt.policy` scope spanning
`OPERATE` and `ADMINISTER`, which ADR-0016 §11.7 correctly rejected; it is split above, with
*accepting* an offered `Route` at `OPERATE` (`mgmt.settings`) and *authoring* `AccessPolicy` at
`ADMINISTER` (`mgmt.admin`). ADR-0016's rule that a scope which cannot be split is `ADMINISTER` is
adopted, which is why `killswitch.mode.set` sits in `mgmt.admin` even for a raise. Third, if
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) revises its class set, **its class
set is authoritative** and this table is amended — the scopes are a grouping under those classes,
never a rival taxonomy.

**Principals are ADR-0016's, not this ADR's.** [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)
§11.7 PS-12a names them normatively and overrides the placeholders an earlier draft here used:
Linux `twinvpn` (`OBSERVE`) and `twinvpn-operators` (`OPERATE`), polkit action
`net.twinvpn.administer` with `auth_admin` — **not** `auth_admin_keep`, so authorization cannot be
cached across actions; Windows `TwinVPN Users` (`OBSERVE`) and `TwinVPN Operators` (`OPERATE`), with
`ADMINISTER` requiring `BUILTIN\Administrators` present **and enabled** in the client's elevated
token; macOS `_twinvpn` / `_twinvpn_op` plus Authorization Services `system.privilege.admin`;
OpenWrt and headless: `root` only, under PS-14's rule (§11.14). Built-in `Users` / `staff` is
deliberately **not** the `OBSERVE` principal — "every local account on this host may enumerate its
peers and endpoints" must be an install-time decision, not a default.

### 11.6 The contract, and its binding to ADR-0003

The MI reuses [ADR-0003](ADR-0003-network-contract-schema-format.md)'s rules; it does **not**
introduce a second schema system.

| Boundary | Encoding | Binding |
|---|---|---|
| MI envelope, requests, responses, events | **B1 protobuf**, length-delimited or channel-framed | Unknown fields preserved and forwarded; explicit integer sizing; 1 MiB / depth 8 caps |
| Signed statements that pass **through** MI (e.g. a `PairingOffer`, a policy bundle being displayed) | **B2 deterministic CBOR in COSE_Sign1**, carried as opaque `bytes` | Verified over received octets; MI MUST NOT re-serialize a signed statement it forwards or renders |
| CLI human and script output; configuration files | **B5 JSON**, UTF-8, **64-bit integers rendered as strings** | ADR-0003 §11 rule 2. This bites concretely: `net_seq`, `contract_seq`, `policy_version` and byte counters in `twinvpn ... --output json` are strings, and a script that treats them as JSON numbers loses precision silently |

**A contradiction in the corpus, resolved here.** [ADR-0003](ADR-0003-network-contract-schema-format.md)
§11 describes B5 as "local config, CLI, diagnostics — JSON … **Never a trust boundary**; never
signed in this form." The local management interface **is** a trust boundary: an unprivileged
caller instructs a privileged agent across it. The resolution is a split, not an exception:

> **MI-4.** B5's JSON is the **rendering** format at the CLI's human/script boundary and the
> configuration-file format ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)).
> The MI **transport** is B1 protobuf, and it is a trust boundary. Authorization at that boundary
> is by OS principal and scope (§11.4, §11.5), never by the encoding, and no MI message is a signed
> statement. B2 statements that traverse MI do so as opaque octets and are verified by their real
> consumer, never by MI.

[ADR-0003](ADR-0003-network-contract-schema-format.md) §11's B5 row should be amended to read
"never a trust boundary **for authentication or authorization**", with a pointer here. That is an
obligation on the integrator, recorded in §11.18; **this ADR does not modify that file.**

### 11.7 Versioning and capability negotiation for the local interface

[ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) §11.1 defines three version
axes — V-1 (wire schema, ADR-0003), V-2 (peer protocol), V-3 (control-plane API) — sharing one
`ProtocolEpoch` number space. The MI is a **fourth axis, in its own number space**:

| Axis | Name | Versions | Owner | Number space |
|---|---|---|---|---|
| **V-4** | **`mi_version`** | The local management contract: operation names, parameter and result shapes, scope requirements, event topics | **This ADR** | **Separate `uint32`**, not the `ProtocolEpoch` |

**Why a separate number space, against the corpus's own "one integer" preference.** ADR-0014's
three axes share a number space because they describe one artifact — a released TwinVPN
*protocol* — observed by operators, support, and telemetry as a single fleet position. `mi_version`
describes something else: the shape of a **local API** whose consumers include third-party
automation that has no notion of a `ProtocolEpoch`. Coupling them would force a `ProtocolEpoch`
bump — with its three-epoch fleet-wide skew guarantee, its 12-month deprecation gates, and its
prologue-binding consequences — every time a field is added to a status response. That is a large
cost for no benefit, and ADR-0014 N-1 explicitly forbids a bump when required receiver behaviour
has not changed. Conversely, a wire epoch bump must not invalidate a working CLI. The two axes
change for different reasons at different cadences, so they are separate integers, and
`version.get` returns both so support and telemetry can still correlate.

**Negotiation at attach.**

```
Hello    { mi_version_min, mi_version_max, client_kind, client_version,
           requested_scopes[], subscribe_topics[] }
HelloAck { mi_version, agent_version, build_profile, granted_scopes[],
           withheld_scopes[], catalogue_digest, event_cursor, protocol_epoch_range,
           platform_ctx }              // {platform, os_version}; see MI-C3
Reject   { Diagnostic }                      // then close
```

- The selected `mi_version` is `min(client.mi_version_max, agent.mi_version_max)` and is **fixed
  for the life of the connection**, exactly as `proto_version` is fixed for the life of a control
  connection ([docs/protocol.md](../protocol.md) §2).
- **The catalogue, not the version, is the capability contract.** `HelloAck` carries a
  `catalogue_digest`; `mi.catalogue.get` returns the full table of
  `(operation, min_mi_version, required_scope, mutating, idempotency_class)`. A client MUST NOT
  call an operation absent from the catalogue it fetched on **this** connection.
- **Why a catalogue and not just an integer.** On a router the agent is built with a reduced
  feature profile — no GUI-facing operations, no per-app routing, possibly no `ubus` bridge — so
  "`mi_version` 4" does not imply "implements operation X". **Build profile is not version.** The
  catalogue is what lets one client speak to a full desktop agent and a stripped router agent
  without a per-profile client. This is the direct local analogue of
  [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md)'s capability negotiation,
  and it exists for the same reason: a version integer cannot express "supported here, absent
  there".

**The compatibility window — and why it differs from the wire's.**

> **MI-5.** An agent MUST serve `mi_version` **N and N-1**. It SHOULD serve **N-2** where its build
> profile includes the legacy shim. The window is **two epochs or 90 days, whichever is longer**.

The wire window is three epochs / 12 months
([ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-24, N-25) because the
peer is *someone else's device*, upgraded on a schedule nobody controls, and the fleet distribution
is a measured fact. The local window is deliberately shorter because the skew is different in kind:
the agent and its shells are normally shipped in **one package**
([ADR-0021](ADR-0021-packaging-distribution-and-updates.md)) and upgraded atomically, and
where they are not, the operator can re-run the installer. Three real long-tail cases justify a
window larger than zero:

| Case | Skew direction | Why the window must cover it |
|---|---|---|
| Live upgrade with a running UI | agent newer | The tray icon nobody restarts can outlive several agent versions |
| Distribution or OpenWrt split packaging (`twinvpn` / `twinvpn-cli`), or a pinned `~/bin` copy | either | The maintainer, not us, chooses the cadence |
| Third-party automation pinned to an older `mi_version` (a home-automation integration, an Ansible module) | client older | Breaking it silently is how a local API loses its ecosystem |

**Behaviour on mismatch — normative, and the part that is most often got wrong.**

| Case | Required behaviour |
|---|---|
| `client.mi_version_max < agent.mi_version_min` | The agent MUST complete enough of the attach to answer, then send `Reject{MGMT.VERSION_TOO_OLD}` carrying `agent_version` and a next action, **then** close. **A silent close is prohibited**: it is indistinguishable from "the agent is not running", and it sends the user to reinstall rather than to update |
| `client.mi_version_min > agent.mi_version_max` | `Reject{MGMT.VERSION_TOO_NEW}`. The message MUST name **which side is behind**, because a newer CLI against an older agent and the reverse have opposite remedies |
| Ranges overlap | Select `min(maxes)`; fixed for the connection |
| Operation absent from the catalogue | `MGMT.OP_UNKNOWN`, naming the operation. **Never** a parse error, never a hang, never a generic failure |
| Unknown field in a known request | Preserved and ignored, per B1 proto3 semantics |
| A change that would alter an existing operation's **semantics** | MUST be a **new operation name**, never a new field on the old one. `mi_version` gates availability; it does not silently redefine behaviour |
| Unknown `reason_code` received by an older client | Degrade to the `DOMAIN` prefix and render the domain-level explanation, per [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 5. §11.12 gives the concrete CLI rendering |
| Agent restarts under a live client | The connection dies. The client MUST reconnect with backoff, **re-`Hello`**, and **re-fetch the catalogue**. It MUST NOT reuse a catalogue cached across a reconnect — the agent may have changed version across the restart, which is exactly what a live upgrade is |

**Read-your-writes across the process boundary.** [docs/protocol.md](../protocol.md) §5.1 obliges a
client not to report a mutating operation complete until its C2 cursor has reached the operation's
`committed_at_net_seq`. Under H2 the reporting client is a different process, so the obligation
must be expressed locally:

> **MI-6.** Every MI response to an operation that maps to a mutating C1 request MUST carry
> `committed_at_net_seq`. Every MI event mirroring a durable control-plane fact MUST carry the
> `net_seq` at which the agent observed it. An MI client MUST NOT report such an operation complete
> to a human until it has observed an event at or past that cursor, or has called `event.resync`
> and received a snapshot cursor at or past it. This discharges
> [docs/protocol.md](../protocol.md) §5.1 across the process boundary, which nothing else in the
> corpus does.

### 11.8 Idempotency

Binding to [ADR-0008](ADR-0008-idempotency.md), applied locally:

| Class | MI expression | Examples |
|---|---|---|
| `DECLARATIVE` | `Request.if_version` against the object's monotonic version; mismatch ⇒ `MGMT.PRECONDITION_FAILED` | `settings.set`, `route.accept.set`, `dns.preference.set`, `killswitch.mode.set` |
| `CEREMONY` | Client-generated `idempotency_key` ≥128 bits (N-4); replay within the window returns the recorded outcome with `MGMT.DUPLICATE_REPLAYED` | `pair.begin`, `pair.confirm`, `device.revoke`, `key.rotate`, `diag.bundle.create`, `diag.capture.set` |
| Naturally idempotent | No key; the state machine already absorbs a repeat — `EV_CONNECT_REQUESTED` is idempotent by [docs/reliability.md](../reliability.md) §4.3 ("a request while already connecting is absorbed") | `session.connect`, `session.disconnect`, `net.up`, `net.down` |
| Read-only | Trivially idempotent | every `mgmt.status` operation |

Two MI-specific rules:

- **MI-7 (the local dedup window is short and non-durable).** The MI ceremony dedup log (S-45) has
  a window of **10 minutes** and a bound of **256 entries**, and is **non-durable by requirement**:
  it MUST NOT survive an agent restart. An MI retry is a socket-level retry inside one human
  interaction, not a cross-network retry across a cellular outage. Making it durable would mean a
  ceremony replayed after a reboot returns a stale recorded outcome instead of being re-evaluated
  against current state — the opposite of what a restart should mean locally.
- **MI-8 (one key from the button press to the coordination service).** Where an MI ceremony
  triggers a control-plane ceremony, the agent MUST derive the C1 `idempotency_key`
  **deterministically from the MI key and the calling principal**, so that (a) a UI that crashes
  mid-pairing and re-issues with the same MI key reaches the recorded C1 outcome under
  [ADR-0008](ADR-0008-idempotency.md) N-5's 24-hour window rather than minting a second `Pairing`,
  and (b) two different local principals cannot collide on, or pre-claim, each other's key. The
  agent MUST NOT forward a client-supplied key verbatim. The composition is deliberate: MI's short
  window catches socket-level retries, and ADR-0008's 24-hour window catches everything else.

### 11.9 The operation catalogue

`Idem` — **key** = ADR-0008 `CEREMONY` key required · **ver** = `if_version` required · **nat** =
naturally idempotent · **ro** = read-only. All operations are request/response except those marked
**ST** (stream). `PLATFORM.PRIV.CLIENT_UNAUTHORIZED`, `PLATFORM.SERVICE.QUARANTINED`, `MGMT.OP_UNKNOWN`, `MGMT.NOT_READY`, `MGMT.SHUTTING_DOWN` and
`MGMT.PAYLOAD_TOO_LARGE` are possible on **every** operation and are omitted from the rows.

| Operation | Scope | Mut. | Idem | Returns | Additional reason codes |
|---|---|---|---|---|---|
| `status.get` | `mgmt.status` | no | ro | Derived `TwinNet`-scope `ConnectionState` per [docs/reliability.md](../reliability.md) §4.7 (worst-wins, with the worst contributor's `reason_code` and a healthy count), enforcement mode, `ProtectionAssertion` + its freshness | — |
| `session.list` | `mgmt.status` | no | ro | Per-peer `Session` rows: `session_id`, peer, one of the twelve `ConnectionState`s ([docs/reliability.md](../reliability.md) §4 — cited, never restated), traffic disposition, path class, current `Diagnostic` | — |
| `session.get` | `mgmt.status` | no | ro | One `Session` plus its `Path` set and the `ConnectionCandidate` ledger (S-14 view; the ledger [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8 item 4 requires) | — |
| `peer.list` / `peer.get` | `mgmt.status` | no | ro | `TrustedPeer` set (S-05), assigned `TwinNet` addresses (S-08), presence (S-11, **advisory, never a gate**) | — |
| `path.list` | `mgmt.status` | no | ro | Active and standby paths, relay identity and region, measured RTT/loss/jitter, S-31 local quality history | — |
| `policy.get` | `mgmt.status` | no | ro | Effective `AccessPolicy` (S-06) and `DNSPolicy` (S-07) snapshots with versions, and the local preferences layered on them | — |
| `killswitch.get` | `mgmt.status` | no | ro | The `EnforcementRecord` ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.13) and the dual-family `ProtectionAssertion` | — |
| `killswitch.exempt.get` | `mgmt.status` | no | ro | The KS-9(2) registered-socket set by class (`BOOTSTRAP` / `RESOLVER`), the per-family exempt byte and packet counters KS-11 requires, and the current divergence figure. **Read-only, always** (MI-11) | — |
| `capability.get` | `mgmt.status` | no | ro | The Platform Network Adapter capability probe ([docs/architecture.md](../architecture.md) §2.5) and per-`Session` negotiated `Capability` sets (S-19) | — |
| `lifecycle.get` | `mgmt.status` | no | ro | The current `HostLifecycleState` (**S-61**, [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md)) — the polled counterpart of the `lifecycle` topic, answerable in every phase in which a process exists (MI-I5-5) | `PLATFORM.LIFECYCLE.*` per [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) |
| `version.get` | `mgmt.status` | no | ro | Agent version, `mi_version` range, `ProtocolEpoch` range, build profile, catalogue digest | — |
| `metrics.get` | `mgmt.status` | no | ro | The local counters, histograms and spans [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.7 requires to be "exposed on a local status interface". **This is that interface** | — |
| `mi.catalogue.get` | `mgmt.status` | no | ro | The full operation table (§11.7) | — |
| `event.subscribe` **ST** | `mgmt.events` | no | nat | Live `Event` stream from the attach cursor | `MGMT.STREAM_COMPACTED`, `MGMT.CLIENT_TOO_SLOW`, `MGMT.CHANNEL_UNSUPPORTED` |
| `event.unsubscribe` | `mgmt.events` | no | nat | — | — |
| `event.resync` | `mgmt.events` | no | nat | `SnapshotBegin` / rows / `SnapshotEnd{cursor}`, then live events from `cursor` (§11.10) | — |
| `diag.report` | `mgmt.diagnostics` | no | ro | The [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.8 connectivity report, all eight parts, rendered offline | `MGMT.RATE_LIMITED` |
| `diag.bundle.create` | `mgmt.settings` | yes | key | An agent-chosen artifact identifier; the redacted Tier-1 bundle is written mode `0600` to an agent-owned directory (MI-D3) | `MGMT.RATE_LIMITED`, `MGMT.DIAG.BUNDLE_CREATED` (INFO, also broadcast as an event) |
| `diag.log.tail` **ST** | `mgmt.diagnostics` | no | ro | Tier-0 ledger entries from `since`, at the current capture level, redacted per §11.15 | `MGMT.RATE_LIMITED` |
| `diag.capture.set` | `mgmt.settings` | yes | key | Raise capture level with a **mandatory** auto-expiry ([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.10) | `MGMT.CAPTURE_EXPIRY_REQUIRED` |
| `session.connect` | `mgmt.connect` | yes | nat | Injects `EV_CONNECT_REQUESTED` ([docs/reliability.md](../reliability.md) §4.3, source "user") | `MGMT.RATE_LIMITED` |
| `session.disconnect` | `mgmt.connect` | yes | nat | Injects `EV_DISCONNECT_REQUESTED` | — |
| `session.reconnect` | `mgmt.connect` | yes | nat | Forces re-establishment; floored at the [docs/reliability.md](../reliability.md) §6.1 backoff floor so it cannot be a local DoS | `MGMT.RATE_LIMITED` |
| `path.probe` | `mgmt.connect` | yes | nat | Forces a path re-probe. Takes a `session_id`, **never an endpoint** (MI-D5) | `MGMT.RATE_LIMITED` |
| `net.up` / `net.down` | `mgmt.connect` | yes | nat | `TwinNet`-scope connect/disconnect. **`net.down` clears the M2 session intent and MUST NOT clear the latch** (MI-K1) | — |
| `settings.set` / `settings.get` | `mgmt.settings` / `mgmt.status` | yes / no | ver / ro | Local preferences (S-24) | `MGMT.PRECONDITION_FAILED` |
| `killswitch.mode.set` | `mgmt.admin` (**ADMINISTER**) | yes | ver | `max(current, requested)` (MI-S3). ADMINISTER even for a raise, per ADR-0016 §11.7 | `MGMT.MONOTONE_REFUSED`, `MGMT.CHANNEL_UNSUPPORTED` (Android), `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `dns.preference.set` | `mgmt.settings` | yes | ver | A preference **within** the signed `DNSPolicy` (MI-S4) | `MGMT.POLICY_FORBIDS` |
| `route.accept.set` | `mgmt.settings` | yes | ver | Which advertised subnets this device installs (S-17 is `LOCAL`, so this is legitimately a local decision) | `MGMT.POLICY_FORBIDS` |
| `exitnode.select` | `mgmt.settings` | yes | ver | Choose among offered exit nodes | `MGMT.POLICY_FORBIDS` |
| `autostart.set` | `mgmt.settings` | yes | ver | — | — |
| `pair.begin` | `mgmt.admin` (**ADMINISTER**) | yes | key | The `PairingOffer` material to render — QR payload or 9-digit SPAKE2 code ([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4). **The one `SECRET` that crosses MI**; see MI-P1 | `MGMT.RATE_LIMITED`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `pair.confirm` | `mgmt.admin` (**ADMINISTER**) | yes | key | Completion; carries `committed_at_net_seq` (MI-6) | `MGMT.PRECONDITION_FAILED`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `pair.cancel` / `pair.status` | `mgmt.admin` | yes / no | nat / ro | — | — |
| `device.revoke` | `mgmt.admin` (**ADMINISTER**) | yes | key | Initiates the `Owner`-signed `RevocationRecord` ceremony; carries `committed_at_net_seq` | `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `key.rotate` | `mgmt.admin` (**ADMINISTER**) | yes | key | [ADR-0007](ADR-0007-device-identity-and-pairing.md) succession | `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `update.status` | `mgmt.status` | no | ro | Current channel, installed version, staged version if any, rollback floor (S-23), last check outcome | `UPDATE.*` per [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| `update.check` | `mgmt.settings` | yes | nat | Queries the update service; **advisory** — a failed check MUST NOT affect a `Session` (I5) | `UPDATE.*`, `MGMT.RATE_LIMITED` |
| `update.stage` | `mgmt.admin` (**ADMINISTER**) | yes | key | Downloads and verifies an artifact without applying it | `UPDATE.*`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `update.apply` | `mgmt.admin` (**ADMINISTER**) | yes | key | Applies a staged artifact. The MI connection dies with the restart; the client reconnects and re-`Hello`s (§11.7) | `UPDATE.*`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `update.rollback` | `mgmt.admin` (**ADMINISTER**) | yes | key | Reverts to the prior artifact. MUST be refused below S-23's minimum supported version — a rollback is not a disarm and MUST NOT clear the latch | `UPDATE.*`, `MGMT.MONOTONE_REFUSED`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |
| `killswitch.disarm.begin` | `mgmt.settings` | no | nat | A `disarm_challenge{challenge_id, expires_in_ms, consequence_text_key}` — the ability to **ask**, not to do | `MGMT.DISARM_NO_LOCAL_AUTHORITY`, `MGMT.CHANNEL_UNSUPPORTED` |
| `killswitch.disarm.commit` | **ephemeral `mgmt.disarm`** | yes | nat | Applies the disarm; emits [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.DISARMED_BY_OWNER` (cited, not minted) | `MGMT.DISARM_REQUIRES_LOCAL_AUTH`, `MGMT.DISARM_NO_LOCAL_AUTHORITY`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED` |

**MI-K2a (update is not disarm).** The five `update.*` verbs land on MI because
[ADR-0021](ADR-0021-packaging-distribution-and-updates.md) §11.18(f) requires it — one interface, no
privileged side channel for the updater either. Two constraints travel with them:
[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) **KS-23** ("the update channel is not an
exception"): an update MUST replace the rule set by **atomic swap**, never remove-then-add, and MUST
NOT clear the latch — so `update.apply` and `update.rollback` are ADMINISTER-class but are **not**
disarm ceremonies and never satisfy KS-21. And **S-23 is monotonic**: `update.rollback` below the
minimum supported version MUST be refused (`MGMT.MONOTONE_REFUSED`), never negotiated.

**MI-K1 (disconnect is not disarm).** `net.down` and `session.disconnect` clear session intent
only. The M2 latch is cleared **exclusively** by the §11.14 ceremony
([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.13). This is the single most likely
place for a local-control design to open a leak, and the rule exists to close it by name.

**MI-P1 (the one `SECRET` that crosses MI).** [ADR-0007](ADR-0007-device-identity-and-pairing.md)
§7.4 requires the joining device to **display** `pairing_secret` as a QR code. Under H2 the renderer
is the unprivileged UI and the key holder is the agent, so the value crosses the MI boundary. This
is permitted, narrowly:

1. Only inside a `pair.begin` response, only over the MI channel, never in any other operation.
2. It MUST NOT be logged at any level, MUST NOT appear in `diag.log.tail`, MUST NOT enter a Tier-1
   bundle, and MUST be dropped by the client at the `not_after_ms` expiry (120 s).
3. It MUST NOT be persisted by either side.

The exposure is **not increased** by the transfer: the process that renders the QR to a camera
already controls the display, so an attacker who owns the UI owns the secret regardless.
[docs/threat-model.md](../threat-model.md) §9's "no rendering path exists, in any tier" governs the
**observability tiers** — logs, bundles, telemetry — and a QR code is not one of them. That
boundary is unstated in the corpus and is recorded as a finding in §11.18.

### 11.10 The event stream

**MI does not invent a second event vocabulary.** Topics carry structures the corpus already owns:

| Topic | Payload | Owner |
|---|---|---|
| `session.state` | `TransitionEvent{from, to, trigger, reason_code, session_id, path_id, occurred_at}` | [docs/reliability.md](../reliability.md) §4.5, verbatim |
| `session.mirror` | `SessionStateChanged` — **this is the "management mirror"** [docs/protocol.md](../protocol.md) §7 names and does not define | [docs/protocol.md](../protocol.md) §7 |
| `diagnostic` | `Diagnostic` | [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.3, verbatim |
| `protection` | `ProtectionAssertion` changes, including expiry to `UNKNOWN` | [ADR-0015](ADR-0015-observability-and-diagnostics.md) O-17/O-18 |
| `peers` / `policy` / `enforcement` / `capability` | Change notifications carrying the new version (`net_seq`, `policy_version`, `contract_seq`) | S-05 / S-06 / S-18 / S-19 |
| `pairing` | Ceremony progress | [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 |
| `lifecycle` | `HostLifecycleState` — the agent's live lifecycle phase, as a **typed event**, never something a client infers or polls for | **S-61**, [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) LC-3 (cited, not redeclared) |
| `mgmt` | `MGMT.DIAG.BUNDLE_CREATED`, capture-level changes, client evictions, `MGMT.UNBLOCK_INVOKED` | This ADR |

> **MI-18 (attribution).** Every event reporting a state change that a local caller **caused** MUST
> carry `actor_principal` — the OS principal of the MI client whose call produced it, or a reserved
> value for agent-internal and peer-initiated causes. This is
> [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-13, and it exists because a
> shared or managed host has more than one principal: "the tunnel went down" and "*Dana* took the
> tunnel down" are different facts, and only the second is answerable when something surprising
> happens. `actor_principal` is `OPERATIONAL`-class ([ADR-0015](ADR-0015-observability-and-diagnostics.md)
> §11.4) — it is a local account name, so it is bucketed or dropped in a Tier-1 bundle and never
> appears in Tier 2.

**Ordering — stated so it cannot contradict [docs/protocol.md](../protocol.md) §5.**

1. **Per-connection FIFO.** Events are delivered in the agent's emission order. `seq` is strictly
   increasing with no gaps, *except* where a `Compacted` marker announces one.
2. **Monotone in `net_seq` for mirrored events.** An MI event mirroring a durable control-plane
   fact carries that fact's `net_seq`, and the agent MUST NOT deliver it before its own C2 cursor
   has reached it. Composed with MI-6, this is exactly the read-your-writes property
   [docs/protocol.md](../protocol.md) §5.1 requires, expressed across the process boundary.
3. **Nothing more is promised.** MI offers **no** ordering between two different `Session`s' events,
   none between an event and an unrelated response, and none across MI connections. This is
   consistent with §5.1's table, which grants total order only to durable events within one
   `TwinNet` and explicitly none to C4/C5/C6.

**Backpressure — the ladder, and why it is inverted relative to a streaming RPC framework.**

| Stage | Trigger | Action |
|---|---|---|
| Normal | queue below watermark | Deliver |
| **Compaction** | queue reaches **64 KiB or 256 events** (**16 KiB / 64** on the router profile), or a write would block past **250 ms** | Drop event **bodies**, then emit an ordered `Compacted{up_to_seq, dropped_by_topic{}}`. The client MUST respond with `event.resync` |
| **Eviction** | the queue is still full after **5 s** | Disconnect the client with `MGMT.CLIENT_TOO_SLOW`, recorded in the Tier-0 ledger |

> **MI-19 (a drop is a recorded gap, never a silence).** No state-changing event may be discarded
> without a record. Compaction emits an **ordered** `Compacted` marker carrying per-topic counts
> before any further event; eviction writes the evicted client, its principal, and its queue depth
> to the Tier-0 ledger. Silently dropping a state-change event on a multi-user host would be
> [docs/reliability.md](../reliability.md) §10's silent failure wearing local clothes, and
> [ADR-0015](ADR-0015-observability-and-diagnostics.md) O-05 forbids it as surely between two local
> processes as between two devices. **The Tier-0 ledger is never the lossy copy**: compaction
> affects one client's delivery queue, never the ledger, so what a client missed remains recoverable
> through `diag.log.tail`.

The compaction-then-declarative-re-read pattern is deliberately the **same idiom** as
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) N-8's `StreamCompacted` on C2. The
product has one recovery pattern for a lagging consumer, not two.

**Coalescing distinguishes two kinds of topic**, because collapsing the wrong one produces a UI
that lies:

- **State-valued topics** (`session.state` current value, `protection`, `policy`, `enforcement`,
  `capability`) are last-writer-wins registers. Only the latest value per key need be retained;
  collapsing loses nothing, because the latest value *is* the truth.
- **Occurrence-valued topics** (`diagnostic`, the transition history, `pairing` progress) cannot be
  collapsed without losing information. They are **counted**, and the count is reported per topic
  in `Compacted.dropped_by_topic`. A UI can then say "12 transitions not shown" instead of
  silently presenting a gap — which is [docs/reliability.md](../reliability.md) §10's no-silent-failure
  rule applied to the management surface.

**Resume after a client restart — race-free, and deliberately not a replay log.**

MI offers **no durable local replay log**. Such a log would be a second copy of the Tier-0 ledger
with a second retention policy and a second redaction boundary, and the Tier-0 ledger already
exists, is always on, and never leaves the device
([ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.1). Instead:

> **MI-9a (`RESYNC_REQUIRED` — resume is not always possible, and must say so).** When a client
> reattaches offering a cursor the agent cannot service — because the agent restarted, was `HELD`
> past its retention, or crossed a lifecycle discontinuity
> ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) I-02(b), LC-21) — the agent
> MUST answer with an explicit `MGMT.RESYNC_REQUIRED` and the client MUST call `event.resync` before
> treating any state as current. It MUST NOT silently restart the stream at a fresh cursor, because a
> client that is not told cannot distinguish "you have missed nothing" from "your cursor is
> meaningless". This is a **distinct** condition from `MGMT.STREAM_COMPACTED`: compaction is
> mid-stream and backpressure-driven and the connection survives it; `RESYNC_REQUIRED` is
> attach-time and continuity-driven. Conflating them would let a client apply the compaction recovery
> path — which assumes its prior state is a valid base — to a cursor that has no base at all.
>
> **MI-9.** `event.resync` returns `SnapshotBegin`, the current value of every subscribed
> state-valued topic, then `SnapshotEnd{cursor}`, then live events from `cursor`. **The snapshot is
> taken under the agent's state lock and `cursor` is assigned inside that lock.** There is therefore
> no window in which an event is both absent from the snapshot and skipped by the stream. A UI that
> restarts reconstructs current truth in one operation, without a race.

*History* — what happened while the client was dead — is a **different question with a different
scope**: `diag.log.tail{since}` under `mgmt.diagnostics`. Current truth is status; history is
diagnostics. Keeping them separate is what allows a status-only principal to exist.

### 11.11 I5 compliance: the data plane outlives the management interface

The claim: **no established-`Session` code path can depend on the MI.** Proved the way
[ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 proves the control-plane case —
four steps, one of them mechanical.

*Step 1 — architectural.* [docs/architecture.md](../architecture.md) §4.2 makes the management
plane observe-only with **no reverse edge**, and mediates all influence on the data plane through
the local durable store (2.20). MI is a management-plane surface. Every MI mutation writes to the
local store or injects an event the state machine **already accepts from other sources**
([docs/reliability.md](../reliability.md) §4.3 lists "user, policy, autostart, peer-initiated" as
sources of `EV_CONNECT_REQUESTED`). MI adds no new edge.

*Step 2 — enumerative.* Walking §11.9: every operation is either (a) a read of state the agent
already holds, (b) an injection of an already-defined event, (c) a write to a `LOCAL`-class state
row the agent already owns, or (d) an initiation of a control-plane ceremony that is a precondition
of `DISCONNECTED`, never of a live `Session`. **No operation is a precondition of any
established-`Session` activity** — keepalive, rekey, path probing, path migration, relay failover,
in-tunnel LAN/exit negotiation, `TwinNet` DNS, and policy evaluation appear nowhere in the
catalogue as dependencies.

*Step 3 — mechanical, and this is what makes it testable.*

> **MI-I5-1.** The MI server module MUST NOT be linked into the datapath module, and no data-plane
> or state-machine module may hold a reference to the MI server. This is a **dependency-graph
> assertion checkable in CI** — the same mechanism
> [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) §11.8 step 3 uses for the
> control-plane client, reused rather than reinvented.
>
> **MI-I5-2.** Event emission is a **non-blocking offer** into a bounded per-connection queue.
> **The emission API has no blocking variant** — there is no waiting `send` to call. A full queue
> is a drop, then a compaction, then an eviction (§11.10). The datapath thread never touches an MI
> file descriptor; a dedicated MI task owns every one.

*Step 4 — negative.*

> **MI-I5-3.** The agent MUST start, establish `Session`s, reach steady state, migrate paths, fail
> over relays, and hold enforcement with **zero MI clients ever attached**, and MUST NOT gate any
> state transition on a client acknowledgement. **A client disconnect — graceful, abrupt, or by
> eviction — MUST have exactly zero effect on tunnel state, enforcement, or any timer**
> ([ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) I-02(e), LC-20 —
> confirmed). Disconnection frees a queue and an S-43 row; it is not an event the state machine can
> observe. Together with **MI-3** (no agent→client RPC
> exists), "wait for the UI" is not expressible in the agent's code: there is no request to wait on
> and no blocking send to block in.
>
> **MI-I5-4.** Failure to create the management endpoint at startup MUST NOT stop the agent, MUST
> NOT disarm enforcement, and MUST NOT prevent a `Session` from establishing. It emits
> `MGMT.LISTEN_FAILED` and the agent runs unmanaged. An agent that refuses to protect traffic
> because nobody can manage it would be an availability defect wearing a safety costume.
>
> **MI-I5-5 (the degraded-agent stub).** The converse also holds, and two siblings require it:
> [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.14(d) and
> [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) I-02(d) / LC-28(4). In
> **every** agent lifecycle phase in which a process exists at all — crash-loop quarantine, `HELD`,
> safe mode, or a supervisor-imposed backoff — **the management channel MUST still answer.** It accepts an attach, serves
> `version.get`, `status.get`, `mi.catalogue.get`, the `lifecycle` topic and the diagnostics reads,
> and answers every other operation with the phase's own code —
> `PLATFORM.SERVICE.QUARANTINED` or `PLATFORM.LIFECYCLE.*`, both adopted from their registrars, never
> a `MGMT.*` twin. **This is the "blocked, not bricked" rule applied to management**
> ([ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-20): enforcement stays armed in every
> one of these phases, so a device whose agent is held and whose management interface is also
> unreachable is indistinguishable from a bricked one, and the user has no path back. This is the difference between a UI that can explain "TwinVPN stopped restarting
> itself after repeated crashes; your traffic is still blocked" and a UI that shows nothing at all,
> which is the outcome [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.6 exists to
> prevent. It is also why the MI server must not depend on datapath or key state to serve a
> connection: MI-I5-1's dependency direction is what makes the stub buildable.

Proof test **P17 clause B** measures all four, including the wedged-client case, and its mutants
`M-P17-3` and `M-P17-4` are exactly the two ways this is got wrong in practice.

### 11.12 The CLI binding

> **MI-C1 (the CLI is generated, not written).** The CLI's command table MUST be generated from the
> operation catalogue at build time. The CLI MUST NOT contain a control verb that is not a
> catalogue operation, and MUST NOT implement behaviour beyond argument marshalling, output
> rendering, and exit-code mapping. A verb with no catalogue entry, or an entry with no verb, is a
> **build failure**. This is the mechanism that makes R-21 true: the CLI cannot drift ahead of or
> behind the contract because it has no logic of its own.

**Command shape.** `twinvpn <noun> <verb> [flags]`, mapping 1:1 onto the catalogue's `noun.verb`
names — `twinvpn status get`, `twinvpn session list`, `twinvpn pair begin`, `twinvpn killswitch
disarm`. Short aliases (`twinvpn status`, `twinvpn up`, `twinvpn down`) are presentation sugar over
the same catalogue entries and are generated with them.

**Output modes.**

| Mode | Default when | Content |
|---|---|---|
| `--output human` | stdout is a TTY | Localized table, colour, the `Diagnostic.summary` and `next_action` in prose |
| `--output json` | stdout is **not** a TTY | **The stable machine surface.** B5 JSON, 64-bit integers as strings ([ADR-0003](ADR-0003-network-contract-schema-format.md) §11 rule 2), carrying `mi_version` so a script can assert |
| `--output json-lines` | explicit | One JSON object per line, for `event.subscribe` and `diag.log.tail` |

> **MI-C2.** The `--output json` shape is versioned with `mi_version` and is subject to the same
> append-only discipline as the wire contract. **Scripts are clients.** Changing the shape of
> `twinvpn status get --output json` is a compatibility break, not a cosmetic change.

**Exit codes** — chosen so automation can act without parsing text:

| Code | Meaning |
|---|---|
| **0** | The operation succeeded |
| **1** | The operation failed for a reason the agent named; a `reason_code` is on stderr and in the JSON |
| **2** | Usage error — bad arguments or unknown subcommand. **Nothing was sent to the agent** |
| **3** | The management channel is unavailable (`MGMT.UNAVAILABLE`) — distinct from 1, because "the service isn't running" and "the operation was refused" demand different automation responses |
| **4** | Authorization refused (`PLATFORM.PRIV.CLIENT_UNAUTHORIZED`, `PLATFORM.PRIV.ADMIN_AUTH_FAILED`, `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`, `MGMT.DISARM_*`) — distinct so a script can tell "re-run with privilege" from "this will never work" |
| **5** | Version incompatible (`MGMT.VERSION_TOO_OLD` / `MGMT.VERSION_TOO_NEW`) — distinct so an installer or a package post-install script can act |
| 6–63 | Reserved for future MI conditions |
| 64+ | **MUST NOT be used**, to avoid collision with `sysexits.h` and with shell conventions (124/125/126/127, 128+n) |

**Reason codes at the shell.** Every non-zero exit prints to **stderr**, in every output mode:

```
PLATFORM.PRIV.CLIENT_UNAUTHORIZED: This account is not permitted to change TwinVPN settings.
next: Add your account to the 'twinvpn-operators' group, or run this with an administrator account.
```

The code appears on stderr **even in `--output json`**, so a `set -e` script that does not parse
JSON still gets it. Per [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rule 4, the
**code is the contract and the text is not**: tests and automation MUST key on the code and MUST
NOT match rendered text, and the CLI's human strings may be reworded or re-translated freely.

**Unknown-code degradation, concretely** ([ADR-0015](ADR-0015-observability-and-diagnostics.md)
§11.2 rule 5). A CLI older than the agent will receive codes it does not know. It MUST render the
**domain-level** explanation from its own registry, with the raw code as detail — never the raw
code alone as the primary line, and never silence:

```
MGMT: TwinVPN's local management interface reported a condition this version of the
      command-line client does not recognise (MGMT.SOMETHING_NEW).
next: Update the TwinVPN command-line client.
```

> **MI-C3 (`platform_ctx` is supplied, never constructed).**
> [ADR-0018](ADR-0018-shared-core-and-build-architecture.md)'s renderer takes a fourth parameter,
> `platform_ctx` = `{platform, os_version}`, because
> [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) LT-3 selects the next-action
> variant by `(platform, os_version_range)` — macOS `SMAppService` on 13+ versus the legacy
> login-item API on 11–12, Android 13+ `POST_NOTIFICATIONS`. **Every MI client MUST use the
> `platform_ctx` the agent supplied in `HelloAck`, verbatim, and MUST NOT construct one from its own
> build constants or its own runtime probe.**

The hazard this closes is specific and would not have been caught by P17 clause A. The CLI and the
GUI are different binaries with different build times and different link-time constants; if each
derived its own `platform_ctx`, the two could disagree **on one host** — a CLI built against an
older SDK reporting a different `os_version` than the GUI beside it — and would then render
different next actions for the same condition. Clause A compares *operation sets* and would pass
while the user-visible advice diverged. Supplying the value from the agent makes byte-identical
GUI/CLI output a property of a **shared call with shared inputs**, rather than of two
implementations happening to agree. The agent is also the correct authority: it is the process
running the platform adapter's capability probe ([docs/architecture.md](../architecture.md) §2.5),
so it holds the true platform facts.

One consequence worth stating, because it is the case that makes the parameter necessary rather
than merely tidy: a **diagnostics bundle carries the `platform_ctx` of the host it was collected
on**. A support workstation rendering a bundle from another platform MUST render with the
*collected* context, not its own — which is exactly why `platform_ctx` is a parameter rather than
being implied by the build, and it is what lets P18 drive every variant from one Linux runner.

**Delegation to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md), stated
explicitly.** ADR-0023 owns the headless and router deployment profile, the configuration-file
format, the router status page, and the `ubus` bridge. It **registers `MGMT.CONFIG.*` under this
ADR's domain**: this ADR reserves and owns the `MGMT` domain and the `MGMT.CONFIG.*` subdomain, and
delegates the naming of its members — parse failures, unknown keys, conflicting keys, a config that
would lower enforcement — to ADR-0023, which contributes them for registration exactly as
[docs/reliability.md](../reliability.md) §3.5 contributes members to subdomains it does not own.
Two obligations travel with the delegation:

1. **No configuration key may disarm the kill switch.** ADR-0023 MUST NOT define one. Disarm is
   §11.14's ceremony only, because a config key that disarms is settable by any process that can
   write the file — including a cron job — which is precisely the C-2 violation.
2. **Configuration is a source of desired state, not a second contract.** The headless agent MUST
   reach its configured state through the same catalogue operations, so a config-set value and a
   CLI-set value cannot diverge in behaviour.

### 11.13 Pairing and enrolment over MI, and the headless problem

Pairing is a **ceremony with a 120-second expiry and a live human confirmation step**
([ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4) — which is why alternative E fails (§6).
Over MI it is three operations (`pair.begin` / `pair.confirm` / `pair.cancel`) plus the `pairing`
event topic, with MI-P1 governing the secret and MI-8 governing the key.

**The headless case is real and is answered rather than deferred.** A router has no camera and no
screen, so the QR path (C-B) is unavailable in the direction that requires *scanning*. The MI
contract does not change; the ceremony method does:

| Situation | Path | MI expression |
|---|---|---|
| Router **displays** an offer to a phone that scans it | C-B, router as offerer | `pair.begin` returns the QR payload; the CLI renders it as **terminal-drawn QR** (a block-character matrix) over SSH or serial |
| Router **joins** a `TwinNet` and cannot scan | C-A (SPAKE2, 9-digit code) | `pair.begin` returns the 9-digit code for the operator to type on the approving device; the 5-attempt / 120-second limits of [ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4 are enforced by the agent, never by the CLI |
| Fully unattended provisioning | **Out of Phase 1 scope, and not foreclosed** | An unattended enrolment path would need a pre-shared enrolment credential, which is an authorization mechanism [ADR-0007](ADR-0007-device-identity-and-pairing.md) owns, not an MI operation. Recorded in §14 revisit condition 6 |

**The residual for router-class targets, stated as vision §4.1 requires.** Where the platform has
no secure element ([C-12]), identity custody degrades to file-based key storage protected only by
filesystem permissions — an **I4** limitation owned by
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.3 and
[ADR-0020](ADR-0020-local-persistence-and-secure-storage.md), not by this ADR. MI's obligation is
narrower and is discharged: **no MI operation exports key material**, at any scope, on any
platform, so MI does not widen that residual by one bit.

### 11.14 The `ADMINISTER` ceremony, and kill-switch disarm as its strictest instance

[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) Q6 requires **per-action
OS-mediated authentication, never cached beyond the action**, for every `ADMINISTER`-class
operation. [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-21 requires **all three** of a
local interactive action, OS-mediated authentication of an `Owner`/administrator principal, and a
confirmation naming the consequence. One two-phase mechanism discharges both; disarm is its
strictest instance because it is the only one that also carries KS-21(3). The **offline**
disarm path — [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §10's unblock command, which by
construction runs when the agent is not there to serve MI — is specified separately in **§11.21.2**.

**The ceremony, generally.** Every `ADMINISTER` operation carries an `admin_credential` field
holding the **result of a platform authentication the agent itself evaluates**, obtained by the
client immediately before the call. The credential is **single-use, bound to one operation and one
principal, and valid for at most 120 s**; the agent MUST reject a credential already consumed by a
preceding action. That is what makes Q6's "never cached beyond it" structural rather than a promise,
and it is asserted by P17 clause C's mutant `M-P17-9`.

Two operations need an agent-issued **challenge** in front of the credential, and therefore a
`.begin` phase: `killswitch.disarm.begin`, because KS-21(3) requires the agent to bind a specific
consequence to the act, and `pair.begin`, because the ceremony is long-running and time-boxed by
[ADR-0007](ADR-0007-device-identity-and-pairing.md) §7.4's own 120 s expiry. `device.revoke` and
`key.rotate` carry the credential on the single call. Disarm is spelled out below because it is the
strictest instance; the other three follow the same shape with KS-21(3) omitted.

1. A client with `mgmt.settings` calls `killswitch.disarm.begin` — the ability to **ask**, not to do.
   The agent returns `disarm_challenge{challenge_id, expires_in_ms = 120000, consequence_text_key}`.
   One outstanding challenge per principal; a failed commit burns it.
2. The client triggers the **platform authentication ceremony**. The **agent** evaluates it against
   the OS. The client's assertion about the result is never believed. If the OS authentication
   itself fails, the emitted code is
   [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s
   `PLATFORM.PRIV.ADMIN_AUTH_FAILED` — **adopted, not duplicated**
   ([docs/reliability.md](../reliability.md) §3.3). `MGMT.DISARM_REQUIRES_LOCAL_AUTH` is the
   narrower, MI-protocol condition: a commit arrived with no challenge, an expired challenge, or a
   challenge belonging to another principal.

| Platform | Mechanism the agent evaluates | Who renders the consequence text |
|---|---|---|
| Linux (desktop, **attended**) | polkit `CheckAuthorization` for action **`net.twinvpn.administer`** with **`auth_admin`** — not `auth_admin_keep`, so nothing is cached across actions ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-12a) — subject = the **caller's** `unix-session` (preferred) or `unix-process` with start-time, `AllowUserInteraction` set | polkit's agent, from the policy file's message. Not the client |
| Windows | The caller's token must carry the Administrators SID **enabled** — which requires the client to have been launched elevated, so a UAC consent the user actually saw has already occurred; alternatively the operation routes to a separately elevated helper | The UAC consent dialog |
| macOS | `AuthorizationCopyRights` for `system.privilege.admin` (or a custom right), evaluated in the agent against an `AuthorizationExternalForm` passed by the client. **The authorization ref is the credential**, not the client's word | Authorization Services' dialog |
| Android | **Not an MI operation.** `MGMT.CHANNEL_UNSUPPORTED` with a next action deep-linking the Settings VPN page (§11.2.2) | Android Settings |
| iOS / iPadOS | **Not an MI operation.** VPN-profile removal in Settings | iOS Settings |
| Headless Linux / OpenWrt (host class HC-3) | No interactive polkit agent exists and there is no console seat. Per [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-14 the operation is **permitted** under OS admin authentication in that session, and is **recorded and disclosed**: principal, session type, and source, with `PLATFORM.PRIV.REMOTE_ADMIN_USED` at `WARN`. If no administrator principal can be authenticated at all — a cron job, an automation account, a non-interactive service — **refuse** with `MGMT.DISARM_NO_LOCAL_AUTHORITY` | The CLI, which MUST print the consequence and require an explicit typed confirmation |

**The seat rule (PS-14), normative here because MI is where it is enforced.**
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.7 PS-14 resolves a genuine
tension the corpus contained: KS-21(1) demands "a local interactive action on the device itself. No
network path, no remote management channel", while R-21 makes headless Linux and OpenWrt
first-class — and those hosts have **no local interactive session, ever**. The two are jointly
unsatisfiable on exactly the targets R-21 exists to protect. PS-14 resolves it **by host class**,
and the MI ceremony expresses both branches:

| Host class | `ADMINISTER` from SSH / RDP / VNC | Codes |
|---|---|---|
| **Attended (HC-1 / HC-2)** — a console seat exists | **Refused.** "Local" means the physical console seat. The agent MUST determine the caller's session type (`sd_pid_get_session` + seat on logind hosts, WTS session and `WTSConnectState` on Windows, console-session check on macOS) and refuse a remote one | `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`; for disarm specifically **also** [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` |
| **Headless (HC-3)** — no seat exists, by construction | **Permitted** under OS admin authentication in that session, recorded with principal, session type and source | `PLATFORM.PRIV.REMOTE_ADMIN_USED` at `WARN` |
| Any class, no authenticable administrator principal (cron, automation, service account) | **Refused** | `MGMT.DISARM_NO_LOCAL_AUTHORITY` |

> **MI-17.** The two-phase ceremony MUST be able to express the refusal branch, and MUST NOT assume
> a console exists. A `killswitch.disarm.begin` on an attended host from a remote session MUST fail
> at **`begin`**, not at `commit` — failing late would render a consequence prompt for an act that
> was never going to be permitted, which trains users to click through prompts.

3. The client calls `killswitch.disarm.commit{challenge_id, platform_credential}`. The agent
   re-verifies against the OS, applies the change, emits
   [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s
   `POLICY.KILLSWITCH.DISARMED_BY_OWNER` — **that ADR's code, not a second one for the same
   condition** ([docs/reliability.md](../reliability.md) §3.3) — and enters a persistent
   `PERMISSIVE_ANNOUNCED` indication.

**Where the consequence text is rendered matters.** A malicious client would happily render a
lying prompt. Where the OS supplies the dialog (polkit, UAC, Authorization Services) the OS renders
it and the client cannot substitute it. On headless targets no OS dialog exists, so the agent
additionally requires an explicit typed confirmation and emits the disarm event to every surface —
which is visibility, not prevention, and is named as such.

**The honest note the corpus does not make.** KS-21(1) says "no network path, no remote management
channel." Is a headless gateway administered over SSH a remote management channel? **The MI is local
to the host; SSH makes any local socket reachable from anywhere.** The corpus does not address
this, so this ADR states the position explicitly:

> **MI-K2, as refined by PS-14.** KS-21's prohibition binds **TwinVPN's own channels**: no
> control-plane message means disarm, no relay or rendezvous path reaches the enforcement decision,
> and MI has no network binding of its own. What it does **not** do is claim that a host
> administrator with a root shell cannot disarm — such an administrator can remove the enforcement
> rules directly. An earlier draft of this ADR concluded from that "a remote host administrator
> always could, with or without MI", and stopped there.
> [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-14 is a better answer and this
> ADR adopts it: **on an attended host the MI refuses the remote administrator anyway**, because
> there the seat requirement is satisfiable and refusing costs nothing; **on a headless host it
> permits and discloses**, because there refusing would break the deployment R-21 exists to protect
> and would buy nothing against an adversary who can already edit the rule set directly. The
> residual is therefore narrower than the earlier statement: *a remote TwinVPN actor can never
> disarm; a remote host administrator is refused where a console seat exists, and on a headless host
> can disarm but cannot do so silently.*

### 11.15 Disclosure posture at the MI boundary

| # | Rule |
|---|---|
| **MI-D1** | `SENSITIVE`-class fields (endpoints, interface names, peer identifiers, hostnames, SSIDs) **are** rendered over MI to an authorized local principal. [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.4's redaction is defined for Tier-1 artifacts *leaving the device*, and §11.10 explicitly permits an `Owner`-initiated capture on their own device to render them. Redacting the `Owner`'s own endpoints in their own UI would make the connectivity report useless without improving anything |
| **MI-D2** | `SECRET`-class values MUST NOT cross MI, with exactly one narrow named exception (MI-P1) |
| **MI-D3** | `diag.bundle.create` produces the **redacted** artifact and returns an **identifier**, never the bytes. The bundle is written mode `0600` in an agent-owned directory, so the user can inspect the same file the client received — preserving [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9's render-then-transfer flow |
| **MI-D4** | **No MI operation accepts a filesystem path, URL, command, file descriptor, or other capability handle from the client.** Output locations are agent-chosen. This removes the confused-deputy class rather than validating against it |
| **MI-D5** | **No MI operation causes the agent to make an outbound request to a client-supplied destination.** `path.probe` takes a `session_id`, never an endpoint — otherwise a privileged process becomes a local port-scanning and SSRF primitive |
| **MI-D6** | Bundle creation is rate-limited, requires an **interactive** local principal, and always emits `MGMT.DIAG.BUNDLE_CREATED` as a persistent event on every surface. [docs/threat-model.md](../threat-model.md) §9's "a remote generate-and-send command MUST NOT exist" holds trivially — MI has no network binding — but an SSH session is *local to the agent and remote to the human*, and the agent cannot tell the difference. The mitigation is **visibility, not prevention**, and that is the residual |
| **MI-D7** | Every mutating MI call writes a Tier-0 ledger entry carrying the principal, the operation, and the outcome code. This is a local audit trail; Tier 0 never leaves the device |

### 11.16 The `MGMT` reason-code domain

**A new domain, and why it is not one of the thirteen.**
[ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 declares thirteen domains and
[docs/reliability.md](../reliability.md) §3.1 restates that "no other domain exists. A condition
that appears to need a new domain is a signal to re-read ADR-0015 §11.2, not to invent one." That
test was applied, and it fails for the three candidates:

- **`CONTROL`** is owned by [ADR-0002](ADR-0002-control-plane-messaging-and-event-bus.md) /
  [ADR-0009](ADR-0009-state-consistency.md) and means the **remote** control plane. Because rule 5
  makes an unknown code degrade to its **`DOMAIN`**, spelling a local-agent failure as `CONTROL.*`
  would make an older client render "the coordination service is unreachable — check your internet
  connection" when the real condition is "the local service is not running". Those are opposite
  diagnoses with opposite next actions, and prefix degradation would actively produce the wrong one.
- **`PLATFORM`** is the OS-integration surface owned by
  [docs/architecture.md](../architecture.md) §2.5. The MI is TwinVPN's own contract, not an OS
  facility; a `PLATFORM` code implies "your operating system did this to us".
- **`INTERNAL`** means a defect, and a stale CLI is not a defect.

> **MI-10 (registration obligation — and a LIVE CONTRADICTION the integrator must resolve).**
> [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 does not merely omit a `MGMT` row; it
> **declares the set closed**: "the thirteen above are closed, and adding one per concept is how a
> registry rots." [docs/reliability.md](../reliability.md) §3.1 restates it as "No other domain
> exists," and the repository validator enforces an allowlist. So this is **not a missing table
> row — it is a shipped ADR and this ADR contradicting each other on the record**, and it must be
> resolved by an explicit amendment to ADR-0015 rather than by a quiet merge.
>
> The resolution this ADR asks for: **reopen the set once, to fourteen**, adding **`MGMT` — the
> local management interface: attachment, authorization, version negotiation, and local-client
> lifecycle (owner: this ADR)** — and widen
> [docs/reliability.md](../reliability.md) §3.1's list to match. The argument is §11.16's, and it is
> a *harm* argument rather than a *tidiness* one: because rule 5 degrades an unknown code to its
> `DOMAIN`, spelling a local-service failure as `CONTROL.*` makes an older client tell the user to
> check their internet connection when their local service is not running. ADR-0015's own stated
> reason for closing the set — "adding one per concept is how a registry rots" — is satisfied: this
> is one domain for one boundary, with one reserved subdomain, and §14 condition 8 is the trigger
> that would reopen the question rather than let it recur.
>
> **This ADR does not modify either file**; the integrator merges, and should record the
> amendment against ADR-0015 explicitly. If ADR-0015's owner declines, every code in §11.16 must be
> respelled and this ADR's §11.16 argument states the concrete harm that follows. The
> `MGMT.CONFIG.*` subdomain is reserved here and delegated to
> [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) (§11.12).

All codes are two or three segments (rule 7) and are carried as strings, never enums.

**Codes adopted from [ADR-0016](ADR-0016-client-process-and-privilege-separation.md), not
duplicated** ([docs/reliability.md](../reliability.md) §3.3 forbids a second identifier for a
condition another ADR has registered). An earlier draft of this ADR minted `MGMT.SCOPE_DENIED`; it
is **withdrawn before registration** and never becomes `ACTIVE`, so this is a pre-registration
correction rather than a rename ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-03).

| Condition at the MI layer | Code emitted | Registrar |
|---|---|---|
| The calling principal lacks the operation's scope/class | `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| An `ADMINISTER` OS authentication was required and not supplied | `PLATFORM.PRIV.ADMIN_AUTH_REQUIRED` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| An `ADMINISTER` OS authentication was attempted and failed | `PLATFORM.PRIV.ADMIN_AUTH_FAILED` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| `ADMINISTER` attempted over SSH/RDP/VNC on an attended host (PS-14) | `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED`; for disarm specifically, also `POLICY.KILLSWITCH.DISARM_REFUSED_REMOTE` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md), [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| `ADMINISTER` permitted remotely on a headless host (PS-14) | `PLATFORM.PRIV.REMOTE_ADMIN_USED` at `WARN` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| The authority is in crash-loop quarantine and is serving a stub | `PLATFORM.SERVICE.QUARANTINED` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| The service is not installed / not running / slow to start | `PLATFORM.SERVICE.{NOT_INSTALLED, UNAVAILABLE, START_TIMEOUT}` | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |

`MGMT.UNAVAILABLE` survives alongside `PLATFORM.SERVICE.UNAVAILABLE` because they are different
facts: the `PLATFORM.SERVICE.*` codes describe **the service's** state as the OS reports it, and are
emitted by the agent or by a client that queried the service manager; `MGMT.UNAVAILABLE` is the
narrower client-side observation that **the management channel** could not be reached, which is the
one condition no agent can report about itself. A client that can reach the service manager SHOULD
prefer the more specific `PLATFORM.SERVICE.*` code.

| `reason_code` | class | sev | term. | user-act. | Condition → user-facing text → next action |
|---|---|---|---|---|---|
| `MGMT.UNAVAILABLE` | PERSISTENT | ERROR | no | **yes** | The management channel could not be reached. "TwinVPN's background service isn't running." → "Start the TwinVPN service." Emitted **client-side**; it is the only code a client mints |
| `MGMT.LISTEN_FAILED` | PERSISTENT | ERROR | no | **yes** | The agent could not create or verify its endpoint. "TwinVPN is protecting this device but cannot be managed." → "Reinstall TwinVPN, or check permissions on the service directory." Protection is unaffected (MI-I5-4) |
| `MGMT.PRINCIPAL_UNVERIFIABLE` | FATAL | CRITICAL | yes | no | Peer credentials could not be obtained. Attach refused, fail closed (MI-A5). Every occurrence is investigated |
| `MGMT.VERSION_TOO_OLD` | PERSISTENT | ERROR | no | **yes** | Client below `mi_version_min`. → "Update the TwinVPN client; the background service is newer." Carries `agent_version` |
| `MGMT.VERSION_TOO_NEW` | PERSISTENT | ERROR | no | **yes** | Client above `mi_version_max`. → "Update the TwinVPN background service; your client is newer." Names which side is behind |
| `MGMT.OP_UNKNOWN` | PERSISTENT | WARN | no | **yes** | Operation absent from this build's catalogue (version **or** build profile). → "This TwinVPN build does not support that action." |
| `MGMT.NOT_READY` | TRANSIENT | INFO | no | no | Starting or rehydrating; not yet authoritative. → "TwinVPN is starting." **Never answered with a fabricated `DISCONNECTED`** |
| `MGMT.SHUTTING_DOWN` | TRANSIENT | INFO | no | no | Draining; carries `drain_deadline_ms`. → "TwinVPN is restarting." |
| `MGMT.CLIENT_TOO_SLOW` | TRANSIENT | WARN | no | no | The client was evicted for backpressure (§11.10). → none; the client reconnects and resyncs |
| `MGMT.STREAM_COMPACTED` | TRANSIENT | INFO | no | no | Events were dropped mid-stream under backpressure; carries per-topic counts. The connection survives. → the client calls `event.resync` |
| `MGMT.RESYNC_REQUIRED` | TRANSIENT | INFO | no | no | An offered cursor cannot be serviced — agent restart, `HELD` past retention, or a lifecycle discontinuity (MI-9a). The client's prior state has **no valid base**. → the client MUST call `event.resync` before treating any state as current |
| `MGMT.RATE_LIMITED` | TRANSIENT | WARN | no | **yes** | Carries `retry_after_ms`. → "Too many requests; try again shortly." |
| `MGMT.PRECONDITION_FAILED` | PERSISTENT | WARN | no | **yes** | `if_version` mismatch ([ADR-0008](ADR-0008-idempotency.md) N-2). → "Someone else changed this setting; reload and try again." |
| `MGMT.DUPLICATE_REPLAYED` | TRANSIENT | INFO | no | no | Idempotency-key hit; the recorded outcome is returned (MI-7). Supplies the local half of ADR-0008 §11.2's `duplicate_replayed` requirement |
| `MGMT.MONOTONE_REFUSED` | POLICY | WARN | no | **yes** | A request would lower enforcement (MI-S3). → "Protection cannot be reduced this way; use the disarm action." **Refused, never silently clamped** |
| `MGMT.POLICY_FORBIDS` | POLICY | WARN | no | **yes** | The preference is outside the signed `AccessPolicy`/`DNSPolicy` (MI-S4). → "Your TwinNet's policy does not permit that setting." |
| `MGMT.DISARM_REQUIRES_LOCAL_AUTH` | POLICY | WARN | no | **yes** | A commit arrived with **no** challenge, an expired one, or one belonging to another principal. → "Confirm as an administrator on this device." When the OS authentication itself *fails*, [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s `PLATFORM.PRIV.ADMIN_AUTH_FAILED` is emitted instead — adopted, never duplicated |
| `MGMT.DISARM_NO_LOCAL_AUTHORITY` | POLICY | ERROR | yes | **yes** | No interactive local principal exists (headless, cron, automation). → "Disarm requires an interactive administrator session on this device." **Terminal for the attempt** |
| `MGMT.CHANNEL_UNSUPPORTED` | PERSISTENT | WARN | no | **yes** | The platform channel cannot carry this operation in the current state (iOS stopped session, Android disarm). → the platform-specific next action, e.g. "Open Settings › VPN." Names the residual rather than hiding it |
| `MGMT.CAPTURE_EXPIRY_REQUIRED` | PERSISTENT | WARN | no | **yes** | A capture-level raise without an expiry was refused. → "Choose how long to capture detailed logs." |
| `MGMT.PAYLOAD_TOO_LARGE` | PERSISTENT | ERROR | no | no | The 1 MiB envelope cap was exceeded |
| `MGMT.DIAG.BUNDLE_CREATED` | TRANSIENT | **INFO** | no | no | A diagnostics bundle was created on this device (MI-D6). Not a failure; it exists so the act is visible on every surface |
| `MGMT.UNBLOCK_INVOKED` | POLICY | **WARN** | no | **yes** | The offline unblock command was invoked while the agent was not running (§11.21.2). Surfaced at next start. → "Protection was removed from this device outside TwinVPN. Re-arm it." Not a failure — a **visibility** obligation |
| `MGMT.AUDIT_GAP` | PERSISTENT | ERROR | no | no | A privileged local act could not be recorded — the `UnblockRecord` was unwritable, or the Tier-0 ledger was unavailable. Enforcement posture is treated as `UNKNOWN` until re-asserted ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-17/O-18). Every occurrence is investigated |
| `MGMT.CONFIG.*` | — | — | — | — | **Subdomain reserved here, members delegated to [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)** (§11.12) |

Every code carries the ADR-0015 §11.2 attribute set (`summary_key`, `next_action_key`, `doc_anchor`
into this section, `evidence_fields`, `introduced_in`, `status`) in the machine-readable registry;
declared evidence fields include `retry_after_ms`, `agent_version`, `client_version`,
`required_scope`, `operation`, `dropped_by_topic`, and `drain_deadline_ms`, all `OPERATIONAL`-class.

### 11.17 Proof test P17 — control parity and management independence

Proposed for [docs/testing-strategy.md](../testing-strategy.md) §4, in that section's form. This
ADR is P17's **conformance surface** (§4.1, rule PT-4): §11.9's catalogue, §11.10's ladder,
§11.11's four steps and §11.16's codes are consumed verbatim.

| | |
|---|---|
| **Proves** | R-21, **R-28**, **R-29**, **R-30**; I5, I3, I6 |
| **Lab scenario** | `S-MGMT-*` on Linux, Windows, macOS (Developer ID), OpenWrt (headless profile), Android, iOS/iPadOS |
| **Preconditions (V3)** | ≥2 paired peers with ≥1 `WAN_DIRECT` and ≥1 `RELAYED` `Session` established and carrying marked traffic; enforcement `ARMED_ON_INTENT`; the baseline marked-traffic loss rate measured with a healthy client attached |
| **Assumptions** | H1, H2; A-02, A-08, A-16, A-17 |

**Clause A — catalogue parity (R-28).** Enumerate `catalogue_ops` via `mi.catalogue.get`; enumerate
`CLI_ops` from the generated command table; enumerate `GUI_ops` from the agent's MI access log
during a scripted walkthrough exercising **every** GUI affordance.
**Oracle: `GUI_ops ⊆ CLI_ops` and `CLI_ops = catalogue_ops`.** A GUI operation outside the catalogue
is a privileged side channel and fails. A catalogue entry with no CLI verb fails.

**Clause A2 — rendered parity (MI-C3).** Over a fixed corpus of `Diagnostic` records spanning every
`class` and both a known and an unknown `reason_code`, render each through the GUI and through
`twinvpn ... --output human` **on the same host**. **Oracle:** the next-action text is
byte-identical, and both calls carry the `platform_ctx` value the agent supplied in `HelloAck`.
Repeat with the agent reporting an `os_version` that crosses an
[ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) LT-3 variant boundary — macOS
12 → 13, Android 12 → 13 — and assert both surfaces switch variant **together**.

**Clause B — management independence (R-29, I5).** With traffic flowing: (i) `SIGSTOP` the GUI for
120 s; (ii) `SIGKILL` it; (iii) attach a synthetic client that subscribes to every topic and then
**never reads its socket**, hold 120 s; (iv) delete the socket file / named pipe; (v) restart the
MI listener alone.
**Oracle**, across all five: **zero** `Session` transitions to `DISCONNECTED`/`FAILED`/`RECONNECTING`;
marked-packet loss at or below the measured baseline; `EnforcementRecord.ruleset_digest` unchanged,
asserted by querying the OS firewall directly (PT-2 wire/OS corroboration), not by asking the agent.
The wedged client MUST be evicted with `MGMT.CLIENT_TOO_SLOW` within its 5 s deadline, and the
eviction MUST appear in the Tier-0 ledger. Case (iv) MUST leave established `Session`s untouched;
case (v) MUST emit `MGMT.LISTEN_FAILED` if the endpoint cannot be recreated, without disarming.
Additionally (vi): `SIGSTOP` the **agent** for 30 s with a client attached and the stream contiguous.
**Oracle:** every subsequent snapshot and event carries an `as_of_ms` whose age, measured on the
host's boot-time monotonic clock, grows monotonically past 30 s — so a consumer can distinguish "no
event was lost" (contiguous `seq`) from "no event was recent" (stale `as_of_ms`). Repeat across a
real host suspend/resume of ≥ 60 s: the measured age MUST include the suspended interval, which is
what falsifies a non-boot-time clock.

**Clause C — authorization (R-30, I3).** From a principal in **no** TwinVPN group: every mutating
operation returns `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` **and has no observable effect**. From a `mgmt.settings`
principal: `killswitch.mode.set` to a lower mode returns `MGMT.MONOTONE_REFUSED`;
`killswitch.disarm.commit` with an absent or forged credential returns
`MGMT.DISARM_REQUIRES_LOCAL_AUTH`; `net.down` leaves the latch armed (MI-K1). In the headless
profile with no interactive session, disarm returns `MGMT.DISARM_NO_LOCAL_AUTHORITY`. Every
`ADMINISTER`-class operation (`pair.begin`, `pair.confirm`, `device.revoke`, `key.rotate`, disarm)
MUST require a **fresh** per-action credential: replaying the credential from a preceding successful
action MUST be refused with `MGMT.DISARM_REQUIRES_LOCAL_AUTH` or
`PLATFORM.PRIV.ADMIN_AUTH_FAILED`, discharging
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) Q6's no-caching rule. Finally, with the agent
**stopped**: the §11.21.2 offline unblock command MUST refuse a non-interactive invocation, MUST
require the same OS authentication as §11.14, and MUST write an `UnblockRecord` **before** removing
the rule set; restarting the agent MUST then emit `MGMT.UNBLOCK_INVOKED` and hold a persistent
`PERMISSIVE_ANNOUNCED` indication.
**Oracle:** `ruleset_digest` is byte-identical before and after **every** refused attempt, read from
the OS.

**Clause D — version skew (R-28).** Run agent `mi_version` N against clients at N, N-1, N-2, N+1.
**Oracle:** N and N-1 fully functional over the catalogue intersection; N-2 either functional or
refused with `MGMT.VERSION_TOO_OLD` **carrying a next action** — never a silent close, never a hang,
never a parse crash; N+1 refused with `MGMT.VERSION_TOO_NEW` naming which side is behind. Then
upgrade the agent in place with a client attached: the client MUST reconnect, re-`Hello`, re-fetch
the catalogue, and MUST NOT issue an operation from its stale catalogue.

**Mutants (V2).** Each is a buildable patch against the release commit; P17 is `PASS` only if the
clean build passes and **every** mutant fails with its expected oracle.

| Mutant | Defect injected | Expected failure |
|---|---|---|
| `M-P17-1` | One GUI-only IPC message bypassing the catalogue | Clause A: `GUI_ops ⊄ CLI_ops` |
| `M-P17-2` | One CLI subcommand removed, catalogue entry retained | Clause A: `CLI_ops ≠ catalogue_ops` |
| `M-P17-3` | Event emission changed to a blocking write | Clause B (iii): datapath stalls; marked-packet loss exceeds baseline |
| `M-P17-4` | A state transition gated on a client acknowledgement | Clause B (i): transitions stall under `SIGSTOP` |
| `M-P17-5` | `mgmt.disarm` grantable at attach | Clause C: `ruleset_digest` changes without an OS credential |
| `M-P17-6` | Platform credential evaluated from a client-supplied field | Clause C: forged credential succeeds |
| `M-P17-9` | `ADMINISTER` credential cached across actions | Clause C: a replayed credential authorizes a second action |
| `M-P17-10` | Unblock command removes the rule set **before** writing the `UnblockRecord` | Clause C: kill the process between the two steps; the restarted agent emits no `MGMT.UNBLOCK_INVOKED` and the act is silent |
| `M-P17-11` | A `killswitch.exempt` **register** operation added to the catalogue | Clause A **and** the MI-11 assertion: a catalogue entry can place a caller's socket in the `BOOTSTRAP` class |
| `M-P17-12` | `as_of_ms` stamped by the client on receipt instead of by the agent (MI-16) | Clause B (vi): age stays near zero while the agent is `SIGSTOP`ped |
| `M-P17-13` | `as_of_ms` taken from `CLOCK_MONOTONIC` instead of `CLOCK_BOOTTIME` (MI-16) | Clause B (vi): the suspend/resume variant reports an age excluding the suspended interval |
| `M-P17-14` | `Diagnostic` reduced to `reason_code` alone, attributes left to client-side registry lookup (MI-14) | Clause D: an N-1 client receiving an N-only code cannot select a `POLICY`-class affordance |
| `M-P17-15` | A resolved `summary` string added to the `Diagnostic` envelope (MI-15) | Clause A **and** the MI-15 assertion: rendered text crosses MI |
| `M-P17-16` | The CLI derives `platform_ctx` from its own build constants instead of `HelloAck` (MI-C3) | Clause A2: at an LT-3 variant boundary the GUI and CLI render different next actions on one host |
| `M-P17-17` | The endpoint is socket-activated instead of agent-created (MI-A3) | Clause B: a client connection starts the agent, so the agent's lifetime is a function of client behaviour; and connecting while the agent is down succeeds then hangs instead of returning `MGMT.UNAVAILABLE` |
| `M-P17-18` | The management channel stops answering while the agent is `HELD` or quarantined (MI-I5-5) | Clause B: the held device cannot be queried, so "blocked" is indistinguishable from "bricked" |
| `M-P17-19` | An unserviceable cursor silently restarts the stream instead of emitting `MGMT.RESYNC_REQUIRED` (MI-9a) | Clause D: after an agent restart the client treats stale state as current with no signal |
| `M-P17-7` | Socket closed without a `Reject` on version mismatch | Clause D: no reject message observed client-side |
| `M-P17-8` | Catalogue cached across a reconnect | Clause D: a stale-catalogue operation is issued after upgrade |

**Positive control (V4).** The same rig with a matched agent/client pair and a healthy GUI shows all
four clauses green, and clause B's baseline shows zero marked-packet loss with the GUI **alive** —
proving the loss detector can observe success before any negative result is believed.

**Pass criteria.** All four clauses green on Linux, Windows, macOS. On OpenWrt (no GUI) clause A
degenerates to `CLI_ops = catalogue_ops` and B/C/D are asserted in full. On Android clause B is
asserted by killing the UI activity while the `VpnService` survives, and clause C's second-principal
half is n/a. On iOS/iPadOS clause B is asserted by killing the containing app while the provider
survives; clauses A and D are asserted against the subset channel; clause C is n/a — **no second
local principal exists**. All nineteen mutants fail.

**Known limits.** P17 cannot prove that a compromised process running as the authorized user is
unable to do what that user can do. That is outside the DAC model's reach and is stated as residual
in §7 and §11.4, not tested.

### 11.18 Interfaces required from other ADRs

| # | Required interface | Owner |
|---|---|---|
| (a0) | Confirmation of the `OBSERVE` / `OPERATE` / `ADMINISTER` class set (Q6), the principal → class grant per platform and host profile, and that the scope → class mapping in §11.5 is the intended grouping | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| (a) | The privileged principal per platform (Linux uid + `CAP_NET_ADMIN`; Windows service account; macOS system extension vs app extension; Android `:vpn` process), and confirmation that **no** further helper accepts a client-supplied capability handle (MI-D4) | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| (b) | Confirmation that the MI server module is **not linked** into the datapath module, as a build-time dependency assertion (MI-I5-1) | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md), [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) |
| (c) | A stable C-ABI surface over which the MI server can read agent state and inject state-machine events without a second copy of the state model, so the CLI, the GUI shell, and the router status page share one implementation | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) |
| (c2) | **Confirmation of [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) §11.16(b) / F-5, with one refinement.** "One contract, two carriages, never two contracts" is **confirmed**: every MI operation that observes or mutates core state maps 1:1 onto a core command or snapshot read, and MI is a transport over F-5's command/event set rather than a second contract. The refinement, now normative as **MI-20 / MI-21** (§11.1.1): MI additionally carries a **closed set of exactly four** MI-layer operations that have no core counterpart and MUST NOT acquire one — `Hello`/scope negotiation (§11.7), `mi.catalogue.get`, `event.resync`, and the MI half of `version.get`. Confining them to the MI layer is what keeps F-1's ABI small, since each would otherwise become a permanently exported function for a concern the in-process caller does not have. `killswitch.exempt.get` is **not** among them — an earlier draft listed it in error; it reads enforcement-layer state, which is a core module, so it is an ordinary core command. Separately, F-5's "**exactly one** totally ordered stream per instance" is core→host; MI **fans it out** to N concurrent clients, each with its own queue, its own `seq`, and its own compaction and eviction ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.2 requires N concurrent observers on iPadOS). An MI `seq` gap therefore means *this client fell behind*, never that the core stream had a gap | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) |
| (d) | The UI holds **no** control state that MI does not expose, and renders `reason_code`s per [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.2 rules 4–5. A UI-local cache of an operation MI cannot perform is a privileged side channel by another name | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) |
| (e) | S-24 (local preferences) and S-17 (route acceptance) MUST have the agent as their **single writer**. If they are stored where the user can also write them directly (registry, `defaults`, a plain config file the agent does not own), S-24 gains a second writer and **I8 is violated** — the config-file path MUST therefore be a *source of desired state the agent reconciles*, never a parallel authority | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md), [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| (f) | Creation of the endpoint's containing directory by the init system with a privileged owner (MI-A3); the Linux `twinvpn` group and Windows `TwinVPN Users` group; the polkit policy file for `net.twinvpn.administer` (`auth_admin`); the pipe DACL; and whether agent and CLI ship as one package — the last of which is what makes MI-5's two-epoch window defensible | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| (g) | When the agent is running at all, and the boundary between "not started" (`MGMT.UNAVAILABLE`) and "started but rehydrating" (`MGMT.NOT_READY`) | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) |
| (g2) | **I-02 accepted in full and discharged here:** (a) the transport is created **by** the running agent and socket activation is prohibited (§11.4 MI-A3); (b) `MGMT.RESYNC_REQUIRED` on an unserviceable cursor (§11.10 MI-9a); (c) `HostLifecycleState` as a typed event on the `lifecycle` topic plus a polled `lifecycle.get` (§11.9, §11.10); (d) the interface answers in `HELD`, safe mode, backoff and quarantine (§11.11 MI-I5-5); (e) client disconnect has zero tunnel-state effect (§11.11 MI-I5-3). Required back: **S-61's** definition and the `PLATFORM.LIFECYCLE.*` codes, which this ADR cites and never redeclares, and `ElapsedClock` per LC-8 as the `as_of_ms` source (§11.3.2) | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) |
| (h) | The `MGMT.CONFIG.*` members, the configuration-file format, the router status page and the `ubus` bridge — with the two obligations in §11.12: **no config key may disarm**, and config is desired state reconciled through the catalogue, never a second contract | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) |
| (i) | A `.proto` definition for `MgmtEnvelope` and the operation parameter/result messages, and the B5 amendment in §11.6 (B5 is "never a trust boundary **for authentication or authorization**") | [ADR-0003](ADR-0003-network-contract-schema-format.md) |
| (j) | Registration of the `MGMT` domain as ADR-0015 §11.2's fourteenth row and of §11.16's codes in the machine-readable registry (MI-10) | [ADR-0015](ADR-0015-observability-and-diagnostics.md) |
| (k) | Confirmation that `POLICY.KILLSWITCH.DISARMED_BY_OWNER` is emitted by the agent on the §11.14 commit, and that KS-21(2)'s OS-mediated authentication is evaluated **by the agent**, not asserted by a caller | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) |
| (k2) | Confirmation of **MI-11**: KS-9(2)'s socket registration is intra-authority (or a single-purpose privileged Mach service on macOS) and is **never** an MI operation, so KS-10's "no other interface can place bytes on a registered socket" holds against the management surface (§11.21.1) | [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md), [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) |
| (k3) | The §10 unblock command as an **agent-independent, package-owned** artifact meeting **MI-13**: same OS authentication as §11.14, no non-interactive flag, `UnblockRecord` written **before** the mutation, network-unreachable (§11.21.2). ADR-0016 §11.5 names the serving component per platform; ADR-0021 ships and signs it | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md), [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) |
| (k4) | A durable, agent-independent location for the `UnblockRecord` that the agent reads at start, with the same write-then-mutate ordering S-34 uses | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md) |
| (l) | The `Pairing` ceremony accepts an `idempotency_key` derived per MI-8, and the ceremony's attempt limits and 120 s expiry are enforced **agent-side**, never client-side | [ADR-0007](ADR-0007-device-identity-and-pairing.md), [ADR-0008](ADR-0008-idempotency.md) |

### 11.19 State ownership

Four new rows for [docs/architecture.md](../architecture.md) §5. None introduces a second writer for
an existing fact; all four are `LOCAL` and non-durable, which is itself the I5 argument.

| # | State | Authoritative writer | Replicas / caches (staleness tolerance) | Consistency class | Durability | On conflict |
|---|---|---|---|---|---|---|
| **S-42** | MI endpoint binding + operation catalogue (`catalogue_digest`, build profile, channel identity, and the served `mi_version` range) | **Local `Device`** — the agent, derived at start from the build profile and local configuration | Clients hold the catalogue **per connection only**; MUST NOT cache it across a reconnect (§11.7) | `LOCAL` | Non-durable; re-derived at every start | The running agent wins. A client's stale catalogue is invalidated by reconnect, never reconciled |
| **S-43** | MI client attachment set (`connection_id →` {principal, granted scopes, negotiated `mi_version`, client kind/version, subscriptions, event cursor, queue depth}) | **Local `Device`** — the agent | None | `LOCAL` | **Non-durable by requirement** — dies with the connection | Single writer. **Never a gate**: the absence of every client MUST NOT change datapath behaviour, enforcement, or any state transition (MI-I5-3) |
| **S-44** | Effective MI scope grant per principal | **Local `Device`** — the agent, derived at **attach** from the kernel-supplied principal plus local configuration | None | `LOCAL` | Non-durable; **re-derived at every attach, never cached across attaches** | Single writer. A group-membership change takes effect on the next attach, which is why grants are attach-immutable (MI-S2) rather than long-lived |
| **S-45** | MI ceremony dedup log (`(principal, mi_idempotency_key) →` outcome) | **Local `Device`** — the agent | None | `LOCAL` | **Non-durable by requirement** — MUST NOT survive an agent restart; bounded to 10 min / 256 entries (MI-7) | Single writer. Non-durability is the correctness property: after a restart a replayed local ceremony is re-evaluated against current state rather than replayed from a stale outcome |

### 11.20 Assumptions register

Format per [docs/architecture.md](../architecture.md) §9.

| # | Assumption | Depends on | If it is wrong, this changes |
|---|---|---|---|
| **A-1** | **H1**: one portable core holds the state machine, policy evaluation and contract handling, exposed over a stable C ABI, with thin native shells | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | The MI server would be reimplemented per platform, so MI-C1's build-time catalogue generation needs per-language codegen and P17 clause A must run per platform rather than once. The *contract* is unaffected — which is the point of making it transport-agnostic |
| **A-2** | **H2**: desktop/server class runs a privileged long-lived agent plus a separate unprivileged UI; on iOS/iPadOS/Android the OS-hosted extension is the agent | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | If a platform is single-process, MI ceases to be a *privilege* boundary there and §11.4/§11.5 collapse to an in-process API on that platform. The catalogue, the CLI binding and P17 clause A survive unchanged, because the CLI still needs a contract. §11.14's ceremony would still be required, because KS-21 is about the *user*, not the process |
| **A-1c** | **CONFIRMED by [ADR-0018](ADR-0018-shared-core-and-build-architecture.md).** F-4 carries `{reason_code, evidence, resolved}`, so MI-14's attribute set is resolved core-side at emission and MI carries it; and `tw_render_diagnostic` takes `platform_ctx`, which the agent supplies to every client (MI-C3) | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | If `resolved` were narrowed back to the bare code, MI would need a second registry outside the core — the R-31 defect class — and MI-14 would have to be discharged by MI-layer lookup instead. If `platform_ctx` were dropped, LT-3 variant selection would move into each shell and GUI/CLI parity would stop being structural |
| **A-1b** | **CONFIRMED, and answered normatively by MI-20 / MI-21 (§11.1.1).** [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) F-5's submit + single-ordered-event-stream model is the core-side shape MI transports; the MI catalogue is **derived from** the core command set rather than defined beside it; and MI's fan-out to N clients is permitted over that one stream | [ADR-0018](ADR-0018-shared-core-and-build-architecture.md) | If the core exposes a per-consumer stream instead, §11.10's compaction moves into the core and MI's queues become pass-through — the ladder's thresholds would then be the core's to set, not this ADR's |
| **A-2b** | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) Q6's three authorization classes (`OBSERVE`/`OPERATE`/`ADMINISTER`) are the principal-level grant model, and §11.5's six scopes group under them | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | If the class set changes, §11.5's mapping table is amended and §11.14's ceremony applies to whichever class carries the per-action rule. The catalogue, the CLI binding and P17 are unaffected |
| **A-3** | **CONFIRMED by [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.7 PS-12a.** The agent's service account and the OS groups that map to scopes exist and are created at install: Linux `twinvpn` / `twinvpn-operators` + polkit `net.twinvpn.administer`; Windows `TwinVPN Users` / `TwinVPN Operators` + elevated `BUILTIN\Administrators`; macOS `_twinvpn` / `_twinvpn_op` + `system.privilege.admin`; OpenWrt `root` only | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md), [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | If no group can be created (a restricted managed host), scopes collapse to a single "authorized local user" tier and §11.5's six-scope model degrades to two (status vs everything). §14 revisit condition 7 covers the same collapse from the other direction |
| **A-11** | **CONFIRMED by [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.2 / §12.6.** Phase 1 macOS is the Developer-ID system-extension shape only, so MI gets XPC with `audit_token_t` attestation; the App Store app-extension variant is rejected and its user-writable App-Group path is **not** a Phase 1 residual | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | If the NE entitlement is refused, ADR-0016 §14(2) falls back to MX-3 (a `LaunchDaemon` owning `utun`), which still yields a root daemon and XPC — §11.2's macOS rows are unchanged. Only a reversal to MX-2 would force the provider-message subset onto macOS, and ADR-0016 rejects that on a security ground |
| **A-12** | **CONFIRMED by [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.3 PS-22.** The MI server lives *inside* the authority process — PS-1 forbids a second privileged process — but as a module with no dependency edge onto the tunnel engine, packet-routing or enforcement modules, and unreachable from them | [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) | MI-I5-1's assertion becomes a **module**-graph rather than a **binary**-graph check. The check is unchanged in kind; only its granularity moves, and P17 clause B remains the behavioural backstop |
| **A-4** | The UI ([ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md)) is MI's primary consumer and holds no control state MI does not expose | [ADR-0019](ADR-0019-application-state-model-and-ui-architecture.md) | If the UI holds authoritative local state, MI-1 is false, R-28 is unmet, and P17 clause A fails — this is the assumption most likely to be violated by convenience |
| **A-5** | Local preferences (S-24) and route acceptance (S-17) have exactly one writer, the agent | [ADR-0020](ADR-0020-local-persistence-and-secure-storage.md), [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | A user-writable settings store gives S-24 two writers and violates **I8**. MI would then need a conflict rule it deliberately does not have |
| **A-6** | **CONFIRMED by [ADR-0021](ADR-0021-packaging-distribution-and-updates.md).** Agent and CLI ship as **one package on every channel**, upgraded atomically | [ADR-0021](ADR-0021-packaging-distribution-and-updates.md) | Closed favourably: MI-5's two-epoch/90-day window does **not** need to lengthen toward ADR-0014's three-epoch/12-month wire window. The three long-tail cases in §11.7 remain the justification for a window larger than zero — a running UI outliving a live upgrade, a pinned `~/bin` copy, and third-party automation — none of which the one-package guarantee removes. §14 condition 3 stays as the falsifiable trigger if the field disagrees |
| **A-7** | Configuration-file control ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md)) is desired state reconciled through the catalogue, and defines no disarming key | [ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) | A disarming config key is a C-2 violation reachable by any process that can write the file. If ADR-0023 needs one, §11.14 must be reopened, not worked around |
| **A-8** | [ADR-0003](ADR-0003-network-contract-schema-format.md) accepts the §11.6 B5 clarification and publishes the MI `.proto` | [ADR-0003](ADR-0003-network-contract-schema-format.md) | If B5 remains "never a trust boundary" without qualification, the corpus contains a live contradiction about the local surface and a reviewer could cite it to justify an unauthenticated local API |
| **A-9** | [ADR-0015](ADR-0015-observability-and-diagnostics.md) accepts `MGMT` as a fourteenth domain | [ADR-0015](ADR-0015-observability-and-diagnostics.md) | Every code here must be respelled into an existing domain, and §11.16's degradation argument predicts the concrete harm: an older client tells the user to check their internet connection when the local service is down |
| **A-10** | **CONFIRMED and sharpened by [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) I-02.** That ADR defines when the agent runs; the agent is **long-lived and never management-activated**, so `MGMT.UNAVAILABLE` is a fault rather than a routine phase on desktop and server class | [ADR-0022](ADR-0022-application-lifecycle-and-background-execution.md) | On a platform where the OS may stop the agent at will (mobile), `MGMT.UNAVAILABLE` becomes routine and clients need a start affordance MI does not define — which is why §11.2.1 marks a stopped iOS provider as *not live* rather than reporting a state. An on-demand desktop agent would additionally falsify MI-A3's socket-activation prohibition and MI-I5-3 together |

### 11.21 Discharging threat-model O-11

[docs/threat-model.md](../threat-model.md) §15 records **O-11** as an open issue and classifies it
as a **defect in the corpus**, not an accepted residual risk:

> **O-11** — *The local management IPC is unspecified.* [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)
> KS-9(2) requires socket registration over "a local, authenticated IPC", and §10 requires "a
> privileged, local, network-independent unblock command". Neither's authentication, authorization,
> or audit contract is defined. *Impact:* Both are the shortest path from local privilege escalation
> to a disarmed kill switch. KS-9(1) bounds the damage but does not define the surface.
> *Proposed owner:* SECURITY / PLATFORM.

**This ADR discharges O-11.** The two named surfaces resolve differently, and the first resolves as
a **negative result** — which is why leaving it implicit would have been dangerous.

#### 11.21.1 KS-9(2) — the socket-registration channel

[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-9(2), verbatim: a packet matches the
bootstrap exception only if "it is emitted on a **socket registered with the enforcement layer** at
bind time via a local, authenticated IPC registration. Unregistered sockets of the same process do
not match."

> **MI-11 (the negative result).** Socket registration under KS-9(2) is **not** an MI operation and
> **MUST NOT** be added to the catalogue. There is no MI operation, at any scope, on any platform,
> that registers, deregisters, or modifies a `BOOTSTRAP` or `RESOLVER` socket.

The reason is KS-10's first bullet, which forbids "a proxy, a SOCKS or HTTP CONNECT listener, a
port-forwarder, a packet-injection API, **or any other interface by which another process can place
bytes on a registered socket**." An MI operation that registered a caller's socket would be exactly
that interface. It would convert the management surface into the bootstrap-exception bypass KS-10
exists to prevent, and it would do so while looking like an ordinary administrative feature. This is
the single most important thing this ADR declines to build.

What the "local, authenticated IPC" of KS-9(2) actually is, under
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s selected topology:

| Platform shape | Where the enforcement layer sits | Registration channel | Authentication of the registrant |
|---|---|---|---|
| Linux, Windows, OpenWrt, Android — enforcement inside the authority | Same process as the sockets ([ADR-0016](ADR-0016-client-process-and-privilege-separation.md) PS-2 keeps the sockets in the authority) | **No IPC exists.** Registration is an in-process call | n/a — there is no channel to authenticate on, and none to attack |
| macOS — the `ksd` `LaunchDaemon` holds the boot anchor separately from the system extension | Two privileged components, both ours | A **separate, single-purpose** Mach service, distinct from `com.twinvpn.agent.mgmt` | XPC audit token plus a Team-ID-pinned code requirement — privileged-to-privileged. [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.2 already forbids `ksd` from accepting any other request |
| iOS, iPadOS | OS-owned | None — the provider's own sockets are excluded from its own tunnel by construction (KS-9(1)) | n/a |

So O-11's three limbs, for this surface:

- **Authentication.** Either no channel exists (the common case, and the strongest possible answer),
  or it is a single-purpose privileged-to-privileged Mach service authenticated by audit token and
  code requirement. No unprivileged principal is admitted on any platform.
- **Authorization.** Vacuous by the same argument: there is no unprivileged caller to authorize.
  MI-11 is what keeps it vacuous, and it is asserted by P17 mutant `M-P17-11`.
- **Audit.** Every registration, deregistration, and KS-12 registration *failure* writes a Tier-0
  ledger entry, and the resulting registry is readable — **read-only** — through
  `killswitch.exempt.get` (§11.9), together with the per-family exempt counters KS-11 requires and
  the divergence figure it compares. A KS-12 failure surfaces as a `Diagnostic`, never as a
  retryable MI error: the socket is simply not exempt, and the honest report is that its traffic is
  dropped.

MI's positive role here is therefore **observation only**, which is precisely what makes KS-11's
"the exemption is thus not merely narrow but *audited*" true at a surface a human can reach.

**A stronger claim, which this ADR endorses as the interface owner.**
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.17 finding 2 observes that
KS-10's safety argument is *topology*-dependent — a property of which process owns the sockets, not
of the exemption — and PS-1/PS-2 make the KS-9 subject and the rule-set owner the same process.
Taken together with MI-11, the conclusion is that **KS-9(2)'s "local, authenticated IPC" is itself
the defect**, and this ADR says so plainly because it owns the surface KS-9(2) would have created:

> **Finding.** Under the selected topology the sockets and the enforcement layer are in one process,
> so registration is an **intra-process call and not IPC at all**. Mandating a "local, authenticated
> IPC" for it would not describe the design — it would **require building** a privileged registration
> endpoint that does not otherwise need to exist, and that endpoint is precisely the confused-deputy
> surface KS-9 and KS-10 exist to deny. A requirement that manufactures the hazard it guards against
> is not a weak requirement; it is a wrong one.
>
> **Recommended amendment to [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) KS-9(2)**, for
> the integrator: replace "via a local, authenticated IPC registration" with a topology-neutral
> obligation — *the socket set is registered with the enforcement layer at bind time by the process
> that owns both; where they are in one process this is an internal invariant, and where a platform
> forces them apart the channel MUST be single-purpose and privileged-to-privileged, never reachable
> by an unprivileged local caller.* That preserves KS-9(2)'s intent (unregistered sockets are not
> exempt, KS-12 unchanged) while removing the implied mandate to build an IPC. O-11's first half then
> resolves by **the surface not existing**, which is a better outcome than specifying it well.

#### 11.21.2 ADR-0012 §10 — the privileged, local, network-independent unblock command

[ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §10, verbatim: "A crash between 'rules
installed' and 'agent running' leaves a host blocked with no UI. Every platform ships a privileged,
local, network-independent unblock command that removes the owner-tagged rule set and clears the
latch, documented in support material. Without it, a bug in this ADR bricks connectivity."

**The structural point that decides everything else: it must work when the agent is not running.**
That is its entire purpose. Therefore:

> **MI-12.** The unblock command MUST NOT depend on the management interface, on the agent process,
> or on any MI channel, and MUST NOT be invocable *by* any MI operation. It is a **package-owned,
> agent-independent artifact** — the same class of artifact as
> [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md) §11.6's boot-time rule installer, served
> by the components [ADR-0016](ADR-0016-client-process-and-privilege-separation.md) §11.5 already
> names (`twinvpn-killswitch` on Linux, the installer-written persistent set on Windows, `ksd` on
> macOS).

There are consequently **two disarm paths**. Both satisfy KS-21; only one is MI, and the difference
is exactly the case O-11 worried about.

| Path | Available when | Channel | Authorization | Audit |
|---|---|---|---|---|
| **Online** — `killswitch.disarm.begin` / `.commit` | The agent is running | MI (§11.14) | Ephemeral `mgmt.disarm`, minted per action by the OS ceremony | Tier-0 ledger entry at the moment of the act (MI-D7), plus `POLICY.KILLSWITCH.DISARMED_BY_OWNER` and a persistent `PERMISSIVE_ANNOUNCED` indication |
| **Offline** — the §10 unblock command | The agent is **not** running — the case that matters | None. A package-owned privileged executable | The **same** OS-mediated administrator authentication as §11.14. No TwinVPN-side credential exists to check, so the OS's is the whole of the authorization | **Deferred** — a durable `UnblockRecord` written before the mutation and ingested at next start |

> **MI-13 (the unblock command's contract).** Normative, and this is the part §10 left as the bare
> word "privileged":
>
> 1. It MUST require the **same OS-mediated administrator authentication** as §11.14's ceremony —
>    polkit `net.twinvpn.administer` (`auth_admin`), UAC consent with Administrators enabled, or
>    `system.privilege.admin`. **"Privileged" means an authenticated administrator act, not merely
>    "runs as root":** a root-owned cron job, a configuration-management run, or a service account
>    MUST NOT be able to invoke it. This closes the authorization half of O-11 for this surface.
> 2. It MUST print the consequence and require an explicit confirmation (KS-21(3)). A
>    `--yes`-style non-interactive flag **MUST NOT exist**, for the same reason
>    `MGMT.DISARM_NO_LOCAL_AUTHORITY` refuses rather than degrades.
> 3. It MUST write a durable `UnblockRecord{invoked_at, principal, ruleset_digest_before,
>    confirmation_text_key}` to a location the agent reads at start, **before** removing the rule
>    set — write-then-mutate, the same ordering rule S-34's `HostResolverRestorePoint` uses, and for
>    the same reason: a record written afterwards is lost in exactly the crash it exists to explain.
> 4. On next start the agent MUST ingest the record, emit `MGMT.UNBLOCK_INVOKED` into the Tier-0
>    ledger and onto the `mgmt` event topic, and hold a **persistent** `PERMISSIVE_ANNOUNCED`
>    indication until the `Owner` re-arms. An unblock that leaves no trace once the agent returns
>    would be an **I3** and **I6** defect.
> 5. If the record cannot be written, the command MUST **still unblock** — bricking the host is the
>    worse failure, which is §10's whole premise — but MUST cause `MGMT.AUDIT_GAP` at next start,
>    and the agent MUST treat enforcement posture as `UNKNOWN` until re-asserted
>    ([ADR-0015](ADR-0015-observability-and-diagnostics.md) O-17/O-18).
> 6. It MUST NOT be reachable over any network path and MUST NOT read configuration from a network
>    location. "Network-independent" in §10 is a *reachability* property, not merely an availability
>    one.

#### 11.21.3 The audit contract — O-11's third limb

O-11 names authentication, authorization **and** audit. Audit is the limb with the least coverage
elsewhere in the corpus, so it is consolidated here rather than left distributed:

| Act | Recorded where | When | Survives agent death? |
|---|---|---|---|
| Every MI mutating call — principal, operation, outcome code | Tier-0 ledger (MI-D7) | At the call | The agent is alive by definition |
| Every `ADMINISTER` ceremony, success **and** failure | Tier-0 + the `mgmt` topic; failures also `PLATFORM.PRIV.ADMIN_AUTH_FAILED` | At the call | As above |
| Online disarm | Tier-0 + `POLICY.KILLSWITCH.DISARMED_BY_OWNER` + persistent `PERMISSIVE_ANNOUNCED` | At the act | The posture survives; the record survives with the ledger |
| KS-9(2) registration, deregistration, and KS-12 failure | Tier-0; readable via `killswitch.exempt.get` | At bind | No — and it need not, since the sockets die with the process |
| KS-11 exempt-egress divergence | `POLICY.EXEMPT.EGRESS_ANOMALY` — [ADR-0012](ADR-0012-kill-switch-and-leak-prevention.md)'s code, **adopted not duplicated** | Continuous | — |
| **Offline unblock** | **Durable `UnblockRecord`, written before the mutation, ingested at next start** | At the act; surfaced at next start | **Yes — this is the point** |
| Diagnostics bundle creation | Tier-0 + `MGMT.DIAG.BUNDLE_CREATED` on every surface (MI-D6) | At the act | With the ledger |

**The residual, stated rather than claimed.** The audit trail is **local, and defensible against
accident rather than against an adversary at agent privilege.**
[ADR-0016](ADR-0016-client-process-and-privilege-separation.md) N4 already declares agent privilege
undefended; a principal who can authenticate as an administrator to invoke the unblock command can
equally delete the `UnblockRecord` and the Tier-0 ledger. What MI-13 guarantees is narrower and
still worth having: a **legitimate** offline unblock is never silent, and an **accidental** one is
always explained on the next start rather than discovered months later as an unexplained
`PERMISSIVE_ANNOUNCED`. Tamper-evidence against a local administrator would require a remote
attestation sink, which [ADR-0015](ADR-0015-observability-and-diagnostics.md) §11.9 forbids ("there
is no support-initiated pull") and which §11.10's privacy posture rules out. The bound is therefore
deliberate, not an oversight.

#### 11.21.4 O-11 disposition

| Limb | KS-9(2) socket registration | ADR-0012 §10 unblock command |
|---|---|---|
| **Authentication** | No channel on four of six platforms; audit-token + code-requirement privileged-to-privileged Mach service on macOS; n/a on iOS/iPadOS (§11.21.1) | OS-mediated administrator authentication, identical to §11.14's ceremony (MI-13(1)) |
| **Authorization** | Vacuous — no unprivileged caller is admitted, and **MI-11** forbids ever creating one | Administrator-only **and interactive-only**; a root cron job is refused (MI-13(1)–(2)) |
| **Audit** | Tier-0 entry per registration and per KS-12 failure; read-only exposure via `killswitch.exempt.get`; KS-11 counters and divergence | Durable `UnblockRecord` written **before** the mutation; `MGMT.UNBLOCK_INVOKED` and persistent `PERMISSIVE_ANNOUNCED` at next start; `MGMT.AUDIT_GAP` when unwritable (MI-13(3)–(5)) |
| **Testable** | P17 clause A + mutant `M-P17-11` | P17 clause C + mutant `M-P17-10` |

**Integrator obligation.** [docs/threat-model.md](../threat-model.md) §15's O-11 row should move out
of the open-issues table with a pointer to this section, and its "Proposed owner: SECURITY /
PLATFORM" resolved to this ADR. **This ADR does not modify that file.**

O-11's stated impact was that both surfaces "are the shortest path from local privilege escalation
to a disarmed kill switch". After this section, neither is a path at all: the first has no
unprivileged entry point and is forbidden from ever acquiring one, and the second requires the same
authenticated interactive administrator act that a direct removal of the rule set would require —
which is the honest bound MI-K2 already states.

## 12. Why the Selected Option Won

1. **Alternative A falsifies the requirement it was meant to serve.** Per-platform surfaces make
   R-21's "same control contract as the GUI" unverifiable — there is no artifact a reviewer could
   point at to reject a GUI-only capability, and P17 clause A would be unwritable. It also
   multiplies the authorization model by six, which means the kill-switch rule (C-2) would be
   re-argued six times and got wrong at least once. Both of those are the failure modes this ADR
   exists to prevent.
2. **Alternative C is the closest runner-up and loses on two platforms and one direction.** gRPC
   would have supplied streaming, deadlines, and status plumbing for free, and its protobuf
   toolchain is already in the product. But there is no gRPC over `sendProviderMessage` and none
   over Binder, so C-10 and C-11 push iOS, iPadOS and Android back into
   alternative A's divergence at exactly the platforms where divergence is most expensive.
   Separately, its flow control backpressures the **producer**, which is the wrong direction for
   R-29: the correct response to a slow local UI is drop-and-resync, not slowing the agent that is
   holding a tunnel up. Alternative D keeps protobuf and discards the channel assumption.
3. **Alternative B's authentication is strictly worse than the filesystem's.** Loopback TCP has no
   peer credentials, so it must invent a bearer token — a new secret with a storage, rotation, and
   leak-into-diagnostics lifecycle, buying nothing over a socket mode bit. It is also reachable by
   every local user, and on Windows from WSL and some container configurations. "A token in a
   0600 file" is filesystem permissions with extra steps and one more asset to lose.
4. **Alternative E cannot express a ceremony or an authorization boundary.** Pairing's 120-second
   expiry, live code, and confirmation step do not fit in a file; neither does "only an interactive
   administrator may disarm", because a config key that disarms is writable by a cron job. It also
   cannot report `MGMT.NOT_READY`, since a status file is either stale or absent and neither is
   distinguishable from "starting". Its genuine advantages — zero listening surface, zero router
   memory, config-as-code — are preserved by keeping configuration as a *source of desired state*
   reconciled through the catalogue (§11.12), which is the useful half without the authorization
   hole.
5. **Separating the contract from the channel is the only structure that survives the hard
   platforms honestly.** On iOS, iPadOS, and Android the OS forbids the channel every other
   alternative assumes. Alternative D still carries the same operations, scopes, schema, and reason
   codes there, and names the transport subset explicitly with `MGMT.CHANNEL_UNSUPPORTED` — which
   is the difference between a stated residual and a silent divergence.
6. **It makes the catalogue a runtime object, which is what makes R-28 and version skew
   tractable.** "What can this build do" is answerable by a client older than the build, on a router
   whose feature profile is smaller than a desktop's. A version integer cannot express that, and
   without it the mixed-version and mixed-profile cases both degrade into guesswork.

## 13. Known Tradeoffs

| Tradeoff | Accepted because | Mitigation |
|---|---|---|
| Framing, negotiation, backpressure, eviction and dedup are all specified by hand rather than inherited from a framework | It is the only way to specify drop-and-resync instead of producer backpressure, which R-29 requires | The whole ladder is one table (§11.10); P17 clause B's mutants `M-P17-3`/`M-P17-4` fail a build that gets it wrong |
| Third-party automation authors write more code than they would against REST | Local automation is a small, mostly-scripted population, and the CLI's stable `--output json` is the supported surface for it | `mi.catalogue.get` is machine-readable; the CLI is the reference client and is generated |
| Two bindings on macOS in the Developer-ID shape (XPC for entitled clients, `AF_UNIX` for the CLI) | XPC's audit-token attestation is strictly better and worth having where it is available; the CLI cannot use it | One contract, two bindings on one OS; the operation set is identical, and P17 clause A runs against both |
| iOS/iPadOS pay a polling cost the other platforms do not | Apple supplies no provider-initiated push (C-10). The alternative is a stale UI, which O-18 forbids | Cadence bound to **scene visibility**, not app foreground; Darwin-notification hints reduce the steady-state need; §14 revisit condition 4 retires this if Apple ships a channel |
| `pairing_secret` crosses the MI boundary (MI-P1) | The renderer and the key holder are different processes under H2, and a QR code is by definition a rendering path | Narrow, named, non-loggable, non-persisted, 120 s; and the exposure is not increased, since the process that draws the QR already controls the display |
| The MI authenticates a **user**, not a **program**, on Linux and Windows | Per-binary allowlisting is defeated by an attacker already running as that user and breaks legitimate clients | Stated as residual (§7, §11.4); everything that must survive a compromised session is bound to the OS ceremony (§11.14) |
| A fourteenth reason-code domain in a taxonomy that declared thirteen closed | Prefix degradation would otherwise produce an actively wrong diagnosis for the most common local failure (§11.16) | One row, one subdomain, an explicit registration obligation (MI-10), and no further widening |
| A shorter compatibility window than the wire's (2 epochs vs 3) | Local skew is a transient of an atomic local upgrade, not a fleet-wide fact | Three long-tail cases enumerated (§11.7); §14 revisit condition 3 lengthens it on measured evidence |
| No durable local event replay log | It would duplicate the Tier-0 ledger with a second retention and redaction policy | `event.resync`'s lock-consistent snapshot for current truth; `diag.log.tail` for history |

## 14. Revisit Conditions

Falsifiable triggers. Any one reopens this ADR.

1. **Router memory.** If the measured steady-state RSS of the MI server exceeds **256 KiB** with
   zero clients attached, or **64 KiB** per attached client, on the **H-EMB** reference device
   ([ADR-0023](ADR-0023-headless-cli-and-embedded-profile.md) owns the hardware envelope; the
   `HC-` prefix is [ADR-0016](ADR-0016-client-process-and-privilege-separation.md)'s process-topology
   axis and is not reused here), the always-listening design is falsified for router class and must be replaced by on-demand socket
   activation or a `ubus`-only profile.
2. **Status latency and poll pressure.** If p95 `status.get` latency exceeds **25 ms** on the
   reference low-end device, or a shipping UI is measured issuing more than **2 MI requests/s** in
   steady state, the push/poll balance is wrong and a coalesced push-only status topic must replace
   the polled read.
3. **Skew distribution.** If Tier-2 aggregates show **>1 % of attaches at `mi_version` N-2 or
   older for >30 consecutive days**, MI-5's two-epoch window is falsified and must lengthen toward
   [ADR-0014](ADR-0014-protocol-versioning-and-capability-negotiation.md) N-24's three-epoch wire
   window.
4. **Apple ships a bidirectional channel.** If a sanctioned provider→app push appears (a reverse
   `sendProviderMessage`, or supported `AF_UNIX` in an App Group container), §11.2.1's polled subset
   is obsolete and the iOS/iPadOS residual is retired.
5. **Eviction rate.** If `MGMT.CLIENT_TOO_SLOW` evictions exceed **1 per device per week at p99**
   in the field, §11.10's watermarks are mis-sized and the coalescing model must be re-derived from
   measurement rather than from ADR-0002's analogy.
6. **A non-interactive management principal appears.** If a consumer that is neither a human shell
   nor our GUI — an MDM agent, an Ansible module, a home-automation integration — requires
   `mgmt.admin` or `mgmt.settings` from a **non-interactive** principal, the interactive gate in
   §11.13/§11.14/§11.15 becomes a functional blocker, and a service-principal scope class with its
   own audit obligation must be designed. Unattended router provisioning is the concrete case.
7. **Peer-credential spoofing.** If a memory-safety or authentication CVE makes `SO_PEERCRED`,
   `GetNamedPipeClientProcessId`, or XPC audit-token retrieval spoofable on a supported platform,
   MI-A1 is falsified and authentication must fall back to filesystem permissions alone, collapsing
   §11.5's six scopes to a single authorized-local-user tier.
8. **Catalogue growth.** If the catalogue exceeds **60 operations**, or more than **4 operations per
   quarter** are added for two consecutive quarters, one flat catalogue is the wrong granularity and
   the contract must be split into independently versioned per-area services (status / control /
   enroll / diagnostics), each with its own `mi_version`.
9. **A second local privilege tier appears.** If a platform introduces a sanctioned way to attest
   the *calling program* on Linux or Windows at the same strength macOS's audit token provides, the
   "authenticates a user, not a program" residual in §7 and §11.4 is no longer forced and a
   per-client-identity scope model becomes worth its cost.
