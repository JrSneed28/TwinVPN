# The macOS shell — the system extension, `ksd`, `twinvpnctl` and `twinvpn-unblock`

**Owner:** `desktop-macos`.
**Authority:** [ADR-0016](../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
(the privilege split), [ADR-0017](../../docs/adr/ADR-0017-local-management-interface.md)
(the local MI), [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.1 and §11.12 (CB-1, CB-2, the layout),
[ADR-0012](../../docs/adr/ADR-0012-kill-switch-and-leak-prevention.md) (the kill
switch), [ADR-0020](../../docs/adr/ADR-0020-local-persistence-and-secure-storage.md)
(the two storage tiers), [ADR-0021](../../docs/adr/ADR-0021-packaging-distribution-and-updates.md)
(distribution). This host is ADR-0016 class **HC-1**;
`docs/application-architecture.md` §7's macOS row is *"NE **system extension** +
minimal `LaunchDaemon` | pf anchor from `/etc/pf.conf`, daemon-applied | Unix
socket / XPC | Developer ID + notarized, stapled"*, and **H2** chose that over the
App Store variant because the App Store variant forfeits KS-19.

---

## 0. Read this first

**Nothing in this directory has been built on macOS, linked, signed, notarized,
installed or run.** The development host is Linux. What that means precisely, and
what it does not mean, is the whole of §7 — and the short version is:

| Artifact | Compiled for `aarch64-apple-darwin` | **Executed** |
|---|---|---|
| `twinvpn-bridge` (Rust) — **the authority** | yes, `-D warnings` | **yes, on Linux** — 134 tests |
| `twinvpn-mi` (Rust) | yes, `-D warnings` | **yes, on Linux** — 31 tests |
| `twinvpnctl` (Rust) | yes, `-D warnings` | **yes, on Linux** — 22 tests |
| `ksd` (Rust) | yes, `-D warnings` | **yes, on Linux** — 12 tests |
| `twinvpn-unblock` (Rust) | yes, `-D warnings` | **yes, on Linux** — 10 tests |
| `TwinVPNTunnel/*.swift` | **no.** Swift 6.1.2 here is the Linux toolchain with no Darwin SDK: no `NetworkExtension`, no `XPC`, no `Security`, no `SystemConfiguration` | **no** |
| `packaging/*` | n/a | **no** |

A green `make cross-check` is a **compile proof and never a behaviour proof**, and
it must not be reported as one.

**What changed in wave 3.** `ownership.md` §9.6 **X-7** closed a defect against
this shell: ADR-0016 §11.2 says the NE system extension is the authority, and
wave 2 put the core, the keys and the management interface in a `LaunchDaemon`
called `twinvpnd` instead. Amendment **PS-22** names the mechanism and the
argument — `NEPacketTunnelProvider.packetFlow` exists only inside the provider
process, the core owns the datapath, and §11.16 (a) / S-47 permit exactly one
process a mutating core handle — so the authority moved into
`twinvpn-bridge`, `twinvpnd` was deleted, and `ksd` narrowed to the KS-19 boot
anchor. §7's gap list is rewritten accordingly.

---

## 1. What is here

| Path | What |
|---|---|
| `twinvpn-bridge/` | **the authority.** The hosted `Core`, the platform adapter, the key handle, the datapath and the management interface — as a Rust `staticlib` the Swift system extension links, plus the C header that is the ABI of record between them |
| `twinvpn-mi/` | the management contract as this shell carries it: the endpoint, the framing, the scope set and the client. Linked by the authority **and** by the CLI, and by nothing privileged |
| `twinvpnctl/` | the unprivileged CLI |
| `ksd/` | the `LaunchDaemon`, narrowed to the KS-19 boot anchor: apply, read back, exit |
| `twinvpn-unblock/` | KS-20a's offline recovery command — package-owned, privileged, and dependent on nothing that can fail to start |
| `TwinVPNTunnel/` | the `NEPacketTunnelProvider` system extension and the XPC management listener, in Swift |
| `TwinVPNApp/` | the host app's system-extension installer, in Swift |
| `packaging/pf.anchor` | the **KS-19 boot artifact**: the fail-closed ruleset in force before the authority runs |
| `packaging/pf.conf.include` | the lines a package adds to `/etc/pf.conf` |
| `packaging/com.twinvpn.ksd.plist` | the **only** `LaunchDaemon`. It applies the boot anchor at `RunAtLoad` and exits — **package-owned** (PS-7) |
| `packaging/*.entitlements`, `*.Info.plist` | the system extension's and the app's |
| `packaging/SIGNING.md` | Developer ID signing, notarization and stapling, **as documented procedure that has never been run** |
| `packaging/install.sh` | an idempotent installer, **never executed** |

### The process topology, after PS-22

| Process | Holds | Does not hold |
|---|---|---|
| `com.twinvpn.app.sysext` (NE system extension, root) | the core, the platform adapter, the datapath, the key handle, the management interface on **both** of ADR-0017 §11.2's macOS channels | — |
| `com.twinvpn.ksd` (`LaunchDaemon`, root) | the KS-19 boot anchor | no core, no keys, no network sockets, no management interface |
| `TwinVPN.app` (per-user, sandboxed) | UI, the VPN profile, the sysext activation | no authority, no key, no recovery path |
| `twinvpnctl` (user) | the CLI over the MI socket | nothing privileged in its dependency graph |
| `twinvpn-unblock` (root, on demand) | the offline removal of the owner-tagged anchor | no core, no MI, no channel |

The adapter these bind is
[`core/crates/twinvpn-platform-macos`](../../core/crates/twinvpn-platform-macos),
which this domain also owns. **169 of its tests execute on the Linux host**: the
pf anchor's text and its `pfctl` read-back parser, the route programme, the
`NEPacketTunnelNetworkSettings` document, the resolver programme, the `PF_ROUTE`
decoder, the mach timebase arithmetic, the power state machine, and the whole
apply/rollback transaction against recording carriers, plus KS-20a's anchor
removal and its read-back.

### Why `twinvpn-mi` is its own crate

ADR-0017 MI-20 and ADR-0018 §11.16 (b) require *"one contract, two carriages,
**never two contracts**"*. Before X-7 the two carriages were two halves of one
`twinvpnd` crate behind a feature gate. The authority has moved into the system
extension and the CLI has not, so the shared half is a crate of its own — and the
exclusion the feature gate used to provide is now **structural**: `twinvpn-mi`
links no core, no platform adapter and no `pf`, so `twinvpnctl` is unprivileged
by its dependency graph rather than by how it is run.

The envelope itself is not here at all. `ownership.md` §9.6 **X-4** moved it into
`core/crates/twinvpn-mgmt`, where all three shells share one declaration; this
crate carries the **transport**.

### Why the core is no longer behind a feature

It was, and the reason was never a design one: `twinvpn-core` pulled
`twinvpn-crypto` → `snow` → `ring`, whose C sources are compiled by a build
script, and there is no Darwin C toolchain on this host — so
`cargo clippy --target aarch64-apple-darwin` failed inside `ring`'s build script
**before it type-checked a line of ours**. `core/Cargo.toml` now selects `snow`'s
default resolver, that edge is gone, and the core-hosting path is inside the
`make cross-check` gate like everything else.

The MI server's edge onto the core is still a one-method trait
(`mgmt::server::CommandSink`, which is PS-4's typed vocabulary), because the two
*design* reasons remain: PS-22 (§11.3) requires the management server to have no
dependency edge onto the datapath, and a recording sink is what makes the
authorization ladder testable on a host with no Darwin kernel.

---

## 2. Environment configuration

Every variable has a default, and **the default is the production value**. None of
them is a security control.

| Variable | Default | What it does |
|---|---|---|
| `TWINVPN_MGMT_SOCKET` | `/var/run/twinvpn/mgmt.sock` | the MI endpoint. ADR-0023 **EM-19** makes changing it restart-requiring, which is what a variable read once at start is. `/var/run` and not Linux's `/run`: on macOS `/var/run` is the real directory. The endpoint's safety comes from `LOCAL_PEERCRED` and the directory check, wherever it points |
| `TWINVPN_LOG_LEVEL` | `info` | `trace`/`debug`/`info`/`warn`/`error`. **`critical` is accepted and mapped to `error`** — `ownership.md` §8 **W-16**, so a value copied verbatim from ADR-0015 §11.5 configures the service rather than failing it. An unrecognised value falls back to `info` **and is logged as unrecognised**: a logging misconfiguration must not be why a VPN agent will not run |
| `TWINVPN_LOG_FORMAT` | `json` under a supervisor, `text` otherwise | follows `XPC_SERVICE_NAME`, which `launchd` sets for a job it started and nothing else sets — the closest macOS has to `systemd`'s `INVOCATION_ID` |
| `TWINVPN_STATE_DIRECTORY` | `/Library/Application Support/TwinVPN` | ADR-0020's macOS store row: `root:wheel`, `0700`, "the system extension / `launchd` daemon only". CB-7: the path is *injected*, never discovered |
| `TWINVPN_OVERLAY_INTERFACE` | `utun7` | the overlay interface name. Tier 2 is interface-scoped, so this is the one name the whole anchor turns on |
| `TWINVPN_GROUP_OBSERVE` / `_OPERATE` / `_ADMINISTER` | `0` | the gids PS-12a's three classes come from. **The package creates the groups; the agent never does.** A gid nobody set is `0`, which grants nothing to any non-root account — it fails closed |
| `TWINVPN_EXEMPT_UID` | `0` | the uid the anchor's class-7 rule matches (KS-9(1)) |
| `COLUMNS` | terminal width | `twinvpnctl` only. EM-44: wrap to `min(COLUMNS, 100)`, legible at 80 and at 40 |
| `NO_COLOR`, `TERM` | — | `twinvpnctl` only. EM-43: colour needs a TTY **and** `NO_COLOR` unset **and** a colour-capable `TERM` |
| `LANG`, `LC_ALL` | — | `twinvpnctl` only. EM-43: UTF-8 glyphs only where these indicate UTF-8. The renderer is fully legible in US-ASCII |
| `TWINVPN_DARWIN_WRITE_TEST` | unset | opts the adapter's `tests/darwin.rs` into the tests that mutate the host. Root **and** this, so a stray `sudo cargo test` cannot install a pf anchor |

The agent reads **no configuration file**.

---

## 3. Local startup

### On this Linux host

```sh
source build/toolchain/env.sh

# Everything that can run, runs:
cd core            && cargo test -p twinvpn-platform-macos   # 169 tests
cd ../shells/macos && cargo test --workspace                 # 209 tests

# Everything that can be type-checked for Darwin, is:
cd ../.. && make cross-check                                 # -D warnings, nothing linked
```

`--all-features` is gone from the second line and its absence is the point: there
are no features left to turn on. The core-hosting path used to be behind
`core-host`; it is unconditional now, so `cargo check` and `make cross-check`
cover the same code.

`Host::start` **will refuse on Linux**, at the privilege posture or at the clocks
depending on who is running it, and that is correct: `pfctl` needs uid 0 and
`ContinuousElapsedClock::from_kernel()` returns `None` off Darwin, where a clock
with a guessed timebase is wrong by a factor of 41 on Apple silicon.
`tvb_ext_start` therefore returns `TVB_ERR` with the step's registered code in
the envelope, which is what `a_start_that_cannot_host_the_authority_refuses_and_
writes_no_handle` asserts.

### On a Mac — the procedure, never performed

```sh
# 1. The principals. The PACKAGE creates them; the agent never does (PS-12a).
sudo dscl . -create /Groups/twinvpn            # OBSERVE
sudo dscl . -create /Groups/twinvpn-operators  # OPERATE
sudo dscl . -create /Groups/twinvpn-admins     # ADMINISTER

# 2. Build. There are no feature flags -- see §1.
cd shells/macos && cargo build --release

# 3. The KS-19 boot artifact, the anchor, the ksd job, twinvpn-unblock, the
#    CLI and the endpoint directory. NOT the authority: it is inside the app.
sudo ./packaging/install.sh

# 4. The system extension -- WHICH IS THE AUTHORITY -- is installed by the APP,
#    through OSSystemExtensionRequest, and requires a Developer ID signature and
#    notarization: see packaging/SIGNING.md. Until it is activated there is no
#    core, no MI socket and no Mach service on this host, and a `twinvpnctl`
#    exits 3 with MGMT.UNAVAILABLE. That is MI-A3's answer and not a defect:
#    M-P17-17 names socket activation as the defect for exactly this case.
```

To grant a person read access, add them to `twinvpn`; to let them connect and
disconnect, add them to `twinvpn-operators`. **Built-in `staff` and `admin` are
deliberately not used** — PS-12a: *"'every local account can enumerate this
device's peers and endpoints' should be an install-time decision (TB-13), not a
platform default."* A membership change takes effect **on the next attach**
(S-44: re-derived at every attach, never cached across attaches).

---

## 4. The start sequence, and what each step refuses

ADR-0016 §11.6, in order, **inside the system extension** —
`twinvpn_bridge::start::StartSequence` is this table as a value the diagnostic
bundle can carry, and `tvb_ext_start` is what runs it. Its tests exercise every
row on this Linux host against injected probes.

`ksd` has its own four-step sequence (`ksd::boot`) and the split is in that
module's header: eight of the ten steps below belong to the authority and moved
with it; privilege, the anchor body, the apply and **the read-back** stayed.

| Step | On failure |
|---|---|
| 1. the KS-19 boot artifact is installed | `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` as a **warning** — and the agent starts anyway. §11.6 step 1 reads as a refusal and PS-7 says the artifact "MUST NOT be a prerequisite for [the authority] to apply"; `desktop-linux` read the pair as warn-and-continue and this shell takes the **same** reading, because two shells behaving differently on one rule is worse than either. Reported to the integration lead, and unchanged since wave 2 |
| 2. the privilege posture | **Fatal** if not root: pf, the route socket and `SCDynamicStore` all require it, and PS-18 forbids starting in a mode that cannot arm enforcement. Root **is itself a named degradation** (`PLATFORM.PRIV.SANDBOX_DEGRADED`), because macOS has no spelling of "this capability and nothing else" — see §7 gap 2 |
| 3. the three clocks, the CSPRNG and the boot identity | **Fatal.** `mach_absolute_time` is suspend-**exclusive** and `mach_continuous_time` is suspend-**inclusive** (ADR-0022 LC-8); the timebase is read once and a failed read refuses rather than guessing. The CSPRNG is **probed at startup**, not on first use |
| 3b. the runtime's I/O driver (**W-43**) | **Fatal.** Fixed upstream (`enable_io()` is on both `TokioRuntime` constructors now), and the probe stays: PS-18's rule is to refuse at startup rather than report a running agent that panics on the first command |
| 4. the adapter's capability probe | **Fatal** if `pfctl(8)` is absent — ADR-0012 §8: arming must never fail open. **KS-9(1) now holds in full**: inside the provider the uid is matched in the anchor and the socket-set half is supplied by the NE runtime, so `ExemptPredicate::ProviderUidAndSocketSet` replaces wave 2's `UidOnly` and the degradation this row used to report is gone. Moving the authority did not only satisfy §11.2, it closed a KS-9 gap — **declared, never assumed**: see §7 gap 11 |
| 4b. reclaim the owner-tagged ruleset (KS-20, PS-8) | **Fatal.** The ruleset is reclaimed *and then* **read back from pf** — `pfctl -s info` for whether the filter is even on, and `pfctl -a twinvpn -s Tables` for the posture, the generation and the per-family scope cardinality. That is the **W-24 query**, not the fact that a load returned `Ok`, and `DarwinProbes::with_read_back` takes an `Assertion` precisely so a boolean cannot be set any other way |
| 5. durable state | **Fatal** if the vault directory is not `0700`. A vault the group can read is a vault every local account can read |
| 6. the core | **Fatal**, `INTERNAL.ABI_VERSION_MISMATCH` (VR-4), checked before any capability is touched. There is no build in which this step is skipped any more |
| 7. the MI endpoint | **Fatal**, `MGMT.UNAVAILABLE`. MI-A3: the authority verifies `/var/run/twinvpn`'s ownership and mode **before** binding, binds a staging name, sets the mode and group, then `rename`s it — `unlink()`-then-`bind()` is prohibited and the word does not appear in the module. The `tokio` reactor attach happens **inside** the runtime, in the accept task, because `from_std` needs one and the bind does not (wave 2 called it outside any runtime, which on a Mac would have panicked on the first start) |
| 8. accept connections | only now (§11.6). The XPC listener is started by `PacketTunnelProvider.startTunnel` **after** `tvb_ext_start` returns a handle, for the same reason |

The authority also **warns and continues** on: the root-with-no-narrowing posture
(PS-17), and a peer whose kernel group list was full and may be truncated.

---

## 5. Debugging

```sh
# What PF says is loaded. This is the W-24 read-back, and it is what the
# ProtectionAssertion is derived from -- never the agent's belief.
sudo pfctl -s info | head -1                       # is the filter even ON
sudo pfctl -a twinvpn -s Tables                    # posture, generation, scope cardinality
sudo pfctl -a twinvpn -s rules -v                  # the rules themselves
sudo pfctl -a twinvpn -s labels                    # the leak canary's counters

# The posture and the generation are pf TABLES, not counters: pf has no named
# counters, so `tv_posture_blocked` xor `tv_posture_protected`, `tv_gen_<n>` and
# `tv_scope4_n<n>` / `tv_scope6_n<n>` are `persist` tables in our own anchor.
# "BLOCKED over nothing" is therefore a value a reader can see.

# Our routes. The host's own are untouched: a full tunnel is four /1 routes,
# never a `route delete default`.
netstat -rn -f inet | head -20
netstat -rn -f inet6 | head -20

# The resolver, as configd holds it.
scutil --dns | head -40
sudo scutil <<< "show State:/Network/Service/<service-id>/DNS"

# The two mach clocks, which are the pair LC-8 says is invisible when it is
# wrong. On a Mac that has slept, the second is strictly larger.
sysctl kern.boottime kern.bootsessionuuid

# The agent's own view of its start:
sudo log stream --predicate 'subsystem == "net.twinvpn"' --level debug

# The authority has no command line: it is a static library inside a system
# extension, and `tvb_ext_start` installs the subscriber. Its environment comes
# from the sysext's, not from a shell.
systemextensionsctl list
sudo launchctl print system/com.twinvpn.ksd

# The KS-19 job, on demand and read-only:
sudo /Library/Application\ Support/TwinVPN/twinvpn-ksd --status

# "Is TwinVPN what is blocking me?" -- asked without changing anything:
sudo twinvpn-unblock --status
```

### Running the tests

```sh
cd core            && cargo test -p twinvpn-platform-macos    # 169, unprivileged
cd ../shells/macos && cargo test --workspace                  # 209, unprivileged
```

Both suites run unprivileged **on Linux**, which is the point: the adapter keeps
every translation layer target-free, so the pf anchor's contents, the read-back
parse, the route programme, the settings document, the resolver programme, the
`PF_ROUTE` decode and the apply/rollback ordering are checked properties rather
than operational ones.

On a Mac, the adapter's `tests/darwin.rs` adds the half no Linux host can reach:

```sh
cd core && cargo test -p twinvpn-platform-macos --test darwin

# The write half needs root AND the opt-in:
sudo TWINVPN_DARWIN_WRITE_TEST=1 \
  cargo test -p twinvpn-platform-macos --test darwin -- --test-threads=1
```

**None of `tests/darwin.rs` has ever run.**

---

## 6. `twinvpnctl`

```
usage: twinvpnctl [--output human|json|json-lines] <noun> <verb>
```

The verb table is **generated from the core's command catalogue** (MI-C1), so
`twinvpnctl --help` lists exactly ADR-0017 §11.9's operations, in its order. A
verb with no catalogue entry, or an entry with no verb, fails
`mi_c1_the_verb_set_and_the_catalogue_are_equal_in_both_directions`.

**Exit codes** are ADR-0017 §11.12's, and 64+ is prohibited:

| | |
|---|---|
| **0** | succeeded |
| **1** | failed for a reason the agent named |
| **2** | usage — **nothing was sent to the agent** |
| **3** | the management channel is unavailable |
| **4** | authorization refused |
| **5** | version incompatible |

The mapping switches on the diagnostic's **domain**, not on a list of individual
codes, so a code registered tomorrow lands in the right bucket with no client
change. The `reason_code` and its `class` go to **stderr in every output mode**,
including `--output json`, "so a `set -e` script that does not parse JSON still
gets it" — and retry policy is driven by the class, not by the exit code
(**EM-37**).

**It never prompts** (EM-38). A state-changing operation without
`--confirm-unprotected` exits **2** rather than reading from a terminal, and
`em38_this_binary_never_reads_from_a_terminal` asserts it over the source.

---

## 7. What is NOT here, stated plainly

Each of these is a gap this wave did not close, with the reason. The list is
renumbered because X-7 removed a component and added two; wave 2's numbering is
not preserved.

### The one that matters most

1. **No line of Swift has been compiled.** Swift 6.1.2 is installed and it is the
   **Linux** toolchain: there is no Darwin SDK, so `NetworkExtension`, `XPC`,
   `Security` and `SystemConfiguration` do not exist here. `swiftc -parse` was run
   over all seven files and they parse — a syntax check with a planted error
   confirming it has teeth — and that is **all**: no type-check, no name
   resolution, no concurrency checking, no API-existence check. Every NE and XPC
   API shape, every `Codable` field name, every `os.Logger` call and every actor
   boundary in `TwinVPNTunnel/` is unverified. This is the single largest risk in
   the directory, and it is why the Swift surface is a `Codable` struct, a buffer
   wrapper, two loops and a listener: **every decision is on the Rust side, where
   it is tested.**

2. **`pfctl` has never parsed the anchor this adapter renders.** `pf::render` is
   exhaustively tested for what it *says* — 24 states, both families, the class
   whitelist, the read-back round trip — and only `pfctl` can say whether Apple's
   fork *accepts* it. Two constructs are most likely to differ: the **`user`**
   rule keyword (KS-9(1)'s uid half; it exists in OpenBSD/FreeBSD pf, unconfirmed
   on Apple's fork) and the ICMPv6 type names. If `user` is absent the anchor
   fails to parse and the KS-19 artifact does not load **at all**, which is why
   `install.sh` gates on `pfctl -n -f` before committing.
   `tests/darwin.rs::the_anchor_this_adapter_renders_is_one_apples_pf_accepts` is
   the assertion that would settle it.

3. **`xpc_connection_get_audit_token` is Apple SPI.** ADR-0016 §11.14 (a) names
   `audit_token_t` over XPC as the macOS peer attestation and ADR-0017 §11.2's
   macOS row says why — "audit-token attestation is not pid-based and therefore
   not TOCTOU-able" — but the only API that returns one is declared in
   `<xpc/private.h>`. `TwinVPNXPCShim.h` declares it, says so at length, and names
   the public alternative (`NSXPCConnection`'s `effectiveUserIdentifier` /
   `effectiveGroupIdentifier` / `processIdentifier` / `auditSessionIdentifier`),
   which covers the two fields the authorization decision uses and loses
   `pidversion`. The swap is confined to one Swift function
   (`ManagementListener.auditTokenBytes(for:)`). **Needs a decision** from
   ADR-0016's owner: §11.14 (a) requires a mechanism Apple does not publish.

### The privilege model

4. **The authority runs as root and cannot narrow itself.** ADR-0016 §11.2 says
   the authority "MUST NOT continue as root 'just this once'", and Linux
   discharges it by dropping to `CAP_NET_ADMIN`. **macOS has no spelling of "this
   capability and nothing else"**: pf, the `PF_ROUTE` socket and `SCDynamicStore`
   all require root, and the equivalents of `systemd`'s hardening directives —
   hardened runtime, library validation — are set at *codesign* time rather than
   by the supervisor. A system extension does not change this: it is root by
   grant. The start sequence reports `PLATFORM.PRIV.SANDBOX_DEGRADED` on **every**
   start rather than letting a reader assume a sandbox that is not there.
   **Needs a decision** from ADR-0016's owner.

5. **`audit_token_t` carries no supplementary group list, so the XPC carriage's
   class map is narrower than the socket's.** ADR-0016 PS-12a derives the three
   authorization classes from **group membership**, and a token carries the
   effective gid and nothing else — there is no `audit_token_to_groups` and no
   XPC API that supplies one. `getsockopt(LOCAL_PEERCRED)` returns up to sixteen
   groups, which is why wave 2 recorded macOS as *better* than Linux here. So an
   XPC client reaches a class only if that class's gid is its **effective** gid,
   which fails **closed** and is flagged (`groups_possibly_truncated` is always
   true on that carriage). It is deliberately **not** patched by looking the uid
   up in Directory Services: a directory answer is a statement about the
   *account*, not about the connected *process*, and MI-A1 asks for the latter.
   `mgmt::audit`'s tests pin the behaviour in both directions.

6. **The XPC code requirement is not checked.** ADR-0017 §11.2's macOS row gives
   the XPC carriage "XPC audit token → **`SecCodeCheckValidity`** against a
   Team-ID-pinned code requirement". The token is decoded and the principal
   derived from it; the client's code signature is **not** verified, because that
   needs `Security.framework`, which this crate does not link. The consequence is
   real: any local process whose euid/egid land in a TwinVPN group can attach,
   not only a Team-signed one.

7. **MI-A3 is discharged by the installer, not by the supervisor.** `systemd` has
   `RuntimeDirectory=`, which recreates `/run/twinvpn` with the right owner and
   mode on every start; neither `launchd` nor `systemextensionsd` has an
   equivalent. So `/var/run/twinvpn` is created once by `install.sh` and the
   authority **verifies and refuses** rather than creating it. That is genuinely
   weaker — the installer runs once, the OS starts the extension every time — and
   after a `/var/run` wipe the MI socket will not bind until the directory is
   restored. The XPC carriage is unaffected, which is one practical argument for
   having two.

8. **`launchd` expresses almost none of ADR-0016 §11.9's hardening table, and the
   sysext expresses none of it either.** No `ProtectSystem`, `PrivateDevices`,
   `RestrictAddressFamilies` or `SystemCallFilter` equivalents exist. The plist
   says so in its header, so its shortness is not read as containment.

9. **PS-9 and PS-10 are not implemented.** ADR-0016 §11.5's macOS row makes
   crash-loop containment the authority's **own durable restart counter (S-40)**
   latching quarantine itself, because launchd has no burst limit — and NE's
   on-demand restart of a system extension has none either. **That counter does
   not exist**, and neither does PS-9 (2)'s degraded stub: an authority that
   cannot start answers nothing at all rather than answering
   `PLATFORM.SERVICE.QUARANTINED`. PS-22 makes this sharper than it was, because
   §11.14 (d) requires the contract to be answerable by that stub.

10. **One `unsafe` block on the management side, and it is load-bearing.**
    `twinvpn-bridge` is on the DP-4 allowlist and its FFI entry points are
    `unsafe` by construction, so a blanket count would say nothing. The
    *management* modules have exactly one: `getsockopt(LOCAL_PEERCRED)` in
    `mgmt::peer::PeerCredentials::read`, because MI-A1 requires a kernel-sourced
    principal and no safe wrapper exists in `std` or in any dependency this shell
    has. `mgmt::tests::the_management_modules_use_unsafe_in_exactly_one_place`
    asserts the budget over the source. `ksd`, `twinvpn-mi`, `twinvpnctl` and
    `twinvpn-unblock` all carry `#![forbid(unsafe_code)]`.

11. **KS-9(1) is now satisfied in full — as a declaration, not an observation.**
    The provider binding declares
    `ExemptPredicate::ProviderUidAndSocketSet`, on the ground that the NE runtime
    excludes the provider's own sockets from the tunnel it is serving. **Nothing
    on this host verifies that**, and nothing in the ADR corpus states it as a
    guarantee rather than as an expectation. If NE does not do it, the predicate
    is silently the weaker uid-only one and `ks9_complete()` is a lie. This is the
    one place the move *strengthened* a claim, which is exactly why it needs
    checking on a Mac.

12. **`xucred` carries at most 16 groups.** On the socket carriage a principal in
    more than sixteen groups may have the relevant one truncated away by the
    kernel. It fails **closed** — fewer scopes than intended — and the authority
    logs a warning when the list came back full.

### The management interface

13. **The XPC carriage never closes a connection.** `tvb_mgmt_exchange` cannot:
    Swift owns the `xpc_connection_t`, and CB-2 forbids Swift deciding *when* to
    close one from a domain fact, so the ABI does not report the session's
    `ending` outward. The refusal is enforced on the Rust side instead — an
    ended session answers `MGMT.UNAVAILABLE` to everything for as long as it
    exists, and no path re-opens one — but the **connection** stays until the
    peer goes away or the tunnel stops. The socket carriage does close. There is
    no rate limit on either (ADR-0017 §11.16's is unimplemented), so a client
    that keeps a rejected session open costs one lock and one `Vec` per message.

14. **No event stream.** `event.subscribe` reaches the core and the core accepts
    it, but neither carriage pushes `Event` frames, and `event.resync` is
    unwired. The `Compacted` marker (MI-19) and §11.10's eviction ladder are
    therefore unexercised. The XPC carriage makes this harder rather than easier:
    it is request/reply, so a push needs a second connection direction that
    nothing here builds.

15. **No ADMINISTER ceremony.** Every ADMINISTER operation is **refused**, not
    performed on a scope alone — §11.5's third consequence and the safe
    direction. Wiring it needs Authorization Services (`system.privilege.admin`,
    KS-21's macOS mechanism), which is a Darwin framework this crate does not
    link. The same framework gap is gap 17's.

16. **`SOCK_STREAM` + length prefix on the socket carriage, not
    `SOCK_SEQPACKET`.** §11.2 prefers the latter "so message boundaries are
    kernel-preserved"; `tokio`'s `UnixListener` is `SOCK_STREAM` only. The cost is
    exactly the one §11.2 names, bounded by the 1 MiB cap being enforced **before
    any allocation**. The XPC carriage does preserve boundaries and uses the same
    length prefix anyway, so a captured message is byte-identical on both — which
    is §11.2's own opening requirement.

17. **`committed_at_net_seq` is always absent, and correctly so.** MI-6's cursor
    is "a real, monotone position in the same log" the C2 stream replays; a
    locally-mutating operation reaches no C1 request and has none. Reporting a
    per-process counter there would tell a client it had read-your-writes when it
    had not.

18. **`platform_ctx.os_version` is empty.** The real answer is
    `sysctl kern.osproductversion`, which is Darwin-only and not wired. MI-C3
    requires clients to use the value **verbatim**, so an empty string renders as
    unknown rather than as a wrong version — the right failure.

19. **The binary is `twinvpnctl`, and ADR-0016 §11.2 / ADR-0017 §11.12 name it
    `twinvpn`.** ADR-0023 EM-42's rendered next actions say `run 'twinvpn peer
    disconnect nas-attic'`, which names a command installed under another name.
    `shells/linux` raised the same deviation; this shell matches it rather than
    having the CLI called one thing on Linux and another on macOS. **Needs a
    decision.**

20. **`isatty` is not called**, because it needs `unsafe` and `twinvpnctl`
    forbids it. The CLI therefore assumes **not a TTY**, which under EM-43 means
    no colour ever. The UTF-8 decision still follows `LANG`/`LC_ALL`.
    Conservative and always correct, and less than EM-43 permits.

### The unblock command

21. **`twinvpn-unblock` checks uid 0 and not MI-13(1)'s ceremony.** MI-13(1)
    requires "the **same OS-mediated administrator authentication** as §11.14's
    ceremony … `system.privilege.admin`" and is explicit that *"'privileged'
    means an authenticated administrator act, not merely 'runs as root'"*. This
    binary is the second: **a root cron job could invoke it**, which MI-13(1)
    forbids. Authorization Services is not linked (gap 15's framework). Named
    rather than papered over by calling `sudo` the ceremony. `shells/linux` makes
    the same trade with `CAP_NET_ADMIN`, so the two shells are consistently
    short of the same rule.

22. **The `UnblockRecord`'s `invoked_at` is `null`.** MI-13(3) names the field;
    CD-1a makes the wall clock evidence-only and three-state, this binary injects
    no `Env` and therefore holds no clock with a declared trust state, and a
    `SystemTime::now()` here would put an untrusted reading into a record that
    reads as authoritative. The authority stamps its own reading when it ingests
    the record. **Whether that is acceptable is MI-13's owner's to say.**

23. **Nothing ingests the `UnblockRecord`.** MI-13(4) requires the authority at
    next start to emit `MGMT.UNBLOCK_INVOKED` into the Tier-0 ledger and the
    `mgmt` topic and hold a persistent `PERMISSIVE_ANNOUNCED` indication until
    the `Owner` re-arms. The record is **written** and never **read**: the start
    sequence has no step for it. The write half is the half that cannot be added
    later without losing the crashes it exists to explain, which is why it is the
    half that exists.

24. **MI-12 names `ksd` as the unblock's serving component on macOS, and this
    build does not serve it there.** MI-12's list is "`twinvpn-killswitch` on
    Linux, the installer-written persistent set on Windows, **`ksd` on macOS**",
    which reads as though `ksd` should accept the unblock as a request — and
    §11.2 does say `ksd` "MUST NOT accept any request **other than** … (b) the
    unblock command's local, admin-authenticated invocation", implying there is a
    request to accept. This build instead makes `twinvpn-unblock` a
    self-contained privileged binary, matching `shells/linux` and MI-12's own
    first sentence ("MUST NOT depend on … any MI channel"). **Reported as a
    reading, not resolved:** a Mach service on `ksd` is a channel with exactly the
    availability problem the rule exists to avoid, and two shells behaving
    differently on one rule is worse than either.

### The adapter's own gaps, restated here because they are the shell's problem

25. **`NetworkConfig::query_link_facts` is not implemented.** It needs the
    underlay's MTU, families, per-family default routes, resolvers and power
    posture — five reads across `getifaddrs`, a `PF_ROUTE` table dump and
    `SCDynamicStore`, none exercisable here. It returns the registered "cannot
    answer" condition rather than inventing facts: `UnderlayFamilies` is what
    ADR-0010 §11.7 branches three ways on, and a wrong answer there is a v6-only
    network silently treated as dual-stack.

26. **`TunnelProvenance::AdapterCreatedUtun` is not implemented, and after X-7
    nothing in this shell selects it.** The `PF_SYSTEM`/`SYSPROTO_CONTROL` open,
    `set_link` and `SIOCSIFMTU` refuse by name. The constants, the
    `ctl_info`/`sockaddr_ctl` layouts and the `_IOWR('N', 3, …)` encoding are
    written and their sizes asserted; the syscalls are not. The authority is the
    provider and is handed a flow, so the unimplemented path is now **dead in
    this shell** — it is kept because ADR-0016 §14(2) names MX-3 (a `LaunchDaemon`
    owning `utun`) as the fallback if Apple refuses the NE entitlement.

27. **`InterfaceProvider::enumerate` has no Darwin source.** The classifier, the
    ownership rule and the facts conversion are tested; `getifaddrs` and
    `SCNetworkInterfaceGetInterfaceType` are not wired, and enumeration
    **refuses** rather than reporting an empty host.

28. **No `PF_ROUTE` socket reader and no IOKit registration.** The decoders
    (`rtmsg`, `power`) are complete and tested against hand-built Darwin messages;
    nothing opens the socket or calls `IORegisterForSystemPower`. What *does* now
    reach the core is the NE-sourced half: `tvb_ext_sleep`, `tvb_ext_wake` and
    `tvb_ext_network_changed` publish into **the adapter's own** interface
    provider, which the core subscribes to. Wave 2 published them into a second
    provider nothing subscribed to — harmless with no core, and a silently
    deaf reconciler the moment there was one.

29. **The Darwin constants were written from the headers and checked against no
    running kernel.** `IPV6_BOUND_IF = 125`, `IP_DONTFRAG = 28`, `AF_INET6 = 30`,
    `CTLIOCGINFO`, the `xucred` layout, the IOKit message numbers, and now the
    eight-word `audit_token_t` layout. Internal consistency is asserted (sizes,
    offsets, the `_IOWR` encoding, the token's field offsets); Apple's actual
    numbers are a compile-and-review claim.

30. **The Keychain and `SCDynamicStore` shims are compile-only.** ~450 lines of CF
    ownership discipline that `make cross-check` type-checks against the real sys
    crates and that has never allocated a `CFString`. The Keychain half matters
    more than it did: the key handle is the extension's now, and §11.14 (g)
    requires it to be openable with no user logged in.

31. **No Secure Enclave signer.** `AbsentElement` reports `hardware_backed:
    false` truthfully and refuses, which §11.16 (l) requires over silently
    substituting a file-backed one. `custody_class` is therefore `ABSENT` on every
    build here.

32. **`record_aead_custody` is `CoreHeld` on every macOS row.** The Secure Enclave
    performs ECIES and signing and offers no general AEAD over caller-supplied
    data, so ADR-0020's survey ("2 of 10 targets") does not include macOS.
    Declared, not inferred.

33. **`StoreRootAttributes::backup_excluded` reports `false`.** ADR-0020 needs
    `NSURLIsExcludedFromBackupKey` *and* a `tmutil addexclusion`; the first is a
    Foundation API this crate does not link and the second is the installer's.
    Reporting `true` would be the core recording an exclusion nobody applied.

34. **`SocketOptions::firewall_mark` has nowhere to go.** Darwin has no `SO_MARK`
    and no policy routing table; the function it serves is served by
    `IP_BOUND_IF`, which is a different mechanism with a different failure mode.
    Reported in `SocketOptionPlan::unsupported` rather than quietly mapped.

35. **`recv_from` does not collect the control data it asked for.** The `cmsg`
    parser is written and tested, and the read path uses `recv_from`, which
    discards ancillary data — so `Datagram::destination` and `::interface` are
    `None` and `truncated` is always `false`. §3.4's reflexive-candidate
    attribution needs the first two.

36. **`RouteEntry::metric` is dropped.** macOS `route(8)` has no metric;
    preference comes from prefix length and network service order.
    `RouteOp::metric_unrepresentable` reports it per operation. Under the
    provider binding the routes are the OS's anyway
    (`RouteCarrier::TunnelSettings`), so this now bites only the MX-3 fallback.

37. **The wall clock declares `Unsynchronised`.** macOS exposes no NTP-sync fact
    through an API this crate reaches, so a reading is `Offset`, never `Trusted`.
    CD-1a makes that the safe direction; anything needing a trusted wall clock
    will not silently get an untrusted one.

38. **`EnforcementConfig::doh_endpoints` and `on_link_prefixes` are empty at
    start.** ADR-0011 §11.9's known-DoH list is an installation fact the seam does
    not carry; KS-4's on-link set is recomputed per network-change event, which
    needs gap 28. Both empty fail **closed**.

39. **The resolver engine of this binding refuses by name.** Under
    `ResolverCarrier::TunnelSettings` the OS installs the resolver from the
    settings document, so `host::NoResolver` is the honest engine to inject: a
    `DynamicStoreEngine` beside it would be a **second writer** for a fact
    `NEPacketTunnelNetworkSettings.dnsSettings` already owns, which is the I8
    defect rather than a belt-and-braces measure. The `SCDynamicStore` code is
    therefore unreachable from this shell — kept for the MX-3 fallback, like
    gap 26.

### The bridge

40. **`causation_id` has no field in the bridge ABI.** §6 rule 6 asks for
    correlation *and* causation across every boundary; the Swift side carries both
    and the second is dropped at this hop. The three `tvb_mgmt_*` entries carry
    **neither**, which is worse: an MI request's correlation id lives in the
    envelope and is therefore opaque to the ABI, so a bridge log line about a
    management exchange cannot be joined to the request it served.

41. **`tvb_ext_app_message` refuses**, now with `MGMT.PRINCIPAL_UNVERIFIABLE`
    rather than wave 2's `MGMT.UNAVAILABLE`. The MI exists; the
    `sendProviderMessage` hop carries no peer credential and MI-A1 requires one.
    The symbol stays exported because F-1 makes it permanent.

42. **The bridge bounds `correlation_id` at 64 bytes, which is its own choice.**
    `limits.json`'s `correlation_id_bytes = 16` is the *binary* width and the ABI
    carries the 36-byte UUID text; 64 matches the registry's largest identifier
    bound. Stated as a choice.

43. **The bridge's error envelope is JSON where `twinvpn-ffi`'s is protobuf**, for
    the same ADR-0015 §11.2 document — chosen because Swift logs it as UTF-8 text.
    Field names are §11.2's verbatim, so a switch is a re-encoding.

44. **`twinvpn-bridge/src/lib.rs` is over the 500-line rule**, and further over it
    than in wave 2. All 17 exported symbols must be in one file for the
    header-drift test to be sure it has seen the whole surface — the same reason
    `twinvpn-ffi/src/lib.rs` is 779. Everything that is not an `extern "C"`
    signature was pushed into `abi`, `report`, `host`, `config`, `probes`,
    `start` and `mgmt/*`. Two of those are over the limit too and for a worse
    reason — `start.rs` and `tests.rs` are long because their test modules are,
    and `mgmt/server.rs`'s was split into `server_tests.rs` rather than left to
    grow.

### Packaging

45. **Nothing is signed, notarized or stapled.** `SIGNING.md` is procedure. No
    Xcode project and no `Package.swift`: SwiftPM cannot produce a
    `.systemextension` bundle, and a manifest that can never build the product
    would be noise. There is also **no bridging header**, which
    `TwinVPNXPCShim.h` needs to be in.

46. **`NEMachServiceName` on a packet-tunnel system extension is unconfirmed**,
    and so is whether a client that is not the containing app can reach a service
    vended that way. It is required for some provider kinds (app-proxy,
    DNS-proxy) and this domain has not confirmed which list packet-tunnel is on.
    **If it turns out that only the containing app can connect, the XPC carriage
    serves the app and the CLI keeps the socket** — which is exactly the split
    ADR-0017 §11.2's macOS row already describes, so the architecture survives
    either answer. That is why both carriages exist.

47. **`SMAppService` vs the pkg form.** The `ksd` plist is the pkg form (absolute
    `ProgramArguments`); the `SMAppService.daemon(plistName:)` form needs
    `BundleProgram` and the plist inside the app bundle. Whether one plist serves
    both is untested.

48. **The boot anchor emits 11 of the runtime anchor's 19 labels.** `lan.*`,
    `mcast.*`, `protected.*` and `deny.fwd.*` need `local_network_access`, the
    on-link prefixes and the overlay interface, none of which exist before the
    authority runs. The read-back parser requires no label to be present, so this
    is correct rather than merely tolerated.

49. **`deny.dns` in the *boot* anchor is scoped to the protected tables, not a
    blanket port 53/853 deny.** A blanket DNS deny in the boot artifact would take
    the host off name resolution before the authority exists. Full class-6
    containment is the runtime anchor's.

50. **`100.64.0.0/10` is RFC 6598 *carrier* space.** A Mac behind CGNAT
    legitimately holds an address in it, and the Tier-2 outbound deny will also
    block that Mac's traffic to a `100.64.x.x` DHCP or DNS server. Linux has
    identical behaviour, so this shell matches it rather than deviating — but it
    is a real-world hazard neither ADR-0010 nor ADR-0012 names.

51. **ADR-0012 §11.6's own macOS residual, restated:** *"Recovery and safe boot do
    not load the LaunchDaemon. Residual exposure: a device booted to Recovery is
    unprotected."*

52. **The `.pkg` cannot install the authority.** The system extension is inside
    the app and activated by `OSSystemExtensionRequest` with administrator
    approval; `install.sh` installs `ksd`, the anchor, `twinvpn-unblock` and the
    CLI, and cannot make the authority exist. That is Apple's model rather than a
    gap in the script, but it means a **fresh install has no core until a user
    opens the app and approves**, which the KS-19 boot anchor is what covers.

### Toolchain

53. **`make cross-check` now covers the whole shell, including the core-hosting
    path.** Wave 2 recorded the opposite as gap 48, with a request: "if
    `twinvpn-crypto` selected `snow`'s pure-Rust resolver rather than
    `ring-accelerated`, the feature could be default and the whole shell would be
    cross-checked." `core/Cargo.toml` did exactly that. **The request is
    discharged**, and the first full run of the newly-covered code found real
    defects — see gap 28 and the §4 note about `from_std` outside a runtime.
