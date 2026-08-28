# The macOS shell — `twinvpnd`, `twinvpnctl`, `twinvpn-bridge` and the system extension

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
| `twinvpn-bridge` (Rust) | yes, `-D warnings` | **yes, on Linux** — 66 tests |
| `twinvpnd` (Rust) | yes, `-D warnings` | **yes, on Linux** — 76 tests |
| `twinvpnctl` (Rust) | yes, `-D warnings` | **yes, on Linux** — 22 tests |
| `TwinVPNTunnel/*.swift` | **no.** Swift 6.1.2 here is the Linux toolchain with no Darwin SDK: no `NetworkExtension`, no `Security`, no `SystemConfiguration` | **no** |
| `packaging/*` | n/a | **no** |

A green `make cross-check` is a **compile proof and never a behaviour proof**, and
it must not be reported as one.

---

## 1. What is here

| Path | What |
|---|---|
| `twinvpnd/` | the privileged `LaunchDaemon`, **and** the `mi` module both Rust binaries share |
| `twinvpnctl/` | the unprivileged CLI |
| `twinvpn-bridge/` | the Rust staticlib the Swift provider links, and the C header that is the ABI of record between them |
| `TwinVPNTunnel/` | the `NEPacketTunnelProvider` system extension, in Swift |
| `TwinVPNApp/` | the host app's system-extension installer, in Swift |
| `packaging/pf.anchor` | the **KS-19 boot artifact**: the fail-closed ruleset in force before the daemon runs |
| `packaging/pf.conf.include` | the lines a package adds to `/etc/pf.conf` |
| `packaging/com.twinvpn.ksd.plist` | the `LaunchDaemon` that applies the boot anchor (`RunAtLoad`) — **package-owned** (PS-7) |
| `packaging/com.twinvpn.twinvpnd.plist` | the authority's `LaunchDaemon` |
| `packaging/*.entitlements`, `*.Info.plist` | the system extension's and the app's |
| `packaging/SIGNING.md` | Developer ID signing, notarization and stapling, **as documented procedure that has never been run** |
| `packaging/install.sh` | an idempotent installer, **never executed** |

The adapter these bind is
[`core/crates/twinvpn-platform-macos`](../../core/crates/twinvpn-platform-macos),
which this domain also owns. **163 of its tests execute on the Linux host**: the
pf anchor's text and its `pfctl` read-back parser, the route programme, the
`NEPacketTunnelNetworkSettings` document, the resolver programme, the `PF_ROUTE`
decoder, the mach timebase arithmetic, the power state machine, and the whole
apply/rollback transaction against recording carriers.

### Why `twinvpnd` is a library as well as a binary

ADR-0017 MI-20 and ADR-0018 §11.16 (b) require *"one contract, two carriages,
**never two contracts**"*. The MI envelope, its framing and its client are
declared **once**, in `twinvpnd`'s `mi` module, and `twinvpnctl` depends on that
crate with `default-features = false` — which excludes the whole `agent` feature,
so the unprivileged CLI links no pf, no route programme, no `SCDynamicStore` and
no core-hosting code.

### Why the core is behind a non-default feature

`twinvpn-core` pulls `twinvpn-crypto` → `snow` → `ring`, whose C sources are
compiled by a build script. There is no Darwin C toolchain on this host, so
`cargo clippy --target aarch64-apple-darwin` fails inside `ring`'s build script
**before it type-checks a line of ours**. So the MI server's edge onto the core is
a one-method trait (`agent::server::CommandSink`, which is PS-4's typed vocabulary
anyway), everything above it is default-on and cross-checked, and only the ~30
lines in `main.rs` that *construct* a `Core` are behind `core-host`. See §7 gap 3.

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
cd core         && cargo test -p twinvpn-platform-macos   # 163 tests
cd ../shells/macos && cargo test --workspace --all-features  # 164 tests

# Everything that can be type-checked for Darwin, is:
cd ../.. && make cross-check                              # -D warnings, nothing linked
```

`twinvpnd` **will refuse to start on Linux**, at the `clocks` step, and that is
correct: `ContinuousElapsedClock::from_kernel()` returns `None` off Darwin, and a
clock with a guessed timebase is wrong by a factor of 41 on Apple silicon.

### On a Mac — the procedure, never performed

```sh
# 1. The principals. The PACKAGE creates them; the agent never does (PS-12a).
sudo dscl . -create /Groups/twinvpn            # OBSERVE
sudo dscl . -create /Groups/twinvpn-operators  # OPERATE
sudo dscl . -create /Groups/twinvpn-admins     # ADMINISTER

# 2. The KS-19 boot artifact, the anchor, the daemon, the endpoint directory.
sudo ./packaging/install.sh

# 3. Build. `core-host` is not default -- see §1.
cd shells/macos && cargo build --release --features core-host

# 4. The system extension is installed by the APP, through
#    OSSystemExtensionRequest, and requires a Developer ID signature and
#    notarization: see packaging/SIGNING.md.
```

To grant a person read access, add them to `twinvpn`; to let them connect and
disconnect, add them to `twinvpn-operators`. **Built-in `staff` and `admin` are
deliberately not used** — PS-12a: *"'every local account can enumerate this
device's peers and endpoints' should be an install-time decision (TB-13), not a
platform default."* A membership change takes effect **on the next attach**
(S-44: re-derived at every attach, never cached across attaches).

---

## 4. The start sequence, and what each step refuses

ADR-0016 §11.6, in order. `agent::start::StartSequence` is this table as a value
the diagnostic bundle can carry; `agent::start`'s tests exercise every row on this
Linux host against injected probes.

| Step | On failure |
|---|---|
| 1. the KS-19 boot artifact is installed | `PLATFORM.ADAPTER_UNAVAILABLE` as a **warning** — and the agent starts anyway. §11.6 step 1 reads as a refusal and PS-7 says the artifact "MUST NOT be a prerequisite for [the authority] to apply"; `desktop-linux` read the pair as warn-and-continue and this shell takes the **same** reading, because two shells behaving differently on one rule is worse than either. See §7 gap 1 |
| 2. the privilege posture | **Fatal** if not root: pf, the route socket and `SCDynamicStore` all require it, and PS-18 forbids starting in a mode that cannot arm enforcement. Root **is itself a named degradation** (`PLATFORM.PRIV.SANDBOX_DEGRADED`), because macOS has no spelling of "this capability and nothing else" — see §7 gap 2 |
| 3. the three clocks, the CSPRNG and the boot identity | **Fatal.** `mach_absolute_time` is suspend-**exclusive** and `mach_continuous_time` is suspend-**inclusive** (ADR-0022 LC-8); the timebase is read once and a failed read refuses rather than guessing. The CSPRNG is **probed at startup**, not on first use |
| 3b. the runtime's I/O driver (**W-43**) | **Fatal.** Fixed upstream (`enable_io()` is on both `TokioRuntime` constructors now), and the probe stays: PS-18's rule is to refuse at startup rather than report a running agent that panics on the first command |
| 4. the adapter's capability probe | **Fatal** if `pfctl(8)` is absent — ADR-0012 §8: arming must never fail open. A KS-9(1) predicate that holds only in its weaker uid-only form is a **named degradation**, never silently upgraded |
| 4b. reclaim the owner-tagged ruleset (KS-20, PS-8) | **Fatal.** The ruleset is reclaimed *and then* **read back from pf** — `pfctl -s info` for whether the filter is even on, and `pfctl -a twinvpn -s Tables` for the posture, the generation and the per-family scope cardinality. That is the **W-24 query**, not the fact that a load returned `Ok`, and `DarwinProbes::with_read_back` takes an `Assertion` precisely so a boolean cannot be set any other way |
| 5. durable state | **Fatal** if the vault directory is not `0700`. A vault the group can read is a vault every local account can read |
| 6. the core | **Fatal**, `INTERNAL.ABI_VERSION_MISMATCH` (VR-4), checked before any capability is touched. In a build without `core-host` this step refuses, which is the honest outcome |
| 7. the MI endpoint | **Fatal**, `MGMT.UNAVAILABLE`. MI-A3: the agent verifies `/var/run/twinvpn`'s ownership and mode **before** binding, binds a staging name, sets the mode and group, then `rename`s it — `unlink()`-then-`bind()` is prohibited and the word does not appear in the module |
| 8. accept connections | only now (§11.6) |

`twinvpnd` also **warns and continues** on: no recognised supervisor (PS-11), the
root-with-no-narrowing posture (PS-17), a KS-9 predicate that holds only in its
weaker form, and a peer whose kernel group list was full and may be truncated.

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
TWINVPN_LOG_LEVEL=trace TWINVPN_LOG_FORMAT=text sudo ./target/debug/twinvpnd
```

### Running the tests

```sh
cd core            && cargo test -p twinvpn-platform-macos    # 163, unprivileged
cd ../shells/macos && cargo test --workspace --all-features   # 164, unprivileged
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

Each of these is a gap this wave did not close, with the reason.

### The one that matters most

1. **No line of Swift has been compiled.** Swift 6.1.2 is installed and it is the
   **Linux** toolchain: there is no Darwin SDK, so `NetworkExtension`, `Security`
   and `SystemConfiguration` do not exist here. `swiftc -parse` was run over all
   six files and they parse — a syntax check with a planted error confirming it
   has teeth — and that is **all**: no type-check, no name resolution, no
   concurrency checking, no API-existence check. Every NE API shape, every
   `Codable` field name, every `os.Logger` call and every actor boundary in
   `TwinVPNTunnel/` is unverified. This is the single largest risk in the
   directory, and it is why the Swift surface was kept to a `Codable` struct, a
   buffer wrapper and two loops: **every decision is on the Rust side, where it is
   tested.**

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

### The privilege model

3. **`twinvpnd` runs as root and cannot narrow itself.** ADR-0016 §11.2 says the
   authority "MUST NOT continue as root 'just this once'", and Linux discharges it
   by dropping to `CAP_NET_ADMIN`. **macOS has no spelling of "this capability and
   nothing else"**: pf, the `PF_ROUTE` socket and `SCDynamicStore` all require
   root, and the equivalents of `systemd`'s hardening directives — hardened
   runtime, library validation — are set at *codesign* time rather than by the
   supervisor. The start sequence reports this as a `PLATFORM.PRIV.SANDBOX_DEGRADED`
   degradation on **every** start rather than letting a reader assume a sandbox
   that is not there. **Needs a decision** from ADR-0016's owner.

4. **ADR-0016 §11.2's macOS row does not contain a `twinvpnd`.** It says the
   system extension *is* the authority and `com.twinvpn.ksd` is not a
   general-purpose helper. This shell adds a third root component that hosts the
   core, owns the pf anchor and serves the MI. The reason is **W-24 and W-25**:
   `twinvpn.h`'s F-9 vtable has no socket capability, no interface enumeration, no
   `installed_ruleset` read-back and no `current_generation`, so a Swift-only
   system extension bound to the C ABI **cannot do NAT traversal and cannot
   produce a `ProtectionAssertion` at all**. **§11.2's macOS row needs
   re-deriving** by the integration lead.

5. **`com.twinvpn.sysext` is not a legal system-extension bundle id.** A system
   extension's identifier must be prefixed by its containing app's, so the ADR
   names a component the platform cannot spell. The packaging uses
   `com.twinvpn.app.sysext`. Reported, not resolved.

6. **MI-A3 is discharged by the installer, not by the supervisor.** `systemd` has
   `RuntimeDirectory=`, which recreates `/run/twinvpn` with the right owner and
   mode on every start; `launchd` has no equivalent. So `/var/run/twinvpn` is
   created once by `install.sh` and `twinvpnd` **verifies and refuses** rather
   than creating it. That is genuinely weaker — the installer runs once, the
   supervisor every boot — and after a `/var/run` wipe the agent will not start
   until the directory is restored.

7. **`launchd` expresses almost none of ADR-0016 §11.9's hardening table.** No
   `ProtectSystem`, `PrivateDevices`, `RestrictAddressFamilies` or
   `SystemCallFilter` equivalents exist. The plists say so in their headers, so
   their shortness is not read as containment.

8. **`launchd` has no burst limit**, so `KeepAlive` alone does not discharge PS-9
   or PS-10. ADR-0016 §11.5's macOS row makes crash-loop containment the
   authority's own durable restart counter (S-40) latching quarantine itself.
   **That counter is not implemented.**

9. **One `unsafe` block, and it is load-bearing.** `#![deny(unsafe_code)]` with
   exactly one `#[allow]`, at `agent::peer::PeerCredentials::read`: MI-A1 requires
   a kernel-sourced principal, `getsockopt(LOCAL_PEERCRED)` is the only source on
   Darwin, and no safe wrapper exists in `std` or in any dependency this shell
   has. `twinvpnd::tests::the_crate_allows_unsafe_in_exactly_one_place` asserts
   the budget. (`shells/linux` forbids `unsafe` outright and loses
   `getgrouplist(3)` for it — a trade available there because the group list
   *refines* the principal, and not available here because `LOCAL_PEERCRED` *is*
   the principal.)

10. **`xucred` carries at most 16 groups.** A principal in more than sixteen
    groups may have the relevant one truncated away by the kernel. It fails
    **closed** — fewer scopes than intended — and the agent logs a warning when
    the list came back full.

### The management interface

11. **No event stream.** `event.subscribe` reaches the core and the core accepts
    it, but the agent pushes no `Event` frames, and `event.resync` is unwired. The
    `Compacted` marker (MI-19) and §11.10's eviction ladder are therefore
    unexercised.

12. **No ADMINISTER ceremony.** Every ADMINISTER operation is **refused**, not
    performed on a scope alone — §11.5's third consequence and the safe direction.
    Wiring it needs Authorization Services (`system.privilege.admin`, KS-21's
    macOS mechanism), which is a Darwin framework this crate does not link.

13. **No XPC.** ADR-0017 §11.2 *prefers* XPC to `com.twinvpn.agent.mgmt` on this
    platform; this wave is `AF_UNIX` only. The name is fixed in one place
    (`mi::XPC_SERVICE_NAME`) and the `LaunchDaemon` plist deliberately does **not**
    declare `MachServices`: a declared service with no server behind it reproduces
    exactly the hang MI-A3 rejects socket activation for.

14. **`SOCK_STREAM` + length prefix, not `SOCK_SEQPACKET`.** §11.2 prefers the
    latter "so message boundaries are kernel-preserved"; `tokio`'s `UnixListener`
    is `SOCK_STREAM` only. The cost is exactly the one §11.2 names, bounded by the
    1 MiB cap being enforced **before any allocation**.

15. **The MI envelope is declared in this shell, and in `shells/linux` too.**
    ADR-0017 §11.3's message appears **nowhere in `contracts/`** —
    `phase1-conflicts.md` OQ-2 excluded an MI transport schema from Phase 2 so the
    MI could not acquire an independent vocabulary. It worked for the *vocabulary*
    (both shells use `twinvpn_mgmt`'s command set) and left the **carriage**
    unspecified, with the consequence that two shells now carry two copies of one
    envelope. **Request: move it into `core/crates/twinvpn-mgmt`**, which is
    `core-foundation`'s.

16. **`committed_at_net_seq` is always absent, and correctly so.** MI-6's cursor
    is "a real, monotone position in the same log" the C2 stream replays; a
    locally-mutating operation reaches no C1 request and has none. Reporting a
    per-process counter there would tell a client it had read-your-writes when it
    had not.

17. **`platform_ctx.os_version` is empty.** The real answer is
    `sysctl kern.osproductversion`, which is Darwin-only and not wired. MI-C3
    requires clients to use the value **verbatim**, so an empty string renders as
    unknown rather than as a wrong version — the right failure.

18. **The binary is `twinvpnctl`, and ADR-0016 §11.2 / ADR-0017 §11.12 name it
    `twinvpn`.** ADR-0023 EM-42's rendered next actions say `run 'twinvpn peer
    disconnect nas-attic'`, which names a command installed under another name.
    `shells/linux` raised the same deviation; this shell matches it rather than
    having the CLI called one thing on Linux and another on macOS. **Needs a
    decision.**

19. **No `twinvpn-unblock`.** KS-20a makes a privileged local unblock command
    mandatory on macOS (one of the four platforms where it is satisfiable), and
    MI-12/MI-13 specify it. It is a separate package-owned binary, not a
    subcommand, "precisely because the case it exists for is 'the authority will
    not start'". Not written, not in `install.sh`, not in `SIGNING.md`.

20. **`isatty` is not called**, because it needs `unsafe`. `twinvpnctl` therefore
    assumes **not a TTY**, which under EM-43 means no colour ever. The UTF-8
    decision still follows `LANG`/`LC_ALL`. Conservative and always correct, and
    less than EM-43 permits.

### The adapter's own gaps, restated here because they are the shell's problem

21. **`NetworkConfig::query_link_facts` is not implemented.** It needs the
    underlay's MTU, families, per-family default routes, resolvers and power
    posture — five reads across `getifaddrs`, a `PF_ROUTE` table dump and
    `SCDynamicStore`, none exercisable here. It returns the registered "cannot
    answer" condition rather than inventing facts: `UnderlayFamilies` is what
    ADR-0010 §11.7 branches three ways on, and a wrong answer there is a v6-only
    network silently treated as dual-stack.

22. **`TunnelProvenance::AdapterCreatedUtun` is not implemented.** The
    `PF_SYSTEM`/`SYSPROTO_CONTROL` open, `set_link` and `SIOCSIFMTU` refuse by
    name. The constants, the `ctl_info`/`sockaddr_ctl` layouts and the
    `_IOWR('N', 3, …)` encoding are written and their sizes asserted; the syscalls
    are not. **The `LaunchDaemon` therefore cannot create a tunnel interface**;
    only the OS-provided (system-extension) path can.

23. **`InterfaceProvider::enumerate` has no Darwin source.** The classifier, the
    ownership rule and the facts conversion are tested; `getifaddrs` and
    `SCNetworkInterfaceGetInterfaceType` are not wired, and enumeration **refuses**
    rather than reporting an empty host.

24. **No `PF_ROUTE` socket reader and no IOKit registration.** The decoders
    (`rtmsg`, `power`) are complete and tested against hand-built Darwin messages;
    nothing opens the socket or calls `IORegisterForSystemPower`, so no change ever
    reaches `MacosInterfaceProvider::publish` at runtime.

25. **The Darwin constants were written from the headers and checked against no
    running kernel.** `IPV6_BOUND_IF = 125`, `IP_DONTFRAG = 28`, `AF_INET6 = 30`,
    `CTLIOCGINFO`, the `xucred` layout, the IOKit message numbers. Internal
    consistency is asserted (sizes, offsets, the `_IOWR` encoding); Apple's actual
    numbers are a compile-and-review claim.

26. **The Keychain and `SCDynamicStore` shims are compile-only.** ~450 lines of CF
    ownership discipline that `make cross-check` type-checks against the real sys
    crates and that has never allocated a `CFString`.

27. **No Secure Enclave signer.** `AbsentElement` reports `hardware_backed: false`
    truthfully and refuses, which §11.16 (l) requires over silently substituting a
    file-backed one. `custody_class` is therefore `ABSENT` on every build here.

28. **`record_aead_custody` is `CoreHeld` on every macOS row.** The Secure Enclave
    performs ECIES and signing and offers no general AEAD over caller-supplied
    data, so ADR-0020's survey ("2 of 10 targets") does not include macOS.
    Declared, not inferred.

29. **`StoreRootAttributes::backup_excluded` reports `false`.** ADR-0020 needs
    `NSURLIsExcludedFromBackupKey` *and* a `tmutil addexclusion`; the first is a
    Foundation API this crate does not link and the second is the installer's.
    Reporting `true` would be the core recording an exclusion nobody applied.

30. **`SocketOptions::firewall_mark` has nowhere to go.** Darwin has no `SO_MARK`
    and no policy routing table; the function it serves is served by
    `IP_BOUND_IF`, which is a different mechanism with a different failure mode.
    Reported in `SocketOptionPlan::unsupported` rather than quietly mapped.

31. **`recv_from` does not collect the control data it asked for.** The `cmsg`
    parser is written and tested, and the read path uses `recv_from`, which
    discards ancillary data — so `Datagram::destination` and `::interface` are
    `None` and `truncated` is always `false`. §3.4's reflexive-candidate
    attribution needs the first two.

32. **`RouteEntry::metric` is dropped.** macOS `route(8)` has no metric; preference
    comes from prefix length and network service order. `RouteOp::metric_unrepresentable`
    reports it per operation.

33. **The wall clock declares `Unsynchronised`.** macOS exposes no NTP-sync fact
    through an API this crate reaches, so a reading is `Offset`, never `Trusted`.
    CD-1a makes that the safe direction; anything needing a trusted wall clock
    will not silently get an untrusted one.

34. **`EnforcementConfig::doh_endpoints` and `on_link_prefixes` are empty at
    start.** ADR-0011 §11.9's known-DoH list is an installation fact the seam does
    not carry; KS-4's on-link set is recomputed per network-change event, which
    needs gap 24. Both empty fail **closed**.

### The bridge

35. **No core handle in `twinvpn-bridge`.** `tvb_ext_start` succeeds and
    `tvb_ext_next_settings` refuses with `PLATFORM.ADAPTER_UNAVAILABLE`, because
    no `NetworkContract` is computed. That places the refusal where NE actually
    fails the start (`startTunnel` completes only once settings are applied) while
    leaving the datapath, the lifecycle facts, the buffer discipline and the panic
    containment reachable and tested through the real C surface.

36. **`causation_id` has no field in the bridge ABI.** §6 rule 6 asks for
    correlation *and* causation across every boundary; the Swift side carries both
    and the second is dropped at this hop.

37. **`tvb_ext_app_message` refuses.** No in-process MI is wired into the
    extension, so `handleAppMessage` has nothing to answer with.

38. **The bridge bounds `correlation_id` at 64 bytes, which is its own choice.**
    `limits.json`'s `correlation_id_bytes = 16` is the *binary* width and the ABI
    carries the 36-byte UUID text; 64 matches the registry's largest identifier
    bound. Stated as a choice.

39. **The bridge's error envelope is JSON where `twinvpn-ffi`'s is protobuf**, for
    the same ADR-0015 §11.2 document — chosen because Swift logs it as UTF-8 text.
    Field names are §11.2's verbatim, so a switch is a re-encoding.

40. **`twinvpn-bridge/src/lib.rs` is 556 lines**, over the 500-line rule. All 14
    exported symbols must be in one file for the header-drift test to be sure it
    has seen the whole surface — the same reason `twinvpn-ffi/src/lib.rs` is 779.

### Packaging

41. **Nothing is signed, notarized or stapled.** `SIGNING.md` is procedure. No
    Xcode project and no `Package.swift`: SwiftPM cannot produce a
    `.systemextension` bundle, and a manifest that can never build the product
    would be noise.

42. **`NEMachServiceName`, the App Group prefix, and whether a system extension
    uses the same `NEProviderClasses` keys as an app extension** are all
    unconfirmed. `com.apple.developer.networking.vpn.api` is on both bundles and
    one is probably redundant.

43. **`SMAppService` vs the pkg form.** The plists are the pkg form (absolute
    `ProgramArguments`); the `SMAppService.daemon(plistName:)` form needs
    `BundleProgram` and the plist inside the app bundle. Whether one plist serves
    both is untested.

44. **The boot anchor emits 11 of the runtime anchor's 19 labels.** `lan.*`,
    `mcast.*`, `protected.*` and `deny.fwd.*` need `local_network_access`, the
    on-link prefixes and the overlay interface, none of which exist before the
    authority runs. The read-back parser requires no label to be present, so this
    is correct rather than merely tolerated.

45. **`deny.dns` in the *boot* anchor is scoped to the protected tables, not a
    blanket port 53/853 deny.** A blanket DNS deny in the boot artifact would take
    the host off name resolution before the authority exists. Full class-6
    containment is the runtime anchor's.

46. **`100.64.0.0/10` is RFC 6598 *carrier* space.** A Mac behind CGNAT
    legitimately holds an address in it, and the Tier-2 outbound deny will also
    block that Mac's traffic to a `100.64.x.x` DHCP or DNS server. Linux has
    identical behaviour, so this shell matches it rather than deviating — but it
    is a real-world hazard neither ADR-0010 nor ADR-0012 names.

47. **ADR-0012 §11.6's own macOS residual, restated:** *"Recovery and safe boot do
    not load the LaunchDaemon. Residual exposure: a device booted to Recovery is
    unprotected."*

### Toolchain

48. **`make cross-check` does not type-check `twinvpnd`'s core-hosting path.**
    `core-host` is not a default feature because `ring`'s C sources cannot be
    cross-compiled here — see §1. `cargo test --workspace --all-features` on Linux
    does compile and exercise it. **Request:** if `twinvpn-crypto` selected
    `snow`'s pure-Rust resolver rather than `ring-accelerated`, the feature could
    be default and the whole shell would be cross-checked.
