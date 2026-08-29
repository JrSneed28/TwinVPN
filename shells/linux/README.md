# The Linux shell — `twinvpnd`, `twinvpnctl` and `twinvpn-unblock`

**Owner:** `desktop-linux`.
**Authority:** [ADR-0016](../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
(the privilege split), [ADR-0017](../../docs/adr/ADR-0017-local-management-interface.md)
(the local MI), [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.1 and §11.12 (CB-1, CB-2, the layout),
[ADR-0023](../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md) (the
headless surface). This host is ADR-0016 class **HC-3**, profile **H-SRV**.

---

## 1. What is here

| Path | What |
|---|---|
| `twinvpnd/` | the privileged agent, **and** the `mi` module both binaries share |
| `twinvpnctl/` | the unprivileged CLI |
| `twinvpn-unblock/` | the **KS-20a offline recovery command**: privileged, local, network-independent, and linking *neither* `twinvpnd` nor the core, because the case it exists for is "the authority will not start" |
| `packaging/twinvpnd.service` | the authority unit — every directive is ADR-0016 §11.9's |
| `packaging/twinvpn-killswitch.service` | the **KS-19 boot artifact**, package-owned (PS-7) |
| `packaging/killswitch.nft` | the ruleset that unit restores |
| `packaging/net.twinvpn.administer.policy` | the polkit action of PS-12a. **Deliberately unwired on this host class**: ADR-0012 KS-21a makes `SO_PEERCRED` plus the administrator class the ceremony on HC-3, so polkit is what an HC-1 build would need and not this one (§7) |

The adapter these binaries bind is
[`core/crates/twinvpn-platform-linux`](../../core/crates/twinvpn-platform-linux),
which this domain also owns.

### Why `twinvpnd` is a library as well as a binary

ADR-0017 MI-20 and ADR-0018 §11.16 (b) require *"one contract, two carriages,
**never two contracts**"*. The MI envelope, its framing and its client are
declared **once**, in `twinvpnd`'s `mi` module, and `twinvpnctl` depends on that
crate with `default-features = false` — which excludes the whole `agent` feature,
so the unprivileged CLI links no tun, no nftables, no netlink and no
core-hosting code. A copy of the framing in each binary would be the second
contract those rules forbid.

---

## 2. Environment configuration

Every variable has a default, and **the default is the production value**
(`infra/README.md`'s convention). None of them is a security control.

| Variable | Default | What it does |
|---|---|---|
| `TWINVPN_MGMT_SOCKET` | `/run/twinvpn/mgmt.sock` | the MI endpoint. ADR-0023 **EM-19** makes changing it restart-requiring, which is what a variable read once at start is. Present for local development and the component tests; the endpoint's safety comes from `SO_PEERCRED` and the directory check, wherever it points |
| `TWINVPN_LOG_LEVEL` | `info` | `trace`/`debug`/`info`/`warn`/`error`. **`critical` is accepted and mapped to `error`** — `ownership.md` §8 **W-16**, so a value copied verbatim from ADR-0015 §11.5 configures the service rather than failing it. An unrecognised value falls back to `info`: a logging misconfiguration must not be why a VPN agent will not run |
| `TWINVPN_LOG_FORMAT` | `json` under a supervisor, `text` otherwise | follows `INVOCATION_ID`, which `systemd` sets and nothing else does |
| `TWINVPN_OVERLAY_INTERFACE` | `twin0` | the overlay interface name. Tier 2 is interface-scoped, so this is the one name the whole ruleset turns on |
| `STATE_DIRECTORY` | `/var/lib/twinvpn` | set by `StateDirectory=twinvpn`. ADR-0016 O8's **0700** vault. CB-7: the path is *injected*, never discovered — and a variable the supervisor sets is an injection |
| `COLUMNS` | terminal width | `twinvpnctl` only. EM-44: wrap to `min(COLUMNS, 100)`, legible at 80 and at 40 |
| `NO_COLOR`, `TERM` | — | `twinvpnctl` only. EM-43: colour needs a TTY **and** `NO_COLOR` unset **and** a colour-capable `TERM` |
| `LANG`, `LC_ALL` | — | `twinvpnctl` only. EM-43: UTF-8 glyphs only where these indicate UTF-8. The renderer is fully legible in US-ASCII |

| `NOTIFY_SOCKET` | — | set by `systemd` for `Type=notify`. `sd_notify(READY=1)`, `WATCHDOG=1` and `STOPPING=1` go here (EM-70). Absent means no supervisor, which PS-11 makes a named degradation rather than a failure — the abstract (`@`-prefixed) form is refused rather than guessed at |

The agent reads **no configuration file**. ADR-0023 EM-11's `twinvpn config
check` and the `IntentDocument` are not in this wave (§7).

---

## 3. Local startup

### The short version, on a developer host

```sh
source build/toolchain/env.sh
cd shells/linux && cargo build

# The agent refuses to start without nft(8) — arming must never fail open
# (ADR-0012 §8) — and refuses to run as root (ADR-0016 §11.2). So a developer
# host needs nftables installed and an unprivileged user with CAP_NET_ADMIN:
sudo setcap cap_net_admin=eip target/debug/twinvpnd

mkdir -p /tmp/twinvpn && chmod 0700 /tmp/twinvpn
TWINVPN_MGMT_SOCKET=/tmp/twinvpn/mgmt.sock \
TWINVPN_LOG_FORMAT=text \
  ./target/debug/twinvpnd

# In another terminal:
TWINVPN_MGMT_SOCKET=/tmp/twinvpn/mgmt.sock ./target/debug/twinvpnctl status get
```

### The installed version

```sh
install -Dm0755 target/release/twinvpnd    /usr/lib/twinvpn/twinvpnd
# D-1: the cargo target stays `twinvpnctl`; the INSTALLED command is `twinvpn`,
# the name ADR-0016 §11.2, ADR-0017 §11.12 and ADR-0023 EM-11/EM-42 all use.
# `twinvpnctl` is kept beside it as a compatibility alias — a symlink, so there
# is one file to replace on upgrade and the two names cannot drift apart.
install -Dm0755 target/release/twinvpnctl  /usr/bin/twinvpn
ln -sfn twinvpn                            /usr/bin/twinvpnctl
install -Dm0755 target/release/twinvpn-unblock /usr/sbin/twinvpn-unblock
install -Dm0644 packaging/twinvpnd.service /etc/systemd/system/twinvpnd.service
install -Dm0644 packaging/twinvpn-killswitch.service \
                                           /etc/systemd/system/twinvpn-killswitch.service
install -Dm0644 packaging/killswitch.nft   /etc/twinvpn/killswitch.nft
install -Dm0644 packaging/net.twinvpn.administer.policy \
                /usr/share/polkit-1/actions/net.twinvpn.administer.policy

# PS-12a's principals. The PACKAGE creates them; the agent never does.
groupadd --system twinvpn
groupadd --system twinvpn-operators
useradd  --system --gid twinvpn --home-dir /var/lib/twinvpn --shell /usr/sbin/nologin twinvpn

systemctl enable --now twinvpn-killswitch.service
systemctl enable --now twinvpnd.service
```

To grant a person read access, add them to `twinvpn`; to let them connect and
disconnect, add them to `twinvpn-operators`. **Built-in `users`/`staff` groups
are deliberately not used** — PS-12a: *"'every local account can enumerate this
device's peers and endpoints' should be an install-time decision (TB-13), not a
platform default."* A membership change takes effect **on the next attach**
(S-44: re-derived at every attach, never cached across attaches).

---

## 4. The start sequence, and what each step refuses

ADR-0016 §11.6, in order. `src/agent/mod.rs`'s `StartSequence` is this table as a
value the diagnostic bundle can carry.

| Step | On failure |
|---|---|
| 1. the KS-19 boot artifact is installed | `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` at CRITICAL — **and the agent starts anyway.** PS-7 makes the artifact package-owned and says the authority "MUST NOT be a prerequisite for it to apply"; refusing would leave the host with neither the boot ruleset *nor* an agent |
| 2. the privilege posture | **Fatal** on: still root; holding `CAP_SYS_MODULE`/`CAP_SYS_ADMIN`/`CAP_DAC_OVERRIDE`/`CAP_SYS_PTRACE` **in the effective set**; or missing `CAP_NET_ADMIN`. §11.2: "the authority MUST NOT continue as root 'just this once'". A wide **bounding** set is a §11.9 hardening directive that did not apply, which PS-17 makes a named `PLATFORM.PRIV.SANDBOX_DEGRADED` warning rather than a refusal |
| 3. the three clocks and the runtime | fatal; the CSPRNG is **probed at startup**, not on first use. `CLOCK_BOOTTIME` is read with `clock_gettime(2)` and entropy with `getrandom(2)` — the `/proc/uptime` and `/dev/urandom` workarounds W-36 forced are **gone** |
| 3b. the runtime's I/O driver | fatal. W-43 is **closed** upstream (`twinvpn-env`'s `TokioRuntime` calls `.enable_io()` in both constructors), so this now passes — and it is kept, because PS-18's shape does not stop being right when the defect it guarded against is fixed. `the_injected_runtime_drives_io_so_w43_is_closed` pins the fix |
| **3c. PS-1's lock** | **Fatal.** `INTERNAL.INVARIANT_VIOLATED` — the code PS-1 names itself. A crash-surviving `flock(2)` on `/run/twinvpn/authority.lock`, taken **before the first privileged mutation of host state**, because two agents arming one host's nftables table is the race. Wave 1 had only the endpoint's bind-and-rename, which is atomic on the *name*: the second agent won the name and the first kept its socket, its `CAP_NET_ADMIN` and its belief that it was the authority |
| 4. the adapter's capability probe | fatal if `nft(8)` is absent — ADR-0012 §8: arming must never fail open, and PS-18 forbids starting "in a mode that cannot arm enforcement while reporting itself as running" |
| 4b. reclaim the owner-tagged ruleset | **Fatal.** §11.6 step (2): the ruleset is *reclaimed or re-asserted* (KS-20, PS-8) and then **read back from the kernel** — the W-24 query, not the fact that the install returned `Ok` |
| 5. the core | `INTERNAL.ABI_VERSION_MISMATCH` (VR-4), checked before any capability is touched |
| 6. the MI endpoint | `MGMT.UNAVAILABLE`. MI-A3: the agent verifies `/run/twinvpn`'s ownership and mode **before** binding, and binds a temporary name then `rename`s it — `unlink()`-then-`bind()` is prohibited |
| 6b. the event drain | a `std::thread`, not a `tokio::spawn`: `Core::next_event` blocks on a condvar, and blocking a runtime worker on a condvar is how a runtime deadlocks |
| 7. accept connections | only now (§11.6) |
| 7b. **EM-69 / EM-70's readiness channels** | the health file is written, `sd_notify(READY=1)` is sent, and the **first watchdog ping is refused unless a fresh `ProtectionAssertion` was obtained**. EM-70: "a watchdog fed by a timer thread proves that the timer thread is alive, which is not the property anybody wants" |

`twinvpnd` also **warns and continues** on four degradations, each named so an
operator can see it rather than infer it: no recognised supervisor (PS-11), a
missing `NoNewPrivileges=yes` or an unnarrowed `CapabilityBoundingSet=`
(PS-17, each named as the unit directive it is), a TPM present that this build
cannot use (§11.16 (l)), and a health file that could not be written (EM-69 has
four other channels).

Group membership is **no longer** among them: `getgrouplist(3)` asks NSS, so an
LDAP/SSSD/`nss-systemd` membership is seen. The file remains the fallback for a
lookup NSS could not *perform*, which is a different fact from "not a member" —
see §7.

### On the way out

`ownership.md` §6 rule 7's order, and CB-6 is the rule that shapes it:

1. `sd_notify(STOPPING=1)`, so `systemd` can tell a clean stop from a crash —
   which is what makes EM-71's crash-loop hold reachable.
2. The endpoint is removed **first**, so a client connecting during the drain
   gets `MGMT.UNAVAILABLE` rather than a successful connect and a hang (§10.3).
3. The health file is retracted. A stale `READY` line outliving the agent is a
   monitoring system told a falsehood by a file.
4. The event stream closes: every per-connection pump wakes and returns, and
   every dispatcher still waiting for a command body is **settled** rather than
   left hanging.
5. The core's `begin_shutdown` drains the write-behind journal.
6. **The installed ruleset is not touched.** CB-6 puts it in the OS's custody so
   that the core going away cannot drop protection, and KS-20 says the same
   thing from the other side: "a crash must leave the host blocked, never open".

## 5. Debugging

```sh
# The agent's own view of its privilege posture, which is what it verifies:
grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs):' /proc/$(pidof twinvpnd)/status

# Who holds PS-1's lock. The pid inside is EVIDENCE; the flock is the exclusion,
# so a stale file naming a dead pid does not keep a successor out.
cat /run/twinvpn/authority.lock
fuser -v /run/twinvpn/authority.lock

# EM-69's health line: state, worst reason_code, the agent's own reading, and
# whether a FRESH ProtectionAssertion was obtained. `unknown` in the last field
# means "we could not ask", which is NOT "unprotected" (O-18).
cat /run/twinvpn/health

# What the KERNEL says is installed — this is the W-24 read-back, and it is what
# the ProtectionAssertion is derived from. Not the agent's belief.
sudo nft --json list table inet twinvpn | jq '.nftables[] | select(.counter)'

# The posture and the generation, held by the kernel:
sudo nft list table inet twinvpn | grep -E 'counter (posture_|gen_)'

# The leak canary's own counters, per family (ADR-0012 KS-11):
sudo nft list table inet twinvpn | grep -E 'counter (deny|exempt)_'

# Our routes and policy rules — table 52 only; the host's own are untouched.
# The fwmark rule reads `not fwmark`, and the inversion is load-bearing: without
# it NOTHING looks in table 52 and the tunnel carries no traffic at all (§7).
ip -4 route show table 52 ; ip -6 route show table 52
ip -4 rule show ; ip -6 rule show

# THE LEAK ORACLE. Which interface would a packet actually leave by? This is the
# kernel's own FIB answer, and it is the question a leak test has — not "did the
# install return Ok".
ip route get 100.64.0.5                      # protected: must say dev twin0
ip -6 route get fd7c:9e5d:2a10::5            # ...and IPv6 at parity
ip route get 198.51.100.7                    # unprotected: must NOT be captured
ip route get 100.64.0.5 mark 0x7677          # ours: must take the UNDERLAY

# DNS: which of ADR-0011 DN-21's two Linux forms this host took.
resolvectl status twin0                      # the preferred, scoped form
grep -c '^# twinvpn-owned' /etc/resolv.conf  # the fallback, owner-tagged

# The three clocks, and the one that is invisible when it is wrong. Both are
# read with clock_gettime(2) now; `chrt` is not involved and neither is /proc.
python3 -c 'import ctypes,os
class T(ctypes.Structure): _fields_=[("s",ctypes.c_long),("n",ctypes.c_long)]
l=ctypes.CDLL("libc.so.6"); t=T()
for name,cid in (("MONOTONIC",1),("BOOTTIME",7)):
    l.clock_gettime(cid,ctypes.byref(t)); print(name, t.s)'
cat /proc/sys/kernel/random/boot_id   # the third discriminator: reboot vs resume

# Trace-level logging, in text, without a supervisor:
TWINVPN_LOG_LEVEL=trace TWINVPN_LOG_FORMAT=text ./target/debug/twinvpnd

# The offline recovery path, when the authority will not start at all. It speaks
# to no socket and needs no running agent, which is the whole point.
twinvpn-unblock --status
twinvpn-unblock --confirm-unprotected
```

### Running the tests

```sh
cd shells/linux && cargo test --workspace                 # 168 tests, unprivileged
cd ../../core   && cargo test -p twinvpn-platform-linux   # 155 tests, unprivileged
```

Both suites run unprivileged, and the adapter's `tests/netns.rs` and
`tests/matrix.rs` **assert the refusal** in that mode rather than skipping — so a
plain `cargo test` still checks that an unprivileged adapter names the right
`reason_code`. Nothing is silently skipped anywhere in this domain.

The write path — creating a tun device, programming addresses and routes into
table 52, installing the `fwmark` policy rules — needs `CAP_NET_ADMIN`, which an
**unprivileged user namespace** grants inside itself:

```sh
cd core
cargo test -p twinvpn-platform-linux --test netns --no-run
unshare --user --map-root-user --net -- \
  env TWINVPN_NETNS_TEST=1 ./target/debug/deps/netns-<hash> --test-threads=1

# THE TEST MATRIX's kernel-facing half — startup, network change, route
# recovery, IPv4 leaks, IPv6 leaks, kill switch, DNS leaks, DNS recovery,
# suspend/resume, daemon restart. `--test-threads=1` is REQUIRED and is not a
# convenience: they share one namespace and one `twin0`, and two of them
# programming it at once is PS-1's race reproduced inside the test binary.
cargo test -p twinvpn-platform-linux --test matrix --no-run
unshare --user --map-root-user --net -- \
  env TWINVPN_NETNS_TEST=1 ./target/debug/deps/matrix-<hash> --test-threads=1

# And to SEE what it programmed, through iproute2 rather than through the
# assertions:
cargo test -p twinvpn-platform-linux --test state_dump --no-run
unshare --user --map-root-user --net -- \
  env TWINVPN_NETNS_TEST=1 ./target/debug/deps/state_dump-<hash> \
  --nocapture --test-threads=1
```

The other two scenarios — **shutdown** and **UI/service separation** — are
process properties rather than kernel ones and live in
`twinvpnd/tests/lifecycle.rs`, so they run under a plain `cargo test`.

**The observer is `iproute2`, deliberately.** Where a test needs to know what the
kernel is holding it asks `ip(8)` rather than this crate's own netlink code, so a
bug in `route::fib`'s attribute numbers cannot make a test pass by being wrong on
both sides. That discipline has now caught two real defects that no unit test
could: `index_of` reading the host's `/sys` from inside a namespace (wave 1), and
the un-inverted `fwmark` rule that made table 52 unreachable to every ordinary
packet while `program()` returned `Ok` and the table held exactly the right route
(this wave — see §7's note on what it cost).

## 6. The CLI — cargo target `twinvpnctl`, installed as `twinvpn`

```
usage: twinvpn [--output human|json|json-lines] <noun> <verb>
```

**Installed name.** `ownership.md` §9.5 **D-1**: the package installs the
`twinvpnctl` build artifact as `/usr/bin/twinvpn` and ships `/usr/bin/twinvpnctl`
beside it as a compatibility symlink. Both spellings work; `twinvpn` is the one
every rendered `next_action`, every usage line and every error prefix names.

The verb table is **generated from the core's command catalogue** (MI-C1), so
`twinvpn --help` lists exactly ADR-0017 §11.9's operations, in its order. A
verb with no catalogue entry, or an entry with no verb, fails the build.

**Exit codes** are ADR-0017 §11.12's, and 64+ is prohibited:

| | |
|---|---|
| **0** | succeeded |
| **1** | failed for a reason the agent named |
| **2** | usage — **nothing was sent to the agent** |
| **3** | the management channel is unavailable |
| **4** | authorization refused |
| **5** | version incompatible |

The `reason_code` goes to **stderr in every output mode**, including
`--output json`, "so a `set -e` script that does not parse JSON still gets it".
Retry policy is driven by `Diagnostic.class`, not by the exit code (**EM-37**).

**It never prompts** (EM-38). A destructive operation without
`--confirm-unprotected` exits **2** rather than reading from a terminal: "a
command that blocks on a terminal read is a hung cron job, which on an
unattended device is indistinguishable from a wedge."

---

## 7. What is NOT here, stated plainly

Each of these is a gap this wave did not close, with the reason. Wave 1's list
had eight; six are closed, and what follows is the **new** set.

### 1. ~~The binary is named `twinvpnctl`, and the ADRs name it `twinvpn`.~~ **CLOSED by D-1.**

`ownership.md` §9.5 **D-1** settled it: *"The cargo target stays `twinvpnctl`
(renaming it churns three shells for nothing a user sees) and the package
installs it as `twinvpn`, with `twinvpnctl` kept as a compatibility alias."*

So the two install lines in §3 are the whole fix — `/usr/bin/twinvpn` is the
real file, `/usr/bin/twinvpnctl` is a symlink to it — and the strings this
binary prints say `twinvpn`. ADR-0016 §11.2's process table, ADR-0017 §11.12's
command shape, ADR-0023 EM-11's `twinvpn config check` and EM-42's
`run 'twinvpn peer disconnect nas-attic'` now all name a command this host
installs. The cargo package name and `[[bin]]` entry are deliberately unchanged;
`twinvpnctl/Cargo.toml`'s header carries the same note so it cannot be lost with
this file.

Still not here: `twinvpn config check` itself. D-1 fixed the *name*, not the
`config` noun — EM-11's dry run and the `IntentDocument` remain out of this wave
(§2's note on the agent reading no configuration file).

### 2. ~~Four of the five event topics carry an empty payload.~~ **CLOSED.** `CoreEventKind::encoded_payload()` landed in the seam work package; `payload_of` is a one-line delegation with no branch on which variant carries a body, so a variant that gains one is carried the day it lands. `Compacted` stays empty, which is the whole truth rather than a missing encoder.

The stream itself is here — pushed `Event` frames, MI-18 attribution, MI-19's
ordered `Compacted` marker, §11.10's three-rung ladder, and `event.resync`'s
snapshot. `CommandCompleted` carries its full body, which is what makes
`Response.result` real (below).

What does not carry a body is `Transition`, `SessionEvent` and `Diagnostic`.
Their bodies are `twinvpn_schema::v1` messages, and encoding them needs a `prost`
dependency this shell has no other use for — `twinvpnd`'s manifest is this
domain's, but adding a proto codec to a shell is exactly the "translate, don't
model" line CB-2 draws. A client currently learns *that* a transition happened,
with its `seq` and its actor, and reads *what* with a follow-up unary call.

**The fix is a core-side one**: either `twinvpn-core` exposes the encoded bytes
on `CoreEventKind` the way it already does for `CommandCompleted { result }`, or
`twinvpn-diag::encode` is widened past `SessionEvent`. Raised for
`core-foundation`; a shell-side prost dependency would be the wrong place.

### 3. `committed_at_net_seq` is always absent, and correctly so.

Unchanged from wave 1, and repeated because it is the kind of "gap" someone
closes by mistake. MI-6 applies to operations that map to a mutating **C1**
request — the five in `server::C1_MAPPING` — and every one needs a control-plane
transport this build does not have (W-12), so each is refused by name before a
response exists. A locally-mutating operation such as `session.connect` reaches
no C1 request and has no `net_seq`. Reporting S-47's generation there, as this
shell once did, tells a client it has read-your-writes when it has not.

### 4. ~~`twinvpn-gateway` has no caller anywhere in the workspace.~~ **CLOSED** (`ownership.md` §9.6 X-3). The MI catalogue gained a `gateway` noun and `twinvpn-core::gateway` is the caller, so ADR-0013 is reachable through the only interface a headless host has. The noun appears in this CLI with no edit here, because the verb table is generated from the catalogue (MI-C1). `gateway.set` is refused by name for ADR-0013 MG-15's own reason: MG-15 refuses an over-committed configuration *at configuration time*, which needs a durable ceiling and a memory measurement this build does not have.

This is the largest finding of the wave and it is **not this domain's to fix**.

- `core/crates/twinvpn-gateway` is complete and well-tested: `PeerTable`,
  `AllowedSources`, `Grant`, `PeerQuota`, `Capacity`, the admission errors.
- `twinvpn-core` declares it as an optional dependency under `feature = "full"`
  and **never `use`s it**. `grep -rn twinvpn_gateway core/crates --include=*.rs`
  outside the crate itself returns nothing.
- None of ADR-0017 §11.9's 47 catalogue operations reaches gateway logic, and
  ADR-0023 EM-35 requires a `gateway` noun the catalogue does not contain.

So the peer table, the grants, the quotas and MG-21's admission refusal are
unreachable from the MI, which is the only interface an H-SRV host has. This is
R-7's shape exactly — "`apply` had no caller anywhere in the product" — one layer
up, and it means ADR-0013's G1 ("N ≥ 16 concurrent peers") is not merely
unimplemented but **unaddressable**.

CB-1 and CB-2 forbid this shell from fixing it: gateway policy is a decision, and
a shell that called `gateway::decide` would be holding one. Routed to
`core-dataplane` and the integration lead.

**What this wave did build** is the half that genuinely is the shell's, and it is
ADR-0023 §11.16's — a screenless, userless host now reports and escalates:
`agent/health.rs` implements EM-69's health file, EM-70's watchdog (fed only from
a fresh `ProtectionAssertion`, never from a timer), EM-71's crash-loop hold in
the unit, and EM-72's structural unreachability of disarm from any automatic
path. KS-20a's `twinvpn-unblock` makes "blocked" not mean "bricked" on a host
with no console.

### 5. `nft(8)` and `conntrack` are still not installed on this host.

Checked, not assumed: `command -v nft conntrack` finds neither. `ip` and
`unshare` **are** present, which is what made this wave's netns work possible.

So the nftables *install* and *read-back* remain unexercised. What is covered
instead: the rendered ruleset and the `nft --json` parser exhaustively (unit),
and the **routing** half against a real kernel with `ip route get` as the oracle
(`tests/matrix.rs`). The kill-switch and DNS-leak tests say at their own
assertion which half they are checking.

This is the largest remaining *testing* gap in the domain, and it is a host
problem rather than a code one: `apt install nftables conntrack` on the CI image
turns four assertions from "the arm fails by name" into "the arm installed and
the kernel read it back".

### 6. `getgrnam_r` is not bound, so a group that exists **only** in a directory service is not resolvable by name.

`getgrouplist(3)` is bound and answers "which groups is this account in" from
every NSS source (gap 6 of wave 1, closed). But `GroupSource::member_of` resolves
a group *name* to a gid from `/etc/group` first, and returns `false` for a name
that file does not contain.

So the remaining case is narrow and specific: a host where `twinvpn` or
`twinvpn-operators` exists **only** in LDAP, with no local entry at all. On such
a host the principal holds fewer scopes than intended — it still fails closed,
and the §3 install instructions create both groups locally, so the normal
installation is unaffected. `getgrnam_r` is another `libc` binding in
`twinvpn-platform-linux::nss` and is a small piece of work; it is named rather
than done because nothing in this wave depended on it.

### 7. `twinvpn config check`, the `IntentDocument`, and EM-18/EM-19/EM-20 are not here.

The agent still reads **no configuration file**. ADR-0023 EM-10's three-stage
validation, EM-11's dry run, EM-18's `max(live, candidate)` reload posture,
EM-19's restart-requiring fields and EM-20's safe hold at boot are a coherent
subsystem that wave 1 did not scope and this wave did not add. `EM-19`'s
substance is honoured in the small — `TWINVPN_MGMT_SOCKET` is read once at start,
which is what "restart-requiring" means — and nothing else of the family exists.

### 8. Two ADR statements this domain could not satisfy as written, resolved toward the safe reading and reported.

Both are in the code at the point of the decision, so a reader meets them where
they matter rather than only here.

**(a) ADR-0016 §11.6's arm ordering is not implementable literally on Linux.**
ADR-0012 §11.8 spells it `create iface (DOWN) -> apply(contract_gen) -> link up`.
An address *can* be added to a down interface; a route **cannot** —
`RTM_NEWROUTE` answers `ENETDOWN`. So the link has to come up between the
addresses and the routes. `matrix_startup_programs_both_families_before_the_link_carries_traffic`
asserts the `ENETDOWN` rather than working around it silently, so the constraint
is visible to whoever next reads the ordering. The leak window §2.3 worries about
is still closed: the interface is created DOWN and the *routes* are what bring
traffic, so nothing is carried before the contract is applied.

**(b) ADR-0023 EM-69 names the health file `$STATE_DIR/health` *and* says
`(tmpfs)`, and on `systemd` those disagree.** `StateDirectory=` is `/var/lib`,
which is persistent; the tmpfs is `RuntimeDirectory=`. This build writes to the
**runtime** directory, because the parenthetical is the load-bearing half — a
health line that survives a reboot is a monitoring system told a falsehood by a
file, which is the exact failure the file exists to prevent. There is no conflict
on OpenWrt, where `$STATE_DIR` is itself on tmpfs, which is likely why it was not
noticed.

### 9. What wave 1 listed and this wave closed, so the list above is read as a delta

| Wave 1 | Now |
|---|---|
| **2.** no event stream; `event.resync` refuses | closed — `agent/events.rs` and `agent/conn.rs`. The "visible consequence" was a **misreading of the core**: `Core::submit` *publishes* the result as `CommandCompleted` rather than withholding it, and `Response.result` is now a real body |
| **2b.** W-43, the runtime has no I/O driver | closed upstream; the probe-branching tests assert the strong side and one test pins the fix |
| **3.** no ADMINISTER ceremony | closed — and wave 1's conclusion was **over-strict**. ADR-0012 **KS-21a** says that on HC-3 "a caller on the local management socket, authenticated by kernel-supplied peer credentials to an administrator principal, satisfies this clause". No polkit and no D-Bus dependency is needed on this host class; `packaging/net.twinvpn.administer.policy` remains for a future HC-1 build |
| **4.** no `twinvpn-unblock` | closed — a separate package-owned binary linking neither `twinvpnd` nor the core |
| **5.** `systemd-resolved` detected and not used | closed — `resolved.rs` reaches `org.freedesktop.resolve1` through `resolvectl(1)`, systemd's own client, so no workspace dependency was added |
| **6.** group membership from `/etc/group` only | closed — `getgrouplist(3)` in the adapter. The narrow residue is gap 6 above |
| **7.** PS-1 not enforced by a lock | closed — `flock(2)` at step 3c |
| **8.** nothing could exercise `nft`, `conntrack` or `ip netns` | **partly** — `ip` and `unshare` are present and are now used hard (gap 5 above). `nft` and `conntrack` still are not |

**And one thing wave 1 did not know it had.** The routing half of the product did
not work: the `fwmark` policy rule was installed un-inverted, so table 52 — which
held exactly the right overlay routes — was consulted only for the agent's *own*
marked packets, and every ordinary packet to a peer found the host's default
route instead. Both families, identically. `program()` returned `Ok`, the table
read back correctly, and every test passed. Only `ip route get` showed it. That
is the entire argument for asserting over the kernel's state rather than over an
install call's return value, and it is why §5's oracle is `iproute2`.
