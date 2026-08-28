# The Linux shell — `twinvpnd` and `twinvpnctl`

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
| `packaging/twinvpnd.service` | the authority unit — every directive is ADR-0016 §11.9's |
| `packaging/twinvpn-killswitch.service` | the **KS-19 boot artifact**, package-owned (PS-7) |
| `packaging/killswitch.nft` | the ruleset that unit restores |
| `packaging/net.twinvpn.administer.policy` | the polkit action of PS-12a (**not yet wired** — see §7) |

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
install -Dm0755 target/release/twinvpnctl  /usr/bin/twinvpnctl
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
| 3. the three clocks and the runtime | fatal; the CSPRNG is **probed at startup**, not on first use |
| 4. the adapter's capability probe | fatal if `nft(8)` is absent — ADR-0012 §8: arming must never fail open, and PS-18 forbids starting "in a mode that cannot arm enforcement while reporting itself as running" |
| 5. the core | `INTERNAL.ABI_VERSION_MISMATCH` (VR-4), checked before any capability is touched |
| 6. the MI endpoint | `MGMT.UNAVAILABLE`. MI-A3: the agent verifies `/run/twinvpn`'s ownership and mode **before** binding, and binds a temporary name then `rename`s it — `unlink()`-then-`bind()` is prohibited |
| 7. accept connections | only now (§11.6) |

`twinvpnd` also **warns and continues** on four degradations, each named so an
operator can see it rather than infer it: no recognised supervisor (PS-11), a
missing `NoNewPrivileges=yes` or an unnarrowed `CapabilityBoundingSet=`
(PS-17, each named as the unit directive it is), a TPM present that this build
cannot use (§11.16 (l)), and group membership readable only from `/etc/group`
(§7).

---

## 5. Debugging

```sh
# The agent's own view of its privilege posture, which is what it verifies:
grep -E '^(Uid|CapEff|CapBnd|NoNewPrivs):' /proc/$(pidof twinvpnd)/status

# What the KERNEL says is installed — this is the W-24 read-back, and it is what
# the ProtectionAssertion is derived from. Not the agent's belief.
sudo nft --json list table inet twinvpn | jq '.nftables[] | select(.counter)'

# The posture and the generation, held by the kernel:
sudo nft list table inet twinvpn | grep -E 'counter (posture_|gen_)'

# The leak canary's own counters, per family (ADR-0012 KS-11):
sudo nft list table inet twinvpn | grep -E 'counter (deny|exempt)_'

# Our routes and policy rules — table 52 only; the host's own are untouched:
ip -4 route show table 52 ; ip -6 route show table 52
ip -4 rule show ; ip -6 rule show

# The three clocks, and the one that is invisible when it is wrong:
cat /proc/uptime          # field 1 is CLOCK_BOOTTIME — the ElapsedClock
cat /proc/sys/kernel/random/boot_id

# Trace-level logging, in text, without a supervisor:
TWINVPN_LOG_LEVEL=trace TWINVPN_LOG_FORMAT=text ./target/debug/twinvpnd
```

### Running the tests

```sh
cd shells/linux && cargo test --workspace                 # 105 tests, unprivileged
cd ../../core   && cargo test -p twinvpn-platform-linux   # 114 tests, unprivileged
```

Both suites run unprivileged, and the adapter's `tests/netns.rs` **asserts the
refusal** in that mode rather than skipping — so a plain `cargo test` still
checks that an unprivileged adapter names the right `reason_code`.

The write path — creating a tun device, programming addresses and routes into
table 52, installing the `fwmark` policy rules — needs `CAP_NET_ADMIN`, which an
**unprivileged user namespace** grants inside itself:

```sh
cd core
cargo test -p twinvpn-platform-linux --test netns --no-run
unshare --user --map-root-user --net -- \
  env TWINVPN_NETNS_TEST=1 ./target/debug/deps/netns-<hash> --test-threads=1

# And to SEE what it programmed, through iproute2 rather than through the
# assertions:
cargo test -p twinvpn-platform-linux --test state_dump --no-run
unshare --user --map-root-user --net -- \
  env TWINVPN_NETNS_TEST=1 ./target/debug/deps/state_dump-<hash> \
  --nocapture --test-threads=1
```

That is how the netlink write path was actually verified — including a bug it
caught that no unit test could: `index_of` originally read `/sys/class/net`,
which is the **host's** sysfs inside a network namespace, so a freshly created
interface was invisible. It asks the kernel over netlink now.

---

## 6. `twinvpnctl`

```
usage: twinvpnctl [--output human|json|json-lines] <noun> <verb>
```

The verb table is **generated from the core's command catalogue** (MI-C1), so
`twinvpnctl --help` lists exactly ADR-0017 §11.9's operations, in its order. A
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

Each of these is a gap this wave did not close, with the reason.

1. **The binary is named `twinvpnctl`, and ADR-0016 §11.2 and ADR-0017 §11.12
   name it `twinvpn`.** ADR-0023 EM-42's rendered next actions say
   `run 'twinvpn peer disconnect nas-attic'`, which names a command that is not
   installed under that name. The path was the integration lead's; renaming it
   is not this domain's call. **Needs a decision.**
2. **No event stream.** `event.subscribe` reaches the core and the core accepts
   it, but the agent does not yet push `Event` frames, and `event.resync`
   refuses rather than returning an empty snapshot a client would read as
   current truth (MI-9a's whole point). ADR-0017 §11.10's compaction and
   eviction ladder is therefore unexercised.
3. **No ADMINISTER ceremony.** Every ADMINISTER operation is **refused**, not
   performed on a scope alone — which is §11.5's third consequence and the safe
   direction. Wiring it needs a polkit client, i.e. a D-Bus dependency
   `core/Cargo.toml` does not declare.
4. **No `twinvpn-unblock`.** ADR-0012 KS-20a makes the offline unblock command
   mandatory on Linux and ADR-0017 MI-12/MI-13 specify it. It is a separate
   package-owned binary, not a subcommand, "precisely because the case it exists
   for is 'the authority will not start'" — and `shells/linux/Cargo.toml`'s
   member list is the integration lead's.
5. **`systemd-resolved` is detected and not used.** ADR-0011 DN-21 prefers it;
   this build takes the owner-tagged `/etc/resolv.conf` path and reports
   `DNS.PLATFORM.SCOPED_API_UNAVAILABLE`'s condition rather than degrading
   silently. §11.9 is explicit that **containment is the guarantee, not the
   file**, and the nftables class-6 denial is installed either way.
6. **Group membership is read from `/etc/group` only.** `getgrouplist(3)` needs
   `unsafe`, which these binaries forbid. An LDAP/SSSD/`nss-systemd` membership
   is not seen, so a principal holds **fewer** scopes than intended — it fails
   closed, and the agent warns at start.
7. **PS-1 is not enforced by a lock.** Two agents would race for the endpoint
   name; the second wins the name and the first keeps its listening socket.
   A crash-surviving lock file is the fix and is not in this wave.
8. **Nothing on this host could exercise `nft`, `conntrack` or `ip netns`** —
   none is installed. The nftables ruleset's *text* and the `nft --json`
   *parser* are tested exhaustively; the *install* and the *read-back* are not.
   See the adapter's own report.
