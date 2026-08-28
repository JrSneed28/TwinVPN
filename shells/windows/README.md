# The Windows shell — `twinvpnsvc` and `twinvpnctl`

**Owner:** `desktop-windows`.
**Authority:** [ADR-0016](../../docs/adr/ADR-0016-client-process-and-privilege-separation.md)
(the privilege split), [ADR-0017](../../docs/adr/ADR-0017-local-management-interface.md)
(the local MI), [ADR-0018](../../docs/adr/ADR-0018-shared-core-and-build-architecture.md)
§11.1 and §11.12 (CB-1, CB-2, the layout),
[ADR-0021](../../docs/adr/ADR-0021-packaging-distribution-and-updates.md) (the MSI
and the signing), [ADR-0022](../../docs/adr/ADR-0022-application-lifecycle-and-background-execution.md)
(the lifecycle),
[ADR-0023](../../docs/adr/ADR-0023-headless-cli-and-embedded-profile.md) (the
headless surface). This host is ADR-0016 class **HC-1** — attended, separable,
with a console seat.

---

## 0. Read this first

**Nothing in this directory has ever been built for Windows, installed, or
run.** It was written on a Linux host. What exists is:

| Claim | How far it goes |
|---|---|
| it compiles for `x86_64-pc-windows-msvc` with `-D warnings` | the adapter crate and `twinvpnctl`: **yes**, cleanly. `twinvpnsvc` with its `service` feature: **not on this host** — `ring`'s build script needs an MSVC-targeting C compiler and there is none here. See §7.19 |
| its target-free layers behave correctly | `cargo test --workspace` here and in the adapter crate, on Linux. Real, and bounded by what "target-free" covers. |
| the MSI installs a working service | **no evidence whatsoever.** WiX has never run. |

§7 is the list of what is not here. Read it before believing anything above it.

---

## 1. What is here

| Path | What |
|---|---|
| `twinvpnsvc/` | `TwinVPNService`, the privileged authority — **and** the `mi` module both binaries share |
| `twinvpnctl/` | the unprivileged CLI |
| `packaging/` | the WiX/MSI definition, the KS-19 boot-filter registration, and the Authenticode/EV signing requirements |

The adapter these binaries bind is
[`core/crates/twinvpn-platform-windows`](../../core/crates/twinvpn-platform-windows),
which this domain also owns.

### Why `twinvpnsvc` is a library as well as a binary

ADR-0017 MI-20 and ADR-0018 §11.16 (b) require *"one contract, two carriages,
**never two contracts**"*. The MI envelope, its framing, its client and the
named pipe's DACL are declared **once**, in `twinvpnsvc`'s `mi` module, and
`twinvpnctl` depends on that crate with `default-features = false` — which
excludes the whole `service` feature, so the unprivileged CLI links no Wintun,
no WFP, no IP Helper and no core-hosting code. A copy of the framing in each
binary would be the second contract those rules forbid.

### Why this shell contains `unsafe`, and `shells/linux` does not

`shells/linux` carries `#![forbid(unsafe_code)]`, and it can: `tokio` gives it
`UnixListener` and `UnixStream::peer_cred()`, so every privileged operation the
Linux agent performs has a safe wrapper somebody else wrote.

There is no equivalent on this platform. SCM registration, the pipe's security
descriptor, the client-token check, the console-seat rule and the power events
are all raw `windows-sys` calls, and every one of them is `unsafe`. So this
crate takes the *adapter's* discipline instead: `unsafe` is confined to
`twinvpnsvc/src/win32/`, every block carries a `// SAFETY:` comment naming its
invariant, and `#![deny(unsafe_op_in_unsafe_fn)]` is on. `twinvpnctl` contains
none. **This is a deviation from the Linux shell's posture and it is stated
rather than discovered** — see §7.

---

## 2. Environment configuration

Every variable has a default, and **the default is the production value**
(`infra/README.md`'s convention). None of them is a security control.

| Variable | Default | What it does |
|---|---|---|
| `TWINVPN_MGMT_PIPE` | `\\.\pipe\TwinVPN\mgmt` | the MI endpoint. ADR-0023 **EM-19** makes changing it restart-requiring, which is what a variable read once at start is. Present for local development and the component tests; the endpoint's safety comes from the DACL, `PIPE_REJECT_REMOTE_CLIENTS` and the client-token check, wherever the name points |
| `TWINVPN_LOG_LEVEL` | `info` | `trace`/`debug`/`info`/`warn`/`error`. **`critical` is accepted and mapped to `error`** — `ownership.md` §8 **W-16**, so a value copied verbatim from ADR-0015 §11.5 configures the service rather than failing it. An unrecognised value falls back to `info`: a logging misconfiguration must not be why a VPN service will not run |
| `TWINVPN_LOG_FORMAT` | `json` under the SCM, `text` otherwise | follows whether the process reached `StartServiceCtrlDispatcherW`, which nothing but a real service start does |
| `TWINVPN_OVERLAY_ADAPTER` | `TwinVPN` | the Wintun adapter's name. `is_overlay` turns on this prefix, and Tier 2 is interface-scoped, so this is the one name the whole permit turns on |
| `TWINVPN_STATE_DIR` | `%ProgramData%\TwinVPN\store` | ADR-0020 §11.9's vault, created by the MSI with `SYSTEM:F`, `Administrators:F`, `Users` denied and inheritance disabled. CB-7: the path is *injected*, never discovered — and a variable read once at start is an injection |
| `TWINVPN_WINDOWS_TEST` | unset | the adapter's `tests/windows_host.rs` opt-in. Unset, the mutating tests **assert the refusal** rather than skipping; set, in an Administrator shell, they install real WFP filters |
| `COLUMNS` | console width | `twinvpnctl` only. EM-44: wrap to `min(COLUMNS, 100)`, legible at 80 and at 40 |
| `NO_COLOR`, `TERM` | — | `twinvpnctl` only. EM-43: colour needs a console **and** `NO_COLOR` unset **and** VT processing available |

The service reads **no configuration file**. ADR-0023 EM-11's `twinvpn config
check` and the `IntentDocument` are not in this wave (§7).

---

## 3. Local startup

### Building, from a Linux host

There is no Windows toolchain here, so what is available is the compile proof:

```sh
source build/toolchain/env.sh

# The compile proof, as far as this host can take it. `make cross-check` runs
# the first of these and then a `--workspace` clippy over this directory, which
# stops inside `ring`'s build script — §7.19 says why, and what to do about it.
cd core && cargo clippy -p twinvpn-platform-windows --all-targets \
    --target x86_64-pc-windows-msvc -- -D warnings
cd ../shells/windows
cargo clippy -p twinvpnctl --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo clippy -p twinvpnsvc --no-default-features --features service --all-targets \
    --target x86_64-pc-windows-msvc -- -D warnings

# The behaviour proof, such as it is: the target-free layers, on Linux.
cargo test --workspace
cd ../../core && cargo test -p twinvpn-platform-windows --features test-support
```

### On a Windows host, when there is one

```powershell
# The service refuses to start without wintun.dll beside it and without the WFP
# engine (arming must never fail open, ADR-0012 §8; PS-18 forbids starting in a
# mode that cannot arm enforcement while reporting itself as running).
cargo build --target x86_64-pc-windows-msvc

# In the foreground, for development. Emits PLATFORM.SERVICE.SUPERVISOR_ABSENT
# at WARN (PS-11), because an unsupervised authority must not claim the
# guarantees a supervised one has.
.\twinvpnsvc.exe --console

# In another console:
.\twinvpnctl.exe status get
```

### The installed version

`packaging/` is the MSI's definition. It installs the binaries and `wintun.dll`,
registers the service with `SERVICE_AUTO_START` (**not** delayed — ADR-0022
LC-12: "delayed start defers the service by ~2 minutes after boot, which
lengthens exactly the window in which the host is fail-closed-and-offline") and
ADR-0016 §11.6's `SERVICE_FAILURE_ACTIONS` ladder, creates PS-12a's local groups
`TwinVPN Users` and `TwinVPN Operators`, creates `%ProgramData%\TwinVPN\store\`
with ADR-0020 §11.9's ACL, and registers the KS-19 boot-time WFP filter set as a
**package-owned** artifact.

**The package creates the groups; the service never does.** To grant a person
read access, add them to `TwinVPN Users`; to let them connect and disconnect,
add them to `TwinVPN Operators`. The built-in `Users` group is deliberately not
used — PS-12a: *"'every local account can enumerate this device's peers and
endpoints' should be an install-time decision (TB-13), not a platform
default."* A membership change takes effect **on the next attach** (S-44:
re-derived at every attach, never cached across attaches).

---

## 4. The start sequence, and what each step refuses

ADR-0016 §11.6, in order. `twinvpnsvc`'s `StartSequence` is this table as a
value the diagnostic bundle can carry.

| Step | On failure |
|---|---|
| 1. the KS-19 boot artifact is registered | `CRITICAL` — **and the service starts anyway.** PS-7 makes the artifact package-owned and says the authority "MUST NOT be a prerequisite for it to apply"; refusing would leave the host with neither the boot filters *nor* a service. The code ADR-0016 §11.12 names for this is `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED`, which the frozen registry does **not** carry — see §8 |
| 2. the single-instance lock (LC-5) | **Fatal.** A named kernel mutex in the `Global\` namespace, held by the service SID. Two authorities on one host is `INTERNAL.INVARIANT_VIOLATED`'s condition (PS-1) |
| 3. the privilege posture | **Fatal** on holding `SeDebugPrivilege` or `SeTcbPrivilege` — ADR-0016 §11.9 forbids both by name — or on missing `SeLoadDriverPrivilege`, without which there is no Wintun adapter. A wider *bounding* set the SCM did not apply is PS-17's `PLATFORM.PRIV.SANDBOX_DEGRADED` **warning**, not a refusal |
| 4. the three clocks, the runtime and the CSPRNG | fatal; the CSPRNG is **probed at startup**, not on first use |
| 5. the adapter's capability probe | fatal if `wintun.dll` is absent or the WFP engine cannot be opened for write. ADR-0012 §8: arming must never fail open, and PS-18 forbids starting "in a mode that cannot arm enforcement while reporting itself as running" |
| 6. reclaim the owner-tagged WFP state, and **read it back** | **Fatal** unless the returned `ProtectionAssertion` is fail-closed **in both families**. §11.6 step (2) and ADR-0022 LC-4 steps 3–4: this is the W-24 query, not the fact that an install returned `Ok` |
| 7. the core | `INTERNAL.ABI_VERSION_MISMATCH` (VR-4), checked before any capability is touched |
| 8. the MI endpoint | `MGMT.UNAVAILABLE`. MI-A3: **the service** creates the pipe and writes its DACL at *every* start — an installer-written ACL would be stale after a restart — with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a squatter fails loudly and `PIPE_REJECT_REMOTE_CLIENTS`, without which the pipe is reachable over SMB |
| 9. accept connections | only now (§11.6) |

`StartSequence::ready()` deliberately does **not** require step 1: PS-7's
artifact is package-owned, and a service that refused to start without it would
turn a packaging problem into an outage.

### Sleep, wake and network change

ADR-0022 §11.6's Windows row and LC-23a. `SERVICE_CONTROL_POWEREVENT` delivers
`PBT_APMSUSPEND` and `PBT_APMRESUMEAUTOMATIC`/`PBT_APMRESUMESUSPEND` on **S3/S4
only**. On **Modern Standby neither fires**, and `EV_SUSPEND` **is not
synthesized there** — the process keeps running, so parking it would be a lie.
What is available there is `PowerSettingRegisterNotification`, from which
display-off plus absent user presence is synthesized as `EV_BACKGROUND`
(LC-23a, and finding F7's battery defect).

LC-24's resume ordering is enforcement first, always:

```text
1. classify: boot_id changed ⇒ not a resume, run LC-4 as a COLD_START;
   same boot_id, gap > 0 ⇒ a resume, measured on the SUSPEND-INCLUSIVE clock
2. query the enforcement layer for BOTH families; re-assert BLOCKED on mismatch
   ───── no packet may be emitted before this line ─────
3. re-acquire what does not survive: sockets, interface handles, subscriptions
4. hand off to the wake ladder
5. emit the measured gap
```

Step 2 precedes step 3 because "the temptation to re-open sockets first is
strong" on desktop. And **a resume never renders a confident stale green**: LC-22
and ADR-0015 O-18 make the protection indicator `UNKNOWN` until a *fresh*
`ProtectionAssertion` arrives, never the remembered value.

---

## 5. Debugging

```powershell
# What the ENGINE says is installed — the W-24 read-back, and what the
# ProtectionAssertion is derived from. Not the service's belief.
netsh wfp show filters file=- | Select-String "TwinVPN"
netsh wfp show state file=wfp.xml   # then read the sublayer and provider blocks

# The service's own privilege posture, which is what step 3 verifies:
sc.exe qprivs TwinVPNService
sc.exe qsidtype TwinVPNService      # must be UNRESTRICTED (ADR-0016 §11.2)
sc.exe qfailure TwinVPNService      # the §11.6 recovery ladder

# Our routes and addresses — the overlay LUID only; the host's own are untouched:
Get-NetRoute -InterfaceAlias TwinVPN*
Get-NetIPAddress -InterfaceAlias TwinVPN*
Get-NetIPInterface -InterfaceAlias TwinVPN* | Select InterfaceMetric

# The NRPT rules, ours and everybody else's. D7's failure lives here:
Get-DnsClientNrptRule
Get-DnsClientNrptPolicy -Effective
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"

# The pipe's DACL, which the service rewrites at every start (MI-A3):
(Get-Acl \\.\pipe\TwinVPN\mgmt).Sddl

# The three clocks, and the one that is invisible when it is wrong:
#   QueryUnbiasedInterruptTimePrecise  — MonotonicClock, sleep EXCLUDED
#   QueryInterruptTimePrecise          — ElapsedClock,   sleep INCLUDED
# There is no shell command for either; the adapter's clock tests are the check.

# Trace-level logging, in text, in the foreground:
$env:TWINVPN_LOG_LEVEL="trace"; $env:TWINVPN_LOG_FORMAT="text"; .\twinvpnsvc.exe --console
```

### Running the tests

```sh
cd shells/windows && cargo test --workspace                  # unprivileged, on Linux
cd ../../core   && cargo test -p twinvpn-platform-windows --features test-support
```

Both suites run **on a Linux host**, because that is the host this domain had.
They exercise the target-free layers: the filter renderer and its read-back, the
route and DNS planners, the restore point, the transactional state machine, the
MI envelope and framing, the DACL, the scope arithmetic and the exit-code
mapping. The syscall shim, the SCM integration and the named pipe itself are
**compiled and never executed**.

The tests that need Windows are written, gated and compiled:

```powershell
# Read-only, unprivileged. Asserts the refusals rather than skipping.
cargo test -p twinvpn-platform-windows --test windows_host

# The write path. An Administrator shell, on a machine you are willing to have
# TwinVPN filters installed on.
$env:TWINVPN_WINDOWS_TEST="1"
cargo test -p twinvpn-platform-windows --test windows_host -- --test-threads=1
```

`--test-threads=1` is not tidiness: there is one WFP sublayer and one routing
table per host, and two tests mutating them concurrently would be testing a race.

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

1. **Nothing here has been built for Windows, installed, or run.** `make
   cross-check` type-checks both this workspace and the adapter crate against the
   real `windows-sys` for `x86_64-pc-windows-msvc` with `-D warnings`. That is a
   compile proof. Every `unsafe` block in `twinvpnsvc/src/win32/` and in the
   adapter's `sys/win/`, `sock/imp.rs`, `iface/imp.rs`, `custody/platform.rs` and
   `wintun/platform.rs` has **never executed**. Wave 2's objective said this
   plainly and it is repeated here because it is the single most important fact
   about this directory.

2. **The MSI has never been built.** `packaging/` is a WiX definition and two
   documents. WiX has not run, nothing has been signed, and no service has been
   registered. The install and uninstall sequences are specifications of what
   should happen, not records of what did.

3. **`twinvpn-unblock.exe` does not exist.** ADR-0012 KS-20a makes the offline
   unblock command mandatory on Windows — it is one of the four platforms where
   the ADR says it is satisfiable — and ADR-0017 MI-12/MI-13 specify it. It is a
   separate package-owned binary, not a subcommand, "precisely because the case
   it exists for is 'the authority will not start'", and adding a third member to
   `shells/windows/Cargo.toml` is a workspace change this domain raised rather
   than made. **Until it ships, "blocked" can become "bricked" on this
   platform** — `packaging/` declares it so the MSI's component list is right the
   day it lands.

2a. **The service does not yet listen.** `mi::dacl::pipe_sddl` renders the
   security descriptor and `service::server::serve` is written and exercised end
   to end over `tokio::io::duplex` — but nothing calls
   `ConvertStringSecurityDescriptorToSecurityDescriptorW` or opens a
   `named_pipe::ServerOptions` accept loop, and nothing wires
   `win32::scm`'s dispatcher to `service::scm`'s transition function.
   `main.rs::serve` **refuses by name** rather than reporting itself ready
   (PS-18). So on a Windows host this binary would complete its start sequence
   and then decline to accept connections, which is the correct direction and is
   not a working service. **These two are the largest single gap in this
   directory.**

2b. **No power-event registration.** `classify_power_event`, `classify_wake` and
   LC-24's `ResumeSequence` are written and tested; `PowerSettingRegisterNotification`
   is never called, and `SERVICE_CONTROL_POWEREVENT` never reaches them because
   of 2a. The ordering is proven; the delivery is not built.

3a. **`twinvpn-restore.exe` does not exist.** ADR-0011 DN-20's restore service —
   the package-owned artifact that repairs a host whose agent will not start, on
   the platform the ADR calls "the highest-risk for D7". The restore point's
   *format* is implemented and its encoder and parser are tested here; the
   process that reads it is not built.

3b. **`twinvpn-bootfilters.dll` does not exist.** The MSI custom action that
   applies `wfp::boot::boot_set()`. The set is defined and tested; the thing that
   installs it is not written. `TwinVPN.wxs` references all three missing
   binaries, so a WiX build fails at `light.exe` with a missing file — which is
   the correct direction.

4. **The binary is named `twinvpnctl`, and ADR-0016 §11.2 names it
   `twinvpn.exe`.** ADR-0023 EM-42's rendered next actions say
   `run 'twinvpn peer disconnect nas-attic'`, which names a command that is not
   installed under that name. `shells/linux` raised the same conflict as W-41 and
   shipped `twinvpnctl`; this shell matched it rather than shipping two different
   names for one CLI on two platforms. **Needs a decision** — rename both, ship a
   `twinvpn` alias beside each, or amend the ADRs.

5. **KS-9(2)'s per-socket exemption is not expressible on this platform.** The
   rule requires the bootstrap exemption to be scoped to a socket *registered
   with the enforcement layer at bind time*. WFP's ALE conditions identify a
   **process** (`ALE_APP_ID` plus `ALE_USER_ID`); only a kernel callout driver
   could distinguish two sockets in one process, and ADR-0016 §10 puts driver
   lifecycle with the installer. So KS-10's `BOOTSTRAP`, `RESOLVER` and class-13
   probe socket classes **collapse into one process-scoped permit**. The residual
   is reported as a value — `wfp::filters::Ks9Residual` — rather than as a
   comment. Two things bound it and neither is this code's doing: KS-10's own
   structural argument (the agent exposes no proxy, no SOCKS listener, no
   port-forwarder), and KS-2, which the ALE layer satisfies for free because it
   classifies only locally originated connections. KS-10a's `UPDATE` class does
   **not** collapse, because the updater is a separate binary with its own
   app-id.

6. **The DoH half of ADR-0011 §11.9's DNS containment is not installed.** The WFP
   block covers UDP/TCP 53 and TCP 853 on every non-overlay interface. §11.9 also
   names "known-DoH endpoints", and that list is a policy input the seam does not
   carry: `twinvpn_platform::DnsConfig` has resolvers, search domains, split
   domains and a default-resolver flag, and nothing that names an encrypted-DNS
   endpoint. **The residual is that a browser with a pinned DoH endpoint on 443
   resolves off-tunnel.** Inventing a config field would be a contract change,
   and `contracts/` is frozen.

7. **KS-11's exempt counters are connections, not bytes.** The rule asks for
   "byte and packet counters for the exempt rule, per family". WFP has no counter
   objects; the only per-filter accounting is the net-event stream, and an ALE
   classification fires **once per connection attempt**. So the counters are a
   fold over events, `CounterSnapshot::unit` carries `Connections`, and a
   comparison against the agent's own frame accounting cannot silently mix the
   two units. Whether `FwpmNetEventEnum` reports its own drops at all is an open
   question the adapter's `tests/windows_host.rs` is written to answer.

8. **No `ADMINISTER` ceremony.** Every `ADMINISTER` operation is **refused**, not
   performed on a scope alone — which is ADR-0017 §11.5's third consequence and
   the safe direction. Wiring it needs the §11.14 elevation flow, and
   `POLICY.KILLSWITCH.DISARMED_BY_OWNER` has no path to being emitted until it
   exists.

9. **`SO_REUSEPORT` and `SO_MARK` have no Windows equivalent, and nothing is
   substituted.** `docs/networking.md` §3.6's birthday-paradox port prediction
   needs `SO_REUSEPORT`; Windows' `SO_REUSEADDR` is **not** an equivalent, because
   it lets a *different process* bind the identical address and port and take over
   delivery. A `reuse_port: true` request is refused at bind with
   `PLATFORM.OS_UNSUPPORTED` rather than quietly downgraded. `SO_MARK` is half of
   KS-9(1)'s Linux predicate and the §5.2 policy-routing key; on this platform
   the predicate is app-id plus SID and there is no routing mark, so
   `firewall_mark` is refused too. **§3.6's gathering strategy needs a
   Windows-specific answer that is not in the corpus.**

10. **`IP_DONTFRAGMENT` sets DF but does not suppress the stack's own path-MTU
    bookkeeping.** `docs/networking.md` §6.2 selects "1280 floor + DPLPMTUD, never
    classic PMTUD". On Windows the two coexist: the stack will act on an ICMP
    "packet too big" that RFC 8899 says to ignore. The ADR does not say which
    wins.

11. **`IP_TOS` is ignored by default on Windows.** Setting it has no effect
    without a QoS policy or the `DisableUserTOSSetting` registry value, and there
    is no error to report. The DSCP the core asks for may not reach the wire.

12. **IPv4 multicast join by interface *index* is not documented to work.**
    `MulticastOptions::interface` is an `InterfaceIndex` and the seam says it is
    "not optional"; Windows' `IP_ADD_MEMBERSHIP` takes an `ip_mreq` whose
    `imr_interface` is an IPv4 **address**. The index is encoded in network byte
    order, which is documented for `IP_MULTICAST_IF` and **not** for
    `IP_ADD_MEMBERSHIP`. The honest fix needs the interface table inside the
    socket provider. IPv6 has no such problem.

13. **Three `NetworkChange` variants have no source in this build.**
    `ResolversChanged`, `Nat64PrefixChanged` and `LinkPostureChanged` are never
    emitted: `NotifyIpInterfaceChange`, `NotifyRouteChange2` and
    `NotifyUnicastIpAddressChange` do not carry them. `ResolversChanged` would
    need a `RegNotifyChangeKeyValue` watch; `LinkPostureChanged` would need the
    power-setting notifications ADR-0022 §11.6's Windows row already names.
    **Nothing is fabricated** — a fabricated posture change is worse than an
    absent one.

14. **The boot identity is derived, and weaker than Linux's.** Windows has no
    `/proc/sys/kernel/random/boot_id`. This build derives one from the boot
    instant (system time minus the *biased* interrupt time, truncated to whole
    seconds) mixed with `MachineGuid`. Two cloned VMs booting in the same second
    collide, so it must never be treated as a device identifier or a secret. A
    boot instant falling within sampling error of a second boundary can derive
    differently in two processes of one boot; the consequence is bounded and in
    the safe direction — ADR-0022 LC-24 step 1 reads it as a cold start, which
    runs the *whole* of LC-4 including the enforcement re-assertion.

15. **A host with no readable `MachineGuid` cannot start.** A decision, recorded
    as one: it mirrors `twinvpn-platform-linux`'s refusal to fabricate a boot id,
    and it means a stripped or hardened image fails rather than running with a
    weaker discriminator.

16. **The Windows adapter reports link-local prefixes and the Linux one does
    not.** `twinvpn-platform-linux` builds a v6 address with its zone and so drops
    `fe80::/10` from `InterfaceFacts.addresses` (its own reported finding); this
    adapter uses `V6Addr::prefix_base`, which strips the zone — correct for a
    prefix. **The core therefore sees a different address set for the same host
    depending on which adapter is bound.** Two adapters should not settle that
    independently; it is the integration lead's.

17. **This shell contains `unsafe`, and `shells/linux` does not.** §1 says why
    and where. It is confined to `twinvpnsvc/src/win32/`, `twinvpnctl` has none,
    and every block carries a `// SAFETY:` comment — but the Linux shell's
    `#![forbid(unsafe_code)]` posture is genuinely stronger and this one does not
    match it.

17a. **`twinvpnctl` refuses colour on a plain `conhost` window that supports
    VT.** EM-43's third condition is a console-mode property readable only
    through `GetConsoleMode`, which is `unsafe`, and this binary has none. It
    asks for `WT_SESSION`/`ANSICON`/`TERM` instead and **fails closed**: plain
    text is legible; a literal `ESC[1m` in an incident record is not.

17b. **The SCM restart ladder is one delay, not two.** ADR-0016 §11.6 specifies
    restart at 1 s and then at 5 s; WiX v3's `util:ServiceConfig` carries a
    single `RestartServiceDelayInSeconds` for all restart actions. The second
    delay needs `sc failure` or a custom action, and neither is written.

17c. **`/guard:cf /CETCOMPAT /DYNAMICBASE /HIGHENTROPYVA` are set nowhere.**
    ADR-0016 §11.9 requires all four. They are a Rust build-configuration
    concern and no `.cargo/config.toml` in this workspace sets them.

17d. **PS-12a's local groups need a custom action the MSI does not have.** WiX
    v3's `util:Group` *references* a group; only `util:User` creates one. The
    `.wxs` declares `CreateGroups`/`RemoveGroups` and implements neither. A
    missing group would not fail the install — it would silently leave the pipe
    DACL naming a SID that does not resolve, which is a **fail-open** shape and
    the one item in this list that most deserves a fix before anything ships.

17e. **PS-21's uninstall order cannot be expressed in Windows Installer
    sequencing.** `StopServices` and `DeleteServices` have fixed positions, so
    steps 1–6 have to run in-process in the service before it stops
    (`--uninstall-prepare`), leaving the installer only steps 7–8. Running 3–6
    from a custom action after `StopServices` would run them with no authority
    holding the WFP session — the ordering PS-21 forbids. The `.wxs` says so; the
    service-side entry point is not written.

17f. **`Principal::account` is always `None`.** A client is attributed by SID
    rather than by account name, so MI-18's `actor_principal` is never absent —
    only less readable. `LookupAccountSidW` can block on a domain round trip and
    the attach path is the wrong place for one.

17g. **`win32::token::service_sid` always refuses.** The service SID is injected
    at construction (CD-2) rather than resolved from the service name, because a
    shell that discovered its own principal would be deciding which principal it
    is.

17h. **No event stream.** `event.subscribe` reaches the core and the core accepts
    it; the service does not yet push `Event` frames. This is inherited from the
    core rather than a Windows gap — `shells/linux/README.md` §7 item 2 records
    the same thing with the same consequence.

18. **Protected Process Light is not claimed.** ADR-0016 §11.9 says so and
    records it as future work: it requires ELAM signing, which is a Microsoft
    process this project has not started.

19. **`make cross-check` now covers this whole workspace — this gap is closed.**
    It previously stopped at the crates that do not link the core, because
    `twinvpnsvc` → `twinvpn-core` → `snow` → `ring`, and `ring`'s build script
    refuses a GNU compiler for `x86_64-pc-windows-msvc`. The integration lead
    removed that edge (`core/Cargo.toml` selects `snow`'s default resolver, which
    keeps ADR-0001 §11's primitives exactly), and the first full run found a real
    error in `main.rs` — two dead imports in `build_adapter`, in code nothing had
    ever compiled. `service/runtime.rs`, `service/server.rs` and `main.rs` are
    now type-checked for the target with `-D warnings` like everything else.

20. **Files exceed the 500-line guidance in several places.** The adapter's
    `sock.rs` (1561), `custody.rs` (1398), `wintun.rs` (1020) and `iface.rs`
    (1015) are the largest. Roughly half of each is tests and doc prose; the
    excess over the Linux references is the *target-free* layer that makes the
    behaviour testable on a host that is not Windows. Splittable, and not split.

---

## 8. Registry substitutions

`contracts/registry/reason_codes.json` is frozen (`ownership.md` §3), and most of
the codes the ADRs name for this platform are not in it. The arithmetic, checked
against the registry rather than estimated:

| Source | Codes the ADR names | Registered |
|---|---|---|
| ADR-0016 §11.12 (`PLATFORM.SERVICE.*` + `PLATFORM.PRIV.*`) | 19 | **3** — `SERVICE.UNINSTALL_INCOMPLETE`, `PRIV.HELPER_UNTRUSTED`, `PRIV.SANDBOX_DEGRADED` |
| ADR-0017 (`MGMT.*`) | 38 | **4** — this is `ownership.md` §8 **W-18**, unchanged, and it lands on this shell exactly as it landed on the Linux one |
| ADR-0012 §11.9 (`POLICY.KILLSWITCH.*`) | 9 | **3** |
| ADR-0020 §11.12 (`STORE.*`) | 19 | 6 |
| ADR-0022 (`PLATFORM.LIFECYCLE.*`) | 6 | **0** |

Nothing here invents one. Where a code is absent, the nearest **registered** code
is emitted and the specified spelling travels beside it in the log's
`specified_code` field — exactly the pattern
`shells/linux/twinvpnd/src/main.rs` uses.

| ADR names | Registered code emitted | What is lost |
|---|---|---|
| `PLATFORM.SERVICE.BOOT_ARTIFACT_UNREGISTERED` (ADR-0016 §11.12) | `PLATFORM.ADAPTER_UNAVAILABLE` | the `SERVICE` subdomain, and the CRITICAL severity |
| `PLATFORM.LIFECYCLE.SINGLE_INSTANCE_CONFLICT` (ADR-0022 LC-5) | `INTERNAL.INVARIANT_VIOLATED` | the `LIFECYCLE` subdomain. The class and severity are right |
| `STORE.KEYSTORE_UNAVAILABLE` (ADR-0020 §11.12) | `AUTH.KEY_STORE_UNAVAILABLE` | the `STORE` domain. Class and remediation are right |
| `STORE.BACKUP_EXCLUSION_FAILED`, `STORE.LOCK_CONTENDED` (ADR-0020 §11.12) | — | **not emitted at all**; there is no near-enough registered code |
| `NET.DRIVER_REPLACED` (ADR-0016 §10) | — | **not emitted**; the Wintun version comparison logs without a code |
| `NET.WFP_UNAVAILABLE` (`docs/networking.md` §5.3) | `PLATFORM.ADAPTER_UNAVAILABLE` | which subsystem was unavailable |
| `POLICY.KILLSWITCH.ASSERTION_MISMATCH`, `RULESET_TAMPERED`, `DISARMED_BY_OWNER`, `DISARM_REFUSED_REMOTE` (ADR-0012 §11.9) | — | **not emitted**; the registry carries three of ADR-0012 §11.9's nine `POLICY.KILLSWITCH.*` codes — `ENGAGED`, `ARM_FAILED` and `UNPROTECTED_FALLBACK`. The *conditions* are all detected and reported as typed values (`netcfg::ProtectionAssertion`, `wfp::readback::Verdict`); what is missing is the code to name them with |
| `POLICY.LEAK.EGRESS_OBSERVED` (ADR-0012 §11.9) | `POLICY.LEAK.DETECTED` | the distinction between "the canary observed egress" and "a leak was detected" |
| `PLATFORM.RESUMED` (ADR-0022 LC-24 step 5) | `NET.RESUME_OK` | the `PLATFORM` domain. The class (`TRANSIENT`) and severity (`INFO`) are right, and the measured gap travels as evidence either way |
| `PLATFORM.SERVICE.UI_DETACHED` (ADR-0016 PS-3) | — | **not emitted**; the *behaviour* PS-3 requires — the last client disconnecting changes nothing — is asserted by a test, which is the half that matters |
| `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` (ADR-0017 §11.12) | `POLICY.POLICY_DENIED` | **the costliest substitution here.** §11.12 gives the specified code its own exit code — **4**, authorization refused — and `POLICY.POLICY_DENIED` reads as a policy verdict, which tells a correct script to stop retrying something a group membership would fix |
| `PLATFORM.PRIV.REMOTE_ADMIN_REFUSED` (PS-14) | `POLICY.POLICY_DENIED` | the *reason*. An administrator on RDP is told "denied" rather than "denied **because this is a remote session**", and the remediation — walk to the console — is the part that is lost |
| `PLATFORM.PRIV.DROP_FAILED`, `PLATFORM.PRIV.CAPABILITY_MISSING` (PS-18) | `PLATFORM.ADAPTER_UNAVAILABLE` | the `PRIV` subdomain, and the FATAL/terminal classification |
| `PLATFORM.SERVICE.SUPERVISOR_ABSENT` (PS-11), `PLATFORM.SERVICE.QUARANTINED` (PS-9), `PLATFORM.PRIV.CAPABILITY_MISSING` (PS-18), `PLATFORM.PRIV.CLIENT_UNAUTHORIZED` / `ADMIN_AUTH_REQUIRED` / `REMOTE_ADMIN_REFUSED` (PS-12, PS-14) | — | **not emitted as codes.** Each condition is detected and refused; what is missing is the registered name to refuse it *with*. `PLATFORM.PRIV.SANDBOX_DEGRADED` is registered and is used for the PS-17 warnings it actually owns |

---

## 9. What this domain found and did not resolve

1. **ADR-0016 §11.6 and ADR-0022 LC-12 disagree about the service start type.**
   §11.6's supervision table says `SERVICE_AUTO_START` **with delayed start**;
   LC-12 says "Automatic wins" and gives the reason — delayed start defers the
   service by about two minutes, which lengthens exactly the window in which the
   host is fail-closed and offline. This build follows **LC-12**: it is later,
   it is reasoned, and it names the trade. The conflict is recorded in
   `packaging/TwinVPN.wxs` beside the element it decides. **Needs a decision.**

1a. **`ownership.md` §6 rule 6 requires `causation_id` to be preserved across
   every component boundary, and ADR-0015 specifies it nowhere.** §11.3's
   `Diagnostic` carries `correlation_id` only, and MI-15 forbids adding a field
   to the MI envelope. This shell therefore carries the pair *locally* — a
   `Correlation` value threaded through its own boundaries — and **never emits
   `causation_id` over MI**, because there is no field for it and inventing one
   would be the second contract MI-20 forbids.

2. **`twinvpn_mgmt::catalogue_digest()` returns a `u64`; ADR-0017 §11.7's
   `HelloAck.catalogue_digest` is a string.** This build renders the integer with
   `to_string()`. §11.7 makes the digest "the capability contract", so if the
   digest ever becomes a hex or base64 form, the two sides will disagree
   *silently* — a client would compute one spelling, the agent another, and the
   mismatch would look like a catalogue change rather than an encoding one.

3. **`windows-sys` 0.61 binds no `SE_GROUP_*` constant.** `SE_GROUP_ENABLED` is
   a literal in `win32/token.rs`, and it is **the bit the whole authorization
   model turns on**: a filtered administrator token still carries the
   `Administrators` SID, as *deny-only*, so a check that looked at membership
   rather than at the enabled bit would grant `ADMINISTER` to every
   administrator account whether or not the client had elevated. There is
   nothing in the crate to assert the literal against, unlike the eighty-eight
   `WIN32_ERROR` constants the adapter does check.

4. **`FWP_E_*` and `NTE_*` are likewise unbound in `windows-sys` 0.61.** Fifteen
   of the adapter's status literals therefore cannot be compared against the
   platform's own headers. What is checked instead is that each survives the
   crate's own signed round-trip and that its facility bits put it in the family
   `oserr` keys on — strictly weaker than the direct comparison the other
   seventy-three get, and said so in the module.

5. **W-43 has landed.** `twinvpn-env`'s `TokioRuntime` now calls `.enable_io()`,
   so this shell carries no equivalent of `shells/linux/README.md` §7 item 2b's
   I/O-driver refusal. Recorded here rather than silently omitted, because a
   reader comparing the two shells' start sequences would otherwise wonder where
   the step went.

---

## 10. W-18 on this platform

No `PlatformError` variant is retryable under the frozen
registry: `PLATFORM.ADAPTER_UNAVAILABLE` is classed `PERSISTENT`, so
`is_retryable()` is `false` even for `WSAEWOULDBLOCK`. This adapter never drives
a decision off it — it returns the variant and lets the core decide, which is
CB-2's direction anyway. Pinned as a test in `oserr.rs` so the day a
`TRANSIENT`-class `PLATFORM.*` code is registered, the test fails and the finding
is deleted.
