# `twinvpn-platform-android`

The Android implementation of the `twinvpn-platform` trait. **This crate is the
seam** (ADR-0018 §11.6).

**Owner:** `mobile-android`.
**Authority:** ADR-0018 §11.2 row 2.5, §11.5, §11.6, CB-1…CB-7, DP-4, PB-1;
`docs/networking.md` §5.1, §5.2's Android row, §5.4, §5.5; ADR-0010, ADR-0011,
ADR-0012, ADR-0019, ADR-0020, ADR-0022;
`docs/implementation/ownership.md` §10.

---

## 1. What is here, and what runs

`ownership.md` §9.2, binding on wave 3 through §10.3: **every layer that can be
target-free is target-free.** The table below is the consequence — the right-hand
column is what `make test` on a Linux host actually exercises.

| Module | Holds | Runs here |
|---|---|---|
| `builder` | the `VpnService.Builder` **programme** rendered from a `NetworkContract` | **yes** |
| `netchange` | `ConnectivityManager.NetworkCallback` decoded and diffed into `NetworkChange` | **yes** |
| `posture` | the three-valued lockdown posture, and the enforcement read-back | **yes** |
| `power` | Doze, thermal, App Standby, and the keepalive plan | **yes** |
| `oserr` | `errno` **and Java exception class** → `PlatformError` | **yes** |
| `codes` | the seventeen unregistered codes and their substitutions | **yes** |
| `sock` | UDP sockets, options, `recvmsg` + `cmsg`, the v4-mapped un-mapping | **yes**, over loopback |
| `tun` | the tun descriptor lifecycle, and both packet directions | **yes**, over a `socketpair` |
| `netcfg` | `apply` / `rollback` / the KS-17 swap / link facts | **yes**, over a fake controller |
| `custody` | Keystore identity and Tier-1 storage | **yes**, over an in-memory element |
| `clock` | `CLOCK_BOOTTIME`, `/dev/urandom`, the boot identity | **yes** |
| `iface` | the change stream and its backpressure | **yes** |
| `bridge::wire` | the bridge encoding, and every bound on it | **yes** |
| `bridge` | the five ingest entry points | **yes** |
| `bridge::jvm`, `bridge::entry` | the JNI symbols and the JVM-backed hostcalls | **no** — `cargo check` only |

`#[cfg(target_os = "android")]` appears in exactly **two** places, both inside
`bridge`: the `jvm` and `entry` module declarations. Everything else compiles for
the host *and* for `aarch64-linux-android` from one source, which is what makes
`make cross-check` a real gate on this crate rather than a formality.

`sock` and `tun` deserve a note: bionic and glibc share the descriptor and socket
API these modules use, so the code exercised over loopback and over a
`socketpair` on this host is **the code that ships**. That is not true of the JNI
layer, and the table says so.

---

## 2. Building and checking

`cargo` is not on the default PATH:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

From `core/`:

```sh
# The real target, against the real bionic crates. -D warnings.
cargo clippy -p twinvpn-platform-android --all-targets \
    --target aarch64-linux-android -- -D warnings

# The host, for every target-free layer.
cargo clippy -p twinvpn-platform-android --all-targets -- -D warnings

# The tests. All of them run; none is `#[ignore]`d.
cargo test -p twinvpn-platform-android

# ADR-0018 T1: CD-3 / CD-I2 / CD-I5 / CB-3.
cargo run -q -p xtask -- lint
```

From the repository root, `make cross-check` runs the target pass as part of the
wave gate.

**Nothing here links and nothing runs on a device.** `cargo check` and `clippy`
need no linker, which is why the target pass works at all; it is a **compile
proof**, not a behaviour proof, and `ownership.md` §9.2 forbids reporting it as
one.

### The one bionic/glibc difference this crate has found

`in6_pktinfo.ipi6_ifindex` is `unsigned int` on glibc and **`int` on bionic**.
`sock::cmsg::ifindex` narrows it totally — a negative or zero index is *not an
interface*, and the failure is a value rather than a panic on a kernel-supplied
number in the middle of the receive path. This is exactly the class of defect
`cross-check` exists to catch, and it is why the target pass is part of the gate
rather than a nice-to-have.

---

## 3. Environment configuration

Everything is **injected at construction** (CD-2). This crate reads no
environment variable, no property, and no ambient path.

| `AndroidAdapterParts` field | Supplied by | Notes |
|---|---|---|
| `controller` | `bridge::jvm::JvmHost`, or a test double | the `VpnService` side |
| `element` | the same object | Keystore; identity **and** Tier-1 are one platform object on Android |
| `store_root` | the shell, from the **credential-encrypted** context | CB-7; created with its attributes before it is handed over |
| `vpn_config` | the core, from user configuration | app exclusions, as a deny list |

The one thing the crate discovers rather than receives is the boot identity, and
it declares which source answered (`BootIdSourceKind`). See §5.

---

## 4. Debugging

- **Which adapter is loaded** — `binding_name()` is `"android-vpnservice"`, and
  it reaches the diagnostic bundle through `CoreBuildIdentity` (S-46).
- **What the adapter can and cannot do** — `AndroidPlatformAdapter::posture()`
  returns the Keystore `SecurityLevel`, whether it is hardware-backed, the
  three-valued lockdown posture, which boot-id source answered, and whether the
  CSPRNG could be drawn from. Declared at startup, never inferred later.
- **What the claim actually is** — `AndroidNetworkConfig::enforcement_view()`
  returns the OS-observed claim, which families it covers, the disposition in
  force, and the posture. `installed_ruleset()` is derived from it.
- **A failure with no obvious cause** — every `PlatformError` carries an
  `OsDetail { code, call }`. `call` is a stable tag (`"bind"`, `"read(tun)"`,
  `"VpnService.Builder.establish"`, `"bridge.addresses"`), so a support case
  greps for a name rather than for a number. A JVM failure carries
  `code = -1`, which is deliberately not `0`: zero means "no OS error at all",
  and the two are different facts.
- **Tracing** — `tracing` is a dependency and no macro in this crate logs a
  value. §6 rule 11 is structural here rather than reviewed: there is no call
  site that could log a key, an item, a payload or an exception *message*.

---

## 5. Decisions taken in this crate, and why

Each of these is a real choice with a cost, recorded here so it is reviewable
rather than discovered.

### 5.1 `BLOCKED` and `PROTECTED` share one route claim

ADR-0012 §11.6 lists **no firewall** for Android: the `VpnService.Builder` route
claim *is* the enforcement point. KS-17 requires the transition between the two
postures to be an atomic swap with rules **never absent** — and the only way to
change a claim on Android is `Builder.establish()` again, which tears the
interface down and rebuilds it, leaving an interval in which *nothing* is
claimed.

So the claim is **identical** in both postures and the swap is a single atomic
store read by the datapath. `swap_is_atomic` is `true` for that reason, and it is
a reason rather than an assertion.

### 5.2 `survives_core_exit` is dynamic, and defaults to `false`

The tun descriptor dies with the process. Only OS-enforced always-on lockdown
outlives it — and a non-DPC app cannot observe whether lockdown is on (LC-40). So
the declaration follows the three-valued posture: `false` unless a managed
configuration reports `CONFIRMED`. That is ADR-0012 §11.6's Android limitation
row (*"everything, until the user enables lockdown"*) made machine-readable.

### 5.3 `set_mtu` is refused after `establish()`

`Builder.setMtu` is only readable at `establish()`, so honouring a post-establish
MTU change means establishing again — which opens the window §5.1 exists to keep
closed. Between a probeable MTU and a leak-free swap this adapter takes the
leak-free swap and returns `PlatformError::OsUnsupported`, which is the seam's
documented way to state a host fact.

**The consequence is stated rather than hidden:** on Android the tunnel MTU is
fixed for the life of a generation. DPLPMTUD still functions — it probes the
*outer* path and the core clamps its own payload — but the inner interface MTU
cannot follow it downward without a new generation. Reported as a finding.

### 5.4 A single-family default claim is **widened**, not refused

A contract asking for a v4 default and no v6 default is the shape ADR-0010 R6
forbids, and on Android an unclaimed family does not fall through to a blocking
rule — it egresses. `builder::render` therefore claims **both** whenever either
is asked for, or whenever the ruleset is `Blocked`. Widening rather than refusing
is the fail-closed direction: claiming `::/0` costs nothing when there is no v6
traffic and closes the leak when there is.

### 5.5 The boot identity has two sources, and says which answered

`/proc/sys/kernel/random/boot_id` is preferred and is exact. Where SELinux makes
it unreadable — common on Android — the identity is derived from
`CLOCK_REALTIME − CLOCK_BOOTTIME`, quantised to 60 s. **Its imprecision is
stated:** a wall-clock step larger than the quantum moves it and reads as a
reboot, whose consequence under LC-7 is `COLD_START` with
`absence_cause = UNKNOWN` → treated as `CRASH`. That is the cautious direction;
the opposite error — *missing* a reboot — this derivation cannot produce, because
a real reboot always moves the boot wall time by more than a minute.

### 5.6 Entropy is `/dev/urandom`, not `getrandom(2)`

Not a lint constraint (W-36's exemption permits the needle here) but an
API-level one: `docs/networking.md` §5.2 sets the floor at **API 26**, and bionic
did not expose `getrandom(2)` until API 28. A `dlsym` probe would be ambient
discovery, which CD-2 forbids. On every Android release `/dev/urandom` is the
same kernel CSPRNG, and `Entropy::fill` never falls back to anything weaker.

---

## 6. Findings this crate carries

Each is pinned by a test rather than left in prose, so registering the missing
piece fails the build and points at the line to delete.

| # | Finding | Where |
|---|---|---|
| **W-18 instance** | **Seventeen** codes the Android rows of the corpus name are absent from the frozen registry — every `PLATFORM.LIFECYCLE.*`, `NET.CONCURRENT_VPN`, `STORE.KEYSTORE_LOCKED`, `POLICY.LEAK.EGRESS_OBSERVED`, `DNS.PLATFORM.PRIVATE_DNS_ACTIVE` among them | `codes::UNREGISTERED`, tripwired |
| **W-40 instance** | No `PlatformError` is retryable under the frozen registry: `EAGAIN` → `Transient` → `PLATFORM.ADAPTER_UNAVAILABLE`, which is classed `PERSISTENT` | `oserr::tests` |
| **KS-9(1) understates Android** | *"the provider's own sockets are excluded from its own tunnel by construction"* is true on iOS and **false here** — `VpnService.protect(int)` is an explicit per-descriptor call, and a socket that misses it loops into our own tunnel | `sock`, and `sock::tests::every_socket_is_protected_before_it_is_bound` |
| **W-24 on Android** | The enforcement read-back is half OS-held (the descriptor's validity) and half process-local (the disposition). No Android API returns the second half | `posture`, documented at `EnforcementView` |
| **W-39** | `InterfaceFacts.addresses` is `Vec<IpPrefix>`, which cannot represent a host address or a link-local one | `netchange::AndroidNetwork::addresses` |

---

## 7. `ownership.md` §10.4, and what this crate exports beyond the trait

W-24 and W-25 record that `twinvpn.h`'s F-9 vtable carries **no**
`installed_ruleset` read-back, **no** `current_generation`, **no** socket
provider and **no** interface enumerator. §10.4 rules that on mobile those stay
in Rust, in-process, here:

| Capability | `twinvpn.h` F-9 | this crate |
|---|---|---|
| sockets (the NAT ladder) | **absent** (W-25) | `sock` |
| interface enumeration and events | **absent** (W-25) | `iface` |
| `installed_ruleset` read-back | **absent** (W-24) | `posture::EnforcementView` |
| `current_generation` | **absent** (W-24) | `netcfg` |
| `set_mtu`, `datapath`, `enforcement_custody`, `supported_families` | absent | present |

The Kotlin side reaches them through `bridge`, which is **not** an ABI of record
and carries **no TwinVPN domain fact** — its vocabulary is Android's, and
`bridge::tests::the_bridge_speaks_android_and_never_twinvpn` asserts it over the
surface's own source.

**This does not discharge W-24 or W-25.** The general claim *"a vtable-only shell
can assert protection"* remains false, and ADR-0018 §11.4 still needs the
amendment they ask for.
