# `twinvpn-platform-ios`

The iOS/iPadOS implementation of the `twinvpn-platform` trait. **This crate is
the seam** (ADR-0018 §11.6).

**Owner:** `mobile-ios` (`docs/implementation/ownership.md` §10.1).

---

## 1. What is verified, and what is not

`ownership.md` §10.3's four categories, for this crate specifically:

| Category | Content | Command |
|---|---|---|
| **executed** | every target-free layer, and every trait implementation driven end to end over a recording host | `cargo test -p twinvpn-platform-ios` — **210 tests** |
| **compiled** | every line, type-checked against the real Darwin sys crates for `aarch64-apple-ios`, `-D warnings`, **never linked, never run** | `make cross-check` |
| **written, not compiled** | nothing in this crate. All Swift is in `shells/ios` | — |
| **written, not executed** | nothing in this crate | — |

The one thing the executed row cannot reach is the four Darwin syscalls in
[`sys`], and the crate asserts their **absence** on the build host rather than
stubbing them into a plausible-looking success. See §4.

---

## 2. Why the crate is shaped the way it is

`ownership.md` §10.3's design rule: "**every layer that can be target-free is
target-free**, `#[cfg]` is confined to the thinnest syscall shim, and everything a
reviewer would want to see exercised runs its tests on this Linux host."

| Module | `#[cfg(target_os)]` | `unsafe` | What it decides |
|---|---|---|---|
| `oserr` | none | none | `errno` / `OSStatus` / `NEVPNError` → registered `reason_code` |
| `settings` | none | none | `NEPacketTunnelNetworkSettings` from a `NetworkContract` |
| `enforce` | none | none | `includeAllNetworks`, on-demand rules, the two rulesets, P09's arithmetic |
| `pathmon` | none | none | `NWPath` snapshot → `NetworkChange` and `LinkFacts` |
| `keychain` | none | none | which accessibility class, access group and protection class |
| `lifecycle` | none | none | stop reasons, the memory ladder, the foreground lease, start classification |
| `cmsg` | none | none | the Darwin control-message walk |
| `sockplan` | none | none | which `setsockopt` calls a `SocketOptions` means |
| `netcfg`, `tun`, `custody`, `iface`, `host` | none | none | the trait implementations, over an injected host |
| `bridge` | none | 5 | pointer marshalling for the Swift bridge |
| `sock` | 1 | 1 | binding and datagram I/O |
| **`sys`** | **all** | 4 | `mach_continuous_time`, `mach_timebase_info`, `getentropy`, `sysctlbyname` |

Every `unsafe` block carries a `// SAFETY:` comment naming its invariant.

The payoff is concrete. Three examples of decisions that would have been Swift,
and are tested here instead:

- **The Darwin control-message alignment.** `<sys/socket.h>` aligns to
  **4** bytes; Linux aligns to 8. A walk written against Linux's alignment
  misparses the second message whenever the first payload is not a multiple of
  8 — which `in_pktinfo` (12 bytes) is not. The failure is a *misparsed address*,
  so it would surface as a reflexive candidate pointing somewhere plausible and
  wrong. `cmsg::tests::two_messages_are_both_read_at_darwins_alignment` catches it
  on Linux.
- **`AF_INET6` is 30 on Darwin and 10 on Linux.** A packet labelled with the
  wrong family is dropped by the OS in silence. `tun` transcribes 30 and asserts
  it differs from `libc::AF_INET6`.
- **`IPV6_V6ONLY` is 27 on Darwin and 26 on Linux; `IP_TOS` is 3 and 1.** A build
  that took Linux's numbers would set `IP_HDRINCL` where it meant `IP_TOS`, and
  none of it fails loudly. `sockplan` transcribes them and asserts the divergence.

---

## 3. Which surface a Swift shell binds

`ownership.md` §8's **W-24** and **W-25**: `twinvpn.h`'s F-9 vtable has no
`installed_ruleset` read-back, no `current_generation`, no socket provider and no
interface enumerator, so a shell bound only to it "cannot do NAT traversal and
cannot produce a `ProtectionAssertion` at all".

§10.4's wave-3 ruling keeps those in Rust, in-process, here, and Swift reaches
them through `bridge` — **internal linkage, versionless, no compatibility
obligation**. There is deliberately no `abi_major` in `bridge` and there must not
be one: a version number would assert a promise the ruling withholds.

`bridge::tests::the_bridge_surface_carries_no_domain_fact` asserts the vtable's
size, so adding an entry fails with a message naming §10.4's rule. That is a
prompt to check the new entry, not a prohibition on ever adding one.

---

## 4. What this crate refuses to fake

- **On the build host, `sys` returns `None` and `Err`.** No fabricated clock
  reading, no substituted entropy, no invented boot id. ADR-0022 LC-8 warns that
  substituting the wrong clock "compiles, passes every test that does not
  suspend, and fails only on a device that actually sleeps" — and a stub that
  returned zero would make `clock`'s tests pass here and the product wrong on a
  phone.
- **`enforce::custody()` reports `survives_core_exit: false`.** ADR-0012 gives
  iOS **`◐`** for agent crash and `SIGKILL`, and the seam's `bool` has no `◐`.
  `true` asserts CB-6's guarantee iOS does not give; `false` understates what the
  OS re-arms. O-18 fixes the direction. **That the seam cannot express `◐` is a
  finding.**
- **`identity_agree` refuses X25519 and substitutes nothing.** ADR-0007 N-5 is
  why: "platform key APIs largely do not offer X25519 ECDH". There is no branch
  in `custody` that reaches for a software key, and no key there to reach for.
- **`record_aead_custody()` is `CoreHeld`, unconditionally.** ADR-0020 §11.3's
  CB-6a table, Apple row: "**No.** The Secure Enclave exposes key *agreement* and
  signing, not an arbitrary-length AEAD over caller data." A constant rather than
  a probe, because a probe would imply the answer could come back the other way.
- **A route metric and a firewall mark are reported as unrepresentable**, not
  silently dropped.
- **The host's system resolvers are declared unreadable, not reported as
  absent.** ADR-0011 §11.5's SPLIT mode forwards default-class names to "the
  host's pre-existing upstream resolvers", and iOS vends no public API that names
  them: Apple's DTS states "iOS does not provide APIs to get per-interface DNS
  configuration information", `SCDynamicStore` is the macOS mechanism and is SPI
  on iOS, and `NEDNSProxyProvider.systemDNSSettings` — the one public read —
  belongs to a **DNS-proxy** provider, not the `NEPacketTunnelProvider` §11.12
  fixes. `<resolv.h>`'s `res_9_ninit(3)` is not the escape hatch: Apple's DTS says
  to "avoid that API wherever possible", its Xcode-16.4 header produced
  `dyld: Symbol not found: ___res_9_state` against the shipping
  `libresolv.9.dylib`, and on iOS it mis-reports IPv6 servers as `AF_UNSPEC`.
  `PathSnapshot::resolvers` is therefore empty **because the list is unreadable**,
  and since the seam's `PerFamily<Vec<IpAddr>>` has no third value,
  `AdapterPosture::system_resolvers_readable` carries the fact — §5.1's rule
  applied. Nothing substitutes a resolver address.

---

## 5. Findings

Reported rather than patched. `contracts/` is frozen (`ownership.md` §3) and
`docs/` belongs to the integration lead.

1. **A `PLATFORM.LIFECYCLE.*` family that ADR-0022 names normatively does not
   exist in the frozen registry.** Absent: `REHYDRATED`,
   `MEMORY_BUDGET_EXCEEDED`, `KEY_UNAVAILABLE_PRE_UNLOCK`,
   `ONDEMAND_RULES_ABSENT`, `REHYDRATE_INCOMPLETE`, `REHYDRATE_TIMEOUT`,
   `LOW_POWER_PROFILE`, `HIBERNATE_RESUMED`, `CRASH_REPORT_SUPPRESSED`. The ten
   registered `PLATFORM.*` codes carry no `LIFECYCLE` subdomain. Also absent:
   `POLICY.KILLSWITCH.BOOT_ENFORCEMENT_UNAVAILABLE` (KS-19),
   `STORE.KEYSTORE_LOCKED`, `STORE.BACKUP_EXCLUSION_FAILED`,
   `STORE.RESTORED_FOREIGN_HOST`, `STORE.LOCK_CONTENDED` (ADR-0020),
   `MGMT.CHANNEL_UNSUPPORTED` (ADR-0017 §11.2.1),
   `POLICY.EXEMPT.PLATFORM_MANDATED` (ADR-0012's iOS limitation row). **Nothing
   here invents one.** Where a registered code owns the condition it is used;
   where none does, the fact is a declared posture value.
2. **`EnforcementCustody::survives_core_exit` is a `bool` and iOS is `◐`.** §4.
3. **`IdentityPublic` requires a `device_id` this crate cannot compute.** It is
   SHA-256 of the generation-0 key (ADR-0007 §7.1) and CD-I2 confines hashing to
   `twinvpn-crypto`. On Linux the gap is invisible because the shell is Rust; a
   Swift shell cannot supply it. `custody::IosIdentityCustody` takes it as an
   injected `IdentityRecord` and **refuses** until it has one.
4. **`PlatformError` has no variant for "the caller exceeded a declared limit".**
   `settings::render` uses the nearest registered condition and names the limit
   in `OsDetail::call`.
5. **`TunnelDevice` has no batched write.** PB-1 budgets one crossing per batch;
   `write_packet` is per-packet, and a buffering implementation would have to
   return `Ok` for a packet that has not reached the OS. This crate writes
   immediately and offers `IosTunnelDevice::write_batch` beside it.
6. **Three documents disagree about the iOS contract-fetch split.**
   `networking.md` §5.4 (corrected) and ADR-0018 §11.12/§11.16 (m) say the
   extension fetches and `core-lite` verifies; ADR-0020 **ST-31** says the app
   fetches and the provider verifies; ADR-0022 **LC-17** says the app does both.
   This domain implements the §11.12 reading, per the brief and PS-24 condition 3.
7. **`causation_id` does not exist in the contract set.** `ownership.md` §6
   rule 6 requires it preserved across every boundary; `MgmtEnvelope` (ADR-0017
   §11.3) defines `request_id` and `correlation_id` and no third field.
8. **W-40 holds here too.** No `PlatformError` is retryable under the frozen
   registry; pinned in `oserr`.

---

## 6. Two defects found by tests written to check a claim

Recorded because they are the clearest evidence that the design rule pays.

- **The lost-event notice was itself being lost.** `iface` first sent
  `EventsLost` down the same bounded queue that had just refused a change — so
  the one subscriber that fell behind was the one subscriber never told. The
  count now lives in an `AtomicU64` beside the queue and is reported *ahead* of
  the events that survived the gap.
- **`catch_unwind` around a call into an `extern "C"` function cannot catch it.**
  Since Rust 1.71 such a function **aborts** at the ABI boundary. The first draft
  of `bridge`'s containment test aborted the whole test binary rather than
  failing. The module header now states precisely what the guard does and does
  not protect, and F-7's rule — the guard goes **inside** each exported body —
  is applied to every `#[no_mangle]` function here.

A third, caught the same way: `netcfg::apply`'s failure path took the same
non-reentrant `Mutex` twice and deadlocked the provider on exactly the path that
most needs to make progress.

---

## 7. Environment, building, debugging

`cargo` is not on the default `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

From the repository root:

```bash
# host: the executed row
cd core && cargo test  -p twinvpn-platform-ios
cd core && cargo clippy -p twinvpn-platform-ios --all-targets -- -D warnings

# target: the compiled row. NEVER LINKED, NEVER RUN.
cd core && cargo clippy -p twinvpn-platform-ios --all-targets \
    --target aarch64-apple-ios -- -D warnings

# the T1 architectural lints (CD-3, CD-I2, CD-I5, CD-CB3)
cd core && cargo run -q -p xtask -- lint

# the full gate
make lint && make test && make test-contracts && make cross-check
```

**No configuration is read from the environment.** CD-2 forbids it and ADR-0020
ST-12e restates it for the store root: every value — the Keychain access group,
the service, the App Group container, the enforcement posture, the tunnel remote
address — arrives through `IosAdapterParts`. There is no environment variable
this crate reads, and adding one would let a value an attacker on the device can
influence reach a Keychain query.

### Debugging without a device

`host::RecordingHost` is the whole story. It records every programme the adapter
rendered and replays whatever the test told it to answer, so the way to
investigate "what would this contract install" is:

```rust
let host = Arc::new(RecordingHost::new("/tmp/store"));
let adapter = IosPlatformAdapter::new(/* … */);
adapter.network_config().apply(&contract).await?;
println!("{}", host.state().settings_applied[0]);
```

`host::DetachedHost` models "no provider is running", which is a **named state**
rather than a null dereference and is what the adapter binds before Swift
registers.

### Debugging on a device

`IosPlatformAdapter::posture()` is the first thing to read. It declares
`EnforcementLimits`, `ClockPosture`, `SocketPosture`, whether the element is
genuinely hardware-backed, and whether a Swift provider has registered — each a
separate field because "this device has a Secure Enclave and this build cannot
use it" and "this is a simulator" have different remediations.
