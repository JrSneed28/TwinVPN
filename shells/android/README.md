# `shells/android` — the TwinVPN Android app

**Owner:** `mobile-android`.
**Authority:** ADR-0018 §11.12 (this path), §11.5's two Android rows, CB-1…CB-4,
PB-1; ADR-0019 §11 (Compose, the permission table, the presentation contract);
ADR-0022 §11.3, §11.4, LC-33, LC-40; ADR-0012 §11.6; ADR-0020 §11;
`docs/networking.md` §5.2, §5.4, §5.5;
`docs/implementation/ownership.md` §10.

---

## 1. Status — read this first

> ## NOTHING IN THIS DIRECTORY HAS BEEN COMPILED.

There is no JDK, no Gradle, no Android SDK and no NDK on the host wave 3 runs
on. Every Kotlin file here, every Gradle script, every resource and every
instrumented test is **written, not compiled** in `ownership.md` §9.2's sense,
and the instrumented suite is additionally **written, not executed**. No `make`
target claims otherwise, and the completion report says so in those words.

What *is* proven is the other half. §2 explains why that is most of the product.

---

## 2. Where the decisions live, and why this shell is thin

`ownership.md` §10.3 states the design rule for the wave:

> **Every layer that can be target-free is target-free.** A mobile domain that
> pushes logic up into Swift or Kotlin has moved it from *executed* to *written,
> not compiled* — and, under CB-2, has probably moved a decision into a shell as
> well. The two failures have the same shape and the same fix.

So this shell is deliberately small, and everything it *would* otherwise decide
lives in `core/crates/twinvpn-platform-android`, which runs **198 tests** on a
Linux host and is type-checked for `aarch64-linux-android` with `-D warnings`.

| Decision | Not here — there | Proof |
|---|---|---|
| which `VpnService.Builder` calls, in which order, claiming what | `builder::render` | executed |
| that a full tunnel claims `0.0.0.0/0` **and** `::/0` | `builder::render` | executed |
| what a `NetworkCallback` burst *means* (the diff) | `netchange::diff` | executed |
| whether a handoff is `MIGRATING` or `RECONNECTING` | `twinvpn-session`, via `twinvpn-core` | executed |
| the three-valued lockdown posture, and that `UNVERIFIED` presents as unprotected | `posture` | executed |
| what `installed_ruleset` may honestly report | `posture::EnforcementView` | executed |
| every `errno` and every Java exception class → a registered `reason_code` | `oserr` | executed |
| every bound on the bridge payload | `bridge::wire` | executed |

What is left in Kotlin is genuinely platform-bound: obtaining a `Builder`,
posting a notification, registering a callback, calling `KeyStore`, drawing.

### The rule you can check by reading

- **`NativeHost.kt`** — the class Rust calls back into. **No method contains a
  branch.** Each is one `builder.addRoute(...)`-shaped statement.
- **`NativeBridge.kt`** — the five calls in. Every parameter is something
  `ConnectivityManager`, `PowerManager` or `VpnService` said. There is no
  `setState`, no `reportError(code)`, no `onConnected`. The Rust side asserts
  this over its own source, so it is a test rather than a convention.
- **`ui/`** — no screen contains a string describing a connection state, a
  failure, or a remediation. `res/values/strings.xml` is chrome only, and its
  header says so. Every sentence a user reads comes from `tw_render_diagnostic`
  (ADR-0018 F-10), resolved from the frozen registry in the caller's locale.

### The one place a domain fact comes close, and what keeps it out

ADR-0022 LC-33 requires the ongoing notification to be *"visually distinct for
`DEGRADED` and `BLOCKED`"*, and ADR-0015 §11.6 requires the same of the status
surface. The obvious implementation is `when (state) { BLOCKED -> red; … }` —
and it is forbidden, because CB-2 bans a shell branch whose condition is a
`ConnectionState`.

The permitted one branches on **`Rendered.severity`** and
**`Rendered.protection`**: registry attributes the core resolved and handed
across in F-4's `resolved` block. The mapping from condition to severity is made
once, in the core, from `contracts/registry/reason_codes.json` — so six shells
cannot diverge on it (R-31), and what remains here is colour and icon, which
CB-4 assigns to the shell in terms. It is concentrated in
`ui/TwinVpnTheme.kt::statusColor` so that a future fifth call site cannot pick a
different hue for the same severity.

---

## 3. Building — what a builder with an SDK would do

None of this has been run. It is written so that the first person with a
toolchain has a sequence rather than a puzzle.

### 3.1 Prerequisites

| Tool | Version | Pinned by |
|---|---|---|
| JDK | 21.0.5 | `build/toolchain/env.sh:10` |
| Kotlin | 2.0.21 | `build/toolchain/env.sh:11`, mirrored in `gradle/libs.versions.toml` |
| Android SDK | platform 35, build-tools 35 | `app/build.gradle.kts` |
| Android NDK | r27+ (16 KiB page alignment, C-12) | see §3.2 |
| Rust targets | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` | `rustup target add` |

### 3.2 The native library

The CDYLIB is not yet built by Gradle. Wiring `cargo` into the Gradle graph is
the `infrastructure` domain's (`build/`), not this one's — this directory may not
edit `build/`, and inventing a second toolchain pin here would be a second place
to keep in step. Until it lands, build per ABI and place the result:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cd core

# One per shipped ABI. `--release` for the §11.9 budget; the debug artifact is
# several times the ceiling and must never be measured against it.
cargo build --release -p twinvpn-platform-android --target aarch64-linux-android

cp target/aarch64-linux-android/release/libtwinvpn_platform_android.so \
   ../shells/android/app/src/main/jniLibs/arm64-v8a/
```

Two things a builder must check, because both fail on a user's device rather
than in CI:

1. **16 KiB load alignment (C-12).** The NDK linker needs
   `-Wl,-z,max-page-size=16384`. A 4 KiB-aligned `.so` refuses to load on a
   device with a 16 KiB page size.
2. **`panic = "unwind"` (ADR-0018 §11.3).** Set in `core/Cargo.toml`'s release
   profile. `abort` would turn a contained panic into a process kill.

### 3.3 The app

```sh
cd shells/android
./gradlew :app:assembleDebug
./gradlew :app:lint
```

`allWarningsAsErrors` is on. A Kotlin half that nobody has compiled must at least
be one nobody can compile sloppily.

### 3.4 The instrumented suite

```sh
./gradlew :app:connectedAndroidTest
```

**Every test in `app/src/androidTest/` will fail on the first run**, and that is
the intended state rather than a defect: their helpers are `TODO("device farm")`.
They describe what a farm must measure; they do not pretend to have measured it.
See §5.

---

## 4. Debugging

- **Which adapter is loaded** — `binding_name()` is `"android-vpnservice"`,
  recorded in `CoreBuildIdentity` (S-46).
- **The declared posture** — `AndroidPlatformAdapter::posture()`: the Keystore
  `SecurityLevel`, whether it is hardware-backed, the three-valued lockdown
  posture, which boot-id source answered, and whether the CSPRNG is drawable.
  ADR-0016 PS-17's principle applied to the adapter: *silently running wider than
  declared is the defect this rule retires.*
- **A thrown `IllegalStateException` from a `native…` call** — its message is a
  **registered `reason_code`**, never a sentence. `adb logcat` will show e.g.
  `PLATFORM.VPN_PERMISSION_DENIED`. The sentence a user should see comes from the
  core (CB-4); a shell that composed one would be R-15's defect.
- **`UnsatisfiedLinkError` at startup** — a missing ABI. ADR-0018 VR-4: shell and
  core ship as one signed artifact, so this is a **packaging defect**, not an
  operating state.
- **The tunnel comes up and nothing flows** — check `VpnService.protect`. On
  Android the provider's own sockets are **not** excluded from its own tunnel by
  construction (see the adapter README §6); an unprotected socket loops.

---

## 5. The test matrix, and which half is where

`ownership.md` §10.5's twelve rows, and where each is covered.

| Row | Host, **executed** | Device, **written not executed** |
|---|---|---|
| foreground / background | `matrix.rs` row 1 | `LifecycleMatrixTest` |
| lock / unlock | `matrix.rs` row 2 (LC-15's locked element) | `LifecycleMatrixTest` |
| network changes | `matrix.rs` row 3 | — |
| cellular ↔ Wi-Fi migration | `matrix.rs` row 4 (**`MIGRATING`, decided by the core**) | — |
| tunnel restart | `matrix.rs` row 5 | — |
| process termination | `matrix.rs` row 6 (the LC-2 rehydration half) | `LifecycleMatrixTest` (the kill) |
| restored connection | `matrix.rs` row 7 | — |
| revoked peers | `matrix.rs` row 8 (both halves) | `DozeAndRevocationTest` (a second VPN app) |
| kill-switch behaviour | `matrix.rs` row 9 (KS-17, LC-40, the keepalive prohibition) | `LeakMeasurementTest` (the boot-to-claim window) |
| IPv4 leaks | `matrix.rs` rows 10–11 | `LeakMeasurementTest` |
| IPv6 leaks | `matrix.rs` rows 10–11 (**both directions**) | `LeakMeasurementTest` (R6's after-the-fact case) |
| DNS leaks | `matrix.rs` row 12 (both resolver families) | `LeakMeasurementTest` (incl. Private DNS) |

`matrix.rs` is `core/crates/twinvpn-platform-android/tests/matrix.rs`, and it
**runs**: `ownership.md` §10.5 rule 1 requires every row that can be a
host-runnable test over the mock adapter to be one, and writing them only as
device tests *"would put them in the written, not executed row for no reason"*.

Rows appear on the device side only where a device genuinely adds something a
host cannot: an OS that kills processes, a Doze controller, a second VPN app, and
a packet capture.

---

## 6. What is NOT done

Stated plainly rather than left to be discovered.

1. **Nothing here compiles.** §1.
2. **The core event stream is not bound.** `core/CoreClient.kt` is a stub, and
   the reason is a contract gap rather than a shortcut: `tw_core_submit` takes
   *"an encoded command from the same command set the local management interface
   carries"*, and **`contracts/` defines no such message** (OQ-2 excluded
   `mgmt.proto`; recorded as `ownership.md` §8 **W-38**). `shells/linux` does not
   hit this because it links the Rust crates and calls typed constructors; a
   Kotlin shell cannot. Inventing an encoding here would create the second
   vocabulary OQ-2 exists to prevent, in the shell least able to keep it in step.
   **Raised as a cross-boundary request; not worked around.**
   Consequence: the UI renders nothing yet, the notification renders its
   placeholder, and the quick-settings tile is `STATE_UNAVAILABLE`. Each is the
   fail-safe value, and none is a fabricated status.
3. **`SocketKeepalive` is not bound to the platform API.**
   `SocketKeepaliveHolder` logs and returns. The API needs a connected
   `DatagramSocket` object and the socket lives on the Rust side (§10.4 puts the
   NAT ladder there); bridging a descriptor back into one is a device-verified
   step. **No fallback was added** — `ownership.md` §10.2(2) forbids an app-side
   alarm cadence, and the honest consequence is that the NAT binding is currently
   maintained by the core's own keepalive traffic, which is more wakeful and not
   incorrect.
4. **`PairingOffer` has no contract.** `ownership.md` §8 **W-21**: the
   deterministic-CBOR payload the C-B ceremony carries appears nowhere in
   `contracts/`. `ui/PairingScreen.kt` can render bytes the core hands it, but
   the two sides have no shared, CI-verified definition of what they are.
5. **The `cargo` build is not wired into Gradle.** §3.2. That is `build/`'s, and
   this directory may not edit it.
6. **No unit tests on the JVM side.** A `src/test/` suite would be *written, not
   compiled* like everything else here, and would duplicate assertions that
   already **run** in Rust. The instrumented suite is where the Kotlin-side
   effort went, because those are the rows a host genuinely cannot reach.

---

## 7. What a device farm is owed

A macOS builder is irrelevant here; an **Android builder with the SDK and NDK**,
and **real devices**, are not.

| Needs | For |
|---|---|
| an SDK + NDK builder | compiling any of §1 at all, and building the CDYLIB per ABI with C-12 alignment |
| a device that can be killed and rebooted | `LifecycleMatrixTest` — OS termination, force-stop, pre-first-unlock boot |
| `dumpsys deviceidle` | `DozeAndRevocationTest` — the LC-8 clock divergence, and the zero-wakeup assertion |
| a second, cooperating VPN app | `onRevoke()` from a slot takeover, and the *do not fight for the slot* assertion |
| a packet capture on the physical interfaces | `LeakMeasurementTest` — all three leak families, and the boot-to-claim window ADR-0012 requires to be **measured** |
| a dual-stack AP fixture | R6's case: IPv6 appearing *after* the tunnel is up |
| a StrongBox device **and** a TEE-only device **and** a software-keymaster device | ADR-0020's assurance ladder reports three levels; only a device proves which is reached |
| a work-profile / secondary-user device | ADR-0020 §11: each Android user is a separate `Device` to a `TwinNet` |
