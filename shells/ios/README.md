# `shells/ios` — the iOS/iPadOS app and NetworkExtension

**Owner:** `mobile-ios` (`docs/implementation/ownership.md` §10.1).
**Authority:** ADR-0018 §11.5's iOS rows, §11.9 row 1, §11.12; ADR-0019 §11.7 and
§11.8; ADR-0012 §11.6's iOS rows; ADR-0017 §11.2.1; ADR-0022 §11.3–§11.10;
`docs/networking.md` §5.

---

## 1. Status, stated first because it is the most important fact here

**Every Swift file in this directory is *written, not compiled*.**

`ownership.md` §10.3's wave-3 table:

| Category | Wave-3 content |
|---|---|
| **written, not compiled** | **all Swift and all Kotlin.** There is no Xcode, no Darwin SDK, no `NetworkExtension`, no JDK, no Gradle, no Android SDK and no NDK on this host |
| **written, not executed** | the XCTest and instrumented-test suites, and every real-device lifecycle test |

`make cross-check` reaches **none** of it, and says so at the target:

```
NOT covered: Swift (shells/ios), Kotlin (shells/android) -- no
Darwin SDK, no JDK/Android SDK/NDK on this host. ownership.md 9.2.
```

Nothing in this directory has been type-checked, built, signed, run, or seen by a
device. Treat a review of it as a review of *design*, not of *behaviour*.

What **is** verified — and it is deliberately most of the interesting part — lives
in `core/crates/twinvpn-platform-ios`, which is Rust, is checked for
`aarch64-apple-ios` with `-D warnings`, and whose 210 tests execute on the Linux
build host. See that crate's README for the split.

---

## 2. Layout

```
shells/ios/
  project.yml                       XcodeGen spec (§4 says why not a .xcodeproj)
  Package.swift                     SwiftPM, for editor tooling and `swift build`
  Sources/
    TwinVPNBridge/include/
      twinvpn_ios_bridge.h          the INTERNAL bridge (ownership.md §10.4)
      module.modulemap              two modules: the ABI of record, and the bridge
    TwinVPNProvider/                the NE extension. NO UI (C-7)
      PacketTunnelProvider.swift    the OS-started process (CB-1 (b))
      BridgeHost.swift              fills tw_ios_host_vtable
      Programmes.swift              decodes what Rust rendered
      PathMonitorBridge.swift       NWPathMonitor, serialised
      KeychainBridge.swift          SecItem / SecKey / the App Group container
    TwinVPNApp/                     the SwiftUI app. UI lives here and only here
      TwinVPNApp.swift              the scene, and CB-4's presentation half
      VPNPermission.swift           install / consent / denial / revocation
      ManagementClient.swift        ADR-0017's iOS subset channel
      ContractCourier.swift         the corrected fetch split (§5)
      Views/                        Status, Pairing, Diagnostics
  TwinVPNTests/                     device-bound. WRITTEN, NOT EXECUTED
  Resources/                        Info.plists and entitlements
```

There is **no `Cargo.toml` here.** The Rust for this platform is
`core/crates/twinvpn-platform-ios`, inside the `core` workspace, because
`ownership.md` §10.4 keeps sockets, the NAT ladder, interface enumeration,
ruleset read-back and `current_generation` in Rust **in-process** rather than
behind an ABI. A second workspace here would suggest there is Rust to build
separately, and there is not.

---

## 3. Building, on a Darwin builder

Nothing below has been run. It is written from the ADRs and from Apple's
documented toolchain, and the first person with a Mac should expect to correct it.

```bash
# 0. Prerequisites: Xcode 15+, the pinned Rust toolchain, xcodegen.
rustup target add aarch64-apple-ios aarch64-apple-ios-sim

# 1. Build the two staticlibs. The FULL core for the provider; `core-lite` for
#    the app (ADR-0018 §11.12's feature profile: schema, crypto verification
#    only, store, trust, diag — and NO data-plane crate).
./Scripts/build-core.sh --target aarch64-apple-ios --profile release
./Scripts/build-core.sh --target aarch64-apple-ios --profile release --features core-lite

# 2. Stage the ABI of record. `twinvpn.h` is `core-composition`'s and is COPIED,
#    never edited here — a second copy that can be edited is a second thing that
#    can drift from the ABI.
./Scripts/stage-headers.sh

# 3. Generate the project.
xcodegen generate

# 4. The size gate. ADR-0018 §11.9 row 1: staticlib <= 12 MB stripped.
./Scripts/check-budget.sh
```

`Scripts/` does not exist yet. It is the first thing a Darwin builder needs and
it is named in §8's debt list rather than stubbed here, because a script that has
never run is worth less than an accurate note that it is missing.

---

## 4. Why there is no committed `.xcodeproj`

A `project.pbxproj` is generated 96-bit identifiers. On a host with no Xcode it
cannot be produced, opened or validated, so a hand-written one would be several
hundred lines of unverifiable identifiers presented as a build system —
`written, not compiled` dressed as `compiled`.

`project.yml` is the same information in a form a reviewer can read and a machine
can check. `xcodegen generate` produces the project on a Darwin builder.

---

## 5. The fetch split, and a three-way conflict this shell sits on

`docs/networking.md` §5.4's **corrected** iOS memory-limit row:

> **The extension FETCHES** (it holds the exempted socket) and hands raw bytes to
> the app; **the app PARSES AND VERIFIES**.

ADR-0016 **PS-24 condition 3** is the mechanism: under `includeAllNetworks` the
app process has no network — its traffic is ADR-0012 class 1/2 protected and
dropped, and it cannot match class 7 because KS-9(1)'s predicate names the
**provider** and iOS has no host firewall to carry an exemption.

`ContractCourier.swift` implements that reading, and records at its head that
**three documents describe this split and they disagree**: ADR-0020 **ST-31** puts
the fetch in the app and the verify in the provider; ADR-0022 **LC-17** puts both
in the app. The disagreement is reported to the integration lead as a finding.

---

## 6. The management channel is a subset, and the subset is disclosed

ADR-0017 §11.2.1: `NETunnelProviderSession.sendProviderMessage` is "the only
Apple-sanctioned app↔provider message path". The **contract** is not a subset —
same operations, same scopes, same schema, same reason codes. The **channel** is:

| | |
|---|---|
| Full request/response, byte-identical framing | carried |
| Agent-initiated push (the event stream) | **not carried** |
| Any message while the session is not connected | **not carried** |

`ManagementClient.swift` implements the three emulations §11.2.1 sanctions:
scene-bound polling at 1 s while a relevant scene is **visible** (not while the
app is foreground — on iPadOS those differ), a payload-free Darwin notification
that triggers a declarative re-read, and a stopped session rendered as **not
live** per ADR-0015 O-18.

The battery cost of polling is the stated residual.

---

## 7. What this shell may not contain, and how to check

CB-2: "A shell MAY translate, marshal, schedule and render. It MUST NOT contain a
branch whose condition is a TwinVPN domain fact."

Concretely, in this directory:

- **No `ConnectionState`.** Grep for it; there is none. A roam is `MIGRATING`
  rather than `RECONNECTING` and that verdict is the core's.
- **No `reason_code` decision.** Codes are *carried* (`ReasonCode` in
  `VPNPermission.swift` is a closed set of four quoted registry entries) and
  *rendered* through `tw_render_diagnostic`. None is invented and none is
  branched on.
- **No user-facing English.** CB-4 puts every rendered string in the core's
  catalogue, and LT-3a puts variant selection there too: "made in core from
  `platform_ctx`, never a shell choosing among returned keys."
- **No `isIdleTimerDisabled`, no background task assertion, no keep-alive
  timer.** `ownership.md` §10.2's two prohibitions.
- **No pairing ceremony.** ADR-0018 §11.2 row 2.7 leaves the shell "camera, QR
  render, display" and nothing else.

The falsification test: delete this whole directory, bind the mock adapter, and
the core still makes every decision correctly.

---

## 8. What a device farm is owed

| Row | Where it is written | Why it needs a device |
|---|---|---|
| OS termination of the extension | `TwinVPNTests/LifecycleTests.swift` | jetsam gives no notice and has no API |
| Extension memory-limit kill | same | the 12 MB budget is only real under load |
| Profile revocation from Settings | same | no API removes our own profile |
| App force-quit (LC-23 / P21) | same | the app must not be a required participant |
| Suspend/resume gap on the right clock | same | LC-8's failure is invisible on a host that never sleeps |
| IPv4, IPv6 and DNS leaks | `TwinVPNTests/LeakAndArmTests.swift` | a leak is a packet we did not see emitted; it needs a capture point off-device |
| **P09 attach-to-arm window** | same | ADR-0012 §14 condition 5 turns on a measured p95 |

Plus, to run any of them: a physical iPhone **and** a physical iPad (ADR-0018
§11.9 lists iPadOS as a distinct farm entry), a provisioning profile with the four
entitlements in `Resources/`, a **supervised** device for the always-on rows, a
second peer, and a capture point on the far side of the uplink.

And, before any of that: `Scripts/build-core.sh`, `Scripts/stage-headers.sh` and
`Scripts/check-budget.sh`, which are named in §3 and do not exist.
