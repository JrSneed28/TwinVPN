# Self-hosted runners for the privileged lifecycle jobs

Three machines. Every requirement below is derived from a step in
`.github/workflows/first-implementation-wave-privileged.yml` or from the
`build/ci/ci-*.sh` it invokes; nothing here is general advice.

Two wiring defects that would have survived buying these machines were fixed on
2026-08-30 — see `ownership.md` §11.6, **G-22** and **G-23**. Before that, a
fully green run on all three machines could not have flipped a single row.

Common to all three:

* Registered against this repository only, in a runner group not shared with any
  other repository. `first-implementation-wave-privileged.yml` has no
  `pull_request` trigger, so no fork can reach them; the group restriction is
  the second lock.
* Rust **1.90.0** via rustup (`rust-toolchain.toml`, `components =
  ["rustfmt","clippy"]`, `profile = "minimal"`). The jobs run
  `rustup show active-toolchain || rustup toolchain install`, so rustup must be
  on the runner service's PATH.
* A warm cargo cache is assumed — none of the three jobs has an `actions/cache`
  step, and the 60-minute timeouts are set on that assumption.
* No production credential of any kind on any of them.

---

## Machine A — `[self-hosted, Windows, twinvpn-vpn-lifecycle]`

**OS.** Windows 11 24H2 or Windows Server 2022+, x86_64. **A VM with automated
snapshot restore, not a desktop.**

**Privilege.** The runner service account must be able to open the Base
Filtering Engine for write and to create/delete a Windows service — LocalSystem,
or a local Administrator with the runner installed as a service. The job calls
`sc.exe query/stop/delete`, `netsh wfp show state`,
`netsh interface show interface`.

**Toolchain.**

* rustup + Rust 1.90.0, host target `x86_64-pc-windows-msvc`.
* MSVC build tools. Known-good floor, as recorded by the hosted lane's own
  evidence: `VisualStudio 18.9.12112.369, MSVC toolset 14.51.36231`.
* Git for Windows — the job sets `defaults.run.shell: bash` and uses
  `cmd //c ver`, which needs MSYS path translation.
* `wintun.dll` installed beside the build.

**No signing material.** Authenticode is ADR-0021's and belongs to the release
pipeline. This rig holds no certificate, password or token.

**Attached devices.** None.

**Persistent state, and how it is reset.**

* WFP filters — **NOT removed by `--cleanup`, deliberately.** ADR-0018 CB-6 and
  ADR-0022 §11.4 require persistent filters to survive the process, so there is
  no supported in-process remover and there must not be one.
* `TwinVPNService` — removed by `--cleanup`.
* `TwinVPN*` overlay adapters — `--cleanup` only *reports* them.

**Therefore an automated snapshot restore or reimage before every run is
mandatory, not a nicety.** `ci-windows.sh --reset` deliberately FAILS rather
than cleans when it finds a leftover service or overlay adapter, so without the
restore the second run and every run after it goes red at step 2.

---

## Machine B — `[self-hosted, macOS, twinvpn-vpn-lifecycle, twinvpn-ios-device]`

**One machine, both labels, and exactly ONE runner process.** Two runner
processes would let `macos-privileged-lifecycle` and `ios-device-lifecycle`
interleave over a machine-global `xcode-select`, one pf ruleset and one
system-extension slot; their separate concurrency groups do not prevent that,
and merging the groups is not the answer — a queued iOS job with the phone
unplugged would hold the macOS job for 24 h, which is the queue-hold this file
was split out to avoid. One process runs one job at a time. That is the control.

**OS.** macOS 26.x on Apple silicon. Floor taken from the hosted lane's own
evidence: `macos 26.5.2`, `macosx SDK 26.5`, `iphoneos SDK 26.5`. **Snapshotted
or disposable. Not a shared developer Mac.**

**Toolchain.**

* **Xcode exactly 26.6** (`TWINVPN_XCODE_VERSION`,
  `build/ci/ci-common-apple.sh:90`), installed as `/Applications/Xcode_26.6.app`
  or as `/Applications/Xcode.app` reporting 26.6. `--print-xcode-path` does
  **not** fall back to the default.
* Swift **6.3.3** — not installed separately; it is what Xcode 26.6 ships, and
  `apple_require_pinned_swift` fails the job if it is not.
* XcodeGen. Homebrew must be present and usable non-interactively: the script
  runs `brew install --quiet xcodegen` when it is missing.
* rustup targets `aarch64-apple-darwin` **and** `x86_64-apple-darwin` (the macOS
  row ships universal 2 and `build-bridge.sh` lipos both), plus
  `aarch64-apple-ios` and `aarch64-apple-ios-sim`.

**Privilege.** Passwordless `sudo` for the runner user. The jobs run
`sudo xcode-select -s`, `sudo -n pfctl -s info`, `sudo -n pfctl -sr`,
`sudo -n twinvpn-unblock --yes`, `sudo -n ifconfig utun7 destroy`.

**Machine configuration, made once and recorded — a CI job may not do this.**

* `systemextensionsctl developer on`.
* SIP configured to permit an unnotarized system extension. Without it,
  activation is refused before any TwinVPN code runs.

**Signing — macOS half.** A Developer ID Application certificate and private key
in a keychain the runner user can unlock **without an interactive prompt**, plus
a provisioning profile carrying
`com.apple.developer.system-extension.install`. `packaging/SIGNING.md` is the
procedure. Use a **CI-only** identity whose revocation is routine.

**Signing and device — iOS half.**

* A physical iPhone attached over USB, unlocked, trusted, Developer Mode on.
* Its UDID in the repository/organisation variable
  **`TWINVPN_IOS_DEVICE_UDID`** — the job reads `vars.TWINVPN_IOS_DEVICE_UDID`,
  not a secret and not a runner env var.
* A provisioning profile carrying `packet-tunnel-provider`, `allow-vpn`, the
  shared keychain access group and the App Group (ADR-0016 §11.2).
* **Supervised** device for the always-on rows: ADR-0022 §11.10's iOS row makes
  true boot-start an MDM payload, unreachable on an unsupervised device.
* A CI-only Apple account and a CI-only device.
* **iPadOS is a DISTINCT row.** ADR-0018 §11.9 lists it separately; an iPhone
  run does not discharge it. That needs a second Mac-plus-iPad and a second job
  instance.

**Persistent state, and how it is reset.**

* The activated system extension — **NOT removed by `--cleanup`.** The script
  runs `systemextensionsctl list` and nothing more; on macOS the sanctioned
  removal is deleting the containing app bundle. **Snapshot or reimage.**
* `xcode-select` global developer directory — set by the job, never restored.
* The owner-tagged pf anchor — removed via `twinvpn-unblock` (KS-20a).
* `utun7` — destroyed by `--cleanup`.
* The installed app on the phone, which is what removes its VPN profile since no
  API removes our own — removed by `ci-ios.sh --cleanup`.
* Any simulator the run booted — shut down by `ci-ios.sh --cleanup`.

---

## Machine C — `[self-hosted, Linux, twinvpn-android-device]`

**OS.** Ubuntu 24.04, **x86_64**. Not arm64: the job invokes
`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang` by that
literal path.

**Toolchain — all of it on the HOST, because this job does none of the setup the
hosted lane does.** `android-link-run` runs `actions/setup-java@v4` and a
`pin the NDK` step; `android-device-lifecycle` runs neither and reads the
environment as it finds it.

* **JDK 21 as the default `JAVA_HOME`.** `app/build.gradle.kts` sets
  `jvmTarget = JVM_21` and `sourceCompatibility`/`targetCompatibility = 21`;
  `build/toolchain/env.sh` pins `TWINVPN_JDK_VERSION=21.0.5`. The hosted lane
  records `openjdk 21.0.12.1`. Under an older JDK, Gradle fails with an
  unsupported-target error that reads as a Kotlin problem.
* **Gradle on PATH.** No `gradlew` is committed; `ci-android.sh:414-419` falls
  back to `command -v gradle` and errors if there is none. AGP is **8.7.3**
  (`gradle/libs.versions.toml`); the hosted lane records Gradle **9.7.1**.
* Android SDK with `platform-tools`, and `ANDROID_SDK_ROOT` or `ANDROID_HOME`
  set — `ci-android.sh` resolves `adb` as `$sdk_root/platform-tools/adb`.
* **NDK r27 or newer**, with `ANDROID_NDK_HOME` pointing at it. The hosted lane
  records `29.0.14206865`. The script errors when it is unset or missing.
* rustup targets `aarch64-linux-android`, `armv7-linux-androideabi`,
  `x86_64-linux-android`, `i686-linux-android`.
* **No KVM and no emulator packages.** This job boots nothing.

**No signing material.** The APK under test is the debug build.

**Attached device — the part that decides whether C-12 is tested at all.**

* A physical **`arm64-v8a`** phone, USB debugging authorised, with
  **`ANDROID_SERIAL`** naming it in the runner service's environment. The job
  exits 1 if `ANDROID_SERIAL` is unset.
* **The device MUST report a 16 KiB page size.** Confirm a candidate before
  buying or dedicating it:

  ```sh
  adb -s <serial> shell getconf PAGE_SIZE            # must print 16384
  adb -s <serial> shell getprop ro.product.cpu.abi   # must print arm64-v8a
  adb -s <serial> shell uname -m                     # aarch64
  ```

  `getconf PAGE_SIZE` is toybox's `sysconf(_SC_PAGESIZE)` — the **running
  kernel's** page size, not a build-time constant, so it cannot be right about
  the wrong thing. In practice this means a Pixel 8/9-class device on Android
  15+ with the 16 KB page-size developer option enabled, or a device that ships
  16 KB by default. The job asserts both facts and goes red on either.

  **Why a 4 KiB device would be worse than no device.**
  `-Wl,-z,max-page-size=16384` (C-12, `ci-android.sh:468`) only raises the
  `p_align` of the `.so`'s `LOAD` segments. A 4 KiB kernel maps a 16 KiB-aligned
  library and a 4 KiB-aligned one equally happily — the refusal C-12 exists to
  prevent occurs only on a 16 KiB kernel, where a `p_align` of `0x1000` makes
  the loader reject the mapping. So on a 4 KiB arm64 phone every boolean in the
  evidence is true, the row flips to PASS, and the alignment flag is tested
  nowhere. That is a vacuous pass, and a vacuous pass is worse than a red row
  because nothing downstream can tell it from a real one.

**Persistent state, and how it is reset.** `net.twinvpn.android` and
`net.twinvpn.android.test`, both uninstalled by
`ci-android.sh --cleanup --privileged`. Unlike Windows there is no persistent
OS-level claim: the `VpnService` claim dies with the process
(`EnforcementView::custody` reports `survives_core_exit: false` unless lockdown
is confirmed), so uninstalling the packages **is** the teardown. The device
should still be factory-resettable or re-flashable.
