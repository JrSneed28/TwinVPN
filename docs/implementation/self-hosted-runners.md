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

---

## Runbook — Machine A on Hyper-V

Machine A is the one row reachable without buying anything, provided the runner
lives in a **guest VM with a checkpoint**, not on the host. Everything below runs
on the Hyper-V host in an elevated PowerShell unless it says otherwise.

The reason for the VM is not tidiness. `ci-windows.sh --cleanup` removes
`TwinVPNService` and the overlay adapter and **deliberately leaves the WFP
filters**, because ADR-0018 CB-6 and ADR-0022 §11.4 require enforcement to
survive the process. `--reset` then refuses to start dirty:

```
::error::the rig still has TwinVPNService registered; it was not restored between runs
::error::the rig still has a TwinVPN overlay adapter; it was not restored between runs
```

So run 1 passes on any Windows box and run 2 onwards fails until something
restores the machine. The checkpoint is that something.

### 1. Create the guest

Two scripts do this; both must run **elevated**, one on the host and one in the
guest.

**Copy them out of the repository first.** They live in `scripts/`, but this
repository is normally checked out inside WSL, and a script run from
`\\wsl.localhost\...` is treated as the Internet zone — the default
`RemoteSigned` execution policy then refuses it. Copy them to a local path and
run from there:

```powershell
mkdir C:\Users\<you>\twinvpn-rig
copy \\wsl.localhost\Ubuntu\home\<you>\TwinVPN\scripts\twinvpn-rig-*.ps1 C:\Users\<you>\twinvpn-rig
cd C:\Users\<you>\twinvpn-rig
```

**Invoke them with a leading `.\`.** PowerShell reads an unprefixed
`dir\name.ps1` as its `Module\Command` syntax, so `scripts\twinvpn-rig-host.ps1`
fails with `The module 'scripts' could not be loaded`. They exist because the ordering below is easy to get wrong in a way that
only shows up on the *second* run.

On the Hyper-V host:

```powershell
.\twinvpn-rig-host.ps1 -Action create -IsoPath C:\iso\Win11_24H2.iso
```

It defaults the VHDX to `C:\Hyper-V` and warns if the drive cannot hold the
disk. It sets `-AutomaticCheckpointsEnabled $false`, which is not tidiness: an
automatic checkpoint taken mid-run captures exactly the dirty state the rig
exists to discard, and restoring to it would start the next run already dirty.

### 2. Provision the guest

**Getting an ISO.** Use the **Windows 11 Enterprise evaluation** — 90 days, no
product key, currently offered as version 25H2 x64, which satisfies the 24H2
floor. It needs a Microsoft account to register before the download.
<https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise>

The consumer multi-edition ISO at
<https://www.microsoft.com/en-us/software-download/windows11> needs no sign-in
but does need a licence key you already hold.

The Hyper-V Quick Create gallery offers no ready-made image for this, so the ISO
is the only route.

**The evaluation expires on wall-clock date, not on VM uptime**, and restoring
the golden checkpoint does not reset it — the checkpoint restores an early
*state*, but Windows compares against the real date. An expired Enterprise
evaluation shuts down roughly hourly, which presents as flaky CI rather than as
a licensing problem. `slmgr /rearm` extends it up to three times (about a year
in total); after that the rig has to be rebuilt or licensed. Budget for that
rather than debugging it.

Install Windows, then, **inside the guest**, elevated:

```powershell
.\twinvpn-rig-guest.ps1 -Action verify
```

It checks each requirement against the machine and prints the fix for anything
missing: Rust 1.90.0 with an `x86_64-pc-windows-msvc` host, cargo on the
**machine** PATH so a service can see it, MSVC build tools discoverable through
the installer's own `vswhere.exe` (the job locates them exactly that way, so a
Visual Studio the installer does not know about will not be found), Git for
Windows for `bash` and `cygpath`, `wintun.dll`, and a running Base Filtering
Engine.

It also checks the two pieces of state `ci-windows.sh --reset` refuses to start
on — a leftover `TwinVPNService` or a `TwinVPN*` overlay adapter. Those are not
hygiene warnings; the job exits 1 and says the rig was not restored.

Prime the cargo cache once before going further. No job here has an
`actions/cache` step and the 60-minute timeout assumes a warm cache.

### 3. Register the runner, ephemeral

Get a registration token from **Settings → Actions → Runners → New self-hosted
runner**, download and extract the runner package to `C:\actions-runner` using
the commands that page shows (its URL and hash change per release), then:

```powershell
.\twinvpn-rig-guest.ps1 -Action register `
    -RepoUrl https://github.com/<owner>/<repo> `
    -Token <TOKEN> `
    -RunnerAccount .\<admin-account> `
    -RunnerPassword (Read-Host -AsSecureString)
```

It re-runs `verify` first and **refuses to register** if anything is unmet — a
runner that accepts a job it cannot run turns a missing prerequisite into a red
gate row, which is strictly worse than no runner.

**`--ephemeral` is the load-bearing flag** and the script always passes it. The
runner takes exactly one job, then deregisters and exits, which is what gives
the host a defined moment to restore. Without it the runner picks up a second
job on a machine still carrying the first run's WFP filters, and that run fails
at `--reset` — correctly, but the error reads as a rig misconfiguration rather
than a missing restore.

The labels are exactly `self-hosted, Windows, twinvpn-vpn-lifecycle`; `runs-on`
matches all three.

The service account may be LocalSystem or a local Administrator. The scripts
take the Administrator route because it is the one `config.cmd` documents a flag
for.

### 4. Take the golden checkpoint

Back on the host, **after** the runner is registered, so a restore comes back
with the runner already installed:

```powershell
.\twinvpn-rig-host.ps1 -Action checkpoint
```

### 5. Restore between runs

The guest cannot restore itself.

```powershell
.\twinvpn-rig-host.ps1 -Action watch
```

restores to `golden` and restarts whenever the guest stops — which an ephemeral
runner causes it to do after each job. Pair it with the 05:00 nightly in
`.github/workflows/first-implementation-wave-privileged.yml`: the guest must be
up and registered before then.

### 6. Confirm it actually flipped the row

A green job is **not** the criterion. `build/acceptance/report.py` re-derives the
verdict from the evidence file and requires `privileged: true` and a non-empty
`lifecycle_transitions`:

```bash
gh run download <privileged-run-id> -p 'evidence-*' -D build/ci/evidence
python3 -c "import json;d=json.load(open('build/ci/evidence/windows-privileged.json'));print(d['privileged'], len(d['lifecycle_transitions']))"
# want: True  <non-zero>
```

Then the gate's own import step picks it up for the same `$GITHUB_SHA` — see
`ownership.md` §11.6 **G-22**, which is why a green run can flip the row at all.

---

## Cloud alternatives to the three remaining machines — 2026-08-30

Researched because the machines are the wave's last blocker and buying four rigs
is not the only option. **One row of three is solvable in the cloud, and it is
not the cheapest way to solve it.**

### macOS — POSSIBLE on AWS EC2 Mac, but buy the Mac mini

The blocker everywhere else is SIP: `systemextensionsctl developer on` needs it
configured, and no Mac host lets a customer reach Recovery mode. **AWS shipped an
EC2 API in May 2025 that disables SIP on Apple silicon without physical access**
— `aws ec2 create-mac-system-integrity-protection-modification-task`, polled with
`describe-mac-modification-tasks`. That is the whole reason this row is open.

Two facts decide how to use it:

* **SIP state is volume-scoped**, not instance- or host-scoped. A stop/start
  re-enables it, a replaced root volume does not inherit it, and it does **not**
  transfer to snapshots or AMIs. So the golden-image trick does not carry SIP:
  bake Xcode and the runner into an AMI if you like, but the SIP task re-runs on
  every fresh root volume. Treat the runner as a long-lived instance that is
  never stopped, and **assert `csrutil status` as a pre-flight step in the job** —
  AWS notes SIP semantics can shift across macOS updates, and a silently
  re-enabled SIP fails deep inside extension activation with a misleading error.
* **Xcode 26.6 requires macOS Tahoe 26.2+.** The Xcode 26 line raised its floor
  mid-series at 26.4. AWS's AMI page prose still says "macOS Sequoia (version
  15)" and is **stale**; the changelog on the same page is authoritative and has
  shipped Tahoe AMIs through 26.6.1 (release 2026.08.26). Launch a Tahoe AMI.
  Xcode is not preinstalled on any of them — the AMIs carry Command Line Tools
  only — so 26.6 is a manual install to `/Applications/Xcode_26.6.app`, which is
  the path `build/ci/ci-common-apple.sh:90` expects.

Other requirements: a one-time SSH prep granting `ec2-user` a secure token
(`dscl . -passwd`, then `sysadminctl`, verified with
`sysadminctl -secureTokenStatus`), passwords of 4–16 characters or the API
rejects them, exactly one bootable volume, and **FileVault must stay off** — AWS
warns the host then fails to boot. The instance is not stopped for the task; it
goes unreachable for 60–90 minutes across a series of reboots.

**Cost, and why it does not win.** Billing is per Dedicated Host with a
**24-hour minimum allocation** — Apple's licence term, not an AWS choice, so no
provider beats it. A nightly job cannot allocate for less than 24 h, so
allocate-daily and run-continuously cost the same. us-east-1 On-Demand,
2026-08-30: `mac2-m2.metal` $0.878/h → **~$641/month**; `mac-m4.metal` $1.23/h →
~$898/month. No Spot, no Reserved; Savings Plans apply. EBS is extra and is not
a rounding error at the 10,000 IOPS / 400 MiB/s AWS recommends.

Against roughly **$600–800 once** for a Mac mini on a desk — which also carries
`twinvpn-ios-device` with an attached iPhone, something no cloud can do. **Buy
the Mac mini.** EC2 Mac is the answer to "we need this row before hardware can
be purchased", not to "this is cheaper".

### iOS — NOT POSSIBLE on any commercial device farm

AWS Device Farm, BrowserStack, Sauce Labs and Firebase Test Lab all **re-sign
the uploaded IPA**, which strips entitlements — `packet-tunnel-provider` is gone
before the tunnel can start. None offers a **supervised** device, which
ADR-0022 §11.10's iOS row needs for the always-on cases. The blocking capability
is entitlement preservation, and it is stated in each provider's own current
documentation. An iPhone attached to the Mac above is the only route.

### Android — NOT POSSIBLE on mainstream farms; ONE open lead

No mainstream farm will hand over a device booted on a **16 KiB kernel**: on a
Pixel that requires an OEM-unlocked bootloader and a data wipe, which no farm
does. Every farm device you can get is a 4 KiB device — and a 4 KiB device is
worse than none, for the reason `self-hosted-runners.md` gives above and the
workflow now hard-fails on.

**The one lead worth 15 minutes: Samsung Remote Test Lab.** Samsung's 2025-07-07
RTL blog states RTL offers 16 KB page-size testing on real devices and captions
a figure "16KB page size devices in Remote Test Lab", and a category page exists
at `developer.samsung.com/remotetestlab/devices/129/16kb-page-size`. Critically,
RTL's Remote Debug Bridge gives a genuine `adb connect localhost:<port>` — **a
real adb shell, not an instrumentation harness** — which is the only reason RTL
is still open when every other farm is closed.

The device list itself is a client-rendered SPA behind a Samsung account and
could not be read; no public catalogue endpoint exists. **So someone must log in
and look.** The check costs one RTL credit (15 minutes; the free tier is 20
credits/day):

1. Sign in, open the **16KB Page Size** category, reserve any device.
2. `adb connect localhost:<port>` from a local machine.
3. Run exactly the two commands the gate runs:
   `adb shell getprop ro.product.cpu.abi` → want `arm64-v8a`;
   `adb shell getconf PAGE_SIZE` → want `16384`.
4. Note whether `adb shell` accepts an **arbitrary** command or only a fixed
   set. That is the difference between a real shell and a harness, and it
   decides whether `appops set <pkg> ACTIVATE_VPN allow` is available later for
   M-19's tunnel half.

Both values right and the Android row has a cloud path. Anything else and the
question is closed for good, and the row needs a Pixel 8/9 you unlock yourself.

### Terms

Nothing forbids either arrangement. GitHub's self-hosted runner documentation
cautions only that they be used with **private** repositories, which the
workflow's absent `pull_request` trigger and fork guard already satisfy. Apple's
macOS SLA gained a **"Leasing for Permitted Developer Services"** clause in Big
Sur, which is what authorises cloud Mac hosting at all and is the source of the
24-hour minimum; CI for your own apps is the permitted use.
