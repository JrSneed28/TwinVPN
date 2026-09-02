# Remote acceptance infrastructure

Everything the First Implementation Wave gate needs that is not a hosted GitHub
runner. Every requirement below is derived from a step in
`.github/workflows/first-implementation-wave-gate.yml` or from the
`build/ci/ci-*.sh` it invokes; nothing here is general advice.

**The rule this document exists to satisfy:** the gate stays evidence-based, and
**local or user-owned physical hardware is no longer an acceptable dependency**
for it. A blocker that can only be closed by someone with a machine in a room is
a purchasing decision wearing an engineering costume.

`self-hosted-runners.md` describes the arrangement this replaced — three
physical machines plus a phone — and is kept for the reasoning it records about
why each row needed what it needed.

---

## 0. What every criterion now carries, and why

Two mechanisms, applied to every row in the `Platform criteria` section of the
acceptance report. Neither existed under the old arrangement.

### 0.1 The environment attestation

Every boolean in a platform evidence file describes what the TEST did. **None of
them describes whether the machine was capable of the claim.** These all
produced well-formed, entirely green evidence:

* a Windows kill-switch run whose caller was never actually elevated, so no
  filter was ever installed and the "armed" window was an unprotected host that
  happened to have no network;
* an Android 16 KiB run on a 4096-byte-page emulator, where the alignment flag
  the criterion is about was applied to every ABI and exercised by nothing;
* a macOS extension run where activation silently failed.

So each criterion names the `environment` keys that must be present and must
hold, `build/acceptance/report.py`'s `PREREQUISITES` table carries them, and
they are checked **before any test result is read**. An environment that failed
its prerequisite attestation cannot produce a green criterion.
`build/acceptance/test_report_prerequisites.py` is the runnable proof of that,
one case per hole.

### 0.2 The external leak oracle

No criterion that makes an egress claim is adjudicated by the platform under
test. `lab/twinoracle` runs off-device; the acceptance job fetches its verdict
**from the oracle**, keyed by a session id the evidence recorded. See
`lab/twinoracle/README.md` for deployment — it is a prerequisite for three of
the five criteria and its absence makes them fail, never pass.

---

## 1. The leak oracle — required by three criteria

One small cloud instance. Public IPv4 **and** public IPv6, plus a delegated DNS
zone. Deployment, the socket layout, and the two host settings that are easy to
get wrong are in `lab/twinoracle/README.md`.

Repository configuration:

| Name | Kind | Value |
|---|---|---|
| `TWINVPN_ORACLE_URL` | variable | the control-plane base URL, e.g. `https://oracle.example:8443` |
| `TWINVPN_ORACLE_TOKEN` | **secret** | the control bearer token, ≥ 32 characters |

The oracle's control listener should be reachable only from the runners and the
GitHub Actions egress ranges. Its data-plane listeners must be reachable from
the public internet — that is the entire point.

---

## 2. `WINDOWS-WFP-KILLSWITCH` — Azure L1 + a disposable nested guest

**Runner label:** `[self-hosted, Windows, twinvpn-azure-l1]`.
**Gate variable:** `TWINVPN_AZURE_L1_REGISTERED=true`.

### 2.1 Why there are two machines and not one

TwinVPN's Windows kill switch installs **persistent** WFP filters, and ADR-0018
CB-6 with ADR-0022 §11.4 require that "shutdown MUST NOT remove enforcement". A
**correct** fail-closed run therefore ends with the machine unable to reach the
network.

On the runner itself that severs the runner agent's connection to GitHub
mid-job: the run is lost, no evidence is uploaded, and correct product behaviour
is indistinguishable from flaky infrastructure. So:

* **L1** is the Azure VM registered as the runner. It never runs the test.
* **L2** is a throwaway Hyper-V guest created per run from a differencing disk
  over a golden VHDX, driven over **PowerShell Direct** — a VMBus channel that
  does not use the guest's network stack and therefore survives the guest
  cutting itself off — and destroyed in a `finally` block on every path.

`build/ci/ci-windows-killswitch.sh` refuses to run without
`TWINVPN_DISPOSABLE_GUEST=1`, which only the controller sets. Running it by hand
on L1 is therefore not possible by accident.

### 2.2 L1 requirements

* **A VM size with nested virtualization.** Dv3/Ev3 or later; any v4/v5 series.
  The Av2, Dv2 and Ev2 sizes cannot host a guest at all, and the failure mode
  without this check is a guest that installs fine and never boots, with a
  message that sends people to look at the golden image.
* The Hyper-V role, and a virtual switch named by `-SwitchName` (default
  `twinvpn-guest`) through which the guest can reach the leak oracle. **Without
  egress the oracle observes nothing and every session is `INCONCLUSIVE`.**
* A guest credential exported once, as the machine's own account:
  `Get-Credential | Export-CliXml C:\Hyper-V\secrets\guest.cred.xml`. Not a
  password on a command line — an argument is visible in the process list.

### 2.3 The golden VHDX

A licensed Windows install, **never domain-joined** (it is going to be cut off
the network on purpose), carrying: the pinned Rust toolchain, **Git for
Windows** (the controller runs `bash.exe` inside the guest), Python 3, and the
VS Build Tools with the MSVC toolset.

It is never written to — the guest runs on a differencing disk over it — so it
does not need restoring between runs and there is no snapshot discipline to get
wrong. That is the main practical difference from the old Hyper-V rig, whose
`--reset` refused to start on a machine the previous run had dirtied.

### 2.4 Repository configuration

| Name | Kind | Value |
|---|---|---|
| `TWINVPN_AZURE_L1_REGISTERED` | variable | `true` once the runner is up |
| `TWINVPN_GOLDEN_VHD` | variable | e.g. `C:\Hyper-V\golden\twinvpn-guest.vhdx` |

Leave `TWINVPN_AZURE_L1_REGISTERED` unset and the job **skips** rather than
queueing for twenty-four hours. The row then reads `NOT-EXECUTED`, which counts
against Phase 5 eligibility exactly as a failure does — promptly, and by name.

---

## 3. `ANDROID-16K-PAGE-SIZE` — an ordinary hosted runner

**No machine at all.** Google ships an official 16 KB page-size Android Emulator
image, so this row no longer needs a Pixel with an OEM-unlocked bootloader and a
wiped data partition — which is what closed every device farm to it.

`build/ci/ci-android.sh --pagesize16k`:

* **discovers** the image rather than hard-coding a package id. The tag has
  moved once already (it was `google_apis_ps16k_experimental` while the feature
  was pre-release), and a hard-coded id turns a rename into "package not found",
  after which somebody eventually deletes the assertion to make CI green. The
  script asks `sdkmanager --list` and fails naming every `ps16k` package it did
  find;
* **refuses to continue** unless `adb shell getconf PAGE_SIZE` returns exactly
  `16384`, before the APK is pushed. A 4096-byte-page emulator cannot produce
  PASS evidence for this criterion;
* runs `zipalign -c -P 16 -v 4` on the **release** APK — the SDK's own checker,
  answering for all four ABIs including the ones the emulator will never load;
* installs the **production** APK. The debug build is a different artifact —
  unminified, not shrunk, packaged differently — and C-12's claim is about the
  `.so` inside the shipped one.

### 3.1 Repository configuration

Installing the production APK means signing it, and `app/build.gradle.kts` gives
the release signing config **no silent fallback to the debug keystore** — a
fallback would make the evidence say `release` while the disk said otherwise.

| Name | Kind |
|---|---|
| `TWINVPN_RELEASE_KEYSTORE_B64` | secret (base64 of the JKS/PKCS12) |
| `TWINVPN_RELEASE_STORE_PASSWORD` | secret |
| `TWINVPN_RELEASE_KEY_ALIAS` | secret |
| `TWINVPN_RELEASE_KEY_PASSWORD` | secret |

---

## 4. `MACOS-SYSEXT-LIFECYCLE` and `MACOS-PRODUCTION-SIGNATURE` — EC2 Mac

**Runner label:** `[self-hosted, macOS, twinvpn-ec2-mac]`.
**Gate variable:** `TWINVPN_EC2_MAC_REGISTERED=true`.

### 4.1 Why these are two criteria

`MACOS-SYSEXT-LIFECYCLE` runs in **developer mode**
(`systemextensionsctl developer on`), which is the only way a non-App-Store
extension activates on a machine CI can drive — and which accepts an extension a
customer's Mac would refuse: an ad-hoc signature, an expired certificate, a
missing notarization ticket, an unstapled bundle.

While both claims shared one macOS evidence file, **a green developer-mode
lifecycle read as "the signed, notarized product works"**. They are now separate
criteria, separate scripts, separate evidence files and separate rows, so
`macos-signature` can be red while `macos-sysext` is green — which is the true
state of affairs more often than not.

`ci-macos-signature.sh` activates nothing and installs nothing to
`/Applications`; it inspects a built artifact, so neither job's state can reach
the other's evidence.

### 4.2 Why EC2 Mac specifically

The blocker everywhere else is SIP: developer mode needs it configured, and no
Mac host lets a customer reach Recovery mode. **AWS exposes SIP configuration
through an API** —
`aws ec2 create-mac-system-integrity-protection-modification-task`, polled with
`describe-mac-modification-tasks`. That is the entire reason this row has a
cloud path.

Two consequences that decide the provisioning:

* **SIP state is volume-scoped**, not instance- or host-scoped. A stop/start
  re-enables it, a replaced root volume does not inherit it, and it does not
  travel in an AMI or a snapshot. So treat the runner as a long-lived instance
  that is never stopped — and `ci-macos-sysext.sh` asserts `csrutil status` as a
  pre-flight anyway, because a silently re-enabled SIP fails deep inside
  activation with a message about the extension rather than about SIP.
* **FileVault must stay off**, exactly one bootable volume, and `ec2-user` needs
  a secure token (`dscl . -passwd`, then `sysadminctl`, verified with
  `sysadminctl -secureTokenStatus`; passwords 4–16 characters or the API rejects
  them). AWS warns the host otherwise fails to boot. The instance goes
  unreachable for 60–90 minutes across the modification task's reboots.

**Xcode is not preinstalled on any EC2 Mac AMI** — they carry Command Line Tools
only — so the pinned version is a manual install to
`/Applications/Xcode_<version>.app`, the path `ci-common-apple.sh` resolves.
Launch a Tahoe AMI: the AMI page's prose is stale, and its changelog on the same
page is authoritative.

**Cost, stated plainly.** Billing is per Dedicated Host with a **24-hour minimum
allocation** — Apple's licence term, not an AWS choice, so no provider beats it.
A nightly job cannot allocate for less than 24 h, so allocate-daily and
run-continuously cost the same. us-east-1 On-Demand, 2026-08-30:
`mac2-m2.metal` $0.878/h → ~$641/month; `mac-m4.metal` $1.23/h → ~$898/month.
No Spot, no Reserved; Savings Plans apply. EBS is extra at the 10,000 IOPS /
400 MiB/s AWS recommends. A Mac mini on a desk is ~$600–800 **once** — but a
desk is exactly what this gate may no longer depend on.

### 4.3 Repository configuration

| Name | Kind | Value |
|---|---|---|
| `TWINVPN_EC2_MAC_REGISTERED` | variable | `true` once the runner is up |
| `TWINVPN_TEAM_ID` | variable | the Apple Developer Team ID |
| `TWINVPN_EXTENSION_BUNDLE_ID` | variable | default `com.twinvpn.app.sysext`, the target `shells/macos/project.yml` builds |
| `TWINVPN_NOTARIZED_APP_URL` | variable | where the release pipeline publishes the signed, notarized, stapled `TwinVPN.zip` |
| `TWINVPN_NOTARIZED_APP_TOKEN` | secret | optional bearer for that URL |

`macos-signature` fetches the **notarized product**, never a CI build: a build
produced on the runner would be signed by whatever identity that machine holds
and notarized by nobody, and checking its signature would tell us about the
runner rather than about the product.

---

## 5. `IOS-NE-FAIL-CLOSED` and `IOS-PROFILE-REMOVAL-HONESTY` — Corellium

**No runner.** A cloud virtual iPhone driven entirely over Corellium's REST API,
so the job runs on an ordinary hosted Linux runner with `curl` and `python3`.

### 5.1 Why Corellium and not a device farm

AWS Device Farm, BrowserStack, Sauce Labs and Firebase Test Lab all **re-sign
the uploaded IPA**, which strips entitlements — `packet-tunnel-provider` is gone
before the tunnel can start. Corellium runs the IPA as given, signature and
entitlements intact, and that single capability is what makes the lane possible.
`ci-ios-corellium.sh` reads the entitlement out of the archive before uploading
anything, so a wrong artifact fails in one line rather than as a provider that
mysteriously never starts.

**The primary path is a NON-JAILBROKEN device**, deliberately. A jailbroken
instance would allow more — arbitrary shell, direct provider manipulation — and
every one of those affordances moves the run further from what a user's iPhone
does.

### 5.2 The security invariant, and the one place it does not apply

The invariant is **not** "Jetsam kills the provider". Jetsam is one cause of
provider disappearance and neither the only nor the interesting one. A crash, a
network transition, and the user disabling the VPN all produce the same
security-relevant condition: **the provider is gone and TwinVPN's authority is
not.** So the job injects five disappearances by five mechanisms and requires
the same external result from each — zero unauthorized IPv4, IPv6 or DNS egress,
observed by the oracle.

**Configuration removal is not one of them, and must not be.** On consumer iOS,
removing the VPN configuration *revokes* TwinVPN's authority to intercept
traffic: the extension is torn down by the system and no API at any entitlement
level available outside MDM continues filtering. A product claiming to block
after removal would be claiming a capability the OS does not grant, and the only
way to pass a test of it would be to make the test lie.

So the corrected consumer criterion is `IOS-PROFILE-REMOVAL-HONESTY`, and it
asserts what the app **says**, not what leaves the device:

1. TwinVPN reports NOT PROTECTED;
2. a green shield is **impossible**;
3. the connected state is cleared;
4. the user receives an actionable protection-lost state;
5. TwinVPN makes **no continued kill-switch claim** — `blocked` is as wrong as
   `protected` here, because both assert TwinVPN is still deciding what leaves.

It carries **no leak-oracle session**, and `report.py` requires none: egress
after removal is expected and correct, and a silence phase over that window
would test a promise the product does not make.

`shells/ios/TwinVPNTests/ProfileRemovalAcceptanceTests.swift` is the
specification, one test per condition.

### 5.3 The supervised/managed criterion is separate and stronger

A supervised device under MDM can carry an Always-On VPN payload the user cannot
remove, and there "zero egress outside the tunnel, ever" is both true and
testable. That is `IOS-SUPERVISED-ALWAYS-ON`. It is `required=False` in the
report — a criterion for an unbuilt product mode should not hold the wave — and
it reads its own evidence file with `product_mode: supervised`, while the
consumer file is pinned to `product_mode: consumer`. The two cannot be swapped,
and a consumer-mode pass can never be recorded as the supervised one.

### 5.4 Repository configuration

| Name | Kind | Value |
|---|---|---|
| `TWINVPN_CORELLIUM_ENABLED` | variable | `true` |
| `CORELLIUM_PROJECT_ID` | variable | the Corellium project |
| `CORELLIUM_API_TOKEN` | secret | |
| `TWINVPN_SIGNED_IPA_URL` | variable | where the release pipeline publishes the **real signed** IPA |
| `TWINVPN_SIGNED_IPA_TOKEN` | secret | optional bearer for that URL |
| `TWINVPN_TEAM_ID` | variable | shared with the macOS rows |

---

## 6. Common to every runner

* Registered against this repository only, in a runner group not shared with any
  other repository. Each self-hosted job carries the fork guard
  (`github.event.pull_request.head.repo.full_name == github.repository`) as a
  second lock.
* Rust **1.90.0** via rustup (`rust-toolchain.toml`), on the runner service's
  PATH.
* **No production credential of any kind.** The signing material the Android job
  needs is a CI keystore, and the notarized macOS product and signed IPA are
  *fetched*, never produced here.
* Every job cleans up on `if: always()`. The Windows guest is destroyed in a
  `finally`; the Mac's extension is deactivated (developer mode is what makes
  `systemextensionsctl uninstall` available, and this criterion runs in it); the
  Corellium instance is stopped and deleted in a shell `trap`, because a leaked
  instance bills by the hour.

---

## 7. What the 2026-08-30 hardening pass added, and the holes it closed

Sections 0–6 describe an arrangement that was already evidence-based. This
section describes what was wrong with it anyway. Every item below is a hole that
produced, or would have produced, a **green row about the wrong thing** — the
same defect the environment attestation exists to catch, found five more times in
the machinery built to catch it.

### 7.1 The sentinel — SILENCE was vacuous, and the fix was vacuous too

A `SILENCE` phase with zero arrivals was a `PASS` even if the oracle's listeners
had been dead for the whole window. A device in a drawer, an oracle that had
crashed, and a working kill switch were the same observation.

So an **independent sentinel** now proves, continuously and throughout every
SILENCE phase, that each of the three data-plane listeners was still capable of
observing an arrival. Continuity for family F over `[t0,t1]` holds only if every
gap in `{t0} ∪ beats(F) ∪ {t1}` is at most `--sentinel-max-gap-ms`. **A family
with zero beats is not continuous**, and missing sentinel evidence never defaults
to true — the absent case and the false case both fail, because absence is what a
deployment that forgot produces.

**The first fix was itself a hole.** `sentinel_token` was returned in the
open-session response, which put it in the hands of the device under test. A DUT
beating that token from its own address during the armed window emits *precisely
the packet the kill switch is supposed to stop*, and the oracle would have filed
it as proof the oracle was alive — a vacuous SILENCE laundered through the
mechanism built to detect vacuous SILENCE. The token moved to
`POST /v1/sessions/{id}/sentinel`, **and** independence is now checked rather
than assumed: an IPv4/IPv6 beat from an address the device was also observed
egressing from is excluded from continuity, so dense forged beats cannot paper
over a real gap. That exclusion yields `INCONCLUSIVE`, not `FAIL` — a sentinel
behind the same NAT as the device presents the device's public address, and
accusing the product of a leak on the strength of a network layout is a lie in
the other direction. Since `INCONCLUSIVE` blocks eligibility exactly as `FAIL`
does, nothing ships on the back of it either way.

**Consequence, and it is not a small one: no lane can host its own sentinel.**
Not one of the three. The EC2 Mac *is* the DUT for `MACOS-SYSEXT-LIFECYCLE`; the
ubuntu controller runs the probe for `IOS-NE-FAIL-CLOSED` and so shares its
source address; and the Windows L1 host only *looks* independent, because the L2
guest's Hyper-V switch ordinarily NATs through L1's own address. All three lanes
had been planned that way. The sentinel is therefore a standing process on a
**separate machine** (§8), holding a beacon token and no control-plane
credential, so that host cannot open, close or read a session.

### 7.2 Attempts — silence from a device that stopped trying

Zero arrivals is also what a device that stopped probing produces. The probe now
self-reports per-family attempt counts, and a family below its configured minimum
(60, roughly a minute at ~1 Hz) is `INCONCLUSIVE`. Self-reporting is weak
evidence and is used accordingly: it can only make a session stricter, never
green. Over-reporting cannot manufacture a pass, and a failed attempts POST is
dropped rather than retried, because under-reporting is the safe direction.

### 7.3 DNS and path identity

DNS adjudication no longer depends on the authoritative server seeing an original
client IP. The probe carries its *intent* in the query name —
`<seq>.<probe_token>.<path_tag>.<zone>`, where `path_tag` is `p` or `u` — and the
oracle independently derives `resolver_id` from the **arriving resolver's**
address through `--resolver <ip>=<id>:<p|u>`. Intent and observation are then
compared: a disagreement during SILENCE is a `FAIL`, and an arrival from an
unmapped resolver sets `dns_resolver_identity_ambiguous` and is `INCONCLUSIVE`.

Two operational traps, both of which read as product failures to anyone who did
not configure the deployment:

* **With no `--resolver` flags at all, every DNS arrival is unattributable, so
  every session is `INCONCLUSIVE`.** This is deliberate and it is not a bug.
* An unconsumed tag letter becomes the token, the beacon matches no session and
  is dropped, and **the family reports zero arrivals — indistinguishable from a
  working kill switch.** The oracle therefore consumes `p`, `u`, `n` and `s`, and
  refuses an unrecognised value rather than defaulting to no-claim.

Distinct protected and unprotected identities are required for IPv4, IPv6 and
DNS. `*_identity_distinct` is nullable, but `null` is accepted *only* where the
adjudicator's table says that family is out of play, and `true` is refused there
too — `true` is the value someone writes to green a row about a leg that was
never exercised. **No lane is currently declared IPv6-less**, so an egress lane
whose network carries no IPv6 to the oracle goes red rather than passing over an
untested IPv6 kill switch. If a lane genuinely cannot carry IPv6 the fix is a
one-line table edit carrying its reason in the diff, not an inference from a
missing value.

### 7.4 Artifact and run binding

Evidence is bound to repository, `GITHUB_SHA`, `GITHUB_RUN_ID`,
`GITHUB_RUN_ATTEMPT`, criterion, and artifact name plus SHA-256. **Same SHA,
different run or attempt, is a rumour from another run** and is refused. Digests
are produced by the job that built the artifact, and the two artifacts that
genuinely cross a boundary — the signed IPA and the notarized app — are verified
after download against an operator-pinned repository variable with no fallback.
A same-job digest proves integrity, not provenance; the requirement stays anyway,
so the field is already checked the day a build moves into its own job.

`MACOS-SYSEXT-LIFECYCLE` requires two digests, the app executable and the
`.systemextension`'s own executable, because an app can activate an extension
built from a different tree and a digest of the app alone leaves the lifecycle
belonging to a pairing nobody assembled. `MACOS-PRODUCTION-SIGNATURE` likewise
requires the pinned `TwinVPN.app.zip` — the one artifact in the whole table with
a chain of custody back to the release pipeline rather than to a runner.

### 7.5 The final gate

`first-wave-acceptance` keeps `if: always()` so the report is always produced,
and redness comes from two independent mechanisms. `build/ci/require-job-results.py`
runs last, reads `toJSON(needs)`, and passes on `success` and nothing else —
`failure`, `cancelled`, `skipped`, an unrecognised conclusion, a job absent from
`needs`, and a missing acceptance report each exit 1 with a message naming the
responsible variable or runner label. `report.py` separately grades the evidence,
where `NOT-EXECUTED` and `INCONCLUSIVE` fail eligibility. **A specialized runner
being unavailable is RED, not green-by-absence**, and there is no fallback on any
criterion.

Two `continue-on-error: true` remain, both on `actions/download-artifact`
collection steps, because that action errors when its pattern matches nothing and
that is the normal case on an unprovisioned run — and killing the job destroys
the only artifact saying which rows are red. Neither can turn a red green: a
failed download leaves the evidence directory empty, absent files read as
`NOT-EXECUTED`, and the results gate fires on the job outcomes regardless.

### 7.6 Android

`getconf PAGE_SIZE` is compared for exact string equality with `16384` **before
anything is installed**, so a 4096-page boot produces no install and no
downstream result. A missing `zipalign` is now a hard error in this lane rather
than a warning, because an absent SDK component must not be indistinguishable
from a measured negative. The system-image sweep takes the highest **stable
integer** API at or below a pinned ceiling and excludes previews in the regex
itself: under the previous parse, `36.1`, `37.0`, `37.1` and `37.2` all reduced
to bare `36`/`37`, so `36.1` tied with real `android-36` and won or lost by
listing order. `system_image_revision` is read from the installed package's
`source.properties`, because the package path carries no version and two runs a
month apart can name the same path and boot different bits.

Every shipped ABI is checked for 16-KiB-safe ELF load alignment by
`build/ci/elf-align.py`, which parses the program header table directly and takes
the **minimum** `p_align` across all `PT_LOAD` segments of each `.so` — one
under-aligned segment is enough for the kernel to refuse the mapping. An ABI
present but unmeasurable is a failure, never a skip, and an APK with no
`lib/*/*.so` is refused as not the artifact under test. The `readelf`-scraping
version this replaced was silently wrong: GNU `readelf` wraps each LOAD across
two lines with `Align` on the continuation, so against real libraries the scraper
found **zero LOAD rows, which reads identically to "no libraries."** The
adjudicator grades the raw per-ABI map rather than a flattened boolean, and
requires `arm64-v8a` in it by name — a map of `{"x86_64": {"aligned": true}}`
passes a naive "every value true" check while being a green row about the one ABI
nobody ships to phones.

---

## 8. What does not exist yet

Every criterion except `ANDROID-16K-PAGE-SIZE` is blocked on infrastructure
rather than on code. The runner labels, repository variables, secrets, oracle
process flags and the standing sentinel host are enumerated, per criterion, in
`remote-acceptance-provisioning.md`. That file is the checklist; this one is the
reasoning behind it.

