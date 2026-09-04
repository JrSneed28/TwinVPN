# Remote acceptance provisioning

What the First Implementation Wave gate needs that nobody has stood up yet.
The reasoning behind each requirement is in `remote-acceptance-infrastructure.md`;
this file is the checklist an operator works from.

## Status, 2026-09-04

**This supersedes the 2026-09-02 status**, which stays below as history. The
design did not move: every lane still runs on a hosted GitHub runner, zero
self-hosted runners and zero Actions variables are still the design, and the
leak oracle, the sentinel and the two per-leg DNS forwarders still run in-box on
the lane's own runner. What moved is the Windows row, which PASSES, and the
account of what holds the last three rows.

The gate reads **26 of 29 required criteria PASS, Phase 5 eligibility FAIL** on
runs 33786997948 (d940e2f) and 33853609809 (6d51118). The contract gate is green
on 6d51118 and T1 supply chain on 84cda77 (crates.io yanked `wnaf` 0.14.0 on
2026-09-03; all eight lockfiles moved to 0.14.1). The three rows that are not
PASS are all NOT-EXECUTED and are the last three required rows in the table.
B-1 stays DEFERRED past Wave 1 and outside the conjunction (`ownership.md`
§11.5 D-9).

**What blocks the remaining three rows is no longer infrastructure, and for the
only lane that reaches `net up` it is no longer the product either.**
`MACOS-PRODUCTION-SIGNATURE` waits on the `TWINVPN_*` variables in
`remote-acceptance-infrastructure.md` §4.3 (three, plus the optional token) and
on a signing/notarization job that does not yet exist; `MACOS-SYSEXT-LIFECYCLE`
and `IOS-NE-FAIL-CLOSED` wait on the wave owner's policy decision. The four
product walls (below) remain product work: they still stop a production build's
`net up` and are a latent second blocker behind the two no-executor rows.

The only secrets configured remain the four `TWINVPN_RELEASE_*` values, which
hold a CI-only Android acceptance keystore that is **not** the Play release
identity and must never sign a shipped build. They stay.

### Everything, by criterion

"Hosted runner" below means an ordinary GitHub-hosted runner, provisioned by
nobody. Where a row also needs something, that something is named. A bare
**PASS** is the gate on d940e2f, run 33786997948.

| Criterion | Needs | State |
|---|---|---|
| `ANDROID-16K-PAGE-SIZE` | hosted runner; the four `TWINVPN_RELEASE_*` secrets | **PASS** (first on run 33367031994) |
| `MACOS-PF-BOOT-ANCHOR` | hosted runner (`macos-26`, root via passwordless sudo) | **PASS** |
| `IOS-FAILCLOSED-CONFIGURATION` | hosted runner (`macos-26` simulator) | **PASS** |
| `IOS-PROFILE-REMOVAL-HONESTY` | hosted runner (`macos-26` simulator) | **PASS** |
| `WINDOWS-WFP-KILLSWITCH` | hosted runner (`windows-2025`, nested Hyper-V guest built per run); `lab/twinpeer` on L1 as the Noise_IKpsk2 far end; `twinvpnsvc` built `--features lab-seed` (never in `default`) reading `TWINVPN_LAB_SEED_FILE` | **PASS** (runs 33750757726 on 08a7ae4, 33786997948 on d940e2f, 33853609809 on 6d51118). Walls 1–2 are closed for the lane by the seed, not by the product; walls 3–4 never bind because the beacon target and the protected relay sit on the peer overlay |
| `MACOS-PRODUCTION-SIGNATURE` | hosted runner (`macos-26`); **`TWINVPN_TEAM_ID`, `TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`**, optional `TWINVPN_NOTARIZED_APP_TOKEN`; **and a signing/notarization job the repository does not have** | required, NOT-EXECUTED, blocked on both: the job **skips by name** when the URL is unset (`first-implementation-wave-gate.yml:1288-1291`), and nothing in the repository can produce what the URL would name (EX-1, below) |
| `MACOS-SYSEXT-LIFECYCLE` | **no executor in the gate**; the cheapest real one is priced below | required, NOT-EXECUTED; **OD-1 open** — keep required with a funded route, or `required=False` in `IOS-SUPERVISED-ALWAYS-ON`'s shape |
| `IOS-NE-FAIL-CLOSED` | **no executor in the gate**; the cheapest real one is priced below | required, NOT-EXECUTED; **same OD-1** |
| `IOS-SUPERVISED-ALWAYS-ON` | only if that product mode ships | out of scope, `required=False` |

### `MACOS-PRODUCTION-SIGNATURE` is blocked twice (EX-1)

The row's premise — that a release pipeline publishes the signed, notarized,
stapled `TwinVPN.zip` the three variables point at — is not true of this
repository. Nothing in it signs, notarizes, staples or publishes a macOS app:
`t4-release.yml`'s jobs (`t3`, `mutants-complete`, `release-blockers`,
`not-verified`) run no `codesign`, `notarytool` or `stapler`; the only such calls
repo-wide are the verifier's own (`build/ci/ci-macos-signature.sh:215-218`,
`:242`); `build/ci/ci-macos.sh:293-299` builds with `CODE_SIGNING_ALLOWED=NO`;
and `shells/macos/packaging/SIGNING.md:11-21` records that not one of its
commands has been executed and (`:205-208`) that the repository has no place to
hold the App Store Connect key. SIGNING.md also notarizes and staples
`TwinVPN.pkg` (`:131`, `:143`) while the verifier unpacks `TwinVPN.zip` and runs
`xcrun stapler validate` on `TwinVPN.app`
(`first-implementation-wave-gate.yml:1357-1360`, `ci-macos-signature.sh:218`),
so a pipeline that followed SIGNING.md verbatim would fail the `stapled` check.

What closes it, in order: a paid Apple Developer Program team (US$99/yr; this
is the Team ID, and the Network Extensions and System Extension capabilities
are self-service there and absent from the free tier), a Developer ID
Application certificate (Installer only if a `.pkg` ships; the verifier consumes
a zip), Developer ID profiles carrying `packet-tunnel-provider-systemextension`,
an App Store Connect API key for `notarytool store-credentials`, and a **new**
hosted `macos-26` job (macOS minutes bill at 10x) that imports the `.p12` into a
temporary keychain, runs `xcodebuild archive` with manual inside-out signing per
SIGNING.md §2–3, `notarytool submit --wait`, `stapler staple TwinVPN.app`,
`ditto -c -k --keepParent TwinVPN.app TwinVPN.zip`, publishes the zip as a
release asset and prints its SHA-256; then set the three variables. Before
wiring it, confirm that the unsigned `ci-macos.sh` build yields
`Contents/Library/SystemExtensions/*.systemextension` —
`ci-macos-signature.sh:242` fails closed otherwise, and this has not been
checked against a run artifact. The row is required, so Phase 5 eligibility
stays FAIL until it runs or the owner defers it alongside OD-1.

### The two rows with no executor, and what one would cost (OD-1, open)

The reasons `report.py` prints for both rows (`NO_EXECUTOR`, `:485-497`), which
`first-implementation-wave-gate.yml:33-38` and the 2026-09-02 status below
repeat, are partly refuted, so the decision cannot be made on those grounds.
Corrected on 2026-09-04:

* **`MACOS-SYSEXT-LIFECYCLE`.** There is no Apple grant to wait for: Network
  Extensions and System Extension are self-service capabilities in
  Certificates, Identifiers & Profiles for any paid team, the portal emits the
  `-systemextension` value for Developer ID profiles, and Apple dropped the
  request process on 2016-11-10 (TN3134 gates only family-controls and
  HotspotHelper). The free tier lacks both capabilities, so the US$99/yr
  membership is the actual prerequisite. The approval half stands: Apple
  documents no bypass of the System Settings toggle for either SIP-disabled or
  `systemextensionsctl developer on` (developer mode relaxes only the
  location/version check); the question stays unmeasured, see "Elsewhere"
  below. The System Extensions MDM payload needs Device Enrollment or ADE. "No
  scriptable macOS runner" is wrong for bare-metal EC2 Mac —
  `aws-samples/amazon-ec2-mac-mdm-enrollment-automation` GUI-scripts
  user-approved Device Enrollment into Jamf, Addigy, Kandji or Fleet after a
  one-time Screen-Sharing AMI setup, and documents pushing a System Extensions
  payload with user approval disabled — and right for hosted `macos-26`: no
  MDM, and no static UDID on arm64, so no ADE. **Cheapest real executor:** the
  paid team (US$99/yr) + a Developer-ID build carrying the `-systemextension`
  profile (which needs the EX-1 signing job) + a `mac2-m2.metal` instance at
  ≈ US$0.878/h with a 24 h minimum (≈ US$21/day while it runs), MDM-enrolled
  (Fleet's free tier plus an APNs push certificate) and registered as a
  self-hosted runner + `ci-macos-sysext.sh` accepting a pre-approved extension +
  a macOS `lab-seed` for walls 1–4 (none exists: the `macos-pf-anchor` evidence
  records `net.up` refusing `AUTH.IDENTITY_MISSING`) + a utun-capable `twinpeer`
  and a reachable oracle (the row is `ORACLE_REQUIRED`, `report.py:444-449`;
  `twinpeer serve` bails off Windows, `lab/twinpeer/src/serve.rs:204-210`) +
  the attestation keys at `report.py:308-314` + the cloud-Mac exclusion at
  `first-implementation-wave-gate.yml:74-77` lifted. Medium confidence that the
  GUI-scripted approval works on the macOS release EC2 offers today. One gap
  sits in front of all of it: no macOS code creates a VPN configuration — there
  is no `saveToPreferences` or `NETunnelProviderManager` under `shells/macos` or
  `core/crates/twinvpn-platform-macos`, and `SystemExtensionInstaller.swift:92`
  only issues the activation request — so `ci-macos-sysext.sh:482`'s
  `twinvpnctl net up` presupposes a configuration nothing installs.
* **`IOS-NE-FAIL-CLOSED`.** The simulator half stands (DTS thread 101663,
  re-verified). "Every commercial device farm re-signs" does not: AWS Device
  Farm private devices (`skipAppResign`, private devices only, an XCUITest or
  Appium package rather than the XCTest package type, from US$200/month), Sauce
  Labs private devices (`resigningEnabled=false`, a build-for-testing `.ipa`
  plus `.xctestrun` via `saucectl`, enterprise quote) and BrowserStack's Custom
  Device Lab (UDID in the profile, entitlements preserved) all keep the
  entitlement, and the repository already recorded that Corellium does not
  re-sign (`ownership.md:1234`, `self-hosted-runners.md:25`). Firebase Test Lab
  (and Bitrise on it), Xcode Cloud (simulator-only) and hosted `macos-26` (no
  devices, no MDM, no static UDID) are correctly excluded. **Cheapest real
  executor:** the paid team (US$99/yr; the free tier lacks the capability) + one
  AWS Device Farm private iPhone (≥ US$200/month) or a Sauce private device,
  its UDID registered in a Development or ad-hoc profile. Prerequisites the
  price omits: device signing in CI (`.p12` and profile in secrets;
  `build/ci/ci-ios.sh:333`'s `-allowProvisioningUpdates` needs an App Store
  Connect key on the runner); an iOS `lab-seed` (none exists — `lab-seed` is
  `shells/windows/twinvpnsvc` only, `Cargo.toml:82` — so walls 1–2 refuse
  `net.up` on any production iOS build); a far end and oracle the phone can
  reach (`twinpeer` is Windows-only by an explicit `bail!` and an unconditional
  `twinvpn-platform-windows` dependency; the row is `ORACLE_REQUIRED` and needs
  the attestation keys at `report.py:374-379`); a lane rewrite, since
  `ci-ios.sh:315-330` runs `xcodebuild test -destination id=<UDID>` against a
  USB-attached device, which no farm accepts; the VPN-consent alert tapped
  through the springboard `XCUIApplication`; and the same exclusion at
  `first-implementation-wave-gate.yml:74-77` lifted. Cost: US$99/yr +
  ≥ US$200/month + secrets infrastructure + an iOS seed + a `twinpeer` port.

**The alternative for both rows is `required=False`** in
`IOS-SUPERVISED-ALWAYS-ON`'s shape (`report.py:767` is the `add(...,
required=True)` signature; `:987-996` is the supervised row's flip), recorded
in the register as a deliberate scope reduction. **OD-1 is the wave owner's
decision and is not made here.** The two options, with the corrected facts:
**(a)** keep both `required=True`, NOT-EXECUTED and blocking Phase 5, and fund
the executor priced above for each; or **(b)** `required=False` for both, in
which case the SIP question under "Elsewhere" below is moot. Whichever is
chosen, the `NO_EXECUTOR` strings, `first-implementation-wave-gate.yml:33-38`
and the 2026-09-02 rows below still carry the refuted reasons and are to be
reworded to these.

### The four product walls, and what the lab seed stands in for

These are what stops a PRODUCTION build's `net up`: `enforce::arm` refuses
`AUTH.IDENTITY_MISSING` without an overlay allocation (wall 1,
`core/crates/twinvpn-core/src/enforce.rs:185-189`) and `AUTH.PEER_UNTRUSTED`
without a verified peer (wall 2, `:191-198`) and blocks the host on the way
out. Walls 3 and 4 refuse nothing; they decide what a TwinnetOnly device routes
and resolves. The Windows lane closes 1–2 with a never-default `lab-seed` build
and a lab peer, aims its beacon and protected relay at the peer overlay so 3–4
never come into play, and PASSES. `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED` have no executor for reasons unrelated to the walls, and an
executor would need the same seed, which exists only for Windows.

1. **No overlay allocation.** `ControlPlanePort::put_local_overlay`
   (`planes.rs:474`) has no production caller; the only callers are tests —
   and, under the never-default `lab-seed` feature only,
   `shells/windows/twinvpnsvc/src/lab_seed.rs:278`.
2. **No verified peer.** No shell binds the control transport, and
   `pair.confirm` is NotWired (`dispatch.rs:194`) because ADR-0007 leaves
   `transcript_hash` with no defined preimage — a specification defect, not
   missing wiring (`pairing/mod.rs:137-165`). The lab seed supplies one verified
   peer through `twinvpn_crypto::testkit::verified_tunnel_key`
   (`lab_seed.rs:211`), a `test-support` fixture that never ships.
3. **No default route.** `RoutingMode::TwinnetOnly` is hard-coded with no exit
   node and no exit grant (`enforce.rs:236-254`), and `exitnode.select` is
   refused (`dispatch.rs:226`), so no operator can change it over the shipped
   interface.
4. **No protected resolver.** DNS is programmed OFF with empty stub addresses,
   and `twinvpn-dns` binds no listener (`enforce.rs:263`, `:525-548`,
   `twinvpn-dns/src/lib.rs:27-32`).

And, outside the device, **no forwarding gateway exists anywhere**: `twinsim
peer` runs no L-DATA tunnel, and `twinvpn-gateway` decides and never forwards.
`lab/twinpeer` (never shipped, ADR-0018 §11.12) is a real L-DATA far end —
`twinvpn_core::lab::drive` + `Pump` on a Wintun adapter — that holds the peer
overlay addresses; it forwards nothing to the internet, so the
forwarding-gateway gap stands. All of this is product work, tracked as such —
not provisioning; the seed is what the pairing ceremony and rendezvous will
replace (`lab_seed.rs:11-23`).

### Repository configuration

Variables, all three of them, all Apple Developer Program facts:
`TWINVPN_TEAM_ID`, `TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`.
None is set, and none can be set truthfully until the EX-1 job exists to
produce what they would name.

Secrets: the four `TWINVPN_RELEASE_*` Android values, which should move to a
KMS/HSM signing operation rather than shipping key material into a runner; and
the optional `TWINVPN_NOTARIZED_APP_TOKEN`, which should be replaced by GitHub
OIDC federation rather than a long-lived value.

The retired variables and the oracle's process flags are as the 2026-09-02
status records them below; nothing there changed.

## Status, 2026-09-02

> **Superseded by the 2026-09-04 status above; kept as history.** Where this
> section disagrees with the one above, the one above is current: the Windows
> row PASSES on three runs and no lane has ever emitted `blocked_on`; only walls
> 1–2 refuse, and `net up` exited 0 with walls 3–4 standing;
> `put_local_overlay` has a non-test caller under `lab-seed`; the Apple facts are
> three variables plus a signing job that does not exist, not "two"; and the
> "entitlement never granted" and "every farm re-signs" reasons for the two
> no-executor rows are refuted. Dated pointers mark each site.

**This supersedes the 2026-08-30 status.** That one listed a standing sentinel
host, an Azure L1 self-hosted runner, an EC2 Mac, a Corellium project and a
public oracle host. **None of them is required now, and none is a gap: zero
self-hosted runners and zero Actions variables is the design.** Every lane runs
on a hosted GitHub runner, and the leak oracle, the sentinel and the two per-leg
DNS forwarders run in-box on the lane's own runner.

The only secrets configured remain the four `TWINVPN_RELEASE_*` values, which
hold a CI-only Android acceptance keystore that is **not** the Play release
identity and must never sign a shipped build. They stay.

**What blocks the remaining rows is no longer infrastructure.** It is four
product walls (below), two Apple facts nobody outside the Developer Program
account can supply, and one policy decision for the wave owner.
*(2026-09-04: superseded — three rows remain, the Windows row passed, and the
blockers are restated in the status above.)*

### Everything, by criterion

"Hosted runner" below means an ordinary GitHub-hosted runner, provisioned by
nobody. Where a row also needs something, that something is named.

| Criterion | Needs | State |
|---|---|---|
| `ANDROID-16K-PAGE-SIZE` | hosted runner; the four `TWINVPN_RELEASE_*` secrets | **PASS** (run 33367031994) |
| `MACOS-PF-BOOT-ANCHOR` | hosted runner (`macos-26`, root via passwordless sudo) | new row; nothing to provision |
| `IOS-FAILCLOSED-CONFIGURATION` | hosted runner (`macos-26` simulator) | new row; nothing to provision |
| `IOS-PROFILE-REMOVAL-HONESTY` | hosted runner (`macos-26` simulator) | redefined as simulator logic; nothing to provision |
| `MACOS-PRODUCTION-SIGNATURE` | hosted runner (`macos-26`); **`TWINVPN_TEAM_ID`, `TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`**, optional `TWINVPN_NOTARIZED_APP_TOKEN` | blocked on the Apple facts only — the job **skips by name** when the URL is unset, and the row reads NOT-EXECUTED *(2026-09-04: also blocked on a signing job that does not exist — EX-1 above)* |
| `WINDOWS-WFP-KILLSWITCH` | hosted runner (`windows-2025`, nested Hyper-V guest built per run) | **blocked on product walls 1–4** — the lane runs to the `net up` refusal and records an executed FAIL with `blocked_on` naming the wall *(2026-09-04: superseded — PASS on runs 33750757726, 33786997948 and 33853609809 via `lab-seed` + `lab/twinpeer`; no lane ever emitted `blocked_on`)* |
| `MACOS-SYSEXT-LIFECYCLE` | **no executor anywhere** — two GUI approvals only MDM can bypass, an Apple entitlement never granted, and no non-NetworkExtension tunnel path. Also blocked on walls 1–4 *(2026-09-04: the capability is self-service for a paid team; an executor would also need a seed in the shape of the Windows lane's `lab-seed` (walls 1–2) and a peer-overlay beacon target (walls 3–4); neither exists for this platform)* | required, NOT-EXECUTED; **policy decision open** (keep required, or defer like `IOS-SUPERVISED-ALWAYS-ON`) |
| `IOS-NE-FAIL-CLOSED` | **no executor anywhere** — a real device with a provisioned packet-tunnel entitlement. Also blocked on walls 1–4 *(2026-09-04: private-device farms keep the entitlement; an executor would also need a seed in the shape of the Windows lane's `lab-seed` (walls 1–2) and a peer-overlay beacon target (walls 3–4); neither exists for this platform)* | required, NOT-EXECUTED; **same policy decision open** |
| `IOS-SUPERVISED-ALWAYS-ON` | only if that product mode ships | out of scope, `required=False` |

### The four product walls that block the egress rows

These are the blocker for `WINDOWS-WFP-KILLSWITCH`, `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED`, on every possible host. `twinvpnctl net up` refuses at
`core/crates/twinvpn-core/src/enforce.rs:185` with `AUTH.IDENTITY_MISSING` and
blocks the host before any tunnel exists, so a lane dies at the `net up` line
before its TUNNELLED phase is ever declared. Each wall is load-bearing on its
own; closing one changes nothing.
*(2026-09-04: superseded — only walls 1–2 refuse, and the Windows lane closes
them with a lab seed; see "The four product walls, and what the lab seed stands
in for" above.)*

1. **No overlay allocation.** `ControlPlanePort::put_local_overlay`
   (`planes.rs:474`) has no production caller; the only callers are tests.
   *(2026-09-04: and `shells/windows/twinvpnsvc/src/lab_seed.rs:278`, under the
   never-default `lab-seed` feature only.)*
2. **No verified peer.** No shell binds the control transport, and
   `pair.confirm` is NotWired (`dispatch.rs:194`) because ADR-0007 leaves
   `transcript_hash` with no defined preimage — a specification defect, not
   missing wiring (`pairing/mod.rs:137-165`).
   *(2026-09-04: the lab seed supplies one verified peer through
   `twinvpn_crypto::testkit::verified_tunnel_key`, `lab_seed.rs:211`, a
   `test-support` fixture that never ships.)*
3. **No default route.** `RoutingMode::TwinnetOnly` is hard-coded with no exit
   node and no exit grant (`enforce.rs:236-254`), and `exitnode.select` is
   refused (`dispatch.rs:226`), so no operator can change it over the shipped
   interface.
4. **No protected resolver.** DNS is programmed OFF with empty stub addresses,
   and `twinvpn-dns` binds no listener (`enforce.rs:263`, `:525-548`,
   `twinvpn-dns/src/lib.rs:27-32`).

And, outside the device, **no forwarding gateway exists anywhere**: `twinsim
peer` runs no L-DATA tunnel, and `twinvpn-gateway` decides and never forwards.
All of this is product work, tracked as such — not provisioning.
*(2026-09-04: `lab/twinpeer` is a real L-DATA far end that forwards nothing to
the internet; the forwarding-gateway gap stands.)*

### Repository configuration

Variables, all three of them, all Apple Developer Program facts:
`TWINVPN_TEAM_ID`, `TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`.

Secrets: the four `TWINVPN_RELEASE_*` Android values, which should move to a
KMS/HSM signing operation rather than shipping key material into a runner; and
the optional `TWINVPN_NOTARIZED_APP_TOKEN`, which should be replaced by GitHub
OIDC federation rather than a long-lived value.

**Retired and no longer needed:** `TWINVPN_AZURE_L1_REGISTERED`,
`TWINVPN_EC2_MAC_REGISTERED`, `TWINVPN_CORELLIUM_ENABLED`, `TWINVPN_GOLDEN_VHD`,
`TWINVPN_SENTINEL_HOST`, `TWINVPN_ORACLE_URL`, `TWINVPN_ORACLE_TOKEN`,
`TWINVPN_EXTENSION_BUNDLE_ID`, `CORELLIUM_PROJECT_ID`, `CORELLIUM_API_TOKEN`,
`TWINVPN_SIGNED_IPA_URL`, `TWINVPN_SIGNED_IPA_SHA256`,
`TWINVPN_SIGNED_IPA_TOKEN`.

The oracle's process flags — `--sentinel-max-gap-ms`, repeatable
`--resolver <ip>=<id>:<p|u>`, `--sentinel-token-file` — are now set by the lane's
own controller when it stands the in-box fabric up. They are still not sent by
the device under test, which remains the last party that should describe the
deployment.

## Known gaps in the probes themselves

These are recorded rather than fixed. Some cannot be closed without work that
has not been done; the ones under the residual device criterion cannot be closed
in their current form at all, and that is a finding rather than a delay.

### Under `IOS-NE-FAIL-CLOSED`, the residual device row

Corellium was the planned executor and cannot be one. These items no longer
block a provisioning step, because there is no Corellium step to provision; they
are recorded as what was learned about that route.

* **Corellium cannot perform three of the five injections.** `app/crash`,
  `network/disable` and `vpn/disable` appear nowhere in Corellium's OpenAPI
  document, nowhere in the generated clients, and nowhere in the WebSocket agent
  protocol the REST `agent/v1/*` paths bridge to. The SDK's only crash surface
  is `crash.subscribe`, a listener that waits for a report the OS produces on
  its own — the agent can observe a crash but cannot cause one.
* **Whether a `NEPacketTunnelProvider` runs at all on a Corellium virtual iPhone
  is unverified.** No primary source states it either way. Every "VPN" surface
  Corellium documents is its own project-level OpenVPN for connecting a
  researcher's machine into the virtual network, which is a different thing
  wearing the same word. If that premise is false the whole route is unfounded.
* **Corellium cannot pass launch arguments to an iOS app.**
  `POST /agent/v1/app/apps/{bundleId}/run` takes the bundle id in the path and
  defines no request body, and the WebSocket `agent.run(bundleID)` takes only a
  bundle id. The lane's `--ci-start-tunnel` and `--ci-report-protection-state`
  therefore had no transport, and nothing under `shells/ios/` implemented them
  either — the trigger was missing at both ends.
* **The Corellium lane ran the probe on the ubuntu controller, not on the
  iPhone**, recording it honestly as `environment.probe_host: "controller"`,
  which the adjudicator refuses. A controller-side probe produces an oracle
  report that is internally consistent and entirely about the wrong machine.
* **`IOS-PROFILE-REMOVAL-HONESTY` no longer needs any of this.** Corellium had
  no mechanism to remove an app-created VPN configuration — it models VPN
  configuration as a Mobile Configuration Profile, and TwinVPN installs no
  `.mobileconfig` — but the criterion is now simulator logic driven by an
  injected "no configuration" observation, and
  `NEVPNManager.removeFromPreferences(completionHandler:)` has existed since
  iOS 8 in any case. Only the user's Settings journey was ever device-only.

### Elsewhere

* **The evaluation-media licence question is open.** The Windows guest is built
  from Windows 11 Enterprise LTSC 2024 evaluation media fetched from Microsoft's
  CDN with a pinned SHA-256. The Evaluation Center gates those images behind a
  registration form that the direct URLs bypass; whether doing so in automation
  is within the licence is not answered here.
* **Whether SIP-disabled bypasses the macOS system-extension approval is
  unverified in either direction.** Apple documents what developer mode and SIP
  each relax, and approval is on neither list, but Apple nowhere states the
  negative. No lane may be built on the hope that it does.
* **Whether concurrent hosted runners share an egress address is unverified.**
  It only matters for the external oracle deployment, which the in-box topology
  replaces; the in-box sentinel's independence is structural.
* **`build/ci/ci-android.sh` is 1593 lines** against the 500-line ceiling, as
  are `build/acceptance/report.py` at 925, `ci-ios-corellium.sh` at 709 and
  `ci-macos-sysext.sh` at 516. Compressing the reasoning out of them would buy
  the line count at the cost of the only thing that makes each correction
  checkable, so the size is recorded as debt instead.
