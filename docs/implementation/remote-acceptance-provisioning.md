# Remote acceptance provisioning

What the First Implementation Wave gate needs that nobody has stood up yet.
The reasoning behind each requirement is in `remote-acceptance-infrastructure.md`;
this file is the checklist an operator works from.

## Status, 2026-08-30

**As of 2026-08-30 this repository has zero registered self-hosted runners and
zero Actions variables.** The only secrets configured are the four
`TWINVPN_RELEASE_*` values, which hold a CI-only Android acceptance keystore that
is **not** the Play release identity and must never sign a shipped build. Every
criterion below is therefore blocked on infrastructure, not on code.

### The sentinel host — one machine, three criteria

**Nothing in the current or planned fleet can be it**, for the reasons in §7.1.
It is one small always-on VM, any cloud, any OS with `bash`, `curl` and
`python3`, whose egress path is shared with neither the oracle nor any device
under test, running `build/ci/leak-probe.sh sentinel` forever as a systemd unit
against the oracle's `--sentinel-token-file` token. It holds no control-plane
credential.

**The hard constraint is an egress ADDRESS, not a machine count.** Its packets
must reach the oracle from a source address that no device under test is ever
observed egressing from — for all three lanes at once. This is what rules out
every cheap answer: another runner in the same GitHub pool can present the same
NAT address as the one running the probe; a second VM in the same Azure VNet
shares the L1 host's outbound IP, and the L2 guest already NATs through L1; a
container on the EC2 Mac *is* the DUT; and a second box in the same office
shares the office's public IP. The oracle discards a beat arriving from a
device-seen address, so **a sentinel that fails this is worse than no sentinel
at all — it looks configured and proves nothing.** A small VM at a different
provider, or in a separate cloud account with its own egress, is the reliable
answer.

It also needs working IPv6 to the oracle. A host without it leaves
`ipv6_sentinel_continuous` false, which is `INCONCLUSIVE` for every criterion
with an IPv6 leg. That is not a nice-to-have.

It is the cheapest item on this list and it gates three of the five remaining
rows: `WINDOWS-WFP-KILLSWITCH`, `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED`. All three lanes exit 2 without `TWINVPN_SENTINEL_HOST`
rather than crediting a sentinel-less silence.

### Everything else, by criterion

| Criterion | Needs | State |
|---|---|---|
| `ANDROID-16K-PAGE-SIZE` | hosted runner; the four `TWINVPN_RELEASE_*` secrets | **PASS** (run 33367031994) |
| `WINDOWS-WFP-KILLSWITCH` | oracle + sentinel host + Azure L1 runner `twinvpn-azure-l1` + golden VHDX | blocked |
| `MACOS-SYSEXT-LIFECYCLE` | oracle + sentinel host + EC2 Mac runner `twinvpn-ec2-mac` + Apple Team ID | blocked |
| `MACOS-PRODUCTION-SIGNATURE` | EC2 Mac runner + a notarized artifact and its pinned digest | blocked |
| `IOS-NE-FAIL-CLOSED` | oracle + sentinel host + Corellium project + a signed IPA and its pinned digest — **and a mechanism for three injections Corellium does not have** | blocked on capability, not only on provisioning |
| `IOS-PROFILE-REMOVAL-HONESTY` | Corellium project + signed IPA — **and a way to remove an app-created VPN configuration, which Corellium has no API for** | blocked on capability, not only on provisioning |
| `IOS-SUPERVISED-ALWAYS-ON` | only if that product mode ships | out of scope |

### Repository configuration

Variables — none is a credential, so none is OIDC-replaceable:
`TWINVPN_AZURE_L1_REGISTERED`, `TWINVPN_EC2_MAC_REGISTERED`,
`TWINVPN_CORELLIUM_ENABLED`, `TWINVPN_GOLDEN_VHD`, `TWINVPN_TEAM_ID`,
`TWINVPN_EXTENSION_BUNDLE_ID`, `CORELLIUM_PROJECT_ID`, `TWINVPN_ORACLE_URL`,
`TWINVPN_SENTINEL_HOST`, `TWINVPN_SIGNED_IPA_URL`, `TWINVPN_SIGNED_IPA_SHA256`,
`TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`.

Secrets: `TWINVPN_ORACLE_TOKEN`, `TWINVPN_SIGNED_IPA_TOKEN` and
`TWINVPN_NOTARIZED_APP_TOKEN` should all be replaced by GitHub OIDC federation
rather than long-lived values. `CORELLIUM_API_TOKEN` has no federation available
and must be project-scoped and rotated. The four `TWINVPN_RELEASE_*` values
should move to a KMS/HSM signing operation rather than shipping key material into
a runner.

Oracle process flags, which no CI job sends because the device under test is the
last party that should describe the deployment: `--sentinel-max-gap-ms`,
repeatable `--resolver <ip>=<id>:<p|u>`, and `--sentinel-token-file`.

## Known gaps in the probes themselves

These are recorded rather than fixed. Some cannot be closed without
infrastructure that does not exist; the Corellium items below cannot be closed
at all in their current form, and that is a finding rather than a delay.

* **Corellium cannot perform three of the five `IOS-NE-FAIL-CLOSED`
  injections, so that criterion cannot be discharged there as specified.** This
  is not "not yet wired". `app/crash`, `network/disable` and `vpn/disable`
  appear nowhere in Corellium's OpenAPI document, nowhere in the generated
  clients, and nowhere in the WebSocket agent protocol the REST `agent/v1/*`
  paths bridge to. The SDK's only crash surface is `crash.subscribe`, a
  listener that waits for a report the OS produces on its own — the agent can
  observe a crash but cannot cause one. The lane now refuses each of the three
  by name rather than downgrading the resulting 404 to a warning and opening a
  SILENCE phase whose premise is false, which is what it did before.
* **`IOS-PROFILE-REMOVAL-HONESTY`'s removal step has no mechanism either.**
  Corellium models VPN configuration as a Mobile Configuration Profile and
  exposes list and delete over `agent/v1/profile/profiles`. TwinVPN installs no
  `.mobileconfig`: the iOS app creates its configuration itself through
  `NETunnelProviderManager.saveToPreferences()`
  (`shells/ios/Sources/TwinVPNApp/VPNPermission.swift`). There is no profile
  object on the device for that API to address.
* **Corellium cannot pass launch arguments to an iOS app.**
  `POST /agent/v1/app/apps/{bundleId}/run` takes the bundle id in the path and
  defines no request body; the WebSocket protocol's `agent.run(bundleID)` takes
  only a bundle id, and the variant that accepts more (`runActivity`) is
  Android-only. The lane's `--ci-start-tunnel` and
  `--ci-report-protection-state` therefore had no transport, and nothing under
  `shells/ios/` implemented them either — the trigger was missing at both ends.
  The chosen replacement is a control file uploaded with
  `PUT /agent/v1/file/device/{path}`, an endpoint that does exist, read at
  launch by a CI-only compiled path.
* **Whether a `NEPacketTunnelProvider` runs at all on a Corellium virtual
  iPhone is unverified.** No primary source — Corellium's API specification,
  its SDKs, its support documentation, or upstream — states it either way.
  Every "VPN" surface Corellium documents is its own project-level OpenVPN for
  connecting a researcher's machine into the virtual network, which is a
  different thing wearing the same word. If this premise is false the entire
  lane is unfounded. It is cheapest to settle with a live smoke test on a trial
  account, not with more reading.
* **`ci-ios-corellium.sh` runs the probe on the ubuntu controller, not on the
  iPhone.** It records this honestly as `environment.probe_host: "controller"`,
  and the adjudicator refuses that value — `IOS-NE-FAIL-CLOSED` therefore cannot
  go green until the probe runs on the device under test. A controller-side probe
  produces an oracle report that is internally consistent and entirely about the
  wrong machine, which is exactly the failure the `probe_host` key exists to
  catch. It is caught, and it is not yet fixed.
* **`build/ci/ci-android.sh` is 1593 lines** against the 500-line ceiling, as are
  `build/acceptance/report.py` at 925 and `ci-ios-corellium.sh`, which grew from
  473 to 675 carrying the corrections above. Both were already over before the
  2026-08-30 pass (1104 and 803 respectively). Splitting the 16 KiB lane out of
  the Android script would restructure the link/run lane with it, which is not
  work to do at the end of a hardening pass; it is recorded as debt rather than
  reported as clean.
