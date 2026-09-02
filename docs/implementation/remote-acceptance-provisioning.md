# Remote acceptance provisioning

What the First Implementation Wave gate needs that nobody has stood up yet.
The reasoning behind each requirement is in `remote-acceptance-infrastructure.md`;
this file is the checklist an operator works from.

## Status, 2026-09-02

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

### Everything, by criterion

"Hosted runner" below means an ordinary GitHub-hosted runner, provisioned by
nobody. Where a row also needs something, that something is named.

| Criterion | Needs | State |
|---|---|---|
| `ANDROID-16K-PAGE-SIZE` | hosted runner; the four `TWINVPN_RELEASE_*` secrets | **PASS** (run 33367031994) |
| `MACOS-PF-BOOT-ANCHOR` | hosted runner (`macos-26`, root via passwordless sudo) | new row; nothing to provision |
| `IOS-FAILCLOSED-CONFIGURATION` | hosted runner (`macos-26` simulator) | new row; nothing to provision |
| `IOS-PROFILE-REMOVAL-HONESTY` | hosted runner (`macos-26` simulator) | redefined as simulator logic; nothing to provision |
| `MACOS-PRODUCTION-SIGNATURE` | hosted runner (`macos-26`); **`TWINVPN_TEAM_ID`, `TWINVPN_NOTARIZED_APP_URL`, `TWINVPN_NOTARIZED_APP_SHA256`**, optional `TWINVPN_NOTARIZED_APP_TOKEN` | blocked on the Apple facts only — the job **skips by name** when the URL is unset, and the row reads NOT-EXECUTED |
| `WINDOWS-WFP-KILLSWITCH` | hosted runner (`windows-2025`, nested Hyper-V guest built per run) | **blocked on product walls 1–4** — the lane runs to the `net up` refusal and records an executed FAIL with `blocked_on` naming the wall |
| `MACOS-SYSEXT-LIFECYCLE` | **no executor anywhere** — two GUI approvals only MDM can bypass, an Apple entitlement never granted, and no non-NetworkExtension tunnel path. Also blocked on walls 1–4 | required, NOT-EXECUTED; **policy decision open** (keep required, or defer like `IOS-SUPERVISED-ALWAYS-ON`) |
| `IOS-NE-FAIL-CLOSED` | **no executor anywhere** — a real device with a provisioned packet-tunnel entitlement. Also blocked on walls 1–4 | required, NOT-EXECUTED; **same policy decision open** |
| `IOS-SUPERVISED-ALWAYS-ON` | only if that product mode ships | out of scope, `required=False` |

### The four product walls that block the egress rows

These are the blocker for `WINDOWS-WFP-KILLSWITCH`, `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED`, on every possible host. `twinvpnctl net up` refuses at
`core/crates/twinvpn-core/src/enforce.rs:185` with `AUTH.IDENTITY_MISSING` and
blocks the host before any tunnel exists, so a lane dies at the `net up` line
before its TUNNELLED phase is ever declared. Each wall is load-bearing on its
own; closing one changes nothing.

1. **No overlay allocation.** `ControlPlanePort::put_local_overlay`
   (`planes.rs:474`) has no production caller; the only callers are tests.
2. **No verified peer.** No shell binds the control transport, and
   `pair.confirm` is NotWired (`dispatch.rs:194`) because ADR-0007 leaves
   `transcript_hash` with no defined preimage — a specification defect, not
   missing wiring (`pairing/mod.rs:137-165`).
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
