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

It is the cheapest item on this list and it gates three of the five remaining
rows: `WINDOWS-WFP-KILLSWITCH`, `MACOS-SYSEXT-LIFECYCLE` and
`IOS-NE-FAIL-CLOSED`. All three lanes exit 2 without `TWINVPN_SENTINEL_HOST`
rather than crediting a sentinel-less silence.

### Everything else, by criterion

| Criterion | Needs | State |
|---|---|---|
| `ANDROID-16K-PAGE-SIZE` | hosted runner; the four `TWINVPN_RELEASE_*` secrets | **executable** |
| `WINDOWS-WFP-KILLSWITCH` | oracle + sentinel host + Azure L1 runner `twinvpn-azure-l1` + golden VHDX | blocked |
| `MACOS-SYSEXT-LIFECYCLE` | oracle + sentinel host + EC2 Mac runner `twinvpn-ec2-mac` + Apple Team ID | blocked |
| `MACOS-PRODUCTION-SIGNATURE` | EC2 Mac runner + a notarized artifact and its pinned digest | blocked |
| `IOS-NE-FAIL-CLOSED` | oracle + sentinel host + Corellium project + a signed IPA and its pinned digest | blocked |
| `IOS-PROFILE-REMOVAL-HONESTY` | Corellium project + signed IPA | blocked |
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
