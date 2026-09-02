# Remote acceptance infrastructure

Everything the First Implementation Wave gate needs that is not a hosted GitHub
runner. Every requirement below is derived from a step in
`.github/workflows/first-implementation-wave-gate.yml` or from the
`build/ci/ci-*.sh` it invokes; nothing here is general advice.

**The rule this document exists to satisfy:** the gate stays evidence-based, and
**local or user-owned physical hardware is no longer an acceptable dependency**
for it. A blocker that can only be closed by someone with a machine in a room is
a purchasing decision wearing an engineering costume.

**This is the current specification, dated 2026-09-02. It supersedes the
arrangement of 2026-08-30 this file used to describe**, which needed an AWS EC2
Mac, an Azure L1 self-hosted runner, a Corellium virtual iPhone, a standing
sentinel host and a public oracle host. **None of them is required now. Zero
self-hosted runners and zero repository variables are the design, not a gap.**
The only external inputs left are the four Apple Developer Program facts in §4.3
— release-pipeline facts, not infrastructure — and the one job that reads them
skips by name when they are unset. `self-hosted-runners.md` records the
arrangement before that one.

---

## 0. The environment attestation

Every boolean in a platform evidence file describes what the TEST did. **None of
them describes whether the machine was capable of the claim.** A Windows run
whose caller was never elevated, an Android 16 KiB run on a 4096-byte-page
emulator, and a macOS run where activation silently failed all produced
well-formed, green evidence. So each criterion names the `environment` keys that
must be present and must hold, `report.py`'s `PREREQUISITES` carries them, and
they are checked **before any test result is read**;
`test_report_prerequisites.py` is the runnable proof, one case per hole.

---

## 1. The leak oracle — in-box, on the lane's own runner

No criterion that makes an egress claim is adjudicated by the platform under
test: `lab/twinoracle` runs off the device, and the acceptance job fetches its
verdict **from the oracle**, keyed by a session id the evidence recorded. Since
2026-09-02 "off the device" means a different address on the same runner rather
than a different machine. **No cloud instance, no public address, no delegated
DNS zone, no standing sentinel host** — the oracle, the sentinel and two per-leg
DNS forwarders run on the runner driving the device under test, on address space
that runner creates for the run. `lab/twinoracle/README.md` §3 carries both.

### 1.1 Why in-box is stronger here, not weaker

The oracle's code has never contained an address-class restriction: it compares
source addresses for set membership and equality and nothing else, and
`is_dut_sourced` (`lab/twinoracle/src/evidence.rs:295-297`) is the whole
independence check. Independence is therefore **address disjointness**, and a
fabric allocating the device's and the sentinel's addresses out of two segments
with **no NAT anywhere between them** satisfies it by construction rather than
by assertion — what the `ponytail:` comment at `evidence.rs:292-294` already
names as the upgrade path from the old deployment, where a device behind the
sentinel's NAT would still have passed.

It is also the only way the IPv6 leg can be exercised at all: hosted runners
have no usable global IPv6 egress
([actions/runner-images#668](https://github.com/actions/runner-images/issues/668),
opened 2020-04-03; [actions/runner#402](https://github.com/actions/runner/issues/402)),
while `ORACLE_FAMILY_MINIMUM_ATTEMPTS` demands 60 IPv6 attempts from every
oracle-backed criterion. An internal segment carries ULA IPv6 with no uplink.

### 1.2 The topology, and the parts of it that are load-bearing

* **The oracle listens on a second, ROUTED segment**, reached only through the
  device's default route. **It must not be on-link with the device** — see the
  local-network row of §1.3: an on-link oracle would be permitted **correctly**,
  and the SILENCE phase would fail for a reason that is not a leak.
* **The sentinel beats from a second host identity on that segment**, disjoint
  from every address the device presents.
* **A stateless per-leg DNS forwarder replaces the delegated zone** — one per
  leg, each named in the oracle's `--resolver <ip>=<id>:<p|u>` map, with the
  device's `nameserver` rewritten when the tunnel comes up so
  `dns_identity_distinct` stays a measurement. **The forwarders must not retry,
  cache or health-check:** one that retransmits on its own manufactures a DNS
  arrival during SILENCE, which the oracle records as a leak and the report
  turns into a FAIL against the product. This is the most dangerous detail here.
* **The control plane is driven by the controller, never by the device.** A
  correct kill switch blocks the device's control POSTs during ARMED, and
  dropped attempt increments push the session under its 60-attempt floor to
  INCONCLUSIVE — the opposite of the truth.

### 1.3 Four address ranges the oracle and the sentinel must avoid

| Range | Why |
|---|---|
| `169.254.0.0/16` and `fe80::/10` | link-local is permitted on every non-overlay interface at `weight::LINK_LOCAL = 7_500` (`filters.rs:406`, prefixes at `:611`) |
| anything **on-link** with the device | class 4 permits `config.on_link_prefixes` at `weight::LOCAL_NETWORK = 7_000` whenever `local_network_access` is set, its default in all three routing modes (`wfp/mod.rs:576`, `filters.rs:418`) |
| `100.64.0.0/10` | in the Tier-1 baseline deny floor, blocked in **both** postures, so the TUNNELLED leg could never arrive (`wfp/mod.rs:666`) |
| `fd7c:9e5d:2a10::/48` | the IPv6 half of that floor (`wfp/mod.rs:674`) |

### 1.4 What the evidence now carries

Two new flat scalar `environment` keys on every oracle-backed criterion, both
measured, both in `PREREQUISITES`: **`oracle_topology`**, `in-box` or
`external`; and **`sentinel_egress_identity`**, the identity the sentinel
presented, which **must differ from both path identities**.
`sentinel_independence_problems` in `build/acceptance/adjudication.py` refuses
one that is absent, empty, or equal to either path identity — the same shape as
`path_identity_problems`, for the same reason: two equal strings are not two
hosts. `sentinel_host` in the oracle report stays **informational and ungated**,
a self-declared string that `test_report_prerequisites.py` carries a deliberate
tripwire to keep ungated.

`leak-probe.sh cmd_open` now expresses the real invariant instead of a partial
blocklist: it refuses loopback and link-local **on both families** — the old
glob inspected no IPv6 beacon at all, and omitted `172.16.0.0/12` and
`198.18.0.0/15` — refuses any beacon address the probe host owns, and accepts a
non-global target only under `TWINVPN_ORACLE_TOPOLOGY=in-box`, so the in-box
deployment must declare itself.

**This narrows what an oracle-backed criterion claims, and the narrowing is
real.** It proves the device's stack refused to originate the connection and
that a party the device cannot reach on-link observed nothing during SILENCE
while its listeners were provably alive. It no longer proves the public internet
was unreachable — for a kill switch enforced at connect time those are the same
decision point — and a same-host sentinel cannot detect a broken route to the
oracle, there being none to break. Both losses are bounded and named here.

---

## 2. `WINDOWS-WFP-KILLSWITCH` — hosted `windows-2025`, guest built per run

**Runner:** `windows-2025`, GitHub-hosted, as L1. No `twinvpn-azure-l1` label,
no `TWINVPN_AZURE_L1_REGISTERED`, no `TWINVPN_GOLDEN_VHD`.

### 2.1 Why there are still two machines, and why both are the runner

The Windows kill switch installs **persistent** WFP filters, and ADR-0018 CB-6
with ADR-0022 §11.4 require that "shutdown MUST NOT remove enforcement". A
**correct** fail-closed run therefore ends with the machine unable to reach the
network, which on the runner itself severs the runner agent mid-job: the run is
lost and correct product behaviour is indistinguishable from flaky
infrastructure. The L1/L2 split stands; L1 is now the hosted runner and L2 is
built from an ISO.

**The on-runner alternative — exempt the runner agent and test in place — is
ruled out by the product's own filters, not by taste.** Every block TwinVPN
installs is a **hard** block: `FilterFlags` carries exactly two fields,
`persistent` and `boot_time` (`wfp/mod.rs:396`, `:405`), no `clear_action_right`
exists anywhere in the crate, and Microsoft's filter-arbitration rules give a
block with no override right as one whose traffic "cannot be permitted at
another sub-layer". No permit at any sublayer or weight keeps the runner agent
alive — and one that did would grant the CI harness unrestricted egress in the
very window the criterion asserts nothing may leave.

### 2.2 The hypervisor is on the image — measured, not assumed

`Hyper-V` with all sub-features, `Hyper-V-PowerShell`, `HypervisorPlatform` and
`VirtualMachinePlatform` are installed at image-build time on `windows-2025` and
`windows-2022` (`actions/runner-images`, `toolset-2025.json` and
`Install-WindowsFeatures.ps1`, read 2026-09-02), and that script ends with
`bcdedit /set hypervisorschedulertype root`.

Measured on this repository on **2026-09-02**, run **33679011635**, scratch
branch `spike/hosted-hyperv`, on hosted `windows-2025`: the Hyper-V role is live
(`vmms` **Running**, root scheduler); **34.5 GB free** on `C:`, against a
documented 14 GB figure that is stale; a **Generation 2 guest reaches
`Running`**; and an **internal switch carries two IPv4 and two ULA IPv6 host
identities**, which is what §1.2's routed second segment is built from.

**GitHub documents nested virtualization on hosted runners as unsupported and
experimental** — "done at your own risk, we offer no guarantees regarding
stability, performance, or compatibility". So the lane produces **NOT-EXECUTED
with a named reason if the hypervisor fails, never a green row:** a capability
measured on one run is not a supported platform, and the difference belongs in
the evidence. Do not create an **external** VM switch either — Azure does not do
Layer 2, so a switch bound to the runner's NIC leaves the guest with no DHCP.

### 2.3 The guest image is built per run, and the binaries are copied in

The golden VHDX existed only because the guest had to build the product. It no
longer does, so the guest collapses to a stock Windows with one local
administrator, which an evaluation ISO gives directly: Windows 11 Enterprise
LTSC 2024 evaluation media, **SHA-256 pinned** — a device under test fetched
over a plain CDN URL with no digest check is whatever the network handed back —
LTSC so the guest's behaviour does not move under the criterion. `install.wim`
is applied straight into a Generation 2 VHDX with DISM and `bcdboot`, skipping
Windows Setup; `unattend.xml` goes into `\Windows\Panther\` and does three
things — one local administrator, skip OOBE, skip the network-location prompt —
all PowerShell Direct requires. **The licence question is flagged, not
answered:** Microsoft's Evaluation Center gates these images behind a
registration form and the direct CDN URLs bypass it, and whether that is within
the licence in automation is a legal question this document does not close. The
term itself is not the issue — the media expires in 180 days and wants
activation within 10, and a guest destroyed within the hour reaches neither.

`twinvpnsvc.exe`, `twinvpnctl.exe` and the `wfp_preconditions` test binary are
built on the runner, which already carries Rust and MSVC, and copied in with
PortableGit and the Python embeddable zip, since `leak-probe.sh` calls `python3`
in three places. **The digest is taken on the host at build time and re-taken
inside the guest after the copy, and a mismatch is refused** — stronger than the
in-guest digest it replaces, which could only attest to what the guest already
had. Evidence returns over `Copy-Item -FromSession` on a `New-PSSession -VMName`
session, a VMBus channel that survives the guest cutting its own network
(`Copy-VMFile` is host-to-guest only). `guest_kind` stays `nested-hyperv-guest`
and `guest_disposable` true, so `report.py` needs no edit; the guest is
destroyed in a `finally` on every path.

**The lane runs to the `net up` refusal and stops there.** See §6.

---

## 3. `ANDROID-16K-PAGE-SIZE` — an ordinary hosted runner

**No machine at all**, and this row PASSES (`ownership.md` §12.5).
`build/ci/ci-android.sh --pagesize16k` **discovers** Google's official 16 KB
page-size emulator image rather than hard-coding a package id, **refuses to
continue** unless `adb shell getconf PAGE_SIZE` returns exactly `16384` before
the APK is pushed, runs `zipalign -c -P 16 -v 4` on the **release** APK, and
installs the **production** APK, because C-12's claim is about the `.so` inside
the shipped one. Signing needs the four `TWINVPN_RELEASE_*` secrets, and the
release config has **no silent fallback to the debug keystore** — that would
make the evidence say `release` while the disk said otherwise.

---

## 4. The macOS rows — hosted `macos-26`, and one premise that was wrong

**Runner:** `macos-26`, GitHub-hosted. No `twinvpn-ec2-mac` label, no
`TWINVPN_EC2_MAC_REGISTERED`. `MACOS-SYSEXT-LIFECYCLE` runs in developer mode,
which accepts an extension a customer's Mac would refuse — an ad-hoc signature,
an expired certificate, a missing notarization ticket, an unstapled bundle — so
it stays a separate criterion, script, evidence file and row from
`MACOS-PRODUCTION-SIGNATURE`: while they shared one file, **a green
developer-mode lifecycle read as "the signed, notarized product works"**.

### 4.1 The SIP premise was wrong

`ci-macos-sysext.sh` and the workflow both said hosted runners cannot carry this
row because developer mode needs SIP configured and no hosted Mac reaches
Recovery. **Hosted macOS images ship with SIP already disabled.** Public run
33476534302, job 99756861345, **2026-09-01**, image `macos-26-arm64`
20260728.0273.1, macOS 26.5.2 build 25F84: `csrutil status` prints "System
Integrity Protection status: disabled", so that pre-flight would pass there
today. **SIP was never the blocker**, and the EC2 Mac's SIP-configuration API —
the entire reason the row had a cloud path — bought nothing hosted lacks.

What SIP and developer mode buy is also narrower than assumed: Apple documents
developer mode as skipping the **location** check ("the system doesn't check the
location of your system extension prior to loading it") and version checks, and
SIP-disabled as bypassing **notarization** checks. Neither is documented as
bypassing user approval, so **whether SIP-disabled also bypasses the
system-extension approval is unverified in either direction.** SIP state is also
not job-controllable and has drifted before (`runner-images` #9091), so no
lane's green may depend on it.

### 4.2 What actually blocks `MACOS-SYSEXT-LIFECYCLE`

Three things, none of which a machine purchase fixes. **Two GUI approvals only
MDM can bypass:** the system-extension toggle in System Settings under Login
Items and Extensions, whose only supported non-interactive route is a
`com.apple.system-extension-policy` payload from a user-approved MDM server; and
the separate VPN-configuration consent dialog `saveToPreferences` raises, for
which Apple DTS (Developer Forums thread 823741, April 2026) named no
suppressing API, entitlement or MDM key. **The entitlement has never been
granted:**
`shells/macos/packaging/TwinVPNTunnel.entitlements` requests
`packet-tunnel-provider-systemextension`, and its own header says Apple has not
granted it — "Until they do, this file describes a build that cannot be signed."
**And there is no non-NetworkExtension tunnel path:**
`core/crates/twinvpn-platform-macos/src/utun.rs:436` returns `ENOSYS` for a
self-created utun, with `tests/darwin.rs` asserting that refusal by name. Nested
virtualization would not help either: it is unavailable on Apple-silicon hosted
runners, and `runner-images` #13505 was opened and closed **not planned on
2026-01-08** — "unavailable due to reasons beyond our control".

**The row therefore has no executor and stays `required=True`.** Two options are
open and this document records both rather than choosing: **(a)** keep it
required, where it reads NOT-EXECUTED and blocks Phase 5, the truthful state; or
**(b)** mark it `required=False` in the shape of `IOS-SUPERVISED-ALWAYS-ON`,
because it tests a capability Apple has not granted this team. **That is a
policy decision for the wave owner**, and either way it belongs in the register
as a deliberate scope reduction rather than slipped in.

Two defects in that lane were fixed while reading it, both of which would have
mattered on any host. It checked enforcement by grepping `pfctl -s Anchors` for
`twinvpn`, which an anchor loaded but never referenced from the main ruleset
passes — so it could report installed enforcement over a host with pf switched
off. And `systemextensionsctl_state`, `developer_mode` and `runner_kind` were
literals rather than the values that were read.

### 4.3 `MACOS-PRODUCTION-SIGNATURE` moves to `macos-26` with no honesty loss

It is pure artifact inspection. `codesign`, `spctl`, `stapler` and
`codesign --check-notarization` all work on the hosted image, Gatekeeper
assessments are enabled there ("assessments enabled", same 2026-09-01 log), and
none of the criterion's `environment` keys describes the machine — an ephemeral
runner is in fact a **better** host for it than a long-lived EC2 Mac sharing a
disk with the job that activates a developer-mode extension. `sip_config` and
`gatekeeper_assessments` are recorded as facts about the host, not
prerequisites: the subject is the artifact. The one row with external inputs,
and they are Apple Developer Program facts:

| Name | Kind | Value |
|---|---|---|
| `TWINVPN_TEAM_ID` | variable | the Apple Developer Team ID |
| `TWINVPN_NOTARIZED_APP_URL` | variable | where the release pipeline publishes the signed, notarized, stapled `TwinVPN.zip` |
| `TWINVPN_NOTARIZED_APP_SHA256` | variable | the pinned digest, verified after download, no fallback |
| `TWINVPN_NOTARIZED_APP_TOKEN` | secret | optional bearer for that URL |

**The job skips by name when `TWINVPN_NOTARIZED_APP_URL` is unset**, and the row
then reads NOT-EXECUTED. It fetches the notarized product and never a CI build:
one produced on the runner would be signed by whatever identity that machine
holds and notarized by nobody, so checking its signature would tell us about the
runner rather than about the product.

### 4.4 `MACOS-PF-BOOT-ANCHOR` — new, required, hosted, root

The part of the old macOS row a hosted runner can honestly carry, and it closes
`shells/macos/README.md` §7 gap 2: **Apple's own pf has never parsed the anchor
this adapter renders.** Root pf on a hosted runner is proven by third-party CI
(`mullvad/pfctl-rs`, run 18098602553, 2025-09-29). On `macos-26` with
passwordless sudo, no oracle, no sentinel, no Team ID and no Apple entitlement,
the lane runs `shells/macos/packaging/install.sh` — the only thing that
validates the rendered anchor with `pfctl -n -f`, splices `/etc/pf.conf` and
runs `pfctl -E` — then `ksd --apply-boot-anchor` and `ksd --status`, and proves:
pf is **enabled**; the `anchor "twinvpn"` reference is present **in the main
ruleset** (the exact form: the wildcard `anchor "twinvpn/*"` the package used
to write evaluates only child anchors and never the anchor's own rules, so
the boot anchor was inert on every Mac until 2026-09-02 — G-35); the anchor's
`twinvpn.deny.*` labels show **evaluations and packets both rising** across a
covered connect; the anchor's rules and its
posture, generation and per-family scope tables are non-empty; a connect into a
covered prefix is **refused** while a control connect **succeeds**. It also runs
the existing `TwinVPNBridgeTests` target as root, driving `tvb_ext_start`
through `privilege_posture`, `capability_probe` and `enforcement_reclaim` — the
first native root execution of that start sequence and its first W-24 read-back
from the kernel. Evidence file `macos-pf-anchor.json`, digest key `twinvpn-ksd`.

**It is deliberately not in `ORACLE_REQUIRED`:** its claim is about a ruleset the
machine loaded, not a packet that left, and the boot anchor denies only
`100.64.0.0/10` and `fd7c:9e5d:2a10::/48` — space no oracle ever sees — so
adding it there would silently require path-identity keys it cannot honestly
produce. **It also stops at the anchor read-back and never reaches `net.up`:**
`enforcement_reclaim` is the session-independent boot-time reclaim, while arming
over a real contract is `net.up`, which refuses for the reasons in §6. Do not
let anyone describe this row as the second thing.

---

## 5. The iOS rows — hosted simulator, and one device-only residual

**No Corellium instance, no device farm, no runner label.** Two rows run in the
iOS Simulator on `macos-26`; the residual device row has no executor.

### 5.1 What the simulator can and cannot do, and why the split is honest

**A packet-tunnel provider cannot run in the simulator.** Apple DTS (Developer
Forums thread 101663, August 2022): the simulator "uses the macOS kernel for its
networking, which makes it infeasible to run iOS network extension providers …
Unless this architecture changes, you will not be able to test iOS NE providers
in the simulator." Rechecked against Xcode 26 through 26.6; nothing revises it.
But `NetworkExtension.framework` is in the simulator SDK, so every
`NETunnelProviderProtocol`, `NETunnelProviderManager` and
`NEOnDemandRuleConnect` is a plain object that can be built and read with no
daemon involved. **Only activation is impossible.**

Apple documents the enforcement itself, in "Route additional traffic through a
personal VPN or packet tunnel provider": "**When the VPN transitions away from
the connected state, the system drops network traffic.**" That promise is scoped
to a configuration that exists and is enabled, which `includeAllNetworks`
selects. So fail-closed after the provider dies is **Apple's** obligation, and
installing the configuration that earns it is **TwinVPN's** — the half a
simulator discharges completely.

### 5.2 `IOS-FAILCLOSED-CONFIGURATION` — new, required, simulator

A simulator XCTest asserting the exact `NETunnelProviderProtocol` and on-demand
rules field by field against the decoded enforcement programme:
`providerBundleIdentifier`, `includeAllNetworks`, `excludeLocalNetworks`,
`isOnDemandEnabled`, `isEnabled`, and every on-demand rule being an
`NEOnDemandRuleConnect`. **The app half (`VPNPermission.install`) and the
extension half (`BridgeHost.applyEnforcement`) must agree on all of it** — drift
between them is the defect `EnforcementProgramme`'s single-declaration argument
exists to prevent, and nothing tested it. Evidence
`ios-failclosed-configuration.json`, digest key `TwinVPN.app/TwinVPN`.

### 5.3 `IOS-PROFILE-REMOVAL-HONESTY` — redefined as simulator logic

The five honesty conditions — TwinVPN reports NOT PROTECTED, a green shield is
**impossible**, the connected state is cleared, the user receives an actionable
protection-lost state, and TwinVPN makes **no continued kill-switch claim**
(`blocked` is as wrong as `protected`, both asserting TwinVPN still decides what
leaves) — are app-side logic, now driven from an **injected "no configuration"
observation** rather than from a real removal.

**The repository's premise that no API removes the app's own profile was
wrong.** `NEVPNManager.removeFromPreferences(completionHandler:)` has existed
since iOS 8 and `NETunnelProviderManager` inherits it, so the removal *event* is
reproducible in code on any provisioned device. The residual device-only claim
is the user's Settings journey, which no assertion here depends on. The row
carries no leak-oracle session and needs none: removing the configuration
*revokes* TwinVPN's authority to intercept traffic, so egress afterwards is
expected, and a silence phase over that window would test a promise the product
does not make.

### 5.4 `IOS-NE-FAIL-CLOSED` — the device-only residual, no executor

What is left after the split is the real Network Extension being invoked, the
tunnel coming up through `NEPacketTunnelFlow`, five provider disappearances
injected by five mechanisms, and an oracle observing zero egress after each. The
invariant is **not** "Jetsam kills the provider": a crash, a network transition
and the user disabling the VPN produce the same security-relevant condition —
the provider is gone and TwinVPN's authority is not.

Corellium cannot discharge it, and that is a finding rather than a delay: **it
cannot perform three of the five injections** — `app/crash`, `network/disable`
and `vpn/disable` appear in no Corellium surface, its only crash API being a
listener that waits for a report the OS produces on its own — and **whether a
`NEPacketTunnelProvider` runs on a Corellium virtual iPhone at all was never
verified.** The row stays `required=True` with no executor and carries §4.2's
policy question. **Recorded, not chosen.**

### 5.5 A simulator row can never satisfy a device row

`PREREQUISITES` pins the two simulator rows to `execution: "simulator"`,
`real_network_extension_invoked: false`, `os_enforcement_exercised: false`,
`device_kind: "ios-simulator"` and `test_count` greater than zero, while the
device row pins `real_network_extension_invoked` to `true`. The two files are
mechanically unusable as each other's evidence, the protection `product_mode`
already gives the consumer and supervised rows. A simulator row discharges
neither iPhone nor iPad device coverage (ADR-0018 §11.9). `test_count > 0` is
not decoration: a filter that matches nothing exits zero, so the count is read
from the `.xcresult` bundle rather than inferred.

**Two local blockers were fixed to make any of this compile:** six harness types
the device suite names (`DeviceCapabilities`, `ProviderHarness`,
`DiagnosticsHarness`, `CaptureHarness`, `NetworkHarness`, `TrafficGenerator`)
existed nowhere in the tree in any language, and `VPNPermission` had no seam —
it built the configuration and handed it to the OS in one unbroken private
sequence, so no test could observe what it built. `IOS-SUPERVISED-ALWAYS-ON` is
otherwise untouched: `required=False`, its evidence pinned to
`product_mode: supervised` against the consumer file's `product_mode: consumer`.

---

## 6. What blocks the egress rows now

**The three egress rows cannot PASS on any infrastructure today, and the blocker
is inside the product rather than in CI.** `twinvpnctl net up` refuses at
`core/crates/twinvpn-core/src/enforce.rs:185` with `AUTH.IDENTITY_MISSING` and
calls `block()` on the way out, so the host ends up blocked **before any tunnel
exists** and, under `set -euo pipefail`, a lane dies at the `net up` line before
its TUNNELLED phase is declared. The failure is in the safe direction — BLOCKED,
not open — but it is a failure, and no runner topology changes it. Four product
walls, each load-bearing; removing any one alone changes nothing:

| # | Wall | Where |
|---|---|---|
| 1 | **No overlay allocation.** `enforce::arm` refuses unless `DataPlaneView::local_overlay()` returns a value. The only writer, `ControlPlanePort::put_local_overlay`, has **no production caller** — the sole callers are tests. | `enforce.rs:185`, `planes.rs:474`, `tests/data_plane_composed.rs:87` |
| 2 | **No verified peer.** `AUTH.PEER_UNTRUSTED` unless some peer carries `tunnel_key_binding_verified`. The one production writer is the control-plane client, and **no shell binds the control transport**. The pairing route is closed too: `pair.confirm` is NotWired because ADR-0007 leaves `transcript_hash` with no defined preimage — a specification defect, not missing wiring. | `enforce.rs:197`, `cp_binding/store.rs:198`, `dispatch.rs:194`, `pairing/mod.rs:137-165` |
| 3 | **No default route.** `RoutingMode::TwinnetOnly` is hard-coded with `selected_exit_node: None` and no exit grant, and that mode adds no candidates beyond the TwinNet host routes, so a beacon aimed at the oracle never enters the tunnel whatever peer exists. `exitnode.select` is refused, so no operator can change it over the shipped interface. | `enforce.rs:236-254`, `twinvpn-route/src/program.rs:263`, `dispatch.rs:226` |
| 4 | **No protected resolver.** DNS is programmed **OFF** with no upstream servers, `block_fallback` set in both families, and empty stub addresses. `twinvpn-dns` opens no socket and binds no listener, and nothing in `core/` or `shells/` listens on port 53 — the four Windows stub addresses are handed to the adapter for a stub that does not exist. | `enforce.rs:263`, `:525-548`, `:279`, `twinvpn-dns/src/lib.rs:27-32` |

And one wall outside the device: **no forwarding gateway exists anywhere.**
`twinsim peer` is a relay peer that "runs no L-DATA tunnel, holds no device
identity, completes no pairing ceremony and speaks to no control plane"; a relay
forwards between two peers on a `pair_tag` and is not an internet egress; and
`twinvpn-gateway` decides admission, policy and quota and **never forwards**.

So the hosted Windows lane **runs to the `net up` refusal and records it as an
executed FAIL with `blocked_on` naming the wall**, in the style the iOS lane
already uses for injections it cannot perform — worth more than a NOT-EXECUTED,
because it is a measurement of a named thing. **Do not close these rows by
weakening the oracle:** `path_identity_problems` compares two strings for
inequality and cannot tell a measurement from a pair of differing literals, so
constants, relaxed checks or a beacon on an address the device owns would each
turn a real blocker into a green row that measures nothing.

---

## 7. Common to every lane

**No self-hosted runner and no runner group** — every lane runs on a hosted,
ephemeral runner, so the fork guard on a registered machine goes with it; Rust
**1.90.0** via rustup; **no production credential of any kind**, the Android
job's signing material being a CI keystore and the notarized macOS product
*fetched*, never produced here; and every job cleans up on `if: always()`, with
the in-box fabric dying with the runner that created it.

---

## 8. The one rule of the 2026-08-30 pass that is retired

That pass added the sentinel-continuity arithmetic, the self-reported attempt
floor, resolver-derived DNS identity, path-identity distinctness, run-and-digest
binding, and the two-mechanism final gate in which **a lane unable to execute is
RED, not green-by-absence**. All still hold; the narrative is in `ownership.md`
§12.4 and the operative statements in `lab/twinoracle/README.md`.

**Retired: "no lane can host its own sentinel, so the sentinel must be a
standing process on a separate machine", and the standing host with it.** It
rested on the premise that a lane's own host NATs through the device's address —
true of a default Hyper-V switch, false of §1.2's routed second segment. The
rule is now §1.2 and §1.4's in-box rule.

---

## 9. What is left

No infrastructure. The gate needs a hosted runner and nothing else, plus the
four Apple facts in §4.3 for the one row that skips by name without them. What
remains is **product work and one policy decision**: the four walls in §6, and
whether `MACOS-SYSEXT-LIFECYCLE` and `IOS-NE-FAIL-CLOSED` stay required and
NOT-EXECUTED or are deferred (§4.2, §5.4). The per-row checklist is
`remote-acceptance-provisioning.md`.
