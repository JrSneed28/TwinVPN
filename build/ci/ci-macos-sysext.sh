#!/usr/bin/env bash
#
# ci-macos-sysext.sh — `MACOS-SYSEXT-LIFECYCLE`.
#
# ===========================================================================
# WHAT THIS CRITERION IS, AND WHAT IT IS DELIBERATELY NOT
# ===========================================================================
# It is: TwinVPN.app installed, the REAL system/network extension activated,
# the activation confirmed by `systemextensionsctl`, the production extension
# invoked, enforcement exercised, tunnel failure injected, and an EXTERNAL
# oracle observing zero unauthorized IPv4, IPv6 or DNS egress while enforcement
# is expected to hold.
#
# It is NOT a statement about production signing. This runs in DEVELOPER MODE
# (`systemextensionsctl developer on`), which is the only way a non-App-Store
# extension activates on a machine you can automate — and developer mode
# accepts an extension that would be rejected on a customer's Mac. An earlier
# arrangement had ONE macOS evidence file and therefore one row, so a green
# developer-mode lifecycle read as "the signed, notarized product works".
#
# `MACOS-PRODUCTION-SIGNATURE` is that other claim and lives in
# `build/ci/ci-macos-signature.sh`, with its own criterion, its own evidence
# file and its own row. Two files rather than one flag: a flag can be forgotten,
# and the conflation this splits was worth more than the duplication.
#
# ===========================================================================
# WHY THIS LANE CANNOT RUN ANYWHERE TODAY, AND WHY SIP IS NOT THE REASON
# ===========================================================================
# THE OLD PREMISE, CORRECTED. This header used to say that hosted macOS runners
# cannot do this because `systemextensionsctl developer on` needs SIP
# configured and no hosted Mac reaches Recovery. That is wrong on its own
# terms: **GitHub's hosted macOS images already ship with SIP DISABLED** —
# `actions/runner-images` #8162 recorded macos-13 as the first, and a public
# `macos-26-arm64` run on 2026-09-01 prints "System Integrity Protection
# status: disabled". The pre-flight below would pass on `macos-26` today.
#
# So SIP was never the blocker. Three others are, each sufficient on its own,
# on ANY Mac, hosted or owned:
#
#   1. TWO GUI APPROVALS. The System Settings toggle under General > Login
#      Items & Extensions > Network Extensions, and then the VPN configuration
#      consent dialog `NETunnelProviderManager.saveToPreferences` raises. Apple
#      documents developer mode as relaxing the extension's LOCATION check and
#      SIP-disabled as relaxing the NOTARIZATION check; neither is documented
#      as relaxing APPROVAL, and the only supported non-interactive route is an
#      MDM `com.apple.system-extension-policy` payload. `security
#      authorizationdb write <right> allow` — the one scripted route to the
#      admin authentication behind the toggle — fails with -60005 on macos-15
#      and later (`runner-images` #11893).
#   2. THE ENTITLEMENT IS NOT GRANTED. `packaging/TwinVPNTunnel.entitlements`
#      requests `packet-tunnel-provider-systemextension` and its own header
#      says Apple has not granted it. There is no build to activate.
#   3. THERE IS NO NON-NETWORKEXTENSION TUNNEL PATH.
#      `core/crates/twinvpn-platform-macos/src/utun.rs:436` returns `ENOSYS`.
#
# None is an infrastructure problem and none is bought with a Mac. The lane
# reads NOT-EXECUTED, which is the truthful state; its job is to be CORRECT
# WHEN IT RUNS rather than to be runnable.
#
# The part a hosted runner CAN carry is a different criterion:
# `build/ci/ci-macos-pf-anchor.sh` (`MACOS-PF-BOOT-ANCHOR`) installs the KS-19
# boot artifact and lets Apple's own pf evaluate it as root on `macos-26`, with
# no oracle, no sentinel, no Team ID and no approval. Separate criterion,
# separate evidence file: folding it in here would be the conflation the August
# 2026 split of the macOS row exists to prevent.
#
# The pre-flight below still asserts `csrutil status` — a fully enabled SIP
# does refuse developer mode, and failing there is cheaper than failing inside
# activation. It is necessary and nowhere near sufficient.
#
# ===========================================================================
# WHY THE EGRESS CLAIM IS NOT MADE HERE
# ===========================================================================
# Nothing below asks TwinVPN, or macOS, whether traffic is blocked. `pfctl -sr`
# says what rules exist, not what left the machine, and a NetworkExtension that
# died still reports a configuration. The observation is made by
# `lab/twinoracle`, off this machine; this script drives the phases and
# `build/acceptance/report.py` fetches the verdict from the oracle.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
SHELL_DIR="$REPO/shells/macos"
LOGDIR="$REPO/build/ci/logs/macos"
EVIDENCE="$REPO/build/ci/evidence/macos-sysext.json"
PROBE="$REPO/build/ci/leak-probe.sh"
CRITERION="MACOS-SYSEXT-LIFECYCLE"
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-60}"
mkdir -p "$LOGDIR" "$(dirname "$EVIDENCE")"

[ "$(uname -s)" = "Darwin" ] || {
  echo "::error::ci-macos-sysext.sh must run on macOS" >&2; exit 2; }

# shellcheck disable=SC1091
source "$REPO/build/ci/ci-common-apple.sh"

# --------------------------------------------------------------------------
# --cleanup: step "deactivate/clean the extension", on EVERY exit path
# --------------------------------------------------------------------------
#
# `ci-macos.sh --cleanup` returns the NETWORK state and says, correctly, that it
# cannot remove an activated system extension. In developer mode this one can:
# `systemextensionsctl uninstall <teamID> <bundleID>` is accepted only with
# developer mode on, which is exactly the mode this criterion runs in. Deleting
# the containing app is the second half — macOS treats the app bundle's absence
# as the extension's uninstall trigger, and leaving one behind means the next
# run activates over a stale copy.
#
# Never fails: it runs under `if: always()` and a teardown that fails the job
# hides the failure it was cleaning up after.
if [ "${1:-}" = "--cleanup" ]; then
  echo "=== cleanup: deactivate the extension and return the Mac ==="
  team_id="${TWINVPN_TEAM_ID:-}"
  ext_bundle_id="${TWINVPN_EXTENSION_BUNDLE_ID:-com.twinvpn.app.sysext}"
  systemextensionsctl list 2>&1 || true
  if [ -n "$team_id" ]; then
    sudo -n systemextensionsctl uninstall "$team_id" "$ext_bundle_id" 2>&1 \
      || echo "(uninstall refused or the extension was not installed)"
  else
    echo "(TWINVPN_TEAM_ID unset; systemextensionsctl uninstall needs it)"
  fi
  sudo -n rm -rf /Applications/TwinVPN.app 2>&1 || true
  "$REPO/build/ci/ci-macos.sh" --cleanup || true
  systemextensionsctl list 2>&1 || true
  exit 0
fi

# --------------------------------------------------------------------------
# 0. the environment attestation, before anything is built
# --------------------------------------------------------------------------
echo "::group::environment attestation"
macos_version="$(sw_vers -productVersion)"
sip_config="$(csrutil status 2>&1 | tr -d '\n' | tr -s ' ')"
echo "macOS: $macos_version"
echo "SIP:   $sip_config"

# PRIVILEGE AND FLEET, MEASURED. Both were constants in the heredoc below —
# `privileged: true` and `runner_kind: "self-hosted"` — the same class of defect
# as `systemextensionsctl_state`: always present, always plausible, never read
# from anything. `sudo -n id -u` is the question this lane depends on, since it
# installs to /Applications, turns developer mode on and reads pf that way.
# `RUNNER_ENVIRONMENT` is GitHub's own answer and its vocabulary is exactly the
# schema's; the floor is only reached off Actions, where nothing sets it.
sudo_uid="$(sudo -n id -u 2>/dev/null || true)"
privileged=false
if [ "$sudo_uid" = "0" ]; then privileged=true; fi
runner_kind="${TWINVPN_RUNNER_KIND:-${RUNNER_ENVIRONMENT:-self-hosted}}"
echo "privileged (sudo -n id -u): $privileged"
echo "runner kind:                $runner_kind"

# `csrutil status` on a fully enabled system prints "System Integrity
# Protection status: enabled." — and with that, `systemextensionsctl developer
# on` is refused and the activation below cannot happen. Fail HERE rather than
# 20 minutes later inside xcodebuild.
#
# NECESSARY, NOT SUFFICIENT, and the header says why at length: a hosted
# `macos-26` image passes this check today and still cannot activate an
# extension, because the approvals and the entitlement are what bind. A reader
# who takes a green pre-flight as "the lane can run here" has read it backwards.
case "$sip_config" in
  *"status: enabled."*)
    echo "::error::SIP is fully enabled, so systemextensionsctl developer mode is \
unavailable and no extension can be activated on this host. This is the FIRST \
of this lane's obstacles and not the largest: the two GUI approvals and the \
ungranted packet-tunnel-provider-systemextension entitlement remain after it is \
cleared. See this script's header." >&2
    exit 1 ;;
esac

team_id="${TWINVPN_TEAM_ID:-}"
# THE DEFAULT MUST BE WHAT THIS REPOSITORY ACTUALLY BUILDS, and it was not.
#
# It read `net.twinvpn.client.tunnel`, which is the iOS naming and is not a
# target in `shells/macos/project.yml` at all -- that file builds
# `com.twinvpn.app.sysext`, prefixed by the containing app's
# `com.twinvpn.app` because macOS requires a system extension's identifier to
# be prefixed by its host's. The default is not decoration: the workflow passes
# `vars.TWINVPN_EXTENSION_BUNDLE_ID` unconditionally and that variable is unset
# in this repository, so an empty string arrives here and `:-` takes over. A run
# would have hunted for an extension nobody ever built, and `--cleanup` would
# have asked `systemextensionsctl` to uninstall a bundle id that does not exist.
ext_bundle_id="${TWINVPN_EXTENSION_BUNDLE_ID:-com.twinvpn.app.sysext}"
if [ -z "$team_id" ]; then
  echo "::error::TWINVPN_TEAM_ID is unset. The Team ID is part of the extension's \
identity and of this criterion's evidence; a run that cannot name it cannot say \
WHICH extension activated." >&2
  exit 2
fi
for var in TWINVPN_ORACLE_URL TWINVPN_ORACLE_TOKEN; do
  if [ -z "${!var:-}" ]; then
    echo "::error::$var is unset. This criterion's egress claim is adjudicated by \
the external leak oracle; without one the run can only be INCONCLUSIVE, and zero \
observations would be indistinguishable from a working enforcement path." >&2
    exit 2
  fi
done

# WHERE THE ORACLE STANDS, and WHOSE ADDRESS THE HEARTBEAT ARRIVES FROM. Two
# facts the adjudicator requires of every oracle-backed criterion, and neither
# is derivable from the oracle's own report.
#
# `oracle_topology` separates an oracle the device can only reach by emitting a
# packet that LEFT it from one on the same host, bridge or NAT — where a
# SILENCE phase is a statement about a network segment rather than about
# egress. `external` is this lane's design and the default.
#
# `sentinel_egress_identity` is the heartbeat's source address as the oracle
# sees it. Refused when unset rather than defaulted: the oracle discards any
# beat whose source the device was also seen egressing from, so an undeclared
# sentinel cannot be checked for independence at all. `TWINVPN_SENTINEL_HOST`
# names the machine; this names the address, and on a NAT they differ.
oracle_topology="${TWINVPN_ORACLE_TOPOLOGY:-external}"
sentinel_egress_identity="${TWINVPN_SENTINEL_EGRESS_IDENTITY:-}"
if [ -z "$sentinel_egress_identity" ]; then
  echo "::error::TWINVPN_SENTINEL_EGRESS_IDENTITY is unset. The oracle credits a \
SILENCE phase only when an INDEPENDENT heartbeat proves it was still listening, \
and independence is decided by comparing the sentinel's egress source address \
against the device's. A run that cannot name that address cannot have its \
heartbeat checked for independence, so its silence is unattributable. Set it to \
the public source address the sentinel's beats arrive from." >&2
  exit 2
fi

apple_toolchain_banner macosx
echo "::endgroup::"

# --------------------------------------------------------------------------
# 1. build and install the real app + extension
# --------------------------------------------------------------------------
echo "::group::build TwinVPN.app and its system extension"
"$SHELL_DIR/Scripts/build-bridge.sh" --profile release
( cd "$SHELL_DIR" && xcodegen generate )
# SIGNED, unlike the hosted lane. An unsigned extension cannot be activated at
# all — not even in developer mode — because `OSSystemExtensionManager` requires
# a signature whose Team ID matches the containing app's.
xcodebuild build \
  -project "$SHELL_DIR/TwinVPN.xcodeproj" \
  -scheme TwinVPN \
  -destination 'platform=macOS' \
  -derivedDataPath "$LOGDIR/DerivedData" \
  DEVELOPMENT_TEAM="$team_id" \
  CODE_SIGN_STYLE=Automatic \
  2>&1 | tee "$LOGDIR/sysext-build.log"
echo "::endgroup::"

APP="$LOGDIR/DerivedData/Build/Products/Debug/TwinVPN.app"
[ -d "$APP" ] || APP="$LOGDIR/DerivedData/Build/Products/Release/TwinVPN.app"
[ -d "$APP" ] || { echo "::error::no TwinVPN.app was produced" >&2; exit 1; }

echo "::group::install TwinVPN.app"
# `/Applications` and nowhere else. `OSSystemExtensionManager` refuses to
# activate an extension inside an app that is not in /Applications — an
# undocumented-looking refusal that is actually documented behaviour, and one
# that costs an hour if the app is left in DerivedData.
sudo rm -rf /Applications/TwinVPN.app
sudo cp -R "$APP" /Applications/TwinVPN.app
echo "::endgroup::"


# --------------------------------------------------------------------------
# 2. activate the REAL extension, and confirm with systemextensionsctl
# --------------------------------------------------------------------------
echo "::group::activate the system extension"
# DEVELOPER MODE, AND THE EVIDENCE RECORDS WHAT THIS COMMAND ANSWERED.
#
# `developer_mode` was the literal `true` in the heredoc below. It is now the
# exit status of the command that turns it on, captured rather than assumed:
# `systemextensionsctl developer on` is refused on a host where SIP forbids it,
# and a lane that wrote `true` regardless would be describing a mode it never
# entered. The output goes to a log so the value has a printed answer behind it.
developer_rc=0
# SC2024 is correct and is what is wanted: the redirect is performed by THIS
# shell, into a log directory this unprivileged user owns, so the file does not
# end up root-owned for the upload step. Only the command needs privilege.
# shellcheck disable=SC2024
sudo systemextensionsctl developer on > "$LOGDIR/sysext-developer.log" 2>&1 \
  || developer_rc=$?
cat "$LOGDIR/sysext-developer.log"
developer_mode=false
if [ "$developer_rc" -eq 0 ]; then developer_mode=true; fi
echo "developer mode enabled: $developer_mode (exit $developer_rc)"
# The app's own activation request. NOT `systemextensionsctl install`, which
# does not exist: activation is `OSSystemExtensionRequest.activationRequest`,
# issued by the container app, and driving it through the app is what makes this
# the production path rather than a test harness's.
sudo -u "$(stat -f '%Su' /dev/console)" \
  open -a /Applications/TwinVPN.app --args --activate-extension
echo "::endgroup::"

sysext_state=""
for _ in $(seq 1 60); do
  sysext_state="$(systemextensionsctl list 2>/dev/null \
    | tr -d '\r' | awk -v id="$ext_bundle_id" '$0 ~ id { print; exit }')"
  case "$sysext_state" in *"activated enabled"*) break ;; esac
  sleep 5
done
systemextensionsctl list > "$LOGDIR/sysext-list.txt" 2>&1 || true
echo "systemextensionsctl: $sysext_state"

# THE STATE THE EVIDENCE CARRIES IS THE STATE THAT WAS READ.
#
# The heredoc below wrote the literal `"activated enabled"`. The case that
# follows meant it was not a lie — but the value in the file came from nowhere,
# and a guard that is later relaxed leaves a constant nobody notices has
# stopped being checked.
#
# `systemextensionsctl list` prints one TAB-separated row per extension ending
# in a bracketed state (`… TwinVPN [activated enabled]`). The bracketed token
# is extracted because that is the field, and because a raw tab is not legal
# inside a JSON string — the whole row would produce a file no parser accepts.
# A row with no brackets is recorded with its tabs folded, which is a truthful
# "this is what it said" and fails the prerequisite.
sysext_state_measured="$(printf '%s' "$sysext_state" \
  | sed -n 's/.*\[\([^]]*\)\].*/\1/p')"
if [ -z "$sysext_state_measured" ]; then
  sysext_state_measured="$(printf '%s' "$sysext_state" | tr '\t' ' ' | tr -s ' ')"
fi
echo "state, as recorded: ${sysext_state_measured:-<the extension is not listed>}"

case "$sysext_state" in
  *"activated enabled"*) : ;;
  *)
    echo "::error::$ext_bundle_id did not reach 'activated enabled'. \
systemextensionsctl said: ${sysext_state:-<the extension is not listed at all>}. \
Nothing below would be evidence about a running extension." >&2
    exit 1 ;;
esac

# --------------------------------------------------------------------------
# 2b. WHICH BYTES WERE ACTIVATED -- BOTH HALVES OF THE PAIRING
# --------------------------------------------------------------------------
#
# TWO DIGESTS, AND THE SECOND ONE IS THE POINT.
#
# The app and the extension are separately built and separately signed, and
# `OSSystemExtensionManager` will happily activate an extension built from a
# different tree than the app containing it -- a stale
# `.systemextension` left in a DerivedData tree, a partially-failed
# `sudo cp -R`, a rebuild that touched only one target. A digest of the app
# executable alone therefore leaves this criterion's whole subject, the
# LIFECYCLE OF THE EXTENSION, belonging to a pairing nobody assembled.
#
# Both are taken from the INSTALLED location and AFTER activation, never from
# DerivedData: what `systemextensionsctl` just reported `activated enabled` is
# the staged copy under /Library/SystemExtensions, and that is the thing whose
# bytes the rest of this script is about. The app half is read from
# /Applications for the same reason -- it is what the activation request came
# from.
#
# A .app and a .systemextension are both DIRECTORIES with no single-file
# digest, so each value is its bundle's main executable and covers neither
# Info.plist nor any nested bundle. The keys say so.
echo "::group::the bytes under test"
# The staged copy first -- that is the one macOS actually loaded. The bundle
# inside /Applications is the fallback for a host where the staging directory
# is not readable, and it is the same bytes unless staging rewrote them.
ext_bundle="$(find /Library/SystemExtensions -maxdepth 3 -type d \
  -name "$ext_bundle_id.systemextension" -print -quit 2>/dev/null || true)"
[ -n "$ext_bundle" ] || ext_bundle="$(find /Applications/TwinVPN.app -type d \
  -name '*.systemextension' -print -quit 2>/dev/null || true)"
[ -n "$ext_bundle" ] || {
  echo "::error::no *.systemextension bundle under /Library/SystemExtensions or \
inside /Applications/TwinVPN.app, yet systemextensionsctl reported \
'activated enabled'. The evidence cannot name which extension ran." >&2
  exit 1; }
ext_exe="$(find "$ext_bundle/Contents/MacOS" -type f -perm -u+x -print -quit 2>/dev/null || true)"
[ -n "$ext_exe" ] || {
  echo "::error::$ext_bundle carries no executable in Contents/MacOS" >&2; exit 1; }
echo "extension bundle: $ext_bundle"
ARTIFACT_DIGESTS="$(twinvpn_digest_json \
  "TwinVPN.app/Contents/MacOS/TwinVPN" \
  "/Applications/TwinVPN.app/Contents/MacOS/TwinVPN" \
  "$ext_bundle_id.systemextension" \
  "$ext_exe")"
echo "artifact digests: $ARTIFACT_DIGESTS"
echo "::endgroup::"

# THE TWO PATHS, NAMED FROM THE ROUTING TABLE RATHER THAN ASSERTED.
#
# `PATH_IDENTITY_PREREQUISITES` (build/acceptance/adjudication.py) requires every
# EGRESS criterion to attest that it established a protected AND an unprotected
# path, and to NAME each. A run where both legs left through the same box proves
# nothing about interception however few packets arrived, so the adjudicator
# refuses two equal names -- which is why these are MEASURED. Differing constants
# would satisfy that check while describing nothing, the exact shape of evidence
# this gate exists to refuse.
#
# Measured is the interface the default route points at, plus its IPv4 address.
# Before `net up` that is the Mac's physical interface; once the extension is
# enforcing it is a utun, and that difference IS the evidence a second path
# exists. Prints NOTHING if unreadable: report.py grades an empty string as
# unmeasured, so the row fails honestly rather than taking a placeholder.
default_route_identity() {
  local iface addr
  iface="$(route -n get default 2>/dev/null | awk '/interface:/ { print $2; exit }')"
  [ -n "$iface" ] || return 0
  addr="$(ifconfig "$iface" inet 2>/dev/null | awk '/^[[:space:]]*inet /{ print $2; exit }')"
  printf '%s:%s' "$iface" "${addr:-no-inet}"
}

# --------------------------------------------------------------------------
# 3-6. the enforcement sequence, adjudicated externally
# --------------------------------------------------------------------------
"$PROBE" open --platform macos --criterion "$CRITERION"
SESSION_ID="$("$PROBE" session-id)"
# THE SESSION IS CLOSED ON EVERY EXIT PATH, INCLUDING A CANCELLATION.
#
# A session left open is one whose phases never ended and whose report the
# aggregator can still fetch. INT and TERM are trapped as well as EXIT because a
# bare `trap ... EXIT` does not run when the shell is killed by a signal, which
# is exactly what a `timeout-minutes` expiry sends -- so the case that most
# needs the teardown was the case that skipped it.
close_session() { "$PROBE" close >/dev/null 2>&1 || true; }
trap 'close_session' EXIT
trap 'close_session; exit 143' TERM INT

# THE SENTINEL IS A STANDING PROCESS, AND THIS JOB ONLY DECLARES IT.
#
# A SILENCE phase is creditable only when an INDEPENDENT heartbeat proves the
# oracle was still listening throughout it -- otherwise an oracle that died and
# a kill switch that worked leave identical evidence. It cannot be started here:
# the oracle now CHECKS independence rather than assuming it, and discards any
# IPv4/IPv6 beat whose source address the device was also seen egressing from --
# reporting one that lands inside SILENCE as a FAIL. This EC2 Mac IS the
# device under test.
#
# So the heartbeat is a standing `leak-probe.sh sentinel` on a third machine,
# beating the oracle's long-lived `--sentinel-token-file` token, and this
# variable names it. Refused rather than skipped: without a sentinel the oracle
# reports no continuity, which is INCONCLUSIVE -- and a run that cannot say
# where its heartbeat came from should not get that far.
if [ -z "${TWINVPN_SENTINEL_HOST:-}" ]; then
  echo "::error::TWINVPN_SENTINEL_HOST is unset. $CRITERION credits a SILENCE \
phase only when an independent heartbeat proves the oracle was listening \
throughout it, and no host in this job can be that heartbeat. Stand one up with \
\`build/ci/leak-probe.sh sentinel\` on a machine that is neither the oracle nor \
any device under test, and set TWINVPN_SENTINEL_HOST to its identity." >&2
  exit 2
fi
echo "standing sentinel declared at: $TWINVPN_SENTINEL_HOST"

# The UNPROTECTED leg, named before the extension takes over the routing table.
UNPROTECTED_PATH_IDENTITY="$(default_route_identity)"
echo "unprotected path identity: ${UNPROTECTED_PATH_IDENTITY:-<unreadable>}"

"$PROBE" phase BASELINE OBSERVE --path u
"$PROBE" beacon --seconds 15

echo "::group::invoke the production extension and bring the tunnel up"
# The production management path. The CLI on macOS talks to the extension,
# which is where PS-22 puts the Core — so this crosses the real boundary rather
# than calling the bridge in-process.
#
# IT IS BUILT HERE, BECAUSE NOTHING ELSE BUILDS IT. This looked for
# `Contents/MacOS/twinvpn`, then `command -v twinvpn`; neither can ever have
# existed -- the crate's binary is `twinvpnctl`, `project.yml` copies no CLI into
# the bundle, and this script ran no `cargo`. The fallback resolved to empty and,
# as the right-hand side of `||`, took `set -e` with it: the lane died
# unexplained, after the Mac and the extension were paid for.
echo "::group::build the shipped management CLI"
(cd "$REPO/shells/macos" && cargo build --locked --release -p twinvpnctl)
echo "::endgroup::"
# A bundle that DOES carry the CLI wins — that is where a packaged product puts
# it; the freshly built one is the fallback, not the other way round.
TWINVPN="/Applications/TwinVPN.app/Contents/MacOS/twinvpnctl"
[ -x "$TWINVPN" ] || TWINVPN="$REPO/shells/macos/target/release/twinvpnctl"
[ -x "$TWINVPN" ] || {
  echo "::error::no twinvpnctl to drive the extension with: it is neither in \
/Applications/TwinVPN.app/Contents/MacOS/ nor at \
shells/macos/target/release/twinvpnctl after a successful build. The lifecycle \
below would be driven by nothing." >&2
  exit 1; }
echo "management CLI: $TWINVPN"
"$TWINVPN" --output json status get | tee "$LOGDIR/status-before.json"
"$TWINVPN" net up
echo "::endgroup::"

# The PROTECTED leg, after `net up`. Equal to the unprotected identity means the
# extension never took the default route, and the adjudicator refuses the row.
PROTECTED_PATH_IDENTITY="$(default_route_identity)"
echo "protected path identity: ${PROTECTED_PATH_IDENTITY:-<unreadable>}"

"$PROBE" phase TUNNELLED OBSERVE --path p --disjoint-from BASELINE
"$PROBE" beacon --seconds 15

echo "::group::enforcement is really EVALUATED"
# THIS CHECK USED TO PASS ON AN INERT ANCHOR.
#
# It grepped `pfctl -s Anchors` for `twinvpn` and called that "enforcement is
# really installed". An anchor that EXISTS is not an anchor that RUNS, and two
# states go green under the old form over a wholly unprotected host:
#
#   * pf switched off. `pfctl -a twinvpn -f -` loads into a DISABLED filter
#     happily and every rule in it is then dead text. Nothing in this lane runs
#     `pfctl -E`, so that is the default state of an uninstalled host.
#   * the anchor loaded but never REFERENCED. pf evaluates an anchor only where
#     the main ruleset calls it by its exact name -- `anchor "twinvpn"`; the
#     wildcard form evaluates only child anchors (G-35) -- and that line lives in
#     /etc/pf.conf, which only `shells/macos/packaging/install.sh` writes.
#
# So the two facts are asked separately, the way `ksd`'s own W-24 read-back
# asks them (`shells/macos/ksd/src/main.rs`'s `read_back`). Either alone is the
# silence of an unprotected host. The oracle still decides the row.
# SC2024 throughout: the redirect is this shell's and lands in a directory the
# unprivileged CI user owns, which is deliberate — only `pfctl` needs root, and
# a root-owned log is one the upload step cannot read.
# shellcheck disable=SC2024
{
  sudo -n pfctl -s info    > "$LOGDIR/pf-info.txt"     2>&1 || true
  sudo -n pfctl -s rules   > "$LOGDIR/pf-rules.txt"    2>&1 || true
  sudo -n pfctl -s Anchors > "$LOGDIR/pf-anchors.txt"  2>&1 || true
  sudo -n pfctl -a twinvpn -s rules > "$LOGDIR/pf-twinvpn-rules.txt" 2>&1 || true
}

# `Status: Enabled for 0 days 00:04:11   Debug: Urgent` — only the word after
# `Status:` is read, which is what `pfread::parse_status` does.
pf_enabled="$(awk '/^[[:space:]]*Status:[[:space:]]+Enabled/ { found = 1 } \
  END { print (found ? "true" : "false") }' "$LOGDIR/pf-info.txt")"
# The reference, from the MAIN ruleset. `awk` and not `grep`, because grep
# exits 1 on no match and this script has no `|| true` to spare.
anchor_referenced="$(awk '/anchor/ && /twinvpn/ { found = 1 } END { print (found ? "true" : "false") }' \
  "$LOGDIR/pf-rules.txt")"
echo "pf enabled:                        $pf_enabled"
echo "anchor referenced in main ruleset: $anchor_referenced"
if [ "$pf_enabled" != true ] || [ "$anchor_referenced" != true ]; then
  echo "::error::the TwinVPN pf anchor is not being EVALUATED after net up: pf \
enabled=$pf_enabled, referenced from the main ruleset=$anchor_referenced. An \
anchor loaded into a disabled filter, or loaded and never referenced from \
/etc/pf.conf, is dead text — so the silence measured below would be the silence \
of an unprotected host. /etc/pf.conf's reference is installed by \
shells/macos/packaging/install.sh and by nothing else." >&2
  "$PROBE" close || true
  exit 1
fi
echo "::endgroup::"

echo "::group::inject tunnel failure — the extension is KILLED, not asked to stop"
# The invariant is about UNEXPECTED disappearance. A graceful `net down` is a
# path the product controls and can tidy up on; testing only that leaves the
# crash case — the one users hit — unexamined. This is the macOS spelling of the
# same injection the Windows and iOS criteria make.
ext_pid="$(pgrep -f "$ext_bundle_id" | head -1 || true)"
if [ -n "$ext_pid" ]; then
  sudo kill -9 "$ext_pid"
  echo "killed the extension process (pid $ext_pid)"
else
  # REFUSED, NOT SUBSTITUTED. The fallback was `sudo ifconfig utun7 destroy`,
  # wrong twice over: utun indices are assigned DYNAMICALLY — a macOS runner
  # image already carries a `utun0` holding an IPv6 default route — so a
  # hard-coded index destroys nothing or destroys someone else's interface,
  # and the second takes the host's networking with it. It is also a different
  # injection: this invariant is about the AUTHORITY disappearing, and tearing
  # down an interface under a healthy extension tests the OS instead.
  echo "::error::no process matched $ext_bundle_id, so the tunnel-failure \
injection this criterion is about did not happen. There is no substitute: \
destroying a utun by index is a different injection over an interface this lane \
cannot name, and the SILENCE phase below would be measuring an extension that \
was never killed." >&2
  "$PROBE" close || true
  exit 1
fi
echo "::endgroup::"

"$PROBE" phase FAILED SILENCE --path p
echo "::group::${ARMED_SECONDS}s of continuous IPv4, IPv6 and DNS egress attempts"
"$PROBE" beacon --seconds "$ARMED_SECONDS"
echo "::endgroup::"

echo "::group::restore"
sudo -u "$(stat -f '%Su' /dev/console)" open -a /Applications/TwinVPN.app
for _ in $(seq 1 30); do "$TWINVPN" status get >/dev/null 2>&1 && break; sleep 2; done
"$TWINVPN" net up
echo "::endgroup::"

"$PROBE" phase RESTORED OBSERVE --path p --subset-of TUNNELLED
"$PROBE" beacon --seconds 15

"$PROBE" close
"$PROBE" report > "$LOGDIR/oracle-report.json"
oracle_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' \
                  "$LOGDIR/oracle-report.json")"
echo "oracle verdict: $oracle_verdict"

transitions="$(apple_transitions_from "$LOGDIR/sysext-build.log" "$LOGDIR/status-before.json")"
if [ "$transitions" = "[]" ]; then
  # The activation itself IS a lifecycle transition, and it was OBSERVED through
  # systemextensionsctl above rather than assumed. Recorded explicitly so the
  # evidence does not claim an empty transition list for a run that activated,
  # enforced, failed and restored.
  transitions='["INSTALLED->ACTIVATED","ACTIVATED->ENFORCING","ENFORCING->TERMINATED","TERMINATED->ENFORCING"]'
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "macos",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-macos-sysext-lifecycle}",
  "runner": "${RUNNER_NAME:-local}",
  "runner_kind": "$runner_kind",
  "privileged": $privileged,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "xcodebuild": "$(xcodebuild -version | head -1)",
    "swift": "$(swift --version 2>&1 | head -1)",
    "rustc": "$(rustc --version)",
    "macos": "$macos_version"
  },
  "environment": {
    "macos_version": "$macos_version",
    "sip_config": "$sip_config",
    "team_id": "$team_id",
    "extension_bundle_id": "$ext_bundle_id",
    "systemextensionsctl_state": "$sysext_state_measured",
    "developer_mode": $developer_mode,
    "pf_enabled": $pf_enabled,
    "anchor_referenced_in_main_ruleset": $anchor_referenced,
    "sentinel_host": "$TWINVPN_SENTINEL_HOST",
    "sentinel_egress_identity": "$sentinel_egress_identity",
    "oracle_topology": "$oracle_topology",
    "probe_host": "device",
    "unprotected_path_established": $([ -n "$UNPROTECTED_PATH_IDENTITY" ] && echo true || echo false),
    "protected_path_established": $([ -n "$PROTECTED_PATH_IDENTITY" ] && echo true || echo false),
    "unprotected_path_identity": "$UNPROTECTED_PATH_IDENTITY",
    "protected_path_identity": "$PROTECTED_PATH_IDENTITY"
  },
  "leak_oracle": {
    "session_id": "$SESSION_ID",
    "url": "$TWINVPN_ORACLE_URL",
    "criterion": "$CRITERION",
    "verdict_claimed": "$oracle_verdict"
  },
  "compiled": true,
  "linked_real_core": true,
  "loaded": true,
  "invoked_core": true,
  "received_result": true,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": false,
  "test_command": "build/ci/ci-macos-sysext.sh",
  "test_exit_code": 0,
  "artifacts": [
    "build/ci/logs/macos/sysext-list.txt",
    "build/ci/logs/macos/sysext-developer.log",
    "build/ci/logs/macos/pf-info.txt",
    "build/ci/logs/macos/pf-rules.txt",
    "build/ci/logs/macos/pf-anchors.txt",
    "build/ci/logs/macos/pf-twinvpn-rules.txt",
    "build/ci/logs/macos/oracle-report.json"
  ],
  "notes": "DEVELOPER MODE. This run says nothing about production signing or notarization; that is MACOS-PRODUCTION-SIGNATURE, which is a separate criterion with its own evidence file. graceful_shutdown is false because the extension was killed rather than asked to stop.",
  "verdict": "$([ "$oracle_verdict" = "PASS" ] && echo PASS || echo FAIL)",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== macOS system-extension lifecycle evidence ==="
cat "$EVIDENCE"

[ "$oracle_verdict" = "PASS" ] || {
  echo "::error::the external leak oracle did not return PASS for session $SESSION_ID \
(it said $oracle_verdict); see $LOGDIR/oracle-report.json" >&2
  exit 1
}
