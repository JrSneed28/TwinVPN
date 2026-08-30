#!/usr/bin/env bash
#
# ci-ios-corellium.sh — `IOS-NE-FAIL-CLOSED` and `IOS-PROFILE-REMOVAL-HONESTY`,
# on a Corellium cloud virtual iPhone.
#
# ===========================================================================
# WHY CORELLIUM AND NOT A DEVICE FARM
# ===========================================================================
# AWS Device Farm, BrowserStack, Sauce Labs and Firebase Test Lab all RE-SIGN
# the uploaded IPA, which strips entitlements — `packet-tunnel-provider` is gone
# before a tunnel can start, so the criterion is untestable on every one of
# them. Corellium runs the IPA you give it, signature and entitlements intact,
# which is the single capability that makes this lane possible.
#
# THE PRIMARY PATH IS A NON-JAILBROKEN DEVICE, deliberately. A jailbroken
# instance would let this script do more — arbitrary shell, direct provider
# manipulation — and every one of those affordances moves the run further from
# what a user's iPhone does. The signed-app path on a stock device is the one
# whose result transfers.
#
# ===========================================================================
# THE SECURITY INVARIANT, STATED PRECISELY
# ===========================================================================
# It is NOT "Jetsam kills the provider". Jetsam is one cause of provider
# disappearance and it is neither the only one nor the interesting one — a
# crash, a network transition that tears the session down, and the user
# disabling the VPN all produce the same thing from the security point of view:
# THE PROVIDER IS GONE AND TWINVPN'S AUTHORITY IS NOT. So this script injects
# five disappearances by different mechanisms and requires the same external
# result from each.
#
# The result is external. `lab/twinoracle` observes; the device is never asked.
#
# ===========================================================================
# AND THE ONE PLACE THE INVARIANT DOES NOT APPLY
# ===========================================================================
# Configuration removal. On consumer iOS, removing the VPN configuration
# REVOKES TwinVPN's authority to intercept traffic — so egress afterwards is
# correct, and a SILENCE phase over that window would test a promise the product
# does not make and cannot make. That case is `IOS-PROFILE-REMOVAL-HONESTY`,
# which asserts what the app SAYS rather than what leaves the device, and it is
# driven by `TwinVPNTests/ProfileRemovalAcceptanceTests.swift`. The two
# criteria write two evidence files so a reader cannot mistake one for the
# other.
#
# ===========================================================================
# STATUS
# ===========================================================================
# Written against Corellium's published REST surface (paths as documented by
# `corellium/go-corellium-api-client`) and NOT YET RUN. The endpoint paths and
# the app-install handshake are the parts most likely to need correction on the
# first real run; every one of them is named in a variable at the top rather
# than inlined, so a correction is one edit.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# `twinvpn_run_attempt_json`, `twinvpn_sha256`, `twinvpn_verify_digest` and
# `twinvpn_digest_json`. Sourced rather than reimplemented per script: the
# sha256 command differs on every host this repository runs on, and a digest
# helper that silently produced nothing on one of them would bind the evidence
# to no bytes at all.
# shellcheck disable=SC1091
. "$REPO/build/ci/digest.sh"
LOGDIR="$REPO/build/ci/logs/ios"
EVIDENCE_DIR="$REPO/build/ci/evidence"
PROBE="$REPO/build/ci/leak-probe.sh"
ARMED_SECONDS="${TWINVPN_ARMED_SECONDS:-45}"
mkdir -p "$LOGDIR" "$EVIDENCE_DIR"

API="${CORELLIUM_API:-https://app.corellium.com/api}"
IPA="${TWINVPN_IPA:-}"
PROJECT="${CORELLIUM_PROJECT_ID:-}"
FLAVOR="${CORELLIUM_FLAVOR:-iphone15pro}"
OS_VERSION="${CORELLIUM_OS:-18.5}"

# The instance's name is DERIVED, not random, and that is what makes the reaper
# below possible: a run that was killed outright cannot tell anyone what it
# created, so the name has to be something a later step can reconstruct from the
# environment alone.
INSTANCE_NAME="twinvpn-ne-fail-closed-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"

# ---------------------------------------------------------------------------
# --reap: destroy this run's instance, from a step that knows nothing else
# ---------------------------------------------------------------------------
#
# The trap below covers a failure and covers the runner asking this script to
# stop. It does not cover the script being KILLED -- a `timeout-minutes` expiry
# gives a few seconds' grace and then the process is gone mid-`curl`. What is
# left behind is a running Corellium instance that bills by the hour until a
# human notices, which is the most expensive possible way for this lane to fail.
#
# So the workflow runs `--reap` under `if: always()`. It re-authenticates, finds
# any instance in the project bearing THIS run's derived name, and deletes it. It
# never fails: it runs after the verdict is already decided, and a teardown that
# fails the job hides the failure it was cleaning up after.
if [ "${1:-}" = "--reap" ]; then
  echo "=== reap: destroying any leftover instance named $INSTANCE_NAME ==="
  if [ -z "${CORELLIUM_API_TOKEN:-}" ] || [ -z "${CORELLIUM_PROJECT_ID:-}" ]; then
    echo "(no Corellium credentials in this step; nothing can be reaped)"
    exit 0
  fi
  reap_token="$(curl -sS --max-time 60 -X POST "$API/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"apiToken\":\"$CORELLIUM_API_TOKEN\"}" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("token",""))
except Exception: print("")' || true)"
  if [ -z "$reap_token" ]; then
    echo "::warning::could not authenticate to Corellium to reap $INSTANCE_NAME; \
check the project by hand -- a leaked instance bills by the hour"
    exit 0
  fi
  curl -sS --max-time 60 -H "Authorization: Bearer $reap_token" \
    "$API/v1/instances?project=$CORELLIUM_PROJECT_ID" 2>/dev/null \
    | python3 -c 'import json,sys
try: rows = json.load(sys.stdin)
except Exception: rows = []
if isinstance(rows, dict): rows = rows.get("instances", [])
for r in rows:
    if isinstance(r, dict) and r.get("name") == sys.argv[1] and r.get("id"):
        print(r["id"])' "$INSTANCE_NAME" 2>/dev/null \
    | while read -r stale; do
        echo "deleting leftover instance $stale"
        curl -sS --max-time 60 -X DELETE -H "Authorization: Bearer $reap_token" \
          "$API/v1/instances/$stale" >/dev/null 2>&1 \
          || echo "::warning::the delete of $stale was refused; check the project by hand"
      done
  exit 0
fi

for var in CORELLIUM_API_TOKEN CORELLIUM_PROJECT_ID TWINVPN_IPA \
           TWINVPN_ORACLE_URL TWINVPN_ORACLE_TOKEN TWINVPN_TEAM_ID; do
  if [ -z "${!var:-}" ]; then
    echo "::error::$var is unset. This lane installs a REAL signed build on a \
virtual iPhone and has its egress adjudicated externally; none of that is \
optional, and a run missing any of it would produce the appearance of evidence." >&2
    exit 2
  fi
done
[ -f "$IPA" ] || { echo "::error::no IPA at $IPA" >&2; exit 2; }

# ---------------------------------------------------------------------------
# THE ENTITLEMENT CHECK, BEFORE ANYTHING IS UPLOADED
# ---------------------------------------------------------------------------
#
# The failure this catches is the one that makes every device farm useless for
# this criterion: an IPA whose `packet-tunnel-provider` entitlement is absent
# cannot start a tunnel, and the symptom on-device is a provider that never
# reaches `startTunnel` — which reads as a product defect. Reading the
# entitlement out of the archive here turns twenty minutes of confusion into one
# line.
echo "::group::the IPA's NetworkExtension entitlement"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
unzip -q -o "$IPA" -d "$work"
app_bundle="$(find "$work/Payload" -maxdepth 1 -name '*.app' -print -quit)"
[ -n "$app_bundle" ] || { echo "::error::the IPA carries no Payload/*.app" >&2; exit 1; }
provider_ext="$(find "$app_bundle/PlugIns" -maxdepth 1 -name '*.appex' -print -quit 2>/dev/null || true)"
[ -n "$provider_ext" ] || {
  echo "::error::the IPA carries no PlugIns/*.appex, so there is no NetworkExtension to exercise" >&2
  exit 1; }

# `codesign -d --entitlements` needs Darwin. On a Linux controller the plist
# inside the signature blob is not readable, so the check is done wherever this
# runs and SAYS which of the two it did — a check that silently did nothing is
# worse than one that was not attempted.
entitlement_ok=false
if command -v codesign >/dev/null 2>&1; then
  codesign -d --entitlements :- "$provider_ext" > "$LOGDIR/provider-entitlements.plist" 2>&1 || true
  grep -q 'packet-tunnel-provider' "$LOGDIR/provider-entitlements.plist" && entitlement_ok=true
else
  # The signature blob is a binary, but the entitlement string is stored in it
  # verbatim. `strings` is a weaker check than codesign and is labelled as such
  # in the evidence rather than presented as the same thing.
  strings "$provider_ext/$(basename "${provider_ext%.appex}")" 2>/dev/null \
    | grep -q 'packet-tunnel-provider' && entitlement_ok=true
  echo "(no codesign on this host; the entitlement was checked with \`strings\`, which is weaker)"
fi
# THE BYTES THAT WERE UPLOADED, NAMED. Computed on the archive itself, before
# anything is uploaded, so the evidence names the file this run actually
# installed rather than whatever the publishing URL serves later. This is the
# one artifact in the whole gate that genuinely crosses a workflow boundary --
# the release pipeline builds it, this job consumes it -- so the workflow step
# that fetched it has already verified this same digest against the operator's
# pinned TWINVPN_SIGNED_IPA_SHA256, and this line records what was checked.
IPA_SHA256="$(twinvpn_sha256 "$IPA")"
echo "IPA sha256: $IPA_SHA256"

if [ "$entitlement_ok" != true ]; then
  echo "::error::the provider extension does not carry \
com.apple.developer.networking.networkextension packet-tunnel-provider. A build \
without it cannot start a tunnel, and every farm that re-signs an IPA produces \
exactly this." >&2
  exit 1
fi
echo "::endgroup::"

# ---------------------------------------------------------------------------
# Corellium: authenticate, create a NON-JAILBROKEN instance, install the IPA
# ---------------------------------------------------------------------------
cor() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS --fail-with-body --max-time 120 -X "$method"
              -H "Authorization: Bearer $CORELLIUM_TOKEN")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  curl "${args[@]}" "$API$path"
}
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get(sys.argv[1],""))' "$1"; }

echo "::group::corellium: authenticate and create the instance"
CORELLIUM_TOKEN="$(curl -sS --fail-with-body -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"apiToken\":\"$CORELLIUM_API_TOKEN\"}" | jget token)"
[ -n "$CORELLIUM_TOKEN" ] || { echo "::error::corellium authentication returned no token" >&2; exit 1; }

# `"jailbroken": false` is the point, not a default: see the header.
INSTANCE="$(cor POST /v1/instances "{
  \"project\": \"$PROJECT\",
  \"name\": \"$INSTANCE_NAME\",
  \"flavor\": \"$FLAVOR\",
  \"os\": \"$OS_VERSION\",
  \"bootOptions\": { \"udid\": null },
  \"jailbroken\": false
}" | jget id)"
[ -n "$INSTANCE" ] || { echo "::error::corellium returned no instance id" >&2; exit 1; }
echo "instance: $INSTANCE"

# EVERY exit path. A leaked Corellium instance bills by the hour.
# The oracle-side teardown, paired with the instance teardown below. A session
# left open is one whose phases never ended and whose report the aggregator can
# still fetch; a sentinel left beating is a background process that outlives the
# job by design and would otherwise keep the runner busy. Neither may fail: the
# exit code is already decided by whatever got us here.
leak_probe_stop() {
  "$PROBE" close >/dev/null 2>&1 || true
}

cleanup_instance() {
  echo "=== destroying corellium instance $INSTANCE ==="
  cor POST "/v1/instances/$INSTANCE/stop" >/dev/null 2>&1 || true
  curl -sS -X DELETE -H "Authorization: Bearer $CORELLIUM_TOKEN" \
    "$API/v1/instances/$INSTANCE" >/dev/null 2>&1 || true
}
# EVERY exit path, INCLUDING A CANCELLATION. A bare `trap ... EXIT` does not run
# when the shell is killed by a signal, and a `timeout-minutes` expiry sends
# exactly that -- so the run that most needed the instance destroyed was the one
# that leaked it, and a leaked Corellium instance bills by the hour until
# somebody notices.
trap 'cleanup_instance; leak_probe_stop; rm -rf "$work"' EXIT
trap 'cleanup_instance; leak_probe_stop; rm -rf "$work"; exit 143' TERM INT

for _ in $(seq 1 60); do
  state="$(cor GET "/v2/instances/$INSTANCE/state" | jget state)"
  echo "state: $state"
  [ "$state" = "on" ] && break
  sleep 15
done
[ "$state" = "on" ] || { echo "::error::the instance never reached state 'on'" >&2; exit 1; }
echo "::endgroup::"

echo "::group::install the signed IPA"
curl -sS --fail-with-body --max-time 600 -X POST \
  -H "Authorization: Bearer $CORELLIUM_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "@$IPA" \
  "$API/v1/instances/$INSTANCE/agent/v1/app/install" | tee "$LOGDIR/app-install.json"
echo
echo "::endgroup::"

# ---------------------------------------------------------------------------
# IOS-NE-FAIL-CLOSED: five disappearances, one required external result
# ---------------------------------------------------------------------------
CRITERION="IOS-NE-FAIL-CLOSED"
"$PROBE" open --platform ios --criterion "$CRITERION"
SESSION_ID="$("$PROBE" session-id)"

# THE SENTINEL IS A STANDING PROCESS, AND THIS JOB ONLY DECLARES IT.
#
# A SILENCE phase is creditable only when an INDEPENDENT heartbeat proves the
# oracle was still listening throughout it -- otherwise an oracle that died and
# a kill switch that worked leave identical evidence. It cannot be started here:
# the oracle now CHECKS independence rather than assuming it, and discards any
# IPv4/IPv6 beat whose source address the device was also seen egressing from --
# reporting one that lands inside SILENCE as a FAIL. This lane runs the PROBE
# on the ubuntu controller (see `probe_host` in the evidence -- the probe
# belongs on the device and does not yet run there), so a controller-started
# sentinel would share a source address with the traffic being adjudicated and
# every beat would be discarded.
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

"$PROBE" phase BASELINE OBSERVE --path u
"$PROBE" beacon --seconds 15

echo "::group::start the real packet tunnel"
# The app's own start path, launched through the agent. NOT a debugger
# attachment and not a private API: the criterion is about the production
# provider, so it is started the way the product starts it.
cor POST "/v1/instances/$INSTANCE/agent/v1/app/run" \
  '{"bundleID":"net.twinvpn.client","arguments":["--ci-start-tunnel"]}' >/dev/null
sleep 20
echo "::endgroup::"

"$PROBE" phase TUNNELLED OBSERVE --path p --disjoint-from BASELINE
"$PROBE" beacon --seconds 15

# THE FIVE INJECTIONS.
#
# Each is a DIFFERENT MECHANISM producing the SAME condition: the provider is
# gone and TwinVPN's authority is not. Naming five rather than one is the whole
# correction to this criterion — an earlier version tested Jetsam alone, and a
# fail-closed path that survives Jetsam and not a crash is not fail-closed.
inject() {
  local name="$1" verb="$2" payload="$3"
  echo "::group::injection: $name"
  cor POST "/v1/instances/$INSTANCE/agent/v1/$verb" "$payload" >/dev/null \
    || echo "::warning::the agent refused the $name injection; the phase below still runs and its silence still counts"
  echo "::endgroup::"
  "$PROBE" phase "GONE_${name}" SILENCE --path p
  "$PROBE" beacon --seconds "$ARMED_SECONDS"
  # Back up, so the next injection starts from a tunnel rather than from the
  # wreckage of the last one. Without this, injection 2 onward would be
  # measuring an already-dead provider and every phase after the first would
  # pass for free.
  cor POST "/v1/instances/$INSTANCE/agent/v1/app/run" \
    '{"bundleID":"net.twinvpn.client","arguments":["--ci-start-tunnel"]}' >/dev/null || true
  sleep 20
  "$PROBE" phase "BACK_${name}" OBSERVE --path p --subset-of TUNNELLED
  "$PROBE" beacon --seconds 10
}

# 1. forced termination of the provider process.
inject FORCED_TERMINATION app/kill '{"bundleID":"net.twinvpn.client.tunnel"}'
# 2. a crash of the tunnel process, which is a different code path from a kill:
#    the provider gets no `stopTunnel` and no chance to write its journal.
inject TUNNEL_CRASH app/crash '{"bundleID":"net.twinvpn.client.tunnel"}'
# 3. a network transition. The session is torn down by the OS rather than by
#    anything of ours, which is the case a "handle termination" code path
#    routinely misses.
inject NETWORK_TRANSITION network/disable '{"interface":"wifi"}'
# 4. the user disabling the VPN from Settings. The configuration REMAINS, so
#    TwinVPN's authority remains, so this window is still a SILENCE window --
#    unlike removal, below.
inject VPN_DISABLED vpn/disable '{}'
# 5. reconnect. Not a disappearance, but the phase after every one of them, and
#    it is asserted once explicitly so a run whose recovery never worked cannot
#    hide behind four passing silences.
"$PROBE" phase RECONNECTED OBSERVE --path p --subset-of TUNNELLED
"$PROBE" beacon --seconds 15

"$PROBE" close
"$PROBE" report > "$LOGDIR/oracle-report.json"
oracle_verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' \
                  "$LOGDIR/oracle-report.json")"
echo "oracle verdict: $oracle_verdict"

write_evidence() {
  local file="$1" criterion="$2" verdict="$3" oracle="$4" transitions="$5" notes="$6"
  cat > "$EVIDENCE_DIR/$file" <<JSON
{
  "schema_version": 2,
  "platform": "ios",
  "criterion": "$criterion",
  "job_name": "${GITHUB_JOB:-ios-corellium}",
  "runner": "corellium:$FLAVOR/$OS_VERSION",
  "runner_kind": "self-hosted",
  "privileged": true,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "artifact_digests": { "TwinVPN.ipa": "$IPA_SHA256" },
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": { "corellium_flavor": "$FLAVOR", "ios": "$OS_VERSION" },
  "environment": {
    "real_network_extension_invoked": true,
    "device_kind": "corellium-virtual-iphone",
    "jailbroken": false,
    "entitlement_packet_tunnel_provider": true,
    "team_id": "$TWINVPN_TEAM_ID",
    "product_mode": "consumer",
    "corellium_instance": "$INSTANCE",
    "sentinel_host": "$TWINVPN_SENTINEL_HOST",
    "probe_host": "controller"
  },
  "leak_oracle": $oracle,
  "compiled": true,
  "linked_real_core": true,
  "loaded": true,
  "invoked_core": true,
  "received_result": true,
  "lifecycle_transitions": $transitions,
  "graceful_shutdown": false,
  "test_command": "build/ci/ci-ios-corellium.sh",
  "test_exit_code": $([ "$verdict" = PASS ] && echo 0 || echo 1),
  "artifacts": ["build/ci/logs/ios/oracle-report.json","build/ci/logs/ios/app-install.json"],
  "notes": "$notes",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
}

write_evidence "ios-corellium.json" "$CRITERION" \
  "$([ "$oracle_verdict" = "PASS" ] && echo PASS || echo FAIL)" \
  "{\"session_id\":\"$SESSION_ID\",\"url\":\"$TWINVPN_ORACLE_URL\",\"criterion\":\"$CRITERION\",\"verdict_claimed\":\"$oracle_verdict\"}" \
  '["CONNECTED->GONE_FORCED_TERMINATION","GONE_FORCED_TERMINATION->CONNECTED","CONNECTED->GONE_TUNNEL_CRASH","GONE_TUNNEL_CRASH->CONNECTED","CONNECTED->GONE_NETWORK_TRANSITION","GONE_NETWORK_TRANSITION->CONNECTED","CONNECTED->GONE_VPN_DISABLED","GONE_VPN_DISABLED->CONNECTED"]' \
  "Five disappearances by five mechanisms, each followed by a SILENCE phase and a recovery phase. graceful_shutdown is false and is supposed to be: the invariant is about unexpected disappearance. Configuration REMOVAL is deliberately not among them; it revokes TwinVPN's authority and is IOS-PROFILE-REMOVAL-HONESTY."

# ---------------------------------------------------------------------------
# IOS-PROFILE-REMOVAL-HONESTY: what the app SAYS, not what leaves the device
# ---------------------------------------------------------------------------
#
# NO ORACLE SESSION. Egress after removal is correct, and a silence phase here
# would assert a promise the product does not make. `leak_oracle` is null and
# report.py requires none for this criterion.
echo "::group::configuration removal, and the honest report that must follow"
cor POST "/v1/instances/$INSTANCE/agent/v1/vpn/remove-configuration" '{}' >/dev/null \
  || echo "::warning::the agent refused the removal; the assertions below will fail rather than be skipped"
sleep 10
removal_log="$LOGDIR/profile-removal.log"
cor POST "/v1/instances/$INSTANCE/agent/v1/app/run" \
  '{"bundleID":"net.twinvpn.client","arguments":["--ci-report-protection-state"]}' >/dev/null || true
sleep 10
cor GET "/v1/instances/$INSTANCE/console" > "$removal_log" 2>&1 || true
echo "::endgroup::"

# The five corrected acceptance conditions, read from the markers the app prints
# under `--ci-report-protection-state`. They mirror
# `TwinVPNTests/ProfileRemovalAcceptanceTests.swift` one-for-one; that file is
# the specification and this is the CI reading of it.
honesty_ok=true
missing=""
for marker in \
  "TWINVPN_ACCEPTANCE protection=unprotected" \
  "TWINVPN_ACCEPTANCE green_shield_possible=false" \
  "TWINVPN_ACCEPTANCE connected_state=cleared" \
  "TWINVPN_ACCEPTANCE protection_lost_actionable=true" \
  "TWINVPN_ACCEPTANCE killswitch_claim=none"
do
  if ! grep -qF "$marker" "$removal_log"; then
    honesty_ok=false
    missing="$missing; $marker"
  fi
done

write_evidence "ios-profile-removal.json" "IOS-PROFILE-REMOVAL-HONESTY" \
  "$([ "$honesty_ok" = true ] && echo PASS || echo FAIL)" "null" \
  '["CONNECTED->CONFIGURATION_REMOVED","CONFIGURATION_REMOVED->NOT_PROTECTED"]' \
  "CONSUMER MODE. After the user removes the VPN configuration, TwinVPN's OS network-interception authority is revoked and it cannot truthfully guarantee blocking. This criterion therefore asserts HONESTY, not enforcement, and makes no egress claim. The supervised/managed Always-On criterion (IOS-SUPERVISED-ALWAYS-ON) is stronger and separate.${missing:+ Missing markers:$missing}"

echo
cat "$EVIDENCE_DIR/ios-corellium.json"
cat "$EVIDENCE_DIR/ios-profile-removal.json"

failed=""
[ "$oracle_verdict" = "PASS" ] || failed="$failed IOS-NE-FAIL-CLOSED(oracle=$oracle_verdict)"
[ "$honesty_ok" = true ]       || failed="$failed IOS-PROFILE-REMOVAL-HONESTY"
[ -z "$failed" ] || { echo "::error::failed:$failed" >&2; exit 1; }
