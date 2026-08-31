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
# STATUS: THIS LANE IS BLOCKED, AND THE BLOCKER IS CORELLIUM'S API
# ===========================================================================
# The first draft of this file was written against a REMEMBERED shape of
# Corellium's REST surface and had never been run. Reading the actual OpenAPI
# document (`corellium/go-corellium-api-client`, `api/openapi.yaml`, openapi
# 3.0.3, API version 7.3.0-27831) alongside the official JS SDK
# (`corellium/corellium-api`, `src/agent.js`, which implements the WebSocket
# agent protocol the REST `agent/v1/*` paths bridge to) showed that roughly half
# the calls it made were wrong, several of them to paths that do not exist. The
# paths below are now the documented ones. Three findings outlived that fix, each
# argued in full where it bites rather than twice:
#
#   * THREE OF THE FIVE INJECTIONS HAVE NO MECHANISM -- no `app/crash`, no
#     device-network control on iOS, no `vpn` namespace. They refuse by name.
#   * LAUNCH ARGUMENTS CANNOT REACH THE APP, so `--ci-start-tunnel` has no route
#     in, and no handler on the app side either. See `app_run`.
#   * CONFIGURATION REMOVAL HAS NO MECHANISM EITHER, for a reason specific to
#     this product. See the removal section at the bottom.
#
# So `IOS-NE-FAIL-CLOSED` as specified cannot be discharged on Corellium today.
# The refusals ARE the deliverable: they are what a blocked criterion is supposed
# to look like, as against a green one that measured nothing.
#
# ONE PREMISE REMAINS UNVERIFIED AND EVERYTHING ABOVE RESTS ON IT: no primary
# source says whether a `NEPacketTunnelProvider` actually runs on a Corellium
# virtual iPhone. Not the API spec, not the SDK, not Corellium's support
# documentation, not upstream -- silence, in both directions. A run of this file
# reaches the first refusal only AFTER creating the instance, installing the IPA
# and taking the BASELINE and TUNNELLED phases, and that ordering is deliberate:
# that prefix is the cheapest test of the premise anyone has, and it is worth
# more than another week of reading.

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

# The two bundle identifiers, read off `shells/ios/project.yml` (:93 and :154).
# The provider's used to read `net.twinvpn.client.tunnel` here, which is the
# MACOS system extension's identifier (`build/ci/ci-macos-sysext.sh:101`) -- the
# iOS extension this criterion is about is `.provider`. A kill aimed at a bundle
# id that is not on the device is the worst failure available to this lane:
# nothing dies, the agent has nothing to complain about, and the SILENCE phase
# that follows scores a tunnel that was never disturbed.
APP_BUNDLE_ID="net.twinvpn.client"
PROVIDER_BUNDLE_ID="net.twinvpn.client.provider"

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
  # PROJECT-SCOPED, and that is not cosmetic. `GET /v1/instances` accepts only
  # `name` and `returnAttr`; there is no `project` query parameter, so the filter
  # this used to pass was ignored and the reaper walked every instance the token
  # could see across every project it had access to. It only ever DELETED a name
  # match, so nothing was destroyed that should not have been -- but scoping a
  # destructive sweep by hoping a query parameter exists is not a thing to leave
  # standing. `GET /v1/projects/{projectId}/instances` is the real one.
  curl -sS --max-time 60 -H "Authorization: Bearer $reap_token" \
    "$API/v1/projects/$CORELLIUM_PROJECT_ID/instances" 2>/dev/null \
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
# CORELLIUM IS NOT CONSISTENT ABOUT THE SHAPE OF A 200, AND ONE OF THE TWO BIT.
# The body of `GET /v2/instances/{id}/state` is a BARE JSON STRING -- literally
# `"on"` -- because `InstanceState` is declared `type: string` with an enum, not
# an object. The previous reader did `json.load(sys.stdin).get(...)`, which
# raises `AttributeError` on a `str`, so under `set -euo pipefail` the very first
# boot poll killed the run. So: take the body itself when it is a string, and the
# named key when it is an object. `/v1/auth/login` returns the object form.
jget() { python3 -c 'import json,sys
d = json.load(sys.stdin)
print(d if isinstance(d, str) else (d.get(sys.argv[1], "") if isinstance(d, dict) else ""))' "$1"; }

# A CAPABILITY CORELLIUM DOES NOT HAVE IS A HARD FAILURE, NOT A WARNING.
#
# What this replaces: a `|| echo "::warning::the agent refused ..."` that turned
# "this endpoint does not exist" into a note and then opened the measurement
# anyway. A SILENCE phase asserts that the provider is GONE; opening one after an
# injection that never happened measures a live tunnel while claiming to measure
# a dead one, and scores it as a pass. That is the exact class of half-true
# evidence §12.4/§12.5 exists to eliminate, so it exits instead -- naming the
# criterion, the step, and the capability that is missing.
refuse_missing_capability() {
  local criterion="$1" step="$2" needs="$3" why="$4"
  echo "::error::$criterion cannot be discharged on Corellium: $step needs \
$needs, and Corellium exposes no such capability -- $why. Refused rather than \
warned: a step that did not happen must not be followed by a measurement that \
scores as though it had." >&2
  exit 1
}

echo "::group::corellium: authenticate and create the instance"
CORELLIUM_TOKEN="$(curl -sS --fail-with-body -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"apiToken\":\"$CORELLIUM_API_TOKEN\"}" | jget token)"
[ -n "$CORELLIUM_TOKEN" ] || { echo "::error::corellium authentication returned no token" >&2; exit 1; }

# NON-JAILBROKEN, WHICH IS OBTAINED BY ASKING FOR NOTHING.
#
# This used to send `"jailbroken": false` under a comment calling it "the point,
# not a default". It was neither: `InstanceCreateOptions` has no `jailbroken`
# field, and the whole 13,701-line OpenAPI document mentions the word only as a
# possible VALUE inside the `patches: string[]` array. The key was inert. The
# instance is non-jailbroken because that is what omitting `"jailbroken"` from
# `patches` gives you -- which would have held just as well had the comment
# claimed the opposite, and that is the tell. `bootOptions.udid` IS a real
# nullable field and stays.
INSTANCE="$(cor POST /v1/instances "{
  \"project\": \"$PROJECT\",
  \"name\": \"$INSTANCE_NAME\",
  \"flavor\": \"$FLAVOR\",
  \"os\": \"$OS_VERSION\",
  \"bootOptions\": { \"udid\": null }
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
# THREE STEPS, NOT ONE.
#
# `POST agent/v1/app/install` takes `AgentInstallBody` -- `{"path": "<a path
# ALREADY ON THE VM>"}`, as `application/json`. It does not accept archive bytes,
# so posting the IPA to it, which is what this used to do, could not have worked
# on any run. The sequence below is the one the official SDK's `installFile()`
# performs and the one the spec documents: ask the agent for a writable temp
# path, PUT the bytes there, then install FROM that path.
ipa_path="$(cor POST "/v1/instances/$INSTANCE/agent/v1/file/temp" | jget path)"
[ -n "$ipa_path" ] || {
  echo "::error::the agent returned no temp path to upload the IPA to" >&2; exit 1; }

# The path is a PATH PARAMETER, so it is percent-encoded into a single segment:
# `/tmp/x` must not turn into two segments and a leading double slash. This
# mirrors the `url.PathEscape` the generated Go client applies to a path
# parameter, and it is the one detail in this file taken from the generator's
# convention rather than read out of the spec text -- so it is the first thing to
# suspect if the upload 404s on the first real run.
ipa_path_enc="$(python3 -c 'import sys,urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))' "$ipa_path")"
curl -sS --fail-with-body --max-time 600 -X PUT \
  -H "Authorization: Bearer $CORELLIUM_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  --data-binary "@$IPA" \
  "$API/v1/instances/$INSTANCE/agent/v1/file/device/$ipa_path_enc" >/dev/null

# Built with `json.dumps` rather than string-pasted: the path is a value this
# script received from the network, and a quote or a backslash in it would
# otherwise produce a malformed body that the agent would reject as a mystery.
cor POST "/v1/instances/$INSTANCE/agent/v1/app/install" \
  "$(python3 -c 'import json,sys; print(json.dumps({"path": sys.argv[1]}))' "$ipa_path")" \
  | tee "$LOGDIR/app-install.json"
echo
echo "::endgroup::"

# ---------------------------------------------------------------------------
# IOS-NE-FAIL-CLOSED: five disappearances, one required external result
# ---------------------------------------------------------------------------
# THE FIVE HONESTY FACTS, DECLARED BEFORE THE FIRST EVIDENCE WRITE.
#
# `write_evidence` shares ONE heredoc between both criteria, so these names are
# interpolated by the IOS-NE-FAIL-CLOSED write as well and `set -u` would abort
# there if they were only assigned later. `false` is the correct initial value,
# not a placeholder: an unmeasured condition is not a satisfied one, and this
# initialisation can only ever make a row red. `check_environment` ignores keys
# a criterion does not require, so their presence in the fail-closed file is
# inert.
reported_not_protected=false
green_shield_impossible=false
connected_state_cleared=false
protection_lost_actionable=false
no_continued_killswitch_claim=false

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

# AND THE SAME FACT KEEPS FOUR KEYS OUT OF THE EVIDENCE BELOW.
#
# `report.py:377` merges `PATH_IDENTITY_PREREQUISITES` into every criterion in
# `ORACLE_REQUIRED`, so `IOS-NE-FAIL-CLOSED` is also required to attest
# `protected_path_established`, `unprotected_path_established`,
# `protected_path_identity`, `unprotected_path_identity`, and `probe_host:
# "device"`. None of the five is written here, deliberately. The values this job
# could produce would be the CONTROLLER's two paths and the CONTROLLER's two
# source identities, which is precisely the false attestation
# `adjudication.py:150-160` names this script for by name. They cannot be written
# truthfully until the probe runs ON the virtual iPhone, and `probe_host` stays
# `"controller"` until it does -- it is a factual claim about where the
# measurement happened, and editing the string would not move the measurement.

"$PROBE" phase BASELINE OBSERVE --path u
"$PROBE" beacon --seconds 15

# LAUNCHING THE APP -- AND THE ARGUMENT THAT CANNOT GO WITH IT.
#
# The real path is `POST agent/v1/app/apps/{bundleId}/run`, with the bundle id as
# a PATH SEGMENT and NO REQUEST BODY. `POST agent/v1/app/run` carrying
# `{"bundleID":...}`, which this script used to send, is not a path the API
# defines at all.
#
# AND THERE IS NOWHERE TO PUT `--ci-start-tunnel`. `app/apps/{bundleId}/run`
# declares no request body; the agent operation underneath it is
# `agent.run(bundleID)` and takes nothing else; the only variant that accepts a
# second parameter is `runActivity(bundleID, activity)`, which is Android-only.
# Corellium cannot pass a launch argument to an iOS app, by any route it exposes.
# Nothing under `shells/ios/` reads that flag either, so the trigger is missing at
# both ends and needs designing as one thing.
#
# It is left to FAIL rather than faked, which is a different judgement from the
# refusals below and turns on the phase kind: TUNNELLED is an OBSERVE phase with
# `--disjoint-from BASELINE`, so a tunnel that never came up fails at the oracle
# on its own. An OBSERVE phase whose premise is false reports the falsehood; a
# SILENCE phase whose premise is false passes for free, which is why only the
# second kind has to be refused before it opens.
app_run() { cor POST "/v1/instances/$INSTANCE/agent/v1/app/apps/$1/run" >/dev/null; }

echo "::group::start the real packet tunnel"
# The app's own start path, launched through the agent. NOT a debugger
# attachment and not a private API: the criterion is about the production
# provider, so it is started the way the product starts it.
app_run "$APP_BUNDLE_ID"
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
#
# ONLY THE FIRST OF THE FIVE CAN BE PERFORMED. The other three are kept below,
# refusing by name, rather than deleted: a silently dropped injection is a
# quietly weakened criterion, and this criterion is only fail-closed BECAUSE it
# demands the same result from five different mechanisms. One that refuses out
# loud is an honest blocker; one that is gone is a smaller promise nobody
# noticed being made.
inject() {
  local name="$1" bundle="$2"
  echo "::group::injection: $name"
  # `app/apps/{bundleId}/kill` -- bundle id in the PATH, no request body. The old
  # `POST app/kill` with a `{"bundleID":...}` body is not a path the API defines.
  # No `|| warning` here either: if the kill did not land, the provider is still
  # running and the SILENCE phase below would score a live tunnel.
  cor POST "/v1/instances/$INSTANCE/agent/v1/app/apps/$bundle/kill" >/dev/null || {
    echo "::error::the agent refused the $name injection against $bundle, so the \
provider is still running. The SILENCE phase that would follow asserts the \
provider is GONE; it is not opened." >&2
    exit 1; }
  echo "::endgroup::"
  "$PROBE" phase "GONE_${name}" SILENCE --path p
  "$PROBE" beacon --seconds "$ARMED_SECONDS"
  # Back up, so the next injection starts from a tunnel rather than from the
  # wreckage of the last one. Without this, injection 2 onward would be
  # measuring an already-dead provider and every phase after the first would
  # pass for free.
  app_run "$APP_BUNDLE_ID"
  sleep 20
  "$PROBE" phase "BACK_${name}" OBSERVE --path p --subset-of TUNNELLED
  "$PROBE" beacon --seconds 10
}

# 1. forced termination of the provider process. The one injection of the five
#    that Corellium can actually carry out.
inject FORCED_TERMINATION "$PROVIDER_BUNDLE_ID"

# 2. a crash of the tunnel process, which is a different code path from a kill:
#    the provider gets no `stopTunnel` and no chance to write its journal.
refuse_missing_capability "$CRITERION" "the TUNNEL_CRASH injection" \
  "an agent operation that forces a running process to crash" \
  "\`app/crash\` appears nowhere in the OpenAPI document and there is no \`Crash*\` \
method on the generated client; the SDK's only crash surface is \
\`crash.subscribe\`, a LISTENER that waits for a report the OS produces on its own, \
so the agent can observe a crash but cannot cause one"

# 3. a network transition. The session is torn down by the OS rather than by
#    anything of ours, which is the case a "handle termination" code path
#    routinely misses.
refuse_missing_capability "$CRITERION" "the NETWORK_TRANSITION injection" \
  "an agent operation that takes the device's network interface down" \
  "the only device-network agent operation is \`GET agent/v1/system/network\`, \
which the spec marks read-only and \"(AOSP only)\"; the raw WebSocket protocol's \
\`wifi.connect\`/\`wifi.disconnect\` are bridged to no REST path and their \
applicability to iOS is unconfirmed"

# 4. the user disabling the VPN from Settings. The configuration REMAINS, so
#    TwinVPN's authority remains, so this window is still a SILENCE window --
#    unlike removal, below.
refuse_missing_capability "$CRITERION" "the VPN_DISABLED injection" \
  "an agent operation that disables an installed VPN configuration" \
  "no \`vpn\` namespace exists in the REST spec or in the WebSocket protocol; \
Corellium's only \"VPN\" surface is the project-level OpenVPN that connects a \
researcher's own machine into the virtual network, which is a different thing \
wearing the same word"
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
  "repository": $(twinvpn_repository_json),
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
    "probe_host": "controller",
    "reported_not_protected": $reported_not_protected,
    "green_shield_impossible": $green_shield_impossible,
    "connected_state_cleared": $connected_state_cleared,
    "protection_lost_actionable": $protection_lost_actionable,
    "no_continued_killswitch_claim": $no_continued_killswitch_claim
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
# AND THIS ONE CANNOT BE TRIGGERED EITHER, FOR A REASON SPECIFIC TO TWINVPN.
#
# `agent/v1/vpn/remove-configuration` was invented; there is no `vpn` namespace.
# The nearest REAL capability is profile management -- `GET
# agent/v1/profile/profiles` returning `{"profiles":["<id>",...]}`, then `DELETE
# agent/v1/profile/profiles/{profileId}` -- and it does not reach this case:
# TwinVPN's iOS VPN configuration is created BY THE APP, through
# `NETunnelProviderManager.saveToPreferences()`
# (`shells/ios/Sources/TwinVPNApp/VPNPermission.swift:103-119`), not installed
# from a `.mobileconfig`. There is no configuration profile object on the device
# for that API to enumerate, let alone delete. Removing it is a Settings
# interaction, and the agent drives no UI.
refuse_missing_capability "IOS-PROFILE-REMOVAL-HONESTY" \
  "removing the VPN configuration" \
  "an agent operation that deletes a VPN configuration the app installed itself" \
  "the profile API only manages installed \`.mobileconfig\` profiles and TwinVPN \
installs none, so there is nothing on the device for it to address"

# Everything from here down is unreachable until that refusal is lifted, and is
# kept because it is the CI reading of the specification rather than scaffolding:
# the marker list mirrors `TwinVPNTests/ProfileRemovalAcceptanceTests.swift`
# one-for-one, and it is what should run the day a removal mechanism exists.
sleep 10
removal_log="$LOGDIR/profile-removal.log"
# `--ci-report-protection-state` cannot be passed -- see `app_run` above; the
# markers below therefore have no way to be produced today.
app_run "$APP_BUNDLE_ID" || true
sleep 10
# `GET /v1/instances/{id}/console` returns `{"url":"wss://..."}` -- a WEBSOCKET
# HANDLE, not log text -- so grepping it for markers, which is what this used to
# do, could never have matched. `consoleLog` is the `text/plain` one.
#
# CAVEAT, RECORDED RATHER THAN ASSUMED AWAY: it is unverified whether `print`,
# `NSLog` or `os_log` output from a signed, non-jailbroken app reaches that
# stream at all. It may carry only kernel/serial console output, in which case
# the markers need a different transport entirely -- a file in the app group read
# back over `agent/v1/file`, say. Do not read a passing marker check as proof
# this works until one has actually been seen arriving.
cor GET "/v1/instances/$INSTANCE/consoleLog" > "$removal_log" 2>&1 || true
echo "::endgroup::"

# The five corrected acceptance conditions, read from the markers the app prints
# under `--ci-report-protection-state`. They mirror
# `TwinVPNTests/ProfileRemovalAcceptanceTests.swift` one-for-one; that file is
# the specification and this is the CI reading of it.
# EACH CONDITION REACHES THE EVIDENCE AS ITS OWN KEY.
#
# This loop used to fold all five into a single `honesty_ok` bit, pick a verdict
# from it and DISCARD the five facts -- so a run that failed one condition and a
# run that failed all five produced the same evidence, and `report.py`'s five
# required keys (`reported_not_protected` and friends) were never written at
# all. The row therefore failed its environment check before its verdict was
# read, which is the same defect the path-identity keys had in the other lanes.
#
# The marker names ARE the key names, deliberately. A translation table between
# what the app prints and what the adjudicator requires is an obvious place to
# drop one, and this lane had already drifted once that way.
honesty_ok=true
missing=""
for key in \
  reported_not_protected \
  green_shield_impossible \
  connected_state_cleared \
  protection_lost_actionable \
  no_continued_killswitch_claim
do
  if grep -qF "TWINVPN_ACCEPTANCE $key=true" "$removal_log"; then
    eval "$key=true"
  else
    honesty_ok=false
    missing="$missing; $key"
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
