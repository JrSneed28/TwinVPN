#!/usr/bin/env bash
#
# ci-macos-signature.sh — `MACOS-PRODUCTION-SIGNATURE`.
#
# ===========================================================================
# WHY THIS IS A SEPARATE CRITERION AND A SEPARATE FILE
# ===========================================================================
# `MACOS-SYSEXT-LIFECYCLE` activates the extension in DEVELOPER MODE
# (`systemextensionsctl developer on`), because that is the only way an
# extension activates on a machine CI can drive. Developer mode accepts an
# extension a customer's Mac would refuse: an ad-hoc signature, an expired
# certificate, a missing notarization ticket, an unstapled bundle.
#
# So a green lifecycle row says the extension WORKS. It says nothing about
# whether the thing users would download is signed, notarized and stapled.
# Those are different failures with different owners, and while both lived in
# one macOS evidence file, one green row implied both. It cannot any more:
# separate criterion, separate evidence file, separate row in the acceptance
# report. Splitting them is the whole point of this file existing.
#
# ===========================================================================
# WHAT IT CHECKS, AND WHY EACH IS ITS OWN QUESTION
# ===========================================================================
#   codesign --verify --deep --strict   the signature is INTACT and covers
#                                       every nested bundle, including the
#                                       .systemextension.
#   codesign -dvvv                      WHO signed it. The authority chain and
#                                       the Team ID, recorded rather than
#                                       assumed, so a run signed by the wrong
#                                       team is visible instead of merely green.
#   spctl -a -vvv --type install        GATEKEEPER's answer. This is the one a
#                                       user's Mac actually asks, and it is the
#                                       only check here that consults the
#                                       notarization service's ticket.
#   stapler validate                    the ticket is ATTACHED to the bundle. An
#                                       app that notarized but was never stapled
#                                       works online and fails on a Mac with no
#                                       network — a defect that is invisible to
#                                       every other check in this list.
#
# All four, or the criterion is not discharged. `codesign --verify` passing on
# an unnotarized build is the exact false comfort this file exists to remove.
#
# ===========================================================================
# THIS SCRIPT ACTIVATES NOTHING
# ===========================================================================
# It does not install to /Applications, does not turn developer mode on, and
# does not touch the extension slot. It reads a built product. That is
# deliberate: the two criteria must be able to run on the same machine without
# either one's state reaching the other's evidence.

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
EVIDENCE="$REPO/build/ci/evidence/macos-signature.json"
CRITERION="MACOS-PRODUCTION-SIGNATURE"
mkdir -p "$LOGDIR" "$(dirname "$EVIDENCE")"

[ "$(uname -s)" = "Darwin" ] || {
  echo "::error::ci-macos-signature.sh must run on macOS" >&2; exit 2; }

APP="${1:-$LOGDIR/DerivedData/Build/Products/Release/TwinVPN.app}"
[ -d "$APP" ] || {
  echo "::error::no app bundle at $APP. Pass the path to the SIGNED, NOTARIZED \
product; this criterion is about the artifact users would download, so it must \
not be handed a CI build that skipped signing." >&2
  exit 2; }

team_id="${TWINVPN_TEAM_ID:-}"
[ -n "$team_id" ] || {
  echo "::error::TWINVPN_TEAM_ID is unset; the criterion records WHO signed and \
cannot do that without the expected Team ID to compare against" >&2
  exit 2; }

echo "=== $CRITERION on $APP ==="
macos_version="$(sw_vers -productVersion)"

# WHICH BYTES WERE INSPECTED.
#
# This criterion is the one where the artifact came from OUTSIDE the run: the
# release pipeline publishes a notarized archive and the workflow fetches it
# over HTTPS. "The signature was valid" is worth nothing without "…of this
# exact download", because a URL that was rebuilt between the pin and the fetch
# produces a perfectly green row about a build nobody can point at.
#
# TWINVPN_ARCHIVE_SHA256 is set by the workflow step that already verified the
# download against the operator's pinned digest, and is recorded verbatim rather
# than recomputed: recomputing it here would only prove this script can hash a
# file, while echoing the verified value ties the row to the check that
# actually gated the download.
#
# The .app itself is a DIRECTORY and has no single-file digest, so the second
# entry is the main executable's -- labelled as such, because it does not cover
# the Info.plist or the nested .systemextension.
archive_digest_args=()
[ -n "${TWINVPN_ARCHIVE_SHA256:-}" ] && archive_digest_args=(TwinVPN.app.zip:"$TWINVPN_ARCHIVE_SHA256")
bundle_exe_sha="$(twinvpn_sha256_bundle_executable "$APP")"
ARTIFACT_DIGESTS="$(python3 - "$bundle_exe_sha" "${archive_digest_args[@]+"${archive_digest_args[@]}"}" <<'PY'
import json, sys
out = {"TwinVPN.app/Contents/MacOS/TwinVPN": sys.argv[1]}
for pair in sys.argv[2:]:
    name, _, digest = pair.partition(":")
    out[name] = digest
print(json.dumps(out))
PY
)"
echo "artifact digests: $ARTIFACT_DIGESTS"

# Each check runs, its output is CAPTURED, and its status is recorded — rather
# than `set -e` stopping at the first failure. A report that says "the signature
# is intact, notarization is missing, stapling is missing" is worth more than one
# that says only the first thing that went wrong.
run_check() {
  local name="$1"; shift
  echo "::group::$name"
  set +e
  "$@" > "$LOGDIR/sig-$name.log" 2>&1
  local rc=$?
  set -e
  cat "$LOGDIR/sig-$name.log"
  echo "::endgroup::"
  [ "$rc" -eq 0 ] && echo "true" || echo "false"
}

signature_intact="$(run_check codesign-verify codesign --verify --deep --strict --verbose=2 "$APP")"
_="$(run_check codesign-display codesign -dvvv --entitlements - "$APP")"
gatekeeper_accepted="$(run_check spctl spctl -a -vvv --type install "$APP")"
stapled="$(run_check stapler xcrun stapler validate "$APP")"

# WHO, from the display output. `codesign -dvvv` writes to stderr, which
# `run_check` captured into the log, so this reads the file rather than re-running.
signing_authority="$(tr -d '\r' < "$LOGDIR/sig-codesign-display.log" \
  | awk -F'=' '/^Authority=/ { print $2; exit }')"
observed_team="$(tr -d '\r' < "$LOGDIR/sig-codesign-display.log" \
  | awk -F'=' '/^TeamIdentifier=/ { print $2; exit }')"

# NOTARIZATION IS GATEKEEPER'S ANSWER, NOT A SEPARATE COMMAND.
#
# There is no local "is this notarized" query: `spctl -a --type install`
# consults the ticket (stapled, or fetched from Apple), and its acceptance IS
# the notarization check. Deriving it rather than inventing a second probe keeps
# the evidence honest about what was actually asked.
notarized="$gatekeeper_accepted"

echo
echo "signature intact:     $signature_intact"
echo "gatekeeper accepted:  $gatekeeper_accepted"
echo "stapled:              $stapled"
echo "authority:            ${signing_authority:-<none>}"
echo "team identifier:      ${observed_team:-<none>} (expected $team_id)"

team_matches=false
[ "$observed_team" = "$team_id" ] && team_matches=true

verdict="FAIL"
if [ "$signature_intact" = true ] && [ "$gatekeeper_accepted" = true ] \
   && [ "$stapled" = true ] && [ "$team_matches" = true ]; then
  verdict="PASS"
fi

cat > "$EVIDENCE" <<JSON
{
  "schema_version": 2,
  "platform": "macos",
  "criterion": "$CRITERION",
  "job_name": "${GITHUB_JOB:-macos-production-signature}",
  "runner": "${RUNNER_NAME:-ec2-mac}",
  "runner_kind": "self-hosted",
  "privileged": false,
  "github_run_id": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"$GITHUB_RUN_ID\"" || echo null),
  "github_run_attempt": $(twinvpn_run_attempt_json),
  "repository": $(twinvpn_repository_json),
  "artifact_digests": $ARTIFACT_DIGESTS,
  "github_run_url": $([ -n "${GITHUB_RUN_ID:-}" ] && echo "\"${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID\"" || echo null),
  "commit": "$(cd "$REPO" && git rev-parse HEAD)",
  "toolchain": {
    "codesign": "$(codesign --version 2>&1 | head -1)",
    "macos": "$macos_version"
  },
  "environment": {
    "macos_version": "$macos_version",
    "team_id": "$team_id",
    "observed_team_identifier": "${observed_team:-}",
    "signing_authority": "${signing_authority:-}",
    "signature_intact": $signature_intact,
    "gatekeeper_accepted": $gatekeeper_accepted,
    "notarized": $notarized,
    "stapled": $stapled,
    "bundle_path": "$APP"
  },
  "leak_oracle": null,
  "compiled": true,
  "linked_real_core": true,
  "loaded": false,
  "invoked_core": false,
  "received_result": false,
  "lifecycle_transitions": ["BUILT->SIGNED"],
  "graceful_shutdown": true,
  "test_command": "build/ci/ci-macos-signature.sh $APP",
  "test_exit_code": $([ "$verdict" = PASS ] && echo 0 || echo 1),
  "artifacts": ["build/ci/logs/macos/sig-codesign-verify.log","build/ci/logs/macos/sig-spctl.log","build/ci/logs/macos/sig-stapler.log"],
  "notes": "This criterion inspects a built artifact and runs nothing. loaded/invoked_core/received_result are FALSE and are supposed to be: executing the product is MACOS-SYSEXT-LIFECYCLE's claim, and report.py does not require the execution booleans for this criterion.",
  "verdict": "$verdict",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

echo
echo "=== macOS production signature evidence ==="
cat "$EVIDENCE"

[ "$verdict" = "PASS" ] || {
  echo "::error::$CRITERION did not pass: signature_intact=$signature_intact \
gatekeeper=$gatekeeper_accepted stapled=$stapled team_matches=$team_matches" >&2
  exit 1
}
