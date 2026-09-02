#!/usr/bin/env bash
#
# digest.sh -- the SHA-256 of a testable artifact, and the `artifact_digests`
# map that binds a criterion's evidence to the exact bytes it tested.
#
# ===========================================================================
# THE FAILURE THIS EXISTS FOR
# ===========================================================================
# An evidence file says "ANDROID-16K-PAGE-SIZE passed". It does not say WHICH
# APK passed. So all of these produce a well-formed green row:
#
#   * a job that installed a stale APK left in `app/build/outputs` by a cached
#     Gradle run, while the commit under test never actually built;
#   * an `ios-corellium` run handed a signed IPA from a URL that has since been
#     rebuilt, so the row is about a build nobody can point at any more;
#   * a `macos-signature` run whose download was truncated by a proxy and whose
#     `codesign --verify` therefore failed for a reason that has nothing to do
#     with the product.
#
# In each case the row is about bytes the report cannot name. So every job that
# PRODUCES a testable artifact records its digest, and every job that DOWNLOADS
# one re-verifies that digest after the download and fails loudly on mismatch.
#
# A digest is an INTEGRITY binding, and only sometimes a provenance one. When
# the artifact was built in the same job that tested it, the digest proves the
# report and the test agree about the bytes -- nothing more. When it crossed a
# job or a workflow boundary (the IPA, the notarized .app) the digest is pinned
# by a repository variable and the check is a real provenance gate: an artifact
# that is not the one the operator pinned cannot be tested at all.
#
# ===========================================================================
# USAGE (sourced, never executed)
# ===========================================================================
#   . "$REPO/build/ci/digest.sh"
#   twinvpn_sha256 "$apk"                       # 64 lowercase hex on stdout
#   twinvpn_verify_digest "$ipa" "$expected"    # fatal on mismatch
#   twinvpn_digest_json app-release.apk "$apk" TwinVPN.ipa "$ipa"
#                                               # {"app-release.apk":"..",...}
#   twinvpn_run_attempt_json                    # "2" or null
#   twinvpn_repository_json                     # "owner/name" or null
#   twinvpn_python -c '...'                     # the interpreter, resolved

# NO `set -e` HERE. This file is sourced into scripts that set their own
# options, and changing a caller's shell options from a helper is how a helper
# starts deciding when its caller exits.

# PYTHON 3, BY WHICHEVER NAME THIS HOST HAS IT UNDER.
#
# `python3` is the floor for leak-probe.sh, report.py and the fallback below,
# and on a GitHub-hosted WINDOWS runner the interpreter on PATH is `python.exe`
# -- `python3` is not guaranteed to exist there at all. A lane that assumed the
# name would fail inside a phase with "command not found", which reads as a
# probe that ran and found nothing. Resolved once, cached in the environment,
# and fatal when there is no Python 3 rather than falling through to Python 2.
twinvpn_python() {
  if [ -z "${TWINVPN_PYTHON:-}" ]; then
    local candidate
    for candidate in python3 python; do
      command -v "$candidate" >/dev/null 2>&1 || continue
      "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[0] == 3 else 1)' \
        >/dev/null 2>&1 || continue
      TWINVPN_PYTHON="$candidate"
      export TWINVPN_PYTHON
      break
    done
  fi
  if [ -z "${TWINVPN_PYTHON:-}" ]; then
    echo "::error::no Python 3 interpreter on PATH (tried python3, python). \
Every evidence path in build/ci/ needs one." >&2
    return 1
  fi
  "$TWINVPN_PYTHON" "$@"
}

# The command differs on every host this repository runs on and NONE of them has
# all four: Linux and git-bash have `sha256sum`, macOS has `shasum`, a bare
# Windows shell has `certutil`. Python 3 is the floor and is already a hard
# dependency of leak-probe.sh and report.py, so the ladder always terminates.
twinvpn_sha256() {
  local file="$1"
  if [ ! -f "$file" ]; then
    echo "::error::digest: no file at $file, so its SHA-256 cannot be recorded \
and the evidence would name bytes that do not exist" >&2
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    # Chunked, deliberately. An IPA is tens of megabytes and reading one into a
    # single `bytes` on a runner with a constrained agent is a way for the
    # digest step to be the thing that fails.
    twinvpn_python - "$file" <<'PY'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as fh:
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PY
  fi
}

# The bundle case. A .app is a DIRECTORY and has no single-file digest, so this
# names the one file whose bytes are the product: the main executable. It is
# labelled as such wherever it is recorded, because a reader who assumes it
# covers the whole bundle would be wrong about the Info.plist and the nested
# .systemextension.
twinvpn_sha256_bundle_executable() {
  local bundle="$1" name
  name="$(basename "${bundle%.app}")"
  twinvpn_sha256 "$bundle/Contents/MacOS/$name"
}

# FATAL on mismatch, and fatal on an unset expectation. "No expected digest was
# configured, so we skipped the check" is the failure mode this whole file
# exists to remove: the caller decides whether a pin is required, and if it
# passes one it gets checked.
twinvpn_verify_digest() {
  local file="$1" expected="$2" label="${3:-$1}" actual
  case "$expected" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) : ;;
    *)
      echo "::error::digest: the expected SHA-256 for $label is \
'${expected:-<unset>}', which is not 64 lowercase hex. A download that is not \
pinned to a digest is not evidence about any particular build." >&2
      return 1 ;;
  esac
  if [ "${#expected}" -ne 64 ]; then
    echo "::error::digest: the expected SHA-256 for $label is ${#expected} \
characters, not 64" >&2
    return 1
  fi
  actual="$(twinvpn_sha256 "$file")" || return 1
  if [ "$actual" != "$expected" ]; then
    echo "::error::digest: $label does not match its pinned SHA-256. \
expected $expected, downloaded $actual. This is either a different build than \
the one the criterion was pinned to, or a truncated transfer; either way the \
run must not proceed to test bytes nobody named." >&2
    return 1
  fi
  echo "$label verified against its pinned SHA-256 ($actual)"
}

# THE RUN ATTEMPT, as a JSON scalar for a heredoc: `"2"` or `null`.
#
# `GITHUB_RUN_ID` is NOT unique to an execution. Re-running a failed workflow
# keeps the run id and increments `GITHUB_RUN_ATTEMPT`, so an evidence file
# written by attempt 1 and an oracle session opened by attempt 2 agree on every
# field they are currently checked against -- commit, run id, criterion -- while
# describing two different executions of two different machines. Recording the
# attempt is what lets `report.py` refuse that pair.
#
# `null` when unset, never `"1"`: a local run genuinely has no attempt number,
# and inventing one would make a developer's laptop look like CI attempt 1.
twinvpn_run_attempt_json() {
  if [ -n "${GITHUB_RUN_ATTEMPT:-}" ]; then
    printf '"%s"' "$GITHUB_RUN_ATTEMPT"
  else
    printf 'null'
  fi
}

# THE REPOSITORY, as a JSON scalar for a heredoc: `"owner/name"` or `null`.
#
# `build/acceptance/adjudication.py`'s `check_run_binding` refuses evidence that
# records no `repository` whenever the environment names one, and the
# environment always names one under Actions. So an evidence file that omits it
# is not merely thinner -- it cannot discharge any criterion at all, on any run
# of this workflow.
#
# What it buys once present: a fork's run, or another repository's run, produces
# evidence that cannot be passed off as this repository's. Commit and run id do
# not separate those -- a fork carries the same commits and numbers its own runs
# from the same series.
#
# `null` when unset, for the same reason as the attempt above: a local run is
# not a run of any repository, and naming one would be an invention.
twinvpn_repository_json() {
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    printf '"%s"' "$GITHUB_REPOSITORY"
  else
    printf 'null'
  fi
}

# The `artifact_digests` map, as a JSON object literal for a heredoc. Takes
# NAME PATH pairs. With no pairs it emits `{}` -- which is what a criterion that
# tests no artifact must record, rather than omitting the key: an absent key and
# an empty map mean different things to report.py, and "this criterion has no
# artifact" is a measurement, not a gap.
twinvpn_digest_json() {
  local out="" name path sum
  while [ $# -ge 2 ]; do
    name="$1"; path="$2"; shift 2
    sum="$(twinvpn_sha256 "$path")" || return 1
    out="${out:+$out, }\"$name\": \"$sum\""
  done
  printf '{%s}' "${out:+ $out }"
}
