#!/usr/bin/env bash
# Resolve every base image in infra/docker/base-images.lock to a sha256 digest.
#
# ADR-0018 §11.11 DP-1: "No unbounded version ranges." DP-2: "Dependencies are
# pinned BY DIGEST in a mirror, not copied into the tree", because
# source-vendoring "makes a dependency bump invisible in the diff, which is
# exactly the review a supply-chain policy exists to force."
#
# A container tag is the same problem in a different shape: `rust:1.90.0` is a
# mutable pointer, so two builds a month apart can differ with nothing in the
# diff to show it. A digest is content-addressed and cannot.
#
# This script does the resolution and REWRITES the lock file. It requires
# registry access. It does not run in a normal build; it runs when a base image
# is deliberately advanced, and its output is reviewed like any other diff.
#
# Verification is by `build/verify/check-budgets.py --check-image-pins`, which
# reports every tag-only entry and fails when TWINVPN_REQUIRE_IMAGE_DIGESTS=1.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="${here}/../../infra/docker/base-images.lock"

if [ ! -f "${lock}" ]; then
  echo "missing ${lock}" >&2
  exit 1
fi

resolver=""
if command -v crane >/dev/null 2>&1; then
  resolver=crane
elif command -v skopeo >/dev/null 2>&1; then
  resolver=skopeo
elif command -v docker >/dev/null 2>&1; then
  resolver=docker
else
  cat >&2 <<'MSG'
No digest resolver found. Install one of:

  crane   (go install github.com/google/go-containerregistry/cmd/crane@latest)
  skopeo  (distribution package)
  docker  (falls back to `docker buildx imagetools inspect`)

Nothing is written. This script does not guess, and it does not leave a
half-resolved lock file behind: a partially pinned lock reads as pinned.
MSG
  exit 1
fi

echo "==> resolving digests with ${resolver}"

resolve() {
  local ref="$1"
  case "${resolver}" in
    crane)
      crane digest "${ref}" 2>/dev/null || true
      ;;
    skopeo)
      skopeo inspect --format '{{.Digest}}' "docker://${ref}" 2>/dev/null || true
      ;;
    docker)
      docker buildx imagetools inspect "${ref}" --format '{{.Manifest.Digest}}' 2>/dev/null || true
      ;;
  esac
}

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

failures=0
while IFS= read -r raw; do
  line="${raw%%$'\r'}"
  trimmed="$(printf '%s' "${line}" | sed 's/^[[:space:]]*//')"
  if [ -z "${trimmed}" ] || [ "${trimmed:0:1}" = "#" ]; then
    printf '%s\n' "${line}" >> "${tmp}"
    continue
  fi

  # shellcheck disable=SC2086
  set -- ${trimmed}
  key="$1"
  ref="$2"

  digest="$(resolve "${ref}")"
  if [ -z "${digest}" ]; then
    echo "!!  ${key}: could not resolve ${ref}" >&2
    failures=$((failures + 1))
    printf '%-11s %s\n' "${key}" "${ref}" >> "${tmp}"
    continue
  fi

  echo "    ${key}: ${digest}"
  printf '%-11s %-58s %s\n' "${key}" "${ref}" "${digest}" >> "${tmp}"
done < "${lock}"

if [ "${failures}" -gt 0 ]; then
  echo >&2
  echo "${failures} image(s) unresolved. Lock file NOT rewritten." >&2
  echo "A partially pinned lock reads as pinned, which is worse than an" >&2
  echo "honest tag-only one." >&2
  exit 1
fi

mv "${tmp}" "${lock}"
trap - EXIT
echo "==> wrote ${lock}"
echo
echo "Review the diff, then set the digest-qualified refs in your .env:"
echo "  TWINVPN_RUST_IMAGE=<ref>@<digest>   etc. — see infra/env.example"
