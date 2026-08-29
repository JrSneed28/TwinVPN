#!/usr/bin/env bash
# Prepare a local development environment for `docker compose up`.
#
# Creates the per-service secret directories the compose file mounts, and
# generates DEVELOPMENT-ONLY key material into them. Everything it writes is
# covered by infra/secrets/.gitignore and MUST NOT be committed, deployed, or
# reused anywhere that matters.
#
# Idempotent: an existing file is never overwritten, so re-running this after
# adding a service does not rotate the keys the running stack is using.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT DELIBERATELY DOES NOT DO
# ---------------------------------------------------------------------------
# It does not write a `.env`, and it does not choose a database password. A
# script that generates a credential and leaves it on disk under a predictable
# name is how a "development" password reaches production. The compose file
# uses `${TWINVPN_PG_PASSWORD:?...}` so an unset value is a readable startup
# error rather than a silent fallback to something known, and choosing it is
# the operator's act, not this script's.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
secrets="${here}/../secrets"
services=(control-plane rendezvous presence relay-a relay-b relay-directory)

have_openssl=1
command -v openssl >/dev/null 2>&1 || have_openssl=0

# ---------------------------------------------------------------------------
# MODES: 0755 directories and 0644 files, NOT 0700/0600, and this is a
# deliberate trade rather than an oversight.
#
# ===========================================================================
# WHY THE TIGHT MODES DID NOT WORK
# ===========================================================================
# Every service image is distroless `:nonroot` and runs as **uid 65532**. The
# compose file bind-mounts these directories into it. A 0700 directory owned by
# the developer's uid cannot be traversed by 65532, and a 0600 file cannot be
# read by it, so every service died at startup with
# `Env(FileUnreadable { key: "TWINVPN_RELAY_ISSUER_KEYS_PATH" })`.
#
# That is not a podman quirk. Docker behaves identically: the uid in the image
# is the uid that opens the file, and it is not the uid that owns it. The
# topology had simply never been started.
#
# ===========================================================================
# WHY LOOSENING IS THE RIGHT END OF THE TRADE HERE, AND WHERE IT IS NOT
# ===========================================================================
# The alternatives were worse:
#
#   - `user: "${UID}:${GID}"` in compose discards the property the Dockerfile
#     treats as structural ("distroless :nonroot ... there is no root user to
#     start from"), for every service, to fix a file mode.
#   - `userns_mode: keep-id` works on podman and not on Docker, so the
#     documented topology would only run on one of them.
#
# What is being loosened is DEVELOPMENT key material: generated per machine
# from OS entropy, covered by infra/secrets/.gitignore, verified unreachable by
# git in build/verify/check-compose.py, and worthless anywhere else. The cost
# is that another local user on the same machine can read it.
#
# THIS DOES NOT GENERALISE. A deployment must give the service's uid access
# through ownership or a secret store, never by widening the mode -- and the
# fact that this script is the only thing that writes these files is what keeps
# the two situations apart.
# ---------------------------------------------------------------------------
echo "==> creating secret directories"
for svc in "${services[@]}"; do
  mkdir -p "${secrets}/${svc}"
  # 0755: the container's uid must be able to TRAVERSE this to reach the files.
  chmod 0755 "${secrets}/${svc}"
done

# ---------------------------------------------------------------------------
# TLS for the four services with a device-facing wire surface.
#
# ===========================================================================
# THE KEY IS THE IDENTITY. THE CERTIFICATE IS GENERATED AND IS NOT USED.
# ===========================================================================
# Read that literally, because the file layout suggests otherwise. ADR-0002
# §11.2 rung 1 is TLS 1.3 with mutual RFC 7250 RAW PUBLIC KEY authentication,
# and `rendezvous` and `presence` now implement exactly that: the server's
# whole identity is `tls.key`, and the peer is authenticated by its public key,
# not by a name in a certificate. ADR-0001 §6 rejected the naming system a
# certificate implies.
#
# `tls.crt` is minted anyway, and each service's config requires it to EXIST,
# because tooling and libraries in this space expect a certificate file to be
# there. Nothing reads its contents and nothing trusts its subject, its SAN or
# its expiry. Deleting it breaks a file-existence check; editing it changes
# nothing at all.
#
# What follows from that: rotating `tls.key` rotates the server's identity and
# every pinning peer must learn the new key. Rotating `tls.crt` accomplishes
# nothing. Do not reason about these two files as a pair.
#
# Client authentication is mandatory and non-configurable in both services, and
# 0-RTT is structurally prohibited (ADR-0001 L-CONTROL, ownership.md §6) - by
# construction, not by certificate choice.
# ---------------------------------------------------------------------------
if [ "${have_openssl}" -eq 1 ]; then
  echo "==> generating development TLS material"
  for svc in control-plane rendezvous presence relay-directory; do
    crt="${secrets}/${svc}/tls.crt"
    key="${secrets}/${svc}/tls.key"
    if [ -f "${crt}" ] && [ -f "${key}" ]; then
      echo "    ${svc}: present, leaving alone"
      continue
    fi
    # Both address families in the SAN, because ADR-0010 R1 is one story
    # covering both and a certificate valid only over v4 would make the
    # IPv6-only profile fail for a reason that has nothing to do with the code.
    openssl req -x509 -newkey ed25519 -nodes \
      -keyout "${key}" -out "${crt}" -days 90 \
      -subj "/CN=${svc}.twinvpn.local" \
      -addext "subjectAltName=DNS:${svc},DNS:${svc}.twinvpn.local,DNS:localhost,IP:127.0.0.1,IP:::1" \
      >/dev/null 2>&1
    # Readable by the container's uid; see the modes note above.
    chmod 0644 "${key}"
    chmod 0644 "${crt}"
    echo "    ${svc}: generated (ed25519, 90 days, DEVELOPMENT ONLY)"
  done
else
  echo "!!  openssl not found - TLS material NOT generated."
  echo "    The four wire-facing services will fail to start. Install openssl"
  echo "    or place tls.crt / tls.key into infra/secrets/<service>/ yourself."
fi

# ---------------------------------------------------------------------------
# Relay static Noise keys and issuer key sets.
#
# ADR-0005 §11.1(2): the relay leg is Noise_IK over X25519 / ChaCha20-Poly1305
# / BLAKE2s - the identical primitive set ADR-0001 already ships, so no new
# dependency (C1/C6). This script writes 32 raw random bytes; deriving the
# public half and encoding it is the relay's own job and is NOT reimplemented
# here, because inventing a second key-handling path outside twinvpn-crypto is
# exactly what CD-I2 forbids.
#
# ADR-0005 §11.3: the relay holds the ISSUER PUBLIC-KEY SET as signed config
# and verifies RelayCapabilityTokens offline against it. That is what lets
# relay admission survive a control-plane partition of any duration
# (testing-strategy A-13) - so the issuer key file is PUBLIC material and its
# absence is a hard failure, never a fallback to "admit everyone".
# ---------------------------------------------------------------------------
echo "==> generating relay key material"
for svc in relay-a relay-b; do
  static="${secrets}/${svc}/static-noise.key"
  if [ ! -f "${static}" ]; then
    head -c 32 /dev/urandom > "${static}"
    # Readable by the container's uid; see the modes note above.
    chmod 0644 "${static}"
    echo "    ${svc}: static Noise key generated (32 random bytes)"
  else
    echo "    ${svc}: static Noise key present, leaving alone"
  fi

  issuer="${secrets}/${svc}/issuer-keys.json"
  if [ ! -f "${issuer}" ]; then
    cat > "${issuer}" <<'JSON'
{
  "_comment": "RelayCapabilityToken issuer public-key set, ADR-0005 §11.3. PUBLIC material only - a relay verifies, it never signs. An EMPTY key set means NO TOKEN VERIFIES, which is the correct fail-closed default: a relay that admitted flows because it had no issuer keys would be an open relay. Populate this from the Owner-rooted issuer once ADR-0007's issuance path exists.",
  "operator_group_id": "local-operator",
  "issuers": []
}
JSON
    chmod 0644 "${issuer}"
    echo "    ${svc}: issuer key set stub written (EMPTY - fails closed)"
  else
    echo "    ${svc}: issuer key set present, leaving alone"
  fi
done

# ---------------------------------------------------------------------------
# The pinned OwnerTrustAnchor set (S-32), TWINVPN_CP_OWNER_ANCHOR_PATH.
#
# One base16 COSE_Key per line. The control plane verifies Owner-signed
# statements against these and against nothing else.
#
# ITS ABSENCE IS A CAPABILITY LOST, NOT A STARTUP FAILURE: with no anchor the
# control plane still enrols, discovers and streams, and refuses every
# Owner-authority statement with AUTH.KEY_UNAVAILABLE. A MALFORMED line IS a
# startup failure, because a half-parsed trust anchor set is worse than none.
#
# The stub written here is EMPTY - comments only. That is the honest default:
# an Owner root of trust is an Owner's to create (ADR-0007, architecture A-04),
# and a key this script invented would be a root of trust nobody chose. Without
# a compose mount, though, Owner-authority commands could not work anywhere but
# a unit test, so the file and its mount exist and are ready to be filled.
# ---------------------------------------------------------------------------
anchors="${secrets}/control-plane/owner-anchors.hex"
if [ ! -f "${anchors}" ]; then
  cat > "${anchors}" <<'HEX'
# TwinVPN OwnerTrustAnchor set (S-32) — one base16 COSE_Key per line.
#
# EMPTY ON PURPOSE. An empty set is fail-closed: every Owner-authority
# statement is refused with AUTH.KEY_UNAVAILABLE, announced at startup rather
# than discovered from a refusal. Enrolment, discovery and the C2 stream all
# still work.
#
# Add your development Owner public key below to exercise Owner-authority
# commands. Blank lines and lines starting with '#' are ignored; anything else
# must be valid base16 or the control plane REFUSES TO START.
HEX
  chmod 0644 "${anchors}"
  echo "    control-plane: OwnerTrustAnchor set stub written (EMPTY - fails closed)"
else
  echo "    control-plane: OwnerTrustAnchor set present, leaving alone"
fi

# RelayMap signing key. ADR-0006 §11.1: one signed COSE_Sign1/CBOR document per
# operator group, issuer Ed25519 over the canonical encoding (ADR-0003).
mapkey="${secrets}/relay-directory/map-signing.key"
if [ ! -f "${mapkey}" ]; then
  if [ "${have_openssl}" -eq 1 ]; then
    openssl genpkey -algorithm ed25519 -out "${mapkey}" >/dev/null 2>&1
    chmod 0644 "${mapkey}"
    echo "    relay-directory: RelayMap signing key generated (ed25519)"
  else
    echo "!!  relay-directory: openssl absent, RelayMap signing key NOT generated"
  fi
else
  echo "    relay-directory: RelayMap signing key present, leaving alone"
fi

# ---------------------------------------------------------------------------
# The DEVELOPMENT relay-credential issuer, and the development relay map.
#
# ===========================================================================
# WHY THIS DOES NOT CONTRADICT THE EMPTY ISSUER SET ABOVE
# ===========================================================================
# The stub written above is empty because an empty set is fail-closed and "a
# relay that admitted flows because it had no issuer keys would be an open
# relay". That is still true and is still the default for a relay that nobody
# has deliberately given credentials to.
#
# What it also means is that NO LEG CAN BE ESTABLISHED in the local
# environment at all — every BIND is refused for the same reason — so not one
# of ADR-0005's admission, quota, pairing or failover paths can be exercised.
# A development environment that cannot reach its own happy path reproduces
# nothing.
#
# So this step is the explicit, separate act that populates it, and it OVERWRITES
# the empty stub above on purpose. Three things keep it from becoming a
# production credential path, and all three are structural:
#
#   1. The signing seed is generated per machine from OS entropy into
#      infra/secrets/dev-issuer/, which infra/secrets/.gitignore covers and
#      build/verify/check-compose.py asks GIT ITSELF to confirm is unreachable.
#   2. The signer is `twinvpn_crypto::testkit`, behind the never-shipped
#      `test-support` feature (ADR-0018 CD-5). No product artifact can link it.
#   3. The tokens are audienced to `local-operator`, and a relay refuses a key
#      set belonging to another operator group.
#
# It needs a Rust toolchain, so it is SKIPPED rather than failed when cargo is
# absent: the TLS and relay material above is still useful without it.
# ---------------------------------------------------------------------------
echo "==> development relay credentials"
# shellcheck disable=SC1091
[ -f "${here}/../../build/toolchain/env.sh" ] && . "${here}/../../build/toolchain/env.sh" >/dev/null 2>&1
if command -v cargo >/dev/null 2>&1; then
  repo="$(cd "${here}/../.." && pwd)"
  ( cd "${repo}/lab" && cargo build --quiet -p twinsim )
  # Cargo honours CARGO_TARGET_DIR, which redirects every workspace's artifacts
  # into one shared directory and leaves the per-workspace `target/` absent.
  sim="${CARGO_TARGET_DIR:-${repo}/lab/target}/debug/twinsim"

  # Idempotent: an existing seed is reused and never rotated. Rotating would
  # invalidate every token a running relay holds, and the symptom — binds
  # refused for no visible reason — is the hardest one here to diagnose.
  "${sim}" issuer init     --seed "${secrets}/dev-issuer/seed.bin"     --relay-secrets "${secrets}/relay-a"     --relay-secrets "${secrets}/relay-b"     --operator-group local-operator

  # The endpoints are the COMPOSE ones. `local-plane.sh` rewrites the map with
  # loopback endpoints for its own host-native run, because ADR-0011 DN-0
  # requires a literal address and the two topologies do not share one.
  "${sim}" map init     --out "${secrets}/dev-issuer/relay-map.json"     --operator-group local-operator     --relay "aaaaaaaaaaaaaaaa=[fd00:7717:1::20]:41641=local=domain-a=${secrets}/relay-a/static-noise.key"     --relay "bbbbbbbbbbbbbbbb=[fd00:7717:1::21]:41641=local=domain-b=${secrets}/relay-b/static-noise.key"
else
  mkdir -p "${secrets}/dev-issuer"
  chmod 0700 "${secrets}/dev-issuer"
  echo "!!  cargo not found - development relay credentials NOT generated."
  echo "    Run 'make toolchains' then 'make dev-issuer'. Until then the"
  echo "    relays will start and admit NOTHING, which is the fail-closed"
  echo "    default and not a fault."
fi

echo
echo "==> done. Next:"
echo "    1. cp infra/env.example .env       (then EDIT it - nothing there is a usable secret)"
echo "    2. docker compose config           (validate)"
echo "    3. docker compose up -d"
echo
echo "    All six services are implemented. Nothing here has been started on a"
echo "    host with Docker yet - see infra/README.md \u00a79 for what is and is not"
echo "    verified."
