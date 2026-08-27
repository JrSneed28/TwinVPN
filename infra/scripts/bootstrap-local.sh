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

echo "==> creating secret directories"
for svc in "${services[@]}"; do
  mkdir -p "${secrets}/${svc}"
  chmod 0700 "${secrets}/${svc}"
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
    chmod 0600 "${key}"
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
    chmod 0600 "${static}"
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
    chmod 0600 "${mapkey}"
    echo "    relay-directory: RelayMap signing key generated (ed25519)"
  else
    echo "!!  relay-directory: openssl absent, RelayMap signing key NOT generated"
  fi
else
  echo "    relay-directory: RelayMap signing key present, leaving alone"
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
