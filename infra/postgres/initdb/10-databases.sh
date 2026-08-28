#!/usr/bin/env bash
# Create the additional logical databases the topology needs.
#
# ADR-0002 B-3 is the reason there are several rather than one: the durable
# event log is "a per-TwinNet append-only `event` relation in the SAME
# transactional store as control-plane state", with net_seq allocated INSIDE
# THE MUTATING TRANSACTION (N-3). That co-location is a correctness property,
# not a packaging convenience, so the control-plane state and its event log
# share `twinvpn_control` and nothing else may be put there.
#
# Presence is explicitly EVENTUALLY CONSISTENT and TTL'd (architecture.md
# §2.13, ADR-0009) and is a HINT SERVICE, never an authority. Putting it in the
# control-plane database would place eventually-consistent hint rows in the same
# transactional scope as revocation, which is exactly the confusion ADR-0009
# exists to prevent.
#
# ---------------------------------------------------------------------------
# THE RELAY-FLEET OWNERSHIP QUESTION, RESOLVED (integration lead, wave 1)
# ---------------------------------------------------------------------------
# architecture.md §2.8 calls the Control Plane Service "the single authoritative
# writer for membership, revocation, policy, and relay-fleet registry", while
# §2.12 says the Relay-Selection Service owns "the relay-fleet registry and
# ranking (authoritative)". Both cannot be the single writer of one fact under
# I8, so one of them is wrong.
#
# The tiebreak is that architecture.md names its OWN authority for exactly this
# question: the state ownership table in §5, which "names a single authoritative
# writer for every persistent fact". §5 row S-09 reads:
#
#     S-09 | `Relay` fleet registry + ranking | Relay-Selection Service (2.12)
#
# REGISTRY AND RANKING TOGETHER, to 2.12. §2.8's sentence is a prose error, and
# an earlier revision of this file guessed the opposite way - it split registry
# into `twinvpn_control` and left ranking here, which would have put two writers
# on one row of §5 in the one place a local topology makes that look normal.
#
# So:
#   twinvpn_relay_directory   S-09 - the fleet registry AND the ranking, plus
#                             the aggregated HealthState ADR-0006 §11.2 scores
#   twinvpn_control           S-30 - the `RelayCapabilityToken` issuance record,
#                             which §5 DOES assign to the Control Plane (2.8)
#                             and ADR-0005 §11.3 makes the relay verify OFFLINE
#
# S-30 living apart from S-09 is not an inconsistency; it is the whole point.
# The issuance record is control-plane state, and the relay never reads it - it
# verifies an Owner-rooted token against a signed issuer key set with no
# control-plane call, which is what makes relay admission survive a partition of
# any duration (architecture.md A-12, testing-strategy A-13).

set -euo pipefail

extra="${TWINVPN_PG_EXTRA_DATABASES:-}"
if [ -z "${extra}" ]; then
  echo "initdb: TWINVPN_PG_EXTRA_DATABASES is empty; nothing to create"
  exit 0
fi

IFS=',' read -r -a databases <<< "${extra}"

for db in "${databases[@]}"; do
  db="$(echo "${db}" | tr -d '[:space:]')"
  [ -n "${db}" ] || continue

  # Reject anything that is not a plain identifier. This runs as the superuser
  # against a value that arrives from the environment, so it is an untrusted
  # input at a boundary and is validated before use (CLAUDE.md, ownership.md
  # rule 9) rather than interpolated hopefully.
  case "${db}" in
    *[!a-z0-9_]*)
      echo "initdb: refusing database name '${db}' - lowercase, digits and underscore only" >&2
      exit 1
      ;;
  esac

  echo "initdb: creating database ${db}"
  psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<-SQL
	CREATE DATABASE "${db}" OWNER "${POSTGRES_USER}" ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
SQL
done

echo "initdb: done"
