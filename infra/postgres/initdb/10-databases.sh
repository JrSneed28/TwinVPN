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
# AN OWNERSHIP AMBIGUITY, REPORTED NOT RESOLVED
# ---------------------------------------------------------------------------
# architecture.md §2.8 makes the Control Plane Service "the single authoritative
# writer for membership, revocation, policy, AND RELAY-FLEET REGISTRY", while
# §2.12 says the Relay-Selection Service owns "the relay-fleet registry and
# ranking (authoritative)". Both cannot be the single writer of the same state
# under I8.
#
# The split taken here reads them as registry-vs-ranking: `twinvpn_control`
# holds the fleet REGISTRY (which relays exist, who operates them),
# `twinvpn_relay_directory` holds the RANKING and aggregated HealthState that
# ADR-0006 §11.2 computes. That is a reading, not a ruling, and the integration
# lead has been asked to disposition it.

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
