#!/usr/bin/env bash
set -euo pipefail

: "${GALIA_GRAFANA_DB_HOST:?missing GALIA_GRAFANA_DB_HOST}"
: "${GALIA_GRAFANA_DB_PORT:?missing GALIA_GRAFANA_DB_PORT}"
: "${GALIA_GRAFANA_DB_USER:?missing GALIA_GRAFANA_DB_USER}"
: "${GALIA_GRAFANA_DB_NAME:?missing GALIA_GRAFANA_DB_NAME}"
: "${GALIA_GRAFANA_SCOPED_PAT:?missing GALIA_GRAFANA_SCOPED_PAT}"
: "${GALIA_GRAFANA_TLS_CA_CERT:?missing GALIA_GRAFANA_TLS_CA_CERT}"

if [[ "$GALIA_GRAFANA_DB_HOST" != "db.nzoviwitcqmsacwiizhh.supabase.co" ]]; then
  echo "FAIL_CLOSED: unexpected database host" >&2
  exit 1
fi
if [[ "$GALIA_GRAFANA_DB_PORT" != "5432" ]]; then
  echo "FAIL_CLOSED: unexpected database port" >&2
  exit 1
fi
if [[ "$GALIA_GRAFANA_DB_USER" != "galia_grafana_ro" ]]; then
  echo "FAIL_CLOSED: unexpected database role" >&2
  exit 1
fi
if [[ "$GALIA_GRAFANA_DB_NAME" != "postgres" ]]; then
  echo "FAIL_CLOSED: unexpected database name" >&2
  exit 1
fi
if [[ "$GALIA_GRAFANA_SCOPED_PAT" != sbp_fc* ]]; then
  echo "FAIL_CLOSED: credential is not a Scoped PAT" >&2
  exit 1
fi

CA_FILE="$(mktemp)"
trap 'rm -f "$CA_FILE"; unset PGPASSWORD PGSSLROOTCERT' EXIT
printf '%s\n' "$GALIA_GRAFANA_TLS_CA_CERT" > "$CA_FILE"
chmod 600 "$CA_FILE"

export PGPASSWORD="$GALIA_GRAFANA_SCOPED_PAT"
export PGSSLMODE=verify-full
export PGSSLROOTCERT="$CA_FILE"

PSQL=(psql
  --no-password
  --set=ON_ERROR_STOP=1
  --host="$GALIA_GRAFANA_DB_HOST"
  --port="$GALIA_GRAFANA_DB_PORT"
  --username="$GALIA_GRAFANA_DB_USER"
  --dbname="$GALIA_GRAFANA_DB_NAME"
)

"${PSQL[@]}" --file="grafana/acceptance/galia_cangrejos_postgres_acceptance.v0_6.sql" >/dev/null

if "${PSQL[@]}" --command="select * from canonical.sources limit 0;" >/dev/null 2>&1; then
  echo "FAIL_CLOSED: canonical.sources unexpectedly readable" >&2
  exit 1
fi

if "${PSQL[@]}" --command="begin; create table public.__galia_grafana_write_probe(id integer); rollback;" >/dev/null 2>&1; then
  echo "FAIL_CLOSED: permanent write unexpectedly succeeded" >&2
  exit 1
fi

unset PGPASSWORD PGSSLROOTCERT
echo "PASS: Grafana runtime acceptance succeeded with verify-full; credential redacted"
