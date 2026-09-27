#!/usr/bin/env bash
set -euo pipefail

python3 tools/validate_galia_grafana_datasource_v0_7.py >/dev/null

if [[ "${GALIA_GRAFANA_PDC_ENABLED,,}" == "true" ]]; then
  echo "FAIL_CLOSED: local psql cannot validate a Grafana Cloud PDC route; use Grafana Save & test and datasource queries" >&2
  exit 2
fi

CA_FILE="$(mktemp)"
trap 'rm -f "$CA_FILE"; unset PGPASSWORD PGSSLROOTCERT PGAPPNAME' EXIT
printf '%s\n' "$GALIA_GRAFANA_TLS_CA_CERT" > "$CA_FILE"
chmod 600 "$CA_FILE"

export PGPASSWORD="$GALIA_GRAFANA_SCOPED_PAT"
export PGSSLMODE=verify-full
export PGSSLROOTCERT="$CA_FILE"
export PGAPPNAME="galia-grafana-acceptance-v0.7"

PSQL=(psql
  --no-password
  --set=ON_ERROR_STOP=1
  --host="$GALIA_GRAFANA_DB_HOST"
  --port="$GALIA_GRAFANA_DB_PORT"
  --username="$GALIA_GRAFANA_DB_USER"
  --dbname="$GALIA_GRAFANA_DB_NAME"
)

"${PSQL[@]}" --file="grafana/acceptance/galia_cangrejos_postgres_acceptance.v0_7.sql" >/dev/null

if "${PSQL[@]}" --command="select * from canonical.sources limit 0;" >/dev/null 2>&1; then
  echo "FAIL_CLOSED: canonical.sources unexpectedly readable" >&2
  exit 1
fi

if "${PSQL[@]}" --command="create table public.__galia_grafana_write_probe(id integer);" >/dev/null 2>&1; then
  "${PSQL[@]}" --command="drop table if exists public.__galia_grafana_write_probe;" >/dev/null 2>&1 || true
  echo "FAIL_CLOSED: permanent write unexpectedly succeeded" >&2
  exit 1
fi

echo "PASS: self-hosted Grafana runtime acceptance succeeded with verify-full; credential redacted"
