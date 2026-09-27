#!/usr/bin/env python3
import os
import sys

EXPECTED = {
    "GALIA_GRAFANA_DB_HOST": "db.nzoviwitcqmsacwiizhh.supabase.co",
    "GALIA_GRAFANA_DB_PORT": "5432",
    "GALIA_GRAFANA_DB_USER": "galia_grafana_ro",
    "GALIA_GRAFANA_DB_NAME": "postgres",
}
REQUIRED = tuple(EXPECTED) + ("GALIA_GRAFANA_PDC_ENABLED", "GALIA_GRAFANA_SCOPED_PAT")


def fail(message: str) -> None:
    raise SystemExit(f"FAIL_CLOSED: {message}")


def main() -> int:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        fail("missing required environment variables: " + ", ".join(missing))

    for name, expected in EXPECTED.items():
        if os.environ[name] != expected:
            fail(f"{name} does not match canonical value")

    pdc = os.environ["GALIA_GRAFANA_PDC_ENABLED"].lower()
    if pdc not in {"true", "false"}:
        fail("GALIA_GRAFANA_PDC_ENABLED must be true or false")

    secret = os.environ["GALIA_GRAFANA_SCOPED_PAT"]
    if not secret.startswith("sbp_"):
        fail("credential does not have expected Supabase PAT prefix")

    if len(secret) < 20:
        fail("credential shape is implausibly short")

    print("PASS: datasource environment contract valid; secret redacted")
    print(f"network_profile={'GRAFANA_CLOUD_PDC_IPV6' if pdc == 'true' else 'SELF_HOSTED_IPV6'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
