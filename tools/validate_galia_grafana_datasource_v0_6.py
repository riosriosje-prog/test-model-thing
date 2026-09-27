#!/usr/bin/env python3
import os
import sys

EXPECTED = {
    "GALIA_GRAFANA_DB_HOST": "db.nzoviwitcqmsacwiizhh.supabase.co",
    "GALIA_GRAFANA_DB_PORT": "5432",
    "GALIA_GRAFANA_DB_USER": "galia_grafana_ro",
    "GALIA_GRAFANA_DB_NAME": "postgres",
}
REQUIRED = tuple(EXPECTED) + ("GALIA_GRAFANA_PDC_ENABLED", "GALIA_GRAFANA_SCOPED_PAT", "GALIA_GRAFANA_TLS_CA_CERT")


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
    if not secret.startswith("sbp_fc"):
        fail("credential is not a Supabase Scoped PAT (expected sbp_fc prefix)")

    if len(secret) < 20:
        fail("credential shape is implausibly short")

    ca_cert = os.environ["GALIA_GRAFANA_TLS_CA_CERT"]
    if "-----BEGIN CERTIFICATE-----" not in ca_cert or "-----END CERTIFICATE-----" not in ca_cert:
        fail("GALIA_GRAFANA_TLS_CA_CERT is not a PEM certificate")

    print("PASS: datasource environment contract valid; secret redacted; CA present")
    print(f"network_profile={'GRAFANA_CLOUD_PDC_IPV6' if pdc == 'true' else 'SELF_HOSTED_IPV6'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
