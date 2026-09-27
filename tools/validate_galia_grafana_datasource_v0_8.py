#!/usr/bin/env python3
import hashlib, ipaddress, json, os, re, sys, time, uuid
from pathlib import Path

PROJECT_REF = "nzoviwitcqmsacwiizhh"
ACTIVATION_ID = "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.6"
ACTIVATION_HEAD = "d0c71aaf76333a7f6b8542e2b48b01cfa0ad6654"
ACTIVATION_SET = "1b0d25ca98a59182ade20d868f371655c7bd86d625d9c8dbd1961f896d5d73c2"
ROLE = "galia_grafana_ro"
EXPECTED = {
    "GALIA_GRAFANA_DB_HOST": "db.nzoviwitcqmsacwiizhh.supabase.co",
    "GALIA_GRAFANA_DB_PORT": "5432",
    "GALIA_GRAFANA_DB_USER": ROLE,
    "GALIA_GRAFANA_DB_NAME": "postgres",
}
REQUIRED = tuple(EXPECTED) + (
    "GALIA_GRAFANA_PDC_ENABLED",
    "GALIA_GRAFANA_SCOPED_PAT",
    "GALIA_GRAFANA_TLS_CA_CERT",
    "GALIA_GRAFANA_ACTIVATION_RECEIPT_PATH",
)
FORBIDDEN_RECEIPT_KEYS = {"email","primary_email","token","access_token","password","pat","pat_value","scoped_pat","scoped_pat_value"}

def fail(message):
    raise SystemExit(f"FAIL_CLOSED: {message}")

def reject_receipt_secrets(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_RECEIPT_KEYS:
                fail(f"forbidden secret-bearing receipt field at {path}.{key}")
            reject_receipt_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            reject_receipt_secrets(child, f"{path}[{i}]")
    elif isinstance(value, str):
        lower = value.lower()
        if "sbp_" in lower:
            fail(f"receipt contains PAT-like material at {path}")
        if "-----begin certificate-----" in lower:
            fail(f"receipt contains CA PEM instead of fingerprint at {path}")

def require_true(receipt, key):
    if receipt.get(key) is not True:
        fail(f"activation receipt requires {key}=true")

def validate_receipt(receipt, pdc_enabled, ca_cert):
    if not isinstance(receipt, dict):
        fail("activation receipt root must be an object")
    reject_receipt_secrets(receipt)
    exact = {
        "schema_version": 1,
        "receipt_type": "GALIA_GRAFANA_JIT_ACTIVATION_RECEIPT",
        "project_ref": PROJECT_REF,
        "activation_contract_candidate_id": ACTIVATION_ID,
        "activation_contract_head": ACTIVATION_HEAD,
        "activation_contract_candidate_set_sha256": ACTIVATION_SET,
        "activation_complete": True,
        "credential_mode": "TEMPORARY_ACCESS_JIT_DIRECT",
        "postgres_role": ROLE,
        "service_pat_belongs_to_gotrue_id_verified": True,
        "scoped_pat_available": True,
        "ssl_enforcement_enabled": True,
        "temporary_access_enabled": True,
        "jit_mapping_verified": True,
        "verify_full_connection_passed": True,
        "secret_material_persisted": False,
        "primary_email_persisted": False,
    }
    for key, expected in exact.items():
        if receipt.get(key) != expected:
            fail(f"activation receipt {key} mismatch")

    try:
        parsed = uuid.UUID(receipt.get("gotrue_id", ""))
    except ValueError:
        fail("activation receipt gotrue_id must be UUID")
    if parsed.int == 0:
        fail("activation receipt gotrue_id must not be nil UUID")

    profile = receipt.get("network_profile")
    expected_profile = "GRAFANA_CLOUD_PDC_IPV6" if pdc_enabled else "SELF_HOSTED_IPV6"
    if profile != expected_profile:
        fail("activation receipt network_profile does not match GALIA_GRAFANA_PDC_ENABLED")

    self_hosted = receipt.get("self_hosted_direct_ipv6_reachability_verified")
    pdc = receipt.get("pdc_agent_ipv6_reachability_verified")
    route_method = receipt.get("route_verification_method")
    tls_method = receipt.get("tls_verification_method")
    if not isinstance(self_hosted, bool) or not isinstance(pdc, bool):
        fail("profile route booleans must be boolean")
    if profile == "SELF_HOSTED_IPV6":
        if (self_hosted, pdc, route_method, tls_method) != (True, False, "SELF_HOSTED_DIRECT_IPV6", "SELF_HOSTED_PSQL_VERIFY_FULL"):
            fail("SELF_HOSTED_IPV6 receipt evidence mismatch")
    elif profile == "GRAFANA_CLOUD_PDC_IPV6":
        if (self_hosted, pdc, route_method, tls_method) != (False, True, "PDC_AGENT_IPV6", "GRAFANA_PDC_SAVE_AND_TEST_VERIFY_FULL"):
            fail("GRAFANA_CLOUD_PDC_IPV6 receipt evidence mismatch")
    else:
        fail("activation receipt network_profile unsupported")

    cidrs = receipt.get("source_cidrs")
    if not isinstance(cidrs, list) or not cidrs:
        fail("activation receipt source_cidrs must be non-empty")
    versions = set()
    for raw in cidrs:
        if not isinstance(raw, str):
            fail("activation receipt source_cidrs entries must be strings")
        try:
            versions.add(ipaddress.ip_network(raw, strict=False).version)
        except ValueError:
            fail(f"invalid activation receipt CIDR: {raw}")
    if 6 not in versions:
        fail("activation receipt must include verified IPv6 egress CIDR")

    expires_at = receipt.get("expires_at")
    if not isinstance(expires_at, int):
        fail("activation receipt expires_at must be Unix seconds integer")
    if expires_at <= int(time.time()):
        fail("activation receipt JIT mapping is expired")

    expected_ca_hash = receipt.get("server_root_ca_sha256")
    if not isinstance(expected_ca_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_ca_hash):
        fail("activation receipt server_root_ca_sha256 invalid")
    actual_ca_hash = hashlib.sha256(ca_cert.encode()).hexdigest()
    if actual_ca_hash != expected_ca_hash:
        fail("GALIA_GRAFANA_TLS_CA_CERT fingerprint does not match activation receipt")
    return profile, str(parsed), expected_ca_hash, route_method, tls_method

def main():
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        fail("missing required environment variables: " + ", ".join(missing))
    for name, expected in EXPECTED.items():
        if os.environ[name] != expected:
            fail(f"{name} does not match canonical value")
    pdc_raw = os.environ["GALIA_GRAFANA_PDC_ENABLED"].lower()
    if pdc_raw not in {"true", "false"}:
        fail("GALIA_GRAFANA_PDC_ENABLED must be true or false")
    pdc_enabled = pdc_raw == "true"

    pat = os.environ["GALIA_GRAFANA_SCOPED_PAT"]
    if not pat.startswith("sbp_fc") or len(pat) < 20:
        fail("credential is not a plausible Supabase Scoped PAT")
    ca_cert = os.environ["GALIA_GRAFANA_TLS_CA_CERT"]
    if "-----BEGIN CERTIFICATE-----" not in ca_cert or "-----END CERTIFICATE-----" not in ca_cert:
        fail("GALIA_GRAFANA_TLS_CA_CERT is not PEM certificate content")
    receipt_path = Path(os.environ["GALIA_GRAFANA_ACTIVATION_RECEIPT_PATH"])
    if not receipt_path.is_file():
        fail("activation receipt path is not a file")
    receipt = json.loads(receipt_path.read_text())
    profile, gotrue_id, ca_hash, route_method, tls_method = validate_receipt(receipt, pdc_enabled, ca_cert)
    print("PASS: datasource v0.8 environment and activation receipt valid")
    print(f"network_profile={profile}")
    print(f"route_verification_method={route_method}")
    print(f"tls_verification_method={tls_method}")
    print(f"gotrue_id={gotrue_id}")
    print(f"server_root_ca_sha256={ca_hash}")
    print("credential=REDACTED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
