#!/usr/bin/env python3
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

PROJECT_REF = "nzoviwitcqmsacwiizhh"
ACTIVATION_ID = "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5"
ACTIVATION_HEAD = "96c468c7f37750620a05e62532f36121569b9877"
ACTIVATION_SET = "20feda3c06beb0464d06067680ee340bda921e7a2a12226c1af6f337500f2f3d"
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
FORBIDDEN_RECEIPT_KEYS = {
    "email",
    "primary_email",
    "token",
    "access_token",
    "password",
    "pat",
    "pat_value",
    "scoped_pat",
    "scoped_pat_value",
}
ALLOWED_PROFILES = {"SELF_HOSTED_IPV6", "GRAFANA_CLOUD_PDC_IPV6"}

def fail(message: str) -> None:
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
        lowered = value.lower()
        if "sbp_" in lowered:
            fail(f"receipt contains PAT-like material at {path}")
        if "-----begin certificate-----" in lowered:
            fail(f"receipt contains CA PEM instead of fingerprint at {path}")

def require_true(receipt: dict, key: str):
    if receipt.get(key) is not True:
        fail(f"activation receipt requires {key}=true")

def validate_receipt(receipt: dict, pdc_enabled: bool, ca_cert: str):
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
        "credential_mode": "TEMPORARY_ACCESS_JIT_DIRECT",
        "postgres_role": ROLE,
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

    for key in (
        "activation_complete",
        "service_pat_belongs_to_gotrue_id_verified",
        "scoped_pat_available",
        "ssl_enforcement_enabled",
        "temporary_access_enabled",
        "jit_mapping_verified",
        "direct_ipv6_reachability_verified",
        "direct_verify_full_connection_passed",
    ):
        require_true(receipt, key)

    if receipt.get("secret_material_persisted") is not False:
        fail("activation receipt must assert secret_material_persisted=false")
    if receipt.get("primary_email_persisted") is not False:
        fail("activation receipt must assert primary_email_persisted=false")

    profile = receipt.get("network_profile")
    if profile not in ALLOWED_PROFILES:
        fail("activation receipt network_profile unsupported")
    expected_profile = "GRAFANA_CLOUD_PDC_IPV6" if pdc_enabled else "SELF_HOSTED_IPV6"
    if profile != expected_profile:
        fail("activation receipt network_profile does not match GALIA_GRAFANA_PDC_ENABLED")
    if profile == "GRAFANA_CLOUD_PDC_IPV6":
        require_true(receipt, "pdc_agent_network_verified")
    elif receipt.get("pdc_agent_network_verified") is not False:
        fail("SELF_HOSTED_IPV6 receipt must have pdc_agent_network_verified=false")

    cidrs = receipt.get("source_cidrs")
    if not isinstance(cidrs, list) or not cidrs:
        fail("activation receipt source_cidrs must be a non-empty list")
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

    return profile, str(parsed), expected_ca_hash

def main() -> int:
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
    if not pat.startswith("sbp_fc"):
        fail("credential is not a Supabase Scoped PAT")
    if len(pat) < 20:
        fail("credential shape is implausibly short")

    ca_cert = os.environ["GALIA_GRAFANA_TLS_CA_CERT"]
    if "-----BEGIN CERTIFICATE-----" not in ca_cert or "-----END CERTIFICATE-----" not in ca_cert:
        fail("GALIA_GRAFANA_TLS_CA_CERT is not PEM certificate content")

    receipt_path = Path(os.environ["GALIA_GRAFANA_ACTIVATION_RECEIPT_PATH"])
    if not receipt_path.is_file():
        fail("activation receipt path is not a file")
    receipt = json.loads(receipt_path.read_text())
    profile, gotrue_id, ca_hash = validate_receipt(receipt, pdc_enabled, ca_cert)

    print("PASS: datasource environment and activation receipt valid")
    print(f"network_profile={profile}")
    print(f"gotrue_id={gotrue_id}")
    print(f"server_root_ca_sha256={ca_hash}")
    print("credential=REDACTED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
