#!/usr/bin/env python3
import argparse
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
CANDIDATE_ID = "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5"
CANDIDATE_HEAD = "96c468c7f37750620a05e62532f36121569b9877"
CANDIDATE_SET = "20feda3c06beb0464d06067680ee340bda921e7a2a12226c1af6f337500f2f3d"
FORBIDDEN_KEYS = {
    "email", "primary_email", "token", "access_token", "password",
    "pat", "pat_value", "token_hash", "authorization",
}
ALLOWED_PROFILES = {"SELF_HOSTED_IPV6", "GRAFANA_CLOUD_PDC_IPV6"}

def fail(message: str) -> None:
    raise SystemExit(f"FAIL_CLOSED: {message}")

def reject_forbidden(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                fail(f"forbidden secret/identity field at {path}.{key}")
            reject_forbidden(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            reject_forbidden(child, f"{path}[{i}]")

def require_true(value, name):
    if value is not True:
        fail(f"{name} must be true")

def require_uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError):
        fail(f"{name} must be UUID")
    if parsed.int == 0:
        fail(f"{name} must not be nil UUID")

def normalized_cidrs(values):
    if not isinstance(values, list) or not values:
        fail("verified_egress_cidrs must be non-empty list")
    out=[]
    versions=set()
    for value in values:
        try:
            network=ipaddress.ip_network(value, strict=False)
        except ValueError:
            fail(f"invalid verified egress CIDR: {value}")
        out.append(str(network))
        versions.add(network.version)
    if 6 not in versions:
        fail("verified egress CIDRs must include IPv6 for current Free-plan route")
    return out

def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--ca-pem-env", required=True)
    parser.add_argument("--pdc-enabled", required=True, choices=["true","false"])
    args=parser.parse_args()

    receipt=json.loads(Path(args.receipt).read_text())
    reject_forbidden(receipt)

    if receipt.get("schema_version") != 1:
        fail("schema_version must equal 1")
    if receipt.get("project_ref") != PROJECT_REF:
        fail("project_ref mismatch")
    activation=receipt.get("activation_candidate") or {}
    if activation.get("candidate_id") != CANDIDATE_ID:
        fail("activation candidate id mismatch")
    if activation.get("candidate_head") != CANDIDATE_HEAD:
        fail("activation candidate head mismatch")
    if activation.get("candidate_set_sha256") != CANDIDATE_SET:
        fail("activation candidate-set mismatch")

    require_true(receipt.get("ssl_enforcement_verified"), "ssl_enforcement_verified")
    if receipt.get("project_status") != "ACTIVE_HEALTHY":
        fail("project_status must be ACTIVE_HEALTHY")
    require_true(receipt.get("temporary_access_enabled"), "temporary_access_enabled")
    require_uuid(receipt.get("gotrue_id"), "gotrue_id")
    require_true(
        receipt.get("service_pat_identity_binding_verified"),
        "service_pat_identity_binding_verified",
    )

    profile=receipt.get("network_profile")
    if profile not in ALLOWED_PROFILES:
        fail("network_profile is not allowed")
    normalized_cidrs(receipt.get("verified_egress_cidrs"))

    if args.pdc_enabled == "true" and profile != "GRAFANA_CLOUD_PDC_IPV6":
        fail("PDC enabled but activation receipt is not PDC profile")
    if args.pdc_enabled == "false" and profile != "SELF_HOSTED_IPV6":
        fail("PDC disabled but activation receipt is not self-hosted profile")

    if receipt.get("jit_mapping_method") not in {"POST","PUT"}:
        fail("jit_mapping_method must be POST or PUT")
    require_true(receipt.get("jit_mapping_verified"), "jit_mapping_verified")
    expires=receipt.get("expires_at")
    if not isinstance(expires, int) or expires <= int(time.time()):
        fail("expires_at must be future Unix seconds")
    require_true(
        receipt.get("direct_verify_full_connection_passed"),
        "direct_verify_full_connection_passed",
    )

    ca_pem=os.environ.get(args.ca_pem_env, "")
    if "-----BEGIN CERTIFICATE-----" not in ca_pem or "-----END CERTIFICATE-----" not in ca_pem:
        fail("CA PEM environment variable is missing or malformed")
    actual_ca_sha=hashlib.sha256(ca_pem.encode()).hexdigest()
    expected_ca_sha=receipt.get("server_root_ca_sha256")
    if not isinstance(expected_ca_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_ca_sha):
        fail("server_root_ca_sha256 must be lowercase 64-hex")
    if actual_ca_sha != expected_ca_sha:
        fail("CA PEM SHA-256 does not match activation receipt")

    print("PASS: activation receipt verified; no secret material emitted")
    return 0

if __name__ == "__main__":
    sys.exit(main())
