#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

MAX_AGE_SECONDS = 900
MIN_JIT_REMAINING_SECONDS = 300
RATIFICATION = "82e5b8e6642d1475ebcee9183b401b1fd010e63b"
PDC_ID = "GALIA-GRAFANA-PDC-OFFICIAL-BINDING-CONTRACT-CANDIDATE-v0.11"
PDC_HEAD = "ce4d638f11d5e63461ec5a2bd99155146c806ec4"
PDC_SET = "ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc"
SUPABASE_HOST = "db.nzoviwitcqmsacwiizhh.supabase.co"
FORBIDDEN_KEYS = {
    "token", "access_token", "password", "secret", "authorization",
    "primary_email", "email", "ca_pem", "private_key", "pat_value",
    "signing_token", "service_account_token"
}

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

def require_exact_keys(value, allowed, name):
    if not isinstance(value, dict):
        fail(f"{name} must be an object")
    actual = set(value)
    expected = set(allowed)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        fail(f"{name} shape mismatch; missing={missing}; extra={extra}")

def require_true(value, name):
    if value is not True:
        fail(f"{name} must be true")

def require_nonempty(value, name):
    if value is None or isinstance(value, bool):
        fail(f"{name} must be non-empty")
    if isinstance(value, str) and not value.strip():
        fail(f"{name} must be non-empty")
    return value

def parse_time(value):
    if not isinstance(value, str):
        fail("observed_at_utc must be an ISO-8601 string")
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        fail("observed_at_utc must be valid ISO-8601")
    if dt.tzinfo is None:
        fail("observed_at_utc must be timezone-aware")
    return dt.astimezone(timezone.utc)

def require_uuid(value, name):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError):
        fail(f"{name} must be UUID")
    if parsed.int == 0:
        fail(f"{name} must not be nil UUID")

def validate(packet):
    reject_forbidden(packet)
    require_exact_keys(packet, {
        "schema_version", "receipt_type", "observed_at_utc", "authority",
        "profile", "grafana", "credentials", "network", "supabase",
        "secret_material_persisted",
    }, "root")

    if packet.get("schema_version") != 1:
        fail("schema_version must equal 1")
    if packet.get("receipt_type") != "GALIA_GRAFANA_EXTERNAL_FACT_PACKET":
        fail("receipt_type mismatch")

    observed = parse_time(packet.get("observed_at_utc"))
    age = (datetime.now(timezone.utc) - observed).total_seconds()
    if age < -60:
        fail("observation timestamp is implausibly in the future")
    if age > MAX_AGE_SECONDS:
        fail("external fact packet is stale")

    authority = packet.get("authority") or {}
    require_exact_keys(authority, {
        "ratification_merge", "pdc_contract_candidate_id",
        "pdc_contract_head", "pdc_contract_candidate_set_sha256",
    }, "authority")
    if authority.get("ratification_merge") != RATIFICATION:
        fail("ratification merge mismatch")
    if authority.get("pdc_contract_candidate_id") != PDC_ID:
        fail("PDC contract candidate id mismatch")
    if authority.get("pdc_contract_head") != PDC_HEAD:
        fail("PDC contract head mismatch")
    if authority.get("pdc_contract_candidate_set_sha256") != PDC_SET:
        fail("PDC contract candidate-set mismatch")

    if packet.get("profile") != "GRAFANA_CLOUD_PDC_IPV6":
        fail("only GRAFANA_CLOUD_PDC_IPV6 is supported by v0.13")

    grafana = packet.get("grafana") or {}
    require_exact_keys(grafana, {"stack_url", "stack_id", "pdc_network"}, "grafana")
    parsed_url = urlparse(grafana.get("stack_url", ""))
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        fail("grafana.stack_url must be a valid https URL")
    require_nonempty(grafana.get("stack_id"), "grafana.stack_id")
    pdc = grafana.get("pdc_network") or {}
    require_exact_keys(pdc, {
        "id", "name", "region", "status", "discovery_source",
        "connected_agents_count",
    }, "grafana.pdc_network")
    for key in ("id", "name", "region", "status"):
        require_nonempty(pdc.get(key), f"grafana.pdc_network.{key}")
    if pdc.get("discovery_source") != "GRAFANA_CLOUD_OFFICIAL_SURFACE":
        fail("PDC network must come from an official Grafana Cloud surface")
    if not isinstance(pdc.get("connected_agents_count"), int) or pdc["connected_agents_count"] < 1:
        fail("connected_agents_count must be >= 1")

    creds = packet.get("credentials") or {}
    require_exact_keys(creds, {
        "grafana_cloud_access_policy_credential_available",
        "grafana_stack_service_account_credential_available",
        "pdc_agent_signing_credential_available",
        "supabase_service_pat_available",
        "credential_domains_distinct_verified",
    }, "credentials")
    for key in (
        "grafana_cloud_access_policy_credential_available",
        "grafana_stack_service_account_credential_available",
        "pdc_agent_signing_credential_available",
        "supabase_service_pat_available",
        "credential_domains_distinct_verified",
    ):
        require_true(creds.get(key), f"credentials.{key}")

    network = packet.get("network") or {}
    require_exact_keys(network, {
        "pdc_agent_ipv6_egress_cidrs", "supabase_host", "supabase_port",
        "route_verified", "permit_remote_open",
    }, "network")
    cidrs = network.get("pdc_agent_ipv6_egress_cidrs")
    if not isinstance(cidrs, list) or not cidrs:
        fail("pdc_agent_ipv6_egress_cidrs must be non-empty")
    normalized = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            fail(f"invalid PDC IPv6 egress CIDR: {cidr}")
        if net.version != 6:
            fail("PDC egress CIDRs must be IPv6")
        if net.is_private or net.is_loopback or net.is_link_local:
            fail("PDC egress CIDR must be externally routable evidence")
        normalized.append(str(net))
    network["pdc_agent_ipv6_egress_cidrs"] = normalized
    if network.get("supabase_host") != SUPABASE_HOST:
        fail("Supabase host mismatch")
    if network.get("supabase_port") != 5432:
        fail("Supabase port mismatch")
    require_true(network.get("route_verified"), "network.route_verified")
    if network.get("permit_remote_open") != f"{SUPABASE_HOST}:5432":
        fail("PermitRemoteOpen is not constrained to the exact Supabase endpoint")

    supabase = packet.get("supabase") or {}
    require_exact_keys(supabase, {
        "ssl_enforcement_enabled", "temporary_access_enabled",
        "jit_mapping_verified", "jit_expires_at", "role", "gotrue_id",
        "service_pat_identity_binding_verified", "server_root_ca_sha256",
    }, "supabase")
    require_true(supabase.get("ssl_enforcement_enabled"), "supabase.ssl_enforcement_enabled")
    require_true(supabase.get("temporary_access_enabled"), "supabase.temporary_access_enabled")
    require_true(supabase.get("jit_mapping_verified"), "supabase.jit_mapping_verified")
    if supabase.get("role") != "galia_grafana_ro":
        fail("Supabase JIT role mismatch")
    require_uuid(supabase.get("gotrue_id"), "supabase.gotrue_id")
    require_true(
        supabase.get("service_pat_identity_binding_verified"),
        "supabase.service_pat_identity_binding_verified",
    )
    expires = supabase.get("jit_expires_at")
    if not isinstance(expires, int):
        fail("supabase.jit_expires_at must be Unix seconds")
    if expires - int(time.time()) < MIN_JIT_REMAINING_SECONDS:
        fail("JIT mapping has insufficient remaining lifetime")
    ca_sha = supabase.get("server_root_ca_sha256")
    if not isinstance(ca_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", ca_sha):
        fail("server_root_ca_sha256 must be lowercase 64-hex")

    if packet.get("secret_material_persisted") is not False:
        fail("secret_material_persisted must be false")

    return {
        "eligibility": "FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE",
        "live_execution_authorized": False,
        "future_human_decision_required": True,
        "profile": packet["profile"],
        "stack_id": grafana["stack_id"],
        "pdc_network_id": pdc["id"],
        "connected_agents_count": pdc["connected_agents_count"],
        "verified_ipv6_egress_cidrs": normalized,
        "jit_expires_at": expires,
        "server_root_ca_sha256": ca_sha,
        "secret_material_persisted": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", required=True)
    args = parser.parse_args()
    packet = json.loads(Path(args.packet).read_text())
    result = validate(packet)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
