#!/usr/bin/env python3
import argparse, ipaddress, json, re, sys, time, uuid
from pathlib import Path

PROJECT_REF = "nzoviwitcqmsacwiizhh"
CANONICAL_TEMP_ENDPOINT = "/v1/projects/{ref}/jit-access"
QUARANTINED_GUIDE_ALIAS = "/v1/projects/{ref}/database/jit-access"
ALLOWED_IDENTITY_SOURCES = {"DASHBOARD_TEMPORARY_ACCESS_UI", "ORGANIZATION_MEMBER_GOTRUE_ID_VERIFIED"}
ALLOWED_PROFILES = {"SELF_HOSTED_IPV6", "GRAFANA_CLOUD_PDC_IPV6"}
FORBIDDEN_KEYS = {"email","primary_email","token","access_token","password","pat_value","scoped_pat_value","authorization"}

def fail(message):
    raise SystemExit(f"FAIL_CLOSED: {message}")

def reject_forbidden_keys(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_KEYS:
                fail(f"forbidden field at {path}.{key}")
            reject_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            reject_forbidden_keys(child, f"{path}[{i}]")

def require_bool(value, name):
    if not isinstance(value, bool):
        fail(f"{name} must be boolean")
    return value

def require_uuid(value, name):
    if not isinstance(value, str):
        fail(f"{name} must be UUID string")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        fail(f"{name} must be UUID string")
    if parsed.int == 0:
        fail(f"{name} must not be nil UUID")
    return str(parsed)

def require_cidrs(values):
    if not isinstance(values, list) or not values:
        fail("network.source_cidrs must be a non-empty list")
    normalized, versions = [], set()
    for value in values:
        if not isinstance(value, str):
            fail("network.source_cidrs entries must be strings")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            fail(f"invalid source CIDR: {value}")
        normalized.append(str(network))
        versions.add(network.version)
    if 6 not in versions:
        fail("selected profile requires at least one verified IPv6 egress CIDR")
    return normalized

def validate(observation):
    if not isinstance(observation, dict):
        fail("observation root must be an object")
    reject_forbidden_keys(observation)
    if observation.get("schema_version") != 1:
        fail("schema_version must equal 1")
    if observation.get("project_ref") != PROJECT_REF:
        fail("project_ref mismatch")
    if observation.get("supabase_plan") != "Free":
        fail("supabase_plan must match current Free plan snapshot")
    if observation.get("project_status") != "ACTIVE_HEALTHY":
        fail("project_status must be ACTIVE_HEALTHY")

    ssl = observation.get("ssl")
    if not isinstance(ssl, dict):
        fail("ssl object required")
    require_bool(ssl.get("current"), "ssl.current")
    ca = ssl.get("server_root_ca")
    if not isinstance(ca, dict):
        fail("ssl.server_root_ca object required")
    if ca.get("source") != "SUPABASE_DASHBOARD_DATABASE_SETTINGS_SERVER_ROOT_CERTIFICATE":
        fail("server root CA source is not canonical")
    if not isinstance(ca.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", ca["sha256"]):
        fail("server root CA sha256 must be lowercase 64-hex")
    if ca.get("pem_stored_in_repository") is not False:
        fail("server root CA PEM must remain out of repository")

    temp = observation.get("temporary_access")
    if not isinstance(temp, dict):
        fail("temporary_access object required")
    if temp.get("current") not in {"enabled", "disabled"}:
        fail("temporary_access.current must be enabled or disabled")
    if temp.get("canonical_endpoint") != CANONICAL_TEMP_ENDPOINT:
        fail("temporary access canonical endpoint mismatch")
    if temp.get("guide_alias_quarantined") != QUARANTINED_GUIDE_ALIAS:
        fail("temporary access quarantined guide alias mismatch")

    identity = observation.get("identity")
    if not isinstance(identity, dict):
        fail("identity object required")
    identity["gotrue_id"] = require_uuid(identity.get("gotrue_id"), "identity.gotrue_id")
    if identity.get("source") not in ALLOWED_IDENTITY_SOURCES:
        fail("identity.source is not an allowed verified source")
    if identity.get("dedicated_service_identity") is not True:
        fail("dedicated service identity is required")
    require_bool(identity.get("service_pat_belongs_to_gotrue_id_verified"), "identity.service_pat_belongs_to_gotrue_id_verified")
    if identity.get("primary_email_persisted") is not False:
        fail("primary email must not be persisted")

    network = observation.get("network")
    if not isinstance(network, dict):
        fail("network object required")
    profile = network.get("profile")
    if profile not in ALLOWED_PROFILES:
        fail("network.profile is not currently allowed")
    network["source_cidrs"] = require_cidrs(network.get("source_cidrs"))
    if network.get("supabase_ipv4_addon") is not False:
        fail("Free-plan snapshot must not claim IPv4 add-on")
    self_hosted = require_bool(network.get("self_hosted_direct_ipv6_reachability_verified"), "network.self_hosted_direct_ipv6_reachability_verified")
    pdc = require_bool(network.get("pdc_agent_ipv6_reachability_verified"), "network.pdc_agent_ipv6_reachability_verified")

    if profile == "SELF_HOSTED_IPV6":
        if network.get("cidr_evidence") != "GRAFANA_HOST_EGRESS_TOWARD_SUPABASE":
            fail("SELF_HOSTED_IPV6 requires Grafana host egress evidence")
        if self_hosted is not True:
            fail("SELF_HOSTED_IPV6 requires direct IPv6 reachability")
        if pdc is not False:
            fail("SELF_HOSTED_IPV6 must not claim PDC-agent verification")
    else:
        if network.get("cidr_evidence") != "PDC_AGENT_EGRESS_TOWARD_SUPABASE":
            fail("GRAFANA_CLOUD_PDC_IPV6 requires PDC-agent egress evidence")
        if pdc is not True:
            fail("GRAFANA_CLOUD_PDC_IPV6 requires PDC-agent IPv6 reachability")
        if self_hosted is not False:
            fail("GRAFANA_CLOUD_PDC_IPV6 must not claim Grafana Cloud direct IPv6 reachability")

    jit = observation.get("jit")
    if not isinstance(jit, dict):
        fail("jit object required")
    require_bool(jit.get("target_exists"), "jit.target_exists")
    expires_at = jit.get("expires_at")
    if not isinstance(expires_at, int):
        fail("jit.expires_at must be integer Unix seconds")
    if expires_at <= int(time.time()):
        fail("jit.expires_at must be in the future")

    scoped = observation.get("scoped_pat")
    if not isinstance(scoped, dict):
        fail("scoped_pat object required")
    require_bool(scoped.get("available"), "scoped_pat.available")
    if scoped.get("expected_prefix") != "sbp_fc":
        fail("scoped PAT prefix contract mismatch")
    if scoped.get("classic_fallback_allowed") is not False:
        fail("Classic PAT fallback must remain disabled")
    return observation

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", required=True)
    parser.add_argument("--emit-normalized", action="store_true")
    args = parser.parse_args()
    normalized = validate(json.loads(Path(args.observation).read_text()))
    if args.emit_normalized:
        print(json.dumps(normalized, indent=2, sort_keys=True))
    else:
        print("PASS: activation observation v0.6 valid")
    return 0

if __name__ == "__main__":
    sys.exit(main())
