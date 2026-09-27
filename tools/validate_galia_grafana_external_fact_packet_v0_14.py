#!/usr/bin/env python3
import argparse, ipaddress, json, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from jsonschema import Draft202012Validator, FormatChecker

MAX_AGE_SECONDS = 900
MIN_JIT_REMAINING_MS = 300_000
RATIFICATION = "82e5b8e6642d1475ebcee9183b401b1fd010e63b"
PDC_ID = "GALIA-GRAFANA-PDC-OFFICIAL-BINDING-CONTRACT-CANDIDATE-v0.11"
PDC_HEAD = "ce4d638f11d5e63461ec5a2bd99155146c806ec4"
PDC_SET = "ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc"
SUPABASE_HOST = "db.nzoviwitcqmsacwiizhh.supabase.co"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "governance" / "galia_grafana_external_fact_packet.schema.v0_14.json"
FORBIDDEN_KEYS = {
    "token","access_token","password","secret","authorization","primary_email","email",
    "ca_pem","private_key","pat_value","signing_token","service_account_token","api_key","credential_value"
}

def fail(message):
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

def validate_schema(packet):
    try:
        schema=json.loads(SCHEMA_PATH.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"schema unavailable or invalid: {exc}")
    errors=sorted(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(packet),
                  key=lambda e:list(e.absolute_path))
    if errors:
        e=errors[0]; path="$"
        for part in e.absolute_path:
            path += f"[{part}]" if isinstance(part,int) else f".{part}"
        fail(f"schema violation at {path}: {e.message}")

def parse_time(value, name):
    try:
        dt=datetime.fromisoformat(value.replace("Z","+00:00"))
    except (AttributeError, ValueError):
        fail(f"{name} must be valid ISO-8601")
    if dt.tzinfo is None:
        fail(f"{name} must be timezone-aware")
    return dt.astimezone(timezone.utc)

def require_fresh(dt, name):
    age=(datetime.now(timezone.utc)-dt).total_seconds()
    if age < -60: fail(f"{name} timestamp is implausibly in the future")
    if age > MAX_AGE_SECONDS: fail(f"{name} is stale")

def require_uuid(value, name):
    try: parsed=uuid.UUID(value)
    except (ValueError,TypeError): fail(f"{name} must be UUID")
    if parsed.int == 0: fail(f"{name} must not be nil UUID")

def global_unicast_ipv6(cidr):
    try: net=ipaddress.ip_network(cidr,strict=False)
    except ValueError: fail(f"invalid PDC IPv6 egress CIDR: {cidr}")
    if net.version != 6: fail("PDC egress CIDRs must be IPv6")
    if (not net.is_global or net.is_multicast or net.network_address.is_unspecified
        or net.network_address.is_loopback or net.network_address.is_link_local
        or net.network_address.is_private or net.network_address.is_reserved or net.prefixlen == 0):
        fail("PDC egress CIDR must be global-unicast routable evidence")
    return str(net)

def validate(packet):
    reject_forbidden(packet)
    validate_schema(packet)

    require_fresh(parse_time(packet["observed_at_utc"],"observed_at_utc"),"external fact packet")
    a=packet["authority"]
    if a["ratification_merge"] != RATIFICATION: fail("ratification merge mismatch")
    if a["pdc_contract_candidate_id"] != PDC_ID: fail("PDC contract candidate id mismatch")
    if a["pdc_contract_head"] != PDC_HEAD: fail("PDC contract head mismatch")
    if a["pdc_contract_candidate_set_sha256"] != PDC_SET: fail("PDC contract candidate-set mismatch")

    g=packet["grafana"]
    u=urlparse(g["stack_url"])
    if u.scheme!="https" or not u.netloc: fail("grafana.stack_url must be a valid https URL")

    normalized=[global_unicast_ipv6(x) for x in packet["network"]["pdc_agent_ipv6_egress_cidrs"]]

    s=packet["supabase"]
    require_uuid(s["gotrue_id"],"supabase.gotrue_id")
    now_ms=time.time_ns()//1_000_000
    if s["jit_expires_at_ms"]-now_ms < MIN_JIT_REMAINING_MS:
        fail("JIT mapping has insufficient remaining lifetime")

    for domain, receipt in packet["evidence"].items():
        require_fresh(parse_time(receipt["observed_at_utc"],f"evidence.{domain}.observed_at_utc"),
                      f"evidence.{domain}")

    return {
        "eligibility":"FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE",
        "live_execution_authorized":False,
        "future_human_decision_required":True,
        "profile":packet["profile"],
        "stack_id":g["stack_id"],
        "pdc_network_id":g["pdc_network"]["id"],
        "connected_agents_count":g["pdc_network"]["connected_agents_count"],
        "verified_ipv6_egress_cidrs":normalized,
        "jit_expires_at_ms":s["jit_expires_at_ms"],
        "server_root_ca_sha256":s["server_root_ca_sha256"],
        "evidence_receipt_sha256":{k:v["receipt_sha256"] for k,v in sorted(packet["evidence"].items())},
        "secret_material_persisted":False
    }

def main():
    p=argparse.ArgumentParser(); p.add_argument("--packet",required=True); args=p.parse_args()
    try: packet=json.loads(Path(args.packet).read_text())
    except (OSError,json.JSONDecodeError) as exc: fail(f"packet unavailable or invalid JSON: {exc}")
    print(json.dumps(validate(packet),indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    sys.exit(main())
