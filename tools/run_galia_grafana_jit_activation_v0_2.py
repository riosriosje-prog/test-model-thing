#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_REF = "nzoviwitcqmsacwiizhh"
BASE = "https://api.supabase.com"
ACK = "YES_I_UNDERSTAND"
ROOT = Path(__file__).resolve().parents[1]
SSL_PAYLOAD = ROOT / "supabase" / "activation" / "galia_grafana_ssl_enable.v0_2.json"
TEMP_PAYLOAD = ROOT / "supabase" / "activation" / "galia_grafana_temp_access_enable.v0_2.json"
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_2.py"

TEMP_REFERENCE = f"/v1/projects/{PROJECT_REF}/jit-access"
TEMP_GUIDE_ALIAS = f"/v1/projects/{PROJECT_REF}/database/jit-access"
SSL_PATH = f"/v1/projects/{PROJECT_REF}/ssl-enforcement"
JIT_PATH = f"/v1/projects/{PROJECT_REF}/database/jit"
JIT_LIST_PATH = f"/v1/projects/{PROJECT_REF}/database/jit/list"

def fail(message: str) -> None:
    raise SystemExit(f"FAIL_CLOSED: {message}")

def request(token: str, method: str, path: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode() or "{}"
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = {"_raw_non_json": raw}
            return response.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"_raw_non_json": raw}
        return exc.code, body

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))

def discover_temp_endpoint(token: str):
    results = []
    for path in (TEMP_REFERENCE, TEMP_GUIDE_ALIAS):
        status, body = request(token, "GET", path)
        results.append((path, status, body))
    good = [(p,s,b) for p,s,b in results if 200 <= s < 300]
    if not good:
        fail("neither documented Temporary Access GET endpoint returned 2xx")
    if len(good) == 2 and canonical(good[0][2]) != canonical(good[1][2]):
        fail("Temporary Access endpoint aliases returned conflicting state")
    return good[0][0], [(p,s) for p,s,_ in results]

def contains_user(value, user_id: str):
    if isinstance(value, dict):
        if value.get("user_id") == user_id:
            return True
        return any(contains_user(v, user_id) for v in value.values())
    if isinstance(value, list):
        return any(contains_user(v, user_id) for v in value)
    return False

def render_mapping():
    env = os.environ.copy()
    result = subprocess.run(
        [sys.executable, str(RENDERER)],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return json.loads(result.stdout)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    plan = {
        "project_ref": PROJECT_REF,
        "default_mode": "dry-run",
        "ssl_path": SSL_PATH,
        "temporary_access_reference": TEMP_REFERENCE,
        "temporary_access_guide_alias": TEMP_GUIDE_ALIAS,
        "jit_list_path": JIT_LIST_PATH,
        "jit_create_method": "POST",
        "jit_update_method": "PUT",
        "grafana_service_pat_read_by_executor": False,
    }

    if not args.apply:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    if os.environ.get("GALIA_ACTIVATION_APPLY") != ACK:
        fail("apply requires GALIA_ACTIVATION_APPLY=YES_I_UNDERSTAND")

    token = os.environ.get("SUPABASE_MANAGEMENT_API_TOKEN", "")
    if not token.startswith("sbp_fc"):
        fail("activation token must be a Scoped PAT with sbp_fc prefix")

    if os.environ.get("GALIA_SSL_CHANGE_AUTHORIZED") != ACK:
        fail("SSL enforcement may reboot the database; set GALIA_SSL_CHANGE_AUTHORIZED=YES_I_UNDERSTAND")

    ssl_payload = json.loads(SSL_PAYLOAD.read_text())
    temp_payload = json.loads(TEMP_PAYLOAD.read_text())
    mapping = render_mapping()
    target_user = mapping["user_id"]

    ssl_status, _ = request(token, "PUT", SSL_PATH, ssl_payload)
    if not 200 <= ssl_status < 300:
        fail(f"SSL enforcement update failed with HTTP {ssl_status}")

    temp_get_path, discovery = discover_temp_endpoint(token)
    temp_put_path = temp_get_path
    temp_status, _ = request(token, "PUT", temp_put_path, temp_payload)
    if not 200 <= temp_status < 300:
        fail(f"Temporary Access enable failed with HTTP {temp_status}")

    list_status, mappings_before = request(token, "GET", JIT_LIST_PATH)
    if not 200 <= list_status < 300:
        fail(f"JIT list failed with HTTP {list_status}")

    method = "PUT" if contains_user(mappings_before, target_user) else "POST"
    map_status, _ = request(token, method, JIT_PATH, mapping)
    if not 200 <= map_status < 300:
        fail(f"JIT mapping {method} failed with HTTP {map_status}")

    verify_status, mappings_after = request(token, "GET", JIT_LIST_PATH)
    if not 200 <= verify_status < 300:
        fail(f"JIT verification list failed with HTTP {verify_status}")
    if not contains_user(mappings_after, target_user):
        fail("target gotrue_id not present after JIT mapping operation")

    receipt = {
        "project_ref": PROJECT_REF,
        "ssl_update_http": ssl_status,
        "temporary_access_discovery": discovery,
        "temporary_access_endpoint_selected": temp_put_path,
        "temporary_access_update_http": temp_status,
        "jit_mapping_method": method,
        "jit_mapping_http": map_status,
        "jit_verify_http": verify_status,
        "target_user_id": target_user,
        "secret_material_persisted": False,
        "grafana_service_pat_read_by_executor": False,
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
