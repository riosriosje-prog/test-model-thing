#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_4.py"

def fail(message: str) -> None:
    raise SystemExit(f"FAIL_CLOSED: {message}")

def one_of(name: str, allowed: set[str]) -> str:
    value = os.environ.get(name, "").strip()
    if value not in allowed:
        fail(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return value

def main() -> int:
    ssl_current = one_of("GALIA_SSL_CURRENT", {"true", "false"})
    temp_current = one_of("GALIA_TEMP_ACCESS_CURRENT", {"enabled", "disabled"})
    jit_exists = one_of("GALIA_JIT_TARGET_EXISTS", {"true", "false"})
    endpoint_choice = one_of("GALIA_TEMP_ENDPOINT_CHOICE", {"reference", "guide_alias"})

    rendered = subprocess.run(
        [sys.executable, str(RENDERER)],
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    mapping = json.loads(rendered.stdout)

    temp_path = (
        "/v1/projects/{ref}/jit-access"
        if endpoint_choice == "reference"
        else "/v1/projects/{ref}/database/jit-access"
    )

    plan = {
        "mode": "PLAN_ONLY",
        "network_io": False,
        "credential_input": False,
        "management_api_write": False,
        "ssl": {
            "current": ssl_current,
            "action": "NOOP" if ssl_current == "true" else "ENABLE_AND_EXPECT_BRIEF_REBOOT",
            "endpoint": "/v1/projects/{ref}/ssl-enforcement",
            "payload_file": "supabase/activation/galia_grafana_ssl_enable.v0_4.json",
        },
        "project_health_gate": "ACTIVE_HEALTHY",
        "temporary_access": {
            "current": temp_current,
            "endpoint_choice": endpoint_choice,
            "endpoint": temp_path,
            "action": "NOOP" if temp_current == "enabled" else "ENABLE",
            "payload_file": "supabase/activation/galia_grafana_temp_access_enable.v0_4.json",
        },
        "jit_mapping": {
            "target_exists": jit_exists,
            "method": "PUT" if jit_exists == "true" else "POST",
            "endpoint": "/v1/projects/{ref}/database/jit",
            "payload": mapping,
        },
        "execution": "OUTSIDE_THIS_CANDIDATE_AFTER_EXPLICIT_HUMAN_AUTHORIZATION",
    }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
