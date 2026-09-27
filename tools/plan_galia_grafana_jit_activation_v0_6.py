#!/usr/bin/env python3
import argparse, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_activation_observation_v0_6.py"
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_6.py"

def run_json(command):
    return json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", required=True)
    args = parser.parse_args()
    observation = run_json([sys.executable, str(VALIDATOR), "--observation", args.observation, "--emit-normalized"])
    mapping = run_json([sys.executable, str(RENDERER), "--observation", args.observation])
    holds = []
    if observation["scoped_pat"]["available"] is not True:
        holds.append("SCOPED_PAT_UNAVAILABLE")
    if observation["identity"]["service_pat_belongs_to_gotrue_id_verified"] is not True:
        holds.append("SERVICE_PAT_IDENTITY_BINDING_UNVERIFIED")
    profile = observation["network"]["profile"]
    route_proof = "SELF_HOSTED_DIRECT_IPV6" if profile == "SELF_HOSTED_IPV6" else "PDC_AGENT_IPV6"
    plan = {
        "mode": "PLAN_ONLY",
        "network_io": False,
        "credential_input": False,
        "management_api_write": False,
        "project_ref": observation["project_ref"],
        "project_status": observation["project_status"],
        "promotion_eligible": len(holds) == 0,
        "holds": holds,
        "ssl": {
            "current": observation["ssl"]["current"],
            "action": "NOOP" if observation["ssl"]["current"] else "ENABLE_AND_EXPECT_BRIEF_REBOOT",
            "endpoint": "/v1/projects/{ref}/ssl-enforcement",
            "server_root_ca_sha256": observation["ssl"]["server_root_ca"]["sha256"],
            "post_change_gate": "ACTIVE_HEALTHY",
        },
        "temporary_access": {
            "current": observation["temporary_access"]["current"],
            "action": "NOOP" if observation["temporary_access"]["current"] == "enabled" else "ENABLE",
            "endpoint": "/v1/projects/{ref}/jit-access",
            "guide_alias": "QUARANTINED_DO_NOT_EXECUTE",
        },
        "jit_mapping": {
            "target_exists": observation["jit"]["target_exists"],
            "method": "PUT" if observation["jit"]["target_exists"] else "POST",
            "endpoint": "/v1/projects/{ref}/database/jit",
            "payload": mapping,
            "expires_at_unit": "unix_seconds",
        },
        "identity": {
            "gotrue_id": observation["identity"]["gotrue_id"],
            "source": observation["identity"]["source"],
            "primary_email_persisted": False,
        },
        "network": {
            "profile": profile,
            "verified_egress_cidrs": observation["network"]["source_cidrs"],
            "cidr_evidence": observation["network"]["cidr_evidence"],
            "route_proof": route_proof,
        },
        "execution": "OUTSIDE_THIS_CANDIDATE_AFTER_EXPLICIT_HUMAN_AUTHORIZATION",
    }
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
