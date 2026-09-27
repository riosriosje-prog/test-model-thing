#!/usr/bin/env python3
import argparse, ipaddress, json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_activation_observation_v0_6.py"

def load(path):
    r = subprocess.run([sys.executable, str(VALIDATOR), "--observation", path, "--emit-normalized"], check=True, capture_output=True, text=True)
    return json.loads(r.stdout)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--observation", required=True)
    a = p.parse_args()
    observation = load(a.observation)
    ipv4, ipv6 = [], []
    for cidr in observation["network"]["source_cidrs"]:
        network = ipaddress.ip_network(cidr, strict=False)
        (ipv4 if network.version == 4 else ipv6).append({"cidr": str(network)})
    allowed = {}
    if ipv4:
        allowed["allowed_cidrs"] = ipv4
    if ipv6:
        allowed["allowed_cidrs_v6"] = ipv6
    payload = {
        "user_id": observation["identity"]["gotrue_id"],
        "roles": [{
            "role": "galia_grafana_ro",
            "allowed_networks": allowed,
            "expires_at": observation["jit"]["expires_at"],
        }],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
