#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_activation_observation_v0_5.py"

def load_observation(path: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--observation", path, "--emit-normalized"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observation", required=True)
    args = parser.parse_args()

    observation = load_observation(args.observation)
    ipv4 = []
    ipv6 = []
    for cidr in observation["network"]["source_cidrs"]:
        network = ipaddress.ip_network(cidr, strict=False)
        target = ipv4 if network.version == 4 else ipv6
        target.append({"cidr": str(network)})

    allowed_networks = {}
    if ipv4:
        allowed_networks["allowed_cidrs"] = ipv4
    if ipv6:
        allowed_networks["allowed_cidrs_v6"] = ipv6

    payload = {
        "user_id": observation["identity"]["gotrue_id"],
        "roles": [
            {
                "role": "galia_grafana_ro",
                "allowed_networks": allowed_networks,
                "expires_at": observation["jit"]["expires_at"],
            }
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
