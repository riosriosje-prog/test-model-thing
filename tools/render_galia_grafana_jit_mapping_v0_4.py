#!/usr/bin/env python3
import ipaddress
import json
import os
import sys
import time
import uuid

ROLE = "galia_grafana_ro"

def fail(message: str) -> None:
    raise SystemExit(f"FAIL_CLOSED: {message}")

def main() -> int:
    user_id = os.environ.get("GALIA_JIT_GOTRUE_USER_ID", "").strip()
    raw_cidrs = os.environ.get("GALIA_JIT_ALLOWED_CIDRS", "").strip()
    raw_expiry = os.environ.get("GALIA_JIT_EXPIRES_AT_MS", "").strip()

    if not user_id:
        fail("missing GALIA_JIT_GOTRUE_USER_ID")
    try:
        parsed_uuid = uuid.UUID(user_id)
    except ValueError:
        fail("GALIA_JIT_GOTRUE_USER_ID must be a UUID")
    if parsed_uuid.int == 0:
        fail("nil UUID is not allowed")

    cidrs = [item.strip() for item in raw_cidrs.split(",") if item.strip()]
    if not cidrs:
        fail("at least one allowed CIDR is required")

    normalized = []
    for cidr in cidrs:
        try:
            normalized.append(str(ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            fail(f"invalid CIDR: {cidr}")

    try:
        expires_at = int(raw_expiry)
    except ValueError:
        fail("GALIA_JIT_EXPIRES_AT_MS must be an integer")
    if expires_at <= int(time.time() * 1000):
        fail("JIT expiry must be in the future")

    payload = {
        "user_id": str(parsed_uuid),
        "user_roles": [{
            "role": ROLE,
            "allowed_networks": {
                "allowed_cidrs": [{"cidr": cidr} for cidr in normalized]
            },
            "expires_at": expires_at
        }]
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
