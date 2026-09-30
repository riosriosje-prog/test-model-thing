#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "research/gates/south_base_gates.v0_2.json"


def fail(msg: str) -> None:
    raise SystemExit("SOUTH_BASE_GATE_FAIL_CLOSED: " + msg)


def main() -> None:
    d = json.loads(PATH.read_text(encoding="utf-8"))
    if d.get("state") != "RESEARCH_CANDIDATE_NOT_PROMOTED":
        fail("gate set must remain unpromoted")
    inv = d.get("invariants", {})
    if inv.get("automatic_promotion") is not False:
        fail("automatic promotion enabled")
    if inv.get("canonical_database_write") is not False:
        fail("canonical write enabled")

    gates = {g["id"]: g for g in d.get("gates", [])}
    required = {
        "SB-EXISTS-BY-1904",
        "SB-MAGNETIC-DISTINCTION",
        "SB-MORRO-BEARING",
        "SB-1936-CORPS-MAP-SURVIVAL",
        "SB-1936-MAP-GRID-COORDINATE",
        "SB-ORIGIN-MODEL",
        "SB-ORIGINAL-STATION-DESCRIPTION",
        "SB-ESTABLISHING-PARTY",
        "SB-ORIGINAL-COORDINATE-MARK",
        "SB-NGS-PID",
    }
    if not required.issubset(gates):
        fail("required gates missing")

    if gates["SB-EXISTS-BY-1904"]["state"] != "PASS":
        fail("existence-by-1904 gate regressed")
    if gates["SB-MAGNETIC-DISTINCTION"]["state"] != "PASS":
        fail("magnetic distinction gate regressed")
    if gates["SB-1936-CORPS-MAP-SURVIVAL"]["state"] != "PASS_LABEL_PRESENT":
        fail("1936 map survival gate regressed")
    if gates["SB-1936-MAP-GRID-COORDINATE"]["state"] != "OPEN":
        fail("1936 exact grid coordinate must remain open")
    if gates["SB-ORIGINAL-STATION-DESCRIPTION"]["state"] != "OPEN_PRIMARY_TARGET":
        fail("original station description must remain primary open target")
    if gates["SB-NGS-PID"]["state"] != "OPEN":
        fail("NGS PID must remain open")
    if gates["SB-ORIGIN-MODEL"]["state"] != "STRONG_HYPOTHESIS_MULTI_STAGE":
        fail("origin model must remain hypothesis")

    print("SOUTH_BASE_GATE_VALIDATION=PASS")
    print("EXISTS_BY_1904=PASS")
    print("MAGNETIC_DISTINCTION=PASS")
    print("MAP_1936_LABEL=PASS")
    print("MAP_1936_GRID_COORDINATE=OPEN")
    print("ORIGINAL_STATION_DESCRIPTION=OPEN_PRIMARY_TARGET")
    print("NGS_PID=OPEN")
    print("ORIGIN_MODEL=STRONG_HYPOTHESIS_MULTI_STAGE")


if __name__ == "__main__":
    main()
