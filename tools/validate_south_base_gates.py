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
        "SB-NGS-MORRO-LIGHTHOUSE-BEARING-DIAGNOSTIC",
        "SB-1936-CORPS-MAP-SURVIVAL",
        "SB-1936-MAP-GRID-COORDINATE",
        "SB-ORIGIN-MODEL",
        "SB-ORIGINAL-STATION-DESCRIPTION",
        "SB-ESTABLISHING-PARTY",
        "SB-ORIGINAL-COORDINATE-MARK",
        "SB-NGS-PID",
        "SB-SAN-JUAN-NORTH-BASE-1899",
        "SB-1899-BASELINE-MEASUREMENT",
        "SB-GA-ORIGINAL-CARD-IMAGE",
    }
    if not required.issubset(gates):
        fail("required gates missing")

    if gates["SB-EXISTS-BY-1904"]["state"] != "PASS":
        fail("existence-by-1904 gate regressed")
    if gates["SB-MAGNETIC-DISTINCTION"]["state"] != "PASS":
        fail("magnetic distinction gate regressed")
    diag = gates["SB-NGS-MORRO-LIGHTHOUSE-BEARING-DIAGNOSTIC"]
    if diag.get("state") != "PASS_INDEPENDENT_GEOMETRIC_CORROBORATION":
        fail("Morro lighthouse bearing diagnostic regressed")
    comp = diag.get("computation", {})
    if comp.get("source_positions", {}).get("from", {}).get("pid") != "TV1051":
        fail("bearing diagnostic South Base PID changed")
    if comp.get("source_positions", {}).get("to", {}).get("pid") != "TV1029":
        fail("bearing diagnostic lighthouse PID changed")
    if abs(float(comp.get("difference_arcsec", 999))) > 15:
        fail("bearing diagnostic no longer agrees within 15 arcseconds")
    if gates["SB-1936-CORPS-MAP-SURVIVAL"]["state"] != "PASS_LABEL_PRESENT":
        fail("1936 map survival gate regressed")
    if gates["SB-1936-MAP-GRID-COORDINATE"]["state"] != "OPEN":
        fail("1936 exact grid coordinate must remain open")
    if gates["SB-ORIGINAL-STATION-DESCRIPTION"]["state"] != "PASS_TEXT_RECOVERED_IN_OFFICIAL_NGS_DATASHEET":
        fail("original station-description content gate regressed")
    if gates["SB-NGS-PID"]["state"] != "PASS":
        fail("NGS PID gate regressed")
    if gates["SB-NGS-PID"].get("resolved", {}).get("pid") != "TV1051":
        fail("South Base PID identity changed")
    if gates["SB-ESTABLISHING-PARTY"]["state"] != "PASS_AGENCY_AND_1899_DESCRIPTOR_INITIALS":
        fail("1899 monumenting agency/descriptor gate regressed")
    if gates["SB-ORIGIN-MODEL"]["state"] != "PASS_1899_MONUMENTATION_WITH_1900_NETWORK_INTEGRATION_SEPARATE":
        fail("1899 monumentation / 1900 integration distinction regressed")
    if gates["SB-SAN-JUAN-NORTH-BASE-1899"]["state"] != "PASS_COMPANION_STATION_IDENTIFIED":
        fail("North Base companion gate regressed")
    if gates["SB-SAN-JUAN-NORTH-BASE-1899"].get("resolved", {}).get("pid") != "TV1049":
        fail("North Base PID identity changed")
    if gates["SB-1899-BASELINE-MEASUREMENT"]["state"] != "OPEN_PRIMARY_TARGET":
        fail("baseline-measurement record must remain open")
    if gates["SB-GA-ORIGINAL-CARD-IMAGE"]["state"] != "OPEN_PROVENANCE_DEPTH":
        fail("GA original-card gate must remain open")

    print("SOUTH_BASE_GATE_VALIDATION=PASS")
    print("EXISTS_BY_1904=PASS")
    print("MAGNETIC_DISTINCTION=PASS")
    print("MORRO_LIGHTHOUSE_BEARING_DIAGNOSTIC=PASS_WITHIN_15_ARCSEC")
    print("MAP_1936_LABEL=PASS")
    print("MAP_1936_GRID_COORDINATE=OPEN")
    print("ORIGINAL_STATION_DESCRIPTION=PASS_TEXT_RECOVERED_IN_OFFICIAL_NGS_DATASHEET")
    print("NGS_PID=PASS:TV1051")
    print("NORTH_BASE_PID=PASS:TV1049")
    print("MONUMENTATION=PASS:1899_CGS")
    print("ORIGIN_MODEL=PASS_1899_MONUMENTATION_WITH_1900_NETWORK_INTEGRATION_SEPARATE")
    print("BASELINE_MEASUREMENT_RECORD=OPEN_PRIMARY_TARGET")
    print("GA_ORIGINAL_CARD=OPEN_PROVENANCE_DEPTH")


if __name__ == "__main__":
    main()
