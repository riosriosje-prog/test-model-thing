#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "research/evidence/south_base.gate_closeout_candidate.v1_1.json"


def fail(msg: str) -> None:
    raise SystemExit("SOUTH_BASE_GATE_FAIL_CLOSED: " + msg)


def main() -> None:
    d = json.loads(PATH.read_text(encoding="utf-8"))

    if d.get("state") != "RESEARCH_CANDIDATE_NOT_PROMOTED":
        fail("candidate state changed")
    if d.get("promotion") != "NO":
        fail("candidate must remain unpromoted")
    if d.get("publication") != "NO_AUTOMATIC_PUBLICATION":
        fail("automatic publication boundary changed")

    gates = {g["id"]: g for g in d.get("gates", [])}
    required = {
        "SOUTHBASE-NGS-PID",
        "SOUTHBASE-ORIGIN-YEAR",
        "SOUTHBASE-ORIGINAL-STATION-DESCRIPTION",
        "SOUTHBASE-ESTABLISHING-PARTY",
        "SANJUAN-BASE-PAIR",
        "SOUTHBASE-PUERTO-RICO-DATUM-POSITION",
        "SOUTHBASE-NAD83-POSITION",
        "SOUTHBASE-MORRO-BEARING-RECONCILIATION",
        "SOUTHBASE-1899-HARBOR-CHART-CONTEXT",
        "SOUTHBASE-1899-CHART-EXPLICIT-STATION-LABEL",
        "FORNEY-1900-ORIGIN-HYPOTHESIS",
        "FORNEY-1900-MORRO-INTEGRATION",
        "SOUTHBASE-ORIGINAL-FIELD-OBSERVATION-COMPUTATION",
    }
    if not required.issubset(gates):
        fail("required gates missing")

    if gates["SOUTHBASE-NGS-PID"].get("state") != "PASS":
        fail("NGS PID gate regressed")
    if gates["SOUTHBASE-NGS-PID"].get("result") != "SAN JUAN SOUTH BASE = NGS PID TV1051":
        fail("TV1051 identity changed")
    if gates["SOUTHBASE-ORIGIN-YEAR"].get("state") != "PASS":
        fail("origin-year gate regressed")
    if gates["SOUTHBASE-ORIGIN-YEAR"].get("result") != "1899":
        fail("origin year changed")
    if gates["SOUTHBASE-ORIGINAL-STATION-DESCRIPTION"].get("state") != "PASS":
        fail("station description gate regressed")
    if gates["SOUTHBASE-ESTABLISHING-PARTY"].get("state") != "PASS_CORROBORATED_IDENTITY":
        fail("establishing-party attribution changed")
    if gates["SOUTHBASE-1899-HARBOR-CHART-CONTEXT"].get("state") != "PASS_DIAGNOSTIC_POSITIONAL_CONTEXT":
        fail("1899 chart contextual gate regressed")
    if gates["SOUTHBASE-1899-CHART-EXPLICIT-STATION-LABEL"].get("state") != "NOT_FOUND_IN_INSPECTED_SCAN":
        fail("chart-label gate changed without review")
    if gates["FORNEY-1900-ORIGIN-HYPOTHESIS"].get("state") != "REJECT_AS_ORIGIN_SUPERSEDED":
        fail("obsolete 1900-origin hypothesis revived")
    if gates["SOUTHBASE-ORIGINAL-FIELD-OBSERVATION-COMPUTATION"].get("state") != "OPEN":
        fail("field-observation/computation gate must remain open")

    pair = gates["SANJUAN-BASE-PAIR"]["result"]
    if pair["south"]["pid"] != "TV1051" or pair["north"]["pid"] != "TV1049":
        fail("San Juan base pair PID changed")
    if pair["south"]["first_recv"] != "1899" or pair["north"]["first_recv"] != "1899":
        fail("San Juan base pair first monumentation date changed")

    bearing = gates["SOUTHBASE-MORRO-BEARING-RECONCILIATION"]
    diff = float(bearing["ngs_geometry_pr_datum"]["bearing_difference_arcsec"])
    if diff >= 15.0:
        fail("Morro bearing reconciliation exceeds 15 arcsec")

    gov = d.get("governance", {})
    if gov.get("human_review_required") is not True:
        fail("human review boundary removed")
    if gov.get("automatic_promotion") is not False:
        fail("automatic promotion enabled")
    if gov.get("canonical_evidence_mutation") is not False:
        fail("canonical evidence mutation enabled")
    if gov.get("dashboard_publication") is not False:
        fail("dashboard publication enabled")

    print("SOUTH_BASE_GATE_VALIDATION=PASS")
    print("SOUTH_BASE_PID=TV1051")
    print("SOUTH_BASE_ORIGIN_YEAR=1899")
    print("NORTH_BASE_PID=TV1049")
    print("1899_CHART_CONTEXT=PASS_DIAGNOSTIC_POSITIONAL_CONTEXT")
    print("1899_CHART_EXPLICIT_LABEL=NOT_FOUND_IN_INSPECTED_SCAN")
    print("FORNEY_1900_ORIGIN=REJECT_AS_ORIGIN_SUPERSEDED")
    print("FIELD_OBSERVATION_COMPUTATION=OPEN")
    print("PROMOTION=NO")


if __name__ == "__main__":
    main()
