#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "research/gates/south_base_gates.v0_7.json"


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
        "SB-1899-WCH-MORRO-CASTLE",
        "SB-1900-SF-MORRO-CASTLE-2",
        "SB-1900-MORRO-LIGHTHOUSE-FIRST-OBSERVED",
        "SB-1899-1900-CAMPAIGN-SEPARATION",
        "SB-1936-CORPS-MAP-SURVIVAL",
        "SB-1936-MAP-GRID-COORDINATE",
        "SB-1899-UNT-SAN-JUAN-HARBOR-MAP",
        "SB-ORIGIN-MODEL",
        "SB-ORIGINAL-STATION-DESCRIPTION",
        "SB-ESTABLISHING-PARTY",
        "SB-ORIGINAL-COORDINATE-MARK",
        "SB-NGS-PID",
        "SB-SAN-JUAN-NORTH-BASE-1899",
        "SB-1899-OFFICIAL-FIELD-WORK-CLASSIFICATION",
        "SB-1899-BASELINE-MEASUREMENT",
        "SB-GA-ORIGINAL-CARD-IMAGE",
        "SB-PROMOTED-DOSSIER-ORIGIN-RECONCILIATION",
        "SB-1899-BASELINE-DIGITAL-SEARCH-SATURATION",
        "SB-1899-SAN-JUAN-EXAMINATION-BLUEPRINT",
        "SB-1900-FORNEY-TV1051-OCCUPATION",
        "SB-NAVY-HYDROGRAPHIC-OFFICE-1899-MAP-CHECK",
        "SB-WCH-NOMINAL-IDENTITY",
        "SB-1899-IIIF-CANVAS-RECOVERY",
        "SB-GA-CARD-DIGITAL-SEARCH",
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
    if gates["SB-1899-SAN-JUAN-HARBOR-CONTROL"]["state"] != "PASS_CAMPAIGN_PLUS_OFFICIAL_1899_STATION_NETWORK":
        fail("1899 San Juan station-network gate regressed")
    if gates["SB-1899-WCH-MORRO-CASTLE"]["state"] != "PASS":
        fail("1899 WCH Morro Castle gate regressed")
    if gates["SB-1899-WCH-MORRO-CASTLE"].get("recovered", {}).get("pid") != "TV1031":
        fail("1899 Morro Castle PID changed")
    if gates["SB-1900-SF-MORRO-CASTLE-2"]["state"] != "PASS_STRONG_PERSONNEL_CORROBORATION":
        fail("1900 SF Morro Castle 2 gate regressed")
    if gates["SB-1900-SF-MORRO-CASTLE-2"].get("recovered", {}).get("pid") != "TV1021":
        fail("1900 Morro Castle 2 PID changed")
    if gates["SB-1900-MORRO-LIGHTHOUSE-FIRST-OBSERVED"]["state"] != "PASS":
        fail("1900 Morro Lighthouse first-observed gate regressed")
    if gates["SB-1900-MORRO-LIGHTHOUSE-FIRST-OBSERVED"].get("recovered", {}).get("pid") != "TV1029":
        fail("Morro Lighthouse PID changed")
    if gates["SB-1899-1900-CAMPAIGN-SEPARATION"]["state"] != "PASS":
        fail("1899/1900 campaign separation gate regressed")
    if gates["SB-1900-FORNEY-NETWORK"]["state"] != "PASS_CAMPAIGN_WITH_DISTINCT_1900_MORRO_CONTROL_LAYER":
        fail("1900 Forney network gate regressed")
    if gates["SB-1936-CORPS-MAP-SURVIVAL"]["state"] != "REJECTED_FALSE_LEAD_ST_THOMAS":
        fail("1936 St. Thomas false lead rejection regressed")
    if gates["SB-1936-MAP-GRID-COORDINATE"]["state"] != "CLOSED_NOT_APPLICABLE_FALSE_LEAD":
        fail("1936 St. Thomas grid gate must remain closed/not applicable")
    if gates["SB-LATER-REOCCUPATION-CONTINUITY"]["state"] != "PASS":
        fail("later South Base reoccupation-continuity gate regressed")
    if gates["SB-1899-UNT-SAN-JUAN-HARBOR-MAP"]["state"] != "PASS_SOURCE_RECOVERED_CONTEXT_ONLY":
        fail("1899 UNT chart-context gate regressed")
    if gates["SB-ORIGINAL-STATION-DESCRIPTION"]["state"] != "PASS_TEXT_RECOVERED_IN_OFFICIAL_NGS_DATASHEET":
        fail("original station-description content gate regressed")
    if gates["SB-NGS-PID"]["state"] != "PASS":
        fail("NGS PID gate regressed")
    if gates["SB-NGS-PID"].get("resolved", {}).get("pid") != "TV1051":
        fail("South Base PID identity changed")
    if gates["SB-ESTABLISHING-PARTY"]["state"] != "PASS_AGENCY_YEAR_AND_DESCRIPTOR_NOMINAL_IDENTITY":
        fail("1899 monumenting agency/descriptor gate regressed")
    if gates["SB-ORIGIN-MODEL"]["state"] != "PASS_1899_MONUMENTATION_WITH_1900_NETWORK_INTEGRATION_SEPARATE":
        fail("1899 monumentation / 1900 integration distinction regressed")
    if gates["SB-SAN-JUAN-NORTH-BASE-1899"]["state"] != "PASS_COMPANION_STATION_IDENTIFIED":
        fail("North Base companion gate regressed")
    if gates["SB-SAN-JUAN-NORTH-BASE-1899"].get("resolved", {}).get("pid") != "TV1049":
        fail("North Base PID identity changed")
    fw = gates["SB-1899-OFFICIAL-FIELD-WORK-CLASSIFICATION"]
    if fw.get("state") != "PASS_LIMITING_EVIDENCE":
        fail("1899 field-work classification gate regressed")
    ti = fw.get("recovered", {}).get("technical_index", {})
    if ti.get("porto_rico_under_triangulation") is not True:
        fail("1899 Porto Rico triangulation classification changed")
    if ti.get("porto_rico_enumerated_under_base_lines") is not False:
        fail("1899 Base-lines limiting evidence changed")
    if gates["SB-1899-BASELINE-MEASUREMENT"]["state"] != "OPEN_ARCHIVAL_REQUIRED_STRONG_LIMITING_EVIDENCE":
        fail("baseline function/measurement record must remain open")
    if gates["SB-GA-ORIGINAL-CARD-IMAGE"]["state"] != "OPEN_ARCHIVAL_REQUIRED":
        fail("GA original-card gate must remain open")
    if gates["SB-PROMOTED-DOSSIER-ORIGIN-RECONCILIATION"]["state"] != "OPEN_HUMAN_RECONCILIATION_REQUIRED":
        fail("promoted-dossier reconciliation must remain explicitly human-gated")
    if gates["SB-1899-BASELINE-DIGITAL-SEARCH-SATURATION"]["state"] != "PASS_SEARCH_SATURATION_WITH_STRONG_OFFICIAL_LIMITING_EVIDENCE":
        fail("baseline digital-search saturation state regressed")
    if gates["SB-1899-SAN-JUAN-EXAMINATION-BLUEPRINT"]["state"] != "OPEN_ARCHIVAL_LEAD":
        fail("1899 San Juan blueprint gate must remain an archival lead")
    if gates["SB-1900-FORNEY-TV1051-OCCUPATION"]["state"] != "OPEN_NO_DIRECT_STATION_TIE":
        fail("Forney/TV1051 occupation must remain open without a direct station tie")
    if gates["SB-NAVY-HYDROGRAPHIC-OFFICE-1899-MAP-CHECK"]["state"] != "PASS_LIMITING_EVIDENCE":
        fail("Hydrographic Office 1899 limiting-evidence gate regressed")
    if gates["SB-WCH-NOMINAL-IDENTITY"]["state"] != "PASS_CROSS_SOURCE_CORROBORATION":
        fail("WCH nominal-identity gate regressed")
    if gates["SB-1899-IIIF-CANVAS-RECOVERY"]["state"] != "PASS_SOURCE_PIXELS_INSPECTED_LIMITING_EVIDENCE":
        fail("1899 IIIF map-inspection gate regressed")
    iiif = gates["SB-1899-IIIF-CANVAS-RECOVERY"].get("recovered", {})
    if iiif.get("canvas_count") != 2:
        fail("1899 IIIF canvas count changed")
    if gates["SB-GA-CARD-DIGITAL-SEARCH"]["state"] != "PASS_SEARCH_SATURATION_CARD_IMAGE_NOT_RECOVERED":
        fail("GA-card digital-search saturation gate regressed")
    if gates["SB-GA-ORIGINAL-CARD-IMAGE"]["state"] != "OPEN_ARCHIVAL_REQUIRED":
        fail("GA original-card gate must remain archival-open")
    if gates["SB-ESTABLISHING-PARTY"]["state"] != "PASS_AGENCY_YEAR_AND_DESCRIPTOR_NOMINAL_IDENTITY":
        fail("establishing-party nominal identity gate regressed")

    print("SOUTH_BASE_GATE_VALIDATION=PASS")
    print("EXISTS_BY_1904=PASS")
    print("MAGNETIC_DISTINCTION=PASS")
    print("MORRO_LIGHTHOUSE_BEARING_DIAGNOSTIC=PASS_WITHIN_15_ARCSEC")
    print("WCH_1899_MORRO_CASTLE=PASS:TV1031")
    print("SF_1900_MORRO_CASTLE_2=PASS:TV1021")
    print("MORRO_LIGHTHOUSE_FIRST_OBSERVED=PASS:1900")
    print("CAMPAIGN_SEPARATION=PASS:1899_WCH__1900_SF")
    print("MAP_1936_LABEL=REJECTED_FALSE_LEAD_ST_THOMAS")
    print("MAP_1936_GRID_COORDINATE=CLOSED_NOT_APPLICABLE_FALSE_LEAD")
    print("LATER_REOCCUPATION_CONTINUITY=PASS")
    print("UNT_1899_MAP=PASS_SOURCE_RECOVERED_CONTEXT_ONLY")
    print("ORIGINAL_STATION_DESCRIPTION=PASS_TEXT_RECOVERED_IN_OFFICIAL_NGS_DATASHEET")
    print("NGS_PID=PASS:TV1051")
    print("NORTH_BASE_PID=PASS:TV1049")
    print("MONUMENTATION=PASS:1899_CGS")
    print("ORIGIN_MODEL=PASS_1899_MONUMENTATION_WITH_1900_NETWORK_INTEGRATION_SEPARATE")
    print("FIELD_WORK_CLASSIFICATION=PASS_LIMITING_EVIDENCE")
    print("BASELINE_MEASUREMENT_RECORD=OPEN_ARCHIVAL_REQUIRED_STRONG_LIMITING_EVIDENCE")
    print("GA_ORIGINAL_CARD=OPEN_PROVENANCE_DEPTH")
    print("PROMOTED_DOSSIER_RECONCILIATION=OPEN_HUMAN_RECONCILIATION_REQUIRED")
    print("BASELINE_DIGITAL_SEARCH=PASS_SEARCH_SATURATION_WITH_STRONG_OFFICIAL_LIMITING_EVIDENCE")
    print("SAN_JUAN_1899_BLUEPRINT=OPEN_ARCHIVAL_LEAD")
    print("FORNEY_TV1051_1900=OPEN_NO_DIRECT_STATION_TIE")
    print("HYDROGRAPHIC_OFFICE_1899_MAP=PASS_LIMITING_EVIDENCE")
    print("WCH_NOMINAL_IDENTITY=PASS_CROSS_SOURCE_CORROBORATION")
    print("IIIF_1899_MAP=PASS_SOURCE_PIXELS_INSPECTED_LIMITING_EVIDENCE")
    print("GA_CARD_DIGITAL_SEARCH=PASS_SEARCH_SATURATION_CARD_IMAGE_NOT_RECOVERED")
    print("GA_ORIGINAL_CARD=OPEN_ARCHIVAL_REQUIRED")


if __name__ == "__main__":
    main()
