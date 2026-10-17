"""GALIA read-only Santurce hydrogeology research admission tests.

Groundwater DEPTH BELOW LAND SURFACE is distinct from datum-referenced head,
flood depth, liquefaction screening assumptions, and a current measured level.
"""
import copy
import json
from pathlib import Path
import unittest


MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "research/gates/santurce_groundwater_evidence.v0_1.json"
)


def validate(record):
    if (
        record["schema_version"] != "galia.santurce.hydrogeology.evidence.v0.1"
        or record["state"] != "AUTHORITY_HOLD"
        or record["canonical_write_authorized"] is not False
        or record["raw_capture_complete"] is not False
        or record["georeferencing_authorized"] is not False
        or record["point_level_prediction_authorized"] is not False
        or record["current_water_table_map_available"] is not False
        or record["human_review_status"] != "PENDING"
    ):
        raise ValueError("Unreviewed groundwater claim was promoted")
    source_by_id = {s["source_id"]: s for s in record["source_register"]}
    if len(source_by_id) != 5 or len(record["source_register"]) != 5:
        raise ValueError("Unexpected or duplicate source IDs")
    if any(s["source_binary_sha256"] is not None
           or s["source_binary_retained"] is not False
           for s in record["source_register"]):
        raise ValueError("Invented captured-source digest")
    obs = record["groundwater_evidence"]
    if len(obs) != 4 or len({o["observation_id"] for o in obs}) != 4:
        raise ValueError("Unexpected groundwater observations")
    for item in obs:
        if item["source_id"] not in source_by_id:
            raise ValueError("Source link absent")
        if (
            item.get("coordinates") is not None
            or item.get("subbarrio_id") is not None
            or item["human_review_status"] != "PENDING"
            or item["quantity_is_current"] is not False
        ):
            raise ValueError("Unreviewed point-level geodata or current label")
    region = next(o for o in obs if o["observation_id"] ==
                  "SAN-JUAN-2005-SWAMP-SHALLOW-WATER-TABLE")
    if (
        region["type"] != "REGIONAL_GEOLOGIC_UNIT_CONDITION"
        or region["source_id"] != "GSA-HENGESH-BACHHUBER-2005"
        or region["upper_bound_m_below_ground"] != 1.5
        or region["lower_bound_m_below_ground"] is not None
        or region["upper_bound_relation"] != "APPROXIMATELY_LESS_THAN"
        or region["site_specific_measurement"] is not False
        or region["includes_santurce_well_id"] is not False
    ):
        raise ValueError("Regional coastal shallow condition mischaracterized")
    model = next(o for o in obs if o["observation_id"] ==
                 "SAN-JUAN-2005-REGIONAL-DEPTH-VARIABILITY")
    if (
        model["reported_regional_depth_m_approx"] != [3, 7]
        or model["modelling_conservative_assumed_max_depth_m"] != 1.5
        or model["site_specific_measurement"] is not False
        or model["confidence_tier"] !=
           "REGIONAL_MODEL_BACKGROUND_NOT_A_SANTURCE_MEASURED_RANGE"
    ):
        raise ValueError("Regional screening value promoted to direct measurement")
    project = next(o for o in obs if o["observation_id"] ==
                   "SANTURCE-CONSERVATORIO-2006-PROJECT")
    if (
        project["source_id"] != "JPI-RAMOS-CONSERVATORIO-2006"
        or project["reported_depth_ft_below_ground"] != [8, 10]
        or project["reported_depth_m_below_ground_approx"] != [2.44, 3.05]
        or project["period_start"] != "2006-02-16"
        or project["period_end"] != "2006-06-08"
        or project["measurement_event_date"] is not None
        or project["method_or_instrument"] != "NOT_REPORTED_IN_RESUME"
        or project["boring_log_available"] is not False
        or project["point_level_prediction_authorized"] is not False
    ):
        raise ValueError("Historical Conservatorio note misrepresented")
    jpi = source_by_id["JPI-RAMOS-CONSERVATORIO-2006"]
    if (
        jpi["source_pdf_page_index_zero_based"] != 4
        or jpi["visual_page_read"] is not True
        or jpi["source_kind"] !=
           "PROJECT_ENGINEER_PROFESSIONAL_RESUME_NOT_GEOTECHNICAL_BORING_LOG"
    ):
        raise ValueError("Source level or page was misrepresented")
    drainage = next(o for o in obs if o["observation_id"] ==
                    "BUENA-VISTA-SANTURCE-EPA-DRAINAGE")
    if (
        drainage["hydrogeology_numeric_depth_m"] is not None
        or drainage["measured_well_id"] is not None
        or drainage["subbarrio_polygon_verified"] is not False
        or drainage["type"] !=
           "QUALITATIVE_COMMUNITY_DRAINAGE_AND_GROUNDWATER_OVERFLOW"
    ):
        raise ValueError("EPA drainage context falsely quantified")
    excluded = record["source_scope_exclusions"]
    if len(excluded) != 1 or excluded[0]["source_id"] != (
        "USGS-NGWMN-MUNOZ-MARIN-1C8-2026"
    ):
        raise ValueError("Missing outside-site hold")
    well = source_by_id[excluded[0]["source_id"]]
    if (
        well["site_number"] != "182443066041502"
        or well["is_santurce_site_verified"] is not False
        or well["eligible_for_santurce_depth_inference"] is not False
        or excluded[0]["allow_extrapolation"] is not False
        or well["displayed_depth_ft_below_ground"] != 15.42
        or well["displayed_measurement_date"] != "2026-07-21"
    ):
        raise ValueError("San Juan well misused as Santurce measurement")
    zones = record["prospective_study_zones"]
    if len(zones) != 3 or any(
        z["depth_estimate_m"] is not None
        or z["actual_station_measurements_available"] is not False
        for z in zones
    ):
        raise ValueError("Historically motivated terrain zones imply numbers")
    if len(record["discrepancies"]) != 4:
        raise ValueError("Missing hydrogeologic distinction")
    for needed in (
        "regional_quadrangle_assumption_to_parcel_depth",
        "2006_construction_level_to_2026_current",
        "qualitative_flooding_to_numeric_groundwater_depth",
        "wells_outside_verified_santurce_to_santurce_data",
        "modelled_water_table_to_ground_surveyed_water_table",
        "document_date_to_groundwater_measurement_date",
        "any_religious_historic_structure_georeferencing",
        "unreviewed_groundwater_value_to_canonical_map",
    ):
        if needed not in record["prohibited_promotions"]:
            raise ValueError("Mandatory source authority hold missing")
    return True


class SanturceGroundwaterEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_candidate_research_is_noncanonical(self):
        self.assertTrue(validate(self.record))
        self.assertFalse(self.record["current_water_table_map_available"])

    def test_shallow_lowland_is_regional_not_a_subbarrio_prediction(self):
        obs = self.record["groundwater_evidence"][0]
        self.assertEqual(obs["upper_bound_m_below_ground"], 1.5)
        self.assertFalse(obs["site_specific_measurement"])
        self.assertIsNone(obs["subbarrio_id"])

    def test_2006_project_retains_date_method_and_boring_limits(self):
        obs = self.record["groundwater_evidence"][2]
        self.assertEqual(obs["reported_depth_ft_below_ground"], [8, 10])
        self.assertIsNone(obs["measurement_event_date"])
        self.assertFalse(obs["boring_log_available"])

    def test_nearby_usgs_reading_cannot_replace_santurce_measurement(self):
        well = self.record["source_register"][4]
        self.assertFalse(well["eligible_for_santurce_depth_inference"])

    def test_fail_closed_on_invented_parcel_reading_or_source_custody(self):
        tests = [
            (("canonical_write_authorized",), True),
            (("current_water_table_map_available",), True),
            (("source_register", 1, "source_binary_sha256"), "a" * 64),
            (("groundwater_evidence", 0, "site_specific_measurement"), True),
            (("groundwater_evidence", 0, "upper_bound_m_below_ground"), 0.1),
            (("groundwater_evidence", 1,
              "modelling_conservative_assumed_max_depth_m"), 6.2),
            (("groundwater_evidence", 2, "measurement_event_date"), "2006-02-16"),
            (("groundwater_evidence", 2, "reported_depth_ft_below_ground"),
             [4, 6]),
            (("groundwater_evidence", 3, "hydrogeology_numeric_depth_m"), 0.5),
            (("source_register", 4, "eligible_for_santurce_depth_inference"),
             True),
            (("prospective_study_zones", 0, "depth_estimate_m"), 0.8),
            (("prohibited_promotions",),
             ["generic"]),
        ]
        for keys, value in tests:
            with self.subTest(mutated=keys):
                altered = copy.deepcopy(self.record)
                obj = altered
                for key in keys[:-1]:
                    obj = obj[key]
                obj[keys[-1]] = value
                with self.assertRaises(ValueError):
                    validate(altered)


if __name__ == "__main__":
    unittest.main()
