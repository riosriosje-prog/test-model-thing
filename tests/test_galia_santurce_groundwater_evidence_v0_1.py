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
    if len(source_by_id) != 7 or len(record["source_register"]) != 7:
        raise ValueError("Unexpected or duplicate source IDs")
    if any(s["source_binary_sha256"] is not None
           or s["source_binary_retained"] is not False
           for s in record["source_register"]):
        raise ValueError("Invented captured-source digest")
    obs = record["groundwater_evidence"]
    if len(obs) != 12 or len({o["observation_id"] for o in obs}) != 12:
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
        "reported_regional_depth_m_approx" in model
        or "LESS THAN" not in model["reported_regional_depth_text"]
        or model["santurce_sands_geologic_unit_code"] != "Qss"
        or model["santurce_sands_Qss_groundwater_depth_m_approx"] != [2, 7]
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

    epa = source_by_id.get("EPA-SHUSTER-ENLACE-SOIL-HYDROLOGY-MAR2015")
    if not epa or (
        epa["source_kind"] !=
        "EPA_ORIGINAL_TECHNICAL_SLIDES_FIELD_SATURATION_CATEGORICAL_MAP_VISUALLY_REVIEWED"
        or epa["field_campaign_month"] != "2015-03"
        or epa["source_pdf_water_table_slide_index_zero_based"] != 10
        or epa["visual_slide_inspected"] is not True
        or epa["source_binary_retained"] is not False
        or epa["source_binary_sha256"] is not None
        or epa["per_site_field_logs_retained"] is not False
        or epa["per_site_measurement_day"] is not None
    ):
        raise ValueError("EPA source or fieldwork provenance misrepresented")
    classes = [o for o in obs if
        o["type"] == "EPA_FIELD_DEPTH_TO_SATURATION_CLASS_2015"]
    expected = {
        "Calle Paraguay": (None, 70, "UP_TO_AND_INCLUDING"),
        "Calle del Pilar": (71, 85, "INCLUSIVE_INTERVAL"),
        "Plaza Israel": (86, 100, "INCLUSIVE_INTERVAL"),
        "Calle 14": (110, 120, "INCLUSIVE_INTERVAL"),
        "Calle Principal": (110, 120, "INCLUSIVE_INTERVAL"),
        "Calle San José": (130, 160, "INCLUSIVE_INTERVAL"),
        "Calle C": (130, 160, "INCLUSIVE_INTERVAL"),
        "Calle William": (None, None, "NO_RESULT_NULL"),
    }
    if len(classes) != 8 or {
        x["site_label_on_figure"] for x in classes
    } != set(expected):
        raise ValueError("Field screening labels or count changed")
    for point in classes:
        if (
            point["source_id"] != "EPA-SHUSTER-ENLACE-SOIL-HYDROLOGY-MAR2015"
            or (
                point["categorical_lower_bound_cm"],
                point["categorical_upper_bound_cm"],
                point["categorical_interval_interpretation"],
            ) != expected[point["site_label_on_figure"]]
            or point["measured_exact_numeric_value_cm"] is not None
            or point["quantity"] !=
                "DEPTH_TO_SATURATION_SCREENING_CLASS_CM_BELOW_LOCAL_GROUND"
            or point["source_pdf_page_zero_based"] != 10
            or point["observation_month_candidate"] != "2015-03"
            or point["observation_event_date"] is not None
            or point["well_or_piezometer_id"] is not None
            or point["original_field_log_available"] is not False
            or point["station_coordinates_available_in_source"] is not False
            or point["hydraulic_head_elevation"] is not None
            or point["hydrological_well_level_certified"] is not False
            or point["location_verified_inside_santurce_subbarrio"] is not False
            or point["quantity_is_current"] is not False
        ):
            raise ValueError("EPA legend class falsely promoted to a well reading")
    for needed in (
        "epa_water_table_figure_color_class_to_exact_centimeter_measurement",
        "epa_2015_depth_to_saturation_to_2026_current_groundwater",
        "epa_field_saturation_to_piezometer_equilibrium_hydraulic_head",
        "epa_fig_map_markers_to_unreviewed_exact_geographic_coordinates",
        "epa_named_street_label_to_confirmed_santurce_subbarrio",
        "epa_null_calle_william_to_numeric_zero_depth",
        "regional_sanjuan_less_than_3_to_7m_upper_bound_to_3_to_7m_santurce_measured_interval",
    ):
        if needed not in record["prohibited_promotions"]:
            raise ValueError("Missing hydropedology epistemic barrier")

    # Slide 15: three STRATIGRAPHIC soil-profile variables, not precise
    # time-varying water-table depth or equilibrium piezometer readings.
    table = record["epa_2015_pedon_profile_table"]
    kaye = source_by_id.get("USGS-KAYE-1959-PP317A")
    if (
        table["source_id"] != "EPA-SHUSTER-ENLACE-SOIL-HYDROLOGY-MAR2015"
        or table["pdf_page_index_zero_based"] != 15
        or table["printed_slide_number"] != 15
        or table["current_groundwater_level_interpretation_authorized"] is not False
        or table["original_pdf_binary_sha256"] is not None
        or table["original_field_master_sheet_available"] is not False
        or table["map_legends_and_table_are_separate_representations"] is not True
        or table["field_sample_date_per_site"] is not None
        or table["independent_boring_log_receipt"] is not None
        or table["no_extrapolation_to_citywide_average"] is not True
        or epa["source_pdf_pedon_profile_table_index_zero_based"] != 15
        or epa["full_master_data_sheet_referenced_but_not_obtained"] is not True
    ):
        raise ValueError("EPA soil-profile table presented as certified water table")
    profile_expected = {
        "Calle 14": ([35,120],[120,420],[0,150]),
        "Calle William": ([120,360],None,[0,360]),
        "Calle del Pilar": (None,[85,360],[0,360]),
        "Calle Principal": (None,[120,360],[0,360]),
        "Plaza Israel": ([0,25],[100,360],[0,140]),
        "Calle Paraguay": (None,[70,240],[0,215]),
        "Calle C": (None,[160,240],[0,160]),
        "Calle San José": (None,[160,360],[0,150]),
    }
    if (
        len(table["rows"]) != 8
        or {p["site_label_on_slide"] for p in table["rows"]} != set(profile_expected)
    ):
        raise ValueError("EPA slide 15 soil-profile rows missing/duplicated")
    for profile in table["rows"]:
        expected = profile_expected[profile["site_label_on_slide"]]
        if (
            (
                profile["redox_interval_cm"],
                profile["saturation_profile_interval_cm"],
                profile["anthropogenic_material_interval_cm"]
            ) != expected
            or profile["source_figure_depth_to_saturation_class_preserved_separately"] is not True
            or profile["exact_groundwater_head_measurement_cm"] is not None
            or profile["piezometer_equilibrium_record_available"] is not False
            or profile["per_site_field_data_sheet_available"] is not False
            or profile["geographic_coordinates_verified"] is not False
            or profile["local_subbarrio_polygon_verified"] is not False
            or profile["depth_reference_datum_verified"] is not False
            or profile["groundwater_level_2026"] is not None
            or profile["human_review_status"] != "PENDING"
        ):
            raise ValueError("Soil-profile interval elevated to quantified aquifer")
    geo = record["geological_sand_boring_context"]
    if (
        kaye is None
        or kaye["publication_year"] != 1959
        or kaye["doi"] != "10.3133/pp317A"
        or kaye["metadata_verified_from_usgs_publication_warehouse"] is not True
        or kaye["original_page_image_visual_review"] is not False
        or kaye["original_boring_log_available"] is not False
        or kaye["source_binary_sha256"] is not None
        or kaye["source_report_year_is_not_boring_event_year"] is not True
        or geo["source_id"] != kaye["source_id"]
        or geo["measured_stratigraphic_penetration_ft"] != 80
        or geo["boring_reached_bottom_of_sand"] is not False
        or geo["water_table_depth_recorded_ft"] is not None
        or geo["groundwater_level_measured"] is not False
        or geo["water_level_measurement_date"] is not None
        or geo["historical_map_grid_coordinate_system_verified"] is not False
        or geo["old_coordinate_to_modern_geodesy_crosswalk_allowed"] is not False
        or geo["exact_surveyed_station_location_verified"] is not False
        or geo["coordinates"] is not None
        or geo["human_review_status"] != "PENDING"
    ):
        raise ValueError("1959 lithologic thickness falsely converted to groundwater")
    for needed in (
        "epa_profile_interval_to_exact_water_table_level",
        "epa_anthropogenic_debris_depth_to_groundwater_depth",
        "epa_redox_depth_to_current_groundwater_depth",
        "epa_null_saturation_to_dry_or_zero_saturation",
        "epa_slide15_depth_interval_to_slide10_legend_class_identity",
        "usgs_kaye_80ft_lithology_to_80ft_water_table",
        "usgs_kaye_1959_report_year_to_specific_boring_date",
        "old_unverified_grid_coordinates_to_present_day_santurce_pin",
    ):
        if needed not in record["prohibited_promotions"]:
            raise ValueError("Missing observed-stratum vs groundwater gate")
    zones = record["prospective_study_zones"]
    if len(zones) != 3 or any(
        z["depth_estimate_m"] is not None
        or z["actual_station_measurements_available"] is not False
        for z in zones
    ):
        raise ValueError("Historically motivated terrain zones imply numbers")
    if len(record["discrepancies"]) != 9:
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


    def test_epa_march2015_has_seven_bands_and_one_missing_point(self):
        points = self.record["groundwater_evidence"][4:]
        self.assertEqual(len(points), 8)
        self.assertEqual(
            sum(p["categorical_upper_bound_cm"] is not None for p in points),
            7,
        )
        missing = next(
            p for p in points if p["site_label_on_figure"] == "Calle William"
        )
        self.assertEqual(
            missing["categorical_interval_interpretation"], "NO_RESULT_NULL"
        )
        self.assertTrue(all(p["measured_exact_numeric_value_cm"] is None
                            for p in points))
        self.assertTrue(validate(self.record))

    def test_epa_field_category_cannot_claim_piezometer_or_subbarrio(self):
        changes = (
            (("groundwater_evidence", 4, "measured_exact_numeric_value_cm"), 70),
            (("groundwater_evidence", 5, "observation_event_date"), "2015-03-17"),
            (("groundwater_evidence", 6, "well_or_piezometer_id"), "W-99"),
            (("groundwater_evidence", 7, "hydraulic_head_elevation"), 3.5),
            (("groundwater_evidence", 8,
              "location_verified_inside_santurce_subbarrio"), True),
            (("groundwater_evidence", 9, "categorical_lower_bound_cm"), 101),
            (("groundwater_evidence", 10, "source_pdf_page_zero_based"), 9),
            (("groundwater_evidence", 11, "categorical_upper_bound_cm"), 0),
            (("source_register", 5, "per_site_measurement_day"), "2015-03-15"),
            (("source_register", 5, "source_binary_sha256"), "a" * 64),
        )
        for route, value in changes:
            with self.subTest(field=route):
                changed = copy.deepcopy(self.record)
                item = changed
                for key in route[:-1]:
                    item = item[key]
                item[route[-1]] = value
                with self.assertRaises(ValueError):
                    validate(changed)


    def test_epa_profile_rows_are_2015_soil_horizons_not_well_levels(self):
        details=self.record["epa_2015_pedon_profile_table"]
        self.assertEqual(len(details["rows"]),8)
        self.assertTrue(details["map_legends_and_table_are_separate_representations"])
        self.assertTrue(details["no_extrapolation_to_citywide_average"])
        missing=next(x for x in details["rows"] if x["site_label_on_slide"]=="Calle William")
        self.assertIsNone(missing["saturation_profile_interval_cm"])
        self.assertEqual(missing["anthropogenic_material_interval_cm"],[0,360])
        self.assertTrue(validate(self.record))

    def test_1959_kaye_sand_boring_is_lithology_not_water_table(self):
        hole=self.record["geological_sand_boring_context"]
        self.assertEqual(hole["measured_stratigraphic_penetration_ft"],80)
        self.assertFalse(hole["groundwater_level_measured"])
        self.assertIsNone(hole["water_table_depth_recorded_ft"])
        self.assertFalse(hole["historic_boring_not_georeferenced"] is False)
        self.assertIsNone(hole["coordinates"])

    def test_soil_horizon_misclassification_fails_closed(self):
        edits=[
            (("epa_2015_pedon_profile_table","rows",0,"saturation_profile_interval_cm"),[120,150]),
            (("epa_2015_pedon_profile_table","rows",1,"saturation_profile_interval_cm"),[0,0]),
            (("epa_2015_pedon_profile_table","rows",2,"exact_groundwater_head_measurement_cm"),85),
            (("epa_2015_pedon_profile_table","rows",3,"piezometer_equilibrium_record_available"),True),
            (("epa_2015_pedon_profile_table","rows",4,"anthropogenic_material_interval_cm"),[0,360]),
            (("epa_2015_pedon_profile_table","rows",5,"groundwater_level_2026"),1.0),
            (("epa_2015_pedon_profile_table","field_sample_date_per_site"),"2015-03-16"),
            (("source_register",6,"original_page_image_visual_review"),True),
            (("geological_sand_boring_context","water_table_depth_recorded_ft"),80),
            (("geological_sand_boring_context","old_coordinate_to_modern_geodesy_crosswalk_allowed"),True)
        ]
        for route,value in edits:
            with self.subTest(field=route):
                changed=copy.deepcopy(self.record)
                node=changed
                for k in route[:-1]:
                    node=node[k]
                node[route[-1]]=value
                with self.assertRaises(ValueError):
                    validate(changed)

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
