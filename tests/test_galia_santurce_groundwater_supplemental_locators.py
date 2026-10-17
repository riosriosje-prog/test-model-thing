"""Noncanonical USACE/NRCS archival locator intake tests for Santurce.

The existence of an official borehole-PDF catalog and a soil-series description
does not establish the site-level water-table depth or a surveyed location.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SUPPLEMENT=ROOT/"research/gates/santurce_groundwater_supplemental_locators.v0_1.json"
MANIFEST=ROOT/"research/gates/santurce_groundwater_evidence.v0_1.json"


def gate(doc,main):
    if (
        doc["schema"]!="galia.santurce.groundwater.supplemental_source_locator.v0.1"
        or doc["state"]!="AUTHORITY_HOLD"
        or doc["canonical_write_authorized"] is not False
        or doc["georeferencing_authorized"] is not False
        or doc["verified_santurce_water_level_station_count"]!=0
        or doc["review_status"]!="PENDING_HUMAN_HYDROGEOLOGICAL_AND_ARCHIVAL_REVIEW"
    ):
        raise ValueError("supplement authority falsely promoted")
    if (
        main["state"]!="AUTHORITY_HOLD"
        or main["canonical_write_authorized"] is not False
        or main["current_water_table_map_available"] is not False
        or main["source_register"].__len__()!=7
        or main["groundwater_evidence"].__len__()!=12
        or main["supplemental_uncaptured_sources"]["path"]!=
           "research/gates/santurce_groundwater_supplemental_locators.v0_1.json"
        or main["supplemental_uncaptured_sources"]["additional_official_source_locators"]!=2
        or main["supplemental_uncaptured_sources"]["additional_confirmed_santurce_water_level_measurements"]!=0
        or main["supplemental_uncaptured_sources"]["counted_as_groundwater_evidence_observation"] is not False
    ):
        raise ValueError("supplement imported as verified groundwater")
    x=doc["sources"]
    if len(x)!=2 or {s["id"] for s in x}!={
        "USDA-NRCS-OSD-MARTIN-PENA-SERIES",
        "USACE-SJM-APPENDIX-A-BORING-LOGS-2021"
    }:
        raise ValueError("source catalog inventory drift")
    for src in x:
        if src["source_original_bytes_received"] is not False or src["source_sha256"] is not None:
            raise ValueError("unearned source-image custody or digest")
    n=next(s for s in x if s["id"]=="USDA-NRCS-OSD-MARTIN-PENA-SERIES")
    if (
        n["series_established"]!=1942
        or n["revision"]!="2000-08"
        or n["type_pedon_in_santurce"] is not False
        or n["mapped_santurce_soil_polygon_verified"] is not False
        or n["depth_to_water_at_santurce_cm"] is not None
        or n["present_day_measurement_valid"] is not False
        or n["soil_series_drainage"]!="VERY_POORLY_DRAINED"
        or n["soil_series_permeability"]!="VERY_SLOW"
    ):
        raise ValueError("NRCS classification promoted to Santurce well")
    u=next(s for s in x if s["id"]=="USACE-SJM-APPENDIX-A-BORING-LOGS-2021")
    if (
        u["library_record_id"]!="19169"
        or u["reported_catalog_pdf_page_count"]!=225
        or u["reported_catalog_pdf_file_bytes"]!=16127707
        or u["individual_boring_log_read"] is not False
        or u["specific_boring_station_id"] is not None
        or u["individual_boring_location"] is not None
        or u["individual_boring_inside_santurce_verified"] is not False
        or u["date_of_boring_verified"] is not None
        or u["static_groundwater_depth_ft_below_surface"] is not None
        or u["level_elevation_prvd02_ft"] is not None
        or u["datum_transformation_verified"] is not False
        or u["catalog_lat_lon_is_borehole_site"] is not False
        or u["original_vertical_datums"]!=["MSL","NGVD29","MLW","MLLW"]
    ):
        raise ValueError("USACE project catalog misused as borehole result")
    plans=doc["archive_search"]
    if len(plans)!=2 or any(x["received"] is not False for x in plans):
        raise ValueError("unearned archival source receipt")
    if plans[0]["verified_station_count"]!=0 or plans[1]["verified_santurce_polygon_count"]!=0:
        raise ValueError("unearned verified station or mapped series")
    e=doc["epa_2015_original_data_acquisition"]
    if (
        e["source_reference"]!="Slide 15: See master data sheet"
        or e["email_published_on_pdf_zero_based_page"]!=22
        or e["outbound_request_sent"] is not False
        or e["master_data_sheet_url_located"] is not False
        or e["master_data_sheet_file_received"] is not False
        or e["site_logs_received"] is not False
        or e["per_site_GPS_coordinates_verified"] is not False
        or e["email_current_deliverability_verified"] is not False
    ):
        raise ValueError("EPA archival contact promoted to data receipt")
    for hold in (
        "nrcs_sabana_seca_type_pedon_to_santurce_street_level",
        "nrcs_high_water_table_soil_series_to_exact_water_depth_cm",
        "usace_public_catalog_location_to_boring_coordinates",
        "usace_1988_2020_diverse_datum_series_to_current_water_level",
        "usace_offshore_mlw_to_upland_santurce_ground_surface",
        "usace_225_page_catalog_to_source_binary_captured",
        "epa_researcher_contact_to_sent_data_request",
        "epa_slide15_see_master_sheet_to_master_sheet_obtained",
    ):
        if hold not in doc["prohibited_promotions"]:
            raise ValueError("missing noncanonical geodata hold")
    return True


class SanturceSupplementalArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=json.loads(SUPPLEMENT.read_text(encoding="utf-8"))
        cls.main=json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_public_official_sources_are_locators_only(self):
        self.assertTrue(gate(self.doc,self.main))
        self.assertEqual(self.doc["verified_santurce_water_level_station_count"],0)

    def test_soil_series_is_not_santurce_type_pedon(self):
        n=self.doc["sources"][0]
        self.assertIn("Sabana Seca",n["type_pedon_location"])
        self.assertFalse(n["mapped_santurce_soil_polygon_verified"])
        self.assertIsNone(n["depth_to_water_at_santurce_cm"])

    def test_offshore_logs_require_individual_datum_and_ground_level(self):
        u=self.doc["sources"][1]
        self.assertFalse(u["individual_boring_log_read"])
        self.assertIsNone(u["static_groundwater_depth_ft_below_surface"])
        self.assertIsNone(u["level_elevation_prvd02_ft"])
        self.assertFalse(u["datum_transformation_verified"])

    def test_unverified_source_appointments_and_values_fail_closed(self):
        edits=[
            (("sources",0,"type_pedon_in_santurce"),True),
            (("sources",0,"depth_to_water_at_santurce_cm"),0),
            (("sources",1,"individual_boring_inside_santurce_verified"),True),
            (("sources",1,"static_groundwater_depth_ft_below_surface"),1.5),
            (("sources",1,"catalog_lat_lon_is_borehole_site"),True),
            (("sources",1,"datum_transformation_verified"),True),
            (("sources",1,"source_sha256"),"b"*64),
            (("archive_search",0,"verified_station_count"),1),
            (("epa_2015_original_data_acquisition","outbound_request_sent"),True),
            (("epa_2015_original_data_acquisition","master_data_sheet_file_received"),True),
            (("verified_santurce_water_level_station_count",),1)
        ]
        for path,value in edits:
            with self.subTest(path=path):
                d=copy.deepcopy(self.doc)
                obj=d
                for k in path[:-1]:
                    obj=obj[k]
                obj[path[-1]]=value
                with self.assertRaises(ValueError):
                    gate(d,self.main)

    def test_supplement_must_not_modify_original_evidence_inventory(self):
        d=copy.deepcopy(self.main)
        d["supplemental_uncaptured_sources"][
            "additional_confirmed_santurce_water_level_measurements"
        ]=2
        with self.assertRaises(ValueError):
            gate(self.doc,d)


if __name__=="__main__":
    unittest.main()
