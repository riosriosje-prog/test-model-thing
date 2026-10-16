"""Fail-closed, read-only tests for Calle Loíza documentary crossroads.

This candidate manifest reports dated administrative *observations*, not
creation of a roadway, verification of original bytes, or a municipal naming act.
"""
import copy
import json
from pathlib import Path
import unittest


RECORD = (
    Path(__file__).resolve().parents[1]
    / "research/gates/loiza_1940_1947_documentary_crossings.v0_1.json"
)


def gate(candidate):
    """Reject any research state pretending to have source or naming authority."""
    if candidate["schema_version"] != "galia.research.loiza_corridor_candidate.v0.1":
        raise ValueError("unexpected version")
    if candidate["state"] != "AUTHORITY_HOLD":
        raise ValueError("must remain on hold")
    for field in (
        "canonical_write_authorized", "raw_capture_complete",
        "reviewed_original_source_bytes", "georeferencing_authorized",
    ):
        if candidate[field] is not False:
            raise ValueError(f"unsafe authority flag: {field}")
    if candidate["human_review_state"] != "PENDING":
        raise ValueError("unearned historical approval")
    sources = candidate["sources"]
    source_ids = [s["source_id"] for s in sources]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("duplicate source IDs")
    if not all(
        s["source_binary_sha256"] is None
        and s["source_binary_byte_length"] is None
        and s["source_bytes_retained"] is False
        for s in sources
    ):
        raise ValueError("invented primary source capture")
    # A visually checked caption on a later NPS registration is NOT a
    # visual check of the original Fire Underwriters map cartouche.
    source_by_id = {s["source_id"]: s for s in sources}
    nps_id = "NPS-NRHP-LOAIZA-CORDERO-FIG19-1918"
    if nps_id not in source_by_id:
        raise ValueError("missing independent institutional map caption")
    nps = source_by_id[nps_id]
    crosswalk = candidate["cartographic_comparison_1917_1918"]
    dates = crosswalk["date_discrepancy"]
    if (
        nps["discovery_mode"] !=
        "INSTITUTIONAL_SECONDARY_FIGURE_CAPTION_VISUALLY_READ"
        or nps["figure_number"] != 19
        or nps["reviewed_printed_pages"] != [36]
        or nps["viewed_pdf_page_index_zero_based"] != 37
        or nps["figure_caption_map_section"] != "SECOND"
        or nps["figure_caption_document_date"] != "1918-01-30"
        or nps["figure_caption_visually_checked"] is not True
        or nps["original_fire_underwriters_map_cartouche_checked"] is not False
    ):
        raise ValueError("Figure 19 caption provenance altered")
    if (
        nps_id not in crosswalk["map_sources"]
        or dates["nps_registration_figure19_caption_date"] !=
           nps["figure_caption_document_date"]
        or dates["nps_caption_visually_checked"] is not True
        or dates["secondary_january_agreement"] is not True
        or dates["indexed_study_map_approval_date"] !=
           nps["figure_caption_document_date"]
        or dates["geo_isla_second_section_date"] != "1918-06-30"
        or dates["resolution"] != "UNRESOLVED"
        or dates["cartouche_original_image_checked"] is not False
        or dates["authoritative_map_revision_date"] is not None
        or dates["event_date"] is not None
    ):
        raise ValueError("secondary date dispute prematurely resolved")
    if "nrhp_figure_caption_to_original_cartouche_authentication" not in (
        candidate["prohibited_promotions"]
    ):
        raise ValueError("secondary caption promotion prohibition omitted")
    # NPS historic narrative is a SECONDARY reading of a UPR archive work.
    # It must not automatically turn two modern street names into one
    # surveyed historical alignment or a documented naming act.
    road_id = "NPS-NRHP-ASHFORD-LOIZA-ROAD-WILSON-1918-MAP"
    if road_id not in source_by_id:
        raise ValueError("missing Ashford NPS route history citation")
    ashford = source_by_id[road_id]
    route = candidate["earlier_route_history_hypothesis"]
    if (
        route["source_id"] != road_id
        or route["source_printed_page"] != 30
        or route["source_pdf_page_index_zero_based"] != 29
        or route["source_text_form"] !=
           "Loíza Road (today Wilson Street and Loiza Street)"
        or route["source_claimed_period"] != "nineteenth century"
        or route["discovery_tier"] !=
           "SECONDARY_HISTORICAL_NARRATIVE_NOT_PRIMARY_ROAD_SURVEY"
        or route["human_review_state"] != "PENDING"
        or route["canonical_write_authorized"] is not False
        or route["geometry"] is not None
        or route["event_date"] is not None
        or route["road_opening_date"] is not None
        or route["name_change_date"] is not None
        or route["specific_shared_segment_verified"] is not False
        or route["historic_to_modern_alignment_verified"] is not False
        or route["nominative_act_verified"] is not False
        or route["relationship_to_1940_loiza_rd"] !=
           "UNRESOLVED_NAMING_AND_SEGMENT_EQUIVALENCE"
    ):
        raise ValueError("Loiza/Wilson historical road narrative promoted")
    dates = crosswalk["date_discrepancy"]
    if (
        ashford["discovery_mode"] !=
        "INSTITUTIONAL_SECONDARY_TEXT_AND_FIGURE_VISUALLY_READ"
        or ashford["reviewed_printed_pages"] != [30, 33]
        or ashford["reviewed_pdf_page_index_zero_based"] != [29, 32]
        or ashford["road_history_footnote_number"] != 41
        or ashford["road_history_referred_work_independently_checked"] is not False
        or ashford["map_figure_number"] != 29
        or ashford["map_figure_footnote_number"] != 46
        or ashford["map_figure_footnote_date"] != "1918-01-30"
        or ashford["figure_29_visually_checked"] is not True
        or ashford["original_fire_underwriters_map_cartouche_checked"] is not False
        or road_id not in crosswalk["map_sources"]
        or dates["nps_ashford_figure29_footnote_date"] != "1918-01-30"
        or dates["nps_ashford_source_printed_page"] != 33
        or dates["nps_ashford_source_pdf_page_index_zero_based"] != 32
        or dates["nps_ashford_figure29_visually_checked"] is not True
        or dates["nps_ashford_original_map_cartouche_checked"] is not False
        or dates["january_secondary_references_count"] != 3
        or dates["resolution"] != "UNRESOLVED"
        or dates["authoritative_map_revision_date"] is not None
    ):
        raise ValueError("Ashford NPS citation or map-date evidence improperly promoted")
    for prohibition in (
        "nps_19c_loiza_road_to_verified_wilson_loiza_alignment",
        "nps_19c_road_narrative_to_municipal_naming_act",
        "nps_figure29_footnote_to_original_1918_cartouche_authentication",
    ):
        if prohibition not in candidate["prohibited_promotions"]:
            raise ValueError("missing Wilson-Loiza or 1918 cartouche quarantine")
    allowed = set(source_ids)
    observations = candidate["observations"]
    ids = [o["observation_id"] for o in observations]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate observations")
    for o in observations:
        if o["source_id"] not in allowed:
            raise ValueError("unattributed observation")
        if o["human_review_state"] != "PENDING" or o["geometry"] is not None:
            raise ValueError("unreviewed geometry or human promotion")
        if o["reference_year"] not in (1940, 1947):
            raise ValueError("unknown document era")
        if o.get("event_date") is not None:
            raise ValueError("document date promoted to event date")
        if o.get("historical_street_opening_date") is not None:
            raise ValueError("road opening date claimed without source")
        if o["reference_year"] == 1947:
            if o["source_id"] != "JPUZ-PR-MEM06-1947":
                raise ValueError("1947 pages attributed to wrong source")
            if not o["source_printed_pages"] or not all(
                p in (26, 28, 29, 31) for p in o["source_printed_pages"]
            ):
                raise ValueError("unverified 1947 page")
            if o.get("document_event_date_equivalence") is not False:
                raise ValueError("document date treated as naming event")
        if o["reference_year"] == 1940:
            census_sources = {
                "ED 8-55": "NARA-1940-ED8-55",
                "ED 8-82": "NARA-1940-ED8-82",
                "ED 8-83": "NARA-1940-ED8-83-84",
                "ED 8-84": "NARA-1940-ED8-83-84",
                "ED 8-89": "NARA-1940-ED8-89-90-91",
                "ED 8-90": "NARA-1940-ED8-89-90-91",
            }
            district = o.get("census_district")
            if district not in census_sources:
                raise ValueError("unverified census ED")
            if o["source_id"] != census_sources[district]:
                raise ValueError("1940 census district attributed to wrong NARA item")
            if district == "ED 8-55":
                if o.get("source_spelling") != "LOIZA RD":
                    raise ValueError("LOIZA RD spelling was incorrectly normalized")
                if "LOIZA RD" not in o["referenced_streets"]:
                    raise ValueError("original road-name form omitted")
            if district in ("ED 8-82", "ED 8-83", "ED 8-84"):
                if o.get("source_spelling") != "CALLE LOIZA":
                    raise ValueError("1940 Calle Loiza transcription drift")
            if district in ("ED 8-83", "ED 8-84"):
                expected = {"CALLE MCLEARY", "CARRION COURT", "CALLE CORDERO"}
                if not expected.issubset(set(o["referenced_streets"])):
                    raise ValueError("McLeary/Carrion/Cordero boundary evidence lost")
    for flag in (
        "street_name_to_official_nominative_act",
        "kings_court_to_mcleary_same_road",
        "boundary_description_to_precise_polygon_or_geopoint",
        "religious_historic_structure_georeferencing",
        "automatic_canonical_write",
    ):
        if flag not in candidate["prohibited_promotions"]:
            raise ValueError(f"missing mandatory prohibition: {flag}")
    return True


class Loiza1940And1947CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_versioned_manifest_fails_closed(self):
        self.assertTrue(gate(self.candidate))
        self.assertEqual(len(self.candidate["sources"]), 10)
        self.assertEqual(len(self.candidate["observations"]), 12)
        self.assertEqual(
            {s["discovery_mode"] for s in self.candidate["sources"]
             if s["source_id"].startswith("NARA-1940-")},
            {"NARA_METADATA_MIRROR_ONLY"},
        )

    def test_1940_and_1947_are_distinct_documentary_windows(self):
        years = [o["reference_year"] for o in self.candidate["observations"]]
        self.assertEqual(years.count(1940), 6)
        self.assertEqual(years.count(1947), 6)
        self.assertEqual(
            {o["census_district"] for o in self.candidate["observations"]
             if o["reference_year"] == 1940},
            {"ED 8-55", "ED 8-82", "ED 8-83",
             "ED 8-84", "ED 8-89", "ED 8-90"},
        )

    def test_1947_kings_court_is_a_named_crossing_not_mcleary_identity(self):
        crossing = next(
            o for o in self.candidate["observations"]
            if o["observation_id"] == "LOIZA-1947-KINGS-COURT-SAN-JORGE"
        )
        self.assertEqual(
            set(crossing["intersection_street_names"]),
            {"Calle Loíza", "King's Court", "Calle San Jorge"}
        )
        self.assertEqual(crossing["source_printed_pages"], [31])
        self.assertIsNone(crossing["geometry"])
        self.assertIn(
            "kings_court_to_mcleary_same_road",
            self.candidate["prohibited_promotions"]
        )

    def test_1940_calle_loiza_and_loiza_road_remain_distinct(self):
        census = {
            o["census_district"]: o for o in self.candidate["observations"]
            if o["reference_year"] == 1940
        }
        self.assertEqual(census["ED 8-55"]["source_spelling"], "LOIZA RD")
        for district in ("ED 8-82", "ED 8-83", "ED 8-84"):
            self.assertEqual(census[district]["source_spelling"], "CALLE LOIZA")
        for district in ("ED 8-83", "ED 8-84"):
            self.assertIn("CALLE MCLEARY", census[district]["referenced_streets"])
            self.assertIn("CARRION COURT", census[district]["referenced_streets"])
            self.assertIsNone(census[district]["geometry"])
            self.assertIsNone(census[district]["event_date"])
        self.assertIn(
            "1940_loiza_rd_to_calle_loiza_continuity_without_cartographic_verification",
            self.candidate["prohibited_promotions"],
        )
        self.assertIn(
            "1940_mcleary_carrion_mentions_to_exact_intersection_or_road_naming_date",
            self.candidate["prohibited_promotions"],
        )

    def test_1940_source_attribution_or_spelling_drift_is_rejected(self):
        for label, district, field, value in (
            ("wrong_naid", "ED 8-83", "source_id", "NARA-1940-ED8-82"),
            ("false_road_continuity", "ED 8-55", "source_spelling", "CALLE LOIZA"),
            ("wrong_source_form", "ED 8-84", "source_spelling", "LOIZA RD"),
            ("lost_mcleary", "ED 8-83", "referenced_streets", ["CALLE LOIZA"]),
        ):
            altered = copy.deepcopy(self.candidate)
            item = next(
                o for o in altered["observations"]
                if o.get("census_district") == district
            )
            item[field] = value
            with self.subTest(mutation=label):
                with self.assertRaises(ValueError):
                    gate(altered)

    def test_unearned_source_hash_approval_or_geometry_are_rejected(self):
        cases = [
            ("source_sha", lambda m: m["sources"][0].__setitem__(
                "source_binary_sha256", "a" * 64)),
            ("canonical", lambda m: m.__setitem__(
                "canonical_write_authorized", True)),
            ("approval", lambda m: m.__setitem__(
                "human_review_state", "APPROVED")),
            ("georeference", lambda m: m["observations"][2].__setitem__(
                "geometry", {"latitude": 18.0, "longitude": -66.0})),
            ("street_event", lambda m: m["observations"][2].__setitem__(
                "historical_street_opening_date", "1947-01-01")),
            ("wrong_source", lambda m: m["observations"][2].__setitem__(
                "source_id", "NARA-1940-ED8-89-90-91")),
        ]
        for label, mutation in cases:
            with self.subTest(mutation=label):
                altered = copy.deepcopy(self.candidate)
                mutation(altered)
                with self.assertRaises(ValueError):
                    gate(altered)

    def test_second_section_date_discrepancy_remains_unresolved(self):
        record = self.candidate["cartographic_comparison_1917_1918"]
        dates = record["date_discrepancy"]
        self.assertEqual(record["authority_state"], "AUTHORITY_HOLD")
        self.assertEqual(record["target_section"], "SECOND")
        self.assertEqual(dates["geo_isla_second_section_date"], "1918-06-30")
        self.assertEqual(dates["indexed_study_map_approval_date"], "1918-01-30")
        self.assertNotEqual(
            dates["geo_isla_second_section_date"],
            dates["indexed_study_map_approval_date"],
        )
        self.assertEqual(dates["resolution"], "UNRESOLVED")
        self.assertFalse(dates["cartouche_original_image_checked"])
        self.assertIsNone(dates["authoritative_map_revision_date"])
        self.assertIsNone(dates["event_date"])

    def test_nps_institutional_caption_corrobates_january_not_cartouche(self):
        dates = self.candidate["cartographic_comparison_1917_1918"][
            "date_discrepancy"
        ]
        source = next(
            source for source in self.candidate["sources"]
            if source["source_id"] == "NPS-NRHP-LOAIZA-CORDERO-FIG19-1918"
        )
        self.assertEqual(dates["nps_registration_figure19_caption_date"],
                         "1918-01-30")
        self.assertEqual(source["figure_caption_document_date"], "1918-01-30")
        self.assertEqual(source["viewed_pdf_page_index_zero_based"], 37)
        self.assertEqual(source["reviewed_printed_pages"], [36])
        self.assertTrue(source["figure_caption_visually_checked"])
        self.assertFalse(source["original_fire_underwriters_map_cartouche_checked"])
        self.assertFalse(dates["cartouche_original_image_checked"])
        self.assertEqual(dates["resolution"], "UNRESOLVED")
        self.assertIsNone(dates["authoritative_map_revision_date"])
        self.assertTrue(gate(self.candidate))

    def test_forged_1918_cartouche_approval_and_caption_drift_fail_closed(self):
        def nps_source(candidate):
            return next(
                s for s in candidate["sources"]
                if s["source_id"] == "NPS-NRHP-LOAIZA-CORDERO-FIG19-1918"
            )
        cases = [
            ("fake_original_checked", lambda d: d[
                "cartographic_comparison_1917_1918"]["date_discrepancy"]
                .__setitem__("cartouche_original_image_checked", True)),
            ("premature_resolution", lambda d: d[
                "cartographic_comparison_1917_1918"]["date_discrepancy"]
                .__setitem__("resolution", "RESOLVED")),
            ("fabricated_original_date", lambda d: d[
                "cartographic_comparison_1917_1918"]["date_discrepancy"]
                .__setitem__("authoritative_map_revision_date", "1918-01-30")),
            ("altered_caption", lambda d: nps_source(d).__setitem__(
                "figure_caption_document_date", "1918-06-30")),
            ("fake_source_cartouche", lambda d: nps_source(d).__setitem__(
                "original_fire_underwriters_map_cartouche_checked", True)),
        ]
        for label, mutation in cases:
            with self.subTest(change=label):
                candidate = copy.deepcopy(self.candidate)
                mutation(candidate)
                with self.assertRaises(ValueError):
                    gate(candidate)

    def test_indexed_1918_map_labels_do_not_authenticate_crossings(self):
        record = self.candidate["cartographic_comparison_1917_1918"]
        self.assertEqual(
            set(record["indexed_only_map_labels"]),
            {"Calle Loiza", "Avenida De Diego"},
        )
        self.assertEqual(len(record["candidate_crosschecks"]), 3)
        later_ids = {
            obs["observation_id"] for obs in self.candidate["observations"]
        }
        for candidate in record["candidate_crosschecks"]:
            self.assertEqual(candidate["map_assertion_status"], "UNTESTED")
            self.assertFalse(candidate["original_map_legible_for_named_crossing"])
            self.assertFalse(candidate["pre_1940_street_intersection_established"])
            self.assertIsNone(candidate["geometry"])
            self.assertTrue(
                set(candidate["later_observation_ids"]).issubset(later_ids)
            )
        for required in (
            "index_derived_map_label_to_historical_intersection",
            "conflicted_second_section_date_to_authoritative_cartographic_date",
            "1918_map_corroboration_to_original_map_custody",
        ):
            self.assertIn(required, self.candidate["prohibited_promotions"])
        repro = next(
            source for source in self.candidate["sources"]
            if source["source_id"] ==
            "OECH-CANGREJOS-SANTURCE-S2-INDEXED-REPRODUCTION"
        )
        self.assertEqual(
            repro["discovery_mode"],
            "SEARCH_INDEX_EXTRACTED_MAP_CAPTION_NOT_ORIGINAL_MAP",
        )
        self.assertIsNone(repro["source_binary_sha256"])
        self.assertFalse(repro["source_bytes_retained"])

    def test_nps_ashford_source_records_wilson_loiza_road_hypothesis_only(self):
        route = self.candidate["earlier_route_history_hypothesis"]
        self.assertEqual(
            route["source_text_form"],
            "Loíza Road (today Wilson Street and Loiza Street)",
        )
        self.assertIsNone(route["geometry"])
        self.assertFalse(route["specific_shared_segment_verified"])
        self.assertFalse(route["historic_to_modern_alignment_verified"])
        self.assertFalse(route["nominative_act_verified"])
        self.assertEqual(
            route["relationship_to_1940_loiza_rd"],
            "UNRESOLVED_NAMING_AND_SEGMENT_EQUIVALENCE",
        )
        ashford = next(
            s for s in self.candidate["sources"]
            if s["source_id"] == route["source_id"]
        )
        self.assertEqual(ashford["road_history_footnote_number"], 41)
        self.assertFalse(ashford["road_history_referred_work_independently_checked"])
        self.assertEqual(ashford["map_figure_footnote_number"], 46)
        self.assertEqual(ashford["map_figure_footnote_date"], "1918-01-30")
        self.assertTrue(ashford["figure_29_visually_checked"])
        self.assertFalse(ashford["original_fire_underwriters_map_cartouche_checked"])

    def test_unearned_wilson_loiza_alignment_and_cartouche_fail_closed(self):
        def ashford(item):
            return next(
                s for s in item["sources"]
                if s["source_id"] == "NPS-NRHP-ASHFORD-LOIZA-ROAD-WILSON-1918-MAP"
            )
        cases = [
            ("unearned_alignment", lambda item: item[
                "earlier_route_history_hypothesis"].__setitem__(
                    "historic_to_modern_alignment_verified", True)),
            ("unearned_shared_segment", lambda item: item[
                "earlier_route_history_hypothesis"].__setitem__(
                    "specific_shared_segment_verified", True)),
            ("invented_naming_act", lambda item: item[
                "earlier_route_history_hypothesis"].__setitem__(
                    "nominative_act_verified", True)),
            ("invented_geometry", lambda item: item[
                "earlier_route_history_hypothesis"].__setitem__(
                    "geometry", {"lat": 18.4, "lon": -66.0})),
            ("asserted_1940_road_identity", lambda item: item[
                "earlier_route_history_hypothesis"].__setitem__(
                    "relationship_to_1940_loiza_rd", "SAME_ROAD")),
            ("fake_Upr_original_check", lambda item: ashford(item).__setitem__(
                "road_history_referred_work_independently_checked", True)),
            ("fabricated_map_cartouche", lambda item: ashford(item).__setitem__(
                "original_fire_underwriters_map_cartouche_checked", True)),
            ("recast_second_section_date", lambda item: item[
                "cartographic_comparison_1917_1918"]["date_discrepancy"]
                .__setitem__("resolution", "RESOLVED")),
        ]
        for label, mutation in cases:
            with self.subTest(mutation=label):
                changed = copy.deepcopy(self.candidate)
                mutation(changed)
                with self.assertRaises(ValueError):
                    gate(changed)

    def test_current_transit_stops_remain_contemporary_only(self):
        reference = self.candidate["contemporary_separate_reference"]
        self.assertEqual(reference["source_id"], "SJ-ROUTE-LOIZA-CURRENT")
        self.assertIn("modern", reference["interpretation"].lower())
        self.assertEqual(self.candidate["state"], "AUTHORITY_HOLD")


if __name__ == "__main__":
    unittest.main()
