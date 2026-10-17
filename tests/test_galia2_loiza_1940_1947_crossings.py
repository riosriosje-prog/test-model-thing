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
    # All pre-1918 newspaper discoveries are SEARCH-INDEX ONLY.
    # Even a correct-looking PDF URL or an indexed "Loiza Road" does not
    # establish an original-page capture, legal naming act or map geometry.
    press = candidate["early_press_name_use_locator_candidates"]
    press_expected = {
        "1910-07-05": (
            "UFDC-CORRESPONDENCIA-1910-07-05-08862",
            "Machuchal, camino de Loiza", "CAMINO DE LOIZA",
            "SEARCH_INDEX_MASTHEAD_OCR"),
        "1911-05-22": (
            "UFDC-TIEMPO-1911-05-22-00119",
            "Machuchal, Loiza road", "LOIZA ROAD",
            "FILENAME_DATE_UNCHECKED"),
        "1913-08-01": (
            "UFDC-TIEMPO-1913-08-01-00789",
            "In Loiza Street, Stop 44, near Park", "LOIZA STREET",
            "FILENAME_DATE_UNCHECKED"),
        "1914-06-04": (
            "UFDC-TIEMPO-1914-06-04-01048",
            "181 Loiza Road near Stop 44", "LOIZA ROAD",
            "FILENAME_DATE_UNCHECKED"),
        "1915-02-25": (
            "UFDC-TIEMPO-1915-02-25-01200",
            "179 Loiza Road. Stop 44", "LOIZA ROAD",
            "FILENAME_DATE_UNCHECKED"),
    }
    if len(press) != len(press_expected):
        raise ValueError("missing or duplicate early newspaper candidates")
    if {o["issue_date_candidate"] for o in press} != set(press_expected):
        raise ValueError("newspaper index issue dates drifted")
    for o in press:
        date = o["issue_date_candidate"]
        sid, text, spelling, date_basis = press_expected[date]
        if (
            o["source_id"] != sid
            or o["source_index_phrase"] != text
            or o["name_form"] != spelling
            or o["issue_date_basis"] != date_basis
            or o["discovery_tier"] != "PUBLIC_SEARCH_INDEX_OCR_ONLY"
            or o["index_text_visually_checked_against_page"] is not False
            or o["masthead_original_checked"] is not False
            or o["original_pdf_captured"] is not False
            or o["original_pdf_sha256"] is not None
            or o["original_page_image_hash"] is not None
            or o["original_page_number"] is not None
            or o["historical_road_segment_established"] is not False
            or o["official_street_naming_act_established"] is not False
            or o["historic_to_modern_street_identity_established"] is not False
            or o["street_opening_date"] is not None
            or o["event_date"] is not None
            or o["coordinates"] is not None
            or o["georeferencing_authorized"] is not False
            or o["human_review_state"] != "PENDING"
        ):
            raise ValueError("unverified press name has unearned historical authority")
        src = source_by_id.get(sid)
        if src is None or (
            src["discovery_mode"] !=
            "PUBLIC_SEARCH_INDEX_OCR_ONLY_NO_ORIGINAL_PDF_CAPTURE"
            or src["reported_edition_date"] != date
            or src["date_inferred_from"] != date_basis
            or src["source_binary_sha256"] is not None
            or src["source_bytes_retained"] is not False
            or src["reviewed_printed_pages"] != []
            or src["pdf_page_count"] is not None
        ):
            raise ValueError("newspaper source provenance or missing-source drift")
    for prohibition in (
        "indexed_pre1918_press_names_to_official_street_naming_act",
        "indexed_pre1918_press_classified_to_precise_address_geopoint",
        "index_date_or_ocr_to_verified_original_masthead",
        "multiple_historic_name_forms_to_same_street_geometry",
        "oldest_discovered_press_index_to_first_historical_street_mention",
    ):
        if prohibition not in candidate["prohibited_promotions"]:
            raise ValueError("missing historical pre-1918 press promotion prohibition")
    # LOC official gazette index leads are earlier than the 1910 commercial
    # candidate, but still lack inspected/custodied page images.
    prior = candidate["pre_1910_official_and_press_locator_candidates"]
    expected = {
        "1901-01-23": (
            "LOC-GACETA-1901-01-23-0077", "OFFICIAL_COURT_NOTICE",
            "en lindes con el camino de Loiza", "CAMINO DE LOIZA"),
        "1901-01-24": (
            "LOC-GACETA-1901-01-24-0080", "OFFICIAL_COURT_NOTICE",
            "seis metros al Norte con el camino de Loiza", "CAMINO DE LOIZA"),
        "1901-10-06": (
            "LOC-GACETA-1901-10-06-0121", "OFFICIAL_COURT_NOTICE",
            "colinda por el Norte con camino de Loiza", "CAMINO DE LOIZA"),
        "1909-03-09": (
            "UFDC-CORRESPONDENCIA-1909-03-09-08384",
            "COMMERCIAL_LAND_ADVERTISEMENT",
            "calle de Loiza con afirmado", "CALLE DE LOIZA"),
        "1909-11-18": (
            "LOC-CORRESPONDENCIA-1909-11-18-0873",
            "MUNICIPAL_ENGINEER_ANNUAL_REPORT_NEWS",
            "1660 metros lineales en las calles de Santurce y camino de Loiza",
            "CAMINO DE LOIZA"),
    }
    if len(prior) != len(expected):
        raise ValueError("unexpected 1901/1909 discovery count")
    if {item["issue_date_candidate"] for item in prior} != set(expected):
        raise ValueError("1901/1909 candidate issue dates changed")
    for item in prior:
        day = item["issue_date_candidate"]
        source_id, record_kind, phrase, original_name = expected[day]
        if (
            item["source_id"] != source_id
            or item["documentary_record_type"] != record_kind
            or item["indexed_name_phrase"] != phrase
            or item["name_form"] != original_name
            or item["issue_date_basis"] != "SEARCH_INDEX_AND_URI_METADATA_ONLY"
            or item["discovery_tier"] not in (
                "LOC_NEWSPAPER_SEARCH_INDEX_OCR_NO_PAGE_CAPTURE",
                "UFDC_SEARCH_INDEX_OCR_NO_ORIGINAL_PDF_CAPTURE",
            )
            or item["original_page_image_read"] is not False
            or item["original_issue_masthead_read"] is not False
            or item["archival_original_bytes_retained"] is not False
            or item["original_pdf_sha256"] is not None
            or item["original_pdf_byte_length"] is not None
            or item["original_printed_page_number"] is not None
            or item["legal_street_naming_act_verified"] is not False
            or item["road_segment_surveyed"] is not False
            or item["road_improvement_length_attributed_to_loiza_alone"] is not False
            or item["historical_event_date"] is not None
            or item["claimed_earliest_historical_use"] is not False
            or item["coordinates"] is not None
            or item["human_review_state"] != "PENDING"
            or item["canonical_write_authorized"] is not False
        ):
            raise ValueError("1901/1909 index lead falsely promoted")
        source = source_by_id.get(source_id)
        if (
            source is None
            or source["discovery_mode"] != item["discovery_tier"]
            or source["reported_edition_date"] != day
            or source["date_inferred_from"] != "SEARCH_INDEX_AND_URI_METADATA_ONLY"
            or source["source_binary_sha256"] is not None
            or source["source_binary_byte_length"] is not None
            or source["source_bytes_retained"] is not False
            or source["reviewed_printed_pages"] != []
        ):
            raise ValueError("1901/1909 source locator or custody drift")
    gazette_23 = next(x for x in prior if x["issue_date_candidate"]=="1901-01-23")
    gazette_24 = next(x for x in prior if x["issue_date_candidate"]=="1901-01-24")
    if (
        gazette_23["judicial_notice_signed_date"] is not None
        or gazette_24["judicial_notice_signed_date"] is not None
        or gazette_23["unattributed_ocr_signed_date_candidate"] !=
           "1901-01-21"
        or gazette_23["notice_applicant_of_calle_vi_solar"] !=
           "UNKNOWN_PENDING_ORIGINAL_COLUMN_READ"
        or gazette_23["duplicate_or_related_notice_source_id"] !=
           gazette_24["source_id"]
        or gazette_24["duplicate_or_related_notice_source_id"] !=
           gazette_23["source_id"]
    ):
        raise ValueError("1901 unsigned and cross-issue candidate lineage lost")
    summary = candidate["pre_1910_index_discovery_summary"]
    if (
        summary["earliest_currently_discovered_gazette_issue_date"] !=
           "1901-01-23"
        or summary["earliest_currently_discovered_source_id"] !=
           gazette_23["source_id"]
        or summary["chronology_event_date_from_issue_date_prohibited"] is not True
        or summary["historical_same_alignment_1901_to_2026_unestablished"] is not True
        or summary["source_capture_gate"] != "RAW_CAPTURE_REQUIRED"
    ):
        raise ValueError("incorrect first-use authority from search chronology")
    cross = summary["cross_issue_notice_identity"]
    candidate_repeat = summary["candidate_cross_issue_republication"]
    if (
        candidate_repeat["source_ids"] !=
           [gazette_23["source_id"], gazette_24["source_id"]]
        or candidate_repeat["relationship_status"] !=
           "POSSIBLE_REPUBLICATION_UNVERIFIED"
        or candidate_repeat["same_notarial_or_judicial_case_proven"] is not False
        or candidate_repeat["exact_verbatim_identity_proven"] is not False
        or candidate_repeat["distinct_case_count"] is not None
        or candidate_repeat["event_date"] is not None
        or candidate_repeat["legal_effect_date"] is not None
        or "same_notice_republication" in summary
    ):
        raise ValueError("two Gámbaro publications promoted to one legal event")
    if (
        len(candidate["discrepancy_ledger"]) != 4
        or len({r["id"] for r in candidate["discrepancy_ledger"]}) != 4
    ):
        raise ValueError("discrepancy ledger missing or duplicated")
    unresolved = {
        "LOIZA-DISC-1901-JAN23-APPLICANT-DATE":
            "UNRESOLVED_RAW_PAGE_REQUIRED",
        "LOIZA-DISC-1901-GAMBARO-CROSS-ISSUE":
            "UNRESOLVED_RAW_PAGE_REQUIRED",
        "LOIZA-DISC-1918-SECOND-SECTION-DATE":
            "UNRESOLVED_ORIGINAL_CARTOUCHE_REQUIRED",
        "LOIZA-DISC-1909-MONITLLA-AGGREGATE":
            "UNRESOLVED_RAW_PAGE_REQUIRED",
    }
    by_id = {r["id"]: r for r in candidate["discrepancy_ledger"]}
    for identifier, status in unresolved.items():
        if identifier not in by_id:
            raise ValueError("discrepancy missing")
        record = by_id[identifier]
        if (
            record["status"] != status
            or record["reviewer_approved"] is not False
            or record["original_page_checked"] is not False
            or record["resolution_event_date"] is not None
            or not record["source_ids"]
            or any(sid not in source_by_id for sid in record["source_ids"])
        ):
            raise ValueError("unreviewed documentary discrepancy promoted")
    if by_id["LOIZA-DISC-1901-JAN23-APPLICANT-DATE"][
        "source_ids"
    ] != [gazette_23["source_id"]]:
        raise ValueError("ambiguous 1901 applicant linked to wrong issue")
    if by_id["LOIZA-DISC-1901-GAMBARO-CROSS-ISSUE"][
        "source_ids"
    ] != [gazette_23["source_id"], gazette_24["source_id"]]:
        raise ValueError("Gámbaro cross-issue source lineage changed")
    for code in (
        "jan23_unattributed_judicial_footer_to_ginorio_or_gambaro_event",
        "gambaro_repeated_name_to_verified_same_judicial_case",
        "candidate_1901_republication_to_established_notice_identity",
    ):
        if code not in candidate["prohibited_promotions"]:
            raise ValueError("new judicial-source anti-promotion gate omitted")
    if (
        cross["claim_id"] !=
           "LOIZA-1901-GAMBARO-REPEATED-NEWSPAPER-APPEARANCE-CANDIDATE"
        or cross["applicant_named_in_both_text_layers"] !=
           "Enrique W. Gámbaro Correa"
        or cross["publication_source_ids"] !=
           [gazette_23["source_id"], gazette_24["source_id"]]
        or cross["publication_issue_dates"] !=
           ["1901-01-23", "1901-01-24"]
        or cross["jan23_web_pdf_text_extracted"] is not True
        or cross["jan24_web_search_index_excerpt_extracted"] is not True
        or cross["jan23_gambaro_identified_in_web_extracted_page_text"]
           is not True
        or cross["jan24_gambaro_identified_in_search_index_text"]
           is not True
        or cross["page_number_from_pdf_printed_header_candidate"] != 3
        or cross["page_image_visually_checked"] is not False
        or cross["two_independent_land_registration_events_established"]
           is not False
        or cross["verbatim_notice_identity_confirmed_against_images"]
           is not False
        or cross["source_page_hash_sha256"] is not None
        or cross["event_date"] is not None
        or cross["case_number"] is not None
        or cross["juridical_disposition"] !=
           "NONCANONICAL_POSSIBLE_CROSS_ISSUE_REPEAT_UNVERIFIED"
    ):
        raise ValueError("1901 Gámbaro duplicate-publication evidence promoted")
    if (
        "Gámbaro Correa" not in gazette_23["index_context"]
        or "Gámbaro Correa" not in gazette_24["index_context"]
    ):
        raise ValueError("Jan 23 Gámbaro OCR mention absent or misattributed")
    if (
        source_by_id[gazette_23["source_id"]][
            "web_text_retrieval_status"
        ] != "OCR_TEXT_EXTRACTED_BUT_SOURCE_IMAGE_SCREENSHOT_403"
        or source_by_id[gazette_23["source_id"]][
            "web_indexed_pdf_text_examined"
        ] is not True
        or source_by_id[gazette_23["source_id"]][
            "original_page_image_verified"
        ] is not False
        or source_by_id[gazette_24["source_id"]][
            "web_indexed_pdf_text_examined"
        ] is not False
        or source_by_id[gazette_24["source_id"]][
            "original_page_image_verified"
        ] is not False
    ):
        raise ValueError("Jan 23/24 source access falsely authenticated")
    for code in (
        "gambaro_1901_republication_to_two_independent_title_events",
        "gambaro_ocr_column_interleaving_to_verbatim_notarial_record",
        "ambiguous_1901_solar_applicant_to_confirmed_person_identity",
    ):
        if code not in candidate["prohibited_promotions"]:
            raise ValueError("missing Jan 1901 cross-issue anti-promotion hold")
    for code in (
        "repeated_1901_judicial_notice_to_independent_multiple_road_events",
        "loc_ocr_index_to_verified_1901_gazette_original_page",
        "1909_1660m_combined_santurce_works_to_loiza_specific_length",
        "1909_land_ad_affirmado_to_canonical_street_construction_date",
        "earliest_indexed_1901_notice_to_first_road_name_use",
    ):
        if code not in candidate["prohibited_promotions"]:
            raise ValueError(f"missing indexed judicial/press hold: {code}")
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
        self.assertEqual(len(self.candidate["sources"]), 20)
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

    def test_1910_to_1915_early_press_are_only_index_locators(self):
        press = self.candidate["early_press_name_use_locator_candidates"]
        self.assertEqual(len(press), 5)
        self.assertEqual(
            {o["name_form"] for o in press},
            {"CAMINO DE LOIZA", "LOIZA ROAD", "LOIZA STREET"},
        )
        self.assertEqual(
            press[0]["issue_date_basis"], "SEARCH_INDEX_MASTHEAD_OCR"
        )
        for item in press[1:]:
            self.assertEqual(item["issue_date_basis"], "FILENAME_DATE_UNCHECKED")
        for item in press:
            self.assertIsNone(item["original_pdf_sha256"])
            self.assertIsNone(item["original_page_number"])
            self.assertIsNone(item["event_date"])
            self.assertFalse(item["official_street_naming_act_established"])
            self.assertFalse(item["georeferencing_authorized"])
        self.assertTrue(gate(self.candidate))

    def test_index_ocr_and_unearned_primary_road_claims_fail_closed(self):
        cases = (
            ("claimed_page_read", "index_text_visually_checked_against_page", True),
            ("claimed_pdf", "original_pdf_captured", True),
            ("invented_page_number", "original_page_number", 4),
            ("fake_legal_act", "official_street_naming_act_established", True),
            ("fake_same_road", "historic_to_modern_street_identity_established", True),
            ("inferred_opening", "street_opening_date", "1910-07-05"),
            ("invented_coords", "coordinates", [18.4, -66.1]),
            ("source_label_drift", "name_form", "CALLE LOIZA"),
            ("misdated_source", "issue_date_basis", "MASTHEAD_VERIFIED"),
        )
        for label, field, value in cases:
            changed = copy.deepcopy(self.candidate)
            changed["early_press_name_use_locator_candidates"][0][field] = value
            with self.subTest(mutation=label):
                with self.assertRaises(ValueError):
                    gate(changed)

    def test_forged_original_newspaper_hash_and_date_are_rejected(self):
        changed = copy.deepcopy(self.candidate)
        item = changed["sources"][-1]
        item["source_binary_sha256"] = "a" * 64
        with self.assertRaises(ValueError):
            gate(changed)
        changed = copy.deepcopy(self.candidate)
        item = changed["early_press_name_use_locator_candidates"][1]
        item["issue_date_candidate"] = "1911-05-23"
        with self.assertRaises(ValueError):
            gate(changed)

    def test_1901_gazette_precedes_1910_commercial_index(self):
        archive = self.candidate["pre_1910_official_and_press_locator_candidates"]
        self.assertEqual(len(archive), 5)
        self.assertEqual(
            {x["documentary_record_type"] for x in archive},
            {"OFFICIAL_COURT_NOTICE", "COMMERCIAL_LAND_ADVERTISEMENT",
             "MUNICIPAL_ENGINEER_ANNUAL_REPORT_NEWS"},
        )
        jan23 = next(x for x in archive if x["issue_date_candidate"]=="1901-01-23")
        jan24 = next(x for x in archive if x["issue_date_candidate"]=="1901-01-24")
        self.assertIsNone(jan23["judicial_notice_signed_date"])
        self.assertEqual(jan23["unattributed_ocr_signed_date_candidate"], "1901-01-21")
        self.assertEqual(
            jan23["duplicate_or_related_notice_source_id"], jan24["source_id"]
        )
        self.assertEqual(
            jan24["duplicate_or_related_notice_source_id"], jan23["source_id"]
        )
        self.assertTrue(all(not x["claimed_earliest_historical_use"]
                            for x in archive))
        self.assertTrue(all(x["historical_event_date"] is None
                            for x in archive))
        self.assertTrue(gate(self.candidate))

    def test_1901_gambaro_already_present_on_jan23_ocr(self):
        group = self.candidate["pre_1910_index_discovery_summary"][
            "cross_issue_notice_identity"
        ]
        self.assertEqual(
            group["applicant_named_in_both_text_layers"],
            "Enrique W. Gámbaro Correa",
        )
        self.assertEqual(
            group["publication_issue_dates"],
            ["1901-01-23", "1901-01-24"],
        )
        self.assertTrue(
            group["jan23_gambaro_identified_in_web_extracted_page_text"]
        )
        self.assertFalse(group["page_image_visually_checked"])
        self.assertFalse(
            group["two_independent_land_registration_events_established"]
        )
        self.assertFalse(
            group["verbatim_notice_identity_confirmed_against_images"]
        )
        self.assertIsNone(group["source_page_hash_sha256"])
        self.assertEqual(
            group["juridical_disposition"],
            "NONCANONICAL_POSSIBLE_CROSS_ISSUE_REPEAT_UNVERIFIED",
        )

    def test_duplicate_1901_publication_cannot_claim_unique_events(self):
        for field, value in (
            ("two_independent_land_registration_events_established", True),
            ("verbatim_notice_identity_confirmed_against_images", True),
            ("page_image_visually_checked", True),
            ("source_page_hash_sha256", "a" * 64),
            ("case_number", "INVENTED"),
            ("event_date", "1901-01-23"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.candidate)
                changed["pre_1910_index_discovery_summary"][
                    "cross_issue_notice_identity"
                ][field] = value
                with self.assertRaises(ValueError):
                    gate(changed)

    def test_1901_original_page_image_false_claim_is_rejected(self):
        changed = copy.deepcopy(self.candidate)
        source = next(
            x for x in changed["sources"]
            if x["source_id"] == "LOC-GACETA-1901-01-23-0077"
        )
        source["original_page_image_verified"] = True
        with self.assertRaises(ValueError):
            gate(changed)
        changed = copy.deepcopy(self.candidate)
        first = changed["pre_1910_official_and_press_locator_candidates"][0]
        first["index_context"] = first["index_context"].replace(
            "Gámbaro Correa", "unknown applicant"
        )
        with self.assertRaises(ValueError):
            gate(changed)

    def test_unattributed_1901_footer_does_not_become_signed_notice(self):
        row = next(
            x for x in self.candidate[
                "pre_1910_official_and_press_locator_candidates"
            ] if x["issue_date_candidate"] == "1901-01-23"
        )
        self.assertIsNone(row["judicial_notice_signed_date"])
        self.assertEqual(
            row["unattributed_ocr_signed_date_candidate"], "1901-01-21"
        )
        self.assertEqual(
            row["notice_applicant_of_calle_vi_solar"],
            "UNKNOWN_PENDING_ORIGINAL_COLUMN_READ",
        )
        summary = self.candidate["pre_1910_index_discovery_summary"]
        self.assertNotIn("same_notice_republication", summary)
        self.assertEqual(
            summary["candidate_cross_issue_republication"][
                "relationship_status"
            ], "POSSIBLE_REPUBLICATION_UNVERIFIED",
        )
        self.assertFalse(
            summary["candidate_cross_issue_republication"][
                "same_notarial_or_judicial_case_proven"
            ]
        )
        self.assertIsNone(
            summary["candidate_cross_issue_republication"][
                "distinct_case_count"
            ]
        )

    def test_discrepancy_ledger_retains_unresolved_evidence_holds(self):
        ledger = self.candidate["discrepancy_ledger"]
        self.assertEqual(len(ledger), 4)
        self.assertEqual(len({item["id"] for item in ledger}), 4)
        for item in ledger:
            self.assertTrue(item["status"].startswith("UNRESOLVED_"))
            self.assertFalse(item["reviewer_approved"])
            self.assertFalse(item["original_page_checked"])
            self.assertIsNone(item["resolution_event_date"])
        self.assertTrue(gate(self.candidate))

    def test_forged_1901_notice_relation_or_discrepancy_promotion_fails(self):
        def jan23(data):
            return next(
                x for x in data["pre_1910_official_and_press_locator_candidates"]
                if x["issue_date_candidate"] == "1901-01-23"
            )
        cases = [
            ("unsupported_signed_date", lambda d: jan23(d).__setitem__(
                "judicial_notice_signed_date", "1901-01-21")),
            ("invented_solar_applicant", lambda d: jan23(d).__setitem__(
                "notice_applicant_of_calle_vi_solar", "Emigdio S. Ginorio")),
            ("forged_identical_case", lambda d: d[
                "pre_1910_index_discovery_summary"
            ]["candidate_cross_issue_republication"].__setitem__(
                "same_notarial_or_judicial_case_proven", True)),
            ("duplicate_reported_as_two_cases", lambda d: d[
                "pre_1910_index_discovery_summary"
            ]["candidate_cross_issue_republication"].__setitem__(
                "distinct_case_count", 2)),
            ("forged_discrepancy_resolution", lambda d: d[
                "discrepancy_ledger"][0].__setitem__(
                "status", "RESOLVED")),
            ("unearned_original_read", lambda d: d[
                "discrepancy_ledger"][1].__setitem__(
                "original_page_checked", True)),
            ("fake_human_review", lambda d: d[
                "discrepancy_ledger"][2].__setitem__(
                "reviewer_approved", True)),
            ("missing_discrepancy", lambda d: d[
                "discrepancy_ledger"].pop()),
        ]
        for label, mutation in cases:
            with self.subTest(case=label):
                changed = copy.deepcopy(self.candidate)
                mutation(changed)
                with self.assertRaises(ValueError):
                    gate(changed)

    def test_1909_engineer_aggregate_does_not_prove_road_specific_length(self):
        entries = self.candidate["pre_1910_official_and_press_locator_candidates"]
        public_works = next(x for x in entries
                            if x["issue_date_candidate"]=="1909-11-18")
        self.assertIn("1660 metros", public_works["indexed_name_phrase"])
        self.assertIn("COMBINED", public_works["interpretive_scope"])
        self.assertFalse(
            public_works["road_improvement_length_attributed_to_loiza_alone"]
        )
        land_ad = next(x for x in entries
                       if x["issue_date_candidate"]=="1909-03-09")
        self.assertEqual(land_ad["name_form"], "CALLE DE LOIZA")
        self.assertFalse(land_ad["road_segment_surveyed"])

    def test_1901_1909_unearned_custody_date_and_event_fail_closed(self):
        probes = (
            ("fake_page", 0, "original_page_image_read", True),
            ("fake_masthead", 0, "original_issue_masthead_read", True),
            ("fake_pdf_hash", 1, "original_pdf_sha256", "a" * 64),
            ("fake_page_number", 2, "original_printed_page_number", 3),
            ("false_first_use", 0, "claimed_earliest_historical_use", True),
            ("event_equals_edition", 0, "historical_event_date", "1901-01-23"),
            ("invented_geopoint", 1, "coordinates", [18.4, -66.1]),
            ("false_road_length", 4,
             "road_improvement_length_attributed_to_loiza_alone", True),
            ("original_claim_promoted", 3, "canonical_write_authorized", True),
            ("misquoted_1901", 0, "indexed_name_phrase", "Calle Loiza"),
        )
        for name, i, field, value in probes:
            with self.subTest(case=name):
                changed = copy.deepcopy(self.candidate)
                changed["pre_1910_official_and_press_locator_candidates"][i][field] = value
                with self.assertRaises(ValueError):
                    gate(changed)

    def test_current_transit_stops_remain_contemporary_only(self):
        reference = self.candidate["contemporary_separate_reference"]
        self.assertEqual(reference["source_id"], "SJ-ROUTE-LOIZA-CURRENT")
        self.assertIn("modern", reference["interpretation"].lower())
        self.assertEqual(self.candidate["state"], "AUTHORITY_HOLD")


if __name__ == "__main__":
    unittest.main()
