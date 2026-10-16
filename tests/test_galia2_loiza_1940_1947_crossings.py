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
        self.assertEqual(len(self.candidate["sources"]), 7)
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

    def test_current_transit_stops_remain_contemporary_only(self):
        reference = self.candidate["contemporary_separate_reference"]
        self.assertEqual(reference["source_id"], "SJ-ROUTE-LOIZA-CURRENT")
        self.assertIn("modern", reference["interpretation"].lower())
        self.assertEqual(self.candidate["state"], "AUTHORITY_HOLD")


if __name__ == "__main__":
    unittest.main()
