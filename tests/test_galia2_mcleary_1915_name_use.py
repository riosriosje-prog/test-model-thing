"""Acceptance tests: 1915 press-name reference cannot import naming authority."""
from datetime import datetime, timezone
import os
import tempfile
import json
from pathlib import Path
import unittest

from galia2.authority import AuthorityLayer
from galia2.core import AuthorityState, Case, CaseState, Stage, StageState
from galia2.historical_shadow import HistoricalClaimShadowBridge, HistoricalShadowStatus
from galia2.orchestrator import StageOrchestrator
from historical_store import HistoricalStore
from pilots.mcleary_1915_name_use import seed_mcleary_1915_name_use
from pilots.mcleary_taft_acceptance import seed_mcleary_taft_acceptance


class McLeary1915NameUseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = HistoricalStore(os.path.join(self.tmp.name, "mcleary1915.sqlite3"))
        self.ids = seed_mcleary_1915_name_use(self.store)
        self.ids_1916 = seed_mcleary_taft_acceptance(self.store)
        self.case = Case(
            case_id="case-mcleary-1915-name-use",
            title="Reported 1915 printed road-name use",
            scope="Document date, unverified transcription, identity, naming-act gates",
            state=CaseState.ACTIVE_RESEARCH,
            created_at=datetime(2026, 10, 16, tzinfo=timezone.utc),
            governing_constitution_version="galia2-v1",
        )
        self.bridge = HistoricalClaimShadowBridge(
            orchestrator=StageOrchestrator(policy_version="galia2-v1", actor="mcleary-gate"),
            authority=AuthorityLayer(policy_version="galia2-v1", actor="mcleary-gate"),
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_1915_claim_is_held_with_raw_capture_blocker(self):
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=Stage(
                stage_id="stage-mcleary-1915",
                case_id=self.case.case_id,
                stage_type="HISTORICAL_CLAIM_SHADOW",
                state=StageState.DISCOVERED,
            ),
            claim_id=self.ids["name_use_claim_id"],
        )
        self.assertEqual(result.status, HistoricalShadowStatus.AUTHORITY_HOLD)
        self.assertEqual(result.stage.state, StageState.AUTHORITY_HOLD)
        self.assertEqual(result.claim.authority_state, AuthorityState.HOLD)
        self.assertIn("RAW_CAPTURE_REQUIRED", result.promotion_blocker_codes)
        self.assertTrue(result.evidence_snapshot)
        self.assertTrue(all(r.output_commit is None for r in result.receipts))
        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id=?",
            (self.ids["name_use_claim_id"],),
        ).fetchone()
        self.assertEqual(row["status"], "PROPOSED")
        self.assertEqual(
            self.store.conn.execute(
                "SELECT COUNT(*) FROM claims WHERE status='CANONICAL'"
            ).fetchone()[0], 0,
        )

    def test_locator_and_transcription_are_not_raw_evidence(self):
        rows = self.store.conn.execute(
            "SELECT acquisition_state, raw_artifact "
            "FROM document_representations WHERE document_id=?",
            (self.ids["document_id"],),
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertFalse(any(r["raw_artifact"] for r in rows))
        self.assertEqual(
            {r["acquisition_state"] for r in rows},
            {"LOCATOR_ONLY", "TEXT_SURROGATE"},
        )

    def test_1915_source_spelling_does_not_identify_1916_road(self):
        self.assertNotEqual(
            self.ids["alias_entity_id"], self.ids_1916["mcleary_street_id"]
        )
        bundle = self.store.claim_bundle(self.ids["name_use_claim_id"])
        self.assertEqual(
            bundle["claim"]["subject_entity_id"], self.ids["alias_entity_id"]
        )
        self.assertEqual(len(bundle["evidence"]), 1)

    def test_document_date_is_not_the_street_naming_event_date(self):
        row = self.store.conn.execute(
            "SELECT document_date, event_date_start "
            "FROM documents WHERE document_id=?",
            (self.ids["document_id"],),
        ).fetchone()
        self.assertEqual(row["document_date"], "1915-11-22")
        self.assertIsNone(row["event_date_start"])
        self.assertIn(
            "RAW_CAPTURE_REQUIRED",
            {r["code"] for r in self.store.claim_promotion_blockers(
                self.ids["name_use_claim_id"]
            )},
        )


    def test_26_nov_ocr_index_is_separate_proposed_claim(self):
        self.assertNotEqual(
            self.ids["name_use_claim_id"], self.ids["indexed_26_claim_id"]
        )
        a = self.store.claim_bundle(self.ids["name_use_claim_id"])
        b = self.store.claim_bundle(self.ids["indexed_26_claim_id"])
        self.assertEqual(
            a["claim"]["subject_entity_id"], b["claim"]["subject_entity_id"]
        )
        self.assertEqual(a["claim"]["status"], "PROPOSED")
        self.assertEqual(b["claim"]["status"], "PROPOSED")
        row = self.store.conn.execute(
            "SELECT document_date, event_date_start FROM documents "
            "WHERE document_id=?",
            (self.ids["indexed_26_document_id"],),
        ).fetchone()
        self.assertEqual(row["document_date"], "1915-11-26")
        self.assertIsNone(row["event_date_start"])
        self.assertEqual(
            self.store.conn.execute(
                "SELECT COUNT(*) FROM claims WHERE status='CANONICAL'"
            ).fetchone()[0], 0,
        )

    def test_26_nov_indexed_ocr_fails_closed_to_hold(self):
        rows = self.store.conn.execute(
            "SELECT acquisition_state, raw_artifact FROM "
            "document_representations WHERE document_id=?",
            (self.ids["indexed_26_document_id"],),
        ).fetchall()
        self.assertEqual(
            {r["acquisition_state"] for r in rows},
            {"LOCATOR_ONLY", "TEXT_SURROGATE"},
        )
        self.assertFalse(any(r["raw_artifact"] for r in rows))
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=Stage(
                stage_id="stage-mcleary-1915-ocr-index",
                case_id=self.case.case_id,
                stage_type="HISTORICAL_CLAIM_SHADOW",
                state=StageState.DISCOVERED,
            ),
            claim_id=self.ids["indexed_26_claim_id"],
        )
        self.assertEqual(result.status, HistoricalShadowStatus.AUTHORITY_HOLD)
        self.assertEqual(result.stage.state, StageState.AUTHORITY_HOLD)
        self.assertIn("RAW_CAPTURE_REQUIRED", result.promotion_blocker_codes)
        self.assertTrue(all(r.output_commit is None for r in result.receipts))


    def test_primary_capture_manifest_is_fail_closed(self):
        gate = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "research/gates/mcleary_1915_primary_capture_gate.v0_1.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(gate["state"], "AUTHORITY_HOLD")
        self.assertFalse(gate["raw_capture_complete"])
        self.assertFalse(gate["authority_mutation"])
        self.assertEqual(len(gate["documentary_observations"]), 2)
        self.assertEqual(
            {r["issue_date"] for r in gate["documentary_observations"]},
            {"1915-11-22", "1915-11-26"},
        )
        self.assertEqual(
            {r["discovery_tier"] for r in gate["documentary_observations"]},
            {"PRIOR_PROJECT_TRANSCRIPTION_ONLY", "SEARCH_INDEX_OCR_ONLY"},
        )
        for record in gate["documentary_observations"]:
            self.assertFalse(record["primary_pdf_available_to_current_review"])
            self.assertIsNone(record["pdf_sha256"])
            self.assertIsNone(record["captured_pdf_byte_length"])
            self.assertIsNone(record["verified_page_image_sha256"])
            self.assertFalse(record["page_image_visually_checked"])
            self.assertFalse(record["typography_verified"])
            self.assertEqual(record["human_review_state"], "PENDING")

    def test_capture_gate_is_linked_to_noncanonical_claims(self):
        gate = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "research/gates/mcleary_1915_primary_capture_gate.v0_1.json"
            ).read_text(encoding="utf-8")
        )
        claim_ids = {
            self.ids["name_use_claim_id"], self.ids["indexed_26_claim_id"]
        }
        self.assertEqual(
            {r["claim_id"] for r in gate["documentary_observations"]},
            claim_ids,
        )
        for claim_id in claim_ids:
            claim = self.store.claim_bundle(claim_id)["claim"]
            self.assertEqual(claim["status"], "PROPOSED")
            self.assertIn(
                "RAW_CAPTURE_REQUIRED",
                {
                    r["code"]
                    for r in self.store.claim_promotion_blockers(claim_id)
                },
            )
        self.assertIn(
            "document_date_to_street_naming_event",
            gate["forbidden_promotions"],
        )
        self.assertIn(
            "search_snippet_to_primary_source",
            gate["forbidden_promotions"],
        )


    def test_rust_snapshot_matches_python_research_manifest(self):
        """A Rust shadow fixture must not drift from the research manifest."""
        root = Path(__file__).resolve().parents[1]
        historical = json.loads(
            (root / "research/gates/mcleary_1915_primary_capture_gate.v0_1.json")
            .read_text(encoding="utf-8")
        )
        rust_snapshot = json.loads(
            (root / "rust/galia-core/tests/fixtures/"
                    "mcleary_1915_primary_capture_gate.v0_1.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(historical, rust_snapshot)
        self.assertEqual(historical["state"], "AUTHORITY_HOLD")
        self.assertFalse(historical["raw_capture_complete"])
        self.assertFalse(historical["authority_mutation"])
        self.assertEqual(
            {r["claim_id"] for r in rust_snapshot["documentary_observations"]},
            {self.ids["name_use_claim_id"], self.ids["indexed_26_claim_id"]},
        )

    def test_changed_issue_date_or_ocr_tier_cannot_pass_parity(self):
        """Even schema-valid metadata alterations constitute snapshot drift."""
        root = Path(__file__).resolve().parents[1]
        historical = json.loads(
            (root / "research/gates/mcleary_1915_primary_capture_gate.v0_1.json")
            .read_text(encoding="utf-8")
        )
        rust_snapshot = json.loads(
            (root / "rust/galia-core/tests/fixtures/"
                    "mcleary_1915_primary_capture_gate.v0_1.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(historical, rust_snapshot)
        for field, changed_value in (
            ("issue_date", "1915-11-23"),
            ("discovery_tier", "PRIOR_PROJECT_TRANSCRIPTION_ONLY"),
        ):
            altered = json.loads(json.dumps(rust_snapshot))
            altered["documentary_observations"][1][field] = changed_value
            self.assertNotEqual(
                historical, altered,
                f"Unexpected parity after altering {field}",
            )


if __name__ == "__main__":
    unittest.main()
