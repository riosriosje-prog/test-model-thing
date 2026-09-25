from datetime import datetime, timezone
import os
import tempfile
import unittest

from galia2.authority import AuthorityLayer
from galia2.core import AuthorityState, Case, CaseState, Stage, StageState
from galia2.historical_shadow import (
    HistoricalClaimShadowBridge,
    HistoricalShadowStatus,
)
from galia2.orchestrator import StageOrchestrator
from historical_store import HistoricalStore
from pilots.mcleary_taft_acceptance import seed_mcleary_taft_acceptance


class McLearyTaftAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = HistoricalStore(os.path.join(self.tmp.name, "mcleary-taft.sqlite3"))
        self.ids = seed_mcleary_taft_acceptance(self.store)
        self.case = Case(
            case_id="case-mcleary-taft-acceptance",
            title="McLeary–Taft nominative-act acceptance test",
            scope=(
                "Separate source-backed street relations from unsupported "
                "nominative/eponym hypotheses"
            ),
            state=CaseState.ACTIVE_RESEARCH,
            created_at=datetime(2026, 9, 25, tzinfo=timezone.utc),
            governing_constitution_version="galia2-v1",
        )
        self.bridge = HistoricalClaimShadowBridge(
            orchestrator=StageOrchestrator(
                policy_version="galia2-v1",
                actor="mcleary-taft-acceptance",
            ),
            authority=AuthorityLayer(
                policy_version="galia2-v1",
                actor="mcleary-taft-acceptance",
            ),
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def stage(self, suffix):
        return Stage(
            stage_id=f"stage-mcleary-taft-{suffix}",
            case_id=self.case.case_id,
            stage_type="HISTORICAL_CLAIM_SHADOW",
            state=StageState.DISCOVERED,
        )

    def test_1916_relation_reaches_hold_but_not_canonical(self):
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage("relation"),
            claim_id=self.ids["relation_claim_id"],
        )
        self.assertEqual(result.status, HistoricalShadowStatus.AUTHORITY_HOLD)
        self.assertEqual(result.stage.state, StageState.AUTHORITY_HOLD)
        self.assertEqual(result.claim.authority_state, AuthorityState.HOLD)
        self.assertTrue(result.evidence_snapshot)
        self.assertIn("RAW_CAPTURE_REQUIRED", result.promotion_blocker_codes)

        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (self.ids["relation_claim_id"],),
        ).fetchone()
        self.assertEqual(row["status"], "PROPOSED")
        canonical = self.store.conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'CANONICAL'"
        ).fetchone()[0]
        self.assertEqual(canonical, 0)
        self.assertTrue(all(receipt.output_commit is None for receipt in result.receipts))

    def test_nominative_eponym_hypothesis_without_evidence_is_quarantined(self):
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage("nominative"),
            claim_id=self.ids["nominative_claim_id"],
        )
        self.assertEqual(result.status, HistoricalShadowStatus.QUARANTINED)
        self.assertEqual(result.stage.state, StageState.QUARANTINED)
        self.assertEqual(result.claim.authority_state, AuthorityState.NONE)
        self.assertEqual(result.evidence_snapshot, ())

        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (self.ids["nominative_claim_id"],),
        ).fetchone()
        self.assertEqual(row["status"], "PROPOSED")
        canonical = self.store.conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'CANONICAL'"
        ).fetchone()[0]
        self.assertEqual(canonical, 0)

    def test_1916_relation_does_not_supply_evidence_to_nominative_claim(self):
        relation_bundle = self.store.claim_bundle(self.ids["relation_claim_id"])
        nominative_bundle = self.store.claim_bundle(self.ids["nominative_claim_id"])

        self.assertGreater(len(relation_bundle["evidence"]), 0)
        self.assertEqual(nominative_bundle["evidence"], [])
        self.assertNotEqual(
            relation_bundle["claim"]["claim_id"],
            nominative_bundle["claim"]["claim_id"],
        )

    def test_raw_locator_is_not_misclassified_as_raw_capture(self):
        rows = self.store.conn.execute(
            """
            SELECT acquisition_state, raw_artifact, content_sha256, byte_length
            FROM document_representations
            WHERE document_id = ?
            ORDER BY representation_id
            """,
            (self.ids["document_id"],),
        ).fetchall()

        self.assertGreaterEqual(len(rows), 2)
        self.assertFalse(
            any(
                row["acquisition_state"] == "RAW_CAPTURED" and row["raw_artifact"] == 1
                for row in rows
            )
        )
        blockers = self.store.claim_promotion_blockers(
            self.ids["relation_claim_id"]
        )
        self.assertIn("RAW_CAPTURE_REQUIRED", {row["code"] for row in blockers})


if __name__ == "__main__":
    unittest.main()
