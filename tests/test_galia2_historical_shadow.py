import ast
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import unittest

from galia2.authority import AuthorityLayer
from galia2.core import (
    AuthorityState,
    Case,
    CaseState,
    Stage,
    StageState,
)
from galia2.historical_shadow import (
    HistoricalClaimShadowBridge,
    HistoricalShadowStatus,
)
from galia2.orchestrator import StageOrchestrator
from historical_store import HistoricalStore
from pilots.condado_shadow import seed_condado_shadow


class P13HistoricalShadowOperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = HistoricalStore(os.path.join(self.tmp.name, "condado.sqlite3"))
        self.ids = seed_condado_shadow(self.store)
        self.case = Case(
            case_id="case-condado-p13",
            title="Finca El Condado shadow operation",
            scope="HistoricalStore claims mirrored into GALIA 2.0 authority hold",
            state=CaseState.ACTIVE_RESEARCH,
            created_at=datetime(2026, 9, 24, tzinfo=timezone.utc),
            governing_constitution_version="galia2-v1",
        )
        self.stage = Stage(
            stage_id="stage-condado-p13",
            case_id=self.case.case_id,
            stage_type="HISTORICAL_CLAIM_SHADOW",
            state=StageState.DISCOVERED,
        )
        self.bridge = HistoricalClaimShadowBridge(
            orchestrator=StageOrchestrator(
                policy_version="galia2-v1",
                actor="p13-shadow-pilot",
            ),
            authority=AuthorityLayer(
                policy_version="galia2-v1",
                actor="p13-shadow-pilot",
            ),
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def _store_fingerprint(self):
        health = self.store.health()
        audit = self.store.conn.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]
        statuses = tuple(
            self.store.conn.execute(
                "SELECT claim_id, status FROM claims ORDER BY claim_id"
            ).fetchall()
        )
        return health, audit, tuple((r[0], r[1]) for r in statuses)

    def test_condado_claim_reaches_authority_hold_without_store_mutation(self):
        before = self._store_fingerprint()
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage,
            claim_id=self.ids["transfer_claim_id"],
        )
        after = self._store_fingerprint()

        self.assertEqual(result.status, HistoricalShadowStatus.AUTHORITY_HOLD)
        self.assertEqual(result.stage.state, StageState.AUTHORITY_HOLD)
        self.assertEqual(result.claim.authority_state, AuthorityState.HOLD)
        self.assertTrue(result.evidence_snapshot)
        self.assertEqual(before, after)
        source_status = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (self.ids["transfer_claim_id"],),
        ).fetchone()["status"]
        self.assertEqual(source_status, "PROPOSED")
        self.assertTrue(all(r.output_commit is None for r in result.receipts))

    def test_raw_capture_blocker_is_preserved_without_promotion(self):
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage,
            claim_id=self.ids["newspaper_claim_id"],
        )
        self.assertEqual(result.status, HistoricalShadowStatus.AUTHORITY_HOLD)
        self.assertIn("RAW_CAPTURE_REQUIRED", result.promotion_blocker_codes)
        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (self.ids["newspaper_claim_id"],),
        ).fetchone()
        self.assertEqual(row["status"], "PROPOSED")
        canonical = self.store.conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'CANONICAL'"
        ).fetchone()[0]
        self.assertEqual(canonical, 0)

    def test_claim_without_evidence_fails_closed_to_quarantine(self):
        claim_id = self.store.propose_claim(
            predicate="unanchored_working_assertion",
            claim_text="Test-only claim with no evidence.",
            object_value="unverified",
            created_by="test-fixture",
        )
        before = self._store_fingerprint()
        result = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage,
            claim_id=claim_id,
        )
        after = self._store_fingerprint()
        self.assertEqual(result.status, HistoricalShadowStatus.QUARANTINED)
        self.assertEqual(result.stage.state, StageState.QUARANTINED)
        self.assertEqual(result.claim.authority_state, AuthorityState.NONE)
        self.assertEqual(before, after)

    def test_bundle_snapshot_is_deterministic(self):
        first = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage,
            claim_id=self.ids["transfer_claim_id"],
        )
        second = self.bridge.mirror_to_hold(
            store=self.store,
            case=self.case,
            stage=self.stage,
            claim_id=self.ids["transfer_claim_id"],
        )
        self.assertEqual(first.bundle_sha256, second.bundle_sha256)
        self.assertEqual(first.evidence_snapshot, second.evidence_snapshot)

    def test_canonical_source_claim_is_rejected_as_imported_authority(self):
        claim_id = self.ids["transfer_claim_id"]
        self.store.review_claim(
            claim_id,
            decision="PROMOTE_CANONICAL",
            reviewer="human-test-reviewer",
            rationale="Fixture-only canonical source-state rejection test.",
        )
        with self.assertRaisesRegex(ValueError, "non-canonical"):
            self.bridge.mirror_to_hold(
                store=self.store,
                case=self.case,
                stage=self.stage,
                claim_id=claim_id,
            )

    def test_module_contains_no_review_promotion_or_persistence_calls(self):
        path = Path(__file__).resolve().parents[1] / "galia2" / "historical_shadow.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden_attrs = {
            "review_claim",
            "record_human_selection",
            "issue_promotion_authorization",
            "stage_generation",
            "publish_generation",
            "rollback",
        }
        used_attrs = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(forbidden_attrs.isdisjoint(used_attrs))


if __name__ == "__main__":
    unittest.main()
