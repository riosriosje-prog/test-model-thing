import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from historical_store import HistoricalStore
from galia2.secured_claim_shadow import SecuredClaimShadowBridge
from galia2.secured_claim_store import SecuredClaimStore
from galia2.secured_claims import EventAuthorityState, UnresolvedLegalState

UTC = timezone.utc


class SecuredClaimShadowBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.historical_path = os.path.join(self.tmp.name, "historical.sqlite3")
        self.secured_path = os.path.join(self.tmp.name, "secured.sqlite3")
        self.source = HistoricalStore(self.historical_path)
        self.target = SecuredClaimStore(self.secured_path)
        self.bridge = SecuredClaimShadowBridge(target_store=self.target)

    def tearDown(self):
        self.source.close()
        self.target.close()
        self.tmp.cleanup()

    def _fingerprint_source(self):
        health = self.source.health()
        statuses = tuple(
            (row["claim_id"], row["status"])
            for row in self.source.conn.execute(
                "SELECT claim_id, status FROM claims ORDER BY claim_id"
            ).fetchall()
        )
        audit_count = self.source.conn.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]
        return health, statuses, audit_count

    def _seed(
        self,
        *,
        claim_id="clm_shadow_1",
        status="PROPOSED",
        event_type="CLAIM_ASSERTION_EVENT",
        effective_at="2026-01-15T00:00:00+00:00",
        with_evidence=True,
        with_profile=True,
        raw_capture_blocked=False,
    ):
        source_id = f"src_{claim_id}"
        document_id = f"doc_{claim_id}"
        self.source.register_source(
            source_type="court_order",
            title="Synthetic secured-claim source",
            custodian="Synthetic Court",
            repository="GALIA test fixture",
            locator="fixture:1",
            source_id=source_id,
        )
        self.source.register_document(
            source_id=source_id,
            title="Synthetic order",
            document_date="2026-01-20",
            event_date_start="2026-01-15",
            content_locator="fixture:1",
            document_id=document_id,
        )
        metadata = {}
        if with_profile:
            metadata["secured_claim_shadow"] = {
                "event_type": event_type,
                "event_effective_at": effective_at,
                "authority": {
                    "authority_id": "auth-synthetic-order",
                    "authority_type": "COURT_ORDER",
                    "citation": "Synthetic Order ¶ 12",
                    "jurisdiction": "US",
                    "effective_date": "2026-01-15T00:00:00+00:00",
                },
            }
        if raw_capture_blocked:
            metadata["promotion_blocked_until_raw_capture"] = True
            metadata["promotion_required_representation_types"] = [
                "scanned_order_pdf"
            ]

        self.source.propose_claim(
            document_id=document_id,
            predicate="asserts_allowed_claim_amount",
            object_value="100000",
            claim_text="Synthetic source assertion that allowed claim is 100000.",
            created_by="fixture",
            metadata=metadata,
            claim_id=claim_id,
        )

        representation_id = None
        if raw_capture_blocked:
            representation_id = self.source.register_document_representation(
                document_id=document_id,
                representation_type="search_index_text_surrogate",
                acquisition_state="TEXT_SURROGATE",
                locator=f"surrogate:{document_id}",
                mime_type="text/plain",
                content_sha256="a" * 64,
                byte_length=10,
                raw_artifact=False,
                representation_id=f"repr_{claim_id}",
            )

        if with_evidence:
            self.source.add_evidence(
                claim_id=claim_id,
                document_id=document_id,
                representation_id=representation_id,
                role="supports",
                locator="fixture:1#p12",
                excerpt=b"allowed claim 100000",
                evidence_id=f"evd_{claim_id}",
            )

        if status == "VALIDATED":
            self.source.review_claim(
                claim_id,
                decision="VALIDATE",
                reviewer="human-fixture",
                rationale="fixture validation",
            )
        elif status == "CANONICAL":
            self.source.review_claim(
                claim_id,
                decision="PROMOTE_CANONICAL",
                reviewer="human-fixture",
                rationale="fixture promotion",
            )
        return claim_id

    def test_01_tagged_proposed_claim_imports(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(result.source_claim_id, cid)
        self.assertEqual(self.target.health()["event_count"], 1)

    def test_02_import_is_nonfinal_assertion(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(result.event.event_type, "CLAIM_ASSERTION_EVENT")
        self.assertEqual(result.event.authority_state, EventAuthorityState.NONFINAL)

    def test_03_source_store_is_not_mutated(self):
        cid = self._seed()
        before = self._fingerprint_source()
        self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        after = self._fingerprint_source()
        self.assertEqual(before, after)

    def test_04_replay_is_idempotent(self):
        cid = self._seed()
        first = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        second = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertFalse(first.replay_idempotent)
        self.assertTrue(second.replay_idempotent)
        self.assertEqual(first.event.event_id, second.event.event_id)
        self.assertEqual(self.target.health()["event_count"], 1)

    def test_05_bundle_change_creates_new_versioned_event(self):
        cid = self._seed()
        first = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.source.review_claim(
            cid,
            decision="VALIDATE",
            reviewer="human-fixture",
            rationale="new source review changes bundle",
        )
        second = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertNotEqual(first.bundle_sha256, second.bundle_sha256)
        self.assertNotEqual(first.event.event_id, second.event.event_id)
        self.assertEqual(self.target.health()["event_count"], 2)

    def test_06_validated_claim_is_allowed_as_nonfinal_assertion(self):
        cid = self._seed(status="VALIDATED")
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(result.source_status, "VALIDATED")
        self.assertEqual(result.event.authority_state, EventAuthorityState.NONFINAL)

    def test_07_canonical_claim_is_rejected_as_imported_authority(self):
        cid = self._seed(status="CANONICAL")
        with self.assertRaisesRegex(UnresolvedLegalState, "non-canonical"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_08_missing_profile_fails_closed(self):
        cid = self._seed(with_profile=False)
        with self.assertRaisesRegex(UnresolvedLegalState, "secured_claim_shadow"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_09_missing_evidence_fails_closed(self):
        cid = self._seed(with_evidence=False)
        with self.assertRaisesRegex(UnresolvedLegalState, "evidence"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_10_operational_allowance_event_cannot_be_smuggled(self):
        cid = self._seed(event_type="CLAIM_ALLOWANCE_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "assertion events only"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_11_secured_status_event_cannot_be_smuggled(self):
        cid = self._seed(event_type="SECURED_STATUS_EVENT")
        with self.assertRaisesRegex(UnresolvedLegalState, "assertion events only"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_12_naive_effective_time_fails_closed(self):
        cid = self._seed(effective_at="2026-01-15T00:00:00")
        with self.assertRaisesRegex(UnresolvedLegalState, "timezone"):
            self.bridge.mirror_claim(source_store=self.source, claim_id=cid)

    def test_13_effective_time_is_source_profile_time(self):
        cid = self._seed(effective_at="2026-01-15T04:00:00-04:00")
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(
            result.event.event_effective_at.isoformat(),
            "2026-01-15T04:00:00-04:00",
        )

    def test_14_authority_reference_is_preserved_not_promoted(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(result.event.authority.citation, "Synthetic Order ¶ 12")
        self.assertEqual(result.event.authority.authority_type, "COURT_ORDER")
        self.assertEqual(result.event.authority_state, EventAuthorityState.NONFINAL)

    def test_15_raw_capture_blocker_is_preserved(self):
        cid = self._seed(raw_capture_blocked=True)
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertIn("RAW_CAPTURE_REQUIRED", result.blocker_codes)
        payload = dict(result.event.payload)
        self.assertIn("RAW_CAPTURE_REQUIRED", payload["blocker_codes_json"])

    def test_16_claim_text_is_hashed_not_copied_into_event_payload(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        payload = dict(result.event.payload)
        self.assertIn("source_claim_text_sha256", payload)
        self.assertNotIn("claim_text", payload)
        self.assertNotIn(
            "Synthetic source assertion that allowed claim is 100000.",
            tuple(payload.values()),
        )

    def test_17_document_and_predicate_lineage_are_preserved(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        payload = dict(result.event.payload)
        self.assertEqual(payload["source_document_id"], f"doc_{cid}")
        self.assertEqual(payload["source_predicate"], "asserts_allowed_claim_amount")

    def test_18_bundle_and_evidence_hashes_are_persisted(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        payload = dict(result.event.payload)
        self.assertEqual(payload["source_bundle_sha256"], result.bundle_sha256)
        self.assertEqual(len(payload["evidence_snapshot_sha256"]), 64)

    def test_19_target_database_has_no_historical_claim_tables(self):
        cid = self._seed()
        self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        tables = {
            row["name"]
            for row in self.target.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertIn("canonical_events", tables)
        self.assertNotIn("claims", tables)
        self.assertNotIn("reviews", tables)

    def test_20_bridge_module_has_no_source_mutation_calls(self):
        path = Path(__file__).resolve().parents[1] / "galia2" / "secured_claim_shadow.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden = {
            "review_claim",
            "propose_claim",
            "add_evidence",
            "register_document",
            "register_source",
            "resolve_discrepancy",
            "record_human_selection",
            "issue_promotion_authorization",
            "publish_generation",
        }
        used = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
        }
        self.assertTrue(forbidden.isdisjoint(used))

    def test_21_source_status_is_embedded_in_event_lineage(self):
        cid = self._seed(status="VALIDATED")
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(dict(result.event.payload)["source_status"], "VALIDATED")

    def test_22_event_id_binds_claim_and_exact_bundle(self):
        cid = self._seed()
        result = self.bridge.mirror_claim(source_store=self.source, claim_id=cid)
        self.assertEqual(
            result.event.event_id,
            f"hist-shadow:{cid}:{result.bundle_sha256}",
        )


if __name__ == "__main__":
    unittest.main()
