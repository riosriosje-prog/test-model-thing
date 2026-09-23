import os
import sqlite3
import tempfile
import unittest

from galia_history_bridge import GaliaResearchBridge, ProposedClaim
from historical_store import HistoricalStore


class HistoricalStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "history.sqlite3")
        self.store = HistoricalStore(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_document_and_event_dates_are_distinct(self):
        source_id = self.store.register_source(
            source_type="court_opinion",
            title="Behn v. Registrador",
            custodian="Poder Judicial",
        )
        document_id = self.store.register_document(
            source_id=source_id,
            title="Opinion",
            document_date="1918-01-01",
            event_date_start="1917-08-24",
            content=b"sample",
        )
        row = self.store.conn.execute(
            """
            SELECT document_date, event_date_start, content_sha256
            FROM documents WHERE document_id = ?
            """,
            (document_id,),
        ).fetchone()
        self.assertEqual(row["document_date"], "1918-01-01")
        self.assertEqual(row["event_date_start"], "1917-08-24")
        self.assertEqual(len(row["content_sha256"]), 64)

    def test_multiple_representations_can_coexist_for_one_document(self):
        document_id = self.store.register_document(title="Newspaper page")
        pdf_rep = self.store.register_document_representation(
            document_id=document_id,
            representation_type="scanned_page_pdf",
            acquisition_state="REMOTE_BLOCKED",
            locator="https://example.invalid/page.pdf",
            source_url="https://example.invalid/page.pdf",
            raw_artifact=False,
        )
        ocr_rep = self.store.register_document_representation(
            document_id=document_id,
            representation_type="institutional_ocr",
            acquisition_state="TEXT_SURROGATE",
            locator="https://example.invalid/page/ocr/",
            source_url="https://example.invalid/page/ocr/",
            raw_artifact=False,
        )
        rows = self.store.conn.execute(
            """
            SELECT representation_id, representation_type, acquisition_state
            FROM document_representations
            WHERE document_id = ?
            ORDER BY representation_type
            """,
            (document_id,),
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["representation_id"] for row in rows},
            {pdf_rep, ocr_rep},
        )
        self.assertEqual(
            {row["acquisition_state"] for row in rows},
            {"REMOTE_BLOCKED", "TEXT_SURROGATE"},
        )

    def test_engine_claim_cannot_be_canonical_without_human_review(self):
        bridge = GaliaResearchBridge(
            self.store,
            engine_version="galia-v1.35",
            prompt_version="research-v0.1",
        )
        _, claim_ids = bridge.record_analysis(
            input_bytes=b"source material",
            output_bytes=b"analysis",
            claims=[
                ProposedClaim(
                    predicate="owned_by",
                    claim_text="The estate was owned by X.",
                    object_value="X",
                )
            ],
        )
        claim_id = claim_ids[0]
        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        self.assertEqual(row["status"], "PROPOSED")

        with self.assertRaises(ValueError):
            self.store.review_claim(
                claim_id,
                decision="PROMOTE_CANONICAL",
                reviewer="",
                rationale="Reviewed against primary source",
            )

        self.store.review_claim(
            claim_id,
            decision="PROMOTE_CANONICAL",
            reviewer="human-reviewer",
            rationale="Reviewed against primary source",
        )
        row = self.store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        self.assertEqual(row["status"], "CANONICAL")

    def test_discrepancy_keeps_conflicting_claims(self):
        c1 = self.store.propose_claim(
            predicate="area",
            claim_text="Area is 148 cuerdas.",
            created_by="import",
            object_value="148 cuerdas",
        )
        c2 = self.store.propose_claim(
            predicate="area",
            claim_text="Area is 148.5 acres.",
            created_by="import",
            object_value="148.5 acres",
        )
        discrepancy_id = self.store.open_discrepancy(
            topic_key="finca-condado-area",
            description="Conflicting historical area statements",
        )
        self.store.attach_discrepancy_claim(
            discrepancy_id=discrepancy_id,
            claim_id=c1,
            stance="version_a",
        )
        self.store.attach_discrepancy_claim(
            discrepancy_id=discrepancy_id,
            claim_id=c2,
            stance="version_b",
        )
        count = self.store.conn.execute(
            """
            SELECT COUNT(*) FROM discrepancy_claims
            WHERE discrepancy_id = ?
            """,
            (discrepancy_id,),
        ).fetchone()[0]
        self.assertEqual(count, 2)

    def test_audit_log_is_append_only(self):
        self.store.register_source(source_type="archive", title="AGPR")
        audit_id = self.store.conn.execute(
            "SELECT audit_id FROM audit_log LIMIT 1"
        ).fetchone()[0]
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.conn.execute(
                "DELETE FROM audit_log WHERE audit_id = ?",
                (audit_id,),
            )

    def test_health(self):
        health = self.store.health()
        self.assertEqual(health["schema_version"], 2)
        self.assertEqual(health["integrity_check"], "ok")
        self.assertIn("document_representations", health["counts"])


if __name__ == "__main__":
    unittest.main()
