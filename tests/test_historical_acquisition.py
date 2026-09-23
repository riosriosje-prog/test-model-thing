import json
import os
import tempfile
import unittest

from historical_acquisition import AcquisitionReceipt, record_acquisition_state
from historical_store import HistoricalStore


class HistoricalAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "history.sqlite3")
        self.store = HistoricalStore(self.path)
        self.document_id = self.store.register_document(
            title="Acquisition test document",
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_remote_blocked_cannot_claim_raw_artifact(self):
        with self.assertRaises(ValueError):
            record_acquisition_state(
                self.store,
                document_id=self.document_id,
                receipt=AcquisitionReceipt(
                    state="REMOTE_BLOCKED",
                    source_url="https://example.invalid/source.pdf",
                    representation_type="pdf",
                    raw_artifact=True,
                ),
            )

    def test_raw_captured_requires_raw_artifact_true(self):
        with self.assertRaises(ValueError):
            record_acquisition_state(
                self.store,
                document_id=self.document_id,
                receipt=AcquisitionReceipt(
                    state="RAW_CAPTURED",
                    source_url="https://example.invalid/source.pdf",
                    representation_type="pdf",
                    raw_artifact=False,
                ),
            )

    def test_remote_blocked_records_metadata_and_audit(self):
        record_acquisition_state(
            self.store,
            document_id=self.document_id,
            receipt=AcquisitionReceipt(
                state="REMOTE_BLOCKED",
                source_url="https://example.invalid/source.pdf",
                representation_type="scanned_page_pdf",
                raw_artifact=False,
                note="Automated byte retrieval blocked",
            ),
        )
        row = self.store.conn.execute(
            "SELECT metadata_json FROM documents WHERE document_id = ?",
            (self.document_id,),
        ).fetchone()
        metadata = json.loads(row["metadata_json"])
        acquisition = metadata["acquisition"]
        self.assertEqual(acquisition["state"], "REMOTE_BLOCKED")
        self.assertFalse(acquisition["raw_artifact"])

        audit = self.store.conn.execute(
            """
            SELECT event_type FROM audit_log
            WHERE object_type = 'document' AND object_id = ?
            ORDER BY audit_id DESC LIMIT 1
            """,
            (self.document_id,),
        ).fetchone()
        self.assertEqual(
            audit["event_type"],
            "document_acquisition_state_recorded",
        )


if __name__ == "__main__":
    unittest.main()
