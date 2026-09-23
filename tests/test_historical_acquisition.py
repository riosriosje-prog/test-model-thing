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

    def test_raw_captured_requires_hash_size_and_raw_artifact(self):
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
        with self.assertRaises(ValueError):
            record_acquisition_state(
                self.store,
                document_id=self.document_id,
                receipt=AcquisitionReceipt(
                    state="RAW_CAPTURED",
                    source_url="https://example.invalid/source.pdf",
                    representation_type="pdf",
                    raw_artifact=True,
                ),
            )

    def test_remote_blocked_creates_representation_and_audit(self):
        representation_id = record_acquisition_state(
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
            """
            SELECT acquisition_state, raw_artifact, source_url, locator
            FROM document_representations
            WHERE representation_id = ?
            """,
            (representation_id,),
        ).fetchone()
        self.assertEqual(row["acquisition_state"], "REMOTE_BLOCKED")
        self.assertEqual(row["raw_artifact"], 0)
        self.assertEqual(
            row["source_url"],
            "https://example.invalid/source.pdf",
        )
        self.assertEqual(
            row["locator"],
            "https://example.invalid/source.pdf",
        )

        audit = self.store.conn.execute(
            """
            SELECT event_type FROM audit_log
            WHERE object_type = 'document_representation'
              AND object_id = ?
            ORDER BY audit_id DESC LIMIT 1
            """,
            (representation_id,),
        ).fetchone()
        self.assertEqual(
            audit["event_type"],
            "document_representation_registered",
        )


if __name__ == "__main__":
    unittest.main()
