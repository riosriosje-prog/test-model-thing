import os
import tempfile
import unittest

from historical_artifacts import HistoricalArtifactStore
from historical_store import HistoricalStore


class HistoricalArtifactStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "history.sqlite3")
        self.artifact_root = os.path.join(self.tmp.name, "artifacts")
        self.store = HistoricalStore(self.db_path)
        self.artifacts = HistoricalArtifactStore(self.artifact_root)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_capture_is_content_addressed_and_deduplicated(self):
        data = b"historical-source-bytes"
        first = self.artifacts.put_bytes(data)
        second = self.artifacts.put_bytes(data)
        self.assertEqual(first, second)
        self.assertTrue(
            self.artifacts.verify(first.sha256, expected_size=len(data))
        )
        self.assertEqual(
            self.artifacts.read_bytes(first.sha256),
            data,
        )

    def test_tamper_is_detected(self):
        receipt = self.artifacts.put_bytes(b"original")
        path = self.artifacts._path_for(receipt.sha256)
        path.write_bytes(b"tampered")
        self.assertFalse(
            self.artifacts.verify(
                receipt.sha256,
                expected_size=receipt.size_bytes,
            )
        )
        with self.assertRaises(ValueError):
            self.artifacts.read_bytes(receipt.sha256)

    def test_document_binding_creates_raw_captured_representation(self):
        source_id = self.store.register_source(
            source_type="court_opinion",
            title="Primary source",
        )
        document_id = self.store.register_document(
            source_id=source_id,
            title="Source document",
        )
        receipt = self.artifacts.put_bytes(b"raw-source-document")
        representation_id = self.artifacts.bind_document(
            self.store,
            document_id,
            receipt,
            representation_type="scanned_source_pdf",
            mime_type="application/pdf",
            source_url="https://example.invalid/source.pdf",
        )

        row = self.store.conn.execute(
            """
            SELECT acquisition_state, content_sha256, byte_length, locator,
                   raw_artifact, mime_type
            FROM document_representations
            WHERE representation_id = ?
            """,
            (representation_id,),
        ).fetchone()
        self.assertEqual(row["acquisition_state"], "RAW_CAPTURED")
        self.assertEqual(row["content_sha256"], receipt.sha256)
        self.assertEqual(row["byte_length"], receipt.size_bytes)
        self.assertEqual(row["locator"], receipt.locator)
        self.assertEqual(row["raw_artifact"], 1)
        self.assertEqual(row["mime_type"], "application/pdf")

        audit = self.store.conn.execute(
            """
            SELECT event_type
            FROM audit_log
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

    def test_distinct_raw_representations_can_coexist(self):
        document_id = self.store.register_document(
            title="Source document",
        )
        first = self.artifacts.put_bytes(b"first")
        second = self.artifacts.put_bytes(b"second")
        first_id = self.artifacts.bind_document(
            self.store,
            document_id,
            first,
            representation_type="scan_pdf",
        )
        second_id = self.artifacts.bind_document(
            self.store,
            document_id,
            second,
            representation_type="scan_jp2",
        )
        self.assertNotEqual(first_id, second_id)
        count = self.store.conn.execute(
            """
            SELECT COUNT(*) FROM document_representations
            WHERE document_id = ? AND acquisition_state = 'RAW_CAPTURED'
            """,
            (document_id,),
        ).fetchone()[0]
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
