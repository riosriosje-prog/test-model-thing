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

    def test_document_binding_records_hash_size_locator_and_audit(self):
        source_id = self.store.register_source(
            source_type="court_opinion",
            title="Primary source",
        )
        document_id = self.store.register_document(
            source_id=source_id,
            title="Source document",
        )
        receipt = self.artifacts.put_bytes(b"raw-source-document")
        self.artifacts.bind_document(
            self.store,
            document_id,
            receipt,
        )

        row = self.store.conn.execute(
            """
            SELECT content_sha256, byte_length, content_locator
            FROM documents WHERE document_id = ?
            """,
            (document_id,),
        ).fetchone()
        self.assertEqual(row["content_sha256"], receipt.sha256)
        self.assertEqual(row["byte_length"], receipt.size_bytes)
        self.assertEqual(row["content_locator"], receipt.locator)

        audit = self.store.conn.execute(
            """
            SELECT event_type, payload_json
            FROM audit_log
            WHERE object_type = 'document' AND object_id = ?
            ORDER BY audit_id DESC LIMIT 1
            """,
            (document_id,),
        ).fetchone()
        self.assertEqual(audit["event_type"], "document_artifact_bound")

    def test_rebinding_to_different_artifact_fails_closed(self):
        document_id = self.store.register_document(
            title="Source document",
        )
        first = self.artifacts.put_bytes(b"first")
        second = self.artifacts.put_bytes(b"second")
        self.artifacts.bind_document(
            self.store,
            document_id,
            first,
        )
        with self.assertRaises(ValueError):
            self.artifacts.bind_document(
                self.store,
                document_id,
                second,
            )


if __name__ == "__main__":
    unittest.main()
