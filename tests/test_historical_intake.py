import os
import tempfile
import unittest

from historical_store import HistoricalStore
from tools.intake_historical_artifact import intake_historical_artifact


class HistoricalArtifactIntakeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "history.sqlite3")
        self.artifact_root = os.path.join(self.tmp.name, "artifacts")
        self.source_file = os.path.join(self.tmp.name, "source.pdf")
        with open(self.source_file, "wb") as f:
            f.write(b"%PDF-1.4\nfixture custodial bytes\n%%EOF\n")

        with HistoricalStore(self.db_path) as store:
            self.document_id = store.register_document(
                title="Historical source pending supplied-file capture",
            )
            self.claim_id = store.propose_claim(
                document_id=self.document_id,
                predicate="marketed_as",
                object_value="El Condado — Parque Residencial",
                claim_text="Fixture claim requiring a newspaper page scan.",
                created_by="test",
                metadata={
                    "promotion_blocked_until_raw_capture": True,
                    "promotion_required_representation_types": [
                        "scanned_newspaper_page_pdf",
                    ],
                },
            )

    def tearDown(self):
        self.tmp.cleanup()

    def test_intake_captures_binds_and_does_not_promote(self):
        result = intake_historical_artifact(
            database_path=self.db_path,
            artifact_root=self.artifact_root,
            document_id=self.document_id,
            file_path=self.source_file,
            representation_type="scanned_newspaper_page_pdf",
            mime_type="application/pdf",
            source_url="https://custodian.example/source.pdf",
            claim_id=self.claim_id,
        )

        self.assertEqual(result["status"], "RAW_CAPTURED")
        self.assertEqual(result["promotion_blockers"], [])
        self.assertFalse(result["claim_promotion_executed"])
        self.assertEqual(result["claim_status"], "PROPOSED")
        self.assertEqual(len(result["sha256"]), 64)

        with HistoricalStore(self.db_path) as store:
            row = store.conn.execute(
                """
                SELECT acquisition_state, raw_artifact, content_sha256,
                       byte_length, representation_type
                FROM document_representations
                WHERE representation_id = ?
                """,
                (result["representation_id"],),
            ).fetchone()
            self.assertEqual(row["acquisition_state"], "RAW_CAPTURED")
            self.assertEqual(row["raw_artifact"], 1)
            self.assertEqual(
                row["representation_type"],
                "scanned_newspaper_page_pdf",
            )
            self.assertEqual(row["content_sha256"], result["sha256"])
            self.assertGreater(row["byte_length"], 0)

            claim_status = store.conn.execute(
                "SELECT status FROM claims WHERE claim_id = ?",
                (self.claim_id,),
            ).fetchone()["status"]
            self.assertEqual(claim_status, "PROPOSED")


if __name__ == "__main__":
    unittest.main()
