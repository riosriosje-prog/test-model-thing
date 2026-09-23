import json
import os
import tempfile
import unittest

from historical_store import HistoricalStore
from historical_store_bundle import (
    bundle_sha256,
    export_bundle,
    load_bundle,
    reconstruct_bundle,
    write_bundle_atomic,
)
from pilots.condado_shadow import LOC_CONDADO_1908_URL, seed_condado_shadow


class CondadoShadowPilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "condado.sqlite3")
        self.store = HistoricalStore(self.db_path)
        self.ids = seed_condado_shadow(self.store)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_pilot_never_auto_promotes_claims(self):
        canonical = self.store.conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'CANONICAL'"
        ).fetchone()[0]
        proposed = self.store.conn.execute(
            "SELECT COUNT(*) FROM claims WHERE status = 'PROPOSED'"
        ).fetchone()[0]
        self.assertEqual(canonical, 0)
        self.assertEqual(proposed, 6)

    def test_condado_area_discrepancy_preserves_all_variants(self):
        discrepancy_id = self.ids["area_discrepancy_id"]
        rows = self.store.conn.execute(
            """
            SELECT c.object_value, c.status, dc.stance
            FROM discrepancy_claims dc
            JOIN claims c ON c.claim_id = dc.claim_id
            WHERE dc.discrepancy_id = ?
            ORDER BY c.object_value
            """,
            (discrepancy_id,),
        ).fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            {row["object_value"] for row in rows},
            {"148 cuerdas", "150 cuerdas", "148.5 acres"},
        )
        self.assertTrue(all(row["status"] == "PROPOSED" for row in rows))

    def test_judicial_claim_has_provenance_anchor(self):
        transfer_claim_id = self.ids["transfer_claim_id"]
        bundle = self.store.claim_bundle(transfer_claim_id)
        self.assertEqual(bundle["claim"]["status"], "PROPOSED")
        self.assertEqual(len(bundle["evidence"]), 1)
        evidence = bundle["evidence"][0]
        self.assertEqual(
            evidence["source_locator"],
            "26 D.P.R. 166 (1918)",
        )
        self.assertEqual(
            evidence["document_date"],
            "1918",
        )
        self.assertEqual(
            evidence["event_date_start"],
            "1917-08-24",
        )

    def test_loc_primary_source_is_fail_closed_when_raw_bytes_unavailable(self):
        document_id = self.ids["newspaper_document_id"]
        row = self.store.conn.execute(
            """
            SELECT content_sha256, byte_length, content_locator, metadata_json
            FROM documents WHERE document_id = ?
            """,
            (document_id,),
        ).fetchone()
        metadata = json.loads(row["metadata_json"])
        self.assertIsNone(row["content_sha256"])
        self.assertIsNone(row["byte_length"])
        self.assertEqual(row["content_locator"], LOC_CONDADO_1908_URL)
        self.assertEqual(
            metadata["acquisition"]["state"],
            "REMOTE_BLOCKED",
        )
        self.assertFalse(metadata["acquisition"]["raw_artifact"])

        claim = self.store.conn.execute(
            """
            SELECT status, metadata_json FROM claims
            WHERE claim_id = ?
            """,
            (self.ids["newspaper_claim_id"],),
        ).fetchone()
        claim_metadata = json.loads(claim["metadata_json"])
        self.assertEqual(claim["status"], "PROPOSED")
        self.assertTrue(
            claim_metadata["promotion_blocked_until_raw_capture"]
        )

    def test_bundle_export_is_deterministic(self):
        first = export_bundle(self.store)
        second = export_bundle(self.store)
        self.assertEqual(first, second)
        self.assertEqual(bundle_sha256(first), bundle_sha256(second))

    def test_bundle_round_trip_reconstructs_provenance_exactly(self):
        bundle_path = os.path.join(self.tmp.name, "condado.bundle.json")
        written_digest = write_bundle_atomic(self.store, bundle_path)
        loaded = load_bundle(bundle_path)
        self.assertEqual(written_digest, bundle_sha256(loaded))

        rebuilt_path = os.path.join(self.tmp.name, "condado-rebuilt.sqlite3")
        rebuilt = reconstruct_bundle(loaded, rebuilt_path)
        try:
            rebuilt_bundle = export_bundle(rebuilt)
            self.assertEqual(bundle_sha256(loaded), bundle_sha256(rebuilt_bundle))
            self.assertEqual(
                self.store.health()["counts"],
                rebuilt.health()["counts"],
            )
        finally:
            rebuilt.close()


if __name__ == "__main__":
    unittest.main()
