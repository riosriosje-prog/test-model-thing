import hashlib
import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "governance/safe_delete_evidence.v4.json"
MANIFEST_PATH = ROOT / "governance/safe_delete_deletion_manifest.v1.json"
EXPECTED_MANIFEST_SHA = "6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708"
SEALED_PREFIX = "/GALIA_FINAL_VAULT_SEALED_2026-09-26/"


class SafeDeleteDeletionManifestV5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(SNAPSHOT_PATH.read_text())
        cls.manifest = json.loads(MANIFEST_PATH.read_text())

    def test_manifest_hash_is_exact(self):
        self.assertEqual(hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(), EXPECTED_MANIFEST_SHA)

    def test_manifest_has_exactly_27_explicit_targets(self):
        self.assertEqual(self.manifest["target_count"], 27)
        self.assertEqual(len(self.manifest["targets"]), 27)
        self.assertEqual(len({t["library_file_id"] for t in self.manifest["targets"]}), 27)

    def test_every_target_has_exact_sealed_preservation_match(self):
        for target in self.manifest["targets"]:
            self.assertEqual(target["sha256"], target["preservation_sha256"])
            self.assertTrue(target["preserved_in_sealed_vault"].startswith(SEALED_PREFIX))
            self.assertEqual(
                self.snapshot["vault_objects"][target["sha256"]]["state"],
                "VERIFIED_IN_FINAL_VAULT",
            )

    def test_sealed_vault_is_explicitly_excluded(self):
        self.assertIn("/GALIA_FINAL_VAULT_SEALED_2026-09-26", self.manifest["explicit_exclusions"])
        self.assertFalse(any(t["path"].startswith(SEALED_PREFIX) for t in self.manifest["targets"]))

    def test_recovery_folder_is_not_bulk_deleted(self):
        self.assertIn("/GALIA_RECOVERY", self.manifest["explicit_exclusions"])
        self.assertFalse(any(t["path"].startswith("/GALIA_RECOVERY/") for t in self.manifest["targets"]))

    def test_corrupt_partial_zip_is_excluded(self):
        self.assertIn(
            "/GALIA_FINAL_VAULT_STAGING_2026-09-26/GALIA_5ED030_BYTE_EXACT_RECOVERY_2026-09-26.zip",
            self.manifest["explicit_exclusions"],
        )
        self.assertFalse(any(
            t["path"].endswith("GALIA_5ED030_BYTE_EXACT_RECOVERY_2026-09-26.zip")
            for t in self.manifest["targets"]
        ))

    def test_chunks_are_not_in_deletion_manifest(self):
        self.assertFalse(any(".part" in t["path"] for t in self.manifest["targets"]))
        self.assertFalse(any(t["path"].endswith("GALIA_5ED030_CHUNK_MANIFEST.json") for t in self.manifest["targets"]))

    def test_gate_is_blocked_only_by_human_deletion_authorization(self):
        result = evaluate_safe_delete(self.snapshot)
        self.assertFalse(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ("human_authorization:ABSENT",))

    def test_manifest_itself_does_not_authorize_delete(self):
        self.assertFalse(self.manifest["delete_authorized"])
        self.assertIsNone(self.manifest["human_authorization"])


if __name__ == "__main__":
    unittest.main()
