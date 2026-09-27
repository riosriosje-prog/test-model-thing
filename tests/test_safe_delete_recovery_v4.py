import copy
import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / "governance/safe_delete_evidence.v3.json").read_text())

TARGET_5ED = "5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6"
VAULT_SHA = "53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf"


class SafeDeleteRecoveryV4Tests(unittest.TestCase):
    def test_current_snapshot_remains_hold(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertFalse(result.safe_to_delete)
        self.assertEqual(
            result.blocking_reasons,
            ("deletion_manifest:ABSENT", "human_authorization:ABSENT"),
        )

    def test_5ed030_is_now_raw_bytes_verified(self):
        item = SNAPSHOT["required_objects"]["cleanup_upstream_5ed030"]
        self.assertEqual(item["state"], "RAW_BYTES_VERIFIED")
        self.assertEqual(item["sha256"], TARGET_5ED)
        self.assertEqual(item["sqlite_integrity"], "ok")
        self.assertEqual(item["foreign_key_violations"], 0)

    def test_irrecoverable_loss_acceptance_is_no_longer_required(self):
        self.assertEqual(
            SNAPSHOT["controls"]["irrecoverable_transient_acceptance"]["state"],
            "NOT_REQUIRED_RAW_BYTES_RECOVERED",
        )
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertFalse(any("irrecoverable_transient_acceptance" in x for x in result.blocking_reasons))

    def test_final_vault_is_verified_and_hash_bound(self):
        vault = SNAPSHOT["controls"]["final_vault"]
        self.assertEqual(vault["state"], "VAULT_BUILT_VERIFIED")
        self.assertEqual(vault["sha256"], VAULT_SHA)

    def test_clean_room_restore_passed(self):
        restore = SNAPSHOT["controls"]["clean_room_restore"]
        self.assertEqual(restore["state"], "PASS")
        self.assertEqual(restore["sqlite_integrity"], "PASS_ALL")
        self.assertEqual(restore["foreign_key_check"], "0_ALL")

    def test_historical_v129_is_now_preserved(self):
        v129 = SNAPSHOT["should_preserve"]["historical_v1_29_binary"]
        self.assertEqual(v129["state"], "RAW_BYTES_VERIFIED")
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertFalse(any(x.startswith("historical_v1_29_binary:") for x in result.advisories))

    def test_exact_deletion_manifest_and_human_approval_are_still_required(self):
        s = copy.deepcopy(SNAPSHOT)
        manifest_sha = "e" * 64
        s["controls"]["deletion_manifest"] = {
            "state": "PRESENT_HASHED",
            "sha256": manifest_sha,
            "targets": [{"object_id": "cleanup_upstream_5ed030", "sha256": TARGET_5ED}],
        }
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ("human_authorization:ABSENT",))

        s["controls"]["human_authorization"] = {
            "state": "EXPLICIT_HUMAN_APPROVAL_BOUND",
            "decision_id": "HUMAN-SAFE-DELETE-TEST",
            "deletion_manifest_sha256": manifest_sha,
            "final_vault_sha256": VAULT_SHA,
        }
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_gate_contains_no_delete_action(self):
        source = (ROOT / "galia2/safe_delete.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)


if __name__ == "__main__":
    unittest.main()
