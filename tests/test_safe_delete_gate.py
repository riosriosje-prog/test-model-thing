import copy
import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / "governance/safe_delete_evidence.v1.json").read_text())


def fully_satisfied_snapshot():
    s = copy.deepcopy(SNAPSHOT)
    for key, item in s["required_objects"].items():
        item["state"] = "RAW_BYTES_VERIFIED"
        if "sha256" not in item:
            expected = item.get("expected_sha256")
            item["sha256"] = expected if expected else "a" * 64

    s["controls"]["ow21_discovery_audit"] = {"state": "DISCOVERY_AUDIT_COMPLETE"}
    vault_sha = "c" * 64
    target_sha = "d" * 64
    manifest_sha = "e" * 64
    s["controls"]["final_vault"] = {"state": "VAULT_BUILT_VERIFIED", "sha256": vault_sha}
    s["controls"]["clean_room_restore"] = {"state": "PASS"}
    s["controls"]["deletion_manifest"] = {
        "state": "PRESENT_HASHED",
        "sha256": manifest_sha,
        "targets": [{"object_id": "old-worktree", "sha256": target_sha}],
    }
    s["vault_objects"] = {
        target_sha: {"state": "VERIFIED_IN_FINAL_VAULT", "object_id": "old-worktree"}
    }
    s["controls"]["human_authorization"] = {
        "state": "EXPLICIT_HUMAN_APPROVAL_BOUND",
        "decision_id": "HUMAN-SAFE-DELETE-TEST",
        "deletion_manifest_sha256": manifest_sha,
        "final_vault_sha256": vault_sha,
    }
    return s


class SafeDeleteGateTests(unittest.TestCase):
    def test_current_snapshot_is_hold(self):
        self.assertFalse(evaluate_safe_delete(SNAPSHOT).safe_to_delete)

    def test_missing_5ed030_is_only_raw_object_blocker(self):
        result = evaluate_safe_delete(SNAPSHOT)
        raw = [x for x in result.blocking_reasons if x.startswith((
            "global_master_1_0_1:",
            "santurce_research_15_003:",
            "v1_30_14_003:",
            "cleanup_948d41:",
            "cleanup_upstream_5ed030:",
            "ow02_checkpoint:",
            "ow10_checkpoint:",
            "ow21_checkpoint:",
        ))]
        self.assertEqual(raw, ["cleanup_upstream_5ed030:RAW_BYTES_NOT_RECOVERED"])

    def test_ow02_raw_is_verified(self):
        item = SNAPSHOT["required_objects"]["ow02_checkpoint"]
        self.assertEqual(item["state"], "RAW_BYTES_VERIFIED")
        self.assertEqual(item["sha256"], "455f67ab608714af9cb2687fb567b600ed7730d386f6d2238bc62a68dde07948")

    def test_ow10_raw_is_verified(self):
        item = SNAPSHOT["required_objects"]["ow10_checkpoint"]
        self.assertEqual(item["state"], "RAW_BYTES_VERIFIED")
        self.assertEqual(item["sha256"], "bbd1188b3141b61a4d7738fdd1dba51244265456b5b0d7b759c2aee4e9ae4eda")

    def test_ow21_raw_is_verified_and_required(self):
        item = SNAPSHOT["required_objects"]["ow21_checkpoint"]
        self.assertEqual(item["state"], "RAW_BYTES_VERIFIED")
        self.assertEqual(item["sha256"], "960e3bb7f1c3aa943a65e20ea2f81fc298391c16f4fd2c2177c56226f2a4c73a")

    def test_ow21_discovery_is_complete(self):
        self.assertEqual(SNAPSHOT["controls"]["ow21_discovery_audit"]["state"], "DISCOVERY_AUDIT_COMPLETE")

    def test_staging_vault_is_not_final_vault(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("final_vault:STAGING_VAULT_BUILT_VERIFIED_WITH_DEFICIT", result.blocking_reasons)

    def test_partial_restore_is_not_final_restore(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("clean_room_restore:PARTIAL_PASS_AVAILABLE_OBJECTS_ONLY", result.blocking_reasons)

    def test_deletion_scope_cannot_be_implicit(self):
        self.assertIn("deletion_manifest:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_human_authorization_is_required(self):
        self.assertIn("human_authorization:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_v129_is_advisory_not_blocking(self):
        s = fully_satisfied_snapshot()
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("historical_v1_29_binary:SHOULD_PRESERVE_IF_RECOVERABLE", result.advisories)

    def test_g28_open_is_forensic_only(self):
        s = fully_satisfied_snapshot()
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("G28_REMAINS_FORENSIC_ONLY", result.advisories)

    def test_same_writer_replay_is_not_safe_delete_blocker(self):
        s = fully_satisfied_snapshot()
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("SQLITE_3_46_1_REPLAY_NOT_REQUIRED_FOR_SAFE_DELETE", result.advisories)

    def test_target_not_in_final_vault_blocks(self):
        s = fully_satisfied_snapshot()
        s["vault_objects"] = {}
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertTrue(any("NOT_VERIFIED_IN_FINAL_VAULT" in x for x in result.blocking_reasons))

    def test_human_manifest_hash_must_match(self):
        s = fully_satisfied_snapshot()
        s["controls"]["human_authorization"]["deletion_manifest_sha256"] = "f" * 64
        self.assertIn("human_authorization:DELETION_MANIFEST_HASH_MISMATCH", evaluate_safe_delete(s).blocking_reasons)

    def test_human_vault_hash_must_match(self):
        s = fully_satisfied_snapshot()
        s["controls"]["human_authorization"]["final_vault_sha256"] = "f" * 64
        self.assertIn("human_authorization:FINAL_VAULT_HASH_MISMATCH", evaluate_safe_delete(s).blocking_reasons)

    def test_all_must_conditions_can_yield_candidate(self):
        result = evaluate_safe_delete(fully_satisfied_snapshot())
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_gate_contains_no_delete_action(self):
        source = (ROOT / "galia2/safe_delete.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)


if __name__ == "__main__":
    unittest.main()
