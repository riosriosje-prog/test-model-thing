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
            if expected:
                item["sha256"] = expected
            else:
                item["sha256"] = ("a" if key == "ow10_checkpoint" else "b") * 64

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
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertFalse(result.safe_to_delete)

    def test_missing_5ed030_blocks(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertTrue(any(x.startswith("cleanup_upstream_5ed030:") for x in result.blocking_reasons))

    def test_missing_ow02_raw_blocks(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertTrue(any(x.startswith("ow02_checkpoint:") for x in result.blocking_reasons))

    def test_missing_ow10_raw_blocks(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertTrue(any(x.startswith("ow10_checkpoint:") for x in result.blocking_reasons))

    def test_ow21_discovery_must_complete(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("ow21_discovery_audit:NOT_COMPLETE", result.blocking_reasons)

    def test_final_vault_must_exist(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("final_vault:NOT_BUILT", result.blocking_reasons)

    def test_clean_room_restore_must_pass(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("clean_room_restore:NOT_RUN", result.blocking_reasons)

    def test_deletion_scope_cannot_be_implicit(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("deletion_manifest:ABSENT", result.blocking_reasons)

    def test_human_authorization_is_required(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("human_authorization:ABSENT", result.blocking_reasons)

    def test_v129_is_advisory_not_blocking(self):
        s = fully_satisfied_snapshot()
        s["should_preserve"]["historical_v1_29_binary"]["state"] = "RAW_BYTES_NOT_RECOVERED"
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("historical_v1_29_binary:SHOULD_PRESERVE_IF_RECOVERABLE", result.advisories)

    def test_g28_open_is_forensic_only(self):
        s = fully_satisfied_snapshot()
        s["forensic_only"]["g28_14_003_to_15_003"]["state"] = "OPEN_UNPROVEN"
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("G28_REMAINS_FORENSIC_ONLY", result.advisories)

    def test_same_writer_replay_is_not_safe_delete_blocker(self):
        s = fully_satisfied_snapshot()
        s["forensic_only"]["sqlite_3_46_1_same_writer_replay"]["state"] = "NOT_RUN"
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("SQLITE_3_46_1_REPLAY_NOT_REQUIRED_FOR_SAFE_DELETE", result.advisories)

    def test_target_not_in_vault_blocks(self):
        s = fully_satisfied_snapshot()
        s["vault_objects"] = {}
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertTrue(any("NOT_VERIFIED_IN_FINAL_VAULT" in x for x in result.blocking_reasons))

    def test_human_manifest_hash_must_match(self):
        s = fully_satisfied_snapshot()
        s["controls"]["human_authorization"]["deletion_manifest_sha256"] = "f" * 64
        result = evaluate_safe_delete(s)
        self.assertIn("human_authorization:DELETION_MANIFEST_HASH_MISMATCH", result.blocking_reasons)

    def test_human_vault_hash_must_match(self):
        s = fully_satisfied_snapshot()
        s["controls"]["human_authorization"]["final_vault_sha256"] = "f" * 64
        result = evaluate_safe_delete(s)
        self.assertIn("human_authorization:FINAL_VAULT_HASH_MISMATCH", result.blocking_reasons)

    def test_all_must_conditions_can_yield_candidate(self):
        result = evaluate_safe_delete(fully_satisfied_snapshot())
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_global_master_and_research_state_are_mandatory(self):
        for key in ("global_master_1_0_1", "santurce_research_15_003"):
            s = fully_satisfied_snapshot()
            s["required_objects"][key]["state"] = "MISSING"
            self.assertFalse(evaluate_safe_delete(s).safe_to_delete)

    def test_gate_contains_no_delete_action(self):
        source = (ROOT / "galia2/safe_delete.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)


if __name__ == "__main__":
    unittest.main()
