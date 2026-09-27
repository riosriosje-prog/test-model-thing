import copy
import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / "governance/safe_delete_evidence.v3.json").read_text())


def deletion_authorized_snapshot():
    s = copy.deepcopy(SNAPSHOT)
    vault_sha = s["controls"]["final_vault"]["sha256"]
    target_sha = "d" * 64
    manifest_sha = "e" * 64
    s["controls"]["deletion_manifest"] = {
        "state": "PRESENT_HASHED",
        "sha256": manifest_sha,
        "targets": [{"object_id": "old-worktree", "sha256": target_sha}],
    }
    s["vault_objects"][target_sha] = {
        "state": "VERIFIED_IN_FINAL_VAULT",
        "object_id": "old-worktree",
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

    def test_5ed030_is_now_raw_bytes_verified(self):
        item = SNAPSHOT["required_objects"]["cleanup_upstream_5ed030"]
        self.assertEqual(item["state"], "RAW_BYTES_VERIFIED")
        self.assertEqual(
            item["sha256"],
            "5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6",
        )
        self.assertEqual(item["recovery_class"], "DETERMINISTIC_REPLAY_BYTE_EXACT_HASH_VERIFIED")
        self.assertFalse(item["manual_header_patch_used"])
        self.assertFalse(item["destructive_rollback_used"])

    def test_irrecoverable_loss_acceptance_is_not_required_after_raw_recovery(self):
        self.assertEqual(
            SNAPSHOT["controls"]["irrecoverable_transient_acceptance"]["state"],
            "NOT_REQUIRED_RAW_BYTES_RECOVERED",
        )
        self.assertFalse(
            any(
                x.startswith("irrecoverable_transient_acceptance:")
                for x in evaluate_safe_delete(SNAPSHOT).blocking_reasons
            )
        )

    def test_final_vault_is_verified(self):
        vault = SNAPSHOT["controls"]["final_vault"]
        self.assertEqual(vault["state"], "VAULT_BUILT_VERIFIED")
        self.assertEqual(
            vault["sha256"],
            "2e964136234ebeccb091998c959ada549af878ea8908414be24889402ad36664",
        )

    def test_clean_room_restore_passes(self):
        self.assertEqual(SNAPSHOT["controls"]["clean_room_restore"]["state"], "PASS")
        self.assertTrue(SNAPSHOT["controls"]["clean_room_restore"]["all_package_hashes_pass"])
        self.assertTrue(SNAPSHOT["controls"]["clean_room_restore"]["all_sqlite_checks_pass"])

    def test_historical_v129_is_preserved(self):
        self.assertEqual(
            SNAPSHOT["should_preserve"]["historical_v1_29_binary"]["state"],
            "RAW_BYTES_VERIFIED",
        )
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertNotIn(
            "historical_v1_29_binary:SHOULD_PRESERVE_IF_RECOVERABLE",
            result.advisories,
        )

    def test_same_writer_replay_is_pass(self):
        self.assertEqual(
            SNAPSHOT["forensic_only"]["sqlite_3_46_1_same_writer_replay"]["state"],
            "PASS",
        )
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertNotIn("SQLITE_3_46_1_REPLAY_NOT_REQUIRED_FOR_SAFE_DELETE", result.advisories)

    def test_g28_remains_forensic_only(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("G28_REMAINS_FORENSIC_ONLY", result.advisories)

    def test_only_deletion_decision_controls_block_current_snapshot(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertEqual(
            set(result.blocking_reasons),
            {"deletion_manifest:ABSENT", "human_authorization:ABSENT"},
        )

    def test_deletion_scope_cannot_be_implicit(self):
        self.assertIn("deletion_manifest:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_deletion_specific_human_authorization_is_required(self):
        self.assertIn("human_authorization:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_authorized_exact_manifest_can_yield_safe_candidate(self):
        result = evaluate_safe_delete(deletion_authorized_snapshot())
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_target_not_in_final_vault_blocks(self):
        s = deletion_authorized_snapshot()
        target_sha = s["controls"]["deletion_manifest"]["targets"][0]["sha256"]
        del s["vault_objects"][target_sha]
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn("deletion_target_0:NOT_VERIFIED_IN_FINAL_VAULT", result.blocking_reasons)

    def test_deletion_manifest_hash_must_match_authorization(self):
        s = deletion_authorized_snapshot()
        s["controls"]["human_authorization"]["deletion_manifest_sha256"] = "f" * 64
        self.assertIn(
            "human_authorization:DELETION_MANIFEST_HASH_MISMATCH",
            evaluate_safe_delete(s).blocking_reasons,
        )

    def test_final_vault_hash_must_match_authorization(self):
        s = deletion_authorized_snapshot()
        s["controls"]["human_authorization"]["final_vault_sha256"] = "f" * 64
        self.assertIn(
            "human_authorization:FINAL_VAULT_HASH_MISMATCH",
            evaluate_safe_delete(s).blocking_reasons,
        )

    def test_gate_contains_no_delete_action(self):
        source = (ROOT / "galia2/safe_delete.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)


if __name__ == "__main__":
    unittest.main()
