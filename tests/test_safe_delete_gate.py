import copy
import hashlib
import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / "governance/safe_delete_evidence.v2.json").read_text())
LOSS_RECORD_PATH = ROOT / "governance/irrecoverable_transient_5ed030.v1.json"


def fully_satisfied_snapshot(*, use_documented_loss=False):
    s = copy.deepcopy(SNAPSHOT)

    if use_documented_loss:
        loss = s["required_objects"]["cleanup_upstream_5ed030"]
        s["controls"]["irrecoverable_transient_acceptance"] = {
            "state": "EXPLICIT_HUMAN_IRRECOVERABLE_TRANSIENT_ACCEPTANCE_BOUND",
            "decision_id": "HUMAN-LOSS-ACCEPTANCE-TEST",
            "object_id": "cleanup_upstream_5ed030",
            "expected_sha256": loss["expected_sha256"],
            "evidence_record_sha256": loss["evidence_record_sha256"],
        }
    else:
        loss = s["required_objects"]["cleanup_upstream_5ed030"]
        loss.clear()
        loss.update({
            "state": "RAW_BYTES_VERIFIED",
            "sha256": "5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6",
        })
        s["controls"]["irrecoverable_transient_acceptance"] = {"state": "NOT_REQUIRED_RAW_BYTES_RECOVERED"}

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

    def test_5ed030_is_documented_loss_not_fabricated_raw_bytes(self):
        item = SNAPSHOT["required_objects"]["cleanup_upstream_5ed030"]
        self.assertEqual(item["state"], "IRRECOVERABLE_TRANSIENT_DOCUMENTED")
        self.assertNotIn("sha256", item)
        self.assertFalse(item["reverse_reconstruction_accepted"])

    def test_loss_record_hash_is_bound_exactly(self):
        expected = SNAPSHOT["required_objects"]["cleanup_upstream_5ed030"]["evidence_record_sha256"]
        actual = hashlib.sha256(LOSS_RECORD_PATH.read_bytes()).hexdigest()
        self.assertEqual(actual, expected)

    def test_documented_loss_requires_separate_human_acceptance(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("irrecoverable_transient_acceptance:ABSENT", result.blocking_reasons)

    def test_nonzero_knowledge_mutation_blocks_loss_path(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["required_objects"]["cleanup_upstream_5ed030"]["knowledge_mutations"]["statements"] = 1
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn("cleanup_upstream_5ed030:KNOWLEDGE_MUTATIONS_NOT_ZERO", result.blocking_reasons)

    def test_wrong_successor_blocks_loss_path(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["required_objects"]["cleanup_upstream_5ed030"]["successor_sha256"] = "f" * 64
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn("cleanup_upstream_5ed030:SUCCESSOR_BINDING_MISMATCH", result.blocking_reasons)

    def test_unproven_classification_blocks_loss_path(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["required_objects"]["cleanup_upstream_5ed030"]["classification"] = "UNKNOWN"
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn("cleanup_upstream_5ed030:CLASSIFICATION_NOT_PROVEN", result.blocking_reasons)

    def test_reverse_reconstruction_cannot_substitute(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["required_objects"]["cleanup_upstream_5ed030"]["reverse_reconstruction_accepted"] = True
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn(
            "cleanup_upstream_5ed030:REVERSE_RECONSTRUCTION_MUST_NOT_SUBSTITUTE_RAW_BYTES",
            result.blocking_reasons,
        )

    def test_acceptance_must_bind_exact_evidence_record(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["controls"]["irrecoverable_transient_acceptance"]["evidence_record_sha256"] = "f" * 64
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertIn(
            "irrecoverable_transient_acceptance:EVIDENCE_RECORD_HASH_MISMATCH",
            result.blocking_reasons,
        )

    def test_raw_recovery_path_still_works_without_loss_acceptance(self):
        result = evaluate_safe_delete(fully_satisfied_snapshot(use_documented_loss=False))
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_strict_documented_loss_path_can_yield_candidate_after_acceptance(self):
        result = evaluate_safe_delete(fully_satisfied_snapshot(use_documented_loss=True))
        self.assertTrue(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ())

    def test_staging_vault_is_not_final_vault(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn(
            "final_vault:STAGING_VAULT_BUILT_VERIFIED_WITH_DOCUMENTED_TRANSIENT_LOSS",
            result.blocking_reasons,
        )

    def test_partial_restore_is_not_final_restore(self):
        result = evaluate_safe_delete(SNAPSHOT)
        self.assertIn("clean_room_restore:PARTIAL_PASS_AVAILABLE_OBJECTS_ONLY", result.blocking_reasons)

    def test_deletion_scope_cannot_be_implicit(self):
        self.assertIn("deletion_manifest:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_deletion_human_authorization_is_still_required(self):
        self.assertIn("human_authorization:ABSENT", evaluate_safe_delete(SNAPSHOT).blocking_reasons)

    def test_v129_is_advisory_not_blocking(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("historical_v1_29_binary:SHOULD_PRESERVE_IF_RECOVERABLE", result.advisories)

    def test_g28_open_is_forensic_only(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("G28_REMAINS_FORENSIC_ONLY", result.advisories)

    def test_same_writer_replay_is_not_safe_delete_blocker(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        result = evaluate_safe_delete(s)
        self.assertTrue(result.safe_to_delete)
        self.assertIn("SQLITE_3_46_1_REPLAY_NOT_REQUIRED_FOR_SAFE_DELETE", result.advisories)

    def test_target_not_in_final_vault_blocks(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["vault_objects"] = {}
        result = evaluate_safe_delete(s)
        self.assertFalse(result.safe_to_delete)
        self.assertTrue(any("NOT_VERIFIED_IN_FINAL_VAULT" in x for x in result.blocking_reasons))

    def test_deletion_authorization_hashes_must_match(self):
        s = fully_satisfied_snapshot(use_documented_loss=True)
        s["controls"]["human_authorization"]["deletion_manifest_sha256"] = "f" * 64
        self.assertIn(
            "human_authorization:DELETION_MANIFEST_HASH_MISMATCH",
            evaluate_safe_delete(s).blocking_reasons,
        )

    def test_gate_contains_no_delete_action(self):
        source = (ROOT / "galia2/safe_delete.py").read_text().lower()
        self.assertNotIn("unlink(", source)
        self.assertNotIn("remove(", source)
        self.assertNotIn("rmtree(", source)


if __name__ == "__main__":
    unittest.main()
