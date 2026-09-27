import json
import unittest
from pathlib import Path

from galia2.safe_delete import evaluate_safe_delete

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = json.loads((ROOT / "governance/safe_delete_evidence.v5.json").read_text())
PREFLIGHT = json.loads((ROOT / "governance/safe_delete_hold_preflight.v1.json").read_text())

class SafeDeleteHoldPreflightV6Tests(unittest.TestCase):
    def test_preflight_is_ready_but_not_authorized(self):
        self.assertEqual(
            PREFLIGHT["status"],
            "READY_FOR_EXPLICIT_HUMAN_DELETE_AUTHORIZATION",
        )
        self.assertFalse(PREFLIGHT["safety"]["delete_authorized"])
        self.assertFalse(PREFLIGHT["safety"]["destructive_action_executed"])

    def test_exact_manifest_and_vault_binding_are_present(self):
        self.assertEqual(
            PREFLIGHT["deletion_manifest"]["sha256"],
            "6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708",
        )
        self.assertEqual(
            PREFLIGHT["final_vault"]["manifest_sha256"],
            "53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf",
        )

    def test_live_target_revalidation_passed(self):
        live=PREFLIGHT["live_revalidation"]
        self.assertEqual(live["deletion_targets_present"], "PASS_27_OF_27")
        self.assertEqual(live["sealed_vault_control_objects_present"], "PASS_17_OF_17")
        self.assertTrue(live["sealed_vault_excluded_from_targets"])
        self.assertTrue(live["recovery_folder_bulk_delete_excluded"])
        self.assertTrue(live["corrupt_partial_zip_excluded"])
        self.assertTrue(live["reconstruction_chunks_excluded"])

    def test_gate_remains_hold_only_for_human_authorization(self):
        result=evaluate_safe_delete(SNAPSHOT)
        self.assertFalse(result.safe_to_delete)
        self.assertEqual(result.blocking_reasons, ("human_authorization:ABSENT",))

if __name__ == "__main__":
    unittest.main()
