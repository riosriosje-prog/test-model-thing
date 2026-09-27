import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REC = json.loads((ROOT / "governance" / "galia_grafana_promotion_reconciliation_candidate.v0_2.json").read_text())
ACT = json.loads((ROOT / "receipts" / "grafana" / "galia_grafana_activation_v0_6_merge_event.v0_2.json").read_text())
DS = json.loads((ROOT / "receipts" / "grafana" / "galia_grafana_datasource_v0_8_merge_event.v0_2.json").read_text())

class GrafanaPromotionReconciliationV02Tests(unittest.TestCase):
    def test_authority_hold_is_active(self):
        self.assertEqual(REC["status"], "AUTHORITY_HOLD_NOT_PROMOTABLE")
        self.assertTrue(REC["authority_hold"]["active"])
        self.assertEqual(REC["scope_of_impact"], "GITHUB_CONTROL_PLANE_ONLY")
        self.assertEqual(REC["external_activation_state"], "NOT_EXECUTED")

    def test_activation_merge_is_not_labeled_valid_promotion(self):
        self.assertTrue(ACT["github_merge_executed"])
        self.assertTrue(ACT["human_promotion_instruction_observed"])
        self.assertFalse(ACT["candidate_was_eligible_at_merge"])
        self.assertFalse(ACT["canonical_promotion_validated"])
        self.assertEqual(ACT["source_candidate_status_at_merge"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertEqual(ACT["constitution_required_status_before_promotion"], "READY_FOR_HUMAN_PROMOTION")
        self.assertEqual(ACT["authority_status"], "AUTHORITY_HOLD_PENDING_RECONCILIATION")

    def test_datasource_merge_is_not_labeled_valid_promotion(self):
        self.assertTrue(DS["github_merge_executed"])
        self.assertTrue(DS["human_promotion_instruction_observed"])
        self.assertFalse(DS["candidate_was_eligible_at_merge"])
        self.assertFalse(DS["canonical_promotion_validated"])
        self.assertEqual(DS["authority_status"], "AUTHORITY_HOLD_PENDING_RECONCILIATION")

    def test_no_external_activation_occurred(self):
        self.assertFalse(ACT["external_activation_executed"])
        self.assertFalse(ACT["ssl_enforcement_changed"])
        self.assertFalse(ACT["temporary_access_changed"])
        self.assertFalse(ACT["jit_mapping_changed"])
        self.assertFalse(DS["grafana_datasource_configured"])
        self.assertFalse(DS["supabase_mutation_executed"])
        self.assertFalse(DS["jit_activation_executed"])

    def test_reconciliation_requires_new_human_decision(self):
        paths = {x["id"] for x in REC["admissible_human_reconciliation_paths"]}
        self.assertEqual(paths, {"RATIFY_AFTER_SCOPE_CORRECTION", "REVERT_CONTROL_PLANE_MERGES"})
        self.assertTrue(REC["semantic_correction_required"]["no_retroactive_silent_relabel"])

if __name__ == "__main__":
    unittest.main()
