import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRACE = json.loads((ROOT / "governance" / "galia_grafana_promotion_trace_candidate.v0_1.json").read_text())
ACT = json.loads((ROOT / "receipts" / "grafana" / "galia_grafana_activation_v0_6_promotion_receipt.json").read_text())
DS = json.loads((ROOT / "receipts" / "grafana" / "galia_grafana_datasource_v0_8_promotion_receipt.json").read_text())

class GrafanaPromotionTraceV01Tests(unittest.TestCase):
    def test_trace_candidate_is_not_itself_promoted(self):
        self.assertEqual(TRACE["status"], "PREPARATION_ONLY_NOT_PROMOTED")
        self.assertIn("NO_AUTHORITY_TRANSFER", TRACE["non_effects"])

    def test_activation_promotion_is_exact(self):
        self.assertTrue(ACT["human_promotion_authorized"])
        self.assertTrue(ACT["promoted"])
        self.assertEqual(ACT["github_pr"], 54)
        self.assertEqual(ACT["candidate_head"], "d0c71aaf76333a7f6b8542e2b48b01cfa0ad6654")
        self.assertEqual(ACT["candidate_set_sha256"], "1b0d25ca98a59182ade20d868f371655c7bd86d625d9c8dbd1961f896d5d73c2")
        self.assertEqual(ACT["promoted_main_commit"], "dd717c61d50240251044040b61956768a3325d14")
        self.assertEqual(ACT["promotion_scope"], "PREPARATION_BASELINE_ONLY")

    def test_v05_ancestry_is_not_separate_promotion(self):
        p = ACT["predecessor"]
        self.assertTrue(p["github_now_reports_merged"])
        self.assertEqual(p["relationship"], "ANCESTOR_INCLUDED_BY_SUCCESSOR")
        self.assertFalse(p["separately_human_promoted"])
        self.assertEqual(p["authority_status"], "NOT_PROMOTED_AS_SEPARATE_BASELINE")

    def test_datasource_promotion_is_exact(self):
        self.assertTrue(DS["human_promotion_authorized"])
        self.assertTrue(DS["promoted"])
        self.assertEqual(DS["github_pr"], 55)
        self.assertEqual(DS["candidate_head"], "b4cb4aee27b1a9479dd6b0ae79f84097e48e6bde")
        self.assertEqual(DS["candidate_set_sha256"], "3b37c650c8b0302990cd62f6cb967bcbcdcaaa3cc97ad73f7a12637055e79e9d")
        self.assertEqual(DS["promoted_main_commit"], "a3b60d02e993a5d0b01e6ef40905f5ba0dfc4892")
        self.assertEqual(DS["promotion_scope"], "PREPARATION_BASELINE_ONLY")

    def test_v07_is_superseded_not_promoted(self):
        p = DS["predecessor"]
        self.assertEqual(p["github_state"], "closed")
        self.assertFalse(p["merged"])
        self.assertEqual(p["relationship"], "SUPERSEDED_BY_V0_8")
        self.assertEqual(p["authority_status"], "NOT_PROMOTED")

    def test_no_external_activation_is_implied(self):
        self.assertFalse(ACT["external_activation_executed"])
        self.assertFalse(DS["grafana_datasource_configured"])
        self.assertFalse(DS["supabase_mutation_executed"])
        self.assertFalse(DS["jit_activation_executed"])

if __name__ == "__main__":
    unittest.main()
