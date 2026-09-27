import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_authority_ratification_candidate.v0_3.json").read_text())
TARGETS = json.loads((ROOT / "governance" / "galia_grafana_authority_ratification_targets.v0_3.json").read_text())
HOLD = json.loads((ROOT / "receipts" / "grafana" / "galia_grafana_authority_hold_snapshot.v0_3.json").read_text())

class GrafanaAuthorityRatificationV03Tests(unittest.TestCase):
    def test_candidate_is_ready_for_human_promotion(self):
        self.assertEqual(MANIFEST["status"], "READY_FOR_HUMAN_PROMOTION")
        self.assertEqual(MANIFEST["promotion_scope"], "PREPARATION_BASELINE_AUTHORITY_RATIFICATION_ONLY")
        self.assertEqual(MANIFEST["promotion_gate"]["authority"], "HUMAN_PENDING")
        for key in ("identity","provenance","hash","source","date","scope","quality"):
            self.assertEqual(MANIFEST["promotion_gate"][key], "PASS")
        self.assertEqual(MANIFEST["promotion_gate"]["conflicts"], "REVIEWED")

    def test_live_execution_remains_blocked(self):
        live = MANIFEST["live_execution"]
        self.assertEqual(live["status"], "BLOCKED_EXTERNAL_FACTS")
        self.assertFalse(live["eligible_for_human_activation_authorization"])
        self.assertTrue(live["requires_separate_candidate"])
        self.assertTrue(live["requires_separate_human_decision"])

    def test_ratification_is_not_retroactive_rewrite(self):
        self.assertTrue(TARGETS["semantic_rules"]["ratification_is_new_authority_event"])
        self.assertFalse(TARGETS["semantic_rules"]["retroactive_eligibility_claim"])
        self.assertFalse(TARGETS["semantic_rules"]["github_merge_event_rewritten"])
        self.assertFalse(MANIFEST["promotion_effect_if_authorized"]["retroactive_eligibility_claim"])

    def test_exact_activation_target(self):
        a = TARGETS["activation"]
        self.assertEqual(a["candidate_id"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.6")
        self.assertEqual(a["github_pr"], 54)
        self.assertEqual(a["source_candidate_head"], "d0c71aaf76333a7f6b8542e2b48b01cfa0ad6654")
        self.assertEqual(a["source_candidate_set_sha256"], "1b0d25ca98a59182ade20d868f371655c7bd86d625d9c8dbd1961f896d5d73c2")
        self.assertEqual(a["github_merge_commit"], "dd717c61d50240251044040b61956768a3325d14")

    def test_exact_datasource_target(self):
        d = TARGETS["datasource"]
        self.assertEqual(d["candidate_id"], "GALIA-GRAFANA-DATASOURCE-CANDIDATE-v0.8")
        self.assertEqual(d["github_pr"], 55)
        self.assertEqual(d["source_candidate_head"], "b4cb4aee27b1a9479dd6b0ae79f84097e48e6bde")
        self.assertEqual(d["source_candidate_set_sha256"], "3b37c650c8b0302990cd62f6cb967bcbcdcaaa3cc97ad73f7a12637055e79e9d")
        self.assertEqual(d["github_merge_commit"], "a3b60d02e993a5d0b01e6ef40905f5ba0dfc4892")

    def test_hold_snapshot_requires_this_exact_candidate(self):
        self.assertTrue(HOLD["hold"]["active"])
        self.assertEqual(
            HOLD["hold_release_condition"],
            "EXPLICIT_HUMAN_PROMOTION_OF_GALIA-GRAFANA-AUTHORITY-RATIFICATION-CANDIDATE-v0.3",
        )

    def test_no_external_side_effects(self):
        external = HOLD["external_state"]
        self.assertTrue(all(value is False for value in external.values()))
        self.assertIn("NO_SUPABASE_MUTATION", MANIFEST["non_effects"])
        self.assertIn("NO_GRAFANA_MUTATION", MANIFEST["non_effects"])

if __name__ == "__main__":
    unittest.main()
