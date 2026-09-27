import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "integrations/cross_plane_reconciliation.v2_3.json").read_text())
SQL = (ROOT / "supabase/bindings/galia_cross_plane_reconciliation_v2_3.sql").read_text()

PROMOTED_TOKEN = "__PROMOTED_MAIN_COMMIT__"
HEAD_TOKEN = "__CANDIDATE_HEAD__"
SET_TOKEN = "__CANDIDATE_SET_SHA256__"


class CrossPlaneReconciliationV23Tests(unittest.TestCase):
    def test_candidate_identity(self):
        self.assertEqual(POLICY["candidate_id"], "GALIA-CROSS-PLANE-RECONCILIATION-v2.3")
        self.assertEqual(POLICY["pr_number"], 43)

    def test_base_commit_exact(self):
        self.assertEqual(POLICY["base_commit"], "cf7a935c24729eba0b23dbf8c6f8cc61c43005be")

    def test_all_identity_tokens_are_required(self):
        binding = POLICY["promotion_binding"]
        self.assertEqual(binding["promoted_main_commit_token"], PROMOTED_TOKEN)
        self.assertEqual(binding["candidate_head_token"], HEAD_TOKEN)
        self.assertEqual(binding["candidate_set_sha256_token"], SET_TOKEN)
        self.assertTrue(binding["promotion_receipt_must_bind_merge_commit"])
        self.assertTrue(binding["promotion_receipt_must_bind_candidate_head"])
        self.assertTrue(binding["promotion_receipt_must_bind_candidate_set_sha256"])

    def test_token_shapes_fail_closed(self):
        self.assertIn("if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_HEAD__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_SET_SHA256__' !~ '^[0-9a-f]{64}$'", SQL)

    def test_receipt_binds_exact_candidate_identity(self):
        self.assertIn("'candidate_pr_number', 43", SQL)
        self.assertIn("'candidate_base_commit', 'cf7a935c24729eba0b23dbf8c6f8cc61c43005be'", SQL)
        self.assertIn("'candidate_head', '__CANDIDATE_HEAD__'", SQL)
        self.assertIn("'candidate_set_sha256', '__CANDIDATE_SET_SHA256__'", SQL)
        self.assertIn("'github_promoted_main_commit', '__PROMOTED_MAIN_COMMIT__'", SQL)

    def test_live_schema_precondition_is_150(self):
        self.assertEqual(POLICY["preconditions"]["live_schema_version"], "1.5.0")
        self.assertIn("v_latest_schema <> '1.5.0'", SQL)

    def test_old_github_binding_is_exact_precondition(self):
        old = "25db17fa583d1561d746ee7d33407d3684ee561d"
        self.assertEqual(POLICY["preconditions"]["github_recorded_revision"], old)
        self.assertIn("and revision = '" + old + "'", SQL)

    def test_old_supabase_binding_is_exact_precondition(self):
        self.assertEqual(POLICY["preconditions"]["supabase_recorded_revision"], "schema:1.4.0")
        self.assertIn("and revision = 'schema:1.4.0'", SQL)

    def test_supabase_target_is_150(self):
        target = POLICY["target_bindings"]["supabase_data_plane"]
        self.assertEqual(target["revision"], "schema:1.5.0")
        self.assertFalse(target["canonical_authority"])
        self.assertFalse(target["source_of_truth"])

    def test_github_remains_canonical_authority(self):
        target = POLICY["target_bindings"]["github_control_plane"]
        self.assertTrue(target["canonical_authority"])
        self.assertTrue(target["source_of_truth"])
        self.assertEqual(POLICY["authority_invariants"]["canonical_authority_provider"], "GITHUB")
        self.assertFalse(POLICY["authority_invariants"]["canonical_authority_transferred"])

    def test_hf_bindings_are_preserved(self):
        self.assertEqual(POLICY["preserved_bindings"]["hf8"]["object_ref"], "Junitos/galia-2")
        self.assertEqual(POLICY["preserved_bindings"]["hf9"]["object_ref"], "Junitos/galia-2-evidence")
        self.assertIn("FAIL_CLOSED HF8 binding drift", SQL)
        self.assertIn("FAIL_CLOSED HF9 binding drift", SQL)

    def test_edge_graph_is_not_mutated(self):
        self.assertNotIn("insert into audit.cross_plane_binding_edges", SQL.lower())
        self.assertNotIn("update audit.cross_plane_binding_edges", SQL.lower())
        self.assertNotIn("delete from audit.cross_plane_binding_edges", SQL.lower())

    def test_no_schema_ddl(self):
        lower = SQL.lower()
        for statement in ("create table","alter table","drop table","create schema","drop schema","create role","alter role","drop role"):
            self.assertNotIn(statement, lower)

    def test_no_canonical_or_staging_dml(self):
        lower = SQL.lower()
        for prefix in ("insert into canonical.","update canonical.","delete from canonical.","insert into staging.","update staging.","delete from staging."):
            self.assertNotIn(prefix, lower)

    def test_only_two_binding_updates(self):
        self.assertEqual(SQL.lower().count("update audit.cross_plane_bindings"), 2)

    def test_each_update_must_affect_exactly_one_row(self):
        self.assertEqual(SQL.lower().count("get diagnostics n = row_count"), 2)
        self.assertEqual(SQL.count("rows updated % != 1"), 2)

    def test_monitoring_surface_is_required(self):
        self.assertIn("table_name = 'galia_overview_v1'", SQL)

    def test_human_decision_is_persisted(self):
        self.assertIn("'CROSS_PLANE_RECONCILIATION'", SQL)
        self.assertIn("'PROMOTE'", SQL)
        self.assertIn("'human:user'", SQL)

    def test_receipt_states_non_effects(self):
        lower = SQL.lower()
        self.assertIn("'authority_transfer', false", lower)
        self.assertIn("'hf_bindings_changed', false", lower)
        self.assertIn("'edge_graph_changed', false", lower)
        self.assertIn("'schema_ddl', false", lower)

    def test_transaction_is_explicit(self):
        self.assertIn("\nbegin;\n", SQL.lower())
        self.assertTrue(SQL.rstrip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
