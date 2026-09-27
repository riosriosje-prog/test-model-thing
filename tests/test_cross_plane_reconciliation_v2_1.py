import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "integrations/cross_plane_reconciliation.v2_1.json").read_text())
SQL = (ROOT / "supabase/bindings/galia_cross_plane_reconciliation_v2_1.sql").read_text()
TOKEN = "__PROMOTED_MAIN_COMMIT__"


class CrossPlaneReconciliationV21Tests(unittest.TestCase):
    def test_candidate_identity(self):
        self.assertEqual(POLICY["candidate_id"], "GALIA-CROSS-PLANE-RECONCILIATION-v2.1")
        self.assertEqual(
            POLICY["reconciliation_id"],
            "GALIA-CROSS-PLANE-RECONCILIATION-2026-09-27-001",
        )

    def test_base_commit_exact(self):
        self.assertEqual(
            POLICY["base_commit"],
            "cf7a935c24729eba0b23dbf8c6f8cc61c43005be",
        )

    def test_merge_commit_is_template_bound(self):
        self.assertEqual(POLICY["promotion_binding"]["template_token"], TOKEN)
        self.assertTrue(POLICY["promotion_binding"]["promotion_receipt_must_bind_merge_commit"])
        self.assertGreaterEqual(SQL.count(TOKEN), 3)
        self.assertIn("!~ '^[0-9a-f]{40}$'", SQL)

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

    def test_edge_graph_is_preconditioned_and_not_mutated(self):
        self.assertEqual(POLICY["preconditions"]["edge_count"], 4)
        self.assertIn("if v_edges <> 4", SQL.lower())
        self.assertNotIn("insert into audit.cross_plane_binding_edges", SQL.lower())
        self.assertNotIn("update audit.cross_plane_binding_edges", SQL.lower())
        self.assertNotIn("delete from audit.cross_plane_binding_edges", SQL.lower())

    def test_no_schema_ddl(self):
        lower = SQL.lower()
        for statement in (
            "create table",
            "alter table",
            "drop table",
            "create schema",
            "drop schema",
            "create role",
            "alter role",
            "drop role",
        ):
            self.assertNotIn(statement, lower)

    def test_no_canonical_or_staging_dml(self):
        lower = SQL.lower()
        for prefix in (
            "insert into canonical.",
            "update canonical.",
            "delete from canonical.",
            "insert into staging.",
            "update staging.",
            "delete from staging.",
        ):
            self.assertNotIn(prefix, lower)

    def test_only_two_binding_updates(self):
        self.assertEqual(SQL.lower().count("update audit.cross_plane_bindings"), 2)
        self.assertIn("github-control-plane-main", SQL)
        self.assertIn("supabase-data-plane", SQL)

    def test_each_update_must_affect_exactly_one_row(self):
        self.assertEqual(SQL.lower().count("get diagnostics n = row_count"), 2)
        self.assertEqual(SQL.count("rows updated % != 1"), 2)

    def test_monitoring_surface_is_required(self):
        self.assertEqual(
            POLICY["preconditions"]["monitoring_surface_required"],
            "monitor.galia_overview_v1",
        )
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
        self.assertTrue(SQL.lstrip().startswith("-- GALIA cross-plane reconciliation v2.1"))
        self.assertIn("\nbegin;\n", SQL.lower())
        self.assertTrue(SQL.rstrip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
