import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "supabase/migrations/20260927150000_galia_monitoring_surface_v1.sql").read_text()
POLICY_PATH = ROOT / "governance/galia_monitoring_surface_candidate.v1.json"


class MonitoringSurfacePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads(POLICY_PATH.read_text())
        cls.lower = MIGRATION.lower()

    def test_candidate_identity_and_schema_versions(self):
        self.assertEqual(self.policy["candidate_id"], "GALIA-MONITORING-CANDIDATE-v1.6")
        self.assertEqual(self.policy["parent_schema_version"], "1.4.0")
        self.assertEqual(self.policy["target_schema_version"], "1.5.0")

    def test_exact_base_commit(self):
        self.assertEqual(
            self.policy["base_commit"],
            "13cde4ff516df154b0a12c33a799e0197505df6c",
        )

    def test_additive_non_destructive(self):
        self.assertTrue(self.policy["change_class"]["additive"])
        self.assertFalse(self.policy["change_class"]["destructive"])

    def test_no_canonical_dml(self):
        for verb in ("insert into canonical.", "update canonical.", "delete from canonical.", "truncate canonical."):
            self.assertNotIn(verb, self.lower)

    def test_monitor_roles_are_nologin_and_no_bypassrls(self):
        self.assertRegex(self.lower, r"create role galia_monitor_owner\s+nologin.*nobypassrls")
        self.assertRegex(self.lower, r"create role galia_monitor_ro\s+nologin.*nobypassrls")

    def test_monitor_schema_is_private(self):
        self.assertIn("create schema monitor authorization galia_monitor_owner", self.lower)
        self.assertIn("revoke all on schema monitor from public, anon, authenticated", self.lower)

    def test_default_privileges_fail_closed(self):
        self.assertIn("revoke all on tables from public", self.lower)
        self.assertIn("grant select on tables to galia_monitor_ro", self.lower)

    def test_reader_is_not_granted_base_schema_usage(self):
        self.assertNotIn("grant usage on schema audit, staging, canonical to galia_monitor_ro", self.lower)

    def test_owner_base_access_is_select_only(self):
        self.assertIn("grant select on", self.lower)
        for verb in ("grant insert", "grant update", "grant delete", "grant all on table"):
            self.assertNotIn(verb, self.lower)

    def test_eighteen_scoped_rls_select_policies(self):
        policies = re.findall(r"create policy galia_monitor_select_", self.lower)
        self.assertEqual(len(policies), 18)
        self.assertNotIn("for insert", self.lower)
        self.assertNotIn("for update", self.lower)
        self.assertNotIn("for delete", self.lower)

    def test_five_monitor_views_exist(self):
        expected = {
            "monitor.galia_overview_v1",
            "monitor.ingest_health_v1",
            "monitor.authority_chain_v1",
            "monitor.research_pipeline_v1",
            "monitor.control_plane_topology_v1",
        }
        found = set(re.findall(r"create view\s+(monitor\.[a-z0-9_]+)", self.lower))
        self.assertEqual(found, expected)

    def test_all_monitor_views_use_security_barrier(self):
        self.assertEqual(self.lower.count("with (security_barrier=true)"), 5)

    def test_ingest_counts_are_separate_lateral_aggregates(self):
        self.assertIn("select count(*)::bigint as candidate_count", self.lower)
        self.assertIn("select count(*)::bigint as seal_count", self.lower)
        self.assertNotIn("count(s.candidate_id)", self.lower)

    def test_integrity_checks_receipt_anchor_and_transition_chain(self):
        self.assertIn("ea.object_hash = cr.terminal_receipt_hash_v2", self.lower)
        self.assertIn("p.transition_hash_v2 = x.prev_transition_hash_v2", self.lower)
        self.assertIn("and chain.transition_chain_valid", self.lower)

    def test_overview_state_is_server_side_and_fail_closed(self):
        self.assertIn("when active_canonical_authority_count <> 1 then 'critical'", self.lower)
        self.assertIn("when closed_ingest_integrity_failures > 0 then 'critical'", self.lower)
        self.assertIn("when cross_plane_hold_count > 0 then 'hold'", self.lower)
        self.assertIn("when ready_candidates > 0 then 'awaiting_human_promotion'", self.lower)

    def test_global_hold_is_not_falsely_modeled(self):
        self.assertIn("'not_modeled'::text as global_authority_hold_state", self.lower)
        self.assertFalse(self.policy["hold_semantics"]["global_authority_hold_modeled"])

    def test_safe_delete_state_is_external(self):
        self.assertIn("'github_governance_required'::text as safe_delete_state_source", self.lower)
        self.assertEqual(self.policy["hold_semantics"]["safe_delete_source"], "GITHUB_GOVERNANCE")

    def test_no_automatic_promotion_surface(self):
        self.assertFalse(self.policy["authority_invariants"]["grafana_write_authority"])
        self.assertTrue(self.policy["authority_invariants"]["human_promotion_required"])
        self.assertNotIn("promotion_receipts values", self.lower)

    def test_schema_registry_metadata_is_explicit(self):
        self.assertIn("'canonical_data_mutation', false", self.lower)
        self.assertIn("'canonical_authorization_metadata_touched', true", self.lower)
        self.assertIn("'monitor_views_security_barrier', true", self.lower)


if __name__ == "__main__":
    unittest.main()
