import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance/galia_grafana_reader_candidate.v1_3.json").read_text())
SQL = (ROOT / "supabase/bindings/galia_grafana_reader_identity_v1_3.sql").read_text()

PROMOTED_TOKEN = "__PROMOTED_MAIN_COMMIT__"
HEAD_TOKEN = "__CANDIDATE_HEAD__"
SET_TOKEN = "__CANDIDATE_SET_SHA256__"


class GaliaGrafanaReaderV13Tests(unittest.TestCase):
    def test_candidate_identity_and_base(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-READER-CANDIDATE-v1.3")
        self.assertEqual(
            MANIFEST["base_commit"],
            "1f82fe94deb9778194c9166e1ee063f6eab52657",
        )
        self.assertEqual(MANIFEST["target_schema_version"], "1.5.0")

    def test_candidate_set_contract(self):
        contract = MANIFEST["candidate_set_hash_contract"]
        self.assertEqual(contract["algorithm"], "SHA-256")
        self.assertEqual(contract["encoding"], "UTF-8")
        self.assertEqual(
            contract["serialization"],
            "sorted path + NUL + file_sha256 + newline",
        )
        self.assertEqual(len(contract["included_paths"]), 4)
        self.assertFalse(contract["self_hash_embedded"])
        self.assertTrue(contract["expected_hash_supplied_at_promotion"])

    def test_identity_tokens_are_required(self):
        binding = MANIFEST["promotion_binding"]
        self.assertEqual(binding["promoted_main_commit_token"], PROMOTED_TOKEN)
        self.assertEqual(binding["candidate_head_token"], HEAD_TOKEN)
        self.assertEqual(binding["candidate_set_sha256_token"], SET_TOKEN)
        self.assertIn("if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_HEAD__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_SET_SHA256__' !~ '^[0-9a-f]{64}$'", SQL)

    def test_role_is_created_nologin_and_least_privilege(self):
        lower = SQL.lower()
        self.assertRegex(
            lower,
            r"create role galia_grafana_ro\s+nologin\s+inherit\s+nosuperuser\s+nocreatedb\s+nocreaterole\s+nobypassrls\s+connection limit 5",
        )
        self.assertNotRegex(lower, r"alter role galia_grafana_ro\s+login")
        self.assertNotRegex(lower, r"\bpassword\b")

    def test_membership_inherits_but_cannot_set_parent_role(self):
        self.assertIn(
            "grant galia_monitor_ro to galia_grafana_ro\n  with inherit true, set false;",
            SQL.lower(),
        )
        self.assertIn("not v_membership.inherit_option or v_membership.set_option", SQL)

    def test_role_session_limits_are_explicit(self):
        lower = SQL.lower()
        self.assertIn("set search_path = monitor, pg_catalog", lower)
        self.assertIn("set statement_timeout = '30s'", lower)
        self.assertIn("set lock_timeout = '5s'", lower)
        self.assertIn("set idle_in_transaction_session_timeout = '30s'", lower)
        self.assertIn("set default_transaction_read_only = on", lower)

    def test_monitor_surface_contract_is_fail_closed(self):
        self.assertEqual(MANIFEST["monitor_contract"]["expected_view_count"], 5)
        self.assertTrue(MANIFEST["monitor_contract"]["security_barrier_required"])
        self.assertIn("v_monitor_views <> 5 or v_security_barrier_views <> 5", SQL)
        for view in (
            "monitor.galia_overview_v1",
            "monitor.ingest_health_v1",
            "monitor.authority_chain_v1",
            "monitor.research_pipeline_v1",
            "monitor.control_plane_topology_v1",
        ):
            self.assertIn(view, SQL)

    def test_no_source_plane_direct_access(self):
        lower = SQL.lower()
        for schema in ("audit", "staging", "canonical"):
            self.assertIn(
                f"has_schema_privilege('galia_grafana_ro','{schema}','usage')",
                lower,
            )
        self.assertIn(
            "has_table_privilege('galia_grafana_ro','audit.schema_versions','select')",
            lower,
        )
        self.assertIn(
            "has_table_privilege('galia_grafana_ro','staging.ingest_batches','select')",
            lower,
        )
        self.assertIn(
            "has_table_privilege('galia_grafana_ro','canonical.sources','select')",
            lower,
        )

    def test_public_schema_leakage_is_blocked(self):
        lower = SQL.lower()
        for schema in ("monitor", "audit", "staging", "canonical"):
            self.assertIn(
                f"has_schema_privilege('public','{schema}','usage')",
                lower,
            )

    def test_control_plane_self_refreshes_exactly_once(self):
        lower = SQL.lower()
        self.assertEqual(lower.count("update audit.cross_plane_bindings"), 1)
        self.assertIn("binding_key='github-control-plane-main'", lower)
        self.assertIn(
            "revision='1f82fe94deb9778194c9166e1ee063f6eab52657'",
            lower,
        )
        self.assertIn("revision='__promoted_main_commit__'", lower)
        self.assertNotIn("binding_key='supabase-data-plane'\n    and revision='__promoted_main_commit__'", lower)

    def test_supabase_binding_is_precondition_only(self):
        lower = SQL.lower()
        self.assertIn("binding_key='supabase-data-plane'", lower)
        self.assertIn("revision='schema:1.5.0'", lower)
        self.assertEqual(
            lower.count("update audit.cross_plane_bindings"),
            1,
        )

    def test_authority_and_edge_invariants_are_preserved(self):
        lower = SQL.lower()
        self.assertIn("v_authorities <> 1 or v_source_truth <> 1 or v_edges <> 4", lower)
        self.assertNotIn("insert into audit.cross_plane_binding_edges", lower)
        self.assertNotIn("update audit.cross_plane_binding_edges", lower)
        self.assertNotIn("delete from audit.cross_plane_binding_edges", lower)

    def test_no_research_data_dml(self):
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

    def test_no_schema_version_bump(self):
        lower = SQL.lower()
        self.assertNotIn("insert into audit.schema_versions", lower)
        self.assertEqual(MANIFEST["target_schema_version"], "1.5.0")

    def test_human_decision_binds_exact_promotion_identity(self):
        self.assertIn("'EXTERNAL_SERVICE_IDENTITY'", SQL)
        self.assertIn("'GALIA-GRAFANA-READER-IDENTITY-2026-09-27-001'", SQL)
        self.assertIn("'candidate_head','__CANDIDATE_HEAD__'", SQL)
        self.assertIn("'candidate_set_sha256','__CANDIDATE_SET_SHA256__'", SQL)
        self.assertIn("'promoted_main_commit','__PROMOTED_MAIN_COMMIT__'", SQL)
        self.assertIn("'login_enabled',false", SQL)
        self.assertIn("'secret_material_persisted',false", SQL)

    def test_external_activation_is_separate(self):
        activation = MANIFEST["external_activation"]
        self.assertTrue(activation["activation_separate"])
        self.assertFalse(activation["secret_material_in_candidate"])
        self.assertFalse(activation["login_activation_in_candidate"])
        self.assertEqual(activation["port"], 5432)
        self.assertTrue(activation["tls_required"])

    def test_renderer_executes_and_resolves_tokens(self):
        path = ROOT / "tools/render_galia_grafana_reader_v1_3.py"
        spec = importlib.util.spec_from_file_location("grafana_reader_renderer", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        actual_set = module.candidate_set_sha256(ROOT)
        self.assertRegex(actual_set, r"^[0-9a-f]{64}$")

        rendered, returned_set = module.render_sql(
            "a" * 40,
            "b" * 40,
            actual_set,
            ROOT,
        )
        self.assertEqual(returned_set, actual_set)
        self.assertNotIn(PROMOTED_TOKEN, rendered)
        self.assertNotIn(HEAD_TOKEN, rendered)
        self.assertNotIn(SET_TOKEN, rendered)
        self.assertIn("'candidate_head','" + ("b" * 40) + "'", rendered)
        self.assertIn("'candidate_set_sha256','" + actual_set + "'", rendered)

    def test_membership_surface_is_exactly_two_rows(self):
        identity = MANIFEST["database_identity"]
        self.assertEqual(identity["membership_count_expected"], 2)
        self.assertEqual(len(identity["expected_memberships"]), 2)
        lower = SQL.lower()
        self.assertIn("unexpected grafana role membership count", lower)
        self.assertIn("platform admin membership contract mismatch", lower)
        self.assertIn("monitor inheritance membership contract mismatch", lower)
        self.assertIn("grantor.rolname='supabase_admin'", lower)
        self.assertIn("member.rolname='postgres'", lower)

    def test_transaction_is_explicit(self):
        self.assertIn("\nbegin;\n", SQL.lower())
        self.assertTrue(SQL.rstrip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
