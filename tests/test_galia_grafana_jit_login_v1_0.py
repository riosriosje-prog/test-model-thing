import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance/galia_grafana_jit_login_candidate.v1_0.json").read_text())
SQL = (ROOT / "supabase/bindings/galia_grafana_jit_login_prep_v1_0.sql").read_text()

PROMOTED_TOKEN = "__PROMOTED_MAIN_COMMIT__"
HEAD_TOKEN = "__CANDIDATE_HEAD__"
SET_TOKEN = "__CANDIDATE_SET_SHA256__"


class GaliaGrafanaJitLoginV10Tests(unittest.TestCase):
    def test_candidate_identity_and_base(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-JIT-LOGIN-CANDIDATE-v1.0")
        self.assertEqual(
            MANIFEST["base_commit"],
            "da889048edb339b8e9995a7c27edafb53e0221ee",
        )
        self.assertEqual(MANIFEST["target_schema_version"], "1.5.0")

    def test_postgres_version_gate_is_documented(self):
        project = MANIFEST["project"]
        self.assertEqual(project["postgres_version"], "17.6.1.166")
        self.assertEqual(
            project["temporary_access_minimum_postgres_version"],
            "17.6.1.081",
        )

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

    def test_login_only_no_password_clause(self):
        lower = SQL.lower()
        self.assertIn("alter role galia_grafana_ro login;", lower)
        self.assertNotRegex(lower, r"alter role galia_grafana_ro[\s\S]*?\bpassword\b")
        self.assertFalse(MANIFEST["database_change"]["password_clause_allowed"])

    def test_password_remains_null_before_and_after(self):
        lower = SQL.lower()
        self.assertGreaterEqual(lower.count("rolpassword is null"), 2)
        self.assertIn("pre-jit persistent password is present", lower)
        self.assertIn("post-jit persistent password is present", lower)
        self.assertIsNone(MANIFEST["database_change"]["password_before"])
        self.assertIsNone(MANIFEST["database_change"]["password_after"])

    def test_role_attributes_are_preserved(self):
        lower = SQL.lower()
        self.assertIn("pre-jit role contract mismatch", lower)
        self.assertIn("post-jit role contract mismatch", lower)
        self.assertIn("rolconnlimit <> 5", lower)
        for forbidden in (
            "alter role galia_grafana_ro superuser",
            "alter role galia_grafana_ro createdb",
            "alter role galia_grafana_ro createrole",
            "alter role galia_grafana_ro bypassrls",
        ):
            self.assertNotIn(forbidden, lower)

    def test_membership_surface_is_preserved(self):
        lower = SQL.lower()
        self.assertIn("unexpected grafana membership count", lower)
        self.assertIn("post-jit membership count mismatch", lower)
        self.assertIn("platform admin membership contract mismatch", lower)
        self.assertIn("monitor inheritance membership contract mismatch", lower)
        self.assertNotIn("grant galia_monitor_ro to galia_grafana_ro", lower)
        self.assertNotIn("revoke galia_monitor_ro from galia_grafana_ro", lower)

    def test_role_settings_are_preserved(self):
        lower = SQL.lower()
        for setting in (
            "default_transaction_read_only=on",
            "idle_in_transaction_session_timeout=30s",
            "lock_timeout=5s",
            "search_path=monitor, pg_catalog",
            "statement_timeout=30s",
        ):
            self.assertIn(setting, lower)
        self.assertIn("post-jit role settings mismatch", lower)

    def test_monitor_surface_and_source_denial_are_preserved(self):
        lower = SQL.lower()
        self.assertIn("v_monitor_views <> 5 or v_security_barrier_views <> 5", lower)
        for view in (
            "monitor.galia_overview_v1",
            "monitor.ingest_health_v1",
            "monitor.authority_chain_v1",
            "monitor.research_pipeline_v1",
            "monitor.control_plane_topology_v1",
        ):
            self.assertIn(view, lower)
        for schema in ("audit", "staging", "canonical"):
            self.assertIn(
                f"has_schema_privilege('galia_grafana_ro','{schema}','usage')",
                lower,
            )

    def test_human_receipt_is_preparation_not_activation(self):
        receipt = MANIFEST["receipt_semantics"]
        self.assertEqual(
            receipt["object_type"],
            "EXTERNAL_SERVICE_JIT_LOGIN_PREPARATION",
        )
        self.assertFalse(receipt["activation_complete"])
        self.assertFalse(receipt["grafana_datasource_configured"])
        self.assertFalse(receipt["password_persisted"])
        self.assertFalse(receipt["jit_mapping_configured"])
        self.assertIn("'activation_complete',false", SQL)
        self.assertIn("'jit_mapping_configured',false", SQL)

    def test_temporary_access_management_api_plan_is_explicit(self):
        plan = MANIFEST["temporary_access_plan"]
        self.assertFalse(plan["configured_by_this_candidate"])
        self.assertTrue(plan["required_for_service_activation"])
        self.assertEqual(
            plan["global_state_endpoint"],
            "GET/PUT /v1/projects/{ref}/database/jit-access",
        )
        self.assertEqual(
            plan["user_mapping_endpoint"],
            "PUT /v1/projects/{ref}/database/jit",
        )
        self.assertEqual(plan["mapped_postgres_role"], "galia_grafana_ro")
        self.assertEqual(plan["mapping_state_after_candidate"], "REQUIRED_EXTERNAL")
        self.assertFalse(plan["token_material_in_repository"])
        self.assertFalse(plan["token_material_in_receipt"])

    def test_jit_true_is_canonical_and_on_is_quarantined(self):
        connection = MANIFEST["temporary_access_plan"]["connection"]
        discrepancy = MANIFEST["documentation_discrepancy"]
        self.assertEqual(connection["jit_option"], "true")
        self.assertEqual(connection["jit_option_quarantined"], "on")
        self.assertEqual(discrepancy["published_documentation_example"], "jit=on")
        self.assertEqual(discrepancy["implementation_evidence"], "jit=true")

    def test_pooler_contract_is_explicit(self):
        connection = MANIFEST["temporary_access_plan"]["connection"]
        self.assertEqual(connection["mode"], "SHARED_POOLER_SESSION")
        self.assertEqual(connection["port"], 5432)
        self.assertEqual(
            connection["username_template"],
            "galia_grafana_ro.nzoviwitcqmsacwiizhh",
        )
        self.assertEqual(
            connection["host_source"],
            "Supabase Dashboard Connect -> Session pooler",
        )
        self.assertEqual(connection["tls_minimum"], "require")

    def test_control_plane_self_refreshes_exactly_once(self):
        lower = SQL.lower()
        self.assertEqual(lower.count("update audit.cross_plane_bindings"), 1)
        self.assertIn("binding_key='github-control-plane-main'", lower)
        self.assertIn(
            "revision='da889048edb339b8e9995a7c27edafb53e0221ee'",
            lower,
        )
        self.assertIn("revision='__promoted_main_commit__'", lower)
        self.assertIn("'credential_activation_state', 'jit_mapping_required'", lower)
        self.assertIn("'credential_mode', 'temporary_access_jit'", lower)

    def test_supabase_binding_and_graph_are_preserved(self):
        lower = SQL.lower()
        self.assertIn("binding_key='supabase-data-plane'", lower)
        self.assertIn("revision='schema:1.5.0'", lower)
        self.assertIn("v_authorities <> 1 or v_source_truth <> 1 or v_edges <> 4", lower)
        self.assertNotIn("insert into audit.cross_plane_binding_edges", lower)
        self.assertNotIn("update audit.cross_plane_binding_edges", lower)
        self.assertNotIn("delete from audit.cross_plane_binding_edges", lower)

    def test_no_schema_version_or_research_data_mutation(self):
        lower = SQL.lower()
        self.assertNotIn("insert into audit.schema_versions", lower)
        for prefix in (
            "insert into canonical.",
            "update canonical.",
            "delete from canonical.",
            "insert into staging.",
            "update staging.",
            "delete from staging.",
        ):
            self.assertNotIn(prefix, lower)

    def test_receipt_binds_exact_promotion_identity(self):
        self.assertIn("'EXTERNAL_SERVICE_JIT_LOGIN_PREPARATION'", SQL)
        self.assertIn("'GALIA-GRAFANA-JIT-LOGIN-PREP-2026-09-27-001'", SQL)
        self.assertIn("'candidate_head','__CANDIDATE_HEAD__'", SQL)
        self.assertIn("'candidate_set_sha256','__CANDIDATE_SET_SHA256__'", SQL)
        self.assertIn("'promoted_main_commit','__PROMOTED_MAIN_COMMIT__'", SQL)

    def test_renderer_executes_and_resolves_tokens(self):
        path = ROOT / "tools/render_galia_grafana_jit_login_v1_0.py"
        spec = importlib.util.spec_from_file_location("grafana_jit_login_renderer", path)
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
        for token in (PROMOTED_TOKEN, HEAD_TOKEN, SET_TOKEN):
            self.assertNotIn(token, rendered)
        self.assertIn("'candidate_head','" + ("b" * 40) + "'", rendered)
        self.assertIn("'candidate_set_sha256','" + actual_set + "'", rendered)

    def test_transaction_is_explicit(self):
        self.assertIn("\nbegin;\n", SQL.lower())
        self.assertTrue(SQL.rstrip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
