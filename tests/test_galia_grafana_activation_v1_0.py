import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance/galia_grafana_activation_candidate.v1_0.json").read_text())
SQL = (ROOT / "supabase/bindings/galia_grafana_login_activation_v1_0.sql").read_text()

PROMOTED_TOKEN = "__PROMOTED_MAIN_COMMIT__"
HEAD_TOKEN = "__CANDIDATE_HEAD__"
SET_TOKEN = "__CANDIDATE_SET_SHA256__"
PASSWORD_TOKEN = "__GRAFANA_PASSWORD__"


class GaliaGrafanaActivationV10Tests(unittest.TestCase):
    def test_candidate_identity_and_base(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-ACTIVATION-CANDIDATE-v1.0")
        self.assertEqual(
            MANIFEST["base_commit"],
            "b072f20362ad753375f3f4291c7b8607fe451a12",
        )
        self.assertEqual(MANIFEST["target_schema_version"], "1.5.0")

    def test_predecessor_identity_is_exact(self):
        predecessor = MANIFEST["predecessor_identity"]
        self.assertEqual(predecessor["candidate_id"], "GALIA-GRAFANA-READER-CANDIDATE-v1.3")
        self.assertEqual(
            predecessor["promoted_main_commit"],
            "b072f20362ad753375f3f4291c7b8607fe451a12",
        )
        self.assertFalse(predecessor["required_login_state"])
        self.assertIn("predecessor identity receipt mismatch", SQL.lower())

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

    def test_promotion_tokens_are_required(self):
        self.assertIn("if '__PROMOTED_MAIN_COMMIT__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_HEAD__' !~ '^[0-9a-f]{40}$'", SQL)
        self.assertIn("if '__CANDIDATE_SET_SHA256__' !~ '^[0-9a-f]{64}$'", SQL)

    def test_runtime_password_contract_is_strict(self):
        secret = MANIFEST["secret_contract"]
        self.assertEqual(secret["source"], "RUNTIME_ONLY")
        self.assertEqual(secret["environment_variable"], "GALIA_GRAFANA_DB_PASSWORD")
        self.assertEqual(secret["allowed_pattern"], "^[A-Za-z0-9_-]{32,64}$")
        self.assertFalse(secret["plaintext_in_repository"])
        self.assertFalse(secret["plaintext_in_receipt"])
        self.assertFalse(secret["secret_derived_hash_in_receipt"])
        self.assertIn(
            "if '__GRAFANA_PASSWORD__' !~ '^[A-Za-z0-9_-]{32,64}$'",
            SQL,
        )

    def test_only_password_token_is_used_for_password_clause(self):
        self.assertIn("password '__grafana_password__';", SQL.lower())
        self.assertEqual(SQL.count(PASSWORD_TOKEN), 3)

    def test_receipt_contains_no_password_token_or_secret_hash(self):
        receipt = SQL[SQL.index("insert into audit.human_decisions"):]
        self.assertNotIn(PASSWORD_TOKEN, receipt)
        self.assertIn("'secret_material_persisted',false", receipt)
        self.assertIn("'secret_derived_hash_persisted',false", receipt)

    def test_activation_only_changes_login_and_password_on_role(self):
        lower = SQL.lower()
        activation = re.search(
            r"alter role galia_grafana_ro\s+login\s+password '__grafana_password__';",
            lower,
        )
        self.assertIsNotNone(activation)
        self.assertNotIn("alter role galia_grafana_ro superuser", lower)
        self.assertNotIn("alter role galia_grafana_ro createdb", lower)
        self.assertNotIn("alter role galia_grafana_ro createrole", lower)
        self.assertNotIn("alter role galia_grafana_ro bypassrls", lower)

    def test_role_contract_is_checked_before_and_after(self):
        lower = SQL.lower()
        self.assertIn("pre-activation role contract mismatch", lower)
        self.assertIn("post-activation role contract mismatch", lower)
        self.assertIn("rolconnlimit <> 5", lower)

    def test_memberships_are_preserved(self):
        lower = SQL.lower()
        self.assertIn("platform admin membership contract mismatch", lower)
        self.assertIn("monitor inheritance membership contract mismatch", lower)
        self.assertIn("post-activation membership count mismatch", lower)
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
        self.assertIn("post-activation role settings mismatch", lower)

    def test_monitor_read_and_source_denial_are_preserved(self):
        lower = SQL.lower()
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

    def test_control_plane_binding_refreshes_exactly_once(self):
        lower = SQL.lower()
        self.assertEqual(lower.count("update audit.cross_plane_bindings"), 1)
        self.assertIn("binding_key='github-control-plane-main'", lower)
        self.assertIn(
            "revision='b072f20362ad753375f3f4291c7b8607fe451a12'",
            lower,
        )
        self.assertIn("revision='__promoted_main_commit__'", lower)

    def test_supabase_binding_remains_schema_150(self):
        lower = SQL.lower()
        self.assertIn("binding_key='supabase-data-plane'", lower)
        self.assertIn("revision='schema:1.5.0'", lower)
        self.assertNotIn("update audit.schema_versions", lower)
        self.assertNotIn("insert into audit.schema_versions", lower)

    def test_no_research_data_dml_or_edge_mutation(self):
        lower = SQL.lower()
        for prefix in (
            "insert into canonical.",
            "update canonical.",
            "delete from canonical.",
            "insert into staging.",
            "update staging.",
            "delete from staging.",
            "insert into audit.cross_plane_binding_edges",
            "update audit.cross_plane_binding_edges",
            "delete from audit.cross_plane_binding_edges",
        ):
            self.assertNotIn(prefix, lower)

    def test_receipt_binds_exact_candidate_identity(self):
        self.assertIn("'EXTERNAL_SERVICE_CREDENTIAL_ACTIVATION'", SQL)
        self.assertIn("'GALIA-GRAFANA-LOGIN-ACTIVATION-2026-09-27-001'", SQL)
        self.assertIn("'candidate_head','__CANDIDATE_HEAD__'", SQL)
        self.assertIn("'candidate_set_sha256','__CANDIDATE_SET_SHA256__'", SQL)
        self.assertIn("'promoted_main_commit','__PROMOTED_MAIN_COMMIT__'", SQL)
        self.assertIn("'login_enabled',true", SQL)
        self.assertIn("'grafana_datasource_configured',false", SQL)

    def test_renderer_executes_without_disclosing_secret(self):
        path = ROOT / "tools/render_galia_grafana_activation_v1_0.py"
        spec = importlib.util.spec_from_file_location("grafana_activation_renderer", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        actual_set = module.candidate_set_sha256(ROOT)
        self.assertRegex(actual_set, r"^[0-9a-f]{64}$")

        dummy = "A" * 40
        rendered, returned_set = module.render_sql(
            "a" * 40,
            "b" * 40,
            actual_set,
            dummy,
            ROOT,
        )
        self.assertEqual(returned_set, actual_set)
        for token in (PROMOTED_TOKEN, HEAD_TOKEN, SET_TOKEN, PASSWORD_TOKEN):
            self.assertNotIn(token, rendered)
        self.assertIn("password '" + dummy + "'", rendered)
        receipt = rendered[rendered.index("insert into audit.human_decisions"):]
        self.assertNotIn(dummy, receipt)

    def test_renderer_rejects_unsafe_password(self):
        path = ROOT / "tools/render_galia_grafana_activation_v1_0.py"
        spec = importlib.util.spec_from_file_location("grafana_activation_renderer_bad", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        actual_set = module.candidate_set_sha256(ROOT)
        with self.assertRaises(SystemExit):
            module.render_sql(
                "a" * 40,
                "b" * 40,
                actual_set,
                "bad password with spaces",
                ROOT,
            )

    def test_grafana_datasource_is_explicitly_out_of_scope(self):
        connection = MANIFEST["grafana_connection"]
        self.assertFalse(connection["configured_by_this_candidate"])
        self.assertEqual(connection["port"], 5432)
        self.assertTrue(connection["tls_required"])

    def test_transaction_is_explicit(self):
        self.assertIn("\nbegin;\n", SQL.lower())
        self.assertTrue(SQL.rstrip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
