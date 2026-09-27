import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "governance" / "galia_grafana_datasource_candidate.v0_4.json"
YAML_PATH = ROOT / "grafana" / "provisioning" / "datasources" / "galia_cangrejos_postgres.v0_4.yaml"
VALIDATOR_PATH = ROOT / "tools" / "validate_galia_grafana_datasource_v0_4.py"
ACCEPTANCE_PATH = ROOT / "grafana" / "acceptance" / "galia_cangrejos_postgres_acceptance.v0_4.sql"
RUNTIME_PATH = ROOT / "tools" / "run_galia_grafana_runtime_acceptance_v0_4.sh"

MANIFEST = json.loads(MANIFEST_PATH.read_text())
YAML = YAML_PATH.read_text()
VALIDATOR = VALIDATOR_PATH.read_text()
ACCEPTANCE = ACCEPTANCE_PATH.read_text()
RUNTIME = RUNTIME_PATH.read_text()


class GaliaGrafanaDatasourceV04Tests(unittest.TestCase):
    def test_candidate_is_preparation_only(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-DATASOURCE-CANDIDATE-v0.4")
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertTrue(MANIFEST["predecessor"]["must_be_promoted_first"])
        self.assertTrue(MANIFEST["predecessor"]["must_rebase_onto_exact_promoted_main_before_promotion"])

    def test_predecessor_identity_is_exact(self):
        p = MANIFEST["predecessor"]
        self.assertEqual(p["candidate_id"], "GALIA-GRAFANA-JIT-LOGIN-CANDIDATE-v1.4")
        self.assertEqual(p["candidate_head"], "14c538d18400da493ab1c354505bd5d75f67c3f3")
        self.assertEqual(
            p["candidate_set_sha256"],
            "9f3b7172a8b31debafec30aec1c8be2ff37e2e100398a8b27803a7d57291b6c9",
        )

    def test_no_literal_pat_or_classic_fallback(self):
        combined = MANIFEST_PATH.read_text() + YAML + VALIDATOR
        self.assertIsNone(re.search(r"sbp_[A-Za-z0-9_-]{8,}", combined))
        c = MANIFEST["credential_contract"]
        self.assertEqual(c["source"], "ENVIRONMENT_ONLY")
        self.assertFalse(c["classic_pat_automatic_fallback"])
        self.assertEqual(c["classic_pat_fallback_state"], "HOLD")
        self.assertEqual(c["scoped_pat_expected_prefix"], "sbp_fc")

    def test_scoped_pat_validator_rejects_classic_shape(self):
        self.assertIn('startswith("sbp_fc")', VALIDATOR)
        self.assertNotIn('startswith("sbp_")', VALIDATOR)

    def test_pdc_contract_matches_postgres_plugin_surface(self):
        pdc = MANIFEST["datasource"]["pdc_support_contract"]
        self.assertEqual(pdc["json_data_key"], "enableSecureSocksProxy")
        self.assertEqual(pdc["postgres_plugin_type"], "boolean")
        self.assertIn("NewSecureSocksProxyContextDialer", pdc["backend_behavior"])
        self.assertTrue(pdc["hostname_preservation"])

    def test_provisioning_uses_environment_variables(self):
        required = [
            "$__env{GALIA_GRAFANA_DB_HOST}",
            "$__env{GALIA_GRAFANA_DB_PORT}",
            "$__env{GALIA_GRAFANA_DB_USER}",
            "$__env{GALIA_GRAFANA_DB_NAME}",
            "$__env{GALIA_GRAFANA_SCOPED_PAT}",
            "$__env{GALIA_GRAFANA_PDC_ENABLED}",
        ]
        for item in required:
            self.assertIn(item, YAML)

    def test_postgres_17_is_explicit(self):
        self.assertEqual(MANIFEST["datasource"]["postgres_version"], 1700)
        self.assertIn("postgresVersion: 1700", YAML)

    def test_provisioning_version_is_monotonic_contract(self):
        ds = MANIFEST["datasource"]
        self.assertEqual(ds["provisioning_version"], 1)
        self.assertEqual(
            ds["provisioning_version_policy"],
            "MONOTONIC_INCREMENT_ON_EACH_PROMOTED_DATASOURCE_CHANGE",
        )
        self.assertIn("version: 1", YAML)

    def test_runtime_probe_shell_syntax(self):
        subprocess.run(["bash", "-n", str(RUNTIME_PATH)], check=True)

    def test_runtime_acceptance_is_fail_closed_and_secret_safe(self):
        self.assertIn("current_user = 'galia_grafana_ro'", ACCEPTANCE)
        for view in MANIFEST["acceptance_contract"]["must_select_monitor_views"]:
            self.assertIn(view, ACCEPTANCE)
        self.assertIn("canonical.sources", RUNTIME)
        self.assertIn("__galia_grafana_write_probe", RUNTIME)
        self.assertIn("rollback", RUNTIME.lower())
        self.assertIn('PGPASSWORD="$GALIA_GRAFANA_SCOPED_PAT"', RUNTIME)
        self.assertNotIn("echo \"$GALIA_GRAFANA_SCOPED_PAT", RUNTIME)
        self.assertNotIn("printf \"$GALIA_GRAFANA_SCOPED_PAT", RUNTIME)

    def test_direct_jit_contract(self):
        self.assertNotIn("pooler.supabase.com", YAML)
        self.assertNotIn("jit=on", YAML)
        self.assertNotIn("jit=true", YAML)
        self.assertIn("sslmode: require", YAML)
        self.assertIn("maxOpenConns: 2", YAML)
        self.assertIn("maxIdleConns: 1", YAML)
        self.assertIn("editable: false", YAML)

    def test_network_profiles_fail_closed(self):
        profiles = MANIFEST["network_profiles"]
        self.assertTrue(profiles["SELF_HOSTED_IPV6"]["supported"])
        self.assertTrue(profiles["GRAFANA_CLOUD_PDC_IPV6"]["supported"])
        self.assertFalse(profiles["GRAFANA_CLOUD_DIRECT_IPV6"]["supported"])
        self.assertEqual(
            profiles["GRAFANA_CLOUD_PDC_IPV6"]["permit_remote_open"],
            "db.nzoviwitcqmsacwiizhh.supabase.co:5432",
        )

    def test_acceptance_contract_exact(self):
        expected = {
            "monitor.galia_overview_v1",
            "monitor.ingest_health_v1",
            "monitor.authority_chain_v1",
            "monitor.research_pipeline_v1",
            "monitor.control_plane_topology_v1",
        }
        self.assertEqual(set(MANIFEST["acceptance_contract"]["must_select_monitor_views"]), expected)
        self.assertEqual(
            set(MANIFEST["acceptance_contract"]["must_fail_schema_usage"]),
            {"audit", "staging", "canonical", "derived"},
        )
        self.assertTrue(MANIFEST["acceptance_contract"]["must_fail_writes"])
        self.assertEqual(MANIFEST["acceptance_contract"]["public_selectable_relations"], 0)

    def test_validator_never_prints_secret(self):
        self.assertIn("GALIA_GRAFANA_SCOPED_PAT", VALIDATOR)
        self.assertNotIn("print(secret", VALIDATOR.lower())
        self.assertNotIn("print(token", VALIDATOR.lower())


if __name__ == "__main__":
    unittest.main()
