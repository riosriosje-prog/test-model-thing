import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "governance" / "galia_grafana_jit_activation_candidate.v0_2.json"
SSL_PATH = ROOT / "supabase" / "activation" / "galia_grafana_ssl_enable.v0_2.json"
TEMP_PATH = ROOT / "supabase" / "activation" / "galia_grafana_temp_access_enable.v0_2.json"
JIT_TEMPLATE_PATH = ROOT / "supabase" / "activation" / "galia_grafana_jit_mapping.template.v0_2.json"
RENDERER_PATH = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_2.py"
EXECUTOR_PATH = ROOT / "tools" / "run_galia_grafana_jit_activation_v0_2.py"

MANIFEST = json.loads(MANIFEST_PATH.read_text())
SSL = json.loads(SSL_PATH.read_text())
TEMP = json.loads(TEMP_PATH.read_text())
JIT_TEMPLATE = json.loads(JIT_TEMPLATE_PATH.read_text())
RENDERER = RENDERER_PATH.read_text()
EXECUTOR = EXECUTOR_PATH.read_text()

class GaliaGrafanaJitActivationV02Tests(unittest.TestCase):
    def test_candidate_is_preparation_only(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.2")
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertIn("NO_MANAGEMENT_API_WRITE", MANIFEST["non_effects"])

    def test_predecessor_is_promoted_v14(self):
        p = MANIFEST["predecessor"]
        self.assertTrue(p["promoted"])
        self.assertEqual(p["github_pr"], 46)
        self.assertEqual(
            p["promoted_main_commit"],
            "a6f3aae4340da9079bdba63df9bdbe46a596cce5",
        )
        self.assertEqual(p["credential_activation_state"], "JIT_MAPPING_REQUIRED")

    def test_management_api_paths_and_discrepancy_are_explicit(self):
        c = MANIFEST["management_api_contract"]
        self.assertEqual(c["ssl_enforcement"]["put"], "/v1/projects/{ref}/ssl-enforcement")
        self.assertEqual(c["temporary_access"]["reference_put"], "/v1/projects/{ref}/jit-access")
        self.assertEqual(c["temporary_access"]["guide_put_alias"], "/v1/projects/{ref}/database/jit-access")
        self.assertEqual(
            c["temporary_access"]["endpoint_discovery"],
            "PROBE_BOTH_READ_ENDPOINTS_FAIL_CLOSED_ON_CONFLICT",
        )
        self.assertEqual(c["jit_mapping"]["create_post"], "/v1/projects/{ref}/database/jit")
        self.assertEqual(c["jit_mapping"]["update_put"], "/v1/projects/{ref}/database/jit")
        self.assertEqual(
            c["jit_mapping"]["operation_selection"],
            "POST_IF_TARGET_USER_ABSENT__PUT_IF_TARGET_USER_PRESENT",
        )

    def test_enable_payloads_are_exact(self):
        self.assertEqual(SSL, {"requestedConfig": {"database": True}})
        self.assertEqual(TEMP, {"state": "enabled"})

    def test_jit_template_is_fail_closed(self):
        self.assertEqual(JIT_TEMPLATE["user_id"], "__GOTRUE_USER_ID_REQUIRED__")
        role = JIT_TEMPLATE["user_roles"][0]
        self.assertEqual(role["role"], "galia_grafana_ro")
        self.assertEqual(role["expires_at"], 0)
        self.assertEqual(
            role["allowed_networks"]["allowed_cidrs"][0]["cidr"],
            "__ALLOWED_CIDR_REQUIRED__",
        )

    def test_credentials_are_separated(self):
        c = MANIFEST["credential_contract"]
        admin = c["activation_admin_token"]
        service = c["grafana_service_pat"]
        self.assertEqual(admin["environment_variable"], "SUPABASE_MANAGEMENT_API_TOKEN")
        self.assertEqual(service["environment_variable"], "GALIA_GRAFANA_SCOPED_PAT")
        self.assertEqual(admin["purpose"], "MANAGEMENT_API_CONFIGURATION_ONLY")
        self.assertEqual(service["purpose"], "POSTGRES_TEMPORARY_ACCESS_PASSWORD_ONLY")
        self.assertFalse(c["reuse_between_roles_default"])
        self.assertFalse(c["classic_pat_automatic_fallback"])
        self.assertTrue(service["must_belong_to_mapped_gotrue_id"])

    def test_permissions_contract(self):
        c = MANIFEST["management_api_contract"]
        self.assertEqual(c["temporary_access"]["scoped_pat_permission"], "Project Settings Read-write")
        self.assertEqual(c["jit_mapping"]["scoped_pat_permission"], "Database JIT Read-write")
        self.assertFalse(MANIFEST["ssl_authorization"]["scoped_pat_permission_exactly_asserted"])

    def test_renderer_success(self):
        env = os.environ.copy()
        env.update({
            "GALIA_JIT_GOTRUE_USER_ID": "11111111-2222-3333-4444-555555555555",
            "GALIA_JIT_ALLOWED_CIDRS": "2001:db8::1/128,192.0.2.44/32",
            "GALIA_JIT_EXPIRES_AT_MS": "4102444800000",
        })
        result = subprocess.run(
            [sys.executable, str(RENDERER_PATH)],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["user_id"], "11111111-2222-3333-4444-555555555555")
        role = payload["user_roles"][0]
        self.assertEqual(role["role"], "galia_grafana_ro")
        self.assertEqual(
            {x["cidr"] for x in role["allowed_networks"]["allowed_cidrs"]},
            {"2001:db8::1/128", "192.0.2.44/32"},
        )
        self.assertEqual(role["expires_at"], 4102444800000)

    def test_renderer_requires_network_restriction(self):
        env = os.environ.copy()
        env.update({
            "GALIA_JIT_GOTRUE_USER_ID": "11111111-2222-3333-4444-555555555555",
            "GALIA_JIT_ALLOWED_CIDRS": "",
            "GALIA_JIT_EXPIRES_AT_MS": "4102444800000",
        })
        result = subprocess.run(
            [sys.executable, str(RENDERER_PATH)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allowed CIDR", result.stderr)

    def test_renderer_has_no_token_handling(self):
        self.assertNotIn("SUPABASE_ACCESS_TOKEN", RENDERER)
        self.assertNotIn("SUPABASE_MANAGEMENT_API_TOKEN", RENDERER)

    def test_executor_is_dry_run_by_default(self):
        result = subprocess.run(
            [sys.executable, str(EXECUTOR_PATH)],
            check=True,
            capture_output=True,
            text=True,
            env={},
        )
        plan = json.loads(result.stdout)
        self.assertEqual(plan["default_mode"], "dry-run")
        self.assertFalse(plan["grafana_service_pat_read_by_executor"])
        self.assertEqual(plan["jit_create_method"], "POST")
        self.assertEqual(plan["jit_update_method"], "PUT")

    def test_executor_never_reads_grafana_service_pat(self):
        self.assertNotIn('os.environ.get("GALIA_GRAFANA_SCOPED_PAT"', EXECUTOR)
        self.assertIn("SUPABASE_MANAGEMENT_API_TOKEN", EXECUTOR)
        self.assertIn("GALIA_SSL_CHANGE_AUTHORIZED", EXECUTOR)
        self.assertIn("GALIA_ACTIVATION_APPLY", EXECUTOR)
        self.assertIn("TEMP_REFERENCE", EXECUTOR)
        self.assertIn("TEMP_GUIDE_ALIAS", EXECUTOR)

    def test_executor_has_no_token_logging(self):
        lowered = EXECUTOR.lower()
        self.assertNotIn("print(token", lowered)
        self.assertNotIn("print(headers", lowered)
        self.assertNotIn("json.dumps(headers", lowered)
        self.assertNotIn('"authorization": receipt', lowered)
        self.assertNotIn('"token": token', lowered)
        self.assertIn('"authorization": f"bearer {token}"', lowered)

if __name__ == "__main__":
    unittest.main()
