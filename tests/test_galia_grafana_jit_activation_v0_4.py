import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_jit_activation_candidate.v0_4.json").read_text())
SSL = json.loads((ROOT / "supabase" / "activation" / "galia_grafana_ssl_enable.v0_4.json").read_text())
TEMP = json.loads((ROOT / "supabase" / "activation" / "galia_grafana_temp_access_enable.v0_4.json").read_text())
JIT = json.loads((ROOT / "supabase" / "activation" / "galia_grafana_jit_mapping.template.v0_4.json").read_text())
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_4.py"
PLANNER = ROOT / "tools" / "plan_galia_grafana_jit_activation_v0_4.py"
PLANNER_TEXT = PLANNER.read_text()

class ActivationV04Tests(unittest.TestCase):
    def test_preparation_only(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.4")
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertIn("NO_NETWORK_IO", MANIFEST["non_effects"])

    def test_docs_discrepancy_is_explicit(self):
        temp = MANIFEST["management_api_contract"]["temporary_access"]
        self.assertEqual(temp["reference_put"], "/v1/projects/{ref}/jit-access")
        self.assertEqual(temp["guide_put_alias"], "/v1/projects/{ref}/database/jit-access")
        self.assertEqual(temp["endpoint_discrepancy"], "UNRESOLVED_IN_CURRENT_SUPABASE_DOCS")

    def test_mapping_methods(self):
        m = MANIFEST["management_api_contract"]["jit_mapping"]
        self.assertEqual(m["create_post"], "/v1/projects/{ref}/database/jit")
        self.assertEqual(m["update_put"], "/v1/projects/{ref}/database/jit")
        self.assertEqual(m["operation_selection"], "POST_IF_TARGET_USER_ABSENT__PUT_IF_TARGET_USER_PRESENT")

    def test_payloads(self):
        self.assertEqual(SSL, {"requestedConfig": {"database": True}})
        self.assertEqual(TEMP, {"state": "enabled"})
        self.assertEqual(JIT["user_id"], "__GOTRUE_USER_ID_REQUIRED__")
        self.assertEqual(JIT["user_roles"][0]["expires_at"], 0)

    def test_credentials_are_separated(self):
        c = MANIFEST["credential_contract"]
        self.assertFalse(c["reuse_between_roles_default"])
        self.assertFalse(c["classic_pat_automatic_fallback"])
        self.assertTrue(c["grafana_service_pat"]["must_belong_to_mapped_gotrue_id"])

    def test_planner_has_no_network_or_credentials(self):
        lowered = PLANNER_TEXT.lower()
        for forbidden in (
            "urllib", "requests", "curl", "bearer ",
            "supabase_management_api_token", "galia_grafana_scoped_pat"
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn('"network_io": False', PLANNER_TEXT)
        self.assertIn('"management_api_write": False', PLANNER_TEXT)

    def test_planner_selects_post_for_absent_mapping(self):
        env = os.environ.copy()
        env.update({
            "GALIA_SSL_CURRENT": "true",
            "GALIA_TEMP_ACCESS_CURRENT": "enabled",
            "GALIA_JIT_TARGET_EXISTS": "false",
            "GALIA_TEMP_ENDPOINT_CHOICE": "reference",
            "GALIA_JIT_GOTRUE_USER_ID": "11111111-2222-3333-4444-555555555555",
            "GALIA_JIT_ALLOWED_CIDRS": "2001:db8::1/128",
            "GALIA_JIT_EXPIRES_AT_MS": "4102444800000",
        })
        result = subprocess.run([sys.executable, str(PLANNER)], check=True, capture_output=True, text=True, env=env)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["jit_mapping"]["method"], "POST")
        self.assertEqual(plan["ssl"]["action"], "NOOP")
        self.assertEqual(plan["temporary_access"]["action"], "NOOP")
        self.assertFalse(plan["network_io"])

    def test_planner_selects_put_for_existing_mapping(self):
        env = os.environ.copy()
        env.update({
            "GALIA_SSL_CURRENT": "false",
            "GALIA_TEMP_ACCESS_CURRENT": "disabled",
            "GALIA_JIT_TARGET_EXISTS": "true",
            "GALIA_TEMP_ENDPOINT_CHOICE": "guide_alias",
            "GALIA_JIT_GOTRUE_USER_ID": "11111111-2222-3333-4444-555555555555",
            "GALIA_JIT_ALLOWED_CIDRS": "192.0.2.44/32",
            "GALIA_JIT_EXPIRES_AT_MS": "4102444800000",
        })
        result = subprocess.run([sys.executable, str(PLANNER)], check=True, capture_output=True, text=True, env=env)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["jit_mapping"]["method"], "PUT")
        self.assertEqual(plan["ssl"]["action"], "ENABLE_AND_EXPECT_BRIEF_REBOOT")
        self.assertEqual(plan["temporary_access"]["action"], "ENABLE")

    def test_unknown_remote_state_fails_closed(self):
        env = os.environ.copy()
        env.update({
            "GALIA_SSL_CURRENT": "unknown",
            "GALIA_TEMP_ACCESS_CURRENT": "enabled",
            "GALIA_JIT_TARGET_EXISTS": "false",
            "GALIA_TEMP_ENDPOINT_CHOICE": "reference",
            "GALIA_JIT_GOTRUE_USER_ID": "11111111-2222-3333-4444-555555555555",
            "GALIA_JIT_ALLOWED_CIDRS": "2001:db8::1/128",
            "GALIA_JIT_EXPIRES_AT_MS": "4102444800000",
        })
        result = subprocess.run([sys.executable, str(PLANNER)], capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_CLOSED", result.stderr)

if __name__ == "__main__":
    unittest.main()
