import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_jit_activation_candidate.v0_5.json").read_text())
JIT_TEMPLATE = json.loads((ROOT / "supabase" / "activation" / "galia_grafana_jit_mapping.template.v0_5.json").read_text())
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_activation_observation_v0_5.py"
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_5.py"
PLANNER = ROOT / "tools" / "plan_galia_grafana_jit_activation_v0_5.py"

def valid_observation(profile="SELF_HOSTED_IPV6", target_exists=False):
    is_pdc = profile == "GRAFANA_CLOUD_PDC_IPV6"
    return {
        "schema_version": 1,
        "project_ref": "nzoviwitcqmsacwiizhh",
        "supabase_plan": "Free",
        "project_status": "ACTIVE_HEALTHY",
        "ssl": {
            "current": True,
            "server_root_ca": {
                "source": "SUPABASE_DASHBOARD_DATABASE_SETTINGS_SERVER_ROOT_CERTIFICATE",
                "sha256": "a" * 64,
                "pem_stored_in_repository": False,
            },
        },
        "temporary_access": {
            "current": "enabled",
            "canonical_endpoint": "/v1/projects/{ref}/jit-access",
            "guide_alias_quarantined": "/v1/projects/{ref}/database/jit-access",
        },
        "identity": {
            "gotrue_id": "11111111-2222-3333-4444-555555555555",
            "source": "ORGANIZATION_MEMBER_GOTRUE_ID_VERIFIED",
            "dedicated_service_identity": True,
            "service_pat_belongs_to_gotrue_id_verified": True,
            "primary_email_persisted": False,
        },
        "network": {
            "profile": profile,
            "source_cidrs": ["2001:db8::1/128", "192.0.2.44/32"],
            "cidr_evidence": (
                "PDC_AGENT_EGRESS_TOWARD_SUPABASE"
                if is_pdc
                else "GRAFANA_HOST_EGRESS_TOWARD_SUPABASE"
            ),
            "direct_ipv6_reachability_verified": True,
            "pdc_agent_network_verified": is_pdc,
            "supabase_ipv4_addon": False,
        },
        "jit": {
            "target_exists": target_exists,
            "expires_at": 4102444800,
        },
        "scoped_pat": {
            "available": True,
            "expected_prefix": "sbp_fc",
            "classic_fallback_allowed": False,
        },
    }

def write_observation(value):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, handle)
    handle.close()
    return handle.name

class ActivationV05Tests(unittest.TestCase):
    def tearDown(self):
        for attr in ("tmp",):
            path = getattr(self, attr, None)
            if path:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass

    def test_candidate_is_plan_only(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5")
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertIn("NO_NETWORK_IO", MANIFEST["non_effects"])
        self.assertIn("NO_MANAGEMENT_API_WRITE", MANIFEST["non_effects"])

    def test_temporary_access_reference_is_canonical(self):
        c = MANIFEST["supabase_doc_contract"]["temporary_access"]
        self.assertEqual(c["canonical_get"], "/v1/projects/{ref}/jit-access")
        self.assertEqual(c["canonical_put"], "/v1/projects/{ref}/jit-access")
        self.assertEqual(c["guide_alias_status"], "DOCUMENTATION_CONFLICT_DO_NOT_EXECUTE")

    def test_permissions_are_exact(self):
        c = MANIFEST["supabase_doc_contract"]
        self.assertEqual(c["temporary_access"]["write_permission"], "Project Settings Read-write")
        self.assertEqual(c["jit_mapping"]["write_permission"], "Database JIT Read-write")
        self.assertEqual(c["ssl_enforcement"]["write_permission"], "SSL Enforcement Read-write")

    def test_jit_request_schema_uses_roles_seconds_and_split_cidrs(self):
        c = MANIFEST["supabase_doc_contract"]["jit_mapping"]
        self.assertEqual(c["request_body"]["roles"], "Array<role grant>")
        self.assertEqual(c["response_field"], "user_roles")
        self.assertEqual(c["expires_at_unit"], "unix_seconds")
        self.assertEqual(c["allowed_networks"]["ipv4_field"], "allowed_cidrs")
        self.assertEqual(c["allowed_networks"]["ipv6_field"], "allowed_cidrs_v6")
        self.assertIn("roles", JIT_TEMPLATE)
        self.assertNotIn("user_roles", JIT_TEMPLATE)

    def test_validator_accepts_verified_self_hosted_observation(self):
        self.tmp = write_observation(valid_observation())
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("PASS", result.stdout)

    def test_validator_accepts_verified_pdc_observation(self):
        self.tmp = write_observation(valid_observation("GRAFANA_CLOUD_PDC_IPV6"))
        subprocess.run(
            [sys.executable, str(VALIDATOR), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )

    def test_validator_rejects_email_persistence(self):
        value = valid_observation()
        value["identity"]["primary_email"] = "not-allowed@example.invalid"
        self.tmp = write_observation(value)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--observation", self.tmp],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden field", result.stderr)

    def test_validator_requires_verified_ipv6_egress(self):
        value = valid_observation()
        value["network"]["source_cidrs"] = ["192.0.2.44/32"]
        self.tmp = write_observation(value)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--observation", self.tmp],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IPv6", result.stderr)

    def test_renderer_splits_ipv4_and_ipv6_and_uses_unix_seconds(self):
        self.tmp = write_observation(valid_observation())
        result = subprocess.run(
            [sys.executable, str(RENDERER), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["user_id"], "11111111-2222-3333-4444-555555555555")
        self.assertIn("roles", payload)
        self.assertNotIn("user_roles", payload)
        role = payload["roles"][0]
        self.assertEqual(role["expires_at"], 4102444800)
        self.assertEqual(role["allowed_networks"]["allowed_cidrs"], [{"cidr": "192.0.2.44/32"}])
        self.assertEqual(role["allowed_networks"]["allowed_cidrs_v6"], [{"cidr": "2001:db8::1/128"}])

    def test_planner_uses_post_for_absent_mapping(self):
        self.tmp = write_observation(valid_observation(target_exists=False))
        result = subprocess.run(
            [sys.executable, str(PLANNER), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        plan = json.loads(result.stdout)
        self.assertTrue(plan["promotion_eligible"])
        self.assertEqual(plan["jit_mapping"]["method"], "POST")
        self.assertEqual(plan["temporary_access"]["endpoint"], "/v1/projects/{ref}/jit-access")
        self.assertEqual(plan["temporary_access"]["guide_alias"], "QUARANTINED_DO_NOT_EXECUTE")
        self.assertFalse(plan["network_io"])
        self.assertFalse(plan["credential_input"])
        self.assertFalse(plan["management_api_write"])

    def test_planner_uses_put_for_existing_mapping(self):
        self.tmp = write_observation(valid_observation(target_exists=True))
        result = subprocess.run(
            [sys.executable, str(PLANNER), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        plan = json.loads(result.stdout)
        self.assertEqual(plan["jit_mapping"]["method"], "PUT")

    def test_planner_holds_when_scoped_pat_unavailable(self):
        value = valid_observation()
        value["scoped_pat"]["available"] = False
        self.tmp = write_observation(value)
        result = subprocess.run(
            [sys.executable, str(PLANNER), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        plan = json.loads(result.stdout)
        self.assertFalse(plan["promotion_eligible"])
        self.assertIn("SCOPED_PAT_UNAVAILABLE", plan["holds"])

    def test_planner_holds_when_service_pat_identity_unverified(self):
        value = valid_observation()
        value["identity"]["service_pat_belongs_to_gotrue_id_verified"] = False
        self.tmp = write_observation(value)
        result = subprocess.run(
            [sys.executable, str(PLANNER), "--observation", self.tmp],
            check=True, capture_output=True, text=True,
        )
        plan = json.loads(result.stdout)
        self.assertFalse(plan["promotion_eligible"])
        self.assertIn("SERVICE_PAT_IDENTITY_BINDING_UNVERIFIED", plan["holds"])

if __name__ == "__main__":
    unittest.main()
