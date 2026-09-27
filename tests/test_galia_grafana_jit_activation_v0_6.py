import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_jit_activation_candidate.v0_6.json").read_text())
TEMPLATE = json.loads((ROOT / "governance" / "galia_grafana_activation_observation.template.v0_6.json").read_text())
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_activation_observation_v0_6.py"
RENDERER = ROOT / "tools" / "render_galia_grafana_jit_mapping_v0_6.py"
PLANNER = ROOT / "tools" / "plan_galia_grafana_jit_activation_v0_6.py"

def valid_observation(profile="SELF_HOSTED_IPV6"):
    pdc = profile == "GRAFANA_CLOUD_PDC_IPV6"
    return {
        "schema_version": 1,
        "project_ref": "nzoviwitcqmsacwiizhh",
        "supabase_plan": "Free",
        "project_status": "ACTIVE_HEALTHY",
        "ssl": {"current": True, "server_root_ca": {"source": "SUPABASE_DASHBOARD_DATABASE_SETTINGS_SERVER_ROOT_CERTIFICATE", "sha256": "a" * 64, "pem_stored_in_repository": False}},
        "temporary_access": {"current": "enabled", "canonical_endpoint": "/v1/projects/{ref}/jit-access", "guide_alias_quarantined": "/v1/projects/{ref}/database/jit-access"},
        "identity": {"gotrue_id": "11111111-2222-3333-4444-555555555555", "source": "ORGANIZATION_MEMBER_GOTRUE_ID_VERIFIED", "dedicated_service_identity": True, "service_pat_belongs_to_gotrue_id_verified": True, "primary_email_persisted": False},
        "network": {
            "profile": profile,
            "source_cidrs": ["2001:db8::1/128"],
            "cidr_evidence": "PDC_AGENT_EGRESS_TOWARD_SUPABASE" if pdc else "GRAFANA_HOST_EGRESS_TOWARD_SUPABASE",
            "self_hosted_direct_ipv6_reachability_verified": not pdc,
            "pdc_agent_ipv6_reachability_verified": pdc,
            "supabase_ipv4_addon": False,
        },
        "jit": {"target_exists": False, "expires_at": 4102444800},
        "scoped_pat": {"available": True, "expected_prefix": "sbp_fc", "classic_fallback_allowed": False},
    }

def write_observation(value):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, handle)
    handle.close()
    return handle.name

class ActivationV06Tests(unittest.TestCase):
    def tearDown(self):
        path = getattr(self, "tmp", None)
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_candidate_is_plan_only(self):
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertIn("NO_MANAGEMENT_API_WRITE", MANIFEST["non_effects"])

    def test_template_is_profile_explicit(self):
        self.assertIn("GRAFANA_HOST_EGRESS", TEMPLATE["network"]["cidr_evidence"])
        self.assertIn("self_hosted_direct_ipv6_reachability_verified", TEMPLATE["network"])
        self.assertIn("pdc_agent_ipv6_reachability_verified", TEMPLATE["network"])

    def test_self_hosted_profile_passes(self):
        self.tmp = write_observation(valid_observation())
        subprocess.run([sys.executable, str(VALIDATOR), "--observation", self.tmp], check=True)

    def test_pdc_profile_passes_without_direct_cloud_claim(self):
        self.tmp = write_observation(valid_observation("GRAFANA_CLOUD_PDC_IPV6"))
        subprocess.run([sys.executable, str(VALIDATOR), "--observation", self.tmp], check=True)

    def test_pdc_rejects_grafana_cloud_direct_ipv6_claim(self):
        value = valid_observation("GRAFANA_CLOUD_PDC_IPV6")
        value["network"]["self_hosted_direct_ipv6_reachability_verified"] = True
        self.tmp = write_observation(value)
        result = subprocess.run([sys.executable, str(VALIDATOR), "--observation", self.tmp], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not claim Grafana Cloud direct IPv6", result.stderr)

    def test_self_hosted_rejects_pdc_claim(self):
        value = valid_observation()
        value["network"]["pdc_agent_ipv6_reachability_verified"] = True
        self.tmp = write_observation(value)
        result = subprocess.run([sys.executable, str(VALIDATOR), "--observation", self.tmp], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not claim PDC-agent", result.stderr)

    def test_renderer_uses_roles_unix_seconds_and_ipv6_field(self):
        self.tmp = write_observation(valid_observation())
        result = subprocess.run([sys.executable, str(RENDERER), "--observation", self.tmp], check=True, capture_output=True, text=True)
        payload = json.loads(result.stdout)
        self.assertIn("roles", payload)
        self.assertNotIn("user_roles", payload)
        self.assertEqual(payload["roles"][0]["expires_at"], 4102444800)
        self.assertEqual(payload["roles"][0]["allowed_networks"]["allowed_cidrs_v6"], [{"cidr": "2001:db8::1/128"}])

    def test_planner_emits_profile_specific_route_proof(self):
        self.tmp = write_observation(valid_observation("GRAFANA_CLOUD_PDC_IPV6"))
        result = subprocess.run([sys.executable, str(PLANNER), "--observation", self.tmp], check=True, capture_output=True, text=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["network"]["route_proof"], "PDC_AGENT_IPV6")
        self.assertFalse(plan["network_io"])
        self.assertFalse(plan["management_api_write"])

if __name__ == "__main__":
    unittest.main()
