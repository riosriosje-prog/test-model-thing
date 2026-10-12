import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_live_execution_candidate.v0_9.json").read_text())
SCHEMA = json.loads((ROOT / "governance" / "galia_grafana_live_execution_evidence.schema.v0_9.json").read_text())
RUNBOOK = (ROOT / "docs" / "galia_grafana_live_execution_runbook.v0_9.md").read_text()

class GrafanaLiveExecutionV09Tests(unittest.TestCase):
    def test_candidate_is_hold_dependent(self):
        self.assertEqual(MANIFEST["status"], "AUTHORITY_HOLD_DEPENDENT_NOT_PROMOTABLE")
        dep = MANIFEST["authority_dependency"]
        self.assertEqual(dep["candidate_id"], "GALIA-GRAFANA-AUTHORITY-RATIFICATION-CANDIDATE-v0.3")
        self.assertEqual(dep["github_pr"], 57)
        self.assertEqual(dep["current_state"], "HUMAN_DECISION_PENDING")

    def test_profiles_are_explicit_and_mutually_named(self):
        profiles = set(MANIFEST["supported_profiles"])
        self.assertEqual(profiles, {"SELF_HOSTED_IPV6", "GRAFANA_CLOUD_PDC_IPV6"})
        unsupported = {x["profile"] for x in MANIFEST["explicitly_unsupported_profiles"]}
        self.assertIn("GRAFANA_CLOUD_DIRECT_IPV6", unsupported)

    def test_cloud_requires_real_pdc_binding(self):
        cloud = MANIFEST["supported_profiles"]["GRAFANA_CLOUD_PDC_IPV6"]
        self.assertTrue(cloud["pdc_required"])
        self.assertTrue(cloud["pdc_network_identity_required"])
        self.assertTrue(cloud["pdc_agent_must_be_connected"])
        self.assertEqual(cloud["pdc_binding_automation_status"], "UNVERIFIED_PUBLIC_CONTRACT_DO_NOT_ASSUME")
        self.assertIn("PDC_BOOLEAN_ALONE_IS_NOT_PDC_BINDING_EVIDENCE", MANIFEST["invariants"])
        self.assertIn("Do not invent a PDC network JSON field.", RUNBOOK)

    def test_cloud_route_target_is_constrained(self):
        cloud = MANIFEST["supported_profiles"]["GRAFANA_CLOUD_PDC_IPV6"]
        self.assertEqual(cloud["permit_remote_open"], "db.nzoviwitcqmsacwiizhh.supabase.co:5432")
        self.assertIn("CONN_MAX_LIFETIME_240_LT_300", MANIFEST["invariants"])

    def test_credential_domains_are_separate(self):
        creds = MANIFEST["credential_domains"]
        self.assertTrue(creds["grafana_service_account_token"]["distinct_from_supabase_pat"])
        self.assertTrue(creds["grafana_pdc_signing_token"]["distinct_from_supabase_pat"])
        self.assertTrue(creds["grafana_pdc_signing_token"]["distinct_from_grafana_service_account_token"])
        for value in creds.values():
            self.assertFalse(value["persist_in_repository"])
            self.assertFalse(value["persist_in_receipt"])

    def test_schema_rejects_direct_cloud_ipv6_by_construction(self):
        profile_enum = SCHEMA["properties"]["profile"]["enum"]
        self.assertNotIn("GRAFANA_CLOUD_DIRECT_IPV6", profile_enum)
        self.assertEqual(set(profile_enum), {"SELF_HOSTED_IPV6", "GRAFANA_CLOUD_PDC_IPV6"})

    def test_no_external_side_effects(self):
        for effect in (
            "NO_SUPABASE_MUTATION",
            "NO_GRAFANA_MUTATION",
            "NO_SSL_CHANGE",
            "NO_TEMPORARY_ACCESS_CHANGE",
            "NO_JIT_MAPPING_CHANGE",
            "NO_SECRET_PERSISTENCE",
            "NO_LIVE_EXECUTION_AUTHORIZATION",
        ):
            self.assertIn(effect, MANIFEST["non_effects"])

if __name__ == "__main__":
    unittest.main()
