import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M = json.loads((ROOT / "governance" / "galia_grafana_pdc_official_binding_candidate.v0_11.json").read_text())
S = json.loads((ROOT / "governance" / "galia_grafana_pdc_binding_contract.schema.v0_11.json").read_text())
R = (ROOT / "docs" / "galia_grafana_pdc_official_binding_runbook.v0_11.md").read_text()

class GrafanaPdcOfficialBindingV011Tests(unittest.TestCase):
    def test_authority_dependency_is_satisfied_but_live_execution_blocked(self):
        self.assertEqual(M["status"], "EXTERNAL_FACTS_BLOCKED_NOT_PROMOTABLE")
        self.assertEqual(M["authority_dependency"]["current_state"], "PROMOTED")
        self.assertTrue(M["authority_dependency"]["satisfied"])
        self.assertTrue(M["current_gates"]["authority_ratification_v0_3_promoted"])
        self.assertFalse(M["current_gates"]["live_execution_candidate_eligible"])
        self.assertTrue(M["authority_hold_reconciliation"]["preparation_baseline_authority_hold_released"])
        self.assertFalse(M["authority_hold_reconciliation"]["live_execution_hold_released"])

    def test_official_binding_mapping(self):
        c = M["official_binding_contract"]
        self.assertEqual(c["terraform_datasource_argument"], "private_data_source_connect_network_id")
        self.assertTrue(c["grafana_json_mapping"]["enableSecureSocksProxy"])
        self.assertEqual(c["grafana_json_mapping"]["secureSocksProxyUsername"], "<PDC_NETWORK_ID>")
        self.assertFalse(c["ui_bootstrap_required"])
        self.assertFalse(c["undocumented_field_invention_required"])

    def test_network_id_contract(self):
        c = M["pdc_network_identity_contract"]
        self.assertEqual(c["provider_datasource"], "grafana_cloud_private_data_source_connect_networks")
        self.assertEqual(c["required_scope_for_discovery"], "accesspolicies:read")
        self.assertEqual(c["network_id_semantics"], "ACCESS_POLICY_ID")
        self.assertEqual(c["modern_identification_scope"], "set:pdc-signing")
        self.assertEqual(c["legacy_identification_scope"], "pdc-signing:write")
        self.assertFalse(c["accesspolicies_write_not_required_for_reading_existing_networks"] is False)
        self.assertFalse(c["accesspolicies_delete_not_required_for_reading_existing_networks"] is False)

    def test_credential_domains_are_separate(self):
        creds=M["credential_domains"]
        self.assertTrue(creds["grafana_cloud_access_policy_token"]["distinct_from_grafana_stack_service_account_token"])
        self.assertTrue(creds["grafana_stack_service_account_token"]["distinct_from_cloud_access_policy_token"])
        self.assertTrue(creds["pdc_agent_signing_token"]["distinct_from_grafana_stack_service_account_token"])
        self.assertTrue(creds["supabase_pat"]["distinct_from_all_grafana_credentials"])
        for v in creds.values():
            self.assertFalse(v["persist_in_repository"])
            self.assertFalse(v["persist_in_receipt"])

    def test_post_binding_evidence_is_fail_closed(self):
        p=S["properties"]
        for k in (
            "enable_secure_socks_proxy",
            "secure_socks_proxy_username_matches_pdc_network_id",
            "datasource_health_passed",
            "verify_full_connection_passed",
            "five_monitor_views_passed",
            "negative_permission_tests_passed",
        ):
            self.assertEqual(p[k]["const"], True)
        self.assertEqual(p["secret_material_persisted"]["const"], False)

    def test_v010_unknown_field_is_superseded(self):
        self.assertEqual(
            M["v0_10_disposition"]["exact_datasource_pdc_binding_api_field_unknown"],
            "SUPERSEDED_BY_OFFICIAL_GRAFANA_PROVIDER_EVIDENCE",
        )
        self.assertIn("no longer treated as unknown", R)

    def test_no_live_side_effects(self):
        for effect in (
            "NO_GRAFANA_CLOUD_API_CALL",
            "NO_GRAFANA_STACK_API_WRITE",
            "NO_SUPABASE_MUTATION",
            "NO_DATASOURCE_CREATE_OR_UPDATE",
            "NO_PDC_NETWORK_CREATE_OR_UPDATE",
            "NO_SECRET_PERSISTENCE",
            "NO_LIVE_EXECUTION_AUTHORIZATION",
        ):
            self.assertIn(effect, M["non_effects"])

if __name__ == "__main__":
    unittest.main()
