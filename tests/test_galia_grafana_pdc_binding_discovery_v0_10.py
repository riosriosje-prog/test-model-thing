import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M = json.loads((ROOT / "governance" / "galia_grafana_pdc_binding_discovery_candidate.v0_10.json").read_text())
S = json.loads((ROOT / "governance" / "galia_grafana_pdc_binding_observation.schema.v0_10.json").read_text())
P = (ROOT / "docs" / "galia_grafana_pdc_binding_discovery_protocol.v0_10.md").read_text()

class GrafanaPdcBindingDiscoveryV010Tests(unittest.TestCase):
    def test_hold_dependency_blocks_execution(self):
        self.assertEqual(M["status"], "AUTHORITY_HOLD_DEPENDENT_NOT_PROMOTABLE")
        self.assertEqual(M["authority_dependency"]["current_state"], "HUMAN_DECISION_PENDING")
        self.assertFalse(M["promotion_eligibility"]["current"])

    def test_binding_field_is_not_invented(self):
        self.assertEqual(
            M["current_contract"]["exact_datasource_pdc_binding_api_field"],
            "UNKNOWN_AND_MUST_NOT_BE_INVENTED",
        )
        self.assertIn("NO_API_BINDING_FIELD_ASSUMPTION", M["non_effects"])
        self.assertIn("candidate binding path", P.lower())

    def test_network_observation_is_specific(self):
        obs = M["current_contract"]["documented_observability"]
        self.assertIn("grafanacloud_grafana_pdc_connected_agents", obs)
        self.assertIn("tunnelID_LABEL_IDENTIFIES_PDC_NETWORK", obs)
        self.assertEqual(S["properties"]["connected_agents_count"]["minimum"], 1)

    def test_least_privilege(self):
        lp = M["minimum_privilege_model"]
        self.assertEqual(lp["pdc_network_read"], "plugins:grafana-pdc-app:private-networks-read")
        self.assertTrue(lp["service_account_role_assignment_supported"])
        self.assertIn("NOT_REQUIRED", lp["pdc_network_write"])

    def test_secrets_not_persisted(self):
        self.assertEqual(S["properties"]["secret_material_persisted"]["const"], False)
        p = P.lower()
        for word in ("supabase pat", "pdc signing token", "service-account token", "ca pem"):
            self.assertIn(word, p)

    def test_repeatability_required_for_automation(self):
        allowed = S["properties"]["diff"]["properties"]["repeatability_status"]["enum"]
        self.assertIn("REPEATED_MATCH", allowed)
        self.assertIn("A single observation is insufficient for automation.", P)

    def test_no_external_side_effects_now(self):
        for effect in (
            "NO_GRAFANA_MUTATION",
            "NO_SUPABASE_MUTATION",
            "NO_DATASOURCE_CREATE_OR_UPDATE",
            "NO_PDC_NETWORK_CREATE_OR_UPDATE",
            "NO_SECRET_PERSISTENCE",
        ):
            self.assertIn(effect, M["non_effects"])

if __name__ == "__main__":
    unittest.main()
