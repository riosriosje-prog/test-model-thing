import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_external_facts_intake_candidate.v0_13.json").read_text())
SCHEMA = json.loads((ROOT / "governance" / "galia_grafana_external_fact_packet.schema.v0_13.json").read_text())
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_external_fact_packet_v0_13.py"

def packet():
    return {
        "schema_version": 1,
        "receipt_type": "GALIA_GRAFANA_EXTERNAL_FACT_PACKET",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "authority": {
            "ratification_merge": "82e5b8e6642d1475ebcee9183b401b1fd010e63b",
            "pdc_contract_candidate_id": "GALIA-GRAFANA-PDC-OFFICIAL-BINDING-CONTRACT-CANDIDATE-v0.11",
            "pdc_contract_head": "ce4d638f11d5e63461ec5a2bd99155146c806ec4",
            "pdc_contract_candidate_set_sha256": "ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc"
        },
        "profile": "GRAFANA_CLOUD_PDC_IPV6",
        "grafana": {
            "stack_url": "https://example.grafana.net",
            "stack_id": "12345",
            "pdc_network": {
                "id": "pdc-network-id",
                "name": "galia-pdc",
                "region": "us-east",
                "status": "observed",
                "discovery_source": "GRAFANA_CLOUD_OFFICIAL_SURFACE",
                "connected_agents_count": 1
            }
        },
        "credentials": {
            "grafana_cloud_access_policy_credential_available": True,
            "grafana_stack_service_account_credential_available": True,
            "pdc_agent_signing_credential_available": True,
            "supabase_service_pat_available": True,
            "credential_domains_distinct_verified": True
        },
        "network": {
            "pdc_agent_ipv6_egress_cidrs": ["2600:1901:0:1::/64"],
            "supabase_host": "db.nzoviwitcqmsacwiizhh.supabase.co",
            "supabase_port": 5432,
            "route_verified": True,
            "permit_remote_open": "db.nzoviwitcqmsacwiizhh.supabase.co:5432"
        },
        "supabase": {
            "ssl_enforcement_enabled": True,
            "temporary_access_enabled": True,
            "jit_mapping_verified": True,
            "jit_expires_at": int(time.time()) + 1800,
            "role": "galia_grafana_ro",
            "gotrue_id": "11111111-2222-3333-4444-555555555555",
            "service_pat_identity_binding_verified": True,
            "server_root_ca_sha256": "a" * 64
        },
        "secret_material_persisted": False
    }

def write_packet(value):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, f)
    f.close()
    return f.name

class ExternalFactsIntakeV013Tests(unittest.TestCase):
    def tearDown(self):
        path = getattr(self, "tmp", None)
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def run_validator(self, value, check=False):
        self.tmp = write_packet(value)
        return subprocess.run(
            [sys.executable, str(VALIDATOR), "--packet", self.tmp],
            check=check, capture_output=True, text=True
        )

    def test_manifest_is_nonpromotable_and_no_side_effects(self):
        self.assertEqual(MANIFEST["status"], "EXTERNAL_FACTS_INTAKE_READY_NOT_PROMOTABLE")
        self.assertFalse(MANIFEST["eligibility_output"]["does_not_authorize_execution"] is False)
        self.assertIn("NO_GRAFANA_CLOUD_API_CALL", MANIFEST["non_effects"])
        self.assertIn("NO_SUPABASE_MUTATION", MANIFEST["non_effects"])

    def test_exact_v011_binding(self):
        b = MANIFEST["base_candidate"]
        self.assertEqual(b["github_pr"], 60)
        self.assertEqual(b["head"], "ce4d638f11d5e63461ec5a2bd99155146c806ec4")
        self.assertEqual(b["candidate_set_sha256"], "ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc")

    def test_schema_locks_profile_and_role(self):
        self.assertEqual(SCHEMA["properties"]["profile"]["const"], "GRAFANA_CLOUD_PDC_IPV6")
        self.assertEqual(SCHEMA["properties"]["supabase"]["properties"]["role"]["const"], "galia_grafana_ro")

    def test_valid_packet_is_eligible_for_future_candidate_only(self):
        result = self.run_validator(packet(), check=True)
        out = json.loads(result.stdout)
        self.assertEqual(out["eligibility"], "FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE")
        self.assertFalse(out["live_execution_authorized"])
        self.assertTrue(out["future_human_decision_required"])

    def test_stale_packet_fails_closed(self):
        value = packet()
        value["observed_at_utc"] = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale", result.stderr)

    def test_short_jit_lifetime_fails_closed(self):
        value = packet()
        value["supabase"]["jit_expires_at"] = int(time.time()) + 60
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("insufficient", result.stderr)

    def test_private_ipv6_is_rejected(self):
        value = packet()
        value["network"]["pdc_agent_ipv6_egress_cidrs"] = ["fd00::/64"]
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("externally routable", result.stderr)

    def test_secret_field_is_rejected(self):
        value = packet()
        value["credentials"]["token"] = "never-store-me"
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden", result.stderr)

    def test_unknown_root_field_fails_closed(self):
        value = packet()
        value["unexpected_nonsecret"] = "not allowed"
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shape mismatch", result.stderr)
        self.assertIn("unexpected_nonsecret", result.stderr)

    def test_unknown_nested_field_fails_closed(self):
        value = packet()
        value["grafana"]["pdc_network"]["unexpected_nonsecret"] = "not allowed"
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shape mismatch", result.stderr)
        self.assertIn("unexpected_nonsecret", result.stderr)

    def test_missing_required_field_fails_closed(self):
        value = packet()
        del value["network"]["route_verified"]
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shape mismatch", result.stderr)
        self.assertIn("route_verified", result.stderr)

    def test_manifest_declares_strict_schema_parity(self):
        self.assertTrue(MANIFEST["fact_packet"]["strict_shape_parity_with_schema"])
        self.assertEqual(MANIFEST["fact_packet"]["unknown_field_policy"], "FAIL_CLOSED")

    def test_wrong_pdc_contract_hash_fails(self):
        value = packet()
        value["authority"]["pdc_contract_candidate_set_sha256"] = "0" * 64
        result = self.run_validator(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate-set mismatch", result.stderr)

if __name__ == "__main__":
    unittest.main()
