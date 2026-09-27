import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_datasource_candidate.v0_7.json").read_text())
SCHEMA = json.loads((ROOT / "governance" / "galia_grafana_activation_receipt.schema.v0_7.json").read_text())
YAML = (ROOT / "grafana" / "provisioning" / "datasources" / "galia_cangrejos_postgres.v0_7.yaml").read_text()
ACCEPTANCE = (ROOT / "grafana" / "acceptance" / "galia_cangrejos_postgres_acceptance.v0_7.sql").read_text()
VALIDATOR_PATH = ROOT / "tools" / "validate_galia_grafana_datasource_v0_7.py"
VALIDATOR = VALIDATOR_PATH.read_text()
RUNTIME_PATH = ROOT / "tools" / "run_galia_grafana_runtime_acceptance_v0_7.sh"
RUNTIME = RUNTIME_PATH.read_text()

CA = "-----BEGIN CERTIFICATE-----\nTEST-CA-V0.7\n-----END CERTIFICATE-----"
CA_SHA = hashlib.sha256(CA.encode()).hexdigest()
FAKE_SCOPED_PAT = "sbp_" + "fc" + ("x" * 32)

def make_receipt(profile="SELF_HOSTED_IPV6"):
    return {
        "schema_version": 1,
        "receipt_type": "GALIA_GRAFANA_JIT_ACTIVATION_RECEIPT",
        "project_ref": "nzoviwitcqmsacwiizhh",
        "activation_contract_candidate_id": "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5",
        "activation_contract_head": "96c468c7f37750620a05e62532f36121569b9877",
        "activation_contract_candidate_set_sha256": "20feda3c06beb0464d06067680ee340bda921e7a2a12226c1af6f337500f2f3d",
        "activation_complete": True,
        "credential_mode": "TEMPORARY_ACCESS_JIT_DIRECT",
        "postgres_role": "galia_grafana_ro",
        "gotrue_id": "11111111-2222-3333-4444-555555555555",
        "service_pat_belongs_to_gotrue_id_verified": True,
        "scoped_pat_available": True,
        "ssl_enforcement_enabled": True,
        "temporary_access_enabled": True,
        "jit_mapping_verified": True,
        "network_profile": profile,
        "source_cidrs": ["2001:db8::1/128"],
        "direct_ipv6_reachability_verified": True,
        "pdc_agent_network_verified": profile == "GRAFANA_CLOUD_PDC_IPV6",
        "server_root_ca_sha256": CA_SHA,
        "expires_at": int(time.time()) + 3600,
        "direct_verify_full_connection_passed": True,
        "secret_material_persisted": False,
        "primary_email_persisted": False,
    }

def write_receipt(value):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, handle)
    handle.close()
    return handle.name

def base_env(receipt_path, pdc=False):
    env = os.environ.copy()
    env.update({
        "GALIA_GRAFANA_DB_HOST": "db.nzoviwitcqmsacwiizhh.supabase.co",
        "GALIA_GRAFANA_DB_PORT": "5432",
        "GALIA_GRAFANA_DB_USER": "galia_grafana_ro",
        "GALIA_GRAFANA_DB_NAME": "postgres",
        "GALIA_GRAFANA_PDC_ENABLED": "true" if pdc else "false",
        "GALIA_GRAFANA_SCOPED_PAT": FAKE_SCOPED_PAT,
        "GALIA_GRAFANA_TLS_CA_CERT": CA,
        "GALIA_GRAFANA_ACTIVATION_RECEIPT_PATH": receipt_path,
    })
    return env

class DatasourceV07Tests(unittest.TestCase):
    def tearDown(self):
        path = getattr(self, "tmp", None)
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_candidate_is_preparation_only(self):
        self.assertEqual(MANIFEST["candidate_id"], "GALIA-GRAFANA-DATASOURCE-CANDIDATE-v0.7")
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertIn("NO_GRAFANA_API_WRITE", MANIFEST["non_effects"])

    def test_activation_dependency_is_exact(self):
        dep = MANIFEST["activation_dependency"]
        self.assertEqual(dep["candidate_id"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5")
        self.assertEqual(dep["github_pr"], 52)
        self.assertEqual(dep["candidate_head"], "96c468c7f37750620a05e62532f36121569b9877")
        self.assertEqual(
            dep["candidate_set_sha256"],
            "20feda3c06beb0464d06067680ee340bda921e7a2a12226c1af6f337500f2f3d",
        )
        self.assertTrue(dep["must_complete_before_datasource_promotion"])

    def test_receipt_schema_binds_activation_contract(self):
        props = SCHEMA["properties"]
        self.assertEqual(props["activation_contract_candidate_id"]["const"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.5")
        self.assertEqual(props["activation_contract_head"]["const"], "96c468c7f37750620a05e62532f36121569b9877")
        self.assertEqual(props["expires_at"]["type"], "integer")

    def test_pdc_lifetime_is_under_300_seconds(self):
        pool = MANIFEST["datasource"]["pool"]
        self.assertEqual(pool["connection_max_lifetime_seconds"], 240)
        self.assertLess(pool["connection_max_lifetime_seconds"], 300)
        self.assertIn("connMaxLifetime: 240", YAML)

    def test_tls_and_pdc_provisioning_contract(self):
        self.assertIn("sslmode: verify-full", YAML)
        self.assertIn("tlsConfigurationMethod: file-content", YAML)
        self.assertIn("tlsCACert: $__env{GALIA_GRAFANA_TLS_CA_CERT}", YAML)
        self.assertIn("enableSecureSocksProxy: $__env{GALIA_GRAFANA_PDC_ENABLED}", YAML)
        self.assertEqual(
            MANIFEST["datasource"]["pdc_support_contract"]["permit_remote_open"],
            "db.nzoviwitcqmsacwiizhh.supabase.co:5432",
        )

    def test_direct_connection_does_not_add_pooler_jit_option(self):
        self.assertNotIn("pooler.supabase.com", YAML)
        self.assertNotIn("jit=on", YAML)
        self.assertNotIn("jit=true", YAML)
        self.assertEqual(
            MANIFEST["datasource"]["temporary_access_option"],
            "NOT_REQUIRED_ON_DIRECT_CONNECTION",
        )

    def test_validator_accepts_valid_self_hosted_receipt(self):
        self.tmp = write_receipt(make_receipt())
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp),
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("PASS", result.stdout)
        self.assertIn("credential=REDACTED", result.stdout)
        self.assertNotIn(FAKE_SCOPED_PAT, result.stdout)

    def test_validator_accepts_valid_pdc_receipt(self):
        self.tmp = write_receipt(make_receipt("GRAFANA_CLOUD_PDC_IPV6"))
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp, pdc=True),
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("network_profile=GRAFANA_CLOUD_PDC_IPV6", result.stdout)

    def test_validator_rejects_ca_fingerprint_mismatch(self):
        value = make_receipt()
        value["server_root_ca_sha256"] = "b" * 64
        self.tmp = write_receipt(value)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fingerprint", result.stderr)

    def test_validator_rejects_expired_mapping(self):
        value = make_receipt()
        value["expires_at"] = int(time.time()) - 1
        self.tmp = write_receipt(value)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expired", result.stderr)

    def test_validator_rejects_profile_mismatch(self):
        self.tmp = write_receipt(make_receipt("GRAFANA_CLOUD_PDC_IPV6"))
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp, pdc=False),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)

    def test_receipt_must_not_contain_secret_material(self):
        value = make_receipt()
        value["token"] = FAKE_SCOPED_PAT
        self.tmp = write_receipt(value)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR_PATH)],
            env=base_env(self.tmp),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("forbidden secret-bearing", result.stderr)

    def test_runtime_probe_is_profile_aware(self):
        subprocess.run(["bash", "-n", str(RUNTIME_PATH)], check=True)
        self.assertIn("local psql cannot validate a Grafana Cloud PDC route", RUNTIME)
        self.assertIn("Save & test", RUNTIME)
        self.assertIn("PGSSLMODE=verify-full", RUNTIME)
        self.assertIn("PGSSLROOTCERT", RUNTIME)

    def test_runtime_acceptance_remains_read_only(self):
        self.assertIn("current_user = 'galia_grafana_ro'", ACCEPTANCE)
        self.assertIn("canonical.sources", RUNTIME)
        self.assertIn("__galia_grafana_write_probe", RUNTIME)
        self.assertNotIn("echo \"$GALIA_GRAFANA_SCOPED_PAT", RUNTIME)
        self.assertNotIn("printf \"$GALIA_GRAFANA_SCOPED_PAT", RUNTIME)

    def test_no_literal_pat_material_in_candidate(self):
        combined = json.dumps(MANIFEST) + YAML + VALIDATOR + RUNTIME
        self.assertNotIn(FAKE_SCOPED_PAT, combined)
        self.assertFalse(MANIFEST["credential_contract"]["classic_pat_automatic_fallback"])

if __name__ == "__main__":
    unittest.main()
