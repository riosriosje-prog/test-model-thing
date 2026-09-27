import hashlib, json, os, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "governance" / "galia_grafana_datasource_candidate.v0_8.json").read_text())
SCHEMA = json.loads((ROOT / "governance" / "galia_grafana_activation_receipt.schema.v0_8.json").read_text())
VALIDATOR = ROOT / "tools" / "validate_galia_grafana_datasource_v0_8.py"
CA = "-----BEGIN CERTIFICATE-----\nFAKE-TEST-CA\n-----END CERTIFICATE-----"
PAT = "sbp_fc_" + "x" * 40

def receipt(profile="SELF_HOSTED_IPV6"):
    pdc = profile == "GRAFANA_CLOUD_PDC_IPV6"
    return {
        "schema_version": 1,
        "receipt_type": "GALIA_GRAFANA_JIT_ACTIVATION_RECEIPT",
        "project_ref": "nzoviwitcqmsacwiizhh",
        "activation_contract_candidate_id": "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.6",
        "activation_contract_head": "d0c71aaf76333a7f6b8542e2b48b01cfa0ad6654",
        "activation_contract_candidate_set_sha256": "1b0d25ca98a59182ade20d868f371655c7bd86d625d9c8dbd1961f896d5d73c2",
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
        "self_hosted_direct_ipv6_reachability_verified": not pdc,
        "pdc_agent_ipv6_reachability_verified": pdc,
        "route_verification_method": "PDC_AGENT_IPV6" if pdc else "SELF_HOSTED_DIRECT_IPV6",
        "server_root_ca_sha256": hashlib.sha256(CA.encode()).hexdigest(),
        "expires_at": int(time.time()) + 3600,
        "tls_verification_method": "GRAFANA_PDC_SAVE_AND_TEST_VERIFY_FULL" if pdc else "SELF_HOSTED_PSQL_VERIFY_FULL",
        "verify_full_connection_passed": True,
        "secret_material_persisted": False,
        "primary_email_persisted": False,
    }

def write(value):
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(value, f)
    f.close()
    return f.name

def env(path, pdc=False):
    out = os.environ.copy()
    out.update({
        "GALIA_GRAFANA_DB_HOST": "db.nzoviwitcqmsacwiizhh.supabase.co",
        "GALIA_GRAFANA_DB_PORT": "5432",
        "GALIA_GRAFANA_DB_USER": "galia_grafana_ro",
        "GALIA_GRAFANA_DB_NAME": "postgres",
        "GALIA_GRAFANA_PDC_ENABLED": "true" if pdc else "false",
        "GALIA_GRAFANA_SCOPED_PAT": PAT,
        "GALIA_GRAFANA_TLS_CA_CERT": CA,
        "GALIA_GRAFANA_ACTIVATION_RECEIPT_PATH": path,
    })
    return out

class DatasourceV08Tests(unittest.TestCase):
    def tearDown(self):
        path = getattr(self, "tmp", None)
        if path:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def test_candidate_is_preparation_only(self):
        self.assertEqual(MANIFEST["status"], "PREPARATION_ONLY_NOT_PROMOTABLE")
        self.assertEqual(MANIFEST["activation_dependency"]["github_pr"], 54)
        self.assertIn("NO_GRAFANA_API_WRITE", MANIFEST["non_effects"])

    def test_schema_binds_activation_v06(self):
        props = SCHEMA["properties"]
        self.assertEqual(props["activation_contract_candidate_id"]["const"], "GALIA-GRAFANA-JIT-ACTIVATION-CANDIDATE-v0.6")
        self.assertEqual(props["activation_contract_head"]["const"], "d0c71aaf76333a7f6b8542e2b48b01cfa0ad6654")
        self.assertEqual(props["activation_contract_candidate_set_sha256"]["const"], "1b0d25ca98a59182ade20d868f371655c7bd86d625d9c8dbd1961f896d5d73c2")

    def test_self_hosted_receipt_passes(self):
        self.tmp = write(receipt())
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp), check=True, capture_output=True, text=True)
        self.assertIn("SELF_HOSTED_PSQL_VERIFY_FULL", r.stdout)

    def test_pdc_receipt_passes_without_direct_cloud_claim(self):
        self.tmp = write(receipt("GRAFANA_CLOUD_PDC_IPV6"))
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp, True), check=True, capture_output=True, text=True)
        self.assertIn("GRAFANA_PDC_SAVE_AND_TEST_VERIFY_FULL", r.stdout)
        self.assertIn("PDC_AGENT_IPV6", r.stdout)

    def test_pdc_rejects_self_hosted_direct_claim(self):
        value = receipt("GRAFANA_CLOUD_PDC_IPV6")
        value["self_hosted_direct_ipv6_reachability_verified"] = True
        self.tmp = write(value)
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp, True), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PDC_IPV6 receipt evidence mismatch", r.stderr)

    def test_pdc_rejects_local_psql_tls_method(self):
        value = receipt("GRAFANA_CLOUD_PDC_IPV6")
        value["tls_verification_method"] = "SELF_HOSTED_PSQL_VERIFY_FULL"
        self.tmp = write(value)
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp, True), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("PDC_IPV6 receipt evidence mismatch", r.stderr)

    def test_ca_mismatch_fails_closed(self):
        value = receipt()
        value["server_root_ca_sha256"] = "b" * 64
        self.tmp = write(value)
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint", r.stderr)

    def test_receipt_cannot_contain_secret(self):
        value = receipt()
        value["token"] = PAT
        self.tmp = write(value)
        r = subprocess.run([sys.executable, str(VALIDATOR)], env=env(self.tmp), capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("forbidden secret-bearing", r.stderr)

if __name__ == "__main__":
    unittest.main()
