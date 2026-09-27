import json, os, subprocess, sys, tempfile, time, unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VALIDATOR=ROOT/"tools"/"validate_galia_grafana_external_fact_packet_v0_14.py"
DOMAINS=[
"authority_binding","grafana_stack_identity","pdc_network_identity","pdc_connected_agent_state",
"pdc_ipv6_route_to_supabase","credential_availability_and_domain_separation",
"supabase_ssl_state","supabase_temporary_access_state","supabase_jit_mapping_state","supabase_server_root_ca_sha256"
]

def evidence():
    now=datetime.now(timezone.utc).isoformat()
    return {d:{"observed_at_utc":now,"method":"SANITIZED_READ_ONLY_OBSERVATION","source_ref":f"receipt://{d}","receipt_sha256":"a"*64} for d in DOMAINS}

def packet():
    return {
      "schema_version":1,"receipt_type":"GALIA_GRAFANA_EXTERNAL_FACT_PACKET",
      "observed_at_utc":datetime.now(timezone.utc).isoformat(),
      "authority":{"ratification_merge":"82e5b8e6642d1475ebcee9183b401b1fd010e63b","pdc_contract_candidate_id":"GALIA-GRAFANA-PDC-OFFICIAL-BINDING-CONTRACT-CANDIDATE-v0.11","pdc_contract_head":"ce4d638f11d5e63461ec5a2bd99155146c806ec4","pdc_contract_candidate_set_sha256":"ea5988231b7585dd6124722520483f258b34e39592de535a251c7bbc7d0296fc"},
      "profile":"GRAFANA_CLOUD_PDC_IPV6",
      "grafana":{"stack_url":"https://example.grafana.net","stack_id":"12345","pdc_network":{"id":"pdc-network-id","name":"galia-pdc","region":"us-east","status":"observed","discovery_source":"GRAFANA_CLOUD_OFFICIAL_SURFACE","connected_agents_count":1}},
      "credentials":{"grafana_cloud_access_policy_credential_available":True,"grafana_stack_service_account_credential_available":True,"pdc_agent_signing_credential_available":True,"supabase_service_pat_available":True,"credential_domains_distinct_verified":True},
      "network":{"pdc_agent_ipv6_egress_cidrs":["2600:1901:0:1::/64"],"supabase_host":"db.nzoviwitcqmsacwiizhh.supabase.co","supabase_port":5432,"route_verified":True,"permit_remote_open":"db.nzoviwitcqmsacwiizhh.supabase.co:5432"},
      "supabase":{"ssl_enforcement_enabled":True,"temporary_access_enabled":True,"jit_mapping_verified":True,"jit_expires_at_ms":time.time_ns()//1_000_000+1_800_000,"role":"galia_grafana_ro","gotrue_id":"11111111-2222-3333-4444-555555555555","service_pat_identity_binding_verified":True,"server_root_ca_sha256":"b"*64},
      "evidence":evidence(),"secret_material_persisted":False
    }

class T(unittest.TestCase):
    def tearDown(self):
        if hasattr(self,"path"):
            try: os.unlink(self.path)
            except FileNotFoundError: pass
    def runv(self,v):
        f=tempfile.NamedTemporaryFile("w",suffix=".json",delete=False); json.dump(v,f); f.close(); self.path=f.name
        return subprocess.run([sys.executable,str(VALIDATOR),"--packet",self.path],capture_output=True,text=True)
    def test_valid(self):
        r=self.runv(packet()); self.assertEqual(r.returncode,0,r.stderr)
        o=json.loads(r.stdout); self.assertEqual(o["eligibility"],"FACTS_COMPLETE_FOR_FUTURE_LIVE_EXECUTION_CANDIDATE"); self.assertFalse(o["live_execution_authorized"])
    def test_schema_unknown_field(self):
        v=packet(); v["credentials"]["display_note"]="x"; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("schema violation",r.stderr)
    def test_schema_type(self):
        v=packet(); v["grafana"]["stack_id"]=[]; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("schema violation",r.stderr)
    def test_secret_alias(self):
        v=packet(); v["credentials"]["api_key"]="x"; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("forbidden",r.stderr)
    def test_missing_evidence(self):
        v=packet(); del v["evidence"]["supabase_ssl_state"]; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("schema violation",r.stderr)
    def test_stale_evidence(self):
        v=packet(); v["evidence"]["supabase_ssl_state"]["observed_at_utc"]=datetime.fromtimestamp(time.time()-3600,timezone.utc).isoformat(); r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("stale",r.stderr)
    def test_jit_ms_short(self):
        v=packet(); v["supabase"]["jit_expires_at_ms"]=time.time_ns()//1_000_000+60_000; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("insufficient",r.stderr)
    def test_seconds_cannot_pass_as_ms(self):
        v=packet(); v["supabase"]["jit_expires_at_ms"]=int(time.time())+1800; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("insufficient",r.stderr)
    def test_multicast_rejected(self):
        v=packet(); v["network"]["pdc_agent_ipv6_egress_cidrs"]=["ff00::/8"]; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("global-unicast",r.stderr)
    def test_default_route_rejected(self):
        v=packet(); v["network"]["pdc_agent_ipv6_egress_cidrs"]=["::/0"]; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("global-unicast",r.stderr)
    def test_private_rejected(self):
        v=packet(); v["network"]["pdc_agent_ipv6_egress_cidrs"]=["fd00::/64"]; r=self.runv(v); self.assertNotEqual(r.returncode,0); self.assertIn("global-unicast",r.stderr)

if __name__=="__main__": unittest.main()
