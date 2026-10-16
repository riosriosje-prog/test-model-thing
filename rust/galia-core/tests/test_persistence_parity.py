"""P7 differential Python/Rust byte-exact conformance. All Rust checks remain read-only."""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

from galia2.persistence import (
    PayloadEntry, GenerationManifest, PromotionEnvelope, HeadPointer, GenerationStore,
    PersistenceValidationError,
)

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "rust" / "galia-core" / "target" / "debug" / "galia-persistence-shadow"
POLICY = "p7"

def sha(b):
    return hashlib.sha256(b).hexdigest()

def bundle(commit, parent, seq):
    payloads = {"evidence/raw.txt": b"historic source bytes\n"}
    entries = tuple(PayloadEntry(k,sha(v),len(v)) for k,v in payloads.items())
    m = GenerationManifest(
        commit_id=commit, seq=seq, parent_commit=parent,
        case_id="cangrejos", schema_version="galia2-core-v1",
        created_at=NOW, payloads=entries,
        authority_decision_id="decision-1", persistence_policy_version=POLICY,
    )
    p = PromotionEnvelope(
        commit_id=commit, case_id=m.case_id,
        manifest_hash=m.sha256, authority_decision_id=m.authority_decision_id,
        authorization_id="auth-id", authorization_policy_version="p5",
        preflight_receipt_id="r1", persistence_policy_version=POLICY,
        published_at=NOW,
    )
    h = HeadPointer(commit,seq,m.sha256,p.sha256)
    encoded = {
        "manifest_hex":m.to_bytes().hex(),
        "promotion_hex":p.to_bytes().hex(),
        "head_hex":h.to_bytes().hex(),
        "payloads_hex":{k:v.hex() for k,v in payloads.items()},
    }
    return encoded, m, p, h

def run(req):
    p = subprocess.run([str(BINARY)],input=json.dumps(req),text=True,capture_output=True,
                       timeout=8,check=False)
    return p.returncode,json.loads(p.stdout)

class PersistenceParity(unittest.TestCase):
    def test_bytes_and_hashes_match_python_p7(self):
        self.assertTrue(BINARY.exists(),"Build Rust shadow CLI first")
        child, m, p, h = bundle("candidate-17","canonical-16",17)
        parent, pm, pp, ph = bundle("canonical-16","canonical-15",16)
        rc,out = run({"generation":child,"parent":parent})
        self.assertEqual(rc,0,out)
        self.assertEqual(out["manifest_hash"],m.sha256)
        self.assertEqual(out["promotion_hash"],p.sha256)
        self.assertEqual(out["commit_id"],h.commit_id)
        self.assertEqual(out["seq"],h.seq)
        self.assertTrue(out["parent_chain_checked"])
        self.assertFalse(out["canonical_writeback"])
        self.assertFalse(out["authority_transfer"])
        self.assertIsNone(out["output_commit"])

    def test_python_p7_disk_validator_and_rust_supplied_bytes_agree(self):
        child,m,p,h = bundle("candidate-17","canonical-16",17)
        with tempfile.TemporaryDirectory() as td:
            s = GenerationStore(td,policy_version=POLICY,actor="parity")
            gen = Path(td)/"generations"/m.commit_id
            (gen/"payload"/"evidence").mkdir(parents=True)
            (gen/"payload"/"evidence"/"raw.txt").write_bytes(bytes.fromhex(child["payloads_hex"]["evidence/raw.txt"]))
            (gen/"manifest.json").write_bytes(m.to_bytes())
            (gen/"promotion.json").write_bytes(p.to_bytes())
            s.head_path.write_bytes(h.to_bytes())
            validated = s.verify_generation(m.commit_id,
                expected_manifest_hash=h.manifest_hash,expected_promotion_hash=h.promotion_hash)
            self.assertEqual(validated.to_bytes(),m.to_bytes())
            rc,out = run({"generation":child})
            self.assertEqual(rc,0,out)
            self.assertFalse(out["parent_chain_checked"])
            (gen/"payload"/"evidence"/"raw.txt").write_bytes(b"tampered")
            with self.assertRaises(PersistenceValidationError):
                s.verify_generation(m.commit_id,expected_manifest_hash=h.manifest_hash)
            child["payloads_hex"]["evidence/raw.txt"]=b"tampered".hex()
            rc,out=run({"generation":child})
            self.assertEqual(rc,2,out)

    def test_negative_replays_are_fail_closed(self):
        child,_,_,_ = bundle("candidate-17","canonical-16",17)
        parent,_,_,_=bundle("canonical-16","canonical-15",16)
        cases = {}
        cases["wrong_parent"]={"generation":child,"parent":bundle("other","canonical-15",16)[0]}
        cases["wrong_seq"]={"generation":child,"parent":bundle("canonical-16","canonical-15",8)[0]}
        cases["tampered_parent"]={"generation":child,"parent":dict(parent,
            payloads_hex={"evidence/raw.txt":b"corruption".hex()})}
        cases["missing_payload"]={"generation":dict(child,payloads_hex={})}
        cases["extra_payload"]={"generation":dict(child,payloads_hex={**child["payloads_hex"],"undocumented":b"x".hex()})}
        cases["tampered_manifest"]={"generation":dict(child,manifest_hex=child["manifest_hex"]+"20")}
        cases["tampered_promotion"]={"generation":dict(child,promotion_hex=child["promotion_hex"]+"20")}
        cases["no_head_newline"]={"generation":dict(child,head_hex=child["head_hex"][:-2])}
        cases["invalid_hex"]={"generation":dict(child,promotion_hex="not hex")}
        for name,request in cases.items():
            with self.subTest(case=name):
                rc,out=run(request)
                self.assertEqual(rc,2,out)
                self.assertEqual(out["status"],"REJECTED",out)
                self.assertFalse(out["canonical_writeback"])
                self.assertFalse(out["authority_transfer"])
                self.assertIsNone(out["output_commit"])

if __name__=="__main__":
    unittest.main()
