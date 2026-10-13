import hashlib
import unittest
from galia2 import authority_reconciliation as f22

def candidate(cid,key):
    sha=lambda v:hashlib.sha256(v.encode()).hexdigest()
    return f22.seal_candidate({
        "candidate_id":cid,"provider_id":"P","scope":"receipt-signing",
        "key_id":key,"key_sha256":sha(key),
        "source_artifact_sha256":sha("artifact"+cid),
        "lineage_sha256":sha("lineage"+cid),
        "valid_from_utc":"2026-01-01T00:00:00Z",
        "authority_assertion":"ACTIVE"})

class TestF22CustodySnapshot(unittest.TestCase):
    def test_sealed_input_isolated(self):
        source=candidate("A","K1")
        source["custody"]={"chain":["original"]}
        sealed=f22.seal_candidate(source)
        source["custody"]["chain"][0]="changed"
        self.assertEqual(sealed["custody"]["chain"],["original"])

    def test_reconciliation_isolated(self):
        a,b=candidate("A","K1"),candidate("B","K2")
        a["custody"]={"chain":["original"]}
        a=f22.seal_candidate(a)
        result=f22.reconcile([a,b])
        a["custody"]["chain"][0]="changed"
        self.assertEqual(result["preserved_candidates"][0]["custody"]["chain"],["original"])
        self.assertEqual(result["reconciliation_sha256"],
            f22._hash({k:v for k,v in result.items() if k!="reconciliation_sha256"}))
