import hashlib
import unittest
from galia2 import authority_reconciliation as f22

def c(cid,k="K1"):
    def h(v): return hashlib.sha256(v.encode()).hexdigest()
    return f22.seal_candidate({"candidate_id":cid,"provider_id":"P","scope":"receipt-signing",
        "key_id":k,"key_sha256":h("key"+k),"source_artifact_sha256":h("artifact"+cid),
        "lineage_sha256":h("lineage"+cid),"valid_from_utc":"2026-01-01T00:00:00Z",
        "authority_assertion":"ACTIVE"})

class TestF22NestedIntegrity(unittest.TestCase):
    def test_sealed_source_isolated(self):
        a=c("A")
        a["custody"]={"receipt":{"operator":"original"}}
        sealed=f22.seal_candidate(a)
        a["custody"]["receipt"]["operator"]="changed"
        self.assertEqual(sealed["custody"]["receipt"]["operator"],"original")

    def test_preserved_nested_custody_isolated(self):
        a,b=c("A",k="K1"),c("B",k="K2")
        a["custody"]={"receipt":{"operator":"original"}}
        a=f22.seal_candidate(a)
        result=f22.reconcile([a,b])
        a["custody"]["receipt"]["operator"]="changed"
        self.assertEqual(result["preserved_candidates"][0]["custody"]["receipt"]["operator"],"original")
        self.assertEqual(result["reconciliation_sha256"],f22._hash({k:v for k,v in result.items() if k!="reconciliation_sha256"}))

    def test_nonfinite_json_denied(self):
        for value in (float("nan"),float("inf"),-float("inf")):
            with self.subTest(value=str(value)):
                a=c("A")
                a["custody"]={"value":value}
                with self.assertRaises(ValueError):
                    f22.seal_candidate(a)

    def test_finite_json_valid(self):
        a,b=c("A",k="K1"),c("B",k="K2")
        a["custody"]={"value":0.5}
        a=f22.seal_candidate(a)
        self.assertEqual(f22.reconcile([a,b])["authority_state"],"AUTHORITY_UNRESOLVED")

if __name__=="__main__":
    unittest.main()
