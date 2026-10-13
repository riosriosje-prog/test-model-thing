import unittest
from galia2 import authority_reconciliation as f22
from tests.test_galia2_authority_reconciliation import c

class TestF22NestedIntegrity(unittest.TestCase):
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
