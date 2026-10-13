import unittest
from galia2 import authority_reconciliation as f22

class TestF22JsonGate(unittest.TestCase):
    def test_nonfinite_denied(self):
        for x in (float("nan"), float("inf"), -float("inf")):
            with self.assertRaises(ValueError):
                f22._canonical_json({"custody": {"value": x}})

    def test_finite_ok(self):
        self.assertEqual(f22._canonical_json({"value": 0.5}), b'{"value":0.5}\n')
