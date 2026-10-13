"""Isolated negative tests for F23 verified-scope gate.

These test early fail-closed checks without asserting trust-root authentication.
"""
from dataclasses import replace
import unittest
from unittest.mock import patch
from galia2.authority import AuthorityScope
from galia2.f23_verified_scope_gate import VerifiedScopeAttestation, bind_with_verified_scope

A = VerifiedScopeAttestation(
    decision_id="d", reviewer_id="r", issuer_id="issuer",
    case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",),
    reconciliation_sha256="a"*64, candidate_set_sha256="b"*64,
    conflict_component_sha256="c"*64, selected_candidate_id="candidate-A",
)
S = AuthorityScope(case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",))
R = {"reconciliation_sha256":"a"*64, "candidate_set_sha256":"b"*64,
     "reconciled_component_sha256":"c"*64, "selected_candidate_id":"candidate-A"}

def call(scope=S, attestation=A, reconciliation=R):
    return bind_with_verified_scope(
        reconciliation, attestation=attestation,
        p5_scope=scope, expected_provider_id="provider-A", expected_external_scope="external-A")

class GateTests(unittest.TestCase):
    def test_missing_attestation(self):
        with self.assertRaisesRegex(ValueError, "attestation required"): call(attestation=None)
    def test_case_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, case_id="foreign"))
    def test_type_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, target_type="foreign"))
    def test_ids_mismatch(self):
        with self.assertRaisesRegex(ValueError, "P5 scope mismatch"):
            call(scope=replace(S, target_ids=("foreign",)))
    def test_reconciliation_mismatch(self):
        with self.assertRaisesRegex(ValueError, "attested reconciliation mismatch"):
            call(reconciliation=dict(R, reconciliation_sha256="d"*64))
    def test_no_trust_root_denies_all(self):
        with patch("galia2.f23_verified_scope_gate.bind_reconciliation") as inner:
            with self.assertRaisesRegex(ValueError, "trusted issuer verification unavailable"):
                call()
            inner.assert_not_called()

if __name__ == "__main__":
    unittest.main()
