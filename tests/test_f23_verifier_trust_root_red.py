"""Fail-closed contract: untrusted issuers cannot be admitted."""
import unittest
from galia2.authority import AuthorityScope
from galia2.f23_verified_scope_gate import VerifiedScopeAttestation, bind_with_verified_scope

class PermissiveVerifierMustNotAuthorize(unittest.TestCase):
    def test_reject_arbitrary_always_true_verifier(self):
        attestation = VerifiedScopeAttestation(
            decision_id="synthetic-decision", reviewer_id="unknown-reviewer",
            issuer_id="untrusted-issuer", case_id="case-A",
            target_type="external-candidate", target_ids=("candidate-A",),
            reconciliation_sha256="a"*64, candidate_set_sha256="b"*64,
            conflict_component_sha256="c"*64, selected_candidate_id="candidate-A")
        reconciliation = {
            "reconciliation_sha256":"a"*64, "candidate_set_sha256":"b"*64,
            "reconciled_component_sha256":"c"*64, "selected_candidate_id":"candidate-A"}
        scope = AuthorityScope(case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",))
        with self.assertRaisesRegex(ValueError, "trusted issuer verification unavailable"):
            bind_with_verified_scope(
                reconciliation, attestation=attestation,
                p5_scope=scope,
                expected_provider_id="provider-A", expected_external_scope="external-A")

if __name__ == "__main__":
    unittest.main()
