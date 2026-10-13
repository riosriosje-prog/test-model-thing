"""RED security contract: caller-supplied approval is not a trust root.

Do not treat this test as passing until a repository-controlled verifier
authenticates the decision against a configured trusted issuer and scope.
"""
import unittest
from unittest.mock import patch
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
        # If bind_reconciliation is reached, the caller has bypassed the trust gate.
        with patch("galia2.f23_verified_scope_gate.bind_reconciliation", return_value="UNSAFE_BIND") as inner:
            with self.assertRaisesRegex(ValueError, "(?i)(trust|issuer|authentic|verifier)"):
                bind_with_verified_scope(
                    reconciliation, attestation=attestation,
                    verify_attestation=lambda _: True, p5_scope=scope,
                    expected_provider_id="provider-A", expected_external_scope="external-A")
            inner.assert_not_called()

if __name__ == "__main__":
    unittest.main()
