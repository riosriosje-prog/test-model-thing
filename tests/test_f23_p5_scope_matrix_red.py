"""F23/P5 contract matrix — synthetic fixture, not authority evidence.

A caller-supplied scope is NOT proof of human authorization. The explicit
scope-to-F22 mapping used here is a proposed contract for a future trusted
decision verifier, not an implemented or authenticated mapping.
"""
import unittest
from unittest.mock import patch
from galia2.authority import AuthorityScope
from galia2 import reconciliation_authority_binding as f23


def fixture():
    candidate = {"candidate_id": "candidate-A", "provider_id": "provider-A", "scope": "external-A"}
    body = {
        "schema_version": f23.f22.SCHEMA,
        "conflict_state": "CONFLICT_DETECTED",
        "authority_state": "RECONCILED_BY_EXPLICIT_HUMAN_DECISION",
        "action_required": None,
        "candidate_set_sha256": "a" * 64,
        "reconciled_component_sha256": "b" * 64,
        "selected_candidate_id": "candidate-A",
        "conflict_components": [{"component_sha256": "b" * 64, "authority_state": "RECONCILED_BY_EXPLICIT_HUMAN_DECISION", "candidate_ids": ["candidate-A"]}],
        "preserved_candidates": [candidate],
        "canonical_effect": "NONE",
        "master_promotion_state": "AUTHORITY_HOLD",
        "byte_identity_effect": "NONE",
        "f5_effect": "NONE",
    }
    return dict(body, reconciliation_sha256=f23.f22._hash(body))


EXPECTED = AuthorityScope(case_id="case-A", target_type="external-candidate", target_ids=("candidate-A",))


class ScopeMatrix(unittest.TestCase):
    def bind(self, scope):
        return f23.bind_reconciliation(
            fixture(),
            expected_candidate_set_sha256="a" * 64,
            expected_component_sha256="b" * 64,
            expected_selected_candidate_id="candidate-A",
            expected_provider_id="provider-A",
            expected_external_scope="external-A",
            p5_scope=scope,
        )

    def test_control_valid_synthetic_scope_reaches_binding(self):
        with patch.object(f23.f22, "validate_candidate", return_value=None):
            result = self.bind(EXPECTED)
        self.assertEqual(result.p5_scope_token, EXPECTED.token)
        self.assertEqual(result.canonical_effect, "NONE")
        self.assertEqual(result.master_promotion_state, "AUTHORITY_HOLD")

    def test_reject_foreign_case_id(self):
        scope = AuthorityScope(case_id="foreign-case", target_type=EXPECTED.target_type, target_ids=EXPECTED.target_ids)
        self.assert_scope_rejected(scope)

    def test_reject_foreign_target_type(self):
        scope = AuthorityScope(case_id=EXPECTED.case_id, target_type="foreign-type", target_ids=EXPECTED.target_ids)
        self.assert_scope_rejected(scope)

    def test_reject_foreign_target_ids(self):
        scope = AuthorityScope(case_id=EXPECTED.case_id, target_type=EXPECTED.target_type, target_ids=("foreign-candidate",))
        self.assert_scope_rejected(scope)

    def assert_scope_rejected(self, scope):
        with patch.object(f23.f22, "validate_candidate", return_value=None):
            with self.assertRaisesRegex(ValueError, "(?i)(p5|scope|case|target|authority)"):
                self.bind(scope)


if __name__ == "__main__":
    unittest.main()
