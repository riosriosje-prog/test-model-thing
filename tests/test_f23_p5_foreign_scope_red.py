"""RED regression: a foreign P5 scope must never bind to an F22 case.

This test intentionally fails on the current F23 implementation. The expected
case/scope relationship must ultimately be verified against authenticated
human-decision evidence; do not 'fix' this by trusting caller-supplied labels.
"""
import unittest
from unittest.mock import patch

from galia2.authority import AuthorityScope
from galia2 import reconciliation_authority_binding as f23


class ForeignP5ScopeContract(unittest.TestCase):
    def test_reject_foreign_case_scope(self):
        candidate = {
            "candidate_id": "candidate-A",
            "provider_id": "provider-A",
            "scope": "external-A",
        }
        body = {
            "schema_version": f23.f22.SCHEMA,
            "conflict_state": "CONFLICT_DETECTED",
            "authority_state": "RECONCILED_BY_EXPLICIT_HUMAN_DECISION",
            "action_required": None,
            "candidate_set_sha256": "a" * 64,
            "reconciled_component_sha256": "b" * 64,
            "selected_candidate_id": "candidate-A",
            "conflict_components": [{
                "component_sha256": "b" * 64,
                "authority_state": "RECONCILED_BY_EXPLICIT_HUMAN_DECISION",
                "candidate_ids": ["candidate-A"],
            }],
            "preserved_candidates": [candidate],
            "canonical_effect": "NONE",
            "master_promotion_state": "AUTHORITY_HOLD",
            "byte_identity_effect": "NONE",
            "f5_effect": "NONE",
        }
        reconciliation = dict(body, reconciliation_sha256=f23.f22._hash(body))
        foreign_scope = AuthorityScope(
            case_id="unrelated-case",
            target_type="unrelated-target-type",
            target_ids=("unrelated-target",),
        )
        with patch.object(f23.f22, "validate_candidate", return_value=None):
            with self.assertRaises(ValueError, msg="foreign P5 scope must fail closed"):
                f23.bind_reconciliation(
                    reconciliation,
                    expected_candidate_set_sha256="a" * 64,
                    expected_component_sha256="b" * 64,
                    expected_selected_candidate_id="candidate-A",
                    expected_provider_id="provider-A",
                    expected_external_scope="external-A",
                    p5_scope=foreign_scope,
                )


if __name__ == "__main__":
    unittest.main()
