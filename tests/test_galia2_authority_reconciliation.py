import copy
import hashlib
import unittest

from galia2 import authority_reconciliation as f22


def x(value):
    return hashlib.sha256(value.encode()).hexdigest()


def c(cid, p="P", s="receipt-signing", k="K1", start="2026-01-01T00:00:00Z", end=None, tag="a", assertion="ACTIVE"):
    return f22.seal_candidate({"candidate_id": cid, "provider_id": p, "scope": s, "key_id": k, "key_sha256": x("key" + k), "source_artifact_sha256": x("artifact" + tag), "lineage_sha256": x("lineage" + tag), "valid_from_utc": start, "valid_until_utc": end, "authority_assertion": assertion})


class TestAuthorityReconciliation(unittest.TestCase):
    def test_same_key_corroborated(self):
        self.assertEqual(f22.reconcile([c("A", tag="1"), c("B", tag="2")])["authority_state"], "SAME_KEY_CORROBORATED")

    def test_overlap_distinct_keys_requires_human_selection(self):
        result = f22.reconcile([c("A", k="K1"), c("B", k="K2")])
        self.assertEqual(result["conflict_state"], "CONFLICT_DETECTED")
        self.assertEqual(result["authority_state"], "AUTHORITY_UNRESOLVED")
        self.assertEqual(result["action_required"], "HUMAN_SELECTION_REQUIRED")
        self.assertIsNone(result["selected_candidate_id"])

    def test_distinct_scopes_are_compatible(self):
        self.assertEqual(f22.reconcile([c("A", s="receipt-signing"), c("B", s="timestamp-signing")])["authority_state"], "NON_OVERLAPPING_COMPATIBLE")

    def test_distinct_providers_are_compatible(self):
        self.assertEqual(f22.reconcile([c("A", p="P1"), c("B", p="P2")])["authority_state"], "NON_OVERLAPPING_COMPATIBLE")

    def test_partial_overlap_conflicts(self):
        self.assertEqual(f22.reconcile([c("A", k="K1", end="2026-06-01T00:00:00Z"), c("B", k="K2", start="2026-05-01T00:00:00Z")])["action_required"], "HUMAN_SELECTION_REQUIRED")

    def test_half_open_boundary_is_non_overlapping(self):
        self.assertEqual(f22.reconcile([c("A", k="K1", end="2026-06-01T00:00:00Z"), c("B", k="K2", start="2026-06-01T00:00:00Z")])["authority_state"], "NON_OVERLAPPING_COMPATIBLE")

    def test_contradictory_revocation_requires_human_selection(self):
        result = f22.reconcile([c("A", k="K1", assertion="ACTIVE"), c("B", k="K1", assertion="REVOKED")])
        self.assertEqual(result["conflict_state"], "CONFLICT_DETECTED")
        self.assertEqual(result["authority_state"], "AUTHORITY_UNRESOLVED")
        self.assertEqual(result["action_required"], "HUMAN_SELECTION_REQUIRED")

    def test_explicit_human_selection_preserves_candidates(self):
        candidates = [c("A", k="K1"), c("B", k="K2")]
        result = f22.reconcile(candidates, f22.make_human_decision(candidates, "A"))
        self.assertEqual(result["conflict_state"], "CONFLICT_DETECTED")
        self.assertEqual(result["authority_state"], "RECONCILED_BY_EXPLICIT_HUMAN_DECISION")
        self.assertIsNone(result["action_required"])
        self.assertEqual({z["candidate_id"] for z in result["preserved_candidates"]}, {"A", "B"})
        self.assertEqual(result["canonical_effect"], "NONE")
        self.assertEqual(result["master_promotion_state"], "AUTHORITY_HOLD")

    def test_candidate_omitted_after_decision_fails_closed(self):
        a, b = c("A", k="K1"), c("B", k="K2")
        decision = f22.make_human_decision([a, b], "A")
        with self.assertRaises(ValueError):
            f22.reconcile([a], decision)
        with self.assertRaisesRegex(ValueError, "candidate set mismatch"):
            f22.reconcile([a, c("C", k="K3")], decision)

    def test_candidate_hash_tamper_fails_closed(self):
        a, b = c("A", k="K1"), c("B", k="K2")
        bad = copy.deepcopy(a)
        bad["source_artifact_sha256"] = x("tampered")
        with self.assertRaisesRegex(ValueError, "candidate hash mismatch"):
            f22.reconcile([bad, b])

    def test_authority_assertion_tamper_fails_closed(self):
        a, b = c("A", k="K1"), c("B", k="K2")
        bad = copy.deepcopy(a)
        bad["authority_assertion"] = "REVOKED"
        with self.assertRaisesRegex(ValueError, "candidate hash mismatch"):
            f22.reconcile([bad, b])

    def test_decision_over_different_set_fails_closed(self):
        a, b = c("A", k="K1"), c("B", k="K2")
        decision = f22.make_human_decision([a, b], "A")
        decision["candidate_set_sha256"] = x("other")
        with self.assertRaises(ValueError):
            f22.reconcile([a, b], decision)

    def test_rejected_candidate_is_preserved(self):
        candidates = [c("A", k="K1"), c("B", k="K2")]
        result = f22.reconcile(candidates, f22.make_human_decision(candidates, "A"))
        self.assertEqual({z["candidate_id"] for z in result["preserved_candidates"]}, {"A", "B"})

    def test_majority_is_not_authority(self):
        result = f22.reconcile([c("A", k="K1", tag="1"), c("B", k="K1", tag="2"), c("C", k="K2", tag="3")])
        self.assertEqual(result["conflict_state"], "CONFLICT_DETECTED")
        self.assertEqual(result["authority_state"], "AUTHORITY_UNRESOLVED")
        self.assertEqual(result["action_required"], "HUMAN_SELECTION_REQUIRED")

    def test_recency_is_not_authority(self):
        result = f22.reconcile([c("A", k="K1", start="2026-01-01T00:00:00Z"), c("B", k="K2", start="2026-09-01T00:00:00Z")])
        self.assertEqual(result["conflict_state"], "CONFLICT_DETECTED")
        self.assertEqual(result["authority_state"], "AUTHORITY_UNRESOLVED")
        self.assertEqual(result["action_required"], "HUMAN_SELECTION_REQUIRED")


if __name__ == "__main__":
    unittest.main()
