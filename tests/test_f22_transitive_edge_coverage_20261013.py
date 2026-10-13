"""F22 transitive temporal conflict coverage — fail-closed regression tests.

A human choice for one vertex of a conflict component cannot silently
reconcile an independent conflicting edge elsewhere in that component.
POC only; not a DW6 identity or authority verification.
"""
import hashlib
import unittest
from galia2 import authority_reconciliation as f22


def h(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def candidate(cid, key, start="2026-01-01T00:00:00Z", end=None):
    return f22.seal_candidate({
        "candidate_id": cid,
        "provider_id": "provider-one",
        "scope": "receipt-signing",
        "key_id": key,
        "key_sha256": h("key-" + key),
        "source_artifact_sha256": h("source-" + cid),
        "lineage_sha256": h("lineage-" + cid),
        "valid_from_utc": start,
        "valid_until_utc": end,
        "authority_assertion": "ACTIVE",
    })


def chain():
    # AB overlap Feb 1–15; BC overlap Feb 15–Mar 1; AC never overlap.
    return [
        candidate("A", "K1", end="2026-02-15T00:00:00Z"),
        candidate("B", "K2", start="2026-02-01T00:00:00Z", end="2026-03-01T00:00:00Z"),
        candidate("C", "K3", start="2026-02-15T00:00:00Z", end="2026-04-01T00:00:00Z"),
    ]


class TestF22TransitiveConflictEdgeCoverage(unittest.TestCase):
    def test_chain_has_two_edges_not_a_c(self):
        result = f22.reconcile(chain())
        self.assertEqual({frozenset(p) for p in result["conflicts"]},
                         {frozenset(("A", "B")), frozenset(("B", "C"))})
        self.assertEqual(len(result["conflict_components"]), 1)

    def test_selecting_endpoint_cannot_settle_other_edge(self):
        candidates = chain()
        decision = f22.make_human_decision(candidates, "A", review_id="HR-edge-A")
        with self.assertRaisesRegex(ValueError, "uncovered conflicting pair"):
            f22.reconcile(candidates, decision)

    def test_selecting_middle_covers_edges_and_preserves_all_candidates(self):
        candidates = chain()
        decision = f22.make_human_decision(candidates, "B", review_id="HR-edge-B")
        result = f22.reconcile(candidates, decision)
        self.assertEqual(result["authority_state"], "RECONCILED_BY_EXPLICIT_HUMAN_DECISION")
        self.assertEqual({c["candidate_id"] for c in result["preserved_candidates"]},
                         {"A", "B", "C"})
        self.assertEqual(result["canonical_effect"], "NONE")
        self.assertEqual(result["master_promotion_state"], "AUTHORITY_HOLD")

    def test_triangle_requires_granular_decisions_not_single_winner(self):
        candidates = [candidate("A", "K1"), candidate("B", "K2"), candidate("C", "K3")]
        for selected in ("A", "B", "C"):
            with self.subTest(selected=selected):
                with self.assertRaisesRegex(ValueError, "uncovered conflicting pair"):
                    f22.reconcile(candidates, f22.make_human_decision(
                        candidates, selected, review_id="HR-triangle-" + selected))

    def test_single_conflict_pair_remains_supported(self):
        candidates = [candidate("A", "K1"), candidate("B", "K2")]
        result = f22.reconcile(candidates, f22.make_human_decision(
            candidates, "A", review_id="HR-single-pair"))
        self.assertEqual(result["authority_state"], "RECONCILED_BY_EXPLICIT_HUMAN_DECISION")


if __name__ == "__main__":
    unittest.main()
