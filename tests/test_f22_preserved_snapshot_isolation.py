"""F22 candidate-only regression: preserve immutable evidence snapshots.

A passing test does not authenticate a custodian or promote master authority.
"""
import hashlib
import unittest

from galia2 import authority_reconciliation as f22


def candidate(candidate_id, key_id):
    digest = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f22.seal_candidate({
        "candidate_id": candidate_id,
        "provider_id": "provider-A",
        "scope": "receipt-signing",
        "key_id": key_id,
        "key_sha256": digest(key_id),
        "source_artifact_sha256": digest("artifact-" + candidate_id),
        "lineage_sha256": digest("lineage-" + candidate_id),
        "valid_from_utc": "2026-01-01T00:00:00Z",
        "valid_until_utc": None,
        "authority_assertion": "ACTIVE",
        "custody_metadata": {"transmission": {"chain": ["source", "custodian"]}},
    })


class F22SnapshotIsolationTests(unittest.TestCase):
    def test_input_nested_mutation_cannot_rewrite_preserved_snapshot(self):
        candidates = [candidate("A", "K1"), candidate("B", "K2")]
        result = f22.reconcile(candidates)
        candidates[0]["custody_metadata"]["transmission"]["chain"][1] = "tampered"
        self.assertEqual(
            result["preserved_candidates"][0]["custody_metadata"]["transmission"]["chain"],
            ["source", "custodian"],
        )
        expected = f22._hash({k: v for k, v in result.items() if k != "reconciliation_sha256"})
        self.assertEqual(result["reconciliation_sha256"], expected)
        self.assertEqual(result["canonical_effect"], "NONE")
        self.assertEqual(result["master_promotion_state"], "AUTHORITY_HOLD")

    def test_result_nested_mutation_cannot_rewrite_source_artifact(self):
        candidates = [candidate("A", "K1"), candidate("B", "K2")]
        result = f22.reconcile(candidates)
        result["preserved_candidates"][0]["custody_metadata"]["transmission"]["chain"][0] = "changed"
        self.assertEqual(
            candidates[0]["custody_metadata"]["transmission"]["chain"],
            ["source", "custodian"],
        )


if __name__ == "__main__":
    unittest.main()
