import unittest
from dataclasses import FrozenInstanceError
from datetime import date, datetime, timezone

from galia2.core import (
    AuthorityDecision,
    AuthorityState,
    Case,
    CaseState,
    Claim,
    ClaimType,
    Derivation,
    Discrepancy,
    DiscrepancyState,
    EvidenceState,
    Receipt,
    SourceArtifact,
    Stage,
    StageState,
)

H = "a" * 64


class CoreSchemaTests(unittest.TestCase):
    def test_case_requires_timezone_aware_timestamp(self):
        with self.assertRaises(ValueError):
            Case("c1", "Taft", "scope", CaseState.OPEN, datetime.now(), "v1")

    def test_source_artifact_is_immutable_and_hash_normalized(self):
        src = SourceArtifact("a1", "AGPR", "ref", date(1915, 1, 1), None, H.upper(), "VERIFIED")
        self.assertEqual(src.sha256, H)
        with self.assertRaises(FrozenInstanceError):
            src.repository = "other"

    def test_source_artifact_rejects_non_sha256(self):
        with self.assertRaises(ValueError):
            SourceArtifact("a1", "AGPR", "ref", None, None, "bad", "VERIFIED")

    def test_derivation_preserves_prompt_engine_separation(self):
        d = Derivation("d1", "a1", "OCR", "engine-2", "prompt-7", "attempt-1", H)
        self.assertEqual(d.engine_version, "engine-2")
        self.assertEqual(d.prompt_version, "prompt-7")
        self.assertNotEqual(d.engine_version, d.prompt_version)

    def test_claim_rejects_reverse_validity_interval(self):
        with self.assertRaises(ValueError):
            Claim(
                "cl1", "c1", "Taft", "EXISTS", "street",
                date(1920, 1, 1), date(1919, 1, 1),
                ClaimType.OBSERVED, EvidenceState.SUPPORTED, AuthorityState.HOLD,
            )

    def test_discrepancy_requires_two_unique_objects(self):
        with self.assertRaises(ValueError):
            Discrepancy("x1", ("a",), "TEMPORAL", "MATERIAL", DiscrepancyState.OPEN)
        with self.assertRaises(ValueError):
            Discrepancy("x2", ("a", "a"), "TEMPORAL", "MATERIAL", DiscrepancyState.OPEN)

    def test_stage_rejects_self_dependency(self):
        with self.assertRaises(ValueError):
            Stage("s1", "c1", "NORMALIZE", StageState.INGESTED, dependencies=("s1",))

    def test_authority_decision_requires_evidence_snapshot(self):
        with self.assertRaises(ValueError):
            AuthorityDecision(
                "ad1", "cl1", "human", "PROMOTE", "claim", (),
                datetime.now(timezone.utc),
            )

    def test_receipt_validates_all_hashes(self):
        Receipt(
            "r1", "INGEST", None, (H,), "commit-1", (H,), "policy-v1", "system",
            datetime.now(timezone.utc), "PASS",
        )
        with self.assertRaises(ValueError):
            Receipt(
                "r2", "INGEST", None, ("bad",), None, (), "policy-v1", "system",
                datetime.now(timezone.utc), "FAIL",
            )


if __name__ == "__main__":
    unittest.main()
