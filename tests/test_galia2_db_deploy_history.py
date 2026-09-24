import unittest
from dataclasses import replace
from datetime import datetime, timezone

from galia2.db_deploy.history import (
    AppliedMigrationRecord,
    HistoryStatus,
    HistoryValidationError,
    append_applied_record,
    validate_candidate_against_history,
    verify_artifact_identity,
    verify_history,
)
from galia2.db_deploy.models import ChangeClass, MigrationCandidate

H1 = "1" * 64
H2 = "2" * 64
E1 = "a" * 64
E2 = "b" * 64
S1 = "c" * 64
S2 = "d" * 64
NOW = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)


def candidate(
    migration_id="M001",
    migration_sha256=H1,
    before="1",
    after="2",
):
    return MigrationCandidate(
        candidate_id=f"candidate-{migration_id}",
        migration_id=migration_id,
        parent_schema_version=before,
        target_schema_version=after,
        migration_sha256=migration_sha256,
        change_class=ChangeClass.ADDITIVE,
        destructive=False,
    )


class AppliedMigrationHistoryTests(unittest.TestCase):
    def test_append_builds_hash_chained_history(self):
        first = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        second = append_applied_record(
            records=first,
            candidate=candidate("M002", H2, "2", "3"),
            schema_fingerprint_after=S2,
            evidence_sha256=E2,
            receipt_id="receipt-2",
            applied_at=NOW,
        )
        self.assertEqual(second[0].sequence, 1)
        self.assertEqual(second[1].sequence, 2)
        self.assertEqual(second[1].previous_record_hash, second[0].record_hash)
        self.assertEqual(verify_history(second), second)

    def test_record_hash_detects_history_tampering(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        tampered = (replace(history[0], schema_version_after="999"),)
        with self.assertRaises(HistoryValidationError):
            verify_history(tampered)

    def test_artifact_identity_detects_edited_applied_migration(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        with self.assertRaisesRegex(
            HistoryValidationError, "applied migration mutated"
        ):
            verify_artifact_identity(history, {"M001": H2})

    def test_artifact_identity_detects_missing_applied_migration(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        with self.assertRaisesRegex(
            HistoryValidationError, "artifact missing"
        ):
            verify_artifact_identity(history, {})

    def test_exact_replay_is_identified_not_reapplied(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        decision = validate_candidate_against_history(candidate(), history)
        self.assertEqual(decision.status, HistoryStatus.ALREADY_APPLIED)

    def test_same_migration_id_with_different_bytes_fails_closed(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        with self.assertRaisesRegex(HistoryValidationError, "reused"):
            validate_candidate_against_history(
                candidate(migration_sha256=H2),
                history,
            )

    def test_parent_schema_must_match_applied_head(self):
        history = append_applied_record(
            records=(),
            candidate=candidate(),
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
        )
        with self.assertRaisesRegex(HistoryValidationError, "parent schema"):
            validate_candidate_against_history(
                candidate("M002", H2, "7", "8"),
                history,
            )

    def test_broken_previous_hash_is_rejected(self):
        first = AppliedMigrationRecord.create(
            sequence=1,
            migration_id="M001",
            migration_sha256=H1,
            schema_version_before="1",
            schema_version_after="2",
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
            previous_record_hash=None,
        )
        second = AppliedMigrationRecord.create(
            sequence=2,
            migration_id="M002",
            migration_sha256=H2,
            schema_version_before="2",
            schema_version_after="3",
            schema_fingerprint_after=S2,
            evidence_sha256=E2,
            receipt_id="receipt-2",
            applied_at=NOW,
            previous_record_hash="f" * 64,
        )
        with self.assertRaisesRegex(HistoryValidationError, "chain break"):
            verify_history((first, second))

    def test_schema_lineage_break_is_rejected_even_with_valid_hash_chain(self):
        first = AppliedMigrationRecord.create(
            sequence=1,
            migration_id="M001",
            migration_sha256=H1,
            schema_version_before="1",
            schema_version_after="2",
            schema_fingerprint_after=S1,
            evidence_sha256=E1,
            receipt_id="receipt-1",
            applied_at=NOW,
            previous_record_hash=None,
        )
        second = AppliedMigrationRecord.create(
            sequence=2,
            migration_id="M002",
            migration_sha256=H2,
            schema_version_before="99",
            schema_version_after="100",
            schema_fingerprint_after=S2,
            evidence_sha256=E2,
            receipt_id="receipt-2",
            applied_at=NOW,
            previous_record_hash=first.record_hash,
        )
        with self.assertRaisesRegex(HistoryValidationError, "schema lineage"):
            verify_history((first, second))


if __name__ == "__main__":
    unittest.main()
