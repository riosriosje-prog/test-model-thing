"""GALIA StageOrchestrator validators for DB migration evidence."""

from __future__ import annotations

from galia2.orchestrator import FailureKind, StageValidation

from .executor import DBMigrationExecution
from .models import MigrationCandidate


def requires_authority_hold(candidate: MigrationCandidate) -> bool:
    return bool(candidate.destructive)


def validate_execution(
    *,
    candidate: MigrationCandidate,
    execution: DBMigrationExecution,
) -> StageValidation:
    evidence = execution.evidence

    identity_ok = (
        evidence.candidate_id == candidate.candidate_id
        and evidence.migration_id == candidate.migration_id
        and evidence.migration_sha256 == candidate.migration_sha256
        and evidence.change_class == candidate.change_class
        and evidence.schema_version_before == candidate.parent_schema_version
        and evidence.schema_version_after == candidate.target_schema_version
        and evidence.destructive_change == candidate.destructive
    )
    if not identity_ok:
        return StageValidation(
            passed=False,
            failure_kind=FailureKind.INTEGRITY,
            message="migration evidence does not match exact candidate identity",
        )

    if evidence.shadow_result != "PASS":
        return StageValidation(
            passed=False,
            failure_kind=FailureKind.INTEGRITY,
            message="shadow execution did not pass",
        )

    if evidence.compatibility_result != "PASS":
        return StageValidation(
            passed=False,
            failure_kind=FailureKind.MATERIAL_CONFLICT,
            message="compatibility validation did not pass",
        )

    if evidence.backfill_result not in {"PASS", "NOT_REQUIRED"}:
        return StageValidation(
            passed=False,
            failure_kind=FailureKind.INTEGRITY,
            message="backfill validation did not pass",
        )

    return StageValidation(
        passed=True,
        guards=frozenset({
            "required_validations_passed",
            "schema_fingerprint_valid",
            "compatibility_checked",
        }),
    )
