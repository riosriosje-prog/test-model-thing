"""Shadow-only execution adapter for database migrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from galia2.orchestrator import FailureKind, StageExecution, StageExecutionFailure

from .fingerprint import schema_fingerprint
from .models import DBMigrationEvidence, MigrationCandidate


class UncertainExecutionOutcome(RuntimeError):
    """The caller cannot determine whether the DB operation committed."""

    def __init__(self, message: str, *, commit_may_have_occurred: bool) -> None:
        super().__init__(message)
        self.commit_may_have_occurred = bool(commit_may_have_occurred)


@dataclass(frozen=True, slots=True)
class ShadowApplyResult:
    after_schema_descriptor: object
    output_ref: str
    backfill_result: str = "NOT_REQUIRED"
    compatibility_result: str = "PASS"


@dataclass(frozen=True, slots=True)
class DBMigrationExecution:
    evidence: DBMigrationEvidence
    output_ref: str

    def as_stage_execution(self) -> StageExecution:
        return StageExecution(
            output_refs=(self.output_ref,),
            output_hashes=(self.evidence.sha256, self.evidence.schema_fingerprint_after),
            guards=frozenset({"output_hash_valid"}),
        )


ShadowApply = Callable[[MigrationCandidate], ShadowApplyResult]


def execute_shadow(
    *,
    candidate: MigrationCandidate,
    before_schema_descriptor: object,
    apply_shadow: ShadowApply,
) -> DBMigrationExecution:
    """Execute against a caller-provided shadow target only.

    c1 intentionally has no production connection primitive.
    """
    before = schema_fingerprint(before_schema_descriptor)
    try:
        result = apply_shadow(candidate)
    except UncertainExecutionOutcome as exc:
        raise StageExecutionFailure(
            FailureKind.PERSISTENCE,
            f"uncertain database execution outcome: {exc}",
        ) from exc
    except StageExecutionFailure:
        raise
    except Exception as exc:
        raise StageExecutionFailure(
            FailureKind.INTEGRITY,
            f"shadow migration failed: {type(exc).__name__}: {exc}",
        ) from exc

    if not isinstance(result, ShadowApplyResult):
        raise TypeError("apply_shadow must return ShadowApplyResult")
    if not result.output_ref.strip():
        raise ValueError("shadow output_ref must be non-empty")

    after = schema_fingerprint(result.after_schema_descriptor)
    evidence = DBMigrationEvidence(
        candidate_id=candidate.candidate_id,
        migration_id=candidate.migration_id,
        migration_sha256=candidate.migration_sha256,
        change_class=candidate.change_class,
        schema_version_before=candidate.parent_schema_version,
        schema_version_after=candidate.target_schema_version,
        schema_fingerprint_before=before,
        schema_fingerprint_after=after,
        shadow_result="PASS",
        backfill_result=result.backfill_result,
        compatibility_result=result.compatibility_result,
        destructive_change=candidate.destructive,
    )
    return DBMigrationExecution(evidence=evidence, output_ref=result.output_ref)
