"""GALIA SAFE_DELETE v10 Library batching adapter.

Corrects the v9 abstract adapter to honor the real personal Library mutation
limit of 20 operations per manage call. This module is connector-agnostic and
does not import or call Files/Library tools directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .delete_authorization import evaluate_delete_authorization

MAX_LIBRARY_OPERATIONS_PER_CALL = 20
EXPECTED_TOTAL_TARGETS = 27
EXPECTED_BATCH_SIZES = (20, 7)


@dataclass(frozen=True)
class BatchExecutionResult:
    executed: bool
    state: str
    completed_batches: tuple[str, ...]
    deleted_library_file_ids: tuple[str, ...]
    blockers: tuple[str, ...]
    batch_receipts: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "executed": self.executed,
            "state": self.state,
            "completed_batches": list(self.completed_batches),
            "deleted_library_file_ids": list(self.deleted_library_file_ids),
            "blockers": list(self.blockers),
            "batch_receipts": [dict(x) for x in self.batch_receipts],
        }


def make_batches(targets: Sequence[Mapping[str, Any]]) -> tuple[tuple[Mapping[str, Any], ...], ...]:
    if len(targets) != EXPECTED_TOTAL_TARGETS:
        raise ValueError("TARGET_COUNT_MISMATCH")
    chunks = tuple(
        tuple(targets[i:i + MAX_LIBRARY_OPERATIONS_PER_CALL])
        for i in range(0, len(targets), MAX_LIBRARY_OPERATIONS_PER_CALL)
    )
    if tuple(len(x) for x in chunks) != EXPECTED_BATCH_SIZES:
        raise ValueError("UNEXPECTED_BATCH_SHAPE")
    return chunks


def build_manage_library_delete_ops(batch: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if not 1 <= len(batch) <= MAX_LIBRARY_OPERATIONS_PER_CALL:
        raise ValueError("BATCH_SIZE_OUT_OF_RANGE")
    seen: set[str] = set()
    ops: list[dict[str, Any]] = []
    for idx, target in enumerate(batch):
        library_file_id = target.get("library_file_id")
        if not isinstance(library_file_id, str) or not library_file_id:
            raise ValueError(f"TARGET_{idx}:LIBRARY_FILE_ID_MISSING")
        if library_file_id in seen:
            raise ValueError(f"TARGET_{idx}:DUPLICATE_LIBRARY_FILE_ID")
        seen.add(library_file_id)
        ops.append({
            "operation": "delete",
            "target": {
                "kind": "file",
                "library_file_id": library_file_id,
            },
        })
    return tuple(ops)


def execute_batched_authorized_deletion(
    targets: Sequence[Mapping[str, Any]],
    authorization_receipt: Mapping[str, Any] | None,
    revalidate_batch: Callable[[str, Sequence[Mapping[str, Any]]], Mapping[str, Any]],
    delete_batch_adapter: Callable[[str, tuple[dict[str, Any], ...]], Sequence[Mapping[str, Any]]],
    *,
    commit: bool = False,
) -> BatchExecutionResult:
    blockers: list[str] = []
    auth = evaluate_delete_authorization(authorization_receipt)
    if not auth.authorized:
        blockers.extend(f"AUTH:{x}" for x in auth.blockers)
    if not commit:
        blockers.append("COMMIT_FLAG_REQUIRED")
    if len(targets) != EXPECTED_TOTAL_TARGETS:
        blockers.append("TARGET_COUNT_MISMATCH")

    if blockers:
        return BatchExecutionResult(
            executed=False,
            state="EXECUTION_HOLD",
            completed_batches=(),
            deleted_library_file_ids=(),
            blockers=tuple(dict.fromkeys(blockers)),
            batch_receipts=(),
        )

    batches = make_batches(targets)
    completed: list[str] = []
    deleted: list[str] = []
    receipts: list[Mapping[str, Any]] = []

    for ordinal, batch in enumerate(batches, start=1):
        batch_id=f"BATCH-{ordinal:02d}"
        validation=dict(revalidate_batch(batch_id, batch))
        if validation.get("status") != "PASS":
            return BatchExecutionResult(
                executed=False,
                state="PARTIAL_OR_FAILED_EXECUTION" if completed else "PRE_BATCH_REVALIDATION_FAILED",
                completed_batches=tuple(completed),
                deleted_library_file_ids=tuple(deleted),
                blockers=(f"{batch_id}:REVALIDATION_FAILED",),
                batch_receipts=tuple(receipts + [{
                    "batch_id":batch_id,
                    "phase":"PRE_DELETE_REVALIDATION",
                    "status":"FAIL",
                    "details":validation,
                }]),
            )

        ops=build_manage_library_delete_ops(batch)
        raw=tuple(delete_batch_adapter(batch_id, ops))
        receipt={
            "batch_id":batch_id,
            "phase":"DELETE",
            "expected_count":len(ops),
            "result_count":len(raw),
            "results":[dict(x) for x in raw],
        }
        receipts.append(receipt)

        if len(raw) != len(ops):
            return BatchExecutionResult(
                executed=False,
                state="PARTIAL_OR_FAILED_EXECUTION",
                completed_batches=tuple(completed),
                deleted_library_file_ids=tuple(deleted),
                blockers=(f"{batch_id}:RESULT_COUNT_MISMATCH",),
                batch_receipts=tuple(receipts),
            )

        batch_deleted: list[str] = []
        batch_blockers: list[str] = []
        for idx, (op, result) in enumerate(zip(ops, raw)):
            expected_id=op["target"]["library_file_id"]
            if result.get("status") != "succeeded":
                batch_blockers.append(f"{batch_id}:ITEM_{idx}:DELETE_FAILED")
                continue
            returned_id=result.get("library_file_id")
            if returned_id not in (None, expected_id):
                batch_blockers.append(f"{batch_id}:ITEM_{idx}:LIBRARY_ID_MISMATCH")
                continue
            batch_deleted.append(expected_id)

        deleted.extend(batch_deleted)
        if batch_blockers:
            return BatchExecutionResult(
                executed=False,
                state="PARTIAL_OR_FAILED_EXECUTION",
                completed_batches=tuple(completed),
                deleted_library_file_ids=tuple(deleted),
                blockers=tuple(batch_blockers),
                batch_receipts=tuple(receipts),
            )

        completed.append(batch_id)

    if len(deleted) != EXPECTED_TOTAL_TARGETS:
        return BatchExecutionResult(
            executed=False,
            state="PARTIAL_OR_FAILED_EXECUTION",
            completed_batches=tuple(completed),
            deleted_library_file_ids=tuple(deleted),
            blockers=("FINAL_DELETED_COUNT_MISMATCH",),
            batch_receipts=tuple(receipts),
        )

    return BatchExecutionResult(
        executed=True,
        state="EXECUTED_EXACT_SCOPE",
        completed_batches=tuple(completed),
        deleted_library_file_ids=tuple(deleted),
        blockers=(),
        batch_receipts=tuple(receipts),
    )
