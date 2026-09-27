"""GALIA SAFE_DELETE execution core.

This module is tool-agnostic. It can invoke an injected deletion adapter only
after an exact authorization receipt and an execution-eligible v8 plan are both
present. It never imports or calls Library/filesystem APIs directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .delete_authorization import evaluate_delete_authorization

EXPECTED_TARGET_COUNT = 27
EXPECTED_OPERATION = "WOULD_DELETE_LIBRARY_OBJECT"
EXECUTION_SCOPE = "EXACT_27_TARGETS_IN_PROMOTED_DELETION_MANIFEST_ONLY"


@dataclass(frozen=True)
class ExecutionResult:
    executed: bool
    state: str
    deleted_library_file_ids: tuple[str, ...]
    blockers: tuple[str, ...]
    adapter_results: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "executed": self.executed,
            "state": self.state,
            "deleted_library_file_ids": list(self.deleted_library_file_ids),
            "blockers": list(self.blockers),
            "adapter_results": [dict(x) for x in self.adapter_results],
        }


def build_library_delete_operations(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Build exact Files-compatible delete descriptors. Does not execute them."""
    blockers: list[str] = []

    if plan.get("state") != "AUTHORIZED_EXECUTION_ELIGIBLE":
        blockers.append("PLAN_NOT_EXECUTION_ELIGIBLE")

    targets = plan.get("targets")
    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
        raise ValueError("PLAN_TARGETS_INVALID")

    operations: list[dict[str, Any]] = []
    seen: set[str] = set()

    for index, target in enumerate(targets):
        if not isinstance(target, Mapping):
            raise ValueError(f"TARGET_{index}:INVALID")

        if target.get("operation") != EXPECTED_OPERATION:
            raise ValueError(f"TARGET_{index}:OPERATION_INVALID")

        library_file_id = target.get("library_file_id")
        if not isinstance(library_file_id, str) or not library_file_id:
            raise ValueError(f"TARGET_{index}:LIBRARY_FILE_ID_MISSING")
        if library_file_id in seen:
            raise ValueError(f"TARGET_{index}:DUPLICATE_LIBRARY_FILE_ID")
        seen.add(library_file_id)

        operations.append({
            "operation": "delete",
            "target": {
                "kind": "file",
                "library_file_id": library_file_id,
            },
        })

    if blockers:
        raise PermissionError(",".join(blockers))

    if len(operations) != EXPECTED_TARGET_COUNT:
        raise ValueError("TARGET_COUNT_MISMATCH")

    return tuple(operations)


def execute_authorized_deletion(
    plan: Mapping[str, Any],
    authorization_receipt: Mapping[str, Any] | None,
    delete_adapter: Callable[[tuple[dict[str, Any], ...]], Sequence[Mapping[str, Any]]],
    *,
    commit: bool = False,
) -> ExecutionResult:
    """Execute only when commit=True and exact authorization/plan checks pass."""

    blockers: list[str] = []

    auth = evaluate_delete_authorization(authorization_receipt)
    if not auth.authorized:
        blockers.extend(f"AUTH:{x}" for x in auth.blockers)

    if plan.get("state") != "AUTHORIZED_EXECUTION_ELIGIBLE":
        blockers.append("PLAN_NOT_EXECUTION_ELIGIBLE")
    if plan.get("executable") is not True:
        blockers.append("PLAN_EXECUTABLE_TRUE_REQUIRED")

    targets = plan.get("targets")
    if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
        blockers.append("PLAN_TARGETS_INVALID")
        targets = []

    if len(targets) != EXPECTED_TARGET_COUNT:
        blockers.append("TARGET_COUNT_MISMATCH")

    if not commit:
        blockers.append("COMMIT_FLAG_REQUIRED")

    blockers = list(dict.fromkeys(blockers))
    if blockers:
        return ExecutionResult(
            executed=False,
            state="EXECUTION_HOLD",
            deleted_library_file_ids=(),
            blockers=tuple(blockers),
            adapter_results=(),
        )

    operations = build_library_delete_operations(plan)
    raw_results = tuple(delete_adapter(operations))

    deleted: list[str] = []
    adapter_blockers: list[str] = []
    for index, (op, result) in enumerate(zip(operations, raw_results)):
        expected_id = op["target"]["library_file_id"]
        if result.get("status") != "succeeded":
            adapter_blockers.append(f"ADAPTER_{index}:DELETE_FAILED")
            continue
        returned_id = result.get("library_file_id")
        if returned_id not in (None, expected_id):
            adapter_blockers.append(f"ADAPTER_{index}:LIBRARY_ID_MISMATCH")
            continue
        deleted.append(expected_id)

    if len(raw_results) != len(operations):
        adapter_blockers.append("ADAPTER_RESULT_COUNT_MISMATCH")

    if adapter_blockers:
        return ExecutionResult(
            executed=False,
            state="PARTIAL_OR_FAILED_EXECUTION",
            deleted_library_file_ids=tuple(deleted),
            blockers=tuple(adapter_blockers),
            adapter_results=raw_results,
        )

    return ExecutionResult(
        executed=True,
        state="EXECUTED_EXACT_SCOPE",
        deleted_library_file_ids=tuple(deleted),
        blockers=(),
        adapter_results=raw_results,
    )
