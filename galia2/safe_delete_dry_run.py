"""GALIA SAFE_DELETE dry-run planner.

This module produces a deterministic, auditable *would-delete* plan. It has no
connector, filesystem, or Library mutation capability and performs no deletion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .delete_authorization import evaluate_delete_authorization

SEALED_VAULT_PREFIX = "/GALIA_FINAL_VAULT_SEALED_2026-09-26/"
EXPECTED_MANIFEST_SHA256 = (
    "6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708"
)
EXPECTED_VAULT_SHA256 = (
    "53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf"
)
EXPECTED_TARGET_COUNT = 27


@dataclass(frozen=True)
class DryRunPlan:
    executable: bool
    state: str
    blockers: tuple[str, ...]
    targets: tuple[dict[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "state": self.state,
            "blockers": list(self.blockers),
            "targets": list(self.targets),
        }


def build_dry_run_plan(
    manifest: Mapping[str, Any],
    live_inventory: Sequence[Mapping[str, Any]],
    authorization_receipt: Mapping[str, Any] | None,
) -> DryRunPlan:
    blockers: list[str] = []

    if manifest.get("target_count") != EXPECTED_TARGET_COUNT:
        blockers.append("MANIFEST_TARGET_COUNT_MISMATCH")

    targets = manifest.get("targets")
    if not isinstance(targets, list) or len(targets) != EXPECTED_TARGET_COUNT:
        blockers.append("MANIFEST_TARGETS_INVALID")
        targets = []

    live_by_library_id = {
        item.get("library_file_id"): item
        for item in live_inventory
        if isinstance(item, Mapping) and item.get("library_file_id")
    }

    plan_targets: list[dict[str, Any]] = []
    seen_library_ids: set[str] = set()

    for index, target in enumerate(targets):
        if not isinstance(target, Mapping):
            blockers.append(f"TARGET_{index}:INVALID")
            continue

        library_file_id = target.get("library_file_id")
        file_id = target.get("file_id")
        path = target.get("path")
        size = target.get("size_bytes")
        sha256 = target.get("sha256")
        preservation_sha = target.get("preservation_sha256")
        preserved_path = target.get("preserved_in_sealed_vault")

        if not library_file_id or library_file_id in seen_library_ids:
            blockers.append(f"TARGET_{index}:LIBRARY_ID_INVALID_OR_DUPLICATE")
        else:
            seen_library_ids.add(library_file_id)

        if not isinstance(path, str) or path.startswith(SEALED_VAULT_PREFIX):
            blockers.append(f"TARGET_{index}:SEALED_VAULT_TARGET_FORBIDDEN")

        if sha256 != preservation_sha:
            blockers.append(f"TARGET_{index}:PRESERVATION_HASH_MISMATCH")

        if not isinstance(preserved_path, str) or not preserved_path.startswith(SEALED_VAULT_PREFIX):
            blockers.append(f"TARGET_{index}:SEALED_PRESERVATION_PATH_INVALID")

        live = live_by_library_id.get(library_file_id)
        if live is None:
            blockers.append(f"TARGET_{index}:LIVE_OBJECT_MISSING")
        else:
            if live.get("file_id") != file_id:
                blockers.append(f"TARGET_{index}:LIVE_FILE_ID_MISMATCH")
            if live.get("path") != path:
                blockers.append(f"TARGET_{index}:LIVE_PATH_MISMATCH")
            if live.get("size_bytes") != size:
                blockers.append(f"TARGET_{index}:LIVE_SIZE_MISMATCH")

        plan_targets.append({
            "ordinal": index + 1,
            "library_file_id": library_file_id,
            "file_id": file_id,
            "path": path,
            "expected_sha256": sha256,
            "expected_size_bytes": size,
            "preserved_in_sealed_vault": preserved_path,
            "operation": "WOULD_DELETE_LIBRARY_OBJECT",
        })

    auth = evaluate_delete_authorization(authorization_receipt)
    if not auth.authorized:
        blockers.extend(f"AUTH:{x}" for x in auth.blockers)

    blockers = list(dict.fromkeys(blockers))
    executable = not blockers
    state = "AUTHORIZED_EXECUTION_ELIGIBLE" if executable else "DRY_RUN_HOLD"

    return DryRunPlan(
        executable=executable,
        state=state,
        blockers=tuple(blockers),
        targets=tuple(plan_targets),
    )
