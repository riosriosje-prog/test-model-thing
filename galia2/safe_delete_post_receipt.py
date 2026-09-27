"""Post-delete receipt verification for GALIA SAFE_DELETE v9."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

EXPECTED_TARGET_COUNT = 27


def verify_post_delete_receipt(
    execution_result: Mapping[str, Any],
    post_inventory_library_ids: Sequence[str],
    sealed_vault_library_ids: Sequence[str],
    expected_sealed_vault_library_ids: Sequence[str],
) -> dict[str, Any]:
    deleted = tuple(execution_result.get("deleted_library_file_ids") or ())
    post_ids = set(post_inventory_library_ids)
    sealed_ids = set(sealed_vault_library_ids)
    expected_sealed = set(expected_sealed_vault_library_ids)

    deleted_absent = all(x not in post_ids for x in deleted)
    sealed_intact = sealed_ids == expected_sealed
    exact_count = len(deleted) == EXPECTED_TARGET_COUNT

    status = "PASS" if deleted_absent and sealed_intact and exact_count else "FAIL"
    return {
        "status": status,
        "deleted_absent": deleted_absent,
        "sealed_vault_intact": sealed_intact,
        "deleted_count_exact": exact_count,
        "deleted_count": len(deleted),
    }
