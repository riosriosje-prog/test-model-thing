"""GALIA F22/3 candidate: deterministic, non-authoritative reconciliation preview.

This additive module preserves F22/2 receipts unchanged. It does not accept
human decisions, authenticate human authority, or authorize F23/P5 binding.
It never writes canonical state or changes AUTHORITY_HOLD.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from . import authority_reconciliation as f22

SCHEMA = "GALIA-F22-RECONCILIATION/3-PREVIEW"
SERIALIZATION_POLICY = "F22-V3-PREVIEW-CANDIDATE-ID-ORDER/1"


def preview_reconciliation(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a permutation-stable, fail-closed F22 *preview* only.

    The full candidate records and their original hashes are retained, but
    ordered canonically by candidate_id. No decision is accepted or inferred.
    Historic F22/2 reconciliation hashes must be verified with the old schema.
    """
    if not isinstance(candidates, list):
        raise ValueError("candidate list required")
    # Legacy F22 performs candidate hash validation and duplicate-ID rejection.
    # Sorting is applied to a deep copy; no caller artifact is modified.
    ordered = deepcopy(sorted(candidates, key=lambda c: c["candidate_id"]))
    result = f22.reconcile(ordered)
    if result["selected_candidate_id"] is not None or result["reconciled_component_sha256"] is not None:
        raise ValueError("preview must not select external authority")
    result.pop("reconciliation_sha256")
    result["schema_version"] = SCHEMA
    result["serialization_policy"] = SERIALIZATION_POLICY
    result["legacy_schema_version"] = f22.SCHEMA
    result["binding_eligibility"] = "BLOCKED_PENDING_HUMAN_PROVENANCE_AND_TEMPORAL_GATES"
    result["canonical_effect"] = "NONE"
    result["master_promotion_state"] = "AUTHORITY_HOLD"
    result["reconciliation_sha256"] = f22._hash(result)
    return result
