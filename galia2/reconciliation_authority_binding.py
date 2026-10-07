"""GALIA F23 — fail-closed binding from F22 reconciliation to P5 authority.

POC only. This adapter validates an exact F22 reconciliation result before
producing a narrowly scoped external-authority binding. It never mutates a
Claim, emits a P5 promotion authorization, closes F5/BYTE_IDENTITY, or lifts
AUTHORITY_HOLD.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict

from . import authority_reconciliation as f22
from .authority import AuthorityScope

SCHEMA = "GALIA-F23-RECONCILIATION-AUTHORITY-BINDING/1"


@dataclass(frozen=True, slots=True)
class ReconciliationAuthorityBinding:
    schema_version: str
    reconciliation_sha256: str
    candidate_set_sha256: str
    conflict_component_sha256: str
    selected_candidate_id: str
    provider_id: str
    external_scope: str
    p5_scope_token: str
    authority_class: str = "EXTERNAL_AUTHORITY_ONLY"
    canonical_effect: str = "NONE"
    master_promotion_state: str = "AUTHORITY_HOLD"
    byte_identity_effect: str = "NONE"
    f5_effect: str = "NONE"


def bind_reconciliation(
    reconciliation: Dict[str, Any],
    *,
    expected_candidate_set_sha256: str,
    expected_component_sha256: str,
    expected_selected_candidate_id: str,
    expected_provider_id: str,
    expected_external_scope: str,
    p5_scope: AuthorityScope,
) -> ReconciliationAuthorityBinding:
    """Validate exact F22 evidence and bind it to a P5 scope without authority escalation."""
    if reconciliation.get("schema_version") != f22.SCHEMA:
        raise ValueError("F22 schema mismatch")
    supplied_hash = reconciliation.get("reconciliation_sha256")
    body = {k: v for k, v in reconciliation.items() if k != "reconciliation_sha256"}
    if not f22._is_hash(supplied_hash) or supplied_hash != f22._hash(body):
        raise ValueError("F22 reconciliation hash mismatch")
    if reconciliation.get("conflict_state") != "CONFLICT_DETECTED":
        raise ValueError("F23 requires an F22 conflict reconciliation")
    if reconciliation.get("authority_state") != "RECONCILED_BY_EXPLICIT_HUMAN_DECISION":
        raise ValueError("F22 authority is not fully reconciled")
    if reconciliation.get("action_required") is not None:
        raise ValueError("F22 still requires human selection")
    if reconciliation.get("candidate_set_sha256") != expected_candidate_set_sha256:
        raise ValueError("candidate set binding mismatch")
    if reconciliation.get("reconciled_component_sha256") != expected_component_sha256:
        raise ValueError("conflict component binding mismatch")
    if reconciliation.get("selected_candidate_id") != expected_selected_candidate_id:
        raise ValueError("selected candidate binding mismatch")

    components = [
        c for c in reconciliation.get("conflict_components", [])
        if c.get("component_sha256") == expected_component_sha256
    ]
    if len(components) != 1 or components[0].get("authority_state") != "RECONCILED_BY_EXPLICIT_HUMAN_DECISION":
        raise ValueError("component is not explicitly reconciled")
    if expected_selected_candidate_id not in components[0].get("candidate_ids", []):
        raise ValueError("selected candidate outside reconciled component")

    preserved = [
        c for c in reconciliation.get("preserved_candidates", [])
        if c.get("candidate_id") == expected_selected_candidate_id
    ]
    if len(preserved) != 1:
        raise ValueError("selected candidate must be preserved exactly once")
    selected = preserved[0]
    f22.validate_candidate(selected)
    if selected.get("provider_id") != expected_provider_id:
        raise ValueError("provider binding mismatch")
    if selected.get("scope") != expected_external_scope:
        raise ValueError("external scope binding mismatch")

    if reconciliation.get("canonical_effect") != "NONE":
        raise ValueError("canonical effect escalation forbidden")
    if reconciliation.get("master_promotion_state") != "AUTHORITY_HOLD":
        raise ValueError("master authority hold must remain")
    if reconciliation.get("byte_identity_effect") != "NONE" or reconciliation.get("f5_effect") != "NONE":
        raise ValueError("upstream gate closure forbidden")

    return ReconciliationAuthorityBinding(
        schema_version=SCHEMA,
        reconciliation_sha256=supplied_hash,
        candidate_set_sha256=expected_candidate_set_sha256,
        conflict_component_sha256=expected_component_sha256,
        selected_candidate_id=expected_selected_candidate_id,
        provider_id=expected_provider_id,
        external_scope=expected_external_scope,
        p5_scope_token=p5_scope.token,
    )
