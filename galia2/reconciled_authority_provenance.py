"""GALIA F24 — reconciled-authority provenance chain.

Additive POC. Seals references across F22 -> F23 -> P5/P6 -> P7 without
granting authority or changing publication state.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib, json, re

from .reconciliation_authority_binding import ReconciliationAuthorityBinding
from .authority import PromotionAuthorization
from .preflight import PreflightReport
from .persistence import PromotionEnvelope

_SHA = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "GALIA-F24-RECONCILED-AUTHORITY-PROVENANCE/1"

def _hash(v):
    return hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def _sha(name, value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{name} must be lowercase SHA-256")
    return value

@dataclass(frozen=True, slots=True)
class ReconciledAuthorityProvenance:
    schema_version: str
    reconciliation_sha256: str
    candidate_set_sha256: str
    conflict_component_sha256: str
    selected_candidate_id: str
    p5_scope_token: str
    authorization_id: str
    authority_decision_id: str
    preflight_receipt_id: str
    promotion_envelope_sha256: str
    authority_class: str = "EXTERNAL_AUTHORITY_ONLY"
    canonical_effect: str = "NONE"
    master_promotion_state: str = "AUTHORITY_HOLD"
    byte_identity_effect: str = "NONE"
    f5_effect: str = "NONE"

    @property
    def sha256(self):
        return _hash(asdict(self))

def seal_provenance(*, binding: ReconciliationAuthorityBinding,
                    authorization: PromotionAuthorization,
                    preflight: PreflightReport,
                    promotion: PromotionEnvelope,
                    expected_authority_decision_id: str) -> ReconciledAuthorityProvenance:
    for name in ("reconciliation_sha256","candidate_set_sha256","conflict_component_sha256"):
        _sha(name, getattr(binding, name))
    if binding.authority_class != "EXTERNAL_AUTHORITY_ONLY":
        raise ValueError("F23 authority class escalation forbidden")
    if binding.canonical_effect != "NONE" or binding.master_promotion_state != "AUTHORITY_HOLD":
        raise ValueError("F23 master authority invariant violated")
    if binding.byte_identity_effect != "NONE" or binding.f5_effect != "NONE":
        raise ValueError("F23 upstream gate invariant violated")
    if authorization.scope.token != binding.p5_scope_token:
        raise ValueError("F23/P5 scope mismatch")
    if authorization.decision_id != expected_authority_decision_id:
        raise ValueError("P5 authority decision mismatch")
    if promotion.authorization_id != authorization.authorization_id:
        raise ValueError("P7/P5 authorization mismatch")
    if promotion.authority_decision_id != expected_authority_decision_id:
        raise ValueError("P7 authority decision mismatch")
    if promotion.preflight_receipt_id != preflight.receipt.receipt_id:
        raise ValueError("P7/P6 preflight receipt mismatch")
    if promotion.authorization_policy_version != authorization.policy_version:
        raise ValueError("P7/P5 policy mismatch")
    if (authorization.scope.case_id != preflight.case_id
            or authorization.scope.case_id != promotion.case_id):
        raise ValueError("P5/P6/P7 case mismatch")
    if (authorization.target_commit != preflight.target_commit
            or authorization.target_commit != promotion.commit_id):
        raise ValueError("P5/P6/P7 target commit mismatch")
    required_checks = {
        "lineage_complete", "schema_valid", "required_stages_complete",
        "no_blocking_discrepancy", "authority_decision_present",
        "authorization_present", "authorization_matches_target",
        "rollback_parent_match", "rollback_integrity_valid",
        "rollback_schema_compatible", "rollback_authority_refs_valid",
        "rollback_known_good",
    }
    if (not preflight.passed or not preflight.checks
            or any(not c.passed for c in preflight.checks)):
        raise ValueError("P6 preflight not passed")
    if (len(preflight.checks) != len(required_checks)
            or {c.name for c in preflight.checks} != required_checks):
        raise ValueError("P6 preflight check set invalid")
    if preflight.guards != frozenset({"preflight_passed", "rollback_target_verified"}):
        raise ValueError("P6 preflight guards invalid")
    if (preflight.receipt.operation != "PROMOTION_PREFLIGHT"
            or preflight.receipt.result != "PASS"
            or preflight.receipt.input_commit != authorization.target_commit
            or preflight.receipt.output_commit is not None
            or preflight.receipt.output_hashes):
        raise ValueError("P6 preflight receipt invalid")
    if (not preflight.receipt.input_hashes
            or preflight.receipt.input_hashes[0] != promotion.manifest_hash):
        raise ValueError("P6/P7 manifest hash mismatch")
    return ReconciledAuthorityProvenance(
        schema_version=SCHEMA,
        reconciliation_sha256=binding.reconciliation_sha256,
        candidate_set_sha256=binding.candidate_set_sha256,
        conflict_component_sha256=binding.conflict_component_sha256,
        selected_candidate_id=binding.selected_candidate_id,
        p5_scope_token=binding.p5_scope_token,
        authorization_id=authorization.authorization_id,
        authority_decision_id=expected_authority_decision_id,
        preflight_receipt_id=preflight.receipt.receipt_id,
        promotion_envelope_sha256=promotion.sha256,
    )
