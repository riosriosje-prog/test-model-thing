"""F23/P5 explicit admission gate; does not authenticate evidence itself.

Until a repository-controlled verifier is implemented, this gate denies all bindings. In particular,
F22's self-hashed human decision is NOT sufficient authentication.
"""
from dataclasses import dataclass
from .authority import AuthorityScope
from .reconciliation_authority_binding import bind_reconciliation

@dataclass(frozen=True, slots=True)
class VerifiedScopeAttestation:
    decision_id: str
    reviewer_id: str
    issuer_id: str
    case_id: str
    target_type: str
    target_ids: tuple[str, ...]
    reconciliation_sha256: str
    candidate_set_sha256: str
    conflict_component_sha256: str
    selected_candidate_id: str

def bind_with_verified_scope(
    reconciliation: dict,
    *,
    attestation: VerifiedScopeAttestation,
    p5_scope: AuthorityScope,
    expected_provider_id: str,
    expected_external_scope: str,
):
    """Fail closed unless an independently trusted verifier approves exact evidence.

    No caller-provided verifier is accepted; this is intentionally deny-all.
    """
    if not isinstance(attestation, VerifiedScopeAttestation):
        raise ValueError("verified scope attestation required")
    if not all(isinstance(v, str) and v.strip() for v in (
        attestation.decision_id, attestation.reviewer_id, attestation.issuer_id,
        attestation.case_id, attestation.target_type,
        attestation.reconciliation_sha256, attestation.candidate_set_sha256,
        attestation.conflict_component_sha256, attestation.selected_candidate_id
    )):
        raise ValueError("incomplete attestation")
    if not attestation.target_ids or len(set(attestation.target_ids)) != len(attestation.target_ids):
        raise ValueError("invalid attested target ids")
    if (p5_scope.case_id, p5_scope.target_type, p5_scope.target_ids) != (
        attestation.case_id, attestation.target_type, attestation.target_ids
    ):
        raise ValueError("P5 scope mismatch")
    if reconciliation.get("reconciliation_sha256") != attestation.reconciliation_sha256:
        raise ValueError("attested reconciliation mismatch")
    if reconciliation.get("candidate_set_sha256") != attestation.candidate_set_sha256:
        raise ValueError("attested candidate set mismatch")
    if reconciliation.get("reconciled_component_sha256") != attestation.conflict_component_sha256:
        raise ValueError("attested component mismatch")
    if reconciliation.get("selected_candidate_id") != attestation.selected_candidate_id:
        raise ValueError("attested selected candidate mismatch")
    raise ValueError("trusted issuer verification unavailable: AUTHORITY_HOLD")
    return bind_reconciliation(
        reconciliation,
        expected_candidate_set_sha256=attestation.candidate_set_sha256,
        expected_component_sha256=attestation.conflict_component_sha256,
        expected_selected_candidate_id=attestation.selected_candidate_id,
        expected_provider_id=expected_provider_id,
        expected_external_scope=expected_external_scope,
        p5_scope=p5_scope,
    )
