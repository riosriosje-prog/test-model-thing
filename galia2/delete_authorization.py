"""GALIA deletion-authorization validator.

This module validates an explicit human authorization receipt against the exact
promoted deletion manifest and final-vault identities. It performs no deletion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

EXPECTED_DELETION_MANIFEST_SHA256 = (
    "6cf056219fa1e036d64e21b3f571bba0f68835a23a134dc47d3982a30d8a1708"
)
EXPECTED_FINAL_VAULT_MANIFEST_SHA256 = (
    "53345029a3d93b931946a2494af357a1beb2a2a989d3507eba23a028c309becf"
)
EXPECTED_TARGET_COUNT = 27
EXPECTED_SCOPE = "EXACT_27_TARGETS_IN_PROMOTED_DELETION_MANIFEST_ONLY"
EXPECTED_STATE = "EXPLICIT_HUMAN_APPROVAL_BOUND"


@dataclass(frozen=True)
class AuthorizationEvaluation:
    authorized: bool
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"authorized": self.authorized, "blockers": list(self.blockers)}


def evaluate_delete_authorization(receipt: Mapping[str, Any] | None) -> AuthorizationEvaluation:
    blockers: list[str] = []

    if not isinstance(receipt, Mapping):
        return AuthorizationEvaluation(False, ("AUTHORIZATION_RECEIPT_ABSENT",))

    if receipt.get("state") != EXPECTED_STATE:
        blockers.append("AUTHORIZATION_STATE_INVALID")

    if not receipt.get("decision_id"):
        blockers.append("DECISION_ID_MISSING")

    decision_text = receipt.get("decision_text")
    if not isinstance(decision_text, str) or not decision_text.strip():
        blockers.append("DECISION_TEXT_MISSING")

    if receipt.get("deletion_manifest_sha256") != EXPECTED_DELETION_MANIFEST_SHA256:
        blockers.append("DELETION_MANIFEST_HASH_MISMATCH")

    if receipt.get("final_vault_manifest_sha256") != EXPECTED_FINAL_VAULT_MANIFEST_SHA256:
        blockers.append("FINAL_VAULT_HASH_MISMATCH")

    if receipt.get("target_count") != EXPECTED_TARGET_COUNT:
        blockers.append("TARGET_COUNT_MISMATCH")

    if receipt.get("authorized_scope") != EXPECTED_SCOPE:
        blockers.append("AUTHORIZED_SCOPE_MISMATCH")

    if receipt.get("delete_authorized") is not True:
        blockers.append("DELETE_AUTHORIZED_TRUE_REQUIRED")

    if receipt.get("destructive_action_executed") not in (False, None):
        blockers.append("RECEIPT_MUST_PRECEDE_DESTRUCTIVE_ACTION")

    blockers = list(dict.fromkeys(blockers))
    return AuthorizationEvaluation(not blockers, tuple(blockers))
