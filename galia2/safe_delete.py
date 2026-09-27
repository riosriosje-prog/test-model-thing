"""GALIA SAFE_DELETE gate.

This module never deletes anything. It only evaluates whether an exact deletion
manifest is eligible for a human-authorized SAFE_TO_DELETE certificate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


REQUIRED_RAW_OBJECTS = (
    "global_master_1_0_1",
    "santurce_research_15_003",
    "v1_30_14_003",
    "cleanup_948d41",
    "cleanup_upstream_5ed030",
    "ow02_checkpoint",
    "ow10_checkpoint",
    "ow21_checkpoint",
)

IRRECOVERABLE_TRANSIENT_POLICY = {
    "cleanup_upstream_5ed030": {
        "expected_sha256": "5ed03098751c71efb5d87ec33f0f9d2894c6a7c729265eb322dfb37e9f42a4b6",
        "successor_object_id": "cleanup_948d41",
        "successor_sha256": "948d41f220e166f6d0e816b424e3bd0f1576f9be1fc3abdc1698fa82cfe507ad",
    }
}

REQUIRED_CONTROL_STATES = {
    "ow21_discovery_audit": "DISCOVERY_AUDIT_COMPLETE",
    "final_vault": "VAULT_BUILT_VERIFIED",
    "clean_room_restore": "PASS",
    "deletion_manifest": "PRESENT_HASHED",
    "human_authorization": "EXPLICIT_HUMAN_APPROVAL_BOUND",
}


@dataclass(frozen=True)
class SafeDeleteEvaluation:
    safe_to_delete: bool
    blocking_reasons: tuple[str, ...]
    advisories: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "safe_to_delete": self.safe_to_delete,
            "blocking_reasons": list(self.blocking_reasons),
            "advisories": list(self.advisories),
        }


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _validate_irrecoverable_transient(
    *,
    key: str,
    item: Mapping[str, Any],
    required_objects: Mapping[str, Any],
    controls: Mapping[str, Any],
) -> list[str]:
    """Validate the narrow evidence-backed exception for a lost transient object.

    This is not a byte-equivalence rule. The missing bytes remain missing.
    The exception only permits SAFE_DELETE evaluation to proceed when a specific
    noncanonical transient loss is documented, bounded, successor-preserved, and
    separately accepted by a human decision bound to the exact object/evidence.
    """

    blockers: list[str] = []
    policy = IRRECOVERABLE_TRANSIENT_POLICY.get(key)
    if policy is None:
        return [f"{key}:IRRECOVERABLE_TRANSIENT_NOT_POLICY_ELIGIBLE"]

    expected_sha = item.get("expected_sha256")
    if expected_sha != policy["expected_sha256"] or not _is_sha256(expected_sha):
        blockers.append(f"{key}:EXPECTED_SHA256_MISMATCH")

    if item.get("classification") != "WORKING_TRANSIENT_NOT_CANONICAL":
        blockers.append(f"{key}:CLASSIFICATION_NOT_PROVEN")

    if item.get("master_modified") is not False:
        blockers.append(f"{key}:MASTER_MODIFICATION_NOT_EXCLUDED")

    if item.get("authority_mutations") != 0:
        blockers.append(f"{key}:AUTHORITY_MUTATIONS_NOT_ZERO")

    knowledge = item.get("knowledge_mutations")
    if not isinstance(knowledge, Mapping) or any(
        knowledge.get(field) != 0 for field in ("sources", "evidence", "statements")
    ):
        blockers.append(f"{key}:KNOWLEDGE_MUTATIONS_NOT_ZERO")

    if item.get("recovery_search_state") != "EXHAUSTIVE_NEGATIVE":
        blockers.append(f"{key}:RECOVERY_SEARCH_NOT_EXHAUSTIVE_NEGATIVE")

    if item.get("reverse_reconstruction_accepted") is not False:
        blockers.append(f"{key}:REVERSE_RECONSTRUCTION_MUST_NOT_SUBSTITUTE_RAW_BYTES")

    evidence_record_sha = item.get("evidence_record_sha256")
    if not _is_sha256(evidence_record_sha):
        blockers.append(f"{key}:EVIDENCE_RECORD_SHA256_INVALID_OR_MISSING")

    successor_id = item.get("successor_object_id")
    successor_sha = item.get("successor_sha256")
    if successor_id != policy["successor_object_id"] or successor_sha != policy["successor_sha256"]:
        blockers.append(f"{key}:SUCCESSOR_BINDING_MISMATCH")
    else:
        successor = required_objects.get(successor_id)
        if (
            not isinstance(successor, Mapping)
            or successor.get("state") != "RAW_BYTES_VERIFIED"
            or successor.get("sha256") != successor_sha
        ):
            blockers.append(f"{key}:SUCCESSOR_NOT_BYTE_VERIFIED")

    acceptance = controls.get("irrecoverable_transient_acceptance")
    if not isinstance(acceptance, Mapping):
        blockers.append("irrecoverable_transient_acceptance:MISSING_CONTROL_ENTRY")
    elif acceptance.get("state") != "EXPLICIT_HUMAN_IRRECOVERABLE_TRANSIENT_ACCEPTANCE_BOUND":
        blockers.append(
            f"irrecoverable_transient_acceptance:{acceptance.get('state', 'STATE_MISSING')}"
        )
    else:
        if acceptance.get("object_id") != key:
            blockers.append("irrecoverable_transient_acceptance:OBJECT_ID_MISMATCH")
        if acceptance.get("expected_sha256") != expected_sha:
            blockers.append("irrecoverable_transient_acceptance:EXPECTED_SHA256_MISMATCH")
        if acceptance.get("evidence_record_sha256") != evidence_record_sha:
            blockers.append("irrecoverable_transient_acceptance:EVIDENCE_RECORD_HASH_MISMATCH")
        if not acceptance.get("decision_id"):
            blockers.append("irrecoverable_transient_acceptance:DECISION_ID_MISSING")

    return blockers


def evaluate_safe_delete(snapshot: Mapping[str, Any]) -> SafeDeleteEvaluation:
    """Evaluate SAFE_DELETE from an evidence snapshot.

    Fail-closed rules:
    - mandatory raw objects must be byte-verified with exact SHA-256, except the
      one policy-enumerated transient-loss path which requires bounded evidence
      plus separate human loss acceptance;
    - every directly recoverable OW checkpoint required by policy is preserved;
    - OW21 discovery must be explicitly completed;
    - an immutable final vault must exist and have an exact SHA-256;
    - clean-room restore must pass from that final vault alone;
    - deletion scope must be explicit and hashed;
    - every deletion target must be covered by the verified final-vault index;
    - explicit deletion approval must bind the exact deletion-manifest and vault hashes.

    The transient-loss path never reconstructs, fabricates, or treats missing bytes
    as byte-equivalent. It only changes whether the documented loss is an absolute
    preservation blocker after a separate human acceptance.
    """

    blockers: list[str] = []
    advisories: list[str] = []

    required_objects = snapshot.get("required_objects")
    if not isinstance(required_objects, Mapping):
        required_objects = {}
        blockers.append("REQUIRED_OBJECT_INVENTORY_MISSING")

    controls = snapshot.get("controls")
    if not isinstance(controls, Mapping):
        controls = {}
        blockers.append("CONTROL_STATE_INVENTORY_MISSING")

    for key in REQUIRED_RAW_OBJECTS:
        item = required_objects.get(key)
        if not isinstance(item, Mapping):
            blockers.append(f"{key}:MISSING_INVENTORY_ENTRY")
            continue

        state = item.get("state")
        if state == "RAW_BYTES_VERIFIED":
            if not _is_sha256(item.get("sha256")):
                blockers.append(f"{key}:INVALID_OR_MISSING_SHA256")
            continue

        if state == "IRRECOVERABLE_TRANSIENT_DOCUMENTED":
            blockers.extend(
                _validate_irrecoverable_transient(
                    key=key,
                    item=item,
                    required_objects=required_objects,
                    controls=controls,
                )
            )
            continue

        blockers.append(f"{key}:{state or 'STATE_MISSING'}")

    for key, expected_state in REQUIRED_CONTROL_STATES.items():
        item = controls.get(key)
        if not isinstance(item, Mapping):
            blockers.append(f"{key}:MISSING_CONTROL_ENTRY")
            continue
        if item.get("state") != expected_state:
            blockers.append(f"{key}:{item.get('state', 'STATE_MISSING')}")

    vault = controls.get("final_vault") if isinstance(controls.get("final_vault"), Mapping) else {}
    vault_sha = vault.get("sha256")
    if vault.get("state") == "VAULT_BUILT_VERIFIED" and not _is_sha256(vault_sha):
        blockers.append("final_vault:INVALID_OR_MISSING_SHA256")

    manifest = controls.get("deletion_manifest") if isinstance(controls.get("deletion_manifest"), Mapping) else {}
    manifest_sha = manifest.get("sha256")
    targets = manifest.get("targets")
    if manifest.get("state") == "PRESENT_HASHED":
        if not _is_sha256(manifest_sha):
            blockers.append("deletion_manifest:INVALID_OR_MISSING_SHA256")
        if not isinstance(targets, list) or not targets:
            blockers.append("deletion_manifest:TARGETS_EMPTY_OR_INVALID")

    vault_objects = snapshot.get("vault_objects")
    if not isinstance(vault_objects, Mapping):
        vault_objects = {}
        if manifest.get("state") == "PRESENT_HASHED":
            blockers.append("VAULT_OBJECT_INDEX_MISSING")

    if isinstance(targets, list):
        for index, target in enumerate(targets):
            if not isinstance(target, Mapping):
                blockers.append(f"deletion_target_{index}:INVALID")
                continue
            target_sha = target.get("sha256")
            if not _is_sha256(target_sha):
                blockers.append(f"deletion_target_{index}:INVALID_OR_MISSING_SHA256")
                continue
            vault_entry = vault_objects.get(target_sha)
            if not isinstance(vault_entry, Mapping) or vault_entry.get("state") != "VERIFIED_IN_FINAL_VAULT":
                blockers.append(f"deletion_target_{index}:NOT_VERIFIED_IN_FINAL_VAULT")

    auth = controls.get("human_authorization") if isinstance(controls.get("human_authorization"), Mapping) else {}
    if auth.get("state") == "EXPLICIT_HUMAN_APPROVAL_BOUND":
        if auth.get("deletion_manifest_sha256") != manifest_sha:
            blockers.append("human_authorization:DELETION_MANIFEST_HASH_MISMATCH")
        if auth.get("final_vault_sha256") != vault_sha:
            blockers.append("human_authorization:FINAL_VAULT_HASH_MISMATCH")
        if not auth.get("decision_id"):
            blockers.append("human_authorization:DECISION_ID_MISSING")

    should = snapshot.get("should_preserve")
    if isinstance(should, Mapping):
        v129 = should.get("historical_v1_29_binary")
        if isinstance(v129, Mapping) and v129.get("state") != "RAW_BYTES_VERIFIED":
            advisories.append("historical_v1_29_binary:SHOULD_PRESERVE_IF_RECOVERABLE")

    forensic = snapshot.get("forensic_only")
    if isinstance(forensic, Mapping):
        g28 = forensic.get("g28_14_003_to_15_003")
        if isinstance(g28, Mapping) and g28.get("state") != "RESOLVED":
            advisories.append("G28_REMAINS_FORENSIC_ONLY")
        replay = forensic.get("sqlite_3_46_1_same_writer_replay")
        if isinstance(replay, Mapping) and replay.get("state") != "PASS":
            advisories.append("SQLITE_3_46_1_REPLAY_NOT_REQUIRED_FOR_SAFE_DELETE")

    blockers = list(dict.fromkeys(blockers))
    advisories = list(dict.fromkeys(advisories))

    return SafeDeleteEvaluation(
        safe_to_delete=(len(blockers) == 0),
        blocking_reasons=tuple(blockers),
        advisories=tuple(advisories),
    )
