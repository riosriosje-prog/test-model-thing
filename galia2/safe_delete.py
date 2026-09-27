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


def evaluate_safe_delete(snapshot: Mapping[str, Any]) -> SafeDeleteEvaluation:
    """Evaluate SAFE_DELETE from an evidence snapshot.

    Fail-closed rules:
    - every mandatory raw object must be byte-verified with exact SHA-256;
    - every directly recoverable OW checkpoint required by policy is preserved;
    - OW21 discovery must be explicitly completed;
    - an immutable final vault must exist and have an exact SHA-256;
    - clean-room restore must pass from that final vault alone;
    - deletion scope must be explicit and hashed;
    - every deletion target must be covered by the verified final-vault index;
    - explicit human approval must bind the exact deletion-manifest and vault hashes.

    G28, same-writer replay, and the historical v1.29 binary are advisory/forensic
    concerns and do not independently block SAFE_DELETE once preservation is proven.
    """

    blockers: list[str] = []
    advisories: list[str] = []

    required_objects = snapshot.get("required_objects")
    if not isinstance(required_objects, Mapping):
        required_objects = {}
        blockers.append("REQUIRED_OBJECT_INVENTORY_MISSING")

    for key in REQUIRED_RAW_OBJECTS:
        item = required_objects.get(key)
        if not isinstance(item, Mapping):
            blockers.append(f"{key}:MISSING_INVENTORY_ENTRY")
            continue
        if item.get("state") != "RAW_BYTES_VERIFIED":
            blockers.append(f"{key}:{item.get('state', 'STATE_MISSING')}")
            continue
        if not _is_sha256(item.get("sha256")):
            blockers.append(f"{key}:INVALID_OR_MISSING_SHA256")

    controls = snapshot.get("controls")
    if not isinstance(controls, Mapping):
        controls = {}
        blockers.append("CONTROL_STATE_INVENTORY_MISSING")

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
