"""GALIA F22 — fail-closed external authority reconciliation.

Candidate-only POC. canonical_effect=NONE; master_promotion_state=AUTHORITY_HOLD.
F22 reconciles evidence-backed F21/F20/F19 authority candidates. It cannot
promote GALIA master, close BYTE_IDENTITY/F5, or rewrite upstream history.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

SCHEMA = "GALIA-F22-RECONCILIATION/1"
DECISION_SCHEMA = "GALIA-F22-HUMAN-DECISION/1"
STATUSES = {
    "CONFLICT_DETECTED",
    "NON_OVERLAPPING_COMPATIBLE",
    "SAME_KEY_CORROBORATED",
    "AUTHORITY_UNRESOLVED",
    "HUMAN_SELECTION_REQUIRED",
    "RECONCILED_BY_EXPLICIT_HUMAN_DECISION",
}


def _canonical_json(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _hash(obj: Any) -> str:
    return hashlib.sha256(_canonical_json(obj)).hexdigest()


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


def _dt(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UTC timestamp required")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def candidate_core(candidate: Dict[str, Any]) -> Dict[str, Any]:
    required = ("candidate_id", "provider_id", "scope", "key_id", "key_sha256", "source_artifact_sha256", "lineage_sha256", "valid_from_utc")
    for key in required:
        if not candidate.get(key):
            raise ValueError("candidate missing " + key)
    for key in ("key_sha256", "source_artifact_sha256", "lineage_sha256"):
        if not _is_hash(candidate[key]):
            raise ValueError(key + " malformed")
    start = _dt(candidate["valid_from_utc"])
    end = _dt(candidate["valid_until_utc"]) if candidate.get("valid_until_utc") else None
    if end and end <= start:
        raise ValueError("invalid authority interval")
    return {key: candidate.get(key) for key in sorted(set(candidate) | {"valid_until_utc"}) if key != "candidate_sha256"}


def seal_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(candidate)
    result["candidate_sha256"] = _hash(candidate_core(result))
    return result


def validate_candidate(candidate: Dict[str, Any]) -> None:
    core = candidate_core(candidate)
    if not _is_hash(candidate.get("candidate_sha256")) or candidate["candidate_sha256"] != _hash(core):
        raise ValueError("candidate hash mismatch")


def overlaps(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if a["provider_id"] != b["provider_id"] or a["scope"] != b["scope"]:
        return False
    a0, b0 = _dt(a["valid_from_utc"]), _dt(b["valid_from_utc"])
    infinity = datetime.max.replace(tzinfo=timezone.utc)
    a1 = _dt(a["valid_until_utc"]) if a.get("valid_until_utc") else infinity
    b1 = _dt(b["valid_until_utc"]) if b.get("valid_until_utc") else infinity
    return max(a0, b0) < min(a1, b1)


def candidate_set_hash(candidates: List[Dict[str, Any]]) -> str:
    return _hash([{"candidate_id": c["candidate_id"], "candidate_sha256": c["candidate_sha256"]} for c in sorted(candidates, key=lambda x: x["candidate_id"])])


def reconcile(candidates: List[Dict[str, Any]], human_decision: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if len(candidates) < 2:
        raise ValueError("F22 requires >=2 candidates")
    for candidate in candidates:
        validate_candidate(candidate)
    ids = [c["candidate_id"] for c in candidates]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate candidate_id")
    set_hash = candidate_set_hash(candidates)
    conflicts, corroborations, compatible = [], [], []
    for index, a in enumerate(candidates):
        for b in candidates[index + 1:]:
            same_domain = a["provider_id"] == b["provider_id"] and a["scope"] == b["scope"]
            if not same_domain or not overlaps(a, b):
                compatible.append([a["candidate_id"], b["candidate_id"]])
            elif a["key_id"] == b["key_id"] and a["key_sha256"] == b["key_sha256"]:
                corroborations.append([a["candidate_id"], b["candidate_id"]])
            else:
                conflicts.append([a["candidate_id"], b["candidate_id"]])
    status = "HUMAN_SELECTION_REQUIRED" if conflicts else ("SAME_KEY_CORROBORATED" if corroborations else "NON_OVERLAPPING_COMPATIBLE")
    selected = None
    if human_decision is not None:
        if status != "HUMAN_SELECTION_REQUIRED":
            raise ValueError("human selection only valid for unresolved conflict")
        if human_decision.get("schema_version") != DECISION_SCHEMA:
            raise ValueError("decision schema mismatch")
        if human_decision.get("candidate_set_sha256") != set_hash:
            raise ValueError("decision candidate set mismatch")
        selected = human_decision.get("selected_candidate_id")
        if selected not in ids:
            raise ValueError("selected candidate absent")
        if human_decision.get("decision") != "SELECT_AUTHORITY":
            raise ValueError("explicit SELECT_AUTHORITY required")
        if not _is_hash(human_decision.get("decision_sha256")):
            raise ValueError("decision_sha256 malformed")
        expected = _hash({k: v for k, v in human_decision.items() if k != "decision_sha256"})
        if human_decision["decision_sha256"] != expected:
            raise ValueError("decision self-hash mismatch")
        status = "RECONCILED_BY_EXPLICIT_HUMAN_DECISION"
    result = {
        "schema_version": SCHEMA,
        "control_id": "GALIA-F22",
        "status": status,
        "candidate_set_sha256": set_hash,
        "candidate_ids": sorted(ids),
        "candidate_hashes": {c["candidate_id"]: c["candidate_sha256"] for c in candidates},
        "conflicts": conflicts,
        "same_key_corroborations": corroborations,
        "compatible_pairs": compatible,
        "selected_candidate_id": selected,
        "preserved_candidates": [dict(c) for c in candidates],
        "canonical_effect": "NONE",
        "master_promotion_state": "AUTHORITY_HOLD",
        "byte_identity_effect": "NONE",
        "f5_effect": "NONE",
        "invariants": ["NO_AUTOMATIC_WINNER", "RECENCY_IS_NOT_AUTHORITY", "MAJORITY_IS_NOT_AUTHORITY", "SIGNATURE_VALID_IS_NOT_KEY_AUTHORITY", "F22_EXTERNAL_AUTHORITY_IS_NOT_GALIA_MASTER_AUTHORITY", "REJECTED_CANDIDATES_REMAIN_PRESERVED"],
    }
    result["reconciliation_sha256"] = _hash(result)
    return result


def make_human_decision(candidates: List[Dict[str, Any]], selected_candidate_id: str, review_id: str = "HR-F22") -> Dict[str, Any]:
    core = {"schema_version": DECISION_SCHEMA, "decision": "SELECT_AUTHORITY", "review_id": review_id, "candidate_set_sha256": candidate_set_hash(candidates), "selected_candidate_id": selected_candidate_id}
    core["decision_sha256"] = _hash(core)
    return core
