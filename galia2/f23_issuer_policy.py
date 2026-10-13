"""F23 issuer governance policy model; advisory validation only.

This module cannot enroll issuers, authenticate reviewers, or authorize a
canonical write. Its validation never overrides AUTHORITY_HOLD.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping


@dataclass(frozen=True, slots=True)
class IssuerPolicy:
    issuer_id: str
    public_key: bytes
    allowed_reviewer_ids: tuple[str, ...]
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False


def validate_issuer_policy(
    issuer_id: str,
    reviewer_id: str,
    at: datetime,
    *,
    policies: Mapping[str, IssuerPolicy],
) -> bytes:
    """Return a policy key only when all local policy checks pass.

    The caller-supplied policies are NOT an independently authenticated trust
    root. A successful return must never be interpreted as binding authority.
    """
    if not isinstance(policies, Mapping):
        raise ValueError("issuer policy registry required")
    if not isinstance(issuer_id, str) or not issuer_id.strip():
        raise ValueError("issuer id required")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise ValueError("reviewer id required")
    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("timezone-aware evaluation time required")
    policy = policies.get(issuer_id)
    if not isinstance(policy, IssuerPolicy) or policy.issuer_id != issuer_id:
        raise ValueError("issuer not enrolled")
    if policy.revoked:
        raise ValueError("issuer revoked")
    if not isinstance(policy.public_key, bytes) or len(policy.public_key) != 32:
        raise ValueError("invalid issuer key")
    if (
        not isinstance(policy.allowed_reviewer_ids, tuple)
        or not policy.allowed_reviewer_ids
        or any(not isinstance(v, str) or not v.strip() for v in policy.allowed_reviewer_ids)
        or len(set(policy.allowed_reviewer_ids)) != len(policy.allowed_reviewer_ids)
    ):
        raise ValueError("invalid reviewer policy")
    if reviewer_id not in policy.allowed_reviewer_ids:
        raise ValueError("reviewer not authorized")
    if any(
        not isinstance(v, datetime) or v.tzinfo is None or v.utcoffset() is None
        for v in (policy.valid_from, policy.valid_until)
    ):
        raise ValueError("timezone-aware policy bounds required")
    if not policy.valid_from < policy.valid_until:
        raise ValueError("invalid policy interval")
    instant = at.astimezone(timezone.utc)
    if not policy.valid_from.astimezone(timezone.utc) <= instant < policy.valid_until.astimezone(timezone.utc):
        raise ValueError("issuer policy inactive")
    return policy.public_key
