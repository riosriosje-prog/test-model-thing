"""GALIA 2.0 release-level authority scope model.

This module is additive and intentionally separate from ``galia2.authority``,
which governs claim-level human authority. It evaluates whether one exact
release is eligible as an integration base inside one exact authority scope.

It performs no state transition, persistence write, HEAD mutation, Legacy
mutation, GitHub write, or promotion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable, Tuple

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _required(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _sha256(name: str, value: str) -> str:
    _required(name, value)
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256")
    return value.lower()


def _unique_ids(name: str, values: Tuple[str, ...]) -> Tuple[str, ...]:
    if not values:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _required(name, value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must contain unique values")
    return values


class ReleaseAuthorityDomain(str, Enum):
    GLOBAL_MASTER = "GLOBAL_MASTER"
    RESEARCH_CANONICAL_STATE = "RESEARCH_CANONICAL_STATE"


class ReleaseAuthorizationQuality(str, Enum):
    DIRECT_FILE_RECORD = "DIRECT_FILE_RECORD"
    EXPLICIT_HUMAN_TRACE_REVALIDATED = "EXPLICIT_HUMAN_TRACE_REVALIDATED"
    DEFECTIVE_GENERIC_CONTINUATION = "DEFECTIVE_GENERIC_CONTINUATION"
    OBSERVED_PROMOTED_STATE_ONLY = "OBSERVED_PROMOTED_STATE_ONLY"
    UNKNOWN = "UNKNOWN"


class G22State(str, Enum):
    PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE = (
        "PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE"
    )
    BLOCK_AMBIGUOUS_MULTIPLE_INTEGRATION_BASES = (
        "BLOCK_AMBIGUOUS_MULTIPLE_INTEGRATION_BASES"
    )
    BLOCK_KNOWN_AUTHORITY_HASH_RAW_BYTES_ABSENT = (
        "BLOCK_KNOWN_AUTHORITY_HASH_RAW_BYTES_ABSENT"
    )
    BLOCK_NO_ELIGIBLE_INTEGRATION_BASE = "BLOCK_NO_ELIGIBLE_INTEGRATION_BASE"


@dataclass(frozen=True, slots=True)
class ReleaseAuthorityScope:
    """Exact release-authority boundary."""

    system_id: str
    domain: ReleaseAuthorityDomain
    scope_id: str

    def __post_init__(self) -> None:
        _required("system_id", self.system_id)
        _required("scope_id", self.scope_id)

    @property
    def token(self) -> str:
        return (
            f"system:{self.system_id}|domain:{self.domain.value}|"
            f"scope:{self.scope_id}"
        )


@dataclass(frozen=True, slots=True)
class ReleaseAuthorityEvidence:
    """Evidence-bound release authority record."""

    release_id: str
    scope: ReleaseAuthorityScope
    artifact_sha256: str
    authorization_quality: ReleaseAuthorizationQuality
    source_evidence_ids: Tuple[str, ...]
    scope_binding_supported: bool
    raw_artifact_present: bool
    historically_promoted_supported: bool
    lineage_reconciled_within_scope: bool
    human_selected_in_current_review: bool

    def __post_init__(self) -> None:
        _required("release_id", self.release_id)
        object.__setattr__(
            self, "artifact_sha256", _sha256("artifact_sha256", self.artifact_sha256)
        )
        object.__setattr__(
            self,
            "source_evidence_ids",
            _unique_ids("source_evidence_ids", self.source_evidence_ids),
        )

    @property
    def human_authorization_supported(self) -> bool:
        return self.authorization_quality in {
            ReleaseAuthorizationQuality.DIRECT_FILE_RECORD,
            ReleaseAuthorizationQuality.EXPLICIT_HUMAN_TRACE_REVALIDATED,
        }

    @property
    def byte_authoritative_candidate(self) -> bool:
        return (
            self.scope_binding_supported
            and self.human_authorization_supported
            and self.historically_promoted_supported
            and self.raw_artifact_present
            and self.lineage_reconciled_within_scope
            and self.human_selected_in_current_review
        )


def same_release_authority_scope(
    left: ReleaseAuthorityEvidence,
    right: ReleaseAuthorityEvidence,
) -> bool:
    return left.scope == right.scope


def cross_scope_transfer_required(
    successor: ReleaseAuthorityEvidence,
    predecessor: ReleaseAuthorityEvidence,
) -> bool:
    return not same_release_authority_scope(successor, predecessor)


def g22_state(
    candidates: Iterable[ReleaseAuthorityEvidence],
    *,
    target_scope: ReleaseAuthorityScope,
) -> G22State:
    """Evaluate one exact authority scope fail-closed."""

    exact_scope = [
        item
        for item in candidates
        if item.scope_binding_supported and item.scope == target_scope
    ]

    eligible = [item for item in exact_scope if item.byte_authoritative_candidate]
    if len(eligible) == 1:
        return G22State.PASS_SINGLE_BYTE_AUTHORITATIVE_INTEGRATION_BASE
    if len(eligible) > 1:
        return G22State.BLOCK_AMBIGUOUS_MULTIPLE_INTEGRATION_BASES

    if any(
        item.human_authorization_supported
        and item.historically_promoted_supported
        and not item.raw_artifact_present
        for item in exact_scope
    ):
        return G22State.BLOCK_KNOWN_AUTHORITY_HASH_RAW_BYTES_ABSENT

    return G22State.BLOCK_NO_ELIGIBLE_INTEGRATION_BASE
