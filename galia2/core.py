"""GALIA 2.0 P1 core schema primitives.

This module is intentionally stdlib-only and has no dependency on Legacy/TMT runtime.
It defines data contracts only; orchestration and transitions belong to later patches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
import re
from typing import Optional, Tuple

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


def _aware_timestamp(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


class CaseState(str, Enum):
    OPEN = "OPEN"
    SCOPED = "SCOPED"
    ACTIVE_RESEARCH = "ACTIVE_RESEARCH"
    PARTIAL_FINDINGS = "PARTIAL_FINDINGS"
    EVIDENCE_CONVERGENCE = "EVIDENCE_CONVERGENCE"
    AUTHORITY_REVIEW = "AUTHORITY_REVIEW"
    CANONICALIZED = "CANONICALIZED"
    SUSPENDED = "SUSPENDED"
    BLOCKED = "BLOCKED"
    REOPENED = "REOPENED"
    SUPERSEDED = "SUPERSEDED"


class StageState(str, Enum):
    DISCOVERED = "DISCOVERED"
    INGESTED = "INGESTED"
    NORMALIZED = "NORMALIZED"
    DERIVED = "DERIVED"
    VALIDATED = "VALIDATED"
    AUTHORITY_HOLD = "AUTHORITY_HOLD"
    HUMAN_SELECTED = "HUMAN_SELECTED"
    PROMOTION_READY = "PROMOTION_READY"
    CANONICAL = "CANONICAL"
    QUARANTINED = "QUARANTINED"
    DISCREPANCY_REVIEW = "DISCREPANCY_REVIEW"
    RECOVERY_INTAKE = "RECOVERY_INTAKE"
    REOPENED = "REOPENED"


class ClaimType(str, Enum):
    OBSERVED = "OBSERVED_CLAIM"
    DERIVED = "DERIVED_CLAIM"
    INTERPRETIVE = "INTERPRETIVE_CLAIM"


class EvidenceState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    SUPPORTED = "SUPPORTED"
    CORROBORATED = "CORROBORATED"
    CONTESTED = "CONTESTED"
    SUPERSEDED = "SUPERSEDED"
    CANONICAL = "CANONICAL"


class AuthorityState(str, Enum):
    NONE = "NONE"
    HOLD = "AUTHORITY_HOLD"
    HUMAN_SELECTED = "HUMAN_SELECTED"
    PROMOTION_READY = "PROMOTION_READY"
    CANONICAL = "CANONICAL"


class DiscrepancyState(str, Enum):
    OPEN = "OPEN"
    EXPLAINED = "EXPLAINED"
    RESOLVED = "RESOLVED"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    title: str
    scope: str
    state: CaseState
    created_at: datetime
    governing_constitution_version: str
    canonical_commit: Optional[str] = None

    def __post_init__(self) -> None:
        _required("case_id", self.case_id)
        _required("title", self.title)
        _required("scope", self.scope)
        _required("governing_constitution_version", self.governing_constitution_version)
        _aware_timestamp("created_at", self.created_at)
        if self.canonical_commit is not None:
            _required("canonical_commit", self.canonical_commit)


@dataclass(frozen=True, slots=True)
class Stage:
    stage_id: str
    case_id: str
    stage_type: str
    state: StageState
    dependencies: Tuple[str, ...] = field(default_factory=tuple)
    input_refs: Tuple[str, ...] = field(default_factory=tuple)
    output_refs: Tuple[str, ...] = field(default_factory=tuple)
    blocking_holds: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _required("stage_id", self.stage_id)
        _required("case_id", self.case_id)
        _required("stage_type", self.stage_type)
        if self.stage_id in self.dependencies:
            raise ValueError("stage cannot depend on itself")


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    artifact_id: str
    repository: str
    repository_ref: str
    document_date: Optional[date]
    event_date_hint: Optional[date]
    sha256: str
    provenance_state: str
    immutable: bool = True

    def __post_init__(self) -> None:
        _required("artifact_id", self.artifact_id)
        _required("repository", self.repository)
        _required("repository_ref", self.repository_ref)
        _required("provenance_state", self.provenance_state)
        object.__setattr__(self, "sha256", _sha256("sha256", self.sha256))
        if self.immutable is not True:
            raise ValueError("SourceArtifact must remain immutable")


@dataclass(frozen=True, slots=True)
class Derivation:
    derivation_id: str
    parent_artifact_id: str
    derivation_type: str
    engine_version: str
    prompt_version: str
    execution_attempt_id: str
    output_hash: str

    def __post_init__(self) -> None:
        _required("derivation_id", self.derivation_id)
        _required("parent_artifact_id", self.parent_artifact_id)
        _required("derivation_type", self.derivation_type)
        _required("engine_version", self.engine_version)
        _required("prompt_version", self.prompt_version)
        _required("execution_attempt_id", self.execution_attempt_id)
        object.__setattr__(self, "output_hash", _sha256("output_hash", self.output_hash))


@dataclass(frozen=True, slots=True)
class Claim:
    claim_id: str
    case_id: str
    subject: str
    predicate: str
    object: str
    valid_from: Optional[date]
    valid_to: Optional[date]
    claim_type: ClaimType
    evidence_state: EvidenceState
    authority_state: AuthorityState

    def __post_init__(self) -> None:
        _required("claim_id", self.claim_id)
        _required("case_id", self.case_id)
        _required("subject", self.subject)
        _required("predicate", self.predicate)
        _required("object", self.object)
        if self.valid_from is not None and self.valid_to is not None and self.valid_from > self.valid_to:
            raise ValueError("valid_from cannot be after valid_to")


@dataclass(frozen=True, slots=True)
class EvidenceLink:
    evidence_link_id: str
    claim_id: str
    artifact_id: str
    relationship: str
    directness: str
    independence_group: str

    def __post_init__(self) -> None:
        _required("evidence_link_id", self.evidence_link_id)
        _required("claim_id", self.claim_id)
        _required("artifact_id", self.artifact_id)
        _required("relationship", self.relationship)
        _required("directness", self.directness)
        _required("independence_group", self.independence_group)


@dataclass(frozen=True, slots=True)
class Discrepancy:
    discrepancy_id: str
    objects: Tuple[str, ...]
    type: str
    materiality: str
    state: DiscrepancyState
    resolution_refs: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        _required("discrepancy_id", self.discrepancy_id)
        _required("type", self.type)
        _required("materiality", self.materiality)
        if len(self.objects) < 2:
            raise ValueError("discrepancy requires at least two compared objects")
        if len(set(self.objects)) != len(self.objects):
            raise ValueError("discrepancy objects must be unique")


@dataclass(frozen=True, slots=True)
class AuthorityDecision:
    decision_id: str
    target_id: str
    reviewer: str
    decision: str
    scope: str
    evidence_snapshot: Tuple[str, ...]
    timestamp: datetime

    def __post_init__(self) -> None:
        _required("decision_id", self.decision_id)
        _required("target_id", self.target_id)
        _required("reviewer", self.reviewer)
        _required("decision", self.decision)
        _required("scope", self.scope)
        _aware_timestamp("timestamp", self.timestamp)
        if not self.evidence_snapshot:
            raise ValueError("authority decision requires an evidence snapshot")


@dataclass(frozen=True, slots=True)
class Receipt:
    receipt_id: str
    operation: str
    input_commit: Optional[str]
    input_hashes: Tuple[str, ...]
    output_commit: Optional[str]
    output_hashes: Tuple[str, ...]
    policy_version: str
    actor: str
    timestamp: datetime
    result: str

    def __post_init__(self) -> None:
        _required("receipt_id", self.receipt_id)
        _required("operation", self.operation)
        _required("policy_version", self.policy_version)
        _required("actor", self.actor)
        _required("result", self.result)
        _aware_timestamp("timestamp", self.timestamp)
        if self.input_commit is not None:
            _required("input_commit", self.input_commit)
        if self.output_commit is not None:
            _required("output_commit", self.output_commit)
        object.__setattr__(self, "input_hashes", tuple(_sha256("input_hash", v) for v in self.input_hashes))
        object.__setattr__(self, "output_hashes", tuple(_sha256("output_hash", v) for v in self.output_hashes))
