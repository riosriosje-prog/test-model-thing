"""GALIA 2.0 P6 promotion preflight.

Pure, stdlib-only evaluation layer over P1-P5. P6 verifies whether a human-selected
candidate is structurally ready to become PROMOTION_READY. It never writes files,
mutates HEAD, persists commits, touches Legacy, or executes canonical promotion.

Safety properties:
* preflight is fail-closed: any failed check emits no preflight guards;
* rollback verification is exact and bound to the candidate parent commit;
* blocking discrepancies prevent readiness;
* P5 promotion authorization must match exact case/scope/target commit/policy;
* a passing preflight still cannot make a Stage CANONICAL; P2 requires the separate
  P5 promotion guards at the final human boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable, FrozenSet, Optional, Tuple
from uuid import uuid4

from .authority import AuthorityScope, PromotionAuthorization
from .core import Receipt

Clock = Callable[[], datetime]
IdFactory = Callable[[str], str]
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _required(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _hash(name: str, value: str) -> str:
    _required(name, value)
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256")
    return value.lower()


def _unique_strings(name: str, values: Tuple[str, ...], *, allow_empty: bool = True) -> Tuple[str, ...]:
    if not allow_empty and not values:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _required(name, value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must contain unique values")
    return values


@dataclass(frozen=True, slots=True)
class CandidateSnapshot:
    """Immutable evidence surface supplied to P6 for one candidate generation."""

    case_id: str
    target_commit: str
    parent_commit: str
    manifest_hash: str
    payload_hashes: Tuple[str, ...]
    lineage_complete: bool
    schema_version: str
    completed_stages: Tuple[str, ...]
    blocking_discrepancy_ids: Tuple[str, ...]
    authority_decision_id: str

    def __post_init__(self) -> None:
        _required("case_id", self.case_id)
        _required("target_commit", self.target_commit)
        _required("parent_commit", self.parent_commit)
        object.__setattr__(self, "manifest_hash", _hash("manifest_hash", self.manifest_hash))
        if not self.payload_hashes:
            raise ValueError("payload_hashes must not be empty")
        object.__setattr__(
            self,
            "payload_hashes",
            tuple(_hash("payload_hash", value) for value in self.payload_hashes),
        )
        _required("schema_version", self.schema_version)
        object.__setattr__(
            self,
            "completed_stages",
            _unique_strings("completed_stages", self.completed_stages, allow_empty=False),
        )
        object.__setattr__(
            self,
            "blocking_discrepancy_ids",
            _unique_strings("blocking_discrepancy_ids", self.blocking_discrepancy_ids),
        )
        _required("authority_decision_id", self.authority_decision_id)
        if self.target_commit == self.parent_commit:
            raise ValueError("target_commit cannot equal parent_commit")


@dataclass(frozen=True, slots=True)
class RollbackSnapshot:
    """Evidence that the exact parent generation is safe as a rollback target."""

    commit_id: str
    manifest_hash: str
    integrity_valid: bool
    schema_compatible: bool
    authority_refs_valid: bool
    known_good: bool

    def __post_init__(self) -> None:
        _required("commit_id", self.commit_id)
        object.__setattr__(self, "manifest_hash", _hash("manifest_hash", self.manifest_hash))


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    passed: bool
    detail: str

    def __post_init__(self) -> None:
        _required("name", self.name)
        _required("detail", self.detail)


@dataclass(frozen=True, slots=True)
class PreflightReport:
    case_id: str
    target_commit: str
    passed: bool
    checks: Tuple[PreflightCheck, ...]
    guards: FrozenSet[str]
    receipt: Receipt

    @property
    def failed_checks(self) -> Tuple[PreflightCheck, ...]:
        return tuple(check for check in self.checks if not check.passed)


class PromotionPreflight:
    """Evaluate P6 readiness without persistence or state mutation."""

    def __init__(
        self,
        *,
        policy_version: str,
        accepted_authority_policy_version: str,
        required_schema_version: str,
        required_stages: Tuple[str, ...],
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
    ) -> None:
        _required("policy_version", policy_version)
        _required("accepted_authority_policy_version", accepted_authority_policy_version)
        _required("required_schema_version", required_schema_version)
        _required("actor", actor)
        self.policy_version = policy_version
        self.accepted_authority_policy_version = accepted_authority_policy_version
        self.required_schema_version = required_schema_version
        self.required_stages = _unique_strings(
            "required_stages", required_stages, allow_empty=False
        )
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory

    def evaluate(
        self,
        *,
        candidate: CandidateSnapshot,
        rollback: RollbackSnapshot,
        authorization: Optional[PromotionAuthorization],
        expected_scope: AuthorityScope,
    ) -> PreflightReport:
        """Return immutable check results and P2 guards only if every check passes."""
        checks = (
            self._check("lineage_complete", candidate.lineage_complete, "candidate lineage must be complete"),
            self._check(
                "schema_valid",
                candidate.schema_version == self.required_schema_version,
                f"candidate schema={candidate.schema_version}; required={self.required_schema_version}",
            ),
            self._check(
                "required_stages_complete",
                set(self.required_stages).issubset(candidate.completed_stages),
                "all required preflight stages must be complete",
            ),
            self._check(
                "no_blocking_discrepancy",
                not candidate.blocking_discrepancy_ids,
                "candidate must have no blocking discrepancies",
            ),
            self._check(
                "authority_decision_present",
                bool(candidate.authority_decision_id),
                "candidate must bind an authority decision",
            ),
            self._check(
                "authorization_present",
                authorization is not None,
                "promotion authorization must be present",
            ),
            self._check(
                "authorization_matches_target",
                self._authorization_matches(
                    candidate=candidate,
                    authorization=authorization,
                    expected_scope=expected_scope,
                ),
                "authorization must match case, scope, decision, target commit, and authority policy",
            ),
            self._check(
                "rollback_parent_match",
                rollback.commit_id == candidate.parent_commit,
                "rollback target must be the candidate parent commit",
            ),
            self._check(
                "rollback_integrity_valid",
                rollback.integrity_valid,
                "rollback target integrity must be verified",
            ),
            self._check(
                "rollback_schema_compatible",
                rollback.schema_compatible,
                "rollback target schema must be compatible",
            ),
            self._check(
                "rollback_authority_refs_valid",
                rollback.authority_refs_valid,
                "rollback target authority references must be valid",
            ),
            self._check(
                "rollback_known_good",
                rollback.known_good,
                "rollback target must be explicitly known-good",
            ),
        )

        passed = all(check.passed for check in checks)
        guards = (
            frozenset({"preflight_passed", "rollback_target_verified"})
            if passed
            else frozenset()
        )
        result = "PASS" if passed else "FAIL:" + ",".join(
            check.name for check in checks if not check.passed
        )
        receipt = Receipt(
            receipt_id=self.id_factory("receipt"),
            operation="PROMOTION_PREFLIGHT",
            input_commit=candidate.target_commit,
            input_hashes=(candidate.manifest_hash, *candidate.payload_hashes, rollback.manifest_hash),
            output_commit=None,
            output_hashes=(),
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=result,
        )
        return PreflightReport(
            case_id=candidate.case_id,
            target_commit=candidate.target_commit,
            passed=passed,
            checks=checks,
            guards=guards,
            receipt=receipt,
        )

    def _authorization_matches(
        self,
        *,
        candidate: CandidateSnapshot,
        authorization: Optional[PromotionAuthorization],
        expected_scope: AuthorityScope,
    ) -> bool:
        if authorization is None:
            return False
        return (
            expected_scope.case_id == candidate.case_id
            and authorization.scope == expected_scope
            and authorization.scope.case_id == candidate.case_id
            and authorization.target_commit == candidate.target_commit
            and authorization.decision_id == candidate.authority_decision_id
            and authorization.policy_version == self.accepted_authority_policy_version
        )

    @staticmethod
    def _check(name: str, passed: bool, detail: str) -> PreflightCheck:
        return PreflightCheck(name=name, passed=bool(passed), detail=detail)
