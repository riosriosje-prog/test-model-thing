"""GALIA 2.0 P5 human authority layer.

This module turns explicit human decisions into narrowly-scoped authority guards.
It does not execute state transitions, persist commits, mutate HEAD, touch Legacy,
or perform promotion preflight. Those responsibilities remain in P2/P3 and P6+.

Safety properties:
* AUTHORITY_HOLD is explicit and reversible as an immutable Claim replacement.
* human-selection guards are emitted only for a structurally valid human decision.
* promotion authorization is bound to one case, exact target IDs and one target commit.
* a present authorization is not the same as a matching authorization.
* all receipts emitted here have output_commit=None.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, FrozenSet, Optional, Tuple
from uuid import uuid4

from .core import AuthorityDecision, AuthorityState, Claim, Receipt


Clock = Callable[[], datetime]
IdFactory = Callable[[str], str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _required(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _unique_ids(name: str, values: Tuple[str, ...]) -> Tuple[str, ...]:
    if not values:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _required(name, value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must contain unique values")
    return values


class HumanDecisionKind(str, Enum):
    SELECT = "SELECT"
    REJECT = "REJECT"
    HOLD = "HOLD"


@dataclass(frozen=True, slots=True)
class AuthorityScope:
    """Exact authority boundary for one case and an ordered set of targets."""

    case_id: str
    target_type: str
    target_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        _required("case_id", self.case_id)
        _required("target_type", self.target_type)
        object.__setattr__(self, "target_ids", _unique_ids("target_ids", self.target_ids))

    @property
    def token(self) -> str:
        return f"case:{self.case_id}|type:{self.target_type}|targets:{','.join(self.target_ids)}"


@dataclass(frozen=True, slots=True)
class PromotionAuthorization:
    authorization_id: str
    decision_id: str
    reviewer: str
    scope: AuthorityScope
    target_commit: str
    evidence_snapshot: Tuple[str, ...]
    policy_version: str
    authorized_at: datetime

    def __post_init__(self) -> None:
        _required("authorization_id", self.authorization_id)
        _required("decision_id", self.decision_id)
        _required("reviewer", self.reviewer)
        _required("target_commit", self.target_commit)
        _required("policy_version", self.policy_version)
        if not self.evidence_snapshot:
            raise ValueError("promotion authorization requires an evidence snapshot")
        if self.authorized_at.tzinfo is None or self.authorized_at.utcoffset() is None:
            raise ValueError("authorized_at must be timezone-aware")


@dataclass(frozen=True, slots=True)
class AuthorityOperation:
    value: object
    receipt: Receipt


class AuthorityLayer:
    """Pure authority boundary for P5.

    The layer can place a Claim into authority hold, validate a human selection,
    issue a narrowly-bound promotion authorization, and derive guards for P2.
    It never calls ``apply_transition`` and therefore cannot advance a Stage itself.
    """

    def __init__(
        self,
        *,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
    ) -> None:
        _required("policy_version", policy_version)
        _required("actor", actor)
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory

    def place_hold(self, *, claim: Claim) -> AuthorityOperation:
        """Return an immutable Claim replacement in AUTHORITY_HOLD."""
        if claim.authority_state not in {AuthorityState.NONE, AuthorityState.HOLD}:
            raise ValueError(
                f"cannot place authority hold from {claim.authority_state.value}"
            )
        held = replace(claim, authority_state=AuthorityState.HOLD)
        return AuthorityOperation(
            held,
            self._receipt(
                operation="AUTHORITY_PLACE_HOLD",
                result=f"HOLD:{claim.claim_id}",
            ),
        )

    def human_selection_guards(
        self,
        *,
        claim: Claim,
        decision: Optional[AuthorityDecision],
        scope: AuthorityScope,
    ) -> FrozenSet[str]:
        """Return P2's human guard only for an exact valid SELECT decision.

        Missing decisions yield no guard. Malformed/mismatched supplied decisions are
        rejected explicitly rather than silently treated as valid.
        """
        if decision is None:
            return frozenset()
        self._validate_scope_for_claim(claim, scope)
        self._validate_decision(claim=claim, decision=decision, scope=scope)
        if decision.decision != HumanDecisionKind.SELECT.value:
            return frozenset()
        if claim.authority_state is not AuthorityState.HOLD:
            raise ValueError("human selection requires claim to be in AUTHORITY_HOLD")
        return frozenset({"human_decision_present"})

    def record_human_selection(
        self,
        *,
        claim: Claim,
        decision: AuthorityDecision,
        scope: AuthorityScope,
    ) -> AuthorityOperation:
        """Record the claim-side authority result after validating the human decision.

        This does not move a Stage; callers must still pass the emitted guard through
        the P2 state machine via P3 orchestration.
        """
        guards = self.human_selection_guards(claim=claim, decision=decision, scope=scope)
        if "human_decision_present" not in guards:
            raise ValueError("decision does not select the target")
        selected = replace(claim, authority_state=AuthorityState.HUMAN_SELECTED)
        return AuthorityOperation(
            selected,
            self._receipt(
                operation="AUTHORITY_HUMAN_SELECTION",
                result=f"SELECTED:{claim.claim_id}:decision={decision.decision_id}",
            ),
        )

    def issue_promotion_authorization(
        self,
        *,
        claim: Claim,
        decision: AuthorityDecision,
        scope: AuthorityScope,
        target_commit: str,
    ) -> AuthorityOperation:
        """Issue immutable authorization bound to an exact future promotion target.

        P5 does not assert that promotion preflight has passed. P6 must validate
        preflight/rollback conditions before a Stage can become PROMOTION_READY.
        """
        _required("target_commit", target_commit)
        self._validate_scope_for_claim(claim, scope)
        self._validate_decision(claim=claim, decision=decision, scope=scope)
        if decision.decision != HumanDecisionKind.SELECT.value:
            raise ValueError("promotion authorization requires a SELECT decision")
        if claim.authority_state not in {
            AuthorityState.HUMAN_SELECTED,
            AuthorityState.PROMOTION_READY,
        }:
            raise ValueError("claim must be human-selected before promotion authorization")

        authorization = PromotionAuthorization(
            authorization_id=self.id_factory("promotion-authorization"),
            decision_id=decision.decision_id,
            reviewer=decision.reviewer,
            scope=scope,
            target_commit=target_commit,
            evidence_snapshot=decision.evidence_snapshot,
            policy_version=self.policy_version,
            authorized_at=self.clock(),
        )
        return AuthorityOperation(
            authorization,
            self._receipt(
                operation="AUTHORITY_ISSUE_PROMOTION_AUTHORIZATION",
                result=(
                    f"AUTHORIZED:{authorization.authorization_id}:"
                    f"target_commit={target_commit}:scope={scope.token}"
                ),
            ),
        )

    def promotion_guards(
        self,
        *,
        authorization: Optional[PromotionAuthorization],
        expected_scope: AuthorityScope,
        target_commit: str,
    ) -> FrozenSet[str]:
        """Return promotion guards without conflating presence with target match."""
        _required("target_commit", target_commit)
        if authorization is None:
            return frozenset()

        guards = {"promotion_authorization_present"}
        if (
            authorization.scope == expected_scope
            and authorization.target_commit == target_commit
            and authorization.policy_version == self.policy_version
        ):
            guards.add("authorization_matches_target")
        return frozenset(guards)

    @staticmethod
    def _validate_scope_for_claim(claim: Claim, scope: AuthorityScope) -> None:
        if scope.case_id != claim.case_id:
            raise ValueError("authority scope case does not match claim case")
        if scope.target_type != "CLAIM":
            raise ValueError("claim authority requires target_type=CLAIM")
        if scope.target_ids != (claim.claim_id,):
            raise ValueError("authority scope must target exactly this claim")

    @staticmethod
    def _validate_decision(
        *,
        claim: Claim,
        decision: AuthorityDecision,
        scope: AuthorityScope,
    ) -> None:
        if decision.target_id != claim.claim_id:
            raise ValueError("authority decision target does not match claim")
        if decision.scope != scope.token:
            raise ValueError("authority decision scope does not match exact structured scope")
        try:
            HumanDecisionKind(decision.decision)
        except ValueError as exc:
            raise ValueError("unsupported human authority decision") from exc

    def _receipt(self, *, operation: str, result: str) -> Receipt:
        return Receipt(
            receipt_id=self.id_factory("receipt"),
            operation=operation,
            input_commit=None,
            input_hashes=(),
            output_commit=None,
            output_hashes=(),
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=result,
        )
