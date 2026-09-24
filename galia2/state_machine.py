"""GALIA 2.0 P2 stage state machine.

Pure, stdlib-only transition policy layered on P1 schemas.
No Legacy/TMT imports, persistence writes, HEAD mutation, or promotion side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import FrozenSet, Mapping, Tuple

from .core import Stage, StageState


class TransitionError(ValueError):
    """Base class for rejected stage transitions."""


class InvalidTransition(TransitionError):
    """Raised when no transition rule exists for the current state/event."""


class GuardRejected(TransitionError):
    """Raised when a transition exists but mandatory guards are unsatisfied."""

    def __init__(self, message: str, *, missing_guards: Tuple[str, ...]) -> None:
        super().__init__(message)
        self.missing_guards = missing_guards


class TransitionEvent(str, Enum):
    INGEST_CONFIRMED = "INGEST_CONFIRMED"
    NORMALIZATION_COMPLETE = "NORMALIZATION_COMPLETE"
    DERIVATION_COMPLETE = "DERIVATION_COMPLETE"
    VALIDATION_PASSED = "VALIDATION_PASSED"
    PLACE_AUTHORITY_HOLD = "PLACE_AUTHORITY_HOLD"
    HUMAN_SELECTION_RECORDED = "HUMAN_SELECTION_RECORDED"
    PREFLIGHT_PASSED = "PREFLIGHT_PASSED"
    PROMOTION_AUTHORIZED = "PROMOTION_AUTHORIZED"

    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    MATERIAL_CONFLICT = "MATERIAL_CONFLICT"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"
    NEW_MATERIAL_EVIDENCE = "NEW_MATERIAL_EVIDENCE"


@dataclass(frozen=True, slots=True)
class TransitionRule:
    from_state: StageState
    event: TransitionEvent
    to_state: StageState
    required_guards: FrozenSet[str] = frozenset()
    human_boundary: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class TransitionDecision:
    stage_id: str
    case_id: str
    from_state: StageState
    event: TransitionEvent
    to_state: StageState
    satisfied_guards: FrozenSet[str]
    required_guards: FrozenSet[str]
    human_boundary: bool

    @property
    def crosses_human_boundary(self) -> bool:
        return self.human_boundary


_PRIMARY_RULES: Tuple[TransitionRule, ...] = (
    TransitionRule(
        StageState.DISCOVERED,
        TransitionEvent.INGEST_CONFIRMED,
        StageState.INGESTED,
        frozenset({"source_artifact_valid"}),
        description="A discovered source may enter ingest only after artifact validation.",
    ),
    TransitionRule(
        StageState.INGESTED,
        TransitionEvent.NORMALIZATION_COMPLETE,
        StageState.NORMALIZED,
        frozenset({"lineage_complete"}),
        description="Normalization requires complete lineage to the ingested input.",
    ),
    TransitionRule(
        StageState.NORMALIZED,
        TransitionEvent.DERIVATION_COMPLETE,
        StageState.DERIVED,
        frozenset({"output_hash_valid"}),
        description="Derived output must be content-addressable before advancing.",
    ),
    TransitionRule(
        StageState.DERIVED,
        TransitionEvent.VALIDATION_PASSED,
        StageState.VALIDATED,
        frozenset({"required_validations_passed"}),
        description="Execution success alone cannot create a validated result.",
    ),
    TransitionRule(
        StageState.VALIDATED,
        TransitionEvent.PLACE_AUTHORITY_HOLD,
        StageState.AUTHORITY_HOLD,
        frozenset({"evidence_snapshot_present"}),
        description="Validated material enters an explicit authority hold before human selection.",
    ),
    TransitionRule(
        StageState.AUTHORITY_HOLD,
        TransitionEvent.HUMAN_SELECTION_RECORDED,
        StageState.HUMAN_SELECTED,
        frozenset({"human_decision_present"}),
        human_boundary=True,
        description="Only an explicit human authority decision can clear AUTHORITY_HOLD.",
    ),
    TransitionRule(
        StageState.HUMAN_SELECTED,
        TransitionEvent.PREFLIGHT_PASSED,
        StageState.PROMOTION_READY,
        frozenset({"preflight_passed", "rollback_target_verified"}),
        description="Promotion readiness requires preflight and a verified rollback target.",
    ),
    TransitionRule(
        StageState.PROMOTION_READY,
        TransitionEvent.PROMOTION_AUTHORIZED,
        StageState.CANONICAL,
        frozenset({"promotion_authorization_present", "authorization_matches_target"}),
        human_boundary=True,
        description="Canonical promotion requires explicit authorization bound to the target.",
    ),
    TransitionRule(
        StageState.CANONICAL,
        TransitionEvent.NEW_MATERIAL_EVIDENCE,
        StageState.REOPENED,
        frozenset({"new_material_evidence"}),
        description="Canonical history may be reopened without destructive overwrite.",
    ),
)


_FAILURE_TARGETS: Mapping[TransitionEvent, StageState] = MappingProxyType({
    TransitionEvent.INTEGRITY_FAILURE: StageState.QUARANTINED,
    TransitionEvent.MATERIAL_CONFLICT: StageState.DISCREPANCY_REVIEW,
    TransitionEvent.PERSISTENCE_FAILURE: StageState.RECOVERY_INTAKE,
})

_FAILURE_GUARDS: Mapping[TransitionEvent, FrozenSet[str]] = MappingProxyType({
    TransitionEvent.INTEGRITY_FAILURE: frozenset({"integrity_failure_confirmed"}),
    TransitionEvent.MATERIAL_CONFLICT: frozenset({"material_conflict_confirmed"}),
    TransitionEvent.PERSISTENCE_FAILURE: frozenset({"persistence_failure_confirmed"}),
})

# Routing an already isolated failure state into another failure state is deliberately
# not implicit. A later recovery patch must make those semantics explicit.
_FAILURE_SOURCE_STATES: FrozenSet[StageState] = frozenset({
    StageState.DISCOVERED,
    StageState.INGESTED,
    StageState.NORMALIZED,
    StageState.DERIVED,
    StageState.VALIDATED,
    StageState.AUTHORITY_HOLD,
    StageState.HUMAN_SELECTED,
    StageState.PROMOTION_READY,
    StageState.CANONICAL,
    StageState.REOPENED,
})

_RULE_INDEX = MappingProxyType({(rule.from_state, rule.event): rule for rule in _PRIMARY_RULES})


# Explicit constitutional safety assertions for the v1 core.
FORBIDDEN_DIRECT_TRANSITIONS: FrozenSet[tuple[StageState, StageState]] = frozenset({
    (StageState.DERIVED, StageState.CANONICAL),
    (StageState.VALIDATED, StageState.CANONICAL),
    (StageState.AUTHORITY_HOLD, StageState.CANONICAL),
    (StageState.RECOVERY_INTAKE, StageState.CANONICAL),
    (StageState.QUARANTINED, StageState.CANONICAL),
    (StageState.DISCREPANCY_REVIEW, StageState.CANONICAL),
})


def transition_rule(state: StageState, event: TransitionEvent) -> TransitionRule:
    """Return the immutable rule for ``state`` + ``event`` or reject it."""
    primary = _RULE_INDEX.get((state, event))
    if primary is not None:
        return primary

    if event in _FAILURE_TARGETS and state in _FAILURE_SOURCE_STATES:
        return TransitionRule(
            from_state=state,
            event=event,
            to_state=_FAILURE_TARGETS[event],
            required_guards=_FAILURE_GUARDS[event],
            description="Fail-closed routing into an isolated review/recovery state.",
        )

    raise InvalidTransition(f"event {event.value} is not valid from state {state.value}")


def evaluate_transition(
    stage: Stage,
    event: TransitionEvent,
    *,
    satisfied_guards: FrozenSet[str] | set[str] | tuple[str, ...] = frozenset(),
) -> TransitionDecision:
    """Evaluate a transition without mutating state.

    This function is intentionally pure. It has no side effects and cannot promote,
    persist, or mutate Legacy. Later orchestration patches may consume its decision.
    """
    guards = frozenset(satisfied_guards)
    rule = transition_rule(stage.state, event)
    missing = tuple(sorted(rule.required_guards - guards))
    if missing:
        raise GuardRejected(
            f"transition {stage.state.value} --{event.value}--> {rule.to_state.value} "
            f"rejected; missing guards: {', '.join(missing)}",
            missing_guards=missing,
        )

    if (stage.state, rule.to_state) in FORBIDDEN_DIRECT_TRANSITIONS:
        # Defensive assertion: current tables should make this unreachable.
        raise InvalidTransition(
            f"forbidden direct transition {stage.state.value} -> {rule.to_state.value}"
        )

    return TransitionDecision(
        stage_id=stage.stage_id,
        case_id=stage.case_id,
        from_state=stage.state,
        event=event,
        to_state=rule.to_state,
        satisfied_guards=guards,
        required_guards=rule.required_guards,
        human_boundary=rule.human_boundary,
    )


def apply_transition(
    stage: Stage,
    event: TransitionEvent,
    *,
    satisfied_guards: FrozenSet[str] | set[str] | tuple[str, ...] = frozenset(),
) -> tuple[Stage, TransitionDecision]:
    """Return a new immutable Stage plus the decision that justified it."""
    decision = evaluate_transition(stage, event, satisfied_guards=satisfied_guards)
    return replace(stage, state=decision.to_state), decision


def allowed_events(state: StageState) -> Tuple[TransitionEvent, ...]:
    """Enumerate direct events allowed from a state, independent of guard satisfaction."""
    events = [rule.event for rule in _PRIMARY_RULES if rule.from_state == state]
    if state in _FAILURE_SOURCE_STATES:
        events.extend(_FAILURE_TARGETS.keys())
    return tuple(dict.fromkeys(events))
