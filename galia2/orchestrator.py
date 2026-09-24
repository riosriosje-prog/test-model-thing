"""GALIA 2.0 P3 stage orchestrator.

Stdlib-only orchestration layered on P1 schemas and the P2 state machine.
This module deliberately has no Legacy/TMT imports, filesystem persistence,
HEAD mutation, network access, or authority-granting side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, FrozenSet, Iterable, Optional, Tuple
from uuid import uuid4

from .core import Receipt, Stage
from .state_machine import (
    TransitionDecision,
    TransitionEvent,
    apply_transition,
)


class OrchestrationStatus(str, Enum):
    ADVANCED = "ADVANCED"
    ROUTED_FAILURE = "ROUTED_FAILURE"
    BLOCKED = "BLOCKED"


class FailureKind(str, Enum):
    INTEGRITY = "INTEGRITY"
    MATERIAL_CONFLICT = "MATERIAL_CONFLICT"
    PERSISTENCE = "PERSISTENCE"


_FAILURE_EVENT = {
    FailureKind.INTEGRITY: TransitionEvent.INTEGRITY_FAILURE,
    FailureKind.MATERIAL_CONFLICT: TransitionEvent.MATERIAL_CONFLICT,
    FailureKind.PERSISTENCE: TransitionEvent.PERSISTENCE_FAILURE,
}

_FAILURE_GUARD = {
    FailureKind.INTEGRITY: "integrity_failure_confirmed",
    FailureKind.MATERIAL_CONFLICT: "material_conflict_confirmed",
    FailureKind.PERSISTENCE: "persistence_failure_confirmed",
}


class StageExecutionFailure(RuntimeError):
    """Typed executor failure that the orchestrator may route fail-closed."""

    def __init__(self, kind: FailureKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True, slots=True)
class StageExecution:
    output_refs: Tuple[str, ...] = ()
    output_hashes: Tuple[str, ...] = ()
    guards: FrozenSet[str] = frozenset()


@dataclass(frozen=True, slots=True)
class StageValidation:
    passed: bool
    guards: FrozenSet[str] = frozenset()
    failure_kind: FailureKind = FailureKind.INTEGRITY
    message: str = ""


@dataclass(frozen=True, slots=True)
class StageRunContext:
    input_commit: Optional[str] = None
    input_hashes: Tuple[str, ...] = ()
    completed_stage_ids: FrozenSet[str] = frozenset()
    satisfied_guards: FrozenSet[str] = frozenset()


@dataclass(frozen=True, slots=True)
class OrchestrationOutcome:
    stage: Stage
    status: OrchestrationStatus
    receipt: Receipt
    decision: Optional[TransitionDecision] = None
    execution: Optional[StageExecution] = None
    reason: str = ""


Executor = Callable[[Stage, StageRunContext], StageExecution]
Validator = Callable[[Stage, StageExecution, StageRunContext], StageValidation]
Clock = Callable[[], datetime]
ReceiptIdFactory = Callable[[], str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _receipt_id() -> str:
    return f"receipt-{uuid4()}"


class StageOrchestrator:
    """Execute one stage attempt and delegate all state authority to P2 policy.

    P3 deliberately does not choose which event should happen next. The caller
    supplies the requested event; P2 decides whether that event is legal and
    whether its guards are satisfied.
    """

    def __init__(
        self,
        *,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        receipt_id_factory: ReceiptIdFactory = _receipt_id,
    ) -> None:
        if not policy_version.strip():
            raise ValueError("policy_version must be non-empty")
        if not actor.strip():
            raise ValueError("actor must be non-empty")
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.receipt_id_factory = receipt_id_factory

    def run_stage(
        self,
        stage: Stage,
        event: TransitionEvent,
        *,
        executor: Executor,
        validators: Iterable[Validator] = (),
        context: StageRunContext = StageRunContext(),
    ) -> OrchestrationOutcome:
        missing_dependencies = tuple(sorted(set(stage.dependencies) - set(context.completed_stage_ids)))
        if missing_dependencies:
            reason = "missing dependencies: " + ", ".join(missing_dependencies)
            return self._blocked(stage, event, context, reason)

        if stage.blocking_holds:
            reason = "blocking holds: " + ", ".join(stage.blocking_holds)
            return self._blocked(stage, event, context, reason)

        try:
            execution = executor(stage, context)
            if not isinstance(execution, StageExecution):
                raise TypeError("executor must return StageExecution")
        except StageExecutionFailure as exc:
            return self._route_failure(
                stage,
                requested_event=event,
                kind=exc.kind,
                context=context,
                execution=None,
                reason=str(exc),
            )
        except Exception as exc:
            # Unknown executor failures are treated as integrity failures. This is
            # fail-closed and preserves the exception text only as receipt context.
            return self._route_failure(
                stage,
                requested_event=event,
                kind=FailureKind.INTEGRITY,
                context=context,
                execution=None,
                reason=f"untyped executor failure: {type(exc).__name__}: {exc}",
            )

        aggregate_guards = set(context.satisfied_guards)
        aggregate_guards.update(execution.guards)

        for validator in tuple(validators):
            validation = validator(stage, execution, context)
            if not isinstance(validation, StageValidation):
                raise TypeError("validator must return StageValidation")
            aggregate_guards.update(validation.guards)
            if not validation.passed:
                return self._route_failure(
                    replace(stage, output_refs=execution.output_refs),
                    requested_event=event,
                    kind=validation.failure_kind,
                    context=context,
                    execution=execution,
                    reason=validation.message or "validator rejected stage output",
                )

        updated, decision = apply_transition(
            replace(stage, output_refs=execution.output_refs),
            event,
            satisfied_guards=frozenset(aggregate_guards),
        )
        receipt = self._receipt(
            stage=stage,
            requested_event=event,
            context=context,
            output_hashes=execution.output_hashes,
            result=f"PASS:{decision.from_state.value}->{decision.to_state.value}",
        )
        return OrchestrationOutcome(
            stage=updated,
            status=OrchestrationStatus.ADVANCED,
            receipt=receipt,
            decision=decision,
            execution=execution,
        )

    def _blocked(
        self,
        stage: Stage,
        event: TransitionEvent,
        context: StageRunContext,
        reason: str,
    ) -> OrchestrationOutcome:
        receipt = self._receipt(
            stage=stage,
            requested_event=event,
            context=context,
            output_hashes=(),
            result=f"BLOCKED:{reason}",
        )
        return OrchestrationOutcome(
            stage=stage,
            status=OrchestrationStatus.BLOCKED,
            receipt=receipt,
            reason=reason,
        )

    def _route_failure(
        self,
        stage: Stage,
        *,
        requested_event: TransitionEvent,
        kind: FailureKind,
        context: StageRunContext,
        execution: Optional[StageExecution],
        reason: str,
    ) -> OrchestrationOutcome:
        failure_event = _FAILURE_EVENT[kind]
        failure_guard = _FAILURE_GUARD[kind]
        routed, decision = apply_transition(
            stage,
            failure_event,
            satisfied_guards={failure_guard},
        )
        receipt = self._receipt(
            stage=stage,
            requested_event=requested_event,
            context=context,
            output_hashes=() if execution is None else execution.output_hashes,
            result=(
                f"ROUTED_FAILURE:{kind.value}:"
                f"{decision.from_state.value}->{decision.to_state.value}:{reason}"
            ),
        )
        return OrchestrationOutcome(
            stage=routed,
            status=OrchestrationStatus.ROUTED_FAILURE,
            receipt=receipt,
            decision=decision,
            execution=execution,
            reason=reason,
        )

    def _receipt(
        self,
        *,
        stage: Stage,
        requested_event: TransitionEvent,
        context: StageRunContext,
        output_hashes: Tuple[str, ...],
        result: str,
    ) -> Receipt:
        return Receipt(
            receipt_id=self.receipt_id_factory(),
            operation=f"STAGE:{stage.stage_type}:{requested_event.value}",
            input_commit=context.input_commit,
            input_hashes=context.input_hashes,
            output_commit=None,  # P3 does not persist or advance HEAD.
            output_hashes=output_hashes,
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=result,
        )
