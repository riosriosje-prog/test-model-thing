"""Local DB-migration state machine.

This does not modify GALIA's promoted StageState contract. It records DB-specific
substate while the global Stage remains governed by galia2.state_machine.
"""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet, Mapping, Tuple

from .models import DBMigrationState


class InvalidTransition(ValueError):
    pass


class GuardRejected(ValueError):
    def __init__(self, message: str, *, missing_guards: Tuple[str, ...]) -> None:
        super().__init__(message)
        self.missing_guards = missing_guards


class DBMigrationEvent(str, Enum):
    VALIDATE_MANIFEST = "VALIDATE_MANIFEST"
    CLASSIFY_CHANGE = "CLASSIFY_CHANGE"
    APPLY_SHADOW = "APPLY_SHADOW"
    VERIFY_DATA = "VERIFY_DATA"
    PLACE_DESTRUCTIVE_HOLD = "PLACE_DESTRUCTIVE_HOLD"
    RECORD_HUMAN_APPROVAL = "RECORD_HUMAN_APPROVAL"
    MARK_DEPLOY_READY = "MARK_DEPLOY_READY"
    VERIFY_DEPLOYMENT = "VERIFY_DEPLOYMENT"
    UNCERTAIN_OUTCOME = "UNCERTAIN_OUTCOME"
    RECONCILIATION_AMBIGUOUS = "RECONCILIATION_AMBIGUOUS"


_RULES: Mapping[tuple[DBMigrationState, DBMigrationEvent], tuple[DBMigrationState, FrozenSet[str]]] = {
    (DBMigrationState.DRAFT, DBMigrationEvent.VALIDATE_MANIFEST): (
        DBMigrationState.MANIFEST_VALID,
        frozenset({"migration_identity_valid"}),
    ),
    (DBMigrationState.MANIFEST_VALID, DBMigrationEvent.CLASSIFY_CHANGE): (
        DBMigrationState.CLASSIFIED,
        frozenset({"change_class_known"}),
    ),
    (DBMigrationState.CLASSIFIED, DBMigrationEvent.APPLY_SHADOW): (
        DBMigrationState.SHADOW_APPLIED,
        frozenset({"shadow_only", "migration_identity_valid"}),
    ),
    (DBMigrationState.SHADOW_APPLIED, DBMigrationEvent.VERIFY_DATA): (
        DBMigrationState.DATA_VERIFIED,
        frozenset({"schema_fingerprint_valid", "compatibility_checked"}),
    ),
    (DBMigrationState.DATA_VERIFIED, DBMigrationEvent.PLACE_DESTRUCTIVE_HOLD): (
        DBMigrationState.DESTRUCTIVE_HOLD,
        frozenset({"destructive_change"}),
    ),
    (DBMigrationState.DESTRUCTIVE_HOLD, DBMigrationEvent.RECORD_HUMAN_APPROVAL): (
        DBMigrationState.HUMAN_APPROVED,
        frozenset({"human_decision_present"}),
    ),
    (DBMigrationState.DATA_VERIFIED, DBMigrationEvent.MARK_DEPLOY_READY): (
        DBMigrationState.DEPLOY_READY,
        frozenset({"non_destructive", "preflight_passed"}),
    ),
    (DBMigrationState.HUMAN_APPROVED, DBMigrationEvent.MARK_DEPLOY_READY): (
        DBMigrationState.DEPLOY_READY,
        frozenset({"human_decision_present", "preflight_passed"}),
    ),
    (DBMigrationState.DEPLOY_READY, DBMigrationEvent.VERIFY_DEPLOYMENT): (
        DBMigrationState.DEPLOYED_VERIFIED,
        frozenset({"post_deploy_verified"}),
    ),
    (DBMigrationState.UNCERTAIN_EXECUTION, DBMigrationEvent.RECONCILIATION_AMBIGUOUS): (
        DBMigrationState.FORENSIC_HOLD,
        frozenset({"reconciliation_ambiguous"}),
    ),
}

_UNCERTAIN_SOURCES = frozenset({
    DBMigrationState.CLASSIFIED,
    DBMigrationState.SHADOW_APPLIED,
    DBMigrationState.DATA_VERIFIED,
    DBMigrationState.DESTRUCTIVE_HOLD,
    DBMigrationState.HUMAN_APPROVED,
    DBMigrationState.DEPLOY_READY,
})


def transition(
    state: DBMigrationState,
    event: DBMigrationEvent,
    *,
    satisfied_guards: FrozenSet[str] | set[str] | tuple[str, ...] = frozenset(),
) -> DBMigrationState:
    guards = frozenset(satisfied_guards)

    if event is DBMigrationEvent.UNCERTAIN_OUTCOME and state in _UNCERTAIN_SOURCES:
        required = frozenset({"uncertain_outcome_confirmed"})
        target = DBMigrationState.UNCERTAIN_EXECUTION
    else:
        rule = _RULES.get((state, event))
        if rule is None:
            raise InvalidTransition(f"{event.value} is not valid from {state.value}")
        target, required = rule

    missing = tuple(sorted(required - guards))
    if missing:
        raise GuardRejected(
            f"{state.value} --{event.value}--> {target.value} rejected",
            missing_guards=missing,
        )
    return target
