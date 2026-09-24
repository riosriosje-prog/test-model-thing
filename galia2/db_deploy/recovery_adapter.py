"""Map uncertain DB outcomes into promoted GALIA recovery semantics."""

from __future__ import annotations

from galia2.recovery_audit import RecoveryTrigger


def recovery_trigger_for_uncertain(*, commit_may_have_occurred: bool) -> RecoveryTrigger:
    if commit_may_have_occurred:
        return RecoveryTrigger.PARTIAL_COMMIT
    return RecoveryTrigger.EXECUTION_INTERRUPTION
