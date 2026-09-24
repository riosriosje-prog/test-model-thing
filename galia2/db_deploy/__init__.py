"""GALIA 2.0 database-deployment candidate adapter.

Candidate: GALIA-DB-DEPLOYMENT-v0.1-c1.
This package is stdlib-only and does not provide direct production deployment.
"""

from .classifier import Classification, classify_delta
from .executor import DBMigrationExecution, ShadowApplyResult, UncertainExecutionOutcome, execute_shadow
from .fingerprint import schema_fingerprint, verify_schema_fingerprint
from .migration_state import DBMigrationEvent, GuardRejected, InvalidTransition, transition
from .models import (
    ChangeClass,
    DBMigrationEvidence,
    DBMigrationState,
    MigrationCandidate,
    SchemaDelta,
)
from .receipts import build_migration_receipt
from .recovery_adapter import recovery_trigger_for_uncertain
from .validators import requires_authority_hold, validate_execution

__all__ = [
    "ChangeClass",
    "Classification",
    "DBMigrationEvent",
    "DBMigrationEvidence",
    "DBMigrationExecution",
    "DBMigrationState",
    "GuardRejected",
    "InvalidTransition",
    "MigrationCandidate",
    "SchemaDelta",
    "ShadowApplyResult",
    "UncertainExecutionOutcome",
    "build_migration_receipt",
    "classify_delta",
    "execute_shadow",
    "recovery_trigger_for_uncertain",
    "requires_authority_hold",
    "schema_fingerprint",
    "transition",
    "validate_execution",
    "verify_schema_fingerprint",
]
