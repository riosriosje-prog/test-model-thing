# GALIA DB Deployment Protocol v0.1-c1

Status: **CANDIDATE / NOT PROMOTED**

This candidate adapts database migration evidence to the promoted GALIA 2.0
governance primitives. It does not modify the global StageState contract and
does not add a second authority, preflight, persistence, or recovery subsystem.

## Boundaries

- No direct production-connection primitive exists in c1.
- Execution is caller-supplied and shadow-only by contract.
- Applied migration identity is SHA-256 bound.
- Schema state is independently fingerprinted from canonical JSON descriptors.
- Destructive changes route to authority hold; they do not auto-promote.
- Uncertain execution outcomes route through existing PERSISTENCE failure and
  RecoveryTrigger.PARTIAL_COMMIT / EXECUTION_INTERRUPTION semantics.
- Existing core Receipt is reused; DBMigrationEvidence is hashed into it.
- No mutation of GALIA Legacy or promoted GALIA 2.0 global state contracts.

## Candidate package

galia2/db_deploy/

The local DBMigrationState is a DB-specific substate only. Global authority and
promotion remain controlled by galia2.state_machine, authority.py, preflight.py,
persistence.py, and recovery_audit.py.

## Promotion condition

PASS is eligibility only. Promotion requires an explicit human decision bound to
the exact candidate/commit/evidence set.
