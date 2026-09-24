"""Bind DB migration evidence to the existing GALIA Receipt primitive."""

from __future__ import annotations

from datetime import datetime

from galia2.core import Receipt

from .models import DBMigrationEvidence


def build_migration_receipt(
    *,
    evidence: DBMigrationEvidence,
    receipt_id: str,
    policy_version: str,
    actor: str,
    timestamp: datetime,
    operation: str = "DB_MIGRATION_SHADOW",
    input_commit: str | None = None,
    output_commit: str | None = None,
    result: str = "PASS",
) -> Receipt:
    return Receipt(
        receipt_id=receipt_id,
        operation=operation,
        input_commit=input_commit,
        input_hashes=(
            evidence.migration_sha256,
            evidence.schema_fingerprint_before,
        ),
        output_commit=output_commit,
        output_hashes=(
            evidence.sha256,
            evidence.schema_fingerprint_after,
        ),
        policy_version=policy_version,
        actor=actor,
        timestamp=timestamp,
        result=result,
    )
