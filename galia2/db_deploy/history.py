"""Applied-migration history verifier for GALIA DB deployment v0.2-c2.

This module is intentionally pure: it does not write to a database, filesystem,
GALIA HEAD, or authority records. It verifies an externally retained applied
migration history and can construct the next immutable record in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import re
from typing import Mapping, Optional, Tuple

from .models import MigrationCandidate, canonical_json_bytes

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _required(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _hash(name: str, value: str) -> str:
    _required(name, value)
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256")
    return value.lower()


def _aware(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


class HistoryValidationError(RuntimeError):
    """Applied migration history is malformed, inconsistent, or tampered."""


class HistoryStatus(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    ALREADY_APPLIED = "ALREADY_APPLIED"


@dataclass(frozen=True, slots=True)
class HistoryDecision:
    status: HistoryStatus
    reason: str


@dataclass(frozen=True, slots=True)
class AppliedMigrationRecord:
    sequence: int
    migration_id: str
    migration_sha256: str
    schema_version_before: str
    schema_version_after: str
    schema_fingerprint_after: str
    evidence_sha256: str
    receipt_id: str
    applied_at: datetime
    previous_record_hash: Optional[str]
    record_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or self.sequence < 1:
            raise ValueError("sequence must be a positive integer")
        _required("migration_id", self.migration_id)
        object.__setattr__(
            self,
            "migration_sha256",
            _hash("migration_sha256", self.migration_sha256),
        )
        _required("schema_version_before", self.schema_version_before)
        _required("schema_version_after", self.schema_version_after)
        object.__setattr__(
            self,
            "schema_fingerprint_after",
            _hash("schema_fingerprint_after", self.schema_fingerprint_after),
        )
        object.__setattr__(
            self,
            "evidence_sha256",
            _hash("evidence_sha256", self.evidence_sha256),
        )
        _required("receipt_id", self.receipt_id)
        _aware("applied_at", self.applied_at)
        if self.previous_record_hash is not None:
            object.__setattr__(
                self,
                "previous_record_hash",
                _hash("previous_record_hash", self.previous_record_hash),
            )
        object.__setattr__(self, "record_hash", _hash("record_hash", self.record_hash))

    def payload_dict(self) -> dict[str, object]:
        return {
            "applied_at": self.applied_at.isoformat(),
            "evidence_sha256": self.evidence_sha256,
            "migration_id": self.migration_id,
            "migration_sha256": self.migration_sha256,
            "previous_record_hash": self.previous_record_hash,
            "receipt_id": self.receipt_id,
            "schema_fingerprint_after": self.schema_fingerprint_after,
            "schema_version_after": self.schema_version_after,
            "schema_version_before": self.schema_version_before,
            "sequence": self.sequence,
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload_dict(), "record_hash": self.record_hash}

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        migration_id: str,
        migration_sha256: str,
        schema_version_before: str,
        schema_version_after: str,
        schema_fingerprint_after: str,
        evidence_sha256: str,
        receipt_id: str,
        applied_at: datetime,
        previous_record_hash: Optional[str],
    ) -> "AppliedMigrationRecord":
        payload = {
            "applied_at": _aware("applied_at", applied_at).isoformat(),
            "evidence_sha256": _hash("evidence_sha256", evidence_sha256),
            "migration_id": _required("migration_id", migration_id),
            "migration_sha256": _hash("migration_sha256", migration_sha256),
            "previous_record_hash": (
                None
                if previous_record_hash is None
                else _hash("previous_record_hash", previous_record_hash)
            ),
            "receipt_id": _required("receipt_id", receipt_id),
            "schema_fingerprint_after": _hash(
                "schema_fingerprint_after", schema_fingerprint_after
            ),
            "schema_version_after": _required(
                "schema_version_after", schema_version_after
            ),
            "schema_version_before": _required(
                "schema_version_before", schema_version_before
            ),
            "sequence": sequence,
        }
        if not isinstance(sequence, int) or sequence < 1:
            raise ValueError("sequence must be a positive integer")
        record_hash = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return cls(record_hash=record_hash, **payload)


def verify_history(
    records: Tuple[AppliedMigrationRecord, ...],
) -> Tuple[AppliedMigrationRecord, ...]:
    """Verify hash chain, sequence, uniqueness, and schema-version continuity."""
    previous_hash: Optional[str] = None
    previous_schema_after: Optional[str] = None
    seen_ids: set[str] = set()

    for expected_sequence, record in enumerate(records, start=1):
        if record.sequence != expected_sequence:
            raise HistoryValidationError(
                f"sequence break: expected {expected_sequence}, got {record.sequence}"
            )
        if record.previous_record_hash != previous_hash:
            raise HistoryValidationError(
                f"history chain break at migration {record.migration_id}"
            )
        expected_hash = hashlib.sha256(
            canonical_json_bytes(record.payload_dict())
        ).hexdigest()
        if record.record_hash != expected_hash:
            raise HistoryValidationError(
                f"record hash mismatch at migration {record.migration_id}"
            )
        if record.migration_id in seen_ids:
            raise HistoryValidationError(
                f"duplicate applied migration_id: {record.migration_id}"
            )
        if (
            previous_schema_after is not None
            and record.schema_version_before != previous_schema_after
        ):
            raise HistoryValidationError(
                "schema lineage break: "
                f"{record.schema_version_before} != {previous_schema_after}"
            )

        seen_ids.add(record.migration_id)
        previous_hash = record.record_hash
        previous_schema_after = record.schema_version_after

    return tuple(records)


def verify_artifact_identity(
    records: Tuple[AppliedMigrationRecord, ...],
    artifact_hashes: Mapping[str, str],
) -> None:
    """Detect mutation/deletion of any migration artifact recorded as applied."""
    verify_history(records)
    for record in records:
        current = artifact_hashes.get(record.migration_id)
        if current is None:
            raise HistoryValidationError(
                f"applied migration artifact missing: {record.migration_id}"
            )
        current = _hash(f"artifact_hashes[{record.migration_id}]", current)
        if current != record.migration_sha256:
            raise HistoryValidationError(
                f"applied migration mutated: {record.migration_id}"
            )


def validate_candidate_against_history(
    candidate: MigrationCandidate,
    records: Tuple[AppliedMigrationRecord, ...],
) -> HistoryDecision:
    """Reject ID reuse and parent-schema drift before any migration execution."""
    verified = verify_history(records)

    for record in verified:
        if record.migration_id != candidate.migration_id:
            continue
        if (
            record.migration_sha256 == candidate.migration_sha256
            and record.schema_version_before == candidate.parent_schema_version
            and record.schema_version_after == candidate.target_schema_version
        ):
            return HistoryDecision(
                HistoryStatus.ALREADY_APPLIED,
                "exact migration identity already exists in applied history",
            )
        raise HistoryValidationError(
            f"migration_id reused with different identity: {candidate.migration_id}"
        )

    if verified:
        current_schema_version = verified[-1].schema_version_after
        if candidate.parent_schema_version != current_schema_version:
            raise HistoryValidationError(
                "candidate parent schema does not match applied history: "
                f"{candidate.parent_schema_version} != {current_schema_version}"
            )

    return HistoryDecision(
        HistoryStatus.ELIGIBLE,
        "candidate is new and parent schema matches applied history",
    )


def append_applied_record(
    *,
    records: Tuple[AppliedMigrationRecord, ...],
    candidate: MigrationCandidate,
    schema_fingerprint_after: str,
    evidence_sha256: str,
    receipt_id: str,
    applied_at: datetime,
) -> Tuple[AppliedMigrationRecord, ...]:
    """Return a new immutable history tuple; never mutates the supplied history."""
    decision = validate_candidate_against_history(candidate, records)
    if decision.status is not HistoryStatus.ELIGIBLE:
        raise HistoryValidationError(
            f"cannot append migration {candidate.migration_id}: {decision.status.value}"
        )

    previous_hash = records[-1].record_hash if records else None
    record = AppliedMigrationRecord.create(
        sequence=len(records) + 1,
        migration_id=candidate.migration_id,
        migration_sha256=candidate.migration_sha256,
        schema_version_before=candidate.parent_schema_version,
        schema_version_after=candidate.target_schema_version,
        schema_fingerprint_after=schema_fingerprint_after,
        evidence_sha256=evidence_sha256,
        receipt_id=receipt_id,
        applied_at=applied_at,
        previous_record_hash=previous_hash,
    )
    return (*records, record)
