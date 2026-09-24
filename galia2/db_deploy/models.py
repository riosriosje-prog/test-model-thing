"""Immutable data contracts for GALIA DB deployment candidate c1."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple

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


def canonical_json_bytes(value: object) -> bytes:
    """Canonical JSON policy aligned with GALIA 2.0 persistence."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class ChangeClass(str, Enum):
    ADDITIVE = "ADDITIVE"
    COMPATIBLE_TRANSFORM = "COMPATIBLE_TRANSFORM"
    BACKFILL = "BACKFILL"
    RENAMING = "RENAMING"
    DEPRECATION = "DEPRECATION"
    DESTRUCTIVE = "DESTRUCTIVE"
    CORRECTIVE = "CORRECTIVE"


class DBMigrationState(str, Enum):
    DRAFT = "DRAFT"
    MANIFEST_VALID = "MANIFEST_VALID"
    CLASSIFIED = "CLASSIFIED"
    SHADOW_APPLIED = "SHADOW_APPLIED"
    DATA_VERIFIED = "DATA_VERIFIED"
    DESTRUCTIVE_HOLD = "DESTRUCTIVE_HOLD"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    DEPLOY_READY = "DEPLOY_READY"
    DEPLOYED_VERIFIED = "DEPLOYED_VERIFIED"
    UNCERTAIN_EXECUTION = "UNCERTAIN_EXECUTION"
    FORENSIC_HOLD = "FORENSIC_HOLD"


@dataclass(frozen=True, slots=True)
class SchemaDelta:
    """Explicit schema-diff facts; c1 deliberately does not parse SQL heuristically."""

    added_objects: Tuple[str, ...] = ()
    removed_objects: Tuple[str, ...] = ()
    altered_objects: Tuple[str, ...] = ()
    renamed_objects: Tuple[Tuple[str, str], ...] = ()
    backfill_required: bool = False
    corrective: bool = False
    backward_compatible: bool = True

    def __post_init__(self) -> None:
        for name, values in (
            ("added_objects", self.added_objects),
            ("removed_objects", self.removed_objects),
            ("altered_objects", self.altered_objects),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must contain unique values")
            for value in values:
                _required(name, value)

        sources = []
        targets = []
        for source, target in self.renamed_objects:
            _required("rename source", source)
            _required("rename target", target)
            sources.append(source)
            targets.append(target)
        if len(set(sources)) != len(sources) or len(set(targets)) != len(targets):
            raise ValueError("renamed_objects must have unique sources and targets")

    @property
    def empty(self) -> bool:
        return not (
            self.added_objects
            or self.removed_objects
            or self.altered_objects
            or self.renamed_objects
            or self.backfill_required
            or self.corrective
        )


@dataclass(frozen=True, slots=True)
class MigrationCandidate:
    candidate_id: str
    migration_id: str
    parent_schema_version: str
    target_schema_version: str
    migration_sha256: str
    change_class: ChangeClass
    destructive: bool
    parent_receipt_sha256: Optional[str] = None

    def __post_init__(self) -> None:
        _required("candidate_id", self.candidate_id)
        _required("migration_id", self.migration_id)
        _required("parent_schema_version", self.parent_schema_version)
        _required("target_schema_version", self.target_schema_version)
        object.__setattr__(self, "migration_sha256", _hash("migration_sha256", self.migration_sha256))
        if self.parent_receipt_sha256 is not None:
            object.__setattr__(
                self,
                "parent_receipt_sha256",
                _hash("parent_receipt_sha256", self.parent_receipt_sha256),
            )


@dataclass(frozen=True, slots=True)
class DBMigrationEvidence:
    candidate_id: str
    migration_id: str
    migration_sha256: str
    change_class: ChangeClass
    schema_version_before: str
    schema_version_after: str
    schema_fingerprint_before: str
    schema_fingerprint_after: str
    shadow_result: str
    backfill_result: str
    compatibility_result: str
    destructive_change: bool

    def __post_init__(self) -> None:
        _required("candidate_id", self.candidate_id)
        _required("migration_id", self.migration_id)
        object.__setattr__(self, "migration_sha256", _hash("migration_sha256", self.migration_sha256))
        _required("schema_version_before", self.schema_version_before)
        _required("schema_version_after", self.schema_version_after)
        object.__setattr__(
            self,
            "schema_fingerprint_before",
            _hash("schema_fingerprint_before", self.schema_fingerprint_before),
        )
        object.__setattr__(
            self,
            "schema_fingerprint_after",
            _hash("schema_fingerprint_after", self.schema_fingerprint_after),
        )
        _required("shadow_result", self.shadow_result)
        _required("backfill_result", self.backfill_result)
        _required("compatibility_result", self.compatibility_result)

    def as_dict(self) -> dict[str, object]:
        return {
            "backfill_result": self.backfill_result,
            "candidate_id": self.candidate_id,
            "change_class": self.change_class.value,
            "compatibility_result": self.compatibility_result,
            "destructive_change": self.destructive_change,
            "migration_id": self.migration_id,
            "migration_sha256": self.migration_sha256,
            "schema_fingerprint_after": self.schema_fingerprint_after,
            "schema_fingerprint_before": self.schema_fingerprint_before,
            "schema_version_after": self.schema_version_after,
            "schema_version_before": self.schema_version_before,
            "shadow_result": self.shadow_result,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.as_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()
