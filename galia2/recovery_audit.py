"""GALIA 2.0 P8 recovery and audit layer.

P8 adds four controls over promoted P1-P7:
- append-only, hash-chained audit events;
- immutable retention of failed execution attempts;
- recovery intake that inspects but does not mutate canonical state;
- explicitly authorized rollback to a previously verified generation.

P8 never creates new evidentiary or canonical authority. A rollback only repoints
HEAD to an already-existing verified generation and requires a human recovery
authorization bound to the exact observed HEAD bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable, Optional, Tuple
from uuid import uuid4

from .core import Receipt
from .persistence import (
    GenerationManifest,
    GenerationStore,
    HeadPointer,
    PersistencePublishError,
    PersistenceValidationError,
)

Clock = Callable[[], datetime]
IdFactory = Callable[[str], str]

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_AUDIT_FILE = "events.jsonl"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _required(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _hash(name: str, value: str) -> str:
    _required(name, value)
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a 64-character hexadecimal SHA-256")
    return value.lower()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _aware(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value


class AuditEventType(str, Enum):
    RECOVERY_INTAKE = "RECOVERY_INTAKE"
    FAILED_ATTEMPT_RETAINED = "FAILED_ATTEMPT_RETAINED"
    ROLLBACK_ATTEMPTED = "ROLLBACK_ATTEMPTED"
    ROLLBACK_SUCCEEDED = "ROLLBACK_SUCCEEDED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class RecoveryTrigger(str, Enum):
    HEAD_CORRUPTION = "HEAD_CORRUPTION"
    MANIFEST_CORRUPTION = "MANIFEST_CORRUPTION"
    PAYLOAD_CORRUPTION = "PAYLOAD_CORRUPTION"
    PARTIAL_COMMIT = "PARTIAL_COMMIT"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    DERIVATION_LOSS = "DERIVATION_LOSS"
    INDEX_LOSS = "INDEX_LOSS"
    EXECUTION_INTERRUPTION = "EXECUTION_INTERRUPTION"
    LINEAGE_BREAK = "LINEAGE_BREAK"
    AUTHORITY_RECORD_MISMATCH = "AUTHORITY_RECORD_MISMATCH"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    event_type: AuditEventType
    actor: str
    timestamp: datetime
    policy_version: str
    affected_refs: Tuple[str, ...]
    details: str
    previous_event_hash: Optional[str]
    event_hash: str

    def __post_init__(self) -> None:
        _required("event_id", self.event_id)
        _required("actor", self.actor)
        _required("policy_version", self.policy_version)
        _required("details", self.details)
        _aware("timestamp", self.timestamp)
        if self.previous_event_hash is not None:
            object.__setattr__(self, "previous_event_hash", _hash("previous_event_hash", self.previous_event_hash))
        object.__setattr__(self, "event_hash", _hash("event_hash", self.event_hash))

    def payload_dict(self) -> dict[str, object]:
        return {
            "affected_refs": list(self.affected_refs),
            "actor": self.actor,
            "details": self.details,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "policy_version": self.policy_version,
            "previous_event_hash": self.previous_event_hash,
            "timestamp": self.timestamp.isoformat(),
        }

    def as_dict(self) -> dict[str, object]:
        return {**self.payload_dict(), "event_hash": self.event_hash}

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        event_type: AuditEventType,
        actor: str,
        timestamp: datetime,
        policy_version: str,
        affected_refs: Tuple[str, ...] = (),
        details: str,
        previous_event_hash: Optional[str],
    ) -> "AuditEvent":
        payload = {
            "affected_refs": list(affected_refs),
            "actor": actor,
            "details": details,
            "event_id": event_id,
            "event_type": event_type.value,
            "policy_version": policy_version,
            "previous_event_hash": previous_event_hash,
            "timestamp": timestamp.isoformat(),
        }
        return cls(
            event_id=event_id,
            event_type=event_type,
            actor=actor,
            timestamp=timestamp,
            policy_version=policy_version,
            affected_refs=affected_refs,
            details=details,
            previous_event_hash=previous_event_hash,
            event_hash=_sha256_bytes(_canonical_json_bytes(payload)),
        )


class AuditValidationError(RuntimeError):
    """Raised when the append-only audit chain is malformed or tampered."""


class RecoveryValidationError(RuntimeError):
    """Raised when a recovery action is not exactly authorized or verified."""


class AuditLedger:
    """Append-only JSONL audit log with per-event hash chaining."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
    ) -> None:
        _required("policy_version", policy_version)
        _required("actor", actor)
        self.root = Path(root)
        self.audit_dir = self.root / "audit"
        self.path = self.audit_dir / _AUDIT_FILE
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def read_events(self) -> Tuple[AuditEvent, ...]:
        if not self.path.exists():
            return ()
        out = []
        previous: Optional[str] = None
        for lineno, raw in enumerate(self.path.read_bytes().splitlines(), start=1):
            if not raw:
                raise AuditValidationError(f"empty audit record at line {lineno}")
            try:
                data = json.loads(raw.decode("utf-8"))
                event = AuditEvent(
                    event_id=data["event_id"],
                    event_type=AuditEventType(data["event_type"]),
                    actor=data["actor"],
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    policy_version=data["policy_version"],
                    affected_refs=tuple(data["affected_refs"]),
                    details=data["details"],
                    previous_event_hash=data["previous_event_hash"],
                    event_hash=data["event_hash"],
                )
            except Exception as exc:
                raise AuditValidationError(f"invalid audit record at line {lineno}: {exc}") from exc
            if event.previous_event_hash != previous:
                raise AuditValidationError(f"audit chain break at line {lineno}")
            expected = _sha256_bytes(_canonical_json_bytes(event.payload_dict()))
            if event.event_hash != expected:
                raise AuditValidationError(f"audit event hash mismatch at line {lineno}")
            previous = event.event_hash
            out.append(event)
        return tuple(out)

    def append(
        self,
        event_type: AuditEventType,
        *,
        affected_refs: Tuple[str, ...] = (),
        details: str,
    ) -> AuditEvent:
        events = self.read_events()
        previous = events[-1].event_hash if events else None
        event = AuditEvent.create(
            event_id=self.id_factory("audit"),
            event_type=event_type,
            actor=self.actor,
            timestamp=self.clock(),
            policy_version=self.policy_version,
            affected_refs=affected_refs,
            details=details,
            previous_event_hash=previous,
        )
        line = _canonical_json_bytes(event.as_dict()) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        try:
            with os.fdopen(fd, "ab", closefd=False) as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        finally:
            os.close(fd)
        return event


@dataclass(frozen=True, slots=True)
class FailedAttemptRecord:
    attempt_id: str
    case_id: str
    stage_id: str
    failure_class: str
    message: str
    input_refs: Tuple[str, ...]
    output_refs: Tuple[str, ...]
    timestamp: datetime

    def __post_init__(self) -> None:
        _required("attempt_id", self.attempt_id)
        _required("case_id", self.case_id)
        _required("stage_id", self.stage_id)
        _required("failure_class", self.failure_class)
        _required("message", self.message)
        _aware("timestamp", self.timestamp)

    def to_bytes(self) -> bytes:
        return _canonical_json_bytes({
            "attempt_id": self.attempt_id,
            "case_id": self.case_id,
            "failure_class": self.failure_class,
            "input_refs": list(self.input_refs),
            "message": self.message,
            "output_refs": list(self.output_refs),
            "stage_id": self.stage_id,
            "timestamp": self.timestamp.isoformat(),
        }) + b"\n"


@dataclass(frozen=True, slots=True)
class RecoveryIntake:
    recovery_id: str
    trigger: RecoveryTrigger
    opened_at: datetime
    observed_head_exists: bool
    observed_head_hash: Optional[str]
    observed_head: Optional[HeadPointer]
    head_error: Optional[str]
    affected_commit: Optional[str]
    mutation_performed: bool = False

    def __post_init__(self) -> None:
        _required("recovery_id", self.recovery_id)
        _aware("opened_at", self.opened_at)
        if self.observed_head_hash is not None:
            object.__setattr__(self, "observed_head_hash", _hash("observed_head_hash", self.observed_head_hash))
        if self.mutation_performed:
            raise ValueError("RecoveryIntake cannot perform mutation")


@dataclass(frozen=True, slots=True)
class RecoveryAuthorization:
    authorization_id: str
    recovery_id: str
    reviewer: str
    target_commit: str
    expected_head_exists: bool
    expected_head_hash: Optional[str]
    policy_version: str
    authorized_at: datetime

    def __post_init__(self) -> None:
        _required("authorization_id", self.authorization_id)
        _required("recovery_id", self.recovery_id)
        _required("reviewer", self.reviewer)
        _required("target_commit", self.target_commit)
        _required("policy_version", self.policy_version)
        _aware("authorized_at", self.authorized_at)
        if self.expected_head_hash is not None:
            object.__setattr__(self, "expected_head_hash", _hash("expected_head_hash", self.expected_head_hash))
        if self.expected_head_exists and self.expected_head_hash is None:
            raise ValueError("existing HEAD authorization requires expected_head_hash")
        if not self.expected_head_exists and self.expected_head_hash is not None:
            raise ValueError("missing HEAD authorization cannot include expected_head_hash")


@dataclass(frozen=True, slots=True)
class RecoveryReceipt:
    receipt_id: str
    recovery_id: str
    operation: str
    previous_head_hash: Optional[str]
    target_commit: str
    target_manifest_hash: str
    authorization_id: str
    actor: str
    timestamp: datetime
    result: str
    creates_authority: bool = False

    def __post_init__(self) -> None:
        _required("receipt_id", self.receipt_id)
        _required("recovery_id", self.recovery_id)
        _required("operation", self.operation)
        _required("target_commit", self.target_commit)
        object.__setattr__(self, "target_manifest_hash", _hash("target_manifest_hash", self.target_manifest_hash))
        if self.previous_head_hash is not None:
            object.__setattr__(self, "previous_head_hash", _hash("previous_head_hash", self.previous_head_hash))
        _required("authorization_id", self.authorization_id)
        _required("actor", self.actor)
        _aware("timestamp", self.timestamp)
        _required("result", self.result)
        if self.creates_authority:
            raise ValueError("recovery receipt cannot create authority")


class RecoveryManager:
    """P8 recovery boundary over a P7 GenerationStore."""

    def __init__(
        self,
        store: GenerationStore,
        *,
        audit: AuditLedger,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
    ) -> None:
        if policy_version != store.policy_version:
            raise ValueError("recovery policy_version must match persistence store")
        if policy_version != audit.policy_version:
            raise ValueError("recovery policy_version must match audit ledger")
        _required("actor", actor)
        self.store = store
        self.audit = audit
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory
        self.forensics = store.root / "forensics"
        self.attempts = self.forensics / "attempts"
        self.receipts = self.forensics / "recovery_receipts"
        self.attempts.mkdir(parents=True, exist_ok=True)
        self.receipts.mkdir(parents=True, exist_ok=True)

    def _head_snapshot(self) -> tuple[bool, Optional[str], Optional[HeadPointer], Optional[str]]:
        if not self.store.head_path.exists():
            return False, None, None, None
        raw = self.store.head_path.read_bytes()
        digest = _sha256_bytes(raw)
        try:
            head = self.store.read_head()
            return True, digest, head, None
        except Exception as exc:
            return True, digest, None, f"{type(exc).__name__}: {exc}"

    def open_intake(
        self,
        trigger: RecoveryTrigger,
        *,
        affected_commit: Optional[str] = None,
    ) -> RecoveryIntake:
        exists, digest, head, error = self._head_snapshot()
        intake = RecoveryIntake(
            recovery_id=self.id_factory("recovery"),
            trigger=trigger,
            opened_at=self.clock(),
            observed_head_exists=exists,
            observed_head_hash=digest,
            observed_head=head,
            head_error=error,
            affected_commit=affected_commit,
            mutation_performed=False,
        )
        self.audit.append(
            AuditEventType.RECOVERY_INTAKE,
            affected_refs=tuple(v for v in (affected_commit, head.commit_id if head else None) if v),
            details=f"trigger={trigger.value};head_error={error or 'NONE'}",
        )
        return intake

    def retain_failed_attempt(self, record: FailedAttemptRecord) -> Receipt:
        path = self.attempts / f"{record.attempt_id}.json"
        if path.exists():
            raise RecoveryValidationError("failed attempt record already exists and is immutable")
        data = record.to_bytes()
        self._write_new_file(path, data)
        digest = _sha256_bytes(data)
        event = self.audit.append(
            AuditEventType.FAILED_ATTEMPT_RETAINED,
            affected_refs=(record.attempt_id, record.case_id, record.stage_id),
            details=f"failure_class={record.failure_class};sha256={digest}",
        )
        return Receipt(
            receipt_id=self.id_factory("receipt"),
            operation="RETAIN_FAILED_ATTEMPT",
            input_commit=None,
            input_hashes=(),
            output_commit=None,
            output_hashes=(digest,),
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=f"RETAINED:{record.attempt_id};audit={event.event_id}",
        )

    def rollback(
        self,
        *,
        intake: RecoveryIntake,
        authorization: RecoveryAuthorization,
    ) -> RecoveryReceipt:
        self._validate_rollback_binding(intake, authorization)
        exists, current_hash, current_head, current_error = self._head_snapshot()
        if exists != authorization.expected_head_exists or current_hash != authorization.expected_head_hash:
            raise RecoveryValidationError("HEAD changed after recovery authorization")

        target = self.store.verify_generation(authorization.target_commit)
        promotion_path = self.store.generations / target.commit_id / "promotion.json"
        target_promotion_hash = _sha256_bytes(promotion_path.read_bytes())
        target_head = HeadPointer(target.commit_id, target.seq, target.sha256, target_promotion_hash)

        if current_head is not None:
            if target.seq >= current_head.seq:
                raise RecoveryValidationError("rollback target must precede current canonical HEAD")
            if target.commit_id != current_head.commit_id:
                self._verify_is_ancestor(current_head, target.commit_id)
        elif current_error is None and not exists:
            # Missing HEAD is allowed only with explicit human authorization to an
            # already verified generation. No automatic target selection occurs.
            pass
        # If HEAD exists but is corrupt/unparseable, exact raw-byte binding above and
        # human target authorization are the authority boundary.

        self.audit.append(
            AuditEventType.ROLLBACK_ATTEMPTED,
            affected_refs=tuple(v for v in (authorization.target_commit, intake.affected_commit) if v),
            details=f"authorization={authorization.authorization_id}",
        )
        try:
            self.store._atomic_write_head(target_head)
        except Exception as exc:
            self.audit.append(
                AuditEventType.ROLLBACK_FAILED,
                affected_refs=(authorization.target_commit,),
                details=f"{type(exc).__name__}: {exc}",
            )
            raise PersistencePublishError(f"recovery rollback failed: {exc}") from exc

        receipt = RecoveryReceipt(
            receipt_id=self.id_factory("recovery-receipt"),
            recovery_id=intake.recovery_id,
            operation="ROLLBACK_HEAD_TO_VERIFIED_GENERATION",
            previous_head_hash=current_hash,
            target_commit=target.commit_id,
            target_manifest_hash=target.sha256,
            authorization_id=authorization.authorization_id,
            actor=self.actor,
            timestamp=self.clock(),
            result=f"ROLLED_BACK_TO:{target.commit_id}",
            creates_authority=False,
        )
        self._write_recovery_receipt(receipt)
        self.audit.append(
            AuditEventType.ROLLBACK_SUCCEEDED,
            affected_refs=(target.commit_id, receipt.receipt_id),
            details=f"authorization={authorization.authorization_id};creates_authority=false",
        )
        return receipt

    def _validate_rollback_binding(self, intake: RecoveryIntake, authorization: RecoveryAuthorization) -> None:
        errors = []
        if authorization.recovery_id != intake.recovery_id:
            errors.append("recovery id mismatch")
        if authorization.policy_version != self.policy_version:
            errors.append("policy version mismatch")
        if authorization.expected_head_exists != intake.observed_head_exists:
            errors.append("HEAD existence binding mismatch")
        if authorization.expected_head_hash != intake.observed_head_hash:
            errors.append("HEAD hash binding mismatch")
        if errors:
            raise RecoveryValidationError("; ".join(errors))

    def _verify_is_ancestor(self, current: HeadPointer, target_commit: str) -> None:
        seen = set()
        commit = current.commit_id
        while commit not in seen:
            seen.add(commit)
            manifest = self.store.verify_generation(commit)
            if manifest.parent_commit == target_commit:
                self.store.verify_generation(target_commit)
                return
            commit = manifest.parent_commit
            if not (self.store.generations / commit).is_dir():
                break
        raise RecoveryValidationError("rollback target is not in current HEAD ancestry")

    def _write_recovery_receipt(self, receipt: RecoveryReceipt) -> None:
        path = self.receipts / f"{receipt.receipt_id}.json"
        data = _canonical_json_bytes({
            "actor": receipt.actor,
            "authorization_id": receipt.authorization_id,
            "creates_authority": receipt.creates_authority,
            "operation": receipt.operation,
            "previous_head_hash": receipt.previous_head_hash,
            "receipt_id": receipt.receipt_id,
            "recovery_id": receipt.recovery_id,
            "result": receipt.result,
            "target_commit": receipt.target_commit,
            "target_manifest_hash": receipt.target_manifest_hash,
            "timestamp": receipt.timestamp.isoformat(),
        }) + b"\n"
        self._write_new_file(path, data)

    @staticmethod
    def _write_new_file(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        finally:
            os.close(fd)
