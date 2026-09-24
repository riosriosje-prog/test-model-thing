"""GALIA 2.0 P7 persistence binding.

P7 binds promoted P1-P6 contracts to an immutable on-disk generation store.
It may stage and publish generation bytes, but it cannot create human authority,
run promotion preflight, or advance a Stage.

The candidate manifest exists *before* P6 and is never rewritten after preflight.
Human/preflight evidence is captured separately in a promotion envelope at publish time,
avoiding a manifest/preflight hash cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Callable, Mapping, Optional, Tuple
from uuid import uuid4

from .authority import AuthorityScope, PromotionAuthorization
from .core import Receipt, StageState
from .preflight import CandidateSnapshot, PreflightReport
from .state_machine import TransitionDecision, TransitionEvent

Clock = Callable[[], datetime]
IdFactory = Callable[[str], str]
ReplaceFn = Callable[[str | bytes | os.PathLike[str] | os.PathLike[bytes], str | bytes | os.PathLike[str] | os.PathLike[bytes]], None]

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MANIFEST_FILE = "manifest.json"
_PROMOTION_FILE = "promotion.json"
_PAYLOAD_DIR = "payload"
_HEAD_FILE = "HEAD"


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


def _safe_payload_path(value: str) -> str:
    _required("payload path", value)
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or value in {_MANIFEST_FILE, _PROMOTION_FILE, _HEAD_FILE}:
        raise ValueError(f"unsafe payload path: {value!r}")
    if not p.parts or any(part in {"", "."} for part in p.parts):
        raise ValueError(f"unsafe payload path: {value!r}")
    normalized = p.as_posix()
    if normalized.startswith(f"{_PAYLOAD_DIR}/"):
        raise ValueError("payload paths are relative to the payload directory")
    return normalized


@dataclass(frozen=True, slots=True)
class PayloadEntry:
    path: str
    sha256: str
    byte_size: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _safe_payload_path(self.path))
        object.__setattr__(self, "sha256", _hash("sha256", self.sha256))
        if not isinstance(self.byte_size, int) or self.byte_size < 0:
            raise ValueError("byte_size must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class GenerationManifest:
    """Candidate content manifest. Created before P6 and never rewritten."""

    commit_id: str
    seq: int
    parent_commit: str
    case_id: str
    schema_version: str
    created_at: datetime
    payloads: Tuple[PayloadEntry, ...]
    authority_decision_id: str
    persistence_policy_version: str

    def __post_init__(self) -> None:
        _required("commit_id", self.commit_id)
        _required("parent_commit", self.parent_commit)
        _required("case_id", self.case_id)
        _required("schema_version", self.schema_version)
        _required("authority_decision_id", self.authority_decision_id)
        _required("persistence_policy_version", self.persistence_policy_version)
        if not isinstance(self.seq, int) or self.seq < 1:
            raise ValueError("seq must be a positive integer")
        if self.commit_id == self.parent_commit:
            raise ValueError("commit_id cannot equal parent_commit")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if not self.payloads:
            raise ValueError("generation manifest requires at least one payload")
        paths = tuple(entry.path for entry in self.payloads)
        if len(set(paths)) != len(paths):
            raise ValueError("payload paths must be unique")

    def as_dict(self) -> dict[str, object]:
        return {
            "authority_decision_id": self.authority_decision_id,
            "case_id": self.case_id,
            "commit_id": self.commit_id,
            "created_at": self.created_at.isoformat(),
            "parent_commit": self.parent_commit,
            "payloads": [
                {"byte_size": p.byte_size, "path": p.path, "sha256": p.sha256}
                for p in self.payloads
            ],
            "persistence_policy_version": self.persistence_policy_version,
            "schema_version": self.schema_version,
            "seq": self.seq,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json_bytes(self.as_dict())

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.to_bytes())


@dataclass(frozen=True, slots=True)
class PromotionEnvelope:
    """Post-P6 publication evidence; separate from the immutable candidate manifest."""

    commit_id: str
    case_id: str
    manifest_hash: str
    authority_decision_id: str
    authorization_id: str
    authorization_policy_version: str
    preflight_receipt_id: str
    persistence_policy_version: str
    published_at: datetime

    def __post_init__(self) -> None:
        _required("commit_id", self.commit_id)
        _required("case_id", self.case_id)
        object.__setattr__(self, "manifest_hash", _hash("manifest_hash", self.manifest_hash))
        _required("authority_decision_id", self.authority_decision_id)
        _required("authorization_id", self.authorization_id)
        _required("authorization_policy_version", self.authorization_policy_version)
        _required("preflight_receipt_id", self.preflight_receipt_id)
        _required("persistence_policy_version", self.persistence_policy_version)
        if self.published_at.tzinfo is None or self.published_at.utcoffset() is None:
            raise ValueError("published_at must be timezone-aware")

    def to_bytes(self) -> bytes:
        return _canonical_json_bytes({
            "authority_decision_id": self.authority_decision_id,
            "authorization_id": self.authorization_id,
            "authorization_policy_version": self.authorization_policy_version,
            "case_id": self.case_id,
            "commit_id": self.commit_id,
            "manifest_hash": self.manifest_hash,
            "persistence_policy_version": self.persistence_policy_version,
            "preflight_receipt_id": self.preflight_receipt_id,
            "published_at": self.published_at.isoformat(),
        })

    @property
    def sha256(self) -> str:
        return _sha256_bytes(self.to_bytes())


@dataclass(frozen=True, slots=True)
class HeadPointer:
    commit_id: str
    seq: int
    manifest_hash: str
    promotion_hash: str

    def __post_init__(self) -> None:
        _required("commit_id", self.commit_id)
        if not isinstance(self.seq, int) or self.seq < 1:
            raise ValueError("seq must be a positive integer")
        object.__setattr__(self, "manifest_hash", _hash("manifest_hash", self.manifest_hash))
        object.__setattr__(self, "promotion_hash", _hash("promotion_hash", self.promotion_hash))

    def to_bytes(self) -> bytes:
        return _canonical_json_bytes({
            "commit_id": self.commit_id,
            "manifest_hash": self.manifest_hash,
            "promotion_hash": self.promotion_hash,
            "seq": self.seq,
        }) + b"\n"


@dataclass(frozen=True, slots=True)
class StagedGeneration:
    commit_id: str
    manifest: GenerationManifest
    manifest_hash: str
    receipt: Receipt

    def __post_init__(self) -> None:
        _required("commit_id", self.commit_id)
        if self.commit_id != self.manifest.commit_id:
            raise ValueError("staged commit_id must match manifest")
        object.__setattr__(self, "manifest_hash", _hash("manifest_hash", self.manifest_hash))
        if self.manifest_hash != self.manifest.sha256:
            raise ValueError("manifest_hash does not match manifest bytes")


@dataclass(frozen=True, slots=True)
class PublishedGeneration:
    head: HeadPointer
    manifest: GenerationManifest
    promotion: PromotionEnvelope
    receipt: Receipt


class PersistenceError(RuntimeError):
    """Base persistence failure."""


class ImmutableGenerationError(PersistenceError):
    """Raised when a write would overwrite an existing generation."""


class PersistenceValidationError(PersistenceError):
    """Raised when persistence or authority bindings do not match exactly."""


class PersistencePublishError(PersistenceError):
    """Raised when durable materialization or atomic HEAD swap fails."""


class GenerationStore:
    """Filesystem persistence boundary for P7.

    Public mutation is intentionally limited to ``stage_generation`` and
    ``publish_generation``. Neither method can synthesize P5/P6/P2 authority objects.
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
        replace_fn: ReplaceFn = os.replace,
    ) -> None:
        _required("policy_version", policy_version)
        _required("actor", actor)
        self.root = Path(root)
        self.generations = self.root / "generations"
        self.staging = self.root / "staging"
        self.head_path = self.root / _HEAD_FILE
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory
        self.replace_fn = replace_fn
        self.generations.mkdir(parents=True, exist_ok=True)
        self.staging.mkdir(parents=True, exist_ok=True)

    def stage_generation(self, *, manifest: GenerationManifest, payloads: Mapping[str, bytes]) -> StagedGeneration:
        """Durably stage candidate bytes without modifying HEAD."""
        self._validate_payloads(manifest, payloads)
        if manifest.persistence_policy_version != self.policy_version:
            raise PersistenceValidationError("manifest persistence policy does not match store")
        final_stage = self.staging / manifest.commit_id
        final_generation = self.generations / manifest.commit_id
        if final_stage.exists() or final_generation.exists():
            raise ImmutableGenerationError(f"generation {manifest.commit_id!r} already exists and is immutable")

        temp = self.staging / f".{manifest.commit_id}.tmp-{uuid4()}"
        try:
            (temp / _PAYLOAD_DIR).mkdir(parents=True, exist_ok=False)
            for entry in manifest.payloads:
                dst = temp / _PAYLOAD_DIR / Path(*PurePosixPath(entry.path).parts)
                dst.parent.mkdir(parents=True, exist_ok=True)
                self._write_new_file(dst, payloads[entry.path])
            self._write_new_file(temp / _MANIFEST_FILE, manifest.to_bytes())
            self._fsync_dir(temp / _PAYLOAD_DIR)
            self._fsync_dir(temp)
            self.replace_fn(temp, final_stage)
            self._fsync_dir(self.staging)
        except Exception as exc:
            raise PersistencePublishError(f"failed to stage generation: {exc}") from exc

        receipt = Receipt(
            receipt_id=self.id_factory("receipt"),
            operation="PERSIST_STAGE_GENERATION",
            input_commit=manifest.parent_commit,
            input_hashes=tuple(entry.sha256 for entry in manifest.payloads),
            output_commit=None,
            output_hashes=(manifest.sha256, *tuple(entry.sha256 for entry in manifest.payloads)),
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=f"STAGED:{manifest.commit_id}",
        )
        return StagedGeneration(manifest.commit_id, manifest, manifest.sha256, receipt)

    def publish_generation(
        self,
        *,
        staged: StagedGeneration,
        candidate: CandidateSnapshot,
        preflight: PreflightReport,
        authorization: PromotionAuthorization,
        expected_scope: AuthorityScope,
        promotion_decision: TransitionDecision,
    ) -> PublishedGeneration:
        """Publish one staged generation and atomically advance HEAD.

        Authority is consumed, not created. The immutable candidate manifest remains
        byte-identical to the object evaluated by P6; publish evidence is written into
        a separate promotion envelope.
        """
        self._validate_publish_bindings(
            staged=staged,
            candidate=candidate,
            preflight=preflight,
            authorization=authorization,
            expected_scope=expected_scope,
            promotion_decision=promotion_decision,
        )
        current = self.read_head()
        if current is None:
            raise PersistenceValidationError("HEAD must already reference the verified parent generation")
        if current.commit_id != staged.manifest.parent_commit:
            raise PersistenceValidationError("current HEAD does not match manifest parent_commit")
        if staged.manifest.seq != current.seq + 1:
            raise PersistenceValidationError("manifest seq must be exactly HEAD.seq + 1")
        self.verify_generation(current.commit_id, expected_manifest_hash=current.manifest_hash, expected_promotion_hash=current.promotion_hash)

        src = self.staging / staged.commit_id
        dst = self.generations / staged.commit_id
        if not src.is_dir():
            raise PersistenceValidationError("staged generation is missing")
        if dst.exists():
            raise ImmutableGenerationError(f"generation {staged.commit_id!r} already exists")
        self._verify_candidate_directory(src, staged.manifest, staged.manifest_hash)

        promotion = PromotionEnvelope(
            commit_id=staged.commit_id,
            case_id=staged.manifest.case_id,
            manifest_hash=staged.manifest_hash,
            authority_decision_id=staged.manifest.authority_decision_id,
            authorization_id=authorization.authorization_id,
            authorization_policy_version=authorization.policy_version,
            preflight_receipt_id=preflight.receipt.receipt_id,
            persistence_policy_version=self.policy_version,
            published_at=self.clock(),
        )

        try:
            self._write_new_file(src / _PROMOTION_FILE, promotion.to_bytes())
            self._fsync_dir(src)
            self.replace_fn(src, dst)
            self._fsync_dir(self.generations)
            head = HeadPointer(staged.commit_id, staged.manifest.seq, staged.manifest_hash, promotion.sha256)
            self._atomic_write_head(head)
        except Exception as exc:
            # Do not delete materialized bytes after failure. Previous HEAD remains the
            # authority anchor; P8 may recover or quarantine the orphan generation.
            raise PersistencePublishError(f"failed to publish generation: {exc}") from exc

        receipt = Receipt(
            receipt_id=self.id_factory("receipt"),
            operation="PERSIST_PUBLISH_GENERATION",
            input_commit=staged.manifest.parent_commit,
            input_hashes=(staged.manifest_hash, promotion.sha256, *tuple(p.sha256 for p in staged.manifest.payloads)),
            output_commit=staged.commit_id,
            output_hashes=(staged.manifest_hash, promotion.sha256),
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock(),
            result=f"PUBLISHED:{staged.commit_id}",
        )
        return PublishedGeneration(head, staged.manifest, promotion, receipt)

    def read_head(self) -> Optional[HeadPointer]:
        if not self.head_path.exists():
            return None
        try:
            raw = json.loads(self.head_path.read_text(encoding="utf-8"))
            return HeadPointer(raw["commit_id"], raw["seq"], raw["manifest_hash"], raw["promotion_hash"])
        except Exception as exc:
            raise PersistenceValidationError(f"invalid HEAD: {exc}") from exc

    def verify_generation(
        self,
        commit_id: str,
        *,
        expected_manifest_hash: Optional[str] = None,
        expected_promotion_hash: Optional[str] = None,
    ) -> GenerationManifest:
        _required("commit_id", commit_id)
        directory = self.generations / commit_id
        if not directory.is_dir():
            raise PersistenceValidationError(f"generation {commit_id!r} not found")
        manifest_path = directory / _MANIFEST_FILE
        promotion_path = directory / _PROMOTION_FILE
        if not manifest_path.is_file() or not promotion_path.is_file():
            raise PersistenceValidationError("generation manifest or promotion envelope missing")
        manifest_raw = manifest_path.read_bytes()
        promotion_raw = promotion_path.read_bytes()
        actual_manifest_hash = _sha256_bytes(manifest_raw)
        actual_promotion_hash = _sha256_bytes(promotion_raw)
        if expected_manifest_hash is not None and actual_manifest_hash != _hash("expected_manifest_hash", expected_manifest_hash):
            raise PersistenceValidationError("generation manifest hash mismatch")
        if expected_promotion_hash is not None and actual_promotion_hash != _hash("expected_promotion_hash", expected_promotion_hash):
            raise PersistenceValidationError("promotion envelope hash mismatch")
        manifest = self._manifest_from_bytes(manifest_raw)
        promotion = self._promotion_from_bytes(promotion_raw)
        if manifest.commit_id != commit_id or promotion.commit_id != commit_id:
            raise PersistenceValidationError("commit_id binding mismatch")
        if promotion.manifest_hash != actual_manifest_hash:
            raise PersistenceValidationError("promotion envelope does not bind exact manifest")
        if promotion.case_id != manifest.case_id or promotion.authority_decision_id != manifest.authority_decision_id:
            raise PersistenceValidationError("promotion envelope identity binding mismatch")
        self._verify_published_directory(directory, manifest, actual_manifest_hash, actual_promotion_hash)
        return manifest

    def _validate_publish_bindings(
        self,
        *,
        staged: StagedGeneration,
        candidate: CandidateSnapshot,
        preflight: PreflightReport,
        authorization: PromotionAuthorization,
        expected_scope: AuthorityScope,
        promotion_decision: TransitionDecision,
    ) -> None:
        manifest = staged.manifest
        errors: list[str] = []
        if not preflight.passed:
            errors.append("preflight did not pass")
        if preflight.guards != frozenset({"preflight_passed", "rollback_target_verified"}):
            errors.append("preflight guards are not exact")
        if preflight.case_id != manifest.case_id or candidate.case_id != manifest.case_id:
            errors.append("case binding mismatch")
        if preflight.target_commit != manifest.commit_id or candidate.target_commit != manifest.commit_id:
            errors.append("target commit binding mismatch")
        if candidate.parent_commit != manifest.parent_commit:
            errors.append("parent commit binding mismatch")
        if candidate.manifest_hash != staged.manifest_hash:
            errors.append("candidate manifest hash mismatch")
        if sorted(candidate.payload_hashes) != sorted(p.sha256 for p in manifest.payloads):
            errors.append("candidate payload hashes mismatch")
        if candidate.schema_version != manifest.schema_version:
            errors.append("schema binding mismatch")
        if candidate.authority_decision_id != manifest.authority_decision_id:
            errors.append("authority decision binding mismatch")
        if authorization.decision_id != manifest.authority_decision_id:
            errors.append("authorization decision mismatch")
        if authorization.target_commit != manifest.commit_id:
            errors.append("authorization target mismatch")
        if authorization.scope != expected_scope or expected_scope.case_id != manifest.case_id:
            errors.append("authorization scope mismatch")
        if promotion_decision.case_id != manifest.case_id:
            errors.append("transition case mismatch")
        if promotion_decision.from_state is not StageState.PROMOTION_READY:
            errors.append("transition must start at PROMOTION_READY")
        if promotion_decision.to_state is not StageState.CANONICAL:
            errors.append("transition must target CANONICAL")
        if promotion_decision.event is not TransitionEvent.PROMOTION_AUTHORIZED:
            errors.append("transition event must be PROMOTION_AUTHORIZED")
        required_promotion_guards = frozenset({"promotion_authorization_present", "authorization_matches_target"})
        if not required_promotion_guards.issubset(promotion_decision.satisfied_guards):
            errors.append("promotion decision lacks final authority guards")
        if not promotion_decision.human_boundary:
            errors.append("promotion decision must cross human boundary")
        if errors:
            raise PersistenceValidationError("; ".join(errors))

    @staticmethod
    def _validate_payloads(manifest: GenerationManifest, payloads: Mapping[str, bytes]) -> None:
        if set(payloads) != {entry.path for entry in manifest.payloads}:
            raise PersistenceValidationError("payload paths do not exactly match manifest")
        for entry in manifest.payloads:
            data = payloads[entry.path]
            if not isinstance(data, bytes):
                raise PersistenceValidationError("payload values must be bytes")
            if len(data) != entry.byte_size:
                raise PersistenceValidationError(f"payload size mismatch for {entry.path}")
            if _sha256_bytes(data) != entry.sha256:
                raise PersistenceValidationError(f"payload hash mismatch for {entry.path}")

    def _verify_candidate_directory(self, directory: Path, manifest: GenerationManifest, expected_manifest_hash: str) -> None:
        manifest_path = directory / _MANIFEST_FILE
        if not manifest_path.is_file() or _sha256_bytes(manifest_path.read_bytes()) != expected_manifest_hash:
            raise PersistenceValidationError("candidate manifest integrity mismatch")
        expected_files = {_MANIFEST_FILE}
        for entry in manifest.payloads:
            path = directory / _PAYLOAD_DIR / Path(*PurePosixPath(entry.path).parts)
            expected_files.add(f"{_PAYLOAD_DIR}/{entry.path}")
            if not path.is_file():
                raise PersistenceValidationError(f"payload missing: {entry.path}")
            data = path.read_bytes()
            if len(data) != entry.byte_size or _sha256_bytes(data) != entry.sha256:
                raise PersistenceValidationError(f"payload integrity mismatch: {entry.path}")
        actual_files = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        if actual_files != expected_files:
            raise PersistenceValidationError("candidate contains undeclared or missing files")

    def _verify_published_directory(
        self,
        directory: Path,
        manifest: GenerationManifest,
        manifest_hash: str,
        promotion_hash: str,
    ) -> None:
        self._verify_payload_files(directory, manifest)
        expected_files = {_MANIFEST_FILE, _PROMOTION_FILE, *{f"{_PAYLOAD_DIR}/{p.path}" for p in manifest.payloads}}
        actual_files = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
        if actual_files != expected_files:
            raise PersistenceValidationError("generation contains undeclared or missing files")
        if _sha256_bytes((directory / _MANIFEST_FILE).read_bytes()) != manifest_hash:
            raise PersistenceValidationError("manifest hash mismatch")
        if _sha256_bytes((directory / _PROMOTION_FILE).read_bytes()) != promotion_hash:
            raise PersistenceValidationError("promotion envelope hash mismatch")

    @staticmethod
    def _verify_payload_files(directory: Path, manifest: GenerationManifest) -> None:
        for entry in manifest.payloads:
            path = directory / _PAYLOAD_DIR / Path(*PurePosixPath(entry.path).parts)
            if not path.is_file():
                raise PersistenceValidationError(f"payload missing: {entry.path}")
            data = path.read_bytes()
            if len(data) != entry.byte_size or _sha256_bytes(data) != entry.sha256:
                raise PersistenceValidationError(f"payload integrity mismatch: {entry.path}")

    def _atomic_write_head(self, head: HeadPointer) -> None:
        tmp = self.root / f".HEAD.tmp-{uuid4()}"
        self._write_new_file(tmp, head.to_bytes())
        self.replace_fn(tmp, self.head_path)
        self._fsync_dir(self.root)

    @staticmethod
    def _write_new_file(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _manifest_from_bytes(raw: bytes) -> GenerationManifest:
        try:
            data = json.loads(raw.decode("utf-8"))
            return GenerationManifest(
                commit_id=data["commit_id"], seq=data["seq"], parent_commit=data["parent_commit"],
                case_id=data["case_id"], schema_version=data["schema_version"],
                created_at=datetime.fromisoformat(data["created_at"]),
                payloads=tuple(PayloadEntry(**entry) for entry in data["payloads"]),
                authority_decision_id=data["authority_decision_id"],
                persistence_policy_version=data["persistence_policy_version"],
            )
        except Exception as exc:
            raise PersistenceValidationError(f"invalid generation manifest: {exc}") from exc

    @staticmethod
    def _promotion_from_bytes(raw: bytes) -> PromotionEnvelope:
        try:
            data = json.loads(raw.decode("utf-8"))
            return PromotionEnvelope(
                commit_id=data["commit_id"], case_id=data["case_id"],
                manifest_hash=data["manifest_hash"], authority_decision_id=data["authority_decision_id"],
                authorization_id=data["authorization_id"],
                authorization_policy_version=data["authorization_policy_version"],
                preflight_receipt_id=data["preflight_receipt_id"],
                persistence_policy_version=data["persistence_policy_version"],
                published_at=datetime.fromisoformat(data["published_at"]),
            )
        except Exception as exc:
            raise PersistenceValidationError(f"invalid promotion envelope: {exc}") from exc
