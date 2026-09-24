"""GALIA 2.0 P4 Legacy shadow adapter.

A deliberately read-only boundary between Legacy execution observations and the
GALIA 2.0 core. The adapter never imports Legacy/TMT, never accepts filesystem
paths or repository handles, and exposes no write/mutation operation.

Callers hand the adapter already-observed Legacy input/output payloads. P4 then
content-addresses those observations, binds them to a GALIA case, can produce
non-authoritative claim candidates, compares Legacy output with a supplied 2.0
output, and emits receipts with ``output_commit=None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from hashlib import sha256
from typing import Callable, Optional
from uuid import uuid4

from .core import (
    AuthorityState,
    Case,
    Claim,
    ClaimType,
    Discrepancy,
    DiscrepancyState,
    EvidenceState,
    Receipt,
)


Payload = str | bytes
Clock = Callable[[], datetime]
IdFactory = Callable[[str], str]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4()}"


def _to_bytes(value: Payload) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("payload must be str or bytes")


def _hash(value: bytes) -> str:
    return sha256(value).hexdigest()


def _text_projection(value: bytes) -> Optional[str]:
    """Return a conservative representation-normalized text view.

    This is intentionally *not* semantic equivalence. It only normalizes line
    endings, trims trailing horizontal whitespace on each line, and removes
    leading/trailing blank space from the whole payload.
    """
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip(" \t") for line in text.split("\n")).strip()


class LegacyDiffKind(str, Enum):
    BYTE_IDENTICAL = "BYTE_IDENTICAL"
    REPRESENTATION_EQUIVALENT = "REPRESENTATION_EQUIVALENT"
    MATERIAL_DIFFERENCE = "MATERIAL_DIFFERENCE"
    MISSING_LEGACY_OUTPUT = "MISSING_LEGACY_OUTPUT"
    MISSING_GALIA2_OUTPUT = "MISSING_GALIA2_OUTPUT"


@dataclass(frozen=True, slots=True)
class LegacyShadowCapture:
    capture_id: str
    case_id: str
    input_ref: str
    output_ref: Optional[str]
    input_payload: bytes
    output_payload: Optional[bytes]
    input_hash: str
    output_hash: Optional[str]
    captured_at: datetime
    origin: str = "LEGACY_SHADOW"


@dataclass(frozen=True, slots=True)
class LegacyComparison:
    comparison_id: str
    case_id: str
    capture_id: str
    legacy_output_hash: Optional[str]
    galia2_output_hash: Optional[str]
    kind: LegacyDiffKind
    material: bool
    discrepancy: Optional[Discrepancy]


@dataclass(frozen=True, slots=True)
class LegacyMappedClaim:
    capture_id: str
    claim: Claim
    origin: str = "LEGACY_SHADOW"


@dataclass(frozen=True, slots=True)
class ShadowOperation:
    value: object
    receipt: Receipt


class LegacyAdapter:
    """Read-only adapter for Legacy observations.

    Safety properties by construction:
    * no Legacy/TMT import or runtime reference;
    * no filesystem/repository/network handle;
    * no write method;
    * all returned domain objects are frozen dataclasses;
    * every receipt has ``output_commit=None``;
    * mapped claims are forced to UNVERIFIED/NONE authority.
    """

    def __init__(
        self,
        *,
        policy_version: str,
        actor: str,
        clock: Clock = _utc_now,
        id_factory: IdFactory = _id,
    ) -> None:
        if not policy_version.strip():
            raise ValueError("policy_version must be non-empty")
        if not actor.strip():
            raise ValueError("actor must be non-empty")
        self.policy_version = policy_version
        self.actor = actor
        self.clock = clock
        self.id_factory = id_factory

    def capture(
        self,
        *,
        case: Case,
        input_payload: Payload,
        output_payload: Optional[Payload],
        input_ref: str = "legacy:input",
        output_ref: Optional[str] = "legacy:output",
    ) -> ShadowOperation:
        if not input_ref.strip():
            raise ValueError("input_ref must be non-empty")
        if output_payload is not None and (output_ref is None or not output_ref.strip()):
            raise ValueError("output_ref is required when output_payload is present")

        in_bytes = _to_bytes(input_payload)
        out_bytes = None if output_payload is None else _to_bytes(output_payload)
        in_hash = _hash(in_bytes)
        out_hash = None if out_bytes is None else _hash(out_bytes)
        now = self.clock()

        capture = LegacyShadowCapture(
            capture_id=self.id_factory("legacy-capture"),
            case_id=case.case_id,
            input_ref=input_ref,
            output_ref=None if out_bytes is None else output_ref,
            input_payload=in_bytes,
            output_payload=out_bytes,
            input_hash=in_hash,
            output_hash=out_hash,
            captured_at=now,
        )
        receipt = self._receipt(
            operation="LEGACY_SHADOW_CAPTURE",
            input_hashes=(in_hash,),
            output_hashes=() if out_hash is None else (out_hash,),
            result="CAPTURED:READ_ONLY",
            timestamp=now,
        )
        return ShadowOperation(capture, receipt)

    def map_claim(
        self,
        *,
        case: Case,
        capture: LegacyShadowCapture,
        claim_id: str,
        subject: str,
        predicate: str,
        object: str,
        valid_from: Optional[date] = None,
        valid_to: Optional[date] = None,
    ) -> ShadowOperation:
        self._require_case(case, capture)
        if capture.output_payload is None:
            raise ValueError("cannot map a claim from a capture with no Legacy output")

        claim = Claim(
            claim_id=claim_id,
            case_id=case.case_id,
            subject=subject,
            predicate=predicate,
            object=object,
            valid_from=valid_from,
            valid_to=valid_to,
            claim_type=ClaimType.DERIVED,
            evidence_state=EvidenceState.UNVERIFIED,
            authority_state=AuthorityState.NONE,
        )
        mapped = LegacyMappedClaim(capture_id=capture.capture_id, claim=claim)
        receipt = self._receipt(
            operation="LEGACY_SHADOW_MAP_CLAIM",
            input_hashes=(capture.output_hash,) if capture.output_hash else (),
            output_hashes=(),
            result="MAPPED:NON_AUTHORITATIVE",
        )
        return ShadowOperation(mapped, receipt)

    def compare(
        self,
        *,
        case: Case,
        capture: LegacyShadowCapture,
        galia2_output: Optional[Payload],
    ) -> ShadowOperation:
        self._require_case(case, capture)
        legacy = capture.output_payload
        current = None if galia2_output is None else _to_bytes(galia2_output)
        current_hash = None if current is None else _hash(current)

        if legacy is None:
            kind = LegacyDiffKind.MISSING_LEGACY_OUTPUT
        elif current is None:
            kind = LegacyDiffKind.MISSING_GALIA2_OUTPUT
        elif capture.output_hash == current_hash:
            kind = LegacyDiffKind.BYTE_IDENTICAL
        else:
            legacy_text = _text_projection(legacy)
            current_text = _text_projection(current)
            if legacy_text is not None and current_text is not None and legacy_text == current_text:
                kind = LegacyDiffKind.REPRESENTATION_EQUIVALENT
            else:
                kind = LegacyDiffKind.MATERIAL_DIFFERENCE

        material = kind in {
            LegacyDiffKind.MATERIAL_DIFFERENCE,
            LegacyDiffKind.MISSING_LEGACY_OUTPUT,
            LegacyDiffKind.MISSING_GALIA2_OUTPUT,
        }
        comparison_id = self.id_factory("legacy-diff")
        discrepancy = None
        if material:
            left = f"legacy:{capture.capture_id}:{capture.output_hash or 'MISSING'}"
            right = f"galia2:{current_hash or 'MISSING'}"
            discrepancy = Discrepancy(
                discrepancy_id=self.id_factory("discrepancy"),
                objects=(left, right),
                type="LEGACY_GALIA2_OUTPUT_DIFF",
                materiality="MATERIAL",
                state=DiscrepancyState.OPEN,
            )

        comparison = LegacyComparison(
            comparison_id=comparison_id,
            case_id=case.case_id,
            capture_id=capture.capture_id,
            legacy_output_hash=capture.output_hash,
            galia2_output_hash=current_hash,
            kind=kind,
            material=material,
            discrepancy=discrepancy,
        )
        receipt = self._receipt(
            operation=f"LEGACY_SHADOW_COMPARE:{kind.value}",
            input_hashes=tuple(h for h in (capture.output_hash, current_hash) if h is not None),
            output_hashes=(),
            result=("DIFF:MATERIAL" if material else "DIFF:NON_MATERIAL"),
        )
        return ShadowOperation(comparison, receipt)

    @staticmethod
    def _require_case(case: Case, capture: LegacyShadowCapture) -> None:
        if case.case_id != capture.case_id:
            raise ValueError("capture belongs to a different case")

    def _receipt(
        self,
        *,
        operation: str,
        input_hashes: tuple[str, ...],
        output_hashes: tuple[str, ...],
        result: str,
        timestamp: Optional[datetime] = None,
    ) -> Receipt:
        return Receipt(
            receipt_id=self.id_factory("receipt"),
            operation=operation,
            input_commit=None,
            input_hashes=input_hashes,
            output_commit=None,
            output_hashes=output_hashes,
            policy_version=self.policy_version,
            actor=self.actor,
            timestamp=self.clock() if timestamp is None else timestamp,
            result=result,
        )
