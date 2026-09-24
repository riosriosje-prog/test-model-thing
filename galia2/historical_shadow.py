"""GALIA 2.0 P13 historical shadow operation bridge.

P13 connects the existing HistoricalStore research surface to the promoted
GALIA 2.0 multistage core without granting authority or mutating canonical
research state.

The bridge is intentionally read-only with respect to HistoricalStore:
it consumes ``claim_bundle`` and ``claim_promotion_blockers`` only. It may
advance an in-memory GALIA 2.0 Stage as far as AUTHORITY_HOLD, but it never
records human review, runs preflight, stages persistence, publishes a
generation, or changes Legacy/model runtime behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Protocol, Tuple, runtime_checkable

from .authority import AuthorityLayer
from .core import (
    AuthorityState,
    Case,
    Claim,
    ClaimType,
    EvidenceState,
    Receipt,
    Stage,
    StageState,
)
from .orchestrator import (
    FailureKind,
    StageExecution,
    StageOrchestrator,
    StageValidation,
)
from .state_machine import TransitionEvent


@runtime_checkable
class HistoricalStoreReadProtocol(Protocol):
    def claim_bundle(self, claim_id: str) -> dict[str, Any]: ...
    def claim_promotion_blockers(self, claim_id: str) -> list[dict[str, Any]]: ...


class HistoricalShadowStatus(str, Enum):
    AUTHORITY_HOLD = "AUTHORITY_HOLD"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True, slots=True)
class HistoricalShadowResult:
    status: HistoricalShadowStatus
    source_claim_id: str
    source_status: str
    bundle_sha256: str
    evidence_snapshot: Tuple[str, ...]
    promotion_blocker_codes: Tuple[str, ...]
    stage: Stage
    claim: Claim
    receipts: Tuple[Receipt, ...]


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _required_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _evidence_snapshot(rows: list[dict[str, Any]]) -> Tuple[str, ...]:
    snapshot: list[str] = []
    for row in rows:
        evidence_id = _required_text("evidence_id", row.get("evidence_id"))
        digest = (
            row.get("representation_content_sha256")
            or row.get("excerpt_sha256")
            or row.get("content_sha256")
        )
        if not isinstance(digest, str) or len(digest) != 64:
            digest = _sha256_json(row)
        snapshot.append(f"{evidence_id}:{digest.lower()}")
    return tuple(snapshot)


class HistoricalClaimShadowBridge:
    """Mirror one HistoricalStore claim into GALIA 2.0 through AUTHORITY_HOLD.

    The bridge does not call HistoricalStore review APIs and has no persistence
    or promotion capability. A source claim that lacks any evidence snapshot is
    fail-closed into QUARANTINED rather than being placed on authority hold.
    """

    def __init__(
        self,
        *,
        orchestrator: StageOrchestrator,
        authority: AuthorityLayer,
    ) -> None:
        self.orchestrator = orchestrator
        self.authority = authority

    def mirror_to_hold(
        self,
        *,
        store: HistoricalStoreReadProtocol,
        case: Case,
        stage: Stage,
        claim_id: str,
    ) -> HistoricalShadowResult:
        if not isinstance(store, HistoricalStoreReadProtocol):
            raise TypeError(
                "store must expose claim_bundle and claim_promotion_blockers"
            )
        if stage.case_id != case.case_id:
            raise ValueError("stage belongs to a different case")
        if stage.state is not StageState.DISCOVERED:
            raise ValueError("P13 requires an initial DISCOVERED stage")

        bundle = store.claim_bundle(claim_id)
        source_claim = bundle.get("claim")
        evidence = bundle.get("evidence")
        if not isinstance(source_claim, dict):
            raise ValueError("claim bundle is missing claim data")
        if not isinstance(evidence, list) or not all(
            isinstance(row, dict) for row in evidence
        ):
            raise ValueError("claim bundle evidence must be a list of objects")

        source_claim_id = _required_text(
            "source claim_id", source_claim.get("claim_id")
        )
        if source_claim_id != claim_id:
            raise ValueError("claim bundle does not match requested claim_id")

        source_status = _required_text(
            "source claim status", source_claim.get("status")
        )
        if source_status not in {"PROPOSED", "VALIDATED"}:
            raise ValueError(
                "P13 accepts only non-canonical PROPOSED or VALIDATED source claims"
            )

        bundle_hash = _sha256_json(bundle)
        snapshot = _evidence_snapshot(evidence)
        blockers = tuple(
            sorted(
                _required_text("blocker code", blocker.get("code"))
                for blocker in store.claim_promotion_blockers(claim_id)
            )
        )

        subject = (
            source_claim.get("subject_entity_id")
            or source_claim.get("document_id")
            or f"historical-store:{claim_id}"
        )
        object_value = (
            source_claim.get("object_value")
            or source_claim.get("object_entity_id")
            or source_claim.get("claim_text")
        )
        mapped = Claim(
            claim_id=claim_id,
            case_id=case.case_id,
            subject=_required_text("mapped subject", subject),
            predicate=_required_text(
                "mapped predicate", source_claim.get("predicate")
            ),
            object=_required_text("mapped object", object_value),
            valid_from=None,
            valid_to=None,
            claim_type=ClaimType.DERIVED,
            evidence_state=(
                EvidenceState.SUPPORTED if snapshot else EvidenceState.UNVERIFIED
            ),
            authority_state=AuthorityState.NONE,
        )

        receipts: list[Receipt] = []
        source_ref = f"historical-store:claim:{claim_id}"

        stage = self._advance(
            stage,
            TransitionEvent.INGEST_CONFIRMED,
            {"source_artifact_valid"},
            source_ref,
            bundle_hash,
            receipts,
        )
        stage = self._advance(
            stage,
            TransitionEvent.NORMALIZATION_COMPLETE,
            {"lineage_complete"},
            source_ref,
            bundle_hash,
            receipts,
        )
        stage = self._advance(
            stage,
            TransitionEvent.DERIVATION_COMPLETE,
            {"output_hash_valid"},
            source_ref,
            bundle_hash,
            receipts,
        )

        if not snapshot:
            outcome = self.orchestrator.run_stage(
                stage,
                TransitionEvent.VALIDATION_PASSED,
                executor=lambda _stage, _ctx: StageExecution(
                    output_refs=(source_ref,),
                    output_hashes=(bundle_hash,),
                ),
                validators=(
                    lambda _stage, _execution, _ctx: StageValidation(
                        passed=False,
                        failure_kind=FailureKind.INTEGRITY,
                        message="historical claim has no evidence snapshot",
                    ),
                ),
            )
            receipts.append(outcome.receipt)
            if outcome.stage.state is not StageState.QUARANTINED:
                raise RuntimeError("missing evidence did not route to QUARANTINED")
            return HistoricalShadowResult(
                status=HistoricalShadowStatus.QUARANTINED,
                source_claim_id=claim_id,
                source_status=source_status,
                bundle_sha256=bundle_hash,
                evidence_snapshot=snapshot,
                promotion_blocker_codes=blockers,
                stage=outcome.stage,
                claim=mapped,
                receipts=tuple(receipts),
            )

        stage = self._advance(
            stage,
            TransitionEvent.VALIDATION_PASSED,
            {"required_validations_passed"},
            source_ref,
            bundle_hash,
            receipts,
        )
        hold = self.authority.place_hold(claim=mapped)
        mapped = hold.value
        receipts.append(hold.receipt)
        stage = self._advance(
            stage,
            TransitionEvent.PLACE_AUTHORITY_HOLD,
            {"evidence_snapshot_present"},
            source_ref,
            bundle_hash,
            receipts,
        )
        if stage.state is not StageState.AUTHORITY_HOLD:
            raise RuntimeError("P13 did not terminate at AUTHORITY_HOLD")

        return HistoricalShadowResult(
            status=HistoricalShadowStatus.AUTHORITY_HOLD,
            source_claim_id=claim_id,
            source_status=source_status,
            bundle_sha256=bundle_hash,
            evidence_snapshot=snapshot,
            promotion_blocker_codes=blockers,
            stage=stage,
            claim=mapped,
            receipts=tuple(receipts),
        )

    def _advance(
        self,
        stage: Stage,
        event: TransitionEvent,
        guards: set[str],
        source_ref: str,
        bundle_hash: str,
        receipts: list[Receipt],
    ) -> Stage:
        outcome = self.orchestrator.run_stage(
            stage,
            event,
            executor=lambda _stage, _ctx: StageExecution(
                output_refs=(source_ref,),
                output_hashes=(bundle_hash,),
                guards=frozenset(guards),
            ),
        )
        receipts.append(outcome.receipt)
        return outcome.stage
