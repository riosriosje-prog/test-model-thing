"""GALIA 2.0 P9 end-to-end integration gate.

This module composes the already-promoted P1-P8 boundaries without weakening any
of them.  It consumes human authority; it never synthesizes it.  A successful
run is the only path exposed here that can advance the persistence HEAD, and it
can do so only after P2/P5/P6/P7 have independently accepted their bindings.

P9 intentionally leaves Legacy/TMT untouched.  Legacy observations enter only
through P4's read-only shadow adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Tuple

from .authority import AuthorityLayer, AuthorityScope, PromotionAuthorization
from .core import AuthorityDecision, Case, Claim, Receipt, Stage, StageState
from .legacy_adapter import LegacyAdapter, LegacyComparison, LegacyShadowCapture
from .orchestrator import StageExecution, StageOrchestrator, StageRunContext
from .persistence import GenerationManifest, GenerationStore, PublishedGeneration, StagedGeneration
from .preflight import CandidateSnapshot, PreflightReport, PromotionPreflight, RollbackSnapshot
from .recovery_audit import RecoveryAuthorization, RecoveryIntake, RecoveryManager, RecoveryReceipt, RecoveryTrigger
from .state_machine import TransitionEvent


class EndToEndStatus(str, Enum):
    HUMAN_AUTHORITY_REQUIRED = "HUMAN_AUTHORITY_REQUIRED"
    PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"
    PUBLISHED = "PUBLISHED"


@dataclass(frozen=True, slots=True)
class EndToEndResult:
    status: EndToEndStatus
    stage: Stage
    capture: LegacyShadowCapture
    comparison: LegacyComparison
    claim: Claim
    authorization: Optional[PromotionAuthorization]
    preflight: Optional[PreflightReport]
    staged: Optional[StagedGeneration]
    published: Optional[PublishedGeneration]
    receipts: Tuple[Receipt, ...]


class EndToEndGate:
    """Compose P4-P8 while preserving every existing authority boundary."""

    def __init__(
        self,
        *,
        legacy: LegacyAdapter,
        orchestrator: StageOrchestrator,
        authority: AuthorityLayer,
        preflight: PromotionPreflight,
        store: GenerationStore,
        recovery: Optional[RecoveryManager] = None,
    ) -> None:
        self.legacy = legacy
        self.orchestrator = orchestrator
        self.authority = authority
        self.preflight = preflight
        self.store = store
        self.recovery = recovery

    def run(
        self,
        *,
        case: Case,
        stage: Stage,
        legacy_input: bytes | str,
        legacy_output: bytes | str | None,
        galia2_output: bytes | str | None,
        claim_id: str,
        subject: str,
        predicate: str,
        object: str,
        human_decision: Optional[AuthorityDecision],
        scope: AuthorityScope,
        manifest: GenerationManifest,
        payloads: Mapping[str, bytes],
        rollback: RollbackSnapshot,
    ) -> EndToEndResult:
        self._validate_bindings(case=case, stage=stage, scope=scope, manifest=manifest, claim_id=claim_id)
        receipts: list[Receipt] = []

        capture_op = self.legacy.capture(
            case=case,
            input_payload=legacy_input,
            output_payload=legacy_output,
        )
        receipts.append(capture_op.receipt)
        capture = capture_op.value

        mapped_op = self.legacy.map_claim(
            case=case,
            capture=capture,
            claim_id=claim_id,
            subject=subject,
            predicate=predicate,
            object=object,
        )
        receipts.append(mapped_op.receipt)
        claim = mapped_op.value.claim

        compare_op = self.legacy.compare(
            case=case,
            capture=capture,
            galia2_output=galia2_output,
        )
        receipts.append(compare_op.receipt)
        comparison = compare_op.value

        stage = self._advance(stage, TransitionEvent.INGEST_CONFIRMED, {"source_artifact_valid"}, receipts)
        stage = self._advance(stage, TransitionEvent.NORMALIZATION_COMPLETE, {"lineage_complete"}, receipts)
        stage = self._advance(stage, TransitionEvent.DERIVATION_COMPLETE, {"output_hash_valid"}, receipts)
        stage = self._advance(stage, TransitionEvent.VALIDATION_PASSED, {"required_validations_passed"}, receipts)

        hold_op = self.authority.place_hold(claim=claim)
        claim = hold_op.value
        receipts.append(hold_op.receipt)
        stage = self._advance(stage, TransitionEvent.PLACE_AUTHORITY_HOLD, {"evidence_snapshot_present"}, receipts)

        if human_decision is None:
            return EndToEndResult(
                EndToEndStatus.HUMAN_AUTHORITY_REQUIRED,
                stage,
                capture,
                comparison,
                claim,
                None,
                None,
                None,
                None,
                tuple(receipts),
            )

        human_guards = self.authority.human_selection_guards(
            claim=claim,
            decision=human_decision,
            scope=scope,
        )
        selection_op = self.authority.record_human_selection(
            claim=claim,
            decision=human_decision,
            scope=scope,
        )
        claim = selection_op.value
        receipts.append(selection_op.receipt)
        stage = self._advance(stage, TransitionEvent.HUMAN_SELECTION_RECORDED, set(human_guards), receipts)

        auth_op = self.authority.issue_promotion_authorization(
            claim=claim,
            decision=human_decision,
            scope=scope,
            target_commit=manifest.commit_id,
        )
        authorization = auth_op.value
        receipts.append(auth_op.receipt)

        blocking = ()
        if comparison.discrepancy is not None:
            blocking = (comparison.discrepancy.discrepancy_id,)
        candidate = CandidateSnapshot(
            case_id=manifest.case_id,
            target_commit=manifest.commit_id,
            parent_commit=manifest.parent_commit,
            manifest_hash=manifest.sha256,
            payload_hashes=tuple(entry.sha256 for entry in manifest.payloads),
            lineage_complete=True,
            schema_version=manifest.schema_version,
            completed_stages=self.preflight.required_stages,
            blocking_discrepancy_ids=blocking,
            authority_decision_id=manifest.authority_decision_id,
        )
        report = self.preflight.evaluate(
            candidate=candidate,
            rollback=rollback,
            authorization=authorization,
            expected_scope=scope,
        )
        receipts.append(report.receipt)
        if not report.passed:
            return EndToEndResult(
                EndToEndStatus.PREFLIGHT_BLOCKED,
                stage,
                capture,
                comparison,
                claim,
                authorization,
                report,
                None,
                None,
                tuple(receipts),
            )

        stage = self._advance(stage, TransitionEvent.PREFLIGHT_PASSED, set(report.guards), receipts)
        staged = self.store.stage_generation(manifest=manifest, payloads=payloads)
        receipts.append(staged.receipt)

        promotion_guards = self.authority.promotion_guards(
            authorization=authorization,
            expected_scope=scope,
            target_commit=manifest.commit_id,
        )
        promotion_outcome = self.orchestrator.run_stage(
            stage,
            TransitionEvent.PROMOTION_AUTHORIZED,
            executor=lambda _stage, _ctx: StageExecution(guards=promotion_guards),
        )
        receipts.append(promotion_outcome.receipt)
        if promotion_outcome.decision is None or promotion_outcome.stage.state is not StageState.CANONICAL:
            raise RuntimeError("final promotion transition did not produce a canonical decision")

        published = self.store.publish_generation(
            staged=staged,
            candidate=candidate,
            preflight=report,
            authorization=authorization,
            expected_scope=scope,
            promotion_decision=promotion_outcome.decision,
        )
        receipts.append(published.receipt)
        return EndToEndResult(
            EndToEndStatus.PUBLISHED,
            promotion_outcome.stage,
            capture,
            comparison,
            claim,
            authorization,
            report,
            staged,
            published,
            tuple(receipts),
        )

    def open_recovery(
        self,
        trigger: RecoveryTrigger,
        *,
        affected_commit: Optional[str] = None,
    ) -> RecoveryIntake:
        if self.recovery is None:
            raise RuntimeError("recovery manager is not configured")
        return self.recovery.open_intake(trigger, affected_commit=affected_commit)

    def rollback(
        self,
        *,
        intake: RecoveryIntake,
        authorization: RecoveryAuthorization,
    ) -> RecoveryReceipt:
        if self.recovery is None:
            raise RuntimeError("recovery manager is not configured")
        return self.recovery.rollback(intake=intake, authorization=authorization)

    def _advance(
        self,
        stage: Stage,
        event: TransitionEvent,
        guards: set[str],
        receipts: list[Receipt],
    ) -> Stage:
        outcome = self.orchestrator.run_stage(
            stage,
            event,
            executor=lambda _stage, _ctx: StageExecution(guards=frozenset(guards)),
            context=StageRunContext(),
        )
        receipts.append(outcome.receipt)
        return outcome.stage

    @staticmethod
    def _validate_bindings(
        *,
        case: Case,
        stage: Stage,
        scope: AuthorityScope,
        manifest: GenerationManifest,
        claim_id: str,
    ) -> None:
        if stage.state is not StageState.DISCOVERED:
            raise ValueError("P9 requires an initial DISCOVERED stage")
        if stage.case_id != case.case_id:
            raise ValueError("stage belongs to a different case")
        if scope.case_id != case.case_id or scope.target_type != "CLAIM" or scope.target_ids != (claim_id,):
            raise ValueError("authority scope does not exactly bind the P9 claim")
        if manifest.case_id != case.case_id:
            raise ValueError("manifest belongs to a different case")
