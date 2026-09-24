import unittest
from datetime import datetime, timezone

from galia2.core import Stage, StageState
from galia2.orchestrator import (
    FailureKind,
    OrchestrationStatus,
    StageExecution,
    StageExecutionFailure,
    StageOrchestrator,
    StageRunContext,
    StageValidation,
)
from galia2.state_machine import GuardRejected, TransitionEvent

H1 = "1" * 64
H2 = "2" * 64
NOW = datetime(2026, 9, 23, 22, 30, tzinfo=timezone.utc)


def stage(state=StageState.DISCOVERED, **kwargs):
    return Stage("s1", "c1", "CORE", state, **kwargs)


def orch():
    return StageOrchestrator(
        policy_version="core-v1+p2",
        actor="galia2-p3-test",
        clock=lambda: NOW,
        receipt_id_factory=lambda: "r-fixed",
    )


class OrchestratorTests(unittest.TestCase):
    def test_successful_stage_execution_advances_and_emits_receipt(self):
        out = orch().run_stage(
            stage(),
            TransitionEvent.INGEST_CONFIRMED,
            executor=lambda s, c: StageExecution(
                output_refs=("artifact:a1",),
                output_hashes=(H2,),
                guards=frozenset({"source_artifact_valid"}),
            ),
            context=StageRunContext(input_commit="commit-0", input_hashes=(H1,)),
        )
        self.assertEqual(out.status, OrchestrationStatus.ADVANCED)
        self.assertEqual(out.stage.state, StageState.INGESTED)
        self.assertEqual(out.stage.output_refs, ("artifact:a1",))
        self.assertEqual(out.receipt.input_commit, "commit-0")
        self.assertEqual(out.receipt.output_commit, None)
        self.assertEqual(out.receipt.output_hashes, (H2,))
        self.assertEqual(out.receipt.receipt_id, "r-fixed")

    def test_missing_dependency_blocks_without_running_executor(self):
        called = []
        def executor(s, c):
            called.append(True)
            return StageExecution(guards=frozenset({"source_artifact_valid"}))

        out = orch().run_stage(
            stage(dependencies=("s0",)),
            TransitionEvent.INGEST_CONFIRMED,
            executor=executor,
        )
        self.assertEqual(out.status, OrchestrationStatus.BLOCKED)
        self.assertEqual(out.stage.state, StageState.DISCOVERED)
        self.assertEqual(called, [])
        self.assertIn("missing dependencies", out.receipt.result)

    def test_dependency_allows_execution_when_completed(self):
        out = orch().run_stage(
            stage(dependencies=("s0",)),
            TransitionEvent.INGEST_CONFIRMED,
            executor=lambda s, c: StageExecution(guards=frozenset({"source_artifact_valid"})),
            context=StageRunContext(completed_stage_ids=frozenset({"s0"})),
        )
        self.assertEqual(out.status, OrchestrationStatus.ADVANCED)

    def test_blocking_hold_blocks_without_executor(self):
        called = []
        out = orch().run_stage(
            stage(blocking_holds=("HOLD-7",)),
            TransitionEvent.INGEST_CONFIRMED,
            executor=lambda s, c: called.append(True),
        )
        self.assertEqual(out.status, OrchestrationStatus.BLOCKED)
        self.assertEqual(called, [])
        self.assertIn("HOLD-7", out.reason)

    def test_typed_integrity_failure_routes_to_quarantine(self):
        def executor(s, c):
            raise StageExecutionFailure(FailureKind.INTEGRITY, "hash mismatch")

        out = orch().run_stage(stage(StageState.NORMALIZED), TransitionEvent.DERIVATION_COMPLETE, executor=executor)
        self.assertEqual(out.status, OrchestrationStatus.ROUTED_FAILURE)
        self.assertEqual(out.stage.state, StageState.QUARANTINED)
        self.assertIn("hash mismatch", out.receipt.result)

    def test_untyped_executor_failure_fails_closed_to_quarantine(self):
        def executor(s, c):
            raise RuntimeError("boom")

        out = orch().run_stage(stage(StageState.INGESTED), TransitionEvent.NORMALIZATION_COMPLETE, executor=executor)
        self.assertEqual(out.stage.state, StageState.QUARANTINED)
        self.assertIn("untyped executor failure", out.reason)

    def test_validator_material_conflict_routes_to_discrepancy_review(self):
        out = orch().run_stage(
            stage(StageState.DERIVED),
            TransitionEvent.VALIDATION_PASSED,
            executor=lambda s, c: StageExecution(output_refs=("claim:c1",), output_hashes=(H2,)),
            validators=(lambda s, e, c: StageValidation(
                False,
                failure_kind=FailureKind.MATERIAL_CONFLICT,
                message="claims disagree",
            ),),
        )
        self.assertEqual(out.status, OrchestrationStatus.ROUTED_FAILURE)
        self.assertEqual(out.stage.state, StageState.DISCREPANCY_REVIEW)
        self.assertEqual(out.stage.output_refs, ("claim:c1",))
        self.assertEqual(out.receipt.output_hashes, (H2,))

    def test_validator_persistence_failure_routes_to_recovery(self):
        out = orch().run_stage(
            stage(StageState.HUMAN_SELECTED),
            TransitionEvent.PREFLIGHT_PASSED,
            executor=lambda s, c: StageExecution(output_hashes=(H2,)),
            validators=(lambda s, e, c: StageValidation(
                False,
                failure_kind=FailureKind.PERSISTENCE,
                message="manifest store unavailable",
            ),),
        )
        self.assertEqual(out.stage.state, StageState.RECOVERY_INTAKE)

    def test_validator_can_supply_required_transition_guard(self):
        out = orch().run_stage(
            stage(StageState.DERIVED),
            TransitionEvent.VALIDATION_PASSED,
            executor=lambda s, c: StageExecution(),
            validators=(lambda s, e, c: StageValidation(
                True, guards=frozenset({"required_validations_passed"})
            ),),
        )
        self.assertEqual(out.stage.state, StageState.VALIDATED)

    def test_orchestrator_does_not_invent_missing_guard(self):
        with self.assertRaises(GuardRejected):
            orch().run_stage(
                stage(StageState.AUTHORITY_HOLD),
                TransitionEvent.HUMAN_SELECTION_RECORDED,
                executor=lambda s, c: StageExecution(),
            )

    def test_context_guard_may_satisfy_human_boundary_but_is_not_created_by_orchestrator(self):
        out = orch().run_stage(
            stage(StageState.AUTHORITY_HOLD),
            TransitionEvent.HUMAN_SELECTION_RECORDED,
            executor=lambda s, c: StageExecution(),
            context=StageRunContext(satisfied_guards=frozenset({"human_decision_present"})),
        )
        self.assertEqual(out.stage.state, StageState.HUMAN_SELECTED)
        self.assertTrue(out.decision.crosses_human_boundary)

    def test_p3_never_sets_output_commit(self):
        out = orch().run_stage(
            stage(),
            TransitionEvent.INGEST_CONFIRMED,
            executor=lambda s, c: StageExecution(guards=frozenset({"source_artifact_valid"})),
        )
        self.assertIsNone(out.receipt.output_commit)

    def test_invalid_executor_return_type_fails_closed(self):
        out = orch().run_stage(
            stage(),
            TransitionEvent.INGEST_CONFIRMED,
            executor=lambda s, c: None,
        )
        self.assertEqual(out.stage.state, StageState.QUARANTINED)
        self.assertIn("TypeError", out.reason)

    def test_invalid_validator_return_type_is_programming_error_not_silent_route(self):
        with self.assertRaises(TypeError):
            orch().run_stage(
                stage(StageState.DERIVED),
                TransitionEvent.VALIDATION_PASSED,
                executor=lambda s, c: StageExecution(),
                validators=(lambda s, e, c: None,),
            )


if __name__ == "__main__":
    unittest.main()
