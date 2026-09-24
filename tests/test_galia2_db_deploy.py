import unittest
from dataclasses import replace
from datetime import datetime, timezone

from galia2.db_deploy import (
    ChangeClass,
    DBMigrationEvent,
    DBMigrationState,
    GuardRejected,
    MigrationCandidate,
    SchemaDelta,
    ShadowApplyResult,
    UncertainExecutionOutcome,
    build_migration_receipt,
    classify_delta,
    execute_shadow,
    recovery_trigger_for_uncertain,
    requires_authority_hold,
    schema_fingerprint,
    transition,
    validate_execution,
)
from galia2.orchestrator import FailureKind, StageExecutionFailure
from galia2.recovery_audit import RecoveryTrigger

H = "a" * 64


def candidate(*, destructive=False, change_class=ChangeClass.ADDITIVE):
    return MigrationCandidate(
        candidate_id="GALIA-DB-DEPLOYMENT-v0.1-c1",
        migration_id="M001",
        parent_schema_version="1",
        target_schema_version="2",
        migration_sha256=H,
        change_class=change_class,
        destructive=destructive,
    )


class DBDeploymentCandidateTests(unittest.TestCase):
    def test_fingerprint_is_deterministic_across_mapping_order(self):
        a = {"tables": {"x": {"columns": ["id", "name"]}}, "version": 2}
        b = {"version": 2, "tables": {"x": {"columns": ["id", "name"]}}}
        self.assertEqual(schema_fingerprint(a), schema_fingerprint(b))

    def test_candidate_rejects_invalid_migration_hash(self):
        with self.assertRaises(ValueError):
            replace(candidate(), migration_sha256="bad")

    def test_additive_delta_classifies_non_destructive(self):
        result = classify_delta(SchemaDelta(added_objects=("table:new",)))
        self.assertEqual(result.change_class, ChangeClass.ADDITIVE)
        self.assertFalse(result.destructive)

    def test_removal_classifies_destructive(self):
        result = classify_delta(SchemaDelta(removed_objects=("column:old",)))
        self.assertEqual(result.change_class, ChangeClass.DESTRUCTIVE)
        self.assertTrue(result.destructive)

    def test_empty_delta_fails_closed(self):
        with self.assertRaises(ValueError):
            classify_delta(SchemaDelta())

    def test_local_state_machine_requires_guards(self):
        with self.assertRaises(GuardRejected):
            transition(DBMigrationState.DRAFT, DBMigrationEvent.VALIDATE_MANIFEST)

    def test_local_state_machine_happy_path_to_data_verified(self):
        state = transition(
            DBMigrationState.DRAFT,
            DBMigrationEvent.VALIDATE_MANIFEST,
            satisfied_guards={"migration_identity_valid"},
        )
        state = transition(
            state,
            DBMigrationEvent.CLASSIFY_CHANGE,
            satisfied_guards={"change_class_known"},
        )
        state = transition(
            state,
            DBMigrationEvent.APPLY_SHADOW,
            satisfied_guards={"shadow_only", "migration_identity_valid"},
        )
        state = transition(
            state,
            DBMigrationEvent.VERIFY_DATA,
            satisfied_guards={"schema_fingerprint_valid", "compatibility_checked"},
        )
        self.assertEqual(state, DBMigrationState.DATA_VERIFIED)

    def test_destructive_path_requires_hold_and_human_approval(self):
        state = transition(
            DBMigrationState.DATA_VERIFIED,
            DBMigrationEvent.PLACE_DESTRUCTIVE_HOLD,
            satisfied_guards={"destructive_change"},
        )
        self.assertEqual(state, DBMigrationState.DESTRUCTIVE_HOLD)
        state = transition(
            state,
            DBMigrationEvent.RECORD_HUMAN_APPROVAL,
            satisfied_guards={"human_decision_present"},
        )
        self.assertEqual(state, DBMigrationState.HUMAN_APPROVED)

    def test_non_destructive_deploy_ready_requires_preflight(self):
        with self.assertRaises(GuardRejected):
            transition(
                DBMigrationState.DATA_VERIFIED,
                DBMigrationEvent.MARK_DEPLOY_READY,
                satisfied_guards={"non_destructive"},
            )

    def test_shadow_executor_builds_evidence_and_stage_execution(self):
        c = candidate()

        def apply_shadow(_):
            return ShadowApplyResult(
                after_schema_descriptor={"tables": {"x": ["id"], "y": ["id"]}},
                output_ref="shadow://M001",
            )

        execution = execute_shadow(
            candidate=c,
            before_schema_descriptor={"tables": {"x": ["id"]}},
            apply_shadow=apply_shadow,
        )
        self.assertEqual(execution.evidence.migration_sha256, H)
        self.assertEqual(execution.evidence.shadow_result, "PASS")
        self.assertEqual(execution.as_stage_execution().output_refs, ("shadow://M001",))
        self.assertEqual(len(execution.as_stage_execution().output_hashes), 2)

    def test_validator_emits_global_stage_validation_guard(self):
        c = candidate()

        execution = execute_shadow(
            candidate=c,
            before_schema_descriptor={"tables": {"x": ["id"]}},
            apply_shadow=lambda _: ShadowApplyResult(
                after_schema_descriptor={"tables": {"x": ["id"], "y": ["id"]}},
                output_ref="shadow://M001",
            ),
        )
        result = validate_execution(candidate=c, execution=execution)
        self.assertTrue(result.passed)
        self.assertIn("required_validations_passed", result.guards)

    def test_validator_rejects_candidate_identity_mismatch(self):
        c = candidate()
        execution = execute_shadow(
            candidate=c,
            before_schema_descriptor={"tables": {"x": ["id"]}},
            apply_shadow=lambda _: ShadowApplyResult(
                after_schema_descriptor={"tables": {"x": ["id"], "y": ["id"]}},
                output_ref="shadow://M001",
            ),
        )
        other = replace(c, migration_id="M002")
        result = validate_execution(candidate=other, execution=execution)
        self.assertFalse(result.passed)
        self.assertEqual(result.failure_kind, FailureKind.INTEGRITY)

    def test_uncertain_shadow_outcome_routes_as_persistence_failure(self):
        def uncertain(_):
            raise UncertainExecutionOutcome("connection dropped", commit_may_have_occurred=True)

        with self.assertRaises(StageExecutionFailure) as ctx:
            execute_shadow(
                candidate=candidate(),
                before_schema_descriptor={"tables": {}},
                apply_shadow=uncertain,
            )
        self.assertEqual(ctx.exception.kind, FailureKind.PERSISTENCE)

    def test_uncertain_outcome_maps_to_promoted_recovery_triggers(self):
        self.assertEqual(
            recovery_trigger_for_uncertain(commit_may_have_occurred=True),
            RecoveryTrigger.PARTIAL_COMMIT,
        )
        self.assertEqual(
            recovery_trigger_for_uncertain(commit_may_have_occurred=False),
            RecoveryTrigger.EXECUTION_INTERRUPTION,
        )

    def test_destructive_candidate_requires_authority_hold(self):
        c = candidate(destructive=True, change_class=ChangeClass.DESTRUCTIVE)
        self.assertTrue(requires_authority_hold(c))
        self.assertFalse(requires_authority_hold(candidate()))

    def test_receipt_binds_migration_and_schema_hashes(self):
        c = candidate()
        execution = execute_shadow(
            candidate=c,
            before_schema_descriptor={"tables": {"x": ["id"]}},
            apply_shadow=lambda _: ShadowApplyResult(
                after_schema_descriptor={"tables": {"x": ["id"], "y": ["id"]}},
                output_ref="shadow://M001",
            ),
        )
        receipt = build_migration_receipt(
            evidence=execution.evidence,
            receipt_id="receipt-db-1",
            policy_version="db-deploy-v0.1-c1",
            actor="test",
            timestamp=datetime.now(timezone.utc),
        )
        self.assertEqual(receipt.input_hashes[0], H)
        self.assertEqual(receipt.output_hashes[0], execution.evidence.sha256)
        self.assertIsNone(receipt.output_commit)


if __name__ == "__main__":
    unittest.main()
