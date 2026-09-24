import unittest

from galia2.core import Stage, StageState
from galia2.state_machine import (
    FORBIDDEN_DIRECT_TRANSITIONS,
    GuardRejected,
    InvalidTransition,
    TransitionEvent,
    allowed_events,
    apply_transition,
    evaluate_transition,
)


def stage(state: StageState) -> Stage:
    return Stage("s1", "c1", "CORE", state)


class StateMachineTests(unittest.TestCase):
    def test_happy_path_requires_every_stage(self):
        s = stage(StageState.DISCOVERED)
        path = [s.state]
        sequence = [
            (TransitionEvent.INGEST_CONFIRMED, {"source_artifact_valid"}),
            (TransitionEvent.NORMALIZATION_COMPLETE, {"lineage_complete"}),
            (TransitionEvent.DERIVATION_COMPLETE, {"output_hash_valid"}),
            (TransitionEvent.VALIDATION_PASSED, {"required_validations_passed"}),
            (TransitionEvent.PLACE_AUTHORITY_HOLD, {"evidence_snapshot_present"}),
            (TransitionEvent.HUMAN_SELECTION_RECORDED, {"human_decision_present"}),
            (TransitionEvent.PREFLIGHT_PASSED, {"preflight_passed", "rollback_target_verified"}),
            (TransitionEvent.PROMOTION_AUTHORIZED, {"promotion_authorization_present", "authorization_matches_target"}),
        ]
        for event, guards in sequence:
            s, _ = apply_transition(s, event, satisfied_guards=guards)
            path.append(s.state)

        self.assertEqual(
            path,
            [
                StageState.DISCOVERED,
                StageState.INGESTED,
                StageState.NORMALIZED,
                StageState.DERIVED,
                StageState.VALIDATED,
                StageState.AUTHORITY_HOLD,
                StageState.HUMAN_SELECTED,
                StageState.PROMOTION_READY,
                StageState.CANONICAL,
            ],
        )

    def test_missing_guard_fails_closed(self):
        with self.assertRaises(GuardRejected) as ctx:
            evaluate_transition(stage(StageState.DERIVED), TransitionEvent.VALIDATION_PASSED)
        self.assertEqual(ctx.exception.missing_guards, ("required_validations_passed",))

    def test_cannot_skip_from_derived_to_promotion(self):
        with self.assertRaises(InvalidTransition):
            evaluate_transition(
                stage(StageState.DERIVED),
                TransitionEvent.PROMOTION_AUTHORIZED,
                satisfied_guards={"promotion_authorization_present", "authorization_matches_target"},
            )

    def test_validated_cannot_promote_directly(self):
        with self.assertRaises(InvalidTransition):
            evaluate_transition(
                stage(StageState.VALIDATED),
                TransitionEvent.PROMOTION_AUTHORIZED,
                satisfied_guards={"promotion_authorization_present", "authorization_matches_target"},
            )

    def test_authority_hold_requires_human_decision(self):
        with self.assertRaises(GuardRejected):
            evaluate_transition(stage(StageState.AUTHORITY_HOLD), TransitionEvent.HUMAN_SELECTION_RECORDED)
        d = evaluate_transition(
            stage(StageState.AUTHORITY_HOLD),
            TransitionEvent.HUMAN_SELECTION_RECORDED,
            satisfied_guards={"human_decision_present"},
        )
        self.assertTrue(d.crosses_human_boundary)
        self.assertEqual(d.to_state, StageState.HUMAN_SELECTED)

    def test_promotion_requires_both_authorization_guards(self):
        with self.assertRaises(GuardRejected) as ctx:
            evaluate_transition(
                stage(StageState.PROMOTION_READY),
                TransitionEvent.PROMOTION_AUTHORIZED,
                satisfied_guards={"promotion_authorization_present"},
            )
        self.assertEqual(ctx.exception.missing_guards, ("authorization_matches_target",))

    def test_integrity_failure_routes_to_quarantine(self):
        d = evaluate_transition(
            stage(StageState.NORMALIZED),
            TransitionEvent.INTEGRITY_FAILURE,
            satisfied_guards={"integrity_failure_confirmed"},
        )
        self.assertEqual(d.to_state, StageState.QUARANTINED)

    def test_material_conflict_routes_to_discrepancy_review(self):
        d = evaluate_transition(
            stage(StageState.CANONICAL),
            TransitionEvent.MATERIAL_CONFLICT,
            satisfied_guards={"material_conflict_confirmed"},
        )
        self.assertEqual(d.to_state, StageState.DISCREPANCY_REVIEW)

    def test_persistence_failure_routes_to_recovery(self):
        d = evaluate_transition(
            stage(StageState.PROMOTION_READY),
            TransitionEvent.PERSISTENCE_FAILURE,
            satisfied_guards={"persistence_failure_confirmed"},
        )
        self.assertEqual(d.to_state, StageState.RECOVERY_INTAKE)

    def test_failure_state_does_not_implicitly_chain(self):
        with self.assertRaises(InvalidTransition):
            evaluate_transition(
                stage(StageState.QUARANTINED),
                TransitionEvent.PERSISTENCE_FAILURE,
                satisfied_guards={"persistence_failure_confirmed"},
            )

    def test_canonical_reopens_on_new_material_evidence(self):
        updated, d = apply_transition(
            stage(StageState.CANONICAL),
            TransitionEvent.NEW_MATERIAL_EVIDENCE,
            satisfied_guards={"new_material_evidence"},
        )
        self.assertEqual(updated.state, StageState.REOPENED)
        self.assertEqual(d.from_state, StageState.CANONICAL)

    def test_canonical_does_not_reopen_without_material_evidence_guard(self):
        with self.assertRaises(GuardRejected):
            evaluate_transition(stage(StageState.CANONICAL), TransitionEvent.NEW_MATERIAL_EVIDENCE)

    def test_apply_transition_does_not_mutate_original_stage(self):
        original = stage(StageState.DISCOVERED)
        updated, _ = apply_transition(
            original,
            TransitionEvent.INGEST_CONFIRMED,
            satisfied_guards={"source_artifact_valid"},
        )
        self.assertEqual(original.state, StageState.DISCOVERED)
        self.assertEqual(updated.state, StageState.INGESTED)
        self.assertIsNot(original, updated)

    def test_forbidden_transition_constants_include_core_safety_rules(self):
        self.assertIn((StageState.DERIVED, StageState.CANONICAL), FORBIDDEN_DIRECT_TRANSITIONS)
        self.assertIn((StageState.VALIDATED, StageState.CANONICAL), FORBIDDEN_DIRECT_TRANSITIONS)
        self.assertIn((StageState.AUTHORITY_HOLD, StageState.CANONICAL), FORBIDDEN_DIRECT_TRANSITIONS)
        self.assertIn((StageState.RECOVERY_INTAKE, StageState.CANONICAL), FORBIDDEN_DIRECT_TRANSITIONS)

    def test_allowed_events_exposes_failure_routes_but_not_promotion_skip(self):
        events = allowed_events(StageState.DERIVED)
        self.assertIn(TransitionEvent.VALIDATION_PASSED, events)
        self.assertIn(TransitionEvent.INTEGRITY_FAILURE, events)
        self.assertNotIn(TransitionEvent.PROMOTION_AUTHORIZED, events)


if __name__ == "__main__":
    unittest.main()
