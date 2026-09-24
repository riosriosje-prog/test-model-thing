import ast
import inspect
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

from galia2.authority import (
    AuthorityLayer,
    AuthorityScope,
    HumanDecisionKind,
)
from galia2.core import (
    AuthorityDecision,
    AuthorityState,
    Claim,
    ClaimType,
    EvidenceState,
    Stage,
    StageState,
)
from galia2.state_machine import TransitionEvent, apply_transition, GuardRejected

NOW = datetime(2026, 9, 23, 23, 30, tzinfo=timezone.utc)


def ids_factory():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return ids


def layer():
    return AuthorityLayer(
        policy_version="core-v1+p2+p3+p4+p5",
        actor="p5-test",
        clock=lambda: NOW,
        id_factory=ids_factory(),
    )


def claim(state=AuthorityState.NONE):
    return Claim(
        claim_id="claim-1",
        case_id="case-1",
        subject="Taft",
        predicate="INTERSECTS",
        object="Loiza",
        valid_from=None,
        valid_to=None,
        claim_type=ClaimType.DERIVED,
        evidence_state=EvidenceState.CORROBORATED,
        authority_state=state,
    )


def scope(case_id="case-1", target_ids=("claim-1",), target_type="CLAIM"):
    return AuthorityScope(case_id, target_type, target_ids)


def decision(kind=HumanDecisionKind.SELECT.value, *, target_id="claim-1", scoped=None):
    s = scope() if scoped is None else scoped
    return AuthorityDecision(
        decision_id="decision-1",
        target_id=target_id,
        reviewer="human-reviewer",
        decision=kind,
        scope=s.token,
        evidence_snapshot=("evidence-1", "evidence-2"),
        timestamp=NOW,
    )


class AuthorityLayerTests(unittest.TestCase):
    def test_place_hold_is_immutable_replacement(self):
        original = claim()
        out = layer().place_hold(claim=original)
        self.assertEqual(original.authority_state, AuthorityState.NONE)
        self.assertEqual(out.value.authority_state, AuthorityState.HOLD)
        self.assertIsNot(original, out.value)
        self.assertIsNone(out.receipt.output_commit)

    def test_place_hold_rejects_post_selection_state(self):
        with self.assertRaises(ValueError):
            layer().place_hold(claim=claim(AuthorityState.HUMAN_SELECTED))

    def test_missing_human_decision_cannot_synthesize_guard(self):
        guards = layer().human_selection_guards(
            claim=claim(AuthorityState.HOLD), decision=None, scope=scope()
        )
        self.assertEqual(guards, frozenset())

    def test_exact_select_decision_emits_human_guard(self):
        guards = layer().human_selection_guards(
            claim=claim(AuthorityState.HOLD), decision=decision(), scope=scope()
        )
        self.assertEqual(guards, frozenset({"human_decision_present"}))

    def test_hold_or_reject_decision_does_not_emit_selection_guard(self):
        for kind in (HumanDecisionKind.HOLD.value, HumanDecisionKind.REJECT.value):
            guards = layer().human_selection_guards(
                claim=claim(AuthorityState.HOLD), decision=decision(kind), scope=scope()
            )
            self.assertEqual(guards, frozenset())

    def test_decision_target_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            layer().human_selection_guards(
                claim=claim(AuthorityState.HOLD),
                decision=decision(target_id="claim-other"),
                scope=scope(),
            )

    def test_decision_scope_mismatch_is_rejected(self):
        wrong = scope(case_id="case-other")
        d = AuthorityDecision(
            "d", "claim-1", "human", "SELECT", wrong.token, ("e",), NOW
        )
        with self.assertRaises(ValueError):
            layer().human_selection_guards(
                claim=claim(AuthorityState.HOLD), decision=d, scope=scope()
            )

    def test_scope_must_target_exactly_one_claim(self):
        with self.assertRaises(ValueError):
            layer().human_selection_guards(
                claim=claim(AuthorityState.HOLD),
                decision=decision(),
                scope=scope(target_ids=("claim-1", "claim-2")),
            )

    def test_record_selection_updates_claim_side_only(self):
        out = layer().record_human_selection(
            claim=claim(AuthorityState.HOLD), decision=decision(), scope=scope()
        )
        self.assertEqual(out.value.authority_state, AuthorityState.HUMAN_SELECTED)
        self.assertIsNone(out.receipt.output_commit)

    def test_authorization_requires_human_selected_claim(self):
        with self.assertRaises(ValueError):
            layer().issue_promotion_authorization(
                claim=claim(AuthorityState.HOLD),
                decision=decision(),
                scope=scope(),
                target_commit="candidate-17",
            )

    def test_authorization_binds_exact_case_targets_commit_and_decision(self):
        out = layer().issue_promotion_authorization(
            claim=claim(AuthorityState.HUMAN_SELECTED),
            decision=decision(),
            scope=scope(),
            target_commit="candidate-17",
        )
        auth = out.value
        self.assertEqual(auth.decision_id, "decision-1")
        self.assertEqual(auth.scope, scope())
        self.assertEqual(auth.target_commit, "candidate-17")
        self.assertEqual(auth.reviewer, "human-reviewer")
        self.assertIsNone(out.receipt.output_commit)
        with self.assertRaises(FrozenInstanceError):
            auth.target_commit = "candidate-18"

    def test_promotion_presence_is_not_target_match(self):
        a = layer()
        auth = a.issue_promotion_authorization(
            claim=claim(AuthorityState.HUMAN_SELECTED),
            decision=decision(),
            scope=scope(),
            target_commit="candidate-17",
        ).value
        guards = a.promotion_guards(
            authorization=auth,
            expected_scope=scope(),
            target_commit="candidate-18",
        )
        self.assertIn("promotion_authorization_present", guards)
        self.assertNotIn("authorization_matches_target", guards)

    def test_exact_authorization_emits_both_promotion_guards(self):
        a = layer()
        auth = a.issue_promotion_authorization(
            claim=claim(AuthorityState.HUMAN_SELECTED),
            decision=decision(),
            scope=scope(),
            target_commit="candidate-17",
        ).value
        guards = a.promotion_guards(
            authorization=auth,
            expected_scope=scope(),
            target_commit="candidate-17",
        )
        self.assertEqual(
            guards,
            frozenset({"promotion_authorization_present", "authorization_matches_target"}),
        )

    def test_absent_authorization_emits_no_promotion_guards(self):
        guards = layer().promotion_guards(
            authorization=None, expected_scope=scope(), target_commit="candidate-17"
        )
        self.assertEqual(guards, frozenset())

    def test_p2_human_boundary_accepts_only_guard_from_valid_decision(self):
        s = Stage("stage-1", "case-1", "AUTHORITY", StageState.AUTHORITY_HOLD)
        a = layer()
        guards = a.human_selection_guards(
            claim=claim(AuthorityState.HOLD), decision=decision(), scope=scope()
        )
        advanced, _ = apply_transition(
            s, TransitionEvent.HUMAN_SELECTION_RECORDED, satisfied_guards=guards
        )
        self.assertEqual(advanced.state, StageState.HUMAN_SELECTED)
        with self.assertRaises(GuardRejected):
            apply_transition(
                s, TransitionEvent.HUMAN_SELECTION_RECORDED, satisfied_guards=frozenset()
            )

    def test_p2_promotion_boundary_rejects_mismatched_target(self):
        s = Stage("stage-1", "case-1", "PROMOTION", StageState.PROMOTION_READY)
        a = layer()
        auth = a.issue_promotion_authorization(
            claim=claim(AuthorityState.HUMAN_SELECTED),
            decision=decision(),
            scope=scope(),
            target_commit="candidate-17",
        ).value
        guards = a.promotion_guards(
            authorization=auth,
            expected_scope=scope(),
            target_commit="candidate-18",
        )
        with self.assertRaises(GuardRejected):
            apply_transition(s, TransitionEvent.PROMOTION_AUTHORIZED, satisfied_guards=guards)

    def test_authority_module_has_no_filesystem_network_or_legacy_imports(self):
        module_path = Path(inspect.getsourcefile(AuthorityLayer))
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        forbidden = {"os", "pathlib", "subprocess", "shutil", "socket", "urllib", "requests", "main"}
        imported = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(imported.isdisjoint(forbidden), imported & forbidden)
        self.assertNotIn("open", called_names)

    def test_authority_layer_exposes_no_transition_or_persistence_method(self):
        public = {
            name
            for name, _ in inspect.getmembers(AuthorityLayer, inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual(
            public,
            {
                "human_selection_guards",
                "issue_promotion_authorization",
                "place_hold",
                "promotion_guards",
                "record_human_selection",
            },
        )


if __name__ == "__main__":
    unittest.main()
