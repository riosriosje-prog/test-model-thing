import ast
import inspect
import unittest
from datetime import datetime, timezone
from pathlib import Path

from galia2.authority import AuthorityScope, PromotionAuthorization
from galia2.core import Stage, StageState
from galia2.preflight import CandidateSnapshot, PromotionPreflight, RollbackSnapshot
from galia2.state_machine import GuardRejected, TransitionEvent, apply_transition

NOW = datetime(2026, 9, 24, 4, 0, tzinfo=timezone.utc)
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


def ids_factory():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return ids


def engine(**kwargs):
    values = dict(
        policy_version="core-v1+p2+p3+p4+p5+p6",
        accepted_authority_policy_version="core-v1+p2+p3+p4+p5",
        required_schema_version="galia2-core-v1",
        required_stages=("SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"),
        actor="p6-test",
        clock=lambda: NOW,
        id_factory=ids_factory(),
    )
    values.update(kwargs)
    return PromotionPreflight(**values)


def scope(case_id="case-1", target_ids=("claim-1",)):
    return AuthorityScope(case_id, "CLAIM", target_ids)


def auth(*, target_commit="candidate-17", decision_id="decision-1", scoped=None, policy=None):
    s = scope() if scoped is None else scoped
    return PromotionAuthorization(
        authorization_id="auth-1",
        decision_id=decision_id,
        reviewer="human-reviewer",
        scope=s,
        target_commit=target_commit,
        evidence_snapshot=("evidence-1",),
        policy_version=policy or "core-v1+p2+p3+p4+p5",
        authorized_at=NOW,
    )


def candidate(**kwargs):
    values = dict(
        case_id="case-1",
        target_commit="candidate-17",
        parent_commit="canonical-16",
        manifest_hash=H1,
        payload_hashes=(H2,),
        lineage_complete=True,
        schema_version="galia2-core-v1",
        completed_stages=("SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"),
        blocking_discrepancy_ids=(),
        authority_decision_id="decision-1",
    )
    values.update(kwargs)
    return CandidateSnapshot(**values)


def rollback(**kwargs):
    values = dict(
        commit_id="canonical-16",
        manifest_hash=H3,
        integrity_valid=True,
        schema_compatible=True,
        authority_refs_valid=True,
        known_good=True,
    )
    values.update(kwargs)
    return RollbackSnapshot(**values)


class PromotionPreflightTests(unittest.TestCase):
    def test_exact_candidate_passes_and_emits_only_preflight_guards(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_checks, ())
        self.assertEqual(report.guards, frozenset({"preflight_passed", "rollback_target_verified"}))
        self.assertIsNone(report.receipt.output_commit)
        self.assertNotIn("promotion_authorization_present", report.guards)

    def test_missing_authorization_fails_closed(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=None, expected_scope=scope()
        )
        self.assertFalse(report.passed)
        names = {c.name for c in report.failed_checks}
        self.assertIn("authorization_present", names)
        self.assertIn("authorization_matches_target", names)
        self.assertEqual(report.guards, frozenset())

    def test_target_commit_mismatch_fails(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(target_commit="candidate-18"), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("authorization_matches_target", {c.name for c in report.failed_checks})

    def test_decision_binding_mismatch_fails(self):
        report = engine().evaluate(
            candidate=candidate(authority_decision_id="decision-2"), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("authorization_matches_target", {c.name for c in report.failed_checks})

    def test_authority_policy_mismatch_fails(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(policy="wrong-policy"), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("authorization_matches_target", {c.name for c in report.failed_checks})

    def test_case_or_scope_mismatch_fails(self):
        other_scope = scope(case_id="case-other")
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(scoped=other_scope), expected_scope=other_scope
        )
        self.assertFalse(report.passed)
        self.assertIn("authorization_matches_target", {c.name for c in report.failed_checks})

    def test_incomplete_lineage_fails(self):
        report = engine().evaluate(
            candidate=candidate(lineage_complete=False), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("lineage_complete", {c.name for c in report.failed_checks})

    def test_schema_mismatch_fails(self):
        report = engine().evaluate(
            candidate=candidate(schema_version="old-schema"), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("schema_valid", {c.name for c in report.failed_checks})

    def test_missing_required_stage_fails(self):
        report = engine().evaluate(
            candidate=candidate(completed_stages=("SCHEMA", "LINEAGE", "AUTHORITY")), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("required_stages_complete", {c.name for c in report.failed_checks})

    def test_blocking_discrepancy_fails(self):
        report = engine().evaluate(
            candidate=candidate(blocking_discrepancy_ids=("disc-1",)), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("no_blocking_discrepancy", {c.name for c in report.failed_checks})

    def test_rollback_must_be_exact_parent(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(commit_id="canonical-15"), authorization=auth(), expected_scope=scope()
        )
        self.assertFalse(report.passed)
        self.assertIn("rollback_parent_match", {c.name for c in report.failed_checks})

    def test_rollback_must_be_known_good_and_verified(self):
        report = engine().evaluate(
            candidate=candidate(),
            rollback=rollback(integrity_valid=False, schema_compatible=False, authority_refs_valid=False, known_good=False),
            authorization=auth(), expected_scope=scope(),
        )
        self.assertFalse(report.passed)
        names = {c.name for c in report.failed_checks}
        self.assertTrue({
            "rollback_integrity_valid", "rollback_schema_compatible",
            "rollback_authority_refs_valid", "rollback_known_good"
        }.issubset(names))

    def test_candidate_rejects_invalid_manifest_hash(self):
        with self.assertRaises(ValueError):
            candidate(manifest_hash="not-a-sha")

    def test_candidate_rejects_duplicate_completed_stages(self):
        with self.assertRaises(ValueError):
            candidate(completed_stages=("SCHEMA", "SCHEMA"))

    def test_passing_report_advances_human_selected_only_to_promotion_ready(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        stage = Stage("stage-1", "case-1", "PROMOTION", StageState.HUMAN_SELECTED)
        advanced, _ = apply_transition(stage, TransitionEvent.PREFLIGHT_PASSED, satisfied_guards=report.guards)
        self.assertEqual(advanced.state, StageState.PROMOTION_READY)

    def test_failed_report_cannot_advance_to_promotion_ready(self):
        report = engine().evaluate(
            candidate=candidate(lineage_complete=False), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        stage = Stage("stage-1", "case-1", "PROMOTION", StageState.HUMAN_SELECTED)
        with self.assertRaises(GuardRejected):
            apply_transition(stage, TransitionEvent.PREFLIGHT_PASSED, satisfied_guards=report.guards)

    def test_passing_preflight_still_cannot_make_stage_canonical(self):
        report = engine().evaluate(
            candidate=candidate(), rollback=rollback(), authorization=auth(), expected_scope=scope()
        )
        stage = Stage("stage-1", "case-1", "PROMOTION", StageState.PROMOTION_READY)
        with self.assertRaises(GuardRejected):
            apply_transition(stage, TransitionEvent.PROMOTION_AUTHORIZED, satisfied_guards=report.guards)

    def test_preflight_module_has_no_filesystem_process_network_or_legacy_imports(self):
        module_path = Path(inspect.getsourcefile(PromotionPreflight))
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

    def test_preflight_exposes_only_evaluate_as_public_action(self):
        public = {
            name for name, _ in inspect.getmembers(PromotionPreflight, inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual(public, {"evaluate"})


if __name__ == "__main__":
    unittest.main()
