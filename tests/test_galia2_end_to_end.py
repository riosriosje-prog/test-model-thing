import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.authority import AuthorityLayer, AuthorityScope
from galia2.core import (
    AuthorityDecision, Case, CaseState, Stage, StageState,
)
from galia2.end_to_end import EndToEndGate, EndToEndStatus
from galia2.legacy_adapter import LegacyAdapter, LegacyDiffKind
from galia2.orchestrator import StageOrchestrator
from galia2.persistence import (
    GenerationManifest, GenerationStore, HeadPointer, PayloadEntry, PromotionEnvelope,
    PersistencePublishError,
)
from galia2.preflight import PromotionPreflight, RollbackSnapshot
from galia2.recovery_audit import (
    AuditLedger, RecoveryAuthorization, RecoveryManager, RecoveryTrigger,
    RecoveryValidationError,
)

NOW = datetime(2026, 9, 24, 6, 0, tzinfo=timezone.utc)
AUTH_POLICY = "core-v1+p2+p3+p4+p5"
PERSIST_POLICY = "core-v1+p2+p3+p4+p5+p6+p7"
RECOVERY_POLICY = PERSIST_POLICY
SCHEMA = "galia2-core-v1"
CASE_ID = "case-e2e"
CLAIM_ID = "claim-e2e"
TARGET = "candidate-17"
PARENT = "canonical-16"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ids_factory():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return ids


def mk_case():
    return Case(
        case_id=CASE_ID,
        title="E2E case",
        scope="P9 integration",
        state=CaseState.ACTIVE_RESEARCH,
        created_at=NOW,
        governing_constitution_version="core-v1",
    )


def mk_stage():
    return Stage("stage-e2e", CASE_ID, "E2E", StageState.DISCOVERED)


def mk_scope(case_id=CASE_ID, claim_id=CLAIM_ID):
    return AuthorityScope(case_id, "CLAIM", (claim_id,))


def mk_decision(scope=None, decision="SELECT", target=CLAIM_ID):
    scope = mk_scope() if scope is None else scope
    return AuthorityDecision(
        decision_id="decision-e2e",
        target_id=target,
        reviewer="human-reviewer",
        decision=decision,
        scope=scope.token,
        evidence_snapshot=("evidence-e2e",),
        timestamp=NOW,
    )


def payloads():
    return {
        "claims.json": b'{"claim":"e2e"}\n',
        "evidence/source.txt": b"source bytes\n",
    }


def entries(data=None):
    data = payloads() if data is None else data
    return tuple(
        PayloadEntry(path=path, sha256=sha(content), byte_size=len(content))
        for path, content in sorted(data.items())
    )


def mk_manifest(*, commit=TARGET, parent=PARENT, seq=17, decision_id="decision-e2e"):
    return GenerationManifest(
        commit_id=commit,
        seq=seq,
        parent_commit=parent,
        case_id=CASE_ID,
        schema_version=SCHEMA,
        created_at=NOW,
        payloads=entries(),
        authority_decision_id=decision_id,
        persistence_policy_version=PERSIST_POLICY,
    )


def seed_parent(store: GenerationStore):
    data = {"base.txt": b"known good\n"}
    m = GenerationManifest(
        commit_id=PARENT,
        seq=16,
        parent_commit="canonical-15",
        case_id=CASE_ID,
        schema_version=SCHEMA,
        created_at=NOW,
        payloads=entries(data),
        authority_decision_id="decision-old",
        persistence_policy_version=PERSIST_POLICY,
    )
    gen = store.generations / m.commit_id
    (gen / "payload").mkdir(parents=True)
    for entry in m.payloads:
        p = gen / "payload" / entry.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data[entry.path])
    (gen / "manifest.json").write_bytes(m.to_bytes())
    promotion = PromotionEnvelope(
        commit_id=m.commit_id,
        case_id=m.case_id,
        manifest_hash=m.sha256,
        authority_decision_id=m.authority_decision_id,
        authorization_id="auth-old",
        authorization_policy_version=AUTH_POLICY,
        preflight_receipt_id="preflight-old",
        persistence_policy_version=PERSIST_POLICY,
        published_at=NOW,
    )
    (gen / "promotion.json").write_bytes(promotion.to_bytes())
    store.head_path.write_bytes(HeadPointer(m.commit_id, m.seq, m.sha256, promotion.sha256).to_bytes())
    return m


def mk_rollback(parent_manifest, **overrides):
    values = dict(
        commit_id=parent_manifest.commit_id,
        manifest_hash=parent_manifest.sha256,
        integrity_valid=True,
        schema_compatible=True,
        authority_refs_valid=True,
        known_good=True,
    )
    values.update(overrides)
    return RollbackSnapshot(**values)


def mk_gate(root, *, with_recovery=True, replace_fn=os.replace):
    legacy = LegacyAdapter(
        policy_version="core-v1+p2+p3+p4",
        actor="p9-legacy",
        clock=lambda: NOW,
        id_factory=ids_factory(),
    )
    orchestrator = StageOrchestrator(
        policy_version="core-v1+p2+p3",
        actor="p9-orchestrator",
        clock=lambda: NOW,
        receipt_id_factory=lambda: "orch-receipt",
    )
    authority = AuthorityLayer(
        policy_version=AUTH_POLICY,
        actor="p9-authority",
        clock=lambda: NOW,
        id_factory=ids_factory(),
    )
    preflight = PromotionPreflight(
        policy_version="core-v1+p2+p3+p4+p5+p6",
        accepted_authority_policy_version=AUTH_POLICY,
        required_schema_version=SCHEMA,
        required_stages=("SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"),
        actor="p9-preflight",
        clock=lambda: NOW,
        id_factory=ids_factory(),
    )
    store = GenerationStore(
        root,
        policy_version=PERSIST_POLICY,
        actor="p9-store",
        clock=lambda: NOW,
        id_factory=ids_factory(),
        replace_fn=replace_fn,
    )
    recovery = None
    if with_recovery:
        audit = AuditLedger(
            root,
            policy_version=RECOVERY_POLICY,
            actor="p9-audit",
            clock=lambda: NOW,
            id_factory=ids_factory(),
        )
        recovery = RecoveryManager(
            store,
            audit=audit,
            policy_version=RECOVERY_POLICY,
            actor="p9-recovery",
            clock=lambda: NOW,
            id_factory=ids_factory(),
        )
    return EndToEndGate(
        legacy=legacy,
        orchestrator=orchestrator,
        authority=authority,
        preflight=preflight,
        store=store,
        recovery=recovery,
    ), store


def run_args(parent_manifest, **overrides):
    values = dict(
        case=mk_case(),
        stage=mk_stage(),
        legacy_input=b"question\n",
        legacy_output=b"same result\n",
        galia2_output=b"same result\n",
        claim_id=CLAIM_ID,
        subject="Taft",
        predicate="HAS_STATE",
        object="validated",
        human_decision=mk_decision(),
        scope=mk_scope(),
        manifest=mk_manifest(),
        payloads=payloads(),
        rollback=mk_rollback(parent_manifest),
    )
    values.update(overrides)
    return values


class P9EndToEndTests(unittest.TestCase):
    def test_01_happy_path_publishes_only_after_all_gates(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent))
            self.assertEqual(result.status, EndToEndStatus.PUBLISHED)
            self.assertEqual(result.stage.state, StageState.CANONICAL)
            self.assertEqual(store.read_head().commit_id, TARGET)
            self.assertIsNotNone(result.preflight)
            self.assertTrue(result.preflight.passed)

    def test_02_missing_human_decision_stops_at_authority_hold(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, human_decision=None))
            self.assertEqual(result.status, EndToEndStatus.HUMAN_AUTHORITY_REQUIRED)
            self.assertEqual(result.stage.state, StageState.AUTHORITY_HOLD)
            self.assertEqual(store.read_head().commit_id, PARENT)
            self.assertEqual(list(store.staging.iterdir()), [])

    def test_03_material_legacy_diff_blocks_preflight_and_publish(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, galia2_output=b"different result\n"))
            self.assertEqual(result.status, EndToEndStatus.PREFLIGHT_BLOCKED)
            self.assertTrue(result.comparison.material)
            self.assertEqual(result.comparison.kind, LegacyDiffKind.MATERIAL_DIFFERENCE)
            self.assertIn("no_blocking_discrepancy", {c.name for c in result.preflight.failed_checks})
            self.assertEqual(store.read_head().commit_id, PARENT)
            self.assertEqual(list(store.staging.iterdir()), [])

    def test_04_representation_equivalent_legacy_output_is_not_material(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, legacy_output="same result\r\n", galia2_output="same result\n"))
            self.assertEqual(result.status, EndToEndStatus.PUBLISHED)
            self.assertEqual(result.comparison.kind, LegacyDiffKind.REPRESENTATION_EQUIVALENT)
            self.assertFalse(result.comparison.material)

    def test_05_non_select_human_decision_cannot_clear_hold(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            with self.assertRaises(ValueError):
                gate.run(**run_args(parent, human_decision=mk_decision(decision="HOLD")))
            self.assertEqual(store.read_head().commit_id, PARENT)

    def test_06_scope_mismatch_is_rejected_before_pipeline_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            bad_scope = mk_scope(case_id="other-case")
            with self.assertRaises(ValueError):
                gate.run(**run_args(parent, scope=bad_scope, human_decision=mk_decision(scope=bad_scope)))
            self.assertEqual(store.read_head().commit_id, PARENT)
            self.assertEqual(list(store.staging.iterdir()), [])

    def test_07_unverified_rollback_target_blocks_preflight(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, rollback=mk_rollback(parent, known_good=False)))
            self.assertEqual(result.status, EndToEndStatus.PREFLIGHT_BLOCKED)
            self.assertIn("rollback_known_good", {c.name for c in result.preflight.failed_checks})
            self.assertEqual(store.read_head().commit_id, PARENT)

    def test_08_candidate_manifest_decision_must_match_human_authority(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, manifest=mk_manifest(decision_id="different-decision")))
            self.assertEqual(result.status, EndToEndStatus.PREFLIGHT_BLOCKED)
            self.assertIn("authorization_matches_target", {c.name for c in result.preflight.failed_checks})
            self.assertEqual(store.read_head().commit_id, PARENT)

    def test_09_only_persistence_publish_receipt_has_output_commit(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent))
            with_commit = [r for r in result.receipts if r.output_commit is not None]
            self.assertEqual(len(with_commit), 1)
            self.assertEqual(with_commit[0].operation, "PERSIST_PUBLISH_GENERATION")
            self.assertEqual(with_commit[0].output_commit, TARGET)

    def test_10_stage_is_not_written_when_preflight_fails(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            result = gate.run(**run_args(parent, galia2_output=b"material mismatch"))
            self.assertEqual(result.status, EndToEndStatus.PREFLIGHT_BLOCKED)
            self.assertIsNone(result.staged)
            self.assertFalse((Path(td) / "staging" / TARGET).exists())
            self.assertFalse((Path(td) / "generations" / TARGET).exists())

    def test_11_recovery_intake_is_observational_and_does_not_move_head(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            gate.run(**run_args(parent))
            before = store.head_path.read_bytes()
            intake = gate.open_recovery(RecoveryTrigger.OTHER, affected_commit=TARGET)
            after = store.head_path.read_bytes()
            self.assertFalse(intake.mutation_performed)
            self.assertEqual(before, after)
            self.assertEqual(store.read_head().commit_id, TARGET)

    def test_12_recovery_requires_exact_authorization_binding(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            gate.run(**run_args(parent))
            intake = gate.open_recovery(RecoveryTrigger.OTHER, affected_commit=TARGET)
            bad = RecoveryAuthorization(
                authorization_id="recovery-auth-bad",
                recovery_id="wrong-recovery-id",
                reviewer="human-reviewer",
                target_commit=PARENT,
                expected_head_exists=intake.observed_head_exists,
                expected_head_hash=intake.observed_head_hash,
                policy_version=RECOVERY_POLICY,
                authorized_at=NOW,
            )
            with self.assertRaises(RecoveryValidationError):
                gate.rollback(intake=intake, authorization=bad)
            self.assertEqual(store.read_head().commit_id, TARGET)

    def test_13_authorized_recovery_rolls_back_to_verified_parent_without_new_authority(self):
        with tempfile.TemporaryDirectory() as td:
            gate, store = mk_gate(td); parent = seed_parent(store)
            gate.run(**run_args(parent))
            intake = gate.open_recovery(RecoveryTrigger.OTHER, affected_commit=TARGET)
            auth = RecoveryAuthorization(
                authorization_id="recovery-auth-good",
                recovery_id=intake.recovery_id,
                reviewer="human-reviewer",
                target_commit=PARENT,
                expected_head_exists=intake.observed_head_exists,
                expected_head_hash=intake.observed_head_hash,
                policy_version=RECOVERY_POLICY,
                authorized_at=NOW,
            )
            receipt = gate.rollback(intake=intake, authorization=auth)
            self.assertEqual(store.read_head().commit_id, PARENT)
            self.assertFalse(receipt.creates_authority)
            self.assertEqual(receipt.target_commit, PARENT)

    def test_14_atomic_head_publish_failure_preserves_previous_head(self):
        with tempfile.TemporaryDirectory() as td:
            def fail_head(src, dst):
                if Path(dst).name == "HEAD":
                    raise OSError("simulated HEAD swap failure")
                return os.replace(src, dst)
            gate, store = mk_gate(td, with_recovery=False, replace_fn=fail_head)
            parent = seed_parent(store)
            with self.assertRaises(PersistencePublishError):
                gate.run(**run_args(parent))
            self.assertEqual(store.read_head().commit_id, PARENT)
            self.assertTrue((Path(td) / "generations" / TARGET).is_dir())


if __name__ == "__main__":
    unittest.main()
