import inspect
import os
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.authority import AuthorityScope, PromotionAuthorization
from galia2.core import Receipt, StageState
from galia2.persistence import (
    GenerationManifest,
    GenerationStore,
    HeadPointer,
    ImmutableGenerationError,
    PayloadEntry,
    PersistencePublishError,
    PersistenceValidationError,
)
from galia2.preflight import CandidateSnapshot, PreflightCheck, PreflightReport
from galia2.state_machine import TransitionDecision, TransitionEvent

NOW = datetime(2026, 9, 24, 5, 0, tzinfo=timezone.utc)
POLICY = "core-v1+p2+p3+p4+p5+p6+p7"
AUTH_POLICY = "core-v1+p2+p3+p4+p5"


def sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def ids_factory():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return ids


def payloads():
    return {"claims.json": b'{"claim":"x"}\n', "evidence/source.txt": b"source bytes\n"}


def entries(data=None):
    data = payloads() if data is None else data
    return tuple(PayloadEntry(path=k, sha256=sha(v), byte_size=len(v)) for k, v in sorted(data.items()))


def manifest(*, commit="candidate-17", parent="canonical-16", seq=17, data=None):
    return GenerationManifest(
        commit_id=commit,
        seq=seq,
        parent_commit=parent,
        case_id="case-1",
        schema_version="galia2-core-v1",
        created_at=NOW,
        payloads=entries(data),
        authority_decision_id="decision-1",
        persistence_policy_version=POLICY,
    )


def authority_scope():
    return AuthorityScope("case-1", "CLAIM", ("claim-1",))


def authorization(*, target="candidate-17", auth_id="auth-1"):
    return PromotionAuthorization(
        authorization_id=auth_id,
        decision_id="decision-1",
        reviewer="human",
        scope=authority_scope(),
        target_commit=target,
        evidence_snapshot=("evidence-1",),
        policy_version=AUTH_POLICY,
        authorized_at=NOW,
    )


def preflight_report(*, target="candidate-17", passed=True, receipt_id="preflight-1"):
    guards = frozenset({"preflight_passed", "rollback_target_verified"}) if passed else frozenset()
    return PreflightReport(
        case_id="case-1",
        target_commit=target,
        passed=passed,
        checks=(PreflightCheck("all", passed, "fixture"),),
        guards=guards,
        receipt=Receipt(
            receipt_id=receipt_id,
            operation="PROMOTION_PREFLIGHT",
            input_commit=target,
            input_hashes=(),
            output_commit=None,
            output_hashes=(),
            policy_version="p6",
            actor="test",
            timestamp=NOW,
            result="PASS" if passed else "FAIL",
        ),
    )


def candidate(m):
    return CandidateSnapshot(
        case_id=m.case_id,
        target_commit=m.commit_id,
        parent_commit=m.parent_commit,
        manifest_hash=m.sha256,
        payload_hashes=tuple(p.sha256 for p in m.payloads),
        lineage_complete=True,
        schema_version=m.schema_version,
        completed_stages=("SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"),
        blocking_discrepancy_ids=(),
        authority_decision_id=m.authority_decision_id,
    )


def promotion_decision(*, case_id="case-1", include_guards=True):
    guards = frozenset({"promotion_authorization_present", "authorization_matches_target"}) if include_guards else frozenset()
    return TransitionDecision(
        stage_id="promotion-stage",
        case_id=case_id,
        from_state=StageState.PROMOTION_READY,
        event=TransitionEvent.PROMOTION_AUTHORIZED,
        to_state=StageState.CANONICAL,
        satisfied_guards=guards,
        required_guards=frozenset({"promotion_authorization_present", "authorization_matches_target"}),
        human_boundary=True,
    )


def store(root, **kwargs):
    values = dict(policy_version=POLICY, actor="p7-test", clock=lambda: NOW, id_factory=ids_factory())
    values.update(kwargs)
    return GenerationStore(root, **values)


def seed_parent(s: GenerationStore):
    data = {"base.txt": b"known good\n"}
    m = GenerationManifest(
        commit_id="canonical-16",
        seq=16,
        parent_commit="canonical-15",
        case_id="case-1",
        schema_version="galia2-core-v1",
        created_at=NOW,
        payloads=entries(data),
        authority_decision_id="old-decision",
        persistence_policy_version=POLICY,
    )
    gen = s.generations / m.commit_id
    (gen / "payload").mkdir(parents=True)
    for e in m.payloads:
        p = gen / "payload" / e.path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data[e.path])
    (gen / "manifest.json").write_bytes(m.to_bytes())
    from galia2.persistence import PromotionEnvelope
    promotion = PromotionEnvelope(
        commit_id=m.commit_id, case_id=m.case_id, manifest_hash=m.sha256,
        authority_decision_id=m.authority_decision_id, authorization_id="old-auth",
        authorization_policy_version=AUTH_POLICY, preflight_receipt_id="old-preflight",
        persistence_policy_version=POLICY, published_at=NOW,
    )
    (gen / "promotion.json").write_bytes(promotion.to_bytes())
    s.head_path.write_bytes(HeadPointer(m.commit_id, m.seq, m.sha256, promotion.sha256).to_bytes())
    return m


class P7PersistenceTests(unittest.TestCase):
    def test_manifest_hash_is_deterministic(self):
        a = manifest()
        b = manifest()
        self.assertEqual(a.to_bytes(), b.to_bytes())
        self.assertEqual(a.sha256, b.sha256)

    def test_payload_path_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            PayloadEntry("../escape", sha(b"x"), 1)
        with self.assertRaises(ValueError):
            PayloadEntry("/absolute", sha(b"x"), 1)

    def test_stage_writes_generation_without_head(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td)
            m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            self.assertEqual(st.manifest_hash, m.sha256)
            self.assertIsNone(s.read_head())
            self.assertTrue((Path(td) / "staging" / m.commit_id / "manifest.json").is_file())
            self.assertIsNone(st.receipt.output_commit)

    def test_stage_rejects_payload_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td)
            with self.assertRaises(PersistenceValidationError):
                s.stage_generation(manifest=manifest(), payloads={**payloads(), "claims.json": b"tampered"})

    def test_stage_is_immutable_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td)
            m = manifest()
            s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(ImmutableGenerationError):
                s.stage_generation(manifest=m, payloads=payloads())

    def test_publish_advances_head_only_with_exact_external_authority(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td)
            seed_parent(s)
            m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            out = s.publish_generation(
                staged=st,
                candidate=candidate(m),
                preflight=preflight_report(),
                authorization=authorization(),
                expected_scope=authority_scope(),
                promotion_decision=promotion_decision(),
            )
            self.assertEqual(s.read_head(), out.head)
            self.assertEqual(out.head.commit_id, "candidate-17")
            self.assertEqual(out.receipt.output_commit, "candidate-17")
            self.assertFalse((Path(td) / "staging" / "candidate-17").exists())
            self.assertTrue((Path(td) / "generations" / "candidate-17").exists())

    def test_publish_does_not_apply_or_mutate_stage(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td)
            seed_parent(s)
            m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            decision = promotion_decision()
            s.publish_generation(
                staged=st, candidate=candidate(m), preflight=preflight_report(),
                authorization=authorization(), expected_scope=authority_scope(),
                promotion_decision=decision,
            )
            self.assertEqual(decision.from_state, StageState.PROMOTION_READY)
            self.assertEqual(decision.to_state, StageState.CANONICAL)

    def test_failed_preflight_cannot_publish(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(passed=False),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )
            self.assertEqual(s.read_head().commit_id, "canonical-16")

    def test_missing_final_authority_guards_cannot_publish(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(include_guards=False),
                )

    def test_wrong_authorization_target_cannot_publish(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest()
            st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(target="other"), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )

    def test_preflight_receipt_is_bound_in_separate_promotion_envelope(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest()
            original_manifest = m.to_bytes()
            st = s.stage_generation(manifest=m, payloads=payloads())
            out = s.publish_generation(
                staged=st, candidate=candidate(m), preflight=preflight_report(receipt_id="preflight-special"),
                authorization=authorization(), expected_scope=authority_scope(),
                promotion_decision=promotion_decision(),
            )
            self.assertEqual(out.promotion.preflight_receipt_id, "preflight-special")
            self.assertEqual((s.generations / m.commit_id / "manifest.json").read_bytes(), original_manifest)

    def test_head_parent_mismatch_cannot_publish(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest(parent="canonical-15")
            st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )

    def test_sequence_must_be_head_plus_one(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s); m = manifest(seq=18)
            st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )

    def test_parent_generation_is_verified_before_publish(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s)
            (s.generations / "canonical-16" / "payload" / "base.txt").write_bytes(b"tampered")
            m = manifest(); st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistenceValidationError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )
            self.assertEqual(s.read_head().commit_id, "canonical-16")

    def test_generation_verification_detects_payload_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s)
            head = s.read_head()
            self.assertIsNotNone(head)
            s.verify_generation("canonical-16", expected_manifest_hash=head.manifest_hash)
            (s.generations / "canonical-16" / "payload" / "base.txt").write_bytes(b"tampered")
            with self.assertRaises(PersistenceValidationError):
                s.verify_generation("canonical-16", expected_manifest_hash=head.manifest_hash)

    def test_generation_verification_rejects_undeclared_file(self):
        with tempfile.TemporaryDirectory() as td:
            s = store(td); seed_parent(s)
            (s.generations / "canonical-16" / "extra.txt").write_text("extra", encoding="utf-8")
            with self.assertRaises(PersistenceValidationError):
                s.verify_generation("canonical-16")

    def test_head_swap_failure_preserves_old_head_and_retains_generation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real_replace = os.replace
            def fail_head(src, dst):
                if Path(dst).name == "HEAD":
                    raise OSError("simulated HEAD failure")
                real_replace(src, dst)
            s = store(td, replace_fn=fail_head)
            # seed without injected replace
            seed_parent(s)
            m = manifest(); st = s.stage_generation(manifest=m, payloads=payloads())
            with self.assertRaises(PersistencePublishError):
                s.publish_generation(
                    staged=st, candidate=candidate(m), preflight=preflight_report(),
                    authorization=authorization(), expected_scope=authority_scope(),
                    promotion_decision=promotion_decision(),
                )
            self.assertEqual(s.read_head().commit_id, "canonical-16")
            self.assertTrue((root / "generations" / "candidate-17").is_dir())

    def test_manifest_policy_must_match_store(self):
        with tempfile.TemporaryDirectory() as td:
            s = GenerationStore(td, policy_version="other", actor="x")
            with self.assertRaises(PersistenceValidationError):
                s.stage_generation(manifest=manifest(), payloads=payloads())

    def test_public_api_does_not_expose_unsafe_head_setter(self):
        public = {
            name for name, _ in inspect.getmembers(GenerationStore, inspect.isfunction)
            if not name.startswith("_")
        }
        self.assertEqual(public, {"stage_generation", "publish_generation", "read_head", "verify_generation"})

    def test_persistence_module_does_not_import_legacy_main_or_mlx(self):
        source = Path(inspect.getsourcefile(GenerationStore)).read_text(encoding="utf-8")
        self.assertNotIn("import main", source)
        self.assertNotIn("from main", source)
        self.assertNotIn("import mlx", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
