import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone

from galia2.persistence import GenerationManifest, GenerationStore, HeadPointer, PayloadEntry, PersistencePublishError, PromotionEnvelope
from galia2.recovery_audit import (
    AuditEventType,
    AuditLedger,
    AuditValidationError,
    FailedAttemptRecord,
    RecoveryAuthorization,
    RecoveryManager,
    RecoveryTrigger,
    RecoveryValidationError,
)

NOW = datetime(2026, 9, 24, 7, 0, tzinfo=timezone.utc)
POLICY = "core-v1+p2+p3+p4+p5+p6+p7+p8"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ids_factory():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return ids


def manifest(commit, parent, seq, data):
    return GenerationManifest(
        commit_id=commit,
        seq=seq,
        parent_commit=parent,
        case_id="case-1",
        schema_version="galia2-core-v1",
        created_at=NOW,
        payloads=tuple(PayloadEntry(k, sha(v), len(v)) for k, v in sorted(data.items())),
        authority_decision_id=f"decision-{seq}",
        persistence_policy_version=POLICY,
    )


def write_generation(store, m, data):
    path = store.generations / m.commit_id
    (path / "payload").mkdir(parents=True)
    for entry in m.payloads:
        dst = path / "payload" / entry.path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data[entry.path])
    (path / "manifest.json").write_bytes(m.to_bytes())
    promotion = PromotionEnvelope(
        commit_id=m.commit_id,
        case_id=m.case_id,
        manifest_hash=m.sha256,
        authority_decision_id=m.authority_decision_id,
        authorization_id=f"auth-{m.seq}",
        authorization_policy_version="authority-v1",
        preflight_receipt_id=f"preflight-{m.seq}",
        persistence_policy_version=POLICY,
        published_at=NOW,
    )
    (path / "promotion.json").write_bytes(promotion.to_bytes())
    return m, promotion


def seed_chain(store):
    d1 = {"a.txt": b"one\n"}
    d2 = {"b.txt": b"two\n"}
    d3 = {"c.txt": b"three\n"}
    m1, p1 = write_generation(store, manifest("c1", "prehistory", 1, d1), d1)
    m2, p2 = write_generation(store, manifest("c2", "c1", 2, d2), d2)
    m3, p3 = write_generation(store, manifest("c3", "c2", 3, d3), d3)
    store.head_path.write_bytes(HeadPointer("c3", 3, m3.sha256, p3.sha256).to_bytes())
    return m1, m2, m3


def build(td, replace_fn=None):
    kwargs = dict(policy_version=POLICY, actor="p8-test", clock=lambda: NOW, id_factory=ids_factory())
    if replace_fn is not None:
        kwargs["replace_fn"] = replace_fn
    store = GenerationStore(td, **kwargs)
    audit = AuditLedger(td, policy_version=POLICY, actor="p8-test", clock=lambda: NOW, id_factory=ids_factory())
    mgr = RecoveryManager(store, audit=audit, policy_version=POLICY, actor="p8-test", clock=lambda: NOW, id_factory=ids_factory())
    return store, audit, mgr


def auth(intake, target):
    return RecoveryAuthorization(
        authorization_id="ra-1",
        recovery_id=intake.recovery_id,
        reviewer="human",
        target_commit=target,
        expected_head_exists=intake.observed_head_exists,
        expected_head_hash=intake.observed_head_hash,
        policy_version=POLICY,
        authorized_at=NOW,
    )


class P8RecoveryAuditTests(unittest.TestCase):
    def test_audit_is_hash_chained_and_verifiable(self):
        with tempfile.TemporaryDirectory() as td:
            _, audit, _ = build(td)
            a = audit.append(AuditEventType.RECOVERY_INTAKE, affected_refs=("c3",), details="one")
            b = audit.append(AuditEventType.ROLLBACK_ATTEMPTED, affected_refs=("c2",), details="two")
            events = audit.read_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].event_hash, a.event_hash)
            self.assertEqual(events[1].previous_event_hash, a.event_hash)
            self.assertEqual(events[1].event_hash, b.event_hash)

    def test_audit_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            _, audit, _ = build(td)
            audit.append(AuditEventType.RECOVERY_INTAKE, details="original")
            raw = audit.path.read_text()
            audit.path.write_text(raw.replace("original", "tampered"))
            with self.assertRaises(AuditValidationError):
                audit.read_events()

    def test_failed_attempt_is_retained_immutably(self):
        with tempfile.TemporaryDirectory() as td:
            _, audit, mgr = build(td)
            rec = FailedAttemptRecord("att-1", "case-1", "stage-2", "INTEGRITY", "hash mismatch", ("in:a",), ("out:b",), NOW)
            receipt = mgr.retain_failed_attempt(rec)
            path = Path(td) / "forensics" / "attempts" / "att-1.json"
            self.assertTrue(path.is_file())
            self.assertIsNone(receipt.output_commit)
            self.assertEqual(len(receipt.output_hashes), 1)
            self.assertEqual(audit.read_events()[-1].event_type, AuditEventType.FAILED_ATTEMPT_RETAINED)
            with self.assertRaises(RecoveryValidationError):
                mgr.retain_failed_attempt(rec)

    def test_recovery_intake_is_observational_only(self):
        with tempfile.TemporaryDirectory() as td:
            store, audit, mgr = build(td)
            seed_chain(store)
            before = store.head_path.read_bytes()
            intake = mgr.open_intake(RecoveryTrigger.EXECUTION_INTERRUPTION, affected_commit="c3")
            self.assertFalse(intake.mutation_performed)
            self.assertEqual(store.head_path.read_bytes(), before)
            self.assertEqual(intake.observed_head.commit_id, "c3")
            self.assertEqual(audit.read_events()[-1].event_type, AuditEventType.RECOVERY_INTAKE)

    def test_corrupt_head_is_captured_not_repaired(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            store.head_path.write_bytes(b"not-json\n")
            before = store.head_path.read_bytes()
            intake = mgr.open_intake(RecoveryTrigger.HEAD_CORRUPTION)
            self.assertIsNone(intake.observed_head)
            self.assertIsNotNone(intake.head_error)
            self.assertEqual(store.head_path.read_bytes(), before)

    def test_authorized_rollback_to_verified_ancestor(self):
        with tempfile.TemporaryDirectory() as td:
            store, audit, mgr = build(td)
            _, m2, m3 = seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.PARTIAL_COMMIT, affected_commit="c3")
            receipt = mgr.rollback(intake=intake, authorization=auth(intake, "c2"))
            head = store.read_head()
            self.assertEqual(head.commit_id, "c2")
            self.assertEqual(head.manifest_hash, m2.sha256)
            self.assertFalse(receipt.creates_authority)
            self.assertTrue((store.generations / m3.commit_id).is_dir())
            self.assertEqual(audit.read_events()[-1].event_type, AuditEventType.ROLLBACK_SUCCEEDED)

    def test_rollback_cannot_target_current_or_future_seq(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.OTHER)
            with self.assertRaises(RecoveryValidationError):
                mgr.rollback(intake=intake, authorization=auth(intake, "c3"))

    def test_verified_orphan_is_not_a_valid_rollback_target(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            orphan_data = {"o.txt": b"orphan\n"}
            orphan = manifest("orphan-4", "c3", 4, orphan_data)
            write_generation(store, orphan, orphan_data)
            intake = mgr.open_intake(RecoveryTrigger.PARTIAL_COMMIT)
            with self.assertRaises(RecoveryValidationError):
                mgr.rollback(intake=intake, authorization=auth(intake, "orphan-4"))
            self.assertEqual(store.read_head().commit_id, "c3")

    def test_rollback_rejects_non_ancestor_even_if_verified(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            data = {"x.txt": b"branch\n"}
            other = manifest("branch-2", "branch-1", 2, data)
            write_generation(store, other, data)
            intake = mgr.open_intake(RecoveryTrigger.LINEAGE_BREAK)
            with self.assertRaises(RecoveryValidationError):
                mgr.rollback(intake=intake, authorization=auth(intake, "branch-2"))

    def test_authorization_must_bind_exact_recovery_case(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.OTHER)
            bad = RecoveryAuthorization("ra-1", "wrong-recovery", "human", "c2", True, intake.observed_head_hash, POLICY, NOW)
            with self.assertRaises(RecoveryValidationError):
                mgr.rollback(intake=intake, authorization=bad)

    def test_authorization_must_bind_exact_head_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            _, m2, _ = seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.OTHER)
            authorization = auth(intake, "c2")
            p2_hash = sha((store.generations / "c2" / "promotion.json").read_bytes())
            store.head_path.write_bytes(HeadPointer("c2", 2, m2.sha256, p2_hash).to_bytes())
            with self.assertRaises(RecoveryValidationError):
                mgr.rollback(intake=intake, authorization=authorization)

    def test_corrupt_head_can_only_be_rolled_back_to_explicit_verified_target(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            _, m2, _ = seed_chain(store)
            store.head_path.write_bytes(b"corrupt-head\n")
            intake = mgr.open_intake(RecoveryTrigger.HEAD_CORRUPTION)
            receipt = mgr.rollback(intake=intake, authorization=auth(intake, "c2"))
            self.assertEqual(store.read_head().commit_id, "c2")
            self.assertEqual(receipt.target_manifest_hash, m2.sha256)

    def test_missing_head_can_only_be_restored_to_explicit_verified_target(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            _, m2, _ = seed_chain(store)
            store.head_path.unlink()
            intake = mgr.open_intake(RecoveryTrigger.HEAD_CORRUPTION)
            authorization = RecoveryAuthorization("ra-1", intake.recovery_id, "human", "c2", False, None, POLICY, NOW)
            mgr.rollback(intake=intake, authorization=authorization)
            self.assertEqual(store.read_head().commit_id, "c2")

    def test_failed_atomic_rollback_retains_old_head_and_audits_failure(self):
        def failing_replace(src, dst):
            if Path(dst).name == "HEAD":
                raise OSError("simulated head failure")
            return __import__("os").replace(src, dst)
        with tempfile.TemporaryDirectory() as td:
            store, audit, mgr = build(td, replace_fn=failing_replace)
            _, _, m3 = seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.OTHER)
            with self.assertRaises(PersistencePublishError):
                mgr.rollback(intake=intake, authorization=auth(intake, "c2"))
            # Old canonical pointer remains byte-identical.
            self.assertEqual(store.read_head().commit_id, "c3")
            self.assertEqual(store.read_head().manifest_hash, m3.sha256)
            self.assertEqual(audit.read_events()[-1].event_type, AuditEventType.ROLLBACK_FAILED)

    def test_recovery_receipt_is_immutable_and_non_authoritative(self):
        with tempfile.TemporaryDirectory() as td:
            store, _, mgr = build(td)
            seed_chain(store)
            intake = mgr.open_intake(RecoveryTrigger.OTHER)
            receipt = mgr.rollback(intake=intake, authorization=auth(intake, "c2"))
            path = Path(td) / "forensics" / "recovery_receipts" / f"{receipt.receipt_id}.json"
            doc = json.loads(path.read_text())
            self.assertFalse(doc["creates_authority"])
            self.assertEqual(doc["target_commit"], "c2")

    def test_p8_has_no_legacy_or_process_dependency(self):
        import galia2.recovery_audit as module
        source = inspect.getsource(module)
        self.assertNotIn("import main", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("mlx", source)

    def test_recovery_manager_exposes_no_auto_target_selection_api(self):
        methods = {name for name, obj in inspect.getmembers(RecoveryManager, inspect.isfunction) if not name.startswith("_")}
        self.assertNotIn("find_last_known_good", methods)
        self.assertNotIn("auto_recover", methods)
        self.assertEqual(methods, {"open_intake", "retain_failed_attempt", "rollback"})

    def test_audit_ledger_exposes_no_delete_or_update_api(self):
        methods = {name for name, obj in inspect.getmembers(AuditLedger, inspect.isfunction) if not name.startswith("_")}
        self.assertEqual(methods, {"append", "read_events"})


if __name__ == "__main__":
    unittest.main()
