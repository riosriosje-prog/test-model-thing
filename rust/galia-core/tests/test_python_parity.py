"""Rust -> Python GALIA P2 conformance. Run after cargo build --bin galia-shadow."""
import json
from pathlib import Path
import subprocess
import unittest

from galia2.core import Stage, StageState
from galia2.state_machine import TransitionEvent, evaluate_transition, TransitionError


ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "rust" / "galia-core" / "target" / "debug" / "galia-shadow"

CASES = [
    ("DISCOVERED", "INGEST_CONFIRMED", ["source_artifact_valid"]),
    ("INGESTED", "NORMALIZATION_COMPLETE", ["lineage_complete"]),
    ("NORMALIZED", "DERIVATION_COMPLETE", ["output_hash_valid"]),
    ("DERIVED", "VALIDATION_PASSED", ["required_validations_passed"]),
    ("VALIDATED", "PLACE_AUTHORITY_HOLD", ["evidence_snapshot_present"]),
    ("AUTHORITY_HOLD", "HUMAN_SELECTION_RECORDED", ["human_decision_present"]),
    ("HUMAN_SELECTED", "PREFLIGHT_PASSED", ["preflight_passed", "rollback_target_verified"]),
    ("PROMOTION_READY", "PROMOTION_AUTHORIZED", ["promotion_authorization_present", "authorization_matches_target"]),
    ("CANONICAL", "NEW_MATERIAL_EVIDENCE", ["new_material_evidence"]),
    ("NORMALIZED", "INTEGRITY_FAILURE", ["integrity_failure_confirmed"]),
    ("CANONICAL", "MATERIAL_CONFLICT", ["material_conflict_confirmed"]),
    ("PROMOTION_READY", "PERSISTENCE_FAILURE", ["persistence_failure_confirmed"]),
    ("DERIVED", "VALIDATION_PASSED", []),
    ("DERIVED", "PROMOTION_AUTHORIZED", ["promotion_authorization_present", "authorization_matches_target"]),
    ("AUTHORITY_HOLD", "HUMAN_SELECTION_RECORDED", []),
    ("PROMOTION_READY", "PROMOTION_AUTHORIZED", ["promotion_authorization_present"]),
    ("CANONICAL", "NEW_MATERIAL_EVIDENCE", []),
    ("QUARANTINED", "PERSISTENCE_FAILURE", ["persistence_failure_confirmed"]),
]


class RustPythonParityTests(unittest.TestCase):
    def test_transition_vectors(self):
        self.assertTrue(BINARY.exists(), "build galia-shadow before running parity tests")
        for state, event, guards in CASES:
            with self.subTest(state=state, event=event, guards=guards):
                py_stage = Stage("s1", "c1", "CORE", StageState(state))
                try:
                    py = evaluate_transition(py_stage, TransitionEvent(event), satisfied_guards=set(guards))
                except TransitionError:
                    py = None

                payload = {
                    "stage": {"stage_id": "s1", "case_id": "c1", "stage_type": "CORE", "state": state},
                    "event": event,
                    "satisfied_guards": guards,
                }
                run = subprocess.run(
                    [str(BINARY)], input=json.dumps(payload), text=True, capture_output=True,
                    check=False, timeout=5,
                )
                rust = json.loads(run.stdout)
                if py is None:
                    self.assertEqual(run.returncode, 2, rust)
                    self.assertEqual(rust["status"], "REJECTED")
                else:
                    self.assertEqual(run.returncode, 0, rust)
                    self.assertEqual(rust["status"], "ADVISORY_ONLY")
                    self.assertEqual(rust["decision"]["to_state"], py.to_state.value)
                    self.assertEqual(rust["decision"]["from_state"], py.from_state.value)
                    self.assertEqual(rust["decision"]["human_boundary"], py.human_boundary)
                    self.assertEqual(set(rust["decision"]["required_guards"]), py.required_guards)
                    self.assertFalse(rust["canonical_writeback"])
                    self.assertFalse(rust["authority_transfer"])
                    self.assertIsNone(rust["output_commit"])


if __name__ == "__main__":
    unittest.main()
