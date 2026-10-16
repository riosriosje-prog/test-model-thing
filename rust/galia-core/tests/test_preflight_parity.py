"""Python GALIA P6 and Rust read-only P6 structural parity (no human authority)."""
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import unittest

from galia2.authority import AuthorityScope, PromotionAuthorization
from galia2.preflight import CandidateSnapshot, PromotionPreflight, RollbackSnapshot

ROOT = Path(__file__).resolve().parents[3]
BINARY = ROOT / "rust" / "galia-core" / "target" / "debug" / "galia-preflight-shadow"
NOW = datetime(2026, 9, 24, 4, 0, tzinfo=timezone.utc)

def baseline():
    return {
        "config": {
            "policy_version": "core-p6",
            "accepted_authority_policy_version": "core-p5",
            "required_schema_version": "galia2-core-v1",
            "required_stages": ["SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"],
            "actor": "shadow-test",
        },
        "candidate": {
            "case_id": "case-1", "target_commit": "candidate-17", "parent_commit": "canonical-16",
            "manifest_hash": "1" * 64, "payload_hashes": ["2" * 64], "lineage_complete": True,
            "schema_version": "galia2-core-v1",
            "completed_stages": ["SCHEMA", "LINEAGE", "DISCREPANCY", "AUTHORITY"],
            "blocking_discrepancy_ids": [], "authority_decision_id": "decision-1",
        },
        "rollback": {
            "commit_id": "canonical-16", "manifest_hash": "3" * 64,
            "integrity_valid": True, "schema_compatible": True,
            "authority_refs_valid": True, "known_good": True,
        },
        "expected_scope": {"case_id": "case-1", "target_type": "CLAIM", "target_ids": ["claim-1"]},
        "authorization": {
            "authorization_id": "auth-1", "decision_id": "decision-1", "reviewer": "human-reviewer",
            "scope": {"case_id": "case-1", "target_type": "CLAIM", "target_ids": ["claim-1"]},
            "target_commit": "candidate-17", "evidence_snapshot": ["evidence-1"],
            "policy_version": "core-p5", "authorized_at": "2026-09-24T04:00:00Z",
        },
    }

def reference(p):
    c = p["config"]
    py = PromotionPreflight(**c, clock=lambda: NOW, id_factory=lambda _: "receipt-1")
    auth = p["authorization"]
    if auth is not None:
        auth = PromotionAuthorization(
            authorization_id=auth["authorization_id"],
            decision_id=auth["decision_id"],
            reviewer=auth["reviewer"],
            scope=AuthorityScope(**{**auth["scope"], "target_ids": tuple(auth["scope"]["target_ids"])}),
            target_commit=auth["target_commit"],
            evidence_snapshot=tuple(auth["evidence_snapshot"]),
            policy_version=auth["policy_version"],
            authorized_at=NOW,
        )
    cand = CandidateSnapshot(**{**p["candidate"],
        "payload_hashes": tuple(p["candidate"]["payload_hashes"]),
        "completed_stages": tuple(p["candidate"]["completed_stages"]),
        "blocking_discrepancy_ids": tuple(p["candidate"]["blocking_discrepancy_ids"])})
    return py.evaluate(
        candidate=cand, rollback=RollbackSnapshot(**p["rollback"]), authorization=auth,
        expected_scope=AuthorityScope(**{**p["expected_scope"],
            "target_ids": tuple(p["expected_scope"]["target_ids"])}),
    )

class PreflightParity(unittest.TestCase):
    def test_scenarios_against_python_p6(self):
        self.assertTrue(BINARY.exists(), "build galia-preflight-shadow first")
        modifiers = {
            "matching": lambda p: None,
            "missing_auth": lambda p: p.update(authorization=None),
            "target_mismatch": lambda p: p["authorization"].update(target_commit="candidate-18"),
            "decision_mismatch": lambda p: p["authorization"].update(decision_id="decision-2"),
            "authority_policy": lambda p: p["authorization"].update(policy_version="invalid-policy"),
            "wrong_scope": lambda p: p["authorization"]["scope"].update(target_ids=["claim-other"]),
            "wrong_case": lambda p: p["expected_scope"].update(case_id="case-other"),
            "lineage": lambda p: p["candidate"].update(lineage_complete=False),
            "schema": lambda p: p["candidate"].update(schema_version="older"),
            "stages": lambda p: p["candidate"].update(completed_stages=["SCHEMA"]),
            "material_conflict": lambda p: p["candidate"].update(blocking_discrepancy_ids=["disc-1"]),
            "rollback_parent": lambda p: p["rollback"].update(commit_id="canonical-15"),
            "rollback_integrity": lambda p: p["rollback"].update(integrity_valid=False),
            "rollback_schema": lambda p: p["rollback"].update(schema_compatible=False),
            "rollback_authority": lambda p: p["rollback"].update(authority_refs_valid=False),
            "rollback_known_good": lambda p: p["rollback"].update(known_good=False),
        }
        for name, change in modifiers.items():
            with self.subTest(case=name):
                p = baseline()
                change(p)
                report = reference(copy.deepcopy(p))
                proc = subprocess.run([str(BINARY)], input=json.dumps(p), capture_output=True,
                                      text=True, timeout=8, check=False)
                rust = json.loads(proc.stdout)
                self.assertEqual(proc.returncode, 0, rust)
                self.assertEqual(rust["status"], "ADVISORY_ONLY")
                value = rust["assessment"]
                self.assertEqual(value["passed"], report.passed)
                self.assertEqual(value["failed_checks"], [c.name for c in report.failed_checks])
                self.assertEqual(
                    [(c["name"], c["passed"]) for c in value["checks"]],
                    [(c.name, c.passed) for c in report.checks],
                )
                self.assertEqual(value["decision_kind"], "STRUCTURAL_ADVISORY_ONLY")
                self.assertFalse(value["canonical_writeback"])
                self.assertFalse(value["authority_transfer"])
                self.assertIsNone(value["output_commit"])
                self.assertNotIn("guards", value)
                self.assertNotIn("receipt", value)

    def test_malformed_candidate_rejected(self):
        p = baseline()
        p["candidate"]["manifest_hash"] = "not-a-sha"
        proc = subprocess.run([str(BINARY)], input=json.dumps(p), capture_output=True,
                              text=True, timeout=8, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stdout)["status"], "REJECTED")

if __name__ == "__main__":
    unittest.main()
