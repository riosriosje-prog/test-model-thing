from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

SPACE = Path(__file__).parents[1] / "huggingface" / "space"
sys.path.insert(0, str(SPACE))

from diagnostics import diagnostic_payload


class HF10DiagnosticSpaceSurfaceTests(unittest.TestCase):
    def test_session_fingerprints_are_isolated_and_deterministic(self):
        a1 = diagnostic_payload("session-a")
        a2 = diagnostic_payload("session-a")
        b = diagnostic_payload("session-b")
        self.assertEqual(a1["session_fingerprint"], a2["session_fingerprint"])
        self.assertNotEqual(a1["session_fingerprint"], b["session_fingerprint"])
        self.assertFalse(a1["session_state_persisted"])

    def test_authority_and_mutation_are_fail_closed(self):
        p = diagnostic_payload("x")
        self.assertEqual(p["mode"], "READ_ONLY_DIAGNOSTIC")
        self.assertEqual(p["authority_source"], "github")
        self.assertEqual(p["promotion_scope"], "SPACE_DIAGNOSTIC_CANDIDATE_ONLY")
        self.assertFalse(p["canonical_authority_transferred"])
        self.assertFalse(p["model_inference_enabled"])
        self.assertFalse(p["checkpoint_writes_enabled"])
        self.assertFalse(p["weight_artifact_bound"])
        self.assertEqual(p["hf8_weight_gate"], "HOLD")
        self.assertEqual(p["hf10_linux_runtime_parity"], "PASS")

    def test_app_source_has_no_environment_secret_or_filesystem_write_surface(self):
        source = (SPACE / "app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            n.func.attr if isinstance(n.func, ast.Attribute)
            else n.func.id if isinstance(n.func, ast.Name)
            else ""
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
        }
        forbidden_calls = {
            "open", "write_text", "write_bytes", "save", "upload_file",
            "upload_folder", "create_commit", "create_repo"
        }
        self.assertTrue(calls.isdisjoint(forbidden_calls))
        self.assertNotIn("os.environ", source)
        self.assertNotIn("HF_TOKEN", source)
        self.assertNotIn("huggingface_hub", source)


if __name__ == "__main__":
    unittest.main()
