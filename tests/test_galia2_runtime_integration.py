from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
import unittest

from galia2.core import Case, CaseState
from galia2.legacy_adapter import LegacyAdapter
from galia2.runtime_integration import (
    RuntimeShadowBridge,
    inspect_legacy_source,
)


GOOD_SOURCE = '''
class Runtime:
    def __init__(self, path: str, threshold: float, **kwargs): pass
    def save(self): pass
    def call(self, c: int, n: int | None, end: bool, save: bool, frozen: bool):
        outputs = self.model(c, n, end, frozen)
        if save: self.save()
        return outputs
    def write(self, b: int): pass
    def chat(self, save: bool, frozen: bool): pass
    def train(self, save: bool, frozen: bool, dataset: str): pass
    def now(self): pass
    def __call__(self, mode: str, dataset: str, save: bool, frozen: bool): pass
if __name__ == '__main__':
    pass
'''


class FakeRuntime:
    def __init__(self, result=(65, 0.25)):
        self.result = result
        self.calls = []
        self.unrelated = {"sentinel": 1}

    def call(self, c, n, end, save, frozen):
        self.calls.append((c, n, end, save, frozen))
        return self.result


class RuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.case = Case(
            case_id="case-runtime",
            title="Runtime integration",
            scope="P10",
            state=CaseState.OPEN,
            created_at=datetime(2026, 9, 24, tzinfo=timezone.utc),
            governing_constitution_version="core-v1",
        )
        self.adapter = LegacyAdapter(policy_version="p10", actor="runtime-shim")
        self.bridge = RuntimeShadowBridge(adapter=self.adapter, legacy_blob_sha="blob123")

    def test_contract_inspector_accepts_current_surface_shape(self):
        report = inspect_legacy_source(GOOD_SOURCE, source_blob_sha="sha")
        self.assertTrue(report.compatible)
        self.assertTrue(report.call_delegates_to_model)
        self.assertTrue(report.save_gate_present)
        self.assertTrue(report.call_returns_outputs)
        self.assertTrue(report.main_guard_present)

    def test_contract_inspector_fails_closed_on_missing_method(self):
        report = inspect_legacy_source(GOOD_SOURCE.replace("    def write(self, b: int): pass\n", ""), source_blob_sha="sha")
        self.assertFalse(report.compatible)
        self.assertIn("write", report.missing_methods)

    def test_contract_inspector_fails_closed_on_call_signature_drift(self):
        bad = GOOD_SOURCE.replace("c: int, n: int | None, end: bool, save: bool, frozen: bool", "c, n, save, frozen")
        report = inspect_legacy_source(bad, source_blob_sha="sha")
        self.assertFalse(report.compatible)
        self.assertIn("call", report.signature_mismatches)

    def test_contract_inspector_requires_main_guard(self):
        report = inspect_legacy_source(GOOD_SOURCE.replace("if __name__ == '__main__':\n    pass\n", ""), source_blob_sha="sha")
        self.assertFalse(report.compatible)
        self.assertFalse(report.main_guard_present)

    def test_bridge_delegates_exactly_once_and_preserves_return_identity(self):
        result = (66, 0.5)
        runtime = FakeRuntime(result=result)
        obs = self.bridge.invoke(case=self.case, runtime=runtime, c=65, n=66, end=True, save=False, frozen=True)
        self.assertEqual(runtime.calls, [(65, 66, True, False, True)])
        self.assertIs(obs.legacy_result, result)

    def test_bridge_shadow_capture_is_non_authoritative(self):
        runtime = FakeRuntime()
        obs = self.bridge.invoke(case=self.case, runtime=runtime, c=65, n=None, end=False, save=False, frozen=True)
        self.assertEqual(obs.capture.origin, "LEGACY_SHADOW")
        self.assertIsNone(obs.capture_receipt.output_commit)
        self.assertIn("READ_ONLY", obs.capture_receipt.result)

    def test_bridge_serialization_is_deterministic(self):
        r1 = FakeRuntime((65, 0.25))
        r2 = FakeRuntime((65, 0.25))
        a = self.bridge.invoke(case=self.case, runtime=r1, c=7, n=8, end=False, save=True, frozen=False)
        b = self.bridge.invoke(case=self.case, runtime=r2, c=7, n=8, end=False, save=True, frozen=False)
        self.assertEqual(a.input_payload, b.input_payload)
        self.assertEqual(a.output_payload, b.output_payload)
        self.assertEqual(a.capture.input_hash, b.capture.input_hash)
        self.assertEqual(a.capture.output_hash, b.capture.output_hash)

    def test_bridge_does_not_patch_or_replace_runtime_attributes(self):
        runtime = FakeRuntime()
        before = (runtime.call.__func__, runtime.unrelated.copy())
        self.bridge.invoke(case=self.case, runtime=runtime, c=1, n=2, end=False, save=False, frozen=False)
        after = (runtime.call.__func__, runtime.unrelated.copy())
        self.assertEqual(before, after)

    def test_bridge_rejects_invalid_byte_before_legacy_execution(self):
        runtime = FakeRuntime()
        with self.assertRaises(ValueError):
            self.bridge.invoke(case=self.case, runtime=runtime, c=256, n=None, end=False, save=False, frozen=False)
        self.assertEqual(runtime.calls, [])

    def test_bridge_rejects_bad_runtime_result_after_single_execution(self):
        runtime = FakeRuntime(result=(999, 0.2))
        with self.assertRaises(ValueError):
            self.bridge.invoke(case=self.case, runtime=runtime, c=1, n=None, end=False, save=False, frozen=False)
        self.assertEqual(len(runtime.calls), 1)

    def test_observation_and_contract_report_are_frozen(self):
        runtime = FakeRuntime()
        obs = self.bridge.invoke(case=self.case, runtime=runtime, c=1, n=None, end=False, save=False, frozen=False)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            obs.case_id = "changed"
        report = inspect_legacy_source(GOOD_SOURCE, source_blob_sha="sha")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.compatible = False

    def test_runtime_integration_module_has_no_filesystem_process_or_mlx_dependency(self):
        source = Path(__file__).parents[1].joinpath("galia2", "runtime_integration.py").read_text()
        forbidden = ("import os", "import subprocess", "import mlx", "open(", "setattr(", "exec(", "eval(")
        for token in forbidden:
            self.assertNotIn(token, source)

    def test_bridge_exposes_no_promotion_or_persistence_method(self):
        public = {name for name in dir(self.bridge) if not name.startswith("_")}
        for forbidden in {"promote", "publish", "rollback", "write", "save", "update_head", "grant_authority"}:
            self.assertNotIn(forbidden, public)

    def test_case_binding_is_preserved(self):
        runtime = FakeRuntime()
        obs = self.bridge.invoke(case=self.case, runtime=runtime, c=65, n=66, end=False, save=False, frozen=False)
        self.assertEqual(obs.case_id, self.case.case_id)
        self.assertEqual(obs.capture.case_id, self.case.case_id)
