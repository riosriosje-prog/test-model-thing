import ast
import inspect
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

from galia2.core import (
    AuthorityState,
    Case,
    CaseState,
    ClaimType,
    EvidenceState,
)
from galia2.legacy_adapter import LegacyAdapter, LegacyDiffKind

NOW = datetime(2026, 9, 23, 22, 45, tzinfo=timezone.utc)


def case(case_id="case-1"):
    return Case(
        case_id=case_id,
        title="Legacy adapter case",
        scope="P4 test",
        state=CaseState.ACTIVE_RESEARCH,
        created_at=NOW,
        governing_constitution_version="core-v1",
    )


def adapter():
    counter = {"n": 0}
    def ids(prefix):
        counter["n"] += 1
        return f"{prefix}-{counter['n']}"
    return LegacyAdapter(
        policy_version="core-v1+p2+p3+p4",
        actor="p4-test",
        clock=lambda: NOW,
        id_factory=ids,
    )


class LegacyAdapterTests(unittest.TestCase):
    def test_capture_hashes_exact_bytes_and_emits_no_commit(self):
        out = adapter().capture(case=case(), input_payload="hola", output_payload="mundo")
        capture = out.value
        self.assertEqual(capture.case_id, "case-1")
        self.assertEqual(len(capture.input_hash), 64)
        self.assertEqual(len(capture.output_hash), 64)
        self.assertEqual(out.receipt.output_commit, None)
        self.assertEqual(out.receipt.operation, "LEGACY_SHADOW_CAPTURE")

    def test_capture_is_immutable(self):
        capture = adapter().capture(case=case(), input_payload=b"x", output_payload=b"y").value
        with self.assertRaises(FrozenInstanceError):
            capture.case_id = "mutated"

    def test_missing_output_is_supported_as_observation_not_fact(self):
        out = adapter().capture(case=case(), input_payload="x", output_payload=None)
        self.assertIsNone(out.value.output_hash)
        self.assertEqual(out.receipt.output_hashes, ())

    def test_claim_mapping_is_forced_non_authoritative(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload="legacy answer").value
        mapped = a.map_claim(
            case=c,
            capture=capture,
            claim_id="claim-1",
            subject="Taft",
            predicate="intersects",
            object="Loiza",
        ).value
        self.assertEqual(mapped.claim.claim_type, ClaimType.DERIVED)
        self.assertEqual(mapped.claim.evidence_state, EvidenceState.UNVERIFIED)
        self.assertEqual(mapped.claim.authority_state, AuthorityState.NONE)
        self.assertEqual(mapped.origin, "LEGACY_SHADOW")

    def test_claim_mapping_rejects_missing_legacy_output(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload=None).value
        with self.assertRaises(ValueError):
            a.map_claim(
                case=c,
                capture=capture,
                claim_id="claim-1",
                subject="A",
                predicate="B",
                object="C",
            )

    def test_cross_case_capture_binding_is_rejected(self):
        a = adapter()
        capture = a.capture(case=case("a"), input_payload="q", output_payload="x").value
        with self.assertRaises(ValueError):
            a.compare(case=case("b"), capture=capture, galia2_output="x")

    def test_byte_identical_outputs_are_non_material(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload=b"same\x00").value
        diff = a.compare(case=c, capture=capture, galia2_output=b"same\x00").value
        self.assertEqual(diff.kind, LegacyDiffKind.BYTE_IDENTICAL)
        self.assertFalse(diff.material)
        self.assertIsNone(diff.discrepancy)

    def test_representation_only_difference_is_non_material_not_semantic(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload="alpha  \r\nbeta\r\n").value
        diff = a.compare(case=c, capture=capture, galia2_output="alpha\nbeta").value
        self.assertEqual(diff.kind, LegacyDiffKind.REPRESENTATION_EQUIVALENT)
        self.assertFalse(diff.material)
        self.assertIsNone(diff.discrepancy)

    def test_material_difference_opens_discrepancy_not_winner(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload="legacy").value
        diff = a.compare(case=c, capture=capture, galia2_output="galia2").value
        self.assertEqual(diff.kind, LegacyDiffKind.MATERIAL_DIFFERENCE)
        self.assertTrue(diff.material)
        self.assertIsNotNone(diff.discrepancy)
        self.assertEqual(diff.discrepancy.type, "LEGACY_GALIA2_OUTPUT_DIFF")
        self.assertEqual(diff.discrepancy.state.value, "OPEN")

    def test_missing_galia2_output_is_material_discrepancy(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload="legacy").value
        diff = a.compare(case=c, capture=capture, galia2_output=None).value
        self.assertEqual(diff.kind, LegacyDiffKind.MISSING_GALIA2_OUTPUT)
        self.assertTrue(diff.material)

    def test_missing_legacy_output_is_material_discrepancy(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload="q", output_payload=None).value
        diff = a.compare(case=c, capture=capture, galia2_output="2.0").value
        self.assertEqual(diff.kind, LegacyDiffKind.MISSING_LEGACY_OUTPUT)
        self.assertTrue(diff.material)

    def test_every_adapter_receipt_has_no_output_commit(self):
        a = adapter()
        c = case()
        cap_op = a.capture(case=c, input_payload="q", output_payload="legacy")
        map_op = a.map_claim(
            case=c, capture=cap_op.value, claim_id="c1", subject="s", predicate="p", object="o"
        )
        cmp_op = a.compare(case=c, capture=cap_op.value, galia2_output="other")
        self.assertTrue(all(op.receipt.output_commit is None for op in (cap_op, map_op, cmp_op)))

    def test_adapter_exposes_no_write_mutation_method(self):
        public = {name for name, _ in inspect.getmembers(LegacyAdapter, inspect.isfunction) if not name.startswith("_")}
        self.assertEqual(public, {"capture", "compare", "map_claim"})

    def test_adapter_module_has_no_filesystem_process_or_legacy_imports(self):
        module_path = Path(inspect.getsourcefile(LegacyAdapter))
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        forbidden_modules = {"os", "pathlib", "subprocess", "shutil", "main"}
        imported = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(imported.isdisjoint(forbidden_modules), imported & forbidden_modules)
        self.assertNotIn("open", called_names)

    def test_binary_nonidentical_outputs_do_not_get_text_equivalence(self):
        a = adapter()
        c = case()
        capture = a.capture(case=c, input_payload=b"q", output_payload=b"\xff\x00").value
        diff = a.compare(case=c, capture=capture, galia2_output=b"\xfe\x00").value
        self.assertEqual(diff.kind, LegacyDiffKind.MATERIAL_DIFFERENCE)


if __name__ == "__main__":
    unittest.main()
