from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "tools" / "verify_galia2_integration.py"
spec = importlib.util.spec_from_file_location("galia2_repo_verify", VERIFIER)
verify_mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verify_mod)


class RepositoryPackageTests(unittest.TestCase):
    def test_expected_main_blob_is_pinned(self):
        self.assertEqual(
            verify_mod.EXPECTED_MAIN_GIT_BLOB_SHA,
            "715b9be844284f13eb885e3301c90c5a04b3c6bc",
        )

    def test_main_is_a_protected_path(self):
        self.assertIn("main.py", verify_mod.LEGACY_PROTECTED_PATHS)

    def test_runtime_module_required(self):
        self.assertIn("galia2/runtime_integration.py", verify_mod.REQUIRED_GALIA_MODULES)

    def test_overlay_has_no_legacy_main(self):
        self.assertFalse((ROOT / "main.py").exists())

    def test_overlay_has_no_legacy_benchmark(self):
        self.assertFalse((ROOT / "benchmark.py").exists())

    def test_git_blob_sha_algorithm(self):
        data = b"hello\n"
        expected = hashlib.sha1(b"blob 6\0hello\n").hexdigest()
        self.assertEqual(verify_mod.git_blob_sha(data), expected)

    def test_verify_rejects_missing_main(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(RuntimeError, "main.py missing"):
                verify_mod.verify(Path(td))

    def test_verify_rejects_wrong_main(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text("print('wrong')\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Legacy main.py drift"):
                verify_mod.verify(root)

    def test_all_required_modules_exist_in_overlay(self):
        self.assertEqual(
            [],
            sorted(path for path in verify_mod.REQUIRED_GALIA_MODULES if not (ROOT / path).is_file()),
        )


if __name__ == "__main__":
    unittest.main()
