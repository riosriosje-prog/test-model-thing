from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.build_hf_export import build_export, verify_export


class HuggingFaceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[1]

    def test_build_export_binds_source_sha_and_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "export"
            manifest = build_export(
                self.root,
                output,
                sha="test-source-sha",
                include_tests=False,
            )
            verify_export(output)

            self.assertEqual(manifest["source_sha"], "test-source-sha")
            self.assertEqual(manifest["source_of_truth"], "github")
            self.assertEqual(
                manifest["promotion_scope"],
                "DISTRIBUTION_MIRROR_ONLY",
            )
            self.assertFalse(manifest["canonical_authority_transferred"])
            self.assertTrue((output / "README.md").is_file())
            self.assertTrue((output / "galia2" / "core.py").is_file())
            self.assertFalse((output / "tests").exists())

            card = (output / "README.md").read_text(encoding="utf-8")
            self.assertIn("test-source-sha", card)
            self.assertIn("source of truth", card)

    def test_manifest_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "export"
            build_export(
                self.root,
                output,
                sha="mutation-test",
                include_tests=False,
            )
            target = output / "main.py"
            target.write_text(
                target.read_text(encoding="utf-8") + "\n# mutation\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                verify_export(output)

    def test_manifest_is_json_and_sorted_file_list(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "export"
            build_export(
                self.root,
                output,
                sha="json-test",
                include_tests=False,
            )
            manifest = json.loads(
                (output / "HF_EXPORT_MANIFEST.json").read_text(
                    encoding="utf-8"
                )
            )
            paths = [row["path"] for row in manifest["files"]]
            self.assertEqual(paths, sorted(paths))
            self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
