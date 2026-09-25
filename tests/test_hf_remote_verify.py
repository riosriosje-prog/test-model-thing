from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.publish_hf_candidate import parse_pr_number, verify_snapshot


class HuggingFaceRemoteVerifyTests(unittest.TestCase):
    def test_parse_pr_number(self) -> None:
        self.assertEqual(
            parse_pr_number("https://huggingface.co/u/r/discussions/17"),
            17,
        )
        self.assertIsNone(parse_pr_number(None))

    def test_parse_pr_number_rejects_unknown_url(self) -> None:
        with self.assertRaises(ValueError):
            parse_pr_number("https://huggingface.co/u/r/commit/abc")

    def test_verify_snapshot_byte_and_hash_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()

            payload = b"GALIA\n"
            for base in (local, remote):
                (base / "a.txt").write_bytes(payload)

            row = {
                "path": "a.txt",
                "bytes": len(payload),
                "sha256": __import__("hashlib").sha256(payload).hexdigest(),
            }
            manifest = {
                "schema_version": 1,
                "source_sha": "abc",
                "files": [row],
            }
            manifest_bytes = (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode()
            for base in (local, remote):
                (base / "HF_EXPORT_MANIFEST.json").write_bytes(
                    manifest_bytes
                )

            result = verify_snapshot(remote, local)
            self.assertEqual(result["verified_files"], 1)
            self.assertEqual(result["source_sha"], "abc")

    def test_verify_snapshot_detects_remote_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()

            good = b"good"
            bad = b"bad!"
            (local / "a.txt").write_bytes(good)
            (remote / "a.txt").write_bytes(bad)

            row = {
                "path": "a.txt",
                "bytes": len(good),
                "sha256": __import__("hashlib").sha256(good).hexdigest(),
            }
            manifest = {
                "schema_version": 1,
                "source_sha": "abc",
                "files": [row],
            }
            manifest_bytes = (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode()
            for base in (local, remote):
                (base / "HF_EXPORT_MANIFEST.json").write_bytes(
                    manifest_bytes
                )

            with self.assertRaises(RuntimeError):
                verify_snapshot(remote, local)


if __name__ == "__main__":
    unittest.main()
