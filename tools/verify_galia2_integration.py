#!/usr/bin/env python3
"""Fail-closed verifier for the GALIA 2.0 add-only repository overlay."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

EXPECTED_MAIN_GIT_BLOB_SHA = "715b9be844284f13eb885e3301c90c5a04b3c6bc"
LEGACY_PROTECTED_PATHS = {
    "main.py",
    "benchmark.py",
    "README.md",
    "requirements.txt",
    ".gitignore",
    "LICENSE.md",
}
REQUIRED_GALIA_MODULES = {
    "galia2/__init__.py",
    "galia2/core.py",
    "galia2/state_machine.py",
    "galia2/orchestrator.py",
    "galia2/legacy_adapter.py",
    "galia2/authority.py",
    "galia2/preflight.py",
    "galia2/persistence.py",
    "galia2/recovery_audit.py",
    "galia2/end_to_end.py",
    "galia2/runtime_integration.py",
}


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def verify(root: Path, *, run_tests: bool = False) -> dict[str, object]:
    main = root / "main.py"
    if not main.is_file():
        raise RuntimeError("main.py missing; refusing integration verification")
    actual_main_sha = git_blob_sha(main.read_bytes())
    if actual_main_sha != EXPECTED_MAIN_GIT_BLOB_SHA:
        raise RuntimeError(
            f"Legacy main.py drift: expected Git blob {EXPECTED_MAIN_GIT_BLOB_SHA}, got {actual_main_sha}"
        )

    missing = sorted(path for path in REQUIRED_GALIA_MODULES if not (root / path).is_file())
    if missing:
        raise RuntimeError(f"missing GALIA 2.0 files: {missing}")

    dirty_protected: list[str] = []
    git_dir = root / ".git"
    if git_dir.exists():
        proc = subprocess.run(
            ["git", "status", "--porcelain", "--", *sorted(LEGACY_PROTECTED_PATHS)],
            cwd=root,
            text=True,
            capture_output=True,
            check=True,
        )
        dirty_protected = [line for line in proc.stdout.splitlines() if line.strip()]
        if dirty_protected:
            raise RuntimeError(f"protected Legacy paths are dirty: {dirty_protected}")

    test_returncode = None
    if run_tests:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_galia2_*.py"],
            cwd=root,
            text=True,
        )
        test_returncode = proc.returncode
        if proc.returncode != 0:
            raise RuntimeError("GALIA 2.0 test suite failed")

    return {
        "legacy_main_git_blob_sha": actual_main_sha,
        "legacy_protected_paths_dirty": dirty_protected,
        "required_galia_modules_present": True,
        "tests_run": run_tests,
        "test_returncode": test_returncode,
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--run-tests", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(Path(args.root).resolve(), run_tests=args.run_tests)
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
