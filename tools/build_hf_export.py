from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


EXPORT_FILES = (
    "LICENSE.md",
    "main.py",
    "benchmark.py",
    "pyproject.toml",
    "requirements.txt",
    "galia_history_bridge.py",
    "historical_acquisition.py",
    "historical_artifacts.py",
    "historical_store.py",
    "historical_store_bundle.py",
)

EXPORT_DIRS = (
    "galia2",
    "src",
)

SKIP_NAMES = {
    "__pycache__",
    ".DS_Store",
}

SKIP_SUFFIXES = {
    ".pyc",
    ".pyo",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_sha(explicit: str | None) -> str:
    if explicit:
        return explicit
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return "UNKNOWN"


def should_skip(path: Path) -> bool:
    if any(part in SKIP_NAMES for part in path.parts):
        return True
    if path.suffix in SKIP_SUFFIXES:
        return True
    return False


def copy_tree_filtered(src: Path, dst: Path) -> None:
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        if should_skip(rel):
            continue
        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def build_export(root: Path, output: Path, *, sha: str, include_tests: bool) -> dict:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    for name in EXPORT_FILES:
        src = root / name
        if not src.is_file():
            raise FileNotFoundError(f"required export file missing: {name}")
        shutil.copy2(src, output / name)

    for name in EXPORT_DIRS:
        src = root / name
        if not src.is_dir():
            raise FileNotFoundError(f"required export directory missing: {name}")
        copy_tree_filtered(src, output / name)

    if include_tests:
        src = root / "tests"
        if not src.is_dir():
            raise FileNotFoundError("tests directory missing")
        copy_tree_filtered(src, output / "tests")

    template = root / "huggingface" / "README.model.md"
    if not template.is_file():
        raise FileNotFoundError("huggingface/README.model.md is missing")

    card = template.read_text(encoding="utf-8")
    card = card.replace("{{SOURCE_REPO}}", "riosriosje-prog/test-model-thing")
    card = card.replace("{{SOURCE_SHA}}", sha)
    (output / "README.md").write_text(card, encoding="utf-8")

    records = []
    for path in sorted(p for p in output.rglob("*") if p.is_file()):
        rel = path.relative_to(output).as_posix()
        if rel == "HF_EXPORT_MANIFEST.json":
            continue
        records.append(
            {
                "path": rel,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    manifest = {
        "schema_version": 1,
        "artifact_type": "GALIA_HUGGINGFACE_DISTRIBUTION_MIRROR",
        "source_repo": "riosriosje-prog/test-model-thing",
        "source_sha": sha,
        "source_of_truth": "github",
        "promotion_scope": "DISTRIBUTION_MIRROR_ONLY",
        "canonical_authority_transferred": False,
        "files": records,
    }
    manifest_path = output / "HF_EXPORT_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Re-read to guarantee valid, deterministic JSON before any upload step.
    json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest


def verify_export(output: Path) -> None:
    manifest_path = output / "HF_EXPORT_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for row in manifest["files"]:
        path = output / row["path"]
        if not path.is_file():
            raise RuntimeError(f"manifest file missing: {row['path']}")
        if path.stat().st_size != row["bytes"]:
            raise RuntimeError(f"size mismatch: {row['path']}")
        actual = sha256_file(path)
        if actual != row["sha256"]:
            raise RuntimeError(f"sha256 mismatch: {row['path']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="hf-export")
    ap.add_argument("--source-sha")
    ap.add_argument("--include-tests", action="store_true")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    output = (root / args.output).resolve()
    sha = source_sha(args.source_sha)

    manifest = build_export(
        root,
        output,
        sha=sha,
        include_tests=args.include_tests,
    )
    verify_export(output)

    manifest_sha = sha256_file(output / "HF_EXPORT_MANIFEST.json")
    print("HF_EXPORT_STATUS=PASS")
    print("HF_EXPORT_SOURCE_SHA=" + sha)
    print("HF_EXPORT_FILE_COUNT=" + str(len(manifest["files"])))
    print("HF_EXPORT_MANIFEST_SHA256=" + manifest_sha)


if __name__ == "__main__":
    main()
