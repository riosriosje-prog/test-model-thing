from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

STATIC_ROOT = Path("huggingface/space")
STATIC_FILES = ["README.md", "app.py", "diagnostics.py", "requirements.txt"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="hf-space-export")
    ap.add_argument("--source-sha", required=True)
    args = ap.parse_args()

    out = Path(args.output)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    rows = []
    for rel in STATIC_FILES:
        src = STATIC_ROOT / rel
        if not src.is_file():
            raise SystemExit(f"missing Space surface file: {src}")
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        rows.append({
            "path": rel,
            "bytes": dst.stat().st_size,
            "sha256": sha256_file(dst),
        })

    manifest = {
        "schema_version": "1.0.0",
        "source_repo": "riosriosje-prog/test-model-thing",
        "source_sha": args.source_sha,
        "source_of_truth": "github",
        "hf_repo_id": "Junitos/galia-2-diagnostic",
        "hf_repo_type": "space",
        "promotion_scope": "SPACE_DIAGNOSTIC_CANDIDATE_ONLY",
        "canonical_authority_transferred": False,
        "diagnostic_only": True,
        "model_inference_enabled": False,
        "checkpoint_writes_enabled": False,
        "weight_artifact_bound": False,
        "historical_evidence_included": False,
        "source_images_included": False,
        "persistent_session_state": False,
        "linux_runtime_parity_gate": "PASS",
        "hf8_weight_gate": "HOLD",
        "files": sorted(rows, key=lambda r: r["path"]),
    }
    path = out / "HF_SPACE_EXPORT_MANIFEST.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("HF10B_EXPORT_STATUS=PASS")
    print("HF10B_SOURCE_SHA=" + args.source_sha)
    print("HF10B_EXPORT_FILE_COUNT=" + str(len(rows)))
    print("HF10B_MANIFEST_SHA256=" + sha256_file(path))


if __name__ == "__main__":
    main()
