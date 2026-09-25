from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

STATIC_ROOT = Path("huggingface/dataset")
STATIC_FILES = [
    "README.md",
    "data/README.md",
    "schema/evidence-record.schema.json",
    "schema/lineage-record.schema.json",
    "schema/discrepancy-record.schema.json",
]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="hf-dataset-export")
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
            raise SystemExit(f"missing static dataset file: {src}")
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
        "hf_repo_id": "Junitos/galia-2-evidence",
        "hf_repo_type": "dataset",
        "promotion_scope": "DATASET_SCHEMA_SURFACE_ONLY",
        "canonical_authority_transferred": False,
        "contains_historical_evidence": False,
        "contains_source_images": False,
        "contains_raw_source_bytes": False,
        "evidence_record_count": 0,
        "files": sorted(rows, key=lambda r: r["path"]),
    }
    manifest_path = out / "HF_DATASET_EXPORT_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF9_EXPORT_STATUS=PASS")
    print("HF9_EXPORT_SOURCE_SHA=" + args.source_sha)
    print("HF9_EVIDENCE_RECORD_COUNT=0")
    print("HF9_EXPORT_FILE_COUNT=" + str(len(rows)))
    print("HF9_EXPORT_MANIFEST_SHA256=" + sha256_file(manifest_path))

if __name__ == "__main__":
    main()
