from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

PR_URL_RE = re.compile(r"/discussions/(\d+)(?:$|[/?#])")

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def parse_pr_number(url: str | None) -> int | None:
    if not url:
        return None
    m = PR_URL_RE.search(url)
    if not m:
        raise ValueError(f"cannot parse Hugging Face PR number from {url!r}")
    return int(m.group(1))

def verify_snapshot(remote_root: Path, local_export: Path) -> dict:
    manifest_path = local_export / "HF_DATASET_EXPORT_MANIFEST.json"
    local_bytes = manifest_path.read_bytes()
    manifest = json.loads(local_bytes)

    remote_manifest = remote_root / "HF_DATASET_EXPORT_MANIFEST.json"
    if remote_manifest.read_bytes() != local_bytes:
        raise RuntimeError("remote dataset manifest bytes do not match local manifest")

    assert manifest["promotion_scope"] == "DATASET_SCHEMA_SURFACE_ONLY"
    assert manifest["canonical_authority_transferred"] is False
    assert manifest["contains_historical_evidence"] is False
    assert manifest["contains_source_images"] is False
    assert manifest["contains_raw_source_bytes"] is False
    assert manifest["evidence_record_count"] == 0

    checked = 0
    for row in manifest["files"]:
        p = remote_root / row["path"]
        if not p.is_file():
            raise RuntimeError(f"remote dataset snapshot missing {row['path']}")
        if sha256_file(p) != row["sha256"]:
            raise RuntimeError(f"remote dataset hash mismatch: {row['path']}")
        if p.stat().st_size != row["bytes"]:
            raise RuntimeError(f"remote dataset size mismatch: {row['path']}")
        checked += 1

    return {
        "source_sha": manifest["source_sha"],
        "manifest_sha256": sha256_file(manifest_path),
        "verified_files": checked,
        "evidence_record_count": manifest["evidence_record_count"],
    }

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-id", required=True)
    ap.add_argument("--export-dir", default="hf-dataset-export")
    ap.add_argument("--receipt", default="hf9-remote-receipt.json")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise SystemExit("HF_TOKEN is required")

    from huggingface_hub import HfApi, snapshot_download
    api = HfApi(token=token)
    api.create_repo(
        repo_id=args.repo_id,
        repo_type="dataset",
        private=True,
        exist_ok=True,
    )

    export_dir = Path(args.export_dir)
    manifest = json.loads((export_dir / "HF_DATASET_EXPORT_MANIFEST.json").read_text())
    info = api.upload_folder(
        repo_id=args.repo_id,
        repo_type="dataset",
        folder_path=str(export_dir),
        path_in_repo=".",
        commit_message="GALIA HF9 schema-only dataset surface " + manifest["source_sha"],
        commit_description="Zero evidence records. Distribution schema surface only; GitHub remains authoritative.",
        create_pr=True,
    )
    pr_number = parse_pr_number(getattr(info, "pr_url", None))
    if pr_number is None:
        raise RuntimeError("HF9 create_pr=True returned no PR URL")

    revision = f"refs/pr/{pr_number}"
    with tempfile.TemporaryDirectory() as td:
        root = Path(snapshot_download(
            repo_id=args.repo_id,
            repo_type="dataset",
            revision=revision,
            local_dir=td,
            token=token,
        ))
        verified = verify_snapshot(root, export_dir)

    receipt = {
        "repo_id": args.repo_id,
        "repo_type": "dataset",
        "private_requested": True,
        "create_pr": True,
        "pr_number": pr_number,
        "pr_url": getattr(info, "pr_url", None),
        "verified_revision": revision,
        "promotion_scope": "DATASET_SCHEMA_SURFACE_ONLY",
        "canonical_authority_transferred": False,
        **verified,
    }
    Path(args.receipt).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF9_REMOTE_VERIFY=PASS")
    print("HF9_REMOTE_REPO_ID=" + args.repo_id)
    print("HF9_REMOTE_REVISION=" + revision)
    print("HF9_REMOTE_VERIFIED_FILES=" + str(receipt["verified_files"]))
    print("HF9_EVIDENCE_RECORD_COUNT=0")
    print("HF9_REMOTE_MANIFEST_SHA256=" + receipt["manifest_sha256"])
    print("HF9_REMOTE_PR_URL=" + str(receipt["pr_url"]))

if __name__ == "__main__":
    main()
