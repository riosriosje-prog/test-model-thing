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
        raise ValueError(f"cannot parse Hugging Face Space PR from {url!r}")
    return int(m.group(1))


def verify_snapshot(remote_root: Path, local_export: Path) -> dict:
    manifest_path = local_export / "HF_SPACE_EXPORT_MANIFEST.json"
    local_bytes = manifest_path.read_bytes()
    manifest = json.loads(local_bytes)

    remote_manifest = remote_root / "HF_SPACE_EXPORT_MANIFEST.json"
    if not remote_manifest.is_file() or remote_manifest.read_bytes() != local_bytes:
        raise RuntimeError("remote Space manifest bytes do not match local manifest")

    assert manifest["promotion_scope"] == "SPACE_DIAGNOSTIC_CANDIDATE_ONLY"
    assert manifest["canonical_authority_transferred"] is False
    assert manifest["diagnostic_only"] is True
    assert manifest["model_inference_enabled"] is False
    assert manifest["checkpoint_writes_enabled"] is False
    assert manifest["weight_artifact_bound"] is False
    assert manifest["persistent_session_state"] is False
    assert manifest["hf8_weight_gate"] == "HOLD"

    checked = 0
    for row in manifest["files"]:
        p = remote_root / row["path"]
        if not p.is_file():
            raise RuntimeError(f"remote Space snapshot missing {row['path']}")
        if sha256_file(p) != row["sha256"]:
            raise RuntimeError(f"remote Space hash mismatch: {row['path']}")
        if p.stat().st_size != row["bytes"]:
            raise RuntimeError(f"remote Space size mismatch: {row['path']}")
        checked += 1

    return {
        "source_sha": manifest["source_sha"],
        "manifest_sha256": sha256_file(manifest_path),
        "verified_files": checked,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-id", required=True)
    ap.add_argument("--export-dir", default="hf-space-export")
    ap.add_argument("--receipt", default="hf10b-space-remote-receipt.json")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise SystemExit("HF_TOKEN is required")

    from huggingface_hub import HfApi, snapshot_download
    api = HfApi(token=token)
    api.create_repo(
        repo_id=args.repo_id,
        repo_type="space",
        space_sdk="gradio",
        private=True,
        exist_ok=True,
    )

    export_dir = Path(args.export_dir)
    manifest = json.loads((export_dir / "HF_SPACE_EXPORT_MANIFEST.json").read_text())
    info = api.upload_folder(
        repo_id=args.repo_id,
        repo_type="space",
        folder_path=str(export_dir),
        path_in_repo=".",
        commit_message="GALIA HF10B diagnostic Space " + manifest["source_sha"],
        commit_description=(
            "Read-only diagnostic candidate. No weights, inference, checkpoint writes, "
            "evidence mutation, or authority transfer."
        ),
        create_pr=True,
    )
    pr_number = parse_pr_number(getattr(info, "pr_url", None))
    if pr_number is None:
        raise RuntimeError("HF10B create_pr=True returned no PR URL")

    revision = f"refs/pr/{pr_number}"
    with tempfile.TemporaryDirectory() as td:
        root = Path(snapshot_download(
            repo_id=args.repo_id,
            repo_type="space",
            revision=revision,
            local_dir=td,
            token=token,
        ))
        verified = verify_snapshot(root, export_dir)

    receipt = {
        "repo_id": args.repo_id,
        "repo_type": "space",
        "private_requested": True,
        "create_pr": True,
        "pr_number": pr_number,
        "pr_url": getattr(info, "pr_url", None),
        "verified_revision": revision,
        "promotion_scope": "SPACE_DIAGNOSTIC_CANDIDATE_ONLY",
        "canonical_authority_transferred": False,
        "space_runtime_promoted": False,
        **verified,
    }
    Path(args.receipt).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF10B_REMOTE_VERIFY=PASS")
    print("HF10B_REMOTE_REPO_ID=" + args.repo_id)
    print("HF10B_REMOTE_REVISION=" + revision)
    print("HF10B_REMOTE_VERIFIED_FILES=" + str(receipt["verified_files"]))
    print("HF10B_REMOTE_MANIFEST_SHA256=" + receipt["manifest_sha256"])
    print("HF10B_REMOTE_PR_URL=" + str(receipt["pr_url"]))


if __name__ == "__main__":
    main()
