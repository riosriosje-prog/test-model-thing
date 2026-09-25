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
        raise ValueError(f"cannot parse Space PR number from {url!r}")
    return int(m.group(1))


def verify(remote_root: Path, local_export: Path) -> dict:
    mp = local_export / "HF_STATIC_SPACE_EXPORT_MANIFEST.json"
    raw = mp.read_bytes()
    m = json.loads(raw)
    remote_mp = remote_root / mp.name
    if not remote_mp.is_file() or remote_mp.read_bytes() != raw:
        raise RuntimeError("remote static Space manifest mismatch")

    assert m["space_sdk"] == "static"
    assert m["promotion_scope"] == "SPACE_STATIC_DIAGNOSTIC_CANDIDATE_ONLY"
    assert m["canonical_authority_transferred"] is False
    assert m["server_runtime"] is False
    assert m["model_inference_enabled"] is False
    assert m["checkpoint_writes_enabled"] is False
    assert m["weight_artifact_bound"] is False
    assert m["persistent_session_state"] is False

    checked = 0
    for row in m["files"]:
        p = remote_root / row["path"]
        if not p.is_file():
            raise RuntimeError(f"missing remote file: {row['path']}")
        if sha256_file(p) != row["sha256"]:
            raise RuntimeError(f"remote hash mismatch: {row['path']}")
        if p.stat().st_size != row["bytes"]:
            raise RuntimeError(f"remote size mismatch: {row['path']}")
        checked += 1

    return {
        "source_sha": m["source_sha"],
        "manifest_sha256": sha256_file(mp),
        "verified_files": checked,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-id", required=True)
    ap.add_argument("--export-dir", default="hf-static-space-export")
    ap.add_argument("--receipt", default="hf10b-static-space-receipt.json")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise SystemExit("HF_TOKEN is required")

    from huggingface_hub import HfApi, snapshot_download
    api = HfApi(token=token)
    api.create_repo(
        repo_id=args.repo_id,
        repo_type="space",
        space_sdk="static",
        private=True,
        exist_ok=True,
    )

    export = Path(args.export_dir)
    m = json.loads((export / "HF_STATIC_SPACE_EXPORT_MANIFEST.json").read_text())
    info = api.upload_folder(
        repo_id=args.repo_id,
        repo_type="space",
        folder_path=str(export),
        path_in_repo=".",
        commit_message="GALIA HF10B static diagnostic " + m["source_sha"],
        commit_description=(
            "Static read-only diagnostic candidate. No server runtime, weights, "
            "checkpoint writes, evidence mutation, or authority transfer."
        ),
        create_pr=True,
    )
    pr = parse_pr_number(getattr(info, "pr_url", None))
    if pr is None:
        raise RuntimeError("create_pr=True returned no Space PR URL")

    revision = f"refs/pr/{pr}"
    with tempfile.TemporaryDirectory() as td:
        root = Path(snapshot_download(
            repo_id=args.repo_id,
            repo_type="space",
            revision=revision,
            local_dir=td,
            token=token,
        ))
        verified = verify(root, export)

    receipt = {
        "repo_id": args.repo_id,
        "repo_type": "space",
        "space_sdk": "static",
        "private_requested": True,
        "create_pr": True,
        "pr_number": pr,
        "pr_url": getattr(info, "pr_url", None),
        "verified_revision": revision,
        "promotion_scope": "SPACE_STATIC_DIAGNOSTIC_CANDIDATE_ONLY",
        "canonical_authority_transferred": False,
        "space_runtime_promoted": False,
        **verified,
    }
    Path(args.receipt).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("HF10B_STATIC_REMOTE_VERIFY=PASS")
    print("HF10B_STATIC_REMOTE_PR_URL=" + receipt["pr_url"])
    print("HF10B_STATIC_REMOTE_MANIFEST_SHA256=" + receipt["manifest_sha256"])


if __name__ == "__main__":
    main()
