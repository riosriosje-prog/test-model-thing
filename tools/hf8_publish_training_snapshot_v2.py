from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from huggingface_hub import HfApi, snapshot_download

MANIFEST_NAME = "HF8_RETRAIN_SNAPSHOT_MANIFEST.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def tree_manifest(root: Path, *, exclude_manifest: bool = False) -> dict[str, dict[str, object]]:
    rows = {}
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        if exclude_manifest and rel == MANIFEST_NAME:
            continue
        rows[rel] = {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="Publish exact HF8 retraining snapshot v2")
    ap.add_argument("--folder", required=True)
    ap.add_argument("--repo-id", default="Junitos/galia-2")
    ap.add_argument("--revision", default="hf8-retrain-v0.1")
    ap.add_argument("--path-in-repo", default="training/hf8-retrain-v0.1")
    ap.add_argument("--token", required=True)
    args = ap.parse_args()

    folder = Path(args.folder).resolve()
    payloads = [p for p in folder.rglob("*.safetensors") if p.is_file()]
    if not payloads:
        raise SystemExit("No .safetensors checkpoint payload present")

    latest_receipt = json.loads((folder / "training-receipt.json").read_text(encoding="utf-8"))
    if latest_receipt.get("artifact_kind") != "REAL_TRAINED_CHECKPOINT":
        raise SystemExit("Latest training receipt is not REAL_TRAINED_CHECKPOINT")
    if latest_receipt.get("authority_binding") != "CURRENT_BOUND":
        raise SystemExit("Latest checkpoint is not CURRENT_BOUND")

    content_files = tree_manifest(folder, exclude_manifest=True)
    manifest_path = folder / MANIFEST_NAME
    manifest_doc = {
        "repo_id": args.repo_id,
        "revision": args.revision,
        "path_in_repo": args.path_in_repo,
        "promotion_scope": "HF8_RETRAIN_STAGING_ONLY",
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
        "latest_cumulative_steps": int(latest_receipt["cumulative_steps"]),
        "latest_payload_sha256": latest_receipt["payload_sha256"],
        "latest_payload_bytes": int(latest_receipt["payload_bytes"]),
        "files": content_files,
    }
    manifest_path.write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    local_tree = tree_manifest(folder)

    api = HfApi(token=args.token)
    repo_info = api.repo_info(
        repo_id=args.repo_id,
        repo_type="model",
        revision=args.revision,
    )
    parent_commit = repo_info.sha

    api.upload_folder(
        repo_id=args.repo_id,
        repo_type="model",
        revision=args.revision,
        folder_path=str(folder),
        path_in_repo=args.path_in_repo,
        delete_patterns="*",
        parent_commit=parent_commit,
        commit_message=(
            "Update GALIA HF8 retraining staging snapshot "
            f"to {latest_receipt['cumulative_steps']} steps"
        ),
    )

    with tempfile.TemporaryDirectory() as td:
        root = Path(snapshot_download(
            repo_id=args.repo_id,
            repo_type="model",
            revision=args.revision,
            token=args.token,
            allow_patterns=[args.path_in_repo + "/**"],
            local_dir=td,
        ))
        remote_root = root / args.path_in_repo
        remote_tree = tree_manifest(remote_root)

    if remote_tree != local_tree:
        missing = sorted(set(local_tree) - set(remote_tree))
        extra = sorted(set(remote_tree) - set(local_tree))
        mismatched = sorted(
            k for k in set(local_tree) & set(remote_tree)
            if local_tree[k] != remote_tree[k]
        )
        raise SystemExit(
            f"Remote snapshot mismatch missing={missing} extra={extra} mismatched={mismatched}"
        )

    remote_manifest = json.loads(
        (remote_root / MANIFEST_NAME).read_text(encoding="utf-8")
    )
    if remote_manifest["latest_payload_sha256"] != latest_receipt["payload_sha256"]:
        raise SystemExit("Remote manifest latest payload SHA mismatch")
    if int(remote_manifest["latest_cumulative_steps"]) != int(latest_receipt["cumulative_steps"]):
        raise SystemExit("Remote manifest cumulative step mismatch")

    print("HF8_STAGING_V2_UPLOAD=PASS")
    print("HF8_STAGING_V2_REMOTE_REREAD=PASS")
    print("HF8_STAGING_V2_FILE_COUNT=" + str(len(local_tree)))
    print("HF8_STAGING_V2_LATEST_STEPS=" + str(latest_receipt["cumulative_steps"]))
    print("HF8_STAGING_V2_PAYLOAD_SHA256=" + latest_receipt["payload_sha256"])
    print("HF8_STAGING_PROMOTED=false")


if __name__ == "__main__":
    main()
