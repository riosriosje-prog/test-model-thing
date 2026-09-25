from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from huggingface_hub import HfApi, snapshot_download

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def tree_manifest(root: Path) -> dict[str, dict[str, object]]:
    rows = {}
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        rows[rel] = {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
    return rows

def main() -> None:
    ap = argparse.ArgumentParser(description="Publish HF8 training snapshot to isolated HF branch")
    ap.add_argument("--folder", required=True)
    ap.add_argument("--repo-id", default="Junitos/galia-2")
    ap.add_argument("--revision", default="hf8-retrain-v0.1")
    ap.add_argument("--path-in-repo", default="training/hf8-retrain-v0.1")
    ap.add_argument("--token", required=True)
    args = ap.parse_args()

    folder = Path(args.folder).resolve()
    if not any(p.suffix == ".safetensors" for p in folder.rglob("*") if p.is_file()):
        raise SystemExit("No .safetensors checkpoint payload present")

    initial = tree_manifest(folder)
    manifest_path = folder / "HF8_RETRAIN_SNAPSHOT_MANIFEST.json"
    manifest_path.write_text(json.dumps({
        "repo_id": args.repo_id,
        "revision": args.revision,
        "path_in_repo": args.path_in_repo,
        "promotion_scope": "HF8_RETRAIN_STAGING_ONLY",
        "canonical_authority_transferred": False,
        "human_promotion_required": True,
        "files": initial,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    local_manifest = tree_manifest(folder)

    api = HfApi(token=args.token)
    try:
        api.create_branch(repo_id=args.repo_id, branch=args.revision, repo_type="model", exist_ok=True)
    except TypeError:
        try:
            api.create_branch(repo_id=args.repo_id, branch=args.revision, repo_type="model")
        except Exception as exc:
            if "already exists" not in str(exc).lower() and "409" not in str(exc):
                raise

    api.upload_folder(
        repo_id=args.repo_id,
        repo_type="model",
        revision=args.revision,
        folder_path=str(folder),
        path_in_repo=args.path_in_repo,
        commit_message="Stage GALIA HF8 reproducible training snapshot",
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
        remote_manifest = tree_manifest(remote_root)

    if remote_manifest != local_manifest:
        missing = sorted(set(local_manifest) - set(remote_manifest))
        extra = sorted(set(remote_manifest) - set(local_manifest))
        mismatched = sorted(
            k for k in set(local_manifest) & set(remote_manifest)
            if local_manifest[k] != remote_manifest[k]
        )
        raise SystemExit(
            f"Remote snapshot mismatch missing={missing} extra={extra} mismatched={mismatched}"
        )

    print("HF8_STAGING_UPLOAD=PASS")
    print("HF8_STAGING_REMOTE_REREAD=PASS")
    print("HF8_STAGING_FILE_COUNT=" + str(len(local_manifest)))
    print("HF8_STAGING_REVISION=" + args.revision)
    print("HF8_STAGING_PROMOTED=false")

if __name__ == "__main__":
    main()
