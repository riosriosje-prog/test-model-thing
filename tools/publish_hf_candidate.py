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


def parse_pr_number(pr_url: str | None) -> int | None:
    if not pr_url:
        return None
    match = PR_URL_RE.search(pr_url)
    if not match:
        raise ValueError(f"cannot parse Hugging Face PR number from {pr_url!r}")
    return int(match.group(1))


def verify_snapshot(snapshot_root: Path, local_export: Path) -> dict:
    manifest_path = local_export / "HF_EXPORT_MANIFEST.json"
    local_manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(local_manifest_bytes.decode("utf-8"))

    remote_manifest = snapshot_root / "HF_EXPORT_MANIFEST.json"
    if not remote_manifest.is_file():
        raise RuntimeError("remote snapshot missing HF_EXPORT_MANIFEST.json")
    if remote_manifest.read_bytes() != local_manifest_bytes:
        raise RuntimeError("remote manifest bytes do not match local manifest")

    checked = 0
    for row in manifest["files"]:
        rel = Path(row["path"])
        local_path = local_export / rel
        remote_path = snapshot_root / rel

        if not local_path.is_file():
            raise RuntimeError(f"local export missing {row['path']}")
        if not remote_path.is_file():
            raise RuntimeError(f"remote snapshot missing {row['path']}")

        local_sha = sha256_file(local_path)
        remote_sha = sha256_file(remote_path)

        if local_sha != row["sha256"]:
            raise RuntimeError(f"local manifest/hash mismatch: {row['path']}")
        if remote_sha != row["sha256"]:
            raise RuntimeError(f"remote snapshot/hash mismatch: {row['path']}")
        if remote_path.stat().st_size != row["bytes"]:
            raise RuntimeError(f"remote snapshot/size mismatch: {row['path']}")
        checked += 1

    return {
        "source_sha": manifest["source_sha"],
        "manifest_sha256": sha256_file(manifest_path),
        "verified_files": checked,
    }


def publish_and_verify(
    *,
    repo_id: str,
    export_dir: Path,
    token: str,
    private: bool,
    create_pr: bool,
) -> dict:
    if "/" not in repo_id:
        raise ValueError("repo_id must be owner-or-org/repo-name")
    if not token:
        raise ValueError("HF_TOKEN is required")

    try:
        from huggingface_hub import HfApi, snapshot_download
    except ImportError as exc:
        raise RuntimeError(
            "huggingface_hub is required only for the remote publish gate; "
            "install requirements-hf.txt before publishing"
        ) from exc

    api = HfApi(token=token)
    api.create_repo(
        repo_id=repo_id,
        repo_type="model",
        private=private,
        exist_ok=True,
    )

    info = api.upload_folder(
        repo_id=repo_id,
        repo_type="model",
        folder_path=str(export_dir),
        path_in_repo=".",
        commit_message=(
            "GALIA distribution mirror "
            + json.loads(
                (export_dir / "HF_EXPORT_MANIFEST.json").read_text(
                    encoding="utf-8"
                )
            )["source_sha"]
        ),
        commit_description=(
            "Distribution mirror only. GitHub remains authoritative."
        ),
        create_pr=create_pr,
    )

    pr_number = parse_pr_number(getattr(info, "pr_url", None))
    if create_pr and pr_number is None:
        raise RuntimeError("create_pr=True but upload returned no PR URL")

    if pr_number is not None:
        revision = f"refs/pr/{pr_number}"
    else:
        revision = getattr(info, "oid", None) or getattr(info, "commit_hash", None)
        if not revision:
            revision = "main"

    with tempfile.TemporaryDirectory() as td:
        remote_root = Path(
            snapshot_download(
                repo_id=repo_id,
                repo_type="model",
                revision=revision,
                local_dir=td,
                token=token,
            )
        )
        verified = verify_snapshot(remote_root, export_dir)

    return {
        "repo_id": repo_id,
        "repo_type": "model",
        "private_requested": private,
        "create_pr": create_pr,
        "pr_number": pr_number,
        "pr_url": getattr(info, "pr_url", None),
        "commit_url": str(getattr(info, "commit_url", "")),
        "commit_oid": str(
            getattr(info, "oid", "")
            or getattr(info, "commit_hash", "")
        ),
        "verified_revision": revision,
        **verified,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-id", required=True)
    ap.add_argument("--export-dir", default="hf-export")
    ap.add_argument("--visibility", choices=("private", "public"), default="private")
    ap.add_argument("--create-pr", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--receipt", default="hf-remote-receipt.json")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise SystemExit("HF_TOKEN is required")

    result = publish_and_verify(
        repo_id=args.repo_id,
        export_dir=Path(args.export_dir),
        token=token,
        private=(args.visibility == "private"),
        create_pr=args.create_pr,
    )

    Path(args.receipt).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("HF_REMOTE_VERIFY=PASS")
    print("HF_REMOTE_REPO_ID=" + result["repo_id"])
    print("HF_REMOTE_REVISION=" + result["verified_revision"])
    print("HF_REMOTE_VERIFIED_FILES=" + str(result["verified_files"]))
    print("HF_REMOTE_MANIFEST_SHA256=" + result["manifest_sha256"])
    if result["pr_url"]:
        print("HF_REMOTE_PR_URL=" + result["pr_url"])


if __name__ == "__main__":
    main()
