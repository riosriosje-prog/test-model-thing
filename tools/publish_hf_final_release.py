#!/usr/bin/env python3
"""Publish and verify the exact GALIA 1.0.1 final release to Hugging Face.

This tool is deliberately fail-closed. It never changes canonical authority.
Hugging Face remains a distribution mirror only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from huggingface_hub import CommitOperationAdd, HfApi, snapshot_download

REPO_ID="Junitos/galia-2"
EXPECTED_SQLITE_SHA="9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354"
EXPECTED_SQLITE_BYTES=488_689_664
EXPECTED_BUNDLE_SHA="4d6560384e4112880a4cea537f1d1e540b4a0290081850904492e7f57a79f025"
EXPECTED_BUNDLE_BYTES=90_294_405
REMOTE_PREFIX="release/1.0.1"

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def verify_local(root: Path) -> dict:
    sqlite=root/"GALIA_CANONICAL_KERNEL_1_0_1_MASTER_PROMOTED.sqlite"
    readme=root/"README.md"
    manifest=root/"RELEASE_MANIFEST.json"
    sums=root/"SHA256SUMS.txt"
    missing=[str(p) for p in (sqlite,readme,manifest,sums) if not p.is_file()]
    if missing:
        raise SystemExit("missing release files: "+", ".join(missing))
    if sqlite.stat().st_size != EXPECTED_SQLITE_BYTES:
        raise SystemExit("sqlite byte-size mismatch")
    if sha256(sqlite) != EXPECTED_SQLITE_SHA:
        raise SystemExit("sqlite SHA-256 mismatch")
    return {
        "sqlite":sqlite,
        "readme":readme,
        "manifest":manifest,
        "sums":sums,
    }

def verify_remote(token: str) -> dict:
    with TemporaryDirectory() as td:
        root=Path(snapshot_download(
            repo_id=REPO_ID,
            repo_type="model",
            revision="main",
            allow_patterns=[f"{REMOTE_PREFIX}/*"],
            local_dir=td,
            token=token,
        ))
        sqlite=root/REMOTE_PREFIX/"GALIA_CANONICAL_KERNEL_1_0_1_MASTER_PROMOTED.sqlite"
        readme=root/REMOTE_PREFIX/"README.md"
        manifest=root/REMOTE_PREFIX/"RELEASE_MANIFEST.json"
        sums=root/REMOTE_PREFIX/"SHA256SUMS.txt"
        for p in (sqlite,readme,manifest,sums):
            if not p.is_file():
                raise SystemExit(f"remote missing {p.relative_to(root)}")
        if sqlite.stat().st_size != EXPECTED_SQLITE_BYTES:
            raise SystemExit("remote sqlite byte-size mismatch")
        digest=sha256(sqlite)
        if digest != EXPECTED_SQLITE_SHA:
            raise SystemExit(f"remote sqlite SHA mismatch: {digest}")
        return {
            "repo_id":REPO_ID,
            "revision":"main",
            "promotion_scope":"DISTRIBUTION_MIRROR_ONLY",
            "canonical_authority_transferred":False,
            "sqlite_sha256":digest,
            "sqlite_bytes":sqlite.stat().st_size,
            "status":"PASS"
        }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--release-dir",type=Path)
    ap.add_argument("--verify-only",action="store_true")
    ap.add_argument("--receipt",type=Path,default=Path("hf-final-release-receipt.json"))
    args=ap.parse_args()
    token=os.environ.get("HF_TOKEN")
    if not token:
        raise SystemExit("HF_TOKEN is required")

    api=HfApi(token=token)
    who=api.whoami()
    if who.get("name")!="Junitos":
        raise SystemExit(f"wrong HF identity: {who.get('name')!r}")

    if not args.verify_only:
        if args.release_dir is None:
            raise SystemExit("--release-dir is required unless --verify-only")
        files=verify_local(args.release_dir)
        operations=[
            CommitOperationAdd(path_in_repo=f"{REMOTE_PREFIX}/GALIA_CANONICAL_KERNEL_1_0_1_MASTER_PROMOTED.sqlite",path_or_fileobj=str(files["sqlite"])),
            CommitOperationAdd(path_in_repo=f"{REMOTE_PREFIX}/README.md",path_or_fileobj=str(files["readme"])),
            CommitOperationAdd(path_in_repo=f"{REMOTE_PREFIX}/RELEASE_MANIFEST.json",path_or_fileobj=str(files["manifest"])),
            CommitOperationAdd(path_in_repo=f"{REMOTE_PREFIX}/SHA256SUMS.txt",path_or_fileobj=str(files["sums"])),
        ]
        api.create_commit(
            repo_id=REPO_ID,
            repo_type="model",
            operations=operations,
            commit_message="Promote GALIA 1.0.1 canonical distribution release",
        )

    receipt=verify_remote(token)
    args.receipt.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("HF_FINAL_RELEASE_POSTVERIFY=PASS")
    print("HF_FINAL_RELEASE_SQLITE_SHA256="+receipt["sqlite_sha256"])

if __name__=="__main__":
    main()
