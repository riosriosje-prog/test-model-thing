#!/usr/bin/env python3
"""Read-only verifier for the promoted GALIA 1.0.1 Hugging Face release."""
from __future__ import annotations
import hashlib, os
from pathlib import Path
from tempfile import TemporaryDirectory
from huggingface_hub import snapshot_download

REPO_ID="Junitos/galia-2"
PREFIX="release/1.0.1"
EXPECTED_SHA="9e98bf9cad5c8efafb7a4f0dc09373ecff532b7f3fdcb483e40c5e0053062354"
EXPECTED_BYTES=488_689_664

def digest(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(8*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

with TemporaryDirectory() as td:
    root=Path(snapshot_download(
        repo_id=REPO_ID, repo_type="model", revision="main",
        allow_patterns=[f"{PREFIX}/*"], local_dir=td,
        token=os.environ.get("HF_TOKEN")
    ))
    p=root/PREFIX/"GALIA_CANONICAL_KERNEL_1_0_1_MASTER_PROMOTED.sqlite"
    if not p.is_file():
        raise SystemExit("REMOTE_BINARY_MISSING")
    if p.stat().st_size!=EXPECTED_BYTES:
        raise SystemExit("REMOTE_SIZE_MISMATCH")
    h=digest(p)
    if h!=EXPECTED_SHA:
        raise SystemExit("REMOTE_SHA_MISMATCH:"+h)
    print("HF_FINAL_RELEASE_VERIFY=PASS")
    print("SHA256="+h)
