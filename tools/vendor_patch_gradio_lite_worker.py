#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

UPSTREAM_WORKER_URL = (
    "https://gradio-lite-previews.s3.amazonaws.com/"
    "PINNED_HF_HUB/dist/assets/webworker-BsZ7XNFH.js"
)
OLD_SHIM = "os.link = lambda src, dst: None"
NEW_SHIM = """def _galia_wasm_os_link(src, dst, *args, **kwargs):
    raise NotImplementedError("os.link is unavailable in Pyodide/WASM")
os.link = _galia_wasm_os_link"""


def patch_worker(source: str) -> str:
    count = source.count(OLD_SHIM)
    if count != 1:
        raise RuntimeError(
            f"expected exactly one Gradio Lite os.link shim, found {count}"
        )
    patched = source.replace(OLD_SHIM, NEW_SHIM, 1)
    if OLD_SHIM in patched:
        raise RuntimeError("legacy os.link shim still present after patch")
    if "_galia_wasm_os_link" not in patched:
        raise RuntimeError("patched worker marker missing")
    return patched


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output",
        default="dist/gradio-lite/assets/webworker-galia.js",
    )
    ap.add_argument("--source-file")
    args = ap.parse_args()

    if args.source_file:
        source = Path(args.source_file).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(UPSTREAM_WORKER_URL, timeout=30) as response:
            source = response.read().decode("utf-8", "strict")

    source_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    patched = patch_worker(source)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(patched, encoding="utf-8")

    digest = hashlib.sha256(patched.encode("utf-8")).hexdigest()
    print("GALIA_GRADIO_LITE_WORKER_PATCH=PASS")
    print("GALIA_GRADIO_LITE_UPSTREAM_WORKER_SHA256=" + source_digest)
    print("GALIA_GRADIO_LITE_WORKER_SHA256=" + digest)
    print("GALIA_GRADIO_LITE_WORKER_OUTPUT=" + str(out))


if __name__ == "__main__":
    main()
