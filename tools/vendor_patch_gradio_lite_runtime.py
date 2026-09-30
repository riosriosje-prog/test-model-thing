#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import re
import urllib.parse
import urllib.request
from pathlib import Path

UPSTREAM_BASE = "https://gradio-lite-previews.s3.amazonaws.com/PINNED_HF_HUB/dist/"
ROOT_FILES = ("lite.js", "lite.css")
ASSET_RE = re.compile(r"(?:\./)?assets/[A-Za-z0-9._+@=-]+")
BROKEN_LINK_RE = re.compile(r"os\.link\s*=\s*lambda\s+src,\s*dst:\s*None")
PATCHED_LINK = (
    'os.link = lambda *args, **kwargs: '
    '(_ for _ in ()).throw(NotImplementedError("os.link unavailable in WASM"))'
)

def patch_worker_text(text: str) -> tuple[str, int]:
    return BROKEN_LINK_RE.subn(PATCHED_LINK, text)

def discover_assets(text: str) -> set[str]:
    return {m.group(0).removeprefix("./") for m in ASSET_RE.finditer(text)}

def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "GALIA-Gradio-Lite-runtime-vendor/1"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read()

def is_text_asset(path: str) -> bool:
    return Path(path).suffix.lower() in {".js", ".css", ".html", ".json"}

def vendor(output: Path, base_url: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    queue = list(ROOT_FILES)
    seen: set[str] = set()
    patch_count = 0
    hashes: dict[str, str] = {}

    while queue:
        rel = queue.pop(0)
        if rel in seen or rel.endswith(".map"):
            continue
        seen.add(rel)

        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", rel)
        data = fetch(url)

        if is_text_asset(rel):
            text = data.decode("utf-8")
            if rel.endswith(".js"):
                text, n = patch_worker_text(text)
                patch_count += n
            for asset in sorted(discover_assets(text)):
                if asset not in seen:
                    queue.append(asset)
            data = text.encode("utf-8")

        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[rel] = hashlib.sha256(data).hexdigest()

    if patch_count < 1:
        raise SystemExit(
            "FAIL_CLOSED: upstream runtime was downloaded but the broken os.link shim "
            "was not found; refusing to publish an unverified runtime"
        )

    (output / "RUNTIME_PATCH.txt").write_text(
        "GALIA Gradio Lite runtime recovery\n"
        f"upstream={base_url}\n"
        f"os_link_patch_count={patch_count}\n"
        f"files={len(hashes)}\n",
        encoding="utf-8",
    )
    return {"files": len(hashes), "patch_count": patch_count, "hashes": hashes}

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="dist/gradio-lite/runtime")
    ap.add_argument("--base-url", default=UPSTREAM_BASE)
    args = ap.parse_args()

    result = vendor(Path(args.output), args.base_url)
    print("GALIA_GRADIO_LITE_RUNTIME_VENDOR=PASS")
    print("GALIA_GRADIO_LITE_RUNTIME_FILES=" + str(result["files"]))
    print("GALIA_GRADIO_LITE_OS_LINK_PATCHES=" + str(result["patch_count"]))

if __name__ == "__main__":
    main()
