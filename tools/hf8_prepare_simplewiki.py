from __future__ import annotations

import argparse
import bz2
import hashlib
import html
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
REF_RE = re.compile(r"<ref\b[^>]*>.*?</ref\s*>|<ref\b[^>]*/\s*>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
TEMPLATE_RE = re.compile(r"\{\{[^{}]*\}\}")
LINK_PIPE_RE = re.compile(r"\[\[[^\]|]+\|([^\]]+)\]\]")
LINK_RE = re.compile(r"\[\[([^\]]+)\]\]")
EXT_LINK_RE = re.compile(r"\[(?:https?://\S+)(?:\s+([^\]]+))?\]")
WS_RE = re.compile(r"\s+")

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def clean_wikitext(text: str) -> str:
    text = COMMENT_RE.sub(" ", text)
    text = REF_RE.sub(" ", text)
    for _ in range(8):
        new = TEMPLATE_RE.sub(" ", text)
        if new == text:
            break
        text = new
    text = LINK_PIPE_RE.sub(r"\1", text)
    text = LINK_RE.sub(r"\1", text)
    text = EXT_LINK_RE.sub(lambda m: m.group(1) or " ", text)
    text = TAG_RE.sub(" ", text)
    text = text.replace("'''", "").replace("''", "")
    text = html.unescape(text)
    return WS_RE.sub(" ", text).strip()

def main() -> None:
    ap = argparse.ArgumentParser(description="Build deterministic SimpleWiki training corpus")
    ap.add_argument("--dump", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--target-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--source-url", required=True)
    args = ap.parse_args()

    dump = Path(args.dump)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    article_count = 0
    output_bytes = 0

    with bz2.open(dump, "rb") as fh, out.open("wb") as dst:
        for _, elem in ET.iterparse(fh, events=("end",)):
            if not elem.tag.endswith("text"):
                continue
            cleaned = clean_wikitext(elem.text or "")
            elem.clear()
            if len(cleaned) < 40:
                continue
            line = (cleaned + "\n").encode("utf-8", errors="ignore")
            if output_bytes + len(line) > args.target_bytes and article_count > 0:
                break
            dst.write(line)
            output_bytes += len(line)
            article_count += 1
            if output_bytes >= args.target_bytes:
                break

    if article_count == 0:
        raise SystemExit("No article text extracted from dump")

    receipt = {
        "gate": "HF8_RETRAIN_CORPUS",
        "source_url": args.source_url,
        "dump_bytes": dump.stat().st_size,
        "dump_sha256": sha256_file(dump),
        "corpus_bytes": out.stat().st_size,
        "corpus_sha256": sha256_file(out),
        "article_count": article_count,
        "target_bytes": args.target_bytes,
        "extractor": "GALIA deterministic XML/wikitext normalizer v0.1",
    }
    Path(args.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("HF8_CORPUS_BUILD=PASS")
    print("HF8_DUMP_SHA256=" + receipt["dump_sha256"])
    print("HF8_CORPUS_SHA256=" + receipt["corpus_sha256"])
    print("HF8_CORPUS_BYTES=" + str(receipt["corpus_bytes"]))
    print("HF8_CORPUS_ARTICLES=" + str(article_count))

if __name__ == "__main__":
    main()
