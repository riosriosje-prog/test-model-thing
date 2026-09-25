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
INLINE_WS_RE = re.compile(r"[ \t\f\v]+")
MULTI_NL_RE = re.compile(r"\n{3,}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def clean_wikitext_preserve_lines(text: str) -> list[str]:
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
    text = INLINE_WS_RE.sub(" ", text)
    text = MULTI_NL_RE.sub("\n\n", text)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if len(line.encode("utf-8", errors="ignore")) >= 8:
            out.append(line)
    return out


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def main() -> None:
    ap = argparse.ArgumentParser(description="Build distributed deterministic SimpleWiki v0.2 corpus")
    ap.add_argument("--dump", required=True)
    ap.add_argument("--train-output", required=True)
    ap.add_argument("--eval-output", required=True)
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--source-url", required=True)
    args = ap.parse_args()

    dump = Path(args.dump)
    train_path = Path(args.train_output)
    eval_path = Path(args.eval_output)
    train_path.parent.mkdir(parents=True, exist_ok=True)
    eval_path.parent.mkdir(parents=True, exist_ok=True)

    pages_seen = pages_train = pages_eval = 0
    train_lines = eval_lines = 0
    train_bytes = eval_bytes = 0

    with bz2.open(dump, "rb") as fh, train_path.open("wb") as train, eval_path.open("wb") as ev:
        for _, elem in ET.iterparse(fh, events=("end",)):
            if local_name(elem.tag) != "page":
                continue

            title = ""
            text = ""
            for child in elem.iter():
                name = local_name(child.tag)
                if name == "title" and child.text and not title:
                    title = child.text
                elif name == "text" and child.text:
                    text = child.text

            pages_seen += 1
            key = hashlib.sha256(title.encode("utf-8", errors="ignore")).digest()[0]
            if key < 32:
                target = train
                split = "train"
                pages_train += 1
            elif key < 36:
                target = ev
                split = "eval"
                pages_eval += 1
            else:
                elem.clear()
                continue

            for line in clean_wikitext_preserve_lines(text):
                payload = (line + "\n").encode("utf-8", errors="ignore")
                target.write(payload)
                if split == "train":
                    train_lines += 1
                    train_bytes += len(payload)
                else:
                    eval_lines += 1
                    eval_bytes += len(payload)
            elem.clear()

    if train_lines == 0 or eval_lines == 0:
        raise SystemExit("Deterministic split produced empty train/eval corpus")

    receipt = {
        "gate": "HF8_RETRAIN_CORPUS_V0_2",
        "source_url": args.source_url,
        "dump_sha256": sha256_file(dump),
        "dump_bytes": dump.stat().st_size,
        "page_split": {
            "hash": "sha256(title_utf8)[0]",
            "train": "0..31",
            "eval": "32..35",
            "ignored": "36..255",
        },
        "pages_seen": pages_seen,
        "pages_train": pages_train,
        "pages_eval": pages_eval,
        "train_lines": train_lines,
        "eval_lines": eval_lines,
        "train_bytes": train_bytes,
        "eval_bytes": eval_bytes,
        "train_sha256": sha256_file(train_path),
        "eval_sha256": sha256_file(eval_path),
        "preprocessor": "GALIA full-dump distributed deterministic cleaner v0.2",
        "upstream_exact_cleaning_claimed": False,
    }
    Path(args.receipt).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("HF8_V02_CORPUS_BUILD=PASS")
    print("HF8_V02_DUMP_SHA256=" + receipt["dump_sha256"])
    print("HF8_V02_TRAIN_SHA256=" + receipt["train_sha256"])
    print("HF8_V02_EVAL_SHA256=" + receipt["eval_sha256"])
    print("HF8_V02_TRAIN_BYTES=" + str(train_bytes))
    print("HF8_V02_EVAL_BYTES=" + str(eval_bytes))
    print("HF8_V02_PAGES_SEEN=" + str(pages_seen))
    print("HF8_V02_PAGES_TRAIN=" + str(pages_train))
    print("HF8_V02_PAGES_EVAL=" + str(pages_eval))


if __name__ == "__main__":
    main()
