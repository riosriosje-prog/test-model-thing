from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


NAME_PATTERNS = (
    r"m[aá]?c\s*\.?\s*leary",
    r"m[eé]\s*\.?\s*leary",
    r"leary\s+ave\b",
    r"avenida\s+[^ ]{0,4}leary\b",
)


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def inspect(pdf: Path, *, date: str, folder: int, url: str) -> dict:
    raw = pdf.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError("not a PDF")
    proc = subprocess.run(
        ["pdftotext", "-layout", str(pdf), "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    text = proc.stdout.decode("utf-8", errors="replace")
    pages = text.split("\f")
    if pages and not pages[-1].strip():
        pages = pages[:-1]

    hits = []
    leary_diagnostics = []
    for page_number, page in enumerate(pages, 1):
        n = normalize(page)

        for m in re.finditer(r"leary", n):
            pos = m.start()
            leary_diagnostics.append(
                {
                    "page_number": page_number,
                    "context": n[max(0, pos-180):min(len(n), pos+360)],
                }
            )

        positions = []
        for pattern in NAME_PATTERNS:
            for m in re.finditer(pattern, n):
                positions.append((m.start(), m.group(0), pattern))
        positions.sort()
        for pos, token, pattern in positions[:8]:
            hits.append(
                {
                    "page_number": page_number,
                    "token": token,
                    "pattern": pattern,
                    "context": n[max(0, pos-260):min(len(n), pos+620)],
                }
            )

    return {
        "date": date,
        "ufdc_folder": folder,
        "source_url": url,
        "raw_pdf_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_pdf_size_bytes": len(raw),
        "page_count": len(pages),
        "hits": hits,
        "leary_diagnostics": leary_diagnostics[:20],
        "claim_promoted": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--date", required=True)
    ap.add_argument("--folder", type=int, required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    result = inspect(
        Path(args.pdf),
        date=args.date,
        folder=args.folder,
        url=args.url,
    )
    Path(args.output).write_text(
        json.dumps(result, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
