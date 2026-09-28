from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


STREET_PATTERNS = (
    r"\bcalle\s+taft\b",
    r"\bavenida\s+taft\b",
    r"\bave\.?\s+taft\b",
    r"\bav\.?\s+taft\b",
    r"\btaft\s+ave\.?\b",
    r"\btaft\s+avenue\b",
    r"\btaft\s+st\.?\b",
    r"\btaft\s+street\b",
)

CONTEXT_TOKENS = (
    "santurce",
    "parada 44",
    "stop 44",
    "mcleary",
    "macleary",
    "carrión",
    "carrion",
    "loíza",
    "loiza",
    "alquila",
    "vende",
    "rent",
    "sale",
)


def normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


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

    street_hits = []
    taft_diagnostics = []

    for page_number, page in enumerate(pages, 1):
        n = normalize(page)

        for m in re.finditer(r"taft", n):
            pos = m.start()
            taft_diagnostics.append(
                {
                    "page_number": page_number,
                    "context": n[max(0, pos - 220):min(len(n), pos + 520)],
                }
            )

        for pattern in STREET_PATTERNS:
            for m in re.finditer(pattern, n):
                pos = m.start()
                context = n[max(0, pos - 320):min(len(n), pos + 720)]
                street_hits.append(
                    {
                        "page_number": page_number,
                        "pattern": pattern,
                        "token": m.group(0),
                        "context": context,
                        "context_signals": [
                            token for token in CONTEXT_TOKENS if token in context
                        ],
                    }
                )

    # Guard against lexical bleed such as "gave Taft" in political news.
    # Qualified street hits require whole-token street designators.
    return {
        "schema_version": 2,
        "scan_type": "GALIA_TAFT_STREET_1915",
        "date": date,
        "ufdc_folder": folder,
        "source_url": url,
        "raw_pdf_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_pdf_size_bytes": len(raw),
        "page_count": len(pages),
        "street_hits": street_hits,
        "taft_diagnostics": taft_diagnostics[:40],
        "claim_promoted": False,
        "eponym_inferred": False,
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
