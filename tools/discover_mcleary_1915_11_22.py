from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def inspect_pdf(pdf_path: str, source_url: str, folder: int) -> dict:
    p = Path(pdf_path)
    raw = p.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError("downloaded object is not a PDF")

    proc = subprocess.run(
        ["pdftotext", "-layout", str(p), "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    text = proc.stdout.decode("utf-8", errors="replace")
    pages = text.split("\f")
    if pages and not pages[-1].strip():
        pages = pages[:-1]

    hits = []
    for page_number, page in enumerate(pages, start=1):
        n = _norm(page)
        for token in ("mcleary", "mc leary", "mc. leary", "me leary", "leary"):
            pos = n.find(token)
            if pos >= 0:
                start = max(0, pos - 320)
                end = min(len(n), pos + 520)
                hits.append(
                    {
                        "page_number": page_number,
                        "token": token,
                        "context": n[start:end],
                    }
                )
                break

    result = {
        "schema_version": 1,
        "discovery_type": "GALIA_MCLEARY_1915_11_22_UFDC_DISCOVERY",
        "source_url": source_url,
        "ufdc_folder": folder,
        "raw_pdf_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_pdf_size_bytes": len(raw),
        "page_count_extracted": len(pages),
        "leary_hits": hits,
        "historical_claim_promoted": False,
        "nominative_act_inferred": False,
    }
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--folder", required=True, type=int)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    result = inspect_pdf(args.pdf, args.source_url, args.folder)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
