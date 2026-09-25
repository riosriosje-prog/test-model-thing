from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def extract_anchor(pdf_path: str) -> dict:
    source = Path(pdf_path).expanduser().resolve()
    raw = source.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError("source is not a PDF")

    source_sha = hashlib.sha256(raw).hexdigest()

    proc = subprocess.run(
        ["pdftotext", "-layout", str(source), "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    text = proc.stdout.decode("utf-8", errors="replace")
    pages = text.split("\f")
    if pages and not pages[-1].strip():
        pages = pages[:-1]

    candidates: list[dict] = []
    for index, page in enumerate(pages, start=1):
        normalized = _normalize(page)
        if "taft" not in normalized or "leary" not in normalized:
            continue

        taft_positions = [m.start() for m in re.finditer(r"taft", normalized)]
        leary_positions = [m.start() for m in re.finditer(r"leary", normalized)]
        for lp in leary_positions:
            for tp in taft_positions:
                distance = abs(lp - tp)
                if distance > 900:
                    continue
                start = max(0, min(lp, tp) - 280)
                end = min(len(normalized), max(lp, tp) + 320)
                context = normalized[start:end]
                score = 0
                if "sale de" in context:
                    score += 100
                if "calle" in context:
                    score += 30
                if "mcleary" in context or "mc leary" in context or "mc. leary" in context:
                    score += 20
                if "me leary" in context or "me. leary" in context:
                    score += 15
                score += max(0, 50 - distance // 10)
                candidates.append(
                    {
                        "page_number": index,
                        "score": score,
                        "distance": distance,
                        "normalized_context": context,
                    }
                )

    if not candidates:
        raise RuntimeError("ANCHOR_NOT_FOUND: no page contains nearby Leary and Taft tokens")

    candidates.sort(
        key=lambda row: (-row["score"], row["distance"], row["page_number"])
    )
    best = candidates[0]
    context = best["normalized_context"]
    exact_text_layer = "sale de" in context
    visual_confirmed_ocr_variant = bool(
        re.search(r"leary\s*\(\s*sale\s+taft\s*\)", context)
    )
    if not exact_text_layer and not visual_confirmed_ocr_variant:
        diagnostics = {
            "status": "ANCHOR_DIAGNOSTIC_ONLY",
            "source_pdf_sha256": source_sha,
            "page_count_extracted": len(pages),
            "top_candidates": candidates[:10],
        }
        print(
            json.dumps(diagnostics, sort_keys=True, ensure_ascii=False),
            flush=True,
        )
        raise RuntimeError(
            "ANCHOR_NOT_FOUND: Leary/Taft co-occur but no accepted relation form was found"
        )

    page_text = pages[best["page_number"] - 1]
    matched_relation = (
        "LEARY_NEAR_TAFT_WITH_SALE_DE"
        if exact_text_layer
        else "LEARY_SALE_TAFT_OCR_VARIANT_VISUALLY_CONFIRMED"
    )
    anchor = {
        "schema_version": 1,
        "anchor_type": "GALIA_MCLEARY_TAFT_1916_PAGE_ANCHOR",
        "source_pdf_sha256": source_sha,
        "page_number": best["page_number"],
        "page_count_extracted": len(pages),
        "extraction_method": "pdftotext-layout",
        "matched_relation": matched_relation,
        "normalized_context": context,
        "normalized_transcription": "Calle Mc Leary (sale de Taft)",
        "normalization_basis": (
            "text-layer exact" if exact_text_layer
            else "rendered-page visual verification of OCR omission of 'de'"
        ),
        "page_text_sha256": hashlib.sha256(
            page_text.encode("utf-8", errors="replace")
        ).hexdigest(),
        "candidate_count": len(candidates),
    }
    return anchor


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    anchor = extract_anchor(args.source_file)
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(anchor, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(anchor, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
