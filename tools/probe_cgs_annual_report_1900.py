#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

import fitz

TITLE = "Report of the Superintendent of the Coast and Geodetic Survey showing the progress of the work from July 1, 1899, to June 30, 1900"
QUERIES = [
    'title:("Report of the Superintendent") AND title:("Coast and Geodetic Survey")',
    'title:("Coast and Geodetic Survey") AND (year:1900 OR year:1901)',
    'creator:("U.S. Coast and Geodetic Survey") AND (year:1900 OR year:1901)',
    'identifier:reportofsuper* AND (year:1900 OR year:1901)',
]

NOAA_PDF_CANDIDATES = [
    "https://library.oarcloud.noaa.gov/docs.lib/htdocs/rescue/cgs/003_pdf/CSC-0103.PDF",
    "https://library.oarcloud.noaa.gov/docs.lib/htdocs/rescue/cgs/003_pdf/CSC-0104.PDF",
    "https://library.oarcloud.noaa.gov/docs.lib/htdocs/rescue/cgs/003_pdf/CSC-0105.PDF",
    "https://docs.lib.noaa.gov/rescue/cgs/003_pdf/CSC-0103.PDF",
    "https://docs.lib.noaa.gov/rescue/cgs/003_pdf/CSC-0104.PDF",
    "https://docs.lib.noaa.gov/rescue/cgs/003_pdf/CSC-0105.PDF",
]

TERMS = [
    "PORTO RICO",
    "PUERTO RICO",
    "FORNEY",
    "BASE LINE",
    "BASE-LINE",
    "SAN JUAN",
    "SOUTH BASE",
    "NORTH BASE",
    "PONCE",
]


def get_json(url: str):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GALIA-SouthBase-AnnualReport-Probe/0.1 (+read-only research validation)"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get_bytes(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "GALIA-SouthBase-AnnualReport-Probe/0.1 (+read-only research validation)"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def windows(text: str, term: str, radius: int = 1800):
    out = []
    upper = text.upper()
    pos = 0
    while True:
        i = upper.find(term.upper(), pos)
        if i < 0:
            break
        a = max(0, i - radius)
        b = min(len(text), i + len(term) + radius)
        out.append({"offset": i, "text": text[a:b]})
        pos = i + len(term)
        if len(out) >= 50:
            break
    return out


def candidate_score(doc: dict) -> int:
    title = str(doc.get("title") or "").lower()
    year = str(doc.get("year") or doc.get("date") or "")
    score = 0
    if "coast and geodetic survey" in title:
        score += 5
    if "superintendent" in title:
        score += 4
    if "1899" in title and "1900" in title:
        score += 6
    if "1901" in year:
        score += 2
    return score


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="research/gates/derived/south_base_annual_report_1900_probe.v0_1.json")
    args = ap.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    receipt = {
        "schema_version": "galia.south_base_annual_report_probe.v1",
        "mode": "READ_ONLY_DISCOVERY",
        "target_title": TITLE,
        "search_queries": QUERIES,
        "status": "SEARCH_FAILED",
        "candidates": [],
        "noaa_pdf_candidates": [],
    }

    try:
        # Prefer NOAA's own digitized report if the historical file numbering can be resolved.
        selected_noaa = None
        for url in NOAA_PDF_CANDIDATES:
            row = {"url": url, "status": "FETCH_FAILED"}
            try:
                payload = get_bytes(url)
                row["byte_size"] = len(payload)
                row["sha256"] = hashlib.sha256(payload).hexdigest()
                if not payload.startswith(b"%PDF"):
                    row["status"] = "NOT_PDF"
                    receipt["noaa_pdf_candidates"].append(row)
                    continue
                doc = fitz.open(stream=payload, filetype="pdf")
                row["page_count"] = doc.page_count
                head_pages = []
                for pno in range(min(8, doc.page_count)):
                    head_pages.append(doc.load_page(pno).get_text("text"))
                head = "\n".join(head_pages)
                row["head_text"] = normalize(head)[:12000]
                h = head.upper()
                title_match = (
                    "COAST AND GEODETIC SURVEY" in h
                    and "JULY 1, 1899" in h
                    and ("JUNE 30, 1900" in h or "JUNE 30 1900" in h)
                )
                row["target_title_match"] = title_match
                row["status"] = "FETCHED"
                receipt["noaa_pdf_candidates"].append(row)
                if title_match and selected_noaa is None:
                    selected_noaa = (url, payload, doc, row)
            except Exception as exc:
                row["error"] = f"{type(exc).__name__}: {exc}"
                receipt["noaa_pdf_candidates"].append(row)

        if selected_noaa is not None:
            url, payload, doc, row = selected_noaa
            all_text_parts = []
            for pno in range(doc.page_count):
                all_text_parts.append(doc.load_page(pno).get_text("text"))
            text = "\n".join(all_text_parts)
            receipt["selected"] = {
                "source": "NOAA",
                "url": url,
                "pdf_sha256": row["sha256"],
                "pdf_bytes": row["byte_size"],
                "page_count": row["page_count"],
            }
            receipt["hits"] = {term: windows(text, term) for term in TERMS}
            pr_contexts = []
            for w in receipt["hits"].get("PORTO RICO", []) + receipt["hits"].get("PUERTO RICO", []):
                norm = normalize(w["text"])
                upper = norm.upper()
                if any(k in upper for k in ("FORNEY", "BASE LINE", "BASE-LINE", "TRIANGULATION", "SAN JUAN", "PONCE")):
                    pr_contexts.append(norm)
            seen = set()
            unique = []
            for x in pr_contexts:
                key = x[:800]
                if key not in seen:
                    seen.add(key)
                    unique.append(x)
            receipt["porto_rico_key_contexts"] = unique[:60]
            receipt["literal_flags"] = {
                "south_base": "SOUTH BASE" in text.upper(),
                "north_base": "NORTH BASE" in text.upper(),
                "forney": "FORNEY" in text.upper(),
                "san_juan": "SAN JUAN" in text.upper(),
                "base_line": "BASE LINE" in text.upper() or "BASE-LINE" in text.upper(),
            }
            receipt["status"] = "FETCHED_AND_INDEXED_NOAA"
            out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True)+"\n", encoding="utf-8")
            print("ANNUAL1900_STATUS=" + receipt["status"])
            print("ANNUAL1900_NOAA_URL=" + url)
            print("ANNUAL1900_PDF_SHA256=" + row["sha256"])
            print("ANNUAL1900_PAGE_COUNT=" + str(row["page_count"]))
            for k,v in receipt["literal_flags"].items():
                print("ANNUAL1900_LITERAL_" + k.upper() + "=" + str(v))
            for i, ctx in enumerate(receipt.get("porto_rico_key_contexts", []), 1):
                print(f"ANNUAL1900_PR_CONTEXT_{i}=" + ctx[:7000])
            return

        # Fall back to catalog discovery if NOAA numbering does not resolve the target.
        merged = {}
        search_urls = []
        for query in QUERIES:
            q = urllib.parse.urlencode({
                "q": query,
                "fl[]": ["identifier", "title", "date", "year", "creator", "description"],
                "rows": "200",
                "page": "1",
                "output": "json",
            }, doseq=True)
            search_url = "https://archive.org/advancedsearch.php?" + q
            search_urls.append(search_url)
            data = get_json(search_url)
            for doc in data.get("response", {}).get("docs", []):
                ident = doc.get("identifier")
                if ident:
                    merged[ident] = doc
        receipt["search_urls"] = search_urls
        candidates = sorted(
            [{**d, "_score": candidate_score(d)} for d in merged.values()],
            key=lambda d: (-d["_score"], str(d.get("identifier"))),
        )
        receipt["candidates"] = candidates
        for cand in candidates[:50]:
            print("ANNUAL1900_CANDIDATE=" + json.dumps({
                "identifier": cand.get("identifier"),
                "title": cand.get("title"),
                "date": cand.get("date"),
                "year": cand.get("year"),
                "score": cand.get("_score"),
            }, ensure_ascii=False, sort_keys=True))
        selected = next((d for d in candidates if d["_score"] >= 9), None)
        if not selected:
            receipt["status"] = "NO_CANDIDATE"
            out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True)+"\n")
            print("ANNUAL1900_STATUS=NO_CANDIDATE")
            return

        ident = selected["identifier"]
        meta_url = f"https://archive.org/metadata/{urllib.parse.quote(ident)}"
        meta = get_json(meta_url)
        files = meta.get("files", [])

        def file_name_candidates():
            preferred = []
            for f in files:
                name = f.get("name", "")
                lower = name.lower()
                if lower.endswith("_djvu.txt"):
                    preferred.append((0, name))
                elif lower.endswith(".txt") and "full text" in str(f.get("format","")).lower():
                    preferred.append((1, name))
                elif lower.endswith(".txt"):
                    preferred.append((2, name))
            return [n for _, n in sorted(preferred)]

        txt_names = file_name_candidates()
        receipt["selected"] = {
            "identifier": ident,
            "title": selected.get("title"),
            "date": selected.get("date"),
            "metadata_url": meta_url,
            "text_candidates": txt_names,
        }
        if not txt_names:
            receipt["status"] = "CANDIDATE_NO_TEXT"
            out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True)+"\n")
            print("ANNUAL1900_STATUS=CANDIDATE_NO_TEXT")
            return

        txt_name = txt_names[0]
        txt_url = f"https://archive.org/download/{urllib.parse.quote(ident)}/{urllib.parse.quote(txt_name)}"
        payload = get_bytes(txt_url)
        text = payload.decode("utf-8", errors="replace")
        receipt["selected"]["text_name"] = txt_name
        receipt["selected"]["text_url"] = txt_url
        receipt["selected"]["text_sha256"] = hashlib.sha256(payload).hexdigest()
        receipt["selected"]["text_bytes"] = len(payload)

        hits = {term: windows(text, term) for term in TERMS}
        receipt["hits"] = hits

        # Pull only contexts that mention Puerto Rico plus our key technical words.
        pr_contexts = []
        for w in hits.get("PORTO RICO", []) + hits.get("PUERTO RICO", []):
            norm = normalize(w["text"])
            upper = norm.upper()
            if any(k in upper for k in ("FORNEY", "BASE LINE", "BASE-LINE", "TRIANGULATION", "SAN JUAN", "PONCE")):
                pr_contexts.append(norm)
        # de-duplicate preserving order
        seen = set()
        unique = []
        for x in pr_contexts:
            key = x[:800]
            if key not in seen:
                seen.add(key)
                unique.append(x)
        receipt["porto_rico_key_contexts"] = unique[:40]

        receipt["literal_flags"] = {
            "south_base": "SOUTH BASE" in text.upper(),
            "north_base": "NORTH BASE" in text.upper(),
            "forney": "FORNEY" in text.upper(),
            "san_juan": "SAN JUAN" in text.upper(),
            "base_line": "BASE LINE" in text.upper() or "BASE-LINE" in text.upper(),
        }
        receipt["status"] = "FETCHED_AND_INDEXED"

    except Exception as exc:
        receipt["error"] = f"{type(exc).__name__}: {exc}"

    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True)+"\n", encoding="utf-8")
    print("ANNUAL1900_STATUS=" + receipt["status"])
    sel = receipt.get("selected", {})
    if sel:
        print("ANNUAL1900_IDENTIFIER=" + str(sel.get("identifier","")))
        print("ANNUAL1900_TEXT_SHA256=" + str(sel.get("text_sha256","")))
    for k,v in receipt.get("literal_flags", {}).items():
        print("ANNUAL1900_LITERAL_" + k.upper() + "=" + str(v))
    for i, ctx in enumerate(receipt.get("porto_rico_key_contexts", []), 1):
        print(f"ANNUAL1900_PR_CONTEXT_{i}=" + ctx[:7000])


if __name__ == "__main__":
    main()
