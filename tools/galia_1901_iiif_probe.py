"""Read-only-by-default LOC IIIF candidate probe for the 1901 Loíza case.

The Library of Congress IIIF image service is a *candidate retrieval route*
for the two published page locators already registered in GALIA PR #121.
The generated image URLs have NOT been successfully fetched or validated
against the 1901 pages in this research environment.

Default invocation has NO network or disk writes:
    python tools/galia_1901_iiif_probe.py

An operator may explicitly attempt retrieval; this writes files ONLY to
the chosen output directory, never into the GALIA canonical database:
    python tools/galia_1901_iiif_probe.py --fetch --output-dir ./quarantine

A successful JPEG transfer is a RAW-BYTES receipt, NOT a historian's
authentication of the newspaper, page identity, text, legal date, or
street alignment. Human review and source/custodian checks remain required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "research/gates/loiza_1940_1947_documentary_crossings.v0_1.json"
)
IIIF_HOST = "tile.loc.gov"
IIIF_BASE = "https://tile.loc.gov/image-services/iiif/"
MAX_JPEG_BYTES = 25 * 1024 * 1024
ISSUES = {
    "1901-01-23": {
        "page_file": "0077",
        "issue_folder": "1901012301",
        "source_id": "LOC-GACETA-1901-01-23-0077",
    },
    "1901-01-24": {
        "page_file": "0080",
        "issue_folder": "1901012401",
        "source_id": "LOC-GACETA-1901-01-24-0080",
    },
}


def iiif_candidate_url(date: str) -> str:
    """Deterministic URL candidate from LOC NDNP path, *not* an access claim."""
    issue = ISSUES[date]
    resource = ":".join((
        "service", "ndnp", "prru", "batch_prru_galleta_ver01", "data",
        "2013201074", "00415662968", issue["issue_folder"],
        issue["page_file"],
    ))
    return IIIF_BASE + resource + "/full/pct:25/0/default.jpg"


def iiif_candidate_info_url(date: str) -> str:
    """Unverified IIIF metadata endpoint, never a source-image receipt."""
    return iiif_candidate_url(date).rsplit("/full/", 1)[0] + "/info.json"


def validate_manifest() -> dict:
    """Refuse capture if tracked LOC source attribution or authority drifted."""
    record = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if (
        record["state"] != "AUTHORITY_HOLD"
        or record["canonical_write_authorized"] is not False
        or record["raw_capture_complete"] is not False
    ):
        raise ValueError("GALIA source authority gate changed")
    sources = {x["source_id"]: x for x in record["sources"]}
    for date, candidate in ISSUES.items():
        source = sources.get(candidate["source_id"])
        expected_fragment = (
            f"/00415662968/{candidate['issue_folder']}/"
            f"{candidate['page_file']}.pdf"
        )
        if (
            not source
            or source["reported_edition_date"] != date
            or expected_fragment not in source["url"]
            or source["source_binary_sha256"] is not None
            or source["source_bytes_retained"] is not False
            or source["discovery_mode"] !=
               "LOC_NEWSPAPER_SEARCH_INDEX_OCR_NO_PAGE_CAPTURE"
        ):
            raise ValueError(f"source locator/authority drift for {date}")
    plan = record["archive_acquisition_plan_1901"]
    if (
        plan["request_submission_status"] != "NOT_SENT"
        or plan["source_material_received"] is not False
        or plan["source_original_image_inspected"] is not False
        or plan["library_of_congress_crosswalk"][
            "reel_number_authenticated_for_target_jan23_jan24_images"
        ] is not False
    ):
        raise ValueError("unverified source access elevated without review")
    return record


class RejectRedirects(HTTPRedirectHandler):
    """Refuse redirects before any HTTP request to the Location target."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def no_redirect_open(request, timeout):
    """Always fetch using an opener that refuses HTTP redirects."""
    return build_opener(RejectRedirects()).open(request, timeout=timeout)


def read_jpeg(url: str, *, opener=None, maximum: int = MAX_JPEG_BYTES) -> bytes:
    """Retrieve bounded JPEG bytes only from exact LOC IIIF host."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != IIIF_HOST:
        raise ValueError("not a Library of Congress HTTPS IIIF host")
    if not url.startswith(IIIF_BASE):
        raise ValueError("unexpected image service path")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("credential/port in source URL")
    resource_path = unquote(parsed.path.split("/")[3])
    if not resource_path.startswith("service:ndnp:prru:batch_prru_galleta_ver01:"):
        raise ValueError("unexpected IIIF source identity")
    # Identify GALIA to the custodial service rather than Python-urllib.
    request = Request(url, headers={
        "User-Agent": "GALIA-Historical-Research/0.1",
        "Accept": "image/jpeg",
    })
    with (opener or no_redirect_open)(request, timeout=30) as response:
        status = getattr(response, "status", 200)
        final_url = response.geturl()
        if status != 200 or final_url != url:
            raise ValueError("non-200 or redirected source response")
        content_type = response.headers.get("Content-Type", "").split(";")[0].lower()
        if content_type != "image/jpeg":
            raise ValueError("source response is not image/jpeg")
        content = response.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("source JPEG exceeds the size limit")
    if len(content) < 1024 or not (
        content.startswith(b"\xff\xd8\xff") and content.endswith(b"\xff\xd9")
    ):
        raise ValueError("source response has invalid JPEG framing")
    return content


def atomic_write_bytes(destination: Path, data: bytes) -> None:
    """Persist after validation, or leave no partial image on failure."""
    # Fail closed on symlinked quarantine paths (including dangling leaves).
    # This is a local preflight guard, not a substitute for dirfd-based
    # O_NOFOLLOW isolation against hostile concurrent path replacement.
    for parent in (destination.parent, *destination.parent.parents):
        if parent.is_symlink():
            raise ValueError("symlinked quarantine directory is forbidden")
    if destination.is_symlink():
        raise ValueError("symlinked quarantine destination is forbidden")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"refusing to overwrite {destination}")
    with tempfile.NamedTemporaryFile(
        prefix=".galia-iiif-", dir=destination.parent, delete=False
    ) as handle:
        temp_path = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        except BaseException:
            temp_path.unlink(missing_ok=True)
            raise
    # Linking a completed temp file into a new pathname is atomic and
    # fails if another process has created that pathname in the meantime.
    # Path.rename() can overwrite an existing destination on POSIX.
    try:
        os.link(temp_path, destination)
    finally:
        temp_path.unlink(missing_ok=True)


def capture_candidate(date: str, output_dir: Path, *, opener=None) -> dict:
    """Return a quarantine receipt; never call the canonical HistoricalStore."""
    url = iiif_candidate_url(date)
    data = read_jpeg(url, opener=opener)
    image_path = output_dir / f"gaceta_{date}_page3_candidate.jpg"
    receipt_path = output_dir / f"gaceta_{date}_page3_candidate.receipt.json"
    # Orphaned image from a prior interrupted capture must never be
    # interpreted as a completed image/receipt transaction.
    if image_path.exists() and not receipt_path.exists():
        raise RuntimeError("incomplete prior quarantine capture: image without receipt")
    if receipt_path.exists() and not image_path.exists():
        raise RuntimeError("incomplete prior quarantine capture: receipt without image")
    if receipt_path.exists() or image_path.exists() or receipt_path.is_symlink() or image_path.is_symlink():
        raise FileExistsError("candidate image or receipt already exists")
    receipt = {
        "receipt_version": "galia.iiif.binary_receipt.v0.1",
        "document_id": f"GACETA-{date}-ED1-P3",
        "source_id": ISSUES[date]["source_id"],
        "locator": url,
        "status": "RAW_BYTES_RECEIVED_PENDING_VISUAL_REVIEW",
        "retrieved_jpeg_sha256": hashlib.sha256(data).hexdigest(),
        "retrieved_jpeg_bytes": len(data),
        "local_image_filename": image_path.name,
        "original_source_custody_authenticated": False,
        "printed_issue_date_verified": False,
        "page_number_verified": False,
        "notice_columns_visually_reviewed": False,
        "historical_human_review_complete": False,
        "canonical_write_authorized": False,
        "legal_street_naming_act_verified": False,
        "source_document_event_date": None,
        "geometry": None,
        "source_type": "IIIF derived JPEG candidate, not original JP2 or PDF",
    }
    atomic_write_bytes(image_path, data)
    try:
        # Verify persisted bytes before publishing a companion receipt.
        # A receipt is never a substitute for checking source custody.
        if (hashlib.sha256(image_path.read_bytes()).hexdigest()
                != receipt["retrieved_jpeg_sha256"]):
            raise ValueError("quarantine image digest mismatch")
        atomic_write_bytes(
            receipt_path,
            (json.dumps(receipt, indent=2, ensure_ascii=False) + "\n").encode(),
        )
    except BaseException:
        image_path.unlink(missing_ok=True)
        raise
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", choices=tuple(ISSUES), action="append")
    parser.add_argument(
        "--fetch", action="store_true",
        help="Explicitly fetch candidate JPEGs to local quarantine only",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("quarantine/loiza-1901"),
    )
    args = parser.parse_args()
    validate_manifest()
    dates = list(dict.fromkeys(args.date or tuple(ISSUES)))
    if not args.fetch:
        print(json.dumps({
            "state": "LOCATOR_ONLY",
            "network_access_attempted": False,
            "filesystem_modified": False,
            "candidate_iiif_urls": {date: iiif_candidate_url(date)
                                    for date in dates},
            "candidate_iiif_metadata_urls": {date: iiif_candidate_info_url(date)
                                             for date in dates},
            "historical_authority": "AUTHORITY_HOLD",
        }, indent=2))
        return 0

    failures = 0
    for date in dates:
        try:
            receipt = capture_candidate(date, args.output_dir)
            print(json.dumps(receipt, ensure_ascii=False))
        except Exception as exc:
            failures += 1
            print(json.dumps({
                "document_id": f"GACETA-{date}-ED1-P3",
                "locator": iiif_candidate_url(date),
                "status": "REMOTE_BLOCKED_NO_SOURCE_BYTES",
                "error": str(exc),
                "source_original_image_received": False,
                "canonical_write_authorized": False,
            }, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
