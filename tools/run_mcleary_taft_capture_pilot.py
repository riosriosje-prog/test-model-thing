from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from historical_artifacts import HistoricalArtifactStore
from historical_store import HistoricalStore
from historical_store_bundle import semantic_fingerprint, write_bundle_atomic
from pilots.mcleary_taft_acceptance import (
    UFDC_MCLEARY_TAFT_1916_URL,
    seed_mcleary_taft_acceptance,
)


def run_pilot(source_file: str, anchor_file: str, output_dir: str) -> dict:
    source = Path(source_file).expanduser().resolve()
    anchor_path = Path(anchor_file).expanduser().resolve()
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    raw = source.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError("McLeary/Taft capture is not a PDF")
    raw_sha = hashlib.sha256(raw).hexdigest()

    anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    if anchor.get("anchor_type") != "GALIA_MCLEARY_TAFT_1916_PAGE_ANCHOR":
        raise ValueError("unexpected page-anchor type")
    if anchor.get("source_pdf_sha256") != raw_sha:
        raise ValueError("page anchor is not bound to exact raw PDF bytes")
    page_number = anchor.get("page_number")
    if not isinstance(page_number, int) or page_number < 1:
        raise ValueError("page anchor has invalid page number")
    context = str(anchor.get("normalized_context") or "")
    if not all(token in context for token in ("leary", "taft", "sale de")):
        raise ValueError("page anchor does not establish the expected street relation")

    db_path = out / "mcleary_taft_shadow.sqlite3"
    artifact_root = out / "artifact_store"
    bundle_path = out / "mcleary_taft_shadow.bundle.json"

    with HistoricalStore(str(db_path)) as store:
        ids = seed_mcleary_taft_acceptance(store)
        relation_claim_id = ids["relation_claim_id"]
        nominative_claim_id = ids["nominative_claim_id"]
        document_id = ids["document_id"]

        blockers_before = store.claim_promotion_blockers(relation_claim_id)
        if [b["code"] for b in blockers_before] != ["RAW_CAPTURE_REQUIRED"]:
            raise AssertionError(
                f"Unexpected blockers before capture: {blockers_before!r}"
            )

        nominative_before = store.claim_bundle(nominative_claim_id)
        if nominative_before["evidence"]:
            raise AssertionError("nominative hypothesis unexpectedly has evidence")

        artifact_store = HistoricalArtifactStore(str(artifact_root))
        artifact = artifact_store.capture_file(str(source))
        if artifact.sha256 != raw_sha:
            raise AssertionError("Artifact-store digest mismatch")

        representation_id = artifact_store.bind_document(
            store,
            document_id,
            artifact,
            representation_type="scanned_newspaper_issue_pdf",
            mime_type="application/pdf",
            source_url=UFDC_MCLEARY_TAFT_1916_URL,
            preferred_for_review=True,
            metadata={
                "pilot": "mcleary-taft-1916-raw-capture",
                "custodian": "University of Florida Digital Collections / dLOC",
                "page_anchor_method": anchor["extraction_method"],
                "page_anchor": page_number,
                "page_text_sha256": anchor["page_text_sha256"],
            },
            representation_id="repr_mcleary_taft_1916_raw_pdf",
        )

        excerpt = context.encode("utf-8")
        store.add_evidence(
            claim_id=relation_claim_id,
            document_id=document_id,
            representation_id=representation_id,
            role="supports",
            locator=f"{UFDC_MCLEARY_TAFT_1916_URL}#page={page_number}",
            excerpt=excerpt,
            metadata={
                "evidence_state": "RAW_SCAN_PAGE_ANCHORED",
                "raw_capture_verified": True,
                "page_anchor_verified": True,
                "page_number": page_number,
                "extraction_method": anchor["extraction_method"],
                "page_text_sha256": anchor["page_text_sha256"],
            },
            evidence_id="evd_mcleary_taft_1916_raw_page_anchor",
        )

        blockers_after = store.claim_promotion_blockers(relation_claim_id)
        if blockers_after:
            raise AssertionError(
                f"Raw capture did not clear relation blocker: {blockers_after!r}"
            )

        relation_status = store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (relation_claim_id,),
        ).fetchone()["status"]
        nominative_status = store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (nominative_claim_id,),
        ).fetchone()["status"]
        if relation_status != "PROPOSED" or nominative_status != "PROPOSED":
            raise AssertionError("raw capture must not auto-promote historical claims")

        nominative_after = store.claim_bundle(nominative_claim_id)
        if nominative_after["evidence"]:
            raise AssertionError(
                "relation evidence must not bleed into nominative/eponym hypothesis"
            )

        semantic_digest = semantic_fingerprint(store)
        bundle_digest = write_bundle_atomic(store, str(bundle_path))
        health = store.health()

    receipt = {
        "schema_version": 1,
        "receipt_type": "GALIA_MCLEARY_TAFT_1916_RAW_CAPTURE_PILOT",
        "status": "RAW_PRIMARY_SOURCE_PAGE_ANCHOR_PASS",
        "source": {
            "date": "1916-03-08",
            "custodian": "University of Florida Digital Collections / dLOC",
            "source_url": UFDC_MCLEARY_TAFT_1916_URL,
            "raw_pdf_sha256": raw_sha,
            "raw_pdf_size_bytes": len(raw),
            "page_number": page_number,
            "page_count_extracted": anchor["page_count_extracted"],
            "page_text_sha256": anchor["page_text_sha256"],
            "extraction_method": anchor["extraction_method"],
            "matched_relation": anchor["matched_relation"],
        },
        "historical_store": {
            "schema_version": health["schema_version"],
            "integrity_check": health["integrity_check"],
            "document_id": document_id,
            "relation_claim_id": relation_claim_id,
            "nominative_claim_id": nominative_claim_id,
            "raw_representation_id": representation_id,
            "promotion_blockers_before_capture": blockers_before,
            "promotion_blockers_after_capture": blockers_after,
            "relation_claim_status_after_capture": relation_status,
            "nominative_claim_status_after_capture": nominative_status,
            "claim_promotion_executed": False,
            "bundle_sha256": bundle_digest,
            "semantic_fingerprint_sha256": semantic_digest,
        },
        "authority": {
            "raw_capture_verified": True,
            "page_anchor_verified": True,
            "relation_objective_gate_satisfied": True,
            "nominative_act_gate_satisfied": False,
            "human_canonical_review_executed": False,
            "canonical_promotion_executed": False,
        },
    }

    receipt_path = out / "CAPTURE_PILOT_RECEIPT.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-file", required=True)
    parser.add_argument("--anchor-file", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    receipt = run_pilot(args.source_file, args.anchor_file, args.output_dir)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
