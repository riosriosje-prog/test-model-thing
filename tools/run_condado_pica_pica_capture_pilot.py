from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from historical_artifacts import HistoricalArtifactStore
from historical_store import HistoricalStore
from historical_store_bundle import write_bundle_atomic
from pilots.condado_shadow import (
    PICA_PICA_CONDADO_1908_URL,
    seed_condado_shadow,
)


def run_pilot(source_file: str, output_dir: str) -> dict:
    source = Path(source_file).expanduser().resolve()
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    raw = source.read_bytes()
    if not raw.startswith(b"%PDF-"):
        raise ValueError("Pica-Pica capture is not a PDF")
    raw_sha = hashlib.sha256(raw).hexdigest()

    db_path = out / "condado_pica_pica_shadow.sqlite3"
    artifact_root = out / "artifact_store"
    bundle_path = out / "condado_pica_pica_shadow.bundle.json"

    with HistoricalStore(str(db_path)) as store:
        ids = seed_condado_shadow(store)
        claim_id = ids["pica_claim_id"]
        document_id = ids["pica_document_id"]

        blockers_before = store.claim_promotion_blockers(claim_id)
        if [b["code"] for b in blockers_before] != ["RAW_CAPTURE_REQUIRED"]:
            raise AssertionError(
                f"Unexpected blockers before capture: {blockers_before!r}"
            )

        artifact_store = HistoricalArtifactStore(str(artifact_root))
        artifact = artifact_store.capture_file(str(source))
        if artifact.sha256 != raw_sha:
            raise AssertionError("Artifact store digest mismatch")

        representation_id = artifact_store.bind_document(
            store,
            document_id,
            artifact,
            representation_type="scanned_newspaper_page_pdf",
            mime_type="application/pdf",
            source_url=PICA_PICA_CONDADO_1908_URL,
            preferred_for_review=True,
            metadata={
                "pilot": "condado-pica-pica-1908-raw-capture",
                "custodian": "University of Florida Digital Collections / dLOC",
            },
        )

        store.add_evidence(
            claim_id=claim_id,
            document_id=document_id,
            representation_id=representation_id,
            role="supports",
            locator=PICA_PICA_CONDADO_1908_URL,
            metadata={
                "evidence_state": "RAW_SCAN_BOUND",
                "raw_capture_verified": True,
            },
        )

        blockers_after = store.claim_promotion_blockers(claim_id)
        if blockers_after:
            raise AssertionError(
                f"Raw capture did not clear objective blocker: {blockers_after!r}"
            )

        claim_status = store.conn.execute(
            "SELECT status FROM claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()["status"]
        if claim_status != "PROPOSED":
            raise AssertionError(
                "Raw capture must not auto-promote historical claims"
            )

        bundle_digest = write_bundle_atomic(store, str(bundle_path))
        health = store.health()

    receipt = {
        "schema_version": 1,
        "receipt_type": "GALIA_CONDADO_PICA_PICA_1908_RAW_CAPTURE_PILOT",
        "status": "RAW_PRIMARY_SOURCE_CAPTURE_PASS",
        "source": {
            "title": "Pica-Pica",
            "date": "1908-05-09",
            "custodian": "University of Florida Digital Collections / dLOC",
            "source_url": PICA_PICA_CONDADO_1908_URL,
            "raw_pdf_sha256": raw_sha,
            "raw_pdf_size_bytes": len(raw),
        },
        "historical_store": {
            "schema_version": health["schema_version"],
            "integrity_check": health["integrity_check"],
            "document_id": document_id,
            "claim_id": claim_id,
            "raw_representation_id": representation_id,
            "promotion_blockers_before_capture": blockers_before,
            "promotion_blockers_after_capture": blockers_after,
            "claim_status_after_capture": claim_status,
            "claim_promotion_executed": False,
            "bundle_sha256": bundle_digest,
        },
        "authority": {
            "raw_capture_verified": True,
            "objective_promotion_gate_satisfied": True,
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
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    receipt = run_pilot(args.source_file, args.output_dir)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
