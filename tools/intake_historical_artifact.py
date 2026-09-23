from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from historical_artifacts import HistoricalArtifactStore
from historical_store import HistoricalStore


def intake_historical_artifact(
    *,
    database_path: str,
    artifact_root: str,
    document_id: str,
    file_path: str,
    representation_type: str,
    mime_type: str | None = None,
    source_url: str | None = None,
    preferred_for_review: bool = True,
    claim_id: str | None = None,
) -> dict[str, Any]:
    """Capture and bind a user/custodian-supplied historical artifact.

    This function deliberately performs no claim promotion. If claim_id is
    supplied, it reports the objective promotion blockers after capture.
    """
    source_file = Path(file_path).expanduser().resolve()
    if not source_file.is_file():
        raise FileNotFoundError(source_file)

    with HistoricalStore(database_path) as store:
        artifact_store = HistoricalArtifactStore(artifact_root)
        artifact = artifact_store.capture_file(str(source_file))
        representation_id = artifact_store.bind_document(
            store,
            document_id,
            artifact,
            representation_type=representation_type,
            mime_type=mime_type,
            source_url=source_url,
            preferred_for_review=preferred_for_review,
            metadata={
                "intake_method": "supplied_file",
                "source_filename": source_file.name,
            },
        )

        result: dict[str, Any] = {
            "status": "RAW_CAPTURED",
            "document_id": document_id,
            "representation_id": representation_id,
            "representation_type": representation_type,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "artifact_locator": artifact.locator,
            "source_url": source_url,
            "claim_promotion_executed": False,
        }
        if claim_id is not None:
            result["claim_id"] = claim_id
            result["promotion_blockers"] = store.claim_promotion_blockers(
                claim_id
            )
            claim = store.conn.execute(
                "SELECT status FROM claims WHERE claim_id = ?",
                (claim_id,),
            ).fetchone()
            if claim is None:
                raise KeyError(f"Unknown claim_id: {claim_id}")
            result["claim_status"] = claim["status"]
        return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture a supplied historical artifact into the GALIA "
            "content-addressed object store and bind it to a document."
        )
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--document-id", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--representation-type", required=True)
    parser.add_argument("--mime-type")
    parser.add_argument("--source-url")
    parser.add_argument("--claim-id")
    parser.add_argument(
        "--not-preferred-for-review",
        action="store_true",
        help="Do not mark this representation as preferred for review.",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    result = intake_historical_artifact(
        database_path=args.database,
        artifact_root=args.artifact_root,
        document_id=args.document_id,
        file_path=args.file,
        representation_type=args.representation_type,
        mime_type=args.mime_type,
        source_url=args.source_url,
        preferred_for_review=not args.not_preferred_for_review,
        claim_id=args.claim_id,
    )
    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
