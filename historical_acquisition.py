from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from historical_store import HistoricalStore

AcquisitionState = Literal[
    "RAW_CAPTURED",
    "TEXT_SURROGATE",
    "REMOTE_BLOCKED",
    "LOCATOR_ONLY",
    "QUARANTINED",
]


@dataclass(frozen=True)
class AcquisitionReceipt:
    state: AcquisitionState
    source_url: str
    representation_type: str
    raw_artifact: bool
    note: str | None = None


def record_acquisition_state(
    store: HistoricalStore,
    *,
    document_id: str,
    receipt: AcquisitionReceipt,
) -> None:
    """Record acquisition state without overstating evidentiary custody.

    A document may be known and locatable before its raw bytes are captured.
    Only RAW_CAPTURED may assert raw_artifact=True.
    """
    if receipt.raw_artifact and receipt.state != "RAW_CAPTURED":
        raise ValueError(
            "Only RAW_CAPTURED may assert possession of raw source bytes"
        )
    if receipt.state == "RAW_CAPTURED" and not receipt.raw_artifact:
        raise ValueError(
            "RAW_CAPTURED requires raw_artifact=True"
        )

    with store.transaction():
        row = store.conn.execute(
            "SELECT document_id FROM documents WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown document_id: {document_id}")

        metadata_row = store.conn.execute(
            "SELECT metadata_json FROM documents WHERE document_id = ?",
            (document_id,),
        ).fetchone()
        import json
        metadata = json.loads(metadata_row["metadata_json"] or "{}")
        metadata["acquisition"] = {
            "state": receipt.state,
            "source_url": receipt.source_url,
            "representation_type": receipt.representation_type,
            "raw_artifact": receipt.raw_artifact,
            "note": receipt.note,
        }
        store.conn.execute(
            "UPDATE documents SET metadata_json = ? WHERE document_id = ?",
            (
                json.dumps(
                    metadata,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
                document_id,
            ),
        )
        store._audit(
            "document_acquisition_state_recorded",
            object_type="document",
            object_id=document_id,
            payload=metadata["acquisition"],
        )
