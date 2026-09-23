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
    locator: str | None = None
    mime_type: str | None = None
    content_sha256: str | None = None
    byte_length: int | None = None
    preferred_for_review: bool = False


def record_acquisition_state(
    store: HistoricalStore,
    *,
    document_id: str,
    receipt: AcquisitionReceipt,
) -> str:
    """Register one independently auditable representation of a document.

    Document identity is distinct from representation identity. A scan, OCR,
    IIIF image, transcription, or blocked remote locator may coexist without
    overwriting each other. Only RAW_CAPTURED may assert possession of raw
    source bytes.
    """
    locator = receipt.locator or receipt.source_url
    return store.register_document_representation(
        document_id=document_id,
        representation_type=receipt.representation_type,
        acquisition_state=receipt.state,
        locator=locator,
        mime_type=receipt.mime_type,
        content_sha256=receipt.content_sha256,
        byte_length=receipt.byte_length,
        source_url=receipt.source_url,
        raw_artifact=receipt.raw_artifact,
        preferred_for_review=receipt.preferred_for_review,
        metadata={"note": receipt.note} if receipt.note is not None else None,
    )
