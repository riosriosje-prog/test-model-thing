from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from historical_store import HistoricalStore


@dataclass(frozen=True)
class ProposedClaim:
    predicate: str
    claim_text: str
    subject_entity_id: str | None = None
    object_entity_id: str | None = None
    object_value: str | None = None
    metadata: dict[str, Any] | None = None


class GaliaResearchBridge:
    """Application-boundary adapter between GALIA and HistoricalStore.

    The bridge deliberately does not alter model checkpoint semantics. Engine
    outputs are stored as provenance-linked PROPOSED claims. Human review in
    HistoricalStore is required for CANONICAL promotion.
    """

    def __init__(
        self,
        store: HistoricalStore,
        *,
        engine_version: str,
        prompt_version: str | None = None,
    ):
        self.store = store
        self.engine_version = engine_version
        self.prompt_version = prompt_version

    def record_analysis(
        self,
        *,
        input_bytes: bytes,
        output_bytes: bytes,
        claims: list[ProposedClaim],
        document_id: str | None = None,
        mode: str = "research_analysis",
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, list[str]]:
        run_id = self.store.record_ingest_run(
            input_bytes=input_bytes,
            output_bytes=output_bytes,
            mode=mode,
            status="COMPLETED",
            engine_version=self.engine_version,
            prompt_version=self.prompt_version,
            metadata=metadata,
        )
        claim_ids = []
        for claim in claims:
            claim_ids.append(
                self.store.propose_claim(
                    predicate=claim.predicate,
                    claim_text=claim.claim_text,
                    created_by=f"engine:{self.engine_version}",
                    document_id=document_id,
                    run_id=run_id,
                    subject_entity_id=claim.subject_entity_id,
                    object_entity_id=claim.object_entity_id,
                    object_value=claim.object_value,
                    metadata=claim.metadata,
                )
            )
        return run_id, claim_ids
