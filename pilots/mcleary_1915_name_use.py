"""Noncanonical 1915 MacLeary name-use source locator pilot.

Prior project work reports 'Avenida MacLeary. Parada 44' in an El Tiempo
issue of 22 Nov 1915, page 4. The primary page has not been recaptured
and checked here. No first mention, municipal act, road alignment or
same-road identity is inferred.
"""
from __future__ import annotations
import hashlib

from historical_acquisition import AcquisitionReceipt, record_acquisition_state
from historical_store import HistoricalStore

SOURCE_URL = (
    "https://ufdcimages.uflib.ufl.edu/AA/00/09/69/97/01444/"
    "1915112201.pdf"
)
PRIOR_TRANSCRIPTION = b"Avenida MacLeary. Parada 44"


def seed_mcleary_1915_name_use(store: HistoricalStore) -> dict[str, str]:
    """Create PROPOSED-only evidence with independent provisional street ID."""
    alias_entity = store.create_entity(
        entity_type="street",
        canonical_name="Avenida MacLeary (1915 source spelling)",
        authority_status="PROVISIONAL",
        metadata={
            "pilot": "mcleary-1915-name-use-v0.1",
            "same_road_as_mcleary_1916": "NOT_ESTABLISHED",
            "nominative_act_status": "UNLOCATED",
        },
        entity_id="ent_street_macleary_1915_source_spelling",
    )
    source = store.register_source(
        source_type="newspaper",
        title="El Tiempo, 22 November 1915 (prior research locator)",
        custodian="University of Florida Digital Collections / dLOC",
        repository="UFDC",
        locator="AA/00/09/69/97/01444/1915112201.pdf",
        url=SOURCE_URL,
        metadata={
            "reported_page": "4",
            "source_issue_and_page_independently_read": False,
            "source_rank": "newspaper_locator_only",
        },
        source_id="src_macleary_1915_11_22",
    )
    document = store.register_document(
        source_id=source,
        title="Reported El Tiempo MacLeary item (22 November 1915)",
        document_date="1915-11-22",
        # No event_date_start: the date of naming/opening is unknown.
        content_locator=SOURCE_URL,
        metadata={
            "page_anchor_reported": "4",
            "page_anchor_independently_verified": False,
            "raw_page_anchor_status": "PENDING_CAPTURE",
        },
        document_id="doc_macleary_1915_11_22",
    )
    record_acquisition_state(
        store,
        document_id=document,
        receipt=AcquisitionReceipt(
            state="LOCATOR_ONLY",
            source_url=SOURCE_URL,
            representation_type="scanned_newspaper_issue_pdf",
            raw_artifact=False,
            note="Institutional locator only; raw page capture pending.",
        ),
        representation_id="repr_macleary_1915_pdf_locator",
    )
    surrogate = store.register_document_representation(
        document_id=document,
        representation_type="research_transcription_surrogate",
        acquisition_state="TEXT_SURROGATE",
        locator=f"surrogate:prior-research:{SOURCE_URL}",
        mime_type="text/plain; charset=utf-8",
        content_sha256=hashlib.sha256(PRIOR_TRANSCRIPTION).hexdigest(),
        byte_length=len(PRIOR_TRANSCRIPTION),
        source_url=SOURCE_URL,
        raw_artifact=False,
        preferred_for_review=False,
        metadata={
            "derivation": "prior_project_transcription_not_reverified",
            "not_a_scan": True,
            "page_anchor_pending": True,
            "not_sufficient_for_claim_promotion": True,
        },
        representation_id="repr_macleary_1915_transcription_surrogate",
    )
    claim = store.propose_claim(
        document_id=document,
        subject_entity_id=alias_entity,
        predicate="reported_printed_name_use",
        object_value="Avenida MacLeary. Parada 44",
        claim_text=(
            "Working observation: prior transcription attributes 'Avenida "
            "MacLeary. Parada 44' to reported El Tiempo 22 Nov 1915 p. 4; "
            "the primary newspaper page has not been recaptured."
        ),
        created_by="galia2-acceptance-fixture",
        metadata={
            "verification_state": "PRIOR_TRANSCRIPTION_ONLY_RAW_CAPTURE_PENDING",
            "promotion_blocked_until_raw_capture": True,
            "does_not_establish": [
                "first_ever_mention", "official_municipal_naming_act",
                "date_of_physical_opening", "same_road_as_1916_mcleary_taft",
                "street_geometry", "eponym_identity",
            ],
        },
        claim_id="clm_macleary_reported_print_name_use_1915_11_22",
    )
    store.add_evidence(
        claim_id=claim,
        document_id=document,
        representation_id=surrogate,
        role="supports",
        locator=SOURCE_URL,
        excerpt=PRIOR_TRANSCRIPTION,
        metadata={
            "evidence_state": "ATTRIBUTED_PRIOR_TRANSCRIPTION_ONLY",
            "raw_capture_required": True,
            "page_anchor_pending": True,
        },
        evidence_id="evd_macleary_1915_prior_transcription",
    )

    # Independent discovery channel: a search-index transcription of the
    # *26 November* issue. Not a verified image of the 22 November item.
    # Never replace the 22-Nov claim or silently infer "first use".
    indexed_26_url = (
        "https://ufdcimages.uflib.ufl.edu/AA/00/09/69/97/01448/"
        "1915112601.pdf"
    )
    indexed_source = store.register_source(
        source_type="newspaper",
        title="El Tiempo, 26 November 1915, p. 4 (indexed OCR)",
        custodian="University of Florida Digital Collections / dLOC",
        repository="UFDC",
        locator="AA/00/09/69/97/01448/1915112601.pdf",
        url=indexed_26_url,
        metadata={
            "reported_page": "4",
            "discovery_channel": "public_search_index",
            "source_issue_and_page_independently_read": False,
            "primary_image_review_status": "PENDING",
        },
        source_id="src_macleary_1915_11_26_indexed",
    )
    indexed_document = store.register_document(
        source_id=indexed_source,
        title="El Tiempo, 26 Nov 1915 — OCR index MacLeary reference",
        document_date="1915-11-26",
        # A later printed reference cannot date the naming act.
        content_locator=indexed_26_url,
        metadata={
            "raw_page_anchor_status": "PENDING_CAPTURE",
            "ocr_index_observation": True,
            "not_independent_primary_image_review": True,
        },
        document_id="doc_macleary_1915_11_26_indexed",
    )
    record_acquisition_state(
        store,
        document_id=indexed_document,
        receipt=AcquisitionReceipt(
            state="LOCATOR_ONLY",
            source_url=indexed_26_url,
            representation_type="scanned_newspaper_issue_pdf",
            raw_artifact=False,
            note="Indexed page text only; primary scanned page not captured.",
        ),
        representation_id="repr_macleary_1915_11_26_pdf_locator",
    )
    indexed_text = b"Avenida MacLeary. Parada 44"
    indexed_surrogate = store.register_document_representation(
        document_id=indexed_document,
        representation_type="search_index_ocr_excerpt",
        acquisition_state="TEXT_SURROGATE",
        locator=f"surrogate:public-search-index:{indexed_26_url}",
        mime_type="text/plain; charset=utf-8",
        content_sha256=hashlib.sha256(indexed_text).hexdigest(),
        byte_length=len(indexed_text),
        source_url=indexed_26_url,
        raw_artifact=False,
        preferred_for_review=False,
        metadata={
            "derivation": "search_engine_extracted_ocr_not_primary_scan",
            "not_a_scan": True,
            "not_sufficient_for_claim_promotion": True,
        },
        representation_id="repr_macleary_1915_11_26_indexed_ocr",
    )
    indexed_claim = store.propose_claim(
        document_id=indexed_document,
        subject_entity_id=alias_entity,
        predicate="indexed_printed_name_use",
        object_value="Avenida MacLeary. Parada 44",
        claim_text=(
            "An OCR search index of El Tiempo, 26 Nov 1915 p. 4, reports "
            "'Avenida MacLeary. Parada 44' in a rental classified; raw "
            "page image not independently checked."
        ),
        created_by="galia2-search-index-triage",
        metadata={
            "verification_state": "INDEXED_OCR_ONLY_RAW_CAPTURE_PENDING",
            "promotion_blocked_until_raw_capture": True,
            "not_independent_primary_image_review": True,
            "does_not_establish": [
                "1915_11_22_transcription_accuracy", "first_ever_mention",
                "official_municipal_naming_act", "street_opening_date",
                "same_road_as_1916_mcleary_taft", "street_geometry",
                "eponym_identity",
            ],
        },
        claim_id="clm_macleary_indexed_print_name_use_1915_11_26",
    )
    store.add_evidence(
        claim_id=indexed_claim,
        document_id=indexed_document,
        representation_id=indexed_surrogate,
        role="supports",
        locator=indexed_26_url,
        excerpt=indexed_text,
        metadata={
            "evidence_state": "SEARCH_INDEX_OCR_ONLY",
            "raw_capture_required": True,
            "page_anchor_pending": True,
        },
        evidence_id="evd_macleary_1915_11_26_indexed_ocr",
    )

    return {
        "alias_entity_id": alias_entity,
        "document_id": document,
        "name_use_claim_id": claim,
        "indexed_26_document_id": indexed_document,
        "indexed_26_claim_id": indexed_claim,
    }
