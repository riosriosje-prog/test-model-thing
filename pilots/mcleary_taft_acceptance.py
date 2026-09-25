from __future__ import annotations

import hashlib

from historical_acquisition import AcquisitionReceipt, record_acquisition_state
from historical_store import HistoricalStore


UFDC_MCLEARY_TAFT_1916_URL = (
    "https://ufdcimages.uflib.ufl.edu/AA/00/09/69/97/01534/"
    "1916030801.pdf"
)


def seed_mcleary_taft_acceptance(store: HistoricalStore) -> dict[str, str]:
    """Seed a non-canonical McLeary/Taft acceptance-test dossier.

    The fixture intentionally separates:
    1. a source-backed 1916 street-relation claim; and
    2. an unsupported nominative/eponym hypothesis.

    Nothing seeded here is CANONICAL. The 1916 newspaper locator is known, but
    the raw issue bytes/page anchor are still pending capture in this fixture.
    """

    taft_street = store.create_entity(
        entity_type="street",
        canonical_name="Calle Taft",
        authority_status="PROVISIONAL",
        metadata={
            "pilot": "mcleary-taft-acceptance-v0.1",
            "nominative_act_status": "UNLOCATED",
        },
        entity_id="ent_street_taft_santurce",
    )
    mcleary_street = store.create_entity(
        entity_type="street",
        canonical_name="Calle McLeary",
        authority_status="PROVISIONAL",
        metadata={"pilot": "mcleary-taft-acceptance-v0.1"},
        entity_id="ent_street_mcleary_santurce",
    )
    william_taft = store.create_entity(
        entity_type="person",
        canonical_name="William Howard Taft",
        authority_status="PROVISIONAL",
        metadata={
            "pilot": "mcleary-taft-acceptance-v0.1",
            "role_note": "possible eponym; not established by this fixture",
        },
        entity_id="ent_person_william_howard_taft",
    )

    source = store.register_source(
        source_type="newspaper",
        title="Puerto Rico newspaper issue — 8 March 1916",
        custodian="University of Florida Digital Collections / dLOC",
        repository="UFDC",
        locator="AA/00/09/69/97/01534/1916030801.pdf",
        url=UFDC_MCLEARY_TAFT_1916_URL,
        metadata={
            "pilot": "mcleary-taft-acceptance-v0.1",
            "source_rank": "primary_newspaper",
            "institutional_custodian": True,
            "serial_title_identification": "PENDING",
        },
        source_id="src_mcleary_taft_1916_03_08",
    )
    document = store.register_document(
        source_id=source,
        title="UFDC newspaper issue, 8 March 1916 — McLeary/Taft locator",
        document_date="1916-03-08",
        event_date_start="1916-03-08",
        content_locator=UFDC_MCLEARY_TAFT_1916_URL,
        metadata={
            "document_date_precision": "day",
            "event_date_precision": "day",
            "representation_expected": "scanned_newspaper_issue_pdf",
            "raw_page_anchor_status": "PENDING_CAPTURE",
        },
        document_id="doc_mcleary_taft_1916_03_08",
    )
    record_acquisition_state(
        store,
        document_id=document,
        receipt=AcquisitionReceipt(
            state="LOCATOR_ONLY",
            source_url=UFDC_MCLEARY_TAFT_1916_URL,
            representation_type="scanned_newspaper_issue_pdf",
            raw_artifact=False,
            note=(
                "Institutional PDF locator confirmed. Raw issue/page bytes are "
                "not embedded in this fixture and must be captured before "
                "canonical promotion."
            ),
        ),
        representation_id="repr_mcleary_taft_1916_pdf_locator",
    )

    surrogate = "Calle McLeary (sale de Taft)".encode("utf-8")
    surrogate_representation = store.register_document_representation(
        document_id=document,
        representation_type="research_transcription_surrogate",
        acquisition_state="TEXT_SURROGATE",
        locator=f"surrogate:prior-research:{UFDC_MCLEARY_TAFT_1916_URL}",
        mime_type="text/plain; charset=utf-8",
        content_sha256=hashlib.sha256(surrogate).hexdigest(),
        byte_length=len(surrogate),
        source_url=UFDC_MCLEARY_TAFT_1916_URL,
        raw_artifact=False,
        preferred_for_review=False,
        metadata={
            "derivation": "prior_research_transcription",
            "not_a_scan": True,
            "page_anchor_pending": True,
            "not_sufficient_for_claim_promotion": True,
        },
        representation_id="repr_mcleary_taft_1916_transcription_surrogate",
    )

    relation_claim = store.propose_claim(
        document_id=document,
        subject_entity_id=mcleary_street,
        predicate="described_as_departing_from",
        object_entity_id=taft_street,
        claim_text=(
            "Working claim: the 8 March 1916 newspaper issue describes "
            "Calle McLeary as 'sale de Taft'."
        ),
        created_by="galia2-acceptance-fixture",
        metadata={
            "verification_state": "PRIMARY_SOURCE_LOCATED_RAW_CAPTURE_PENDING",
            "promotion_blocked_until_raw_capture": True,
            "promotion_required_representation_types": [
                "scanned_newspaper_issue_pdf",
            ],
            "does_not_establish": [
                "date_of_physical_opening",
                "formal_nominative_act",
                "eponym_identity",
            ],
        },
        claim_id="clm_mcleary_departs_from_taft_1916_03_08",
    )
    store.add_evidence(
        claim_id=relation_claim,
        document_id=document,
        representation_id=surrogate_representation,
        role="supports",
        locator=UFDC_MCLEARY_TAFT_1916_URL,
        excerpt=surrogate,
        metadata={
            "evidence_state": "TEXT_SURROGATE_ONLY",
            "raw_capture_required": True,
            "page_anchor_pending": True,
        },
        evidence_id="evd_mcleary_taft_1916_transcription",
    )

    nominative_claim = store.propose_claim(
        subject_entity_id=taft_street,
        predicate="formally_named_after",
        object_entity_id=william_taft,
        claim_text=(
            "Unsupported working hypothesis: Calle Taft was formally named "
            "after William Howard Taft by a municipal nominative act."
        ),
        created_by="galia2-acceptance-fixture",
        metadata={
            "verification_state": "UNSUPPORTED_HYPOTHESIS",
            "required_evidence": (
                "municipal ordinance, minutes, approved plan, or equivalent "
                "contemporaneous nominative record"
            ),
            "inference_prohibited_from": [
                "street_name_similarity",
                "later_map_labels",
                "1916_mcleary_relation",
            ],
        },
        claim_id="clm_taft_formally_named_after_william_h_taft",
    )

    return {
        "taft_street_id": taft_street,
        "mcleary_street_id": mcleary_street,
        "william_taft_id": william_taft,
        "document_id": document,
        "relation_claim_id": relation_claim,
        "nominative_claim_id": nominative_claim,
    }
