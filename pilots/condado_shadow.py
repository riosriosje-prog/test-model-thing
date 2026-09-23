from __future__ import annotations

import hashlib

from historical_acquisition import AcquisitionReceipt, record_acquisition_state
from historical_store import HistoricalStore


LOC_CONDADO_1908_URL = (
    "https://tile.loc.gov/storage-services/service/ndnp/prru/"
    "batch_prru_foca_ver01/data/sn91099747/0027176568A/"
    "1908090401/0252.pdf"
)

PICA_PICA_CONDADO_1908_URL = (
    "https://ufdcimages.uflib.ufl.edu/AA/00/09/81/80/00265/"
    "1908050901.pdf"
)


def seed_condado_shadow(store: HistoricalStore) -> dict[str, object]:
    """Seed a deliberately non-canonical Finca El Condado pilot.

    The pilot preserves currently known research assertions and disagreement
    structure. It does not adjudicate title, acreage, or identity questions.
    """

    estate = store.create_entity(
        entity_type="estate",
        canonical_name="Finca El Condado",
        authority_status="PROVISIONAL",
        metadata={
            "pilot": "finca-condado-v0.1",
            "canonical_identity_status": "UNRESOLVED",
        },
    )
    hernand = store.create_entity(
        entity_type="person",
        canonical_name="Hernand Behn",
        authority_status="PROVISIONAL",
    )
    sosthenes = store.create_entity(
        entity_type="person",
        canonical_name="Sosthenes Behn",
        authority_status="PROVISIONAL",
    )

    behn_source = store.register_source(
        source_type="court_opinion",
        title="Behn v. Registrador de San Juan",
        custodian="Tribunal Supremo de Puerto Rico",
        repository="D.P.R.",
        locator="26 D.P.R. 166 (1918)",
        metadata={
            "pilot": "finca-condado-v0.1",
            "source_rank": "primary_judicial",
            "raw_artifact_state": "LOCATOR_ONLY_PENDING_CAPTURE",
        },
    )
    behn_doc = store.register_document(
        source_id=behn_source,
        title="Behn v. Registrador de San Juan, 26 D.P.R. 166 (1918)",
        document_date="1918",
        event_date_start="1917-08-24",
        content_locator="26 D.P.R. 166 (1918)",
        metadata={
            "raw_artifact_state": "LOCATOR_ONLY_PENDING_CAPTURE",
            "document_date_precision": "year",
            "event_date_precision": "day",
        },
    )

    transfer_claim = store.propose_claim(
        document_id=behn_doc,
        subject_entity_id=sosthenes,
        predicate="transferred_undivided_half_interest_to",
        object_entity_id=hernand,
        claim_text=(
            "Working claim: on 24 August 1917 Sosthenes Behn transferred "
            "an undivided half interest associated with Finca El Condado "
            "to Hernand Behn."
        ),
        created_by="legacy-research-import",
        metadata={
            "estate_entity_id": estate,
            "verification_state": "PROPOSED_FROM_CITATION_PENDING_RAW_ARTIFACT",
        },
    )
    store.add_evidence(
        claim_id=transfer_claim,
        document_id=behn_doc,
        role="supports",
        locator="26 D.P.R. 166 (1918)",
        metadata={
            "evidence_state": "CITATION_ANCHOR_ONLY",
            "excerpt_capture_required": True,
        },
    )

    location_claim = store.propose_claim(
        document_id=behn_doc,
        subject_entity_id=estate,
        predicate="described_location",
        object_value="El Condado y Bayola, sección norte de Santurce",
        claim_text=(
            "Working claim: the judicial description places Finca El Condado "
            "at El Condado and Bayola in the northern section of Santurce."
        ),
        created_by="legacy-research-import",
        metadata={
            "verification_state": "PROPOSED_FROM_CITATION_PENDING_RAW_ARTIFACT",
        },
    )
    store.add_evidence(
        claim_id=location_claim,
        document_id=behn_doc,
        role="supports",
        locator="26 D.P.R. 166 (1918)",
        metadata={"evidence_state": "CITATION_ANCHOR_ONLY"},
    )

    # First institutional primary-source acquisition target. Library of
    # Congress exposes the 4 Sep 1908 page containing the El Condado /
    # Parque Residencial advertisement, but the raw PDF endpoint may be
    # unavailable to an automated acquisition environment. We preserve that
    # distinction instead of treating a text surrogate as the raw scan.
    newspaper_source = store.register_source(
        source_type="newspaper",
        title="La Correspondencia de Puerto Rico",
        custodian="Library of Congress",
        repository="Chronicling America",
        locator="LCCN sn91099747; 1908-09-04; page image/PDF 0252",
        url=LOC_CONDADO_1908_URL,
        metadata={
            "source_rank": "primary_newspaper",
            "institutional_custodian": True,
        },
    )
    newspaper_doc = store.register_document(
        source_id=newspaper_source,
        title=(
            "La Correspondencia de Puerto Rico, "
            "4 de septiembre de 1908 — El Condado / Parque Residencial"
        ),
        document_date="1908-09-04",
        event_date_start="1908-09-04",
        content_locator=LOC_CONDADO_1908_URL,
        metadata={
            "document_date_precision": "day",
            "event_date_precision": "day",
            "representation_expected": "scanned_newspaper_page_pdf",
        },
    )
    newspaper_pdf_representation = record_acquisition_state(
        store,
        document_id=newspaper_doc,
        receipt=AcquisitionReceipt(
            state="REMOTE_BLOCKED",
            source_url=LOC_CONDADO_1908_URL,
            representation_type="scanned_newspaper_page_pdf",
            raw_artifact=False,
            note=(
                "Institutional source located and independently discoverable; "
                "raw PDF bytes were not capturable in the current acquisition "
                "environment. Do not substitute derived text as raw scan."
            ),
        ),
    )
    indexed_heading = (
        "EL CONDADO — PARQUE RESIDENCIAL\nBEHN BROTHERS"
    ).encode("utf-8")
    newspaper_text_representation = store.register_document_representation(
        document_id=newspaper_doc,
        representation_type="search_index_text_surrogate",
        acquisition_state="TEXT_SURROGATE",
        locator=f"surrogate:web-index:{LOC_CONDADO_1908_URL}",
        mime_type="text/plain; charset=utf-8",
        content_sha256=hashlib.sha256(indexed_heading).hexdigest(),
        byte_length=len(indexed_heading),
        source_url=LOC_CONDADO_1908_URL,
        raw_artifact=False,
        preferred_for_review=False,
        metadata={
            "derivation": "search_index_extraction",
            "scope": "heading_and_advertiser_only",
            "not_a_scan": True,
            "not_sufficient_for_claim_promotion": True,
        },
    )

    newspaper_claim = store.propose_claim(
        document_id=newspaper_doc,
        subject_entity_id=estate,
        predicate="marketed_as",
        object_value="El Condado — Parque Residencial",
        claim_text=(
            "Working claim: on 4 September 1908 Behn Brothers marketed "
            "El Condado as a residential park."
        ),
        created_by="source-discovery-import",
        metadata={
            "verification_state": "PRIMARY_SOURCE_LOCATED_RAW_CAPTURE_PENDING",
            "promotion_blocked_until_raw_capture": True,
            "promotion_required_representation_types": [
                "scanned_newspaper_page_pdf",
                "scanned_newspaper_page_image",
            ],
        },
    )
    store.add_evidence(
        claim_id=newspaper_claim,
        document_id=newspaper_doc,
        representation_id=newspaper_text_representation,
        role="supports",
        locator=LOC_CONDADO_1908_URL,
        excerpt=indexed_heading,
        metadata={
            "evidence_state": "TEXT_SURROGATE_ONLY",
            "raw_capture_required": True,
            "representation_does_not_unlock_promotion": True,
        },
    )

    # Alternate primary-source route independent of the blocked LoC PDF.
    # Pica-Pica (San Juan), 9 May 1908, contains an El Condado sales
    # advertisement by Behn Brothers. The UFDC/dLOC PDF is the preferred raw
    # capture target; UPR also preserves the serial on microfilm.
    pica_source = store.register_source(
        source_type="newspaper",
        title="Pica-Pica",
        custodian="University of Florida Digital Collections / dLOC",
        repository="Digital Library of the Caribbean",
        locator="Pica-Pica; San Juan; 1908-05-09; issue PDF",
        url=PICA_PICA_CONDADO_1908_URL,
        metadata={
            "source_rank": "primary_newspaper",
            "institutional_custodian": True,
            "independent_custodial_route": "UPR microfilm",
        },
    )
    pica_doc = store.register_document(
        source_id=pica_source,
        title="Pica-Pica, 9 de mayo de 1908 — anuncio El Condado",
        document_date="1908-05-09",
        event_date_start="1908-05-09",
        content_locator=PICA_PICA_CONDADO_1908_URL,
        metadata={
            "document_date_precision": "day",
            "event_date_precision": "day",
            "representation_expected": "scanned_newspaper_page_pdf",
        },
    )
    pica_pdf_locator = record_acquisition_state(
        store,
        document_id=pica_doc,
        receipt=AcquisitionReceipt(
            state="LOCATOR_ONLY",
            source_url=PICA_PICA_CONDADO_1908_URL,
            representation_type="scanned_newspaper_page_pdf",
            raw_artifact=False,
            note=(
                "UFDC/dLOC raw PDF target located; acquisition is attempted "
                "by the dedicated GitHub Actions capture pilot."
            ),
        ),
    )
    pica_indexed_text = (
        "EL CONDADO\n"
        "Se venden grandes y saludables solares á precios módicos.\n"
        "Behn Brothers, ESQUINA TETUAN Y SAN JUSTO."
    ).encode("utf-8")
    pica_text_representation = store.register_document_representation(
        document_id=pica_doc,
        representation_type="search_index_text_surrogate",
        acquisition_state="TEXT_SURROGATE",
        locator=f"surrogate:web-index:{PICA_PICA_CONDADO_1908_URL}",
        mime_type="text/plain; charset=utf-8",
        content_sha256=hashlib.sha256(pica_indexed_text).hexdigest(),
        byte_length=len(pica_indexed_text),
        source_url=PICA_PICA_CONDADO_1908_URL,
        raw_artifact=False,
        preferred_for_review=False,
        metadata={
            "derivation": "search_index_extraction",
            "not_a_scan": True,
            "not_sufficient_for_claim_promotion": True,
        },
    )
    pica_claim = store.propose_claim(
        document_id=pica_doc,
        subject_entity_id=estate,
        predicate="advertised_for_sale",
        object_value="large healthy lots at modest prices",
        claim_text=(
            "Working claim: on 9 May 1908 Pica-Pica advertised El Condado "
            "lots for sale by Behn Brothers."
        ),
        created_by="source-discovery-import",
        metadata={
            "verification_state": "PRIMARY_SOURCE_LOCATED_RAW_CAPTURE_PENDING",
            "promotion_blocked_until_raw_capture": True,
            "promotion_required_representation_types": [
                "scanned_newspaper_page_pdf",
                "scanned_newspaper_page_image",
            ],
        },
    )
    store.add_evidence(
        claim_id=pica_claim,
        document_id=pica_doc,
        representation_id=pica_text_representation,
        role="supports",
        locator=PICA_PICA_CONDADO_1908_URL,
        excerpt=pica_indexed_text,
        metadata={
            "evidence_state": "TEXT_SURROGATE_ONLY",
            "raw_capture_required": True,
            "representation_does_not_unlock_promotion": True,
        },
    )

    notes_source = store.register_source(
        source_type="research_working_note",
        title="GALIA working note — Finca El Condado cabida variants",
        repository="GALIA shadow pilot",
        locator="pilot:finca-condado-v0.1:area-variants",
        metadata={
            "source_rank": "working_note",
            "authority": "NON_CANONICAL",
        },
    )
    notes_doc = store.register_document(
        source_id=notes_source,
        title="Unresolved acreage/cabida variants",
        content_locator="pilot:finca-condado-v0.1:area-variants",
        metadata={
            "artifact_state": "WORKING_ASSERTION_CONTAINER",
            "not_a_primary_source": True,
        },
    )

    area_values = ("148 cuerdas", "150 cuerdas", "148.5 acres")
    area_claims: list[str] = []
    for value in area_values:
        area_claims.append(
            store.propose_claim(
                document_id=notes_doc,
                subject_entity_id=estate,
                predicate="reported_area",
                object_value=value,
                claim_text=(
                    f"Unresolved working assertion: Finca El Condado "
                    f"is reported as {value}."
                ),
                created_by="legacy-research-import",
                metadata={
                    "verification_state": "UNVERIFIED_WORKING_ASSERTION",
                    "normalization_forbidden": True,
                },
            )
        )

    discrepancy = store.open_discrepancy(
        topic_key="finca-condado-area",
        description=(
            "Conflicting working assertions report the estate as 148 cuerdas, "
            "150 cuerdas, or 148.5 acres. Preserve all variants until the "
            "original registral description or equivalent primary evidence "
            "resolves the issue."
        ),
        metadata={
            "pilot": "finca-condado-v0.1",
            "resolution_gate": "PRIMARY_REGISTRAL_OR_EQUIVALENT_EVIDENCE",
        },
    )
    for index, claim_id in enumerate(area_claims, start=1):
        store.attach_discrepancy_claim(
            discrepancy_id=discrepancy,
            claim_id=claim_id,
            stance=f"variant_{index}",
        )

    return {
        "estate_entity_id": estate,
        "hernand_entity_id": hernand,
        "sosthenes_entity_id": sosthenes,
        "behn_document_id": behn_doc,
        "transfer_claim_id": transfer_claim,
        "location_claim_id": location_claim,
        "newspaper_document_id": newspaper_doc,
        "newspaper_pdf_representation_id": newspaper_pdf_representation,
        "newspaper_text_representation_id": newspaper_text_representation,
        "newspaper_claim_id": newspaper_claim,
        "pica_document_id": pica_doc,
        "pica_pdf_locator_representation_id": pica_pdf_locator,
        "pica_text_representation_id": pica_text_representation,
        "pica_claim_id": pica_claim,
        "area_claim_ids": area_claims,
        "area_discrepancy_id": discrepancy,
    }
