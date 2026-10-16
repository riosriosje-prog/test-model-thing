//! Read-only provenance gate for historical source-location observations.
//!
//! This module deliberately cannot produce CANONICAL or RAW_CAPTURED. It
//! assesses *absence* of primary source bytes and keeps a human evidence gate
//! visible. It does not fetch documents, verify a newspaper, infer same-road
//! identity, or grant historical authority.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const CAPTURE_GATE_SCHEMA: &str = "galia.research.primary_capture_gate.v0.1";
const REQUIRED_PROHIBITIONS: [&str; 6] = [
    "source_index_to_raw_capture",
    "document_date_to_street_naming_event",
    "printed_name_to_municipal_act",
    "provisional_1915_alias_to_1916_street_identity",
    "search_snippet_to_primary_source",
    "automatic_canonical_write",
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureGate {
    schema_version: String,
    project_id: String,
    case_id: String,
    record_date: String,
    state: String,
    authority_mutation: bool,
    raw_capture_complete: bool,
    claim_scope: String,
    documentary_observations: Vec<DocumentObservation>,
    requirements_before_raw_capture_record: Vec<String>,
    forbidden_promotions: Vec<String>,
    external_access_limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentObservation {
    document_id: String,
    claim_id: String,
    issue_date: String,
    publication: String,
    reported_page: String,
    url: String,
    discovery_tier: String,
    primary_pdf_available_to_current_review: bool,
    pdf_sha256: Option<String>,
    captured_pdf_byte_length: Option<u64>,
    verified_page_image_sha256: Option<String>,
    page_image_visually_checked: bool,
    typography_verified: bool,
    retrieval_observation: String,
    human_review_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HistoricalCaptureHold {
    pub disposition: &'static str,
    pub project_id: String,
    pub case_id: String,
    pub observed_claim_ids: Vec<String>,
    pub blocker: &'static str,
    pub canonical_write_authorized: bool,
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

/// Validate a provisional historical capture manifest and emit only a HOLD.
/// The serialized receipt is advisory; it is NOT cryptographic attestation,
/// independently acquired source bytes, or P5 human approval.
pub fn inspect_historical_capture_hold(
    json: &str,
) -> Result<HistoricalCaptureHold, &'static str> {
    let gate: CaptureGate =
        serde_json::from_str(json).map_err(|_| "unrecognized or malformed capture manifest")?;

    if gate.schema_version != CAPTURE_GATE_SCHEMA {
        return Err("capture schema version is not recognized");
    }
    if !nonempty(&gate.project_id)
        || !nonempty(&gate.case_id)
        || !nonempty(&gate.claim_scope)
        || NaiveDate::parse_from_str(&gate.record_date, "%Y-%m-%d").is_err()
    {
        return Err("capture manifest has invalid identity or record date");
    }
    if gate.state != "AUTHORITY_HOLD"
        || gate.authority_mutation
        || gate.raw_capture_complete
    {
        return Err("capture manifest is not a non-authoritative hold");
    }
    if gate.documentary_observations.is_empty()
        || gate.requirements_before_raw_capture_record.is_empty()
        || gate.external_access_limitations.is_empty()
    {
        return Err("capture manifest is missing source observations or limitations");
    }

    let forbidden: HashSet<&str> = gate
        .forbidden_promotions
        .iter()
        .map(String::as_str)
        .collect();
    if !REQUIRED_PROHIBITIONS.iter().all(|rule| forbidden.contains(rule)) {
        return Err("mandatory historical promotion prohibitions are missing");
    }

    let record_date =
        NaiveDate::parse_from_str(&gate.record_date, "%Y-%m-%d")
            .map_err(|_| "invalid record date")?;
    let mut documents = HashSet::new();
    let mut claims = HashSet::new();
    for row in &gate.documentary_observations {
        if !nonempty(&row.document_id)
            || !nonempty(&row.claim_id)
            || !nonempty(&row.publication)
            || !nonempty(&row.reported_page)
            || !nonempty(&row.retrieval_observation)
            || !row.url.starts_with("https://")
        {
            return Err("source locator or identification is incomplete");
        }
        let issue_date = NaiveDate::parse_from_str(&row.issue_date, "%Y-%m-%d")
            .map_err(|_| "invalid document date")?;
        if issue_date > record_date {
            return Err("document issue date is later than gate record date");
        }
        if !documents.insert(row.document_id.as_str())
            || !claims.insert(row.claim_id.as_str())
        {
            return Err("document and claim identities must be distinct");
        }
        if row.discovery_tier != "PRIOR_PROJECT_TRANSCRIPTION_ONLY"
            && row.discovery_tier != "SEARCH_INDEX_OCR_ONLY"
        {
            return Err("capture has unrecognized discovery tier");
        }
        if row.primary_pdf_available_to_current_review
            || row.pdf_sha256.is_some()
            || row.captured_pdf_byte_length.is_some()
            || row.verified_page_image_sha256.is_some()
            || row.page_image_visually_checked
            || row.typography_verified
            || row.human_review_state != "PENDING"
        {
            return Err("unverified observation falsely asserts primary capture or review");
        }
    }

    let mut observed_claim_ids: Vec<String> =
        gate.documentary_observations.into_iter().map(|row| row.claim_id).collect();
    observed_claim_ids.sort();

    Ok(HistoricalCaptureHold {
        disposition: "AUTHORITY_HOLD",
        project_id: gate.project_id,
        case_id: gate.case_id,
        observed_claim_ids,
        blocker: "RAW_CAPTURE_REQUIRED",
        canonical_write_authorized: false,
    })
}
