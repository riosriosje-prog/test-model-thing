use galia_core_shadow::historical_capture::{
    inspect_historical_capture_hold, CAPTURE_GATE_SCHEMA,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/mcleary_1915_primary_capture_gate.v0_1.json"
    ))
    .expect("known fixture JSON")
}

fn assess(value: &Value) -> Result<galia_core_shadow::historical_capture::HistoricalCaptureHold, &'static str> {
    inspect_historical_capture_hold(&value.to_string())
}

#[test]
fn verified_fixture_yields_only_authority_hold() {
    let source = fixture();
    assert_eq!(source["schema_version"], CAPTURE_GATE_SCHEMA);
    let result = assess(&source).unwrap();
    assert_eq!(result.disposition, "AUTHORITY_HOLD");
    assert_eq!(result.blocker, "RAW_CAPTURE_REQUIRED");
    assert!(!result.canonical_write_authorized);
    assert_eq!(result.project_id, "mcleary");
    assert_eq!(result.observed_claim_ids.len(), 2);
    assert!(result.observed_claim_ids[0].contains("1915_11_22"));
    assert!(result.observed_claim_ids[1].contains("1915_11_26"));
}

#[test]
fn wrongly_asserted_raw_capture_is_rejected() {
    let mut a = fixture();
    a["raw_capture_complete"] = json!(true);
    assert!(assess(&a).is_err());
}

#[test]
fn authority_mutation_and_canonical_state_are_rejected() {
    let mut a = fixture();
    a["authority_mutation"] = json!(true);
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["state"] = json!("CANONICAL");
    assert!(assess(&b).is_err());
}

#[test]
fn signed_or_unsourced_hash_is_not_considered_capture() {
    let mut a = fixture();
    a["documentary_observations"][0]["pdf_sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][1]["captured_pdf_byte_length"] = json!(44932618);
    assert!(assess(&b).is_err());
    let mut c = fixture();
    c["documentary_observations"][1]["verified_page_image_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(assess(&c).is_err());
}

#[test]
fn unverified_review_claims_are_rejected() {
    let mut a = fixture();
    a["documentary_observations"][1]["page_image_visually_checked"] = json!(true);
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][1]["typography_verified"] = json!(true);
    assert!(assess(&b).is_err());
    let mut c = fixture();
    c["documentary_observations"][0]["human_review_state"] = json!("APPROVED");
    assert!(assess(&c).is_err());
}

#[test]
fn false_positive_primary_pdf_availability_is_rejected() {
    let mut a = fixture();
    a["documentary_observations"][0]["primary_pdf_available_to_current_review"] =
        json!(true);
    assert!(assess(&a).is_err());
}

#[test]
fn event_date_and_imported_authority_fields_are_rejected() {
    let mut a = fixture();
    a["documentary_observations"][0]["street_naming_event_date"] =
        json!("1915-11-22");
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["canonical_write_authorized"] = json!(true);
    assert!(assess(&b).is_err());
}

#[test]
fn foreign_schema_and_source_discovery_tier_are_rejected() {
    let mut a = fixture();
    a["schema_version"] = json!("galia.research.primary_capture_gate.v9");
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][0]["discovery_tier"] = json!("PRIMARY_SCAN");
    assert!(assess(&b).is_err());
}

#[test]
fn invalid_issue_dates_and_backdated_claims_are_rejected() {
    let mut a = fixture();
    a["documentary_observations"][0]["issue_date"] = json!("1915-02-30");
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][0]["issue_date"] = json!("2027-01-01");
    assert!(assess(&b).is_err());
    let mut c = fixture();
    c["record_date"] = json!("2026-99-10");
    assert!(assess(&c).is_err());
}

#[test]
fn duplicate_document_or_claim_ids_are_rejected() {
    let mut a = fixture();
    a["documentary_observations"][1]["document_id"] =
        a["documentary_observations"][0]["document_id"].clone();
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][1]["claim_id"] =
        b["documentary_observations"][0]["claim_id"].clone();
    assert!(assess(&b).is_err());
}

#[test]
fn source_locator_must_be_present_but_does_not_grant_trust() {
    let mut a = fixture();
    a["documentary_observations"][0]["url"] =
        json!("http://insecure.example/issue.pdf");
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["documentary_observations"][0]["retrieval_observation"] = json!(" ");
    assert!(assess(&b).is_err());
}

#[test]
fn dropping_any_mandatory_prohibition_is_rejected() {
    let a = fixture();
    for rule in [
        "source_index_to_raw_capture",
        "document_date_to_street_naming_event",
        "printed_name_to_municipal_act",
        "provisional_1915_alias_to_1916_street_identity",
        "search_snippet_to_primary_source",
        "automatic_canonical_write",
    ] {
        let mut b = a.clone();
        b["forbidden_promotions"] = Value::Array(
            b["forbidden_promotions"].as_array().unwrap()
                .iter().filter(|v| v.as_str() != Some(rule))
                .cloned().collect()
        );
        assert!(assess(&b).is_err(), "missing prohibition: {rule}");
    }
}

#[test]
fn missing_documentary_evidence_and_limitations_fail_closed() {
    let mut a = fixture();
    a["documentary_observations"] = json!([]);
    assert!(assess(&a).is_err());
    let mut b = fixture();
    b["external_access_limitations"] = json!([]);
    assert!(assess(&b).is_err());
    let mut c = fixture();
    c["requirements_before_raw_capture_record"] = json!([]);
    assert!(assess(&c).is_err());
}
