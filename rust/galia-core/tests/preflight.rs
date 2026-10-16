use galia_core_shadow::authority::{AuthorityScope, PromotionAuthorization};
use galia_core_shadow::preflight::{assess_preflight, CandidateSnapshot, PreflightConfig, PreflightRequest, RollbackSnapshot};

fn request() -> PreflightRequest {
    let scope = AuthorityScope {
        case_id: "case-1".into(),
        target_type: "CLAIM".into(),
        target_ids: vec!["claim-1".into()],
    };
    PreflightRequest {
        config: PreflightConfig {
            policy_version: "core-p6".into(),
            accepted_authority_policy_version: "core-p5".into(),
            required_schema_version: "galia2-core-v1".into(),
            required_stages: vec!["SCHEMA".into(), "LINEAGE".into(), "DISCREPANCY".into(), "AUTHORITY".into()],
            actor: "shadow-test".into(),
        },
        candidate: CandidateSnapshot {
            case_id: "case-1".into(),
            target_commit: "candidate-17".into(),
            parent_commit: "canonical-16".into(),
            manifest_hash: "1".repeat(64),
            payload_hashes: vec!["2".repeat(64)],
            lineage_complete: true,
            schema_version: "galia2-core-v1".into(),
            completed_stages: vec!["SCHEMA".into(), "LINEAGE".into(), "DISCREPANCY".into(), "AUTHORITY".into()],
            blocking_discrepancy_ids: vec![],
            authority_decision_id: "decision-1".into(),
        },
        rollback: RollbackSnapshot {
            commit_id: "canonical-16".into(),
            manifest_hash: "3".repeat(64),
            integrity_valid: true,
            schema_compatible: true,
            authority_refs_valid: true,
            known_good: true,
        },
        authorization: Some(PromotionAuthorization {
            authorization_id: "auth-1".into(),
            decision_id: "decision-1".into(),
            reviewer: "human-reviewer".into(),
            scope: scope.clone(),
            target_commit: "candidate-17".into(),
            evidence_snapshot: vec!["evidence-1".into()],
            policy_version: "core-p5".into(),
            authorized_at: "2026-09-24T04:00:00Z".into(),
        }),
        expected_scope: scope,
    }
}

#[test]
fn matching_reference_fixture_is_advisory_only() {
    let r = assess_preflight(&request()).unwrap();
    assert!(r.passed);
    assert_eq!(r.checks.len(), 12);
    assert!(r.failed_checks.is_empty());
    assert!(r.output_commit.is_none());
    assert!(!r.authority_transfer);
    assert!(!r.canonical_writeback);
    assert_eq!(r.decision_kind, "STRUCTURAL_ADVISORY_ONLY");
}

#[test]
fn missing_authorization_fails_both_authorization_gates() {
    let mut req = request();
    req.authorization = None;
    let result = assess_preflight(&req).unwrap();
    assert!(!result.passed);
    assert_eq!(result.failed_checks, ["authorization_present", "authorization_matches_target"]);
}

#[test]
fn authority_must_match_exact_target_decision_scope_policy() {
    let mut req = request();
    req.authorization.as_mut().unwrap().target_commit = "candidate-18".into();
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["authorization_matches_target"]);
    req = request();
    req.authorization.as_mut().unwrap().decision_id = "decision-2".into();
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["authorization_matches_target"]);
    req = request();
    req.authorization.as_mut().unwrap().scope.target_ids = vec!["claim-2".into()];
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["authorization_matches_target"]);
    req = request();
    req.authorization.as_mut().unwrap().policy_version = "wrong-policy".into();
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["authorization_matches_target"]);
    req = request();
    req.expected_scope.case_id = "case-other".into();
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["authorization_matches_target"]);
}

#[test]
fn rollback_must_be_exact_verified_known_good_parent() {
    let mut req = request();
    req.rollback.commit_id = "canonical-15".into();
    req.rollback.integrity_valid = false;
    req.rollback.schema_compatible = false;
    req.rollback.authority_refs_valid = false;
    req.rollback.known_good = false;
    let r = assess_preflight(&req).unwrap();
    assert_eq!(r.failed_checks, [
        "rollback_parent_match", "rollback_integrity_valid",
        "rollback_schema_compatible", "rollback_authority_refs_valid", "rollback_known_good",
    ]);
    assert!(!r.passed);
}

#[test]
fn material_conflict_blocks_structural_readiness() {
    let mut req = request();
    req.candidate.blocking_discrepancy_ids = vec!["discrepancy-1".into()];
    assert_eq!(assess_preflight(&req).unwrap().failed_checks, ["no_blocking_discrepancy"]);
}

#[test]
fn incomplete_lineage_schema_stages_are_distinct_errors() {
    let mut req = request();
    req.candidate.lineage_complete = false;
    req.candidate.schema_version = "old-schema".into();
    req.candidate.completed_stages.pop();
    let r = assess_preflight(&req).unwrap();
    assert_eq!(r.failed_checks, ["lineage_complete", "schema_valid", "required_stages_complete"]);
}

#[test]
fn candidate_rejects_bad_hash_and_duplicate_stages() {
    let mut req = request();
    req.candidate.manifest_hash = "not-a-sha".into();
    assert!(assess_preflight(&req).is_err());
    req = request();
    req.candidate.completed_stages.push("SCHEMA".into());
    assert!(assess_preflight(&req).is_err());
}

#[test]
fn cannot_reuse_parent_as_target_or_empty_scope() {
    let mut req = request();
    req.candidate.target_commit = req.candidate.parent_commit.clone();
    assert!(assess_preflight(&req).is_err());
    req = request();
    req.expected_scope.target_ids = vec![];
    assert!(assess_preflight(&req).is_err());
}

#[test]
fn duplicate_evidence_reference_rejected() {
    let mut req = request();
    req.authorization.as_mut().unwrap().evidence_snapshot = vec!["e".into(), "e".into()];
    assert!(assess_preflight(&req).is_err());
}

#[test]
fn strict_json_envelope_rejects_unknown_fields() {
    let mut v = serde_json::to_value(request()).unwrap();
    v["unknown_override"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreflightRequest>(v).is_err());
}
