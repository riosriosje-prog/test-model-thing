use std::collections::BTreeSet;
use galia_core_shadow::core::{SourceArtifact, Stage, StageState};
use galia_core_shadow::state_machine::{
    allowed_events, apply_transition, evaluate_transition, TransitionError, TransitionEvent,
};

fn stage(state: StageState) -> Stage {
    Stage {
        stage_id: "s1".into(),
        case_id: "c1".into(),
        stage_type: "CORE".into(),
        state,
        dependencies: vec![],
        input_refs: vec![],
        output_refs: vec![],
        blocking_holds: vec![],
    }
}
fn guards(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn happy_path_requires_all_eight_steps() {
    use TransitionEvent as E;
    use StageState as S;
    let checks: &[(E, &[&str], S)] = &[
        (E::IngestConfirmed, &["source_artifact_valid"], S::Ingested),
        (E::NormalizationComplete, &["lineage_complete"], S::Normalized),
        (E::DerivationComplete, &["output_hash_valid"], S::Derived),
        (E::ValidationPassed, &["required_validations_passed"], S::Validated),
        (E::PlaceAuthorityHold, &["evidence_snapshot_present"], S::AuthorityHold),
        (E::HumanSelectionRecorded, &["human_decision_present"], S::HumanSelected),
        (E::PreflightPassed, &["preflight_passed", "rollback_target_verified"], S::PromotionReady),
        (E::PromotionAuthorized, &["promotion_authorization_present", "authorization_matches_target"], S::Canonical),
    ];
    let mut s = stage(S::Discovered);
    for &(event, required, expected) in checks {
        let (next, decision) = apply_transition(&s, event, &guards(required)).unwrap();
        assert_eq!(s.state, decision.from_state, "input stage must not mutate");
        assert_eq!(decision.to_state, expected);
        s = next;
    }
    assert_eq!(s.state, S::Canonical);
}

#[test]
fn missing_guard_rejects_instead_of_advancing() {
    let err = evaluate_transition(
        &stage(StageState::Derived),
        TransitionEvent::ValidationPassed,
        &BTreeSet::new(),
    ).unwrap_err();
    assert_eq!(err, TransitionError::MissingGuards(vec!["required_validations_passed".into()]));
}

#[test]
fn cannot_bypass_authority_holds() {
    for from in [StageState::Derived, StageState::Validated, StageState::AuthorityHold] {
        assert!(matches!(
            evaluate_transition(&stage(from), TransitionEvent::PromotionAuthorized,
                &guards(&["promotion_authorization_present", "authorization_matches_target"])),
            Err(TransitionError::InvalidTransition { .. })
        ));
    }
}

#[test]
fn human_boundary_is_explicit() {
    let event = TransitionEvent::HumanSelectionRecorded;
    assert!(evaluate_transition(&stage(StageState::AuthorityHold), event, &BTreeSet::new()).is_err());
    let selected = evaluate_transition(
        &stage(StageState::AuthorityHold), event, &guards(&["human_decision_present"])
    ).unwrap();
    assert!(selected.human_boundary);
    let final_decision = evaluate_transition(
        &stage(StageState::PromotionReady), TransitionEvent::PromotionAuthorized,
        &guards(&["promotion_authorization_present", "authorization_matches_target"])
    ).unwrap();
    assert!(final_decision.human_boundary);
}

#[test]
fn promotion_needs_both_guards() {
    let err = evaluate_transition(
        &stage(StageState::PromotionReady), TransitionEvent::PromotionAuthorized,
        &guards(&["promotion_authorization_present"]),
    ).unwrap_err();
    assert_eq!(err, TransitionError::MissingGuards(vec!["authorization_matches_target".into()]));
}

#[test]
fn failures_are_isolated_and_cannot_chain() {
    let routes = [
        (TransitionEvent::IntegrityFailure, "integrity_failure_confirmed", StageState::Quarantined),
        (TransitionEvent::MaterialConflict, "material_conflict_confirmed", StageState::DiscrepancyReview),
        (TransitionEvent::PersistenceFailure, "persistence_failure_confirmed", StageState::RecoveryIntake),
    ];
    for (event, guard, expected) in routes {
        let decision = evaluate_transition(&stage(StageState::Canonical), event, &guards(&[guard])).unwrap();
        assert_eq!(decision.to_state, expected);
        assert!(evaluate_transition(&stage(expected), event, &guards(&[guard])).is_err());
    }
}

#[test]
fn canonical_reopens_only_for_new_material_evidence() {
    let s = stage(StageState::Canonical);
    let event = TransitionEvent::NewMaterialEvidence;
    assert!(evaluate_transition(&s, event, &BTreeSet::new()).is_err());
    let (next, _) = apply_transition(&s, event, &guards(&["new_material_evidence"])).unwrap();
    assert_eq!(next.state, StageState::Reopened);
    assert_eq!(s.state, StageState::Canonical);
}

#[test]
fn allowed_events_do_not_include_promotion_shortcuts() {
    let events = allowed_events(StageState::Derived);
    assert!(events.contains(&TransitionEvent::ValidationPassed));
    assert!(events.contains(&TransitionEvent::IntegrityFailure));
    assert!(!events.contains(&TransitionEvent::PromotionAuthorized));
    assert!(allowed_events(StageState::Quarantined).is_empty());
}

#[test]
fn invalid_stage_fails_closed() {
    let mut s = stage(StageState::Discovered);
    s.dependencies.push(s.stage_id.clone());
    assert!(matches!(
        evaluate_transition(&s, TransitionEvent::IngestConfirmed, &guards(&["source_artifact_valid"])),
        Err(TransitionError::InvalidStage(_))
    ));
}

#[test]
fn source_artifact_hash_date_immutability_validation() {
    let mut src = SourceArtifact {
        artifact_id: "a1".into(),
        repository: "AGPR".into(),
        repository_ref: "reg-1".into(),
        document_date: Some("1915-03-01".into()),
        event_date_hint: Some("1914-12-31".into()),
        sha256: "a".repeat(64),
        provenance_state: "VERIFIED".into(),
        immutable: true,
    };
    assert!(src.validate().is_ok());
    src.document_date = Some("1915-02-30".into());
    assert!(src.validate().is_err());
    src.document_date = Some("1916-02-29".into());
    assert!(src.validate().is_ok());
    src.immutable = false;
    assert!(src.validate().is_err());
    src.immutable = true;
    src.sha256 = "bad".into();
    assert!(src.validate().is_err());
}

#[test]
fn json_contract_is_strict_and_stable() {
    let s = stage(StageState::AuthorityHold);
    let serialized = serde_json::to_string(&s).unwrap();
    assert!(serialized.contains("AUTHORITY_HOLD"));
    let decoded: Stage = serde_json::from_str(&serialized).unwrap();
    assert_eq!(decoded, s);
    assert!(serde_json::from_str::<Stage>(
        r#"{"stage_id":"s","case_id":"c","stage_type":"x","state":"NOT_A_STATE"}"#
    ).is_err());
}
