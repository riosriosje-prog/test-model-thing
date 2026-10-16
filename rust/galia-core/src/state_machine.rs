//! Exact transition-table port of GALIA P2 (galia2/state_machine.py).
//! Guard strings are assumed externally attested; this is NOT an authority verifier.
use std::collections::BTreeSet;
use std::fmt;
use serde::{Deserialize, Serialize};
use crate::core::{Stage, StageState};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransitionEvent {
    IngestConfirmed,
    NormalizationComplete,
    DerivationComplete,
    ValidationPassed,
    PlaceAuthorityHold,
    HumanSelectionRecorded,
    PreflightPassed,
    PromotionAuthorized,
    IntegrityFailure,
    MaterialConflict,
    PersistenceFailure,
    NewMaterialEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransitionDecision {
    pub stage_id: String,
    pub case_id: String,
    pub from_state: StageState,
    pub event: TransitionEvent,
    pub to_state: StageState,
    pub satisfied_guards: BTreeSet<String>,
    pub required_guards: BTreeSet<String>,
    pub human_boundary: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidStage(&'static str),
    InvalidTransition { state: StageState, event: TransitionEvent },
    MissingGuards(Vec<String>),
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStage(e) => write!(f, "invalid stage: {e}"),
            Self::InvalidTransition { state, event } => {
                write!(f, "invalid transition {state:?} with {event:?}")
            }
            Self::MissingGuards(items) => write!(f, "missing guards: {}", items.join(", ")),
        }
    }
}
impl std::error::Error for TransitionError {}

#[derive(Clone, Copy)]
struct Rule {
    to_state: StageState,
    guards: &'static [&'static str],
    human_boundary: bool,
}

fn rule(to_state: StageState, guards: &'static [&'static str], human_boundary: bool) -> Rule {
    Rule { to_state, guards, human_boundary }
}

fn failure_source(state: StageState) -> bool {
    matches!(state,
        StageState::Discovered | StageState::Ingested | StageState::Normalized
        | StageState::Derived | StageState::Validated | StageState::AuthorityHold
        | StageState::HumanSelected | StageState::PromotionReady
        | StageState::Canonical | StageState::Reopened
    )
}

fn transition_rule(state: StageState, event: TransitionEvent) -> Result<Rule, TransitionError> {
    use StageState as S;
    use TransitionEvent as E;
    let primary = match (state, event) {
        (S::Discovered, E::IngestConfirmed) =>
            Some(rule(S::Ingested, &["source_artifact_valid"], false)),
        (S::Ingested, E::NormalizationComplete) =>
            Some(rule(S::Normalized, &["lineage_complete"], false)),
        (S::Normalized, E::DerivationComplete) =>
            Some(rule(S::Derived, &["output_hash_valid"], false)),
        (S::Derived, E::ValidationPassed) =>
            Some(rule(S::Validated, &["required_validations_passed"], false)),
        (S::Validated, E::PlaceAuthorityHold) =>
            Some(rule(S::AuthorityHold, &["evidence_snapshot_present"], false)),
        (S::AuthorityHold, E::HumanSelectionRecorded) =>
            Some(rule(S::HumanSelected, &["human_decision_present"], true)),
        (S::HumanSelected, E::PreflightPassed) =>
            Some(rule(S::PromotionReady, &["preflight_passed", "rollback_target_verified"], false)),
        (S::PromotionReady, E::PromotionAuthorized) =>
            Some(rule(S::Canonical, &["promotion_authorization_present", "authorization_matches_target"], true)),
        (S::Canonical, E::NewMaterialEvidence) =>
            Some(rule(S::Reopened, &["new_material_evidence"], false)),
        _ => None,
    };
    if let Some(found) = primary {
        return Ok(found);
    }
    if failure_source(state) {
        let isolation = match event {
            E::IntegrityFailure =>
                Some(rule(S::Quarantined, &["integrity_failure_confirmed"], false)),
            E::MaterialConflict =>
                Some(rule(S::DiscrepancyReview, &["material_conflict_confirmed"], false)),
            E::PersistenceFailure =>
                Some(rule(S::RecoveryIntake, &["persistence_failure_confirmed"], false)),
            _ => None,
        };
        if let Some(found) = isolation {
            return Ok(found);
        }
    }
    Err(TransitionError::InvalidTransition { state, event })
}

pub fn evaluate_transition(
    stage: &Stage,
    event: TransitionEvent,
    satisfied_guards: &BTreeSet<String>,
) -> Result<TransitionDecision, TransitionError> {
    stage.validate().map_err(TransitionError::InvalidStage)?;
    let found = transition_rule(stage.state, event)?;
    let required: BTreeSet<String> = found.guards.iter().map(|s| (*s).to_owned()).collect();
    let missing: Vec<String> = required.difference(satisfied_guards).cloned().collect();
    if !missing.is_empty() {
        return Err(TransitionError::MissingGuards(missing));
    }

    // Constitutional defence in depth against any future rule-table mistake.
    let forbidden = matches!((stage.state, found.to_state),
        (StageState::Derived, StageState::Canonical)
        | (StageState::Validated, StageState::Canonical)
        | (StageState::AuthorityHold, StageState::Canonical)
        | (StageState::RecoveryIntake, StageState::Canonical)
        | (StageState::Quarantined, StageState::Canonical)
        | (StageState::DiscrepancyReview, StageState::Canonical)
    );
    if forbidden {
        return Err(TransitionError::InvalidTransition { state: stage.state, event });
    }
    Ok(TransitionDecision {
        stage_id: stage.stage_id.clone(),
        case_id: stage.case_id.clone(),
        from_state: stage.state,
        event,
        to_state: found.to_state,
        satisfied_guards: satisfied_guards.clone(),
        required_guards: required,
        human_boundary: found.human_boundary,
    })
}

pub fn apply_transition(
    stage: &Stage,
    event: TransitionEvent,
    satisfied_guards: &BTreeSet<String>,
) -> Result<(Stage, TransitionDecision), TransitionError> {
    let decision = evaluate_transition(stage, event, satisfied_guards)?;
    let mut next = stage.clone();
    next.state = decision.to_state;
    Ok((next, decision))
}

pub fn allowed_events(state: StageState) -> Vec<TransitionEvent> {
    use StageState as S;
    use TransitionEvent as E;
    let mut events = match state {
        S::Discovered => vec![E::IngestConfirmed],
        S::Ingested => vec![E::NormalizationComplete],
        S::Normalized => vec![E::DerivationComplete],
        S::Derived => vec![E::ValidationPassed],
        S::Validated => vec![E::PlaceAuthorityHold],
        S::AuthorityHold => vec![E::HumanSelectionRecorded],
        S::HumanSelected => vec![E::PreflightPassed],
        S::PromotionReady => vec![E::PromotionAuthorized],
        S::Canonical => vec![E::NewMaterialEvidence],
        _ => vec![],
    };
    if failure_source(state) {
        events.extend([E::IntegrityFailure, E::MaterialConflict, E::PersistenceFailure]);
    }
    events
}
