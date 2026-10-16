//! P6 pure, advisory-only preflight diagnostics.
//! Input booleans and authority envelopes are NOT independently verified or trusted.
//! Emits no usable human-approval/preflight guards or canonical write instructions.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use crate::authority::{AuthorityScope, PromotionAuthorization, matches_target};

fn nonempty(s: &str) -> bool { !s.trim().is_empty() }
fn hash_ok(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) }
fn unique_nonempty(xs: &[String], allow_empty: bool) -> bool {
    (allow_empty || !xs.is_empty()) && xs.iter().all(|x| nonempty(x))
        && xs.iter().collect::<BTreeSet<_>>().len() == xs.len()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSnapshot {
    pub case_id: String,
    pub target_commit: String,
    pub parent_commit: String,
    pub manifest_hash: String,
    pub payload_hashes: Vec<String>,
    pub lineage_complete: bool,
    pub schema_version: String,
    pub completed_stages: Vec<String>,
    pub blocking_discrepancy_ids: Vec<String>,
    pub authority_decision_id: String,
}
impl CandidateSnapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [&self.case_id, &self.target_commit, &self.parent_commit, &self.schema_version,
            &self.authority_decision_id].iter().any(|s| !nonempty(s)) {
            return Err("candidate identity required");
        }
        if self.target_commit == self.parent_commit {
            return Err("candidate target_commit cannot equal parent_commit");
        }
        if !hash_ok(&self.manifest_hash)
            || self.payload_hashes.is_empty()
            || !self.payload_hashes.iter().all(|h| hash_ok(h)) {
            return Err("candidate requires valid SHA-256 manifest and payload hashes");
        }
        if !unique_nonempty(&self.completed_stages, false)
            || !unique_nonempty(&self.blocking_discrepancy_ids, true) {
            return Err("candidate stages or discrepancies invalid/duplicated");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackSnapshot {
    pub commit_id: String,
    pub manifest_hash: String,
    pub integrity_valid: bool,
    pub schema_compatible: bool,
    pub authority_refs_valid: bool,
    pub known_good: bool,
}
impl RollbackSnapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !nonempty(&self.commit_id) || !hash_ok(&self.manifest_hash) {
            return Err("rollback identity/hash invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightConfig {
    pub policy_version: String,
    pub accepted_authority_policy_version: String,
    pub required_schema_version: String,
    pub required_stages: Vec<String>,
    pub actor: String,
}
impl PreflightConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [&self.policy_version, &self.accepted_authority_policy_version,
            &self.required_schema_version, &self.actor].iter().any(|s| !nonempty(s))
            || !unique_nonempty(&self.required_stages, false) {
            return Err("invalid preflight config");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightRequest {
    pub config: PreflightConfig,
    pub candidate: CandidateSnapshot,
    pub rollback: RollbackSnapshot,
    pub authorization: Option<PromotionAuthorization>,
    pub expected_scope: AuthorityScope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreflightCheck {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PreflightAssessment {
    pub case_id: String,
    pub target_commit: String,
    pub passed: bool,
    pub checks: Vec<PreflightCheck>,
    pub failed_checks: Vec<String>,
    pub output_commit: Option<String>,
    pub canonical_writeback: bool,
    pub authority_transfer: bool,
    pub decision_kind: &'static str,
}

pub fn assess_preflight(input: &PreflightRequest) -> Result<PreflightAssessment, &'static str> {
    let cfg = &input.config;
    let cand = &input.candidate;
    let rb = &input.rollback;
    cfg.validate()?;
    cand.validate()?;
    rb.validate()?;
    input.expected_scope.validate()?;
    if let Some(auth) = &input.authorization {
        auth.validate()?;
    }

    // Order and names intentionally match Python P6.
    let required: BTreeSet<&str> = cfg.required_stages.iter().map(String::as_str).collect();
    let completed: BTreeSet<&str> = cand.completed_stages.iter().map(String::as_str).collect();
    let auth_matches = input.authorization.as_ref().is_some_and(|auth| matches_target(
        auth, &input.expected_scope, &cand.case_id, &cand.authority_decision_id,
        &cand.target_commit, &cfg.accepted_authority_policy_version
    ));
    let raw_checks = [
        ("lineage_complete", cand.lineage_complete),
        ("schema_valid", cand.schema_version == cfg.required_schema_version),
        ("required_stages_complete", required.is_subset(&completed)),
        ("no_blocking_discrepancy", cand.blocking_discrepancy_ids.is_empty()),
        ("authority_decision_present", nonempty(&cand.authority_decision_id)),
        ("authorization_present", input.authorization.is_some()),
        ("authorization_matches_target", auth_matches),
        ("rollback_parent_match", rb.commit_id == cand.parent_commit),
        ("rollback_integrity_valid", rb.integrity_valid),
        ("rollback_schema_compatible", rb.schema_compatible),
        ("rollback_authority_refs_valid", rb.authority_refs_valid),
        ("rollback_known_good", rb.known_good),
    ];

    let checks = raw_checks.iter().map(|(name, passed)| PreflightCheck {
        name: (*name).to_owned(), passed: *passed,
    }).collect::<Vec<_>>();
    let failed_checks = checks.iter().filter(|check| !check.passed)
        .map(|check| check.name.clone()).collect::<Vec<_>>();
    Ok(PreflightAssessment {
        case_id: cand.case_id.clone(),
        target_commit: cand.target_commit.clone(),
        passed: failed_checks.is_empty(),
        checks,
        failed_checks,
        output_commit: None,
        canonical_writeback: false,
        authority_transfer: false,
        decision_kind: "STRUCTURAL_ADVISORY_ONLY",
    })
}
