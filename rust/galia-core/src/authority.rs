//! P5 authority-envelope structural checks (untrusted inputs).
//! Does not issue, authenticate, sign, persist or revoke human decisions.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScope {
    pub case_id: String,
    pub target_type: String,
    pub target_ids: Vec<String>,
}

fn required(s: &str) -> bool { !s.trim().is_empty() }

fn unique_nonempty(xs: &[String]) -> bool {
    !xs.is_empty() && xs.iter().all(|x| required(x)) &&
        xs.iter().collect::<BTreeSet<_>>().len() == xs.len()
}

impl AuthorityScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !required(&self.case_id) || !required(&self.target_type)
            || !unique_nonempty(&self.target_ids) {
            return Err("invalid exact authority scope");
        }
        Ok(())
    }

    pub fn token(&self) -> String {
        format!("case:{}|type:{}|targets:{}",
            self.case_id, self.target_type, self.target_ids.join(","))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionAuthorization {
    pub authorization_id: String,
    pub decision_id: String,
    pub reviewer: String,
    pub scope: AuthorityScope,
    pub target_commit: String,
    pub evidence_snapshot: Vec<String>,
    pub policy_version: String,
    pub authorized_at: String,
}

impl PromotionAuthorization {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.scope.validate()?;
        if [
            &self.authorization_id, &self.decision_id, &self.reviewer,
            &self.target_commit, &self.policy_version, &self.authorized_at,
        ].iter().any(|x| !required(x)) || !unique_nonempty(&self.evidence_snapshot) {
            return Err("invalid authorization envelope");
        }
        Ok(())
    }
}

/// **Structural comparison only.** A caller-supplied envelope is not a human authorization.
pub fn matches_target(
    auth: &PromotionAuthorization,
    scope: &AuthorityScope,
    case_id: &str,
    decision_id: &str,
    target_commit: &str,
    policy_version: &str,
) -> bool {
    scope.case_id == case_id
        && auth.scope == *scope
        && auth.scope.case_id == case_id
        && auth.decision_id == decision_id
        && auth.target_commit == target_commit
        && auth.policy_version == policy_version
}
