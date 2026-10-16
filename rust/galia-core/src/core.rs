//! GALIA P1 contracts: a limited, deliberate parity port from galia2/core.py.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StageState {
    Discovered,
    Ingested,
    Normalized,
    Derived,
    Validated,
    AuthorityHold,
    HumanSelected,
    PromotionReady,
    Canonical,
    Quarantined,
    DiscrepancyReview,
    RecoveryIntake,
    Reopened,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage {
    pub stage_id: String,
    pub case_id: String,
    pub stage_type: String,
    pub state: StageState,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub input_refs: Vec<String>,
    #[serde(default)]
    pub output_refs: Vec<String>,
    #[serde(default)]
    pub blocking_holds: Vec<String>,
}

impl Stage {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.stage_id.trim().is_empty() {
            return Err("stage_id must be nonempty");
        }
        if self.case_id.trim().is_empty() {
            return Err("case_id must be nonempty");
        }
        if self.stage_type.trim().is_empty() {
            return Err("stage_type must be nonempty");
        }
        if self.dependencies.iter().any(|id| id == &self.stage_id) {
            return Err("stage cannot depend on itself");
        }
        Ok(())
    }
}

/// Dates are kept separate. The document date never implies the event date.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArtifact {
    pub artifact_id: String,
    pub repository: String,
    pub repository_ref: String,
    pub document_date: Option<String>,
    pub event_date_hint: Option<String>,
    pub sha256: String,
    pub provenance_state: String,
    #[serde(default = "default_true")]
    pub immutable: bool,
}

fn default_true() -> bool {
    true
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ISO date validator rejects impossible day/month combinations without external crates.
fn valid_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    if !b.iter().enumerate().all(|(i, x)| i == 4 || i == 7 || x.is_ascii_digit()) {
        return false;
    }
    let y: u32 = s[0..4].parse().unwrap_or(0);
    let m: usize = s[5..7].parse().unwrap_or(0);
    let d: u32 = s[8..10].parse().unwrap_or(0);
    if y == 0 || !(1..=12).contains(&m) {
        return false;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    d >= 1 && d <= days[m - 1]
}

impl SourceArtifact {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.artifact_id.trim().is_empty()
            || self.repository.trim().is_empty()
            || self.repository_ref.trim().is_empty()
            || self.provenance_state.trim().is_empty()
        {
            return Err("source identity and provenance must be nonempty");
        }
        if !valid_sha256(&self.sha256) {
            return Err("sha256 must contain 64 hex characters");
        }
        if !self.immutable {
            return Err("source artifacts must remain immutable");
        }
        if self.document_date.as_deref().is_some_and(|x| !valid_iso_date(x))
            || self.event_date_hint.as_deref().is_some_and(|x| !valid_iso_date(x))
        {
            return Err("date must be a valid ISO YYYY-MM-DD date");
        }
        Ok(())
    }
}
